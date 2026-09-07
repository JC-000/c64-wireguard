#!/usr/bin/env python3
"""Issue #147: prove the wire-encryption tool's absence claims can fire.

    python3.13 tools/test_wire_encryption_control.py [--seed N]

`test_wire_encryption_live.py` asserts four times that a marker is ABSENT
from a WireGuard datagram. Absence assertions are the cheapest thing in
testing to pass for the wrong reason: a searcher that looks at an empty
buffer, encodes the needle the way the host holds it rather than the way
the wire carries it, or compares a str to bytes reports every datagram
clean, and the tool then says the tunnel encrypts whether or not it does.

This suite runs entirely on the host -- no U64E, no VICE -- because the
question is about the SEARCHER and the pairing, not about the C64. It
builds a REAL WireGuard session in process (the same `WireGuardResponder`
and the same Noise handshake the live tool uses, via
test_wg_responder_loopback's initiator, with no sockets) so that the
ciphertext the absence arm is asserted over is genuine ChaCha20-Poly1305
output of the very call the live tool makes, not a stand-in.

Four legs:

  A. the searcher's own selftest (finds every wire encoding, refuses every
     vacuous search).
  B. THE PAIRING, on real ciphertext: the control FIRES on the
     counterfactual cleartext datagram while absence HOLDS on the
     ciphertext, in both directions; and a deliberately-cleartext datagram
     fed to the absence arm makes it FAIL.
  C. THE MUTATION PROOF: with the searcher deliberately broken (blind,
     wrong needle encoding, mismatched types) the control goes RED while
     the absence arm stays GREEN -- which is exactly the divergence that
     distinguishes a working searcher from one that cannot fire, and is
     the state the tool was shipped in before this change.
  D. identity: the live tool calls THIS searcher, not a copy of it. A
     control that exercises a parallel implementation proves the parallel
     implementation works.
  E. the gate: a searcher that fails its own selftest ABORTS the live tool
     before the device is touched, rather than producing four absence
     PASSes nobody can interpret.

Randomised per the standing rule: every marker is drawn from a seeded RNG
and the seed is logged and reproducible via --seed / TEST_SEED.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(TOOLS.parent))

import wire_plaintext_search as wps                           # noqa: E402
import test_wire_encryption_live as live                      # noqa: E402
import test_wg_responder_loopback as lb                       # noqa: E402
from test_uci_handshake_live import ascii_to_petscii          # noqa: E402
from wg_responder.keys import generate_keypair                # noqa: E402
from wg_responder.responder import WireGuardResponder         # noqa: E402

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail else ""), flush=True)
    return bool(ok)


def make_session():
    """A completed WireGuard session, in process, no sockets.

    Same responder class and same Noise construction the live tool runs
    against; `handle_initiation` is the exact call its server thread makes.
    """
    init_priv, init_pub = (bytes.fromhex(h) for h in generate_keypair())
    resp_priv, resp_pub = (bytes.fromhex(h) for h in generate_keypair())
    psk = bytes(32)
    responder = WireGuardResponder(static_priv=resp_priv,
                                   peer_static_pub=init_pub, psk=psk)
    sender_idx = int.from_bytes(os.urandom(4), "little")
    t1, initiator_noise = lb.build_type1(init_priv, init_pub, resp_pub,
                                         psk, sender_idx)
    t2 = responder.handle_initiation(t1)
    initiator_noise.read_message(t2[12:60])
    resp_sender_idx = struct.unpack_from("<I", t2, 4)[0]
    return responder, initiator_noise, resp_sender_idx


def leg_a() -> None:
    print("\n=== A. the searcher's selftest ===", flush=True)
    for ok, label, detail in wps.selftest():
        check(ok, label, detail)


def leg_b(seed: int) -> None:
    print("\n=== B. the pairing, over REAL ChaCha20-Poly1305 output ===",
          flush=True)
    responder, initiator_noise, resp_idx = make_session()

    # --- host -> C64, the shape sections 2 and 4b assert over -------------
    text = (f"{live.random_words(seed + 21, live.REPLY_ALPHABET)} END "
            f"{live.random_suffix(seed + 22, live.REPLY_ALPHABET)}")
    body = ascii_to_petscii(text)
    pkt = responder.encrypt_transport(body)
    ctrl, absence = wps.absence_and_control(pkt, body, {"marker": text},
                                            "[host->C64] ")
    check(ctrl[0], ctrl[1], ctrl[2])
    check(absence[0], absence[1], absence[2])

    # --- C64 -> host, the shape sections 1 and 1b assert over -------------
    # The initiator stands in for the C64: its Type-4 is built by the same
    # Noise cipherstate the C64's would be, and `decrypt_transport` is the
    # very call the live tool taps.
    ctext = (f"{live.random_words(seed + 23, live.REQUEST_ALPHABET)} END "
             f"{live.random_suffix(seed + 24, live.REQUEST_ALPHABET)}")
    cbody = ascii_to_petscii(ctext)
    raw = lb.build_type4(initiator_noise, cbody, resp_idx, 0)
    plain = responder.decrypt_transport(raw)
    check(plain == cbody, "[C64->host] the datagram decrypts to the marker",
          f"{len(plain)} B")
    ctrl2, absence2 = wps.absence_and_control(raw, plain, {"marker": ctext},
                                              "[C64->host] ")
    check(ctrl2[0], ctrl2[1], ctrl2[2])
    check(absence2[0], absence2[1], absence2[2])

    # --- THE PAIRING PROOF: a cleartext datagram must make absence FAIL ---
    # This is what "the absence assertion is load-bearing" means. The
    # buffer is what the C64 would have transmitted with transport_send's
    # encrypt removed: its own header, its own payload, unencrypted.
    cleartext_dgram = raw[:wps.T4_HDR_LEN] + plain
    ctrl3, absence3 = wps.absence_and_control(cleartext_dgram, plain,
                                              {"marker": ctext}, "[mutant] ")
    check(not absence3[0],
          "MUTANT: the absence assertion FAILS on a cleartext datagram",
          absence3[2])
    check(ctrl3[0], "MUTANT: its control still fires", ctrl3[2])

    # A one-byte corruption of the ciphertext must not resurrect a hit,
    # and must not silence the control either.
    bent = bytearray(raw)
    bent[wps.T4_HDR_LEN + 4] ^= 0x01
    ctrl4, absence4 = wps.absence_and_control(bytes(bent), plain,
                                              {"marker": ctext}, "[bitflip] ")
    check(absence4[0] and ctrl4[0],
          "a one-bit-corrupted datagram: absence holds AND the control fires",
          f"{absence4[2]}")


class _Mutation:
    """Break the searcher, restore it afterwards."""

    def __init__(self, label: str, attr: str, replacement):
        self.label, self.attr, self.replacement = label, attr, replacement

    def __enter__(self):
        self.original = getattr(wps, self.attr)
        setattr(wps, self.attr, self.replacement)
        return self

    def __exit__(self, *exc):
        setattr(wps, self.attr, self.original)
        return False


def leg_c(seed: int) -> None:
    print("\n=== C. mutation proof: a broken searcher goes RED at the "
          "control and GREEN at the absence arm ===", flush=True)
    responder, _noise, _idx = make_session()
    text = (f"{live.random_words(seed + 31, live.REPLY_ALPHABET)} END "
            f"{live.random_suffix(seed + 32, live.REPLY_ALPHABET)}")
    body = ascii_to_petscii(text)
    pkt = responder.encrypt_transport(body)
    needles = {"marker": text}

    def arms():
        ctrl, absence = wps.absence_and_control(pkt, body, needles, "")
        return ctrl[0], absence[0], ctrl[2]

    ok_ctrl, ok_abs, _ = arms()
    check(ok_ctrl and ok_abs,
          "baseline (searcher intact): control fires AND absence holds")

    # M1 -- blind: the search examines the buffer and always reports
    # nothing. This is the failure mode the un-controlled tool could not
    # distinguish from an encrypting tunnel.
    with _Mutation("blind", "search_forms", lambda hay, pat: []):
        ok_ctrl, ok_abs, detail = arms()
        check(not ok_ctrl and ok_abs,
              "M1 blind searcher: CONTROL red, absence still green",
              f"control_ok={ok_ctrl} absence_ok={ok_abs}; {detail}")

    # M2 -- wrong needle encoding: the needle is encoded the way the host
    # holds it rather than the way the wire carries it (the 2026-09-07
    # false null, in miniature).
    def utf16_forms(t):
        raw = t.encode("utf-16-le") if isinstance(t, str) else bytes(t)
        return {"exact": raw}

    with _Mutation("utf16", "needle_forms", utf16_forms):
        ok_ctrl, ok_abs, detail = arms()
        check(not ok_ctrl and ok_abs,
              "M2 wrong needle encoding: CONTROL red, absence still green",
              f"control_ok={ok_ctrl} absence_ok={ok_abs}; {detail}")

    # M3 -- mismatched types: str against bytes. This one must be LOUD,
    # not merely red: a searcher that silently returns "no hits" for a
    # type error is the same class of defect one level down.
    with _Mutation("str-needle", "needle_forms",
                   lambda t: {"exact": t if isinstance(t, str) else t}):
        try:
            wps.absence_and_control(pkt, body, needles, "")
            check(False, "M3 mismatched types: the search REFUSES",
                  "returned a verdict instead of raising")
        except TypeError as exc:
            check(True, "M3 mismatched types: the search REFUSES", str(exc))

    # M4 -- an empty buffer. Absence over nothing is the purest vacuous
    # pass and must raise rather than report clean.
    try:
        wps.plaintext_absent(b"", needles)
        check(False, "M4 empty buffer: the search REFUSES",
              "returned a verdict instead of raising")
    except wps.VacuousSearchError as exc:
        check(True, "M4 empty buffer: the search REFUSES", str(exc))

    ok_ctrl, ok_abs, _ = arms()
    check(ok_ctrl and ok_abs,
          "after every mutation is reverted, both arms are green again")


def leg_d(seed: int) -> None:
    print("\n=== D. the live tool calls THIS searcher, and its markers are "
          "seeded ===", flush=True)
    # getattr, not attribute access: on a tree where the live tool has not
    # been wired to the searcher these must be recorded as FAILURES, not
    # crash the suite before the rest of the legs report.
    check(getattr(live, "absence_and_control", None) is wps.absence_and_control,
          "test_wire_encryption_live uses the controlled searcher itself",
          "identity, not a look-alike: a control over a parallel copy "
          "would only prove the copy works")
    check(getattr(live, "wps", None) is wps,
          "the live tool's `wps` is this module")

    builders = {name: getattr(live, f"_build_marker_{key}", None)
                for name, key in (("MARKER_HOST", "host"),
                                  ("MARKER_TAMPER", "tamper"),
                                  ("MARKER_ALIVE", "alive"))}
    for name, fn in builders.items():
        if fn is None:
            check(False, f"{name} is seeded",
                  f"no _build_marker_* builder: {name} is a fixed string "
                  f"({getattr(live, name, None)!r})")
            continue
        x, y = fn(seed), fn(seed + 1)
        check(x != y and fn(seed) == x,
              f"{name} is seeded: different per seed, reproducible per seed",
              f"{x[:24]!r} vs {y[:24]!r}")
    allowed = set(live.REPLY_ALPHABET) | set(" END0123456789")
    live_fns = [fn for fn in builders.values() if fn is not None]
    check(bool(live_fns) and all(set(fn(seed)) <= allowed for fn in live_fns),
          "host->C64 markers stay in REPLY_ALPHABET",
          "disjoint from REQUEST_ALPHABET, so an echo of the C64's own "
          "message can never satisfy them")


def leg_e() -> None:
    print("\n=== E. a blind searcher aborts the run before the device is "
          "touched ===", flush=True)
    import types

    import test_uci_handshake_live as real                    # noqa: F401

    # A stand-in for the handshake tool that records the call instead of
    # loading a PRG onto the shared U64E: reaching it at all IS the
    # failure this leg tests for. It keeps every other attribute of the
    # real module so the live tool's own imports still resolve.
    touched: list[list[str]] = []
    # device_session too: the live tool's `finally` restores 1 MHz on the
    # host it was given, which on a tree without the gate is a second way
    # the device is reached. Recording it keeps this leg entirely offline.
    import device_session as real_ds
    ds_stub = types.ModuleType("device_session")
    ds_stub.__dict__.update(real_ds.__dict__)
    ds_stub.restore_idle = lambda *a, **k: touched.append(["restore_idle", *map(str, a)])
    stub = types.ModuleType("test_uci_handshake_live")
    stub.__dict__.update(real.__dict__)
    stub.main = lambda argv=None: (touched.append(list(sys.argv)), 0)[1]
    argv = sys.argv
    with _Mutation("selftest-fails", "selftest",
                   lambda: [(False, "forced failure", "M5")]):
        sys.modules["test_uci_handshake_live"] = stub
        sys.modules["device_session"] = ds_stub
        sys.argv = ["test_wire_encryption_live.py",
                    "--host", "203.0.113.9", "--seed", "1"]
        try:
            rc = live.main()
        finally:
            sys.argv = argv
            sys.modules["test_uci_handshake_live"] = real
            sys.modules["device_session"] = real_ds
    check(rc == 2 and not touched,
          "a failing searcher selftest aborts with rc=2 and no device access",
          f"rc={rc}, handshake tool invoked {len(touched)} time(s)")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()
    seed = live.resolve_seed(args.seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed} or "
          f"TEST_SEED={seed})", flush=True)

    leg_a()
    leg_b(seed)
    leg_c(seed)
    leg_d(seed)
    leg_e()

    failed = [label for ok, label in results if not ok]
    print("\n" + "=" * 60, flush=True)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed",
          flush=True)
    for label in failed:
        print(f"  FAILED: {label}", flush=True)
    print("=" * 60, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
