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
    # The count in that PASS line is what a reader trusts about coverage,
    # so it is asserted rather than printed: five branches, but for an
    # uppercase marker petscii_form is the identity, so FOUR distinct
    # patterns are searched.
    distinct = len(set(wps.needle_forms(text).values()))
    check(f"in {distinct} distinct encoding(s)" in absence[2]
          and distinct == 4,
          "the absence line reports the number of DISTINCT patterns "
          "searched, not the number of branches",
          f"{distinct} distinct of {len(wps.needle_forms(text))} branches; "
          f"detail: {absence[2]}")

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

    # The control must depend on the payload it is handed, not merely on
    # the shape of the buffer. Flip ONE byte in the middle of the marker
    # inside the counterfactual body and the control has to go red -- a
    # control that stays green here is reporting the header, or nothing.
    bent_body = bytearray(plain)
    bent_body[len(bent_body) // 2] ^= 0x01
    ctrl_bent, _ = wps.absence_and_control(raw, bytes(bent_body),
                                           {"marker": ctext}, "[bent] ")
    check(not ctrl_bent[0],
          "the control is payload-sensitive: one flipped byte inside the "
          "counterfactual marker turns it RED",
          f"byte {len(bent_body) // 2} of {len(bent_body)}; {ctrl_bent[2]}")

    # THE INDEPENDENT ORACLE for screen codes: the live tool's own
    # `_screen_text`, which decodes $0400 for the "the C64 DECRYPTED it"
    # half of the claim. It was written for a different purpose by a
    # different path, so it cannot be bent to agree with screen_code_form.
    # Round-tripping every printable byte through both is what makes the
    # form assert something about the ENCODING rather than about itself.
    class _FakeScreen:
        def __init__(self, data): self.data = data
        def read_memory(self, addr, n):
            assert (addr, n) == (0x0400, 1000)
            return (self.data + b"\x20" * 1000)[:1000]

    probe_bytes = bytes(range(0x20, 0x80))
    decoded = live._screen_text(_FakeScreen(wps.screen_code_form(probe_bytes)))
    mismatch = [(hex(b), decoded[i], chr(b).upper())
                for i, b in enumerate(probe_bytes)
                if decoded[i] != "." and decoded[i] != chr(b).upper()]
    resolved = sum(1 for i, b in enumerate(probe_bytes) if decoded[i] != ".")
    check(not mismatch and resolved >= 26 + 10 + 1,
          "screen_code_form round-trips through the live tool's OWN "
          "_screen_text decoder",
          f"{resolved}/{len(probe_bytes)} bytes decode back to themselves "
          f"(the rest are the ones _screen_text renders '.'); "
          f"mismatches: {mismatch[:6]}")

    # The screen-code encoding, end to end through the pair: a datagram
    # carrying the marker as $01-$1A must NOT pass the absence arm. Before
    # screen_code_form existed this was reported absent with both arms
    # green -- the encoding a C64 leak is most likely to be copied from.
    screen_dgram = raw[:wps.T4_HDR_LEN] + wps.screen_code_form(cbody)
    _c, screen_absence = wps.absence_and_control(screen_dgram, plain,
                                                 {"marker": ctext},
                                                 "[screen] ")
    check(not screen_absence[0],
          "a datagram carrying the marker in SCREEN CODES fails the "
          "absence arm", screen_absence[2])


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
    # Same LENGTH, wrong bytes -- a length change would trip the
    # needle-fits guard and raise, which is loud; this is the quiet form of
    # the defect, where the search runs to completion looking for bytes the
    # wire never carries.
    def miscoded_forms(t):
        raw = t.encode("ascii") if isinstance(t, str) else bytes(t)
        return {"exact": bytes(b ^ 0x20 for b in raw)}

    with _Mutation("miscoded", "needle_forms", miscoded_forms):
        ok_ctrl, ok_abs, detail = arms()
        check(not ok_ctrl and ok_abs,
              "M2 wrong needle encoding: CONTROL red, absence still green",
              f"control_ok={ok_ctrl} absence_ok={ok_abs}; {detail}")

    # M3 -- mismatched types, and specifically the silent kind. An int
    # haystack is the one CPython does NOT catch: bytes(64) is 64 zero
    # bytes, so without _as_haystack's isinstance check the search reports
    # a CLEAN ABSENCE over a buffer that never existed. Both arms of this
    # are failable: the guard must raise, and its removal must produce
    # exactly that silent pass (otherwise the guard is not load-bearing).
    try:
        wps.plaintext_absent(64, needles)
        check(False, "M3 an int haystack is REFUSED",
              "returned a verdict instead of raising")
    except TypeError as exc:
        check("bytes-like" in str(exc), "M3 an int haystack is REFUSED",
              str(exc))
    with _Mutation("no-type-guard", "_as_haystack", lambda buf: bytes(buf)):
        try:
            ok, detail = wps.plaintext_absent(64, needles)
        except Exception as exc:                              # noqa: BLE001
            ok, detail = None, f"{type(exc).__name__}: {exc}"
        check(ok is True,
              "M3 the type guard is load-bearing: without it an int "
              "haystack reports a CLEAN ABSENCE",
              f"absent={ok}; {detail}")

    # M5/M6 -- the two mutations that USED to pass. Breaking
    # screen_code_form (off by one; nonsense) left the whole suite at
    # 41/41 while DELETING the form alarmed, because every check of it
    # built its haystack by calling it. They are kept here so that can
    # never come back: each must make the selftest's screen-code rows red.
    def _screen_rows():
        return [(ok, label) for ok, label, _ in wps.selftest()
                if "screen" in label]

    for name, fn in (
            ("M5 off-by-one",
             lambda n: bytes((b - 0x41) if 0x41 <= b <= 0x5A else b for b in n)),
            ("M6 nonsense",
             lambda n: bytes(((b - 0x40 + 0x60) & 0xFF) if 0x41 <= b <= 0x5A
                             else b for b in n))):
        with _Mutation(name, "screen_code_form", fn):
            rows = _screen_rows()
            check(bool(rows) and not all(ok for ok, _ in rows),
                  f"{name}: a WRONG screen-code mapping is caught, not just "
                  f"a missing one",
                  f"{[label for ok, label in rows if not ok]}")

    # M4 -- an empty buffer. Absence over nothing is the purest vacuous
    # pass and must raise rather than report clean.
    try:
        wps.plaintext_absent(b"", needles)
        check(False, "M4 empty buffer: the search REFUSES",
              "returned a verdict instead of raising")
    except Exception as exc:                                  # noqa: BLE001
        check(isinstance(exc, wps.VacuousSearchError)
              and "nothing was searched" in str(exc),
              "M4 empty buffer: the search REFUSES",
              f"{type(exc).__name__}: {exc}")

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

    # The four absence assertions go through _absence_pair, which must
    # DELEGATE (not reimplement) on the normal path and must turn a
    # refusal into scored FAILs rather than a traceback mid-hardware-run.
    pair_fn = getattr(live, "_absence_pair", None)
    hdr = bytes([4, 0, 0, 0]) + b"\x01\x02\x03\x04" + b"\x00" * 8
    text = live.random_words(seed + 41, live.REPLY_ALPHABET)
    body = text.encode("ascii")
    dgram = hdr + bytes((b * 29 + 5) & 0xFF for b in range(len(body) + 16))
    if pair_fn is None:
        check(False, "the live tool's absence calls go through a wrapper "
                     "that scores a refused search", "no _absence_pair")
    else:
        check(pair_fn(dgram, body, {"m": text}, "")
              == wps.absence_and_control(dgram, body, {"m": text}, ""),
              "on the normal path _absence_pair returns exactly what the "
              "searcher returns", "delegation, not a second implementation")
        # A header-only datagram: the search is impossible, so the marker
        # must NOT come back "absent".
        try:
            rows = pair_fn(hdr, body, {"m": text}, "[torn] ")
        except Exception as exc:                              # noqa: BLE001
            rows, why = [], f"raised {type(exc).__name__}: {exc}"
        else:
            why = f"{[(ok, l) for ok, l, _ in rows]}"
        check(len(rows) == 2 and not any(ok for ok, _l, _d in rows)
              and "NOT ASSERTED" in rows[1][2],
              "a refused search lands as scored FAILs, not a traceback", why)

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
    # The property is "every letter a host->C64 marker carries comes from
    # REPLY_ALPHABET", so the only thing exempted is the literal ` END `
    # separator -- not the characters E, N and D wherever they occur. The
    # loose version (allowed = REPLY_ALPHABET | set(" END")) admitted E and
    # D, which are REQUEST_ALPHABET letters, anywhere in the string, and
    # would not have noticed a builder switching alphabets.
    live_fns = [fn for fn in builders.values() if fn is not None]
    for wire_len in (None, "832"):
        # BOTH configurations: WIRE_MSG_LEN is the full-size-tunnel knob,
        # and it is where _sized's filler used to reintroduce A-M. A suite
        # that only ever runs in the default configuration is how that got
        # in.
        prior = os.environ.get("WIRE_MSG_LEN")
        if wire_len is None:
            os.environ.pop("WIRE_MSG_LEN", None)
        else:
            os.environ["WIRE_MSG_LEN"] = wire_len
        try:
            stray = {}
            for fn in live_fns:
                text = fn(seed)
                rest = " ".join(t for t in text.split(" ") if t != "END")
                bad = set(rest) - set(live.REPLY_ALPHABET) - {" "}
                if bad:
                    stray[fn.__name__] = (sorted(bad), len(text))
            check(bool(live_fns) and not stray,
                  f"host->C64 markers use ONLY REPLY_ALPHABET "
                  f"(WIRE_MSG_LEN={wire_len or 'unset'})",
                  f"stray characters: {stray}" if stray else
                  f"{len(live_fns)} builder(s), "
                  f"{len(live_fns and live_fns[0](seed))} chars; disjoint "
                  f"from REQUEST_ALPHABET, so an echo of the C64's own "
                  f"message can never satisfy them")
        finally:
            if prior is None:
                os.environ.pop("WIRE_MSG_LEN", None)
            else:
                os.environ["WIRE_MSG_LEN"] = prior


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
