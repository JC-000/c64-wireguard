#!/usr/bin/env python3
"""tools/test_warp_instrument_vice.py — the two INSTRUMENT defects of issue
#128 that live in the firmware, on a real 6510 (VICE).

Case 4 — CAUSE CONFLATION
    `transport_decrypt` (src/wg/transport.s:403-786) has a single `lda #$ff`
    result shared by FIVE rejection causes, and `@decrypt_fail` in
    session.s prints one string for all of them. So "DECRYPT FAILED" on the
    screen is not evidence of an AEAD failure — which is exactly how #128's
    "9/9 fail AEAD" was manufactured. This drives all five causes plus a
    genuinely ChaCha20-Poly1305-sealed packet and asserts what the build
    actually promises — see the conditional contract below.

    Cause numbering follows the comment already in src/wg/session.s:449-453:
      1 type byte != 4        2 counter byte 7 >= $10
      3 replay / duplicate    4 udp_recv_len < 32
      5 Poly1305 tag mismatch (the only one that IS "failed AEAD")
      0 success

Case 2 PREMISE — PEER BYTES REACH THE GLASS
    The host-side false-positive tests in tools/test_warp_instrument_unit.py
    rest on one claim about the firmware: `display_payload`
    (src/wg/session.s:634) prints peer-supplied bytes to the screen and does
    NOT set `msg_recv_len`, so the tool sees recv_len == 0 and evaluates its
    screen scrape over bytes the peer chose. That claim is proven here on
    the real print path rather than assumed. Since #129 the bytes are passed
    through a printable filter, which is why the injection is *readable*:
    the assertion is byte-exact on SCREEN CODES, not a keyword search.

The case-4 contract is CONDITIONAL on the build, so the suite is honest
without crying wolf:

  * no `tp_reject_cause` (every build today) — it PINS THE CONFLATION,
    requiring all five causes to share the one $ff exit. That is true now,
    so it passes; it goes RED the day any of the five stops sharing it,
    which is the day the contract changed and the tests did not. The run
    prints the conflation as a measured property, not a passing grade.
  * `tp_reject_cause` present — it requires five DISTINCT and CORRECT
    codes, so a correct fix stays green and an incorrect one fails.

Discrimination is HOST-SIDE today and that is sufficient: the poison fill
in tools/test_warp_live.py decides arrived-vs-never-arrived, the replay
window decides accepted-vs-rejected, the receive buffer gives causes 1-4
directly, and the host-side Poly1305 check observes cause 5 rather than
inferring it. A device cause byte would be corroboration, not a
prerequisite.

Case 2's premise is expected GREEN on every tree — it is a premise, not a
defect — and is proved to alarm by corrupting one byte of the injected
payload (--prove-detector).

The payload for every case is drawn from a seeded RNG, logged, and
reproducible with --seed. The only fixed text is the injected marker, and
it is a suffix.

Usage:
    python3 tools/test_warp_instrument_vice.py [--seed S] [--prove-detector]

Requires build/wireguard.prg + build/labels.txt (any backend; nothing here
touches the network). C64_SKIP_BUILD=1 to reuse an existing build.
"""
from __future__ import annotations

import argparse
import os
import random
import string
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness import (  # noqa: E402
    Labels, ViceConfig, ViceInstanceManager, jsr, read_bytes, wait_for_text,
    write_bytes,
)
from c64_test_harness.encoding.screen_codes import SCREEN_CODE_TABLE  # noqa: E402

PRG_PATH = PROJECT_ROOT / "build" / "wireguard.prg"
LABELS_PATH = PROJECT_ROOT / "build" / "labels.txt"

SCREEN_COLS, SCREEN_ROWS = 40, 25
CAUSE_LABEL = "tp_reject_cause"

# Disjoint from anything the firmware prints itself, so a stray firmware
# line can never satisfy a peer-injection assertion.
PEER_ALPHABET = string.ascii_uppercase + string.digits

_ASCII_TO_CODE: dict[str, int] = {}
for _code, _ch in enumerate(SCREEN_CODE_TABLE):
    _ASCII_TO_CODE.setdefault(_ch, _code)


class Result:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}\n        {detail}")


# =============================================================================
# Packet construction
# =============================================================================
def wg_nonce(counter_le8: bytes) -> bytes:
    """WireGuard's ChaCha20-Poly1305 nonce: 4 zero bytes then the counter.

    `transport_build_nonce` builds it from tp_recv_counter_tmp, which is a
    byte-for-byte copy of udp_recv_buf[8..15], so the counter is
    little-endian in both places.
    """
    return b"\x00" * 4 + counter_le8


def seal(key: bytes, counter_le8: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305(key).encrypt(wg_nonce(counter_le8), plaintext, None)


def type4_packet(counter: int, body: bytes, *, key: bytes | None = None,
                 rng: random.Random) -> bytes:
    """A Type-4 transport datagram. With *key*, the tag is genuine."""
    ctr = counter.to_bytes(8, "little")
    receiver = bytes(rng.randrange(256) for _ in range(4))
    if key is not None:
        sealed = seal(key, ctr, body)
    else:                       # random ciphertext+tag: Poly1305 must reject
        sealed = body + bytes(rng.randrange(256) for _ in range(16))
    return bytes([4, 0, 0, 0]) + receiver + ctr + sealed


# =============================================================================
# Device-side setup
# =============================================================================
def reset_recv_state(tr, L, key: bytes) -> None:
    """Put the receive path in a known state before every trial.

    Without this a trial inherits the previous trial's replay window and a
    cause-3 reject can be manufactured by accident — the same class of
    mistake as the stale state this whole suite is about.
    """
    write_bytes(tr, L.address("hs_transport_recv"), key)
    write_bytes(tr, L.address("rw_counter_max"), bytes(8))
    write_bytes(tr, L.address("rw_bitmap"), bytes(256))
    write_bytes(tr, L.address("rw_new_counter"), bytes(1))
    write_bytes(tr, L.address("tp_recv_counter"), bytes(8))
    write_bytes(tr, L.address("tp_payload_len"), bytes(2))
    write_bytes(tr, L.address("msg_recv_len"), bytes(2))
    if L.address(CAUSE_LABEL) is not None:
        write_bytes(tr, L.address(CAUSE_LABEL), bytes([0xAA]))  # poison


def stage_datagram(tr, L, packet: bytes, *, declared_len: int | None = None) -> None:
    write_bytes(tr, L.address("udp_recv_buf"), packet)
    n = len(packet) if declared_len is None else declared_len
    write_bytes(tr, L.address("udp_recv_len"), n.to_bytes(2, "little"))


def run_decrypt(tr, L) -> tuple[int, int | None]:
    """jsr transport_decrypt; return (A, cause) — cause None when no label."""
    regs = jsr(tr, L.address("transport_decrypt"), timeout=30.0)
    a = regs["A"]
    cause = None
    if L.address(CAUSE_LABEL) is not None:
        cause = read_bytes(tr, L.address(CAUSE_LABEL), 1)[0]
    return a & 0xFF, cause


# =============================================================================
# Case 4 — cause conflation
# =============================================================================
def case4_cause_conflation(tr, L, rng: random.Random, res: Result) -> None:
    print("\n[case 4] transport_decrypt: five reject causes, one exit")
    key = bytes(rng.randrange(256) for _ in range(32))
    body = bytes(rng.randrange(256) for _ in range(rng.randrange(64, 200)))

    # --- build one trial per documented cause ---------------------------
    bad_type = rng.choice([b for b in range(256) if b != 4])
    p1 = bytearray(type4_packet(1, body, key=key, rng=rng))
    p1[0] = bad_type                                    # cause 1

    p2 = bytearray(type4_packet(1, body, key=key, rng=rng))
    p2[15] = rng.randrange(0x10, 0x100)                 # cause 2 (ctr byte 7)

    p3 = type4_packet(1, body, key=key, rng=rng)        # cause 3, see below
    p4 = type4_packet(1, body, key=key, rng=rng)        # cause 4, short len
    p5 = type4_packet(1, body, key=None, rng=rng)       # cause 5, bad tag
    p0 = type4_packet(1, body, key=key, rng=rng)        # cause 0, valid

    trials = [
        ("cause1-type-byte", bytes(p1), None, 1),
        ("cause2-counter-limit", bytes(p2), None, 2),
        ("cause3-replay-duplicate", p3, None, 3),
        ("cause4-underflow", p4, rng.randrange(1, 32), 4),
        ("cause5-tag-mismatch", p5, None, 5),
        ("cause0-valid-packet", p0, None, 0),
    ]

    observed: dict[str, tuple[int, int | None]] = {}
    for name, packet, declared, want in trials:
        reset_recv_state(tr, L, key)
        if want == 3:
            # Counter 1 already received: max=1 and its bitmap bit set.
            write_bytes(tr, L.address("rw_counter_max"),
                        (1).to_bytes(8, "little"))
            write_bytes(tr, L.address("rw_bitmap") + 0, bytes([0x02]))
        stage_datagram(tr, L, packet, declared_len=declared)
        a, cause = run_decrypt(tr, L)
        observed[name] = (a, cause)
        print(f"        {name:<24} A=${a:02X} {CAUSE_LABEL}="
              f"{'<no such label>' if cause is None else cause}")

    # Ground truth first: each trial must have gone the way it was built.
    res.check(observed["cause0-valid-packet"][0] == 0x00,
              "case4/valid-packet-accepted",
              "a genuinely sealed packet was rejected "
              f"(A=${observed['cause0-valid-packet'][0]:02X}) — the trial "
              "construction, not the firmware, is what this run measured")
    rejects = [n for n, _, _, w in trials if w != 0]
    res.check(all(observed[n][0] == 0xFF for n in rejects),
              "case4/all-five-reject",
              "not every cause actually rejected: "
              + ", ".join(f"{n}=A${observed[n][0]:02X}" for n in rejects))

    # The defect.
    # The contract is CONDITIONAL on what the build actually exports, so
    # this suite pins today's known-bad behaviour instead of asserting
    # against a symbol nobody has agreed to add.
    #
    # Without a cause byte the suite PINS THE CONFLATION: it requires all
    # five causes to be indistinguishable, which is exactly what is true
    # today. That is not a green over a defect — the defect is recorded, in
    # the run's own output, as a measured property. It goes RED the moment
    # any of the five stops returning the shared $ff, i.e. the moment
    # someone changes this contract without changing the tests, which is
    # the failure this suite exists to prevent.
    #
    # With a cause byte it requires five DISTINCT and CORRECT codes. So a
    # correct fix stays green and an incorrect one fails. Neither branch
    # cries wolf.
    if L.address(CAUSE_LABEL) is None:
        res.check(len({observed[n][0] for n in rejects}) == 1
                  and observed[rejects[0]][0] == 0xFF,
                  "case4/conflation-is-total",
                  "the five causes no longer share one exit value: "
                  + ", ".join(f"{n}=A${observed[n][0]:02X}" for n in rejects)
                  + ". If that is deliberate, this suite's contract is stale "
                    "and must be updated in the same commit")
        print(f"        NOTE: no '{CAUSE_LABEL}' in this build. All five "
              f"reject causes return A=$FF and are indistinguishable on the "
              f"device; discrimination is HOST-SIDE only (poison fill for "
              f"arrival, replay-window delta for accept, buffer inspection "
              f"for causes 1-4, host Poly1305 for cause 5). This is a "
              f"recorded property, not a passing grade.")
        return

    res.check(True, "case4/cause-label-exists")
    codes = {n: observed[n][1] for n, _, _, _ in trials}
    wanted = {n: w for n, _, _, w in trials}
    res.check(len(set(codes.values())) == len(codes), "case4/causes-distinct",
              f"cause codes are not all distinct: {codes}")
    for name in codes:
        res.check(codes[name] == wanted[name], f"case4/{name}",
                  f"expected cause {wanted[name]}, got {codes[name]}")


# =============================================================================
# Case 2 premise — peer bytes reach the screen, msg_recv_len untouched
# =============================================================================
def case2_premise(tr, L, rng: random.Random, res: Result,
                  corrupt: bool = False) -> None:
    print("\n[case 2 premise] display_payload prints peer bytes; "
          "msg_recv_len stays 0")
    marker = b"MSG> DECRYPT FAILED"
    # display_payload prints "RECV: " (6 chars) first; align the marker to a
    # row boundary so the 40-column wrap cannot break it. A peer picking its
    # own padding does exactly this.
    pad = (SCREEN_COLS - len("RECV: ")) % SCREEN_COLS
    head = "".join(rng.choice(PEER_ALPHABET) for _ in range(pad)).encode()
    tail = "".join(rng.choice(PEER_ALPHABET) for _ in range(37)).encode()
    payload = head + marker + tail
    if corrupt:
        i = rng.randrange(len(payload))
        payload = payload[:i] + bytes([payload[i] ^ 0x01]) + payload[i + 1:]
        print(f"        detector proof: byte {i} of the payload flipped")

    write_bytes(tr, L.address("msg_recv_len"), bytes(2))
    write_bytes(tr, L.address("tp_packet") + 16, payload)
    write_bytes(tr, L.address("tp_payload_len"),
                len(payload).to_bytes(2, "little"))
    jsr(tr, L.address("display_payload"), timeout=30.0)

    codes = list(tr.read_screen_codes())
    rows = [codes[r * SCREEN_COLS:(r + 1) * SCREEN_COLS]
            for r in range(SCREEN_ROWS)]
    # Structural, not a text search: the exact screen codes the peer's bytes
    # must have produced, compared row-slice to row-slice.
    want = [_ASCII_TO_CODE[c] for c in marker.decode()]
    landed = any(row[c:c + len(want)] == want
                 for row in rows for c in range(SCREEN_COLS - len(want) + 1))
    res.check(landed, "case2premise/peer-bytes-on-screen",
              "the peer's bytes did not reach the screen verbatim — the "
              "host-side false-positive cases rest on this")

    recv_len = int.from_bytes(read_bytes(tr, L.address("msg_recv_len"), 2),
                              "little")
    res.check(recv_len == 0, "case2premise/msg-recv-len-untouched",
              f"msg_recv_len={recv_len} after display_payload; the tool's "
              "`if recv_len == 0` guard would not have evaluated the scrape")


# =============================================================================
def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--prove-detector", action="store_true",
                   help="corrupt one byte of the injected payload; the "
                        "case-2 premise assertion must go RED")
    p.add_argument("--only", default=None, help="'4' or '2'")
    args = p.parse_args(argv)

    os.chdir(PROJECT_ROOT)
    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], capture_output=True)
        r = subprocess.run(["make"], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            return 2
    if not PRG_PATH.exists() or not LABELS_PATH.exists():
        print(f"FATAL: {PRG_PATH} / {LABELS_PATH} missing")
        return 2

    import hashlib
    prg = PRG_PATH.read_bytes()
    print(f"PRG fingerprint: sha256={hashlib.sha256(prg).hexdigest()} "
          f"({len(prg)} B) {CAUSE_LABEL}="
          f"{'present' if Labels.from_file(str(LABELS_PATH)).address(CAUSE_LABEL) else 'ABSENT'}")

    L = Labels.from_file(str(LABELS_PATH))
    for need in ("transport_decrypt", "display_payload", "udp_recv_buf",
                 "udp_recv_len", "hs_transport_recv", "rw_counter_max",
                 "rw_bitmap", "tp_packet", "tp_payload_len", "msg_recv_len"):
        if L.address(need) is None:
            print(f"FATAL: label '{need}' not found")
            return 2

    res = Result()
    config = ViceConfig(prg_path=str(PRG_PATH), warp=True, ntsc=True,
                        sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        tr = inst.transport
        if wait_for_text(tr, "Q=QUIT", timeout=90.0) is None:
            print("FATAL: main menu never appeared")
            mgr.release(inst)
            return 2
        # Safety: land in a harmless loop after jsr() returns.
        write_bytes(tr, 0x0339, bytes([0x4C, 0x39, 0x03]))

        if args.only in (None, "4"):
            case4_cause_conflation(tr, L, rng, res)
        if args.only in (None, "2"):
            case2_premise(tr, L, rng, res, corrupt=args.prove_detector)
        mgr.release(inst)

    total = res.passed + res.failed
    print(f"\nResults: {res.passed}/{total} passed")
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
