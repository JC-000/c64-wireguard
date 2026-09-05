#!/usr/bin/env python3
"""UCI UDP read-size probe — does `net_poll` deliver what was sent?

WHAT THIS FILE USED TO DO, AND WHY THAT MATTERED
================================================

Until 2026-09-04 this tool had NO ASSERTION OF ANY KIND. The docstring
above this line promised "confirm against the expected pattern (byte i ==
i & 0xFF)"; `_verify_pattern` was defined and never called (it was the
only module-level function in the file with zero call sites), and `main()`
ended `_print_summary(results); return 0` — no return value anywhere
depended on `results`. Every wrong-length, wrong-content and
never-delivered row printed and the process exited 0.

That is not a dormant assertion, it is a retracted result. This tool
produced the claim "the raw path is clean at 1000/1420/1472, verified
byte-for-byte", and that claim was cited to rule the UCI multi-block read
OUT of issue #128 — pointing the investigation away from `net_poll`, which
is where the defect (#130, `@block_short`) actually was. The claim was
vacuous. The sizes it reported clean happen to sit outside the fatal
staging window, so the conclusion survived; the evidence never supported
it.

Two further defects made it blind even had it scored:

  * the poison fill was 64 bytes wide (`b"\xCC" * 64`) and the readback was
    16 head bytes plus 16 at `udp_recv_buf + rx_len - 16`. #130's
    signature is a copy that stops at 893 under an announced 1008+ — MID
    BUFFER, outside every window this tool looked at.
  * `make_pattern`'s byte i = i & 0xFF collides with any fixed poison
    byte at some offset, so even a wide `\xCC` fill could not have
    measured a stop exactly.

WHAT IT DOES NOW
================

For each size in SIZES:
  1. POISON udp_recv_buf to its full structural capacity (derived from
     `udp_recv_len - udp_recv_buf`, not assumed) with
     `poison_pattern` — `P[i] = (i + seed) % 251`, the same fill
     tools/test_warp_live.py and the upstream firmware lane's
     `net_target_test.py` use, so all three read the same bytes the same
     way. Verified by read-back before the trial starts.
  2. Choose the reply bytes with `_payload_for`: seeded random, forced to
     differ from the poison at EVERY offset, with a short fixed marker as
     a SUFFIX. A coincidence therefore cannot move the measured stop.
  3. Reset udp_recv_ready / udp_recv_len, kick the responder, poll.
  4. Read the WHOLE buffer back and compute two independent quantities:
       * `poison_stop` — how far the firmware actually WROTE.
       * `_verify_pattern` — whether those bytes are the bytes sent.
  5. SCORE it. `score_results` is a pure function over the recorded rows
     and `main()` returns non-zero when it reports anything.

The two quantities answer different questions and both are needed. A
short read has `poison_stop < udp_recv_len` with every written byte
correct; corruption has `poison_stop == udp_recv_len` with a mismatch.
Only the pair distinguishes "the copy stopped early" from "the copy was
wrong", and #128 spent two days unable to tell them apart.

ALARM PROOF
===========

`--self-check` runs the scorer over fabricated rows — clean, corrupt at a
known offset, nothing delivered, and a short read stopping at a response
block boundary — and requires it to flag each one, naming the offset. No
device, no responder, milliseconds. Run it and you know the detector
fires. It is also what makes this file safe to trust again: the previous
version would have passed every hardware run ever put through it.

Runs at 1 MHz with debug-stream capture for failure post-mortem. SPEED IS
A TEST AXIS AND 1 MHz IS THE WRONG END OF IT: `@block_short` is reached
only when DATA_AV reads clear AND STATE is $20/$00 in the same latched
byte, which is a race between the 6510 and the FPGA's staging. At 1 MHz
the block is essentially always staged in time. A run intended to observe
$8F must sweep TURBO_MHZ and count occurrences per speed.
"""
from __future__ import annotations

import datetime as _dt
import os
import random
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = "/Users/someone/Documents/c64-test-harness/src"
if SRC not in sys.path:
    sys.path.insert(0, SRC)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from c64_test_harness import (
    DeviceLock, DeviceLockTimeout, Labels, enable_uci, get_uci_enabled,
    probe_u64, write_bytes,
)
from c64_test_harness.backends.u64_debug_capture import DebugCapture
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import (
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (
    DEBUG_MODE_6510, check_measurement_environment, get_debug_stream_mode,
    get_turbo_mhz, recover, runner_health_check,
    set_debug_stream_mode, set_reu, set_turbo_mhz,
    Ultimate64MeasurementEnvironmentError,
)

# Reuse helpers from the echo test.
from test_uci_udp_echo_live import (  # type: ignore[import-not-found]
    BOOT_TIMEOUT, CARRY, DEBUG_PORT, GO_FLAG, SENTINEL, SEND_BUF,
    STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_SEND, STEP_POLL,
    STEP_TIMEOUT, TRAMP, _payload, resolve_seed,
    _install_trampoline, _local_ip_for, _run_step, _safe, _wait_boot,
    log,
)

from uci.udp_size_responder import UDPSizeResponder, make_pattern  # type: ignore[import-not-found]

# The poison vocabulary is NOT redefined here. tools/test_warp_live.py
# already carries it, and it was adopted there from the firmware lane's
# tests/e2e/io/command_interface/net_target_test.py `pattern()`, so this
# probe, the WARP tool and the Ultimate's own test suite all read the same
# bytes the same way. A fourth private scheme would make three sets of
# hardware evidence incomparable. The one-sided-rename risk this import
# carries is exactly what tools/test_suite_imports.py watches for.
from test_warp_live import (  # type: ignore[import-not-found]
    POISON_SEED, _recv_buf_capacity, poison_pattern, poison_stop,
)

# --- the outbound kick payload ---------------------------------------------
# REPAIRED 2026-09-03 WITHOUT A HARDWARE RUN. Broken by f021458 (on master,
# shipped in PR #112), which moved tools/test_uci_udp_echo_live.py to seeded
# random payloads and deleted the TEST_PAYLOAD this file imported. The import
# is top-level, so this suite died at import — before argparse, before its
# first assertion — and stayed dead until tools/test_suite_imports.py found
# it. The repair below restores the payload from the echo suite's NEW seeded
# API and changes nothing else; it has been import-checked only. NEXT PERSON
# ON A U64E: verify this probe actually runs before trusting it. A green
# import is not a green run.
#
# Same alphabet as the old constant (REQUEST_BYTE_ALPHABET is range(0x40,
# 0x60); the old bytes were 0x40 + i % 32) and the same 32-byte length this
# file's docstring documents as fixed. 32 also keeps the payload inside
# SEND_BUF, which is under 64 bytes.
KICK_LEN = 32
KICK_SEED = resolve_seed()
TEST_PAYLOAD = _payload(KICK_LEN, KICK_SEED)
assert len(TEST_PAYLOAD) == KICK_LEN <= 64, "kick must fit in SEND_BUF"

# The REPLY alphabet must be DISJOINT from the request's. The kick uses
# REQUEST_BYTE_ALPHABET = range(0x40, 0x60) (see test_uci_udp_echo_live);
# a reply drawn from the full 0..255 range with a marker outside 0x40-0x5F
# means a loopback or an echoed request can never satisfy a reply check.
# Fixed text is a SUFFIX only, so it cannot be what an instrument keys on
# at offset 0.
# Lower-case deliberately: the request alphabet is 0x40-0x5F, so upper
# case would collide (this assertion caught exactly that on the first
# draft). Lower case is 0x61-0x7A and '-' is 0x2D, all outside it.
REPLY_MARKER = b"\x01uci-size-probe-reply-end\x01"
assert not (set(REPLY_MARKER) & set(range(0x40, 0x60))), (
    "reply marker shares bytes with the request alphabet")

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
# Sweep chosen to bracket every boundary this adapter cares about:
#   860  = WG_MTU, the send-bound tunnel MTU
#   892  = UCI_DATA_QUEUE_MAX, the largest single SOCKET_WRITE payload
#   893  = one over it (a split, historically silent)
#   1420 = a standard-MTU WireGuard datagram — exercises the fw 3.15
#          multi-block Data More receive path
#   1472 = UCI_READ_CHUNK_MAX, the largest datagram that reaches the device
#          at all (lwIP IP_REASSEMBLY = 0)
# Probe LARGE-FIRST on a freshly power-cycled unit: this device degrades after
# roughly five program loads, and sizes measured late in a session report that
# degradation as if it were firmware behaviour.
SIZES = [1472, 1420, 1000, 893, 892, 860, 600, 512, 32]
PER_SIZE_TIMEOUT = 3.0


def _required_labels() -> list[str]:
    return [
        "main_loop", "net_init", "net_dhcp_acquire", "net_udp_listen", "net_udp_send",
        "net_poll", "net_local_ip", "net_last_error", "mul_dma_hi",
        "wg_peer_ip", "wg_peer_port", "net_udp_dest_ip", "net_udp_dest_port", "wg_local_port",
        "udp_recv_ready", "udp_recv_len", "uci_read_hdr", "uci_status_buf", "uci_status_len", "uci_status_seen", "udp_recv_buf", "net_udp_send_len",
    ]


def _setup_peer(tr: Ultimate64Transport, L: dict, host_ip: str, port: int) -> None:
    octets = bytes(int(x) for x in host_ip.split("."))
    write_bytes(tr, L["wg_peer_ip"], octets)
    # wg_peer_port = BE (ip65 native + disk_config storage; uci/net.s swaps
    # on push). wg_local_port = LE (net_udp_listen stores A=lo,X=hi).
    write_bytes(tr, L["wg_peer_port"], bytes([port >> 8, port & 0xFF]))
    # §13.1: the backend reads net_udp_dest_*, NOT wg_peer_*.
    # In the app these are staged by session_stage_dest before each
    # send; a host-side driver calling net_udp_send directly is the
    # caller and must stage them itself.
    write_bytes(tr, L["net_udp_dest_ip"], octets)
    write_bytes(tr, L["net_udp_dest_port"], bytes([port >> 8, port & 0xFF]))
    write_bytes(tr, L["wg_local_port"], bytes([port & 0xFF, port >> 8]))
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    write_bytes(tr, L["net_udp_send_len"], bytes([len(TEST_PAYLOAD), 0]))
    log.info("peer set to %s:%d", host_ip, port)


def _payload_for(rng: random.Random, n: int, poison: bytes) -> bytes:
    """`n` reply bytes that differ from the poison at EVERY offset.

    Without this, the last written byte coincides with the poison with
    probability 1/251, `poison_stop`'s backward scan extends the surviving
    run by one, and the measured stop reads one below the truth. Here the
    stop is an EXACT assertion, so the coincidence is designed out rather
    than tolerated. (In the tunnel the reply is ciphertext and the same
    coincidence is real; there it is handled by
    classify_recv_buffer's tolerance in tools/test_warp_live.py.)

    The standing rule is that what crosses the wire is randomised and the
    seed is logged, with fixed markers only ever as a SUFFIX — a fixed
    leading pattern is exactly what an instrument can be gamed by.
    """
    out = bytearray(rng.randrange(256) for _ in range(n))
    if n >= len(REPLY_MARKER):
        out[n - len(REPLY_MARKER):] = REPLY_MARKER
    for i in range(n):
        while out[i] == poison[i]:
            out[i] = (out[i] + 1 + rng.randrange(255)) & 0xFF
    return bytes(out)


def _reset_recv_state(tr: Ultimate64Transport, L: dict, poison: bytes) -> None:
    """Zero the ready/len flags and POISON THE WHOLE receive buffer.

    The 64-byte `b"\xCC" * 64` guard region this replaced could not see
    #130 even in principle: that defect stops the copy at 893 bytes under
    an announced length of 1008 or more, which is past the end of the old
    fill and past both of the old read windows. The buffer is poisoned to
    its full structural capacity and the fill is VERIFIED BY READ-BACK, so
    "the poison did not stick" can never be mistaken for "the firmware
    wrote here".
    """
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    tr.write_memory(L["udp_recv_buf"], poison)
    back = bytes(tr.read_memory(L["udp_recv_buf"], len(poison)))
    if back != poison:
        first = next((i for i, (a, b) in enumerate(zip(back, poison))
                      if a != b), min(len(back), len(poison)))
        raise RuntimeError(
            f"poison fill did not stick: {len(poison)} bytes written to "
            f"udp_recv_buf ${L['udp_recv_buf']:04X}, read back differs "
            f"first at offset {first}. Every measurement in this trial "
            f"would be attributing the firmware's writes to a buffer whose "
            f"starting state is unknown.")


def _verify_pattern(buf: bytes, expected: bytes) -> tuple[bool, str]:
    """Does `buf` hold the bytes that actually crossed the wire?

    *expected* is the responder's `last_response` — what was SENT, not
    what the host meant to send. Comparing against the intent would make a
    responder bug indistinguishable from a firmware bug.

    Returns (ok, detail); the detail NAMES THE FIRST DIFFERING OFFSET,
    because "the content is wrong" and "the content is wrong starting at
    893" are different findings and only the second one identifies a
    response-block boundary.
    """
    n = len(expected)
    if len(buf) < n:
        return False, f"short read: got {len(buf)} need {n}"
    actual = buf[:n]
    if actual != expected:
        for i, (a, e) in enumerate(zip(actual, expected)):
            if a != e:
                return False, (f"mismatch at byte {i} of {n}: "
                               f"got ${a:02X} want ${e:02X}")
    return True, "OK"


def _probe_one_size(
    tr: Ultimate64Transport, L: dict, responder: UDPSizeResponder,
    size: int, listener_kick_ok: bool,
    rng: random.Random, poison: bytes,
) -> dict:
    reply = _payload_for(rng, size, poison)
    responder.response_size = size
    responder.response_payload = reply
    responder.last_response = None
    _reset_recv_state(tr, L, poison)
    # Arm the sticky status capture: zero the length so this iteration's
    # first status line is the one that sticks.
    write_bytes(tr, L["uci_status_len"], bytes([0]))
    write_bytes(tr, SEND_BUF, TEST_PAYLOAD)
    write_bytes(tr, L["net_udp_send_len"], bytes([len(TEST_PAYLOAD), 0]))

    # Kick the responder.
    requests_before = responder.responses_sent
    send_carry = _run_step(
        tr, step_id=STEP_SEND, target=L["net_udp_send"],
        reg_a=SEND_BUF & 0xFF, reg_x=SEND_BUF >> 8,
    )
    nle_after_send = tr.read_memory(L["net_last_error"], 1)[0]

    # Wait for the responder to actually send (so the firmware has data).
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if responder.responses_sent > requests_before:
            break
        time.sleep(0.02)
    sent_back = responder.responses_sent > requests_before

    # Poll up to PER_SIZE_TIMEOUT for udp_recv_ready.
    polls = 0
    deadline = time.monotonic() + PER_SIZE_TIMEOUT
    ready = 0
    while time.monotonic() < deadline:
        _run_step(tr, step_id=STEP_POLL, target=L["net_poll"], timeout=45.0)  # TEMP: 893 B reads are fence-bound at 1 MHz
        polls += 1
        ready = tr.read_memory(L["udp_recv_ready"], 1)[0]
        if ready:
            break
        time.sleep(0.02)

    # Raw SOCKET_READ response header, BEFORE the §13.3 validation consumes
    # it. Read unconditionally: the interesting case is an oversized datagram
    # where nothing was delivered, and gating on `ready` would miss exactly
    # that row. c64-lib-contract#139 records this value as unmeasured.
    hlo, hhi = tr.read_memory(L["uci_read_hdr"], 2)
    rx_hdr = hlo | (hhi << 8)

    # fw 3.15 reports "04,DATAGRAM TRUNCATED: <real length>" on the $DF1F
    # status line. uci_drain_status now captures it instead of discarding it.
    # uci_status_len is STICKY-FIRST (uci_cmd.s:655-657) and armed above, so it
    # is this iteration's FIRST line's length -- deliberate here. But the BUFFER
    # is rewritten from offset 0 on EVERY drain (@dst_idx zeroed at :593), so a
    # later line's bytes can sit under an earlier line's length. uci_status_seen
    # (:645, non-sticky) is the count for the drain whose bytes are actually in
    # the buffer. Record BOTH: a disagreement is the splice, and it is how a real
    # "04,DATAGRAM TRUNCATED: 1420" gets reported as a short, complete-looking
    # line. Same defect was shipped in test_warp_live.py and fixed there.
    n = tr.read_memory(L["uci_status_len"], 1)[0]
    n_seen = (tr.read_memory(L["uci_status_seen"], 1)[0]
              if "uci_status_seen" in L else None)
    # DIAGNOSTIC: read the whole buffer regardless of the length byte, so we
    # can tell "only one byte captured" from "buffer full, length wrong".
    raw = bytes(tr.read_memory(L["uci_status_buf"], 40))
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    status = (f"len={n} seen={n_seen} [{printable}]"
              + ("  SPLICE: sticky length disagrees with this drain's count"
                 if n_seen is not None and n_seen != n else ""))

    # Read the WHOLE buffer, ALWAYS — not a head window, not gated on
    # `ready`. The interesting cases are exactly the ones the old 16-head /
    # 16-tail windows could not see: a copy that stopped mid-buffer (#130
    # stops at 893 under an announced 1008+), and a datagram that was never
    # delivered but left bytes behind. Gating on `ready` would skip the
    # second one entirely.
    buf = bytes(tr.read_memory(L["udp_recv_buf"], len(poison)))
    stop = poison_stop(buf, poison)

    rx_len = 0
    if ready:
        lo, hi = tr.read_memory(L["udp_recv_len"], 2)
        rx_len = lo | (hi << 8)

    # What actually crossed the wire, not what we meant to send.
    on_wire = responder.last_response
    if on_wire is None:
        content_ok, content_detail = False, "responder never sent a reply"
    else:
        content_ok, content_detail = _verify_pattern(buf, on_wire)

    # Try a second poll to see if firmware has more (stream-style).
    second_ready = 0
    second_len = 0
    if ready:
        write_bytes(tr, L["udp_recv_ready"], bytes([0]))
        write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
        _run_step(tr, step_id=STEP_POLL, target=L["net_poll"], timeout=45.0)  # TEMP: 893 B reads are fence-bound at 1 MHz
        second_ready = tr.read_memory(L["udp_recv_ready"], 1)[0]
        if second_ready:
            lo, hi = tr.read_memory(L["udp_recv_len"], 2)
            second_len = lo | (hi << 8)

    nle_final = tr.read_memory(L["net_last_error"], 1)[0]
    return {
        "size": size,
        "rx_hdr": rx_hdr,
        "status": status,
        "send_carry": send_carry,
        "nle_after_send": nle_after_send,
        "sent_back": sent_back,
        "wire_len": len(on_wire) if on_wire is not None else -1,
        "polls": polls,
        "ready": int(ready),
        "rx_len": rx_len,
        "poison_stop": stop,
        "content_ok": content_ok,
        "content_detail": content_detail,
        "rx_first16": buf[:16].hex(),
        "rx_tail16": buf[max(0, stop - 16):stop].hex(),
        "second_ready": int(second_ready),
        "second_len": second_len,
        "nle_final": f"${nle_final:02X}",
    }


#: net_last_error codes that mean "this datagram was deliberately refused",
#: as opposed to delivered-but-wrong. A refusal is a legitimate outcome for
#: an oversized datagram and must not be scored as corruption; it is still
#: reported, and a refusal is only accepted when NOTHING was delivered.
REFUSAL_CODES = {0x88, 0x8A, 0x8F, 0x89}

#: One UCI response block. A `poison_stop` landing exactly here under a
#: larger announced length is #130's signature, and saying so in the failure
#: text is the difference between "wrong" and "wrong in the known way".
RESPONSE_BLOCK = 893


def score_results(results: list[dict]) -> list[str]:
    """The verdict. Pure function over the recorded rows; no device.

    THIS FUNCTION IS THE WHOLE POINT OF THE 2026-09-04 REPAIR. Before it,
    `main()` ended `_print_summary(results); return 0` and no return value
    anywhere depended on `results`, so every row printed and the process
    exited 0 whatever the firmware did. A probe whose verdict cannot reach
    an exit code is a data logger, and citing one as a control — which is
    what happened to #128 — attributes to measurement something that was
    never measured.

    Returns a list of human-readable failures; empty means clean. Rows are
    scored on FOUR independent questions, because collapsing them is how
    the #128 investigation lost two days:

      1. did the responder actually put bytes on the wire?  (no reply is a
         broken harness, not a firmware verdict, and must not be silent)
      2. was the datagram delivered at all?
      3. `poison_stop` — how far did the firmware WRITE?
      4. `_verify_pattern` — are those bytes the bytes that were sent?

    A short read is (3) < udp_recv_len with (4) clean on the prefix; a
    corruption is (3) == udp_recv_len with (4) dirty. Only the pair tells
    them apart.
    """
    failures: list[str] = []
    for r in results:
        size = r["size"]
        tag = f"size={size}"
        nle = r.get("nle_final", "$00")
        nle_val = int(nle.lstrip("$"), 16) if isinstance(nle, str) else nle

        # (1) The harness itself.
        if not r.get("sent_back"):
            failures.append(
                f"{tag}: the responder never sent a reply, so this row "
                f"measures the host, not the firmware. A trial that never "
                f"reached the wire is not evidence of anything.")
            continue
        if r.get("wire_len", -1) != size:
            failures.append(
                f"{tag}: responder put {r.get('wire_len')} bytes on the "
                f"wire, not {size} — the row is mislabelled at the source.")
            continue

        # (2) Delivered?
        if not r.get("ready"):
            if nle_val in REFUSAL_CODES and r.get("poison_stop", 0) == 0:
                # A clean refusal: nothing delivered AND nothing written.
                continue
            failures.append(
                f"{tag}: nothing delivered (udp_recv_ready=0) and this is "
                f"not a clean refusal — net_last_error={nle}, "
                f"poison_stop={r.get('poison_stop')}. Either the datagram "
                f"was dropped without an error code, or it was refused "
                f"AFTER writing {r.get('poison_stop')} bytes into the "
                f"buffer.")
            continue

        # (3) How far did it write?
        stop = r.get("poison_stop", 0)
        rx_len = r.get("rx_len", 0)
        if rx_len != size:
            failures.append(
                f"{tag}: delivered with udp_recv_len={rx_len}, but {size} "
                f"bytes were sent — the length the caller will trust does "
                f"not match the datagram.")
        if stop != rx_len:
            extra = ""
            if stop == RESPONSE_BLOCK and rx_len > RESPONSE_BLOCK:
                extra = (f" This is the #130 signature exactly: the copy "
                         f"stopped at one response block ({RESPONSE_BLOCK}) "
                         f"while udp_recv_len reported the announced total, "
                         f"so the caller reads {rx_len - stop} bytes of "
                         f"stale buffer as datagram content.")
            failures.append(
                f"{tag}: SHORT READ DELIVERED AS FULL LENGTH. The firmware "
                f"wrote {stop} bytes (poison survives from there on) but "
                f"udp_recv_ready is set with udp_recv_len={rx_len}."
                + extra)

        # (4) Are the bytes right?
        if not r.get("content_ok"):
            failures.append(
                f"{tag}: content does not match what was sent — "
                f"{r.get('content_detail')}"
                + ("" if stop != rx_len else
                   " The whole announced length WAS written, so this is "
                   "corruption, not truncation."))
    return failures


def _print_summary(results: list[dict]) -> None:
    print()
    print("=" * 110)
    print(f"{'requested':>9} {'wire':>6} {'rx_len':>7} {'stop':>6} {'hdr':>7} "
          f"{'polls':>6} {'sent':>5} {'ready':>5} {'2nd?':>5} {'2nd_len':>8} "
          f"{'nle':>4} {'content':>8}  status")
    print("-" * 110)
    for r in results:
        print(
            f"{r['size']:>9} {r.get('wire_len', -1):>6} {r['rx_len']:>7} "
            f"{r.get('poison_stop', -1):>6} {('$%04X' % r['rx_hdr']):>7} "
            f"{r['polls']:>6} {str(r['sent_back']):>5} "
            f"{r['ready']:>5} {r['second_ready']:>5} {r['second_len']:>8} "
            f"{r['nle_final']:>4} {('OK' if r.get('content_ok') else 'BAD'):>8}"
            f"  {r.get('status','')}"
        )
        if not r.get("content_ok"):
            print(f"{'':>9}   -> {r.get('content_detail','')}")
    print("=" * 110)


def self_check() -> int:
    """ALARM PROOF: fabricate rows and require `score_results` to flag them.

    The previous version of this file would have passed every hardware run
    ever put through it, because it had no assertion at all. That is not a
    thing you can find by reading a green log — you find it by breaking the
    subject on purpose and checking the alarm sounds. So this runs the REAL
    scorer over rows shaped exactly like the four outcomes that matter, and
    requires each to be reported.

    No device, no responder, no build. Milliseconds.
    """
    print("=== self-check: does the scorer fire? ===")
    rng = random.Random(0xC0FFEE)
    poison = poison_pattern(1500)
    ok_n = 1109
    reply = _payload_for(rng, ok_n, poison)

    def row(**kw) -> dict:
        base = dict(size=ok_n, wire_len=ok_n, sent_back=True, ready=1,
                    rx_len=ok_n, poison_stop=ok_n, content_ok=True,
                    content_detail="OK", nle_final="$00", rx_hdr=ok_n,
                    polls=1, second_ready=0, second_len=0, status="",
                    rx_first16="", rx_tail16="", send_carry=0,
                    nle_after_send=0)
        base.update(kw)
        return base

    # The CONTROL. A clean row must score clean, or every case below is
    # satisfied by a scorer that simply fails everything.
    clean = score_results([row()])
    if clean:
        print(f"FAIL control: a clean row was reported as {clean!r}. A "
              "scorer that fails everything discriminates nothing.")
        return 1
    print("  PASS  control: a clean, fully-delivered row scores clean")

    # The buffer the firmware would hold if the copy stopped at one block.
    truncated = bytearray(poison)
    truncated[:RESPONSE_BLOCK] = reply[:RESPONSE_BLOCK]
    got_stop = poison_stop(bytes(truncated), poison)
    if got_stop != RESPONSE_BLOCK:
        print(f"FAIL: poison_stop measured {got_stop} on a buffer written "
              f"to exactly {RESPONSE_BLOCK} — the measurement this file "
              f"rests on is wrong before any scoring happens.")
        return 1
    print(f"  PASS  poison_stop measures a {RESPONSE_BLOCK}-byte write "
          f"exactly")

    # One byte corrupted mid-buffer, everything else written.
    corrupt_at = 947
    corrupted = bytearray(reply)
    corrupted[corrupt_at] ^= 0xFF
    bad_content = _verify_pattern(bytes(corrupted), reply)

    cases = [
        ("nothing crossed the wire",
         row(sent_back=False), "never sent a reply"),
        ("delivered nothing, no error code",
         row(ready=0, rx_len=0, poison_stop=0, nle_final="$00"),
         "not a clean refusal"),
        ("delivered nothing but wrote 893 bytes first",
         row(ready=0, rx_len=0, poison_stop=RESPONSE_BLOCK,
             nle_final="$8F"),
         "AFTER writing 893"),
        ("#130: short read delivered as full length",
         row(poison_stop=RESPONSE_BLOCK), "#130 signature"),
        ("content corrupt at a known offset",
         row(content_ok=bad_content[0], content_detail=bad_content[1]),
         f"mismatch at byte {corrupt_at}"),
        ("responder sent a different length than the row claims",
         row(wire_len=ok_n - 1), "not "),
    ]
    failed = 0
    for name, r, want in cases:
        got = score_results([r])
        if not got:
            print(f"  FAIL  {name}: scorer reported NOTHING")
            failed += 1
        elif not any(want in g for g in got):
            print(f"  FAIL  {name}: reported {got!r}, which does not name "
                  f"{want!r}")
            failed += 1
        else:
            print(f"  PASS  {name}")

    # A clean REFUSAL is a legitimate outcome and must NOT be scored as a
    # failure, or the scorer cries wolf on every oversized datagram.
    refusal = score_results([row(ready=0, rx_len=0, poison_stop=0,
                                nle_final="$8A")])
    if refusal:
        print(f"  FAIL  a clean refusal ($8A, nothing written, nothing "
              f"delivered) was scored as {refusal!r} — this scorer would "
              f"cry wolf on every legitimately-rejected datagram")
        failed += 1
    else:
        print("  PASS  a clean refusal is reported, not failed")

    if failed:
        print(f"\n{failed} alarm(s) did not fire. Do not trust a run of "
              f"this tool until they do.")
        return 1
    print("\nThe scorer fires on every outcome it claims to detect, and "
          "stays quiet on the two that are legitimate.")
    return 0


def main() -> int:
    if "--self-check" in sys.argv:
        return self_check()
    # Standing directive: log the seed once, reproducible via TEST_SEED.
    print(f"kick payload: {KICK_LEN} B, seed {KICK_SEED} "
          f"(reproduce with TEST_SEED={KICK_SEED})", flush=True)
    host = os.environ.get("U64_HOST")
    if not host:
        print("SKIP: U64_HOST not set", file=sys.stderr); return 77
    if not os.environ.get("U64_ALLOW_MUTATE"):
        print("SKIP: U64_ALLOW_MUTATE not set", file=sys.stderr); return 77

    if not os.environ.get("C64_SKIP_BUILD"):
        import subprocess
        for cmd in (["make", "clean"], ["make", "BACKEND=uci"]):
            r = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True)
            if r.returncode != 0:
                sys.stderr.write(r.stderr.decode(errors="replace")); return 1

    labels = Labels.from_file(PROJECT_ROOT / "build" / "labels.txt")
    L = {n: labels[n] for n in _required_labels()}

    lock = DeviceLock(host)
    try:
        # 120s ceiling per c64-test skill — heartbeat extends deadline
        # for live progressing holders; only fires on wedged/dead.
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        log.error("DeviceLock acquire failed: host=%s holder_pid=%s "
                  "pid_alive=%s lockfile_age=%.1fs reachable_rest=%s",
                  e.device_host, e.holder_pid, e.pid_alive,
                  e.lockfile_age_seconds, e.device_reachable_rest)
        print(f"SKIP: {e}"); return 77

    # The lock is HELD from here, and until this change nothing between the
    # acquire and the main try/finally below released it: a raise in the
    # health check, in client.reboot() or in enable_uci leaked the lock, and
    # the next lane would queue behind a holder that no longer existed until
    # the heartbeat gave up on it.
    setup_ok = False
    try:
        # Reachability, INSIDE the lock. It is a REST read to the shared
        # device and used to run before the lock was held. Standing rule:
        # every access queues through the harness, reads included — an
        # unserialised read can observe another lane's half-applied config
        # rewrite and raise nothing.
        if not probe_u64(host).reachable:
            print(f"SKIP: {host} unreachable")
            return 77

        client = Ultimate64Client(host=host, timeout=10.0)
        tr = Ultimate64Transport(host=host, timeout=10.0, client=client)

        # Detect wedged-runner state before doing destructive work.
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner is wedged: %s — running recover()", exc)
            step = recover(client)
            log.info("recover() returned %r — re-checking runner", step)
            runner_health_check(client)

        log.info("rebooting U64 to clear UCI state...")
        client.reboot()
        time.sleep(10.0)
        if not get_uci_enabled(client):
            log.info("re-enabling UCI via REST")
            enable_uci(client); time.sleep(0.5)

        orig_mhz = _safe(get_turbo_mhz, client)
        orig_mode = _safe(get_debug_stream_mode, client) or ""
        local_ip = _local_ip_for(host)
        setup_ok = True
    finally:
        if not setup_ok:
            lock.release()

    cap = DebugCapture(port=DEBUG_PORT)
    responder = UDPSizeResponder(port=0)
    results: list[dict] = []
    try:
        responder.start()
        log.info("size responder bound on %s:%d", local_ip, responder.port)
        cap.start()
        set_debug_stream_mode(client, DEBUG_MODE_6510)
        set_turbo_mhz(client, 1)
        # Verify turbo stuck at 1 MHz (harness PR #106 footgun).
        try:
            check_measurement_environment(client)
        except Ultimate64MeasurementEnvironmentError as exc:
            print(f"SKIP: {exc}"); return 77
        _safe(set_reu, client, True, "512 KB")
        time.sleep(0.5)
        client.stream_debug_start(f"{local_ip}:{DEBUG_PORT}")

        prg = (PROJECT_ROOT / "build" / "wireguard.prg").read_bytes()
        client.run_prg(prg)
        log.info("PRG sent; waiting for boot...")
        _wait_boot(tr, L["mul_dma_hi"])
        _setup_peer(tr, L, local_ip, responder.port)
        _install_trampoline(tr, L["main_loop"])

        # Bring the WG net stack up and open the UCI socket via the first send.
        c = _run_step(tr, step_id=STEP_INIT, target=L["net_init"])
        if c != 0:
            log.error("net_init failed; aborting probe"); return 1
        _run_step(tr, step_id=STEP_DHCP, target=L["net_dhcp_acquire"])
        _run_step(tr, step_id=STEP_LISTEN, target=L["net_udp_listen"],
                  reg_a=responder.port & 0xFF, reg_x=responder.port >> 8)

        # The buffer's real capacity, read structurally from the labels
        # (udp_recv_len is the field immediately after udp_recv_buf) rather
        # than assumed to be 1500.
        cap = _recv_buf_capacity(L)
        poison = poison_pattern(cap)
        rng = random.Random(KICK_SEED)
        log.info("poison: %d bytes, P[i]=(i+$%02X)%%251, capacity read "
                 "structurally from labels", cap, POISON_SEED)
        for size in SIZES:
            if size > cap:
                log.warning("skipping size=%d: larger than the %d-byte "
                            "udp_recv_buf, so the poison cannot cover it "
                            "and poison_stop would be unmeasurable",
                            size, cap)
                continue
            log.info("--- probing size=%d ---", size)
            results.append(_probe_one_size(tr, L, responder, size, True,
                                           rng, poison))

    finally:
        try: client.stream_debug_stop()
        except Exception: pass
        time.sleep(0.3)
        result = cap.stop()
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = ARTIFACTS_DIR / f"uci_size_probe_{stamp}.txt"
        log.info("trace persisted to %s (cycles=%d)", path, result.total_cycles)
        with open(path, "w") as f:
            f.write(f"# packets={result.packets_received} dropped={result.packets_dropped} "
                    f"duration={result.duration_seconds:.3f} cycles={result.total_cycles}\n")
            for i, cyc in enumerate(result.trace):
                if not cyc.is_cpu: continue
                f.write(f"{i:08d} {cyc.address:04X} "
                        f"rw={'R' if cyc.is_read else 'W'} data={cyc.data:02X}\n")
        if orig_mhz is not None: _safe(set_turbo_mhz, client, orig_mhz)
        if orig_mode: _safe(set_debug_stream_mode, client, orig_mode)
        responder.stop(); responder.join(timeout=1.0)
        lock.release()

    _print_summary(results)

    if not results:
        print("\nFAIL: no size was probed at all. An empty run is not a "
              "clean run.")
        return 1
    failures = score_results(results)
    if failures:
        print(f"\nFAIL: {len(failures)} problem(s) across {len(results)} "
              f"size(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nPASS: all {len(results)} size(s) delivered the exact bytes "
          f"that crossed the wire, with poison_stop == udp_recv_len on "
          f"every one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
