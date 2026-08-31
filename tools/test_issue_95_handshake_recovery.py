#!/usr/bin/env python3
"""test_issue_95_handshake_recovery.py — gate suite for PR #91's two recovery
behaviours.

WHY THIS EXISTS
---------------
The severity of issue #95 was downgraded (from "permanent handshake poisoning,
no retry, no timeout, human intervention required") to "one bounded, recoverable
handshake attempt is aborted".  That downgrade rests ENTIRELY on two behaviours
PR #91 introduced, and until this file nothing in the gate asserted either:

  1. the 90 s handshake deadline — src/wg/timer.s:70-71 (HS_TIMEOUT_JIFFIES)
     and timer_check_handshake at src/wg/timer.s:304-327, reached from
     timer_check's HS_SENT arm at :124-137.  Also boot.s:186-201, which no
     longer pre-filters timer_check on wg_state == ACTIVE.
  2. @hs_fail calling `jsr session_reset` — src/wg/session.s:279-290.

Revert either and #95 silently returns to its filed severity: HS_SENT becomes
absorbing again, and the hs_c/hs_h corruption that hs_process_response leaves
behind (handshake.s:733/754/793/832/857, all before aead_decrypt at :910) stops
being latent and becomes reachable.  timer.s is precisely the file the automatic
retry that #84, #95 and #106 all want would touch.

So this suite asserts the BEHAVIOURS, not the bug.  It must fail if #91 is
reverted; that is demonstrated in the PR description with measured numbers.

D1/D1c/D1n  the deadline fires, does not fire early, and does not fire unarmed
D2/D2n      the real main loop reclaims HS_SENT (covers the boot.s gate too)
D3/D3n      a rejected Type 2 lands in IDLE with the deadline disarmed
D3s/D3sn    --slow: same as D3 without the scalarmult stub

Every positive assertion is paired with a control that strips its precondition,
because an assertion that cannot fail is not an assertion.

Usage:
    python3 tools/test_issue_95_handshake_recovery.py [--slow] [--verbose]
"""

import os
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
    goto, set_breakpoint, delete_breakpoint, wait_for_pc,
)
from c64_test_harness.transport import TimeoutError as HarnessTimeout
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

IDLE_LOOP = 0x0339
PARK = bytes([0x4C, 0x39, 0x03])          # jmp $0339

SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2

# src/wg/timer.s:70-71 — HS_TIMEOUT_JIFFIES = 5400 (90 s at 60 Hz).
HS_TIMEOUT_JIFFIES = 5400
PAST_DEADLINE = 6000                      # 100 s
INSIDE_DEADLINE = 600                     # 10 s

VERBOSE = False
LABELS = None


class Results:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail):
        self.rows.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    def note(self, name, detail):
        print(f"  [info] {name}: {detail}")

    def summary(self):
        bad = [r for r in self.rows if not r[1]]
        print("\n" + "=" * 72)
        print(f"{len(self.rows) - len(bad)}/{len(self.rows)} assertions passed")
        if bad:
            print("\nFAILED:")
            for n, _, d in bad:
                print(f"  {n}: {d}")
        print("=" * 72)
        return len(bad)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def read_jiffies(t):
    """C64 jiffy clock: $A0 = hi, $A1 = mid, $A2 = lo."""
    hi, mid, lo = read_bytes(t, 0x00A0, 3)
    return (hi << 16) | (mid << 8) | lo


def jiffies_bytes(v):
    v &= 0xFFFFFF
    return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def arm_hs_sent(t, labels, age_jiffies, armed=1):
    """Put the machine in HS_SENT with an initiation `age_jiffies` old."""
    write_bytes(t, labels["wg_state"], bytes([SESSION_HS_SENT]))
    write_bytes(t, labels["hs_timer_armed"], bytes([armed]))
    write_bytes(t, labels["session_start_jiffy"],
                jiffies_bytes(read_jiffies(t) - age_jiffies))


def state_of(t, labels):
    return (read_bytes(t, labels["wg_state"], 1)[0],
            read_bytes(t, labels["hs_timer_armed"], 1)[0])


# ---------------------------------------------------------------------------
# D1 — timer_check reclaims an over-deadline HS_SENT
# ---------------------------------------------------------------------------

def d1_deadline(t, labels, res):
    arm_hs_sent(t, labels, PAST_DEADLINE)
    jsr(t, labels["timer_check"], timeout=60.0)
    state, armed = state_of(t, labels)
    res.check(
        "D1 deadline fires past 90 s",
        state == SESSION_IDLE and armed == 0,
        f"age {PAST_DEADLINE} jiffies (>{HS_TIMEOUT_JIFFIES}): "
        f"wg_state {SESSION_HS_SENT} -> {state}, hs_timer_armed 1 -> {armed}",
    )

    # Control: inside the deadline nothing may happen.  Without this, D1 would
    # also pass against a timer_check that tore down HS_SENT unconditionally.
    arm_hs_sent(t, labels, INSIDE_DEADLINE)
    jsr(t, labels["timer_check"], timeout=60.0)
    state, armed = state_of(t, labels)
    res.check(
        "D1c control: inside the deadline HS_SENT survives",
        state == SESSION_HS_SENT and armed == 1,
        f"age {INSIDE_DEADLINE} jiffies: wg_state = {state} (want "
        f"{SESSION_HS_SENT}), hs_timer_armed = {armed} (want 1)",
    )

    # Control: precondition stripped.  hs_timer_armed = 0 means "no initiation
    # this build actually sent" (timer.s:296-300), so the deadline must not
    # fire even though the timestamp is ancient.
    arm_hs_sent(t, labels, PAST_DEADLINE, armed=0)
    jsr(t, labels["timer_check"], timeout=60.0)
    state, armed = state_of(t, labels)
    res.check(
        "D1n control: unarmed deadline does not fire",
        state == SESSION_HS_SENT,
        f"age {PAST_DEADLINE} jiffies but hs_timer_armed=0: "
        f"wg_state = {state} (want {SESSION_HS_SENT})",
    )


# ---------------------------------------------------------------------------
# D2 — the REAL main loop reclaims it (covers boot.s' removed outer gate)
# ---------------------------------------------------------------------------

def _reached(t, addr, timeout):
    """Resume into boot.s' main_loop and report whether the CPU reaches `addr`.

    Breakpoints, not sleeps: VICE's binary monitor HALTS emulation between
    commands, so time.sleep() advances the C64 by nothing and a polling version
    of this check reports "did not happen" for a machine that was never running.
    goto() sets PC and resumes; wait_for_pc blocks on the monitor's stopped
    event.  The CPU is left paused on a hit, still running on a miss.
    """
    bp = set_breakpoint(t, addr)
    try:
        goto(t, LABELS["main_loop"])
        try:
            wait_for_pc(t, addr, timeout=timeout)
            return True
        except (HarnessTimeout, TimeoutError):
            return False
    finally:
        delete_breakpoint(t, bp)


def d2_main_loop(t, labels, res):
    """D1 proves timer_check HANDLES HS_SENT.  It does not prove anything CALLS
    it in that state — before #91 boot.s gated the call on wg_state == ACTIVE,
    and that outer gate was the binding one (boot.s:194-201).  Re-adding it
    would leave D1 green while the deadline never fired in production.
    """
    # D2a — the loop reaches timer_check's HS_SENT arm at all.  Inside the
    # deadline, so nothing fires; this isolates "is it called" from "does it
    # fire".  timer_check_handshake is only reachable via that arm.
    arm_hs_sent(t, labels, INSIDE_DEADLINE)
    hit = _reached(t, labels["timer_check_handshake"], 10.0)
    res.check(
        "D2a boot.s main_loop reaches timer_check's HS_SENT arm",
        hit,
        "timer_check_handshake "
        + ("reached" if hit else "NEVER reached")
        + " while wg_state=HS_SENT — this is the boot.s outer gate #91 removed",
    )

    # D2 — end to end: an expired, armed initiation is reclaimed by the real
    # loop, reaching session_reset.
    arm_hs_sent(t, labels, PAST_DEADLINE)
    hit = _reached(t, labels["session_reset"], 10.0)
    res.check(
        "D2 main loop reclaims an over-deadline HS_SENT",
        hit,
        "session_reset " + ("reached" if hit else "NEVER reached")
        + f" from main_loop with an initiation {PAST_DEADLINE} jiffies old",
    )

    # D2n control — precondition stripped: unarmed, so session_reset must NOT
    # be reached even though the timestamp is equally ancient.  Distinguishes
    # "correctly did nothing" from "was never running", because D2a already
    # proved the loop runs and reaches the HS_SENT arm.
    arm_hs_sent(t, labels, PAST_DEADLINE, armed=0)
    hit = _reached(t, labels["session_reset"], 3.0)
    state = read_bytes(t, labels["wg_state"], 1)[0]
    res.check(
        "D2n control: unarmed HS_SENT is not reclaimed by the loop",
        (not hit) and state == SESSION_HS_SENT,
        f"session_reset reached = {hit} (want False), wg_state = {state} "
        f"(want {SESSION_HS_SENT})",
    )


# ---------------------------------------------------------------------------
# D3 — a rejected Type 2 lands in IDLE with the deadline disarmed
# ---------------------------------------------------------------------------

def forged_type2(receiver_index=b'\x99\x99\x99\x99'):
    """92 bytes of attacker-chosen material.  Nothing on this path is
    authenticated before hs_process_response mutates hs_c/hs_h, so the AEAD at
    handshake.s:910 is what rejects it."""
    p = bytearray(92)
    p[0] = 2
    p[4:8] = b'\xDE\xAD\xBE\xEF'                      # responder sender_index
    p[8:12] = receiver_index                          # never compared to ours
    p[12:44] = bytes([(i * 3 + 5) & 0xFF for i in range(32)])   # ephemeral
    p[44:60] = b'\xFF' * 16                           # bogus AEAD tag
    return bytes(p)


def deliver_type2(t, labels, pkt, timeout):
    write_bytes(t, labels["udp_recv_buf"], pkt)
    write_bytes(t, labels["udp_recv_len"], struct.pack('<H', len(pkt)))
    write_bytes(t, labels["udp_recv_ready"], bytes([1]))
    jsr(t, labels["session_handle_packet"], timeout=timeout)


def d3_hs_fail(t, labels, res, stub=True):
    """hs_process_response does 2 X25519 scalarmults (handshake.s:769, 808)
    BEFORE the AEAD that rejects the packet, which is what made this assertion
    slow.  The scalarmults are irrelevant to what is under test here: the packet
    is forged, so the AEAD rejects it whatever the DH produced, and the control
    flow through @hs_fail is identical.  Stubbing them to RTS keeps this in the
    fast group.  D3s re-runs it unstubbed under --slow to show the stub does not
    change the outcome.
    """
    tag = "D3" if stub else "D3s"
    saved = None
    if stub:
        saved = bytes(read_bytes(t, labels["x25519_scalarmult"], 1))
        write_bytes(t, labels["x25519_scalarmult"], b'\x60')      # RTS

    try:
        c_before = bytes(read_bytes(t, labels["hs_c"], 32))
        arm_hs_sent(t, labels, INSIDE_DEADLINE)   # inside the deadline, so the
                                                  # timer cannot be what resets
        before, _ = state_of(t, labels)
        deliver_type2(t, labels, forged_type2(), 60.0 if stub else 25000.0)
        state, armed = state_of(t, labels)
        c_after = bytes(read_bytes(t, labels["hs_c"], 32))

        res.check(
            f"{tag} rejected Type 2 lands in IDLE, deadline disarmed",
            before == SESSION_HS_SENT and state == SESSION_IDLE and armed == 0,
            f"wg_state {before} -> {state} (want {SESSION_IDLE}), "
            f"hs_timer_armed -> {armed} (want 0), well inside the 90 s deadline",
        )
        res.note(
            f"{tag} hs_c after the rejected Type 2",
            f"{c_before[:8].hex()} -> {c_after[:8].hex()} "
            f"(changed={c_after != c_before}) — the #95 chain corruption is "
            f"still present; it is LATENT only because of the reset above",
        )

        # Control: precondition stripped.  A Type 2 arriving outside HS_SENT
        # must be dropped by the state gate at session.s:245-249 and change
        # nothing — so D3's transition really came from @hs_fail.
        write_bytes(t, labels["wg_state"], bytes([SESSION_ACTIVE]))
        write_bytes(t, labels["hs_timer_armed"], bytes([0]))
        deliver_type2(t, labels, forged_type2(), 60.0 if stub else 25000.0)
        state, _ = state_of(t, labels)
        res.check(
            f"{tag}n control: Type 2 outside HS_SENT is ignored",
            state == SESSION_ACTIVE,
            f"wg_state = {state} (want {SESSION_ACTIVE}, i.e. untouched)",
        )
    finally:
        if saved is not None:
            write_bytes(t, labels["x25519_scalarmult"], saved)


# ---------------------------------------------------------------------------

REQUIRED = [
    "wg_state", "hs_timer_armed", "session_start_jiffy", "hs_c",
    "timer_check", "timer_check_handshake", "session_reset",
    "session_handle_packet", "main_loop", "x25519_scalarmult",
    "udp_recv_buf", "udp_recv_len", "udp_recv_ready",
]


def main():
    global VERBOSE
    args = sys.argv[1:]
    VERBOSE = "--verbose" in args
    slow = "--slow" in args

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        r = subprocess.run(["make"], capture_output=True, text=True,
                           cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
            sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing from {LABELS_PATH}: {missing}")
        sys.exit(1)

    global LABELS
    LABELS = labels

    res = Results()
    # The REU cartridge costs nothing here — the fast group runs zero X25519
    # scalarmults and X25519 is the only REU consumer — but a REU=1 build with
    # no cartridge computes garbage, so attach it rather than depend on which
    # profile happened to be built.
    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                     extra_args=["-reu", "-reusize", "512"])
    t0 = time.time()
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid} port={inst.port}")
        t = inst.transport
        if binary_wait_for_boot_ready(t, labels, timeout=300.0) is None:
            print("FATAL: boot_ready never set")
            sys.exit(1)
        write_bytes(t, IDLE_LOOP, PARK)
        if "reu_mul_init" in labels:
            jsr(t, labels["reu_mul_init"], timeout=180.0)
        print("VICE ready.\n")

        print("--- D1: the 90 s handshake deadline (timer.s:304-327) ---")
        d1_deadline(t, labels, res)
        print()
        print("--- D3: @hs_fail -> session_reset (session.s:286) ---")
        d3_hs_fail(t, labels, res, stub=True)
        print()
        if slow:
            print("--- D3s: same, unstubbed (2x X25519) ---")
            d3_hs_fail(t, labels, res, stub=False)
            print()
        # D2 LAST: it releases the CPU into main_loop, which never returns, so
        # the takeover park cannot be restored afterwards.
        print("--- D2: boot.s main_loop drives it (boot.s:186-201) ---")
        d2_main_loop(t, labels, res)
        print()

        mgr.release(inst)

    print(f"wall clock: {time.time() - t0:.1f} s")
    sys.exit(1 if res.summary() else 0)


if __name__ == "__main__":
    main()
