#!/usr/bin/env python3
"""test_tai64n_monotonic.py — issue #87: the Type-1 TAI64N timestamp must be
strictly increasing across initiations.

WireGuard's responder drops an initiation whose 12-byte TAI64N timestamp is
<= the greatest it has already accepted from that peer. On the unfixed tree
every initiation carries `tai64n_base_time || 00000001`: config_load (run at
the top of every session_initiate) calls tai64n_init, which resets
hs_timestamp to the base, and tai64n_increment then bumps it to nanos=1.
Against a conformant peer the first handshake succeeds and every rekey after
it is silently dropped.

What is exercised is the REAL initiation path — session_initiate, which runs
config_load, entropy_fill, the timestamp step and hs_create_initiation — with
three routines stubbed over DMA so a call takes seconds instead of ~hours
under VICE warp:

    x25519_base, x25519_scalarmult   RTS      (3 scalarmults per Type-1; the
                                              DH output is irrelevant to the
                                              timestamp)
    net_udp_send                     CLC/RTS  (VICE has no UCI and this
                                              backend has no ethernet here;
                                              carry clear = "sent", so
                                              session_initiate reaches
                                              SESSION_HS_SENT, which is
                                              asserted as a precondition)

Everything else is the shipped code. The timestamp is read back from
hs_timestamp[0..11] over DMA and compared as a 96-bit big-endian INTEGER.

Cases (each on a freshly staged config with a random base time):
    A  two initiations, jiffy clock untouched      -> strictly increasing;
                                                     seconds == base (+drift)
    B  jiffy clock advanced by a random delta      -> seconds advanced by
       between the two calls ($A0-$A2 written        delta//60 (+drift), still
       directly)                                     strictly increasing
    C  100 consecutive initiations                 -> every step strictly
       (C2: tai64n_seq staged 16 below 10^9)         increasing
    D  config_load between two initiations, SAME   -> must NOT reset: second
       base time (the exact #87 mechanism)           still strictly greater
    E  config_load with a NEW, LARGER base time    -> may jump forward, never
                                                     backward
    E2 config_load with a NEW, SMALLER base time   -> never backward

RED on master e4af731: A, B, C, C2, D, E2.  E passes on the unfixed tree
because the forward jump dominates; its strictness check is the same
comparison E2 makes, and E2 is red, so the check is proven to alarm.

Usage:
    python3 tools/test_tai64n_monotonic.py [--seed S] [--verbose] [--count N]
"""

import os
import random
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
CALL_TIMEOUT = 300.0        # one stubbed session_initiate under warp: seconds

SESSION_HS_SENT = 1
JIFFY = 0xA0                # KERNAL jiffy clock, $A0 hi / $A1 mid / $A2 lo
IDLE_LOOP = 0x0339
PARK = bytes([0x4C, 0x39, 0x03])          # JMP $0339

TAI64_EPOCH = 0x4000000000000000          # TAI64 label for 1970-01-01

REQUIRED = [
    "session_initiate", "config_load", "hs_create_initiation",
    "tai64n_init", "tai64n_now", "tai64n_increment",
    "tai64n_base_time", "tai64n_init_jiffy", "tai64n_seq", "hs_timestamp",
    "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
    "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port", "cfg_preshared_key",
    "x25519_base", "x25519_scalarmult", "net_udp_send", "wg_state",
]


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail):
        self.rows.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    def note(self, name, detail):
        if VERBOSE:
            print(f"  [info] {name}: {detail}")

    def summary(self):
        bad = [r for r in self.rows if not r[1]]
        print("\n" + "=" * 72)
        print(f"Results: {len(self.rows) - len(bad)}/{len(self.rows)} passed, "
              f"{len(bad)} failed")
        if bad:
            print("\nFAILED:")
            for n, _, d in bad:
                print(f"  {n}: {d}")
        print("=" * 72)
        return len(bad)


# ---------------------------------------------------------------------------
# Timestamp helpers — integers, never strings
# ---------------------------------------------------------------------------

def ts_int(ts):
    return int.from_bytes(ts, "big")


def ts_secs(ts):
    return int.from_bytes(ts[0:8], "big")


def ts_nanos(ts):
    return int.from_bytes(ts[8:12], "big")


def fmt(ts):
    return f"{ts[0:8].hex()}|{ts[8:12].hex()} (secs={ts_secs(ts)}, nanos={ts_nanos(ts)})"


def read_ts(t, L):
    return bytes(read_bytes(t, L["hs_timestamp"], 12))


def read_jiffy(t):
    b = bytes(read_bytes(t, JIFFY, 3))
    return (b[0] << 16) | (b[1] << 8) | b[2]


def write_jiffy(t, v):
    v &= 0xFFFFFF
    write_bytes(t, JIFFY, bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]))


# ---------------------------------------------------------------------------
# Staging
# ---------------------------------------------------------------------------

class BaseTimes:
    """Random base times that only ever grow across cases.

    Each case stages its own config. A fix that remembers the greatest
    timestamp it ever emitted must not be tripped by a LATER case staging an
    EARLIER base, so the sequence is strictly increasing by at least two hours
    (case B advances the jiffy clock by up to an hour, and that advance sticks).
    """

    def __init__(self, rng):
        self.rng = rng
        self.cur = TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000)

    def next(self):
        self.cur += self.rng.randrange(7200, 86400)
        return self.cur


def install_stubs(t, L):
    saved = {}
    for name, stub in (("x25519_base", b"\x60"),
                       ("x25519_scalarmult", b"\x60"),
                       ("net_udp_send", b"\x18\x60")):      # CLC; RTS
        saved[name] = bytes(read_bytes(t, L[name], len(stub)))
        write_bytes(t, L[name], stub)
    return saved


def restore_stubs(t, L, saved):
    for name, orig in saved.items():
        write_bytes(t, L[name], orig)


def stage_config(t, L, rng, base_secs):
    """Write a random peer config plus the base time and anchor the epoch,
    which is what a disk config load does before the first initiation."""
    rb = lambda n: bytes(rng.randrange(256) for _ in range(n))
    write_bytes(t, L["cfg_static_priv"], rb(32))
    write_bytes(t, L["cfg_static_pub"], rb(32))
    write_bytes(t, L["cfg_peer_pub"], rb(32))
    write_bytes(t, L["cfg_peer_endpoint_ip"], rb(4))
    write_bytes(t, L["cfg_peer_endpoint_port"], rb(2))
    write_bytes(t, L["cfg_preshared_key"], rb(32))
    write_bytes(t, L["tai64n_base_time"], base_secs.to_bytes(8, "big"))
    jsr(t, L["tai64n_init"], timeout=30.0)


def initiate(t, L, res, tag):
    """Run session_initiate (stubbed) and return (timestamp, jiffies consumed).

    wg_state must land on HS_SENT: that is the proof the stubbed path ran to
    the send and back, rather than bailing out somewhere before the timestamp.
    """
    write_bytes(t, L["wg_state"], bytes([0]))
    j0 = read_jiffy(t)
    t0 = time.monotonic()
    jsr(t, L["session_initiate"], timeout=CALL_TIMEOUT)
    dt = time.monotonic() - t0
    j1 = read_jiffy(t)
    state = read_bytes(t, L["wg_state"], 1)[0]
    if state != SESSION_HS_SENT:
        res.check(f"{tag} precondition: stubbed session_initiate reached HS_SENT",
                  False, f"wg_state={state} (want {SESSION_HS_SENT})")
    ts = read_ts(t, L)
    drift = (j1 - j0) & 0xFFFFFF
    res.note(f"{tag} initiate", f"{fmt(ts)} in {dt:.1f}s, jiffies {j0}->{j1} (+{drift})")
    return ts, drift


def drift_secs(drift):
    """Upper bound on seconds the jiffy clock could have contributed."""
    return drift // 60 + 1


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def case_a(t, L, rng, bases, res):
    base = bases.next()
    stage_config(t, L, rng, base)
    ts1, d1 = initiate(t, L, res, "A#1")
    ts2, d2 = initiate(t, L, res, "A#2")
    res.check("A: second initiation strictly greater than the first (96-bit int)",
              ts_int(ts2) > ts_int(ts1),
              f"ts1={fmt(ts1)} ts2={fmt(ts2)}")
    for tag, ts, d in (("ts1", ts1, d1), ("ts2", ts2, d1 + d2)):
        lo, hi = base, base + drift_secs(d)
        res.check(f"A: {tag} seconds == staged base (+<= {hi - base} s drift)",
                  lo <= ts_secs(ts) <= hi,
                  f"secs={ts_secs(ts)} base={base} allowed [{lo}, {hi}]")


def case_b(t, L, rng, bases, res):
    base = bases.next()
    stage_config(t, L, rng, base)
    ts1, d1 = initiate(t, L, res, "B#1")
    delta = rng.randrange(60, 60 * 3600)            # 1 s .. 1 h of jiffies
    j = read_jiffy(t)
    if j + delta >= 0xFFFFFF:
        delta = rng.randrange(60, 0xFFFFFF - j - 1)
    write_jiffy(t, j + delta)
    got = read_jiffy(t)
    res.check("B: jiffy clock advanced by delta (read-back)",
              got == j + delta, f"wrote {j}+{delta}={j + delta}, read {got}")
    ts2, d2 = initiate(t, L, res, "B#2")
    adv = ts_secs(ts2) - ts_secs(ts1)
    lo, hi = delta // 60, (delta + d1 + d2) // 60 + 1
    res.check(f"B: seconds advanced by delta//60 = {delta // 60} (allowed [{lo}, {hi}])",
              lo <= adv <= hi,
              f"advanced by {adv}; ts1={fmt(ts1)} ts2={fmt(ts2)}")
    res.check("B: still strictly increasing (96-bit int)",
              ts_int(ts2) > ts_int(ts1),
              f"ts1={fmt(ts1)} ts2={fmt(ts2)}")


def run_chain(t, L, res, tag, count):
    prev = None
    first_bad = None
    bad = 0
    for i in range(count):
        ts, _ = initiate(t, L, res, f"{tag}#{i}")
        if prev is not None and ts_int(ts) <= ts_int(prev):
            bad += 1
            if first_bad is None:
                first_bad = (i, prev, ts)
        prev = ts
    if first_bad is None:
        detail = f"{count} initiations, all strictly increasing; last={fmt(prev)}"
    else:
        i, p, c = first_bad
        detail = (f"{bad} of {count - 1} steps NOT increasing; first at #{i}: "
                  f"ts[{i - 1}]={fmt(p)} ts[{i}]={fmt(c)}")
    res.check(f"{tag}: {count} consecutive initiations strictly increasing", bad == 0, detail)
    return prev


def case_c(t, L, rng, bases, res, count):
    base = bases.next()
    stage_config(t, L, rng, base)
    run_chain(t, L, res, "C", count)
    # C2: the sub-second counter staged 16 below 10^9, so the chain crosses
    # the nanosecond rollover. Only strictness is asserted — wireguard-go
    # compares the 12 bytes as one big-endian value and never range-checks
    # the nanos — but a design that carries into seconds is exercised here.
    base = bases.next()
    stage_config(t, L, rng, base)
    write_bytes(t, L["tai64n_seq"], (999_999_984).to_bytes(4, "big"))
    last = run_chain(t, L, res, "C2", min(count, 40))
    res.note("C2 nanos after the chain",
             f"{ts_nanos(last)} ({'>' if ts_nanos(last) > 999_999_999 else '<='} 10^9-1)")


def case_d_e(t, L, rng, bases, res):
    base = bases.next()
    stage_config(t, L, rng, base)
    ts1, _ = initiate(t, L, res, "D#1")

    # D — the #87 mechanism itself: config_load with the SAME base time.
    jsr(t, L["config_load"], timeout=30.0)
    mid = read_ts(t, L)
    res.note("D hs_timestamp right after config_load", fmt(mid))
    ts2, _ = initiate(t, L, res, "D#2")
    res.check("D: config_load (same base) between initiations does not reset — "
              "second still strictly greater",
              ts_int(ts2) > ts_int(ts1),
              f"ts1={fmt(ts1)} after-config_load={fmt(mid)} ts2={fmt(ts2)}")

    # E — NEW, LARGER base time: may jump forward, never backward.
    base_up = base + rng.randrange(7200, 86400)
    write_bytes(t, L["tai64n_base_time"], base_up.to_bytes(8, "big"))
    jsr(t, L["config_load"], timeout=30.0)
    ts3, _ = initiate(t, L, res, "E#1")
    res.check("E: config_load with a LARGER base — strictly greater (forward jump allowed)",
              ts_int(ts3) > ts_int(ts2),
              f"base {base}->{base_up}; ts2={fmt(ts2)} ts3={fmt(ts3)} "
              f"jumped={'yes' if ts_secs(ts3) >= base_up else 'no'}")

    # E2 — NEW, SMALLER base time: never backward.
    base_down = base - rng.randrange(7200, 86400)
    write_bytes(t, L["tai64n_base_time"], base_down.to_bytes(8, "big"))
    jsr(t, L["config_load"], timeout=30.0)
    ts4, _ = initiate(t, L, res, "E2#1")
    res.check("E2: config_load with a SMALLER base — never backward (strictly greater)",
              ts_int(ts4) > ts_int(ts3),
              f"base {base_up}->{base_down}; ts3={fmt(ts3)} ts4={fmt(ts4)}")


# ---------------------------------------------------------------------------

def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)
    args = sys.argv[1:]
    VERBOSE = "--verbose" in args
    seed = int(os.environ.get("TEST_SEED", random.randrange(2 ** 31)))
    count = 100
    for i, a in enumerate(args):
        if a == "--seed":
            seed = int(args[i + 1])
        elif a == "--count":
            count = int(args[i + 1])
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed}); chain length {count}")

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        r = subprocess.run(["make"], capture_output=True, text=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
            sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing from {LABELS_PATH}: {missing}")
        sys.exit(1)

    res = Results()
    bases = BaseTimes(rng)
    # REU attached for the same reason test_issue_95 does: the scalarmults are
    # stubbed so it costs nothing, but a REU=1 build with no cartridge is not
    # the tree that was built.
    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                     extra_args=["-reu", "-reusize", "512"])
    t0 = time.time()
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        t = inst.transport
        if binary_wait_for_boot_ready(t, labels, timeout=300.0) is None:
            print("FATAL: boot_ready never set")
            sys.exit(1)
        write_bytes(t, IDLE_LOOP, PARK)
        saved = install_stubs(t, labels)
        print("VICE ready; x25519_base/x25519_scalarmult -> RTS, net_udp_send -> CLC/RTS\n")

        print("--- A: two initiations, jiffy clock untouched ---")
        case_a(t, labels, rng, bases, res)
        print("\n--- B: jiffy clock advanced between initiations ---")
        case_b(t, labels, rng, bases, res)
        print(f"\n--- C: {count} consecutive initiations (+ C2 across the nanos rollover) ---")
        case_c(t, labels, rng, bases, res, count)
        print("\n--- D/E/E2: config_load between initiations ---")
        case_d_e(t, labels, rng, bases, res)

        restore_stubs(t, labels, saved)
        mgr.release(inst)

    print(f"\nwall clock: {time.time() - t0:.1f} s  (seed {seed})")
    sys.exit(1 if res.summary() else 0)


if __name__ == "__main__":
    main()
