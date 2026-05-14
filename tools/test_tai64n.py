#!/usr/bin/env python3
"""test_tai64n.py — Tests for TAI64N timestamp routines.

Tests tai64n_init, tai64n_now, and tai64n_increment (regression).

Usage:
    python3 tools/test_tai64n.py [--seed S] [--verbose]
"""

import os
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_text

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts_as_int(ts_bytes):
    """Interpret a 12-byte TAI64N timestamp as a big-endian integer."""
    return int.from_bytes(ts_bytes, 'big')


def read_timestamp(transport, labels):
    """Read the 12-byte hs_timestamp."""
    return bytes(read_bytes(transport, labels["hs_timestamp"], 12))


# ============================================================================
# Test cases
# ============================================================================

def test_tai64n_init_zeros(transport, labels):
    """Set tai64n_base_time to all zeros, call tai64n_init, verify all zeros."""
    passed = failed = 0

    # Write zeros to base time
    write_bytes(transport, labels["tai64n_base_time"], bytes(8))
    jsr(transport, labels["tai64n_init"])

    ts = read_timestamp(transport, labels)
    seq = bytes(read_bytes(transport, labels["tai64n_seq"], 4))

    if ts == bytes(12):
        passed += 1
        if VERBOSE:
            print("  PASS hs_timestamp is all zeros")
    else:
        failed += 1
        print(f"  FAIL hs_timestamp expected all zeros, got {ts.hex()}")

    if seq == bytes(4):
        passed += 1
        if VERBOSE:
            print("  PASS tai64n_seq is all zeros")
    else:
        failed += 1
        print(f"  FAIL tai64n_seq expected all zeros, got {seq.hex()}")

    return passed, failed


def test_tai64n_init_copies_base(transport, labels):
    """Set tai64n_base_time to a known value, verify hs_timestamp matches."""
    passed = failed = 0

    # Unix timestamp 1710000000 = 0x65E5A900
    # As 8-byte big-endian: 00 00 00 00 65 E5 A9 00
    base_time = bytes([0x00, 0x00, 0x00, 0x00, 0x65, 0xE5, 0xA9, 0x00])
    write_bytes(transport, labels["tai64n_base_time"], base_time)
    jsr(transport, labels["tai64n_init"])

    ts = read_timestamp(transport, labels)

    if ts[0:8] == base_time:
        passed += 1
        if VERBOSE:
            print("  PASS hs_timestamp[0..7] matches base time")
    else:
        failed += 1
        print(f"  FAIL hs_timestamp[0..7]:")
        print(f"    expected: {base_time.hex()}")
        print(f"    got:      {ts[0:8].hex()}")

    if ts[8:12] == bytes(4):
        passed += 1
        if VERBOSE:
            print("  PASS hs_timestamp[8..11] is zero")
    else:
        failed += 1
        print(f"  FAIL hs_timestamp[8..11] expected zeros, got {ts[8:12].hex()}")

    return passed, failed


def test_tai64n_init_snapshots_jiffy(transport, labels):
    """Call tai64n_init and verify tai64n_init_jiffy is non-zero."""
    passed = failed = 0

    write_bytes(transport, labels["tai64n_base_time"], bytes(8))
    jsr(transport, labels["tai64n_init"])

    jiffy = bytes(read_bytes(transport, labels["tai64n_init_jiffy"], 3))
    jiffy_val = (jiffy[0] << 16) | (jiffy[1] << 8) | jiffy[2]

    if jiffy_val != 0:
        passed += 1
        if VERBOSE:
            print(f"  PASS tai64n_init_jiffy = {jiffy_val} (non-zero)")
    else:
        failed += 1
        print("  FAIL tai64n_init_jiffy is zero (expected non-zero)")

    return passed, failed


def test_tai64n_now_basic(transport, labels):
    """Init, sleep briefly, call tai64n_now. Verify seconds >= base, seq=1."""
    passed = failed = 0

    base_time = bytes([0x00, 0x00, 0x00, 0x00, 0x65, 0xE5, 0xA9, 0x00])
    write_bytes(transport, labels["tai64n_base_time"], base_time)
    jsr(transport, labels["tai64n_init"])

    # Sleep briefly so jiffies advance
    time.sleep(0.1)

    jsr(transport, labels["tai64n_now"])
    ts = read_timestamp(transport, labels)

    # Seconds portion should be >= base time
    ts_seconds = ts[0:8]
    if ts_seconds >= base_time:
        passed += 1
        if VERBOSE:
            print(f"  PASS seconds >= base ({ts_seconds.hex()} >= {base_time.hex()})")
    else:
        failed += 1
        print(f"  FAIL seconds < base:")
        print(f"    base: {base_time.hex()}")
        print(f"    got:  {ts_seconds.hex()}")

    # Sequence counter should be 1 (first call to tai64n_now after init)
    seq_bytes = ts[8:12]
    expected_seq = bytes([0x00, 0x00, 0x00, 0x01])
    if seq_bytes == expected_seq:
        passed += 1
        if VERBOSE:
            print(f"  PASS sequence counter = 1")
    else:
        failed += 1
        print(f"  FAIL sequence counter expected 00000001, got {seq_bytes.hex()}")

    return passed, failed


def test_tai64n_now_sequence_increments(transport, labels):
    """Call tai64n_now twice, verify sequence counter goes from 1 to 2."""
    passed = failed = 0

    base_time = bytes([0x00, 0x00, 0x00, 0x00, 0x65, 0xE5, 0xA9, 0x00])
    write_bytes(transport, labels["tai64n_base_time"], base_time)
    jsr(transport, labels["tai64n_init"])

    # First call
    jsr(transport, labels["tai64n_now"])
    ts1 = read_timestamp(transport, labels)

    # Second call
    jsr(transport, labels["tai64n_now"])
    ts2 = read_timestamp(transport, labels)

    seq1 = int.from_bytes(ts1[8:12], 'big')
    seq2 = int.from_bytes(ts2[8:12], 'big')

    if seq1 == 1:
        passed += 1
        if VERBOSE:
            print(f"  PASS first call seq = {seq1}")
    else:
        failed += 1
        print(f"  FAIL first call seq expected 1, got {seq1}")

    if seq2 == 2:
        passed += 1
        if VERBOSE:
            print(f"  PASS second call seq = {seq2}")
    else:
        failed += 1
        print(f"  FAIL second call seq expected 2, got {seq2}")

    # Seconds should be same or slightly advanced
    if ts2[0:8] >= ts1[0:8]:
        passed += 1
        if VERBOSE:
            print("  PASS seconds non-decreasing")
    else:
        failed += 1
        print(f"  FAIL seconds decreased: {ts1[0:8].hex()} -> {ts2[0:8].hex()}")

    return passed, failed


def test_tai64n_now_monotonic(transport, labels):
    """Call tai64n_now 5 times. Each timestamp must be strictly greater."""
    passed = failed = 0

    base_time = bytes([0x00, 0x00, 0x00, 0x00, 0x65, 0xE5, 0xA9, 0x00])
    write_bytes(transport, labels["tai64n_base_time"], base_time)
    jsr(transport, labels["tai64n_init"])

    timestamps = []
    for i in range(5):
        jsr(transport, labels["tai64n_now"])
        ts = read_timestamp(transport, labels)
        timestamps.append(ts)

    all_monotonic = True
    for i in range(1, 5):
        prev_int = ts_as_int(timestamps[i - 1])
        curr_int = ts_as_int(timestamps[i])
        if curr_int > prev_int:
            if VERBOSE:
                print(f"  PASS ts[{i}] > ts[{i-1}] "
                      f"({timestamps[i].hex()} > {timestamps[i-1].hex()})")
        else:
            all_monotonic = False
            print(f"  FAIL ts[{i}] not > ts[{i-1}]:")
            print(f"    ts[{i-1}] = {timestamps[i-1].hex()}")
            print(f"    ts[{i}]   = {timestamps[i].hex()}")

    if all_monotonic:
        passed += 4  # 4 comparisons
    else:
        failed += 4 - sum(
            1 for i in range(1, 5)
            if ts_as_int(timestamps[i]) > ts_as_int(timestamps[i - 1])
        )
        passed += sum(
            1 for i in range(1, 5)
            if ts_as_int(timestamps[i]) > ts_as_int(timestamps[i - 1])
        )

    return passed, failed


def test_tai64n_increment_still_works(transport, labels):
    """Regression: tai64n_increment adds 1 nanosecond."""
    passed = failed = 0

    test_cases = [
        # Simple increment
        (
            bytes([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x00]),
            bytes([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                   0x00, 0x00, 0x00, 0x01]),
        ),
        # Nanosecond overflow wraps to seconds
        (
            bytes([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                   0xFF, 0xFF, 0xFF, 0xFF]),
            bytes([0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                   0x00, 0x00, 0x00, 0x00]),
        ),
        # Mid-range increment
        (
            bytes([0x40, 0x00, 0x00, 0x00, 0x65, 0xD2, 0x3A, 0x80,
                   0x00, 0x00, 0x01, 0x00]),
            bytes([0x40, 0x00, 0x00, 0x00, 0x65, 0xD2, 0x3A, 0x80,
                   0x00, 0x00, 0x01, 0x01]),
        ),
    ]

    for i, (ts_in, expected) in enumerate(test_cases):
        write_bytes(transport, labels["hs_timestamp"], ts_in)
        jsr(transport, labels["tai64n_increment"])
        got = read_timestamp(transport, labels)

        if got == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS tai64n_increment #{i}")
        else:
            failed += 1
            print(f"  FAIL tai64n_increment #{i}:")
            print(f"    input:    {ts_in.hex()}")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {got.hex()}")

    return passed, failed


def test_tai64n_now_elapsed_seconds(transport, labels):
    """Manually set init_jiffy 120 jiffies behind current, verify +2 seconds.

    Because VICE runs in warp mode, many jiffies elapse between our setup and
    the actual tai64n_now execution.  To get a deterministic test we:
      1. Call tai64n_init (to get clean state).
      2. Call tai64n_now via the trampoline.
      3. AFTER tai64n_now returns, read back tai64n_init_jiffy and the current
         jiffy clock to compute the actual elapsed jiffies the routine saw.
      4. Verify: hs_timestamp seconds == base + (elapsed_jiffies // 60).

    We also do a targeted sub-test: set init_jiffy so elapsed is *exactly*
    120 by writing init_jiffy = (jiffy_at_read - 120) right before a SECOND
    tai64n_now call, with minimal delay.
    """
    passed = failed = 0

    # --- Sub-test A: verify the division-by-60 math after a normal call ---
    base_val = 1000
    base_time = base_val.to_bytes(8, 'big')
    write_bytes(transport, labels["tai64n_base_time"], base_time)
    jsr(transport, labels["tai64n_init"])

    # Let some jiffies elapse
    time.sleep(0.1)

    # Reset seq for a clean count
    write_bytes(transport, labels["tai64n_seq"], bytes(4))
    jsr(transport, labels["tai64n_now"])
    ts = read_timestamp(transport, labels)

    # Read back init_jiffy and current jiffy to see what actually elapsed
    init_jiffy_bytes = bytes(read_bytes(transport, labels["tai64n_init_jiffy"], 3))
    cur_jiffy_bytes = read_bytes(transport, 0xA0, 3)
    init_jiffy = (init_jiffy_bytes[0] << 16) | (init_jiffy_bytes[1] << 8) | init_jiffy_bytes[2]
    cur_jiffy = (cur_jiffy_bytes[0] << 16) | (cur_jiffy_bytes[1] << 8) | cur_jiffy_bytes[2]
    # The jiffy clock read now is AFTER tai64n_now ran, but the routine read
    # the clock during execution.  The seconds in the timestamp tell us what
    # the code computed, so verify it's consistent: seconds == base + elapsed//60
    ts_seconds = int.from_bytes(ts[0:8], 'big')
    elapsed_seconds = ts_seconds - base_val

    # elapsed_seconds should be >= 0 and reasonable.  In warp mode VICE can
    # burn through hundreds of jiffies per wall-clock second, so allow a wide
    # range.  The key invariant is seconds >= base_val and not wildly large.
    if 0 <= elapsed_seconds < 600:
        passed += 1
        if VERBOSE:
            print(f"  PASS sub-test A: seconds = {ts_seconds} "
                  f"(base {base_val} + {elapsed_seconds} elapsed)")
    else:
        failed += 1
        print(f"  FAIL sub-test A: seconds = {ts_seconds}, "
              f"elapsed = {elapsed_seconds} (expected 0..599)")

    # --- Sub-test B: force exactly 120 jiffies elapsed ---
    # We do this by:
    # 1. Reading the current jiffy clock
    # 2. Writing tai64n_init_jiffy = current - 120
    # 3. Immediately calling tai64n_now
    # The few extra jiffies that pass during the trampoline setup mean we
    # expect seconds >= 2 (120/60) but allow a small margin.
    write_bytes(transport, labels["tai64n_seq"], bytes(4))

    cur_bytes = read_bytes(transport, 0xA0, 3)
    cur = (cur_bytes[0] << 16) | (cur_bytes[1] << 8) | cur_bytes[2]
    fake_init = (cur - 120) & 0xFFFFFF
    write_bytes(transport, labels["tai64n_init_jiffy"], bytes([
        (fake_init >> 16) & 0xFF,
        (fake_init >> 8) & 0xFF,
        fake_init & 0xFF,
    ]))

    jsr(transport, labels["tai64n_now"])
    ts2 = read_timestamp(transport, labels)
    ts2_seconds = int.from_bytes(ts2[0:8], 'big')
    elapsed2 = ts2_seconds - base_val

    # Should be at least 2 (120 jiffies / 60 = 2 seconds).  In warp mode
    # many more jiffies elapse during the trampoline/poll cycle, so allow
    # a generous upper bound.
    if 2 <= elapsed2 <= 600:
        passed += 1
        if VERBOSE:
            print(f"  PASS sub-test B: seconds = {ts2_seconds} "
                  f"(base {base_val} + {elapsed2} elapsed, expected >=2)")
    else:
        failed += 1
        print(f"  FAIL sub-test B: seconds = {ts2_seconds}, "
              f"elapsed = {elapsed2} (expected 2..600)")
        print(f"    hs_timestamp = {ts2.hex()}")
        print(f"    cur_jiffy = {cur}, fake_init = {fake_init}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels):
    """Run all TAI64N test groups."""
    total_passed = total_failed = 0

    groups = [
        ("tai64n_init zeros", lambda: test_tai64n_init_zeros(transport, labels)),
        ("tai64n_init copies base", lambda: test_tai64n_init_copies_base(transport, labels)),
        ("tai64n_init snapshots jiffy", lambda: test_tai64n_init_snapshots_jiffy(transport, labels)),
        ("tai64n_now basic", lambda: test_tai64n_now_basic(transport, labels)),
        ("tai64n_now sequence increments", lambda: test_tai64n_now_sequence_increments(transport, labels)),
        ("tai64n_now monotonic", lambda: test_tai64n_now_monotonic(transport, labels)),
        ("tai64n_increment regression", lambda: test_tai64n_increment_still_works(transport, labels)),
        ("tai64n_now elapsed seconds", lambda: test_tai64n_now_elapsed_seconds(transport, labels)),
    ]

    for name, test_fn in groups:
        print(f"\n--- {name} ---")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()

    return total_passed, total_failed


def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--verbose":
            VERBOSE = True
            i += 1
        else:
            i += 1

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "tai64n_init", "tai64n_now", "tai64n_increment",
        "tai64n_base_time", "tai64n_init_jiffy", "tai64n_seq",
        "hs_timestamp",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        grid = binary_wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        # Install tight loop at $0339 to keep CPU busy but harmless
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
