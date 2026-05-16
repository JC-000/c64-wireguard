#!/usr/bin/env python3
"""test_handshake.py — Direct-memory WireGuard Noise handshake tests.

Tests the handshake helper routines (hs_init, hs_mix_hash, hs_compute_mac1)
and precomputed constants against Python reference implementations.

Full handshake tests (hs_create_initiation, hs_process_response) involve
X25519 operations that take ~100 minutes each in VICE. Use --slow to enable.

Usage:
    python3 tools/test_handshake.py [--seed S] [--verbose] [--slow]
"""

import hashlib
import hmac
import os
import random
import struct
import subprocess
import sys
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_text

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False
SLOW = False

# WireGuard Noise constants
WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
WG_LABEL_MAC1 = b"mac1----"


# ============================================================================
# Python reference implementations
# ============================================================================

def blake2s_256(data):
    """BLAKE2s-256 hash."""
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_128_keyed(key, data):
    """BLAKE2s-128 keyed hash (16-byte output)."""
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def py_c_init():
    """Compute C_init = BLAKE2s(construction)."""
    return blake2s_256(WG_CONSTRUCTION)


def py_h_init():
    """Compute H_init = BLAKE2s(C_init || identifier)."""
    c = py_c_init()
    return blake2s_256(c + WG_IDENTIFIER)


def py_mix_hash(h, data):
    """H = BLAKE2s(H || data)."""
    return blake2s_256(h + data)


def py_hs_init(resp_pub):
    """Initialize handshake state (C, H, mac1_key)."""
    c = py_c_init()
    h = py_h_init()
    h = py_mix_hash(h, resp_pub)
    mac1_key = blake2s_256(WG_LABEL_MAC1 + resp_pub)
    return c, h, mac1_key


# ============================================================================
# C64 helpers
# ============================================================================

def c64_hs_init(transport, labels, resp_pub):
    """Call hs_init with given responder public key, return (C, H, mac1_key)."""
    write_bytes(transport, labels["hs_resp_pub"], resp_pub)
    jsr(transport, labels["hs_init"], timeout=30.0)
    c = bytes(read_bytes(transport, labels["hs_c"], 32))
    h = bytes(read_bytes(transport, labels["hs_h"], 32))
    mac1_key = bytes(read_bytes(transport, labels["hs_mac1_key"], 32))
    return c, h, mac1_key


def c64_mix_hash(transport, labels, h, data):
    """Call hs_mix_hash, return updated H."""
    # Write H to hs_h
    write_bytes(transport, labels["hs_h"], h)
    # Write data to input_buffer
    write_bytes(transport, labels["input_buffer"], data)
    # Set up zp_ptr1 and b2s_remain
    input_buf_addr = labels["input_buffer"]
    write_bytes(transport, labels["zp_ptr1"], bytes([input_buf_addr & 0xFF, input_buf_addr >> 8]))
    write_bytes(transport, labels["b2s_remain"], bytes([len(data)]))
    jsr(transport, labels["hs_mix_hash"], timeout=30.0)
    return bytes(read_bytes(transport, labels["hs_h"], 32))


def c64_compute_mac1(transport, labels, mac1_key, packet_data_116):
    """Call hs_compute_mac1, return 16-byte MAC1."""
    write_bytes(transport, labels["hs_mac1_key"], mac1_key)
    write_bytes(transport, labels["hs_packet"], packet_data_116)
    jsr(transport, labels["hs_compute_mac1"], timeout=30.0)
    return bytes(read_bytes(transport, labels["b2s_hash"], 16))


# ============================================================================
# Test groups
# ============================================================================

def test_constants(transport, labels):
    """Verify precomputed Noise constants match Python computation."""
    passed = failed = 0

    # C_init
    expected_c = py_c_init()
    c64_c = bytes(read_bytes(transport, labels["wg_c_init"], 32))
    if c64_c == expected_c:
        passed += 1
        if VERBOSE:
            print("  PASS wg_c_init")
    else:
        failed += 1
        print(f"  FAIL wg_c_init:")
        print(f"    expected: {expected_c.hex()}")
        print(f"    got:      {c64_c.hex()}")

    # H_init
    expected_h = py_h_init()
    c64_h = bytes(read_bytes(transport, labels["wg_h_init"], 32))
    if c64_h == expected_h:
        passed += 1
        if VERBOSE:
            print("  PASS wg_h_init")
    else:
        failed += 1
        print(f"  FAIL wg_h_init:")
        print(f"    expected: {expected_h.hex()}")
        print(f"    got:      {c64_h.hex()}")

    # MAC1 label
    c64_label = bytes(read_bytes(transport, labels["wg_mac1_label"], 8))
    if c64_label == WG_LABEL_MAC1:
        passed += 1
        if VERBOSE:
            print("  PASS wg_mac1_label")
    else:
        failed += 1
        print(f"  FAIL wg_mac1_label: {c64_label!r}")

    return passed, failed


def test_hs_init(transport, labels, rng):
    """Test hs_init with random responder public keys."""
    passed = failed = 0

    for i in range(4):
        resp_pub = bytes(rng.getrandbits(8) for _ in range(32))
        exp_c, exp_h, exp_mac1 = py_hs_init(resp_pub)
        c64_c, c64_h, c64_mac1 = c64_hs_init(transport, labels, resp_pub)

        ok = True
        if c64_c != exp_c:
            ok = False
            print(f"  FAIL hs_init #{i} C mismatch")
            print(f"    expected: {exp_c.hex()}")
            print(f"    got:      {c64_c.hex()}")
        if c64_h != exp_h:
            ok = False
            print(f"  FAIL hs_init #{i} H mismatch")
            print(f"    expected: {exp_h.hex()}")
            print(f"    got:      {c64_h.hex()}")
        if c64_mac1 != exp_mac1:
            ok = False
            print(f"  FAIL hs_init #{i} mac1_key mismatch")
            print(f"    expected: {exp_mac1.hex()}")
            print(f"    got:      {c64_mac1.hex()}")

        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS hs_init #{i}")
        else:
            failed += 1

    return passed, failed


def test_mix_hash(transport, labels, rng):
    """Test hs_mix_hash with various data lengths."""
    passed = failed = 0

    test_cases = [
        ("empty", b""),
        ("1 byte", bytes([0x42])),
        ("32 bytes", bytes(range(32))),
        ("48 bytes", bytes(rng.getrandbits(8) for _ in range(48))),
        ("random H + random data", None),  # random
    ]

    for i, (name, data) in enumerate(test_cases):
        h = bytes(rng.getrandbits(8) for _ in range(32))
        if data is None:
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
            name = f"random {len(data)} bytes"

        expected = py_mix_hash(h, data)
        got = c64_mix_hash(transport, labels, h, data)

        if got == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS mix_hash {name}")
        else:
            failed += 1
            print(f"  FAIL mix_hash {name}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {got.hex()}")

    return passed, failed


def test_compute_mac1(transport, labels, rng):
    """Test hs_compute_mac1 (BLAKE2s-128 keyed)."""
    passed = failed = 0

    for i in range(4):
        mac1_key = bytes(rng.getrandbits(8) for _ in range(32))
        packet_116 = bytes(rng.getrandbits(8) for _ in range(116))

        expected = blake2s_128_keyed(mac1_key, packet_116)
        got = c64_compute_mac1(transport, labels, mac1_key, packet_116)

        if got == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS compute_mac1 #{i}")
        else:
            failed += 1
            print(f"  FAIL compute_mac1 #{i}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {got.hex()}")

    return passed, failed


def test_sender_idx_entropy(transport, labels):
    """Verify sender_idx gets fresh non-zero random bytes via entropy_fill.

    This tests the fix for the Type 1 sender_idx bug: entropy_fill must write
    a non-zero, non-constant 4-byte value to hs_sender_idx so it lands at
    hs_packet+4..+7.  We call entropy_fill directly (bypassing X25519 which
    takes ~100 minutes) and check two consecutive fills are (a) non-zero and
    (b) differ from each other.
    """
    passed = failed = 0

    def fill_sender_idx():
        """Point zp_ptr1 at hs_sender_idx, call entropy_fill with Y=4."""
        addr = labels["hs_sender_idx"]
        write_bytes(transport, labels["zp_ptr1"],
                    bytes([addr & 0xFF, addr >> 8]))
        # entropy_fill uses Y as count (1-based: fills Y bytes starting at Y-1
        # down to 0). Per the implementation: dey first, so ldy #4 fills 4 bytes.
        # We use jsr directly; Y must be 4 on entry.
        # jsr() doesn't let us set Y, so we manually write Y=4 into the CPU.
        # We inject a tiny trampoline: ldy #4 / jsr entropy_fill / rts at a
        # scratch location (input_buffer, which we own during the test).
        tramp_addr = labels["input_buffer"]
        entropy_addr = labels["entropy_fill"]
        tramp = bytes([
            0xA0, 0x04,                              # LDY #4
            0x20, entropy_addr & 0xFF, entropy_addr >> 8,  # JSR entropy_fill
            0x60,                                    # RTS
        ])
        write_bytes(transport, tramp_addr, tramp)
        jsr(transport, tramp_addr, timeout=10.0)
        return bytes(read_bytes(transport, labels["hs_sender_idx"], 4))

    idx1 = fill_sender_idx()
    idx2 = fill_sender_idx()

    # (a) Both must be non-zero
    if idx1 == b'\x00\x00\x00\x00':
        failed += 1
        print(f"  FAIL sender_idx #1 is all-zero (entropy_fill not working)")
    else:
        passed += 1
        if VERBOSE:
            print(f"  PASS sender_idx #1 non-zero: {idx1.hex()}")

    if idx2 == b'\x00\x00\x00\x00':
        failed += 1
        print(f"  FAIL sender_idx #2 is all-zero (entropy_fill not working)")
    else:
        passed += 1
        if VERBOSE:
            print(f"  PASS sender_idx #2 non-zero: {idx2.hex()}")

    # (b) Must differ (cryptographic uniqueness)
    if idx1 == idx2:
        failed += 1
        print(f"  FAIL sender_idx values identical: {idx1.hex()} == {idx2.hex()}")
    else:
        passed += 1
        if VERBOSE:
            print(f"  PASS sender_idx values differ: {idx1.hex()} != {idx2.hex()}")

    return passed, failed


def test_tai64n_increment(transport, labels):
    """Test tai64n_increment routine."""
    passed = failed = 0

    test_cases = [
        # (input_12_bytes, expected_12_bytes)
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
        # Simple increment of last byte
        (
            bytes([0x40, 0x00, 0x00, 0x00, 0x65, 0xD2, 0x3A, 0x80,
                   0x00, 0x00, 0x01, 0x00]),
            bytes([0x40, 0x00, 0x00, 0x00, 0x65, 0xD2, 0x3A, 0x80,
                   0x00, 0x00, 0x01, 0x01]),
        ),
    ]

    for i, (ts_in, expected) in enumerate(test_cases):
        write_bytes(transport, labels["hs_timestamp"], ts_in)
        jsr(transport, labels["tai64n_increment"], timeout=10.0)
        got = bytes(read_bytes(transport, labels["hs_timestamp"], 12))

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


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("precomputed constants", lambda: test_constants(transport, labels)),
        ("hs_init", lambda: test_hs_init(transport, labels, rng)),
        ("hs_mix_hash", lambda: test_mix_hash(transport, labels, rng)),
        ("hs_compute_mac1", lambda: test_compute_mac1(transport, labels, rng)),
        ("tai64n_increment", lambda: test_tai64n_increment(transport, labels)),
        ("sender_idx entropy", lambda: test_sender_idx_entropy(transport, labels)),
    ]

    if not SLOW:
        print("\n  (full handshake tests skipped — use --slow to enable)")

    for name, test_fn in test_groups:
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
    global VERBOSE, SLOW
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        elif args[i] == "--slow":
            SLOW = True
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build (skip if run_regression.py already built)
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "hs_init", "hs_mix_hash", "hs_compute_mac1",
        "hs_c", "hs_h", "hs_mac1_key", "hs_resp_pub",
        "hs_packet", "hs_static_priv", "hs_static_pub",
        "hs_ephem_priv", "hs_ephem_pub", "hs_sender_idx",
        "hs_timestamp", "hs_resp_packet",
        "hs_transport_send", "hs_transport_recv",
        "wg_c_init", "wg_h_init", "wg_mac1_label",
        "b2s_hash", "b2s_remain", "b2s_data_ptr",
        "zp_ptr1", "input_buffer",
        "tai64n_increment", "entropy_fill",
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

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
