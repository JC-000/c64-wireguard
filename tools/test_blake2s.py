#!/usr/bin/env python3
"""test_blake2s.py — Direct-memory BLAKE2s, HMAC, and KDF tests.

Tests BLAKE2s-256 (unkeyed + keyed), HMAC-BLAKE2s, and WireGuard KDF
against Python reference implementations via jsr() calls.

Usage:
    python3 tools/test_blake2s.py [--seed S] [--verbose]
"""

import hashlib
import hmac as hmac_mod
import json
import os
import random
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceProcess, ViceTransport,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc7693_vectors.json")

VERBOSE = False


def robust_jsr(transport, addr, timeout=10.0, retries=3):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.3)
                continue
            raise


def blake2s_ref(data, key=b"", digest_size=32):
    """Python reference BLAKE2s."""
    return hashlib.blake2s(data, key=key, digest_size=digest_size).digest()


def hmac_blake2s_ref(key, data):
    """Python reference HMAC-BLAKE2s-256."""
    return hmac_mod.new(
        key, data, lambda: hashlib.blake2s(digest_size=32)
    ).digest()


# ============================================================================
# C64 helper functions
# ============================================================================

def c64_blake2s_init(transport, labels, out_len=32, key=b""):
    """Call blake2s_init on C64. If keyed, writes key to input_buffer first."""
    if key:
        write_bytes(transport, labels["input_buffer"], key)
    # Set parameters in memory (blake2s_init reads from b2s_out_len/b2s_key_len)
    write_bytes(transport, labels["b2s_out_len"], bytes([out_len]))
    write_bytes(transport, labels["b2s_key_len"], bytes([len(key)]))
    robust_jsr(transport, labels["blake2s_init"], timeout=10.0)


def c64_blake2s_update(transport, labels, data):
    """Call blake2s_update on C64 with given data."""
    if len(data) == 0:
        return
    buf_addr = labels["input_buffer"]
    write_bytes(transport, buf_addr, data)
    # Set b2s_data_ptr and b2s_remain
    write_bytes(transport, labels["b2s_data_ptr"],
                bytes([buf_addr & 0xFF, buf_addr >> 8]))
    write_bytes(transport, labels["b2s_remain"], bytes([len(data)]))
    robust_jsr(transport, labels["blake2s_update"], timeout=30.0)


def c64_blake2s_final(transport, labels):
    """Call blake2s_final and return the hash."""
    robust_jsr(transport, labels["blake2s_final"], timeout=30.0)
    return read_bytes(transport, labels["b2s_hash"], 32)


def c64_blake2s_hash(transport, labels, data, key=b""):
    """Full BLAKE2s hash on C64: init, update, final."""
    c64_blake2s_init(transport, labels, out_len=32, key=key)
    c64_blake2s_update(transport, labels, data)
    return c64_blake2s_final(transport, labels)


def c64_hmac_blake2s(transport, labels, key, data):
    """Call hmac_blake2s on C64."""
    # Write key to a temp area and set hmac_key_ptr/len
    key_addr = labels["input_buffer"]
    write_bytes(transport, key_addr, key)
    write_bytes(transport, labels["hmac_key_ptr"],
                bytes([key_addr & 0xFF, key_addr >> 8]))
    write_bytes(transport, labels["hmac_key_len"], bytes([len(key)]))

    # Write data after key in input_buffer
    data_addr = key_addr + len(key)
    if data:
        write_bytes(transport, data_addr, data)
    write_bytes(transport, labels["hmac_data_ptr"],
                bytes([data_addr & 0xFF, data_addr >> 8]))
    write_bytes(transport, labels["hmac_data_len"], bytes([len(data)]))

    robust_jsr(transport, labels["hmac_blake2s"], timeout=60.0)
    return read_bytes(transport, labels["b2s_hash"], 32)


def c64_kdf(transport, labels, chaining_key, input_data, outputs=1):
    """Call kdf_1/2/3 on C64."""
    # Write chaining key to kdf_prk
    write_bytes(transport, labels["kdf_prk"], chaining_key)

    # Write input data
    inp_addr = labels["input_buffer"]
    if input_data:
        write_bytes(transport, inp_addr, input_data)
    write_bytes(transport, labels["kdf_input_ptr"],
                bytes([inp_addr & 0xFF, inp_addr >> 8]))
    write_bytes(transport, labels["kdf_input_len"], bytes([len(input_data)]))

    # Call appropriate KDF function
    if outputs == 1:
        func = labels["kdf_1"]
    elif outputs == 2:
        func = labels["kdf_2"]
    else:
        func = labels["kdf_3"]

    robust_jsr(transport, func, timeout=120.0)

    result = [read_bytes(transport, labels["kdf_out1"], 32)]
    if outputs >= 2:
        result.append(read_bytes(transport, labels["kdf_out2"], 32))
    if outputs >= 3:
        result.append(read_bytes(transport, labels["kdf_out3"], 32))
    return result


# ============================================================================
# Test functions
# ============================================================================

def test_word32_add(transport, labels):
    """Test 32-bit addition."""
    passed = failed = 0

    test_cases = [
        (0x00000001, 0x00000002, 0x00000003, "simple add"),
        (0xFFFFFFFF, 0x00000001, 0x00000000, "overflow wrap"),
        (0x12345678, 0x9ABCDEF0, 0xACF13568, "large add"),
        (0x00000000, 0x00000000, 0x00000000, "zero + zero"),
        (0x80000000, 0x80000000, 0x00000000, "MSB overflow"),
    ]

    for a_val, b_val, expected, desc in test_cases:
        # Write operands to b2s_tmp0 and b2s_tmp1
        a_bytes = a_val.to_bytes(4, "little")
        b_bytes = b_val.to_bytes(4, "little")
        write_bytes(transport, labels["b2s_tmp0"], a_bytes)
        write_bytes(transport, labels["b2s_tmp1"], b_bytes)

        # Set up pointers: src1=b2s_tmp0, src2=b2s_tmp1, dst=b2s_tmp0
        write_bytes(transport, labels["w32_src1"],
                    bytes([labels["b2s_tmp0"] & 0xFF, labels["b2s_tmp0"] >> 8]))
        write_bytes(transport, labels["w32_src2"],
                    bytes([labels["b2s_tmp1"] & 0xFF, labels["b2s_tmp1"] >> 8]))
        write_bytes(transport, labels["w32_dst"],
                    bytes([labels["b2s_tmp0"] & 0xFF, labels["b2s_tmp0"] >> 8]))

        robust_jsr(transport, labels["add32"])
        result = read_bytes(transport, labels["b2s_tmp0"], 4)
        result_val = int.from_bytes(result, "little")

        if result_val == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS add32: {desc}")
        else:
            failed += 1
            print(f"  FAIL add32 {desc}: 0x{a_val:08X} + 0x{b_val:08X} = "
                  f"0x{result_val:08X}, expected 0x{expected:08X}")

    return passed, failed


def test_word32_xor(transport, labels):
    """Test 32-bit XOR."""
    passed = failed = 0

    test_cases = [
        (0xAAAAAAAA, 0x55555555, 0xFFFFFFFF, "alternating bits"),
        (0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, "self-XOR"),
        (0x12345678, 0x00000000, 0x12345678, "XOR with zero"),
    ]

    for a_val, b_val, expected, desc in test_cases:
        a_bytes = a_val.to_bytes(4, "little")
        b_bytes = b_val.to_bytes(4, "little")
        write_bytes(transport, labels["b2s_tmp0"], a_bytes)
        write_bytes(transport, labels["b2s_tmp1"], b_bytes)

        write_bytes(transport, labels["w32_src1"],
                    bytes([labels["b2s_tmp0"] & 0xFF, labels["b2s_tmp0"] >> 8]))
        write_bytes(transport, labels["w32_src2"],
                    bytes([labels["b2s_tmp1"] & 0xFF, labels["b2s_tmp1"] >> 8]))
        write_bytes(transport, labels["w32_dst"],
                    bytes([labels["b2s_tmp0"] & 0xFF, labels["b2s_tmp0"] >> 8]))

        robust_jsr(transport, labels["xor32"])
        result = read_bytes(transport, labels["b2s_tmp0"], 4)
        result_val = int.from_bytes(result, "little")

        if result_val == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS xor32: {desc}")
        else:
            failed += 1
            print(f"  FAIL xor32 {desc}: 0x{result_val:08X}, expected 0x{expected:08X}")

    return passed, failed


def test_word32_rotations(transport, labels):
    """Test 32-bit rotations: rotr 7, 8, 12, 16."""
    passed = failed = 0

    def rotr32(val, n):
        return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

    test_values = [0x12345678, 0x80000001, 0xDEADBEEF, 0x00000001, 0xFFFFFFFF]
    rotations = [
        (7, "rotr32_7"),
        (8, "rotr32_8"),
        (12, "rotr32_12"),
        (16, "rotr32_16"),
    ]

    for val in test_values:
        for rot_amount, rot_label in rotations:
            expected = rotr32(val, rot_amount)
            val_bytes = val.to_bytes(4, "little")
            write_bytes(transport, labels["b2s_tmp0"], val_bytes)
            write_bytes(transport, labels["w32_dst"],
                        bytes([labels["b2s_tmp0"] & 0xFF, labels["b2s_tmp0"] >> 8]))

            robust_jsr(transport, labels[rot_label])
            result = read_bytes(transport, labels["b2s_tmp0"], 4)
            result_val = int.from_bytes(result, "little")

            if result_val == expected:
                passed += 1
                if VERBOSE:
                    print(f"  PASS {rot_label}: 0x{val:08X} >>> {rot_amount} = 0x{expected:08X}")
            else:
                failed += 1
                print(f"  FAIL {rot_label}: 0x{val:08X} >>> {rot_amount} = "
                      f"0x{result_val:08X}, expected 0x{expected:08X}")

    return passed, failed


def test_blake2s_unkeyed(transport, labels):
    """Test BLAKE2s-256 unkeyed hash against known vectors."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["blake2s_256_unkeyed"]:
        data = bytes.fromhex(vec["input"])
        expected = bytes.fromhex(vec["hash"])

        result = c64_blake2s_hash(transport, labels, data)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS unkeyed: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL unkeyed {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_blake2s_keyed(transport, labels):
    """Test BLAKE2s-256 keyed hash against official KAT vectors."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["blake2s_256_keyed"]:
        key = bytes.fromhex(vec["key"])
        data = bytes.fromhex(vec["input"])
        expected = bytes.fromhex(vec["hash"])

        result = c64_blake2s_hash(transport, labels, data, key=key)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS keyed: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL keyed {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_blake2s_random(transport, labels, rng, count=5):
    """Test BLAKE2s with random inputs against Python reference."""
    passed = failed = 0

    for i in range(count):
        length = rng.randint(1, 63)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        expected = blake2s_ref(data)

        result = c64_blake2s_hash(transport, labels, data)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS random unkeyed #{i}: {length} bytes")
        else:
            failed += 1
            print(f"  FAIL random unkeyed #{i} ({length} bytes, data={data.hex()}):")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_blake2s_boundary(transport, labels):
    """Test BLAKE2s at block boundary sizes: 1, 55, 56, 63, 64, 65, 128."""
    passed = failed = 0

    for length in [1, 55, 56, 63, 64, 65, 127, 128]:
        data = bytes(range(length % 256)) if length <= 256 else bytes(i % 256 for i in range(length))
        # Truncate to fit in single update call (max 255)
        if length > 255:
            continue
        expected = blake2s_ref(data)

        result = c64_blake2s_hash(transport, labels, data)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS boundary: {length} bytes")
        else:
            failed += 1
            print(f"  FAIL boundary {length} bytes:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_hmac_blake2s(transport, labels, rng):
    """Test HMAC-BLAKE2s against Python reference."""
    passed = failed = 0

    test_cases = [
        (bytes(32), b"", "zero key, empty data"),
        (bytes(32), b"test", "zero key, 'test'"),
        (bytes(range(32)), b"", "sequential key, empty data"),
        (bytes(range(32)), b"abc", "sequential key, 'abc'"),
        (b"key" + bytes(29), bytes(range(64)), "short key, 64-byte data"),
    ]

    # Add random test cases
    for i in range(3):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        data_len = rng.randint(0, 64)
        data = bytes(rng.randint(0, 255) for _ in range(data_len))
        test_cases.append((key, data, f"random #{i}"))

    for key, data, desc in test_cases:
        expected = hmac_blake2s_ref(key, data)
        result = c64_hmac_blake2s(transport, labels, key, data)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS hmac: {desc}")
        else:
            failed += 1
            print(f"  FAIL hmac {desc}:")
            print(f"    key:      {key.hex()}")
            print(f"    data:     {data.hex()}")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_kdf(transport, labels):
    """Test WireGuard KDF (kdf_1, kdf_2, kdf_3) against Python reference."""
    passed = failed = 0

    test_cases = [
        (bytes(32), b"test", "zero C, 'test' input"),
        (bytes(range(32)), b"", "sequential C, empty input"),
        (bytes(range(32)), bytes(range(32)), "sequential C, sequential input"),
    ]

    for chaining_key, input_data, desc in test_cases:
        # Compute Python reference
        prk = hmac_blake2s_ref(chaining_key, input_data)
        t1_ref = hmac_blake2s_ref(prk, bytes([0x01]))
        t2_ref = hmac_blake2s_ref(prk, t1_ref + bytes([0x02]))
        t3_ref = hmac_blake2s_ref(prk, t2_ref + bytes([0x03]))

        # Test kdf_1
        [t1] = c64_kdf(transport, labels, chaining_key, input_data, outputs=1)
        if t1 == t1_ref:
            passed += 1
            if VERBOSE:
                print(f"  PASS kdf_1: {desc}")
        else:
            failed += 1
            print(f"  FAIL kdf_1 {desc}:")
            print(f"    expected: {t1_ref.hex()}")
            print(f"    got:      {t1.hex()}")

        # Test kdf_2
        [t1, t2] = c64_kdf(transport, labels, chaining_key, input_data, outputs=2)
        if t1 == t1_ref and t2 == t2_ref:
            passed += 1
            if VERBOSE:
                print(f"  PASS kdf_2: {desc}")
        else:
            failed += 1
            print(f"  FAIL kdf_2 {desc}:")
            if t1 != t1_ref:
                print(f"    T1 expected: {t1_ref.hex()}")
                print(f"    T1 got:      {t1.hex()}")
            if t2 != t2_ref:
                print(f"    T2 expected: {t2_ref.hex()}")
                print(f"    T2 got:      {t2.hex()}")

        # Test kdf_3
        [t1, t2, t3] = c64_kdf(transport, labels, chaining_key, input_data, outputs=3)
        if t1 == t1_ref and t2 == t2_ref and t3 == t3_ref:
            passed += 1
            if VERBOSE:
                print(f"  PASS kdf_3: {desc}")
        else:
            failed += 1
            print(f"  FAIL kdf_3 {desc}:")
            if t1 != t1_ref:
                print(f"    T1 expected: {t1_ref.hex()}")
                print(f"    T1 got:      {t1.hex()}")
            if t2 != t2_ref:
                print(f"    T2 expected: {t2_ref.hex()}")
                print(f"    T2 got:      {t2.hex()}")
            if t3 != t3_ref:
                print(f"    T3 expected: {t3_ref.hex()}")
                print(f"    T3 got:      {t3.hex()}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("word32 add", lambda: test_word32_add(transport, labels)),
        ("word32 xor", lambda: test_word32_xor(transport, labels)),
        ("word32 rotations", lambda: test_word32_rotations(transport, labels)),
        ("BLAKE2s unkeyed", lambda: test_blake2s_unkeyed(transport, labels)),
        ("BLAKE2s keyed", lambda: test_blake2s_keyed(transport, labels)),
        ("BLAKE2s random", lambda: test_blake2s_random(transport, labels, rng)),
        ("BLAKE2s boundary", lambda: test_blake2s_boundary(transport, labels)),
        ("HMAC-BLAKE2s", lambda: test_hmac_blake2s(transport, labels, rng)),
        ("WireGuard KDF", lambda: test_kdf(transport, labels)),
    ]

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
    global VERBOSE
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
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    print("Building...")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    result = subprocess.run(["make"], capture_output=True, text=True, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "blake2s_init", "blake2s_update", "blake2s_final",
        "blake2s_hash_oneshot", "b2s_hash", "b2s_data_ptr", "b2s_remain",
        "b2s_block", "b2s_h", "b2s_v", "b2s_tmp0", "b2s_tmp1",
        "input_buffer",
        "add32", "xor32", "rotr32_7", "rotr32_8", "rotr32_12", "rotr32_16",
        "w32_src1", "w32_src2", "w32_dst",
        "hmac_blake2s", "hmac_key_ptr", "hmac_key_len",
        "hmac_data_ptr", "hmac_data_len",
        "kdf_1", "kdf_2", "kdf_3",
        "kdf_prk", "kdf_out1", "kdf_out2", "kdf_out3",
        "kdf_input_ptr", "kdf_input_len",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            sys.exit(1)

        transport = ViceTransport(port=config.port)
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
