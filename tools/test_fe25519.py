#!/usr/bin/env python3
"""test_fe25519.py — Direct-memory field arithmetic mod 2^255-19 tests.

Tests fe_add, fe_sub, fe_mul, fe_sqr, fe_inv, fe_cswap, fe_mul_a24,
fe_copy, fe_zero, fe_one, fe_reduce_final against Python reference.

Usage:
    python3 tools/test_fe25519.py [--seed S] [--verbose]
"""

import os
import random
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

# p = 2^255 - 19
P = (1 << 255) - 19


# ============================================================================
# Python reference
# ============================================================================

def fe_add_ref(a, b):
    return (a + b) % P

def fe_sub_ref(a, b):
    return (a - b) % P

def fe_mul_ref(a, b):
    return (a * b) % P

def fe_sqr_ref(a):
    return (a * a) % P

def fe_inv_ref(a):
    return pow(a, P - 2, P)

def fe_mul_a24_ref(a):
    return (a * 121665) % P


def int_to_le32(val):
    """Convert integer to 32-byte little-endian bytes."""
    return (val % P).to_bytes(32, "little")

def le32_to_int(data):
    """Convert 32-byte little-endian bytes to integer."""
    return int.from_bytes(data, "little")

def rand_fe(rng):
    """Generate a random field element in [0, p-1]."""
    return rng.randint(0, P - 1)


# ============================================================================
# C64 helper functions
# ============================================================================

def set_fe_ptrs(transport, labels, src1=None, src2=None, dst=None):
    """Set fe_src1, fe_src2, fe_dst zero-page pointers."""
    if src1 is not None:
        write_bytes(transport, labels["fe25519_src1"],
                    bytes([src1 & 0xFF, src1 >> 8]))
    if src2 is not None:
        write_bytes(transport, labels["fe25519_src2"],
                    bytes([src2 & 0xFF, src2 >> 8]))
    if dst is not None:
        write_bytes(transport, labels["fe25519_dst"],
                    bytes([dst & 0xFF, dst >> 8]))


def write_fe(transport, addr, val):
    """Write a field element (integer) to C64 memory as 32-byte LE."""
    write_bytes(transport, addr, int_to_le32(val))


def read_fe(transport, addr):
    """Read a 32-byte LE field element from C64 memory, return as integer."""
    return le32_to_int(read_bytes(transport, addr, 32))


def c64_fe_add(transport, labels, a, b):
    """Compute a + b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_add"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_sub(transport, labels, a, b):
    """Compute a - b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_sub"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_mul(transport, labels, a, b):
    """Compute a * b mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_mul"], timeout=120.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_sqr(transport, labels, a):
    """Compute a^2 mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_sqr"], timeout=120.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_inv(transport, labels, a):
    """Compute a^(p-2) mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    # fe_inv takes ~253 squarings + 11 muls — very slow
    jsr(transport, labels["fe25519_inv"], timeout=600.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_mul_a24(transport, labels, a):
    """Compute a * 121665 mod p on C64."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_mul_a24"], timeout=60.0)
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_copy(transport, labels, a):
    """Copy a field element via fe_copy."""
    write_fe(transport, labels["fe_tmp1"], a)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_copy"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_zero(transport, labels):
    """Zero a field element via fe_zero."""
    # Write nonzero first to prove it gets zeroed
    write_fe(transport, labels["fe_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_zero"])
    return read_fe(transport, labels["fe_tmp3"])


def c64_fe_one(transport, labels):
    """Set a field element to 1 via fe_one."""
    write_fe(transport, labels["fe_tmp3"], P - 1)
    set_fe_ptrs(transport, labels, dst=labels["fe_tmp3"])
    jsr(transport, labels["fe25519_one"])
    return read_fe(transport, labels["fe_tmp3"])


# ============================================================================
# Test functions
# ============================================================================

def test_copy_zero_one(transport, labels):
    """Test fe_copy, fe_zero, fe_one."""
    passed = failed = 0

    # fe_zero
    result = c64_fe_zero(transport, labels)
    if result == 0:
        passed += 1
        if VERBOSE: print("  PASS fe_zero")
    else:
        failed += 1
        print(f"  FAIL fe_zero: got {result}")

    # fe_one
    result = c64_fe_one(transport, labels)
    if result == 1:
        passed += 1
        if VERBOSE: print("  PASS fe_one")
    else:
        failed += 1
        print(f"  FAIL fe_one: got {result}")

    # fe_copy
    test_val = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0
    result = c64_fe_copy(transport, labels, test_val)
    if result == test_val:
        passed += 1
        if VERBOSE: print("  PASS fe_copy")
    else:
        failed += 1
        print(f"  FAIL fe_copy: expected {test_val:#x}, got {result:#x}")

    return passed, failed


def test_add(transport, labels, rng):
    """Test fe_add with identity, commutativity, boundary, random."""
    passed = failed = 0

    cases = [
        ("0+0", 0, 0),
        ("0+1", 0, 1),
        ("1+1", 1, 1),
        ("p-1+1", P - 1, 1),          # should wrap to 0
        ("p-1+p-1", P - 1, P - 1),    # should give p-3 mod p
        ("large+large", P - 10, 15),   # wraps: 5 mod p
    ]

    # Add random cases
    for i in range(6):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_add_ref(a, b)
        result = c64_fe_add(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS add {name}")
        else:
            failed += 1
            print(f"  FAIL add {name}: expected {expected}, got {result}")

    return passed, failed


def test_sub(transport, labels, rng):
    """Test fe_sub with identity, boundary, random."""
    passed = failed = 0

    cases = [
        ("0-0", 0, 0),
        ("1-0", 1, 0),
        ("1-1", 1, 1),
        ("0-1", 0, 1),                # should give p-1
        ("10-20", 10, 20),            # should give p-10
        ("p-1-0", P - 1, 0),
    ]

    for i in range(6):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_sub_ref(a, b)
        result = c64_fe_sub(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sub {name}")
        else:
            failed += 1
            print(f"  FAIL sub {name}: expected {expected}, got {result}")

    return passed, failed


def test_mul(transport, labels, rng):
    """Test fe_mul with identity, zero, random."""
    passed = failed = 0

    cases = [
        ("0*0", 0, 0),
        ("0*1", 0, 1),
        ("1*1", 1, 1),
        ("2*3", 2, 3),
        ("a*0", rand_fe(rng), 0),
        ("1*a", 1, rand_fe(rng)),
    ]

    for i in range(4):
        a, b = rand_fe(rng), rand_fe(rng)
        cases.append((f"random #{i}", a, b))

    for name, a, b in cases:
        expected = fe_mul_ref(a, b)
        result = c64_fe_mul(transport, labels, a, b)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mul {name}")
        else:
            failed += 1
            print(f"  FAIL mul {name}:")
            print(f"    a = {a}")
            print(f"    b = {b}")
            print(f"    expected = {expected}")
            print(f"    got      = {result}")

    return passed, failed


def test_sqr(transport, labels, rng):
    """Test fe_sqr against fe_mul(a,a) and Python."""
    passed = failed = 0

    cases = [0, 1, 2, P - 1, rand_fe(rng), rand_fe(rng), rand_fe(rng)]

    for i, a in enumerate(cases):
        expected = fe_sqr_ref(a)
        result = c64_fe_sqr(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS sqr #{i}")
        else:
            failed += 1
            print(f"  FAIL sqr #{i}: a={a}, expected={expected}, got={result}")

    return passed, failed


def test_mul_a24(transport, labels, rng):
    """Test fe_mul_a24 (multiply by 121665)."""
    passed = failed = 0

    cases = [0, 1, 2, 121665, P - 1, rand_fe(rng), rand_fe(rng), rand_fe(rng)]

    for i, a in enumerate(cases):
        expected = fe_mul_a24_ref(a)
        result = c64_fe_mul_a24(transport, labels, a)
        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS mul_a24 #{i}")
        else:
            failed += 1
            print(f"  FAIL mul_a24 #{i}: a={a}, expected={expected}, got={result}")

    return passed, failed


def test_inv(transport, labels, rng):
    """Test fe_inv: inv(1) == 1.

    Full fe_inv takes ~10 minutes per call in VICE due to ~265 field
    multiplications with remote monitor overhead (~2.4s each).
    Only test trivial case; use --slow-inv flag for full tests.
    """
    passed = failed = 0

    # inv(1) is fast because 1^n = 1 (zero-skip optimization in fe_mul)
    cases = [1]

    # Check for --slow-inv flag
    if "--slow-inv" in sys.argv:
        cases = [1, 2]
        print("  NOTE: --slow-inv enabled, inv(2) will take ~10 minutes")

    for i, a in enumerate(cases):
        print(f"    inv test #{i} (a={a:#x})...", end="", flush=True)
        inv_a = c64_fe_inv(transport, labels, a)
        expected = fe_inv_ref(a)

        if inv_a == expected:
            passed += 1
            print(" PASS" if VERBOSE else " ok")
        else:
            failed += 1
            print(f" FAIL")
            print(f"    expected inv = {expected}")
            print(f"    got inv      = {inv_a}")
            product = (a * inv_a) % P
            print(f"    a * got_inv mod p = {product}")

    return passed, failed


def test_cswap(transport, labels, rng):
    """Test fe_cswap constant-time swap."""
    passed = failed = 0

    a = rand_fe(rng)
    b = rand_fe(rng)

    # Test no-swap (mask = 0x00)
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"])
    # Write mask to A via a byte in memory and LDA before jsr
    # Actually, fe_cswap expects A register. jsr() can't set A.
    # Use a wrapper: write the mask byte, then have a tiny trampoline.
    # Simpler: write mask to fe_carry directly and skip the STA in fe_cswap.
    # But that changes the code. Better: use the input_buffer as a trampoline.
    #
    # Actually the easiest approach: write a 3-byte trampoline at cassette_buf
    # LDA #$00; JMP fe_cswap
    cswap_addr = labels["fe25519_cswap"]
    # Use input_buffer for the trampoline since jsr() uses cassette_buf ($0334)
    trampoline = labels["input_buffer"]

    # No-swap test (mask = $00)
    write_bytes(transport, trampoline, bytes([
        0xA9, 0x00,                          # LDA #$00
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,  # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe_tmp1"])
    r_b = read_fe(transport, labels["fe_tmp2"])

    if r_a == a and r_b == b:
        passed += 1
        if VERBOSE: print("  PASS cswap no-swap")
    else:
        failed += 1
        print(f"  FAIL cswap no-swap: a changed={r_a != a}, b changed={r_b != b}")

    # Swap test (mask = $FF)
    write_fe(transport, labels["fe_tmp1"], a)
    write_fe(transport, labels["fe_tmp2"], b)
    set_fe_ptrs(transport, labels,
                src1=labels["fe_tmp1"],
                src2=labels["fe_tmp2"])
    write_bytes(transport, trampoline, bytes([
        0xA9, 0xFF,                          # LDA #$FF
        0x4C, cswap_addr & 0xFF, cswap_addr >> 8,  # JMP fe_cswap
    ]))
    jsr(transport, trampoline)
    r_a = read_fe(transport, labels["fe_tmp1"])
    r_b = read_fe(transport, labels["fe_tmp2"])

    if r_a == b and r_b == a:
        passed += 1
        if VERBOSE: print("  PASS cswap swap")
    else:
        failed += 1
        print(f"  FAIL cswap swap: expected ({b:#x},{a:#x}), got ({r_a:#x},{r_b:#x})")

    return passed, failed


def test_reduce_final(transport, labels):
    """Test fe_reduce_final with values >= p."""
    passed = failed = 0

    cases = [
        ("p itself", P, 0),           # p → 0
        ("p+1", P + 1, 1),           # p+1 → 1
        ("p-1", P - 1, P - 1),       # stays
        ("0", 0, 0),
        ("1", 1, 1),
    ]

    for name, val, expected in cases:
        # Write raw bytes (may be >= p)
        raw = val.to_bytes(32, "little")
        write_bytes(transport, labels["fe_tmp3"], raw)
        set_fe_ptrs(transport, labels, dst=labels["fe_tmp3"])
        jsr(transport, labels["fe25519_reduce_final"])
        result = read_fe(transport, labels["fe_tmp3"])

        if result == expected:
            passed += 1
            if VERBOSE: print(f"  PASS reduce_final {name}")
        else:
            failed += 1
            print(f"  FAIL reduce_final {name}: expected {expected}, got {result}")

    return passed, failed


def test_add_sub_inverse(transport, labels, rng):
    """Test that (a + b) - b == a."""
    passed = failed = 0

    for i in range(4):
        a = rand_fe(rng)
        b = rand_fe(rng)
        sum_ab = c64_fe_add(transport, labels, a, b)
        result = c64_fe_sub(transport, labels, sum_ab, b)
        if result == a:
            passed += 1
            if VERBOSE: print(f"  PASS add_sub_inverse #{i}")
        else:
            failed += 1
            print(f"  FAIL add_sub_inverse #{i}: expected {a}, got {result}")

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
        ("copy/zero/one", lambda: test_copy_zero_one(transport, labels)),
        ("reduce_final", lambda: test_reduce_final(transport, labels)),
        ("fe_add", lambda: test_add(transport, labels, rng)),
        ("fe_sub", lambda: test_sub(transport, labels, rng)),
        ("add/sub inverse", lambda: test_add_sub_inverse(transport, labels, rng)),
        ("fe_mul", lambda: test_mul(transport, labels, rng)),
        ("fe_sqr", lambda: test_sqr(transport, labels, rng)),
        ("fe_mul_a24", lambda: test_mul_a24(transport, labels, rng)),
        ("fe_cswap", lambda: test_cswap(transport, labels, rng)),
        ("fe_inv", lambda: test_inv(transport, labels, rng)),
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

    # --- Symbol-name compatibility shim ---------------------------------
    # The in-tree fe25519/x25519 path (default build) exports the scratch
    # buffers as fe_tmp{1..4}. The c64-x25519 sibling (USE_X25519_SIBLING=1,
    # v0.6.0+) renames the equivalents to fe25519_tmp{1..4} to match its
    # own canonical naming. The test driver only cares about the resolved
    # addresses, so we install bidirectional aliases at load time and let
    # the rest of the file keep using the historical fe_tmp* names.
    #
    # fe_wide moves to a ZP-pinned working buffer in the sibling and is no
    # longer emitted as a labels.txt entry; it's also unused by this test
    # (only referenced in the required-list sanity check), so we drop it
    # from required when the sibling owns the build.
    _BUF_ALIASES = (
        ("fe_tmp1", "fe25519_tmp1"),
        ("fe_tmp2", "fe25519_tmp2"),
        ("fe_tmp3", "fe25519_tmp3"),
        ("fe_tmp4", "fe25519_tmp4"),
    )
    for legacy, canonical in _BUF_ALIASES:
        if legacy not in labels and canonical in labels:
            labels._by_name[legacy] = labels._by_name[canonical]
        elif canonical not in labels and legacy in labels:
            labels._by_name[canonical] = labels._by_name[legacy]

    required = [
        "fe25519_src1", "fe25519_src2", "fe25519_dst",
        "fe25519_copy", "fe25519_zero", "fe25519_one",
        "fe25519_add", "fe25519_sub", "fe25519_mul", "fe25519_sqr", "fe25519_inv",
        "fe25519_cswap", "fe25519_mul_a24", "fe25519_reduce_final",
        "fe_tmp1", "fe_tmp2", "fe_tmp3", "fe_tmp4",
        "fe_p",
        "cassette_buf",
        "input_buffer",
    ]
    # fe_wide is in-tree-only — sibling pins it to ZP and skips the
    # labels.txt entry. Test code doesn't actually use this label, but
    # validate its presence when the in-tree path is active so an
    # accidental drop on that side is still caught.
    if "fe_wide" in labels:
        required.append("fe_wide")
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

        # Need sqtab initialized for multiply operations
        # Call poly1305_init with dummy key to build sqtab
        print("Initializing sqtab (quarter-square table)...")
        write_bytes(transport, labels["poly_r"], bytes(16))
        write_bytes(transport, labels["poly_s"], bytes(16))
        jsr(transport, labels["poly1305_init"], timeout=30.0)
        print("sqtab ready")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
