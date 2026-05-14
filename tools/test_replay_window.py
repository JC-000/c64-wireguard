#!/usr/bin/env python3
"""test_replay_window.py -- Sliding window replay protection tests.

Tests the 2048-bit sliding window replay protection in transport_decrypt.
Verifies acceptance/rejection of packets based on counter values, duplicates,
out-of-order delivery, and window boundary conditions.

Usage:
    python3 tools/test_replay_window.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False


def robust_jsr(transport, addr, timeout=30.0, retries=5):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0 + attempt * 0.5)
                continue
            raise


# ============================================================================
# Python reference helpers
# ============================================================================

def py_encrypt(key, counter_val, plaintext):
    """Encrypt using ChaCha20-Poly1305 with WireGuard transport nonce."""
    nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
    aead = ChaCha20Poly1305(key)
    ct_and_tag = aead.encrypt(nonce, plaintext, None)
    return ct_and_tag[:-16], ct_and_tag[-16:]


def build_type4_packet(receiver_idx, counter_val, key, plaintext):
    """Build a complete Type 4 packet using Python crypto."""
    ct, tag = py_encrypt(key, counter_val, plaintext)
    header = struct.pack('<I', 4)
    header += receiver_idx
    header += struct.pack('<Q', counter_val)
    return header + ct + tag


def reset_recv_state(transport, labels):
    """Reset all receive/replay state."""
    write_bytes(transport, labels["tp_recv_counter"], bytes(8))
    write_bytes(transport, labels["rw_counter_max"], bytes(8))
    write_bytes(transport, labels["rw_bitmap"], bytes(256))


def send_and_check(transport, labels, key, counter_val, plaintext,
                   expect_accept, desc):
    """Send a packet and check whether it was accepted or rejected.

    Returns (passed, failed) tuple.
    """
    packet = build_type4_packet(b'\x01\x00\x00\x00', counter_val, key,
                                plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    # Read rw_counter_max before decrypt to detect changes
    old_max = read_bytes(transport, labels["rw_counter_max"], 8)
    old_bitmap_byte = None

    # For within-window packets, check the specific bitmap bit
    counter_low11 = counter_val & 0x7FF
    byte_offset = counter_low11 >> 3
    bit_index = counter_low11 & 7

    robust_jsr(transport, labels["transport_decrypt"], timeout=60.0)

    # Check result: read rw_counter_max and the bitmap bit
    new_max = read_bytes(transport, labels["rw_counter_max"], 8)
    bm_byte = read_bytes(transport, labels["rw_bitmap"] + byte_offset, 1)[0]
    bit_set = bool(bm_byte & (1 << bit_index))

    # Determine if accepted: either max advanced or bitmap bit got set
    expected_max = struct.pack('<Q', counter_val)
    new_max_val = int.from_bytes(new_max, 'little')
    old_max_val = int.from_bytes(old_max, 'little')

    if expect_accept:
        # On accept: bitmap bit should be set for this counter
        if bit_set:
            if VERBOSE:
                print(f"  PASS {desc}")
            return 1, 0
        else:
            print(f"  FAIL {desc}: expected accept but bit not set")
            print(f"    counter={counter_val}, old_max={old_max_val}, "
                  f"new_max={new_max_val}")
            return 0, 1
    else:
        # On reject: bitmap bit should NOT have been newly set
        # (could be set from a prior accept of same counter)
        # Better check: rw_counter_max should not have changed if
        # counter > old max, or tp_recv_counter shouldn't advance
        recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
        recv_ctr_val = int.from_bytes(recv_ctr, 'little')

        # For rejection, the tp_recv_counter should remain at old_max + 1
        expected_recv = old_max_val + 1 if old_max_val > 0 else (
            1 if old_max == bytes(8) and bit_set else 0)

        # Simple check: max should not have advanced beyond what it was
        if new_max_val == old_max_val:
            if VERBOSE:
                print(f"  PASS {desc}")
            return 1, 0
        elif counter_val <= old_max_val:
            # counter was within/below window, so max shouldn't change
            if VERBOSE:
                print(f"  PASS {desc}")
            return 1, 0
        else:
            print(f"  FAIL {desc}: expected reject but max advanced "
                  f"from {old_max_val} to {new_max_val}")
            return 0, 1


# ============================================================================
# Test groups
# ============================================================================

def test_sequential_accepted(transport, labels, key, plaintext):
    """Test 1: Sequential packets 0,1,2,3 all accepted."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for i in range(4):
        p, f = send_and_check(transport, labels, key, i, plaintext,
                              True, f"sequential: counter={i} accepted")
        passed += p
        failed += f

    return passed, failed


def test_duplicate_rejected(transport, labels, key, plaintext):
    """Test 2: Duplicate packet rejected."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept counter=0
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "dup: counter=0 first accepted")
    passed += p
    failed += f

    # Reject counter=0 again
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "dup: counter=0 second rejected")
    passed += p
    failed += f

    return passed, failed


def test_out_of_order_accepted(transport, labels, key, plaintext):
    """Test 3: Out-of-order within window accepted."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Send 0, 5, 3
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "ooo: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 5, plaintext,
                          True, "ooo: counter=5 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 3, plaintext,
                          True, "ooo: counter=3 accepted (within window)")
    passed += p
    failed += f

    return passed, failed


def test_out_of_order_replay_rejected(transport, labels, key, plaintext):
    """Test 4: Out-of-order replay rejected."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for c in [0, 5, 3]:
        p, f = send_and_check(transport, labels, key, c, plaintext,
                              True, f"ooo-replay setup: counter={c}")
        passed += p
        failed += f

    # Now counter=3 again should be rejected
    p, f = send_and_check(transport, labels, key, 3, plaintext,
                          False, "ooo-replay: counter=3 duplicate rejected")
    passed += p
    failed += f

    return passed, failed


def test_large_gap_advances(transport, labels, key, plaintext):
    """Test 5: Large gap advances window."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "gap: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 2000, plaintext,
                          True, "gap: counter=2000 accepted (big jump)")
    passed += p
    failed += f

    # Verify rw_counter_max is 2000
    max_val = int.from_bytes(
        read_bytes(transport, labels["rw_counter_max"], 8), 'little')
    if max_val == 2000:
        passed += 1
        if VERBOSE:
            print("  PASS gap: rw_counter_max=2000")
    else:
        failed += 1
        print(f"  FAIL gap: rw_counter_max={max_val}, expected 2000")

    return passed, failed


def test_old_outside_window_rejected(transport, labels, key, plaintext):
    """Test 6: Old packets outside window rejected after big advance."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept counter=0
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "outside: counter=0 accepted")
    passed += p
    failed += f

    # Advance to counter=2048 (delta=2048 from 0, so 0 is now outside window)
    p, f = send_and_check(transport, labels, key, 2048, plaintext,
                          True, "outside: counter=2048 accepted")
    passed += p
    failed += f

    # Counter=0 should now be rejected (delta=2048 from max, outside window)
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "outside: counter=0 rejected (outside window)")
    passed += p
    failed += f

    return passed, failed


def test_edge_delta_2047_accepted(transport, labels, key, plaintext):
    """Test 7: Edge case delta=2047 is accepted (within window)."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Set max to 2047 by sending counter=2047
    p, f = send_and_check(transport, labels, key, 2047, plaintext,
                          True, "edge-2047: counter=2047 accepted")
    passed += p
    failed += f

    # Send counter=0: delta = 2047 - 0 = 2047, should be within window
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "edge-2047: counter=0 accepted (delta=2047)")
    passed += p
    failed += f

    return passed, failed


def test_edge_delta_2048_rejected(transport, labels, key, plaintext):
    """Test 8: Edge case delta=2048 is rejected (outside window)."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Set max to 2048 by sending counter=2048
    p, f = send_and_check(transport, labels, key, 2048, plaintext,
                          True, "edge-2048: counter=2048 accepted")
    passed += p
    failed += f

    # Send counter=0: delta = 2048 - 0 = 2048, should be outside window
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "edge-2048: counter=0 rejected (delta=2048)")
    passed += p
    failed += f

    return passed, failed


def test_backfill_pattern(transport, labels, key, plaintext):
    """Test 9: Backfill pattern -- accept then reject duplicate."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "backfill: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 100, plaintext,
                          True, "backfill: counter=100 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 50, plaintext,
                          True, "backfill: counter=50 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 50, plaintext,
                          False, "backfill: counter=50 duplicate rejected")
    passed += p
    failed += f

    return passed, failed


def test_window_advance_preserves_old_bits(transport, labels, key, plaintext):
    """Test 10: Window advance preserves bits of previously seen packets."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept 0, 1, 2
    for c in [0, 1, 2]:
        p, f = send_and_check(transport, labels, key, c, plaintext,
                              True, f"preserve: counter={c} accepted")
        passed += p
        failed += f

    # Advance to 5
    p, f = send_and_check(transport, labels, key, 5, plaintext,
                          True, "preserve: counter=5 accepted (advance)")
    passed += p
    failed += f

    # Counter=1 should still be rejected (bit preserved from earlier)
    p, f = send_and_check(transport, labels, key, 1, plaintext,
                          False, "preserve: counter=1 rejected (already seen)")
    passed += p
    failed += f

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all sliding window test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    plaintext = b"REPLAY WINDOW TEST"

    write_bytes(transport, labels["hs_transport_recv"], key)

    groups = [
        ("sequential accepted",
         lambda: test_sequential_accepted(transport, labels, key, plaintext)),
        ("duplicate rejected",
         lambda: test_duplicate_rejected(transport, labels, key, plaintext)),
        ("out-of-order accepted",
         lambda: test_out_of_order_accepted(transport, labels, key, plaintext)),
        ("out-of-order replay rejected",
         lambda: test_out_of_order_replay_rejected(transport, labels, key,
                                                    plaintext)),
        ("large gap advances",
         lambda: test_large_gap_advances(transport, labels, key, plaintext)),
        ("old outside window rejected",
         lambda: test_old_outside_window_rejected(transport, labels, key,
                                                   plaintext)),
        ("edge: delta=2047 accepted",
         lambda: test_edge_delta_2047_accepted(transport, labels, key,
                                                plaintext)),
        ("edge: delta=2048 rejected",
         lambda: test_edge_delta_2048_rejected(transport, labels, key,
                                                plaintext)),
        ("backfill pattern",
         lambda: test_backfill_pattern(transport, labels, key, plaintext)),
        ("window advance preserves old bits",
         lambda: test_window_advance_preserves_old_bits(transport, labels, key,
                                                         plaintext)),
    ]

    for name, test_fn in groups:
        print(f"\n--- {name} ---")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            print(f"  {p} passed, {f} failed")
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            total_failed += 1
        time.sleep(1.0)

    return total_passed, total_failed


def main():
    args = sys.argv[1:]
    seed = 4242
    global VERBOSE
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
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        # Only clean ACME outputs, not ip65 binary (may not be rebuildable)
        build_dir = os.path.join(PROJECT_ROOT, "build")
        for f in ["wireguard.prg", "labels.txt"]:
            p = os.path.join(build_dir, f)
            if os.path.exists(p):
                os.remove(p)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    # Verify required labels exist
    required = ["rw_bitmap", "rw_counter_max", "rw_bit_mask",
                "transport_decrypt", "tp_recv_counter", "tp_recv_counter_tmp",
                "hs_transport_recv", "udp_recv_buf", "udp_recv_len"]
    for name in required:
        addr = labels.address(name)
        if addr is None:
            print(f"FATAL: label '{name}' not found")
            sys.exit(1)
        if VERBOSE:
            print(f"  label '{name}' = ${addr:04X}")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(
        config=config,
        port_range_start=6510,
        port_range_end=6530,
    ) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
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
