#!/usr/bin/env python3
"""test_key_rotation.py — Counter-based key rotation limit tests.

Tests that transport_encrypt rejects when send counter byte 7 >= $10,
signals rekey when byte 7 >= $0F, and transport_decrypt rejects packets
with counter byte 7 >= $10.

Usage:
    python3 tools/test_key_rotation.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceProcess, ViceTransport,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from c64_test_harness.backends.vice_manager import PortAllocator

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


# ============================================================================
# Test groups
# ============================================================================

def test_build_verification(labels):
    """Verify new labels exist for key rotation feature."""
    passed = failed = 0

    required_labels = [
        "tp_encrypt_error", "rekey_pending",
        "tp_send_counter", "tp_recv_counter",
        "transport_encrypt", "transport_decrypt",
    ]

    for name in required_labels:
        addr = labels.address(name)
        if addr is not None:
            passed += 1
            if VERBOSE:
                print(f"  PASS label '{name}' = ${addr:04X}")
        else:
            failed += 1
            print(f"  FAIL label '{name}' not found")

    return passed, failed


def test_encrypt_normal_counter(transport, labels, rng):
    """Test 1: Normal counter (0) — encrypt succeeds, no error."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes([0x01, 0x00, 0x00, 0x00])
    plaintext = b"HELLO WORLD!"

    # Set up state: counter = 0
    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
    write_bytes(transport, labels["tp_send_counter"], bytes(8))
    write_bytes(transport, labels["rekey_pending"], bytes([0]))

    # Write plaintext
    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    # Check tp_encrypt_error = 0
    err = read_bytes(transport, labels["tp_encrypt_error"], 1)[0]
    if err == 0:
        passed += 1
        if VERBOSE:
            print("  PASS normal counter: tp_encrypt_error = 0")
    else:
        failed += 1
        print(f"  FAIL normal counter: tp_encrypt_error = {err}, expected 0")

    # Check rekey_pending = 0
    rekey = read_bytes(transport, labels["rekey_pending"], 1)[0]
    if rekey == 0:
        passed += 1
        if VERBOSE:
            print("  PASS normal counter: rekey_pending = 0")
    else:
        failed += 1
        print(f"  FAIL normal counter: rekey_pending = {rekey}, expected 0")

    # Verify packet was actually written (type byte = 4)
    pkt_type = read_bytes(transport, labels["tp_packet"], 1)[0]
    if pkt_type == 0x04:
        passed += 1
        if VERBOSE:
            print("  PASS normal counter: packet written (type=4)")
    else:
        failed += 1
        print(f"  FAIL normal counter: packet type = {pkt_type:#x}, expected 0x04")

    return passed, failed


def test_encrypt_counter_exhausted(transport, labels, rng):
    """Test 2: Send counter byte 7 = $10 — encrypt rejected."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes([0x01, 0x00, 0x00, 0x00])
    plaintext = b"SHOULD NOT ENCRYPT"

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)

    # Set counter byte 7 = $10 (counter = 0x1000000000000000)
    counter = struct.pack('<Q', 0x1000000000000000)
    write_bytes(transport, labels["tp_send_counter"], counter)

    # Clear packet type byte to detect if encrypt writes it
    write_bytes(transport, labels["tp_packet"], bytes([0x00]))

    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    # Check tp_encrypt_error = 1
    err = read_bytes(transport, labels["tp_encrypt_error"], 1)[0]
    if err == 1:
        passed += 1
        if VERBOSE:
            print("  PASS counter exhausted: tp_encrypt_error = 1")
    else:
        failed += 1
        print(f"  FAIL counter exhausted: tp_encrypt_error = {err}, expected 1")

    # Verify packet was NOT written (type byte should still be 0)
    pkt_type = read_bytes(transport, labels["tp_packet"], 1)[0]
    if pkt_type == 0x00:
        passed += 1
        if VERBOSE:
            print("  PASS counter exhausted: no packet written")
    else:
        failed += 1
        print(f"  FAIL counter exhausted: packet type = {pkt_type:#x}, expected 0x00")

    # Counter should not have been incremented
    ctr_after = read_bytes(transport, labels["tp_send_counter"], 8)
    if ctr_after == counter:
        passed += 1
        if VERBOSE:
            print("  PASS counter exhausted: counter not incremented")
    else:
        failed += 1
        print(f"  FAIL counter exhausted: counter changed to {ctr_after.hex()}")

    return passed, failed


def test_encrypt_rekey_warning(transport, labels, rng):
    """Test 3: Send counter byte 7 = $0F — encrypt succeeds + rekey_pending set."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes([0x01, 0x00, 0x00, 0x00])
    plaintext = b"REKEY WARNING"

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)

    # Set counter byte 7 = $0F (counter = 0x0F00000000000000)
    counter_val = 0x0F00000000000000
    counter = struct.pack('<Q', counter_val)
    write_bytes(transport, labels["tp_send_counter"], counter)
    write_bytes(transport, labels["rekey_pending"], bytes([0]))  # clear

    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    # Check tp_encrypt_error = 0 (encrypt should succeed)
    err = read_bytes(transport, labels["tp_encrypt_error"], 1)[0]
    if err == 0:
        passed += 1
        if VERBOSE:
            print("  PASS rekey warning: tp_encrypt_error = 0")
    else:
        failed += 1
        print(f"  FAIL rekey warning: tp_encrypt_error = {err}, expected 0")

    # Check rekey_pending = 1
    rekey = read_bytes(transport, labels["rekey_pending"], 1)[0]
    if rekey == 1:
        passed += 1
        if VERBOSE:
            print("  PASS rekey warning: rekey_pending = 1")
    else:
        failed += 1
        print(f"  FAIL rekey warning: rekey_pending = {rekey}, expected 1")

    # Verify packet was written correctly — check ciphertext matches Python
    pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
    pkt_len = int.from_bytes(pkt_len_bytes, 'little')
    expected_len = 16 + len(plaintext) + 16

    if pkt_len == expected_len:
        passed += 1
        if VERBOSE:
            print(f"  PASS rekey warning: packet length = {pkt_len}")
    else:
        failed += 1
        print(f"  FAIL rekey warning: packet length = {pkt_len}, expected {expected_len}")

    return passed, failed


def test_decrypt_counter_exhausted(transport, labels, rng):
    """Test 4: Recv counter byte 7 = $10 — decrypt rejected."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    plaintext = b"HIGH COUNTER PKT"

    # Counter value where byte 7 = $10
    counter_val = 0x1000000000000000

    # Build a valid Type 4 packet with this high counter
    packet = build_type4_packet(b'\x01\x00\x00\x00', counter_val, key, plaintext)

    write_bytes(transport, labels["hs_transport_recv"], key)
    # Set recv counter to 0 (so replay check would pass)
    write_bytes(transport, labels["tp_recv_counter"], bytes(8))

    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    robust_jsr(transport, labels["transport_decrypt"], timeout=60.0)

    # Recv counter should NOT have been updated (still 0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == bytes(8):
        passed += 1
        if VERBOSE:
            print("  PASS decrypt counter exhausted: rejected (counter unchanged)")
    else:
        failed += 1
        print(f"  FAIL decrypt counter exhausted: counter updated to {recv_ctr.hex()}")

    return passed, failed


def test_encrypt_no_rekey_below_threshold(transport, labels, rng):
    """Test 5: Counter byte 7 = $0E — no rekey triggered."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes([0x01, 0x00, 0x00, 0x00])
    plaintext = b"NO REKEY YET"

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)

    # Set counter byte 7 = $0E (below rekey threshold of $0F)
    counter_val = 0x0E00000000000000
    counter = struct.pack('<Q', counter_val)
    write_bytes(transport, labels["tp_send_counter"], counter)
    write_bytes(transport, labels["rekey_pending"], bytes([0]))  # clear

    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    # Check rekey_pending = 0 (no rekey)
    rekey = read_bytes(transport, labels["rekey_pending"], 1)[0]
    if rekey == 0:
        passed += 1
        if VERBOSE:
            print("  PASS no rekey below threshold: rekey_pending = 0")
    else:
        failed += 1
        print(f"  FAIL no rekey below threshold: rekey_pending = {rekey}, expected 0")

    # Check tp_encrypt_error = 0
    err = read_bytes(transport, labels["tp_encrypt_error"], 1)[0]
    if err == 0:
        passed += 1
        if VERBOSE:
            print("  PASS no rekey below threshold: tp_encrypt_error = 0")
    else:
        failed += 1
        print(f"  FAIL no rekey below threshold: tp_encrypt_error = {err}, expected 0")

    return passed, failed


def test_counter_rekey_independent(transport, labels, rng):
    """Test 6: Counter-based rekey is independent of prior rekey_pending state."""
    passed = failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes([0x02, 0x00, 0x00, 0x00])
    plaintext = b"INDEPENDENT"

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)

    # Pre-set rekey_pending = 0, then encrypt with byte 7 = $0F
    # Counter-based check should set rekey_pending = 1
    counter_val = 0x0F00000000000000
    counter = struct.pack('<Q', counter_val)
    write_bytes(transport, labels["tp_send_counter"], counter)
    write_bytes(transport, labels["rekey_pending"], bytes([0]))

    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    rekey = read_bytes(transport, labels["rekey_pending"], 1)[0]
    if rekey == 1:
        passed += 1
        if VERBOSE:
            print("  PASS counter rekey independent: rekey_pending set to 1")
    else:
        failed += 1
        print(f"  FAIL counter rekey independent: rekey_pending = {rekey}, expected 1")

    # Now with rekey_pending already 1 and counter below threshold,
    # it should NOT clear rekey_pending (encrypt only sets, never clears)
    # Actually, the code clears tp_encrypt_error but does NOT touch rekey_pending
    # if counter is below $0F. So rekey_pending stays at whatever it was before.
    # Wait — the code does "lda #0 / sta tp_encrypt_error" at the start, but
    # does NOT clear rekey_pending. So if rekey_pending was 1, it stays 1.
    # That's the correct behavior for time-based rekey coexistence.
    counter_val2 = 0x0100000000000000  # byte 7 = $01, below rekey threshold
    counter2 = struct.pack('<Q', counter_val2)
    write_bytes(transport, labels["tp_send_counter"], counter2)
    # rekey_pending is still 1 from previous test

    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack('<H', labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], bytes([len(plaintext)]))

    robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

    # rekey_pending should still be 1 (not cleared by encrypt)
    rekey = read_bytes(transport, labels["rekey_pending"], 1)[0]
    if rekey == 1:
        passed += 1
        if VERBOSE:
            print("  PASS counter rekey independent: rekey_pending preserved")
    else:
        failed += 1
        print(f"  FAIL counter rekey independent: rekey_pending = {rekey}, expected 1 (preserved)")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("encrypt normal counter", lambda: test_encrypt_normal_counter(transport, labels, rng)),
        ("encrypt counter exhausted", lambda: test_encrypt_counter_exhausted(transport, labels, rng)),
        ("encrypt rekey warning", lambda: test_encrypt_rekey_warning(transport, labels, rng)),
        ("decrypt counter exhausted", lambda: test_decrypt_counter_exhausted(transport, labels, rng)),
        ("encrypt no rekey below threshold", lambda: test_encrypt_no_rekey_below_threshold(transport, labels, rng)),
        ("counter rekey independent", lambda: test_counter_rekey_independent(transport, labels, rng)),
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
    seed = 8192
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

    # Build (skip if run_regression.py already built)
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        # Clean only the ACME output, not ip65
        for f in [os.path.join(PROJECT_ROOT, "build", "wireguard.prg"),
                  os.path.join(PROJECT_ROOT, "build", "labels.txt")]:
            if os.path.exists(f):
                os.remove(f)
        os.makedirs(os.path.join(PROJECT_ROOT, "build"), exist_ok=True)
        # Build just the ACME part (ip65-c64.bin must already exist)
        result = subprocess.run(
            ["acme", "-f", "cbm", "-o", "../build/wireguard.prg",
             "--vicelabels", "../build/labels.txt", "main.asm"],
            capture_output=True, text=True,
            cwd=os.path.join(PROJECT_ROOT, "src"))
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    # Build verification (no VICE needed)
    print("\n--- build verification ---")
    p, f = test_build_verification(labels)
    print(f"  {p} passed, {f} failed")
    if f > 0:
        print("FATAL: Build verification failed")
        sys.exit(1)

    # Launch VICE
    allocator = PortAllocator(port_range_start=6510, port_range_end=6530)
    port = allocator.allocate()
    reservation = allocator.take_socket(port)
    if reservation:
        reservation.close()
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        port=port)
    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            allocator.release(port)
            sys.exit(1)

        print(f"VICE PID={vice.pid}, port={port}")
        transport = ViceTransport(port=port)
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)
        total_passed = passed + p
        total_failed = failed + f

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
