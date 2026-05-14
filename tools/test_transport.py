#!/usr/bin/env python3
"""test_transport.py — Direct-memory WireGuard transport packet tests.

Tests transport_init, counter_inc64, transport_build_nonce,
transport_encrypt, transport_decrypt, replay protection, and round-trip
against Python ChaCha20-Poly1305 reference.

Usage:
    python3 tools/test_transport.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_text

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False


def reset_recv_state(transport, labels):
    """Reset all receive/replay state (counter, sliding window bitmap, max)."""
    write_bytes(transport, labels["tp_recv_counter"], bytes(8))
    # Reset sliding window replay state
    if "rw_counter_max" in labels:
        write_bytes(transport, labels["rw_counter_max"], bytes(8))
    if "rw_bitmap" in labels:
        write_bytes(transport, labels["rw_bitmap"], bytes(256))


# ============================================================================
# Python reference helpers
# ============================================================================

def py_encrypt(key, counter_val, plaintext):
    """Encrypt using ChaCha20-Poly1305 with WireGuard transport nonce.

    Returns (ciphertext, tag) where ciphertext is len(plaintext) bytes
    and tag is 16 bytes.
    """
    nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
    aead = ChaCha20Poly1305(key)
    ct_and_tag = aead.encrypt(nonce, plaintext, None)  # no AAD
    return ct_and_tag[:-16], ct_and_tag[-16:]


def py_decrypt(key, counter_val, ciphertext, tag):
    """Decrypt using ChaCha20-Poly1305 with WireGuard transport nonce.

    Returns plaintext or raises on auth failure.
    """
    nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext + tag, None)


def build_type4_packet(receiver_idx, counter_val, key, plaintext):
    """Build a complete Type 4 packet using Python crypto."""
    ct, tag = py_encrypt(key, counter_val, plaintext)
    header = struct.pack('<I', 4)  # type = 4
    header += receiver_idx
    header += struct.pack('<Q', counter_val)
    return header + ct + tag


# ============================================================================
# Test groups
# ============================================================================

def test_build_verification(labels):
    """Verify new labels exist and memory layout is correct."""
    passed = failed = 0

    required_labels = [
        "transport_init", "counter_inc64", "transport_build_nonce",
        "transport_encrypt", "transport_decrypt", "transport_send",
        "tp_send_counter", "tp_recv_counter", "tp_recv_counter_tmp",
        "tp_peer_recv_idx", "tp_payload_ptr", "tp_payload_len",
        "tp_packet", "tp_packet_len",
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

    # tp_packet must be below $7800 (sqtab)
    tp_packet_addr = labels.address("tp_packet")
    if tp_packet_addr is not None and tp_packet_addr < 0x7800:
        passed += 1
        if VERBOSE:
            print(f"  PASS tp_packet ${tp_packet_addr:04X} < $7800")
    else:
        failed += 1
        addr_str = f"${tp_packet_addr:04X}" if tp_packet_addr else "None"
        print(f"  FAIL tp_packet {addr_str} not below $7800")

    # tp_packet + 1500 must be below $7800
    if tp_packet_addr is not None and tp_packet_addr + 1500 < 0x7800:
        passed += 1
        if VERBOSE:
            print(f"  PASS tp_packet end ${tp_packet_addr+1500:04X} < $7800")
    else:
        failed += 1
        print(f"  FAIL tp_packet buffer extends past $7800")

    # transport code should be after crypto (> $32F0)
    transport_init_addr = labels.address("transport_init")
    if transport_init_addr is not None and transport_init_addr > 0x32F0:
        passed += 1
        if VERBOSE:
            print(f"  PASS transport_init ${transport_init_addr:04X} > $32F0")
    else:
        failed += 1
        print(f"  FAIL transport_init not in crypto region")

    return passed, failed


def test_counter_inc64(transport, labels):
    """Test 64-bit counter increment with carry propagation."""
    passed = failed = 0

    test_cases = [
        # (initial, expected, description)
        (bytes(8), bytes([1,0,0,0,0,0,0,0]), "0 -> 1"),
        (bytes([0xFF,0,0,0,0,0,0,0]), bytes([0,1,0,0,0,0,0,0]), "$FF -> $100"),
        (bytes([0xFF,0xFF,0,0,0,0,0,0]), bytes([0,0,1,0,0,0,0,0]), "$FFFF -> $10000"),
        (bytes([0xFF,0xFF,0xFF,0,0,0,0,0]), bytes([0,0,0,1,0,0,0,0]), "$FFFFFF -> $1000000"),
        (bytes([0xFF,0xFF,0xFF,0xFF,0,0,0,0]), bytes([0,0,0,0,1,0,0,0]), "$FFFFFFFF -> $100000000"),
        (bytes([0xFF,0xFF,0xFF,0xFF,0xFF,0,0,0]), bytes([0,0,0,0,0,1,0,0]), "5-byte carry"),
        (bytes([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0]), bytes([0,0,0,0,0,0,1,0]), "6-byte carry"),
        (bytes([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0]), bytes([0,0,0,0,0,0,0,1]), "7-byte carry"),
    ]

    for initial, expected, desc in test_cases:
        # Write counter to tp_send_counter (reuse as scratch)
        write_bytes(transport, labels["tp_send_counter"], initial)

        # Point zp_ptr1 to tp_send_counter
        ptr_bytes = struct.pack('<H', labels["tp_send_counter"])
        write_bytes(transport, labels["zp_ptr1"], ptr_bytes)

        jsr(transport, labels["counter_inc64"])

        result = read_bytes(transport, labels["tp_send_counter"], 8)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS counter_inc64: {desc}")
        else:
            failed += 1
            print(f"  FAIL counter_inc64 {desc}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_transport_build_nonce(transport, labels):
    """Test nonce construction from counter."""
    passed = failed = 0

    test_cases = [
        (0, "counter=0"),
        (1, "counter=1"),
        (0x0102030405060708, "large counter"),
    ]

    for counter_val, desc in test_cases:
        counter_bytes = struct.pack('<Q', counter_val)
        write_bytes(transport, labels["tp_send_counter"], counter_bytes)

        ptr_bytes = struct.pack('<H', labels["tp_send_counter"])
        write_bytes(transport, labels["zp_ptr1"], ptr_bytes)

        jsr(transport, labels["transport_build_nonce"])

        nonce = read_bytes(transport, labels["aead_nonce"], 12)
        expected = b'\x00' * 4 + counter_bytes

        if nonce == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS build_nonce: {desc}")
        else:
            failed += 1
            print(f"  FAIL build_nonce {desc}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {nonce.hex()}")

    return passed, failed


def test_transport_encrypt(transport, labels, rng):
    """Test encryption against Python ChaCha20-Poly1305."""
    passed = failed = 0

    sizes = [1, 14, 32, 64, 128, 200]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = rng.randint(0, 0xFFFF)

        # Set up C64 state
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_send_counter"],
                    struct.pack('<Q', counter_val))

        # Write plaintext to input_buffer
        write_bytes(transport, labels["input_buffer"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["input_buffer"]))
        write_bytes(transport, labels["tp_payload_len"], struct.pack('<H', size))

        jsr(transport, labels["transport_encrypt"], timeout=60.0)

        # Read total packet length
        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        expected_len = 16 + size + 16

        if pkt_len != expected_len:
            failed += 1
            print(f"  FAIL encrypt #{i} ({size}B): "
                  f"pkt_len={pkt_len}, expected={expected_len}")
            continue

        # Read packet
        packet = read_bytes(transport, labels["tp_packet"], pkt_len)

        # Verify header
        pkt_type = struct.unpack('<I', packet[0:4])[0]
        pkt_recv_idx = packet[4:8]
        pkt_counter = struct.unpack('<Q', packet[8:16])[0]

        if pkt_type != 4:
            failed += 1
            print(f"  FAIL encrypt #{i}: type={pkt_type}, expected=4")
            continue

        if pkt_recv_idx != receiver_idx:
            failed += 1
            print(f"  FAIL encrypt #{i}: receiver_idx mismatch")
            continue

        if pkt_counter != counter_val:
            failed += 1
            print(f"  FAIL encrypt #{i}: counter={pkt_counter}, "
                  f"expected={counter_val}")
            continue

        # Verify ciphertext+tag against Python
        ct_tag = packet[16:]
        py_ct, py_tag = py_encrypt(key, counter_val, plaintext)

        if ct_tag == py_ct + py_tag:
            passed += 1
            if VERBOSE:
                print(f"  PASS encrypt #{i}: {size} bytes, "
                      f"counter={counter_val}")
        else:
            failed += 1
            print(f"  FAIL encrypt #{i} ({size}B): crypto mismatch")
            print(f"    py ct+tag: {(py_ct + py_tag).hex()}")
            print(f"    c64:       {ct_tag.hex()}")

        # Verify counter was incremented
        new_ctr = read_bytes(transport, labels["tp_send_counter"], 8)
        expected_ctr = struct.pack('<Q', counter_val + 1)
        if new_ctr != expected_ctr:
            print(f"  WARN encrypt #{i}: counter not incremented properly")

    return passed, failed


def test_transport_decrypt(transport, labels, rng):
    """Test decryption of Python-encrypted packets."""
    passed = failed = 0

    sizes = [1, 14, 32, 64, 128, 200]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = i  # sequential counters for replay protection
        our_sender_idx = bytes(rng.randint(0, 255) for _ in range(4))

        # Build packet with Python
        packet = build_type4_packet(our_sender_idx, counter_val, key, plaintext)

        # Set up C64 state
        write_bytes(transport, labels["hs_transport_recv"], key)
        reset_recv_state(transport, labels)

        # Write packet to udp_recv_buf
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(packet)))

        jsr(transport, labels["transport_decrypt"], timeout=60.0)

        # Check return value — read A from the last state
        # Actually we need to check tp_payload_len and the decrypted data
        result_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        result_data = read_bytes(transport, labels["tp_packet"] + 16, size)

        if result_len == size and result_data == plaintext:
            passed += 1
            if VERBOSE:
                print(f"  PASS decrypt #{i}: {size} bytes")
        else:
            failed += 1
            print(f"  FAIL decrypt #{i} ({size}B):")
            if result_len != size:
                print(f"    len: got {result_len}, expected {size}")
            if result_data != plaintext:
                # Find first diff
                for j in range(min(len(result_data), len(plaintext))):
                    if result_data[j] != plaintext[j]:
                        print(f"    first diff at byte {j}: "
                              f"got 0x{result_data[j]:02X}, "
                              f"expected 0x{plaintext[j]:02X}")
                        break

    return passed, failed


def test_decrypt_failures(transport, labels, rng):
    """Test that decryption rejects tampered/invalid packets."""
    passed = failed = 0
    key = bytes(rng.randint(0, 255) for _ in range(32))
    plaintext = b"HELLO WIREGUARD!"
    counter_val = 0

    # Reset recv counter
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # --- Test 1: Tampered ciphertext ---
    packet = bytearray(build_type4_packet(b'\x01\x02\x03\x04',
                                           counter_val, key, plaintext))
    packet[20] ^= 0xFF  # flip a ciphertext byte

    write_bytes(transport, labels["udp_recv_buf"], bytes(packet))
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))
    reset_recv_state(transport, labels)

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    # After decrypt, check a flag or read the payload_len
    # On failure, aead_decrypt returns A=$FF which transport_decrypt propagates
    # We need to verify failure by checking that something indicates error
    # Best approach: try reading tp_payload_len and see if data is NOT the plaintext
    # Actually, let's check via a different mechanism - write a known sentinel
    # before decrypt and verify it wasn't overwritten as success
    #
    # Better: on failure, transport_decrypt does NOT update tp_recv_counter
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == bytes(8):  # counter not updated = failure path taken
        passed += 1
        if VERBOSE:
            print("  PASS decrypt fail: tampered ciphertext")
    else:
        failed += 1
        print("  FAIL decrypt should reject tampered ciphertext")

    # --- Test 2: Tampered tag ---
    packet = bytearray(build_type4_packet(b'\x01\x02\x03\x04',
                                           counter_val, key, plaintext))
    packet[-1] ^= 0xFF  # flip last byte of tag

    write_bytes(transport, labels["udp_recv_buf"], bytes(packet))
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))
    reset_recv_state(transport, labels)

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == bytes(8):
        passed += 1
        if VERBOSE:
            print("  PASS decrypt fail: tampered tag")
    else:
        failed += 1
        print("  FAIL decrypt should reject tampered tag")

    # --- Test 3: Wrong key ---
    wrong_key = bytes(rng.randint(0, 255) for _ in range(32))
    packet = build_type4_packet(b'\x01\x02\x03\x04',
                                 counter_val, key, plaintext)

    write_bytes(transport, labels["hs_transport_recv"], wrong_key)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))
    reset_recv_state(transport, labels)

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == bytes(8):
        passed += 1
        if VERBOSE:
            print("  PASS decrypt fail: wrong key")
    else:
        failed += 1
        print("  FAIL decrypt should reject wrong key")

    # Restore correct key for remaining tests
    write_bytes(transport, labels["hs_transport_recv"], key)

    # --- Test 4: Wrong type byte ---
    packet = bytearray(build_type4_packet(b'\x01\x02\x03\x04',
                                           counter_val, key, plaintext))
    packet[0] = 0x01  # change type to 1

    write_bytes(transport, labels["udp_recv_buf"], bytes(packet))
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))
    reset_recv_state(transport, labels)

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == bytes(8):
        passed += 1
        if VERBOSE:
            print("  PASS decrypt fail: wrong type byte")
    else:
        failed += 1
        print("  FAIL decrypt should reject wrong type")

    return passed, failed


def test_replay_protection(transport, labels, rng):
    """Test that replay protection rejects out-of-order packets."""
    passed = failed = 0
    key = bytes(rng.randint(0, 255) for _ in range(32))
    plaintext = b"REPLAY TEST DATA"

    write_bytes(transport, labels["hs_transport_recv"], key)
    reset_recv_state(transport, labels)  # start at 0

    # --- Test 1: Accept counter=0 (first packet) ---
    packet = build_type4_packet(b'\x01\x00\x00\x00', 0, key, plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    expected_ctr = struct.pack('<Q', 1)  # should be 0+1=1
    if recv_ctr == expected_ctr:
        passed += 1
        if VERBOSE:
            print("  PASS replay: counter=0 accepted, next=1")
    else:
        failed += 1
        print(f"  FAIL replay: counter=0 not accepted, "
              f"recv_ctr={recv_ctr.hex()}")

    # --- Test 2: Accept counter=1 (sequential) ---
    packet = build_type4_packet(b'\x01\x00\x00\x00', 1, key, plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    expected_ctr = struct.pack('<Q', 2)
    if recv_ctr == expected_ctr:
        passed += 1
        if VERBOSE:
            print("  PASS replay: counter=1 accepted, next=2")
    else:
        failed += 1
        print(f"  FAIL replay: counter=1 not accepted, "
              f"recv_ctr={recv_ctr.hex()}")

    # --- Test 3: Reject counter=0 (replay) ---
    packet = build_type4_packet(b'\x01\x00\x00\x00', 0, key, plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == expected_ctr:  # should still be 2
        passed += 1
        if VERBOSE:
            print("  PASS replay: counter=0 rejected (replay)")
    else:
        failed += 1
        print(f"  FAIL replay: counter=0 should be rejected, "
              f"recv_ctr={recv_ctr.hex()}")

    # --- Test 4: Reject counter=1 (replay) ---
    packet = build_type4_packet(b'\x01\x00\x00\x00', 1, key, plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    if recv_ctr == expected_ctr:  # should still be 2
        passed += 1
        if VERBOSE:
            print("  PASS replay: counter=1 rejected (replay)")
    else:
        failed += 1
        print(f"  FAIL replay: counter=1 should be rejected, "
              f"recv_ctr={recv_ctr.hex()}")

    # --- Test 5: Accept counter=5 (skip ahead) ---
    packet = build_type4_packet(b'\x01\x00\x00\x00', 5, key, plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    jsr(transport, labels["transport_decrypt"], timeout=60.0)
    recv_ctr = read_bytes(transport, labels["tp_recv_counter"], 8)
    expected_ctr = struct.pack('<Q', 6)
    if recv_ctr == expected_ctr:
        passed += 1
        if VERBOSE:
            print("  PASS replay: counter=5 accepted (skip ahead), next=6")
    else:
        failed += 1
        print(f"  FAIL replay: counter=5 not accepted, "
              f"recv_ctr={recv_ctr.hex()}")

    return passed, failed


def test_round_trip(transport, labels, rng):
    """Test encrypt then decrypt round-trip on C64."""
    passed = failed = 0

    sizes = [1, 16, 32, 64, 200]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        receiver_idx = bytes([i + 1, 0, 0, 0])

        # Set up for encrypt
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_send_counter"], bytes(8))

        write_bytes(transport, labels["input_buffer"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["input_buffer"]))
        write_bytes(transport, labels["tp_payload_len"], struct.pack('<H', size))

        jsr(transport, labels["transport_encrypt"], timeout=60.0)

        # Read the encrypted packet
        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        packet = read_bytes(transport, labels["tp_packet"], pkt_len)

        # Now set up for decrypt — use same key as recv key
        write_bytes(transport, labels["hs_transport_recv"], key)
        reset_recv_state(transport, labels)

        # Copy packet to udp_recv_buf
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', pkt_len))

        jsr(transport, labels["transport_decrypt"], timeout=60.0)

        # Verify round-trip
        result_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        result_data = read_bytes(transport, labels["tp_packet"] + 16, size)

        if result_len == size and result_data == plaintext:
            passed += 1
            if VERBOSE:
                print(f"  PASS round-trip #{i}: {size} bytes")
        else:
            failed += 1
            print(f"  FAIL round-trip #{i} ({size}B):")
            if result_len != size:
                print(f"    len: got {result_len}, expected {size}")
            if result_data != plaintext:
                for j in range(min(len(result_data), len(plaintext))):
                    if result_data[j] != plaintext[j]:
                        print(f"    first diff at byte {j}")
                        break

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("counter_inc64", lambda: test_counter_inc64(transport, labels)),
        ("transport_build_nonce", lambda: test_transport_build_nonce(transport, labels)),
        ("transport_encrypt", lambda: test_transport_encrypt(transport, labels, rng)),
        ("transport_decrypt", lambda: test_transport_decrypt(transport, labels, rng)),
        ("decrypt failures", lambda: test_decrypt_failures(transport, labels, rng)),
        ("replay protection", lambda: test_replay_protection(transport, labels, rng)),
        ("round-trip", lambda: test_round_trip(transport, labels, rng)),
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

    return total_passed, total_failed


def main():
    args = sys.argv[1:]
    seed = 7539
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

    # Build verification (no VICE needed)
    print("\n--- build verification ---")
    p, f = test_build_verification(labels)
    print(f"  {p} passed, {f} failed")
    if f > 0:
        print("FATAL: Build verification failed")
        sys.exit(1)

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
        total_passed = passed + p
        total_failed = failed + f

        mgr.release(inst)

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
