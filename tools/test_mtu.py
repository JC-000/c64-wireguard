#!/usr/bin/env python3
"""test_mtu.py — MTU enhancement tests for >255 byte payloads.

Tests that transport_encrypt and transport_decrypt correctly handle
payloads from 256 to 1400 bytes using 16-bit length fields and copy loops.

Usage:
    python3 tools/test_mtu.py [--seed S] [--verbose]
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


def robust_jsr(transport, addr, timeout=30.0, retries=5, poll_interval=0.2):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout, poll_interval=poll_interval)
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


def py_decrypt(key, counter_val, ciphertext, tag):
    """Decrypt using ChaCha20-Poly1305 with WireGuard transport nonce."""
    nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext + tag, None)


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
    """Verify MTU-related labels and memory layout."""
    passed = failed = 0

    # tp_packet + 1500 must be below $7800
    tp_packet_addr = labels.address("tp_packet")
    if tp_packet_addr is not None and tp_packet_addr + 1500 < 0x7800:
        passed += 1
        if VERBOSE:
            print(f"  PASS tp_packet ${tp_packet_addr:04X} + 1500 "
                  f"= ${tp_packet_addr+1500:04X} < $7800")
    else:
        failed += 1
        addr_str = f"${tp_packet_addr:04X}" if tp_packet_addr else "None"
        print(f"  FAIL tp_packet {addr_str} + 1500 would exceed $7800")

    # udp_recv_buf + 1500 must be below $7800
    udp_buf_addr = labels.address("udp_recv_buf")
    if udp_buf_addr is not None and udp_buf_addr + 1500 < 0x7800:
        passed += 1
        if VERBOSE:
            print(f"  PASS udp_recv_buf ${udp_buf_addr:04X} + 1500 "
                  f"= ${udp_buf_addr+1500:04X} < $7800")
    else:
        failed += 1
        addr_str = f"${udp_buf_addr:04X}" if udp_buf_addr else "None"
        print(f"  FAIL udp_recv_buf {addr_str} + 1500 would exceed $7800")

    # cc20_remain_hi must exist
    hi_addr = labels.address("cc20_remain_hi")
    if hi_addr is not None:
        passed += 1
        if VERBOSE:
            print(f"  PASS cc20_remain_hi = ${hi_addr:04X}")
    else:
        failed += 1
        print("  FAIL cc20_remain_hi label not found")

    # tp_payload_len must be 2 bytes (word)
    # Verify by checking that tp_packet follows tp_payload_len by 2
    pl_addr = labels.address("tp_payload_len")
    if pl_addr is not None and tp_packet_addr is not None:
        gap = tp_packet_addr - pl_addr
        if gap == 2:
            passed += 1
            if VERBOSE:
                print(f"  PASS tp_payload_len is 2 bytes (gap={gap})")
        else:
            failed += 1
            print(f"  FAIL tp_payload_len gap to tp_packet is {gap}, expected 2")

    return passed, failed


def test_encrypt_large(transport, labels, rng):
    """Test encryption of payloads >255 bytes against Python reference."""
    passed = failed = 0

    sizes = [256, 500, 1000, 1400]

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

        # Write plaintext to udp_recv_buf (large scratch area)
        write_bytes(transport, labels["udp_recv_buf"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["udp_recv_buf"]))
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', size))

        timeout = 120.0 if size >= 1000 else 90.0
        robust_jsr(transport, labels["transport_encrypt"], timeout=timeout, poll_interval=2.0)

        # Read total packet length
        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        expected_len = 16 + size + 16

        if pkt_len != expected_len:
            failed += 1
            print(f"  FAIL encrypt {size}B: "
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
            print(f"  FAIL encrypt {size}B: type={pkt_type}, expected=4")
            continue

        if pkt_recv_idx != receiver_idx:
            failed += 1
            print(f"  FAIL encrypt {size}B: receiver_idx mismatch")
            continue

        if pkt_counter != counter_val:
            failed += 1
            print(f"  FAIL encrypt {size}B: counter mismatch")
            continue

        # Verify ciphertext+tag against Python
        ct_tag = packet[16:]
        py_ct, py_tag = py_encrypt(key, counter_val, plaintext)

        if ct_tag == py_ct + py_tag:
            passed += 1
            if VERBOSE:
                print(f"  PASS encrypt {size}B: crypto matches Python")
        else:
            failed += 1
            # Find first diff
            expected = py_ct + py_tag
            for j in range(min(len(ct_tag), len(expected))):
                if ct_tag[j] != expected[j]:
                    print(f"  FAIL encrypt {size}B: first diff at byte {j}")
                    break
            else:
                print(f"  FAIL encrypt {size}B: length mismatch "
                      f"c64={len(ct_tag)} py={len(expected)}")

    return passed, failed


def test_decrypt_large(transport, labels, rng):
    """Test decryption of Python-encrypted large packets."""
    passed = failed = 0

    sizes = [256, 500, 1000, 1400]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = i
        our_sender_idx = bytes(rng.randint(0, 255) for _ in range(4))

        # Build packet with Python
        packet = build_type4_packet(our_sender_idx, counter_val, key, plaintext)

        # Set up C64 state
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["tp_recv_counter"], bytes(8))

        # Write packet to udp_recv_buf
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(packet)))

        timeout = 120.0 if size >= 1000 else 90.0
        robust_jsr(transport, labels["transport_decrypt"], timeout=timeout, poll_interval=2.0)

        # Check result
        result_len = int.from_bytes(
            read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        result_data = read_bytes(transport, labels["tp_packet"] + 16, size)

        if result_len == size and result_data == plaintext:
            passed += 1
            if VERBOSE:
                print(f"  PASS decrypt {size}B")
        else:
            failed += 1
            print(f"  FAIL decrypt {size}B:")
            if result_len != size:
                print(f"    len: got {result_len}, expected {size}")
            if result_data != plaintext:
                for j in range(min(len(result_data), len(plaintext))):
                    if result_data[j] != plaintext[j]:
                        print(f"    first diff at byte {j}: "
                              f"got 0x{result_data[j]:02X}, "
                              f"expected 0x{plaintext[j]:02X}")
                        break

    return passed, failed


def test_round_trip_large(transport, labels, rng):
    """Test encrypt then decrypt round-trip for large payloads."""
    passed = failed = 0

    sizes = [256, 500, 1000]

    for i, size in enumerate(sizes):
        if i > 0:
            time.sleep(1.0)

        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        receiver_idx = bytes([i + 1, 0, 0, 0])

        # Set up for encrypt
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_send_counter"], bytes(8))

        # Write plaintext to udp_recv_buf (using as scratch)
        write_bytes(transport, labels["udp_recv_buf"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["udp_recv_buf"]))
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', size))

        timeout = 120.0 if size >= 1000 else 90.0
        robust_jsr(transport, labels["transport_encrypt"], timeout=timeout, poll_interval=2.0)

        # Read the encrypted packet
        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        packet = read_bytes(transport, labels["tp_packet"], pkt_len)

        # Now set up for decrypt
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["tp_recv_counter"], bytes(8))

        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', pkt_len))

        robust_jsr(transport, labels["transport_decrypt"], timeout=timeout, poll_interval=2.0)

        # Verify round-trip
        result_len = int.from_bytes(
            read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        result_data = read_bytes(transport, labels["tp_packet"] + 16, size)

        if result_len == size and result_data == plaintext:
            passed += 1
            if VERBOSE:
                print(f"  PASS round-trip {size}B")
        else:
            failed += 1
            print(f"  FAIL round-trip {size}B:")
            if result_len != size:
                print(f"    len: got {result_len}, expected {size}")
            if result_data != plaintext:
                for j in range(min(len(result_data), len(plaintext))):
                    if result_data[j] != plaintext[j]:
                        print(f"    first diff at byte {j}")
                        break

    return passed, failed


def test_python_reference_large(transport, labels, rng):
    """Encrypt on C64, verify with Python for large payloads."""
    passed = failed = 0

    sizes = [256, 500, 1000]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = rng.randint(0, 0xFFFF)

        # Encrypt on C64
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], b'\x01\x00\x00\x00')
        write_bytes(transport, labels["tp_send_counter"],
                    struct.pack('<Q', counter_val))

        write_bytes(transport, labels["udp_recv_buf"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["udp_recv_buf"]))
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', size))

        timeout = 120.0 if size >= 1000 else 90.0
        robust_jsr(transport, labels["transport_encrypt"], timeout=timeout, poll_interval=2.0)

        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        packet = read_bytes(transport, labels["tp_packet"], pkt_len)

        # Decrypt with Python
        ct = packet[16:-16]
        tag = packet[-16:]
        try:
            decrypted = py_decrypt(key, counter_val, ct, tag)
            if decrypted == plaintext:
                passed += 1
                if VERBOSE:
                    print(f"  PASS py-verify {size}B")
            else:
                failed += 1
                print(f"  FAIL py-verify {size}B: plaintext mismatch")
        except Exception as e:
            failed += 1
            print(f"  FAIL py-verify {size}B: Python decrypt failed: {e}")

    return passed, failed


def test_regression_small(transport, labels, rng):
    """Regression: verify small payloads still work correctly."""
    passed = failed = 0

    sizes = [0, 1, 16, 64, 200]

    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = i

        # Build packet with Python
        packet = build_type4_packet(b'\x01\x00\x00\x00', counter_val,
                                    key, plaintext)

        # Set up C64
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["tp_recv_counter"], bytes(8))
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(packet)))

        robust_jsr(transport, labels["transport_decrypt"], timeout=60.0)

        result_len = int.from_bytes(
            read_bytes(transport, labels["tp_payload_len"], 2), 'little')

        if size == 0:
            # Keepalive: payload_len should be 0
            if result_len == 0:
                passed += 1
                if VERBOSE:
                    print(f"  PASS regression: keepalive (0B)")
            else:
                failed += 1
                print(f"  FAIL regression: keepalive len={result_len}")
        else:
            result_data = read_bytes(transport, labels["tp_packet"] + 16, size)
            if result_len == size and result_data == plaintext:
                passed += 1
                if VERBOSE:
                    print(f"  PASS regression: {size}B")
            else:
                failed += 1
                print(f"  FAIL regression: {size}B "
                      f"(len={result_len}, expected={size})")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all MTU test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("regression small payloads",
         lambda: test_regression_small(transport, labels, rng)),
        ("encrypt large payloads",
         lambda: test_encrypt_large(transport, labels, rng)),
        ("decrypt large payloads",
         lambda: test_decrypt_large(transport, labels, rng)),
        ("round-trip large",
         lambda: test_round_trip_large(transport, labels, rng)),
        ("Python reference verify",
         lambda: test_python_reference_large(transport, labels, rng)),
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
    seed = 1500
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

    # Build verification (no VICE needed)
    print("\n--- build verification ---")
    p, f = test_build_verification(labels)
    print(f"  {p} passed, {f} failed")
    if f > 0:
        print("FATAL: Build verification failed")
        sys.exit(1)

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
