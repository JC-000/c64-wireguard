#!/usr/bin/env python3
"""test_mtu.py — MTU enhancement tests for >255 byte payloads.

Tests that transport_encrypt and transport_decrypt correctly handle
16-bit payload lengths (256-1400 bytes) after the MTU enhancement.
Also regression-tests small payloads (0-200 bytes).

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
    read_bytes, write_bytes, wait_for_text,
)
from c64_test_harness.execute import set_register
from c64_test_harness.transport import (
    TimeoutError as HarnessTimeoutError,
    ConnectionError as TransportConnectionError,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False


# ---------------------------------------------------------------------------
# Flag-based jsr() — reliable replacement for breakpoint-based jsr()
# ---------------------------------------------------------------------------

def jsr_flag(transport, addr, timeout=10.0, scratch_addr=0x0334,
             poll_interval=0.5):
    """Call a subroutine at *addr* using flag-based completion detection.

    Uses a trampoline that sets a flag byte after the subroutine returns.
    Polls the flag via memory reads instead of using breakpoints.  This
    avoids VICE's text monitor becoming unresponsive during long warp-mode
    computations.
    """
    lo = addr & 0xFF
    hi = (addr >> 8) & 0xFF
    flag_addr = scratch_addr + 16
    loop_addr = scratch_addr + 15
    trampoline = bytes([
        0xA9, 0x00,
        0x8D, flag_addr & 0xFF, (flag_addr >> 8) & 0xFF,
        0x20, lo, hi,
        0xA9, 0xFF,
        0x8D, flag_addr & 0xFF, (flag_addr >> 8) & 0xFF,
        0x4C, loop_addr & 0xFF, (loop_addr >> 8) & 0xFF,
        0x00,
    ])
    transport.write_memory(scratch_addr, trampoline)
    transport.write_memory(flag_addr, bytes([0x00]))
    set_register(transport, "PC", scratch_addr)

    deadline = time.monotonic() + timeout
    while True:
        time.sleep(poll_interval)
        if time.monotonic() >= deadline:
            raise HarnessTimeoutError(
                f"JSR ${addr:04X} did not return within {timeout}s"
            )
        try:
            data = transport.read_memory(flag_addr, 1)
            if data[0] == 0xFF:
                try:
                    return transport.read_registers()
                except TransportConnectionError:
                    return {}
        except TransportConnectionError:
            continue


def robust_jsr(transport, addr, timeout=10.0, retries=3, poll_interval=0.5):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr_flag(transport, addr, timeout=timeout,
                            poll_interval=poll_interval)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.3)
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


def reset_transport_state(transport, labels):
    """Reset all transport state for a fresh encrypt or decrypt."""
    write_bytes(transport, labels["tp_send_counter"], bytes(8))
    write_bytes(transport, labels["tp_recv_counter"], bytes(8))
    write_bytes(transport, labels["tp_payload_len"], struct.pack('<H', 0))
    if "rw_counter_max" in labels:
        write_bytes(transport, labels["rw_counter_max"], bytes(8))
    if "rw_bitmap" in labels:
        write_bytes(transport, labels["rw_bitmap"], bytes(256))
    if "rw_new_counter" in labels:
        write_bytes(transport, labels["rw_new_counter"], bytes(1))


# ============================================================================
# Test functions — each returns (passed, failed)
# ============================================================================

def test_build_verification(labels):
    """Verify MTU-related labels and memory layout."""
    passed = failed = 0

    for name in ["transport_encrypt", "transport_decrypt",
                 "tp_payload_len", "tp_packet", "tp_packet_len",
                 "aead_data_len", "udp_recv_buf", "udp_recv_len"]:
        if labels.address(name) is not None:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL label '{name}' not found")

    # tp_packet must be below $7800
    tp = labels.address("tp_packet")
    if tp is not None and tp + 1500 < 0x7800:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL tp_packet buffer extends past $7800")

    # udp_recv_buf must fit 1500
    ub = labels.address("udp_recv_buf")
    if ub is not None and ub + 1500 < 0x7800:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL udp_recv_buf buffer extends past $7800")

    return passed, failed


def test_encrypt(transport, labels, rng, sizes):
    """Test encryption at given sizes against Python reference."""
    passed = failed = 0

    for size in sizes:
        key = bytes(rng.randint(0, 255) for _ in range(32))
        receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = rng.randint(0, 0xFFFF)

        reset_transport_state(transport, labels)
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_send_counter"],
                    struct.pack('<Q', counter_val))

        # Use udp_recv_buf as scratch for plaintext source
        write_bytes(transport, labels["udp_recv_buf"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["udp_recv_buf"]))
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', size))

        timeout = 30.0
        pi = 0.5
        robust_jsr(transport, labels["transport_encrypt"],
                   timeout=timeout, poll_interval=pi)

        pkt_len = int.from_bytes(
            read_bytes(transport, labels["tp_packet_len"], 2), 'little')
        expected_len = 16 + size + 16

        if pkt_len != expected_len:
            failed += 1
            print(f"  FAIL encrypt {size}B: pkt_len={pkt_len}, "
                  f"expected={expected_len}")
            continue

        packet = read_bytes(transport, labels["tp_packet"], pkt_len)
        py_ct, py_tag = py_encrypt(key, counter_val, plaintext)

        if packet[16:] == py_ct + py_tag:
            passed += 1
            if VERBOSE:
                print(f"  PASS encrypt {size}B")
        else:
            failed += 1
            print(f"  FAIL encrypt {size}B: crypto mismatch")

    return passed, failed


def test_decrypt(transport, labels, rng, sizes):
    """Test decryption of Python-encrypted packets at given sizes."""
    passed = failed = 0

    for size in sizes:
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = 0

        packet = build_type4_packet(b'\x01\x00\x00\x00', counter_val,
                                    key, plaintext)

        reset_transport_state(transport, labels)
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(packet)))

        timeout = 30.0
        pi = 0.5
        robust_jsr(transport, labels["transport_decrypt"],
                   timeout=timeout, poll_interval=pi)

        result_len = int.from_bytes(
            read_bytes(transport, labels["tp_payload_len"], 2), 'little')

        if size == 0:
            if result_len == 0:
                passed += 1
                if VERBOSE:
                    print(f"  PASS decrypt keepalive (0B)")
            else:
                failed += 1
                print(f"  FAIL decrypt keepalive: len={result_len}")
        else:
            result_data = read_bytes(transport, labels["tp_packet"] + 16,
                                     size)
            if result_len == size and result_data == plaintext:
                passed += 1
                if VERBOSE:
                    print(f"  PASS decrypt {size}B")
            else:
                failed += 1
                print(f"  FAIL decrypt {size}B: "
                      f"len={result_len}, expected={size}")

    return passed, failed


def test_round_trip(transport, labels, rng, sizes):
    """Test encrypt-then-decrypt round trip on C64."""
    passed = failed = 0

    for size in sizes:
        key = bytes(rng.randint(0, 255) for _ in range(32))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        receiver_idx = bytes([0x01, 0x00, 0x00, 0x00])

        # Encrypt
        reset_transport_state(transport, labels)
        write_bytes(transport, labels["hs_transport_send"], key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)

        write_bytes(transport, labels["udp_recv_buf"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["udp_recv_buf"]))
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', size))

        timeout = 30.0
        pi = 0.5
        robust_jsr(transport, labels["transport_encrypt"],
                   timeout=timeout, poll_interval=pi)

        pkt_len = int.from_bytes(
            read_bytes(transport, labels["tp_packet_len"], 2), 'little')
        packet = read_bytes(transport, labels["tp_packet"], pkt_len)

        # Decrypt
        reset_transport_state(transport, labels)
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["udp_recv_buf"], packet)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', pkt_len))

        robust_jsr(transport, labels["transport_decrypt"],
                   timeout=timeout, poll_interval=pi)

        result_len = int.from_bytes(
            read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        result_data = read_bytes(transport, labels["tp_packet"] + 16, size)

        if result_len == size and result_data == plaintext:
            passed += 1
            if VERBOSE:
                print(f"  PASS round-trip {size}B")
        else:
            failed += 1
            print(f"  FAIL round-trip {size}B: "
                  f"len={result_len}, expected={size}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all MTU test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("small encrypt (regression)",
         lambda: test_encrypt(transport, labels, rng,
                              [0, 1, 16, 64, 200])),
        ("small decrypt (regression)",
         lambda: test_decrypt(transport, labels, rng,
                              [0, 1, 16, 64, 200])),
        ("large encrypt",
         lambda: test_encrypt(transport, labels, rng,
                              [256, 500, 1000, 1300, 1400, 1468])),
        ("large decrypt",
         lambda: test_decrypt(transport, labels, rng,
                              [256, 500, 1000, 1300, 1400, 1468])),
        ("large round-trip",
         lambda: test_round_trip(transport, labels, rng,
                                 [256, 500, 1000, 1300, 1468])),
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

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True,
                        cwd=PROJECT_ROOT)
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
    bv_p, bv_f = test_build_verification(labels)
    print(f"  {bv_p} passed, {bv_f} failed")
    if bv_f > 0:
        print("FATAL: Build verification failed")
        sys.exit(1)

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True,
                        sound=False)

    with ViceInstanceManager(
        config=config,
        port_range_start=6510,
        port_range_end=6530,
    ) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0,
                             verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)
        total_passed = passed + bv_p
        total_failed = failed + bv_f

        mgr.release(inst)

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
