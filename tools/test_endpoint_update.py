#!/usr/bin/env python3
"""test_endpoint_update.py — Endpoint roaming tests.

Tests that endpoint_update correctly updates wg_peer_ip and wg_peer_port
when the source IP or port of a received packet differs from the stored peer.

Usage:
    python3 tools/test_endpoint_update.py [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
import time

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
# Test groups
# ============================================================================

def test_build_verification(labels):
    """Verify new labels exist in the build."""
    passed = failed = 0

    required_labels = [
        "endpoint_update",
        "udp_recv_src_port",
        "udp_recv_src_ip",
        "wg_peer_ip",
        "wg_peer_port",
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

    # udp_recv_src_port should be right after udp_recv_src_ip (4 bytes)
    src_ip = labels.address("udp_recv_src_ip")
    src_port = labels.address("udp_recv_src_port")
    if src_ip is not None and src_port is not None:
        if src_port == src_ip + 4:
            passed += 1
            if VERBOSE:
                print(f"  PASS udp_recv_src_port at src_ip+4")
        else:
            failed += 1
            print(f"  FAIL udp_recv_src_port=${src_port:04X} != src_ip+4=${src_ip+4:04X}")

    return passed, failed


def test_different_ip_updates(transport, labels):
    """Test that different source IP causes peer update."""
    passed = failed = 0

    # Set initial peer IP and port
    initial_ip = bytes([10, 0, 0, 1])
    initial_port = bytes([0xCA, 0x6C])  # big-endian port 51820
    write_bytes(transport, labels["wg_peer_ip"], initial_ip)
    write_bytes(transport, labels["wg_peer_port"], initial_port)

    # Set different source IP, same port
    new_ip = bytes([192, 168, 1, 100])
    write_bytes(transport, labels["udp_recv_src_ip"], new_ip)
    write_bytes(transport, labels["udp_recv_src_port"], initial_port)

    robust_jsr(transport, labels["endpoint_update"])

    # Verify peer IP was updated
    result_ip = read_bytes(transport, labels["wg_peer_ip"], 4)
    result_port = read_bytes(transport, labels["wg_peer_port"], 2)

    if result_ip == new_ip:
        passed += 1
        if VERBOSE:
            print("  PASS different IP updates wg_peer_ip")
    else:
        failed += 1
        print(f"  FAIL different IP: expected {new_ip.hex()}, got {result_ip.hex()}")

    if result_port == initial_port:
        passed += 1
        if VERBOSE:
            print("  PASS port unchanged when only IP differs")
    else:
        failed += 1
        print(f"  FAIL port changed: expected {initial_port.hex()}, got {result_port.hex()}")

    return passed, failed


def test_different_port_updates(transport, labels):
    """Test that different source port causes peer update."""
    passed = failed = 0

    # Set initial peer IP and port
    initial_ip = bytes([10, 0, 0, 1])
    initial_port = bytes([0xCA, 0x6C])  # 51820 big-endian
    write_bytes(transport, labels["wg_peer_ip"], initial_ip)
    write_bytes(transport, labels["wg_peer_port"], initial_port)

    # Set same IP, different port
    new_port = bytes([0x1F, 0x90])  # 8080 big-endian
    write_bytes(transport, labels["udp_recv_src_ip"], initial_ip)
    write_bytes(transport, labels["udp_recv_src_port"], new_port)

    robust_jsr(transport, labels["endpoint_update"])

    result_ip = read_bytes(transport, labels["wg_peer_ip"], 4)
    result_port = read_bytes(transport, labels["wg_peer_port"], 2)

    if result_port == new_port:
        passed += 1
        if VERBOSE:
            print("  PASS different port updates wg_peer_port")
    else:
        failed += 1
        print(f"  FAIL different port: expected {new_port.hex()}, got {result_port.hex()}")

    if result_ip == initial_ip:
        passed += 1
        if VERBOSE:
            print("  PASS IP unchanged when only port differs")
    else:
        failed += 1
        print(f"  FAIL IP changed: expected {initial_ip.hex()}, got {result_ip.hex()}")

    return passed, failed


def test_same_endpoint_no_change(transport, labels):
    """Test that same IP+port causes no writes (values stay the same)."""
    passed = failed = 0

    ip_val = bytes([172, 16, 0, 5])
    port_val = bytes([0xCA, 0x6C])

    # Set peer and source to same values
    write_bytes(transport, labels["wg_peer_ip"], ip_val)
    write_bytes(transport, labels["wg_peer_port"], port_val)
    write_bytes(transport, labels["udp_recv_src_ip"], ip_val)
    write_bytes(transport, labels["udp_recv_src_port"], port_val)

    robust_jsr(transport, labels["endpoint_update"])

    result_ip = read_bytes(transport, labels["wg_peer_ip"], 4)
    result_port = read_bytes(transport, labels["wg_peer_port"], 2)

    if result_ip == ip_val and result_port == port_val:
        passed += 1
        if VERBOSE:
            print("  PASS same endpoint: no change")
    else:
        failed += 1
        print(f"  FAIL same endpoint changed: ip={result_ip.hex()}, port={result_port.hex()}")

    return passed, failed


def test_both_ip_and_port_change(transport, labels):
    """Test that both IP and port update when both differ."""
    passed = failed = 0

    # Initial
    write_bytes(transport, labels["wg_peer_ip"], bytes([10, 0, 0, 1]))
    write_bytes(transport, labels["wg_peer_port"], bytes([0xCA, 0x6C]))

    # New source: completely different
    new_ip = bytes([203, 0, 113, 42])
    new_port = bytes([0xBB, 0x01])
    write_bytes(transport, labels["udp_recv_src_ip"], new_ip)
    write_bytes(transport, labels["udp_recv_src_port"], new_port)

    robust_jsr(transport, labels["endpoint_update"])

    result_ip = read_bytes(transport, labels["wg_peer_ip"], 4)
    result_port = read_bytes(transport, labels["wg_peer_port"], 2)

    if result_ip == new_ip:
        passed += 1
        if VERBOSE:
            print("  PASS both changed: IP updated")
    else:
        failed += 1
        print(f"  FAIL both changed IP: expected {new_ip.hex()}, got {result_ip.hex()}")

    if result_port == new_port:
        passed += 1
        if VERBOSE:
            print("  PASS both changed: port updated")
    else:
        failed += 1
        print(f"  FAIL both changed port: expected {new_port.hex()}, got {result_port.hex()}")

    return passed, failed


def test_source_port_capture(transport, labels):
    """Test that net_udp_recv_cb captures source port from UDP header."""
    passed = failed = 0

    # We need ip65_udp_inp address to write test data
    udp_inp = labels.address("ip65_udp_inp")
    if udp_inp is None:
        print("  SKIP: ip65_udp_inp label not found")
        return 0, 0

    # Build a minimal fake UDP packet at ip65_udp_inp:
    # bytes 0-1: source port (big-endian)
    # bytes 2-3: dest port
    # bytes 4-5: length (big-endian, includes 8-byte header)
    # bytes 6-7: checksum
    # bytes 8+:  payload
    src_port_be = bytes([0xCA, 0x6C])  # 51820
    dest_port_be = bytes([0x1F, 0x90])
    payload = b"TEST"
    udp_len = 8 + len(payload)
    udp_header = src_port_be + dest_port_be + struct.pack('>H', udp_len) + b'\x00\x00'
    udp_packet = udp_header + payload

    # Also need a fake source IP at ip65_udp_inp - 8
    fake_src_ip = bytes([10, 0, 0, 99])
    write_bytes(transport, udp_inp - 8, fake_src_ip + bytes(4))  # src IP + padding

    # Write the UDP packet data
    write_bytes(transport, udp_inp, udp_packet)

    # Clear current values
    write_bytes(transport, labels["udp_recv_src_port"], bytes(2))
    write_bytes(transport, labels["udp_recv_ready"], bytes(1))

    # Call the callback
    net_udp_recv_cb = labels.address("net_udp_recv_cb")
    if net_udp_recv_cb is None:
        print("  SKIP: net_udp_recv_cb label not found")
        return 0, 0

    robust_jsr(transport, net_udp_recv_cb)

    # Check source port was captured
    result_port = read_bytes(transport, labels["udp_recv_src_port"], 2)
    if result_port == src_port_be:
        passed += 1
        if VERBOSE:
            print(f"  PASS source port captured: {result_port.hex()}")
    else:
        failed += 1
        print(f"  FAIL source port: expected {src_port_be.hex()}, got {result_port.hex()}")

    # Also verify source IP was captured
    result_ip = read_bytes(transport, labels["udp_recv_src_ip"], 4)
    if result_ip == fake_src_ip:
        passed += 1
        if VERBOSE:
            print(f"  PASS source IP still captured correctly")
    else:
        failed += 1
        print(f"  FAIL source IP: expected {fake_src_ip.hex()}, got {result_ip.hex()}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels):
    """Run all test groups."""
    total_passed = total_failed = 0

    groups = [
        ("different IP updates", lambda: test_different_ip_updates(transport, labels)),
        ("different port updates", lambda: test_different_port_updates(transport, labels)),
        ("same endpoint no change", lambda: test_same_endpoint_no_change(transport, labels)),
        ("both IP and port change", lambda: test_both_ip_and_port_change(transport, labels)),
        ("source port capture", lambda: test_source_port_capture(transport, labels)),
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
    global VERBOSE
    for arg in args:
        if arg == "--verbose":
            VERBOSE = True

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

        passed, failed = run_tests(transport, labels)
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
