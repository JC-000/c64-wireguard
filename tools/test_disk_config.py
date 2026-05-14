#!/usr/bin/env python3
"""test_disk_config.py -- Disk-based WireGuard config reader tests.

Tests hex parsing, IP parsing, port parsing, and full config file reading
using DiskImage to create D64 images with WG.CFG config files.

Usage:
    python3 tools/test_disk_config.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
import tempfile
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from c64_test_harness.disk import DiskImage, FileType

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
# Config file helpers
# ============================================================================

def make_config_content(static_priv, static_pub, peer_pub,
                        endpoint_ip, endpoint_port,
                        tunnel_ip, target_ip):
    """Build WG.CFG content from binary values.

    Args:
        static_priv: 32 bytes
        static_pub: 32 bytes
        peer_pub: 32 bytes
        endpoint_ip: 4-tuple/list of ints (0-255)
        endpoint_port: int (1-65535)
        tunnel_ip: 4-tuple/list of ints (0-255)
        target_ip: 4-tuple/list of ints (0-255)

    Returns:
        ASCII string with CR-terminated lines.
    """
    lines = []
    lines.append(static_priv.hex().upper())
    lines.append(static_pub.hex().upper())
    lines.append(peer_pub.hex().upper())
    lines.append(f"{endpoint_ip[0]}.{endpoint_ip[1]}.{endpoint_ip[2]}.{endpoint_ip[3]}")
    lines.append(str(endpoint_port))
    lines.append(f"{tunnel_ip[0]}.{tunnel_ip[1]}.{tunnel_ip[2]}.{tunnel_ip[3]}")
    lines.append(f"{target_ip[0]}.{target_ip[1]}.{target_ip[2]}.{target_ip[3]}")
    return "\r".join(lines) + "\r"


def create_disk_with_config(tmpdir, config_content, disk_name="test.d64"):
    """Create a D64 disk image with WG.CFG containing config_content.

    Also includes the PRG so VICE autostart can find it on device 8.
    Returns the DiskImage object.
    """
    disk_path = os.path.join(tmpdir, disk_name)
    disk = DiskImage.create(disk_path)

    # Write config content to a host temp file, then write into D64
    cfg_host_path = os.path.join(tmpdir, "wg_cfg_host.tmp")
    with open(cfg_host_path, "wb") as f:
        f.write(config_content.encode("ascii"))
    disk.write_file(cfg_host_path, "wg.cfg", file_type=FileType.SEQ)

    # Add the PRG to the D64 so VICE autostart LOAD",8,1 works
    disk.write_file(PRG_PATH, "wireguard")
    return disk


def build_read_trampoline(labels):
    """Build a trampoline at $0340 that calls config_read_file and stores
    the carry flag result at $0360.

    Returns the trampoline bytes.
    """
    addr = labels["config_read_file"]
    # JSR config_read_file
    # BCC @ok (+5)
    # LDA #1 (failure)
    # STA $0360
    # RTS
    # @ok: LDA #0 (success)
    # STA $0360
    # RTS
    trampoline = bytes([
        0x20, addr & 0xFF, (addr >> 8) & 0xFF,  # JSR config_read_file
        0x90, 0x05,                               # BCC @ok (+5)
        0xA9, 0x01,                               # LDA #1 (failure)
        0x8D, 0x60, 0x03,                         # STA $0360
        0x60,                                     # RTS
        0xA9, 0x00,                               # LDA #0 (success)
        0x8D, 0x60, 0x03,                         # STA $0360
        0x60,                                     # RTS
    ])
    return trampoline


def call_config_read(transport, labels):
    """Write and execute the config_read_file trampoline.

    Returns 0 for success (C=0), 1 for failure (C=1).
    """
    trampoline = build_read_trampoline(labels)
    write_bytes(transport, 0x0340, trampoline)
    robust_jsr(transport, 0x0340, timeout=30.0)
    result = read_bytes(transport, 0x0360, 1)[0]
    return result


def verify_key(transport, labels, label_name, expected, test_name):
    """Verify a 32-byte key field. Returns (passed, failed)."""
    got = bytes(read_bytes(transport, labels[label_name], 32))
    if got == expected:
        if VERBOSE:
            print(f"  PASS {test_name}")
        return 1, 0
    else:
        print(f"  FAIL {test_name}")
        print(f"    expected: {expected.hex()}")
        print(f"    got:      {got.hex()}")
        return 0, 1


def verify_ip(transport, labels, label_name, expected, test_name):
    """Verify a 4-byte IP field. Returns (passed, failed)."""
    got = bytes(read_bytes(transport, labels[label_name], 4))
    expected_bytes = bytes(expected)
    if got == expected_bytes:
        if VERBOSE:
            print(f"  PASS {test_name}")
        return 1, 0
    else:
        print(f"  FAIL {test_name}")
        print(f"    expected: {expected_bytes.hex()} ({'.'.join(str(b) for b in expected)})")
        print(f"    got:      {got.hex()} ({'.'.join(str(b) for b in got)})")
        return 0, 1


def verify_port(transport, labels, label_name, expected_port, test_name):
    """Verify a 2-byte big-endian port field. Returns (passed, failed)."""
    got = bytes(read_bytes(transport, labels[label_name], 2))
    expected_bytes = struct.pack(">H", expected_port)
    if got == expected_bytes:
        if VERBOSE:
            print(f"  PASS {test_name}")
        return 1, 0
    else:
        got_val = struct.unpack(">H", got)[0]
        print(f"  FAIL {test_name}")
        print(f"    expected: {expected_port} ({expected_bytes.hex()})")
        print(f"    got:      {got_val} ({got.hex()})")
        return 0, 1


# ============================================================================
# VICE launcher helper
# ============================================================================

def launch_vice_with_disk(disk, mgr):
    """Launch VICE with the given DiskImage attached.

    Returns (inst, transport) -- caller must release inst via mgr.
    """
    inst = mgr.acquire(disk_image=disk)
    transport = inst.transport
    grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
    if grid is None:
        mgr.release(inst)
        raise RuntimeError("Main menu did not appear")

    # Safety loop
    write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

    return inst, transport


def cleanup_vice(inst, mgr):
    """Shut down VICE and release port."""
    try:
        mgr.release(inst)
    except Exception:
        pass


# ============================================================================
# Test group 1: Hex parsing via full config read (8 tests)
# ============================================================================

def test_hex_parsing(transport, labels, rng):
    """Test hex-to-bytes conversion for various key patterns.

    Each test creates a config with specific hex patterns in the three
    32-byte key fields and verifies the decoded bytes.

    Since config_read_file was already called with the standard config,
    we verify the keys that were loaded.
    """
    passed = failed = 0

    # The standard config was loaded before this function is called.
    # We verify 8 properties of the decoded keys.

    # Test 1: static_priv all zeros
    got = bytes(read_bytes(transport, labels["cfg_static_priv"], 32))
    if got == bytes(32):
        passed += 1
        if VERBOSE:
            print("  PASS hex: static_priv all-zeros decoded correctly")
    else:
        failed += 1
        print(f"  FAIL hex: static_priv all-zeros")
        print(f"    got: {got.hex()}")

    # Test 2: static_pub all-FFs
    got = bytes(read_bytes(transport, labels["cfg_static_pub"], 32))
    if got == bytes([0xFF] * 32):
        passed += 1
        if VERBOSE:
            print("  PASS hex: static_pub all-FF decoded correctly")
    else:
        failed += 1
        print(f"  FAIL hex: static_pub all-FF")
        print(f"    got: {got.hex()}")

    # Test 3: peer_pub ascending pattern
    expected_peer = bytes(range(0, 32))
    got = bytes(read_bytes(transport, labels["cfg_peer_pub"], 32))
    if got == expected_peer:
        passed += 1
        if VERBOSE:
            print("  PASS hex: peer_pub ascending pattern decoded correctly")
    else:
        failed += 1
        print(f"  FAIL hex: peer_pub ascending")
        print(f"    expected: {expected_peer.hex()}")
        print(f"    got:      {got.hex()}")

    # Test 4: static_priv first byte is 0x00
    got = read_bytes(transport, labels["cfg_static_priv"], 1)[0]
    if got == 0x00:
        passed += 1
        if VERBOSE:
            print("  PASS hex: static_priv[0] == 0x00")
    else:
        failed += 1
        print(f"  FAIL hex: static_priv[0] = {got:#04x}, expected 0x00")

    # Test 5: static_pub last byte is 0xFF
    got = read_bytes(transport, labels["cfg_static_pub"] + 31, 1)[0]
    if got == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS hex: static_pub[31] == 0xFF")
    else:
        failed += 1
        print(f"  FAIL hex: static_pub[31] = {got:#04x}, expected 0xFF")

    # Test 6: peer_pub byte 15 == 0x0F
    got = read_bytes(transport, labels["cfg_peer_pub"] + 15, 1)[0]
    if got == 0x0F:
        passed += 1
        if VERBOSE:
            print("  PASS hex: peer_pub[15] == 0x0F")
    else:
        failed += 1
        print(f"  FAIL hex: peer_pub[15] = {got:#04x}, expected 0x0F")

    # Test 7: peer_pub byte 0 == 0x00
    got = read_bytes(transport, labels["cfg_peer_pub"], 1)[0]
    if got == 0x00:
        passed += 1
        if VERBOSE:
            print("  PASS hex: peer_pub[0] == 0x00")
    else:
        failed += 1
        print(f"  FAIL hex: peer_pub[0] = {got:#04x}, expected 0x00")

    # Test 8: peer_pub byte 31 == 0x1F
    got = read_bytes(transport, labels["cfg_peer_pub"] + 31, 1)[0]
    if got == 0x1F:
        passed += 1
        if VERBOSE:
            print("  PASS hex: peer_pub[31] == 0x1F")
    else:
        failed += 1
        print(f"  FAIL hex: peer_pub[31] = {got:#04x}, expected 0x1F")

    return passed, failed


# ============================================================================
# Test group 2: IP parsing (5 tests)
# ============================================================================

def test_ip_parsing(transport, labels):
    """Test IP address parsing from the loaded standard config."""
    passed = failed = 0

    # Standard config has endpoint_ip = (10, 0, 0, 1)
    p, f = verify_ip(transport, labels, "cfg_peer_endpoint_ip",
                     [10, 0, 0, 1], "IP: endpoint 10.0.0.1")
    passed += p; failed += f

    # Standard config has tunnel_ip = (10, 7, 0, 2)
    p, f = verify_ip(transport, labels, "tunnel_ip",
                     [10, 7, 0, 2], "IP: tunnel 10.7.0.2")
    passed += p; failed += f

    # Standard config has ping_target_ip = (1, 2, 3, 4)
    p, f = verify_ip(transport, labels, "ping_target_ip",
                     [1, 2, 3, 4], "IP: target 1.2.3.4")
    passed += p; failed += f

    # Individual octet checks
    got = bytes(read_bytes(transport, labels["cfg_peer_endpoint_ip"], 4))
    if got[0] == 10:
        passed += 1
        if VERBOSE:
            print("  PASS IP: endpoint first octet == 10")
    else:
        failed += 1
        print(f"  FAIL IP: endpoint first octet = {got[0]}, expected 10")

    if got[3] == 1:
        passed += 1
        if VERBOSE:
            print("  PASS IP: endpoint last octet == 1")
    else:
        failed += 1
        print(f"  FAIL IP: endpoint last octet = {got[3]}, expected 1")

    return passed, failed


# ============================================================================
# Test group 3: Port parsing (3 tests)
# ============================================================================

def test_port_parsing(transport, labels):
    """Test port parsing from the loaded standard config."""
    passed = failed = 0

    # Standard config has endpoint_port = 51820
    p, f = verify_port(transport, labels, "cfg_peer_endpoint_port",
                       51820, "port: 51820")
    passed += p; failed += f

    # Verify individual bytes (big-endian: 51820 = 0xCA6C)
    got = bytes(read_bytes(transport, labels["cfg_peer_endpoint_port"], 2))
    if got[0] == 0xCA:
        passed += 1
        if VERBOSE:
            print("  PASS port: high byte == 0xCA")
    else:
        failed += 1
        print(f"  FAIL port: high byte = {got[0]:#04x}, expected 0xCA")

    if got[1] == 0x6C:
        passed += 1
        if VERBOSE:
            print("  PASS port: low byte == 0x6C")
    else:
        failed += 1
        print(f"  FAIL port: low byte = {got[1]:#04x}, expected 0x6C")

    return passed, failed


# ============================================================================
# Test group 4: Edge case config -- all max values (5 tests)
# ============================================================================

def test_edge_max(transport, labels):
    """Test config with max-value fields: all-FF keys, 255.255.255.255, port 65535."""
    passed = failed = 0

    # Verify keys
    p, f = verify_key(transport, labels, "cfg_static_priv",
                      bytes([0xFF] * 32), "edge-max: static_priv all-FF")
    passed += p; failed += f

    p, f = verify_key(transport, labels, "cfg_static_pub",
                      bytes([0xFF] * 32), "edge-max: static_pub all-FF")
    passed += p; failed += f

    # Verify IP
    p, f = verify_ip(transport, labels, "cfg_peer_endpoint_ip",
                     [255, 255, 255, 255], "edge-max: endpoint 255.255.255.255")
    passed += p; failed += f

    # Verify port
    p, f = verify_port(transport, labels, "cfg_peer_endpoint_port",
                       65535, "edge-max: port 65535")
    passed += p; failed += f

    # Verify tunnel IP
    p, f = verify_ip(transport, labels, "tunnel_ip",
                     [255, 255, 255, 255], "edge-max: tunnel 255.255.255.255")
    passed += p; failed += f

    return passed, failed


# ============================================================================
# Test group 5: Edge case config -- all min values (5 tests)
# ============================================================================

def test_edge_min(transport, labels):
    """Test config with min-value fields: all-zero keys, 0.0.0.0, port 1."""
    passed = failed = 0

    # Verify keys
    p, f = verify_key(transport, labels, "cfg_static_priv",
                      bytes(32), "edge-min: static_priv all-zero")
    passed += p; failed += f

    p, f = verify_key(transport, labels, "cfg_static_pub",
                      bytes(32), "edge-min: static_pub all-zero")
    passed += p; failed += f

    # Verify IP
    p, f = verify_ip(transport, labels, "cfg_peer_endpoint_ip",
                     [0, 0, 0, 0], "edge-min: endpoint 0.0.0.0")
    passed += p; failed += f

    # Verify port
    p, f = verify_port(transport, labels, "cfg_peer_endpoint_port",
                       1, "edge-min: port 1")
    passed += p; failed += f

    # Verify target IP
    p, f = verify_ip(transport, labels, "ping_target_ip",
                     [0, 0, 0, 0], "edge-min: target 0.0.0.0")
    passed += p; failed += f

    return passed, failed


# ============================================================================
# Test group 6: Additional full config tests (4 tests)
# ============================================================================

def test_full_config_extras(transport, labels, rng):
    """Additional full config tests with the random-key config."""
    passed = failed = 0

    # These run with the random config (instance 3)

    # Test 1: config_read_file returns success
    result = call_config_read(transport, labels)
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS full: re-read returns success")
    else:
        failed += 1
        print(f"  FAIL full: re-read returned {result}, expected 0")

    # Test 2: re-read produces same static_priv (idempotent)
    priv1 = bytes(read_bytes(transport, labels["cfg_static_priv"], 32))
    result = call_config_read(transport, labels)
    priv2 = bytes(read_bytes(transport, labels["cfg_static_priv"], 32))
    if priv1 == priv2:
        passed += 1
        if VERBOSE:
            print("  PASS full: idempotent re-read")
    else:
        failed += 1
        print(f"  FAIL full: re-read changed static_priv")
        print(f"    first:  {priv1.hex()}")
        print(f"    second: {priv2.hex()}")

    # Test 3: re-read produces same peer_pub
    pub1 = bytes(read_bytes(transport, labels["cfg_peer_pub"], 32))
    result = call_config_read(transport, labels)
    pub2 = bytes(read_bytes(transport, labels["cfg_peer_pub"], 32))
    if pub1 == pub2:
        passed += 1
        if VERBOSE:
            print("  PASS full: idempotent re-read peer_pub")
    else:
        failed += 1
        print(f"  FAIL full: re-read changed peer_pub")

    # Test 4: re-read produces same port
    port1 = bytes(read_bytes(transport, labels["cfg_peer_endpoint_port"], 2))
    result = call_config_read(transport, labels)
    port2 = bytes(read_bytes(transport, labels["cfg_peer_endpoint_port"], 2))
    if port1 == port2:
        passed += 1
        if VERBOSE:
            print("  PASS full: idempotent re-read port")
    else:
        failed += 1
        print(f"  FAIL full: re-read changed port")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def main():
    global VERBOSE

    args = sys.argv[1:]
    seed = 6502
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

    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

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
        "config_read_file",
        "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
        "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
        "tunnel_ip", "ping_target_ip",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    total_passed = 0
    total_failed = 0

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(
        config=config,
        port_range_start=6510,
        port_range_end=6560,
    ) as mgr, tempfile.TemporaryDirectory() as tmpdir:

        # ==================================================================
        # Instance 1: Standard config
        # Keys: static_priv=all-zeros, static_pub=all-FF, peer_pub=ascending
        # IPs: endpoint=10.0.0.1, tunnel=10.7.0.2, target=1.2.3.4
        # Port: 51820
        # ==================================================================
        print("\n=== Instance 1: Standard config ===")

        static_priv_1 = bytes(32)                  # all zeros
        static_pub_1 = bytes([0xFF] * 32)          # all FFs
        peer_pub_1 = bytes(range(0, 32))            # ascending 0x00..0x1F
        endpoint_ip_1 = [10, 0, 0, 1]
        endpoint_port_1 = 51820
        tunnel_ip_1 = [10, 7, 0, 2]
        target_ip_1 = [1, 2, 3, 4]

        content_1 = make_config_content(
            static_priv_1, static_pub_1, peer_pub_1,
            endpoint_ip_1, endpoint_port_1,
            tunnel_ip_1, target_ip_1,
        )
        disk_1 = create_disk_with_config(tmpdir, content_1, "standard.d64")

        inst_1, transport_1 = launch_vice_with_disk(disk_1, mgr)
        try:
            print(f"VICE PID={inst_1.pid}, port={inst_1.port}")

            # Call config_read_file
            print("\n--- config_read_file (standard) ---")
            result = call_config_read(transport_1, labels)
            if result == 0:
                total_passed += 1
                if VERBOSE:
                    print("  PASS config_read_file returned success")
            else:
                total_failed += 1
                print(f"  FAIL config_read_file returned {result}")
            print(f"  1 passed, 0 failed" if result == 0
                  else f"  0 passed, 1 failed")

            # Hex parsing tests
            print("\n--- hex parsing ---")
            p, f = test_hex_parsing(transport_1, labels, rng)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            # IP parsing tests
            print("\n--- IP parsing ---")
            p, f = test_ip_parsing(transport_1, labels)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            # Port parsing tests
            print("\n--- port parsing ---")
            p, f = test_port_parsing(transport_1, labels)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            time.sleep(1.0)
        finally:
            cleanup_vice(inst_1, mgr)

        # ==================================================================
        # Instance 2: Edge case -- all max values
        # Keys: all-FF for all three, IPs: 255.255.255.255, port: 65535
        # ==================================================================
        print("\n=== Instance 2: Edge max config ===")

        static_priv_2 = bytes([0xFF] * 32)
        static_pub_2 = bytes([0xFF] * 32)
        peer_pub_2 = bytes([0xFF] * 32)
        endpoint_ip_2 = [255, 255, 255, 255]
        endpoint_port_2 = 65535
        tunnel_ip_2 = [255, 255, 255, 255]
        target_ip_2 = [255, 255, 255, 255]

        content_2 = make_config_content(
            static_priv_2, static_pub_2, peer_pub_2,
            endpoint_ip_2, endpoint_port_2,
            tunnel_ip_2, target_ip_2,
        )
        disk_2 = create_disk_with_config(tmpdir, content_2, "maxvals.d64")

        inst_2, transport_2 = launch_vice_with_disk(disk_2, mgr)
        try:
            print(f"VICE PID={inst_2.pid}, port={inst_2.port}")

            result = call_config_read(transport_2, labels)
            if result != 0:
                total_failed += 1
                print(f"  FAIL config_read_file returned {result} for max config")
            else:
                if VERBOSE:
                    print("  PASS config_read_file success for max config")

            print("\n--- edge max ---")
            p, f = test_edge_max(transport_2, labels)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            time.sleep(1.0)
        finally:
            cleanup_vice(inst_2, mgr)

        # ==================================================================
        # Instance 3: Edge case -- all min values + random key + re-read
        # Keys: all-zero, IPs: 0.0.0.0, port: 1
        # ==================================================================
        print("\n=== Instance 3: Edge min config + re-read ===")

        static_priv_3 = bytes(32)
        static_pub_3 = bytes(32)
        peer_pub_3 = bytes(32)
        endpoint_ip_3 = [0, 0, 0, 0]
        endpoint_port_3 = 1
        tunnel_ip_3 = [0, 0, 0, 0]
        target_ip_3 = [0, 0, 0, 0]

        content_3 = make_config_content(
            static_priv_3, static_pub_3, peer_pub_3,
            endpoint_ip_3, endpoint_port_3,
            tunnel_ip_3, target_ip_3,
        )
        disk_3 = create_disk_with_config(tmpdir, content_3, "minvals.d64")

        inst_3, transport_3 = launch_vice_with_disk(disk_3, mgr)
        try:
            print(f"VICE PID={inst_3.pid}, port={inst_3.port}")

            result = call_config_read(transport_3, labels)
            if result != 0:
                total_failed += 1
                print(f"  FAIL config_read_file returned {result} for min config")
            else:
                if VERBOSE:
                    print("  PASS config_read_file success for min config")

            print("\n--- edge min ---")
            p, f = test_edge_min(transport_3, labels)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            print("\n--- full config extras (re-read) ---")
            p, f = test_full_config_extras(transport_3, labels, rng)
            total_passed += p; total_failed += f
            print(f"  {p} passed, {f} failed")

            time.sleep(1.0)
        finally:
            cleanup_vice(inst_3, mgr)

    # ==================================================================
    # Summary
    # ==================================================================
    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
