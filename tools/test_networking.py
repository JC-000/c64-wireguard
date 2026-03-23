#!/usr/bin/env python3
"""test_networking.py — Phase 4 networking infrastructure tests.

Tests:
  1. Build verification: PRG builds with ip65 blob, labels resolve
  2. ip65 blob presence: $2000 contains valid JMP opcodes (jump table)
  3. ZP save/restore: net_save_zp / net_restore_zp round-trips correctly
  4. Memory layout: boot+net before $2000, crypto after ip65 blob

Usage:
    python3 tools/test_networking.py [--seed S] [--verbose]
"""

import os
import random
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


def print_pass(msg):
    if VERBOSE:
        print(f"  PASS: {msg}")


def print_fail(msg):
    print(f"  FAIL: {msg}")


# ============================================================================
# Test: Build verification
# ============================================================================

def test_build_verification(labels):
    """Verify PRG exists and key labels are present."""
    passed = 0
    failed = 0

    # Check PRG exists
    assert os.path.exists(PRG_PATH), f"PRG not found: {PRG_PATH}"
    prg_size = os.path.getsize(PRG_PATH)
    assert prg_size > 10000, f"PRG too small: {prg_size}"
    print_pass(f"PRG exists ({prg_size} bytes)")
    passed += 1

    # Check critical labels exist
    critical_labels = [
        "main_loop", "start", "net_init", "net_dhcp", "net_poll",
        "net_save_zp", "net_restore_zp", "net_udp_listen", "net_udp_send",
        "net_udp_recv_cb", "net_print_ip", "do_net_init",
        "zp_save_buf", "udp_recv_buf", "udp_recv_ready",
        "wg_peer_ip", "wg_peer_port", "wg_local_port", "net_initialized",
        "blake2s_init", "chacha20_init", "poly1305_init",
        "fe_add", "x25519_scalarmult", "hs_init",
    ]
    for label in critical_labels:
        if label not in labels:
            print_fail(f"Missing label: {label}")
            failed += 1
        else:
            print_pass(f"Label {label} = ${labels[label]:04X}")
            passed += 1

    return passed, failed


# ============================================================================
# Test: Memory layout verification
# ============================================================================

def test_memory_layout(labels):
    """Verify boot+net before $2000, crypto after ip65 blob."""
    passed = 0
    failed = 0

    # boot+net must be before $2000
    boot_net_labels = ["main_loop", "start", "net_init", "net_save_zp",
                       "net_restore_zp", "do_net_init"]
    for label in boot_net_labels:
        addr = labels[label]
        if addr >= 0x2000:
            print_fail(f"{label} (${addr:04X}) not before $2000")
            failed += 1
        else:
            print_pass(f"{label} at ${addr:04X} (before $2000)")
            passed += 1

    # crypto must be after ip65 blob (at least $32F0)
    crypto_labels = ["blake2s_init", "chacha20_init", "poly1305_init",
                     "fe_add", "x25519_scalarmult", "hs_init"]
    for label in crypto_labels:
        addr = labels[label]
        if addr < 0x32F0:
            print_fail(f"{label} (${addr:04X}) overlaps ip65 blob")
            failed += 1
        else:
            print_pass(f"{label} at ${addr:04X} (after ip65)")
            passed += 1

    # data must not exceed $7800 (sqtab region)
    data_labels = ["net_initialized", "udp_recv_buf"]
    for label in data_labels:
        addr = labels[label]
        if addr >= 0x7800:
            print_fail(f"{label} (${addr:04X}) overlaps sqtab at $7800")
            failed += 1
        else:
            print_pass(f"{label} at ${addr:04X} (before $7800)")
            passed += 1

    return passed, failed


# ============================================================================
# Test: ip65 blob presence
# ============================================================================

def test_ip65_blob(transport):
    """Verify $2000 contains JMP opcodes (ip65 jump table)."""
    passed = 0
    failed = 0

    # Read first 30 bytes of jump table (10 x 3-byte JMP entries)
    data = read_bytes(transport, 0x2000, 30)

    # Each entry should be a JMP ($4C)
    for i in range(10):
        offset = i * 3
        opcode = data[offset]
        if opcode != 0x4C:
            print_fail(f"Jump table entry {i} at ${0x2000+offset:04X}: "
                       f"expected $4C (JMP), got ${opcode:02X}")
            failed += 1
        else:
            target = data[offset+1] | (data[offset+2] << 8)
            print_pass(f"Jump table +{offset}: JMP ${target:04X}")
            passed += 1

    return passed, failed


# ============================================================================
# Test: ZP save/restore
# ============================================================================

def test_zp_save_restore(transport, labels, rng):
    """Test ZP save/restore.

    Strategy:
    - net_save_zp: write known data to ZP, call save, read save buffer (stable)
    - net_restore_zp: write known data to save buffer, use trampoline at $0334
      that calls restore + copies ZP to a check buffer atomically (avoids KERNAL
      clobbering ZP between restore and read)
    """
    passed = 0
    failed = 0

    zp_start = 0x02
    zp_size = 26  # $02-$1B inclusive
    save_buf = labels["zp_save_buf"]
    # Use area after udp_recv_buf for check buffer (safe scratch)
    check_buf = labels["udp_recv_buf"]  # 256 bytes, we only need 26

    # Build trampoline at $0334 (cassette buffer):
    # JSR net_restore_zp   ; 3 bytes
    # LDX #25              ; 2 bytes
    # - LDA $02,X          ; 2 bytes
    #   STA check_buf,X    ; 3 bytes
    #   DEX                ; 1 byte
    #   BPL -              ; 2 bytes
    # RTS                  ; 1 byte
    restore_addr = labels["net_restore_zp"]
    trampoline = bytes([
        0x20, restore_addr & 0xFF, restore_addr >> 8,  # JSR net_restore_zp
        0xA2, zp_size - 1,                              # LDX #25
        0xB5, zp_start,                                 # LDA $02,X
        0x9D, check_buf & 0xFF, check_buf >> 8,         # STA check_buf,X
        0xCA,                                            # DEX
        0x10, 0xF8,                                      # BPL -5 (back to LDA)
        0x60,                                            # RTS
    ])
    # $0340: past jsr()'s own trampoline at $0334 (5 bytes + breakpoint at $0337)
    trampoline_addr = 0x0340

    # --- Test save ---
    for trial in range(5):
        test_data = bytes(rng.randint(0, 255) for _ in range(zp_size))

        # Write to ZP and call save
        write_bytes(transport, zp_start, test_data)
        jsr(transport, labels["net_save_zp"])

        # Read save buffer (not in ZP, so KERNAL won't clobber it)
        saved = read_bytes(transport, save_buf, zp_size)
        if saved != test_data:
            print_fail(f"Save trial {trial}: buffer mismatch")
            print_fail(f"  Expected: {test_data.hex()}")
            print_fail(f"  Got:      {saved.hex()}")
            failed += 1
        else:
            print_pass(f"ZP save trial {trial}")
            passed += 1

    # --- Test restore (using trampoline) ---
    write_bytes(transport, trampoline_addr, trampoline)

    for trial in range(5):
        test_data = bytes(rng.randint(0, 255) for _ in range(zp_size))

        # Write known data to save buffer
        write_bytes(transport, save_buf, test_data)

        # Clear check buffer
        write_bytes(transport, check_buf, bytes(zp_size))

        # Call trampoline: restore ZP + copy to check buffer atomically
        jsr(transport, trampoline_addr)

        # Read check buffer
        result = read_bytes(transport, check_buf, zp_size)
        if result != test_data:
            print_fail(f"Restore trial {trial}: mismatch")
            print_fail(f"  Expected: {test_data.hex()}")
            print_fail(f"  Got:      {result.hex()}")
            failed += 1
        else:
            print_pass(f"ZP restore trial {trial}")
            passed += 1

    return passed, failed


# ============================================================================
# Test: Data buffer initialization
# ============================================================================

def test_data_buffers(transport, labels):
    """Verify network data buffers are initialized to zero."""
    passed = 0
    failed = 0

    checks = [
        ("udp_recv_ready", 1),
        ("net_initialized", 1),
        ("wg_peer_port", 2),
        ("wg_local_port", 2),
    ]

    for name, size in checks:
        data = read_bytes(transport, labels[name], size)
        if data != bytes(size):
            print_fail(f"{name} not zero-initialized: {data.hex()}")
            failed += 1
        else:
            print_pass(f"{name} zero-initialized")
            passed += 1

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def main():
    global VERBOSE

    seed = 7539
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--verbose":
            VERBOSE = True
        elif arg == "--seed" and i + 2 < len(sys.argv):
            seed = int(sys.argv[i + 2])

    rng = random.Random(seed)
    print(f"test_networking.py (seed={seed})")
    print()

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    total_passed = 0
    total_failed = 0

    # --- Static tests (no VICE needed) ---
    print("=== Build verification ===")
    p, f = test_build_verification(labels)
    total_passed += p
    total_failed += f

    print(f"\n=== Memory layout ===")
    p, f = test_memory_layout(labels)
    total_passed += p
    total_failed += f

    # --- VICE tests ---
    print(f"\n=== ip65 blob + ZP save/restore (VICE) ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        grid = binary_wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("VICE ready")

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("\n--- ip65 blob ---")
        p, f = test_ip65_blob(transport)
        total_passed += p
        total_failed += f

        print("\n--- ZP save/restore ---")
        p, f = test_zp_save_restore(transport, labels, rng)
        total_passed += p
        total_failed += f

        print("\n--- Data buffers ---")
        p, f = test_data_buffers(transport, labels)
        total_passed += p
        total_failed += f

        mgr.release(inst)

    # --- Summary ---
    print(f"\n{'='*50}")
    total = total_passed + total_failed
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")

    if total_failed > 0:
        sys.exit(1)
    print("All tests passed!")


if __name__ == "__main__":
    main()
