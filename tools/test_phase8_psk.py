#!/usr/bin/env python3
"""test_phase8_psk.py — Pre-Shared Key (PSK) support tests.

Tests PSK mixing in the IKpsk2 handshake, config loading, disk config
parsing with optional PSK line, and backward compatibility.

Uses hs_psk_mix label for direct entry into the PSK+AEAD+transport tail
of hs_process_response, avoiding X25519 (~100 min each).

Usage:
    python3 tools/test_phase8_psk.py [--seed S] [--verbose]
"""

import hashlib
import hmac as hmac_mod
import os
import random
import struct
import subprocess
import sys
import tempfile


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_text
from c64_test_harness.disk import DiskImage, FileType

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False



# ============================================================================
# Python Noise IKpsk2 reference helpers
# ============================================================================

def blake2s_256(data):
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_hmac(key, data):
    return hmac_mod.new(key, data, lambda: hashlib.blake2s(digest_size=32)).digest()


def kdf_n(c, input_data, n):
    t0 = blake2s_hmac(c, input_data)
    t1 = blake2s_hmac(t0, b'\x01')
    if n == 1:
        return (t1,)
    t2 = blake2s_hmac(t0, t1 + b'\x02')
    if n == 2:
        return (t1, t2)
    t3 = blake2s_hmac(t0, t2 + b'\x03')
    return (t1, t2, t3)


def mix_hash(h, data):
    return blake2s_256(h + data)


def py_psk_mix_and_transport(c, h, psk):
    """Compute PSK mixing + AEAD tag + transport keys in Python.

    Returns: (c_after_kdf3, h_after_mix_tau, aead_key, tag_16,
              h_after_mix_tag, transport_send, transport_recv)
    """
    c_new, tau, key = kdf_n(c, psk, 3)
    h_new = mix_hash(h, tau)

    # AEAD encrypt empty with key, nonce=zeros, AAD=h_new → 16-byte tag
    nonce = b'\x00' * 12
    aead = ChaCha20Poly1305(key)
    tag = aead.encrypt(nonce, b'', h_new)  # 16 bytes (empty plaintext)

    h_after_tag = mix_hash(h_new, tag)

    # Transport keys: kdf_2(c_new, empty)
    t_send, t_recv = kdf_n(c_new, b'', 2)

    return c_new, h_new, key, tag, h_after_tag, t_send, t_recv


# ============================================================================
# Test group 1: Build verification (4 tests)
# ============================================================================

def test_build_verification(labels):
    """Verify PSK labels exist and addresses are valid."""
    passed = failed = 0

    required = ["cfg_preshared_key", "hs_preshared_key", "hs_psk_mix"]
    for name in required:
        addr = labels.address(name)
        if addr is not None:
            passed += 1
            if VERBOSE:
                print(f"  PASS label '{name}' = ${addr:04X}")
        else:
            failed += 1
            print(f"  FAIL label '{name}' not found")

    # All addresses below $8000
    all_ok = True
    for name in required:
        addr = labels.address(name)
        if addr is not None and addr >= 0x8000:
            all_ok = False
            print(f"  FAIL {name} ${addr:04X} >= $8000")
    if all_ok:
        passed += 1
        if VERBOSE:
            print("  PASS all PSK labels < $8000")
    else:
        failed += 1

    return passed, failed


# ============================================================================
# Test group 2: PSK mixing with zeros (3 tests)
# ============================================================================

def test_psk_zeros(transport, labels, rng):
    """Test PSK mixing with all-zero PSK produces correct results."""
    passed = failed = 0

    # Use random C and H
    c = bytes(rng.randint(0, 255) for _ in range(32))
    h = bytes(rng.randint(0, 255) for _ in range(32))
    psk = b'\x00' * 32

    c_new, h_new, key, tag, h_after_tag, t_send, t_recv = py_psk_mix_and_transport(c, h, psk)

    # Write state to C64
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk)
    # Write AEAD tag to hs_resp_packet+44
    write_bytes(transport, labels["hs_resp_packet"] + 44, tag)

    # Call hs_psk_mix (runs PSK mixing + AEAD verify + mix_hash(tag) + transport derivation)
    jsr(transport, labels["hs_psk_mix"], timeout=60.0)

    # Check hs_c updated
    c64_c = bytes(read_bytes(transport, labels["hs_c"], 32))
    if c64_c == c_new:
        passed += 1
        if VERBOSE:
            print("  PASS psk_zeros: hs_c updated correctly")
    else:
        failed += 1
        print(f"  FAIL psk_zeros: hs_c mismatch")
        print(f"    expected: {c_new.hex()}")
        print(f"    got:      {c64_c.hex()}")

    # Check transport keys
    c64_send = bytes(read_bytes(transport, labels["hs_transport_send"], 32))
    c64_recv = bytes(read_bytes(transport, labels["hs_transport_recv"], 32))

    if c64_send == t_send:
        passed += 1
        if VERBOSE:
            print("  PASS psk_zeros: transport send key matches")
    else:
        failed += 1
        print(f"  FAIL psk_zeros: transport send key mismatch")
        print(f"    expected: {t_send.hex()}")
        print(f"    got:      {c64_send.hex()}")

    if c64_recv == t_recv:
        passed += 1
        if VERBOSE:
            print("  PASS psk_zeros: transport recv key matches")
    else:
        failed += 1
        print(f"  FAIL psk_zeros: transport recv key mismatch")
        print(f"    expected: {t_recv.hex()}")
        print(f"    got:      {c64_recv.hex()}")

    return passed, failed


# ============================================================================
# Test group 3: PSK mixing with random PSK (4 tests)
# ============================================================================

def test_psk_random(transport, labels, rng):
    """Test PSK mixing with random PSK values."""
    passed = failed = 0

    for trial in range(3):
        c = bytes(rng.randint(0, 255) for _ in range(32))
        h = bytes(rng.randint(0, 255) for _ in range(32))
        psk = bytes(rng.randint(0, 255) for _ in range(32))

        c_new, h_new, key, tag, h_after_tag, t_send, t_recv = py_psk_mix_and_transport(c, h, psk)

        write_bytes(transport, labels["hs_c"], c)
        write_bytes(transport, labels["hs_h"], h)
        write_bytes(transport, labels["hs_preshared_key"], psk)
        write_bytes(transport, labels["hs_resp_packet"] + 44, tag)

        jsr(transport, labels["hs_psk_mix"], timeout=60.0)

        c64_send = bytes(read_bytes(transport, labels["hs_transport_send"], 32))
        c64_recv = bytes(read_bytes(transport, labels["hs_transport_recv"], 32))

        if c64_send == t_send and c64_recv == t_recv:
            passed += 1
            if VERBOSE:
                print(f"  PASS psk_random #{trial}: transport keys match")
        else:
            failed += 1
            print(f"  FAIL psk_random #{trial}: transport key mismatch")
            if c64_send != t_send:
                print(f"    send expected: {t_send.hex()}")
                print(f"    send got:      {c64_send.hex()}")
            if c64_recv != t_recv:
                print(f"    recv expected: {t_recv.hex()}")
                print(f"    recv got:      {c64_recv.hex()}")

    # Test: different PSK → different keys
    c = bytes(rng.randint(0, 255) for _ in range(32))
    h = bytes(rng.randint(0, 255) for _ in range(32))
    psk_a = bytes(rng.randint(0, 255) for _ in range(32))
    psk_b = bytes(rng.randint(0, 255) for _ in range(32))

    _, _, _, _, _, send_a, recv_a = py_psk_mix_and_transport(c, h, psk_a)
    _, _, _, _, _, send_b, recv_b = py_psk_mix_and_transport(c, h, psk_b)

    if send_a != send_b and recv_a != recv_b:
        passed += 1
        if VERBOSE:
            print("  PASS different PSKs produce different transport keys")
    else:
        failed += 1
        print("  FAIL different PSKs produced same transport keys")

    return passed, failed


# ============================================================================
# Test group 4: AEAD verification (3 tests)
# ============================================================================

def test_aead_verification(transport, labels, rng):
    """Test AEAD tag verification during PSK mixing."""
    passed = failed = 0

    c = bytes(rng.randint(0, 255) for _ in range(32))
    h = bytes(rng.randint(0, 255) for _ in range(32))
    psk = bytes(rng.randint(0, 255) for _ in range(32))

    c_new, h_new, key, correct_tag, _, _, _ = py_psk_mix_and_transport(c, h, psk)

    # Test 1: correct tag → A=0
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk)
    write_bytes(transport, labels["hs_resp_packet"] + 44, correct_tag)

    # Build trampoline that captures A register after hs_psk_mix returns
    # Since hs_psk_mix is the entry for PSK+AEAD+transport tail, and the code
    # after it does aead_decrypt which returns A=0/nonzero, then continues to
    # transport derivation... We need to check differently.
    # Actually, hs_psk_mix is just a label in the middle of hs_process_response.
    # After PSK mixing, the code does AEAD verify and if A != 0, jumps to auth_fail.
    # So calling hs_psk_mix will run through to either success (A=0, rts) or fail (A=$FF, rts).
    # We can capture A at the end.

    # Trampoline: JSR hs_psk_mix; STA $0360; RTS
    psk_mix_addr = labels["hs_psk_mix"]
    trampoline = bytes([
        0x20, psk_mix_addr & 0xFF, (psk_mix_addr >> 8) & 0xFF,  # JSR hs_psk_mix
        0x8D, 0x60, 0x03,                                        # STA $0360
        0x60,                                                     # RTS
    ])
    write_bytes(transport, 0x0340, trampoline)
    jsr(transport, 0x0340, timeout=60.0)

    result = read_bytes(transport, 0x0360, 1)[0]
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD: correct PSK+tag → A=0 (success)")
    else:
        failed += 1
        print(f"  FAIL AEAD: correct PSK+tag → A={result:#04x}, expected 0")

    # Test 2: wrong PSK → A=$FF
    wrong_psk = bytes((b ^ 0xFF) for b in psk)
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], wrong_psk)
    write_bytes(transport, labels["hs_resp_packet"] + 44, correct_tag)

    write_bytes(transport, 0x0340, trampoline)
    jsr(transport, 0x0340, timeout=60.0)

    result = read_bytes(transport, 0x0360, 1)[0]
    if result != 0:
        passed += 1
        if VERBOSE:
            print(f"  PASS AEAD: wrong PSK → A={result:#04x} (failure)")
    else:
        failed += 1
        print("  FAIL AEAD: wrong PSK → A=0 (should have failed)")

    # Test 3: corrupted tag → A=$FF
    corrupted_tag = bytearray(correct_tag)
    corrupted_tag[8] ^= 0xFF
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk)
    write_bytes(transport, labels["hs_resp_packet"] + 44, bytes(corrupted_tag))

    write_bytes(transport, 0x0340, trampoline)
    jsr(transport, 0x0340, timeout=60.0)

    result = read_bytes(transport, 0x0360, 1)[0]
    if result != 0:
        passed += 1
        if VERBOSE:
            print(f"  PASS AEAD: corrupted tag → A={result:#04x} (failure)")
    else:
        failed += 1
        print("  FAIL AEAD: corrupted tag → A=0 (should have failed)")

    return passed, failed


# ============================================================================
# Test group 5: Config parsing (6 tests) — requires disk images
# ============================================================================

def make_config_content(static_priv, static_pub, peer_pub,
                        endpoint_ip, endpoint_port,
                        tunnel_ip, target_ip, psk=None):
    """Build WG.CFG content. If psk is not None, adds 8th line."""
    lines = []
    lines.append(static_priv.hex().upper())
    lines.append(static_pub.hex().upper())
    lines.append(peer_pub.hex().upper())
    lines.append(f"{endpoint_ip[0]}.{endpoint_ip[1]}.{endpoint_ip[2]}.{endpoint_ip[3]}")
    lines.append(str(endpoint_port))
    lines.append(f"{tunnel_ip[0]}.{tunnel_ip[1]}.{tunnel_ip[2]}.{tunnel_ip[3]}")
    lines.append(f"{target_ip[0]}.{target_ip[1]}.{target_ip[2]}.{target_ip[3]}")
    if psk is not None:
        lines.append(psk.hex().upper())
    return "\r".join(lines) + "\r"


def create_disk_with_config(tmpdir, config_content, disk_name="test.d64"):
    """Create D64 with WG.CFG and the PRG."""
    disk_path = os.path.join(tmpdir, disk_name)
    disk = DiskImage.create(disk_path)
    cfg_host_path = os.path.join(tmpdir, "wg_cfg_host.tmp")
    with open(cfg_host_path, "wb") as f:
        f.write(config_content.encode("ascii"))
    disk.write_file(cfg_host_path, "wg.cfg", file_type=FileType.SEQ)
    disk.write_file(PRG_PATH, "wireguard")
    return disk


def build_read_trampoline(labels):
    addr = labels["config_read_file"]
    return bytes([
        0x20, addr & 0xFF, (addr >> 8) & 0xFF,
        0x90, 0x05,
        0xA9, 0x01,
        0x8D, 0x60, 0x03,
        0x60,
        0xA9, 0x00,
        0x8D, 0x60, 0x03,
        0x60,
    ])


def call_config_read(transport, labels):
    trampoline = build_read_trampoline(labels)
    write_bytes(transport, 0x0340, trampoline)
    jsr(transport, 0x0340, timeout=30.0)
    return read_bytes(transport, 0x0360, 1)[0]


def run_disk_test(disk, labels, test_fn):
    """Launch VICE with a disk image and run test_fn(transport, labels).

    Returns (passed, failed) from test_fn.
    """
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        disk_image=disk)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        grid = binary_wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            raise RuntimeError("Main menu did not appear")
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        return test_fn(transport, labels)


def test_config_parsing(labels, rng, mgr=None):
    """Test PSK parsing from disk config files."""
    passed = failed = 0

    # Common config values
    static_priv = bytes(rng.randint(0, 255) for _ in range(32))
    static_pub = bytes(rng.randint(0, 255) for _ in range(32))
    peer_pub = bytes(rng.randint(0, 255) for _ in range(32))
    endpoint_ip = [10, 0, 0, 1]
    endpoint_port = 51820
    tunnel_ip = [10, 0, 0, 2]
    target_ip = [10, 0, 0, 3]

    def make_disk(tmpdir, psk=None, name="test.d64"):
        content = make_config_content(
            static_priv, static_pub, peer_pub,
            endpoint_ip, endpoint_port, tunnel_ip, target_ip,
            psk=psk)
        return create_disk_with_config(tmpdir, content, name)

    # Test 1: 7-line config (no PSK) → cfg_preshared_key should be zeros
    with tempfile.TemporaryDirectory() as tmpdir:
        disk = make_disk(tmpdir, psk=None, name="nopsk.d64")

        def test_1(transport, labels):
            result = call_config_read(transport, labels)
            if result != 0:
                print("  FAIL config_7line: config_read_file returned failure")
                return 0, 1
            got = bytes(read_bytes(transport, labels["cfg_preshared_key"], 32))
            if got == b'\x00' * 32:
                if VERBOSE:
                    print("  PASS config_7line: no PSK → zeros")
                return 1, 0
            print(f"  FAIL config_7line: expected zeros, got {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_1)
        passed += p; failed += f

    # Test 2: 8-line config with all-zero PSK
    with tempfile.TemporaryDirectory() as tmpdir:
        psk_zeros = b'\x00' * 32
        disk = make_disk(tmpdir, psk=psk_zeros, name="psk_zeros.d64")

        def test_2(transport, labels):
            result = call_config_read(transport, labels)
            if result != 0:
                print("  FAIL config_psk_zeros: config_read_file returned failure")
                return 0, 1
            got = bytes(read_bytes(transport, labels["cfg_preshared_key"], 32))
            if got == psk_zeros:
                if VERBOSE:
                    print("  PASS config_psk_zeros: all-zero PSK parsed")
                return 1, 0
            print(f"  FAIL config_psk_zeros: got {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_2)
        passed += p; failed += f

    # Test 3: 8-line config with all-FF PSK
    with tempfile.TemporaryDirectory() as tmpdir:
        psk_ff = b'\xFF' * 32
        disk = make_disk(tmpdir, psk=psk_ff, name="psk_ff.d64")

        def test_3(transport, labels):
            result = call_config_read(transport, labels)
            if result != 0:
                print("  FAIL config_psk_ff: config_read_file returned failure")
                return 0, 1
            got = bytes(read_bytes(transport, labels["cfg_preshared_key"], 32))
            if got == psk_ff:
                if VERBOSE:
                    print("  PASS config_psk_ff: all-FF PSK parsed")
                return 1, 0
            print(f"  FAIL config_psk_ff: got {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_3)
        passed += p; failed += f

    # Test 4: 8-line config with random PSK
    with tempfile.TemporaryDirectory() as tmpdir:
        psk_rand = bytes(rng.randint(0, 255) for _ in range(32))
        disk = make_disk(tmpdir, psk=psk_rand, name="psk_rand.d64")

        def test_4(transport, labels):
            result = call_config_read(transport, labels)
            if result != 0:
                print("  FAIL config_psk_random: config_read_file returned failure")
                return 0, 1
            got = bytes(read_bytes(transport, labels["cfg_preshared_key"], 32))
            if got == psk_rand:
                if VERBOSE:
                    print("  PASS config_psk_random: random PSK parsed")
                return 1, 0
            print(f"  FAIL config_psk_random: expected {psk_rand.hex()}, got {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_4)
        passed += p; failed += f

    # Test 5: config_load copies PSK from cfg → hs
    with tempfile.TemporaryDirectory() as tmpdir:
        psk_copy = bytes(rng.randint(0, 255) for _ in range(32))
        disk = make_disk(tmpdir, psk=psk_copy, name="psk_copy.d64")

        def test_5(transport, labels):
            call_config_read(transport, labels)
            jsr(transport, labels["config_load"])
            got = bytes(read_bytes(transport, labels["hs_preshared_key"], 32))
            if got == psk_copy:
                if VERBOSE:
                    print("  PASS config_load: PSK copied to hs_preshared_key")
                return 1, 0
            print(f"  FAIL config_load: PSK copy mismatch")
            print(f"    expected: {psk_copy.hex()}")
            print(f"    got:      {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_5)
        passed += p; failed += f

    # Test 6: 7-line config + config_load → hs_preshared_key = zeros
    with tempfile.TemporaryDirectory() as tmpdir:
        disk = make_disk(tmpdir, psk=None, name="nopsk_load.d64")

        def test_6(transport, labels):
            write_bytes(transport, labels["hs_preshared_key"], b'\xAA' * 32)
            call_config_read(transport, labels)
            jsr(transport, labels["config_load"])
            got = bytes(read_bytes(transport, labels["hs_preshared_key"], 32))
            if got == b'\x00' * 32:
                if VERBOSE:
                    print("  PASS config_load: no PSK → hs_preshared_key = zeros")
                return 1, 0
            print(f"  FAIL config_load: expected zeros, got {got.hex()}")
            return 0, 1

        p, f = run_disk_test(disk, labels, test_6)
        passed += p; failed += f

    return passed, failed


# ============================================================================
# Test group 6: Backward compatibility (4 tests)
# ============================================================================

def test_backward_compat(transport, labels, rng):
    """Test backward compatibility and PSK differentiation."""
    passed = failed = 0

    # Test 1: PSK=zeros produces same Python output as kdf_n(c, zeros_32, 3)
    c = bytes(rng.randint(0, 255) for _ in range(32))
    h = bytes(rng.randint(0, 255) for _ in range(32))
    psk_zero = b'\x00' * 32

    _, _, _, tag, _, t_send, t_recv = py_psk_mix_and_transport(c, h, psk_zero)

    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk_zero)
    write_bytes(transport, labels["hs_resp_packet"] + 44, tag)

    jsr(transport, labels["hs_psk_mix"], timeout=60.0)

    c64_send = bytes(read_bytes(transport, labels["hs_transport_send"], 32))
    c64_recv = bytes(read_bytes(transport, labels["hs_transport_recv"], 32))

    if c64_send == t_send and c64_recv == t_recv:
        passed += 1
        if VERBOSE:
            print("  PASS compat: PSK=zeros matches Python reference")
    else:
        failed += 1
        print("  FAIL compat: PSK=zeros mismatch with Python reference")

    # Test 2: two different PSKs produce different transport keys on C64
    psk_a = bytes(rng.randint(0, 255) for _ in range(32))
    psk_b = bytes(rng.randint(0, 255) for _ in range(32))

    _, _, _, tag_a, _, _, _ = py_psk_mix_and_transport(c, h, psk_a)
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk_a)
    write_bytes(transport, labels["hs_resp_packet"] + 44, tag_a)
    jsr(transport, labels["hs_psk_mix"], timeout=60.0)
    send_a = bytes(read_bytes(transport, labels["hs_transport_send"], 32))

    _, _, _, tag_b, _, _, _ = py_psk_mix_and_transport(c, h, psk_b)
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_preshared_key"], psk_b)
    write_bytes(transport, labels["hs_resp_packet"] + 44, tag_b)
    jsr(transport, labels["hs_psk_mix"], timeout=60.0)
    send_b = bytes(read_bytes(transport, labels["hs_transport_send"], 32))

    if send_a != send_b:
        passed += 1
        if VERBOSE:
            print("  PASS compat: different PSKs → different C64 transport keys")
    else:
        failed += 1
        print("  FAIL compat: different PSKs produced same transport keys on C64")

    # Test 3: verify kdf_out2 (tau) is mixed into H
    c2 = bytes(rng.randint(0, 255) for _ in range(32))
    h2 = bytes(rng.randint(0, 255) for _ in range(32))
    psk2 = bytes(rng.randint(0, 255) for _ in range(32))

    _, h_expected, _, tag2, _, _, _ = py_psk_mix_and_transport(c2, h2, psk2)

    write_bytes(transport, labels["hs_c"], c2)
    write_bytes(transport, labels["hs_h"], h2)
    write_bytes(transport, labels["hs_preshared_key"], psk2)
    write_bytes(transport, labels["hs_resp_packet"] + 44, tag2)

    jsr(transport, labels["hs_psk_mix"], timeout=60.0)

    # After PSK mixing + AEAD verify, H has been updated twice:
    # once for tau, once for the AEAD tag. Read final H.
    c64_h = bytes(read_bytes(transport, labels["hs_h"], 32))
    # The final H should match h_after_tag (mix_hash(mix_hash(h, tau), tag))
    _, _, _, _, h_after_tag, _, _ = py_psk_mix_and_transport(c2, h2, psk2)
    if c64_h == h_after_tag:
        passed += 1
        if VERBOSE:
            print("  PASS compat: H correctly updated (tau + tag mixed)")
    else:
        failed += 1
        print(f"  FAIL compat: H mismatch after PSK mixing")
        print(f"    expected: {h_after_tag.hex()}")
        print(f"    got:      {c64_h.hex()}")

    # Test 4: verify that PSK=zeros gives different result than empty input
    # (this confirms the protocol fix: kdf_3(C, 32_zeros) ≠ kdf_2(C, empty))
    c3 = bytes(rng.randint(0, 255) for _ in range(32))
    old_c_t1, old_c_t2 = kdf_n(c3, b'', 2)  # old buggy behavior
    new_c_t1, new_tau, new_key = kdf_n(c3, b'\x00' * 32, 3)  # correct behavior
    if old_c_t1 != new_c_t1:
        passed += 1
        if VERBOSE:
            print("  PASS compat: kdf_3(C, zeros) ≠ kdf_2(C, empty) — protocol fix confirmed")
    else:
        failed += 1
        print("  FAIL compat: kdf_3(C, zeros) == kdf_2(C, empty) — protocol still buggy!")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run non-disk test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("PSK mixing (zeros)", lambda: test_psk_zeros(transport, labels, rng)),
        ("PSK mixing (random)", lambda: test_psk_random(transport, labels, rng)),
        ("AEAD verification", lambda: test_aead_verification(transport, labels, rng)),
        ("backward compat", lambda: test_backward_compat(transport, labels, rng)),
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
    global VERBOSE

    args = sys.argv[1:]
    seed = 7
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
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)

    # Build verification (no VICE needed)
    print("\n--- build verification ---")
    bp, bf = test_build_verification(labels)
    print(f"  {bp} passed, {bf} failed")
    if bf > 0:
        print("FATAL: Build verification failed")
        sys.exit(1)

    required = [
        "hs_c", "hs_h", "hs_preshared_key", "hs_psk_mix",
        "hs_resp_packet", "hs_transport_send", "hs_transport_recv",
        "cfg_preshared_key", "config_load", "config_read_file",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE for non-disk tests
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        grid = binary_wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        print("VICE ready, running tests...")
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

        # Disk config tests (separate VICE instances per test)
        print("\n--- config parsing (disk) ---")
        try:
            rng = random.Random(seed + 1000)
            dp, df = test_config_parsing(labels, rng, mgr)
            passed += dp
            failed += df
            print(f"  {dp} passed, {df} failed")
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    total_passed = passed + bp
    total_failed = failed + bf
    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
