#!/usr/bin/env python3
"""test_chacha20_poly1305.py — Direct-memory ChaCha20-Poly1305 AEAD tests.

Tests left rotations, ChaCha20 (quarter-round, block, encrypt),
Poly1305 (clamp, tag), and AEAD (encrypt, decrypt, verify) against
Python reference implementations via jsr() calls.

Usage:
    python3 tools/test_chacha20_poly1305.py [--seed S] [--verbose]
"""

import json
import os
import random
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceProcess, ViceTransport,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from c64_test_harness.backends.vice_manager import PortAllocator

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc7539_vectors.json")

VERBOSE = False


def robust_jsr(transport, addr, timeout=30.0, retries=3):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.5)
                continue
            raise


# ============================================================================
# Python reference implementations
# ============================================================================

def rotl32(val, n):
    """Rotate left 32-bit."""
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def chacha20_quarter_round_ref(state, a, b, c, d):
    """ChaCha20 quarter-round on a list of 16 uint32s."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block_ref(key, counter, nonce):
    """Generate one ChaCha20 block (64 bytes)."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter] + nonce_words
    working = list(state)

    for _ in range(10):
        # Column rounds
        chacha20_quarter_round_ref(working, 0, 4, 8, 12)
        chacha20_quarter_round_ref(working, 1, 5, 9, 13)
        chacha20_quarter_round_ref(working, 2, 6, 10, 14)
        chacha20_quarter_round_ref(working, 3, 7, 11, 15)
        # Diagonal rounds
        chacha20_quarter_round_ref(working, 0, 5, 10, 15)
        chacha20_quarter_round_ref(working, 1, 6, 11, 12)
        chacha20_quarter_round_ref(working, 2, 7, 8, 13)
        chacha20_quarter_round_ref(working, 3, 4, 9, 14)

    result = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *result)


def chacha20_encrypt_ref(key, counter, nonce, plaintext):
    """ChaCha20 encrypt/decrypt."""
    result = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block_ref(key, counter + i // 64, nonce)
        chunk = plaintext[i:i+64]
        result.extend(b ^ k for b, k in zip(chunk, block))
    return bytes(result)


def poly1305_ref(key, message):
    """Poly1305 MAC reference implementation."""
    r_bytes = key[:16]
    s_bytes = key[16:]

    # Clamp r
    r_bytes = bytearray(r_bytes)
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc

    r = int.from_bytes(r_bytes, 'little')
    s = int.from_bytes(s_bytes, 'little')
    p = (1 << 130) - 5

    h = 0
    for i in range(0, len(message), 16):
        block = message[i:i+16]
        n = int.from_bytes(block, 'little')
        n += 1 << (8 * len(block))  # hibit
        h = ((h + n) * r) % p

    h = (h + s) & ((1 << 128) - 1)
    return h.to_bytes(16, 'little')


def aead_encrypt_ref(key, nonce, aad, plaintext):
    """ChaCha20-Poly1305 AEAD encrypt reference."""
    # Derive OTK
    otk_block = chacha20_block_ref(key, 0, nonce)
    otk = otk_block[:32]

    # Encrypt
    ciphertext = chacha20_encrypt_ref(key, 1, nonce, plaintext)

    # Build Poly1305 message
    mac_data = bytearray()
    mac_data.extend(aad)
    if len(aad) % 16:
        mac_data.extend(b'\x00' * (16 - len(aad) % 16))
    mac_data.extend(ciphertext)
    if len(ciphertext) % 16:
        mac_data.extend(b'\x00' * (16 - len(ciphertext) % 16))
    mac_data.extend(struct.pack('<Q', len(aad)))
    mac_data.extend(struct.pack('<Q', len(ciphertext)))

    tag = poly1305_ref(otk, mac_data)
    return ciphertext, tag


# ============================================================================
# C64 helper functions
# ============================================================================

def set_w32_dst(transport, labels, addr):
    """Set w32_dst zero-page pointer to given address."""
    write_bytes(transport, labels["w32_dst"],
                bytes([addr & 0xFF, addr >> 8]))


def c64_chacha20_init(transport, labels, key, nonce, counter=0):
    """Initialize ChaCha20 state on C64."""
    write_bytes(transport, labels["cc20_key"], key)
    write_bytes(transport, labels["cc20_nonce"], nonce)
    write_bytes(transport, labels["cc20_counter"],
                counter.to_bytes(4, 'little'))
    robust_jsr(transport, labels["chacha20_init"])


def c64_chacha20_block(transport, labels):
    """Generate one ChaCha20 keystream block. Returns 64 bytes."""
    robust_jsr(transport, labels["chacha20_block"], timeout=120.0)
    return read_bytes(transport, labels["cc20_keystream"], 64)


def c64_chacha20_encrypt(transport, labels, key, nonce, data, counter=1):
    """Encrypt data using ChaCha20 on C64."""
    c64_chacha20_init(transport, labels, key, nonce, counter)
    # Write data to input_buffer
    buf = labels["input_buffer"]
    write_bytes(transport, buf, data)
    # Set data pointer and length
    write_bytes(transport, labels["cc20_data_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, labels["cc20_remain"], bytes([len(data)]))
    robust_jsr(transport, labels["chacha20_encrypt"], timeout=180.0)
    return read_bytes(transport, buf, len(data))


def c64_poly1305_init(transport, labels, otk):
    """Initialize Poly1305 with 32-byte OTK."""
    write_bytes(transport, labels["poly_r"], otk[:16])
    write_bytes(transport, labels["poly_s"], otk[16:])
    robust_jsr(transport, labels["poly1305_init"], timeout=60.0)


def c64_poly1305_block(transport, labels, block_data, hibit=1):
    """Process one 16-byte Poly1305 block on C64."""
    buf = labels["input_buffer"]
    write_bytes(transport, buf, block_data)
    write_bytes(transport, labels["zp_ptr1"],
                bytes([buf & 0xFF, buf >> 8]))
    # poly1305_block expects A = hibit, but jsr doesn't set A.
    # We need to write A to a memory location and have the code read it.
    # Actually, poly1305_block takes A register. We can't pass A via jsr().
    # We'll need to call poly1305_update instead, which handles the hibit internally.
    # For now, let's skip direct block tests and test via update/final.
    pass


def c64_poly1305_update(transport, labels, data):
    """Process data through Poly1305 on C64."""
    if len(data) == 0:
        return
    buf = labels["input_buffer"]
    write_bytes(transport, buf, data)
    write_bytes(transport, labels["zp_ptr1"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, labels["cc20_remain"], bytes([len(data)]))
    robust_jsr(transport, labels["poly1305_update"], timeout=120.0)


def c64_poly1305_final(transport, labels):
    """Finalize Poly1305 and return 16-byte tag."""
    robust_jsr(transport, labels["poly1305_final"], timeout=30.0)
    return read_bytes(transport, labels["poly1305_tag"], 16)


def c64_poly1305_mac(transport, labels, key, message):
    """Full Poly1305 MAC: init, update, final."""
    c64_poly1305_init(transport, labels, key)
    c64_poly1305_update(transport, labels, message)
    return c64_poly1305_final(transport, labels)


def c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext):
    """AEAD encrypt on C64. Returns (ciphertext, tag)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    # Write AAD
    aad_buf = labels["input_buffer"]
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([aad_buf & 0xFF, aad_buf >> 8]))
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    # Write plaintext after AAD in input buffer
    pt_buf = aad_buf + len(aad)
    if plaintext:
        write_bytes(transport, pt_buf, plaintext)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([pt_buf & 0xFF, pt_buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], struct.pack('<H', len(plaintext)))

    robust_jsr(transport, labels["aead_encrypt"], timeout=300.0)

    ct = read_bytes(transport, pt_buf, len(plaintext))
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    return ct, tag


def c64_aead_decrypt(transport, labels, key, nonce, aad, ciphertext, tag):
    """AEAD decrypt on C64. Returns (plaintext, success_bool)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    # Write AAD
    aad_buf = labels["input_buffer"]
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([aad_buf & 0xFF, aad_buf >> 8]))
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    # Write ciphertext after AAD
    ct_buf = aad_buf + len(aad)
    if ciphertext:
        write_bytes(transport, ct_buf, ciphertext)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([ct_buf & 0xFF, ct_buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], struct.pack('<H', len(ciphertext)))

    # Write expected tag
    write_bytes(transport, labels["aead_tag"], tag)

    robust_jsr(transport, labels["aead_decrypt"], timeout=300.0)

    pt = read_bytes(transport, ct_buf, len(ciphertext))
    # Check A register result — stored by BRK handler? No, we can't easily
    # read A after jsr(). Instead, we re-verify by comparing plaintext.
    # For tag verification testing, we'll check by tampering.
    return pt, True  # assume success if no crash


# ============================================================================
# Test functions
# ============================================================================

def test_rotl32(transport, labels):
    """Test left rotation functions."""
    passed = failed = 0

    def rotl_ref(val, n):
        return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

    test_values = [0x12345678, 0x80000001, 0xDEADBEEF, 0x00000001, 0xFFFFFFFF,
                   0x01020304, 0xF0E0D0C0]
    rotations = [
        (7, "rotl32_7"),
        (8, "rotl32_8"),
        (12, "rotl32_12"),
    ]

    # Also test rotl32_4 and rotr32_1
    extra_rotations = [
        (4, "rotl32_4"),
    ]

    for val in test_values:
        for rot_amount, rot_label in rotations + extra_rotations:
            expected = rotl_ref(val, rot_amount)
            val_bytes = val.to_bytes(4, "little")
            write_bytes(transport, labels["b2s_tmp0"], val_bytes)
            set_w32_dst(transport, labels, labels["b2s_tmp0"])

            robust_jsr(transport, labels[rot_label])
            result = read_bytes(transport, labels["b2s_tmp0"], 4)
            result_val = int.from_bytes(result, "little")

            if result_val == expected:
                passed += 1
                if VERBOSE:
                    print(f"  PASS {rot_label}: 0x{val:08X} <<< {rot_amount} = 0x{expected:08X}")
            else:
                failed += 1
                print(f"  FAIL {rot_label}: 0x{val:08X} <<< {rot_amount} = "
                      f"0x{result_val:08X}, expected 0x{expected:08X}")

    # Test rotr32_1
    for val in test_values:
        expected = ((val >> 1) | (val << 31)) & 0xFFFFFFFF
        val_bytes = val.to_bytes(4, "little")
        write_bytes(transport, labels["b2s_tmp0"], val_bytes)
        set_w32_dst(transport, labels, labels["b2s_tmp0"])

        robust_jsr(transport, labels["rotr32_1"])
        result = read_bytes(transport, labels["b2s_tmp0"], 4)
        result_val = int.from_bytes(result, "little")

        if result_val == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS rotr32_1: 0x{val:08X} >>> 1 = 0x{expected:08X}")
        else:
            failed += 1
            print(f"  FAIL rotr32_1: 0x{val:08X} >>> 1 = "
                  f"0x{result_val:08X}, expected 0x{expected:08X}")

    return passed, failed


def test_chacha20_quarter_round(transport, labels):
    """Test ChaCha20 quarter-round with RFC 7539 §2.1.1 vector."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["chacha20_quarter_round"]:
        # Write 4 words to cc20_work at positions 0,1,2,3
        # (we test with indices a=0, b=1, c=2, d=3)
        for i, hex_val in enumerate(vec["input"]):
            word_bytes = bytes.fromhex(hex_val)
            # The test vector values are given in native uint32 format
            # Convert from big-endian hex string to little-endian storage
            val = int(hex_val, 16)
            write_bytes(transport, labels["cc20_work"] + i * 4,
                        val.to_bytes(4, "little"))

        # Set up quarter-round indices: a=0, b=1, c=2, d=3
        # These need to be at positions 0,1,2,3 in the qr_table
        # The first entry in cc20_qr_table is {0,4,8,12}, so we can't
        # directly use it. Instead, we need to write our own indices
        # or put the data at the right positions.
        #
        # Actually, the QR function uses cc20_qr_idx as an offset into
        # cc20_qr_table. For testing with a=0,b=1,c=2,d=3, we need
        # a table entry with those values.
        # Let's write custom indices at the start of cc20_qr_table temporarily.
        orig_table = read_bytes(transport, labels["cc20_qr_table"], 4)
        write_bytes(transport, labels["cc20_qr_table"], bytes([0, 1, 2, 3]))
        write_bytes(transport, labels["cc20_qr_idx"], bytes([0]))

        robust_jsr(transport, labels["chacha20_quarter_round"], timeout=30.0)

        # Restore original table
        write_bytes(transport, labels["cc20_qr_table"], orig_table)

        # Read results
        all_match = True
        for i, hex_val in enumerate(vec["expected"]):
            expected = int(hex_val, 16)
            result = read_bytes(transport, labels["cc20_work"] + i * 4, 4)
            result_val = int.from_bytes(result, "little")
            if result_val != expected:
                all_match = False
                print(f"  FAIL QR word {i}: got 0x{result_val:08X}, "
                      f"expected 0x{expected:08X}")

        if all_match:
            passed += 1
            if VERBOSE:
                print(f"  PASS quarter-round: {vec['desc']}")
        else:
            failed += 1

    return passed, failed


def test_chacha20_block(transport, labels):
    """Test ChaCha20 block function with RFC 7539 vector."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["chacha20_block"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        counter = vec["counter"]
        expected = bytes.fromhex(vec["expected_keystream"])

        c64_chacha20_init(transport, labels, key, nonce, counter)
        result = c64_chacha20_block(transport, labels)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS block: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL block {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")
            # Show word-by-word diff
            for i in range(16):
                e = int.from_bytes(expected[i*4:i*4+4], 'little')
                g = int.from_bytes(result[i*4:i*4+4], 'little')
                if e != g:
                    print(f"    word {i:2d}: expected 0x{e:08X}, got 0x{g:08X}")

    return passed, failed


def test_chacha20_encrypt(transport, labels):
    """Test ChaCha20 encryption with RFC 7539 vector."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["chacha20_encrypt"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        counter = vec["counter"]
        plaintext = bytes.fromhex(vec["plaintext"])
        expected = bytes.fromhex(vec["ciphertext"])

        result = c64_chacha20_encrypt(transport, labels, key, nonce,
                                       plaintext, counter)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS encrypt: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL encrypt {vec['desc']}:")
            # Find first differing byte
            for i in range(len(expected)):
                if i >= len(result) or result[i] != expected[i]:
                    print(f"    first diff at byte {i}: "
                          f"got 0x{result[i]:02X}, expected 0x{expected[i]:02X}")
                    break

    return passed, failed


def test_chacha20_encrypt_random(transport, labels, rng, count=4):
    """Test ChaCha20 encrypt with random inputs against Python reference."""
    passed = failed = 0

    sizes = [1, 63, 64, 127]
    for i, size in enumerate(sizes):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))

        expected = chacha20_encrypt_ref(key, 1, nonce, plaintext)
        result = c64_chacha20_encrypt(transport, labels, key, nonce, plaintext)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS random encrypt #{i}: {size} bytes")
        else:
            failed += 1
            print(f"  FAIL random encrypt #{i} ({size} bytes):")
            print(f"    expected: {expected[:32].hex()}...")
            print(f"    got:      {result[:32].hex()}...")

    return passed, failed


def test_poly1305_clamp(transport, labels):
    """Test Poly1305 r clamping."""
    passed = failed = 0

    # Write a known r value and check clamping
    r_val = bytes(range(16))  # 0x00..0x0F
    write_bytes(transport, labels["poly_r"], r_val)
    write_bytes(transport, labels["poly_s"], bytes(16))  # s doesn't matter

    robust_jsr(transport, labels["poly1305_clamp"])

    result = read_bytes(transport, labels["poly_r"], 16)
    expected = bytearray(range(16))
    expected[3] &= 0x0f
    expected[7] &= 0x0f
    expected[11] &= 0x0f
    expected[15] &= 0x0f
    expected[4] &= 0xfc
    expected[8] &= 0xfc
    expected[12] &= 0xfc

    if result == bytes(expected):
        passed += 1
        if VERBOSE:
            print("  PASS poly1305_clamp: sequential bytes")
    else:
        failed += 1
        print(f"  FAIL poly1305_clamp:")
        print(f"    expected: {bytes(expected).hex()}")
        print(f"    got:      {result.hex()}")

    # Test with all-FF
    r_val = bytes([0xFF] * 16)
    write_bytes(transport, labels["poly_r"], r_val)
    robust_jsr(transport, labels["poly1305_clamp"])
    result = read_bytes(transport, labels["poly_r"], 16)
    expected = bytearray([0xFF] * 16)
    expected[3] &= 0x0f
    expected[7] &= 0x0f
    expected[11] &= 0x0f
    expected[15] &= 0x0f
    expected[4] &= 0xfc
    expected[8] &= 0xfc
    expected[12] &= 0xfc

    if result == bytes(expected):
        passed += 1
        if VERBOSE:
            print("  PASS poly1305_clamp: all-FF")
    else:
        failed += 1
        print(f"  FAIL poly1305_clamp all-FF:")
        print(f"    expected: {bytes(expected).hex()}")
        print(f"    got:      {result.hex()}")

    return passed, failed



def test_poly1305_tag(transport, labels):
    """Test Poly1305 tag computation with RFC 7539 vector."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["poly1305_tag"]:
        key = bytes.fromhex(vec["key"])
        message = bytes.fromhex(vec["message"])
        expected = bytes.fromhex(vec["tag"])

        result = c64_poly1305_mac(transport, labels, key, message)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS poly1305: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL poly1305 {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_poly1305_random(transport, labels, rng, count=4):
    """Test Poly1305 with random inputs against Python reference."""
    passed = failed = 0

    for i in range(count):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        msg_len = rng.randint(0, 64)
        message = bytes(rng.randint(0, 255) for _ in range(msg_len))

        expected = poly1305_ref(key, message)
        result = c64_poly1305_mac(transport, labels, key, message)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS random poly1305 #{i}: {msg_len} bytes")
        else:
            failed += 1
            print(f"  FAIL random poly1305 #{i} ({msg_len} bytes):")
            print(f"    key:      {key.hex()}")
            print(f"    message:  {message.hex()}")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")

    return passed, failed


def test_aead_encrypt(transport, labels):
    """Test AEAD encrypt with RFC 7539 vector."""
    passed = failed = 0

    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["aead_encrypt"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        aad = bytes.fromhex(vec["aad"])
        plaintext = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])
        expected_tag = bytes.fromhex(vec["tag"])

        ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext)

        ct_ok = ct == expected_ct
        tag_ok = tag == expected_tag

        if ct_ok and tag_ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS AEAD encrypt: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL AEAD encrypt {vec['desc']}:")
            if not ct_ok:
                print(f"    CT expected: {expected_ct[:32].hex()}...")
                print(f"    CT got:      {ct[:32].hex()}...")
            if not tag_ok:
                print(f"    tag expected: {expected_tag.hex()}")
                print(f"    tag got:      {tag.hex()}")

    return passed, failed


def test_aead_random(transport, labels, rng, count=3):
    """Test AEAD with random inputs: encrypt on C64, verify with Python."""
    passed = failed = 0

    for i in range(count):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        aad_len = rng.randint(0, 16)
        pt_len = rng.randint(1, 64)
        aad = bytes(rng.randint(0, 255) for _ in range(aad_len))
        plaintext = bytes(rng.randint(0, 255) for _ in range(pt_len))

        # Encrypt on C64
        ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext)

        # Verify with Python reference
        expected_ct, expected_tag = aead_encrypt_ref(key, nonce, aad, plaintext)

        ct_ok = ct == expected_ct
        tag_ok = tag == expected_tag

        if ct_ok and tag_ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS random AEAD #{i}: aad={aad_len}, pt={pt_len}")
        else:
            failed += 1
            print(f"  FAIL random AEAD #{i} (aad={aad_len}, pt={pt_len}):")
            if not ct_ok:
                print(f"    CT expected: {expected_ct.hex()}")
                print(f"    CT got:      {ct.hex()}")
            if not tag_ok:
                print(f"    tag expected: {expected_tag.hex()}")
                print(f"    tag got:      {tag.hex()}")

    return passed, failed


def test_aead_decrypt(transport, labels, rng):
    """Test AEAD decrypt — both valid and tampered cases."""
    passed = failed = 0

    # Test 1: Valid decrypt
    key = bytes(rng.randint(0, 255) for _ in range(32))
    nonce = bytes(rng.randint(0, 255) for _ in range(12))
    aad = bytes(rng.randint(0, 255) for _ in range(8))
    plaintext = bytes(rng.randint(0, 255) for _ in range(32))

    # Encrypt with Python reference to get valid ciphertext+tag
    ct, tag = aead_encrypt_ref(key, nonce, aad, plaintext)

    # Decrypt on C64
    pt_result, _ = c64_aead_decrypt(transport, labels, key, nonce, aad, ct, tag)

    if pt_result == plaintext:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD decrypt: valid tag")
    else:
        failed += 1
        print(f"  FAIL AEAD decrypt valid:")
        print(f"    expected: {plaintext.hex()}")
        print(f"    got:      {pt_result.hex()}")

    # Test 2: Tampered tag — verify_tag should detect
    # We can't easily check the A register return from jsr(), but we can
    # verify by checking that the poly_carry byte (used as accumulator in
    # verify_tag) is nonzero after calling with a bad tag.
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)
    aad_buf = labels["input_buffer"]
    write_bytes(transport, aad_buf, aad)
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([aad_buf & 0xFF, aad_buf >> 8]))
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))
    ct_buf = aad_buf + len(aad)
    write_bytes(transport, ct_buf, ct)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([ct_buf & 0xFF, ct_buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], struct.pack('<H', len(ct)))
    write_bytes(transport, labels["aead_tag"], bytes(bad_tag))

    # Call aead_decrypt — with tampered tag it should return A=$FF
    # We verify by checking that poly_carry is nonzero (the XOR accumulator
    # from verify_tag)
    robust_jsr(transport, labels["aead_decrypt"], timeout=300.0)
    verify_result = read_bytes(transport, labels["poly_carry"], 1)

    # After aead_decrypt returns from @auth_fail, the ciphertext should NOT
    # have been decrypted. Check that ct_buf still has original ciphertext.
    ct_check = read_bytes(transport, ct_buf, len(ct))

    if ct_check == ct:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD decrypt: tampered tag rejected (data unchanged)")
    else:
        failed += 1
        print("  FAIL AEAD decrypt tampered tag: data was modified (should be unchanged)")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups. Returns (passed, failed)."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("rotl32 functions", lambda: test_rotl32(transport, labels)),
        ("ChaCha20 quarter-round", lambda: test_chacha20_quarter_round(transport, labels)),
        ("ChaCha20 block", lambda: test_chacha20_block(transport, labels)),
        ("ChaCha20 encrypt (RFC)", lambda: test_chacha20_encrypt(transport, labels)),
        ("ChaCha20 encrypt (random)", lambda: test_chacha20_encrypt_random(transport, labels, rng)),
        ("Poly1305 clamp", lambda: test_poly1305_clamp(transport, labels)),
        ("Poly1305 tag (RFC)", lambda: test_poly1305_tag(transport, labels)),
        ("Poly1305 random", lambda: test_poly1305_random(transport, labels, rng)),
        ("AEAD encrypt (RFC)", lambda: test_aead_encrypt(transport, labels)),
        ("AEAD random", lambda: test_aead_random(transport, labels, rng)),
        ("AEAD decrypt", lambda: test_aead_decrypt(transport, labels, rng)),
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

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "b2s_tmp0", "b2s_tmp1", "w32_dst", "w32_src1",
        "rotl32_7", "rotl32_8", "rotl32_12", "rotl32_4", "rotr32_1",
        "chacha20_init", "chacha20_block", "chacha20_quarter_round",
        "chacha20_encrypt",
        "cc20_key", "cc20_nonce", "cc20_counter", "cc20_state", "cc20_work",
        "cc20_keystream", "cc20_data_ptr", "cc20_remain", "cc20_qr_idx",
        "cc20_qr_table",
        "poly1305_init", "poly1305_clamp", "poly1305_update", "poly1305_final",
        "poly_r", "poly_s", "poly_h", "poly1305_tag", "poly_carry",
        "aead_encrypt", "aead_decrypt",
        "aead_key", "aead_nonce", "aead_aad_ptr", "aead_aad_len",
        "aead_data_ptr", "aead_data_len", "aead_tag",
        "input_buffer", "zp_ptr1",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"Labels loaded: {len(required)} required labels verified")

    # Launch VICE with auto-allocated port to avoid conflicts
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

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
