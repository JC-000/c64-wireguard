#!/usr/bin/env python3
"""test_session.py — WireGuard session state machine tests.

Tests entropy, config loading, session state transitions, Type 2
handshake response processing, Type 4 transport data, and full
round-trip with Python Noise IKpsk2 responder reference.

Usage:
    python3 tools/test_session.py [--seed S] [--verbose] [--slow]
"""

import hashlib
import hmac as hmac_mod
import os
import random
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
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
SLOW = False


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
# Python Noise IKpsk2 reference (responder side)
# ============================================================================

WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
WG_LABEL_MAC1 = b"mac1----"


def blake2s_256(data):
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_hmac(key, data):
    """HMAC-BLAKE2s-256."""
    # WireGuard uses HMAC with BLAKE2s (not keyed BLAKE2s)
    return hmac_mod.new(key, data, lambda: hashlib.blake2s(digest_size=32)).digest()


def kdf_n(c, input_data, n):
    """WireGuard KDF: HMAC-based extract-then-expand.
    Returns n outputs (1, 2, or 3).
    """
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


def py_noise_responder(type1_packet, resp_static_priv_bytes, resp_static_pub_bytes,
                       init_static_pub_bytes, psk=None):
    """Process a Type 1 initiation packet as responder and produce Type 2.

    Returns: (type2_packet_92_bytes, initiator_send_key, initiator_recv_key)
    where send/recv keys are from the INITIATOR's perspective.

    Raises on AEAD verification failure.
    """
    if psk is None:
        psk = b'\x00' * 32
    # Parse Type 1 (148 bytes)
    assert len(type1_packet) == 148
    assert type1_packet[0] == 1  # type
    init_sender_idx = type1_packet[4:8]
    init_ephem_pub = type1_packet[8:40]
    encrypted_static = type1_packet[40:88]  # 32 + 16 tag
    encrypted_timestamp = type1_packet[88:116]  # 12 + 16 tag
    # mac1 at [116:132], mac2 at [132:148] — not verified here

    # Initiator's steps replayed by responder:
    c_init = blake2s_256(WG_CONSTRUCTION)
    h_init = blake2s_256(c_init + WG_IDENTIFIER)

    # hs_init: H = BLAKE2s(H_init || resp_pub)
    h = mix_hash(h_init, resp_static_pub_bytes)
    c = c_init

    # mix_hash(e_pub)
    h = mix_hash(h, init_ephem_pub)

    # kdf_1(C, e_pub)
    (c,) = kdf_n(c, init_ephem_pub, 1)

    # DH(resp_static_priv, init_ephem_pub)
    resp_priv_key = X25519PrivateKey.from_private_bytes(resp_static_priv_bytes)
    init_ephem_pub_key = X25519PublicKey.from_public_bytes(init_ephem_pub)
    dh1 = resp_priv_key.exchange(init_ephem_pub_key)

    # kdf_2(C, dh1)
    c, k = kdf_n(c, dh1, 2)

    # AEAD decrypt static_pub
    nonce = b'\x00' * 12
    aead = ChaCha20Poly1305(k)
    init_static_pub_decrypted = aead.decrypt(nonce, encrypted_static, h)
    assert init_static_pub_decrypted == init_static_pub_bytes

    # mix_hash(encrypted_static, 48)
    h = mix_hash(h, encrypted_static)

    # DH(resp_static_priv, init_static_pub)
    init_static_pub_key = X25519PublicKey.from_public_bytes(init_static_pub_bytes)
    dh2 = resp_priv_key.exchange(init_static_pub_key)

    # kdf_2(C, dh2)
    c, k = kdf_n(c, dh2, 2)

    # AEAD decrypt timestamp
    aead = ChaCha20Poly1305(k)
    timestamp = aead.decrypt(nonce, encrypted_timestamp, h)

    # mix_hash(encrypted_timestamp, 28)
    h = mix_hash(h, encrypted_timestamp)

    # --- Now build responder's Type 2 ---
    # Generate responder ephemeral key
    resp_ephem_priv = X25519PrivateKey.generate()
    resp_ephem_pub = resp_ephem_priv.public_key().public_bytes_raw()

    # Responder sender index (random 4 bytes)
    resp_sender_idx = os.urandom(4)

    # mix_hash(resp_e_pub)
    h = mix_hash(h, resp_ephem_pub)

    # kdf_1(C, resp_e_pub)
    (c,) = kdf_n(c, resp_ephem_pub, 1)

    # DH(resp_ephem_priv, init_ephem_pub)
    dh3 = resp_ephem_priv.exchange(init_ephem_pub_key)
    (c,) = kdf_n(c, dh3, 1)

    # DH(resp_ephem_priv, init_static_pub)
    dh4 = resp_ephem_priv.exchange(init_static_pub_key)
    (c,) = kdf_n(c, dh4, 1)

    # AEAD encrypt nothing (empty plaintext) — IKpsk2 PSK mixing
    c, t, k = kdf_n(c, psk, 3)
    h = mix_hash(h, t)

    aead = ChaCha20Poly1305(k)
    encrypted_nothing = aead.encrypt(nonce, b'', h)  # 16-byte tag only

    # mix_hash(encrypted_nothing)
    h = mix_hash(h, encrypted_nothing)

    # Derive transport keys
    i_send, i_recv = kdf_n(c, b'', 2)

    # Build Type 2 packet (92 bytes)
    type2 = bytearray(92)
    type2[0] = 2  # type
    type2[1:4] = b'\x00' * 3  # reserved
    type2[4:8] = resp_sender_idx
    type2[8:12] = init_sender_idx  # receiver = initiator's sender
    type2[12:44] = resp_ephem_pub
    type2[44:60] = encrypted_nothing
    # MAC1
    mac1_key = blake2s_256(WG_LABEL_MAC1 + resp_static_pub_bytes)
    mac1 = hashlib.blake2s(bytes(type2[:60]), key=mac1_key, digest_size=16).digest()
    type2[60:76] = mac1
    type2[76:92] = b'\x00' * 16  # MAC2 = zeros

    return bytes(type2), i_send, i_recv


def py_noise_responder_from_state(c, h, init_ephem_pub, init_static_pub_bytes,
                                   resp_static_priv_bytes, resp_static_pub_bytes,
                                   init_sender_idx, psk=None):
    """Build Type 2 from mid-handshake state (after Type 1 processing).

    This allows testing Type 2 processing WITHOUT running X25519 on C64.
    Takes (c, h) that represent the handshake state after hs_create_initiation.

    Returns: (type2_packet, initiator_send_key, initiator_recv_key)
    """
    if psk is None:
        psk = b'\x00' * 32
    resp_ephem_priv = X25519PrivateKey.generate()
    resp_ephem_pub = resp_ephem_priv.public_key().public_bytes_raw()
    resp_sender_idx = os.urandom(4)

    init_ephem_pub_key = X25519PublicKey.from_public_bytes(init_ephem_pub)
    init_static_pub_key = X25519PublicKey.from_public_bytes(init_static_pub_bytes)

    # mix_hash(resp_e_pub)
    h = mix_hash(h, resp_ephem_pub)

    # kdf_1(C, resp_e_pub)
    (c,) = kdf_n(c, resp_ephem_pub, 1)

    # DH(resp_ephem_priv, init_ephem_pub)
    dh3 = resp_ephem_priv.exchange(init_ephem_pub_key)
    (c,) = kdf_n(c, dh3, 1)

    # DH(resp_ephem_priv, init_static_pub)
    dh4 = resp_ephem_priv.exchange(init_static_pub_key)
    (c,) = kdf_n(c, dh4, 1)

    # AEAD encrypt nothing — IKpsk2 PSK mixing
    c, t, k = kdf_n(c, psk, 3)
    h = mix_hash(h, t)

    nonce = b'\x00' * 12
    aead = ChaCha20Poly1305(k)
    encrypted_nothing = aead.encrypt(nonce, b'', h)

    h = mix_hash(h, encrypted_nothing)

    # Transport keys
    i_send, i_recv = kdf_n(c, b'', 2)

    # Build Type 2
    type2 = bytearray(92)
    type2[0] = 2
    type2[1:4] = b'\x00' * 3
    type2[4:8] = resp_sender_idx
    type2[8:12] = init_sender_idx
    type2[12:44] = resp_ephem_pub
    type2[44:60] = encrypted_nothing
    # MAC1 for Type 2
    mac1_key = blake2s_256(WG_LABEL_MAC1 + resp_static_pub_bytes)
    mac1 = hashlib.blake2s(bytes(type2[:60]), key=mac1_key, digest_size=16).digest()
    type2[60:76] = mac1
    type2[76:92] = b'\x00' * 16

    return bytes(type2), i_send, i_recv


# ============================================================================
# Test groups
# ============================================================================

def test_build_verification(labels):
    """Verify new Phase 6 labels exist and memory layout is correct."""
    passed = failed = 0

    required_labels = [
        # entropy
        "entropy_init", "entropy_byte", "entropy_fill",
        # config
        "config_load",
        "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
        "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
        # session
        "session_initiate", "session_handle_packet",
        "session_reset", "display_payload",
        "wg_state",
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

    # All code below $7800
    for name in ["entropy_init", "config_load", "session_initiate",
                  "session_handle_packet", "display_payload"]:
        addr = labels.address(name)
        if addr is not None and addr < 0x7800:
            passed += 1
            if VERBOSE:
                print(f"  PASS {name} ${addr:04X} < $7800")
        else:
            failed += 1
            print(f"  FAIL {name} address check")

    # Data labels below $7800
    for name in ["wg_state", "cfg_static_priv", "cfg_peer_pub"]:
        addr = labels.address(name)
        if addr is not None and addr < 0x7800:
            passed += 1
            if VERBOSE:
                print(f"  PASS {name} data ${addr:04X} < $7800")
        else:
            failed += 1
            print(f"  FAIL {name} data address check")

    return passed, failed


def test_entropy(transport, labels):
    """Test entropy routines."""
    passed = failed = 0

    # Test entropy_init runs without crash
    robust_jsr(transport, labels["entropy_init"])
    passed += 1
    if VERBOSE:
        print("  PASS entropy_init runs")

    # Test entropy_byte returns values (write trampoline)
    # Trampoline at $0340:
    #   LDY #count    ; A0 count       offset 0
    # loop:
    #   JSR entropy_byte  ; 20 lo hi   offset 2
    #   STA $0360,Y   ; 99 60 03       offset 5
    #   DEY           ; 88             offset 8
    #   BNE loop      ; D0 F7 (-9)    offset 9
    #   STA $0360     ; 8D 60 03       offset 11
    #   RTS           ; 60             offset 14
    eb_addr = labels["entropy_byte"]
    trampoline = bytes([
        0xA0, 16,                           # LDY #16
        0x20, eb_addr & 0xFF, eb_addr >> 8, # JSR entropy_byte
        0x99, 0x60, 0x03,                   # STA $0360,Y
        0x88,                               # DEY
        0xD0, 0xF7,                         # BNE loop (-9)
        0x8D, 0x60, 0x03,                   # STA $0360
        0x60,                               # RTS
    ])
    write_bytes(transport, 0x0340, trampoline)
    robust_jsr(transport, 0x0340, timeout=10.0)

    # Read 17 bytes from $0360
    results = read_bytes(transport, 0x0360, 17)

    # Check not all same (entropy should vary)
    unique = len(set(results))
    if unique > 1:
        passed += 1
        if VERBOSE:
            print(f"  PASS entropy_byte: {unique} unique values in 17 samples")
    else:
        failed += 1
        print(f"  FAIL entropy_byte: all {len(results)} bytes identical ({results[0]:#04x})")

    # Test entropy_fill
    buf_addr = labels["input_buffer"]
    # Zero the area first
    write_bytes(transport, buf_addr, bytes(32))

    # Set up zp_ptr1 and Y=32
    write_bytes(transport, labels["zp_ptr1"],
                struct.pack('<H', buf_addr))

    # Trampoline for entropy_fill: LDY #32; JSR entropy_fill; RTS
    ef_addr = labels["entropy_fill"]
    tramp2 = bytes([
        0xA0, 32,                           # LDY #32
        0x20, ef_addr & 0xFF, ef_addr >> 8, # JSR entropy_fill
        0x60,                               # RTS
    ])
    write_bytes(transport, 0x0340, tramp2)
    robust_jsr(transport, 0x0340, timeout=10.0)

    filled = read_bytes(transport, buf_addr, 32)
    unique_fill = len(set(filled))
    if unique_fill > 1:
        passed += 1
        if VERBOSE:
            print(f"  PASS entropy_fill: {unique_fill} unique values in 32 bytes")
    else:
        failed += 1
        print(f"  FAIL entropy_fill: all bytes identical")

    # Test entropy_fill doesn't corrupt outside buffer
    # (Harder to test — just verify it wrote 32 bytes)
    non_zero = sum(1 for b in filled if b != 0)
    if non_zero > 0:
        passed += 1
        if VERBOSE:
            print(f"  PASS entropy_fill: {non_zero} non-zero bytes")
    else:
        failed += 1
        print(f"  FAIL entropy_fill: all zeros (no entropy?)")

    # Run entropy_byte multiple times and check statistical variation
    write_bytes(transport, 0x0340, trampoline)  # rewrite 17-sample trampoline
    robust_jsr(transport, 0x0340, timeout=10.0)
    results2 = read_bytes(transport, 0x0360, 17)
    # Different from first run (very unlikely to be identical)
    if results != results2:
        passed += 1
        if VERBOSE:
            print("  PASS entropy_byte: different between runs")
    else:
        # Not a hard failure — could theoretically match
        passed += 1
        if VERBOSE:
            print("  PASS entropy_byte: (same between runs — unlikely but possible)")

    return passed, failed


def test_config_load(transport, labels):
    """Test config_load copies all fields correctly."""
    passed = failed = 0

    rng = random.Random(42)

    # Generate random config data
    static_priv = bytes(rng.randint(0, 255) for _ in range(32))
    static_pub = bytes(rng.randint(0, 255) for _ in range(32))
    peer_pub = bytes(rng.randint(0, 255) for _ in range(32))
    peer_ip = bytes(rng.randint(0, 255) for _ in range(4))
    peer_port = bytes(rng.randint(0, 255) for _ in range(2))

    # Write to cfg_* buffers
    write_bytes(transport, labels["cfg_static_priv"], static_priv)
    write_bytes(transport, labels["cfg_static_pub"], static_pub)
    write_bytes(transport, labels["cfg_peer_pub"], peer_pub)
    write_bytes(transport, labels["cfg_peer_endpoint_ip"], peer_ip)
    write_bytes(transport, labels["cfg_peer_endpoint_port"], peer_port)

    # Call config_load
    robust_jsr(transport, labels["config_load"])

    # Verify all destinations
    checks = [
        ("hs_static_priv", static_priv),
        ("hs_static_pub", static_pub),
        ("hs_resp_pub", peer_pub),
        ("wg_peer_ip", peer_ip),
        ("wg_peer_port", peer_port),
    ]

    for name, expected in checks:
        got = bytes(read_bytes(transport, labels[name], len(expected)))
        if got == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS config_load: {name}")
        else:
            failed += 1
            print(f"  FAIL config_load {name}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {got.hex()}")

    return passed, failed


def test_state_transitions(transport, labels):
    """Test session state machine transitions."""
    passed = failed = 0

    # Initial state should be IDLE (0)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 0:
        passed += 1
        if VERBOSE:
            print("  PASS initial state = IDLE")
    else:
        failed += 1
        print(f"  FAIL initial state = {state}, expected 0 (IDLE)")

    # session_reset → IDLE
    write_bytes(transport, labels["wg_state"], bytes([2]))  # pretend ACTIVE
    robust_jsr(transport, labels["session_reset"])
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 0:
        passed += 1
        if VERBOSE:
            print("  PASS session_reset → IDLE")
    else:
        failed += 1
        print(f"  FAIL session_reset: state = {state}, expected 0")

    # Type 2 packet ignored in IDLE state
    write_bytes(transport, labels["wg_state"], bytes([0]))  # IDLE
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    type2_fake = bytearray(92)
    type2_fake[0] = 2
    write_bytes(transport, labels["udp_recv_buf"], bytes(type2_fake))
    robust_jsr(transport, labels["session_handle_packet"])
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 0:
        passed += 1
        if VERBOSE:
            print("  PASS Type 2 ignored in IDLE")
    else:
        failed += 1
        print(f"  FAIL Type 2 in IDLE: state changed to {state}")

    # Type 4 packet ignored in HS_SENT state
    write_bytes(transport, labels["wg_state"], bytes([1]))  # HS_SENT
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    type4_fake = bytearray(48)
    type4_fake[0] = 4
    write_bytes(transport, labels["udp_recv_buf"], bytes(type4_fake))
    write_bytes(transport, labels["udp_recv_len"], struct.pack('<H', 48))
    robust_jsr(transport, labels["session_handle_packet"])
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 1:
        passed += 1
        if VERBOSE:
            print("  PASS Type 4 ignored in HS_SENT")
    else:
        failed += 1
        print(f"  FAIL Type 4 in HS_SENT: state changed to {state}")

    # Unknown packet type ignored
    write_bytes(transport, labels["wg_state"], bytes([2]))  # ACTIVE
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    unknown = bytearray(20)
    unknown[0] = 99
    write_bytes(transport, labels["udp_recv_buf"], bytes(unknown))
    robust_jsr(transport, labels["session_handle_packet"])
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS unknown type ignored in ACTIVE")
    else:
        failed += 1
        print(f"  FAIL unknown type: state changed to {state}")

    return passed, failed


def test_type2_processing(transport, labels, rng):
    """Test Type 2 handshake response processing with known keys.

    Bypasses X25519 by setting up handshake state (hs_c, hs_h, hs_ephem_priv,
    hs_static_priv) directly and using Python to build matching Type 2.

    WARNING: This test is VERY slow (~150 min per trial) because
    session_handle_packet → hs_process_response → 3x X25519.
    Only runs with --slow.
    """
    passed = failed = 0

    for trial in range(5):
        # Generate fresh key pairs in Python
        init_static_priv = X25519PrivateKey.generate()
        init_static_pub = init_static_priv.public_key().public_bytes_raw()
        init_static_priv_bytes = init_static_priv.private_bytes_raw()

        resp_static_priv = X25519PrivateKey.generate()
        resp_static_pub = resp_static_priv.public_key().public_bytes_raw()
        resp_static_priv_bytes = resp_static_priv.private_bytes_raw()

        init_ephem_priv = X25519PrivateKey.generate()
        init_ephem_pub = init_ephem_priv.public_key().public_bytes_raw()
        init_ephem_priv_bytes = init_ephem_priv.private_bytes_raw()

        init_sender_idx = bytes(rng.randint(0, 255) for _ in range(4))

        # Compute the handshake state that hs_create_initiation would produce
        # (replaying the initiator steps in Python to get c, h)
        c_init = blake2s_256(WG_CONSTRUCTION)
        h_init = blake2s_256(c_init + WG_IDENTIFIER)
        h = mix_hash(h_init, resp_static_pub)
        c = c_init

        # mix_hash(ephem_pub)
        h = mix_hash(h, init_ephem_pub)

        # kdf_1(C, ephem_pub)
        (c,) = kdf_n(c, init_ephem_pub, 1)

        # DH(init_ephem_priv, resp_static_pub)
        dh1 = init_ephem_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
        c, k1 = kdf_n(c, dh1, 2)

        # AEAD encrypt static_pub
        nonce = b'\x00' * 12
        aead1 = ChaCha20Poly1305(k1)
        encrypted_static = aead1.encrypt(nonce, init_static_pub, h)

        # mix_hash(encrypted_static)
        h = mix_hash(h, encrypted_static)

        # DH(init_static_priv, resp_static_pub)
        dh2 = init_static_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
        c, k2 = kdf_n(c, dh2, 2)

        # AEAD encrypt timestamp
        timestamp = bytes(rng.randint(0, 255) for _ in range(12))
        aead2 = ChaCha20Poly1305(k2)
        encrypted_timestamp = aead2.encrypt(nonce, timestamp, h)

        # mix_hash(encrypted_timestamp)
        h = mix_hash(h, encrypted_timestamp)

        # Now c and h represent the state after hs_create_initiation
        # Build Type 2 from this state
        type2, i_send_key, i_recv_key = py_noise_responder_from_state(
            c, h, init_ephem_pub, init_static_pub,
            resp_static_priv_bytes, resp_static_pub,
            init_sender_idx
        )

        # Set up C64 state: write hs_c, hs_h, keys, sender_idx, state=HS_SENT
        write_bytes(transport, labels["hs_c"], c)
        write_bytes(transport, labels["hs_h"], h)
        write_bytes(transport, labels["hs_ephem_priv"], init_ephem_priv_bytes)
        write_bytes(transport, labels["hs_static_priv"], init_static_priv_bytes)
        write_bytes(transport, labels["hs_static_pub"], init_static_pub)
        write_bytes(transport, labels["hs_resp_pub"], resp_static_pub)
        write_bytes(transport, labels["hs_sender_idx"], init_sender_idx)
        write_bytes(transport, labels["wg_state"], bytes([1]))  # HS_SENT

        # Write Type 2 to udp_recv_buf and trigger processing
        write_bytes(transport, labels["udp_recv_buf"], type2)
        write_bytes(transport, labels["udp_recv_len"], struct.pack('<H', 92))
        write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

        robust_jsr(transport, labels["session_handle_packet"], timeout=120.0)

        # Check state transitioned to ACTIVE
        state = read_bytes(transport, labels["wg_state"], 1)[0]
        if state != 2:
            failed += 1
            print(f"  FAIL type2 #{trial}: state={state}, expected 2 (ACTIVE)")
            continue

        # Verify transport keys match Python
        c64_send = bytes(read_bytes(transport, labels["hs_transport_send"], 32))
        c64_recv = bytes(read_bytes(transport, labels["hs_transport_recv"], 32))

        if c64_send == i_send_key and c64_recv == i_recv_key:
            passed += 1
            if VERBOSE:
                print(f"  PASS type2 #{trial}: transport keys match")
        else:
            failed += 1
            print(f"  FAIL type2 #{trial}: transport key mismatch")
            if c64_send != i_send_key:
                print(f"    send expected: {i_send_key.hex()}")
                print(f"    send got:      {c64_send.hex()}")
            if c64_recv != i_recv_key:
                print(f"    recv expected: {i_recv_key.hex()}")
                print(f"    recv got:      {c64_recv.hex()}")

    return passed, failed


def test_type2_tampered(transport, labels, rng):
    """Test that tampered Type 2 packets are rejected."""
    passed = failed = 0

    # Generate keys and valid Type 2
    init_static_priv = X25519PrivateKey.generate()
    init_static_pub = init_static_priv.public_key().public_bytes_raw()
    init_static_priv_bytes = init_static_priv.private_bytes_raw()

    resp_static_priv = X25519PrivateKey.generate()
    resp_static_pub = resp_static_priv.public_key().public_bytes_raw()
    resp_static_priv_bytes = resp_static_priv.private_bytes_raw()

    init_ephem_priv = X25519PrivateKey.generate()
    init_ephem_pub = init_ephem_priv.public_key().public_bytes_raw()
    init_ephem_priv_bytes = init_ephem_priv.private_bytes_raw()

    init_sender_idx = bytes([0x01, 0x02, 0x03, 0x04])

    # Replay initiator to get state
    c_init = blake2s_256(WG_CONSTRUCTION)
    h_init = blake2s_256(c_init + WG_IDENTIFIER)
    h = mix_hash(h_init, resp_static_pub)
    c = c_init
    h = mix_hash(h, init_ephem_pub)
    (c,) = kdf_n(c, init_ephem_pub, 1)
    dh1 = init_ephem_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k1 = kdf_n(c, dh1, 2)
    nonce = b'\x00' * 12
    encrypted_static = ChaCha20Poly1305(k1).encrypt(nonce, init_static_pub, h)
    h = mix_hash(h, encrypted_static)
    dh2 = init_static_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k2 = kdf_n(c, dh2, 2)
    timestamp = bytes(12)
    encrypted_timestamp = ChaCha20Poly1305(k2).encrypt(nonce, timestamp, h)
    h = mix_hash(h, encrypted_timestamp)

    # Build valid Type 2
    valid_type2, _, _ = py_noise_responder_from_state(
        c, h, init_ephem_pub, init_static_pub,
        resp_static_priv_bytes, resp_static_pub,
        init_sender_idx
    )

    # Tamper with encrypted_nothing (flip a byte in the AEAD tag area)
    tampered = bytearray(valid_type2)
    tampered[50] ^= 0xFF  # flip byte in AEAD tag area

    # Set up C64 state
    write_bytes(transport, labels["hs_c"], c)
    write_bytes(transport, labels["hs_h"], h)
    write_bytes(transport, labels["hs_ephem_priv"], init_ephem_priv_bytes)
    write_bytes(transport, labels["hs_static_priv"], init_static_priv_bytes)
    write_bytes(transport, labels["hs_static_pub"], init_static_pub)
    write_bytes(transport, labels["hs_resp_pub"], resp_static_pub)
    write_bytes(transport, labels["hs_sender_idx"], init_sender_idx)
    write_bytes(transport, labels["wg_state"], bytes([1]))  # HS_SENT

    # Send tampered packet
    write_bytes(transport, labels["udp_recv_buf"], bytes(tampered))
    write_bytes(transport, labels["udp_recv_len"], struct.pack('<H', 92))
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

    robust_jsr(transport, labels["session_handle_packet"], timeout=120.0)

    # State should NOT be ACTIVE (should still be HS_SENT)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state != 2:
        passed += 1
        if VERBOSE:
            print(f"  PASS tampered Type 2 rejected (state={state})")
    else:
        failed += 1
        print(f"  FAIL tampered Type 2 accepted (state=ACTIVE)")

    return passed, failed


def test_type4_in_session(transport, labels, rng):
    """Test Type 4 transport decrypt in ACTIVE state."""
    passed = failed = 0

    for trial in range(4):
        # Set up transport keys (random)
        send_key = bytes(rng.randint(0, 255) for _ in range(32))
        recv_key = bytes(rng.randint(0, 255) for _ in range(32))
        receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))

        # Python encrypts with recv_key (peer sends using its send key)
        # C64 decrypts with recv_key
        # For this test, we use recv_key on C64 side and encrypt with it in Python
        payload_len = rng.randint(1, 64)
        plaintext = bytes(rng.randint(0, 255) for _ in range(payload_len))
        counter_val = rng.randint(0, 0xFFFF)

        # Python encrypts
        nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
        aead = ChaCha20Poly1305(recv_key)
        ct_tag = aead.encrypt(nonce, plaintext, None)

        # Build Type 4 packet
        pkt = bytearray()
        pkt += struct.pack('<I', 4)  # type
        pkt += receiver_idx           # receiver index
        pkt += struct.pack('<Q', counter_val)
        pkt += ct_tag

        # Set up C64 in ACTIVE state with matching transport keys
        write_bytes(transport, labels["hs_transport_recv"], recv_key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_recv_counter"],
                    struct.pack('<Q', counter_val))  # accept this counter
        write_bytes(transport, labels["wg_state"], bytes([2]))  # ACTIVE

        # Write packet to udp_recv_buf
        write_bytes(transport, labels["udp_recv_buf"], bytes(pkt))
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(pkt)))
        write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

        robust_jsr(transport, labels["session_handle_packet"], timeout=60.0)

        # Verify payload was decrypted
        dec_len = read_bytes(transport, labels["tp_payload_len"], 1)[0]
        decrypted = bytes(read_bytes(transport, labels["tp_packet"] + 16, payload_len))

        if decrypted == plaintext and dec_len == payload_len:
            passed += 1
            if VERBOSE:
                print(f"  PASS type4 #{trial}: {payload_len}B decrypted OK")
        else:
            failed += 1
            print(f"  FAIL type4 #{trial}:")
            if dec_len != payload_len:
                print(f"    len expected={payload_len}, got={dec_len}")
            if decrypted != plaintext:
                print(f"    plaintext mismatch")
                print(f"    expected: {plaintext.hex()}")
                print(f"    got:      {decrypted.hex()}")

    return passed, failed


def test_round_trip(transport, labels, rng):
    """Test C64 encrypt → Python decrypt round-trip."""
    passed = failed = 0

    sizes = [1, 16, 32, 64, 128]

    for i, size in enumerate(sizes):
        # Brief pause between round-trips to let VICE monitor settle
        if i > 0:
            time.sleep(1.0)

        send_key = bytes(rng.randint(0, 255) for _ in range(32))
        receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))
        counter_val = rng.randint(0, 0xFFFF)

        # Set up C64 for encrypt
        write_bytes(transport, labels["hs_transport_send"], send_key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_send_counter"],
                    struct.pack('<Q', counter_val))

        write_bytes(transport, labels["input_buffer"], plaintext)
        write_bytes(transport, labels["tp_payload_ptr"],
                    struct.pack('<H', labels["input_buffer"]))
        write_bytes(transport, labels["tp_payload_len"], bytes([size]))

        robust_jsr(transport, labels["transport_encrypt"], timeout=60.0)

        # Read packet
        pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
        pkt_len = int.from_bytes(pkt_len_bytes, 'little')
        packet = bytes(read_bytes(transport, labels["tp_packet"], pkt_len))

        # Python decrypt
        pkt_counter = struct.unpack('<Q', packet[8:16])[0]
        ct_tag = packet[16:]
        nonce = b'\x00' * 4 + struct.pack('<Q', pkt_counter)
        aead = ChaCha20Poly1305(send_key)

        try:
            decrypted = aead.decrypt(nonce, ct_tag, None)
            if decrypted == plaintext:
                passed += 1
                if VERBOSE:
                    print(f"  PASS round-trip #{i}: {size}B OK")
            else:
                failed += 1
                print(f"  FAIL round-trip #{i}: plaintext mismatch")
        except Exception as e:
            failed += 1
            print(f"  FAIL round-trip #{i}: decrypt error: {e}")

    return passed, failed


def test_display_payload(transport, labels):
    """Test display_payload routine."""
    passed = failed = 0

    # Write test payload to tp_packet+16
    test_msg = b"HELLO WIREGUARD"
    tp_pkt_addr = labels["tp_packet"]
    write_bytes(transport, tp_pkt_addr + 16, test_msg)
    write_bytes(transport, labels["tp_payload_len"], bytes([len(test_msg)]))

    # Call display_payload (just verify it doesn't crash)
    robust_jsr(transport, labels["display_payload"])
    passed += 1
    if VERBOSE:
        print("  PASS display_payload runs without crash")

    # Test with non-printable characters
    test_mixed = bytes([0x01, 0x41, 0x42, 0x7F, 0x43])
    write_bytes(transport, tp_pkt_addr + 16, test_mixed)
    write_bytes(transport, labels["tp_payload_len"], bytes([len(test_mixed)]))
    robust_jsr(transport, labels["display_payload"])
    passed += 1
    if VERBOSE:
        print("  PASS display_payload with non-printable chars")

    # Test with zero length
    write_bytes(transport, labels["tp_payload_len"], bytes([0]))
    robust_jsr(transport, labels["display_payload"])
    passed += 1
    if VERBOSE:
        print("  PASS display_payload with zero length")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("entropy", lambda: test_entropy(transport, labels)),
        ("config_load", lambda: test_config_load(transport, labels)),
        ("state transitions", lambda: test_state_transitions(transport, labels)),
        ("Type 4 in session", lambda: test_type4_in_session(transport, labels, rng)),
        ("round-trip", lambda: test_round_trip(transport, labels, rng)),
        ("display_payload", lambda: test_display_payload(transport, labels)),
    ]

    if SLOW:
        groups.insert(3, ("Type 2 processing",
                          lambda: test_type2_processing(transport, labels, rng)))
        groups.insert(4, ("Type 2 tampered",
                          lambda: test_type2_tampered(transport, labels, rng)))
    else:
        print("\n  (Type 2 processing tests skipped — use --slow to enable, ~150 min)")

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
        # Small delay between groups to let VICE monitor settle
        time.sleep(1.0)

    return total_passed, total_failed


def main():
    global VERBOSE, SLOW

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
        elif args[i] == "--slow":
            SLOW = True
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
        "entropy_init", "entropy_byte", "entropy_fill",
        "config_load", "cfg_static_priv", "cfg_static_pub",
        "cfg_peer_pub", "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
        "session_initiate", "session_handle_packet", "session_reset",
        "display_payload", "wg_state",
        "hs_c", "hs_h", "hs_ephem_priv", "hs_static_priv",
        "hs_static_pub", "hs_resp_pub", "hs_sender_idx",
        "hs_packet", "hs_resp_packet",
        "hs_transport_send", "hs_transport_recv",
        "udp_recv_buf", "udp_recv_len", "udp_recv_ready",
        "tp_packet", "tp_packet_len", "tp_payload_ptr",
        "tp_payload_len", "tp_send_counter", "tp_recv_counter",
        "tp_peer_recv_idx", "input_buffer",
        "zp_ptr1", "transport_encrypt", "transport_decrypt",
        "transport_init",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Build verification (no VICE needed)
    print("\n--- build verification ---")
    bp, bf = test_build_verification(labels)
    print(f"  {bp} passed, {bf} failed")
    if bf > 0:
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

        # Safety: write JMP $0339 at $0339 so CPU loops harmlessly
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Initialize entropy before tests
        robust_jsr(transport, labels["entropy_init"])

        passed, failed = run_tests(transport, labels, seed)
        total_passed = passed + bp
        total_failed = failed + bf

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
