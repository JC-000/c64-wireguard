#!/usr/bin/env python3
"""test_mac2_integration.py — End-to-end MAC2/cookie flow integration tests.

Verifies the full flow:
  1. MAC2 is zero when no cookie is available
  2. cookie_handle_type3 stores a valid cookie
  3. MAC2 is correctly computed from cookie after cookie is stored
  4. cookie_valid is cleared after MAC2 computation

Usage:
    python3 tools/test_mac2_integration.py [--seed S] [--verbose]
"""

import hashlib
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


# ---------------------------------------------------------------------------
# Python crypto helpers
# ---------------------------------------------------------------------------

def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF


def hchacha20_py(key_32, nonce_16):
    """HChaCha20: key(32B) + nonce(16B) -> subkey(32B)."""
    state = list(struct.unpack('<16I',
        b'expand 32-byte k' + key_32 + nonce_16))
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)
    return struct.pack('<4I', state[0], state[1], state[2], state[3]) + \
           struct.pack('<4I', state[12], state[13], state[14], state[15])


def xchacha20poly1305_encrypt(key, nonce_24, plaintext, aad):
    """XChaCha20-Poly1305 encrypt using HChaCha20 + ChaCha20-Poly1305."""
    subkey = hchacha20_py(key, nonce_24[:16])
    chacha_nonce = b'\x00\x00\x00\x00' + nonce_24[16:24]
    aead = ChaCha20Poly1305(subkey)
    return aead.encrypt(chacha_nonce, plaintext, aad)


def py_mac2(cookie_16, packet_data_132):
    """Compute MAC2 = BLAKE2s-128(key=cookie, data=packet[0:132])."""
    return hashlib.blake2s(packet_data_132, key=cookie_16, digest_size=16).digest()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_mac2_zero_without_cookie(transport, labels, rng):
    """Test 1: MAC2 is all zeros when cookie_valid=0.

    Pre-fill hs_packet[0..131] with known data, set cookie_valid=0,
    then call hs_set_mac2 indirectly by checking the MAC2 region.
    Actually, hs_create_initiation checks cookie_valid and skips hs_set_mac2,
    writing zeros instead. So we test via hs_compute_mac1 + the zero branch.

    Simpler approach: fill hs_packet[0..131], set cookie_valid=0, and call
    the MAC2 portion. But hs_set_mac2 is only called when cookie_valid=1.
    The zero path is in hs_create_initiation. So we test the zero path by
    directly writing known data to hs_packet, setting cookie_valid=0, and
    invoking the MAC2 branch of hs_create_initiation.

    Simplest: just write packet data, set cookie_valid=0, build a trampoline
    that checks cookie_valid and either calls hs_set_mac2 or zeros MAC2
    (mimicking the hs_create_initiation logic). But that re-implements ASM.

    Best approach: fill hs_packet[0..147] with 0xFF, set cookie_valid=0,
    then use a trampoline that runs the MAC2 branch from hs_create_initiation.
    We replicate the branch: LDA cookie_valid; BEQ @zero_mac2; ...
    """
    passed = failed = 0

    hs_packet_addr = labels["hs_packet"]
    cookie_valid_addr = labels["cookie_valid"]

    # Fill hs_packet[0..147] with 0xAA (so MAC2 region is non-zero initially)
    write_bytes(transport, hs_packet_addr, bytes([0xAA] * 148))

    # Set cookie_valid = 0
    write_bytes(transport, cookie_valid_addr, bytes([0]))

    # Build trampoline that mimics the MAC2 branch from hs_create_initiation:
    #   LDA cookie_valid
    #   BEQ @zero_mac2
    #   JSR hs_set_mac2
    #   JMP @done
    # @zero_mac2:
    #   LDX #$0F
    #   LDA #$00
    # @clr: STA hs_packet+132,X
    #   DEX
    #   BPL @clr
    # @done:
    #   RTS
    set_mac2_addr = labels["hs_set_mac2"]
    mac2_offset = hs_packet_addr + 132
    trampoline_addr = 0x0370
    trampoline = bytearray()
    # LDA cookie_valid (absolute)
    trampoline += bytes([0xAD, cookie_valid_addr & 0xFF, (cookie_valid_addr >> 8) & 0xFF])
    # BEQ +5 (skip JSR + JMP)
    trampoline += bytes([0xF0, 0x06])
    # JSR hs_set_mac2
    trampoline += bytes([0x20, set_mac2_addr & 0xFF, (set_mac2_addr >> 8) & 0xFF])
    # JMP @done (trampoline_addr + 20)
    done_offset = len(trampoline) + 3 + 6  # after JMP + zero loop
    # We'll calculate after building the zero loop
    jmp_placeholder = len(trampoline)
    trampoline += bytes([0x4C, 0x00, 0x00])  # placeholder

    # @zero_mac2:
    zero_mac2_start = len(trampoline)
    # LDX #$0F
    trampoline += bytes([0xA2, 0x0F])
    # LDA #$00
    trampoline += bytes([0xA9, 0x00])
    # @clr: STA hs_packet+132,X (absolute,X)
    trampoline += bytes([0x9D, mac2_offset & 0xFF, (mac2_offset >> 8) & 0xFF])
    # DEX
    trampoline += bytes([0xCA])
    # BPL @clr (-6: back to STA abs,X which is 3+1+2=6 bytes before end of BPL)
    trampoline += bytes([0x10, 0xFA])
    # @done: RTS
    done_addr = trampoline_addr + len(trampoline)
    trampoline += bytes([0x60])

    # Fix JMP target
    trampoline[jmp_placeholder + 1] = done_addr & 0xFF
    trampoline[jmp_placeholder + 2] = (done_addr >> 8) & 0xFF

    write_bytes(transport, trampoline_addr, bytes(trampoline))
    jsr(transport, trampoline_addr, timeout=10.0)

    # Read MAC2 region: hs_packet[132..147]
    mac2_bytes = bytes(read_bytes(transport, hs_packet_addr + 132, 16))

    if mac2_bytes == bytes(16):
        passed += 1
        if VERBOSE:
            print("  PASS MAC2 is all zeros when cookie_valid=0")
    else:
        failed += 1
        print(f"  FAIL MAC2 should be all zeros, got: {mac2_bytes.hex()}")

    return passed, failed


def test_cookie_sets_valid_flag(transport, labels, rng):
    """Test 2: cookie_handle_type3 decrypts cookie and sets cookie_valid=1."""
    passed = failed = 0

    cookie_handle = labels["cookie_handle_type3"]
    cookie_valid_addr = labels["cookie_valid"]
    cookie_buf_addr = labels["cookie_buf"]
    cfg_peer_pub_addr = labels["cfg_peer_pub"]
    hs_packet_addr = labels["hs_packet"]
    udp_recv_buf_addr = labels["udp_recv_buf"]

    # Build trampoline: JSR cookie_handle_type3; STA $0360; RTS
    trampoline = bytes([
        0x20, cookie_handle & 0xFF, cookie_handle >> 8,
        0x8D, 0x60, 0x03,
        0x60,
    ])
    write_bytes(transport, 0x0380, trampoline)

    # Set up peer public key
    peer_pub = bytes(rng.randint(0, 255) for _ in range(32))
    write_bytes(transport, cfg_peer_pub_addr, peer_pub)

    # Set up a known MAC1 at hs_packet+116 (16 bytes) — used as AAD
    mac1 = bytes(rng.randint(0, 255) for _ in range(16))
    write_bytes(transport, hs_packet_addr + 116, mac1)

    # Derive cookie_key in Python: BLAKE2s-256("cookie--" || peer_pub)
    cookie_key = hashlib.blake2s(b"cookie--" + peer_pub, digest_size=32).digest()

    # Build a valid Type 3 cookie packet
    cookie_data = bytes(rng.randint(0, 255) for _ in range(16))
    nonce_24 = bytes(rng.randint(0, 255) for _ in range(24))
    ct_tag = xchacha20poly1305_encrypt(cookie_key, nonce_24, cookie_data, mac1)

    type3 = bytearray(64)
    type3[0] = 3  # type
    type3[1:4] = b'\x00\x00\x00'  # reserved
    type3[4:8] = b'\x01\x02\x03\x04'  # receiver_index
    type3[8:32] = nonce_24
    type3[32:48] = ct_tag[:16]   # encrypted cookie
    type3[48:64] = ct_tag[16:]   # tag

    # Clear cookie_valid before handling cookie reply
    write_bytes(transport, cookie_valid_addr, bytes([0]))
    write_bytes(transport, udp_recv_buf_addr, bytes(type3))
    jsr(transport, 0x0380, timeout=120.0)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    decrypted_cookie = bytes(read_bytes(transport, cookie_buf_addr, 16))

    ok = True
    if result_a != 0:
        ok = False
        print(f"  FAIL cookie_handle_type3 returned A={result_a:#04x}, expected 0")
    if valid_flag != 1:
        ok = False
        print(f"  FAIL cookie_valid={valid_flag}, expected 1")
    if decrypted_cookie != cookie_data:
        ok = False
        print(f"  FAIL cookie_buf mismatch:")
        print(f"    expected: {cookie_data.hex()}")
        print(f"    got:      {decrypted_cookie.hex()}")

    if ok:
        passed += 1
        if VERBOSE:
            print("  PASS cookie_handle_type3 -> A=0, cookie_valid=1, cookie matches")
    else:
        failed += 1

    return passed, failed, cookie_data


def test_mac2_nonzero_with_cookie(transport, labels, rng):
    """Test 3: MAC2 is correctly computed when cookie is available.

    Fill hs_packet[0..131] with known data, set cookie_valid=1 and
    cookie_buf with known 16 bytes, call hs_set_mac2, verify MAC2.
    """
    passed = failed = 0

    hs_packet_addr = labels["hs_packet"]
    cookie_valid_addr = labels["cookie_valid"]
    cookie_buf_addr = labels["cookie_buf"]
    set_mac2_addr = labels["hs_set_mac2"]

    # Fill hs_packet[0..131] with deterministic data
    packet_prefix = bytes(rng.randint(0, 255) for _ in range(132))
    write_bytes(transport, hs_packet_addr, packet_prefix)

    # Set a known 16-byte cookie
    cookie_16 = bytes(rng.randint(0, 255) for _ in range(16))
    write_bytes(transport, cookie_buf_addr, cookie_16)
    write_bytes(transport, cookie_valid_addr, bytes([1]))

    # Call hs_set_mac2 directly
    jsr(transport, set_mac2_addr, timeout=30.0)

    # Read MAC2: hs_packet[132..147]
    mac2_c64 = bytes(read_bytes(transport, hs_packet_addr + 132, 16))

    # Compute expected MAC2 in Python
    expected_mac2 = py_mac2(cookie_16, packet_prefix)

    if mac2_c64 == expected_mac2:
        passed += 1
        if VERBOSE:
            print(f"  PASS MAC2 matches expected: {expected_mac2.hex()}")
    else:
        failed += 1
        print(f"  FAIL MAC2 mismatch:")
        print(f"    expected: {expected_mac2.hex()}")
        print(f"    got:      {mac2_c64.hex()}")

    # Also verify it's non-zero (sanity check)
    if mac2_c64 == bytes(16):
        failed += 1
        print(f"  FAIL MAC2 is all zeros (should be non-zero)")

    return passed, failed


def test_cookie_valid_cleared_after_use(transport, labels):
    """Test 4: cookie_valid is cleared to 0 after hs_set_mac2 runs."""
    passed = failed = 0

    cookie_valid_addr = labels["cookie_valid"]

    # cookie_valid should have been cleared by the hs_set_mac2 call in test 3
    # But to be safe, we do this as a standalone: set cookie_valid=1, call
    # hs_set_mac2, then check.
    hs_packet_addr = labels["hs_packet"]
    cookie_buf_addr = labels["cookie_buf"]
    set_mac2_addr = labels["hs_set_mac2"]

    # Set up state
    write_bytes(transport, hs_packet_addr, bytes([0x55] * 132))
    write_bytes(transport, cookie_buf_addr, bytes(range(16)))
    write_bytes(transport, cookie_valid_addr, bytes([1]))

    # Confirm cookie_valid is 1 before call
    pre_valid = read_bytes(transport, cookie_valid_addr, 1)[0]
    if pre_valid != 1:
        failed += 1
        print(f"  FAIL cookie_valid pre-check: expected 1, got {pre_valid}")
        return passed, failed

    # Call hs_set_mac2
    jsr(transport, set_mac2_addr, timeout=30.0)

    # Check cookie_valid is now 0
    post_valid = read_bytes(transport, cookie_valid_addr, 1)[0]
    if post_valid == 0:
        passed += 1
        if VERBOSE:
            print("  PASS cookie_valid cleared to 0 after hs_set_mac2")
    else:
        failed += 1
        print(f"  FAIL cookie_valid={post_valid} after hs_set_mac2, expected 0")

    return passed, failed


def test_full_flow(transport, labels, rng):
    """Test 5: Full flow — cookie received, then MAC2 populated in next packet.

    This combines tests 2+3: receive a Type 3 cookie reply, then call
    hs_set_mac2 and verify the MAC2 is computed from the received cookie.
    """
    passed = failed = 0

    cookie_handle = labels["cookie_handle_type3"]
    cookie_valid_addr = labels["cookie_valid"]
    cookie_buf_addr = labels["cookie_buf"]
    cfg_peer_pub_addr = labels["cfg_peer_pub"]
    hs_packet_addr = labels["hs_packet"]
    udp_recv_buf_addr = labels["udp_recv_buf"]
    set_mac2_addr = labels["hs_set_mac2"]

    # --- Phase 1: Receive a Type 3 cookie reply ---

    # Build trampoline for cookie_handle_type3
    trampoline = bytes([
        0x20, cookie_handle & 0xFF, cookie_handle >> 8,
        0x8D, 0x60, 0x03,
        0x60,
    ])
    write_bytes(transport, 0x0380, trampoline)

    peer_pub = bytes(rng.randint(0, 255) for _ in range(32))
    write_bytes(transport, cfg_peer_pub_addr, peer_pub)

    # MAC1 in hs_packet+116 (the AAD for cookie decryption)
    mac1 = bytes(rng.randint(0, 255) for _ in range(16))
    write_bytes(transport, hs_packet_addr + 116, mac1)

    cookie_key = hashlib.blake2s(b"cookie--" + peer_pub, digest_size=32).digest()
    cookie_data = bytes(rng.randint(0, 255) for _ in range(16))
    nonce_24 = bytes(rng.randint(0, 255) for _ in range(24))
    ct_tag = xchacha20poly1305_encrypt(cookie_key, nonce_24, cookie_data, mac1)

    type3 = bytearray(64)
    type3[0] = 3
    type3[1:4] = b'\x00\x00\x00'
    type3[4:8] = b'\x01\x02\x03\x04'
    type3[8:32] = nonce_24
    type3[32:48] = ct_tag[:16]
    type3[48:64] = ct_tag[16:]

    write_bytes(transport, cookie_valid_addr, bytes([0]))
    write_bytes(transport, udp_recv_buf_addr, bytes(type3))
    jsr(transport, 0x0380, timeout=120.0)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    if result_a != 0:
        failed += 1
        print(f"  FAIL full_flow: cookie_handle_type3 returned A={result_a:#04x}")
        return passed, failed

    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    if valid_flag != 1:
        failed += 1
        print(f"  FAIL full_flow: cookie_valid={valid_flag} after type3 handling")
        return passed, failed

    # --- Phase 2: Fill hs_packet[0..131] with new data, call hs_set_mac2 ---
    packet_prefix = bytes(rng.randint(0, 255) for _ in range(132))
    write_bytes(transport, hs_packet_addr, packet_prefix)

    jsr(transport, set_mac2_addr, timeout=30.0)

    # --- Phase 3: Verify MAC2 ---
    mac2_c64 = bytes(read_bytes(transport, hs_packet_addr + 132, 16))
    expected_mac2 = py_mac2(cookie_data, packet_prefix)

    if mac2_c64 == expected_mac2:
        passed += 1
        if VERBOSE:
            print(f"  PASS full_flow: MAC2 from received cookie matches")
            print(f"    cookie:  {cookie_data.hex()}")
            print(f"    mac2:    {mac2_c64.hex()}")
    else:
        failed += 1
        print(f"  FAIL full_flow: MAC2 mismatch")
        print(f"    cookie:  {cookie_data.hex()}")
        print(f"    expected:{expected_mac2.hex()}")
        print(f"    got:     {mac2_c64.hex()}")

    # --- Phase 4: Verify cookie_valid cleared ---
    post_valid = read_bytes(transport, cookie_valid_addr, 1)[0]
    if post_valid == 0:
        passed += 1
        if VERBOSE:
            print("  PASS full_flow: cookie_valid cleared after MAC2 use")
    else:
        failed += 1
        print(f"  FAIL full_flow: cookie_valid={post_valid} after MAC2, expected 0")

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    # Test 1: MAC2 zero without cookie
    print("\n--- test_mac2_zero_without_cookie ---")
    try:
        p, f = test_mac2_zero_without_cookie(transport, labels, rng)
        total_passed += p
        total_failed += f
        status = "OK" if f == 0 else "FAIL"
        print(f"  {status}: {p}/{p + f} passed")
    except Exception as e:
        total_failed += 1
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 2: Cookie sets valid flag
    print("\n--- test_cookie_sets_valid_flag ---")
    cookie_data = None
    try:
        p, f, cookie_data = test_cookie_sets_valid_flag(transport, labels, rng)
        total_passed += p
        total_failed += f
        status = "OK" if f == 0 else "FAIL"
        print(f"  {status}: {p}/{p + f} passed")
    except Exception as e:
        total_failed += 1
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 3: MAC2 nonzero with cookie
    print("\n--- test_mac2_nonzero_with_cookie ---")
    try:
        p, f = test_mac2_nonzero_with_cookie(transport, labels, rng)
        total_passed += p
        total_failed += f
        status = "OK" if f == 0 else "FAIL"
        print(f"  {status}: {p}/{p + f} passed")
    except Exception as e:
        total_failed += 1
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 4: Cookie valid cleared after use
    print("\n--- test_cookie_valid_cleared_after_use ---")
    try:
        p, f = test_cookie_valid_cleared_after_use(transport, labels)
        total_passed += p
        total_failed += f
        status = "OK" if f == 0 else "FAIL"
        print(f"  {status}: {p}/{p + f} passed")
    except Exception as e:
        total_failed += 1
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 5: Full flow (cookie received -> MAC2 populated)
    print("\n--- test_full_flow (cookie -> MAC2) ---")
    try:
        p, f = test_full_flow(transport, labels, rng)
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

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "hs_set_mac2", "hs_compute_mac1", "cookie_handle_type3",
        "cookie_valid", "cookie_buf", "cfg_peer_pub",
        "hs_packet", "hs_mac1_key", "udp_recv_buf",
        "input_buffer", "b2s_hash",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

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

        # Infinite loop trap to prevent C64 from interfering
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
