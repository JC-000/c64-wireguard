#!/usr/bin/env python3
"""test_phase7.py — Phase 7 application layer tests.

Tests IP packet construction, ICMP/UDP tunnel payloads, timer elapsed
comparisons, keepalive packets, cookie handling, payload routing,
and round-trip tunnel encryption.

Usage:
    python3 tools/test_phase7.py [--seed S] [--verbose]
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
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False



# ============================================================================
# Python reference implementations
# ============================================================================

def py_ip_checksum(data):
    """Python reference for RFC 1071 internet checksum."""
    if len(data) % 2:
        data = data + b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s > 0xffff:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


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


def xchacha20poly1305_decrypt(key, nonce_24, ciphertext_tag, aad):
    """XChaCha20-Poly1305 decrypt using HChaCha20 + ChaCha20-Poly1305."""
    subkey = hchacha20_py(key, nonce_24[:16])
    chacha_nonce = b'\x00\x00\x00\x00' + nonce_24[16:24]
    aead = ChaCha20Poly1305(subkey)
    return aead.decrypt(chacha_nonce, ciphertext_tag, aad)


def py_build_ip_header(total_len, protocol, src_ip, dst_ip):
    """Build a 20-byte IPv4 header with computed checksum."""
    hdr = bytearray(20)
    hdr[0] = 0x45           # version=4, IHL=5
    hdr[1] = 0x00           # DSCP/ECN
    hdr[2] = (total_len >> 8) & 0xFF
    hdr[3] = total_len & 0xFF
    hdr[4:6] = b'\x00\x00'  # identification
    hdr[6:8] = b'\x40\x00'  # DF=1
    hdr[8] = 0x40           # TTL=64
    hdr[9] = protocol
    hdr[10:12] = b'\x00\x00'  # checksum (zero for computation)
    hdr[12:16] = src_ip
    hdr[16:20] = dst_ip
    # Compute checksum
    cksum = py_ip_checksum(bytes(hdr))
    hdr[10] = (cksum >> 8) & 0xFF
    hdr[11] = cksum & 0xFF
    return bytes(hdr)


def py_build_icmp_echo_reply(src_ip, dst_ip, icmp_id, seq):
    """Build a 28-byte ICMP echo reply IP packet."""
    # ICMP echo reply: type=0, code=0, checksum, id, seq
    icmp = bytearray(8)
    icmp[0] = 0   # type = echo reply
    icmp[1] = 0   # code
    icmp[2:4] = b'\x00\x00'  # checksum placeholder
    icmp[4] = (icmp_id >> 8) & 0xFF
    icmp[5] = icmp_id & 0xFF
    icmp[6] = (seq >> 8) & 0xFF
    icmp[7] = seq & 0xFF
    # ICMP checksum
    cksum = py_ip_checksum(bytes(icmp))
    icmp[2] = (cksum >> 8) & 0xFF
    icmp[3] = cksum & 0xFF
    # IP header
    ip_hdr = py_build_ip_header(28, 1, src_ip, dst_ip)
    return ip_hdr + bytes(icmp)


def py_build_udp_packet(src_ip, dst_ip, port, payload):
    """Build an IP/UDP packet with given payload."""
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    # UDP header
    udp = bytearray(8)
    udp[0] = (port >> 8) & 0xFF    # src port hi
    udp[1] = port & 0xFF           # src port lo
    udp[2] = (port >> 8) & 0xFF    # dst port hi
    udp[3] = port & 0xFF           # dst port lo
    udp[4] = (udp_len >> 8) & 0xFF
    udp[5] = udp_len & 0xFF
    udp[6:8] = b'\x00\x00'         # no checksum
    ip_hdr = py_build_ip_header(total_len, 17, src_ip, dst_ip)
    return ip_hdr + bytes(udp) + payload


# ============================================================================
# Test groups
# ============================================================================

def test_build_verification(labels):
    """Verify Phase 7 labels exist and addresses < $8000."""
    passed = failed = 0

    required_labels = [
        "ip_checksum", "icmp_build_echo", "icmp_parse_reply",
        "udp_tunnel_build", "udp_tunnel_parse",
        "hchacha20", "cookie_handle_type3", "hs_set_mac2",
        "timer_session_start", "timer_check", "timer_mark_send",
        "timer_elapsed_cmp", "config_read_file",
        "ip_packet_buf", "cookie_valid",
        "hs_sender_idx", "hs_mac1_valid",
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

    return passed, failed


def test_ip_checksum(transport, labels, rng):
    """Test ip_checksum with various buffers."""
    passed = failed = 0

    input_buf = labels["input_buffer"]
    zp_ptr1 = labels["zp_ptr1"]
    zp_tmp1 = labels["zp_tmp1"]
    ip_cksum = labels["ip_checksum"]
    cksum_result = labels["ip_cksum_result"]

    def run_checksum(data):
        """Write data, call ip_checksum, return 2-byte result."""
        write_bytes(transport, input_buf, data)
        write_bytes(transport, zp_ptr1, struct.pack('<H', input_buf))
        write_bytes(transport, zp_tmp1, bytes([len(data)]))
        jsr(transport, ip_cksum)
        return bytes(read_bytes(transport, cksum_result, 2))

    # Test 1: Zero buffer 2 bytes -> checksum of 0x0000 = 0xFFFF
    result = run_checksum(b'\x00\x00')
    expected = py_ip_checksum(b'\x00\x00')
    exp_bytes = bytes([(expected >> 8) & 0xFF, expected & 0xFF])
    if result == exp_bytes:
        passed += 1
        if VERBOSE:
            print(f"  PASS zero 2B: {result.hex()}")
    else:
        failed += 1
        print(f"  FAIL zero 2B: got {result.hex()}, expected {exp_bytes.hex()}")

    # Test 2: Zero buffer 4 bytes
    result = run_checksum(b'\x00\x00\x00\x00')
    expected = py_ip_checksum(b'\x00\x00\x00\x00')
    exp_bytes = bytes([(expected >> 8) & 0xFF, expected & 0xFF])
    if result == exp_bytes:
        passed += 1
        if VERBOSE:
            print(f"  PASS zero 4B: {result.hex()}")
    else:
        failed += 1
        print(f"  FAIL zero 4B: got {result.hex()}, expected {exp_bytes.hex()}")

    # Test 3: Zero buffer 20 bytes
    result = run_checksum(b'\x00' * 20)
    expected = py_ip_checksum(b'\x00' * 20)
    exp_bytes = bytes([(expected >> 8) & 0xFF, expected & 0xFF])
    if result == exp_bytes:
        passed += 1
        if VERBOSE:
            print(f"  PASS zero 20B: {result.hex()}")
    else:
        failed += 1
        print(f"  FAIL zero 20B: got {result.hex()}, expected {exp_bytes.hex()}")

    # Test 4: Known IPv4 header (RFC 1071 example-like)
    # Standard header: version=4, IHL=5, tot_len=60, id=1, DF, TTL=64,
    # proto=6, src=192.168.1.100, dst=10.0.0.1
    test_hdr = bytes([
        0x45, 0x00, 0x00, 0x3C,  # ver/ihl, dscp, total length
        0x00, 0x01, 0x40, 0x00,  # id, flags+frag
        0x40, 0x06, 0x00, 0x00,  # ttl, proto=TCP, checksum=0
        0xC0, 0xA8, 0x01, 0x64,  # src: 192.168.1.100
        0x0A, 0x00, 0x00, 0x01,  # dst: 10.0.0.1
    ])
    result = run_checksum(test_hdr)
    expected = py_ip_checksum(test_hdr)
    exp_bytes = bytes([(expected >> 8) & 0xFF, expected & 0xFF])
    if result == exp_bytes:
        passed += 1
        if VERBOSE:
            print(f"  PASS RFC header: {result.hex()}")
    else:
        failed += 1
        print(f"  FAIL RFC header: got {result.hex()}, expected {exp_bytes.hex()}")

    # Tests 5-10: Random even-length buffers
    for i in range(6):
        length = rng.choice([2, 4, 6, 10, 14, 20])
        data = bytes(rng.randint(0, 255) for _ in range(length))
        result = run_checksum(data)
        expected = py_ip_checksum(data)
        exp_bytes = bytes([(expected >> 8) & 0xFF, expected & 0xFF])
        if result == exp_bytes:
            passed += 1
            if VERBOSE:
                print(f"  PASS random #{i}: {length}B checksum {result.hex()}")
        else:
            failed += 1
            print(f"  FAIL random #{i}: {length}B got {result.hex()}, expected {exp_bytes.hex()}")
            print(f"    data: {data.hex()}")

    return passed, failed


def test_icmp_build(transport, labels, rng):
    """Test icmp_build_echo builds correct IP/ICMP packets."""
    passed = failed = 0

    tunnel_ip_addr = labels["tunnel_ip"]
    target_ip_addr = labels["ping_target_ip"]
    ping_seq_addr = labels["ping_seq"]
    ip_pkt_buf = labels["ip_packet_buf"]
    icmp_build = labels["icmp_build_echo"]

    for trial in range(8):
        src_ip = bytes(rng.randint(1, 254) for _ in range(4))
        dst_ip = bytes(rng.randint(1, 254) for _ in range(4))
        seq_val = rng.randint(0, 0xFFFE)

        # Set up state
        write_bytes(transport, tunnel_ip_addr, src_ip)
        write_bytes(transport, target_ip_addr, dst_ip)
        # ping_seq is big-endian
        write_bytes(transport, ping_seq_addr,
                    bytes([(seq_val >> 8) & 0xFF, seq_val & 0xFF]))

        jsr(transport, icmp_build)

        # Read the 28-byte packet
        pkt = bytes(read_bytes(transport, ip_pkt_buf, 28))

        ok = True
        errors = []

        # Total length = 28
        total_len = (pkt[2] << 8) | pkt[3]
        if total_len != 28:
            errors.append(f"total_len={total_len}, expected 28")
            ok = False

        # Protocol = ICMP (1)
        if pkt[9] != 1:
            errors.append(f"protocol={pkt[9]}, expected 1")
            ok = False

        # Src IP
        if pkt[12:16] != src_ip:
            errors.append(f"src_ip={pkt[12:16].hex()}, expected {src_ip.hex()}")
            ok = False

        # Dst IP
        if pkt[16:20] != dst_ip:
            errors.append(f"dst_ip={pkt[16:20].hex()}, expected {dst_ip.hex()}")
            ok = False

        # ICMP type=8, code=0
        if pkt[20] != 8:
            errors.append(f"icmp_type={pkt[20]}, expected 8")
            ok = False
        if pkt[21] != 0:
            errors.append(f"icmp_code={pkt[21]}, expected 0")
            ok = False

        # ICMP ID = $C640 (big-endian: $C6, $40)
        if pkt[24] != 0xC6 or pkt[25] != 0x40:
            errors.append(f"icmp_id={pkt[24]:02X}{pkt[25]:02X}, expected C640")
            ok = False

        # Sequence matches
        pkt_seq = (pkt[26] << 8) | pkt[27]
        if pkt_seq != seq_val:
            errors.append(f"seq={pkt_seq}, expected {seq_val}")
            ok = False

        # IP header checksum valid (zero check of entire header)
        ip_hdr = pkt[:20]
        verify_cksum = py_ip_checksum(ip_hdr)
        if verify_cksum != 0:
            errors.append(f"ip_checksum invalid (verify={verify_cksum:#06x})")
            ok = False

        # ICMP checksum valid
        icmp_data = pkt[20:28]
        verify_icmp_cksum = py_ip_checksum(icmp_data)
        if verify_icmp_cksum != 0:
            errors.append(f"icmp_checksum invalid (verify={verify_icmp_cksum:#06x})")
            ok = False

        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS icmp_build #{trial}: seq={seq_val}")
        else:
            failed += 1
            print(f"  FAIL icmp_build #{trial}: {'; '.join(errors)}")

    return passed, failed


def test_icmp_parse(transport, labels):
    """Test icmp_parse_reply with various crafted packets."""
    passed = failed = 0

    tp_packet = labels["tp_packet"]
    icmp_parse = labels["icmp_parse_reply"]

    # Build trampoline: JSR icmp_parse_reply; STA $0360; RTS
    trampoline = bytes([
        0x20, icmp_parse & 0xFF, icmp_parse >> 8,  # JSR
        0x8D, 0x60, 0x03,                          # STA $0360
        0x60,                                       # RTS
    ])
    write_bytes(transport, 0x0340, trampoline)

    def parse_and_read(ip_pkt):
        """Write IP packet at tp_packet+16, call parse, return A."""
        write_bytes(transport, tp_packet + 16, ip_pkt)
        jsr(transport, 0x0340)
        return read_bytes(transport, 0x0360, 1)[0]

    # Test 1: Valid echo reply (proto=1, type=0, ID=$C640)
    valid_reply = py_build_icmp_echo_reply(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', 0xC640, 1)
    result = parse_and_read(valid_reply)
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS valid echo reply -> A=0")
    else:
        failed += 1
        print(f"  FAIL valid echo reply: A={result:#04x}, expected 0")

    # Test 2: Wrong ICMP type (8 = echo request instead of 0 = reply)
    bad_type = bytearray(valid_reply)
    bad_type[20] = 8  # echo request
    # Recompute ICMP checksum
    icmp_part = bytearray(bad_type[20:28])
    icmp_part[2:4] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(icmp_part))
    bad_type[22] = (cksum >> 8) & 0xFF
    bad_type[23] = cksum & 0xFF
    result = parse_and_read(bytes(bad_type))
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong ICMP type -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong ICMP type: A={result:#04x}, expected $FF")

    # Test 3: Wrong protocol (17=UDP instead of 1=ICMP)
    bad_proto = bytearray(valid_reply)
    bad_proto[9] = 17
    # Recompute IP checksum
    bad_proto[10:12] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(bad_proto[:20]))
    bad_proto[10] = (cksum >> 8) & 0xFF
    bad_proto[11] = cksum & 0xFF
    result = parse_and_read(bytes(bad_proto))
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong protocol -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong protocol: A={result:#04x}, expected $FF")

    # Test 4: Wrong ICMP ID ($DEAD instead of $C640)
    bad_id = bytearray(valid_reply)
    bad_id[24] = 0xDE
    bad_id[25] = 0xAD
    # Recompute ICMP checksum
    icmp_part = bytearray(bad_id[20:28])
    icmp_part[2:4] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(icmp_part))
    bad_id[22] = (cksum >> 8) & 0xFF
    bad_id[23] = cksum & 0xFF
    result = parse_and_read(bytes(bad_id))
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong ICMP ID -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong ICMP ID: A={result:#04x}, expected $FF")

    # Test 5: Valid reply with different sequence number
    reply2 = py_build_icmp_echo_reply(
        b'\xC0\xA8\x01\x01', b'\xC0\xA8\x01\x02', 0xC640, 0x1234)
    result = parse_and_read(reply2)
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS valid reply seq=0x1234 -> A=0")
    else:
        failed += 1
        print(f"  FAIL valid reply seq=0x1234: A={result:#04x}, expected 0")

    # Test 6: Wrong ICMP ID low byte only
    bad_id_lo = bytearray(valid_reply)
    bad_id_lo[25] = 0x41  # $C641 instead of $C640
    icmp_part = bytearray(bad_id_lo[20:28])
    icmp_part[2:4] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(icmp_part))
    bad_id_lo[22] = (cksum >> 8) & 0xFF
    bad_id_lo[23] = cksum & 0xFF
    result = parse_and_read(bytes(bad_id_lo))
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong ICMP ID low byte -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong ICMP ID low byte: A={result:#04x}, expected $FF")

    return passed, failed


IP_UDP_HDR_LEN = 28     # 20 B IPv4 + 8 B UDP, the inner framing of a message


def tunnel_mtu(labels):
    """WG_MTU of the build under test, from labels.txt.

    Two independent sources, and they must agree. `WG_MTU` is an equate
    that src/exports.s promotes to a label (issue #70); a build predating
    that export has no such label, but `ip_packet_buf` is `.res WG_MTU`
    and `ip_pkt_len` is declared directly after it (src/wg/data.s), so
    their distance IS the MTU — a structural reading that no comment can
    drift away from. Returns (mtu, source_description).
    """
    structural = labels["ip_pkt_len"] - labels["ip_packet_buf"]
    exported = labels.address("WG_MTU")
    if exported is not None and exported != structural:
        raise AssertionError(
            f"WG_MTU label ({exported}) disagrees with ip_pkt_len - "
            f"ip_packet_buf ({structural}); ip_packet_buf is no longer "
            f".res WG_MTU, or ip_pkt_len moved")
    if exported is not None:
        return exported, "WG_MTU label"
    return structural, "ip_pkt_len - ip_packet_buf (WG_MTU not exported)"


def test_udp_build(transport, labels, rng):
    """Test udp_tunnel_build constructs correct IP/UDP packets."""
    passed = failed = 0

    input_buf = labels["input_buffer"]
    tunnel_ip_addr = labels["tunnel_ip"]
    target_ip_addr = labels["ping_target_ip"]
    msg_port_addr = labels["msg_port"]
    ip_pkt_buf = labels["ip_packet_buf"]
    zp_ptr1 = labels["zp_ptr1"]
    zp_tmp1 = labels["zp_tmp1"]
    udp_build = labels["udp_tunnel_build"]

    test_sizes = [1, 5, 20, 40, 8, 15]

    for i, text_len in enumerate(test_sizes):
        src_ip = bytes(rng.randint(1, 254) for _ in range(4))
        dst_ip = bytes(rng.randint(1, 254) for _ in range(4))
        port_val = rng.randint(1024, 65534)
        port_be = bytes([(port_val >> 8) & 0xFF, port_val & 0xFF])
        text = bytes(rng.randint(0x20, 0x7E) for _ in range(text_len))

        write_bytes(transport, tunnel_ip_addr, src_ip)
        write_bytes(transport, target_ip_addr, dst_ip)
        write_bytes(transport, msg_port_addr, port_be)
        write_bytes(transport, input_buf, text)
        write_bytes(transport, zp_ptr1, struct.pack('<H', input_buf))
        # udp_tunnel_build takes a 16-bit length in zp_tmp1/zp_tmp2 (§13.3);
        # zero the high byte or stale checksum residue clamps it to MSG_TEXT_MAX.
        write_bytes(transport, zp_tmp1, struct.pack('<H', text_len))

        jsr(transport, udp_build)

        total_pkt_len = 28 + text_len
        pkt = bytes(read_bytes(transport, ip_pkt_buf, total_pkt_len))

        ok = True
        errors = []

        # IP total length
        ip_total = (pkt[2] << 8) | pkt[3]
        if ip_total != total_pkt_len:
            errors.append(f"ip_total={ip_total}, expected {total_pkt_len}")
            ok = False

        # Protocol = UDP (17)
        if pkt[9] != 17:
            errors.append(f"protocol={pkt[9]}, expected 17")
            ok = False

        # Src/Dst IP
        if pkt[12:16] != src_ip:
            errors.append(f"src_ip mismatch")
            ok = False
        if pkt[16:20] != dst_ip:
            errors.append(f"dst_ip mismatch")
            ok = False

        # UDP src port = dst port = msg_port
        if pkt[20:22] != port_be:
            errors.append(f"udp_sport={pkt[20:22].hex()}, expected {port_be.hex()}")
            ok = False
        if pkt[22:24] != port_be:
            errors.append(f"udp_dport={pkt[22:24].hex()}, expected {port_be.hex()}")
            ok = False

        # UDP length
        udp_len = (pkt[24] << 8) | pkt[25]
        if udp_len != 8 + text_len:
            errors.append(f"udp_len={udp_len}, expected {8 + text_len}")
            ok = False

        # Payload
        if pkt[28:28 + text_len] != text:
            errors.append("payload mismatch")
            ok = False

        # IP header checksum
        ip_hdr = pkt[:20]
        verify = py_ip_checksum(ip_hdr)
        if verify != 0:
            errors.append(f"ip_checksum invalid (verify={verify:#06x})")
            ok = False

        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS udp_build #{i}: {text_len}B")
        else:
            failed += 1
            print(f"  FAIL udp_build #{i}: {'; '.join(errors)}")

    # --- In-place build (issue #70) ---
    #
    # do_message_input stages the typed text at ip_packet_buf+28, i.e. the
    # exact bytes udp_tunnel_build copies it INTO, so the text copy is an
    # identity copy (src -> same address, byte-forward, so no byte is read
    # after it was overwritten). That is what let msg_input_buf be dropped
    # and the datagram cap grow to 1472 without new RAM.
    #
    # This case cannot be red on a build that still has msg_input_buf: the
    # routine is the same either way. What it guards is the aliasing itself —
    # a future "optimisation" that copies backwards, that clears the payload
    # area before copying, or that writes the headers through the same pointer
    # would corrupt an in-place text while still passing the cases above,
    # which copy from a separate buffer. So the pattern must be NON-CONSTANT
    # (a repeating byte would survive any shift or partial overwrite) and the
    # length must be the full MSG_TEXT_MAX (a shorter copy never crosses the
    # page boundaries the 16-bit copy loop has to get right).
    mtu, mtu_src = tunnel_mtu(labels)
    msg_text_max = mtu - IP_UDP_HDR_LEN
    payload_addr = ip_pkt_buf + IP_UDP_HDR_LEN
    ip_pkt_len_addr = labels["ip_pkt_len"]
    if VERBOSE:
        print(f"  in-place: WG_MTU={mtu} via {mtu_src}; "
              f"MSG_TEXT_MAX={msg_text_max}; payload at ${payload_addr:04X}")

    # Full-size, plus one that ends mid-page after crossing at least one page
    # boundary — the two shapes the copy loop distinguishes.
    for label, text_len in (("full MSG_TEXT_MAX", msg_text_max),
                            ("page+remainder", min(msg_text_max, 300))):
        src_ip = bytes(rng.randint(1, 254) for _ in range(4))
        dst_ip = bytes(rng.randint(1, 254) for _ in range(4))
        port_val = rng.randint(1024, 65534)
        port_be = bytes([(port_val >> 8) & 0xFF, port_val & 0xFF])
        # Every byte value, no period: a shift, a dropped page or a
        # partial clear all change it.
        text = bytes(rng.randint(0, 255) for _ in range(text_len))

        write_bytes(transport, tunnel_ip_addr, src_ip)
        write_bytes(transport, target_ip_addr, dst_ip)
        write_bytes(transport, msg_port_addr, port_be)
        # Junk in the header area: the build must overwrite all 28 bytes.
        write_bytes(transport, ip_pkt_buf, bytes([0xA5] * IP_UDP_HDR_LEN))
        write_bytes(transport, payload_addr, text)
        write_bytes(transport, zp_ptr1, struct.pack('<H', payload_addr))
        write_bytes(transport, zp_tmp1, struct.pack('<H', text_len))
        write_bytes(transport, ip_pkt_len_addr, b'\xFF\xFF')

        jsr(transport, udp_build)

        total_pkt_len = IP_UDP_HDR_LEN + text_len
        pkt = bytes(read_bytes(transport, ip_pkt_buf, total_pkt_len))
        pkt_len = int.from_bytes(read_bytes(transport, ip_pkt_len_addr, 2),
                                 'little')
        errors = []
        if pkt_len != total_pkt_len:
            errors.append(f"ip_pkt_len={pkt_len}, expected {total_pkt_len}")
        if text_len == msg_text_max and pkt_len != mtu:
            errors.append(f"full text did not fill WG_MTU ({mtu})")
        ip_total = (pkt[2] << 8) | pkt[3]
        if ip_total != total_pkt_len:
            errors.append(f"ip_total={ip_total}, expected {total_pkt_len}")
        if pkt[9] != 17:
            errors.append(f"protocol={pkt[9]}, expected 17")
        if pkt[12:16] != src_ip or pkt[16:20] != dst_ip:
            errors.append("src/dst ip mismatch")
        if pkt[20:22] != port_be or pkt[22:24] != port_be:
            errors.append("udp ports mismatch")
        udp_len = (pkt[24] << 8) | pkt[25]
        if udp_len != 8 + text_len:
            errors.append(f"udp_len={udp_len}, expected {8 + text_len}")
        if py_ip_checksum(pkt[:20]) != 0:
            errors.append("ip_checksum invalid")
        got = pkt[IP_UDP_HDR_LEN:]
        if got != text:
            bad = [k for k in range(text_len) if got[k] != text[k]]
            errors.append(
                f"in-place payload corrupted: {len(bad)} of {text_len} bytes "
                f"differ, first at offset {bad[0]} "
                f"(got ${got[bad[0]]:02X}, expected ${text[bad[0]]:02X})")
        if errors:
            failed += 1
            print(f"  FAIL udp_build in-place ({label}, {text_len}B): "
                  f"{'; '.join(errors)}")
        else:
            passed += 1
            if VERBOSE:
                print(f"  PASS udp_build in-place ({label}): {text_len}B "
                      f"identity copy intact")

    return passed, failed


def test_read_input_line(transport, labels):
    """read_input_line stages the typed text at ip_packet_buf+28 (issue #70).

    The keyboard line is read through KERNAL GETIN, which drains the
    10-byte queue at $0277 / $C6 — ordinary RAM, so the test types by
    writing it (the same trick tools/wg_c64_input.py uses on hardware).
    Nine characters and a RETURN fit in one queue.

    RED on a build that still stores into msg_input_buf: the count is
    right but the bytes are somewhere else. The address is the contract
    do_message_input relies on when it hands zp_ptr1 = ip_packet_buf+28
    to udp_tunnel_build, so this is the test that pins the two together.
    """
    passed = failed = 0

    ril = labels["read_input_line"]
    msg_input_len = labels["msg_input_len"]
    staged = labels["ip_packet_buf"] + IP_UDP_HDR_LEN
    typed = b"WGTEST123"                      # 9 chars, PETSCII == ASCII here
    assert len(typed) + 1 <= 10, "must fit the KERNAL queue with its RETURN"

    # Sentinels: a fresh value in the staging area so a stale match is
    # impossible, and a non-zero count so "9" cannot be a leftover.
    write_bytes(transport, staged, bytes([0xEE] * (len(typed) + 1)))
    write_bytes(transport, msg_input_len, b'\x77\x77')
    # Queue bytes FIRST, count LAST (the IRQ keyboard scan reads the count).
    write_bytes(transport, 0x0277, typed + b'\x0D')
    write_bytes(transport, 0x00C6, bytes([len(typed) + 1]))

    jsr(transport, ril, timeout=30.0)

    count = int.from_bytes(read_bytes(transport, msg_input_len, 2), 'little')
    got = bytes(read_bytes(transport, staged, len(typed)))
    errors = []
    if count != len(typed):
        errors.append(f"msg_input_len={count}, expected {len(typed)}")
    if got != typed:
        where = ""
        legacy = labels.address("msg_input_buf")
        if legacy is not None:
            there = bytes(read_bytes(transport, legacy, len(typed)))
            where = (f"; msg_input_buf still exists at ${legacy:04X} and "
                     f"holds {there!r}")
        errors.append(
            f"text at ip_packet_buf+28 (${staged:04X}) is {got!r}, "
            f"expected {typed!r}{where}")
    if errors:
        failed += 1
        print(f"  FAIL read_input_line stages at ip_packet_buf+28: "
              f"{'; '.join(errors)}")
    else:
        passed += 1
        if VERBOSE:
            print(f"  PASS read_input_line: {len(typed)} chars at "
                  f"${staged:04X}, msg_input_len={count}")
    return passed, failed


def test_udp_parse(transport, labels):
    """Test udp_tunnel_parse with crafted IP/UDP packets."""
    passed = failed = 0

    tp_packet = labels["tp_packet"]
    msg_port_addr = labels["msg_port"]
    msg_recv_ptr_addr = labels["msg_recv_ptr"]
    msg_recv_len_addr = labels["msg_recv_len"]
    udp_parse = labels["udp_tunnel_parse"]

    # Trampoline: JSR udp_tunnel_parse; STA $0360; RTS
    trampoline = bytes([
        0x20, udp_parse & 0xFF, udp_parse >> 8,
        0x8D, 0x60, 0x03,
        0x60,
    ])
    write_bytes(transport, 0x0340, trampoline)

    def parse_and_read(ip_pkt, payload_len=None):
        """Write IP packet at tp_packet+16, call parse, return A.

        tp_payload_len is an input to udp_tunnel_parse since issue #97: the
        inner text is bounded by what the packet actually decrypted to, not
        only by MSG_TEXT_MAX. The honest case passes nothing and gets
        tp_payload_len = len(ip_pkt).
        """
        write_bytes(transport, tp_packet + 16, ip_pkt)
        write_bytes(transport, labels["tp_payload_len"],
                    struct.pack('<H', len(ip_pkt) if payload_len is None
                                      else payload_len))
        jsr(transport, 0x0340)
        return read_bytes(transport, 0x0360, 1)[0]

    # Set msg_port to a known value (big-endian)
    port_val = 9999
    port_be = bytes([(port_val >> 8) & 0xFF, port_val & 0xFF])
    write_bytes(transport, msg_port_addr, port_be)

    # Test 1: Valid UDP packet with matching port
    payload = b"HELLO"
    ip_pkt = py_build_udp_packet(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', port_val, payload)
    result = parse_and_read(ip_pkt)
    if result == 0:
        passed += 1
        if VERBOSE:
            print("  PASS valid UDP -> A=0")
    else:
        failed += 1
        print(f"  FAIL valid UDP: A={result:#04x}, expected 0")

    # Test 2: Check msg_recv_len is correct
    recv_len = read_bytes(transport, msg_recv_len_addr, 1)[0]
    if recv_len == len(payload):
        passed += 1
        if VERBOSE:
            print(f"  PASS msg_recv_len={recv_len}")
    else:
        failed += 1
        print(f"  FAIL msg_recv_len={recv_len}, expected {len(payload)}")

    # Test 3: Wrong protocol (ICMP instead of UDP)
    bad_proto = bytearray(ip_pkt)
    bad_proto[9] = 1  # ICMP
    bad_proto[10:12] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(bad_proto[:20]))
    bad_proto[10] = (cksum >> 8) & 0xFF
    bad_proto[11] = cksum & 0xFF
    result = parse_and_read(bytes(bad_proto))
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong protocol -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong protocol: A={result:#04x}, expected $FF")

    # Test 4: Wrong destination port
    wrong_port = 8888
    wrong_pkt = py_build_udp_packet(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', wrong_port, b"TEST")
    # The check in udp_tunnel_parse looks at dst port (bytes 22-23)
    # but our py_build_udp_packet uses same port for src and dst.
    # We need dst port != msg_port. py_build_udp_packet sets both same,
    # so wrong_port != port_val should trigger failure.
    result = parse_and_read(wrong_pkt)
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS wrong port -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong port: A={result:#04x}, expected $FF")

    # Test 5: Valid with longer payload
    long_payload = b"A" * 30
    ip_pkt2 = py_build_udp_packet(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', port_val, long_payload)
    result = parse_and_read(ip_pkt2)
    recv_len2 = read_bytes(transport, msg_recv_len_addr, 1)[0]
    if result == 0 and recv_len2 == 30:
        passed += 1
        if VERBOSE:
            print(f"  PASS valid UDP 30B -> A=0, len={recv_len2}")
    else:
        failed += 1
        print(f"  FAIL valid UDP 30B: A={result:#04x}, len={recv_len2}")

    # Test 6 (issue #97): the inner UDP length header declares more text than
    # the packet decrypted to. Those bytes were never received — printing
    # them discloses the previous packet's plaintext. The end-to-end proof is
    # test_session.py's test_tunnel_text_payload_bound; this is the unit form.
    result = parse_and_read(ip_pkt2, payload_len=len(ip_pkt2) - 10)
    recv_len3 = int.from_bytes(read_bytes(transport, msg_recv_len_addr, 2),
                               'little')
    if result == 0xFF or recv_len3 <= 20:
        passed += 1
        if VERBOSE:
            print(f"  PASS inflated length header -> A={result:#04x}, "
                  f"len={recv_len3} (20 text bytes decrypted)")
    else:
        failed += 1
        print(f"  FAIL inflated length header accepted: A={result:#04x}, "
              f"len={recv_len3}, but only 20 text bytes were decrypted")

    # Test 7 (issue #97): a payload too short to hold an IP+UDP header at all
    # must be rejected, not read as though it held text.
    result = parse_and_read(ip_pkt2, payload_len=20)
    if result == 0xFF:
        passed += 1
        if VERBOSE:
            print("  PASS 20-byte payload (no room for a UDP header) -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL 20-byte payload accepted: A={result:#04x}")

    return passed, failed


def test_timer_elapsed(transport, labels):
    """Test timer_elapsed_cmp with various jiffy values."""
    passed = failed = 0

    tec_addr = labels["timer_elapsed_cmp"]
    zp_ptr1 = labels["zp_ptr1"]

    # We'll use a scratch area at $0370 for saved jiffy values (3 bytes)
    saved_addr = 0x0370

    def make_timer_trampoline(curr_hi, curr_mid, curr_lo, thr_lo, thr_hi):
        """Build trampoline that sets jiffy clock atomically (SEI/CLI)
        and calls timer_elapsed_cmp, storing carry result."""
        return bytes([
            0x78,                                   # SEI  (disable IRQ)
            0xA9, curr_hi,                          # LDA #curr_hi
            0x85, 0xA0,                             # STA $A0
            0xA9, curr_mid,                         # LDA #curr_mid
            0x85, 0xA1,                             # STA $A1
            0xA9, curr_lo,                          # LDA #curr_lo
            0x85, 0xA2,                             # STA $A2
            0xA9, thr_lo,                           # LDA #thr_lo
            0xA2, thr_hi,                           # LDX #thr_hi
            0x20, tec_addr & 0xFF, tec_addr >> 8,   # JSR timer_elapsed_cmp
            0x58,                                   # CLI  (re-enable IRQ)
            0x90, 0x06,                             # BCC @no (+6)
            0xA9, 0x01,                             # LDA #1
            0x8D, 0x60, 0x03,                       # STA $0360
            0x60,                                   # RTS
            # @no:
            0xA9, 0x00,                             # LDA #0
            0x8D, 0x60, 0x03,                       # STA $0360
            0x60,                                   # RTS
        ])

    def run_timer_test(saved_hi, saved_mid, saved_lo,
                       curr_hi, curr_mid, curr_lo,
                       thr_lo, thr_hi):
        """Set up and run timer_elapsed_cmp, return carry (0 or 1)."""
        # Write saved jiffy time
        write_bytes(transport, saved_addr,
                    bytes([saved_hi, saved_mid, saved_lo]))
        # Set zp_ptr1 to point to saved buffer
        write_bytes(transport, zp_ptr1, struct.pack('<H', saved_addr))
        # Build and run trampoline (jiffy clock written atomically inside)
        tramp = make_timer_trampoline(curr_hi, curr_mid, curr_lo,
                                      thr_lo, thr_hi)
        write_bytes(transport, 0x0340, tramp)
        jsr(transport, 0x0340)
        return read_bytes(transport, 0x0360, 1)[0]

    # Test 1: Elapsed = 0, threshold = 1 -> C=0
    carry = run_timer_test(0, 0, 10, 0, 0, 10, 1, 0)
    if carry == 0:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=0, thr=1 -> C=0")
    else:
        failed += 1
        print(f"  FAIL elapsed=0, thr=1: carry={carry}, expected 0")

    # Test 2: Elapsed = 1, threshold = 1 -> C=1 (elapsed >= threshold)
    carry = run_timer_test(0, 0, 10, 0, 0, 11, 1, 0)
    if carry == 1:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=1, thr=1 -> C=1")
    else:
        failed += 1
        print(f"  FAIL elapsed=1, thr=1: carry={carry}, expected 1")

    # Test 3: Elapsed = 599, threshold = 600 ($0258) -> C=0 (keepalive not yet)
    # saved=0, current elapsed in mid:lo = 599 = $0257
    carry = run_timer_test(0, 0, 0, 0, 0x02, 0x57, 0x58, 0x02)
    if carry == 0:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=599, thr=600 -> C=0")
    else:
        failed += 1
        print(f"  FAIL elapsed=599, thr=600: carry={carry}, expected 0")

    # Test 4: Elapsed = 600, threshold = 600 -> C=1 (keepalive now)
    carry = run_timer_test(0, 0, 0, 0, 0x02, 0x58, 0x58, 0x02)
    if carry == 1:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=600, thr=600 -> C=1")
    else:
        failed += 1
        print(f"  FAIL elapsed=600, thr=600: carry={carry}, expected 1")

    # Test 5: Elapsed = 601, threshold = 600 -> C=1
    carry = run_timer_test(0, 0, 0, 0, 0x02, 0x59, 0x58, 0x02)
    if carry == 1:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=601, thr=600 -> C=1")
    else:
        failed += 1
        print(f"  FAIL elapsed=601, thr=600: carry={carry}, expected 1")

    # Test 6: Large elapsed, threshold = 7200 ($1C20) -> C=1
    # Elapsed = 8000 = $1F40
    carry = run_timer_test(0, 0, 0, 0, 0x1F, 0x40, 0x20, 0x1C)
    if carry == 1:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=8000, thr=7200 -> C=1")
    else:
        failed += 1
        print(f"  FAIL elapsed=8000, thr=7200: carry={carry}, expected 1")

    # Test 7: Exact threshold match for expire (10800 = $2A30)
    carry = run_timer_test(0, 0, 0, 0, 0x2A, 0x30, 0x30, 0x2A)
    if carry == 1:
        passed += 1
        if VERBOSE:
            print("  PASS elapsed=10800, thr=10800 -> C=1")
    else:
        failed += 1
        print(f"  FAIL elapsed=10800, thr=10800: carry={carry}, expected 1")

    # Test 8: Non-zero saved time, elapsed just under threshold
    # saved mid=0x10, lo=0x05; current mid=0x12, lo=0x5C
    # elapsed mid = 0x02, lo = 0x57 = 599
    carry = run_timer_test(0, 0x10, 0x05, 0, 0x12, 0x5C, 0x58, 0x02)
    if carry == 0:
        passed += 1
        if VERBOSE:
            print("  PASS non-zero saved, elapsed=599, thr=600 -> C=0")
    else:
        failed += 1
        print(f"  FAIL non-zero saved, elapsed=599: carry={carry}, expected 0")

    return passed, failed


def test_keepalive(transport, labels, rng):
    """Test empty Type 4 packet (keepalive) encrypt and decrypt."""
    passed = failed = 0

    for trial in range(4):
        send_key = bytes(rng.randint(0, 255) for _ in range(32))
        recv_key = bytes(rng.randint(0, 255) for _ in range(32))
        receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))
        counter_val = rng.randint(0, 0xFFFF)

        if trial < 2:
            # C64 encrypts keepalive, Python decrypts
            write_bytes(transport, labels["hs_transport_send"], send_key)
            write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
            write_bytes(transport, labels["tp_send_counter"],
                        struct.pack('<Q', counter_val))
            write_bytes(transport, labels["tp_payload_len"], bytes([0, 0]))

            jsr(transport, labels["transport_encrypt"])

            pkt_len_bytes = read_bytes(transport, labels["tp_packet_len"], 2)
            pkt_len = int.from_bytes(pkt_len_bytes, 'little')
            packet = bytes(read_bytes(transport, labels["tp_packet"], pkt_len))

            # Type should be 4
            pkt_type = struct.unpack('<I', packet[:4])[0]
            if pkt_type != 4:
                failed += 1
                print(f"  FAIL keepalive encrypt #{trial}: type={pkt_type}")
                continue

            # Total length should be 16 (header) + 16 (tag) = 32
            if pkt_len != 32:
                failed += 1
                print(f"  FAIL keepalive encrypt #{trial}: pkt_len={pkt_len}, expected 32")
                continue

            # Python decrypt
            pkt_counter = struct.unpack('<Q', packet[8:16])[0]
            ct_tag = packet[16:]
            nonce = b'\x00' * 4 + struct.pack('<Q', pkt_counter)
            aead = ChaCha20Poly1305(send_key)
            try:
                decrypted = aead.decrypt(nonce, ct_tag, None)
                if decrypted == b'':
                    passed += 1
                    if VERBOSE:
                        print(f"  PASS keepalive encrypt #{trial}: empty payload")
                else:
                    failed += 1
                    print(f"  FAIL keepalive encrypt #{trial}: decrypted not empty")
            except Exception as e:
                failed += 1
                print(f"  FAIL keepalive encrypt #{trial}: decrypt error: {e}")
        else:
            # Python encrypts keepalive, C64 decrypts
            nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
            aead = ChaCha20Poly1305(recv_key)
            ct_tag = aead.encrypt(nonce, b'', None)

            pkt = bytearray()
            pkt += struct.pack('<I', 4)
            pkt += receiver_idx
            pkt += struct.pack('<Q', counter_val)
            pkt += ct_tag

            write_bytes(transport, labels["hs_transport_recv"], recv_key)
            write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
            write_bytes(transport, labels["tp_recv_counter"],
                        struct.pack('<Q', counter_val))
            write_bytes(transport, labels["wg_state"], bytes([2]))  # ACTIVE

            write_bytes(transport, labels["udp_recv_buf"], bytes(pkt))
            write_bytes(transport, labels["udp_recv_len"],
                        struct.pack('<H', len(pkt)))
            write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

            jsr(transport, labels["session_handle_packet"], timeout=60.0)

            dec_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')
            if dec_len == 0:
                passed += 1
                if VERBOSE:
                    print(f"  PASS keepalive decrypt #{trial}: payload_len=0")
            else:
                failed += 1
                print(f"  FAIL keepalive decrypt #{trial}: payload_len={dec_len}, expected 0")

    return passed, failed


def test_cookie(transport, labels, rng):
    """Test cookie_handle_type3 with XChaCha20-Poly1305."""
    passed = failed = 0

    cookie_handle = labels["cookie_handle_type3"]
    cookie_valid_addr = labels["cookie_valid"]
    cookie_buf_addr = labels["cookie_buf"]
    cfg_peer_pub_addr = labels["cfg_peer_pub"]
    hs_packet_addr = labels["hs_packet"]
    udp_recv_buf_addr = labels["udp_recv_buf"]

    # Trampoline: JSR cookie_handle_type3; STA $0360; RTS
    trampoline = bytes([
        0x20, cookie_handle & 0xFF, cookie_handle >> 8,
        0x8D, 0x60, 0x03,
        0x60,
    ])
    write_bytes(transport, 0x0340, trampoline)

    # Set up peer public key
    peer_pub = bytes(rng.randint(0, 255) for _ in range(32))
    write_bytes(transport, cfg_peer_pub_addr, peer_pub)

    # Set up a known MAC1 at hs_packet+116 (16 bytes)
    mac1 = bytes(rng.randint(0, 255) for _ in range(16))
    write_bytes(transport, hs_packet_addr + 116, mac1)

    # Derive cookie_key in Python: BLAKE2s-256("cookie--" || peer_pub)
    cookie_key = hashlib.blake2s(b"cookie--" + peer_pub, digest_size=32).digest()

    # Test 1: Valid cookie -> A=0, cookie_valid=1, cookie_buf matches
    cookie_data = bytes(rng.randint(0, 255) for _ in range(16))
    nonce_24 = bytes(rng.randint(0, 255) for _ in range(24))
    ct_tag = xchacha20poly1305_encrypt(cookie_key, nonce_24, cookie_data, mac1)
    # ct_tag = 16 bytes ciphertext + 16 bytes tag = 32 bytes

    # Build Type 3 packet (64 bytes)
    type3 = bytearray(64)
    type3[0] = 3  # type
    type3[1:4] = b'\x00\x00\x00'  # reserved
    type3[4:8] = b'\x01\x02\x03\x04'  # receiver_index
    type3[8:32] = nonce_24
    type3[32:48] = ct_tag[:16]   # encrypted cookie
    type3[48:64] = ct_tag[16:]   # tag

    # Clear cookie_valid first
    # Issue #94: cookie_handle_type3 now requires the reply to be addressed to
    # our current sender index, and requires that we have actually sent an
    # initiation (hs_mac1_valid, the hasLastMAC1 equivalent). This is a unit
    # test of the XChaCha20-Poly1305 path, not of those guards, so satisfy
    # both preconditions explicitly. tools/test_issue_94_cookie_reply.py owns
    # the guard behaviour.
    write_bytes(transport, labels["hs_sender_idx"], b'\x01\x02\x03\x04')
    write_bytes(transport, labels["hs_mac1_valid"], bytes([1]))

    write_bytes(transport, cookie_valid_addr, bytes([0]))
    write_bytes(transport, udp_recv_buf_addr, bytes(type3))
    jsr(transport, 0x0340)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    decrypted_cookie = bytes(read_bytes(transport, cookie_buf_addr, 16))

    if result_a == 0 and valid_flag == 1 and decrypted_cookie == cookie_data:
        passed += 1
        if VERBOSE:
            print("  PASS valid cookie -> A=0, cookie matches")
    else:
        failed += 1
        print(f"  FAIL valid cookie: A={result_a:#04x}, valid={valid_flag}, "
              f"cookie={'match' if decrypted_cookie == cookie_data else 'MISMATCH'}")

    # Test 2: Tampered tag -> A=$FF, cookie_valid stays 0
    write_bytes(transport, cookie_valid_addr, bytes([0]))
    tampered = bytearray(type3)
    tampered[60] ^= 0xFF  # flip byte in tag
    write_bytes(transport, udp_recv_buf_addr, bytes(tampered))
    jsr(transport, 0x0340)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    if result_a == 0xFF and valid_flag == 0:
        passed += 1
        if VERBOSE:
            print("  PASS tampered tag -> A=$FF, cookie_valid=0")
    else:
        failed += 1
        print(f"  FAIL tampered tag: A={result_a:#04x}, valid={valid_flag}")

    # Test 3: Wrong nonce -> A=$FF
    write_bytes(transport, cookie_valid_addr, bytes([0]))
    wrong_nonce = bytearray(type3)
    wrong_nonce[8] ^= 0xFF  # flip first nonce byte
    write_bytes(transport, udp_recv_buf_addr, bytes(wrong_nonce))
    jsr(transport, 0x0340)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    if result_a == 0xFF and valid_flag == 0:
        passed += 1
        if VERBOSE:
            print("  PASS wrong nonce -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL wrong nonce: A={result_a:#04x}, valid={valid_flag}")

    # Test 4: Second valid cookie overwrites first
    cookie_data2 = bytes(rng.randint(0, 255) for _ in range(16))
    nonce_24b = bytes(rng.randint(0, 255) for _ in range(24))
    ct_tag2 = xchacha20poly1305_encrypt(cookie_key, nonce_24b, cookie_data2, mac1)

    type3b = bytearray(64)
    type3b[0] = 3
    type3b[1:4] = b'\x00\x00\x00'
    # Same receiver_index as type3: issue #94 made cookie_handle_type3 check
    # it against hs_sender_idx, and this case is about a second cookie
    # OVERWRITING the first, not about the index. Changing it here would make
    # the $FF that follows come from the index guard rather than from the
    # AEAD, which is the opposite of what test 4 asks.
    type3b[4:8] = b'\x01\x02\x03\x04'
    type3b[8:32] = nonce_24b
    type3b[32:48] = ct_tag2[:16]
    type3b[48:64] = ct_tag2[16:]

    write_bytes(transport, cookie_valid_addr, bytes([0]))
    write_bytes(transport, udp_recv_buf_addr, bytes(type3b))
    jsr(transport, 0x0340)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    decrypted_cookie2 = bytes(read_bytes(transport, cookie_buf_addr, 16))
    if result_a == 0 and decrypted_cookie2 == cookie_data2:
        passed += 1
        if VERBOSE:
            print("  PASS second cookie overwrites first")
    else:
        failed += 1
        print(f"  FAIL second cookie: A={result_a:#04x}, "
              f"match={decrypted_cookie2 == cookie_data2}")

    # Test 5: Tampered ciphertext -> A=$FF
    write_bytes(transport, cookie_valid_addr, bytes([0]))
    tampered_ct = bytearray(type3)
    tampered_ct[35] ^= 0xFF  # flip byte in encrypted cookie
    write_bytes(transport, udp_recv_buf_addr, bytes(tampered_ct))
    jsr(transport, 0x0340)

    result_a = read_bytes(transport, 0x0360, 1)[0]
    valid_flag = read_bytes(transport, cookie_valid_addr, 1)[0]
    if result_a == 0xFF and valid_flag == 0:
        passed += 1
        if VERBOSE:
            print("  PASS tampered ciphertext -> A=$FF")
    else:
        failed += 1
        print(f"  FAIL tampered ciphertext: A={result_a:#04x}, valid={valid_flag}")

    return passed, failed


def test_payload_routing(transport, labels, rng):
    """Test session_handle_packet routes decrypted payloads correctly."""
    passed = failed = 0

    def encrypt_and_send(recv_key, receiver_idx, counter_val, inner_ip_pkt):
        """Encrypt inner IP packet as Type 4 and write to C64."""
        nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
        aead = ChaCha20Poly1305(recv_key)
        ct_tag = aead.encrypt(nonce, inner_ip_pkt, None)

        pkt = bytearray()
        pkt += struct.pack('<I', 4)
        pkt += receiver_idx
        pkt += struct.pack('<Q', counter_val)
        pkt += ct_tag

        write_bytes(transport, labels["hs_transport_recv"], recv_key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_recv_counter"],
                    struct.pack('<Q', counter_val))
        # Reset sliding window state so counter is accepted
        if "rw_counter_max" in labels:
            write_bytes(transport, labels["rw_counter_max"], bytes(8))
        if "rw_bitmap" in labels:
            write_bytes(transport, labels["rw_bitmap"], bytes(256))
        write_bytes(transport, labels["wg_state"], bytes([2]))

        write_bytes(transport, labels["udp_recv_buf"], bytes(pkt))
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(pkt)))
        write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

        jsr(transport, labels["session_handle_packet"], timeout=60.0)

    # Set up msg_port for UDP routing tests
    port_val = 9999
    port_be = bytes([(port_val >> 8) & 0xFF, port_val & 0xFF])
    write_bytes(transport, labels["msg_port"], port_be)

    recv_key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))
    counter = 0

    # Test 1: ICMP echo reply (proto=1, type=0, ID=$C640) -> recognized
    icmp_reply = py_build_icmp_echo_reply(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', 0xC640, 42)
    encrypt_and_send(recv_key, receiver_idx, counter, icmp_reply)
    counter += 1
    # If it got here without crash, the routing worked
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS ICMP echo reply routed (no crash)")
    else:
        failed += 1
        print(f"  FAIL ICMP echo reply: state={state}")

    # Test 2: ICMP other type (type=3, destination unreachable) -> fallback display
    icmp_other = bytearray(py_build_icmp_echo_reply(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', 0xC640, 1))
    icmp_other[20] = 3  # type=3 (dest unreachable)
    # Recompute ICMP checksum
    icmp_part = bytearray(icmp_other[20:28])
    icmp_part[2:4] = b'\x00\x00'
    cksum = py_ip_checksum(bytes(icmp_part))
    icmp_other[22] = (cksum >> 8) & 0xFF
    icmp_other[23] = cksum & 0xFF
    encrypt_and_send(recv_key, receiver_idx, counter, bytes(icmp_other))
    counter += 1
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS ICMP other type routed to fallback (no crash)")
    else:
        failed += 1
        print(f"  FAIL ICMP other type: state={state}")

    # Test 3: UDP with matching port -> msg_recv_len set
    payload_text = b"TEST MSG"
    udp_pkt = py_build_udp_packet(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', port_val, payload_text)
    encrypt_and_send(recv_key, receiver_idx, counter, udp_pkt)
    counter += 1
    recv_len = read_bytes(transport, labels["msg_recv_len"], 1)[0]
    if recv_len == len(payload_text):
        passed += 1
        if VERBOSE:
            print(f"  PASS UDP matching port: msg_recv_len={recv_len}")
    else:
        failed += 1
        print(f"  FAIL UDP matching port: msg_recv_len={recv_len}, expected {len(payload_text)}")

    # Test 4: UDP with wrong port -> fallback display (no msg_recv_len update)
    # First clear msg_recv_len
    write_bytes(transport, labels["msg_recv_len"], bytes([0]))
    wrong_port_pkt = py_build_udp_packet(
        b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02', 8888, b"WRONG")
    encrypt_and_send(recv_key, receiver_idx, counter, wrong_port_pkt)
    counter += 1
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS UDP wrong port -> fallback (no crash)")
    else:
        failed += 1
        print(f"  FAIL UDP wrong port: state={state}")

    # Test 5: Raw TCP payload (proto=6) -> fallback display
    tcp_pkt = py_build_ip_header(40, 6, b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02')
    tcp_pkt += b'\x00' * 20  # dummy TCP data
    encrypt_and_send(recv_key, receiver_idx, counter, tcp_pkt)
    counter += 1
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS TCP payload -> fallback (no crash)")
    else:
        failed += 1
        print(f"  FAIL TCP payload: state={state}")

    # Test 6: Tampered Type 4 should not crash (decrypt failure)
    nonce = b'\x00' * 4 + struct.pack('<Q', counter)
    aead = ChaCha20Poly1305(recv_key)
    ct_tag = aead.encrypt(nonce, b'\x00' * 20, None)
    bad_pkt = bytearray()
    bad_pkt += struct.pack('<I', 4)
    bad_pkt += receiver_idx
    bad_pkt += struct.pack('<Q', counter)
    bad_pkt += ct_tag
    bad_pkt[20] ^= 0xFF  # tamper ciphertext

    write_bytes(transport, labels["hs_transport_recv"], recv_key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
    write_bytes(transport, labels["tp_recv_counter"],
                struct.pack('<Q', counter))
    write_bytes(transport, labels["wg_state"], bytes([2]))
    write_bytes(transport, labels["udp_recv_buf"], bytes(bad_pkt))
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(bad_pkt)))
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    jsr(transport, labels["session_handle_packet"], timeout=60.0)
    counter += 1

    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 2:
        passed += 1
        if VERBOSE:
            print("  PASS tampered Type 4 rejected (no crash)")
    else:
        failed += 1
        print(f"  FAIL tampered Type 4: state={state}")

    # Test 7: Empty payload (keepalive) recognized as proto routing edge case
    encrypt_and_send(recv_key, receiver_idx, counter, b'')
    counter += 1
    # tp_payload_len should be 0 after keepalive
    dec_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')
    if dec_len == 0:
        passed += 1
        if VERBOSE:
            print("  PASS empty payload (keepalive) handled")
    else:
        failed += 1
        print(f"  FAIL empty payload: tp_payload_len={dec_len}")

    # Test 8: Type 4 in wrong state (IDLE) -> ignored
    write_bytes(transport, labels["wg_state"], bytes([0]))  # IDLE
    nonce = b'\x00' * 4 + struct.pack('<Q', counter)
    aead = ChaCha20Poly1305(recv_key)
    ct_tag = aead.encrypt(nonce, b'\x42' * 10, None)
    pkt = bytearray()
    pkt += struct.pack('<I', 4)
    pkt += receiver_idx
    pkt += struct.pack('<Q', counter)
    pkt += ct_tag
    write_bytes(transport, labels["udp_recv_buf"], bytes(pkt))
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(pkt)))
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    jsr(transport, labels["session_handle_packet"], timeout=60.0)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    if state == 0:
        passed += 1
        if VERBOSE:
            print("  PASS Type 4 ignored in IDLE state")
    else:
        failed += 1
        print(f"  FAIL Type 4 in IDLE: state changed to {state}")

    return passed, failed


def test_round_trip(transport, labels, rng):
    """Test round-trip tunnel packet construction and encryption."""
    passed = failed = 0

    tunnel_ip_addr = labels["tunnel_ip"]
    target_ip_addr = labels["ping_target_ip"]
    ping_seq_addr = labels["ping_seq"]
    msg_port_addr = labels["msg_port"]
    input_buf = labels["input_buffer"]
    ip_pkt_buf = labels["ip_packet_buf"]
    zp_ptr1 = labels["zp_ptr1"]
    zp_tmp1 = labels["zp_tmp1"]

    # Fixed IPs for round-trip tests
    src_ip = bytes([10, 0, 0, 2])
    dst_ip = bytes([10, 0, 0, 1])
    port_val = 9999
    port_be = bytes([(port_val >> 8) & 0xFF, port_val & 0xFF])

    write_bytes(transport, tunnel_ip_addr, src_ip)
    write_bytes(transport, target_ip_addr, dst_ip)
    write_bytes(transport, msg_port_addr, port_be)

    # --- Test 1-2: C64 builds ICMP echo request, Python verifies ---
    for trial in range(2):
        seq_val = rng.randint(0, 0xFFFE)
        write_bytes(transport, ping_seq_addr,
                    bytes([(seq_val >> 8) & 0xFF, seq_val & 0xFF]))
        jsr(transport, labels["icmp_build_echo"])
        pkt = bytes(read_bytes(transport, ip_pkt_buf, 28))

        ok = True
        # Verify IP checksum
        if py_ip_checksum(pkt[:20]) != 0:
            ok = False
        # Verify ICMP checksum
        if py_ip_checksum(pkt[20:28]) != 0:
            ok = False
        # Verify protocol
        if pkt[9] != 1:
            ok = False
        # Verify IPs
        if pkt[12:16] != src_ip or pkt[16:20] != dst_ip:
            ok = False

        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS C64->Py ICMP #{trial}: seq={seq_val}")
        else:
            failed += 1
            print(f"  FAIL C64->Py ICMP #{trial}: verification failed")

    # --- Test 3-4: C64 builds UDP message, Python verifies ---
    for trial in range(2):
        text = bytes(rng.randint(0x20, 0x7E) for _ in range(rng.randint(5, 30)))
        write_bytes(transport, input_buf, text)
        write_bytes(transport, zp_ptr1, struct.pack('<H', input_buf))
        write_bytes(transport, zp_tmp1, bytes([len(text)]))
        jsr(transport, labels["udp_tunnel_build"])

        total_len = 28 + len(text)
        pkt = bytes(read_bytes(transport, ip_pkt_buf, total_len))

        ok = True
        if py_ip_checksum(pkt[:20]) != 0:
            ok = False
        if pkt[9] != 17:
            ok = False
        if pkt[28:28 + len(text)] != text:
            ok = False

        if ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS C64->Py UDP #{trial}: {len(text)}B")
        else:
            failed += 1
            print(f"  FAIL C64->Py UDP #{trial}")

    # --- Test 5-7: Python builds ICMP reply, encrypts as Type 4, C64 decrypts ---
    recv_key = bytes(rng.randint(0, 255) for _ in range(32))
    receiver_idx = bytes(rng.randint(0, 255) for _ in range(4))

    for trial in range(3):
        counter_val = trial
        seq = rng.randint(1, 0xFFFF)
        reply_pkt = py_build_icmp_echo_reply(dst_ip, src_ip, 0xC640, seq)

        nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
        aead = ChaCha20Poly1305(recv_key)
        ct_tag = aead.encrypt(nonce, reply_pkt, None)

        type4 = bytearray()
        type4 += struct.pack('<I', 4)
        type4 += receiver_idx
        type4 += struct.pack('<Q', counter_val)
        type4 += ct_tag

        write_bytes(transport, labels["hs_transport_recv"], recv_key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_recv_counter"],
                    struct.pack('<Q', counter_val))
        # Reset sliding window state so counter is accepted
        if "rw_counter_max" in labels:
            write_bytes(transport, labels["rw_counter_max"], bytes(8))
        if "rw_bitmap" in labels:
            write_bytes(transport, labels["rw_bitmap"], bytes(256))

        # Write to udp_recv_buf (transport_decrypt reads from there)
        write_bytes(transport, labels["udp_recv_buf"], bytes(type4))
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(type4)))
        jsr(transport, labels["transport_decrypt"], timeout=60.0)

        # Read A result from transport_decrypt: check via tp_payload_len
        dec_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')
        decrypted = bytes(read_bytes(transport, labels["tp_packet"] + 16,
                                     len(reply_pkt)))

        if decrypted == reply_pkt and dec_len == len(reply_pkt):
            # Now test icmp_parse_reply via trampoline
            icmp_parse = labels["icmp_parse_reply"]
            tramp = bytes([
                0x20, icmp_parse & 0xFF, icmp_parse >> 8,
                0x8D, 0x60, 0x03,
                0x60,
            ])
            write_bytes(transport, 0x0340, tramp)
            jsr(transport, 0x0340)
            parse_result = read_bytes(transport, 0x0360, 1)[0]
            if parse_result == 0:
                passed += 1
                if VERBOSE:
                    print(f"  PASS Py->C64 ICMP #{trial}: decrypt+parse OK")
            else:
                failed += 1
                print(f"  FAIL Py->C64 ICMP #{trial}: parse_reply={parse_result:#04x}")
        else:
            failed += 1
            print(f"  FAIL Py->C64 ICMP #{trial}: decrypt mismatch")

    # --- Test 8-10: Python builds UDP, encrypts, C64 decrypts and parses ---
    write_bytes(transport, labels["msg_port"], port_be)

    for trial in range(3):
        counter_val = 100 + trial
        msg_text = bytes(rng.randint(0x41, 0x5A) for _ in range(rng.randint(3, 20)))
        udp_pkt = py_build_udp_packet(dst_ip, src_ip, port_val, msg_text)

        nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
        aead = ChaCha20Poly1305(recv_key)
        ct_tag = aead.encrypt(nonce, udp_pkt, None)

        type4 = bytearray()
        type4 += struct.pack('<I', 4)
        type4 += receiver_idx
        type4 += struct.pack('<Q', counter_val)
        type4 += ct_tag

        write_bytes(transport, labels["hs_transport_recv"], recv_key)
        write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
        write_bytes(transport, labels["tp_recv_counter"],
                    struct.pack('<Q', counter_val))
        # Reset sliding window state so counter is accepted
        if "rw_counter_max" in labels:
            write_bytes(transport, labels["rw_counter_max"], bytes(8))
        if "rw_bitmap" in labels:
            write_bytes(transport, labels["rw_bitmap"], bytes(256))

        write_bytes(transport, labels["udp_recv_buf"], bytes(type4))
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(type4)))
        jsr(transport, labels["transport_decrypt"], timeout=60.0)

        dec_len = int.from_bytes(read_bytes(transport, labels["tp_payload_len"], 2), 'little')

        if dec_len == len(udp_pkt):
            # Parse UDP via trampoline
            udp_parse = labels["udp_tunnel_parse"]
            tramp = bytes([
                0x20, udp_parse & 0xFF, udp_parse >> 8,
                0x8D, 0x60, 0x03,
                0x60,
            ])
            write_bytes(transport, 0x0340, tramp)
            jsr(transport, 0x0340)
            parse_result = read_bytes(transport, 0x0360, 1)[0]
            recv_msg_len = read_bytes(transport, labels["msg_recv_len"], 1)[0]

            if parse_result == 0 and recv_msg_len == len(msg_text):
                # Read actual message text from msg_recv_ptr
                msg_ptr = int.from_bytes(
                    read_bytes(transport, labels["msg_recv_ptr"], 2), 'little')
                recv_text = bytes(read_bytes(transport, msg_ptr, len(msg_text)))
                if recv_text == msg_text:
                    passed += 1
                    if VERBOSE:
                        print(f"  PASS Py->C64 UDP #{trial}: {len(msg_text)}B text matches")
                else:
                    failed += 1
                    print(f"  FAIL Py->C64 UDP #{trial}: text mismatch")
                    print(f"    expected: {msg_text.hex()}")
                    print(f"    got:      {recv_text.hex()}")
            else:
                failed += 1
                print(f"  FAIL Py->C64 UDP #{trial}: parse={parse_result:#04x}, "
                      f"len={recv_msg_len}, expected {len(msg_text)}")
        else:
            failed += 1
            print(f"  FAIL Py->C64 UDP #{trial}: dec_len={dec_len}, "
                  f"expected {len(udp_pkt)}")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    groups = [
        ("IP checksum", lambda: test_ip_checksum(transport, labels, rng)),
        ("ICMP build", lambda: test_icmp_build(transport, labels, rng)),
        ("ICMP parse", lambda: test_icmp_parse(transport, labels)),
        ("UDP build", lambda: test_udp_build(transport, labels, rng)),
        ("read_input_line", lambda: test_read_input_line(transport, labels)),
        ("UDP parse", lambda: test_udp_parse(transport, labels)),
        ("timer elapsed", lambda: test_timer_elapsed(transport, labels)),
        ("keepalive", lambda: test_keepalive(transport, labels, rng)),
        ("cookie", lambda: test_cookie(transport, labels, rng)),
        ("payload routing", lambda: test_payload_routing(transport, labels, rng)),
        ("round-trip tunnel", lambda: test_round_trip(transport, labels, rng)),
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
        "ip_checksum", "icmp_build_echo", "icmp_parse_reply",
        "udp_tunnel_build", "udp_tunnel_parse",
        "hchacha20", "cookie_handle_type3", "hs_set_mac2",
        "timer_session_start", "timer_check", "timer_mark_send",
        "timer_elapsed_cmp", "config_read_file",
        "ip_packet_buf", "ip_pkt_len", "cookie_valid", "cookie_buf",
        "hs_sender_idx", "hs_mac1_valid",
        "read_input_line", "msg_input_len",
        "input_buffer", "zp_ptr1", "zp_tmp1",
        "tunnel_ip", "ping_target_ip", "ping_seq",
        "ip_cksum_result", "msg_port", "msg_recv_ptr", "msg_recv_len",
        "tp_packet", "tp_packet_len", "tp_payload_ptr",
        "tp_payload_len", "tp_send_counter", "tp_recv_counter",
        "tp_peer_recv_idx", "cfg_peer_pub",
        "hs_transport_send", "hs_transport_recv",
        "hs_packet", "udp_recv_buf", "udp_recv_len", "udp_recv_ready",
        "transport_encrypt", "transport_decrypt",
        "session_handle_packet", "wg_state",
        "session_start_jiffy", "last_send_jiffy",
        "blake2s_init", "blake2s_update", "blake2s_final",
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
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        grid = binary_wait_for_boot_ready(transport, labels, timeout=180.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)
        total_passed = passed + bp
        total_failed = failed + bf

        mgr.release(inst)

    total = total_passed + total_failed
    print(f"\n{'='*60}")
    print(f"Results: {total_passed}/{total} passed, {total_failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
