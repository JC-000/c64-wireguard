#!/usr/bin/env python3
"""Loopback test for tools/wg_responder — no U64E required.

Constructs a full WireGuard Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake
in pure Python, sends it to ``WireGuardResponder`` running in a daemon
thread, and verifies the Type-2 reply + Type-4 transport round-trip on
both 127.0.0.1 and the host's LAN IP. Useful as a fast smoke check
before C64-side handshake debugging: if this fails, the Python
responder itself is broken; if it passes, the host stack is exonerated.

Run::

    /opt/homebrew/bin/python3.13 tools/test_wg_responder_loopback.py
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# Add repo root so the wg_responder package is importable regardless of cwd.
REPO = str(Path(__file__).resolve().parent.parent)
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from tools.wg_responder.keys import generate_keypair
from tools.wg_responder.responder import (
    WireGuardResponder,
    CONSTRUCTION, IDENTIFIER,
    LABEL_MAC1,
    MSG_TYPE_INITIATION, MSG_TYPE_TRANSPORT,
    T1_TOTAL, T1_OFF_SENDER, T1_OFF_NOISE, T1_OFF_MAC1,
    T2_TOTAL, T2_OFF_SENDER, T2_OFF_RECEIVER,
)
from noise.connection import NoiseConnection, Keypair


def _blake2s(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()

def _mac1_key(static_pubkey: bytes) -> bytes:
    return _blake2s(LABEL_MAC1 + static_pubkey)

def _compute_mac1(msg_bytes: bytes, mac1_key: bytes) -> bytes:
    h = hashlib.blake2s(key=mac1_key, digest_size=16)
    h.update(msg_bytes)
    return h.digest()


class ResponderThread(threading.Thread):
    def __init__(self, responder: WireGuardResponder):
        super().__init__(daemon=True)
        self.responder = responder
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(10.0)
        self.port = self.sock.getsockname()[1]
        self.error: Exception | None = None
        self.type1_received = False
        self.type4_received = False
        self.type4_plaintext: bytes | None = None

    def run(self):
        try:
            data, addr = self.sock.recvfrom(65535)
            print(f"[responder] recvfrom {addr} len={len(data)} type=0x{data[0]:02x}", flush=True)
            self.type1_received = True
            if data[0] != MSG_TYPE_INITIATION:
                self.error = RuntimeError(f"Expected Type1, got 0x{data[0]:02x}")
                return
            try:
                resp_pkt = self.responder.handle_initiation(data)
            except Exception as exc:
                self.error = exc
                return
            print(f"[responder] sending Type2 ({len(resp_pkt)} bytes) to {addr}", flush=True)
            self.sock.sendto(resp_pkt, addr)

            data4, addr4 = self.sock.recvfrom(65535)
            print(f"[responder] recvfrom {addr4} len={len(data4)} type=0x{data4[0]:02x}", flush=True)
            self.type4_received = True
            try:
                pt = self.responder.decrypt_transport(data4)
                self.type4_plaintext = pt
                print(f"[responder] decrypted Type4: {pt!r}", flush=True)
            except Exception as exc:
                self.error = exc
        except Exception as exc:
            self.error = exc


def build_type1(initiator_priv, initiator_pub, responder_pub, psk, sender_idx):
    tai64n_epoch = 4611686018427387914
    tai_secs = tai64n_epoch + int(time.time()) + 37
    timestamp = struct.pack(">QI", tai_secs, 0)

    noise = NoiseConnection.from_name(CONSTRUCTION)
    noise.set_prologue(IDENTIFIER)
    noise.set_psks(psk=psk)
    noise.set_keypair_from_private_bytes(Keypair.STATIC, initiator_priv)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, responder_pub)
    noise.set_as_initiator()
    noise.start_handshake()

    noise_msg1 = bytes(noise.write_message(timestamp))
    assert len(noise_msg1) == 108, f"noise_msg1 is {len(noise_msg1)} bytes, expected 108"

    hdr_and_noise = (
        bytes([MSG_TYPE_INITIATION, 0, 0, 0])
        + struct.pack("<I", sender_idx)
        + noise_msg1
    )
    mac1 = _compute_mac1(hdr_and_noise, _mac1_key(responder_pub))
    pkt = hdr_and_noise + mac1 + bytes(16)
    assert len(pkt) == T1_TOTAL
    return pkt, noise


def build_type4(noise, plaintext, receiver_idx, counter):
    ciphertext = bytes(noise.encrypt(plaintext))
    hdr = (
        bytes([MSG_TYPE_TRANSPORT, 0, 0, 0])
        + struct.pack("<I", receiver_idx)
        + struct.pack("<Q", counter)
    )
    return hdr + ciphertext


def run_test(listen_ip: str = "127.0.0.1", label: str = "loopback") -> bool:
    print(f"\n{'='*60}", flush=True)
    print(f"TEST: {label} ({listen_ip})", flush=True)
    print(f"{'='*60}", flush=True)

    init_priv_hex, init_pub_hex = generate_keypair()
    resp_priv_hex, resp_pub_hex = generate_keypair()
    init_priv = bytes.fromhex(init_priv_hex)
    init_pub  = bytes.fromhex(init_pub_hex)
    resp_priv = bytes.fromhex(resp_priv_hex)
    resp_pub  = bytes.fromhex(resp_pub_hex)
    psk = bytes(32)

    print(f"  initiator pub: {init_pub.hex()}", flush=True)
    print(f"  responder pub: {resp_pub.hex()}", flush=True)

    responder = WireGuardResponder(static_priv=resp_priv, peer_static_pub=init_pub, psk=psk)
    rt = ResponderThread(responder)
    rt.start()
    resp_port = rt.port
    print(f"  responder listening on 127.0.0.1:{resp_port}", flush=True)

    sender_idx = int.from_bytes(os.urandom(4), "little")
    t1_pkt, initiator_noise = build_type1(init_priv, init_pub, resp_pub, psk, sender_idx)
    print(f"  Type1 built: {len(t1_pkt)} bytes, sender_idx=0x{sender_idx:08x}", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.sendto(t1_pkt, (listen_ip, resp_port))
    print(f"  Type1 sent to {listen_ip}:{resp_port}", flush=True)

    try:
        t2_data, t2_from = sock.recvfrom(65535)
    except socket.timeout:
        print("FAIL: timeout waiting for Type-2 response", flush=True)
        if rt.error:
            print(f"  responder error: {rt.error}", flush=True)
        return False

    print(f"  Type2 received: {len(t2_data)} bytes from {t2_from}", flush=True)

    ok = True
    if t2_data[0] != 0x02:
        print(f"FAIL: Type2 byte0=0x{t2_data[0]:02x}, expected 0x02", flush=True)
        ok = False
    if len(t2_data) != T2_TOTAL:
        print(f"FAIL: Type2 length={len(t2_data)}, expected {T2_TOTAL}", flush=True)
        ok = False
    else:
        resp_sender_idx   = struct.unpack_from("<I", t2_data, T2_OFF_SENDER)[0]
        resp_receiver_idx = struct.unpack_from("<I", t2_data, T2_OFF_RECEIVER)[0]
        if resp_receiver_idx != sender_idx:
            print(f"FAIL: Type2 receiver_idx=0x{resp_receiver_idx:08x} != our sender_idx=0x{sender_idx:08x}", flush=True)
            ok = False
        else:
            print(f"  Type2 OK: byte0=0x02, len=92, sender=0x{resp_sender_idx:08x}, receiver=0x{resp_receiver_idx:08x}", flush=True)

    if not ok:
        return False

    noise_msg2 = t2_data[12:60]
    try:
        initiator_noise.read_message(noise_msg2)
    except Exception as exc:
        print(f"FAIL: initiator noise.read_message(Type2 payload) raised: {exc}", flush=True)
        return False
    print("  initiator noise.read_message(Type2) OK — handshake complete", flush=True)

    payload = b"hello from loopback test"
    t4_pkt = build_type4(initiator_noise, payload, resp_sender_idx, 0)
    sock.sendto(t4_pkt, (listen_ip, resp_port))
    print(f"  Type4 sent: {len(t4_pkt)} bytes, payload={payload!r}", flush=True)

    rt.join(timeout=5.0)
    if rt.is_alive():
        print("FAIL: responder thread timed out after Type4", flush=True)
        return False
    if rt.error:
        print(f"FAIL: responder thread error: {rt.error}", flush=True)
        return False
    if not rt.type4_received:
        print("FAIL: responder never received Type4", flush=True)
        return False
    if rt.type4_plaintext != payload:
        print(f"FAIL: decrypted plaintext={rt.type4_plaintext!r}, expected={payload!r}", flush=True)
        return False

    print(f"  Type4 decrypted correctly: {rt.type4_plaintext!r}", flush=True)
    print(f"PASS [{label}]", flush=True)
    return True


def main():
    passed = []
    failed = []

    if run_test("127.0.0.1", "loopback 127.0.0.1"):
        passed.append("loopback 127.0.0.1")
    else:
        failed.append("loopback 127.0.0.1")

    try:
        lan_ip = socket.gethostbyname(socket.gethostname())
        if lan_ip == "127.0.0.1":
            import subprocess
            out = subprocess.check_output(["ifconfig", "en0"], text=True)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "inet6" not in line:
                    lan_ip = line.split()[1]
                    break
    except Exception:
        lan_ip = "127.0.0.1"

    if lan_ip != "127.0.0.1":
        if run_test(lan_ip, f"LAN {lan_ip}"):
            passed.append(f"LAN {lan_ip}")
        else:
            failed.append(f"LAN {lan_ip}")
    else:
        print(f"\nSkipping LAN test (resolved to {lan_ip})", flush=True)

    print(f"\n{'='*60}", flush=True)
    print(f"SUMMARY: {len(passed)} passed, {len(failed)} failed", flush=True)
    for t in passed:
        print(f"  PASS: {t}", flush=True)
    for t in failed:
        print(f"  FAIL: {t}", flush=True)

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
