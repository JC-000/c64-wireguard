#!/usr/bin/env python3
"""Self-test for tools/wg_responder — no C64 hardware needed.

Spawns WireGuardResponder in a background thread, runs a Python initiator
against it over a loopback UDP socket, and asserts:
  (a) initiator's Type 1 reaches the responder
  (b) responder's Type 2 reaches the initiator and decodes correctly
  (c) one Type 4 round-trip (initiator→responder and responder→initiator)

Run::

    /opt/homebrew/bin/python3.13 tools/test_wg_responder.py

Exit 0 on success.
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
from typing import Optional

# ── path setup ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from noise.connection import NoiseConnection, Keypair  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from wg_responder.responder import (  # noqa: E402
    CONSTRUCTION,
    IDENTIFIER,
    LABEL_MAC1,
    MSG_TYPE_INITIATION,
    MSG_TYPE_RESPONSE,
    MSG_TYPE_TRANSPORT,
    NOISE_MSG1_LEN,
    NOISE_MSG2_LEN,
    T1_OFF_MAC1,
    T1_OFF_MAC2,
    T1_TOTAL,
    T2_HDR_LEN,
    T2_OFF_MAC1,
    T2_TOTAL,
    T4_HDR_LEN,
    WireGuardResponder,
    _blake2s,
    _compute_mac1,
    _mac1_key,
)
from wg_responder.keys import generate_keypair, priv_to_pub  # noqa: E402

# ── helpers ───────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"  {msg}", flush=True)


def _tai64n_now() -> bytes:
    """Return a 12-byte TAI64N timestamp (seconds since 1970 + nanoseconds)."""
    import time as _time
    secs = int(_time.time()) + 0x400000000000000A  # TAI offset
    nanos = 0
    return struct.pack(">QI", secs, nanos)


# ── initiator helpers ─────────────────────────────────────────────────────

def build_type1(
    init_noise: NoiseConnection,
    init_priv_bytes: bytes,
    resp_pub: bytes,
    psk: bytes,
    prologue: bytes,
) -> tuple[bytes, int]:
    """Build a Type-1 (148-byte) initiation packet.

    Returns (packet_bytes, sender_idx).
    """
    tai64n = _tai64n_now()
    noise_payload = bytes(init_noise.write_message(tai64n))
    assert len(noise_payload) == NOISE_MSG1_LEN, (
        f"noise msg1 should be {NOISE_MSG1_LEN} bytes, got {len(noise_payload)}"
    )

    sender_idx = int.from_bytes(os.urandom(4), "little")
    hdr = bytes([MSG_TYPE_INITIATION, 0, 0, 0]) + struct.pack("<I", sender_idx)
    body_up_to_mac1 = hdr + noise_payload
    assert len(body_up_to_mac1) == T1_OFF_MAC1, (
        f"body_up_to_mac1 should be {T1_OFF_MAC1} bytes, got {len(body_up_to_mac1)}"
    )

    m1_key = _mac1_key(resp_pub)
    mac1   = _compute_mac1(body_up_to_mac1, m1_key)
    mac2   = bytes(16)
    pkt    = body_up_to_mac1 + mac1 + mac2
    assert len(pkt) == T1_TOTAL, f"Type1 should be {T1_TOTAL} bytes, got {len(pkt)}"
    return pkt, sender_idx


def process_type2(
    init_noise: NoiseConnection,
    packet: bytes,
    init_pub: bytes,
    sender_idx_we_sent: int,
) -> int:
    """Validate and process a Type-2 response packet.

    Returns the responder's sender_idx (our receiver_idx for future transport).
    """
    assert len(packet) == T2_TOTAL, f"Type2 should be {T2_TOTAL} bytes, got {len(packet)}"
    assert packet[0] == MSG_TYPE_RESPONSE, f"Expected Type2, got 0x{packet[0]:02x}"
    assert packet[1:4] == b"\x00\x00\x00", "Reserved bytes not zero in Type 2"

    resp_sender_idx = struct.unpack_from("<I", packet, 4)[0]
    receiver_idx    = struct.unpack_from("<I", packet, 8)[0]
    assert receiver_idx == sender_idx_we_sent, (
        f"Type2 receiver_idx 0x{receiver_idx:08x} != our sender_idx 0x{sender_idx_we_sent:08x}"
    )

    # Verify MAC1 (keyed on initiator's static pub — that's *us*)
    body_up_to_mac1 = packet[:T2_OFF_MAC1]
    m1_key = _mac1_key(init_pub)
    expected_mac1 = _compute_mac1(body_up_to_mac1, m1_key)
    actual_mac1   = packet[T2_OFF_MAC1 : T2_OFF_MAC1 + 16]
    assert expected_mac1 == actual_mac1, (
        f"Type2 MAC1 mismatch: expected={expected_mac1.hex()} actual={actual_mac1.hex()}"
    )

    noise_payload = packet[T2_HDR_LEN : T2_HDR_LEN + NOISE_MSG2_LEN]
    init_noise.read_message(noise_payload)
    assert init_noise.handshake_finished, "Initiator handshake should be finished after Type2"

    return resp_sender_idx


def build_type4_initiator(
    init_noise: NoiseConnection,
    plaintext: bytes,
    resp_sender_idx: int,
    counter: int,
) -> bytes:
    """Encrypt plaintext as a Type-4 transport packet to the responder."""
    ciphertext = bytes(init_noise.encrypt(plaintext))
    hdr = (
        bytes([MSG_TYPE_TRANSPORT, 0, 0, 0])
        + struct.pack("<I", resp_sender_idx)
        + struct.pack("<Q", counter)
    )
    return hdr + ciphertext


# ── responder thread ──────────────────────────────────────────────────────

class ResponderThread(threading.Thread):
    """Runs WireGuardResponder.handle_initiation in a background thread.

    Stores the Type-2 response and any received Type-4 plaintext.
    """

    def __init__(
        self,
        responder: WireGuardResponder,
        listen_port: int,
    ) -> None:
        super().__init__(daemon=True)
        self.responder    = responder
        self.listen_port  = listen_port
        self.type2_packet: Optional[bytes] = None
        self.type4_plaintext: Optional[bytes] = None
        self.error:  Optional[Exception] = None
        self._sock:  Optional[socket.socket] = None
        self._ready = threading.Event()

    def run(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(10.0)
            self._sock.bind(("127.0.0.1", self.listen_port))
            self._ready.set()

            # Wait for Type 1
            data, addr = self._sock.recvfrom(65535)
            _log(f"[responder] received {len(data)}-byte packet from {addr}")

            self.type2_packet = self.responder.handle_initiation(data)
            _log(f"[responder] sending {len(self.type2_packet)}-byte Type2 to {addr}")
            self._sock.sendto(self.type2_packet, addr)

            # Wait for Type 4
            data4, addr4 = self._sock.recvfrom(65535)
            _log(f"[responder] received {len(data4)}-byte Type4 from {addr4}")
            self.type4_plaintext = self.responder.decrypt_transport(data4)
            _log(f"[responder] decrypted Type4: {self.type4_plaintext!r}")

            # Send Type 4 back
            reply = self.responder.encrypt_transport(b"pong:" + self.type4_plaintext)
            _log(f"[responder] sending {len(reply)}-byte Type4 reply")
            self._sock.sendto(reply, addr4)

        except Exception as exc:
            self.error = exc
        finally:
            if self._sock:
                self._sock.close()

    def wait_ready(self, timeout: float = 2.0) -> None:
        if not self._ready.wait(timeout=timeout):
            raise RuntimeError("Responder thread did not become ready in time")


# ── test body ─────────────────────────────────────────────────────────────

def run_test() -> None:
    print("=== wg_responder self-test ===")

    # ── (1) generate keypairs ─────────────────────────────────────────────
    print("\n[1] Generating keypairs…")
    resp_priv_hex, resp_pub_hex = generate_keypair()
    init_priv_hex, init_pub_hex = generate_keypair()
    assert priv_to_pub(resp_priv_hex) == resp_pub_hex, "priv_to_pub round-trip failed (resp)"
    assert priv_to_pub(init_priv_hex) == init_pub_hex, "priv_to_pub round-trip failed (init)"
    _log("keys OK")

    resp_priv_bytes = bytes.fromhex(resp_priv_hex)
    resp_pub_bytes  = bytes.fromhex(resp_pub_hex)
    init_priv_bytes = bytes.fromhex(init_priv_hex)
    init_pub_bytes  = bytes.fromhex(init_pub_hex)
    psk             = os.urandom(32)
    prologue        = IDENTIFIER

    # ── (2) start responder thread ─────────────────────────────────────────
    print("\n[2] Starting responder thread…")
    port = 55000 + (os.getpid() % 1000)
    wg_resp = WireGuardResponder(resp_priv_bytes, init_pub_bytes, psk)
    rt = ResponderThread(wg_resp, listen_port=port)
    rt.start()
    rt.wait_ready()
    _log(f"responder listening on 127.0.0.1:{port}")

    # ── (3) initiator side ────────────────────────────────────────────────
    print("\n[3] Initiator: setting up noise connection…")
    init_noise = NoiseConnection.from_name(CONSTRUCTION)
    init_noise.set_prologue(prologue)
    init_noise.set_psks(psk=psk)
    init_noise.set_keypair_from_private_bytes(Keypair.STATIC, init_priv_bytes)
    init_noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, resp_pub_bytes)
    init_noise.set_as_initiator()
    init_noise.start_handshake()

    # ── (4) build and send Type 1 ─────────────────────────────────────────
    print("\n[4] Initiator: building and sending Type 1…")
    t1_pkt, our_sender_idx = build_type1(
        init_noise, init_priv_bytes, resp_pub_bytes, psk, prologue
    )
    _log(f"Type1: {len(t1_pkt)} bytes, sender_idx=0x{our_sender_idx:08x}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10.0)
    sock.sendto(t1_pkt, ("127.0.0.1", port))
    _log("Type1 sent")

    # ── (5) receive and validate Type 2 ───────────────────────────────────
    print("\n[5] Initiator: receiving Type 2…")
    t2_data, _ = sock.recvfrom(65535)
    _log(f"Type2 received: {len(t2_data)} bytes")

    resp_sender_idx = process_type2(init_noise, t2_data, init_pub_bytes, our_sender_idx)
    _log(f"Type2 OK — responder sender_idx=0x{resp_sender_idx:08x}")
    assert init_noise.handshake_finished, "Initiator handshake not finished after Type2"
    print("  PASS: Type 1 reached responder, Type 2 decoded correctly")

    # ── (6) Type 4: initiator → responder ─────────────────────────────────
    print("\n[6] Sending Type 4 (initiator → responder)…")
    t4_pkt = build_type4_initiator(init_noise, b"ping from python", resp_sender_idx, counter=0)
    _log(f"Type4 out: {len(t4_pkt)} bytes")
    sock.sendto(t4_pkt, ("127.0.0.1", port))

    # ── (7) Type 4: responder → initiator ─────────────────────────────────
    print("\n[7] Receiving Type 4 (responder → initiator)…")
    t4_reply, _ = sock.recvfrom(65535)
    _log(f"Type4 reply: {len(t4_reply)} bytes")
    assert t4_reply[0] == MSG_TYPE_TRANSPORT, f"Expected Type4, got 0x{t4_reply[0]:02x}"

    # Initiator decrypts the reply
    ct_reply = t4_reply[T4_HDR_LEN:]
    pt_reply = bytes(init_noise.decrypt(bytes(ct_reply)))
    _log(f"Type4 reply decrypted: {pt_reply!r}")
    assert pt_reply == b"pong:ping from python", f"Unexpected reply plaintext: {pt_reply!r}"
    print("  PASS: Type 4 round-tripped successfully")

    sock.close()
    rt.join(timeout=5.0)
    if rt.error:
        raise rt.error

    print("\n=== ALL ASSERTIONS PASSED ===")


if __name__ == "__main__":
    run_test()
