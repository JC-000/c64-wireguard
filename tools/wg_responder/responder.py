#!/usr/bin/env python3
"""WireGuard handshake responder backed by noiseprotocol 0.3.1.

Handles the responder side of Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s as used
by WireGuard.  Designed to be maximally patient — no timeouts, no rekey, no
keepalive — so the C64's ~9-minute Type-1 computation never races a deadline.

Wire-format layout
------------------
Type 1 (initiation, 148 bytes):
    msg_type(1) | reserved(3) | sender_idx(4 LE)
    | noise_payload(108)          ← ephemeral(32)+enc_static(48)+enc_ts(28)
    | mac1(16) | mac2(16)
    Total: 4+4+108+16+16 = 148 ✓

Type 2 (response, 92 bytes):
    msg_type(1) | reserved(3) | sender_idx(4 LE) | receiver_idx(4 LE)
    | noise_payload(48)           ← ephemeral(32)+enc_nothing(16)
    | mac1(16) | mac2(16)
    Total: 4+4+4+48+16+16 = 92 ✓

Type 4 (transport data):
    msg_type(1) | reserved(3) | receiver_idx(4 LE) | counter(8 LE)
    | encrypted_data(n+16)       ← AEAD ciphertext (tag included)

MAC1 key for Type 1 = BLAKE2s("mac1----" || responder_static_pub)
MAC1 key for Type 2 = BLAKE2s("mac1----" || initiator_static_pub)
MAC2 = 16 zero bytes (no cookie exchange).
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Optional

from noise.connection import NoiseConnection, Keypair

# ── WireGuard protocol constants ───────────────────────────────────────────
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER   = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1   = b"mac1----"

MSG_TYPE_INITIATION = 0x01
MSG_TYPE_RESPONSE   = 0x02
MSG_TYPE_TRANSPORT  = 0x04

# Noise payload sizes for IKpsk2/25519/ChaChaPoly/BLAKE2s with 12-byte TAI64N
# Initiator write_message(tai64n_12b) → 32+48+28 = 108 bytes
# Responder write_message(b"")       → 32+16    =  48 bytes
NOISE_MSG1_LEN = 108
NOISE_MSG2_LEN = 48

# Type 1 offsets
T1_TOTAL       = 148
T1_OFF_SENDER  = 4      # 4-byte LE sender index
T1_OFF_NOISE   = 8      # noise payload starts here
T1_OFF_MAC1    = T1_OFF_NOISE + NOISE_MSG1_LEN   # = 116
T1_OFF_MAC2    = T1_OFF_MAC1 + 16                # = 132

# Type 2 offsets
T2_TOTAL         = 92
T2_HDR_LEN       = 12   # type(1)+reserved(3)+sender_idx(4)+receiver_idx(4)
T2_OFF_SENDER    = 4
T2_OFF_RECEIVER  = 8
T2_OFF_NOISE     = T2_HDR_LEN
T2_OFF_MAC1      = T2_OFF_NOISE + NOISE_MSG2_LEN  # = 60
T2_OFF_MAC2      = T2_OFF_MAC1 + 16               # = 76

# Type 4 header length
T4_HDR_LEN = 16   # type(1)+reserved(3)+receiver_idx(4)+counter(8)


# ── MAC helpers ────────────────────────────────────────────────────────────

def _blake2s(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def _mac1_key(static_pubkey: bytes) -> bytes:
    """BLAKE2s(LABEL_MAC1 || static_pubkey) — 32-byte keying material."""
    return _blake2s(LABEL_MAC1 + static_pubkey)


def _compute_mac1(msg_bytes: bytes, mac1_key: bytes) -> bytes:
    """16-byte BLAKE2s MAC over msg_bytes with the given 32-byte key."""
    h = hashlib.blake2s(key=mac1_key, digest_size=16)
    h.update(msg_bytes)
    return h.digest()


# ── Responder class ────────────────────────────────────────────────────────

class WireGuardResponder:
    """Stateful WireGuard responder (receives Type 1, sends Type 2, handles Type 4).

    Parameters
    ----------
    static_priv:
        Our 32-byte X25519 private key (raw, little-endian).
    peer_static_pub:
        Initiator's (C64's) 32-byte X25519 public key.
    psk:
        Optional 32-byte pre-shared key.  Defaults to 32 zero bytes.
    """

    def __init__(
        self,
        static_priv: bytes,
        peer_static_pub: bytes,
        psk: Optional[bytes] = None,
    ) -> None:
        if len(static_priv) != 32:
            raise ValueError("static_priv must be 32 bytes")
        if len(peer_static_pub) != 32:
            raise ValueError("peer_static_pub must be 32 bytes")

        self._static_priv     = static_priv
        self._peer_static_pub = peer_static_pub
        self._psk             = psk if psk is not None else bytes(32)

        # Derive our static public key (needed for MAC1 verification on Type 1)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        _priv_obj = X25519PrivateKey.from_private_bytes(static_priv)
        self._static_pub: bytes = _priv_obj.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        # Precompute MAC1 key for verifying incoming Type 1 (keyed on our pub)
        self._mac1_key_for_t1 = _mac1_key(self._static_pub)
        # MAC1 key for outgoing Type 2 (keyed on initiator/peer pub)
        self._mac1_key_for_t2 = _mac1_key(self._peer_static_pub)

        # Per-handshake state
        self._noise: Optional[NoiseConnection] = None
        self._c64_sender_idx: Optional[int] = None   # C64's sender_idx from Type 1
        self._my_sender_idx:  int = int.from_bytes(os.urandom(4), "little")
        self._send_counter:   int = 0

        self.handshake_complete = False

    # ── public API ────────────────────────────────────────────────────────

    def handle_initiation(self, packet: bytes) -> bytes:
        """Process a 148-byte Type-1 packet and return a 92-byte Type-2 packet.

        Raises ValueError on any parsing or cryptographic failure.
        """
        if len(packet) != T1_TOTAL:
            raise ValueError(f"Type 1 must be {T1_TOTAL} bytes, got {len(packet)}")
        if packet[0] != MSG_TYPE_INITIATION:
            raise ValueError(f"Not a Type-1 packet (byte0=0x{packet[0]:02x})")
        if packet[1:4] != b"\x00\x00\x00":
            raise ValueError("Reserved bytes not zero in Type 1")

        # Verify MAC1 (keyed on our static public key)
        body_up_to_mac1 = packet[:T1_OFF_MAC1]
        expected_mac1   = _compute_mac1(body_up_to_mac1, self._mac1_key_for_t1)
        actual_mac1     = packet[T1_OFF_MAC1 : T1_OFF_MAC1 + 16]
        if expected_mac1 != actual_mac1:
            raise ValueError(
                f"Type-1 MAC1 mismatch: expected={expected_mac1.hex()} "
                f"actual={actual_mac1.hex()}"
            )

        self._c64_sender_idx = struct.unpack_from("<I", packet, T1_OFF_SENDER)[0]
        noise_payload = packet[T1_OFF_NOISE : T1_OFF_MAC1]   # 108 bytes

        # (Re-)initialise Noise responder for this handshake
        self._noise = NoiseConnection.from_name(CONSTRUCTION)
        self._noise.set_prologue(IDENTIFIER)
        self._noise.set_psks(psk=self._psk)
        self._noise.set_keypair_from_private_bytes(Keypair.STATIC, self._static_priv)
        self._noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, self._peer_static_pub)
        self._noise.set_as_responder()
        self._noise.start_handshake()

        # Consume Type-1 noise payload; returns the decrypted timestamp
        self._noise.read_message(noise_payload)

        # Produce Type-2 noise payload (empty application payload → 48 bytes)
        noise_msg2 = bytes(self._noise.write_message(b""))

        self.handshake_complete = True
        self._send_counter = 0

        return self._build_type2(noise_msg2)

    def decrypt_transport(self, packet: bytes) -> bytes:
        """Decrypt a Type-4 transport packet; return plaintext bytes."""
        if not self.handshake_complete or self._noise is None:
            raise RuntimeError("Handshake not complete yet")
        if len(packet) < T4_HDR_LEN + 16:
            raise ValueError(f"Type-4 packet too short ({len(packet)} bytes)")
        if packet[0] != MSG_TYPE_TRANSPORT:
            raise ValueError(f"Not a Type-4 packet (byte0=0x{packet[0]:02x})")
        ciphertext = packet[T4_HDR_LEN:]
        return bytes(self._noise.decrypt(bytes(ciphertext)))

    def encrypt_transport(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* and return a Type-4 transport packet addressed to C64."""
        if not self.handshake_complete or self._noise is None:
            raise RuntimeError("Handshake not complete yet")
        ciphertext = bytes(self._noise.encrypt(plaintext))
        receiver_idx = self._c64_sender_idx or 0
        counter      = self._send_counter
        self._send_counter += 1
        hdr = (
            bytes([MSG_TYPE_TRANSPORT, 0, 0, 0])
            + struct.pack("<I", receiver_idx)
            + struct.pack("<Q", counter)
        )
        return hdr + ciphertext

    # ── internal helpers ──────────────────────────────────────────────────

    def _build_type2(self, noise_msg2: bytes) -> bytes:
        """Wrap *noise_msg2* in a WireGuard Type-2 wire packet (92 bytes)."""
        hdr = (
            bytes([MSG_TYPE_RESPONSE, 0, 0, 0])
            + struct.pack("<I", self._my_sender_idx)
            + struct.pack("<I", self._c64_sender_idx or 0)
        )
        body_up_to_mac1 = hdr + noise_msg2         # 12 + 48 = 60 bytes
        mac1 = _compute_mac1(body_up_to_mac1, self._mac1_key_for_t2)
        mac2 = bytes(16)                           # no cookie active
        pkt  = body_up_to_mac1 + mac1 + mac2       # 60+16+16 = 92 bytes
        assert len(pkt) == T2_TOTAL, f"BUG: built {len(pkt)}-byte Type 2, expected {T2_TOTAL}"
        return pkt
