#!/usr/bin/env python3
"""Key-generation helpers for wg_responder test setup."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_keypair() -> tuple[str, str]:
    """Return (priv_hex, pub_hex) for a fresh X25519 keypair."""
    priv_key = X25519PrivateKey.generate()
    priv_bytes = priv_key.private_bytes_raw()
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes.hex(), pub_bytes.hex()


def priv_to_pub(priv_hex: str) -> str:
    """Derive the public key hex from a private key hex string."""
    priv_bytes = bytes.fromhex(priv_hex)
    priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pub_bytes.hex()
