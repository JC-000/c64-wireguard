#!/usr/bin/env python3
"""Patient WireGuard UDP responder — waits forever for the C64.

Usage::

    /opt/homebrew/bin/python3.13 -m tools.wg_responder.server \\
        --listen 0.0.0.0:51820 \\
        --priv <hex32> \\
        --peer-pub <hex32> \\
        [--psk <hex32>]

The peer address is *learned* from the first valid Type-1 packet; no
``--peer-addr`` flag is required.  All logging goes to stderr with timestamps.
"""
from __future__ import annotations

import argparse
import datetime
import socket
import struct
import sys

from .responder import (
    MSG_TYPE_INITIATION,
    MSG_TYPE_RESPONSE,
    MSG_TYPE_TRANSPORT,
    WireGuardResponder,
)


# ── logging helper ────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def _log(msg: str) -> None:
    print(f"[{_ts()}] {msg}", file=sys.stderr, flush=True)


def _hexdump32(data: bytes) -> str:
    return data[:32].hex(" ")


def _decode_type(data: bytes) -> str:
    if not data:
        return "empty"
    t = data[0]
    if t == MSG_TYPE_INITIATION:
        if len(data) >= 8:
            sender = struct.unpack_from("<I", data, 4)[0]
            return f"Type1/initiation sender_idx=0x{sender:08x} len={len(data)}"
        return f"Type1/initiation len={len(data)}"
    if t == MSG_TYPE_RESPONSE:
        if len(data) >= 12:
            sender   = struct.unpack_from("<I", data, 4)[0]
            receiver = struct.unpack_from("<I", data, 8)[0]
            return (
                f"Type2/response sender_idx=0x{sender:08x} "
                f"receiver_idx=0x{receiver:08x} len={len(data)}"
            )
        return f"Type2/response len={len(data)}"
    if t == MSG_TYPE_TRANSPORT:
        if len(data) >= 16:
            receiver = struct.unpack_from("<I", data, 4)[0]
            counter  = struct.unpack_from("<Q", data, 8)[0]
            return (
                f"Type4/transport receiver_idx=0x{receiver:08x} "
                f"counter={counter} len={len(data)}"
            )
        return f"Type4/transport len={len(data)}"
    return f"unknown type=0x{t:02x} len={len(data)}"


# ── main server loop ──────────────────────────────────────────────────────

def run_server(
    listen_addr: str,
    listen_port: int,
    responder: WireGuardResponder,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, listen_port))
    _log(f"STATE listening on {listen_addr}:{listen_port} (no timeout — waiting for C64)")

    peer_addr: tuple[str, int] | None = None
    state = "WAIT_TYPE1"

    while True:
        data, addr = sock.recvfrom(65535)
        _log(f"RECV from {addr[0]}:{addr[1]} — {_decode_type(data)}")
        _log(f"  hex: {_hexdump32(data)}")

        if not data:
            continue

        pkt_type = data[0]

        if pkt_type == MSG_TYPE_INITIATION:
            if state != "WAIT_TYPE1":
                _log("WARNING: received Type1 while not in WAIT_TYPE1 — re-handshaking")
            peer_addr = addr
            _log(f"STATE learned peer address: {peer_addr[0]}:{peer_addr[1]}")
            try:
                response = responder.handle_initiation(data)
            except ValueError as exc:
                _log(f"ERROR processing Type1: {exc}")
                continue
            _log(f"SEND to {peer_addr[0]}:{peer_addr[1]} — {_decode_type(response)}")
            _log(f"  hex: {_hexdump32(response)}")
            sock.sendto(response, peer_addr)
            state = "ACTIVE"
            _log("STATE → ACTIVE (handshake complete)")

        elif pkt_type == MSG_TYPE_TRANSPORT:
            if state != "ACTIVE":
                _log("WARNING: received Type4 before handshake complete — ignoring")
                continue
            try:
                plaintext = responder.decrypt_transport(data)
                _log(f"TYPE4 decrypted {len(plaintext)} bytes plaintext: {plaintext[:64]!r}")
            except Exception as exc:
                _log(f"ERROR decrypting Type4: {exc}")

        else:
            _log(f"IGNORED unhandled packet type 0x{pkt_type:02x}")


# ── CLI entry point ───────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patient WireGuard responder — no timeouts, waits for C64."
    )
    parser.add_argument("--listen", default="0.0.0.0:51820",
                        help="host:port to listen on (default: 0.0.0.0:51820)")
    parser.add_argument("--priv", required=True,
                        help="Responder static private key (32 bytes hex)")
    parser.add_argument("--peer-pub", required=True,
                        help="Peer (C64) static public key (32 bytes hex)")
    parser.add_argument("--psk", default=None,
                        help="Pre-shared key (32 bytes hex, optional)")
    args = parser.parse_args()

    host, _, port_str = args.listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_str)

    priv_bytes     = bytes.fromhex(args.priv)
    peer_pub_bytes = bytes.fromhex(args.peer_pub)
    psk_bytes      = bytes.fromhex(args.psk) if args.psk else None

    responder = WireGuardResponder(priv_bytes, peer_pub_bytes, psk_bytes)
    run_server(host, port, responder)


if __name__ == "__main__":
    main()
