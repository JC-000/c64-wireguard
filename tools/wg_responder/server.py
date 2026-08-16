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
import threading

from c64_test_harness.encoding import char_to_petscii

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


def _say(msg: str) -> None:
    """Chat output on stdout, so it survives `2>/dev/null` and pipes cleanly.

    Diagnostics stay on stderr via _log(); the conversation is the product.
    """
    print(msg, flush=True)


# ── PETSCII <-> ASCII ─────────────────────────────────────────────────────
#
# The C64 end of this tunnel is a keyboard and a screen, not a byte pipe.
# do_message_input captures PETSCII from GETIN, and display_payload passes
# bytes to CHROUT, which interprets PETSCII. Sending raw ASCII mostly works
# by accident (the two agree on $20-$5E) and then produces mojibake the
# moment anyone types a lowercase letter, because unshifted PETSCII letters
# live at $41-$5A and display as UPPERCASE.

def ascii_to_petscii(text: str) -> bytes:
    """Encode a typed line for the C64.

    Uses the harness's char_to_petscii where it has a mapping, which folds
    case the way the default charset expects. Unmappable characters become
    '.' rather than raising: a chat client that dies on a stray emoji is
    worse than one that drops it.
    """
    out = bytearray()
    for ch in text:
        try:
            out.append(char_to_petscii(ch))
        except (ValueError, KeyError):
            out.append(ord("."))
    return bytes(out)


def petscii_to_ascii(data: bytes) -> str:
    """Decode what the C64 sent into something readable in a terminal.

    display_payload's own filter is the model: printable range through,
    everything else a dot. $C1-$DA is the shifted-letter block, which maps
    onto A-Z.
    """
    out = []
    for b in data:
        if 0x20 <= b <= 0x5E:
            out.append(chr(b))
        elif 0xC1 <= b <= 0xDA:
            out.append(chr(b - 0x80))
        elif b in (0x0D, 0x0A):
            out.append(" ")
        else:
            out.append(".")
    return "".join(out)


def strip_tunnel_headers(plaintext: bytes) -> bytes:
    """Return the user-visible payload from a decrypted Type-4 plaintext.

    The C64 has TWO send paths and they do not agree on framing:

      do_send_test    raw text. Measured on hardware: 15 bytes,
                      48454c4c4f20574952454755415244 = "HELLO WIREGUARD".
      do_message_input (the M=MSG menu entry, i.e. what a person actually
                      types) calls udp_tunnel_build first, so the plaintext
                      is 20 bytes of IPv4 + 8 of UDP + the text.

    Printing the second one raw shows the header as 28 leading dots and
    hides nothing useful, so detect and strip it: IPv4 version nibble 4,
    protocol 17 (UDP), and a total-length field consistent with what
    arrived. Anything else is passed through untouched — a wrong guess
    here would eat 28 bytes of somebody's message.
    """
    if len(plaintext) >= 28 and (plaintext[0] >> 4) == 4 and plaintext[9] == 17:
        total_len = int.from_bytes(plaintext[2:4], "big")
        if total_len == len(plaintext):
            return plaintext[28:]
    return plaintext


# The C64's inbound path is the binding constraint, not the 1500-byte
# tp_packet buffer: the Ultimate's SOCKET_READ truncates above 512 bytes
# silently (issue #46). Stay well under it — 16 bytes of Type-4 header and
# 16 of Poly1305 tag ride along with the plaintext.
MAX_CHAT_PAYLOAD = 240


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


# ── shared session state ──────────────────────────────────────────────────

class _Session:
    """Socket + responder + learned peer, shared between the two threads.

    The lock is not decorative. responder.encrypt_transport() MUTATES the
    send counter and the underlying noise CipherState nonce, and the C64
    validates that counter against its replay window. Two encrypts racing
    would interleave nonces and desynchronise the stream — a bug that would
    surface as sporadic decrypt failures on the C64 rather than anything
    obviously threading-shaped.
    """

    def __init__(self, sock: socket.socket, responder: WireGuardResponder):
        self.sock = sock
        self.responder = responder
        self.peer_addr: tuple[str, int] | None = None
        self.active = False
        self.lock = threading.Lock()
        self.sent = 0

    def send_text(self, text: str) -> bool:
        payload = ascii_to_petscii(text)
        if len(payload) > MAX_CHAT_PAYLOAD:
            _say(f"!! message truncated to {MAX_CHAT_PAYLOAD} bytes "
                 f"(was {len(payload)}) — the Ultimate's SOCKET_READ "
                 f"silently truncates above 512 (#46)")
            payload = payload[:MAX_CHAT_PAYLOAD]
        with self.lock:
            if not self.active or self.peer_addr is None:
                _say("!! no session yet — waiting for the C64's handshake. "
                     "At 1 MHz that is ~13 min; at 48 MHz with REU=0, ~30 s.")
                return False
            try:
                pkt = self.responder.encrypt_transport(payload)
                self.sock.sendto(pkt, self.peer_addr)
                self.sent += 1
            except Exception as exc:
                _log(f"ERROR sending Type4: {type(exc).__name__}: {exc}")
                return False
        _log(f"SEND Type4 {len(pkt)}B to {self.peer_addr[0]}:{self.peer_addr[1]} "
             f"(msg #{self.sent}, {len(payload)}B plaintext)")
        return True


def _stdin_loop(session: _Session) -> None:
    """Read typed lines and push them down the tunnel.

    Runs as a daemon so Ctrl-C in the recv loop tears the whole thing down
    without needing to interrupt a blocking readline.
    """
    _say("-- type a message and press enter to send to the C64; "
         "/quit to exit --")
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line in ("/quit", "/q"):
            _say("-- closing --")
            import os
            os._exit(0)
        if not line:
            continue
        if session.send_text(line):
            _say(f"you> {line}")


# ── main server loop ──────────────────────────────────────────────────────

def run_server(
    listen_addr: str,
    listen_port: int,
    responder: WireGuardResponder,
    interactive: bool = False,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, listen_port))
    _log(f"STATE listening on {listen_addr}:{listen_port} (no timeout — waiting for C64)")

    session = _Session(sock, responder)
    if interactive:
        threading.Thread(target=_stdin_loop, args=(session,),
                         daemon=True, name="stdin").start()

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
            with session.lock:
                session.peer_addr = peer_addr
                session.active = True
            if interactive:
                _say(f"-- session up with {peer_addr[0]} — you can type now --")

        elif pkt_type == MSG_TYPE_TRANSPORT:
            if state != "ACTIVE":
                _log("WARNING: received Type4 before handshake complete — ignoring")
                continue
            try:
                plaintext = responder.decrypt_transport(data)
                _log(f"TYPE4 decrypted {len(plaintext)} bytes plaintext: {plaintext[:64]!r}")
                if interactive:
                    text = petscii_to_ascii(strip_tunnel_headers(plaintext)).rstrip()
                    if text:
                        _say(f"c64> {text}")
            except Exception as exc:
                _log(f"ERROR decrypting Type4: {type(exc).__name__}: {exc}")

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
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Two-way chat: print decrypted C64 messages and "
                             "send typed lines back over the tunnel. Without "
                             "it the server stays receive-only, which is what "
                             "the handshake tests expect.")
    args = parser.parse_args()

    host, _, port_str = args.listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_str)

    priv_bytes     = bytes.fromhex(args.priv)
    peer_pub_bytes = bytes.fromhex(args.peer_pub)
    psk_bytes      = bytes.fromhex(args.psk) if args.psk else None

    responder = WireGuardResponder(priv_bytes, peer_pub_bytes, psk_bytes)
    run_server(host, port, responder, interactive=args.interactive)


if __name__ == "__main__":
    main()
