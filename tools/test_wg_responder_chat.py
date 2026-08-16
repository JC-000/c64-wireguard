#!/usr/bin/env python3
"""Loopback test for server.py's interactive chat mode — no U64E required.

Runs the real `python -m tools.wg_responder.server --interactive` as a
subprocess, drives a full Noise handshake at it from a pure-Python
"C64" initiator, then checks BOTH directions of the chat:

  C64 -> host   a PETSCII Type-4 arrives and is printed as `c64> ...`
  host -> C64   a line typed on stdin arrives as a Type-4 the initiator
                can decrypt, and decodes back to the text typed

Why a subprocess rather than importing run_server(): the thing under test
is the wiring — the stdin thread, the lock around the send counter, the
PETSCII conversion at both edges and the stdout/stderr split. Importing
the functions would test the parts while skipping the assembly, which is
where the bugs in this change would live.

Run::

    /opt/homebrew/opt/python@3.13/bin/python3.13 tools/test_wg_responder_chat.py
"""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from test_wg_responder_loopback import build_type1  # noqa: E402
from wg_responder.keys import generate_keypair      # noqa: E402
from wg_responder.responder import MSG_TYPE_TRANSPORT  # noqa: E402

T4_HDR_LEN = 16
PORT = 51899


def _read_until(proc, needle, timeout=15.0):
    """Collect proc stdout until *needle* appears. Returns (found, text)."""
    out = []
    deadline = time.monotonic() + timeout
    os.set_blocking(proc.stdout.fileno(), False)
    while time.monotonic() < deadline:
        try:
            chunk = proc.stdout.read()
        except Exception:
            chunk = None
        if chunk:
            out.append(chunk)
            if needle in "".join(out):
                return True, "".join(out)
        time.sleep(0.05)
    return False, "".join(out)


def main() -> int:
    priv_hex, pub_hex = generate_keypair()          # responder (host)
    c64_priv_hex, c64_pub_hex = generate_keypair()  # initiator ("C64")
    psk = bytes(32)

    proc = subprocess.Popen(
        [sys.executable, "-m", "tools.wg_responder.server",
         "--listen", f"127.0.0.1:{PORT}",
         "--priv", priv_hex, "--peer-pub", c64_pub_hex,
         "--psk", psk.hex(), "--interactive"],
        cwd=str(PROJECT_ROOT),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    failures = []
    try:
        time.sleep(1.5)  # let it bind

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(15.0)
        sock.bind(("127.0.0.1", 0))

        # ── handshake ────────────────────────────────────────────────────
        type1, noise = build_type1(
            bytes.fromhex(c64_priv_hex), bytes.fromhex(c64_pub_hex),
            bytes.fromhex(pub_hex), psk, 0x11223344,
        )
        sock.sendto(type1, ("127.0.0.1", PORT))
        type2, _ = sock.recvfrom(65535)
        if len(type2) != 92:
            failures.append(f"Type-2 was {len(type2)} bytes, expected 92")
        noise.read_message(bytes(type2[12:60]))
        ok, text = _read_until(proc, "session up with")
        print(f"  {'PASS' if ok else 'FAIL'}: server announces the session")
        if not ok:
            failures.append("no 'session up' announcement")

        # ── C64 -> host ──────────────────────────────────────────────────
        # "HELLO FROM C64" in PETSCII, which for unshifted letters is the
        # same codes as ASCII uppercase.
        msg_up = b"HELLO FROM C64"
        ct = noise.encrypt(msg_up)
        hdr = (bytes([MSG_TYPE_TRANSPORT, 0, 0, 0])
               + struct.pack("<I", 0) + struct.pack("<Q", 0))
        sock.sendto(hdr + ct, ("127.0.0.1", PORT))
        ok, text = _read_until(proc, "c64> HELLO FROM C64")
        print(f"  {'PASS' if ok else 'FAIL'}: inbound printed as chat line")
        if not ok:
            failures.append(f"inbound not shown; saw: {text[-300:]!r}")

        # ── host -> C64, twice, to exercise the send counter ─────────────
        for n, typed in enumerate(("hello c64", "second message")):
            proc.stdin.write(typed + "\n")
            proc.stdin.flush()
            data, _ = sock.recvfrom(65535)
            if data[0] != MSG_TYPE_TRANSPORT:
                failures.append(f"expected Type-4, got 0x{data[0]:02x}")
                continue
            counter = struct.unpack_from("<Q", data, 8)[0]
            plain = bytes(noise.decrypt(bytes(data[T4_HDR_LEN:])))
            # server upper-cases via PETSCII, which is what the C64 shows
            expect = typed.upper().encode()
            good = plain == expect and counter == n
            print(f"  {'PASS' if good else 'FAIL'}: outbound #{n} "
                  f"counter={counter} plaintext={plain!r}")
            if not good:
                failures.append(
                    f"msg {n}: got {plain!r} counter={counter}, "
                    f"expected {expect!r} counter={n}")

        # ── oversize is truncated, not fatal ─────────────────────────────
        proc.stdin.write("X" * 400 + "\n")
        proc.stdin.flush()
        data, _ = sock.recvfrom(65535)
        plain = bytes(noise.decrypt(bytes(data[T4_HDR_LEN:])))
        good = len(plain) == 240
        print(f"  {'PASS' if good else 'FAIL'}: oversize truncated to "
              f"{len(plain)}B (cap 240, SOCKET_READ limit #46)")
        if not good:
            failures.append(f"oversize gave {len(plain)}B, expected 240")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAIL — {len(failures)} problem(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS — interactive chat works both ways in loopback")
    return 0


if __name__ == "__main__":
    sys.exit(main())
