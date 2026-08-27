#!/usr/bin/env python3
"""Prove the tunnel actually encrypts, on live hardware.

    U64_ALLOW_MUTATE=1 python3.13 tools/test_wire_encryption_live.py --host <ip>

Until now the evidence that traffic was encrypted was INDIRECT: the host's
noise.decrypt() succeeded, and ChaCha20-Poly1305 only yields plaintext plus a
valid tag to someone holding the session key, so cleartext on the wire would
have thrown instead of decoding. That is real evidence but it is an argument,
not a test — it never asserted that the plaintext is ABSENT from the bytes on
the wire, that repeated plaintext produces different ciphertext, or that
tampering is rejected. This does.

WHY THE RESPONDER SOCKET IS A VALID WIRE TAP: we are the peer. The datagram
handed to decrypt_transport is byte-for-byte what the C64 transmitted, before
any interpretation. No pcap or elevated privileges are needed to inspect the
real thing; a capture would only add visibility of OTHER ports, which matters
for the disclosure below rather than for the encryption claim.

DISCLOSED CONTROL-PLANE LEAK, so nobody reads a PASS here as more than it is:
this test types the C64's line by writing its KERNAL keyboard queue over the
Ultimate's REST/DMA interface, which is plain HTTP. That text therefore does
cross the LAN in the clear on port 80 on its way IN, and the same is true of
the staged private keys in every tool here. That is the test harness's control
plane, not the tunnel. What is asserted below is strictly about the WireGuard
UDP port. A human typing at the C64's own keyboard has no such exposure.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import wg_c64_input                                          # noqa: E402

# Distinct per direction so a hit can never be attributed to the wrong one.
import os as _os

def _sized(marker: str, tail: str) -> str:
    """WIRE_MSG_LEN pads a marker with filler to that many chars (832 =
    MSG_TEXT_MAX drives the full-size tunnel path); unset keeps it short."""
    n = int(_os.environ.get("WIRE_MSG_LEN", "0"))
    if n <= len(marker) + len(tail) + 1:
        return marker
    filler = "ABCDEFGHIJKLMNOPQRSTUVWXY "
    body = (filler * (n // len(filler) + 1))[: n - len(marker) - len(tail) - 2]
    return f"{marker} {body} {tail}"

MARKER_C64 = _sized("ZEBRA QUARTZ ONE TWO THREE", "END ZEBRA")
MARKER_HOST = _sized("QUASAR EIGHT NINE SIXTY", "END QUASAR")
MARKER_TAMPER = "MUTANT PACKET SHOULD NOT APPEAR"

T4_HDR_LEN = 16     # type(1) + reserved(3) + receiver_idx(4) + counter(8)

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((ok, label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail else ""), flush=True)
    return ok


def _screen_text(tr) -> str:
    """Read the C64's screen RAM and decode it to ASCII.

    Screen codes, not PETSCII: 1-26 are A-Z. Used to prove the C64 DECRYPTED
    something, which is the other half of the claim — absence of plaintext on
    the wire is only interesting if the far end still receives the message.
    """
    scr = bytes(tr.read_memory(0x0400, 1000))
    out = []
    for b in scr:
        if b == 32:
            out.append(" ")
        elif 1 <= b <= 26:
            out.append(chr(b + 64))
        elif 33 <= b <= 63:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def build_probe():
    from test_uci_handshake_live import (
        ascii_to_petscii, petscii_to_ascii, strip_tunnel_headers,
    )

    def probe(tr, L, rt, responder) -> int:
        # Tap the raw inbound datagrams. The responder thread calls this on
        # every Type-4, so we see the wire bytes AND what they decrypt to,
        # paired, without touching the thread's logic.
        seen: list[tuple[bytes, bytes]] = []
        original_decrypt = responder.decrypt_transport

        def tapped(pkt):
            plain = original_decrypt(pkt)
            seen.append((bytes(pkt), bytes(plain)))
            return plain

        responder.decrypt_transport = tapped

        print("\n=== 1. C64 -> host: is the plaintext on the wire? ===",
              flush=True)
        if not wg_c64_input.send_message(tr, MARKER_C64):
            return check(False, "C64 accepted the keystrokes") and 1

        marker_bytes = MARKER_C64.encode("ascii")
        pair = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and pair is None:
            time.sleep(0.3)
            for raw, plain in seen:
                shown = petscii_to_ascii(strip_tunnel_headers(plain))
                if MARKER_C64 in shown:
                    pair = (raw, plain, shown)
                    break

        if pair is None:
            check(False, "C64's message arrived at all",
                  f"{len(seen)} Type-4s seen, none containing the marker")
        else:
            raw, plain, shown = pair
            check(marker_bytes not in raw,
                  "marker ABSENT from the datagram on the wire",
                  f"datagram {len(raw)}B, ciphertext starts "
                  f"{raw[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}")
            check(MARKER_C64 in shown,
                  "same datagram DECRYPTS to the marker",
                  f"decrypted: {shown.strip()!r}")
            # The AEAD tag is what makes the decrypt meaningful rather than a
            # guess: ciphertext is plaintext length + 16.
            check(len(raw) == T4_HDR_LEN + len(plain) + 16,
                  "length accounts for a 16-byte Poly1305 tag",
                  f"{len(raw)} == {T4_HDR_LEN} hdr + {len(plain)} plain + 16 tag")

        print("\n=== 2. host -> C64: same question, our direction ===",
              flush=True)
        pkt1 = responder.encrypt_transport(ascii_to_petscii(MARKER_HOST))
        rt.send_raw(pkt1)
        check(MARKER_HOST.encode("ascii") not in pkt1,
              "marker ABSENT from the datagram we transmit",
              f"datagram {len(pkt1)}B, ciphertext starts "
              f"{pkt1[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}")
        time.sleep(4.0)
        check(MARKER_HOST in _screen_text(tr),
              "the C64 DECRYPTED it (text present in its screen RAM)")

        print("\n=== 3. does identical plaintext repeat on the wire? ===",
              flush=True)
        pkt2 = responder.encrypt_transport(ascii_to_petscii(MARKER_HOST))
        rt.send_raw(pkt2)
        check(pkt1[T4_HDR_LEN:] != pkt2[T4_HDR_LEN:],
              "identical plaintext yields DIFFERENT ciphertext",
              "nonce/counter advances, so the stream is not a fixed keystream")
        check(pkt1[8:16] != pkt2[8:16],
              "the counter field advanced",
              f"{int.from_bytes(pkt1[8:16],'little')} -> "
              f"{int.from_bytes(pkt2[8:16],'little')}")
        time.sleep(3.0)

        print("\n=== 4. is the C64 authenticating, or just decrypting? ===",
              flush=True)
        # Flip one ciphertext bit. A cipher without integrity would hand the
        # C64 corrupted plaintext and it would print something; Poly1305 means
        # it must reject the packet outright.
        good = bytearray(responder.encrypt_transport(
            ascii_to_petscii(MARKER_TAMPER)))
        good[T4_HDR_LEN + 4] ^= 0x01
        rt.send_raw(bytes(good))
        time.sleep(4.0)
        check(MARKER_TAMPER not in _screen_text(tr),
              "C64 REJECTED a packet with one flipped ciphertext bit")

        # And prove the rejection did not wedge the session.
        alive = "STILL ALIVE AFTER TAMPER"
        rt.send_raw(responder.encrypt_transport(ascii_to_petscii(alive)))
        time.sleep(4.0)
        check(alive in _screen_text(tr),
              "session still works after the forgery was rejected")

        print("\n=== 5. what IS in the clear, by design ===", flush=True)
        if seen:
            raw = seen[-1][0]
            print(f"  Type-4 header (cleartext by WireGuard's design): "
                  f"{raw[:T4_HDR_LEN].hex(' ')}", flush=True)
            print(f"    type=0x{raw[0]:02x} receiver_idx="
                  f"0x{int.from_bytes(raw[4:8],'little'):08x} "
                  f"counter={int.from_bytes(raw[8:16],'little')}", flush=True)
            print("  Everything after those 16 bytes is ciphertext+tag.",
                  flush=True)

        failed = [label for ok, label in results if not ok]
        print("\n" + "=" * 60, flush=True)
        print(f"{len(results) - len(failed)}/{len(results)} checks passed",
              flush=True)
        for label in failed:
            print(f"  FAILED: {label}", flush=True)
        print("=" * 60, flush=True)
        return 1 if failed else 0

    return probe


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("U64_HOST"))
    p.add_argument("--turbo", type=int, default=48)
    args = p.parse_args()
    if not args.host:
        print("ERROR: pass --host <ip> or set U64_HOST", file=sys.stderr)
        return 2

    os.environ.setdefault("U64_ALLOW_MUTATE", "1")
    import test_uci_handshake_live as live
    live.post_session_hook = build_probe()
    sys.argv = ["test_uci_handshake_live.py", "--chat",
                "--host", args.host, "--turbo", str(args.turbo)]
    try:
        return live.main()
    finally:
        try:
            from c64_test_harness.backends.ultimate64_client import Ultimate64Client
            from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz
            set_turbo_mhz(Ultimate64Client(args.host), 1)
        except Exception:                                     # noqa: BLE001
            pass


if __name__ == "__main__":
    sys.exit(main())
