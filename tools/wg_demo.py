#!/usr/bin/env python3
"""wg_demo.py — an unattended two-way conversation over the tunnel, at 48 MHz.

    /opt/homebrew/bin/python3.13 tools/wg_demo.py --host 192.168.2.81

Brings the tunnel up, then runs a scripted dialogue in which BOTH ends
actually speak: this host encrypts its lines and sends them, and the C64's
replies are typed into its real keyboard queue from here, so they travel
through do_message_input -> udp_tunnel_build -> transport_send exactly as if
someone were sitting at the machine. Nothing is faked on either side; the
only shortcut is who presses the keys.

It rekeys itself, so it runs until you stop it. rekey_pending has no consumer
in the firmware — timer.s raises the flag and prints REKEY NEEDED, and nothing
ever acts on it — so a session dies at 180 s. We drive the H menu entry
instead, which re-runs the proven do_handshake path.

WHY 48 MHz IS NOT OPTIONAL HERE: a handshake is ~90 s of Type-1 plus ~36 s to
process the Type-2 at 48 MHz, which fits inside WireGuard's 180 s session
lifetime with room to spare. At 1 MHz the same handshake is ~21.7 minutes,
about 7x the entire lifetime of the session it is meant to replace, so a
self-sustaining chat is arithmetically impossible at stock speed. The demo
therefore refuses to run below turbo rather than appearing to hang.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import wg_c64_input                                          # noqa: E402

CHAT_TURBO_MHZ = 48
IDLE_TURBO_MHZ = 1

# WireGuard's own REJECT_AFTER_TIME. timer.s enforces it as 10800 jiffies off
# the 60 Hz KERNAL clock, which is wall time and therefore unaffected by turbo.
SESSION_LIFETIME_S = 180.0

# Start a replacement session this far in. A rekey costs ~126 s of compute
# during which the C64 is heads-down and answers nothing, so going early
# wastes usable session; going late risks expiring mid-sentence. 140 s leaves
# 40 s of slack for a turn already in flight.
REKEY_AFTER_S = 140.0

TURN_PAUSE_S = 4.0      # slow enough to read on the C64's screen

# Both ends are writing to a 40-column display, and display_payload prefixes
# inbound text with "RECV: ". read_input_line also stops storing at 40
# characters, so keep every line comfortably under both limits.
DIALOGUE: list[tuple[str, str]] = [
    ("C64",  "1 MHZ. 64K OF RAM. NO CRYPTO UNIT."),
    ("HOST", "AND YET YOU SPEAK WIREGUARD."),
    ("C64",  "X25519 IN 6502. 90 SECONDS."),
    ("HOST", "MY LAPTOP DOES IT IN 40 MICROSEC."),
    ("C64",  "YOU HAVE 8 BILLION TRANSISTORS."),
    ("HOST", "YOU HAVE ABOUT 3500."),
    ("C64",  "EVERY ONE OF THEM EARNS ITS KEEP."),
    ("HOST", "CHACHA20-POLY1305 ON A BREADBIN."),
    ("C64",  "SAY BREADBIN ONE MORE TIME."),
    ("HOST", "APOLOGIES. ON A LEGEND."),
    ("C64",  "MY KEYS NEVER LEFT THIS MACHINE."),
    ("HOST", "NOISE IKPSK2. BY THE BOOK."),
    ("C64",  "NO SECURE ENCLAVE. JUST RAM."),
    ("HOST", "AND A 6502 THAT REFUSES TO QUIT."),
    ("C64",  "40 COLUMNS IS ENOUGH FOR ANYONE."),
    ("HOST", "SHALL WE REKEY AND GO AGAIN?"),
    ("C64",  "I HAVE ALL THE TIME IN THE WORLD."),
]


def _say(msg: str) -> None:
    print(msg, flush=True)


def _drain(rt, petscii_to_ascii, strip_tunnel_headers) -> None:
    """Print anything the C64 has said since we last looked.

    Keepalives are 0-byte Type-4s and decode to nothing, so they fall out
    here naturally rather than needing a special case.
    """
    for raw in rt.drain_type4():
        text = petscii_to_ascii(strip_tunnel_headers(raw)).rstrip()
        if text:
            _say(f"  C64 > {text}")


def build_demo_loop():
    """Return a _chat_loop-compatible callable running the dialogue."""

    from test_uci_handshake_live import (
        SESSION_ACTIVE, ascii_to_petscii, petscii_to_ascii,
        strip_tunnel_headers,
    )

    def demo_loop(tr, L, rt, responder) -> int:
        wg_state = L["wg_state"]
        session_started = time.monotonic()
        turn = 0

        _say("")
        _say("=" * 52)
        _say("  tunnel up — starting dialogue (Ctrl-C to stop)")
        _say("=" * 52)

        try:
            while True:
                age = time.monotonic() - session_started
                state = tr.read_memory(wg_state, 1)[0]

                if state != SESSION_ACTIVE or age > REKEY_AFTER_S:
                    why = ("session expired" if state != SESSION_ACTIVE
                           else f"session {age:.0f}s old, "
                                f"expires at {SESSION_LIFETIME_S:.0f}s")
                    _say("")
                    _say(f"-- REKEY ({why}) — the C64 is computing a fresh "
                         f"handshake,")
                    _say("   ~2 min at 48 MHz. It answers nothing until it "
                         "lands. --")
                    t0 = time.monotonic()
                    if not wg_c64_input.rekey(tr, wg_state, SESSION_ACTIVE):
                        _say("!! rekey failed — wg_state never reached ACTIVE")
                        return 1
                    session_started = time.monotonic()
                    _say(f"-- rekeyed in {session_started - t0:.0f}s; "
                         f"conversation resumes --")
                    _say("")
                    continue

                speaker, line = DIALOGUE[turn % len(DIALOGUE)]
                turn += 1

                if speaker == "HOST":
                    rt.send_raw(responder.encrypt_transport(
                        ascii_to_petscii(line)))
                    _say(f"  HOST> {line}")
                else:
                    # Typed into the C64's real keyboard queue: it goes out
                    # through do_message_input, so what comes back to us is a
                    # genuine tunnelled packet, IPv4+UDP headers and all.
                    if not wg_c64_input.send_message(tr, line):
                        _say("!! the C64 did not consume the keystrokes "
                             "(busy or wedged)")
                        return 1

                time.sleep(TURN_PAUSE_S)
                _drain(rt, petscii_to_ascii, strip_tunnel_headers)

        except KeyboardInterrupt:
            _say("\n-- stopped --")
            return 0

    return demo_loop


def _restore_speed(host: str) -> None:
    """Put the shared device back to 1 MHz. Never raises."""
    try:
        from c64_test_harness.backends.ultimate64_client import Ultimate64Client
        from c64_test_harness.backends.ultimate64_helpers import (
            get_turbo_mhz, set_turbo_mhz,
        )
        client = Ultimate64Client(host)
        if get_turbo_mhz(client) != IDLE_TURBO_MHZ:
            set_turbo_mhz(client, IDLE_TURBO_MHZ)
            print(f"-- device restored to {IDLE_TURBO_MHZ} MHz --",
                  file=sys.stderr, flush=True)
    except Exception as exc:                                  # noqa: BLE001
        print(f"!! could not restore {IDLE_TURBO_MHZ} MHz on {host}: "
              f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)


def main() -> int:
    argv = sys.argv[1:]
    host = None
    passthrough: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--host" and i + 1 < len(argv):
            host, i = argv[i + 1], i + 2
            continue
        if argv[i].startswith("--host="):
            host, i = argv[i].split("=", 1)[1], i + 1
            continue
        passthrough.append(argv[i])
        i += 1

    host = host or os.environ.get("U64_HOST")
    if not host:
        print("ERROR: no device address. Pass --host <ip> or set U64_HOST.",
              file=sys.stderr)
        return 2

    os.environ.setdefault("U64_ALLOW_MUTATE", "1")

    import test_uci_handshake_live as live
    live.post_session_hook = build_demo_loop()

    sys.argv = [
        "test_uci_handshake_live.py",
        "--chat",                       # reaches the post-session hook
        "--host", host,
        "--turbo", str(CHAT_TURBO_MHZ),
        *passthrough,
    ]
    try:
        return live.main()
    except KeyboardInterrupt:
        return 0
    finally:
        _restore_speed(host)


if __name__ == "__main__":
    sys.exit(main())
