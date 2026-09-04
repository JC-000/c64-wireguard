#!/usr/bin/env python3
"""wg_chat.py — hold a conversation with the C64 over the WireGuard tunnel.

    /opt/homebrew/bin/python3.13 tools/wg_chat.py --host 192.168.2.81

Type a line here and it appears on the C64's screen; press M on the C64 and
what you type there appears here. ``/quit`` ends the session.

WHAT THIS IS: a thin front end over test_uci_handshake_live.py's --chat mode,
which already does the whole job — build, upload, stage the config, drive
do_handshake to SESSION_ACTIVE, hand the machine back to its own main loop,
then relay. This file exists because that name and its flag matrix describe a
regression test, not a thing you sit in front of, and because two of its
defaults are wrong for interactive use:

  * TURBO. The test defaults to 1 MHz, where the handshake costs ~21.7 min
    before you can type a word. At 48 MHz it is ~90 s. Chat is not a
    measurement, so there is no reason to pay the 1 MHz price here.

  * RESTORING IT. The test sets turbo and leaves it set. The U64E is shared
    with other sessions, and a machine found at a stale 48 MHz has already
    cost this project an afternoon, so we put it back on the way out —
    including on Ctrl-C, which is how an interactive session normally ends.

WHY --host HAS NO DEFAULT: the device's address moves with the user. The
in-repo tools still default to the home LAN address, which is wrong whenever
the machine is travelling, and a wrong default fails as "unreachable" rather
than as "you forgot the flag". Pass it, or set U64_HOST.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import wg_c64_input                                          # noqa: E402
from c64_caps import C64_TUNNEL_MTU                          # noqa: E402

CHAT_TURBO_MHZ = 48
IDLE_TURBO_MHZ = 1

# Rekey before WireGuard's 180 s REJECT_AFTER_TIME strands us. The firmware
# raises rekey_pending and prints REKEY NEEDED but nothing consumes the flag,
# so left alone every session dies at 180 s; we drive the H menu entry, which
# re-runs the same do_handshake that brought the session up in the first
# place. ~126 s of compute at 48 MHz, which fits; at 1 MHz it could not.
REKEY_AFTER_S = 140.0


def _restore_speed(host: str) -> None:
    """Put the shared device back to 1 MHz. Never raises.

    Called from a finally, so it must not mask the real exit path: a failure
    to restore is worth a warning, never a traceback that buries whatever
    actually ended the session.
    """
    # Through the harness lock: this is a WRITE to a shared device, and it
    # runs after the locked body has released. An unserialised restore can
    # land inside another lane's run — see tools/device_session.py.
    from device_session import restore_idle
    restore_idle(host, IDLE_TURBO_MHZ)


def build_chat_loop():
    """Interactive chat that keeps itself alive across session expiry.

    Same two directions as the tool's built-in _chat_loop — type here to
    print on the C64, press M there to send back — plus a watchdog that
    re-establishes the session before it times out.

    Sends are refused while a rekey is in flight rather than silently
    dropped: the C64 is single-threaded and spends those ~126 s inside a
    scalarmult, so it is not polling the network and anything sent then is
    genuinely gone. Saying so beats letting someone type into a void.
    """
    from test_uci_handshake_live import (
        SESSION_ACTIVE, ascii_to_petscii, petscii_to_ascii,
        strip_tunnel_headers,
    )

    def chat_loop(tr, L, rt, responder) -> int:
        wg_state = L["wg_state"]
        stop = threading.Event()
        rekeying = threading.Event()
        lock = threading.Lock()

        def sender() -> None:
            print("-- type to send to the C64; press M on the C64 to send "
                  "back; /quit to exit --", flush=True)
            for line in sys.stdin:
                line = line.rstrip("\n")
                if line in ("/quit", "/q"):
                    stop.set()
                    return
                if not line:
                    continue
                if rekeying.is_set():
                    print("!! rekeying — the C64 is computing and not "
                          "listening; try again shortly", flush=True)
                    continue
                payload = ascii_to_petscii(line)
                if len(payload) > C64_TUNNEL_MTU:
                    print(f"!! truncated to {C64_TUNNEL_MTU}B (C64 tunnel "
                          f"MTU, derived from src/net/uci/net_caps.inc)",
                          flush=True)
                    payload = payload[:C64_TUNNEL_MTU]
                try:
                    with lock:
                        pkt = responder.encrypt_transport(payload)
                    rt.send_raw(pkt)
                    print(f"you> {line}", flush=True)
                except Exception as exc:                      # noqa: BLE001
                    print(f"!! send failed: {type(exc).__name__}: {exc}",
                          flush=True)

        threading.Thread(target=sender, daemon=True,
                         name="chat-stdin").start()

        session_started = time.monotonic()
        while not stop.is_set():
            time.sleep(0.2)

            for raw in rt.drain_type4():
                text = petscii_to_ascii(strip_tunnel_headers(raw)).rstrip()
                if text:
                    print(f"c64> {text}", flush=True)

            age = time.monotonic() - session_started
            state = tr.read_memory(wg_state, 1)[0]
            if state == SESSION_ACTIVE and age <= REKEY_AFTER_S:
                continue

            why = ("expired" if state != SESSION_ACTIVE
                   else f"{age:.0f}s old")
            print(f"-- rekeying ({why}); ~2 min at 48 MHz, hold on --",
                  flush=True)
            rekeying.set()
            try:
                ok = wg_c64_input.rekey(tr, wg_state, SESSION_ACTIVE)
            finally:
                rekeying.clear()
            if not ok:
                print("!! rekey failed — wg_state never reached ACTIVE",
                      flush=True)
                return 1
            session_started = time.monotonic()
            print("-- rekeyed; carry on --", flush=True)

        return 0

    return chat_loop


def main() -> int:
    argv = sys.argv[1:]

    host = None
    passthrough: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
            i += 2
            continue
        if argv[i].startswith("--host="):
            host = argv[i].split("=", 1)[1]
            i += 1
            continue
        passthrough.append(argv[i])
        i += 1

    host = host or os.environ.get("U64_HOST")
    if not host:
        print(__doc__.strip(), file=sys.stderr)
        print("\nERROR: no device address. Pass --host <ip> or set U64_HOST.",
              file=sys.stderr)
        return 2

    # The underlying tool refuses to run without this gate, and rightly:
    # it reboots the machine and rewrites its memory. Chat cannot do its job
    # without both, so consent is implicit in running this file at all —
    # but say so rather than setting it silently.
    if os.environ.get("U64_ALLOW_MUTATE") != "1":
        print("-- this reboots the C64 and writes its memory; proceeding --",
              file=sys.stderr)
        os.environ["U64_ALLOW_MUTATE"] = "1"

    print(f"-- connecting to {host}; handshake takes ~90 s at "
          f"{CHAT_TURBO_MHZ} MHz, then you can type --", file=sys.stderr)

    sys.argv = [
        "test_uci_handshake_live.py",
        "--chat",
        "--host", host,
        "--turbo", str(CHAT_TURBO_MHZ),
        *passthrough,
    ]

    import test_uci_handshake_live as live
    live.post_session_hook = build_chat_loop()
    try:
        return live.main()
    except KeyboardInterrupt:
        print("\n-- interrupted --", file=sys.stderr)
        return 0
    finally:
        _restore_speed(host)


if __name__ == "__main__":
    sys.exit(main())
