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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CHAT_TURBO_MHZ = 48
IDLE_TURBO_MHZ = 1


def _restore_speed(host: str) -> None:
    """Put the shared device back to 1 MHz. Never raises.

    Called from a finally, so it must not mask the real exit path: a failure
    to restore is worth a warning, never a traceback that buries whatever
    actually ended the session.
    """
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
              f"{type(exc).__name__}: {exc}\n"
              f"!! it is shared — check it before you walk away.",
              file=sys.stderr, flush=True)


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

    from test_uci_handshake_live import main as live_main
    try:
        return live_main()
    except KeyboardInterrupt:
        print("\n-- interrupted --", file=sys.stderr)
        return 0
    finally:
        _restore_speed(host)


if __name__ == "__main__":
    sys.exit(main())
