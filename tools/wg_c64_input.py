#!/usr/bin/env python3
"""Drive the C64's keyboard from the host, over DMA.

WHY THIS EXISTS: once the tunnel is up, test_uci_handshake_live.py hands the
machine back to its own main loop and host-side trampoline control is gone by
design — there is no way left to call a routine on the C64. But main_loop and
read_input_line both take their input from KERNAL getin ($FFE4), which reads
the keyboard BUFFER rather than the hardware matrix. That buffer is ordinary
RAM, and read/write_memory still work after the handoff because they are DMA,
not CPU. So we can type.

That single fact buys two things the C64 cannot do for itself:

  * an unattended demo — press M, type a line, press RETURN, all from here,
    so both ends of the conversation move without a human at the keyboard;
  * REKEY — press H, which re-runs do_handshake. rekey_pending has no
    consumer in the firmware (timer.s sets it, nothing acts on it), so a
    session otherwise dies at 180 s. Driving the existing, proven menu entry
    beats writing new in-session rekey assembly to get a chat that lasts.

BUFFER MECHANICS: the KERNAL queue is 10 bytes at $0277 with its count at $C6
(max from $0289). Write the bytes FIRST and the count LAST — the IRQ keyboard
scan reads the count to decide whether the queue is live, so setting it early
races the scan. Then wait for the count to fall back to 0, which is the C64
telling us it consumed them; it is also the only honest progress signal while
the machine is busy in a 90-second scalarmult and consuming nothing.
"""
from __future__ import annotations

import time

KBD_BUFFER = 0x0277     # KERNAL keyboard queue
KBD_COUNT  = 0x00C6     # number of characters waiting in it
KBD_MAX    = 10         # queue length; $0289 XMAX, never assume more

# read_input_line stops storing at 40 characters and silently drops the rest,
# so a longer line would be truncated on the C64 rather than here, where the
# caller can see it happen.
C64_INPUT_MAX = 40


def _wait_drained(tr, timeout: float = 10.0) -> bool:
    """Block until the C64 has eaten the queue. False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(KBD_COUNT, 1)[0] == 0:
            return True
        time.sleep(0.05)
    return False


def press_key(tr, char: str, timeout: float = 10.0) -> bool:
    """Type a single key, e.g. 'M' or 'H'. Returns False if never consumed."""
    if not _wait_drained(tr, timeout):
        return False
    tr.write_memory(KBD_BUFFER, bytes([ord(char)]))
    tr.write_memory(KBD_COUNT, bytes([1]))
    return _wait_drained(tr, timeout)


def type_text(tr, text: str, timeout: float = 20.0) -> bool:
    """Type a string, ten characters at a time, waiting for each chunk.

    Chunking is not optional: writing more than KBD_MAX bytes would run off
    the end of the queue into $0281+ (the KERNAL's own memory-bottom pointers),
    which is a far more interesting bug than a truncated message.
    """
    payload = text.encode("ascii", errors="replace")
    for i in range(0, len(payload), KBD_MAX):
        chunk = payload[i:i + KBD_MAX]
        if not _wait_drained(tr, timeout):
            return False
        tr.write_memory(KBD_BUFFER, chunk)
        tr.write_memory(KBD_COUNT, bytes([len(chunk)]))
    return _wait_drained(tr, timeout)


def send_message(tr, text: str, timeout: float = 30.0) -> bool:
    """Make the C64 send *text* down the tunnel: M, the line, RETURN.

    Mirrors exactly what a person at the machine does, so it exercises
    do_message_input and udp_tunnel_build rather than some host-only
    shortcut — the demo is only worth watching if it is the real path.
    """
    text = text.upper()[:C64_INPUT_MAX]
    if not press_key(tr, "M", timeout):
        return False
    time.sleep(0.3)                     # let the prompt print
    if not type_text(tr, text, timeout):
        return False
    return press_key(tr, "\r", timeout)


def wait_for_state(tr, wg_state_addr: int, want: int,
                   timeout: float, poll: float = 1.0) -> bool:
    """Poll wg_state until it equals *want*."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(wg_state_addr, 1)[0] == want:
            return True
        time.sleep(poll)
    return False


def rekey(tr, wg_state_addr: int, active_value: int = 2,
          timeout: float = 420.0) -> bool:
    """Re-establish the session by pressing H, then wait for SESSION_ACTIVE.

    Costs a full handshake — roughly 90 s of Type-1 plus 36 s to process the
    Type-2 at 48 MHz, and about 22 minutes at 1 MHz, which is why the demo
    insists on turbo. The C64 is single-threaded and computing throughout, so
    it neither polls the network nor accepts keystrokes until it lands; do not
    interpret that silence as a wedge.
    """
    if not press_key(tr, "H", timeout=15.0):
        return False
    return wait_for_state(tr, wg_state_addr, active_value, timeout)
