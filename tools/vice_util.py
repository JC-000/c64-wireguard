"""Shared VICE binary monitor helpers for test scripts.

The binary monitor auto-pauses the CPU on every command.  The standard
``wait_for_text()`` from ``c64_test_harness`` does not resume between
polls, so the C64 never makes progress.  This module provides
``binary_wait_for_text()`` which follows the pattern from the harness's
own ``test_vice_core.py``.
"""

import time

from c64_test_harness import ScreenGrid, read_bytes


def binary_wait_for_text(transport, needle, timeout=60.0, poll_interval=2.0):
    """Poll screen for *needle*, resuming the CPU between reads.

    The binary monitor auto-pauses the CPU when any command is sent.
    This helper resumes the CPU after each screen read so the KERNAL
    can continue updating the screen.

    Returns the matching ``ScreenGrid``, or ``None`` on timeout.
    """
    needle_upper = needle.upper()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        grid = ScreenGrid.from_transport(transport)
        if needle_upper in grid.continuous_text().upper():
            return grid
        transport.resume()
        time.sleep(poll_interval)
    return None


def binary_wait_for_boot_ready(transport, labels, timeout=120.0, poll_interval=2.0):
    """Poll ``boot_ready`` until boot.s sets it, resuming the CPU between reads.

    ``title_msg``'s "Q=QUIT" (see ``binary_wait_for_text``) prints BEFORE
    the crypto table build (``poly1305_lib_init``/``sqtab_init`` +
    ``reu_mul_init``) — it means "boot started", not "boot finished".
    Gating on it lets a suite proceed against a half-booted machine, and
    since every suite then drives crypto by direct-memory ``jsr``, no
    suite actually depended on boot completing (issue #55).

    ``boot_ready`` (src/wg/data.s) is set to 1 as the last act of
    ``start:`` in src/boot.s, only after the table build has returned.
    Polling the byte directly — rather than waiting for the "READY."
    text boot.s also prints at that point — is preferred because it is
    immune to screen layout: it doesn't care what row the marker lands
    on or whether anything else on screen changed.

    Returns a truthy value (the byte read, ``b'\\x01'``) on success, or
    ``None`` on timeout — matching ``binary_wait_for_text``'s contract.

    TIMEOUTS: call sites want generous ones. The waits this replaced
    matched title text that appears almost immediately, so 60 s was
    ample; this one waits for the crypto table build to actually finish
    (~2 s per instance standalone, and the regression gate runs 18
    suites concurrently, each with its own VICE). A 60 s budget was
    observed timing out under that contention — `test_type2_slow` waits
    on six instances in sequence — so call sites use 180 s, and the
    multi-instance ones 300 s. The only cost of a large budget is paid
    on a genuine failure, whereas a tight one buys a flaky gate.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if read_bytes(transport, labels["boot_ready"], 1) == b"\x01":
            return b"\x01"
        transport.resume()
        time.sleep(poll_interval)
    return None
