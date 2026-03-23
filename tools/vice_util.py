"""Shared VICE binary monitor helpers for test scripts.

The binary monitor auto-pauses the CPU on every command.  The standard
``wait_for_text()`` from ``c64_test_harness`` does not resume between
polls, so the C64 never makes progress.  This module provides
``binary_wait_for_text()`` which follows the pattern from the harness's
own ``test_vice_core.py``.
"""

import time

from c64_test_harness import ScreenGrid


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
