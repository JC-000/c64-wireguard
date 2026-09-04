#!/usr/bin/env python3
"""Queue for the shared device through the harness lock — always, including
for reads and for teardown.

The rule this exists to enforce: **every access to the shared Ultimate goes
through the harness DeviceLock**, not just the long test bodies. Reads and
one-line restores were the exceptions people made, and both bit us on
2026-09-03/04:

* Three lanes drove `10.43.23.81` that evening. The harness lock serialised
  only the ones that opted in, so a lane doing `run_prg` — a genuine
  load-and-run that REPLACES the program another lane is talking to —
  landed mid-scenario in an 18-minute suite that took no lock. It presented
  as device degradation, and a power cycle was nearly performed, which
  would have "fixed" it and destroyed the evidence.
* A config READ taken during another lane's transactional config rewrite
  returns a coherent-looking value from a half-applied state. Nothing
  raises. That is the unreproducible one-off that costs someone a day six
  weeks later — the same shape as every other trap in this repo, where the
  expensive part is that the wrong answer looks like a right one.

So: not "lock the parts that mutate". Lock the access.

`locked_client()` yields None rather than an unlocked client when the lock
cannot be had, so a caller CANNOT accidentally fall through to touching the
device anyway — the failure mode is a warning and no action, never a
silent unserialised write.

    with locked_client(host, purpose="restore 1 MHz") as client:
        if client is None:
            return                    # said so, did nothing
        set_turbo_mhz(client, 1)
"""
from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from typing import Optional

# Teardown/restore work is short; do not sit on a queue for two minutes to
# write one config byte. Long test bodies use their own larger timeout.
RESTORE_LOCK_TIMEOUT_S = 30.0

log = logging.getLogger("device_session")


@contextmanager
def locked_client(host: str, timeout: float = RESTORE_LOCK_TIMEOUT_S,
                  purpose: str = "device access", logger=None):
    """Acquire the harness DeviceLock, yield an Ultimate64Client, release.

    Yields **None** if the lock cannot be acquired: the caller must check,
    and doing nothing is the correct outcome. Never yields an unlocked
    client — that would defeat the point.

    Not re-entrant: if the calling process ALREADY holds the lock (a live
    test inside its own locked region), do not use this — just use the
    client you have.
    """
    out = logger or log
    from c64_test_harness import DeviceLock, DeviceLockTimeout
    from c64_test_harness.backends.ultimate64_client import Ultimate64Client

    lock = DeviceLock(host)
    try:
        lock.acquire_or_raise(timeout=timeout)
    except DeviceLockTimeout as exc:
        out.warning(
            "%s on %s SKIPPED: device lock busy after %.0fs (%s). Another "
            "lane holds it — doing nothing rather than an unserialised "
            "write. The device may be left in a non-default state; check "
            "it before you walk away.", purpose, host, timeout, exc)
        yield None
        return
    try:
        yield Ultimate64Client(host)
    finally:
        try:
            lock.release()
        except Exception as exc:                              # noqa: BLE001
            out.warning("lock release after %s failed: %r", purpose, exc)


def restore_idle(host: str, idle_mhz: int = 1, logger=None) -> bool:
    """Put the shared device back to `idle_mhz`, under the lock.

    Returns True if it was restored (or already there), False if the lock
    was busy or the call failed. Never raises: a failure to restore is
    worth a warning, never a traceback that buries whatever ended the
    session.
    """
    out = logger or log
    try:
        from c64_test_harness.backends.ultimate64_helpers import (
            get_turbo_mhz, set_turbo_mhz,
        )
        with locked_client(host, purpose=f"restore {idle_mhz} MHz",
                           logger=out) as client:
            if client is None:
                return False
            if get_turbo_mhz(client) != idle_mhz:
                set_turbo_mhz(client, idle_mhz)
                print(f"-- device restored to {idle_mhz} MHz --",
                      file=sys.stderr, flush=True)
            return True
    except Exception as exc:                                  # noqa: BLE001
        print(f"!! could not restore {idle_mhz} MHz on {host}: "
              f"{type(exc).__name__}: {exc}\n"
              f"!! it is shared — check it before you walk away.",
              file=sys.stderr, flush=True)
        return False
