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
import time
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

    # EVERY SETUP STEP IS GUARDED, and the reason is worth stating because
    # the un-guarded version of this shipped and looked fine. Callers use
    # this from a `finally`: teardown paths, restores, the last thing a
    # failing run does. Anything that escapes from here REPLACES the
    # traceback that says what actually went wrong with one about the
    # cleanup — the single most expensive way for a helper to fail.
    #
    # The import, DeviceLock(), acquire_or_raise's non-timeout errors (an
    # OSError from the lockfile, say) and Ultimate64Client() were all
    # outside any try. A broken harness install raised ImportError out of a
    # caller's finally; an unwritable lock directory raised PermissionError.
    #
    # Every one of them means the same thing operationally — THE LOCK
    # CANNOT BE HAD — and this function already has a correct answer for
    # that: yield None, say so, do nothing. An unserialised write is never
    # the fallback.
    #
    # NOT guarded, deliberately: the `yield` itself. Swallowing there would
    # eat the CALLER's exception, which is the opposite of the point.
    try:
        from c64_test_harness import DeviceLock, DeviceLockTimeout
        from c64_test_harness.backends.ultimate64_client import Ultimate64Client
        lock = DeviceLock(host)
    except Exception as exc:                                  # noqa: BLE001
        out.warning(
            "%s on %s SKIPPED: cannot reach the harness lock at all (%r). "
            "Doing nothing rather than an unserialised write. The device "
            "may be left in a non-default state; check it before you walk "
            "away.", purpose, host, exc)
        yield None
        return

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
    except Exception as exc:                                  # noqa: BLE001
        out.warning(
            "%s on %s SKIPPED: acquiring the device lock failed (%r) — not "
            "a timeout, so this is the lock MECHANISM, not a busy peer. "
            "Doing nothing rather than an unserialised write.",
            purpose, host, exc)
        yield None
        return

    try:
        client = Ultimate64Client(host)
    except Exception as exc:                                  # noqa: BLE001
        # We hold the lock here and are about to yield None, so it has to
        # come back before we leave — the `finally` below is not reached
        # on this path.
        out.warning("%s on %s SKIPPED: could not construct a client (%r)",
                    purpose, host, exc)
        try:
            lock.release()
        except Exception as rexc:                             # noqa: BLE001
            out.warning("lock release after %s failed: %r", purpose, rexc)
        yield None
        return

    try:
        yield client
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


# ── teardown ──────────────────────────────────────────────────────────────
#
# One helper, adopted by every live tool, instead of each reimplementing a
# different subset of clock / REU / reset. Issue #134 surveyed seven tools
# and found exactly one that reset the C64; the other six abandoned their
# UDP sockets on every exit path.
#
# WHY A RESET IS THE WHOLE RECOVERY CONTRACT. The network target closes its
# sockets from the C64 reset ISR — c64_reset() calls close_all_sockets()
# (GideonZ/1541ultimate#814) — and nothing else does. MEMP_NUM_UDP_PCB is 8
# and the firmware holds several itself, so a client gets four or five.
# Strand one per run and OPEN_UDP eventually answers "85,ERROR OPENING
# SOCKET", which reads as a regression in whatever changed most recently
# rather than as an inherited condition. That confusion cost two lanes a day
# on 2026-09-03 (issue #58).
#
# WHY THE SENTINEL, and not just "we called reset() and it did not raise".
# PUT /v1/machine:reset returns 204 for having ACCEPTED the request. It is
# not a statement that the 6510 restarted, and this repo has repeatedly
# found teardowns that reported success without verifying (see the note on
# recover() below). So: write a byte the KERNAL reset MUST destroy, reset,
# and require it gone.
#
# $03FF is chosen because the KERNAL's RAMTAS ($FD50) clears $0002-$0101,
# $0200-$02FF and $0300-$03FF with a zero fill (disassembled from
# kernal-901227-03.bin, not remembered). $03FF is inside that range, is
# used by neither the KERNAL nor BASIC, and is used by nothing in src/ or
# tools/ — checked, as opposed to assumed, because $0334 and $03E0-$03E3
# ARE trampoline scratch for several tools here.
#
# "WHICH THE RESET VECTOR CALLS UNCONDITIONALLY" is what this comment said,
# and it is FALSE. $FCE2 runs the CBM80 autostart-cartridge check BEFORE
# `JSR $FD50`, and on a match does `JMP ($8000)` — RAMTAS never executes.
# So with a cartridge presenting a CBM80 signature (an RR-Net arm with a
# cart in the port, or a Cartridge Preference serving one), a PERFECTLY
# GOOD reset leaves the sentinel standing.
#
# The check stays as it is: a surviving sentinel still means "the C64 did
# not come back to a KERNAL-initialised state", which is the thing the
# caller needs to know, and being loud on a cartridge machine is the safe
# direction. What had to change is the MESSAGE, which asserted flatly that
# the 6510 did not restart. It now names the other explanation, because a
# teardown that confidently misdiagnoses a working reset costs exactly the
# kind of day this helper exists to prevent.
#
# THE ORDER MATTERS AND IS THE POINT. Reading $03FF == $00 after a reset
# proves nothing on its own: $00 is also what a device answers when the read
# path is broken, and what the address held before we touched it. So the
# sentinel WRITE is verified by read-back FIRST, and if the sentinel does
# not land the result is "unverified", never "restored" — an instrument that
# cannot fail is not an instrument. (This is the defect class where the
# check assumes the property it exists to measure: the $DE00 host read, the
# $630E probe. Ask what this reports if the reset is BROKEN, and whether it
# could tell.)
#
# NOT recover(): it probes REACHABILITY, which the device answers from the
# FPGA's HTTP stack whether or not the 6510 reset. It is the right tool for
# "is this device wedged" and the wrong one for "did my reset take".

class _RestoreUnavailable(Exception):
    """The clock/REU restore could not even be attempted. Internal: it
    short-circuits to the reset, which is the part that must always run."""


RESET_SENTINEL_ADDR = 0x03FF
RESET_SENTINEL_VALUE = 0xA5


def reset_and_verify(client, settle_s: float = 2.0, logger=None) -> str:
    """Reset the C64 and PROVE it took, by sentinel read-back.

    Returns one of:

    ``"verified"``   sentinel landed, reset issued, sentinel is gone.
    ``"unverified"`` the reset was issued but could not be checked — the
                     sentinel would not land, or the post-reset read
                     failed. NOT a success: the caller is told the sockets
                     may still be stranded.
    ``"failed"``     the sentinel landed and SURVIVED the reset, or
                     ``reset()`` itself raised. The reset did not take.

    Never raises: this runs from a ``finally`` and must not bury whatever
    actually ended the session.
    """
    out = logger or log
    addr, want = RESET_SENTINEL_ADDR, RESET_SENTINEL_VALUE

    sentinel_placed = False
    try:
        client.write_mem(addr, bytes([want]))
        got = client.read_mem(addr, 1)[0]
        sentinel_placed = (got == want)
        if not sentinel_placed:
            out.warning(
                "reset check DISARMED: wrote $%02x to $%04X and read back "
                "$%02x. The reset will still be issued, but it cannot be "
                "verified — do not read the result as proof.",
                want, addr, got)
    except Exception as exc:                                  # noqa: BLE001
        out.warning("reset check DISARMED: could not place the sentinel at "
                    "$%04X (%r). Reset will be issued unverified.",
                    addr, exc)

    try:
        client.reset()
    except Exception as exc:                                  # noqa: BLE001
        out.error("C64 reset FAILED to issue: %r — UDP sockets may be "
                  "stranded; the next lane's OPEN_UDP can fail with $85 "
                  "and it will NOT look like their fault.", exc)
        return "failed"

    time.sleep(settle_s)

    if not sentinel_placed:
        out.warning("C64 reset issued but UNVERIFIED (sentinel never armed)")
        return "unverified"

    try:
        after = client.read_mem(addr, 1)[0]
    except Exception as exc:                                  # noqa: BLE001
        out.warning("C64 reset issued but UNVERIFIED: post-reset read of "
                    "$%04X failed (%r)", addr, exc)
        return "unverified"

    if after == want:
        out.error(
            "C64 reset NOT CONFIRMED: $%04X still reads the sentinel $%02x "
            "%.1fs after reset(). The KERNAL's RAMTAS zero-fills "
            "$0200-$03FF, so on a stock machine this means the 6510 did "
            "not restart and the UDP sockets are still open — the next "
            "lane's OPEN_UDP can fail with $85 and it will NOT look like "
            "their fault. ONE OTHER EXPLANATION, check it before chasing "
            "the first: $FCE2 tests for a CBM80 autostart cartridge and "
            "does JMP ($8000) BEFORE calling RAMTAS, so a cart in the port "
            "or a Cartridge Preference serving a CBM80 image gives this "
            "same reading for a reset that worked perfectly.",
            addr, want, settle_s)
        return "failed"

    out.info("C64 reset VERIFIED ($%04X: $%02x -> $%02x) — UDP sockets "
             "closed and the command interface left idle", addr, want, after)
    return "verified"


def teardown_device(host: str, client=None, idle_mhz: int = 1,
                    reu_off: bool = True, reset: bool = True,
                    logger=None) -> dict:
    """The shared exit path for every live tool: clock, REU, reset, verified.

    Pass *client* when the caller ALREADY holds the DeviceLock (a live test
    tearing down inside its own locked region); leave it None and this takes
    the lock itself via :func:`locked_client`. Never touches the device
    unserialised.

    Each stage gets its OWN try. The reset used to be the last statement of
    the same try as the clock and REU restore, so a throw from
    ``set_turbo_mhz`` / ``get_turbo_mhz`` — precisely what happens when a run
    is aborting against a flaky device — skipped it. The one case where the
    reset matters most was the one case that lost it.

    Returns ``{"turbo": <mhz|None>, "reu": bool, "reset": <status|None>}``.
    Never raises.
    """
    out = logger or log

    def _body(c) -> dict:
        st = {"turbo": None, "reu": False, "reset": None}
        try:
            # The import is INSIDE the try. It was outside once, and the
            # test for this (a stubbed harness module) showed the helper
            # propagating an ImportError out of a caller's `finally` —
            # which replaces whatever actually ended the session with a
            # traceback about the teardown. Nothing in here may raise.
            try:
                from c64_test_harness.backends.ultimate64_helpers import (
                    get_turbo_mhz, set_turbo_mhz, set_reu,
                )
            except Exception as exc:                          # noqa: BLE001
                out.error("restore helpers unavailable (%r) — going "
                          "straight to the reset", exc)
                raise _RestoreUnavailable from exc
            # Clock and REU get separate trys for the same reason the reset
            # does: a device flaky enough to throw on the clock is a device
            # whose REU also needs detaching, and vice versa. Sharing one
            # try makes each restore conditional on the one before it.
            try:
                set_turbo_mhz(c, idle_mhz)
                time.sleep(1.0)
                # Read back: set_turbo_mhz returning is not the clock having
                # changed. A prior session's 48 MHz survives a reset.
                st["turbo"] = get_turbo_mhz(c)
                if st["turbo"] != idle_mhz:
                    out.error("clock restore DID NOT TAKE: asked for %d MHz, "
                              "device reads %s MHz", idle_mhz, st["turbo"])
            except Exception as exc:                          # noqa: BLE001
                out.error("clock restore failed: %r", exc)
            if reu_off:
                try:
                    set_reu(c, False)
                    st["reu"] = True
                except Exception as exc:                      # noqa: BLE001
                    out.error("REU detach failed: %r — the next lane "
                              "inherits an attached REU", exc)
        except _RestoreUnavailable:
            pass
        finally:
            if reset:
                st["reset"] = reset_and_verify(c, logger=out)
        return st

    if client is not None:
        return _body(client)

    # Belt and braces over the guarded locked_client above. "Never raises"
    # is a contract this function is called on from `finally` blocks, and a
    # contract that holds only as long as its callee's does is not one.
    try:
        with locked_client(host, purpose="teardown", logger=out) as c:
            if c is None:
                return {"turbo": None, "reu": False, "reset": None}
            return _body(c)
    except Exception as exc:                                  # noqa: BLE001
        out.error("teardown of %s failed outright (%r) — device state is "
                  "UNKNOWN and its UDP sockets may be stranded", host, exc)
        return {"turbo": None, "reu": False, "reset": None}
