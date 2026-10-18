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

    REU FAULT (issue #69): once boot_ready is set, the image's sticky
    ``x25519_reu_fault`` byte (c64-x25519 §8.2 settle) is read too, and a
    non-zero value RAISES ``BootReuFault`` instead of returning ($01 =
    settle spin timed out, $02 = a $DF00 bit-5 sample). Booting the REU=1
    PRG under a VICE with no REU sets $02 — an open-bus read of $DF00 —
    while boot_ready is still set, and every X25519 after that is silently
    wrong (measured
    2026-10-18: RFC 7748 vector 1 gave 5cf4f2af... for c3da5537...). It is
    raised rather than folded into the ``None`` return because callers print
    "boot did not complete" for ``None``, which would name the wrong cause.
    A build without the label (the legacy in-tree crypto) is not checked.
    Host-side only: nothing is added to the PRG. NECESSARY, NOT SUFFICIENT:
    an REU that is present but too small boots with $00 (its high banks
    alias the low ones), so the size comes from ``vice_reu_args`` and is
    proven by tools/test_vice_reu_matches_build.py R1/R3, not by this check.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if read_bytes(transport, labels["boot_ready"], 1) == b"\x01":
            _refuse_reu_fault(transport, labels)
            return b"\x01"
        transport.resume()
        time.sleep(poll_interval)
    return None


class BootReuFault(RuntimeError):
    """The booted image reports an REU settle fault (see vice_reu_args)."""


def _label(labels, name):
    """Address of *name* in a Labels object or a plain mapping, else None."""
    if hasattr(labels, "address"):
        return labels.address(name)
    return labels.get(name)


def _refuse_reu_fault(transport, labels):
    addr = _label(labels, "x25519_reu_fault")
    if addr is None:
        return
    val = read_bytes(transport, addr, 1)[0]
    if val:
        # Bit meanings per libs/x25519 src/x25519_init.s
        # (x25519_reu_settle_slow): $01 = the bounded settle spin expired
        # without END OF BLOCK; $02 = a $DF00 sample had bit 5 (VERIFY
        # ERROR) set. With no REU attached $DF00 is open bus, so $02 there
        # is typically an open-bus artefact, not a real verify — and a REU
        # access on open bus need not set EITHER bit.
        bits = []
        if val & 0x01:
            bits.append("$01 settle spin timed out without END OF BLOCK")
        if val & 0x02:
            bits.append("$02 $DF00 bit 5 seen (with no REU attached, "
                        "typically an open-bus read)")
        if val & ~0x03:
            bits.append(f"${val & ~0x03 & 0xFF:02X} undefined bits")
        raise BootReuFault(
            f"x25519_reu_fault = ${val:02X} at boot (boot_ready is set): "
            f"{'; '.join(bits)}. The REU the multiply tables were stashed in "
            f"is not behaving like one, so X25519 on this machine cannot be "
            f"trusted. This build needs VICE extra_args "
            f"{vice_reu_args(labels)} — pass vice_util.vice_reu_args(labels) "
            f"to ViceConfig instead of spelling the REU flags by hand.")


# VICE -reusize accepts these KiB values (VICE 3.10 manual, REU section).
_VICE_REU_SIZES_KIB = (128, 256, 512, 1024, 2048, 4096, 8192, 16384)

# Contract §5 manifest equates, one per linked library: the REU banks that
# library's code claims, as a bit mask. Both are emitted into labels.txt.
_REU_MANIFEST = ("LIB_X25519_REU_BANKS_USED",
                 "LIB_CHACHA20_POLY1305_REU_BANKS_USED")


def vice_reu_args(labels):
    """The VICE extra_args that match the BUILT image's REU use (issue #69).

    *labels* is a ``Labels`` object, a plain ``{name: address}`` mapping, or a
    path to labels.txt. Derived from the image, never from what the suite's
    author expected the build to be:

    * the contract §5 masks LIB_X25519_REU_BANKS_USED |
      LIB_CHACHA20_POLY1305_REU_BANKS_USED: zero (REU=0, onchip profile)
      gives ``[]`` — no REU, so a stray REU access is not masked by one —
      and non-zero gives the smallest VICE REU covering the highest claimed
      bank (64 KiB per bank; $3B -> bank 5 -> 384 KiB -> 512);
    * no manifest at all is the legacy in-tree build (USE_X25519_SIBLING=0),
      which the Makefile only permits at REU=1: if its ``reu_mul_init`` is
      present it gets 512 KiB (src/crypto/fe25519.s uses banks 0-1);
    * neither: ``ValueError`` — there is nothing to derive from, and guessing
      is how 24 gate suites came to boot the REU build without an REU.
    """
    if isinstance(labels, (str, bytes)) or hasattr(labels, "__fspath__"):
        from c64_test_harness import Labels
        labels = Labels.from_file(str(labels))
    present = [n for n in _REU_MANIFEST if _label(labels, n) is not None]
    if present:
        banks = 0
        for name in present:
            banks |= _label(labels, name)
        if banks == 0:
            return []
        need_kib = banks.bit_length() * 64
        size = next((s for s in _VICE_REU_SIZES_KIB if s >= need_kib), None)
        if size is None:
            raise ValueError(f"REU banks mask ${banks:X} needs {need_kib} KiB, "
                             f"beyond VICE's largest REU")
        return ["-reu", "-reusize", str(size)]
    # A sibling build whose mask is MISSING is not the legacy build: with
    # X25519_REU_BANK >= 11 the mask exceeds $FFFF and the Makefile drops it
    # from labels.txt (it keeps only 16-bit values). Guessing 512 KiB there
    # would be too small, so refuse instead.
    sibling = [n for n in labels if str(n).startswith(("LIB_X25519_",
                                                       "LIB_CHACHA20_POLY1305_"))]
    if sibling:
        raise ValueError(
            f"labels.txt has contract manifest symbols ({sibling[0]}, ...) but "
            f"no REU_BANKS_USED mask — most likely a relocated REU bank pushed "
            f"it above $FFFF and the Makefile dropped it; cannot size the REU")
    if _label(labels, "reu_mul_init") is not None:
        return ["-reu", "-reusize", "512"]
    raise ValueError("cannot tell whether this build needs an REU: labels.txt "
                     "has neither the contract §5 REU_BANKS_USED manifest nor "
                     "reu_mul_init")
