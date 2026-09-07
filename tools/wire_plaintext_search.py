#!/usr/bin/env python3
"""The searcher behind every "plaintext is ABSENT from the wire" claim.

WHY THIS MODULE EXISTS (issue #147). `test_wire_encryption_live.py` asserted
absence four times with four inline ``needle not in raw`` expressions and
never once demonstrated that the search could produce a non-null. A search
that looks at the wrong buffer, encodes the needle the wrong way, compares
mismatched types or silently examines zero bytes reports a clean absence in
every one of those cases, and a tool built out of them says the tunnel
encrypts whether or not it does.

So absence is never asserted here on its own. `absence_and_control` returns
TWO results from ONE searcher: the absence claim over the real datagram, and
a positive control over the COUNTERFACTUAL datagram -- the bytes the same
sender would have emitted had it not encrypted (its real cleartext body
behind its real Type-4 header). The control runs the identical
`plaintext_absent` call the absence claim runs, and requires it to FAIL.
That is the mutation arm and the control in one object: if the searcher
cannot find plaintext in a datagram that IS plaintext, its silence about
the ciphertext means nothing, and the pair goes red together.

THE ENCODING TRAP, measured on 2026-09-07 (issue #147 comment). A control
written the obvious way -- search for the literal ASCII marker where the
plaintext is known to be -- returned ZERO hits across a whole capture, and
looked exactly like a passing absence test. The text had crossed the wire
hex-encoded in a URL query string, ten characters per request. The needle
must match the TRANSPORT encoding, not the one the host happens to hold, so
`needle_forms` enumerates the forms the C64's own send path can emit and the
counterfactual is built from the REAL post-encoding bytes wherever the
caller has them (the responder's decrypt output). Where a caller has no
decrypt for that datagram it may fall back to a host-side re-encoding, and
`body_source` says so in the check's detail line -- that is a weaker
control, disclosed, not the normal path.

Vacuity is refused rather than reported: an empty buffer, an empty needle
set, an empty needle, a needle/haystack of the wrong type, or a needle
LONGER than the buffer raises instead of returning "absent". Those are the
ways the search examines nothing, and every one of them passes silently if
it is allowed to return a verdict.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The searcher primitive is the ip65 hardware suite's, not a second copy of
# it: that one is already selftested (ip65_hw_checks.selftest_library) and
# has found real leaks. Two independent implementations of "does this text
# appear in these bytes" is exactly how the two tools drift apart.
from ip65_hw_checks import (                                  # noqa: E402
    petscii_form, petscii_shifted_form, search_forms,
)

T4_HDR_LEN = 16     # type(1) + reserved(3) + receiver_idx(4) + counter(8)


def screen_code_form(needle: bytes) -> bytes:
    """The bytes this text occupies in the C64's SCREEN RAM.

    A fifth encoding, and not a hypothetical one: `_screen_text` in the
    live tool decodes exactly this mapping to read $0400, so a buffer that
    was copied from (or shares a routine with) screen RAM carries letters
    as $01-$1A, not $41-$5A. None of exact/petscii/petscii-shifted/reversed
    can see that, and screen RAM is the single most plausible place a C64
    leak would be copied FROM. MEASURED before it was added: a screen-code
    copy of the marker in a datagram was reported ABSENT with both arms of
    the pair green.

    Letters (either case) fold to 1-26; $20-$3F -- space, digits and
    punctuation -- are the same code in both, which is the inverse of what
    `_screen_text` decodes.
    """
    out = bytearray(needle)
    for i, b in enumerate(out):
        if 0x41 <= b <= 0x5A:
            out[i] = b - 0x40
        elif 0x61 <= b <= 0x7A:
            out[i] = b - 0x60
    return bytes(out)


class VacuousSearchError(ValueError):
    """The search would have examined nothing. Never a clean absence."""


@dataclass(frozen=True)
class Hit:
    label: str          # which named plaintext
    form: str           # exact | petscii | petscii-shifted |
                        # screen-code | reversed
    offset: int
    length: int

    def __str__(self) -> str:
        return f"{self.label}:{self.form}@{self.offset}+{self.length}"


def needle_forms(text: str | bytes) -> dict[str, bytes]:
    """Every byte form of *text* the C64's send path could put on the wire.

    exact/petscii/petscii-shifted because the 6510 emits letters in either
    PETSCII block depending on the case mode in force, and our uppercase
    alphabets make `petscii_form` a no-op -- the shifted block is the form
    an ASCII-only needle would look straight past. screen-code because
    that is what sits in $0400 and what this repo's own `_screen_text`
    reads back. Reversed because a
    descending-index copy loop is ordinary 6502 code and reversed plaintext
    on the wire is just as readable to whoever holds the capture.
    """
    if isinstance(text, str):
        raw = text.encode("ascii")
    elif isinstance(text, (bytes, bytearray, memoryview)):
        raw = bytes(text)
    else:
        raise TypeError(f"needle must be str or bytes, got {type(text).__name__}")
    if not raw:
        raise VacuousSearchError("empty needle: a search for nothing always succeeds")
    return {
        "exact": raw,
        "petscii": petscii_form(raw),
        "petscii-shifted": petscii_shifted_form(raw),
        "screen-code": screen_code_form(raw),
        "reversed": raw[::-1],
    }


def _as_haystack(buf) -> bytes:
    if isinstance(buf, str):
        raise TypeError("haystack is a str: bytes were expected, and a str "
                        "needle would never match wire bytes")
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise TypeError(f"haystack must be bytes-like, got {type(buf).__name__}")
    raw = bytes(buf)
    if not raw:
        raise VacuousSearchError("empty haystack: nothing was searched")
    return raw


def find_plaintext(buf, needles: dict[str, str]) -> list[Hit]:
    """Every appearance of every named plaintext in *buf*, in every form.

    Raises rather than returning [] when the search would be vacuous.
    """
    hay = _as_haystack(buf)
    if not needles:
        raise VacuousSearchError("no needles: nothing was looked for")
    hits: list[Hit] = []
    for label, text in needles.items():
        forms = needle_forms(text)
        # A fifth vacuity class, and the one that hides best: a needle
        # LONGER than what is being searched cannot appear no matter what
        # the sender did, so "absent" is arithmetic, not evidence. An
        # all-header datagram against a 36-byte marker used to come back
        # clean this way.
        need = len(forms["exact"])
        if need > len(hay):
            raise VacuousSearchError(
                f"needle {label!r} is {need} B but only {len(hay)} B were "
                f"searched: it could not have appeared at any offset")
        for form, pat in forms.items():
            for got_form, at, ln in search_forms(hay, pat):
                # search_forms re-derives forms of what it is handed; we
                # already enumerated ours, so only its own "exact" branch
                # is new information for this pattern.
                if got_form != "exact":
                    continue
                hits.append(Hit(label, form, at, ln))
    return hits


def plaintext_absent(buf, needles: dict[str, str]) -> tuple[bool, str]:
    """THE absence check. (ok, detail); ok is False if any plaintext is found.

    This is the single function every absence assertion in the live wire
    tool calls, and the same one its positive control calls. There is no
    second copy to drift.
    """
    hits = find_plaintext(buf, needles)
    n = len(bytes(buf))
    if hits:
        return False, (f"{len(hits)} hit(s) in {n} B: "
                       + ", ".join(str(h) for h in hits[:6]))
    forms = len(needle_forms(next(iter(needles.values()))))
    return True, (f"{n} B searched for {len(needles)} needle(s) "
                  f"[{', '.join(needles)}] in {forms} encodings each; no hit")


def cleartext_counterfactual(datagram, body, *, hdr_len: int = T4_HDR_LEN) -> bytes:
    """The datagram this sender would have emitted had it NOT encrypted.

    *body* should be the real post-encoding plaintext (the responder's
    decrypt output for an inbound datagram, or the exact bytes handed to
    encrypt_transport for an outbound one). A host-side re-encoding is a
    weaker control -- it can only prove the searcher finds what the HOST
    thinks the wire carries, which is how the pcap control returned a false
    null -- so callers that must fall back to one say so via *body_source*.
    The header is the datagram's own, so the control's buffer differs from
    the asserted one only in the property under test.
    """
    raw = _as_haystack(datagram)
    payload = _as_haystack(body)
    if len(raw) < hdr_len:
        raise VacuousSearchError(
            f"datagram is {len(raw)} B, shorter than its {hdr_len}-byte header")
    return raw[:hdr_len] + payload


def absence_and_control(datagram, body, needles: dict[str, str], prefix: str,
                        *, hdr_len: int = T4_HDR_LEN,
                        body_source: str = "decrypted wire bytes",
                        ) -> list[tuple[bool, str, str]]:
    """(ok, label, detail) for the CONTROL then the absence claim.

    The control is not a second searcher: it is `plaintext_absent` again,
    over the counterfactual cleartext datagram, required to come back
    False. If the searcher is blind, the control is the check that says so.
    """
    ctrl_buf = cleartext_counterfactual(datagram, body, hdr_len=hdr_len)
    ctrl_absent, ctrl_detail = plaintext_absent(ctrl_buf, needles)
    absent, detail = plaintext_absent(datagram, needles)
    return [
        (not ctrl_absent,
         f"{prefix}CONTROL: the same absence check FAILS on the "
         f"counterfactual cleartext datagram",
         f"{len(ctrl_buf)} B = {hdr_len} B of the real header + "
         f"{len(bytes(body))} B of {body_source}; {ctrl_detail}"),
        (absent,
         f"{prefix}marker ABSENT from the datagram on the wire",
         detail),
    ]


# ── selftest: proves the searcher can fire, and refuses to be vacuous ──────

def selftest() -> list[tuple[bool, str, str]]:
    """Run before any absence claim is believed. (ok, label, detail)."""
    out: list[tuple[bool, str, str]] = []

    def rec(ok, label, detail=""):
        out.append((bool(ok), label, detail))

    hdr = bytes([4, 0, 0, 0]) + b"\x01\x02\x03\x04" + b"\x00" * 8
    text = "MDCK BAMA AAKHMD DBD DIG END BMBGIKKL"
    needles = {"probe": text}

    # EACH form is controlled separately, by its OWN label. A bare
    # "something was found" would be satisfied by any one surviving branch:
    # for our uppercase alphabets `petscii_form` is the identity, so a
    # corrupted "exact" branch stays invisible behind the petscii hit at
    # the same offset. MEASURED: appending one byte to the exact needle
    # left a len()>=1 assertion green.
    rec(any(h.form == "exact"
            for h in find_plaintext(hdr + text.encode("ascii"), needles)),
        "selftest: the exact ASCII form is FOUND, labelled `exact`")
    # A LOWERCASE probe is what makes the petscii branch non-degenerate:
    # the wire bytes then differ from the ASCII the host holds, which is
    # the whole reason the branch exists.
    lower = text.lower()
    lower_hits = find_plaintext(hdr + petscii_form(lower.encode()),
                                {"probe": lower})
    rec(any(h.form == "petscii" for h in lower_hits)
        and not any(h.form == "exact" for h in lower_hits),
        "selftest: lowercase text folded to PETSCII is FOUND, and only "
        "the `petscii` branch finds it")
    rec(any(h.form == "petscii-shifted"
            for h in find_plaintext(hdr + petscii_shifted_form(text.encode()),
                                    needles)),
        "selftest: the shifted-PETSCII form is FOUND, labelled "
        "`petscii-shifted`")
    rec(any(h.form == "reversed"
            for h in find_plaintext(hdr + text.encode()[::-1], needles)),
        "selftest: the reversed form is FOUND, labelled `reversed`")
    # Screen codes: the letters land in $01-$1A, which no other branch
    # searches for. Asserted by its own label for the same reason as the
    # rest -- a sibling branch matching at the same offset would otherwise
    # keep a dead branch looking alive.
    screen_hits = find_plaintext(hdr + screen_code_form(text.encode()), needles)
    rec(any(h.form == "screen-code" for h in screen_hits)
        and not any(h.form in ("exact", "petscii") for h in screen_hits),
        "selftest: the screen-code form is FOUND, labelled `screen-code`, "
        "and no ASCII/PETSCII branch sees it")
    rec(plaintext_absent(hdr + b"\xa7" * 200, needles)[0],
        "selftest: unrelated bytes are reported ABSENT")

    # The 2026-09-07 false null, pinned: a needle split ten characters per
    # request, or hex-encoded, is NOT contiguous plaintext and must not be
    # reported as a hit -- but neither may it be mistaken for proof that
    # the searcher works.
    split = hdr + b"|".join(text.encode()[i:i + 10] for i in range(0, len(text), 10))
    rec(plaintext_absent(split, needles)[0],
        "selftest: a needle split across chunks is not a contiguous hit")
    rec(plaintext_absent(hdr + text.encode().hex().upper().encode(), needles)[0],
        "selftest: a hex-encoded needle is not an ASCII hit")

    # Each refusal is pinned to ITS OWN message, not merely to
    # VacuousSearchError: the guards overlap (an empty haystack also trips
    # the needle-fits guard), so a bare `except VacuousSearchError` stays
    # green with one of them deleted and stops distinguishing them.
    for label, want, thunk in (
        ("empty haystack", "nothing was searched",
         lambda: plaintext_absent(b"", needles)),
        ("empty needle", "a search for nothing",
         lambda: plaintext_absent(hdr, {"probe": ""})),
        ("no needles", "nothing was looked for",
         lambda: plaintext_absent(hdr, {})),
        # 16 B of Type-4 header against a 37-byte marker: the shape a torn
        # or header-only datagram takes, where "absent" is arithmetic
        # rather than evidence.
        ("a needle longer than the buffer (all-header datagram)",
         "could not have appeared at any offset",
         lambda: plaintext_absent(hdr, needles)),
    ):
        try:
            thunk()
            rec(False, f"selftest: {label} is REFUSED", "returned a verdict")
        except Exception as exc:                              # noqa: BLE001
            rec(isinstance(exc, VacuousSearchError) and want in str(exc),
                f"selftest: {label} is REFUSED",
                f"{type(exc).__name__}: {exc} (wanted {want!r})")
    # The expected substring pins each refusal to THIS module's guard.
    # `bytes("...")` and `hay.find(str)` raise TypeError on their own, so a
    # bare `except TypeError` here would stay green with the guards deleted
    # and would be testing CPython. `bytes(17)`, by contrast, silently
    # yields 17 zero bytes -- that guard is the only thing between an int
    # and a clean absence over a buffer that never existed.
    for label, want, thunk in (
        ("str haystack", "bytes were expected",
         lambda: plaintext_absent(text, needles)),
        ("int needle", "needle must be str or bytes",
         lambda: plaintext_absent(hdr, {"probe": 17})),
        ("int haystack", "must be bytes-like",
         lambda: plaintext_absent(17, needles)),
    ):
        try:
            thunk()
            rec(False, f"selftest: {label} is REFUSED", "returned a verdict")
        except Exception as exc:                              # noqa: BLE001
            rec(want in str(exc), f"selftest: {label} is REFUSED by this "
                f"module's own guard",
                f"{type(exc).__name__}: {exc} (wanted {want!r})")

    # And the pairing itself: ciphertext-shaped noise absent, its own
    # cleartext counterfactual found.
    body = petscii_form(text.encode())
    fake_ct = hdr + bytes((b * 37 + 11) & 0xFF for b in range(len(body) + 16))
    pair = absence_and_control(fake_ct, body, needles, "selftest: ")
    rec(pair[0][0], "selftest: the CONTROL fires on the counterfactual",
        pair[0][2])
    rec(pair[1][0], "selftest: absence holds on the ciphertext", pair[1][2])
    return out


if __name__ == "__main__":
    rows = selftest()
    for ok, label, detail in rows:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}"
              + (f"\n          {detail}" if detail else ""))
    bad = [r for r in rows if not r[0]]
    print(f"{len(rows) - len(bad)}/{len(rows)} selftest checks passed")
    sys.exit(1 if bad else 0)
