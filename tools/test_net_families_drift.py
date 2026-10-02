#!/usr/bin/env python3
"""test_net_families_drift.py -- our NET_FAMILY_* bits must equal c64-https's.

Host-side only: reads two source files, parses them, compares. No build, no
VICE, no device, no DeviceLock, milliseconds.

    python3 tools/test_net_families_drift.py              # real trees
    python3 tools/test_net_families_drift.py --seed 1234  # reproduce proofs

WHY THIS EXISTS
===============

``src/net/net_families.inc`` holds the SPEC §13.0 family bits. §13 was
retired at c64-lib-contract v1.0.0, so there is no upstream left to copy
from, and c64-https keeps an independent copy at the same path. The bits are
what a backend manifest exports and what a consumer asserts against, so the
two repos disagreeing on one is a silent ABI split. Both repos keep their
copy and each guards it against the other; the c64-https half is
c64-https#278 (its own ``tools/test_net_families_drift.py``). This is ours.

WHAT IT REQUIRES
================

Set EQUALITY of names, checked in BOTH directions as two separate checks
(a bit only in ours, a bit only in theirs; a rename shows as one of each),
then equal values for every shared name. Every failure names the bit and,
for a value, both values.

Per file, peer included: it parses (below), it defines at least one bit and
the parsed row count equals an INDEPENDENT count, no name is defined twice,
and the values are distinct single bits.

THE PARSER FAILS CLOSED, AND ITS "LOOKS LIKE" SET IS NOT ITS OWN PATTERN
=======================================================================

The strict form is exactly what both files use today::

    NET_FAMILY_<NAME> = $hhhh      ; spaces, not tabs; 4 UPPERCASE hex digits

The set of lines that must match it is NOT selected by a regex sharing the
parser's prefix (the gap c64-https's registry test had: a candidate regex
that only fires on lines the parser would almost accept is circular). It is
every non-blank code line (text before ``;``) except the three include-guard
lines, compared as whitespace-normalised STRINGS. So ``NET_FAMILY_X=$1``,
``NET_FAMILY_X = $00G1``, a lowercase ``$000a``, a tab, ``:=``, ``.set``,
``.define``, an expression, a typo'd ``NET_FAMLY_X`` -- each fails, quoting
its file and line. A line the parser cannot read is never skipped.

The independent row count is the number of ``NET_FAMILY_`` tokens in the
comment-stripped text, counted with ``str.count`` -- not line-based, no
regex. On file inputs it is dominated by the fail-closed parse (any file
that moves it also has an unparseable line); what it guards is the PARSER:
a loop that drops a row it matched. Its alarm is proved against a corrupted
parser in the built-in proofs below. The nonzero half is NOT dominated: an
empty file parses cleanly and would otherwise compare vacuously.

This parser is STRICTER than c64-https#278's (which also accepts 1-4 hex
digits, lowercase, decimal and ``.define``). A peer edit in one of those
spellings fails here as unparseable even though it is legal there. That is
deliberate: the bits are a cross-repo agreement, so any edit to the peer's
block should be a reason for a human to look.

LOCATING THE PEER
=================

``$C64_HTTPS_ROOT`` if set (no fallback if it is wrong), else the parent of
whatever the ``ip65`` symlink resolves to -- that symlink is this repo's
existing pointer at the sibling checkout (``ip65 -> ../c64-https/ip65``),
and the isolated-gate recipe repoints it, so the peer follows -- else
``../c64-https`` next to the repo. The variable name mirrors c64-https's
``C64_WIREGUARD_ROOT``.

A peer checkout that is MISSING FAILS (exit 1). ``C64_NO_PEER_REGISTRY=1``
(exactly "1"; the same variable c64-https uses for this peer, one peer, one
hatch -- this repo had no equivalent) excuses ONLY an absent checkout: the
peer checks are SKIPPED with a loud warning, the local checks still run, and
the exit is 0. It does not suppress a comparison that can run. A checkout
that IS found but has no families file is a failure even under the opt-out:
the peer moved or deleted its copy.

``$NET_FAMILIES_PROJECT_ROOT`` repoints OUR side (default: this file's
repo), named after ``IP65_PROJECT_ROOT`` in test_ip65_hw_checks_unit.py.
It exists so a mutated copy of our file can be tested without touching the
tree.

BUILT-IN ALARM PROOFS
=====================

Every run also replays a mutation catalogue against temp copies of OUR
file, in-process: rename a bit, flip one value bit, a bit only in the peer,
a bit only in ours, boundary malformations of the strict form, an empty
file, a duplicate, and a corrupted parser. Each must turn the expected check
RED and name the bit or line; two survivors (comment-only edit, reordered
equates) must stay GREEN. Which bit is mutated and the added bit's name come
from a seeded RNG, logged once (``--seed`` / ``TEST_SEED``). A proof that
fails is a check that has stopped being able to fire, and fails the run.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import sys
import tempfile
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent
SELF_ROOT_ENV = "NET_FAMILIES_PROJECT_ROOT"
PEER_ROOT_ENV = "C64_HTTPS_ROOT"
OPT_OUT_ENV = "C64_NO_PEER_REGISTRY"
FAMILIES_REL = Path("src") / "net" / "net_families.inc"

GUARD_LINES = frozenset({
    ".ifndef NET_FAMILIES_INC_INCLUDED",
    "NET_FAMILIES_INC_INCLUDED = 1",
    ".endif",
})
STRICT_EQUATE = re.compile(r"^(NET_FAMILY_[A-Z][A-Z0-9_]*) += +\$([0-9A-F]{4})$")
TOKEN = "NET_FAMILY_"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _code(raw):
    return raw.split(";", 1)[0].strip()


def parse(text, label):
    """(rows, bad). rows: [(lineno, name, value)]; bad: ['label:N: line'].

    Every non-blank code line that is not an include-guard line must match
    STRICT_EQUATE; otherwise it is reported, never skipped.
    """
    rows, bad = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        code = _code(raw)
        if not code or " ".join(code.split()) in GUARD_LINES:
            continue
        m = STRICT_EQUATE.match(code)
        if not m:
            bad.append(f"{label}:{lineno}: {raw.rstrip()!r}")
            continue
        rows.append((lineno, m.group(1), int(m.group(2), 16)))
    return rows, bad


def independent_count(text):
    """NET_FAMILY_ tokens in comment-stripped text. No regex, not per-row."""
    return "\n".join(_code(l) for l in text.splitlines()).count(TOKEN)


# ---------------------------------------------------------------------------
# Checks. Each returns a list of failure strings; empty = PASS.
# ---------------------------------------------------------------------------

def check_parses(side):
    if not side["bad"]:
        return []
    return [f"{side['who']}: {len(side['bad'])} line(s) are neither an "
            f"include-guard line nor a strict `NET_FAMILY_<NAME> = $hhhh` "
            f"equate (spaces, 4 uppercase hex digits, no expression): "
            + "; ".join(side["bad"])]


def check_row_count(side):
    n, ind = len(side["rows"]), independent_count(side["text"])
    out = []
    if n == 0:
        out.append(f"{side['who']}: parsed ZERO NET_FAMILY_* equates -- an "
                   f"empty table would compare vacuously")
    if n != ind:
        out.append(f"{side['who']}: parsed {n} equate row(s) but the file's "
                   f"code holds {ind} `{TOKEN}` token(s) -- a row was "
                   f"dropped or a non-equate use exists")
    return out


def check_no_duplicates(side):
    seen, out = {}, []
    for lineno, name, _ in side["rows"]:
        if name in seen:
            out.append(f"{side['who']}: {name} defined twice "
                       f"(lines {seen[name]} and {lineno})")
        seen.setdefault(name, lineno)
    return out


def check_single_bits(side):
    out, by_value = [], {}
    for _, name, v in side["rows"]:
        if v == 0 or v & (v - 1):
            out.append(f"{side['who']}: {name} = ${v:04X} is not a single bit")
        by_value.setdefault(v, []).append(name)
    for v, names in sorted(by_value.items()):
        if len(set(names)) > 1:
            out.append(f"{side['who']}: ${v:04X} is claimed by "
                       f"{sorted(set(names))}")
    return out


def _bits(side):
    return {name: v for _, name, v in side["rows"]}


def check_only_in_ours(ours, peer):
    a, b = _bits(ours), _bits(peer)
    return [f"{n} = ${a[n]:04X} is in ours but NOT in the peer"
            for n in sorted(set(a) - set(b))]


def check_only_in_peer(ours, peer):
    a, b = _bits(ours), _bits(peer)
    return [f"{n} = ${b[n]:04X} is in the peer but NOT in ours"
            for n in sorted(set(b) - set(a))]


def check_values_agree(ours, peer):
    a, b = _bits(ours), _bits(peer)
    return [f"{n}: ours ${a[n]:04X}, peer ${b[n]:04X}"
            for n in sorted(set(a) & set(b)) if a[n] != b[n]]


LOCAL_CHECKS = [("parses", check_parses), ("row_count", check_row_count),
                ("no_duplicates", check_no_duplicates),
                ("single_bits", check_single_bits)]
CROSS_CHECKS = [("names_only_in_ours", check_only_in_ours),
                ("names_only_in_peer", check_only_in_peer),
                ("values_agree", check_values_agree)]


def load(path, who, text=None):
    if text is None:
        text = Path(path).read_text(encoding="utf-8")
    rows, bad = parse(text, str(path))
    return {"who": who, "path": str(path), "text": text,
            "rows": rows, "bad": bad}


def run_checks(ours, peer):
    """[(check_name, failures)] for every check; peer may be None."""
    results = [(f"ours_{n}", fn(ours)) for n, fn in LOCAL_CHECKS]
    if peer is not None:
        results += [(f"peer_{n}", fn(peer)) for n, fn in LOCAL_CHECKS]
        results += [(n, fn(ours, peer)) for n, fn in CROSS_CHECKS]
    return results


# ---------------------------------------------------------------------------
# Peer location
# ---------------------------------------------------------------------------

def locate_peer(self_root):
    env = os.environ.get(PEER_ROOT_ENV)
    if env:
        return Path(env), f"${PEER_ROOT_ENV}"
    link = self_root / "ip65"
    if link.is_symlink():
        target = link.resolve()
        if target.is_dir():
            return target.parent, f"parent of the ip65 symlink ({link} -> {os.readlink(link)})"
    return self_root.parent / "c64-https", "../c64-https next to the repo"


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Built-in alarm proofs
# ---------------------------------------------------------------------------

def _replace_line(text, lineno, new):
    lines = text.splitlines()
    lines[lineno - 1] = new
    return "\n".join(lines) + "\n"


def _insert_after(text, lineno, new):
    lines = text.splitlines()
    lines.insert(lineno, new)
    return "\n".join(lines) + "\n"


def _with_parser(fn):
    """Run fn() with `parse` replaced by a corrupted copy, then restore."""
    global parse
    real = parse

    def lossy(text, label):
        rows, bad = real(text, label)
        return rows[:-1], bad  # drops the last matched row silently
    parse = lossy
    try:
        return fn()
    finally:
        parse = real


def alarm_proofs(ours_text, rng):
    """[(proof_name, ok, detail)]. ours_text must itself be green."""
    base_rows, base_bad = parse(ours_text, "base")
    if base_bad or not base_rows:
        return [("baseline", False, "our file is not green, so no mutation "
                 "proof is meaningful")]
    lineno, victim, value = rng.choice(base_rows)
    used = {v for _, _, v in base_rows}
    free = next(1 << i for i in range(16) if (1 << i) not in used)
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    new_name = "NET_FAMILY_Z" + "".join(rng.choice(alpha) for _ in range(5))
    renamed = victim + "".join(rng.choice(alpha) for _ in range(3))
    flipped = value ^ (1 << rng.randrange(16))
    if flipped == value:
        flipped ^= 1
    added = f"{new_name} = ${free:04X}"
    last_line = base_rows[-1][0]

    def peer_mut(text):
        return load("PEER", "peer", text)

    ours = load("OURS", "ours", ours_text)
    # name, peer_text, ours_text, expected-red check, needle in its message
    cases = [
        ("rename", _replace_line(ours_text, lineno,
                                 f"{renamed} = ${value:04X}"), None,
         "names_only_in_ours", victim),
        ("rename(other dir)", _replace_line(ours_text, lineno,
                                            f"{renamed} = ${value:04X}"), None,
         "names_only_in_peer", renamed),
        ("value one bit", _replace_line(ours_text, lineno,
                                        f"{victim} = ${flipped:04X}"), None,
         "values_agree", f"{victim}: ours ${value:04X}, peer ${flipped:04X}"),
        ("value +1 near boundary", _replace_line(
            ours_text, lineno, f"{victim} = ${(value + 1) & 0xFFFF:04X}"),
         None, "values_agree", victim),
        ("bit only in peer", _insert_after(ours_text, last_line, added), None,
         "names_only_in_peer", new_name),
        ("bit only in ours", None, _insert_after(ours_text, last_line, added),
         "names_only_in_ours", new_name),
        ("duplicate in peer", _insert_after(
            ours_text, last_line, f"{victim} = ${value:04X}"), None,
         "peer_no_duplicates", victim),
        ("empty peer", ".ifndef NET_FAMILIES_INC_INCLUDED\n"
         "NET_FAMILIES_INC_INCLUDED = 1\n.endif\n", None,
         "peer_row_count", "ZERO"),
    ]
    for label, bad_line in [
            ("no spaces", f"{victim}=${value:04X}"),
            ("3 hex digits", f"{victim} = ${value:03X}"),
            ("5 hex digits", f"{victim} = ${value:05X}"),
            # Only the CASE differs from a strict line: `$000A` would parse.
            ("lowercase hex", f"{victim} = ${0xA:04x}"),
            ("non-hex digit", f"{victim} = $00G1"),
            ("tab separator", f"{victim}\t= ${value:04X}"),
            ("colon-equals", f"{victim} := ${value:04X}"),
            ("decimal", f"{victim} = {value}"),
            ("expression", f"{victim} = ${value:04X} + 0"),
            ("typo prefix", f"NET_FAMLY_{victim[len(TOKEN):]} = ${value:04X}"),
            (".define", f".define {victim} ${value:04X}")]:
        cases.append((f"malformed: {label}",
                      _replace_line(ours_text, lineno, bad_line), None,
                      "peer_parses", f":{lineno}:"))

    out = []
    for name, ptext, otext, want, needle in cases:
        o = load("OURS", "ours", otext) if otext is not None else ours
        p = peer_mut(ptext if ptext is not None else ours_text)
        res = dict(run_checks(o, p))
        msgs = res.get(want, [])
        ok = bool(msgs) and any(needle in m for m in msgs)
        out.append((name, ok, f"{want}: " + (msgs[0] if msgs
                                             else "stayed GREEN")))

    # The independent count against a CORRUPTED parser (it alone sees this).
    def lossy_run():
        o = load("OURS", "ours", ours_text)
        return dict(run_checks(o, load("PEER", "peer", ours_text)))
    res = _with_parser(lossy_run)
    msgs = res["ours_row_count"]
    out.append(("parser drops a row", bool(msgs) and "token" in msgs[0],
                "ours_row_count: " + (msgs[0] if msgs else "stayed GREEN")))

    # Survivors: these must stay GREEN everywhere.
    lines = ours_text.splitlines()
    eq_idx = [r[0] - 1 for r in base_rows]
    reordered = list(lines)
    for i, j in zip(eq_idx, reversed(eq_idx)):
        reordered[i] = lines[j]
    survivors = [
        ("survivor: comment-only edit",
         _replace_line(ours_text, lineno, lines[lineno - 1].split(";")[0]
                       .rstrip() + "   ; reworded comment, NET_FAMILY_Q = $8000")),
        ("survivor: reordered equates", "\n".join(reordered) + "\n"),
    ]
    for name, ptext in survivors:
        res = run_checks(ours, peer_mut(ptext))
        red = [(n, m) for n, m in res if m]
        out.append((name, not red,
                    "all GREEN" if not red else f"went RED: {red[0]}"))
    return out


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=None,
                    help="seed for the alarm-proof mutations (or TEST_SEED)")
    args = ap.parse_args(argv)
    seed = args.seed if args.seed is not None else int(
        os.environ.get("TEST_SEED", random.randrange(2 ** 31)))
    print(f"seed: {seed}  (reproduce with --seed {seed} or TEST_SEED={seed})")

    self_root = Path(os.environ.get(SELF_ROOT_ENV, DEFAULT_ROOT))
    ours_path = self_root / FAMILIES_REL
    print(f"ours: {ours_path}"
          + (f"  (from ${SELF_ROOT_ENV})" if os.environ.get(SELF_ROOT_ENV)
             else ""))
    passed = failed = skipped = 0

    def report(name, msgs):
        nonlocal passed, failed
        if msgs:
            failed += 1
            print(f"FAIL  {name}")
            for m in msgs:
                print(f"      {m}")
        else:
            passed += 1
            print(f"PASS  {name}")

    if not ours_path.is_file():
        report("ours_present", [f"{ours_path} does not exist"])
        print(f"\nResults: {passed} passed, {failed} failed, 0 skipped")
        return 1
    print(f"      sha256[:16] {fingerprint(ours_path)}")
    ours = load(ours_path, "ours")

    peer_root, how = locate_peer(self_root)
    peer_path = peer_root / FAMILIES_REL
    print(f"peer: {peer_path}  (from {how})")
    peer = None
    opted_out = os.environ.get(OPT_OUT_ENV, "").strip() == "1"
    if not peer_root.is_dir():
        if opted_out:
            print("!" * 72)
            print(f"WARNING: {OPT_OUT_ENV}=1 and no c64-https checkout at "
                  f"{peer_root}.")
            print("The cross-repo NET_FAMILY_* comparison is SKIPPED. This run "
                  "certifies NOTHING")
            print("about agreement with c64-https's copy; only our own file "
                  "was checked.")
            print("!" * 72)
            skipped = len(LOCAL_CHECKS) + len(CROSS_CHECKS)
        else:
            report("peer_present", [
                f"no c64-https checkout at {peer_root} ({how}), so our "
                f"NET_FAMILY_* bits are UNVERIFIED against the peer. Set "
                f"{PEER_ROOT_ENV}=/path/to/c64-https, or {OPT_OUT_ENV}=1 to "
                f"accept an unverified run"])
    elif not peer_path.is_file():
        report("peer_present", [
            f"c64-https checkout {peer_root} has no {FAMILIES_REL}: the peer "
            f"moved or deleted its copy of the family bits (not excused by "
            f"{OPT_OUT_ENV})"])
    else:
        print(f"      sha256[:16] {fingerprint(peer_path)}")
        peer = load(peer_path, "peer")
        report("peer_present", [])

    for name, msgs in run_checks(ours, peer):
        report(name, msgs)

    print("\nalarm proofs (in-process, temp copies of OUR file):")
    proofs = alarm_proofs(ours["text"], random.Random(seed))
    proofs_ok = 0
    for name, ok, detail in proofs:
        print(f"  {'ok    ' if ok else 'BROKEN'}  {name}: {detail}")
        proofs_ok += ok
    report(f"alarm_proofs ({proofs_ok}/{len(proofs)} fired as expected)",
           [] if proofs_ok == len(proofs) else
           [f"{len(proofs) - proofs_ok} proof(s) did not behave -- a check "
            f"that can no longer fire, or a survivor that went RED"])

    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped"
          + (f"  [{OPT_OUT_ENV}=1: peer comparison NOT run]" if skipped
             else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
