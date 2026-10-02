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
lines, compared as whitespace-normalised STRINGS and accepted only at their
positions: ``.ifndef`` and ``= 1`` as the first two code lines, ``.endif`` as
the last, each exactly once (a second guard block after the real ``.endif``
defines nothing ca65 will see). So ``NET_FAMILY_X=$1``,
``NET_FAMILY_X = $00G1``, a lowercase ``$000a``, a tab, ``:=``, ``.set``,
``.define``, an expression, a typo'd ``NET_FAMLY_X`` -- each fails, quoting
its file and line. A line the parser cannot read is never skipped.

The independent row count is the number of ``NET_FAMILY_`` tokens in the
comment-stripped text, counted with ``str.count`` -- not line-based, no
regex. It is NOT dominated by the parse: ``NET_FAMILY_ANET_FAMILY_B =
$0010`` matches the strict form but holds two tokens. It also guards the
parser itself (a loop that drops a row it matched). The nonzero half catches
a file whose guard lines parse but which defines nothing.

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

The peer must BE c64-https: it may not resolve to this tree, and it must
carry ``src/tls13.s`` (c64-https has it; c64-wireguard never has). Otherwise
a c64-wireguard worktree passed as the peer compares our file with itself.
Both are failures the opt-out does not excuse.

The peer's commit is recorded, offline (no fetch): ``git rev-parse HEAD``
(also on the ``Results:`` line), whether its families file is dirty, and how
far it is behind its upstream as of its last fetch. Dirty, behind, or not a
git checkout of its own is a loud WARNING, not a failure.

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

Every run also replays a mutation catalogue in-process, on in-memory
variants of our file (most fed in as the peer, one as ours): rename, every
one of the 16 bits flipped on every row, one-sided bits, non-single-bit and
shared values, boundary malformations, misplaced guard lines, an empty
file, a duplicate, a two-token name, a corrupted parser, and peer-identity
cases on throwaway directories. Each must turn the expected check RED and
name the bit or line; survivors (comment-only edit, reordered equates, a
genuine c64-https-shaped peer) must stay GREEN. Renamed/added names and the
malformed line's victim come from a seeded RNG, logged once (``--seed`` /
``TEST_SEED``); the value and single-bit proofs do not depend on the seed. A
proof that fails is a check that can no longer fire, and fails the run. If
our own file is red the proofs are not run (reported as NOT RUN).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent
SELF_ROOT_ENV = "NET_FAMILIES_PROJECT_ROOT"
PEER_ROOT_ENV = "C64_HTTPS_ROOT"
OPT_OUT_ENV = "C64_NO_PEER_REGISTRY"
FAMILIES_REL = Path("src") / "net" / "net_families.inc"

GUARD_OPEN = ".ifndef NET_FAMILIES_INC_INCLUDED"
GUARD_SET = "NET_FAMILIES_INC_INCLUDED = 1"
GUARD_END = ".endif"
GUARD_LINES = frozenset({GUARD_OPEN, GUARD_SET, GUARD_END})
PEER_MARKER = Path("src") / "tls13.s"
STRICT_EQUATE = re.compile(r"^(NET_FAMILY_[A-Z][A-Z0-9_]*) += +\$([0-9A-F]{4})$")
TOKEN = "NET_FAMILY_"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _code(raw):
    return raw.split(";", 1)[0].strip()


def parse(text, label):
    """(rows, bad). rows: [(lineno, name, value)]; bad: ['label:N: line'].

    The first two code lines must be GUARD_OPEN, GUARD_SET and the last
    GUARD_END; a guard line anywhere else, and every other code line that
    does not match STRICT_EQUATE, is reported, never skipped.
    """
    rows, bad = [], []
    code_lines = [(n, raw, _code(raw))
                  for n, raw in enumerate(text.splitlines(), 1) if _code(raw)]
    k = len(code_lines)
    slots = {0: GUARD_OPEN, 1: GUARD_SET, k - 1: GUARD_END} if k >= 3 else {}
    if k < 3:
        bad.append(f"{label}: {k} code line(s) -- no complete include guard "
                   f"({GUARD_OPEN!r}, {GUARD_SET!r} ... {GUARD_END!r})")
    for idx, want in sorted(slots.items()):
        n, raw, code = code_lines[idx]
        if " ".join(code.split()) != want:
            bad.append(f"{label}:{n}: expected {want!r} as code line "
                       f"{'#' + str(idx + 1) if idx < 2 else '(last)'}, "
                       f"got {raw.rstrip()!r}")
    for idx, (lineno, raw, code) in enumerate(code_lines):
        if idx in slots:
            continue
        if " ".join(code.split()) in GUARD_LINES:
            bad.append(f"{label}:{lineno}: include-guard line out of place: "
                       f"{raw.rstrip()!r}")
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


def peer_identity_problems(self_root, peer_root):
    """Failures if `peer_root` is this tree or is not a c64-https checkout."""
    out = []
    if (peer_root.resolve() == self_root.resolve()
            or (peer_root / FAMILIES_REL).resolve()
            == (self_root / FAMILIES_REL).resolve()):
        out.append(f"peer {peer_root} resolves to THIS tree ({self_root}): "
                   f"comparing our file with itself certifies nothing")
    if not (peer_root / PEER_MARKER).is_file():
        out.append(f"peer {peer_root} has no {PEER_MARKER}, so it is not a "
                   f"c64-https checkout (a c64-wireguard tree or worktree "
                   f"would compare our file with a copy of itself)")
    return out


def _git(root, *args):
    try:
        r = subprocess.run(["git", "-C", str(root), *args],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def peer_provenance(peer_root):
    """(short HEAD or None, info lines, warnings). Offline: never fetches."""
    top = _git(peer_root, "rev-parse", "--show-toplevel")
    if top is None or Path(top).resolve() != peer_root.resolve():
        return None, [], [f"peer {peer_root} is not the root of its own git "
                          f"checkout: the compared commit is UNRECORDED"]
    head = _git(peer_root, "rev-parse", "HEAD")
    branch = _git(peer_root, "rev-parse", "--abbrev-ref", "HEAD")
    info, warns = [f"peer HEAD {head} ({branch})"], []
    dirty = _git(peer_root, "status", "--porcelain", "--", str(FAMILIES_REL))
    if dirty:
        warns.append(f"peer {FAMILIES_REL} has uncommitted changes "
                     f"({dirty!r}): compared the working copy, not HEAD")
    up = _git(peer_root, "rev-parse", "--abbrev-ref",
              "--symbolic-full-name", "@{u}")
    if up:
        counts = _git(peer_root, "rev-list", "--left-right", "--count",
                      f"HEAD...{up}")
        ahead, behind = (int(x) for x in counts.split())
        info.append(f"peer vs {up} as of its last fetch (none done here): "
                    f"{ahead} ahead, {behind} behind")
        if behind:
            warns.append(f"peer is {behind} commit(s) BEHIND {up} (as of its "
                         f"last fetch): this run compared an OLD c64-https")
    else:
        info.append("peer has no upstream configured: staleness unknown")
    return head[:7], info, warns


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


def _identity_proofs(ours_text):
    out = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        roots = {}
        for name, marker in [("self", False), ("wg_worktree", False),
                             ("https", True)]:
            r = td / name
            (r / FAMILIES_REL).parent.mkdir(parents=True)
            (r / FAMILIES_REL).write_text(ours_text)
            if marker:
                (r / PEER_MARKER).write_text("; marker\n")
            roots[name] = r
        (td / "alias").symlink_to(roots["self"])
        for label, peer, needle in [
                ("peer is this tree", roots["self"], "THIS tree"),
                ("peer is a symlink to this tree", td / "alias", "THIS tree"),
                ("peer is a c64-wireguard copy", roots["wg_worktree"],
                 str(PEER_MARKER))]:
            msgs = peer_identity_problems(roots["self"], peer)
            out.append((f"identity: {label}",
                        any(needle in m for m in msgs),
                        "peer_is_c64_https: "
                        + (msgs[0] if msgs else "stayed GREEN")))
        msgs = peer_identity_problems(roots["self"], roots["https"])
        out.append(("survivor: c64-https-shaped peer", not msgs,
                    "all GREEN" if not msgs else f"went RED: {msgs[0]}"))
    return out


def alarm_proofs(ours_text, rng):
    """[(proof_name, ok, detail)], or None if our own file is red."""
    ours = load("OURS", "ours", ours_text)
    if any(m for _, m in run_checks(ours, load("PEER", "peer", ours_text))):
        return None
    base_rows = ours["rows"]
    lineno, victim, value = rng.choice(base_rows)
    used = {v for _, _, v in base_rows}
    free = next(1 << i for i in range(16) if (1 << i) not in used)
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    new_name = "NET_FAMILY_Z" + "".join(rng.choice(alpha) for _ in range(5))
    renamed = victim + "".join(rng.choice(alpha) for _ in range(3))
    added = f"{new_name} = ${free:04X}"
    last_line = base_rows[-1][0]
    end_line = max(n for n, raw in enumerate(ours_text.splitlines(), 1)
                   if _code(raw))

    def peer_mut(text):
        return load("PEER", "peer", text)

    # name, peer_text, ours_text, expected-red check, needle in its message
    cases = [
        ("rename", _replace_line(ours_text, lineno,
                                 f"{renamed} = ${value:04X}"), None,
         "names_only_in_ours", victim),
        ("rename(other dir)", _replace_line(ours_text, lineno,
                                            f"{renamed} = ${value:04X}"), None,
         "names_only_in_peer", renamed),
        ("bit only in peer", _insert_after(ours_text, last_line, added), None,
         "names_only_in_peer", new_name),
        ("bit only in ours", None, _insert_after(ours_text, last_line, added),
         "names_only_in_ours", new_name),
        ("duplicate in peer", _insert_after(
            ours_text, last_line, f"{victim} = ${value:04X}"), None,
         "peer_no_duplicates", victim),
        ("empty peer", f"{GUARD_OPEN}\n{GUARD_SET}\n{GUARD_END}\n", None,
         "peer_row_count", "ZERO"),
        ("two-token name", _insert_after(
            ours_text, last_line, f"NET_FAMILY_ANET_FAMILY_B = ${free:04X}"),
         None, "peer_row_count", f"parsed {len(base_rows) + 1} equate row(s) "
         f"but the file's code holds {len(base_rows) + 2}"),
        ("second guard block after .endif", _insert_after(
            _replace_line(ours_text, lineno, ""), end_line,
            f"{GUARD_OPEN}\n{victim} = ${value:04X}\n{GUARD_END}"), None,
         "peer_parses", "out of place"),
        (".if 0 around an equate", _insert_after(_insert_after(
            ours_text, lineno, GUARD_END), lineno - 1, ".if 0"), None,
         "peer_parses", ".if 0"),
        ("stray .ifdef line", _insert_after(
            ours_text, lineno, f".ifdef {victim}"), None,
         "peer_parses", ".ifdef"),
    ]
    # Single-bit proofs: deterministic, on the first and last rows.
    (l0, n0, v0), (l1, n1, v1) = base_rows[0], base_rows[-1]
    for label, line_no, text_line, needle in [
            ("two names, one value", l1, f"{n1} = ${v0:04X}", "claimed by"),
            ("$0000 value", l0, f"{n0} = $0000", f"{n0} = $0000 is not"),
            ("two-bit value $0003", l0, f"{n0} = $0003",
             f"{n0} = $0003 is not"),
            ("top bit plus one $8001", l1, f"{n1} = $8001",
             f"{n1} = $8001 is not")]:
        cases.append((f"single bits: {label}",
                      _replace_line(ours_text, line_no, text_line), None,
                      "peer_single_bits", needle))
    cases.append(("single bits: ours $0003", None,
                  _replace_line(ours_text, l0, f"{n0} = $0003"),
                  "ours_single_bits", f"{n0} = $0003 is not"))
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
        msgs = dict(run_checks(o, p)).get(want, [])
        ok = any(needle in m for m in msgs)
        out.append((name, ok, f"{want}: " + (msgs[0] if msgs
                                             else "stayed GREEN")))

    # Every one of the 16 bits flipped on every row: deterministic, so a
    # comparator or parser that sees only some bits fails on every run.
    missed = []
    for ln, name, v in base_rows:
        for bit in range(16):
            w = v ^ (1 << bit)
            msgs = check_values_agree(
                ours, peer_mut(_replace_line(ours_text, ln,
                                             f"{name} = ${w:04X}")))
            if not any(f"{name}: ours ${v:04X}, peer ${w:04X}" in m
                       for m in msgs):
                missed.append(f"{name} ${v:04X}->${w:04X}")
    total = 16 * len(base_rows)
    out.append((f"values: every bit flipped on every row ({total} flips)",
                not missed, f"values_agree caught {total - len(missed)}/"
                f"{total}" + (f"; missed {missed[:4]}" if missed else "")))

    # The independent count against a CORRUPTED parser.
    def lossy_run():
        o = load("OURS", "ours", ours_text)
        return dict(run_checks(o, load("PEER", "peer", ours_text)))
    msgs = _with_parser(lossy_run)["ours_row_count"]
    out.append(("parser drops a row", any("token" in m for m in msgs),
                "ours_row_count: " + (msgs[0] if msgs else "stayed GREEN")))

    out += _identity_proofs(ours_text)

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
        red = [(n, m) for n, m in run_checks(ours, peer_mut(ptext)) if m]
        out.append((name, not red,
                    "all GREEN" if not red else f"went RED: {red[0]}"))
    return out


def _banner(lines):
    print("!" * 72)
    for line in lines:
        print(f"WARNING: {line}")
    print("!" * 72)


# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=None,
                    help="seed for the alarm-proof mutations (or TEST_SEED)")
    args = ap.parse_args(argv)
    if args.seed is not None:
        seed = args.seed
    elif os.environ.get("TEST_SEED", "").strip():
        try:
            seed = int(os.environ["TEST_SEED"])
        except ValueError:
            ap.error(f"TEST_SEED must be an integer, got "
                     f"{os.environ['TEST_SEED']!r}")
    else:
        seed = random.randrange(2 ** 31)
    print(f"seed: {seed}  (reproduce with --seed {seed} or TEST_SEED={seed})")

    self_root = Path(os.environ.get(SELF_ROOT_ENV, DEFAULT_ROOT))
    ours_path = self_root / FAMILIES_REL
    print(f"ours: {ours_path}"
          + (f"  (from ${SELF_ROOT_ENV})" if os.environ.get(SELF_ROOT_ENV)
             else ""))
    passed = failed = skipped = 0
    peer_tag = "peer@none"

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
        print(f"\nResults: {passed} passed, {failed} failed, 0 skipped  "
              f"{peer_tag}")
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
            _banner([f"{OPT_OUT_ENV}=1 and no c64-https checkout at "
                     f"{peer_root}.",
                     "The cross-repo NET_FAMILY_* comparison is SKIPPED. This "
                     "run certifies NOTHING",
                     "about agreement with c64-https's copy; only our own "
                     "file was checked."])
            skipped = len(LOCAL_CHECKS) + len(CROSS_CHECKS)
        else:
            report("peer_present", [
                f"no c64-https checkout at {peer_root} ({how}), so our "
                f"NET_FAMILY_* bits are UNVERIFIED against the peer. Set "
                f"{PEER_ROOT_ENV}=/path/to/c64-https, or {OPT_OUT_ENV}=1 to "
                f"accept an unverified run"])
    elif peer_identity_problems(self_root, peer_root):
        report("peer_is_c64_https",
               peer_identity_problems(self_root, peer_root)
               + [f"(not excused by {OPT_OUT_ENV})"])
    elif not peer_path.is_file():
        report("peer_present", [
            f"c64-https checkout {peer_root} has no {FAMILIES_REL}: the peer "
            f"moved or deleted its copy of the family bits (not excused by "
            f"{OPT_OUT_ENV})"])
    else:
        print(f"      sha256[:16] {fingerprint(peer_path)}")
        short, info, warns = peer_provenance(peer_root)
        for line in info:
            print(f"      {line}")
        if warns:
            _banner(warns)
        peer_tag = f"peer@{short}" if short else "peer@not-a-git-checkout"
        if short and warns:
            peer_tag += "(WARN)"
        peer = load(peer_path, "peer")
        report("peer_present", [])

    for name, msgs in run_checks(ours, peer):
        report(name, msgs)

    print("\nalarm proofs (in-process, in-memory variants of our file):")
    proofs = alarm_proofs(ours["text"], random.Random(seed))
    if proofs is None:
        print("  NOT RUN: our own file is red (see the ours_* failures above), "
              "so no mutation of it proves anything")
    else:
        proofs_ok = 0
        for name, ok, detail in proofs:
            print(f"  {'ok    ' if ok else 'BROKEN'}  {name}: {detail}")
            proofs_ok += ok
        report(f"alarm_proofs ({proofs_ok}/{len(proofs)} fired as expected)",
               [] if proofs_ok == len(proofs) else
               [f"{len(proofs) - proofs_ok} proof(s) did not behave -- a "
                f"check that can no longer fire, or a survivor that went RED"])

    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped  "
          f"{peer_tag}"
          + (f"  [{OPT_OUT_ENV}=1: peer comparison NOT run]" if skipped
             else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
