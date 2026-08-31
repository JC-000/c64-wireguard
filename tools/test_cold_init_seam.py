#!/usr/bin/env python3
"""test_cold_init_seam.py — nothing in tools/ may CALL into the reclaimed
cold-init span.

Since #107, LIB_X25519_INIT_CODE is reclaimed as APP_BSS: boot.s zero-fills
the span once sqtab_init / mul_tables_init / reu_mul_init have run, so those
addresses hold $00 (BRK) for the rest of the program's life. Calling one is
neither a no-op nor a clean crash — it wedges the machine.

This trap has now caught three suites, every one created by copying a
working `jsr(transport, labels["reu_mul_init"], ...)` line out of a sibling
suite that predated #107:

    tools/test_type2_slow.py                    (removed in #103)
    tools/test_issue_95_handshake_recovery.py   (removed in #103)
    tools/test_issue_94_95_adversarial.py       (removed in #105)

Two details explain why careful authors kept shipping it, and both belong
here rather than only in issue #109:

  * `if "reu_mul_init" in labels:` returns **True**. The reclaim removes the
    code, not the symbol — it survives as a genuine link-time address in
    labels.txt. That guard reads as "only call this if the build has it",
    and every build satisfies it.

  * The entry point sits BELOW the APP_BSS boundary, so the `jsr` runs real
    instructions before falling into zeroed RAM. Measured on 04606f3 at
    REU=1: reu_mul_init = $87D1, APP_BSS starts $8800, so 47 bytes of
    surviving code execute first. (It was 69 bytes on b4ca1d8 — the figure
    moves with every relink, which is exactly why this check derives the
    span instead of quoting an address.) The machine hangs at an
    unpredictable point rather than faulting at the entry, and the symptom
    is `TimeoutError: No stopped event within 180.0s`, which names neither
    the symbol nor the cause.

WHAT THIS CHECKS: that no call site in tools/ executes an address inside the
span. Reading and writing those addresses is FINE and ubiquitous — the span
is overlaid by ordinary APP_BSS variables (hs_c, hs_packet, hs_sender_idx,
udp_recv_buf and more all live inside it), so a check for "references a
symbol in the span" would flag hundreds of correct lines and be turned off
within a day. The invariant is about execution, not reference.

The span comes from __LIB_X25519_INIT_CODE_LOAD__ and
__LIB_X25519_INIT_CODE_SIZE__ in labels.txt, never from a hardcoded address,
so it follows the segment whenever it moves.

Import-only and emulator-free: it parses source and reads labels.txt, so it
runs in milliseconds and fires at edit time — which is where it has to fire,
since every instance so far was born as a copy-paste.

WHY THERE IS NO RUNTIME GUARD TO GO WITH IT. The obvious place would be a
checking wrapper around jsr(), but 37 suites do `from c64_test_harness import
jsr` and call it directly, so a wrapper in tools/vice_util.py would guard only
the call sites that opted in — and a call site that opted in is one whose
author already knew. Guarding it for real means changing jsr() in the sibling
c64-test-harness package, and library changes in this project go through an
issue in the library's own repo rather than a local patch. That is worth
doing and is not this PR. Until then the static check is the whole defence,
which is the right way round anyway: it fires when the line is written rather
than the first time someone runs the suite on a REU build.

    python3 tools/test_cold_init_seam.py [--verbose]
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LABELS_PATH = PROJECT_ROOT / "build" / "labels.txt"
TOOLS_DIR = PROJECT_ROOT / "tools"

SPAN_LOAD = "__LIB_X25519_INIT_CODE_LOAD__"
SPAN_SIZE = "__LIB_X25519_INIT_CODE_SIZE__"

# Functions that EXECUTE their address argument on the C64, and which
# positional argument that is. Explicit rather than inferred: the analyser
# has to know jsr(t, a) runs `a` while read_bytes(t, a, n) merely reads it,
# and nothing in the name says so.
EXEC_FUNCS = {
    "jsr": 1,                 # c64_test_harness.jsr(transport, addr, ...)
    "call_capturing_a": 1,    # local trampoline helper of the same shape
}

VERBOSE = "--verbose" in sys.argv[1:]

passed = failed = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")
        for line in detail.splitlines():
            print(f"        {line}")


# ---------------------------------------------------------------------------
# labels.txt
# ---------------------------------------------------------------------------

def load_labels(path: Path) -> dict[str, int]:
    """Parse VICE label lines: `al C:89A4 .hs_packet`.

    NOTE the shape of the size export: the Makefile rewrites every value into
    the `C:xxxx` address form, so __LIB_X25519_INIT_CODE_SIZE__ arrives
    looking exactly like an address (`al C:033A`). It is a byte count. Read
    it as one; treating it as an address yields a span starting at $033A and
    a check that silently never matches anything.
    """
    out: dict[str, int] = {}
    pat = re.compile(r"^al C:([0-9a-fA-F]{4}) \.(\S+)\s*$")
    for line in path.read_text().splitlines():
        m = pat.match(line)
        if m:
            out[m.group(2)] = int(m.group(1), 16)
    return out


# ---------------------------------------------------------------------------
# source analysis
# ---------------------------------------------------------------------------

def _label_name_from_node(node: ast.AST) -> str | None:
    """Recover the label name an expression resolves to, if it plainly does.

    Handles the two forms every suite uses, without caring what the labels
    object is called:

        <anything>["name"]
        <anything>.address("name") / .get("name")
    """
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("address", "get") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
    return None


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local variable -> label name for simple `x = labels["n"]` binds.

    Covers the common indirection (`addr = labels["reu_mul_init"]` then
    `jsr(t, addr)`). Deliberately flow-insensitive: a name rebound twice is
    reported under both, which over-reports rather than under-reports.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) \
                else [node.target]
            name = _label_name_from_node(node.value) if node.value else None
            if not name:
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    aliases[t.id] = name
    return aliases


def _guarded_by_presence_test(node: ast.AST, parents: dict) -> bool:
    """True if this call sits under an `if "sym" in labels:`-style test.

    Only affects the message: the guard is satisfied by every build, so it
    never makes the call safe. Saying so at the failure is the difference
    between a reader fixing the bug and a reader trusting the guard.
    """
    cur = node
    while cur in parents:
        parent = parents[cur]
        if isinstance(parent, ast.If):
            dumped = ast.dump(parent.test)
            if "Compare" in dumped and "In(" in dumped:
                return True
            if "address" in dumped or "'get'" in dumped:
                return True
        cur = parent
    return False


def find_exec_sites(source: str) -> list[tuple[int, str, str, bool]]:
    """Return (lineno, func_name, label_name, presence_guarded) per call that
    executes a label-derived address."""
    tree = ast.parse(source)
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    aliases = _collect_aliases(tree)
    sites: list[tuple[int, str, str, bool]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = getattr(node.func, "id", getattr(node.func, "attr", None))
        if fname not in EXEC_FUNCS:
            continue
        idx = EXEC_FUNCS[fname]
        if len(node.args) <= idx:
            continue
        arg = node.args[idx]
        name = _label_name_from_node(arg)
        if name is None and isinstance(arg, ast.Name):
            name = aliases.get(arg.id)
        if name is None:
            continue
        sites.append((node.lineno, fname, name,
                      _guarded_by_presence_test(node, parents)))
    return sites


# ---------------------------------------------------------------------------
# the check itself
# ---------------------------------------------------------------------------

def violations_in(source: str, lo: int, hi: int, labels: dict[str, int]):
    """Execution sites whose target address falls inside [lo, hi)."""
    out = []
    for lineno, fname, label, guarded in find_exec_sites(source):
        addr = labels.get(label)
        if addr is not None and lo <= addr < hi:
            out.append((lineno, fname, label, addr, guarded))
    return out


def describe(path_label: str, v) -> str:
    lineno, fname, label, addr, guarded = v
    msg = (f"{path_label}:{lineno}  {fname}(..., {label}) "
           f"-> ${addr:04X} is inside the reclaimed span")
    if guarded:
        msg += ("\n  the `in labels` / .address() guard around this returns "
                "True: #107 removed the CODE, not the symbol")
    return msg


# ---------------------------------------------------------------------------
# self-test: the check must be seen to fail
# ---------------------------------------------------------------------------

# The synthetic sources are BUILT from symbols this link actually has, not
# written with `reu_mul_init` baked in. That name exists only in the REU
# profile: under REU=0 the segment holds sqtab_init / mul_tables_init and
# nothing else, so a hardcoded mutant resolved to no address, was correctly
# not flagged, and the self-test failed on a build with nothing wrong with
# it. Measured — that is not a hypothetical. A self-test that red-lights on
# half the builds trains people to ignore it, which is worse than not having
# one, and it is the same "derive, do not hardcode" rule the span itself
# follows.

MUTANT_TMPL = """
def main(transport, labels):
    if "{sym}" in labels:
        jsr(transport, labels["{sym}"], timeout=180.0)
"""

MUTANT_ALIASED_TMPL = """
def main(transport, labels):
    addr = labels["{sym}"]
    jsr(transport, addr, timeout=180.0)
"""

CONTROL_READ_TMPL = """
def main(transport, labels):
    read_bytes(transport, labels["{sym}"], 2)
    write_bytes(transport, labels["{sym}"], b"\\x00")
"""

CONTROL_OUTSIDE_TMPL = """
def main(transport, labels):
    jsr(transport, labels["{sym}"], timeout=60.0)
"""


def _pick_symbols(lo: int, hi: int, labels: dict[str, int]):
    """One symbol inside the span and one outside, chosen from this link.

    Inside: prefer a real cold-init entry point by name so the self-test
    reads like the bug it models; fall back to the lowest-addressed symbol
    in the span, which is the segment start and therefore always a code
    entry rather than an overlaid variable.
    """
    inside = sorted((a, n) for n, a in labels.items()
                    if lo <= a < hi and not n.startswith("__"))
    if not inside:
        return None, None
    preferred = [n for a, n in inside
                 if n in ("reu_mul_init", "sqtab_init", "mul_tables_init")]
    in_sym = preferred[0] if preferred else inside[0][1]

    for cand in ("session_handle_packet", "timer_check", "blake2s_init"):
        addr = labels.get(cand)
        if addr is not None and not (lo <= addr < hi):
            return in_sym, cand
    out = [n for n, a in sorted(labels.items())
           if not (lo <= a < hi) and not n.startswith("__")]
    return in_sym, (out[0] if out else None)


def self_test(lo: int, hi: int, labels: dict[str, int]) -> None:
    """A check nobody has watched fail is not yet a check.

    These run the real analyser against synthetic sources on every run, so
    the red half cannot rot the way a one-off manual demonstration does. The
    two controls are what stop the check from degenerating into "flag
    everything": if the read control ever failed, the check would be
    condemning the hundreds of legitimate accesses to APP_BSS variables that
    share these addresses.
    """
    print("\n=== self-test: the analyser detects what it exists to detect ===")

    in_sym, out_sym = _pick_symbols(lo, hi, labels)
    check("a symbol inside the span exists to build the self-test from",
          in_sym is not None,
          "the span resolved but contains no symbols — the check cannot "
          "prove itself, so treat its green as unverified")
    if in_sym is None:
        return
    print(f"  (in-span symbol: {in_sym} ${labels[in_sym]:04X}; "
          f"out-of-span: {out_sym})")

    v = violations_in(MUTANT_TMPL.format(sym=in_sym), lo, hi, labels)
    check("mutant: guarded jsr into the span is flagged", len(v) == 1,
          "the analyser did not flag the exact shape that bit three suites")
    if v:
        check("mutant: the useless presence guard is reported", v[0][4],
              "the message must say the `in labels` guard is always True")

    v = violations_in(MUTANT_ALIASED_TMPL.format(sym=in_sym), lo, hi, labels)
    check("mutant: jsr through a local alias is flagged", len(v) == 1,
          "addr = labels[...] then jsr(t, addr) must not slip past")

    v = violations_in(CONTROL_READ_TMPL.format(sym=in_sym), lo, hi, labels)
    check("control: reading an address in the span is NOT flagged",
          len(v) == 0,
          "the span is overlaid by live APP_BSS variables; flagging reads "
          "would condemn hundreds of correct lines")

    if out_sym:
        v = violations_in(CONTROL_OUTSIDE_TMPL.format(sym=out_sym), lo, hi,
                          labels)
        check("control: jsr to a symbol outside the span is NOT flagged",
              len(v) == 0,
              "only the reclaimed span is out of bounds")


# ---------------------------------------------------------------------------

def main() -> int:
    if not LABELS_PATH.exists():
        print(f"FAIL  {LABELS_PATH} not found — build first "
              f"(this check reads the span from the link, not from a "
              f"hardcoded address)")
        return 1

    labels = load_labels(LABELS_PATH)
    lo = labels.get(SPAN_LOAD)
    size = labels.get(SPAN_SIZE)

    print("=== reclaimed cold-init span ===")
    if lo is None or size is None:
        # USE_X25519_SIBLING=0 links no such segment, so there is nothing to
        # reclaim and nothing to protect. Report it rather than passing mute:
        # a silent pass here is indistinguishable from a check that has
        # stopped resolving its own symbols.
        print(f"  NOTE  {SPAN_LOAD}/{SPAN_SIZE} absent from labels.txt — "
              f"no cold segment in this link, nothing to check")
        print("\nResults: 0/0 passed, 0 failed")
        return 0

    hi = lo + size
    print(f"  ${lo:04X}-${hi - 1:04X}  ({size} bytes), from {SPAN_LOAD} "
          f"+ {SPAN_SIZE}")
    if VERBOSE:
        inside = sorted((a, n) for n, a in labels.items()
                        if lo <= a < hi and not n.startswith("__"))
        print(f"  {len(inside)} symbols resolve inside it "
              f"(code entry points AND overlaid APP_BSS variables):")
        for a, n in inside:
            print(f"    ${a:04X}  {n}")

    print("\n=== tools/ call sites ===")
    scanned = 0
    all_bad: list[str] = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        # This file is NOT skipped. The mutants are `.format()` templates
        # whose placeholder resolves to no real label, so they cannot
        # self-flag — verified — and skipping would leave the one file most
        # likely to grow a real call site unscanned.
        try:
            source = path.read_text()
        except OSError as exc:
            all_bad.append(f"{path.name}: unreadable ({exc})")
            continue
        try:
            bad = violations_in(source, lo, hi, labels)
        except SyntaxError as exc:
            all_bad.append(f"{path.name}: does not parse ({exc})")
            continue
        scanned += 1
        for v in bad:
            all_bad.append(describe(f"tools/{path.name}", v))

    check(f"no tools/*.py call site executes an address in the span "
          f"({scanned} files scanned)",
          not all_bad,
          "\n".join(all_bad) + (
              "\n\nSince #107 these addresses hold $00 (BRK) after boot. "
              "The call does not fail cleanly — it hangs, because the entry "
              "sits below the APP_BSS boundary and runs surviving code "
              "first. Delete the call: there is no build in which it is "
              "needed." if all_bad else ""))

    self_test(lo, hi, labels)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
