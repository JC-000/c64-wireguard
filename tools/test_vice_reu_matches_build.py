#!/usr/bin/env python3
"""test_vice_reu_matches_build.py — every gate VICE suite must boot the PRG on
a machine that matches the build: an REU attached iff the build uses one
(issue #69).

THE DEFECT. The gate builds with plain `make`, and `Makefile` has
`REU ?= 1`, so every pooled suite loads the REU profile. Before this suite,
24 of the 33 gate suites that start VICE did so WITHOUT `-reu`. Measured
2026-10-18 on master d4431ab, REU=1 PRG booted under VICE with no REU:

    boot_ready = $01, x25519_reu_fault = $02   ($DF00 bit 5 seen by the §8.2
                                                 settle in reu_mul_init — with
                                                 no REU, an open-bus read)
    x25519_scalarmult (RFC 7748 vector 1) = 5cf4f2af..., expected c3da5537...
                                                 fault afterwards $03

and with `-reu -reusize 512`: fault $00, vector matches. So a machine without
an REU boots normally and then computes WRONG X25519 results with no other
symptom. Every one of the 24 suites happened to pass because none of them
executes the REU multiply path — measured by planting BRK at fe25519_mul,
fe25519_sqr, reu_fetch_mul_row, reu_fetch_doubled_row and reu_clear_wide
right after boot, running each suite with its master gate arguments, and
reading the plants back intact at teardown; all 24 still passed, while the
fe25519 control derailed on the first plant. (The fault byte is NOT a usable
"was the REU touched" instrument: bit 0 is a settle-spin timeout and bit 1 a
$DF00 bit-5 sample, and on open bus a fetch need set neither — 8 random
fe25519_mul calls with no REU were all wrong with the byte staying $02.) That
is luck, not coverage: the next suite that adds one handshake gets silently
wrong crypto and a confusing failure two layers up.

THE FIX this suite holds in place, in two parts:

  * tools/vice_util.vice_reu_args(labels) derives the VICE REU arguments from
    the BUILT image — the contract §5 manifest equates
    LIB_X25519_REU_BANKS_USED / LIB_CHACHA20_POLY1305_REU_BANKS_USED in
    labels.txt — instead of a literal each suite copied. An REU=0 (onchip)
    build gets no REU, so a stray REU access there is not masked either.
  * tools/vice_util.binary_wait_for_boot_ready REFUSES (raises
    BootReuFault) when the booted image reports a non-zero x25519_reu_fault.
    This is a host-side check: nothing is added to the PRG (the boot halt in
    b49f50b was declined for its 25 B of APP_DATA).

WHAT THIS CHECKS:

  S  Static, over every file TESTS + SERIAL_TESTS name. The set of files that
     construct a ViceConfig must EQUAL the set whose every ViceConfig gets
     extra_args from vice_reu_args(...) AND that call
     binary_wait_for_boot_ready — reported both ways, per call site. No gate
     suite may spell "-reu"/"-reusize" itself. It fails CLOSED on the ways
     around a checked ViceConfig call: an `as` alias, ViceConfig used as a
     value (`VC = ViceConfig`, functools.partial), getattr by name,
     `cfg.extra_args = ...`, extra_args handed to any other callable
     (dataclasses.replace), a wrapper around vice_reu_args(...), and
     ViceProcess / EthVice / an "x64sc" string. The scanner is proven able to
     fire on synthetic sources (S0) and to find real sites (positive control)
     before its verdict on the tree counts.
  D  Derivation, on synthetic label maps: banks 0 -> no REU; $3B -> 512 KiB;
     legacy in-tree build (no manifest, reu_mul_init present) -> REU; nothing
     to go on -> refuse.
  R  Runtime, in VICE, on the gate's own build: booting with the derived
     arguments must give x25519_reu_fault == 0 AND compute RFC 7748 vector 1
     correctly (R1); booting with NO REU must make binary_wait_for_boot_ready
     raise (R2); booting with the next REU size DOWN must miscompute (R3).
     The fault byte is necessary but NOT sufficient: an REU that is present
     but too small boots with $00 (its high banks alias the low ones —
     measured at 128 and 256 KiB in review), which is why R1 runs the vector
     and R3 proves that check can see a wrong size. R2 and R3 are alarm
     proofs, run every time rather than trusted from a report. On an REU=0
     build there is no REU path that can fault or alias, so they report N/A
     (and say so) instead of passing.

    python3 tools/test_vice_reu_matches_build.py [--static-only] [--verbose]
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
PRG_PATH = PROJECT_ROOT / "build" / "wireguard.prg"
LABELS_PATH = PROJECT_ROOT / "build" / "labels.txt"
sys.path.insert(0, str(TOOLS_DIR))

VERBOSE = "--verbose" in sys.argv[1:]
STATIC_ONLY = "--static-only" in sys.argv[1:]

DERIVE_FN = "vice_reu_args"
BOOT_FN = "binary_wait_for_boot_ready"
FORBIDDEN_LITERALS = {"-reu", "-reusize", "+reu"}
# Ways to start VICE that bypass ViceConfig's extra_args entirely.
RAW_LAUNCHERS = {"ViceProcess", "EthVice"}

# The ONLY gate file allowed to start VICE on a non-derived attachment: this
# one, whose R2 arm deliberately boots the OPPOSITE attachment to prove the
# refusal fires. Each entry must still name a gate file (S0e).
EXEMPT = {
    "tools/test_vice_reu_matches_build.py":
        "R2 boots the opposite REU attachment on purpose (alarm proof)",
}


class Check:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, cond, what, detail=""):
        if cond:
            self.passed += 1
            print(f"  PASS  {what}")
        else:
            self.failed += 1
            print(f"  FAIL  {what}")
            if detail:
                for line in str(detail).splitlines():
                    print(f"        {line}")
        return cond


# ---------------------------------------------------------------- static ---
def _call_name(node):
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def scan_source(src: str, filename: str = "<src>"):
    """Return (vice_sites, bad_sites, has_boot_wait, literal_hits).

    vice_sites: line numbers of every ViceConfig(...) call.
    bad_sites:  (line, reason) for each site whose extra_args does not come
                from a vice_reu_args(...) call.
    literal_hits: line numbers of string constants spelling an REU flag.
    """
    tree = ast.parse(src, filename)
    vice_sites, bad, literal_hits = [], [], []
    has_boot_wait = False
    # Names ViceConfig is reachable under in this file (`import ... as VC`).
    cfg_names = {"ViceConfig"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "ViceConfig" and a.asname:
                    cfg_names.add(a.asname)
    call_funcs = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    docstrings = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                          ast.ClassDef)) and n.body:
            first = n.body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == BOOT_FN:
                has_boot_wait = True
            if name in RAW_LAUNCHERS:
                # Starts VICE without a ViceConfig the scanner could check.
                vice_sites.append(node.lineno)
                bad.append((node.lineno, f"{name}() starts VICE outside a checked "
                                         f"ViceConfig"))
            if name in cfg_names:
                vice_sites.append(node.lineno)
                kw = next((k for k in node.keywords if k.arg == "extra_args"), None)
                if kw is None:
                    bad.append((node.lineno, "no extra_args (REU attachment not derived)"))
                elif not (isinstance(kw.value, ast.Call)
                          and _call_name(kw.value) == DERIVE_FN):
                    # Exactly the call, nothing wrapped around it: a slice,
                    # a conditional or a concatenation could discard or
                    # override what it derived.
                    bad.append((node.lineno, f"extra_args is not exactly "
                                             f"{DERIVE_FN}(...)"))
            # extra_args handed to ANY other callable (dataclasses.replace,
            # functools.partial(ViceConfig, ...)) must also be exactly derived.
            if name not in cfg_names:
                for k in node.keywords:
                    if k.arg == "extra_args" and not (
                            isinstance(k.value, ast.Call)
                            and _call_name(k.value) == DERIVE_FN):
                        vice_sites.append(node.lineno)
                        bad.append((node.lineno, f"extra_args passed to {name or '?'}()"
                                                 f" is not exactly {DERIVE_FN}(...)"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.strip() in FORBIDDEN_LITERALS:
                literal_hits.append(node.lineno)
            if id(node) not in docstrings and (
                    node.value == "ViceConfig" or "x64sc" in node.value):
                # getattr(mod, "ViceConfig") or a hand-rolled x64sc launch.
                vice_sites.append(node.lineno)
                bad.append((node.lineno, f"string {node.value[:30]!r} reaches VICE "
                                         f"around the checked ViceConfig path"))
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr == "extra_args":
                    vice_sites.append(node.lineno)
                    bad.append((node.lineno, "extra_args assigned after "
                                             "construction"))
        elif (isinstance(node, ast.Name) and node.id in cfg_names
              and isinstance(node.ctx, ast.Load) and id(node) not in call_funcs):
            # ViceConfig used as a VALUE (VC = ViceConfig, partial(ViceConfig))
            vice_sites.append(node.lineno)
            bad.append((node.lineno, f"{node.id} used as a value, not called "
                                     f"directly"))
    literal_hits = sorted(set(literal_hits))
    return vice_sites, bad, has_boot_wait, literal_hits


def gate_suite_files():
    spec = importlib.util.spec_from_file_location(
        "run_regression", TOOLS_DIR / "run_regression.py")
    rr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rr)
    files = []
    for _name, cmd in list(rr.TESTS) + list(rr.SERIAL_TESTS):
        path = PROJECT_ROOT / cmd[0]
        if path.name == "run_regression.py":
            continue
        if path not in files:
            files.append(path)
    return files


def static_checks(chk: Check):
    print("S0  scanner self-test (it must be able to fire before its verdict counts)")
    good = ("from vice_util import vice_reu_args, binary_wait_for_boot_ready\n"
            "c = ViceConfig(prg_path=P, extra_args=vice_reu_args(labels))\n"
            "binary_wait_for_boot_ready(t, labels)\n")
    no_extra = "c = ViceConfig(prg_path=P)\nbinary_wait_for_boot_ready(t, l)\n"
    literal = ("c = ViceConfig(prg_path=P, extra_args=['-reu', '-reusize', '512'])\n"
               "binary_wait_for_boot_ready(t, l)\n")
    no_wait = "c = ViceConfig(prg_path=P, extra_args=vice_reu_args(l))\n"
    s, b, w, lit = scan_source(good)
    chk.ok(s == [2] and not b and w and not lit, "S0a compliant source passes",
           f"sites={s} bad={b} wait={w} lit={lit}")
    s, b, w, lit = scan_source(no_extra)
    chk.ok(len(b) == 1, "S0b ViceConfig without extra_args is flagged", f"bad={b}")
    s, b, w, lit = scan_source(literal)
    chk.ok(len(b) == 1 and lit, "S0c hardcoded -reu literal is flagged", f"bad={b} lit={lit}")
    s, b, w, lit = scan_source(no_wait)
    chk.ok(not w, "S0d missing boot wait is detected", f"wait={w}")
    # Bypasses found by adversarial review of this suite's first draft.
    bypasses = [
        ("S0f aliased import (ViceConfig as VC) is still a site",
         "from c64_test_harness import ViceConfig as VC\nc = VC(prg_path=P)\n"),
        ("S0g derived args discarded by a slice are flagged",
         "c = ViceConfig(prg_path=P, extra_args=vice_reu_args(l)[:0])\n"),
        ("S0h derived args overridden by a conditional are flagged",
         "c = ViceConfig(prg_path=P, extra_args=[] if vice_reu_args(l) else [])\n"),
        ("S0i ViceProcess launch is flagged",
         "p = ViceProcess(cfg)\n"),
        ("S0j EthVice rig launch is flagged",
         "r = EthVice(prg, labels, reu=False)\n"),
        ("S0k extra_args assigned after construction is flagged",
         "cfg = make()\ncfg.extra_args = []\n"),
        ("S0l dataclasses.replace(cfg, extra_args=[]) is flagged",
         "cfg2 = dataclasses.replace(cfg, extra_args=[])\n"),
        ("S0m functools.partial(ViceConfig, ...) is flagged",
         "mk = functools.partial(ViceConfig, warp=True)\n"),
        ("S0n alias by assignment (VC = ViceConfig) is flagged",
         "VC = ViceConfig\n"),
        ("S0o getattr(mod, 'ViceConfig') is flagged",
         "VC = getattr(h, 'ViceConfig')\n"),
        ("S0p subprocess launching x64sc is flagged",
         "subprocess.Popen(['x64sc', '-warp', prg])\n"),
    ]
    for what, src in bypasses:
        s, b, w, lit = scan_source(src)
        chk.ok(bool(s) and len(b) == 1, what, f"sites={s} bad={b}")

    print("S   gate suites: REU attachment derived from the build, at every site")
    files = gate_suite_files()
    constructs, compliant = set(), set()
    detail = []
    rels = {str(p.relative_to(PROJECT_ROOT)) for p in files}
    stale = sorted(set(EXEMPT) - rels)
    chk.ok(not stale, f"S0e every exemption names a gate file ({sorted(EXEMPT)})",
           f"stale exemptions: {stale}")
    for path in files:
        rel = str(path.relative_to(PROJECT_ROOT))
        if rel in EXEMPT:
            continue
        src = path.read_text()
        sites, bad, has_wait, lits = scan_source(src, rel)
        if not sites:
            if lits:
                detail.append(f"{rel}: REU flag literal at line(s) {lits}")
            continue
        constructs.add(rel)
        problems = [f"{rel}:{ln}: {why}" for ln, why in bad]
        if not has_wait:
            problems.append(f"{rel}: starts VICE but never calls {BOOT_FN}() "
                            f"(the boot-time REU-fault refusal lives there)")
        if lits:
            problems.append(f"{rel}: REU flag literal at line(s) {lits} — use {DERIVE_FN}()")
        if problems:
            detail.extend(problems)
        else:
            compliant.add(rel)
        if VERBOSE:
            print(f"        {rel}: sites={sites} ok={not problems}")
    # Positive control: the scanner must find the suites we KNOW start VICE.
    known = {"tools/test_fe25519.py", "tools/test_x25519.py", "tools/test_transport.py"}
    chk.ok(known <= constructs, "S1 scanner finds the known VICE suites (positive control)",
           f"missing: {sorted(known - constructs)}")
    chk.ok(len(constructs) >= 30, f"S2 scanned {len(constructs)} gate suites that start VICE "
           f"(of {len(files)} gate files)")
    chk.ok(constructs == compliant and not detail,
           "S3 set(gate suites starting VICE) == set(suites deriving REU args + boot wait)",
           "not compliant: " + ", ".join(sorted(constructs - compliant)) + "\n" + "\n".join(detail))


# ------------------------------------------------------------ derivation ---
def derivation_checks(chk: Check):
    print("D   vice_reu_args derivation (synthetic label maps)")
    try:
        from vice_util import vice_reu_args
    except ImportError as exc:
        chk.ok(False, "D0 tools/vice_util.py exports vice_reu_args", repr(exc))
        return
    cases = [
        ("D1 REU=0 build (both manifests 0) -> no REU",
         {"LIB_X25519_REU_BANKS_USED": 0, "LIB_CHACHA20_POLY1305_REU_BANKS_USED": 0}, []),
        ("D2 REU=1 build (x25519 banks $3B: 0,1,3,4,5) -> 512 KiB",
         {"LIB_X25519_REU_BANKS_USED": 0x3B, "LIB_CHACHA20_POLY1305_REU_BANKS_USED": 0},
         ["-reu", "-reusize", "512"]),
        ("D3 boundary: highest bank 3 (256 KiB exactly) -> 256",
         {"LIB_X25519_REU_BANKS_USED": 0x08}, ["-reu", "-reusize", "256"]),
        ("D4 boundary: highest bank 4 (320 KiB) -> 512",
         {"LIB_X25519_REU_BANKS_USED": 0x10}, ["-reu", "-reusize", "512"]),
        ("D5 chacha-only banks count too",
         {"LIB_X25519_REU_BANKS_USED": 0, "LIB_CHACHA20_POLY1305_REU_BANKS_USED": 0x01},
         ["-reu", "-reusize", "128"]),
        ("D6 legacy in-tree build (no manifest, reu_mul_init) -> REU",
         {"reu_mul_init": 0x4822, "boot_ready": 0x908F}, ["-reu", "-reusize", "512"]),
    ]
    for what, labels, want in cases:
        try:
            got = vice_reu_args(labels)
        except Exception as exc:                                  # noqa: BLE001
            got = f"raised {exc!r}"
        chk.ok(got == want, what, f"got {got}, want {want}")
    try:
        got = vice_reu_args({"boot_ready": 0x908F})
        chk.ok(False, "D7 no manifest and no REU code -> refuse", f"returned {got}")
    except ValueError:
        chk.ok(True, "D7 no manifest and no REU code -> refuse")
    # A relocated bank (X25519_REU_BANK >= 11) pushes the mask above $FFFF and
    # the Makefile drops it from labels.txt; the other manifest symbols stay.
    # That must refuse, not fall back to the legacy 512 KiB guess.
    try:
        got = vice_reu_args({"reu_mul_init": 0x87D1,
                             "LIB_X25519_RESIDENT_BYTES": 0x213A})
        chk.ok(False, "D8 sibling build with its mask dropped -> refuse",
               f"returned {got}")
    except ValueError:
        chk.ok(True, "D8 sibling build with its mask dropped -> refuse")


# --------------------------------------------------------------- runtime ---
VECTORS_PATH = PROJECT_ROOT / "test" / "rfc7748_vectors.json"


def runtime_checks(chk: Check):
    print("R   runtime, gate build: derived attachment boots clean AND computes "
          "X25519 correctly; no REU refuses; an undersized REU miscomputes")
    import json
    from c64_test_harness import (Labels, ViceConfig, ViceInstanceManager,
                                  jsr, read_bytes, write_bytes)
    import vice_util
    if not hasattr(vice_util, "vice_reu_args") or not hasattr(vice_util, "BootReuFault"):
        chk.ok(False, "R0 vice_util provides vice_reu_args and BootReuFault")
        return
    if not PRG_PATH.exists() or not LABELS_PATH.exists():
        chk.ok(False, "R0 gate build present", f"missing {PRG_PATH} or {LABELS_PATH}")
        return
    labels = Labels.from_file(str(LABELS_PATH))
    derived = vice_util.vice_reu_args(labels)
    fault_addr = labels.address("x25519_reu_fault")
    print(f"        build needs REU: {bool(derived)} (args {derived}); "
          f"x25519_reu_fault @ {fault_addr and hex(fault_addr)}")
    vec = json.loads(VECTORS_PATH.read_text())["x25519_scalarmult"][0]
    scalar = bytearray(bytes.fromhex(vec["scalar"]))
    scalar[0] &= 0xF8
    scalar[31] = (scalar[31] & 0x7F) | 0x40
    u = bytes.fromhex(vec["u_coordinate"])
    expected = bytes.fromhex(vec["expected"])

    def boot(extra, kat):
        """-> (state, fault byte, KAT result bytes or None)."""
        cfg = ViceConfig(prg_path=str(PRG_PATH), warp=True, ntsc=True,
                         sound=False, extra_args=list(extra))
        with ViceInstanceManager(config=cfg) as mgr:
            inst = mgr.acquire()
            t = inst.transport
            try:
                try:
                    r = vice_util.binary_wait_for_boot_ready(t, labels, timeout=180.0)
                except vice_util.BootReuFault as exc:
                    return "refused", str(exc), None
                if r is None:
                    return "timeout", None, None
                f = (read_bytes(t, fault_addr, 1)[0]
                     if fault_addr is not None else None)
                got = None
                if kat:
                    write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))
                    write_bytes(t, labels["x25_scalar"], bytes(scalar))
                    write_bytes(t, labels["x25_u"], u)
                    jsr(t, labels["x25519_scalarmult"], timeout=1800.0)
                    got = read_bytes(t, labels["x25_result"], 32)
                return "booted", f, got
            finally:
                mgr.release(inst)

    # R1: the fault byte alone is NOT sufficient — an REU that is present but
    # too small also boots with $00 (its high banks alias the low ones; review
    # of this suite measured 128 and 256 KiB: fault $00, vector 1 wrong). So
    # the derived attachment must also COMPUTE the RFC 7748 vector.
    state, val, got = boot(derived, kat=True)
    chk.ok(state == "booted" and val in (None, 0) and got == expected,
           f"R1 derived attachment {derived or '(none)'}: boots, fault $00, "
           f"RFC 7748 vector 1 correct",
           f"state={state} fault={val} got={got.hex() if got else got} "
           f"want={expected.hex()}")
    if not derived:
        print("  N/A   R2/R3: REU=0 build — no REU path exists that could fault or "
              "alias, so neither alarm can be provoked here (not counted as a pass)")
        return
    # R2: the alarm for the fault-byte refusal.
    state, val, _ = boot([], kat=False)
    chk.ok(state == "refused",
           "R2 alarm proof: same REU build with NO REU -> boot wait refuses",
           f"state={state} value={val}")
    if state == "refused":
        print(f"        refusal text: {val}")
    # R3: the next VICE size DOWN from the derived one must miscompute. This is
    # what makes R1's KAT a check on the SIZE (not just on presence), and it is
    # the boundary vice_reu_args' rounding has to get right.
    size = int(derived[derived.index("-reusize") + 1])
    smaller = size // 2
    if smaller < 128:
        print(f"  N/A   R3: derived size {size} KiB is VICE's smallest")
        return
    state, val, got = boot(["-reu", "-reusize", str(smaller)], kat=True)
    chk.ok(state == "refused" or (state == "booted" and got != expected),
           f"R3 alarm proof: one size down ({smaller} KiB) gives a wrong vector "
           f"(or is refused)",
           f"state={state} fault={val} got={got.hex() if got else got}")
    print(f"        {smaller} KiB: state={state} fault={val} "
          f"vector={'MATCH' if got == expected else 'mismatch'}")


def main() -> int:
    chk = Check()
    static_checks(chk)
    derivation_checks(chk)
    if not STATIC_ONLY:
        runtime_checks(chk)
    total = chk.passed + chk.failed
    print(f"\nResults: {chk.passed}/{total} passed")
    return 0 if chk.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
