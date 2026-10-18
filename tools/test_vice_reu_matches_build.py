#!/usr/bin/env python3
"""test_vice_reu_matches_build.py — every gate VICE suite must boot the PRG on
a machine that matches the build: an REU attached iff the build uses one
(issue #69).

THE DEFECT. The gate builds with plain `make`, and `Makefile` has
`REU ?= 1`, so every pooled suite loads the REU profile. Before this suite,
24 of the 33 gate suites that start VICE did so WITHOUT `-reu`. Measured
2026-10-18 on master d4431ab, REU=1 PRG booted under VICE with no REU:

    boot_ready = $01, x25519_reu_fault = $02   (VERIFY ERROR seen by the
                                                 §8.2 settle in reu_mul_init)
    x25519_scalarmult (RFC 7748 vector 1) = 5cf4f2af..., expected c3da5537...
                                                 fault afterwards $03

and with `-reu -reusize 512`: fault $00, vector matches. So a machine without
an REU boots normally and then computes WRONG X25519 results with no other
symptom. Every one of the 24 suites happened to pass because none of them
reaches an REU-backed multiply (measured: the fault byte read just before
each suite's VICE instance was torn down was $02 in all 24, never with bit 0
set — bit 0 is what an REU fetch on the missing REU records). That is luck,
not coverage: the next suite that adds one handshake gets silently wrong
crypto and a confusing failure two layers up.

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
     suite may spell "-reu"/"-reusize" itself. The scanner is proven able to
     fire on synthetic sources (S0) and to find real sites (positive control)
     before its verdict on the tree counts.
  D  Derivation, on synthetic label maps: banks 0 -> no REU; $3B -> 512 KiB;
     legacy in-tree build (no manifest, reu_mul_init present) -> REU; nothing
     to go on -> refuse.
  R  Runtime, in VICE, on the gate's own build: booting with the derived
     arguments must give x25519_reu_fault == 0, and booting with the OPPOSITE
     attachment must make binary_wait_for_boot_ready raise. The second arm is
     the alarm proof, run every time rather than trusted from a report. On an
     REU=0 build there is no REU path that can fault, so that arm reports N/A
     (and says so) instead of passing.

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
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == BOOT_FN:
                has_boot_wait = True
            if name == "ViceConfig":
                vice_sites.append(node.lineno)
                kw = next((k for k in node.keywords if k.arg == "extra_args"), None)
                if kw is None:
                    bad.append((node.lineno, "no extra_args (REU attachment not derived)"))
                elif not any(isinstance(n, ast.Call) and _call_name(n) == DERIVE_FN
                             for n in ast.walk(kw.value)):
                    bad.append((node.lineno, f"extra_args does not call {DERIVE_FN}()"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.strip() in FORBIDDEN_LITERALS:
                literal_hits.append(node.lineno)
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


# --------------------------------------------------------------- runtime ---
def runtime_checks(chk: Check):
    print("R   runtime, gate build: derived attachment boots clean; opposite refuses")
    from c64_test_harness import (Labels, ViceConfig, ViceInstanceManager,
                                  read_bytes)
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

    def boot(extra):
        cfg = ViceConfig(prg_path=str(PRG_PATH), warp=True, ntsc=True,
                         sound=False, extra_args=list(extra))
        with ViceInstanceManager(config=cfg) as mgr:
            inst = mgr.acquire()
            try:
                try:
                    r = vice_util.binary_wait_for_boot_ready(
                        inst.transport, labels, timeout=180.0)
                except vice_util.BootReuFault as exc:
                    return "refused", str(exc)
                if r is None:
                    return "timeout", None
                f = (read_bytes(inst.transport, fault_addr, 1)[0]
                     if fault_addr is not None else None)
                return "booted", f
            finally:
                mgr.release(inst)

    state, val = boot(derived)
    chk.ok(state == "booted" and (val in (None, 0)),
           f"R1 derived attachment {derived or '(none)'}: boots, x25519_reu_fault == $00",
           f"state={state} value={val}")
    if derived:
        state, val = boot([])
        chk.ok(state == "refused",
               "R2 alarm proof: same REU build with NO REU -> boot wait refuses",
               f"state={state} value={val}")
        if state == "refused":
            print(f"        refusal text: {val}")
    else:
        print("  N/A   R2: REU=0 build — no REU path exists that could fault, so the "
              "refusal cannot be provoked here (not counted as a pass)")


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
