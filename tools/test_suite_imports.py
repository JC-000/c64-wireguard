#!/usr/bin/env python3
"""test_suite_imports.py — every tools/test_*.py must still IMPORT.

No rig, no emulator, no build. Milliseconds.

WHY THIS EXISTS
===============

tools/test_ip65_listener_leak.py imported ``bpf_capture_available`` from
``c64_test_harness.backends.vice_lifecycle``. The harness DELETED that name
in c3fe7aa ("ask whether VICE can get rawnet, not whether /dev/bpf* is
open"). The import is top-level, so the file died at import — before
argparse, before its preflight, before its first assertion — and it stayed
dead with nothing reporting it. It is not in run_regression.py's list (it
is rig-only), so the gate was never falsely green; the suite was simply
orphaned. It was also the ONLY suite covering listen/close/re-listen
ownership, over exactly the window in which #120's fix changed those paths.

A suite that raises ImportError before its first line is indistinguishable
from a suite with nothing to say. That is the failure this catches, and it
needs no hardware to catch — which is why the rig-only suites cannot be in
the gate but this check can.

WHAT IT DOES
============

Imports every ``tools/test_*.py`` as a module (importlib, no execution of
any main()) and fails on ImportError, a missing symbol, or any other
exception raised at import time. A file is only ever SKIPPED for a reason
it states out loud — a genuinely optional third-party dependency — never
for anything that looks like our own breakage.

IMPORT-TIME SIDE EFFECTS: guarded three ways. ``__name__`` is not
``"__main__"``, so no suite runs its main(). ``sys.argv`` is replaced with
a bare program name for the duration, so a module doing argparse at import
cannot see this runner's flags. And the import happens in a SUBPROCESS, one
per suite, so a module that starts a thread, opens a socket, spawns VICE or
calls sys.exit() at import cannot damage this process or the ones after it.

THE ALARM PROOF is --self-check: it writes a temporary suite that imports a
name the harness does not have, confirms this checker reports it, and
deletes it again. Run it and you know the detector fires.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)

#: Third-party modules a suite may legitimately not have installed. A
#: ModuleNotFoundError naming one of these is a SKIP with the reason
#: printed; anything else, including a missing name inside a module that
#: does exist, is a failure. Deliberately short: our own modules and the
#: harness are never optional.
OPTIONAL_DEPS = {"cryptography", "serial", "pytest", "numpy"}

#: One-liner run in a subprocess: import the file at *path* as a module.
_CHILD = """\
import importlib.util, sys, os
sys.argv = ["import-probe"]
sys.path.insert(0, {tools!r})
spec = importlib.util.spec_from_file_location("_probe_" + {stem!r}, {path!r})
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
"""


def suite_files() -> list[str]:
    return sorted(
        os.path.join(TOOLS_DIR, f)
        for f in os.listdir(TOOLS_DIR)
        if f.startswith("test_") and f.endswith(".py")
        and f != os.path.basename(__file__)
    )


def probe(path: str, timeout: float = 60.0) -> tuple[str, str]:
    """Import *path* in a subprocess. Returns (verdict, detail).

    verdict is "ok", "skip" or "fail".
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    code = _CHILD.format(tools=TOOLS_DIR, stem=stem, path=path)
    try:
        r = subprocess.run([sys.executable, "-c", code], cwd=PROJECT_ROOT,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "fail", (f"import did not finish in {timeout:.0f}s — a suite "
                        "must not block at import time")
    if r.returncode == 0:
        return "ok", ""
    err = (r.stderr or r.stdout).strip()
    last = err.splitlines()[-1] if err else f"exit {r.returncode}"
    # A missing OPTIONAL third-party package is the one tolerated outcome,
    # and only when the module name is on the list. "No module named
    # 'c64_test_harness'" is a real failure, not a skip.
    if "ModuleNotFoundError" in last:
        name = last.split("'")[1] if "'" in last else ""
        root = name.split(".")[0]
        if root in OPTIONAL_DEPS:
            return "skip", f"optional dependency {root!r} not installed"
    return "fail", err[-1500:]


def self_check() -> int:
    """Alarm proof: a suite importing a deleted symbol MUST be reported."""
    print("=== self-check: does the detector fire? ===")
    path = os.path.join(TOOLS_DIR, "test_zz_import_alarm_probe.py")
    if os.path.exists(path):
        print(f"FAIL: {path} already exists; refusing to overwrite")
        return 1
    with open(path, "w") as fh:
        fh.write("from c64_test_harness.backends.vice_lifecycle import "
                 "bpf_capture_available  # deleted in c3fe7aa\n")
    try:
        verdict, detail = probe(path)
    finally:
        os.unlink(path)
    if verdict != "fail":
        print(f"FAIL: the checker said {verdict!r} for a file importing a "
              "name the harness deleted — it would not have caught the "
              "listener-leak breakage either")
        return 1
    head = detail.splitlines()[-1] if detail else ""
    print(f"  PASS  reported as fail: {head}")
    print("  the detector fires; a dead import cannot hide from it")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-check", action="store_true",
                    help="prove the detector fires, then exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.self_check:
        return self_check()

    files = suite_files()
    print(f"=== importing {len(files)} tools/test_*.py suites ===")
    failures: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    for path in files:
        name = os.path.basename(path)
        verdict, detail = probe(path)
        if verdict == "ok":
            if args.verbose:
                print(f"  ok    {name}")
        elif verdict == "skip":
            skipped.append((name, detail))
            print(f"  SKIP  {name}: {detail}")
        else:
            failures.append((name, detail))
            print(f"  FAIL  {name}")

    print("")
    if skipped:
        print(f"{len(skipped)} suite(s) skipped for a stated optional "
              f"dependency.")
    if failures:
        for name, detail in failures:
            print(f"--- {name} ---")
            for line in detail.splitlines()[-12:]:
                print(f"    {line}")
        print("")
        print(f"FAIL: {len(failures)} of {len(files)} suites cannot be "
              "imported.")
        print("A suite that raises at import time never runs a single "
              "assertion, and looks exactly like a suite with nothing to "
              "say. Fix the import; do not delete the suite.")
        return 1
    print(f"All {len(files) - len(skipped)} importable suites imported "
          f"cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
