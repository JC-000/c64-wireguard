#!/usr/bin/env python3
"""Unit tests for tools/u64_firmware.py — the /v1/info build-identity check.

Host-side only: no device, no lock, no network (fetch_info is never called
here). What is worth testing is the JUDGEMENT, not the HTTP:

  * an unrecognised git_commit_hash must NOT be an error — the next
    legitimate rebase produces one, and a host-side allowlist that refuses
    it would block a good build;
  * firmware with no git_commit_hash at all must say so plainly rather
    than silently reading as "not the spike";
  * a measured image must be reported as measured.

Run::

    python3 tools/test_u64_firmware.py [--verbose]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from u64_firmware import KNOWN_BUILDS, VERDICTS, describe_build  # noqa: E402

# The image measured on 2026-09-03 (WARP interop, 4 handshakes ACTIVE).
INFO_A474 = {
    "product": "Ultimate 64 Elite",
    "firmware_version": "3.15",
    "git_commit_hash": "a474a7ed",
    "fpga_version": "125",
    "core_version": "1.4F",
    "unique_id": "601A96",
    "errors": [],
}

# The same device BEFORE upstream added the field (fpga 124 image).
INFO_NO_HASH = {
    "product": "Ultimate 64 Elite",
    "firmware_version": "3.15",
    "fpga_version": "124",
    "core_version": "1.4F",
    "unique_id": "601A96",
    "errors": [],
}


def _check(name, cond, detail, fails, verbose, _n=[0]):
    _n[0] += 1
    if cond:
        if verbose:
            print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}: {detail}")
        fails.append(name)
    return _n[0]


def main(argv) -> int:
    verbose = "--verbose" in argv
    fails: list = []

    # 1. A measured image reports as measured, and names the evidence.
    v, text = describe_build(INFO_A474)
    _check("measured image -> chunked", v == "chunked", f"got {v!r}", fails, verbose)
    _check("measured image names the hash", "a474a7ed" in text,
           f"hash absent from {text!r}", fails, verbose)

    # 2. An unknown hash is a WARNING, not a refusal. This is the one that
    #    matters: the next rebase lands here, and refusing it would be worse
    #    than running and letting the $16 send path decide.
    v, text = describe_build(dict(INFO_A474, git_commit_hash="deadbeef"))
    _check("unknown hash -> unknown", v == "unknown", f"got {v!r}", fails, verbose)
    _check("unknown hash is not an error", v != "unreachable" and v in VERDICTS,
           f"got {v!r}", fails, verbose)
    _check("unknown hash points at the behavioural check", "$8E" in text,
           f"no $8E hint in {text!r}", fails, verbose)

    # 3. Firmware predating the field must say so, NOT read as "not spike".
    v, text = describe_build(INFO_NO_HASH)
    _check("missing field -> no-hash", v == "no-hash", f"got {v!r}", fails, verbose)
    _check("missing field names the $16 probe as the only way",
           "$03 $16" in text, f"no probe hint in {text!r}", fails, verbose)

    # 4. An empty string is missing, not a hash.
    v, _ = describe_build(dict(INFO_A474, git_commit_hash=""))
    _check("empty hash -> no-hash", v == "no-hash", f"got {v!r}", fails, verbose)

    # 5. No answer at all is distinguishable from every image verdict.
    v, _ = describe_build(None)
    _check("no info -> unreachable", v == "unreachable", f"got {v!r}", fails, verbose)

    # 6. Every recorded build carries a reason it is recorded.
    for h, (kind, detail) in KNOWN_BUILDS.items():
        _check(f"{h} records evidence", len(detail) > 40 and kind in VERDICTS,
               f"thin entry {detail!r}", fails, verbose)

    # Counted, not hardcoded: a check that stops running must not keep
    # inflating the total it is reported against.
    n = _check.__defaults__[0][0]
    if fails:
        print(f"FAIL: {len(fails)} of {n} checks failed: {', '.join(fails)}")
        return 1
    print(f"PASS: {n}/{n} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
