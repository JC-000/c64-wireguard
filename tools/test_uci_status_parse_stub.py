#!/usr/bin/env python3
"""test_uci_status_parse_stub.py -- VICE-side unit test for the UCI STATUS
leading-code parser (issue #72).

The refused-socket-open path (uci_udp_connect surfacing UCI_ERR_OPEN_REFUSED
when the firmware posts `85,ERROR OPENING SOCKET` on the $DF1F STATUS channel)
is HARDWARE-ONLY: VICE does not emulate the Ultimate Command Interface, so it
cannot reproduce the firmware refusal itself. What IS backend-independent and
therefore testable in VICE is the pure ASCII-to-byte parse at the heart of that
decision: uci_status_leading_code, which reads uci_status_buf[0..1] ("NN") and
returns A = NN as a byte with Z=1 iff the code is "00" (OK).

This test loads status-line prefixes into uci_status_buf and jsr()s the parser
directly, proving:
  - "00" -> A=0,  Z=1  (OK, uci_udp_connect proceeds to read the socket_id)
  - "85" -> A=85, Z=0  (refusal -> UCI_ERR_OPEN_REFUSED)
  - other real firmware codes parse to their decimal value
  - a non-digit prefix yields a non-zero (fail-safe: never mistaken for "00")

Usage:
    python3 tools/test_uci_status_parse_stub.py

Env:
    C64_SKIP_BUILD=1   skip `make BACKEND=uci`
"""

import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

TRAMP_ADDR = 0x0340
RESULT_ADDR = 0x0360   # byte: parser's returned A
ZFLAG_ADDR = 0x0361    # byte: 1 if parser returned Z=1 ("00"), else 0

# (status prefix ASCII, expected decimal code, expected Z==1)
CASES = [
    (b"00,OK",                      0,  True),
    (b"85,ERROR OPENING SOCKET",   85,  False),
    (b"82,PARAMETER(S) OUT OF RANGE", 82, False),
    (b"04,DATAGRAM TRUNCATED: 1420", 4,  False),
    (b"10,SOMETHING",              10,  False),
    # Fail-safe: a non-digit prefix must NOT parse as "00". '?'=0x3F, '0'=0x30
    # so ('?'-'0')=0x0F; whatever the arithmetic yields it must be non-zero
    # (Z=0) so a malformed status is treated as a refusal, never as OK.
    (b"??,GARBAGE",              None,  False),
]


def build():
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set -- skipping build")
        return
    result = subprocess.run(
        ["make", "BACKEND=uci"],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)


def call_parser(transport, parser_addr):
    """jsr the parser; capture returned A and its Z flag into known cells.

    STA does not disturb processor flags, so the Z produced by the parser's
    final ADC survives the `STA result` and is read by the BEQ below.
    """
    lo = parser_addr & 0xFF
    hi = (parser_addr >> 8) & 0xFF
    r_lo, r_hi = RESULT_ADDR & 0xFF, (RESULT_ADDR >> 8) & 0xFF
    z_lo, z_hi = ZFLAG_ADDR & 0xFF, (ZFLAG_ADDR >> 8) & 0xFF
    tramp = bytes([
        0x20, lo, hi,          # JSR uci_status_leading_code
        0x8D, r_lo, r_hi,      # STA RESULT_ADDR      (flags preserved)
        0xF0, 0x06,            # BEQ +6 -> @zero (PC after this insn is +8)
        0xA9, 0x00,            # LDA #$00             (Z was clear)
        0x8D, z_lo, z_hi,      # STA ZFLAG_ADDR
        0x60,                  # RTS
        # @zero:
        0xA9, 0x01,            # LDA #$01             (Z was set)
        0x8D, z_lo, z_hi,      # STA ZFLAG_ADDR
        0x60,                  # RTS
    ])
    write_bytes(transport, TRAMP_ADDR, tramp)
    write_bytes(transport, RESULT_ADDR, bytes([0xEE]))  # sentinels
    write_bytes(transport, ZFLAG_ADDR, bytes([0xEE]))
    jsr(transport, TRAMP_ADDR, timeout=5.0)
    a = read_bytes(transport, RESULT_ADDR, 1)[0]
    z = read_bytes(transport, ZFLAG_ADDR, 1)[0]
    return a, z


def run_tests(transport, labels):
    passed = failed = 0
    parser = labels["uci_status_leading_code"]
    status_buf = labels["uci_status_buf"]

    for prefix, want_code, want_zero in CASES:
        write_bytes(transport, status_buf, prefix)
        a, z = call_parser(transport, parser)
        z_ok = (z == 1) == want_zero
        code_ok = (want_code is None) or (a == want_code)
        # Fail-safe cases only assert non-zero.
        if want_code is None:
            code_ok = a != 0
        if z_ok and code_ok:
            print(f"PASS {prefix.split(b',')[0].decode():>2} -> "
                  f"A={a} (0x{a:02X}), Z={z}")
            passed += 1
        else:
            print(f"FAIL {prefix!r}: got A={a} (0x{a:02X}), Z={z}; "
                  f"want code={want_code}, zero={want_zero}")
            failed += 1

    return passed, failed


def main():
    os.chdir(PROJECT_ROOT)
    build()

    labels = Labels.from_file(LABELS_PATH)
    required = ["uci_status_leading_code", "uci_status_buf"]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing exported label(s): {', '.join(missing)}")
        print("Hint: was the PRG built with BACKEND=uci?")
        sys.exit(1)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        grid = binary_wait_for_boot_ready(transport, labels, timeout=180.0)
        if grid is None:
            print("FATAL: main menu did not appear")
            mgr.release(inst)
            sys.exit(1)

        # Park the CPU harmlessly after any jsr() returns.
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed = run_tests(transport, labels)
        mgr.release(inst)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
