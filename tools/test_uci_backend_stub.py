#!/usr/bin/env python3
"""test_uci_backend_stub.py -- VICE-side UCI backend error-path test.

VICE does not emulate the Ultimate Command Interface. $DF1D will not
read back $C9 (UCI_ID_VALUE), so net_init must fail with C=1 and
net_last_error = UCI_ERR_NOT_PRESENT ($81). This test proves the
detection + error-reporting path of src/net/uci/net.s is wired
correctly: the probe returns a "not present" verdict rather than
hanging, and the error code is surfaced to the caller.

Usage:
    python3 tools/test_uci_backend_stub.py

Env:
    C64_SKIP_BUILD=1   skip `make clean && make BACKEND=uci`
"""

import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Per src/net/uci/uci_errors.inc. The linker's -Ln label listing exports
# only labels carrying `.export`, so this constant is not resolvable
# from labels.txt -- hardcoded here and kept in sync manually.
UCI_ERR_NOT_PRESENT = 0x81

# Scratch area for the carry-capture trampoline. $0340 is past jsr()'s
# own trampoline at $0334 and well below $0400 screen RAM.
TRAMP_ADDR = 0x0340
CARRY_ADDR = 0x0360  # byte written by the trampoline: 1 = C set, 0 = C clear


def build():
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set -- skipping build")
        return
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    result = subprocess.run(
        ["make", "BACKEND=uci"],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)


def call_net_init_capture_carry(transport, net_init_addr):
    """Call net_init via a trampoline that stores the carry flag.

    Returns (carry: int 0|1). jsr() returns a register dict whose status-
    register key varies across VICE builds ("FL" vs "SR"), so instead of
    relying on that we use the same pattern as tools/test_phase7.py:
    emit 6502 that BCC's over "LDA #1" to "LDA #0" and stores the result
    in a known memory cell.
    """
    lo = net_init_addr & 0xFF
    hi = (net_init_addr >> 8) & 0xFF
    c_lo = CARRY_ADDR & 0xFF
    c_hi = (CARRY_ADDR >> 8) & 0xFF
    tramp = bytes([
        0x20, lo, hi,        # JSR net_init
        0x90, 0x06,          # BCC +6 -> @clear
        0xA9, 0x01,          # LDA #$01
        0x8D, c_lo, c_hi,    # STA $0360
        0x60,                # RTS
        # @clear:
        0xA9, 0x00,          # LDA #$00
        0x8D, c_lo, c_hi,    # STA $0360
        0x60,                # RTS
    ])
    write_bytes(transport, TRAMP_ADDR, tramp)
    write_bytes(transport, CARRY_ADDR, bytes([0xFF]))  # sentinel != 0,1
    jsr(transport, TRAMP_ADDR, timeout=5.0)
    return read_bytes(transport, CARRY_ADDR, 1)[0]


def run_tests(transport, labels):
    passed = failed = 0
    net_init = labels["net_init"]
    net_last_error = labels["net_last_error"]
    uci_socket_id = labels["uci_socket_id"]
    # uci_socket_open is defined with .res 1 immediately after uci_socket_id
    # in src/net/uci/net.s but is not .export'd, so it's absent from the
    # -Ln label file. Address it by positional offset from uci_socket_id.
    uci_socket_open = uci_socket_id + 1

    # --- Test 1: net_init without UCI hardware returns C=1 and sets error
    write_bytes(transport, net_last_error, b"\x00")
    carry = call_net_init_capture_carry(transport, net_init)
    err = read_bytes(transport, net_last_error, 1)[0]
    sid = read_bytes(transport, uci_socket_id, 1)[0]
    sopen = read_bytes(transport, uci_socket_open, 1)[0]
    if carry == 1 and err == UCI_ERR_NOT_PRESENT and sid == 0 and sopen == 0:
        print(f"PASS Test 1: net_init -> C=1, err=${err:02X}, "
              f"socket_id={sid}, socket_open={sopen}")
        passed += 1
    else:
        print(f"FAIL Test 1: C={carry} (want 1), err=${err:02X} "
              f"(want ${UCI_ERR_NOT_PRESENT:02X}), "
              f"socket_id={sid} (want 0), socket_open={sopen} (want 0)")
        failed += 1

    # --- Test 2: repeated net_init is idempotent (no deadlock, same result)
    carries = []
    errs = []
    for _ in range(3):
        write_bytes(transport, net_last_error, b"\x00")
        carries.append(call_net_init_capture_carry(transport, net_init))
        errs.append(read_bytes(transport, net_last_error, 1)[0])
    if carries == [1, 1, 1] and errs == [UCI_ERR_NOT_PRESENT] * 3:
        print(f"PASS Test 2: 3x net_init idempotent, "
              f"C={carries}, err={[f'${e:02X}' for e in errs]}")
        passed += 1
    else:
        print(f"FAIL Test 2: C={carries} (want [1,1,1]), "
              f"err={[f'${e:02X}' for e in errs]} "
              f"(want 3x ${UCI_ERR_NOT_PRESENT:02X})")
        failed += 1

    # --- Test 3: net_last_error label holds the correct byte
    final_err = read_bytes(transport, net_last_error, 1)
    if final_err == bytes([UCI_ERR_NOT_PRESENT]):
        print(f"PASS Test 3: net_last_error byte == ${UCI_ERR_NOT_PRESENT:02X}")
        passed += 1
    else:
        print(f"FAIL Test 3: net_last_error={final_err.hex()} "
              f"(want {UCI_ERR_NOT_PRESENT:02x})")
        failed += 1

    return passed, failed


def main():
    os.chdir(PROJECT_ROOT)
    build()

    labels = Labels.from_file(LABELS_PATH)
    required = ["net_init", "net_last_error", "uci_socket_id"]
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

        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("FATAL: main menu did not appear")
            mgr.release(inst)
            sys.exit(1)

        # Safety loop: JMP $0339 at $0339 so the CPU parks harmlessly
        # after any jsr() returns (BASIC ROM is banked out).
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        passed, failed = run_tests(transport, labels)
        mgr.release(inst)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
