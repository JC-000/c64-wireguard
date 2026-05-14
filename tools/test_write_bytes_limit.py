#!/usr/bin/env python3
"""test_write_bytes_limit.py — Verify write_bytes works at all sizes up to 256.

After the auto-chunking fix in c64-test-harness, this should pass at all sizes.

Usage:
    python3 tools/test_write_bytes_limit.py [--iterations N]
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

TEST_ADDR = 0xC000


def flush_print(*args, **kwargs):
    print(*args, **kwargs, flush=True)


def main():
    os.chdir(PROJECT_ROOT)

    iterations = 5
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--iterations" and i < len(sys.argv) - 1:
            iterations = int(sys.argv[i + 1])

    # Build
    flush_print("Building...")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        flush_print(f"Build failed:\n{result.stderr}")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    flush_print("Starting VICE...")

    with ViceInstanceManager(
        config=config,
        port_range_start=6510,
        port_range_end=6530,
    ) as mgr:
        inst = mgr.acquire()
        flush_print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            flush_print("FATAL: Main menu did not appear")
            sys.exit(1)

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        flush_print(f"VICE ready. Test address: ${TEST_ADDR:04X}")

        # Test key sizes spanning the old truncation boundary (84) and up to 256
        test_sizes = [1, 16, 32, 64, 80, 84, 85, 88, 96, 100, 128, 160, 192, 224, 256]

        flush_print(f"Testing {len(test_sizes)} sizes x {iterations} iterations each\n")
        flush_print(f"{'Size':>5}  {'Pass':>5}/{iterations:<5}  Result")
        flush_print("-" * 35)

        total_pass = 0
        total_fail = 0

        for size in test_sizes:
            passes = 0
            fails = 0
            fail_info = None

            for it in range(iterations):
                pattern = bytes([(i + it * 37) & 0xFF for i in range(size)])
                write_bytes(transport, TEST_ADDR, pattern)
                readback = read_bytes(transport, TEST_ADDR, size)

                if readback == pattern:
                    passes += 1
                else:
                    fails += 1
                    if fail_info is None:
                        for j in range(min(len(readback), len(pattern))):
                            if readback[j] != pattern[j]:
                                fail_info = f"byte {j}: expected 0x{pattern[j]:02X}, got 0x{readback[j]:02X}"
                                break

            total_pass += passes
            total_fail += fails
            status = "OK" if fails == 0 else f"FAIL  {fail_info}"
            flush_print(f"{size:>5}  {passes:>5}/{iterations:<5}  {status}")

        flush_print("-" * 35)
        total = total_pass + total_fail
        flush_print(f"\nTotal: {total_pass}/{total} passed")
        if total_fail == 0:
            flush_print("All sizes pass with auto-chunking fix!")

        mgr.release(inst)

        sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
