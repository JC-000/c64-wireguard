#!/usr/bin/env python3
"""bench_fe_ops.py — Benchmark fe_mul and fe_sqr timing on C64.

Measures jiffy clock ticks for fe_mul and fe_sqr with random field elements.
Since the wireguard PRG has no bench_start/bench_stop helpers, we inject a
small 6502 timing subroutine into the cassette buffer ($0334).

Usage:
    python3 tools/bench_fe_ops.py [--iterations N]
"""

import os
import random
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, load_code,
)
from vice_util import binary_wait_for_text

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

P = (1 << 255) - 19

# Jiffy clock zero-page locations (big-endian: $A0=MSB, $A1, $A2=LSB)
JIFFY_MSB = 0xA0
JIFFY_MID = 0xA1
JIFFY_LSB = 0xA2

# We store the captured jiffy clock at $03C0 (well within cassette buffer)
RESULT_ADDR = 0x03C0

# Our timing subroutine lives at $0350 (avoids $0334 which jsr() uses)
TIMER_ADDR = 0x0350

# jsr() trampoline scratch at default $0334
JSR_SCRATCH = 0x0334

# Safety loop at $0339 (after menu appears, prevents main loop interference)
SAFETY_LOOP_ADDR = 0x0339


def int_to_le32(val):
    return (val % P).to_bytes(32, "little")


def build_timer_subroutine(target_addr):
    """Build a 6502 subroutine that times a JSR to target_addr.

    Layout at $0334:
        SEI                 ; 78
        LDA #$00            ; A9 00
        STA $A0             ; 85 A0
        STA $A1             ; 85 A1
        STA $A2             ; 85 A2
        CLI                 ; 58
        JSR target          ; 20 lo hi
        SEI                 ; 78
        LDA $A0             ; A5 A0
        STA $03C0           ; 8D C0 03
        LDA $A1             ; A5 A1
        STA $03C1           ; 8D C1 03
        LDA $A2             ; A5 A2
        STA $03C2           ; 8D C2 03
        CLI                 ; 58
        RTS                 ; 60
    """
    lo = target_addr & 0xFF
    hi = (target_addr >> 8) & 0xFF
    return bytes([
        0x78,                   # SEI
        0xA9, 0x00,             # LDA #$00
        0x85, JIFFY_MSB,        # STA $A0
        0x85, JIFFY_MID,        # STA $A1
        0x85, JIFFY_LSB,        # STA $A2
        0x58,                   # CLI
        0x20, lo, hi,           # JSR target
        0x78,                   # SEI
        0xA5, JIFFY_MSB,        # LDA $A0
        0x8D, RESULT_ADDR & 0xFF, (RESULT_ADDR >> 8) & 0xFF,  # STA $03C0
        0xA5, JIFFY_MID,        # LDA $A1
        0x8D, (RESULT_ADDR + 1) & 0xFF, ((RESULT_ADDR + 1) >> 8) & 0xFF,  # STA $03C1
        0xA5, JIFFY_LSB,        # LDA $A2
        0x8D, (RESULT_ADDR + 2) & 0xFF, ((RESULT_ADDR + 2) >> 8) & 0xFF,  # STA $03C2
        0x58,                   # CLI
        0x60,                   # RTS
    ])


def read_result_ticks(transport):
    """Read the 3-byte jiffy clock result from RESULT_ADDR."""
    data = read_bytes(transport, RESULT_ADDR, 3)
    return (data[0] << 16) | (data[1] << 8) | data[2]


def bench_fe_mul(transport, labels, a, b):
    """Time a single fe_mul call in jiffy ticks."""
    write_bytes(transport, labels["fe_tmp1"], int_to_le32(a))
    write_bytes(transport, labels["fe_tmp2"], int_to_le32(b))
    write_bytes(transport, labels["fe_src1"],
                bytes([labels["fe_tmp1"] & 0xFF, (labels["fe_tmp1"] >> 8) & 0xFF]))
    write_bytes(transport, labels["fe_src2"],
                bytes([labels["fe_tmp2"] & 0xFF, (labels["fe_tmp2"] >> 8) & 0xFF]))
    write_bytes(transport, labels["fe_dst"],
                bytes([labels["fe_tmp3"] & 0xFF, (labels["fe_tmp3"] >> 8) & 0xFF]))

    # Load and run timer subroutine for fe_mul
    code = build_timer_subroutine(labels["fe_mul"])
    load_code(transport, TIMER_ADDR, code)
    jsr(transport, TIMER_ADDR, timeout=120.0)
    return read_result_ticks(transport)


def bench_fe_sqr(transport, labels, a):
    """Time a single fe_sqr call in jiffy ticks."""
    write_bytes(transport, labels["fe_tmp1"], int_to_le32(a))
    write_bytes(transport, labels["fe_src1"],
                bytes([labels["fe_tmp1"] & 0xFF, (labels["fe_tmp1"] >> 8) & 0xFF]))
    write_bytes(transport, labels["fe_dst"],
                bytes([labels["fe_tmp3"] & 0xFF, (labels["fe_tmp3"] >> 8) & 0xFF]))

    code = build_timer_subroutine(labels["fe_sqr"])
    load_code(transport, TIMER_ADDR, code)
    jsr(transport, TIMER_ADDR, timeout=120.0)
    return read_result_ticks(transport)


def main():
    os.chdir(PROJECT_ROOT)

    iterations = 5
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--iterations" and i + 1 < len(args):
            iterations = int(args[i + 1])
            i += 2
        else:
            i += 1

    seed = 25519
    rng = random.Random(seed)

    labels = Labels.from_file(LABELS_PATH)

    # Verify required labels exist
    required = ["fe_mul", "fe_sqr", "fe_tmp1", "fe_tmp2", "fe_tmp3",
                "fe_src1", "fe_src2", "fe_dst"]
    for name in required:
        if name not in labels:
            print(f"FATAL: label '{name}' not found in {LABELS_PATH}")
            sys.exit(1)

    print(f"fe_mul = ${labels['fe_mul']:04X}")
    print(f"fe_sqr = ${labels['fe_sqr']:04X}")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport
        grid = binary_wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("Menu appeared, REU tables initialized.")

        # Install safety loop to prevent main loop from interfering
        write_bytes(transport, SAFETY_LOOP_ADDR, bytes([0x4C, 0x39, 0x03]))

        print(f"\n--- fe_mul benchmark ({iterations} iterations) ---")
        mul_ticks = []
        for i in range(iterations):
            a = rng.randint(1, P - 1)
            b = rng.randint(1, P - 1)
            ticks = bench_fe_mul(transport, labels, a, b)
            mul_ticks.append(ticks)
            ms = ticks * 1000 / 60  # NTSC: 60 Hz jiffy clock
            print(f"  fe_mul #{i}: {ticks} jiffies ({ms:.0f} ms)")

        avg_mul = sum(mul_ticks) / len(mul_ticks)
        print(f"  Average: {avg_mul:.1f} jiffies ({avg_mul * 1000 / 60:.0f} ms)")

        print(f"\n--- fe_sqr benchmark ({iterations} iterations) ---")
        sqr_ticks = []
        for i in range(iterations):
            a = rng.randint(1, P - 1)
            ticks = bench_fe_sqr(transport, labels, a)
            sqr_ticks.append(ticks)
            ms = ticks * 1000 / 60
            print(f"  fe_sqr #{i}: {ticks} jiffies ({ms:.0f} ms)")

        avg_sqr = sum(sqr_ticks) / len(sqr_ticks)
        print(f"  Average: {avg_sqr:.1f} jiffies ({avg_sqr * 1000 / 60:.0f} ms)")

        # Estimate full X25519 time
        # 255 ladder steps x (4 mul + 1 mul_a24 + 2 sqr + 4 add/sub) per step
        # + 1 inversion (~253 sqr + 11 mul)
        # Total: ~255*4 + 11 = 1031 muls, 255*2 + 253 = 763 sqrs
        est_muls = 1031
        est_sqrs = 763
        est_total = est_muls * avg_mul + est_sqrs * avg_sqr
        est_sec = est_total / 60  # NTSC
        print(f"\n--- Estimated full X25519 time ---")
        print(f"  {est_muls} muls x {avg_mul:.1f} + {est_sqrs} sqrs x {avg_sqr:.1f}")
        print(f"  = {est_total:.0f} jiffies = {est_sec:.0f}s = {est_sec / 60:.1f} min")

        mgr.release(inst)

    print("\nDone.")


if __name__ == "__main__":
    main()
