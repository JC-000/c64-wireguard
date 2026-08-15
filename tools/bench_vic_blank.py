#!/usr/bin/env python3
"""bench_vic_blank.py — quantify the VIC-II blanking speedup on WG's crypto.

WHY THIS EXISTS

The VIC-II steals cycles from the 6510. On every "badline" (once per 8
raster lines while the display is enabled) it halts the CPU for ~40-43
cycles to fetch character/colour data, and sprite DMA steals more. Setting
DEN=0 in $D011 blanks the display and stops that theft outright, handing
the cycles back to the CPU. The c64-x25519 library ships `vic_blank` /
`vic_unblank` for exactly this and documents "~20-25%" (filed as c64-x25519#103) — but that is the
LIBRARY's number, measured on the library's own harness. This tool measures
it on WG's workload, on WG's build, so the claim in our docs is ours.

It matters here more than in most projects: a full WireGuard handshake is
~23 minutes of wall clock on hardware, and real `wg` peers time out long
before that. Every percent is a percent off a number that is already past
the point of usability.

WHAT IS MEASURED

Elapsed EMULATED time via the CIA1 TOD clock ($DC08-$DC0B). It is emulated
time, not host time, so VICE warp mode does not distort it — host wall
clock would be measuring the emulator, not the C64.

NOT the KERNAL jiffy clock at $A0-$A2, which is the obvious choice and is
WRONG for this job. The jiffy clock is advanced by the KERNAL's IRQ
handler, so it stops dead for any routine that masks interrupts — and
x25519_scalarmult does. Measured: a scalarmult that demonstrably ran
(19.7 s of host wall clock, correct RFC 7748 output) advanced the jiffy
clock by 1 tick. Both legs then "took" the same time and the benchmark
reported a confident, meaningless 1.000x. TOD is a hardware counter and
keeps running with I set, which is why this project already uses it for
interrupt-independent deadlines elsewhere.

TOD registers are BCD, and reading them uses a latch protocol: reading the
hours register latches the whole bank and reading tenths releases it, so
they must be read HR -> MIN -> SEC -> TENTHS in that order or the value
tears. That is why this is done by a 6502 routine rather than four
monitor peeks.

USAGE

    python3 tools/bench_vic_blank.py [--iterations N] [--quick] [--verbose]

    --quick   skip the X25519 scalarmult legs (~4.3 min emulated each);
              symmetric primitives only.
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

VERBOSE = False

# --- C64-side addresses -----------------------------------------------------
VIC_CTRL1 = 0xD011
DEN_BIT = 0x10

CIA1_TOD_TENTHS = 0xDC08
CIA1_CRB = 0xDC0F

# $C000-$CFFF is free RAM on a stock C64: not used by BASIC, not claimed by
# any WG segment (the image ends at $9FFF), and not the harness's own jsr
# scratch at $0334.
STUB = 0xC000           # repeat-loop stub
CNT_OUTER = 0xC020
CNT_INNER = 0xC021
TOD_START = 0xC030      # "zero and start TOD" routine
TOD_READ = 0xC050       # "latch and snapshot TOD" routine
TOD_RESULT = 0xC070     # 4 bytes: hr, min, sec, tenths (BCD)


def build_tod_start():
    """Zero CIA1 TOD and start it.

    Clearing $DC0F bit 7 selects TOD-write (not alarm-write) mode. Writing
    the hours register stops the clock; writing tenths restarts it. So the
    write order is the reverse of the read order.
    """
    return bytes([
        0xAD, 0x0F, 0xDC,        # lda $DC0F
        0x29, 0x7F,              # and #$7F      (bit7=0 -> write TOD)
        0x8D, 0x0F, 0xDC,        # sta $DC0F
        0xA9, 0x00,              # lda #$00
        0x8D, 0x0B, 0xDC,        # sta $DC0B     hours   (halts TOD)
        0x8D, 0x0A, 0xDC,        # sta $DC0A     minutes
        0x8D, 0x09, 0xDC,        # sta $DC09     seconds
        0x8D, 0x08, 0xDC,        # sta $DC08     tenths  (starts TOD)
        0x60,                    # rts
    ])


def build_tod_read():
    """Snapshot CIA1 TOD into TOD_RESULT as hr, min, sec, tenths.

    Order is load-bearing: reading $DC0B latches all four registers, and
    reading $DC08 releases the latch. Any other order returns a torn value
    that can straddle a second boundary.
    """
    r = TOD_RESULT
    return bytes([
        0xAD, 0x0B, 0xDC,                    # lda $DC0B  hours (latches)
        0x8D, r & 0xFF, (r >> 8) & 0xFF,     # sta TOD_RESULT+0
        0xAD, 0x0A, 0xDC,                    # lda $DC0A  minutes
        0x8D, (r + 1) & 0xFF, (r + 1) >> 8,  # sta TOD_RESULT+1
        0xAD, 0x09, 0xDC,                    # lda $DC09  seconds
        0x8D, (r + 2) & 0xFF, (r + 2) >> 8,  # sta TOD_RESULT+2
        0xAD, 0x08, 0xDC,                    # lda $DC08  tenths (releases)
        0x8D, (r + 3) & 0xFF, (r + 3) >> 8,  # sta TOD_RESULT+3
        0x60,                                # rts
    ])


def _bcd(b):
    return (b >> 4) * 10 + (b & 0x0F)


def read_tod_tenths(transport):
    """Elapsed tenths of a second since the last tod_start()."""
    jsr(transport, TOD_READ, timeout=10.0)
    hr, mn, sc, tn = read_bytes(transport, TOD_RESULT, 4)
    # Hours carries an AM/PM flag in bit 7; mask it. 12-hour BCD wraps to
    # 12 rather than 0, which does not matter over benchmark durations but
    # would silently add 12 h if it ever did.
    hours = _bcd(hr & 0x7F) % 12
    return ((hours * 60 + _bcd(mn)) * 60 + _bcd(sc)) * 10 + _bcd(tn & 0x0F)


def tod_start(transport):
    jsr(transport, TOD_START, timeout=10.0)


def build_loop_stub(target, outer, inner):
    """Assemble a call-N-times loop.

    Counters live in MEMORY, not X/Y, because every routine under test
    clobbers both. An earlier register-based version silently ran a
    different iteration count per leg, which is exactly the kind of error
    that produces a clean-looking but meaningless ratio.

        lda #outer / sta CNT_OUTER
    o:  lda #inner / sta CNT_INNER
    i:  jsr target
        dec CNT_INNER / bne i
        dec CNT_OUTER / bne o
        rts
    """
    lo, hi = target & 0xFF, (target >> 8) & 0xFF
    return bytes([
        0xA9, outer,                    # C000 lda #outer
        0x8D, CNT_OUTER & 0xFF, 0xC0,   # C002 sta CNT_OUTER
        0xA9, inner,                    # C005 lda #inner      <- outer loop
        0x8D, CNT_INNER & 0xFF, 0xC0,   # C007 sta CNT_INNER
        0x20, lo, hi,                   # C00A jsr target      <- inner loop
        0xCE, CNT_INNER & 0xFF, 0xC0,   # C00D dec CNT_INNER
        0xD0, 0xF8,                     # C010 bne -8  -> C00A
        0xCE, CNT_OUTER & 0xFF, 0xC0,   # C012 dec CNT_OUTER
        0xD0, 0xEE,                     # C015 bne -18 -> C005
        0x60,                           # C017 rts
    ])


def set_blank(transport, blanked):
    """Set or clear DEN in $D011 without disturbing the other bits."""
    cur = read_bytes(transport, VIC_CTRL1, 1)[0]
    new = (cur & ~DEN_BIT) if blanked else (cur | DEN_BIT)
    write_bytes(transport, VIC_CTRL1, bytes([new]))
    return new


def time_run(transport, target, outer, inner, blanked, timeout):
    """Run target outer*inner times, return elapsed tenths of a second.

    The display is restored before the TOD read so the read itself runs
    under identical conditions in both legs.
    """
    write_bytes(transport, STUB, build_loop_stub(target, outer, inner))
    set_blank(transport, blanked)
    tod_start(transport)
    jsr(transport, STUB, timeout=timeout)
    set_blank(transport, False)
    return read_tod_tenths(transport)


def bench(transport, labels, name, symbol, outer, inner, setup=None,
          timeout=7200.0):
    """Measure one routine blanked vs unblanked. Returns a result dict."""
    addr = labels.address(symbol)
    if addr is None:
        print(f"  SKIP {name}: '{symbol}' not in labels.txt")
        return None

    reps = outer * inner
    if setup:
        setup()
    on = time_run(transport, addr, outer, inner, False, timeout)
    if setup:
        setup()
    off = time_run(transport, addr, outer, inner, True, timeout)

    # Guard the resolution explicitly. At 0.1 s granularity a leg shorter
    # than ~20 s can show a difference that is pure quantisation, and the
    # tool would report it with three decimal places of false confidence.
    if on < 200 or off < 200:
        print(f"  SKIP {name}: legs too short for 0.1 s resolution "
              f"({on/10:.1f}s / {off/10:.1f}s) — raise the iteration count")
        return None

    speedup = on / off
    saved = 100.0 * (on - off) / on
    print(f"  {name:24} {reps:6d}x  display-on {on/10:8.1f} s  "
          f"blanked {off/10:8.1f} s   {speedup:.3f}x  ({saved:.1f}% less time)")
    return {"name": name, "symbol": symbol, "reps": reps,
            "on": on, "off": off, "speedup": speedup, "saved_pct": saved}


def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    quick = "--quick" in sys.argv
    VERBOSE = "--verbose" in sys.argv

    print("Building...")
    r = subprocess.run(["make"], capture_output=True, text=True,
                       cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(f"Build failed:\n{r.stderr}")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)

    # -reu is REQUIRED, not optional tuning. VICE attaches no REU by
    # default, and the default WG profile's fe25519_mul reads its product
    # rows out of REU-resident tables — without one, reu_mul_init spins on
    # REU registers that never become ready and boot never completes, while
    # direct-jsr benchmarking still "works" against garbage. An earlier run
    # of this tool measured the REU legs that way; the numbers looked
    # perfectly consistent and meant nothing.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        if binary_wait_for_boot_ready(transport, labels, timeout=180.0) is None:
            print("FATAL: boot did not complete")
            sys.exit(1)

        # Install the TOD helpers once; the loop stub is rewritten per leg.
        write_bytes(transport, TOD_START, build_tod_start())
        write_bytes(transport, TOD_READ, build_tod_read())

        # Sanity-check the clock before trusting it to grade anything:
        # start it, burn a known amount of emulated time, confirm TOD moved
        # by roughly that much. A TOD that never starts reads 0 forever,
        # which would make every leg "infinitely fast" rather than error.
        tod_start(transport)
        write_bytes(transport, STUB,
                    build_loop_stub(labels["blake2s_compress"], 4, 200))
        jsr(transport, STUB, timeout=600.0)
        probe = read_tod_tenths(transport)
        if probe < 10:
            print(f"FATAL: CIA1 TOD did not advance ({probe} tenths) — "
                  f"cannot time anything with it")
            sys.exit(1)
        print(f"TOD sanity: 800x blake2s_compress = {probe/10:.1f} s emulated")

        # Boot has run: sqtab_init and reu_mul_init have built the tables
        # the multiply paths read. Benching before that would measure a
        # cold, wrong machine.
        print(f"\nVIC blanking benchmark — WG build, NTSC, 1 MHz emulated")
        print(f"{'':26} {'reps':>6}  {'display on':>14}  {'blanked':>16}"
              f"   speedup\n" + "-" * 96)

        results = []

        # --- Symmetric primitives ------------------------------------------
        # Pure CPU, no REU. These carry the AEAD (transport) path.
        for name, sym, o, i in [
            ("blake2s_compress", "blake2s_compress", 40, 200),
            ("chacha20_block", "chacha20_block", 20, 200),
            ("poly1305_block", "poly1305_block", 20, 200),
        ]:
            res = bench(transport, labels, name, sym, o, i, timeout=1800.0)
            if res:
                results.append(res)

        # --- Field arithmetic ----------------------------------------------
        # fe25519_mul is the REU-DMA multiply in the default profile, so
        # this leg also covers whether blanking helps a DMA-bound path.
        # (REU transfers are themselves halted by badlines, so it should.)
        def seed_fe():
            for slot in ("fe_src1", "fe_src2"):
                a = labels.address(slot)
                if a is not None:
                    write_bytes(transport, a, bytes(range(1, 33)))

        for name, sym, o, i in [
            ("fe25519_mul", "fe25519_mul", 20, 200),
            ("fe25519_sqr", "fe25519_sqr", 20, 200),
        ]:
            res = bench(transport, labels, name, sym, o, i, setup=seed_fe,
                        timeout=1800.0)
            if res:
                results.append(res)

        # --- The headline: a full X25519 scalar multiply --------------------
        # One rep; ~4.3 min emulated is ~15,500 jiffies, far more resolution
        # than the loop legs need.
        if not quick:
            def seed_scalarmult():
                write_bytes(transport, labels["x25_scalar"], bytes(range(32)))
                write_bytes(transport, labels["x25_u"], bytes([9] + [0] * 31))
                jsr(transport, labels["x25519_clamp"], timeout=30.0)

            res = bench(transport, labels, "x25519_scalarmult",
                        "x25519_scalarmult", 1, 1, setup=seed_scalarmult,
                        timeout=7200.0)
            if res:
                results.append(res)

        # --- Summary --------------------------------------------------------
        print("-" * 96)
        if not results:
            print("No measurements taken.")
            sys.exit(1)

        best = max(r["speedup"] for r in results)
        worst = min(r["speedup"] for r in results)
        mean = sum(r["speedup"] for r in results) / len(results)
        print(f"{len(results)} routines measured. "
              f"speedup range {worst:.3f}x - {best:.3f}x, mean {mean:.3f}x")

        sm = next((r for r in results if r["symbol"] == "x25519_scalarmult"),
                  None)
        if sm:
            # Project the scalarmult figure only. The handshake row that
            # used to live here was an UPPER BOUND, not an estimate: it
            # scaled README's 23 min by this ratio, which silently assumes
            # the whole handshake runs blanked. It does not — vic_boost
            # blanks the five scalar multiplies and the boot table build,
            # and restores the display in between.
            print(f"  {'scalarmult':16} {4.3:5.1f} min ->"
                  f" {4.3 / sm['speedup']:5.1f} min blanked"
                  f"  (saves {4.3 - 4.3 / sm['speedup']:.1f} min)")
            print()
            print("  For the handshake, do not scale from the above — the")
            print("  measured end-to-end figure is in")
            print("  tools/bench_vic_blank_handshake.py: 6.1% on Type-2")
            print("  processing (462.8 s -> 434.4 s, 28.4 s saved).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
