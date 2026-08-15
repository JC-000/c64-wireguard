#!/usr/bin/env python3
"""bench_vic_blank_handshake.py — end-to-end VIC blanking saving on the
Type-2 handshake half.

WHY A SECOND BENCHMARK

`bench_vic_blank.py` measures individual primitives and prints a
projected handshake saving by scaling README's hardware figure by the
per-routine ratio. That projection assumes the WHOLE handshake runs
blanked, which is false: `src/wg/vic_boost.s` blanks only around the
five scalar multiplies and the boot table build, and restores the
display in between so progress output stays visible. The projection is
therefore an upper bound, not an estimate.

This tool measures the real thing instead. `session_handle_packet` is
the Type-2 processing half of the handshake — README's "~9 min" leg —
and performs 3x X25519 plus the surrounding KDF/AEAD work. Timing it
with blanking as-shipped versus disabled gives an actual saving over a
real code path, including the unblanked stretches between the scalar
multiplies, which is exactly what the projection cannot capture.

HOW THE "WITHOUT" LEG WORKS

By patching `vic_boost_begin` to an immediate RTS ($60) at runtime,
rather than building a second PRG. Same binary, same addresses, same
layout, same cache behaviour — the ONLY difference between legs is
whether DEN gets cleared. A separate build would risk attributing a
layout or alignment difference to blanking. The original bytes are
restored afterwards and the restore is verified.

Note `vic_boost_end` is deliberately NOT patched: it only sets DEN,
which is harmless when DEN was never cleared, and leaving it in keeps
the two legs' instruction counts closer.

MEASUREMENT

CIA1 TOD (`$DC08-$DC0B`), reusing the helpers in `bench_vic_blank.py` —
emulated time, unaffected by warp, and unaffected by the interrupt
masking that makes the KERNAL jiffy clock useless here.

USAGE
    python3 tools/bench_vic_blank_handshake.py [--trials N]
"""

import os
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench_vic_blank import (  # noqa: E402
    build_tod_start, build_tod_read, read_tod_tenths, tod_start,
    TOD_START, TOD_READ,
)
from test_type2_slow import prepare_valid_trial  # noqa: E402

import random  # noqa: E402
import struct  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

RTS = 0x60


def load_trial(transport, labels, trial):
    """Write one Type-2 trial's handshake state, as test_type2_slow does."""
    write_bytes(transport, labels["hs_c"], trial["c"])
    write_bytes(transport, labels["hs_h"], trial["h"])
    write_bytes(transport, labels["hs_ephem_priv"], trial["ephem_priv"])
    write_bytes(transport, labels["hs_static_priv"], trial["static_priv"])
    write_bytes(transport, labels["hs_static_pub"], trial["static_pub"])
    write_bytes(transport, labels["hs_resp_pub"], trial["resp_pub"])
    write_bytes(transport, labels["hs_sender_idx"], trial["sender_idx"])
    write_bytes(transport, labels["hs_preshared_key"], b"\x00" * 32)
    write_bytes(transport, labels["wg_state"], bytes([1]))          # HS_SENT
    write_bytes(transport, labels["udp_recv_buf"], trial["type2_packet"])
    write_bytes(transport, labels["udp_recv_len"], struct.pack("<H", 92))
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))


def time_type2(transport, labels, trial):
    """Run one Type-2 processing pass, return (tenths, final_wg_state)."""
    load_trial(transport, labels, trial)
    tod_start(transport)
    jsr(transport, labels["session_handle_packet"], timeout=25000.0)
    tenths = read_tod_tenths(transport)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    return tenths, state


def main():
    os.chdir(PROJECT_ROOT)
    trials = 1
    if "--trials" in sys.argv:
        trials = int(sys.argv[sys.argv.index("--trials") + 1])

    labels = Labels.from_file(LABELS_PATH)
    rng = random.Random(51820)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        print(f"VICE PID={inst.pid}, port={inst.port}")

        if binary_wait_for_boot_ready(t, labels, timeout=300.0) is None:
            print("FATAL: boot did not complete")
            sys.exit(1)
        print("boot complete (tables built)")

        write_bytes(t, TOD_START, build_tod_start())
        write_bytes(t, TOD_READ, build_tod_read())

        boost = labels["vic_boost_begin"]
        original = bytes(read_bytes(t, boost, 8))
        print(f"vic_boost_begin @ ${boost:04X}: "
              + " ".join(f"{b:02X}" for b in original))

        print(f"\nType-2 handshake processing (session_handle_packet, 3x X25519)")
        print(f"{'trial':>6}  {'blanking ON':>14}  {'blanking OFF':>14}"
              f"  {'saved':>9}  speedup  state")
        print("-" * 74)

        rows = []
        for i in range(trials):
            trial = prepare_valid_trial(rng, i)

            # Leg A: as shipped.
            write_bytes(t, boost, original)
            on_t, on_state = time_type2(t, labels, trial)

            # Leg B: vic_boost_begin -> immediate RTS, so DEN is never cleared.
            write_bytes(t, boost, bytes([RTS]))
            off_t, off_state = time_type2(t, labels, trial)

            # Restore before anything else touches the machine.
            write_bytes(t, boost, original)
            assert bytes(read_bytes(t, boost, 8)) == original, "restore failed"

            ok = (on_state == 2 and off_state == 2)
            speed = off_t / on_t if on_t else 0.0
            print(f"{i:>6}  {on_t/10:11.1f} s  {off_t/10:11.1f} s"
                  f"  {(off_t-on_t)/10:8.1f} s  {speed:6.3f}x"
                  f"  {'OK' if ok else f'BAD {on_state}/{off_state}'}")
            rows.append((on_t, off_t, ok))

        print("-" * 74)
        if not all(ok for _, _, ok in rows):
            print("FAIL: a trial did not reach SESSION_ACTIVE (state 2) on both "
                  "legs — the measurement is not comparing equivalent work")
            sys.exit(1)

        on_tot = sum(r[0] for r in rows)
        off_tot = sum(r[1] for r in rows)
        print(f"blanking ON  {on_tot/10:8.1f} s    "
              f"blanking OFF {off_tot/10:8.1f} s")
        print(f"saved {(off_tot-on_tot)/10:.1f} s of {off_tot/10:.1f} s "
              f"= {100.0*(off_tot-on_tot)/off_tot:.1f}%  "
              f"({off_tot/on_tot:.3f}x)")
        print()
        print("This is the REAL saving on this code path, including the")
        print("unblanked stretches between the scalar multiplies — unlike the")
        print("per-primitive projection in bench_vic_blank.py, which assumes")
        print("the whole handshake runs blanked and is therefore an upper bound.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
