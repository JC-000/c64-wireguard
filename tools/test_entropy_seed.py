#!/usr/bin/env python3
"""test_entropy_seed.py -- issue #89: the RNG whitening state must not start
from a fixed constant.

WHAT THIS GUARDS.  ``entropy_state`` (src/crypto/entropy.s) is the persistent
byte that ``entropy_byte`` / ``entropy_fill`` feed back into every output, and
``entropy_fill`` is what writes ``hs_ephem_priv`` -- the WireGuard ephemeral
PRIVATE key -- in ``session_initiate`` (src/wg/session.s:159-164).  Its
declaration used to claim the start value was "whatever RAM held".  It is not:
``entropy_state`` lives in APP_EXTRA_BSS, the cfg loads that into MAIN_AREA_HI,
and MAIN_AREA_HI is declared ``file = %O, fill = yes, fillval = $00``, so the
PRG image covers the address and LOAD stamps $00 over it on every single run,
on every machine.

WHY IT IS NOT COSMETIC.  Measured under VICE (200 paired trials, master):
in 2.00% of calls the two hardware reads cancel and ``entropy_fill``'s output
is a pure function of ``entropy_state`` alone.  With the state fixed at $00
that function has one value, and it is machine-independent:

    f0 07 fc 01 ff 00 7f c0 1f  (repeating, period 9)

i.e. on the first handshake after LOAD there is a few-percent chance the
ephemeral private key is a constant an attacker can precompute.  Seeding the
state does not cure that cancellation -- that is a separate defect -- but it
does stop the cancelled case from collapsing onto one universal key.

THE ASSERTIONS.  Boot the PRG in ``RUNS`` independent VICE instances and, in
each, sample ``entropy_state`` before and after ``entropy_init``:

  1. before ``entropy_init`` the state equals the byte the PRG image carries
     at that address.  Characterization: it passes on both trees and it is
     what makes assertions 2-4 mean anything -- without it "the state
     changed" could just be leftover RAM.
  2. ``entropy_init`` moved the state off that load-time constant.
  3. the post-init states are not all identical across the independent runs.
     Assertion 2 alone would pass on an ``lda #$a5 / sta entropy_state``
     mutant; this one would not.
  4. within one run, re-stamping the state to $00 and calling
     ``entropy_init`` ``SEED_SAMPLES`` times must yield many distinct values.
     Same teeth as 3 but with a real sample size instead of RUNS=4.
  5. the 32 bytes ``entropy_fill`` produces straight after ``entropy_init``
     differ across the independent runs.  This is issue #89's acceptance
     criterion ("two runs produce different ephemeral keys") stated
     directly.  NOTE it already passes on master -- CIA1 timer A's phase
     varies between VICE boots -- so it is a guard, not the red test.

VACUITY CONTROL.  ``--vacuity-control`` skips every ``entropy_init`` call and
changes nothing else.  On a CORRECT tree it must FAIL assertions 2, 3 and 4:
if they still pass without the routine that is supposed to satisfy them, they
were measuring the harness rather than the code.  Run it whenever you touch
this file.

HARDWARE.  Everything here runs under VICE and nothing here measures the
QUALITY of the entropy -- SID OSC3 is a clock-derived ramp under VICE, not
noise, so the amount of unpredictability a real C64 contributes is out of
this suite's reach.  What it can prove is that the start value is no longer a
compile-time constant, and that is exactly what #89 is about.

Usage:
    python3 tools/test_entropy_seed.py [--seed S] [--verbose]
                                       [--runs N] [--vacuity-control]
"""

import os
import struct
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
VACUITY_CONTROL = False

# Independent VICE boots.  Four is enough for "not all identical" to be
# decisive against a constant while staying inside the gate's time budget;
# assertion 4 carries the statistical weight.
RUNS = 4

# In-run samples for assertion 4, and the floor they must clear.  32 samples
# of a byte drawn from live CIA1 timer A / raster phase come back with ~30
# distinct values in practice; 8 leaves a wide margin without admitting
# anything that could pass by stamping two or three constants.
SEED_SAMPLES = 32
SEED_MIN_DISTINCT = 8

# Scratch trampoline address (cassette buffer, same slot test_session.py uses).
TRAMPOLINE = 0x0340


def prg_image_byte(addr):
    """Return the byte the PRG file carries for *addr*, or None if the image
    does not cover it.

    This is the load-time value: a PRG is a load address followed by a
    contiguous byte stream, so file offset 2 + (addr - load) is what LOAD
    writes to *addr*.
    """
    with open(PRG_PATH, "rb") as fh:
        data = fh.read()
    load = data[0] | (data[1] << 8)
    offset = 2 + addr - load
    if offset < 2 or offset >= len(data):
        return None
    return data[offset]


def collect_run(labels, run_index):
    """Boot one fresh VICE instance and sample the entropy state.

    Returns (at_boot, after_init, key32, seed_samples).
    """
    es = labels["entropy_state"]
    ef = labels["entropy_fill"]
    ei = labels["entropy_init"]
    ephem = labels["hs_ephem_priv"]

    # LDY #32 / JSR entropy_fill / RTS.  CLC first so the ROL's carry-in is
    # the same in every run and cannot masquerade as entropy.
    tramp = bytes([
        0x18,                               # CLC
        0xA0, 32,                           # LDY #32
        0x20, ef & 0xFF, ef >> 8,           # JSR entropy_fill
        0x60,                               # RTS
    ])

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        if VERBOSE:
            print(f"  run {run_index}: VICE PID={inst.pid} port={inst.port}")
        grid = binary_wait_for_boot_ready(transport, labels, timeout=180.0)
        if grid is None:
            raise RuntimeError(f"run {run_index}: main menu did not appear")

        at_boot = read_bytes(transport, es, 1)[0]

        if not VACUITY_CONTROL:
            jsr(transport, ei, timeout=10.0)
        after_init = read_bytes(transport, es, 1)[0]

        write_bytes(transport, labels["zp_ptr1"], struct.pack('<H', ephem))
        write_bytes(transport, TRAMPOLINE, tramp)
        jsr(transport, TRAMPOLINE, timeout=10.0)
        key32 = read_bytes(transport, ephem, 32)

        seeds = []
        for _ in range(SEED_SAMPLES):
            write_bytes(transport, es, b"\x00")
            if not VACUITY_CONTROL:
                jsr(transport, ei, timeout=10.0)
            seeds.append(read_bytes(transport, es, 1)[0])

    return at_boot, after_init, key32, seeds


def run_tests(labels):
    passed = failed = 0

    es = labels["entropy_state"]
    image = prg_image_byte(es)
    print(f"entropy_state = ${es:04X}, PRG image byte = "
          f"{'(not covered)' if image is None else f'${image:02X}'}")
    if image is None:
        print("FAIL setup: the PRG image does not cover entropy_state -- the "
              "load-time value is no longer a file constant, so this suite's "
              "premise needs re-deriving")
        return 0, 1

    runs = [collect_run(labels, i) for i in range(RUNS)]

    # --- 1. characterization: LOAD stamps the image byte ---------------
    for i, (at_boot, _, _, _) in enumerate(runs):
        if at_boot == image:
            passed += 1
            if VERBOSE:
                print(f"  PASS run {i}: entropy_state at boot = ${at_boot:02X}"
                      f" (the PRG image byte, as expected)")
        else:
            failed += 1
            print(f"  FAIL run {i}: entropy_state at boot = ${at_boot:02X}, "
                  f"expected the image byte ${image:02X} -- the load-time "
                  f"premise of assertions 2-4 no longer holds")

    # --- 2. entropy_init moves the state off the constant --------------
    for i, (at_boot, after_init, _, _) in enumerate(runs):
        if after_init != at_boot:
            passed += 1
            if VERBOSE:
                print(f"  PASS run {i}: entropy_init moved the state "
                      f"${at_boot:02X} -> ${after_init:02X}")
        else:
            failed += 1
            print(f"  FAIL run {i}: entropy_init left entropy_state at "
                  f"${after_init:02X} -- the whitening state still starts "
                  f"from the load-time constant, so entropy_fill's output "
                  f"in a cancelled phase is the same key on every machine "
                  f"(issue #89)")

    # --- 3. the post-init state is not the same constant every run -----
    post = [r[1] for r in runs]
    if len(set(post)) > 1:
        passed += 1
        if VERBOSE:
            print(f"  PASS post-init states across {RUNS} independent boots: "
                  f"{[f'${v:02X}' for v in post]}")
    else:
        failed += 1
        print(f"  FAIL post-init state is ${post[0]:02X} in all {RUNS} "
              f"independent boots -- a seed that does not vary between runs "
              f"is a constant with extra steps")

    # --- 4. the seed itself varies, with a real sample size ------------
    for i, (_, _, _, seeds) in enumerate(runs):
        distinct = len(set(seeds))
        if distinct >= SEED_MIN_DISTINCT:
            passed += 1
            if VERBOSE:
                print(f"  PASS run {i}: {distinct}/{SEED_SAMPLES} distinct "
                      f"seeds from a fixed $00 prior state")
        else:
            failed += 1
            print(f"  FAIL run {i}: only {distinct}/{SEED_SAMPLES} distinct "
                  f"seeds from a fixed $00 prior state (need "
                  f">= {SEED_MIN_DISTINCT}) -- entropy_init is not sampling "
                  f"anything that varies")

    # --- 5. #89 acceptance: independent runs, different key bytes ------
    keys = [r[2] for r in runs]
    if len(set(keys)) == RUNS:
        passed += 1
        if VERBOSE:
            print(f"  PASS {RUNS} independent runs produced {RUNS} distinct "
                  f"32-byte entropy_fill outputs")
    else:
        failed += 1
        dupes = RUNS - len(set(keys))
        print(f"  FAIL {dupes} of {RUNS} independent runs produced a "
              f"REPEATED 32-byte ephemeral key: "
              f"{[k.hex() for k in keys]}")

    return passed, failed


def main():
    global VERBOSE, VACUITY_CONTROL, RUNS
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            i += 2                      # accepted for gate uniformity; unused
        elif args[i] == "--runs" and i + 1 < len(args):
            RUNS = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        elif args[i] == "--vacuity-control":
            VACUITY_CONTROL = True
            i += 1
        else:
            i += 1

    if VACUITY_CONTROL:
        print("VACUITY CONTROL: entropy_init is NOT called. Assertions 2, 3 "
              "and 4 must FAIL on a correct tree.")

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        build_dir = os.path.join(PROJECT_ROOT, "build")
        for name in ("wireguard.prg", "labels.txt"):
            path = os.path.join(build_dir, name)
            if os.path.exists(path):
                os.remove(path)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)

    # Every name here exists on master too, so this file runs unchanged
    # against the unfixed tree -- the red baseline is a real run, not a
    # missing-symbol error.
    required = ["entropy_state", "entropy_init", "entropy_fill",
                "hs_ephem_priv", "zp_ptr1"]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: label '{name}' not found")
            sys.exit(1)

    print(f"\n--- #89: entropy_state must not start from a fixed constant "
          f"({RUNS} independent boots) ---")
    passed, failed = run_tests(labels)

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
