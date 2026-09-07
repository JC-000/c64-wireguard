#!/usr/bin/env python3
"""test_x25519_reu_fault_surfaced.py — the REU settle fault must not be silent.

c64-x25519 v0.12.0+ (SPEC v0.13.0 §8.2) records REU post-execute settle
failures in one sticky exported byte, `x25519_reu_fault`:

    $01  a bounded spin expired without END OF BLOCK ($DF00 bit 6)
    $02  $DF00 bit 5 (VERIFY ERROR) was observed

The spin has NO error return — the byte is the whole reporting channel.
Nothing in c64-wireguard reads it, so on the REU profile every DMA in the
multiply-table build can fail and boot still runs to completion.
That is the fail-open this suite exists to make loud.

PROFILE COVERAGE — read before trusting a green run.
The settle code (`x25519_reu_settle_slow`) exists ONLY in the REU profile.
Under `lib-x25519-onchip` (REU=0, which is what we SHIP as
wireguard-rrnet-noreu-mtu1440.prg) the fault byte still EXISTS in
LIB_X25519_DATA and is documented as always $00 — so a test that merely
asserts the symbol is present passes on both builds and measures nothing.
Leg 1 asserts the two profiles' symbol sets by EQUALITY in both
directions, and legs 2/3 refuse to run against a build with no settle
code rather than passing vacuously.

Legs
  1  profile_symbol_sets   REU=1 and REU=0 label sets, equality both ways.
  2  fault_is_silent       REU=1 PRG on VICE with NO REU attached: the
                           settle records $02 and boot completes
                           (boot_ready=1) anyway.  <-- the RED leg
  3  control_reu_present   Same PRG on VICE WITH an REU: fault is $00 and
                           boot completes.  Proves leg 2's alarm is
                           discriminating, not stuck-on.

MUTATES THE BUILD TREE (leg 1 builds both REU profiles). Register serial
in tools/run_regression.py and restore the default build on exit.

VICE COVERAGE: complete for this gap. The settle reads $DF00, which VICE
emulates for both the REU-present and REU-absent cases, and the
REU-absent case is a genuine fault injection with no poking. What VICE
canNOT cover is the hardware trigger this guard was written for — the
fw-3.15 REU regression at 48 MHz (issue #69), where a REAL REU needs the
post-execute settle. That leg is hardware-only; see HARDWARE_LEG below.

Usage:
    python3 tools/test_x25519_reu_fault_surfaced.py [--seed S] [--keep-build]
"""

import os
import random
import re
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vice_util import binary_wait_for_boot_ready   # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
PRG_PATH = os.path.join(BUILD_DIR, "wireguard.prg")
LABELS_PATH = os.path.join(BUILD_DIR, "labels.txt")

# The §8.2 surface, split by which profile is allowed to carry it.
FAULT_DATA_SYMS = {"x25519_reu_fault", "x25519_reu_settle_cnt", "x25519_reu_settle_smp"}
SETTLE_CODE_SYMS = {"x25519_reu_settle_slow"}

# Readiness is boot_ready (src/wg/data.s), set as the last act of start:
# in src/boot.s. NOT title_msg's "Q=QUIT" — that prints BEFORE the crypto
# table build, so a screen wait on it matches a half-booted machine and
# this whole suite would report "boot completed" for a machine that never
# got past reu_mul_init (issue #55). Structural byte, not screen text.

# HARDWARE_LEG (designed, NOT executed here):
#   U64E, physical/emulated REU, REU=1 PRG, turbo set AFTER the REU is
#   enabled, sweep 1 / 4 / 48 MHz. At each speed: boot, read
#   x25519_reu_fault over DMA, and assert it is $00 at every speed the
#   build claims (X25519_MAX_CLOCK_MHZ = 48). A non-zero byte at 48 MHz
#   is issue #69 reproducing through the library's own instrument
#   instead of through a wrong scalarmult. Teardown restores 1 MHz + REU
#   off and asserts by read-back; DeviceLock throughout; C64_SKIP_BUILD=1
#   after the manual REU=1 build, with the PRG fingerprint logged.
#   Speed knob: WG_REU_FAULT_TURBO_MHZ.


def _make(reu: int) -> None:
    subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, capture_output=True, check=False)
    r = subprocess.run(["make", f"REU={reu}"], cwd=PROJECT_ROOT,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"FATAL: REU={reu} build failed:\n{r.stdout[-4000:]}\n{r.stderr[-4000:]}")


def _label_names() -> set:
    """Every label name in the current build, as a plain set."""
    names = set()
    with open(LABELS_PATH, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^al\s+\S+\s+\.(\S+)\s*$", line)
            if m:
                names.add(m.group(1))
    return names


def _boot(extra_args, timeout=300.0):
    """Boot the current PRG under VICE, return (boot_ready_set, fault, addr)."""
    labels = Labels.from_file(LABELS_PATH)
    addr = labels["x25519_reu_fault"]
    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                     extra_args=list(extra_args))
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        try:
            ready = binary_wait_for_boot_ready(inst.transport, labels, timeout=timeout)
            fault = read_bytes(inst.transport, addr, 1)[0]
        finally:
            mgr.release(inst)
    return (ready is not None), fault, addr


def leg1_profile_symbol_sets():
    """Set equality both ways: which profile carries the settle code."""
    print("\n--- leg 1: profile symbol sets (equality both ways) ---")
    failed = 0

    _make(1)
    reu_syms = _label_names()
    _make(0)
    onchip_syms = _label_names()

    got_reu_data = FAULT_DATA_SYMS & reu_syms
    got_reu_code = SETTLE_CODE_SYMS & reu_syms
    got_on_data = FAULT_DATA_SYMS & onchip_syms
    got_on_code = SETTLE_CODE_SYMS & onchip_syms

    if got_reu_data != FAULT_DATA_SYMS:
        print(f"  FAIL REU=1 fault-data symbol set: expected exactly {sorted(FAULT_DATA_SYMS)}, "
              f"got {sorted(got_reu_data)} (missing {sorted(FAULT_DATA_SYMS - got_reu_data)}) — "
              f"the pinned c64-x25519 predates SPEC v0.13.0 §8.2 or the archive dropped data.o")
        failed += 1
    if got_reu_code != SETTLE_CODE_SYMS:
        print(f"  FAIL REU=1 settle-code symbol set: expected exactly {sorted(SETTLE_CODE_SYMS)}, "
              f"got {sorted(got_reu_code)} — legs 2/3 would run against a build with no "
              f"REU_SETTLE path and pass vacuously")
        failed += 1
    if got_on_data != FAULT_DATA_SYMS:
        print(f"  FAIL REU=0 fault-data symbol set: expected exactly {sorted(FAULT_DATA_SYMS)}, "
              f"got {sorted(got_on_data)} — the onchip profile is documented to keep the "
              f"byte (always $00), so its absence means the profile split moved")
        failed += 1
    if got_on_code != set():
        print(f"  FAIL REU=0 settle-code symbol set: expected exactly [], got {sorted(got_on_code)} — "
              f"the shipped no-REU artifact must carry NO settle path; if it does, this suite's "
              f"'shipped build is out of scope' claim is wrong and legs 2/3 must be extended to it")
        failed += 1

    if failed == 0:
        print(f"  ok  REU=1 carries {sorted(FAULT_DATA_SYMS | SETTLE_CODE_SYMS)}; "
              f"REU=0 carries {sorted(FAULT_DATA_SYMS)} and NO settle code")
        print("  note SHIPPED ARTIFACT IS REU=0: this gap cannot occur there, and legs 2/3 "
              "deliberately do not test it. Do not read a green run as covering the shipped PRG.")
    return (1 if failed == 0 else 0), failed


def leg2_fault_is_silent():
    """RED leg: a recorded settle fault does not stop the boot."""
    print("\n--- leg 2: a REU settle fault must not be silent (VICE, NO REU attached) ---")
    _make(1)
    syms = _label_names()
    if not SETTLE_CODE_SYMS <= syms:
        print(f"  REFUSED: {sorted(SETTLE_CODE_SYMS)} absent from the build — there is no "
              f"REU_SETTLE path to fault, so this leg would pass without measuring anything")
        return 0, 1

    reached, fault, addr = _boot(extra_args=[])
    print(f"  x25519_reu_fault @ ${addr:04X} = ${fault:02X}; boot_ready set = {reached}")

    failed = 0
    # Instrument self-check FIRST: if no fault was recorded, the injection
    # did not happen and any verdict below is meaningless.
    if fault == 0:
        print("  FAIL injection did not fire: x25519_reu_fault == $00 with NO REU attached. "
              "Expected a non-zero settle fault ($01 bound expired / $02 VERIFY ERROR). "
              "This leg measures nothing until that is fixed — do not read it as a pass.")
        return 0, 1

    if reached:
        print(f"  FAIL fail-open: the multiply-table build recorded x25519_reu_fault=${fault:02X} "
              f"(every REU DMA in reu_mul_init was unconfirmed) and boot still set boot_ready. Nothing in c64-wireguard reads the byte, so a "
              f"wrong scalarmult would be produced with no alarm. The consumer must check "
              f"x25519_reu_fault after reu_mul_init and refuse.")
        failed += 1
    else:
        print(f"  ok  boot refused to set boot_ready with x25519_reu_fault=${fault:02X}")

    return (1 if failed == 0 else 0), failed


def leg3_control_reu_present():
    """Control arm: with a working REU the fault is clear and boot proceeds."""
    print("\n--- leg 3: control — VICE WITH an REU attached ---")
    reached, fault, addr = _boot(extra_args=["-reu", "-reusize", "512"])
    print(f"  x25519_reu_fault @ ${addr:04X} = ${fault:02X}; boot_ready set = {reached}")

    failed = 0
    if fault != 0:
        print(f"  FAIL control arm faulted: expected x25519_reu_fault == $00 with a working REU, "
              f"got ${fault:02X}. Leg 2's alarm is then stuck-on and proves nothing.")
        failed += 1
    if not reached:
        print(f"  FAIL control arm did not boot: boot_ready never set with a working REU "
              f"and a clear fault byte — the guard is refusing a healthy machine.")
        failed += 1
    if failed == 0:
        print("  ok  fault $00 and boot proceeds — the leg-2 assertion discriminates both ways")
    return (1 if failed == 0 else 0), failed


def main():
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    keep = False
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1]); i += 2
        elif args[i] == "--keep-build":
            keep = True; i += 1
        else:
            i += 1
    if os.environ.get("TEST_SEED"):
        seed = int(os.environ["TEST_SEED"])
    random.seed(seed)
    # Seed is logged for parity with the wire suites; this suite's inputs are
    # the two build profiles and the presence/absence of an REU, neither of
    # which is randomisable. Nothing here crosses a wire.
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    passed = failed = 0
    try:
        for leg in (leg1_profile_symbol_sets, leg2_fault_is_silent, leg3_control_reu_present):
            p, f = leg()
            passed += p
            failed += f
    finally:
        if not keep:
            print("\nrestoring the default build (REU=1, ip65)...")
            subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, capture_output=True, check=False)
            subprocess.run(["make"], cwd=PROJECT_ROOT, capture_output=True, check=False)

    total = passed + failed
    print(f"\n{'='*60}\nResults: {passed}/{total} legs passed, {failed} failed\n{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
