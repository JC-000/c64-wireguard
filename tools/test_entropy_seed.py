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
  5. any two runs that reached ``entropy_fill`` with DIFFERENT whitening
     states produced different 32-byte keys.  This is issue #89's acceptance
     criterion ("two runs produce different ephemeral keys") in the only
     form VICE can decide: two VICE instances booting the same PRG can be
     bit-identical machines, and identical machines legitimately produce
     identical keys, so the unconditional form can fail on correct code.
     Measured failing on both trees at a similar rate, and #107's more
     deterministic boot made it worse.  Conditioning it on the states having
     differed keeps the property that matters -- the seed propagates into
     the key -- and drops the part that only measures VICE.  It contributes
     nothing on the unfixed tree, where every state is $00; assertions 2-4
     are the red ones.

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


def prg_image_bytes(addr, length):
    """`prg_image_byte` for a run of bytes; None if the image is short."""
    with open(PRG_PATH, "rb") as fh:
        data = fh.read()
    load = data[0] | (data[1] << 8)
    offset = 2 + addr - load
    if offset < 2 or offset + length > len(data):
        return None
    return data[offset:offset + length]


SID_V3_CTRL = 0xD412            # voice-3 control register
CTRL_SCAN_LIMIT = 256           # sanity cap on the decode walk

# --- a 6502 instruction-length table, documented opcodes only -------------
#
# An opcode NOT in here stops the walk with a failure. That is deliberate:
# the alternative to knowing an instruction's length is guessing it, and a
# guess desynchronises the decoder so that operand bytes get read as
# opcodes — which is the exact failure mode of the byte-pattern scan this
# replaces, just moved one level down.
_LEN1 = [0x00, 0x08, 0x0A, 0x18, 0x28, 0x2A, 0x38, 0x40, 0x48, 0x4A, 0x58,
         0x60, 0x68, 0x6A, 0x78, 0x88, 0x8A, 0x98, 0x9A, 0xA8, 0xAA, 0xB8,
         0xBA, 0xC8, 0xCA, 0xD8, 0xE8, 0xEA, 0xF8]
_LEN2 = ([0x09, 0x29, 0x49, 0x69, 0xA0, 0xA2, 0xA9, 0xC0, 0xC9, 0xE0, 0xE9]
         + [0x05, 0x06, 0x24, 0x25, 0x26, 0x45, 0x46, 0x65, 0x66, 0x84,
            0x85, 0x86, 0xA4, 0xA5, 0xA6, 0xC4, 0xC5, 0xC6, 0xE4, 0xE5, 0xE6]
         + [0x15, 0x16, 0x35, 0x36, 0x55, 0x56, 0x75, 0x76, 0x94, 0x95,
            0xB4, 0xB5, 0xD5, 0xD6, 0xF5, 0xF6]
         + [0x96, 0xB6]
         + [0x01, 0x21, 0x41, 0x61, 0x81, 0xA1, 0xC1, 0xE1]
         + [0x11, 0x31, 0x51, 0x71, 0x91, 0xB1, 0xD1, 0xF1]
         + [0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0])
_LEN3 = ([0x0D, 0x0E, 0x1D, 0x1E, 0x19, 0x20, 0x2C, 0x2D, 0x2E, 0x39, 0x3D,
          0x3E, 0x4C, 0x4D, 0x4E, 0x59, 0x5D, 0x5E, 0x6C, 0x6D, 0x6E, 0x79,
          0x7D, 0x7E, 0x8C, 0x8D, 0x8E, 0x99, 0x9D, 0xAC, 0xAD, 0xAE, 0xB9,
          0xBC, 0xBD, 0xBE, 0xCC, 0xCD, 0xCE, 0xD9, 0xDD, 0xDE, 0xEC, 0xED,
          0xEE, 0xF9, 0xFD, 0xFE])
OPLEN = {}
for _grp, _n in ((_LEN1, 1), (_LEN2, 2), (_LEN3, 3)):
    for _op in _grp:
        assert _op not in OPLEN, f"duplicate opcode ${_op:02X} in the length table"
        OPLEN[_op] = _n
assert len(OPLEN) == 151, f"expected 151 documented opcodes, have {len(OPLEN)}"

# Stores whose target address is IN the instruction, so it can be read.
ABS_STORES = {0x8D: ("STA", 0xA9, "LDA"),
              0x8E: ("STX", 0xA2, "LDX"),
              0x8C: ("STY", 0xA0, "LDY")}
# Stores whose target is base+index: not readable statically.
INDEXED_ABS_STORES = {0x9D: "STA abs,X", 0x99: "STA abs,Y"}
# Stores through a zero-page pointer: not readable statically at all.
INDIRECT_STORES = {0x81: "STA (zp,X)", 0x91: "STA (zp),Y"}
# entropy_fill's `sta (zp_ptr1),y` is the ONE indirect store this module is
# supposed to contain. Pinned as a count so a NEW one has to be justified.
EXPECTED_INDIRECT_STORES = 1
RTS = 0x60


def decode_entropy_region(labels):
    """Linear-decode entropy_init..end-of-entropy_fill from the built image.

    Returns (instructions, error). Each instruction is
    (addr, opcode, operand_bytes). *error* is a string when the walk could
    not complete, in which case nothing downstream may be trusted.

    WHY A DECODER AND NOT A BYTE SEARCH, third time around. The .assert in
    entropy.s pins the CONSTANT, and the instruction can stop using it. The
    first version of this function pinned the ENCODING -- it searched for
    the literal bytes `8D 12 D4` -- and the instruction can stop using that
    too. Review built two clean images shipping $88 (NOISE + TEST) to
    $D412, and both scored 4/4 PASS against it:

        ldx #$00 / lda #$88 / sta sid_v3_ctrl,x      ; opcode $9D
        ldx #$88 / stx sid_v3_ctrl                   ; opcode $8E

    plus $99 (,Y), $8C (STY) and $91 ((zp),Y) equally invisible. Each fix
    had moved the guard closer to the value that reaches the chip without
    arriving at it; a search for one encoding is a guard against one
    spelling.

    So: walk instructions, and treat every store form as in scope. The rule
    that makes this hold up is not "know every way to write to $D412" --
    that list is open-ended -- but "FAIL on any form whose target or value
    cannot be read here". Unknown opcode, unreadable target, unreadable
    value: all failures, none silent passes.
    """
    ei = labels["entropy_init"]
    ef = labels["entropy_fill"]
    blob = prg_image_bytes(ei, CTRL_SCAN_LIMIT)
    if blob is None:
        return [], f"the PRG image does not cover entropy_init (${ei:04X})"

    out = []
    off = 0
    while off < len(blob):
        addr = ei + off
        op = blob[off]
        n = OPLEN.get(op)
        if n is None:
            return out, (f"undecodable opcode ${op:02X} at ${addr:04X}. The "
                         f"walk cannot continue without guessing an "
                         f"instruction length, and a wrong guess reads "
                         f"operands as opcodes — which is how the previous "
                         f"version of this check was defeated.")
        if off + n > len(blob):
            return out, (f"instruction at ${addr:04X} runs past the "
                         f"{CTRL_SCAN_LIMIT}-byte window")
        out.append((addr, op, blob[off + 1:off + n]))
        off += n
        # entropy_fill is the last of the three routines (source order, and
        # the link preserves it), so its rts ends the region. Bounding on a
        # decoded instruction rather than a byte count means the window
        # cannot silently include or exclude a neighbouring routine.
        if op == RTS and addr >= ef:
            return out, None
    return out, (f"walked {CTRL_SCAN_LIMIT} bytes from entropy_init without "
                 f"reaching an rts at or after entropy_fill (${ef:04X})")


def check_sid_ctrl_in_image(labels):
    """#101: assert the byte that actually REACHES $D412, in the built image.

    The .assert pair in entropy.s pins `SID_V3_CTRL_NOISE`; the instruction
    is free to abandon the symbol (`lda #$88` builds rc=0 with both asserts
    green). This decodes the shipped image instead.

    Bit 1 (SYNC) is deliberately NOT pinned; see the note in entropy.s.
    """
    results = []
    insns, err = decode_entropy_region(labels)
    if err:
        results.append((False, "the entropy region decodes", err))
        return results
    results.append((True,
                    f"the entropy region decodes cleanly "
                    f"({len(insns)} instructions)", ""))

    sid_writes = 0
    indirect = 0
    for i, (addr, op, operand) in enumerate(insns):
        if op in INDIRECT_STORES:
            indirect += 1
            continue

        if op in INDEXED_ABS_STORES:
            base = operand[0] | (operand[1] << 8)
            # An index is 0..255, so any base in this span can land on
            # $D412. The target is not knowable from the image, so this is
            # a failure by construction rather than something to reason
            # about -- review's `sta sid_v3_ctrl,x` mutant lives here.
            if SID_V3_CTRL - 0xFF <= base <= SID_V3_CTRL:
                results.append((False,
                                f"{INDEXED_ABS_STORES[op]} ${base:04X} at "
                                f"${addr:04X} can reach $D412",
                                "the target is base+index and cannot be "
                                "read statically, so the value arriving at "
                                "the SID is unverifiable here. Write the "
                                "voice-3 control with an absolute store, or "
                                "re-derive this guard."))
            continue

        if op not in ABS_STORES:
            continue
        target = operand[0] | (operand[1] << 8)
        if target != SID_V3_CTRL:
            continue

        sid_writes += 1
        mnem, want_load, load_name = ABS_STORES[op]
        if i == 0:
            results.append((False,
                            f"{mnem} $D412 at ${addr:04X} has a preceding "
                            f"instruction", "it is the first instruction in "
                            "the region, so the value is unreadable"))
            continue
        paddr, pop, poperand = insns[i - 1]
        if pop != want_load:
            results.append((False,
                            f"{mnem} $D412 at ${addr:04X} is fed by "
                            f"{load_name} #imm",
                            f"preceded by opcode ${pop:02X} at ${paddr:04X}, "
                            f"not {load_name} #imm — the value is computed "
                            f"or loaded from memory, so it cannot be read "
                            f"statically. This branch is the point of the "
                            f"check: an unreadable value FAILS."))
            continue
        imm = poperand[0]
        results.append((bool(imm & 0x80),
                        f"the byte written to $D412 (${imm:02X}, via {mnem} "
                        f"at ${addr:04X}) has bit 7 NOISE set",
                        "without the noise waveform $D41B is not an LFSR "
                        "tap and entropy_byte's non-affinity argument, and "
                        "the 0/6144 hardware result, do not apply"))
        results.append((not (imm & 0x08),
                        f"the byte written to $D412 (${imm:02X}, via {mnem} "
                        f"at ${addr:04X}) has bit 3 TEST clear",
                        "TEST holds the oscillator in reset and freezes "
                        "$D41B to a constant — the exact degeneracy #101 "
                        "is about. VICE cannot catch this: it does not "
                        "clock reSID at all"))

    # At least one, or a build that dropped the SID setup satisfies every
    # all-quantifier above vacuously.
    results.append((sid_writes >= 1,
                    f"the entropy region writes $D412 at all "
                    f"({sid_writes} absolute store(s))",
                    "no store to $D412 found — the SID voice-3 setup is "
                    "gone, and every claim entropy_byte makes about $D41B "
                    "not being clock-affine rests on it"))

    # Set equality, not membership: entropy_fill's `sta (zp_ptr1),y` is the
    # one indirect store this module should contain, and an indirect store
    # can target anything. A NEW one has to be justified rather than
    # absorbed.
    results.append((indirect == EXPECTED_INDIRECT_STORES,
                    f"the entropy region has exactly "
                    f"{EXPECTED_INDIRECT_STORES} indirect store "
                    f"(entropy_fill's), found {indirect}",
                    "an indirect store's target is a zero-page pointer and "
                    "cannot be read from the image, so a new one makes the "
                    "$D412 claim above conditional on something this check "
                    "cannot see"))

    # Byte-pattern sweep OUTSIDE the decoded region. Say what it is: the
    # rest of the image is code mixed with data and cannot be linearly
    # decoded, so this is a search for store ENCODINGS carrying the literal
    # operand $D412 — a strictly weaker check than the one above, kept
    # because it is nearly free. It is NOT a proof that nothing else writes
    # the register. The previous version of this line claimed "no code
    # outside entropy_init writes $D412", which was both too strong (it is
    # a byte search) and mislabelled (the window was the first 64 bytes of
    # entropy_init, which already overlapped entropy_byte).
    with open(PRG_PATH, "rb") as fh:
        data = fh.read()
    load = data[0] | (data[1] << 8)
    body = data[2:]
    lo, hi = SID_V3_CTRL & 0xFF, SID_V3_CTRL >> 8
    region_lo = insns[0][0]
    region_hi = insns[-1][0]
    others = []
    for op in list(ABS_STORES) + list(INDEXED_ABS_STORES):
        pat = bytes([op, lo, hi])
        j = body.find(pat)
        while j >= 0:
            a = load + j
            if not (region_lo <= a <= region_hi):
                others.append((a, op))
            j = body.find(pat, j + 1)
    results.append((not others,
                    f"no store-opcode byte pattern targeting $D412 appears "
                    f"outside the decoded region (byte search, not a "
                    f"decode — see the comment)",
                    "found at " + ", ".join(f"${a:04X} (op ${o:02X})"
                                            for a, o in others)
                    + " — entropy_init's value may not be the one the chip "
                      "ends up holding"))
    return results


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

    # --- 5. #89 acceptance, conditioned so it cannot fail on correct code --
    #
    # The unconditional form -- "RUNS independent boots must produce RUNS
    # distinct keys" -- is #89's stated acceptance criterion and it is NOT
    # decidable under VICE.  Two VICE instances booting the same PRG can be
    # bit-identical machines: same cycle count at every instruction, so the
    # same jiffy, timer A, raster and OSC3 at the moment entropy_init runs,
    # so the same seed and the same entropy_fill reads, so legitimately the
    # same key.  Host-timing jitter usually perturbs that, which is why the
    # unconditional form usually passes -- but "usually" is a flaky gate
    # assertion, and it was measured failing on BOTH trees at a similar rate
    # (master d48c452: 2 collisions in 24 boots; this tree: 1 in 16).  It got
    # worse when #107 made the boot path more deterministic.
    #
    # So assert the part the fix is actually responsible for: if two runs
    # reached entropy_fill with DIFFERENT whitening states, they must not
    # produce the same key.  That is what "the seed propagates into the key"
    # means, it fires if the seed is computed but not consumed, and it cannot
    # fail on two identical machines because its precondition excludes them.
    #
    # Vacuity note: on the unfixed tree every post-init state is $00, so the
    # precondition never holds and this contributes no assertion at all.  It
    # is not part of the red baseline and is not claimed to be -- assertions
    # 2, 3 and 4 are what fail there.  The identical-machine count is printed
    # either way, because a run where every machine was identical would mean
    # this assertion checked nothing and the reader should see that.
    keys = [r[2] for r in runs]
    post = [r[1] for r in runs]

    violations, compared, identical_machines = [], 0, 0
    for i in range(RUNS):
        for j in range(i + 1, RUNS):
            if post[i] != post[j]:
                compared += 1
                if keys[i] == keys[j]:
                    violations.append((i, j))
            elif keys[i] == keys[j]:
                identical_machines += 1

    if identical_machines and VERBOSE:
        print(f"  NOTE {identical_machines} run pair(s) were bit-identical "
              f"machines (same seed, same key) -- expected under VICE, "
              f"excluded from the assertion below")

    if compared == 0:
        print(f"  SKIP no two runs reached entropy_fill with different "
              f"whitening states, so key propagation was not exercised "
              f"(expected on the unfixed tree, where every state is $00)")
    elif not violations:
        passed += 1
        if VERBOSE:
            print(f"  PASS {compared} run pair(s) with different whitening "
                  f"states produced different 32-byte ephemeral keys")
    else:
        failed += 1
        print(f"  FAIL {len(violations)} run pair(s) reached entropy_fill "
              f"with DIFFERENT whitening states and still produced the SAME "
              f"32-byte ephemeral key -- the seed is not propagating into "
              f"the key: "
              f"{[(i, j, keys[i].hex()) for i, j in violations]}")

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

    # Image-level and emulator-free, so it runs first and costs nothing.
    print("\n--- #101: the SID voice-3 control byte IN THE BUILT IMAGE ---")
    passed = failed = 0
    for ok, label, detail in check_sid_ctrl_in_image(labels):
        if ok:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failed += 1
            print(f"  FAIL  {label}\n        {detail}")

    print(f"\n--- #89: entropy_state must not start from a fixed constant "
          f"({RUNS} independent boots) ---")
    p2, f2 = run_tests(labels)
    passed += p2
    failed += f2

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
