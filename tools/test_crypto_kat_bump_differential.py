#!/usr/bin/env python3
"""test_crypto_kat_bump_differential.py — do the bumped libraries compute the same answers?

Two questions, deliberately separated because they fail for different reasons.

ABSOLUTE (legs 1-2). Does the CURRENT build still reproduce the published
vectors — RFC 7748 §6.1 for X25519, RFC 8439 §2.8.2 for ChaCha20-Poly1305
AEAD? A library bump that broke the primitive outright shows up here.

DIFFERENTIAL (legs 3-4). Does the current build produce BYTE-IDENTICAL
results to a baseline PRG built from the pre-bump pins, over seeded random
inputs? This is the question the published vectors cannot answer. The
x25519 v0.16.0 `fe25519_mul_a24` carry fix changes computed output for
inputs that REACH the defect, and the RFC vectors are three fixed inputs
that may or may not reach it. Only random coverage can distinguish "the
fix is behaviour-preserving on our traffic" from "we never happened to
look at an input where it matters". A DIFFERENCE here is not automatically
a regression — if the baseline was wrong at that input, differing is the
whole point — so leg 3 cross-checks every disagreement against an
independent host-side X25519 and says which side is right.

The differential legs need a baseline PRG. Without --baseline-prg they do
not run, and the suite says so and EXITS NON-ZERO rather than reporting a
green run that answered only half the question.

REQUIRES AN REU. The REU=1 profile keeps its multiply rows in REU banks;
with no REU attached, $DF00 reads open bus, x25519_reu_fault records $02
and every row is stale. Both instances are launched with
`-reu -reusize 512`, as tools/test_fe25519.py already does.

VICE-ONLY and complete: these are pure CPU/RAM computations with no
device dependence. The one thing VICE cannot decide is whether the SAME
inputs give the same answers on real hardware at turbo; that is a
hardware leg (see HARDWARE_LEG) and it is a re-run of legs 1+3 on the
U64E at 1 and 48 MHz, not a different test.

Usage:
    python3 tools/test_crypto_kat_bump_differential.py \
        --baseline-prg PATH --baseline-labels PATH \
        [--prg PATH] [--labels PATH] [--iterations N] [--seed S]
"""

import json
import os
import random
import struct
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vice_util import binary_wait_for_boot_ready   # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
V7748 = os.path.join(PROJECT_ROOT, "test", "rfc7748_vectors.json")
V7539 = os.path.join(PROJECT_ROOT, "test", "rfc7539_vectors.json")

REU_ARGS = ["-reu", "-reusize", "512"]

# HARDWARE_LEG (designed, NOT executed here):
#   Re-run legs 1 and 3 on the U64E with the REU enabled, at
#   WG_KAT_TURBO_MHZ = 1 and 48, turbo set AFTER the REU. Legs 1/3 are
#   the whole content; nothing about them is emulator-specific, and the
#   point of the hardware run is that the REU is real and the ladder is
#   running 48x faster than the settle was bracketed against 1 MHz.
#   Assert x25519_reu_fault == $00 at both speeds alongside the results
#   (a differing scalarmult WITH a set fault byte is a DMA fault, not a
#   library regression, and the two must not be confused). DeviceLock
#   throughout, C64_SKIP_BUILD=1 after a manual REU=1 build, PRG
#   fingerprint logged, teardown restores 1 MHz + REU off by read-back.


# --- host-side X25519 reference (RFC 7748), used only to adjudicate ----------

_P = 2**255 - 19


def _host_x25519(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _clamp(scalar: bytes) -> bytes:
    """RFC 7748 clamping. x25519_scalarmult does NOT clamp — the caller must,
    and tools/test_x25519.py's RFC leg does exactly this. Feeding it a raw
    scalar makes every vector 'fail' against a published answer computed for
    the clamped one, which is a bug in the test, not in the library."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


# --- C64 drivers -------------------------------------------------------------

def c64_scalarmult(t, labels, scalar, u):
    write_bytes(t, labels["x25_scalar"], scalar)
    write_bytes(t, labels["x25_u"], u)
    jsr(t, labels["x25519_scalarmult"], timeout=7200.0)
    return read_bytes(t, labels["x25_result"], 32)


def c64_aead_encrypt(t, labels, key, nonce, aad, pt):
    write_bytes(t, labels["aead_key"], key)
    write_bytes(t, labels["aead_nonce"], nonce)
    aad_buf = labels["input_buffer"]
    if aad:
        write_bytes(t, aad_buf, aad)
    write_bytes(t, labels["aead_aad_ptr"], struct.pack("<H", aad_buf))
    write_bytes(t, labels["aead_aad_len"], bytes([len(aad)]))
    pt_buf = aad_buf + len(aad)
    if pt:
        write_bytes(t, pt_buf, pt)
    write_bytes(t, labels["aead_data_ptr"], struct.pack("<H", pt_buf))
    write_bytes(t, labels["aead_data_len"], struct.pack("<H", len(pt)))
    jsr(t, labels["aead_encrypt"], timeout=300.0)
    return read_bytes(t, pt_buf, len(pt)), read_bytes(t, labels["poly1305_tag"], 16)


# --- the inputs the differential runs on -------------------------------------

def make_inputs(rng, n_scalar, n_aead):
    """Seeded inputs, generated ONCE so both builds see byte-identical work."""
    sm = []
    for _ in range(n_scalar):
        # Clamped, because that is the only shape WG ever hands the ladder
        # and the only shape the host adjudicator computes for.
        sm.append((_clamp(bytes(rng.randrange(256) for _ in range(32))),
                   bytes(rng.randrange(256) for _ in range(32))))
    ae = []
    for _ in range(n_aead):
        n = rng.randrange(0, 200)
        ae.append((bytes(rng.randrange(256) for _ in range(32)),
                   bytes(rng.randrange(256) for _ in range(12)),
                   bytes(rng.randrange(256) for _ in range(rng.choice([0, 12, 16]))),
                   bytes(rng.randrange(256) for _ in range(n))))
    return sm, ae


def collect(prg, labels_path, sm_inputs, ae_inputs, tag):
    """Boot one PRG and compute every result. Returns (sm_out, ae_out, fault)."""
    labels = Labels.from_file(labels_path)
    cfg = ViceConfig(prg_path=prg, warp=True, ntsc=True, sound=False,
                     extra_args=list(REU_ARGS))
    sm_out, ae_out = [], []
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        try:
            if binary_wait_for_boot_ready(inst.transport, labels, timeout=300.0) is None:
                raise SystemExit(f"FATAL: {tag}: boot_ready never set for {prg}")
            t = inst.transport
            write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))
            fault = None
            if labels.address("x25519_reu_fault") is not None:
                fault = read_bytes(t, labels["x25519_reu_fault"], 1)[0]
            t0 = time.monotonic()
            for i, (s, u) in enumerate(sm_inputs):
                sm_out.append(c64_scalarmult(t, labels, s, u))
                if i == 0:
                    print(f"  [{tag}] first scalarmult took {time.monotonic() - t0:.1f}s")
            for key, nonce, aad, pt in ae_inputs:
                ae_out.append(c64_aead_encrypt(t, labels, key, nonce, aad, pt))
        finally:
            mgr.release(inst)
    return sm_out, ae_out, fault


# --- legs --------------------------------------------------------------------

def leg1_x25519_rfc7748(prg, labels_path):
    print("\n--- leg 1: X25519 against RFC 7748 (current build) ---")
    labels = Labels.from_file(labels_path)
    vecs = json.load(open(V7748))["x25519_scalarmult"]
    failed = 0
    cfg = ViceConfig(prg_path=prg, warp=True, ntsc=True, sound=False, extra_args=list(REU_ARGS))
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        try:
            if binary_wait_for_boot_ready(inst.transport, labels, timeout=300.0) is None:
                raise SystemExit("FATAL: boot_ready never set")
            t = inst.transport
            write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))
            for v in vecs:
                s, u, exp = (_clamp(bytes.fromhex(v["scalar"])),
                             bytes.fromhex(v["u_coordinate"]),
                             bytes.fromhex(v["expected"]))
                got = c64_scalarmult(t, labels, s, u)
                if got != exp:
                    print(f"  FAIL {v['desc']}: scalarmult returned {got.hex()}, "
                          f"RFC 7748 publishes {exp.hex()}")
                    failed += 1
                else:
                    print(f"  ok  {v['desc']}")

            # Alarm proof: this leg must be capable of failing. Flip ONE bit of
            # the last vector's scalar and require the published answer NOT to
            # come back. (Byte 1, so clamping cannot absorb it: clamp touches
            # only byte 0's low 3 bits and byte 31's top two.)
            s = bytearray(_clamp(bytes.fromhex(vecs[-1]["scalar"])))
            s[1] ^= 0x01
            exp = bytes.fromhex(vecs[-1]["expected"])
            got = c64_scalarmult(t, labels, bytes(s), bytes.fromhex(vecs[-1]["u_coordinate"]))
            if got == exp:
                print(f"  FAIL alarm proof: flipping bit 0 of scalar byte 1 STILL returned the "
                      f"published answer {exp.hex()} — this leg cannot detect a wrong scalarmult "
                      f"and its passes above mean nothing")
                failed += 1
            else:
                print(f"  ok  alarm proof: one flipped scalar bit changes the result "
                      f"({got.hex()[:16]}... != {exp.hex()[:16]}...)")
        finally:
            mgr.release(inst)
    return (1 if failed == 0 else 0), failed


def leg2_aead_rfc8439(prg, labels_path):
    print("\n--- leg 2: ChaCha20-Poly1305 AEAD against RFC 8439 §2.8.2 (current build) ---")
    labels = Labels.from_file(labels_path)
    v = json.load(open(V7539))["aead_encrypt"][0]
    key, nonce = bytes.fromhex(v["key"]), bytes.fromhex(v["nonce"])
    aad, pt = bytes.fromhex(v["aad"]), bytes.fromhex(v["plaintext"])
    exp_ct, exp_tag = bytes.fromhex(v["ciphertext"]), bytes.fromhex(v["tag"])
    failed = 0
    cfg = ViceConfig(prg_path=prg, warp=True, ntsc=True, sound=False, extra_args=list(REU_ARGS))
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        try:
            if binary_wait_for_boot_ready(inst.transport, labels, timeout=300.0) is None:
                raise SystemExit("FATAL: boot_ready never set")
            t = inst.transport
            write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))
            ct, tag = c64_aead_encrypt(t, labels, key, nonce, aad, pt)
            if ct != exp_ct:
                print(f"  FAIL {v['desc']}: ciphertext differs from the RFC at byte "
                      f"{next(i for i in range(len(ct)) if ct[i] != exp_ct[i])} "
                      f"({ct.hex()[:32]}... vs {exp_ct.hex()[:32]}...)")
                failed += 1
            elif tag != exp_tag:
                print(f"  FAIL {v['desc']}: tag {tag.hex()}, RFC publishes {exp_tag.hex()}")
                failed += 1
            else:
                print(f"  ok  {v['desc']}: ciphertext and tag byte-exact")

            # Alarm proof: one flipped plaintext byte must move both outputs.
            pt2 = bytearray(pt)
            pt2[0] ^= 0x01
            ct2, tag2 = c64_aead_encrypt(t, labels, key, nonce, aad, bytes(pt2))
            if ct2 == exp_ct or tag2 == exp_tag:
                print(f"  FAIL alarm proof: flipping one plaintext bit left "
                      f"{'ciphertext' if ct2 == exp_ct else 'tag'} unchanged — this leg cannot "
                      f"detect a broken AEAD")
                failed += 1
            else:
                print("  ok  alarm proof: one flipped plaintext bit moves ciphertext AND tag")
        finally:
            mgr.release(inst)
    return (1 if failed == 0 else 0), failed


def leg3_differential(name, base, cur, inputs, describe, adjudicate=None):
    """Byte-identical results across the bump, over the same seeded inputs."""
    print(f"\n--- {name} ---")
    failed = 0
    if not cur or len(cur) != len(base):
        print(f"  FAIL {name}: collected {len(base)} baseline and {len(cur)} current results — "
              f"an empty or ragged comparison reports 'byte-identical' without comparing "
              f"anything. Check --iterations and both collect() runs.")
        return 0, 1
    diffs = []
    for i, (b, c) in enumerate(zip(base, cur)):
        if b != c:
            diffs.append(i)
    if not diffs:
        print(f"  ok  {len(cur)}/{len(cur)} results byte-identical across the bump")
        return 1, 0

    print(f"  {len(diffs)} of {len(cur)} results DIFFER across the bump")
    for i in diffs[:5]:
        print(f"    #{i}: {describe(inputs[i])}")
        print(f"        baseline {base[i]!r}")
        print(f"        bumped   {cur[i]!r}")
        if adjudicate is not None:
            verdict = adjudicate(inputs[i], base[i], cur[i])
            print(f"        {verdict}")
    print(f"  FAIL {name}: the bumped libraries do not reproduce the baseline's results on "
          f"{len(diffs)}/{len(cur)} seeded random inputs. Read the adjudication lines above "
          f"before calling this a regression — if the baseline disagrees with the host "
          f"reference and the bumped build agrees, the bump FIXED those inputs.")
    failed += 1
    return 0, failed


def main():
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    prg, labels_path = PRG_PATH, LABELS_PATH
    base_prg = base_labels = None
    n_scalar, n_aead = 8, 24
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1]); i += 2
        elif a == "--prg" and i + 1 < len(args):
            prg = args[i + 1]; i += 2
        elif a == "--labels" and i + 1 < len(args):
            labels_path = args[i + 1]; i += 2
        elif a == "--baseline-prg" and i + 1 < len(args):
            base_prg = args[i + 1]; i += 2
        elif a == "--baseline-labels" and i + 1 < len(args):
            base_labels = args[i + 1]; i += 2
        elif a == "--iterations" and i + 1 < len(args):
            n_scalar = int(args[i + 1]); i += 2
        else:
            i += 1
    if os.environ.get("TEST_SEED"):
        seed = int(os.environ["TEST_SEED"])
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    print(f"current  PRG: {prg}")
    print(f"baseline PRG: {base_prg}")

    passed = failed = 0
    p, f = leg1_x25519_rfc7748(prg, labels_path)
    passed += p; failed += f
    p, f = leg2_aead_rfc8439(prg, labels_path)
    passed += p; failed += f

    if not base_prg or not base_labels:
        print("\n--- legs 3-4: differential across the bump ---")
        print("  FAIL NOT RUN: --baseline-prg / --baseline-labels were not given. The published "
              "vectors above are three fixed inputs; they cannot tell whether the "
              "fe25519_mul_a24 carry fix changed results on inputs that reach the defect. "
              "Reporting this as a pass would answer half the question and look like all of it.")
        failed += 1
    else:
        sm_in, ae_in = make_inputs(rng, n_scalar, n_aead)
        print(f"\ncollecting {len(sm_in)} scalarmults + {len(ae_in)} AEAD encrypts on each build...")
        b_sm, b_ae, b_fault = collect(base_prg, base_labels, sm_in, ae_in, "baseline")
        c_sm, c_ae, c_fault = collect(prg, labels_path, sm_in, ae_in, "bumped")
        print(f"  x25519_reu_fault: baseline={b_fault}, bumped="
              f"{'$%02X' % c_fault if c_fault is not None else None}")
        if c_fault:
            print(f"  FAIL the bumped run recorded x25519_reu_fault=${c_fault:02X}: its REU DMAs "
                  f"were unconfirmed, so any difference below is a DMA fault, not a library "
                  f"result. Fix the REU configuration before reading legs 3-4.")
            failed += 1

        p, f = leg3_differential(
            "leg 3: X25519 scalarmult, baseline vs bumped", b_sm, c_sm, sm_in,
            lambda inp: f"scalar={inp[0].hex()[:16]}... u={inp[1].hex()[:16]}...",
            lambda inp, b, c: (
                "host reference agrees with BOTH (impossible — they differ)"
                if b == c else
                ("host reference agrees with the BUMPED build: the bump FIXED this input"
                 if _host_x25519(inp[0], inp[1]) == c else
                 ("host reference agrees with the BASELINE: the bump REGRESSED this input"
                  if _host_x25519(inp[0], inp[1]) == b else
                  "host reference agrees with NEITHER: both builds are wrong here"))))
        passed += p; failed += f

        p, f = leg3_differential(
            "leg 4: AEAD encrypt (ciphertext + tag), baseline vs bumped", b_ae, c_ae, ae_in,
            lambda inp: f"key={inp[0].hex()[:16]}... aad={len(inp[2])}B pt={len(inp[3])}B")
        passed += p; failed += f

    total = passed + failed
    print(f"\n{'='*60}\nResults: {passed}/{total} legs passed, {failed} failed\n{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
