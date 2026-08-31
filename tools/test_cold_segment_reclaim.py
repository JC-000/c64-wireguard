#!/usr/bin/env python3
"""test_cold_segment_reclaim.py — issue #103: prove LIB_X25519_INIT_CODE is dead.

WHAT THIS EXISTS TO PROVE

`LIB_X25519_INIT_CODE` holds the x25519 archive's cold init: `sqtab_init`
(a.k.a. `mul_tables_init`), `reu_mul_init` and `reu_probe`. Both cfgs had
described it as "reclaimable as scratch RAM after boot" since the archive
was ingested, and nothing had ever reclaimed it — the claim was inherited,
not tested. Issue #103 needed those 826 bytes, so the claim had to become a
fact.

It is now reclaimed: `APP_BSS_OVERLAY` lays `APP_BSS` over that span, and
`src/boot.s` zeroes it the instant the table build returns. That means the
cold code is not merely unreferenced after boot — it is **destroyed**, and
$00 is `BRK`, so any surviving entry into it derails into the KERNAL BRK
handler rather than silently doing something plausible.

That is what makes this test a red/green rather than a coverage claim:

  GREEN  the span reads back as $00, and every product of the destroyed code
         is still intact and still correct — the quarter-square table at
         $8000 that `sqtab_init` built, and the REU multiplication rows that
         `reu_mul_init` built, exercised through a real `fe25519_mul`.

  RED    the test drives the ONE guarded call site that can still branch into
         the span — `poly1305_init`'s `jsr sqtab_init`, gated on chacha's
         `sqtab_ready` — by clearing that gate on purpose. The call must NOT
         return. If it does return, the span was not actually erased and
         every "green" result above is meaningless, so this is checked
         explicitly rather than assumed.

Note what "the gate passed" would NOT have proven: the suites in tools/ could
all pass while never once entering the cold segment, which is exactly the
situation you are in whether the code is dead or merely rarely needed. The
RED case is the part that distinguishes those two worlds.

WHY THE OTHER SUITES STOPPED RE-RUNNING reu_mul_init

Three suites (test_fe25519, test_blake2s_keylen_regression, test_type2_slow)
used to `jsr reu_mul_init` after takeover, because before issue #55 they
waited on the "Q=QUIT" title text, which boot.s prints BEFORE the table
build. Since #55 they wait on `boot_ready`, which boot.s sets AFTER it
(see the docstring on vice_util.binary_wait_for_boot_ready). The rebuild has
been redundant ever since, and is now impossible: those addresses are BSS.
Their continuing to pass is the second half of the evidence here.

Usage:
    python3 tools/test_cold_segment_reclaim.py
"""
import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from c64_test_harness.transport import TimeoutError as HarnessTimeout
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# src/crypto/shared/sqtab_base.inc
WG_SQTAB_LO = 0x8000
WG_SQTAB_HI = 0x8200

P = 2**255 - 19


def _fe_scratch(labels):
    """Resolve the three field-element scratch buffers on either build.

    The in-tree fe25519 exports fe_tmp{1..3}; the c64-x25519 sibling calls
    the same buffers fe25519_tmp{1..3}. Same shim test_fe25519.py carries.
    """
    for legacy, canonical in (("fe_tmp1", "fe25519_tmp1"),
                              ("fe_tmp2", "fe25519_tmp2"),
                              ("fe_tmp3", "fe25519_tmp3")):
        if labels.address(legacy) is None and labels.address(canonical) is not None:
            labels._by_name[legacy] = labels._by_name[canonical]
    return labels["fe_tmp1"], labels["fe_tmp2"], labels["fe_tmp3"]


def le32_to_int(b):
    return int.from_bytes(b, "little")


def int_to_le32(v):
    return v.to_bytes(32, "little")


def check_span_erased(tr, load, size):
    """T1 — boot.s actually zeroed the reclaimed span."""
    data = read_bytes(tr, load, size)
    nonzero = [(load + i, b) for i, b in enumerate(data) if b != 0]
    if nonzero:
        head = ", ".join(f"${a:04X}=${v:02X}" for a, v in nonzero[:8])
        print(f"FAIL T1: {len(nonzero)} of {size} bytes in the reclaimed span "
              f"${load:04X}-${load + size - 1:04X} are not $00 ({head}). "
              f"boot.s's zero-fill did not run, or did not cover the span — "
              f"APP_BSS variables living there are holding cold init code.")
        return False
    print(f"PASS T1: reclaimed span ${load:04X}-${load + size - 1:04X} "
          f"({size} bytes) reads back all $00 — the cold init code is gone "
          f"and those addresses are zero-initialised APP_BSS")
    return True


def check_sqtab_intact(tr):
    """T2 — the table sqtab_init built survived the code being erased."""
    lo = read_bytes(tr, WG_SQTAB_LO, 512)
    hi = read_bytes(tr, WG_SQTAB_HI, 512)
    bad = []
    for i in range(512):
        want = (i * i) // 4
        if lo[i] != (want & 0xFF) or hi[i] != ((want >> 8) & 0xFF):
            bad.append(i)
    if bad:
        print(f"FAIL T2: quarter-square table wrong at {len(bad)} of 512 "
              f"entries (first: i={bad[0]}). sqtab_init's output did not "
              f"survive; either it never ran or the zero-fill overran into "
              f"$8000-$83FF.")
        return False
    print("PASS T2: all 512 quarter-square entries at $8000/$8200 match "
          "floor(i*i/4) — sqtab_init's product outlived sqtab_init")
    return True


def check_reu_tables_intact(tr, labels):
    """T3 — the REU rows reu_mul_init built are still there and still right.

    fe25519_mul reads them through reu_fetch_mul_row on every limb product,
    so a correct result here means the destroyed reu_mul_init's output is
    intact AND the hot multiply path never re-enters the cold segment.
    """
    if "fe25519_mul" not in labels:
        print("SKIP T3: no fe25519_mul label")
        return True
    t1, t2, t3 = _fe_scratch(labels)
    cases = [
        (2, 3),
        (P - 1, P - 1),
        (0x1234567890ABCDEF, 0xFEDCBA0987654321),
    ]
    ok = True
    for a, b in cases:
        write_bytes(tr, t1, int_to_le32(a))
        write_bytes(tr, t2, int_to_le32(b))
        for name, addr in (("fe25519_src1", t1),
                           ("fe25519_src2", t2),
                           ("fe25519_dst", t3)):
            write_bytes(tr, labels[name], bytes([addr & 0xFF, addr >> 8]))
        jsr(tr, labels["fe25519_mul"], timeout=120.0)
        got = le32_to_int(read_bytes(tr, t3, 32)) % P
        want = (a * b) % P
        if got != want:
            print(f"FAIL T3: fe25519_mul({a:#x}, {b:#x}) = {got:#x}, "
                  f"expected {want:#x} — the REU multiplication rows "
                  f"reu_mul_init built are wrong or gone")
            ok = False
    if ok:
        print(f"PASS T3: fe25519_mul correct on {len(cases)} known answers — "
              "reu_mul_init's REU rows outlived reu_mul_init, and the hot "
              "multiply path does not re-enter the reclaimed span")
    return ok


def check_span_is_usable_bss(tr, load, size):
    """T4 — the reclaimed span is RAM we own, not a mirror or a hole.

    RESTORES THE SPAN BYTE FOR BYTE afterwards. The first version of this
    left the span zeroed, which silently disarmed T5: on a tree where the
    reclaim had NOT happened, T4 erased the live sqtab_init itself, and T5
    then "passed" by derailing on damage this test had done. Measured — the
    pre-reclaim tree scored 4/5 with T1 the only failure, when it should
    have scored 3/5. Any check that writes to the span has to put it back.
    """
    original = read_bytes(tr, load, size)
    probe = bytes((i * 37 + 11) & 0xFF for i in range(size))
    write_bytes(tr, load, probe)
    back = read_bytes(tr, load, size)
    write_bytes(tr, load, original)
    if back != probe:
        first = next(i for i in range(size) if back[i] != probe[i])
        print(f"FAIL T4: reclaimed span does not hold what is written to it "
              f"(first mismatch at ${load + first:04X}: wrote "
              f"${probe[first]:02X}, read ${back[first]:02X}) — it is not "
              f"usable as APP_BSS")
        return False
    print(f"PASS T4: all {size} bytes of the reclaimed span round-trip a "
          "write — it is ordinary read/write RAM available to APP_BSS")
    return True


def check_red_guarded_reentry(tr, labels):
    """T5 (RED) — force the one live branch into the span; it must derail.

    poly1305_init contains `lda sqtab_ready / bne skip / jsr sqtab_init`.
    sqtab_ready is set once at boot and never cleared, which is the whole
    reason the reclaim is safe. Clear it and the jsr goes to the erased
    span, where $00 = BRK. The call must not return.

    If it DOES return, the span still holds executable cold init and T1-T4
    were measuring the wrong thing.
    """
    if "sqtab_ready" not in labels or "poly1305_init" not in labels:
        print("SKIP T5: no sqtab_ready / poly1305_init label (non-sibling build)")
        return True
    saved = read_bytes(tr, labels["sqtab_ready"], 1)
    if saved[0] == 0:
        print("FAIL T5: sqtab_ready is already 0 after boot — the guard that "
              "makes this reclaim safe is not actually set, so a routine "
              "AEAD call would branch into the erased span")
        return False
    write_bytes(tr, labels["sqtab_ready"], bytes([0]))
    try:
        # The harness raises its own TimeoutError (c64_test_harness.transport),
        # which does NOT subclass the builtin — catching the builtin here
        # silently turns the red case into an error instead of a pass.
        jsr(tr, labels["poly1305_init"], timeout=8.0)
    except (HarnessTimeout, TimeoutError):
        print("PASS T5 (red): with sqtab_ready cleared, poly1305_init's "
              "jsr sqtab_init entered the erased span and never returned — "
              "the span is genuinely destroyed, and a live re-entry would "
              "be caught, not tolerated")
        return True
    print("FAIL T5 (red): poly1305_init returned with sqtab_ready cleared. "
          "It took the jsr sqtab_init branch into a span that is supposed to "
          "be erased and came back, so the cold code is still executable "
          "there and T1-T4 prove nothing.")
    return False


def main():
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], capture_output=True)
        r = subprocess.run(["make", "BACKEND=uci", "USE_X25519_SIBLING=1"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            return 1

    labels = Labels.from_file(LABELS_PATH)

    load = labels.address("__LIB_X25519_INIT_CODE_LOAD__")
    size = labels.address("__LIB_X25519_INIT_CODE_SIZE__")
    if load is None or size is None:
        print("FATAL: __LIB_X25519_INIT_CODE_LOAD__/_SIZE__ missing from "
              f"{LABELS_PATH}. They come from `define = yes` on the segment "
              "in cfg/c64-wireguard-*.cfg; without them boot.s cannot know "
              "what to zero and this test cannot know what to check.")
        return 1
    if size == 0:
        print("SKIP: LIB_X25519_INIT_CODE is empty (USE_X25519_SIBLING=0) — "
              "there is no cold segment to reclaim in this build")
        return 0

    _fe_scratch(labels)
    for n in ("fe_tmp1", "fe_tmp2", "fe_tmp3", "fe25519_src1", "fe25519_src2",
              "fe25519_dst", "fe25519_mul"):
        if labels.address(n) is None:
            print(f"FATAL: label {n} missing")
            return 1

    print(f"reclaimed span: ${load:04X}-${load + size - 1:04X} ({size} bytes)")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    results = []
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        tr = inst.transport
        if binary_wait_for_boot_ready(tr, labels, timeout=300.0) is None:
            print("FATAL: boot_ready never set")
            return 1
        # Park the main loop so it cannot race our direct-memory calls.
        write_bytes(tr, 0x0339, bytes([0x4C, 0x39, 0x03]))

        # Order matters. T5 derails the CPU, so it goes last; and every
        # check before it must leave the span exactly as boot left it, or
        # T5 stops discriminating (see check_span_is_usable_bss).
        results.append(check_span_erased(tr, load, size))
        results.append(check_sqtab_intact(tr))
        results.append(check_reu_tables_intact(tr, labels))
        results.append(check_span_is_usable_bss(tr, load, size))
        results.append(check_red_guarded_reentry(tr, labels))

        mgr.release(inst)

    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} passed")
    print(f"{'=' * 60}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
