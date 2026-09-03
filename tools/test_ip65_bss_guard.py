#!/usr/bin/env python3
"""test_ip65_bss_guard.py — issue #80, the structural guard.

The ip65 blob is a position-linked `.incbin`; its BSS is claimed by the
driver at RUNTIME, so ld65 sees no allocation there and cannot detect a
collision with our own segments. #80 was exactly that: the blob's BSS at
$4000 sat on top of APP_CODE and the chacha archive, linked clean, and
one DHCP exchange overwrote 1017 bytes of code. It is fixed by relinking
the blob at $A000 and reserving IP65_BSS in the consumer cfg, with link-
time asserts in src/net/ip65/ip65_blob.s.

THOSE ASSERTS HAVE A BLIND SPOT, which is why this suite exists. They
compare the §13.7 EQUATE (LIB_NET_IP65_BLOB_BSS_BASE = $A000, hand-
maintained) against the consumer cfg's IP65_BSS region. Neither side is
the blob. Point ip65-build/ip65.cfg's BSS back at $4000 and the blob
relinks there, ip65-c64.map says so, the equate still says $A000, the cfg
still says $A000, and every assert in ip65_blob.s stays green — measured,
see the alarm proof in the PR. The ONLY machine-readable record of where
the blob's BSS really went is ip65-build/ip65-c64.map, and nothing in the
link reads it.

So this suite reads it. From the two maps and the cfg, it asserts:

  1. every WG segment (build/wireguard.map) is DISJOINT from the IP65_BSS
     reservation (cfg MEMORY) — nothing of ours has grown into the window
     (disjointness, not a ceiling: a segment linked above $BFFF is legal);
  2. every WG segment is disjoint from the blob's MEASURED BSS
     (ip65-c64.map `BSS` row) — the #80 collision itself;
  3. the measured BSS lies inside the IP65_BSS reservation — the blob is
     where the consumer says it is, not merely somewhere harmless;
  4. the §13.7 equates exported into build/labels.txt agree with the
     measurement (base equal, size equal) — the declaration consumers
     compose against cannot drift from the artifact;
  5. the measured BSS misses every other MEMORY region of the cfg
     (LOADER, NET_CODE, MAIN_AREA_*, SQTAB_HOLE, APP_BSS_OVERLAY).

ALARM PROOF: `--self-test` runs the same checker on the pre-#80 layout
(blob BSS $4000-$4F3F under today's WG map) and requires it to FAIL, so a
detector that quietly passes on the defect is caught here rather than
trusted. The real-artifact version of that proof (ip65.cfg edited to
$4000, blob relinked, this suite run) is recorded in the PR.

This RETIRES the FATAL-exit path of tools/test_ip65_bss_corruption.py:
that runtime probe measured the corruption while the overlap existed and,
now that it does not, has nothing to check; the separation is asserted
here at link level instead, in the gate. The runtime probe keeps its rig
scaffold (tools/vice_eth_rig.py) for the VICE-ethernet suites.

Build-tree mutator (needs a BACKEND=ip65 build; builds one unless
C64_SKIP_BUILD): listed under SERIAL_TESTS in tools/run_regression.py.

Usage:
    python3 tools/test_ip65_bss_guard.py [--self-test] [--verbose]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    CFG_PATH, IP65_MAP_PATH, LABELS_PATH, WG_MAP_PATH, assert_ip65_build,
    build_ip65, parse_cfg_memory, parse_map_segments,
)

IP65_BSS_REGION = "IP65_BSS"
EQ_BASE = "LIB_NET_IP65_BLOB_BSS_BASE"
EQ_SIZE = "LIB_NET_IP65_BLOB_BSS_SIZE"


def _hx(lo: int, hi: int) -> str:
    return f"${lo:04X}-${hi:04X}"


def check_layout(wg_segs: dict[str, tuple[int, int]],
                 blob_bss: tuple[int, int],
                 regions: dict[str, tuple[int, int]],
                 equates: dict[str, int | None]) -> list[str]:
    """Return the list of violations (empty == the layout is safe).

    Pure: takes parsed inputs so --self-test can feed it the defect.
    """
    problems: list[str] = []
    bss_lo, bss_hi = blob_bss
    if IP65_BSS_REGION not in regions:
        return [f"cfg has no {IP65_BSS_REGION} MEMORY region — the "
                "reservation that #80 introduced is gone"]
    res_lo, res_hi = regions[IP65_BSS_REGION]

    # 1 + 2: our segments must be DISJOINT from the reservation and from
    # the measured BSS. Disjointness, not a ceiling: the previous form
    # flagged any segment ending at or above res_lo, which would have
    # false-positived on a segment legitimately linked ABOVE the window
    # (there is RAM at $C000-$CFFF, and a future cfg may use it). What
    # matters is overlap, and only overlap. [a,b] and [c,d] are disjoint
    # iff b < c or d < a.
    for name, (lo, hi) in sorted(wg_segs.items(), key=lambda kv: kv[1][0]):
        if max(lo, res_lo) <= min(hi, res_hi):
            problems.append(
                f"WG segment {name} {_hx(lo, hi)} OVERLAPS the "
                f"{IP65_BSS_REGION} reservation {_hx(res_lo, res_hi)}")
        if max(lo, bss_lo) <= min(hi, bss_hi):
            problems.append(
                f"WG segment {name} {_hx(lo, hi)} OVERLAPS the blob's "
                f"measured BSS {_hx(bss_lo, bss_hi)} (issue #80: ip65's frame "
                f"buffers would overwrite it)")

    # 3: the blob is inside the reservation.
    if not (res_lo <= bss_lo and bss_hi <= res_hi):
        problems.append(
            f"blob BSS {_hx(bss_lo, bss_hi)} (ip65-build/ip65-c64.map) is not "
            f"inside the {IP65_BSS_REGION} reservation {_hx(res_lo, res_hi)} "
            "(cfg/c64-wireguard-ip65.cfg) — ip65-build/ip65.cfg and the "
            "consumer cfg have drifted apart")

    # 4: the §13.7 declaration matches the artifact.
    base, size = equates.get(EQ_BASE), equates.get(EQ_SIZE)
    if base is None or size is None:
        problems.append(f"{EQ_BASE}/{EQ_SIZE} not exported into labels.txt "
                        "(src/net/ip65/ip65_blob.s SPEC 13.7 exports)")
    else:
        if base != bss_lo:
            problems.append(
                f"{EQ_BASE} = ${base:04X} but the blob's BSS is linked at "
                f"${bss_lo:04X} — the equate the link asserts trust no longer "
                "names the real address (relink without refreshing "
                "ip65_blob.s?)")
        if size != bss_hi - bss_lo + 1:
            problems.append(
                f"{EQ_SIZE} = {size} but the measured BSS is "
                f"{bss_hi - bss_lo + 1} bytes {_hx(bss_lo, bss_hi)} — refresh "
                "src/net/ip65/ip65_blob.s after the relink")

    # 5: the blob misses every other region.
    for rname, (lo, hi) in regions.items():
        if rname == IP65_BSS_REGION:
            continue
        if max(lo, bss_lo) <= min(hi, bss_hi):
            problems.append(
                f"blob BSS {_hx(bss_lo, bss_hi)} overlaps cfg region {rname} "
                f"{_hx(lo, hi)}")
    return problems


def measured_inputs():
    ip65_segs = parse_map_segments(IP65_MAP_PATH)
    if "BSS" not in ip65_segs:
        raise RuntimeError(f"{IP65_MAP_PATH}: no BSS segment")
    wg_segs = parse_map_segments(WG_MAP_PATH)
    regions = parse_cfg_memory(CFG_PATH)
    labels = Labels.from_file(LABELS_PATH)
    equates = {EQ_BASE: labels.address(EQ_BASE), EQ_SIZE: labels.address(EQ_SIZE)}
    return wg_segs, ip65_segs["BSS"], regions, equates


def self_test(wg_segs, regions, equates, verbose: bool) -> bool:
    """The pre-#80 layout must trip the checker."""
    defect_bss = (0x4000, 0x4F3F)
    problems = check_layout(wg_segs, defect_bss, regions, equates)
    if verbose:
        for p in problems:
            print(f"      alarm: {p}")
    ok = any("OVERLAPS the blob's measured BSS" in p for p in problems) \
        and any("not inside the IP65_BSS reservation" in p for p in problems)
    # And the converse, so the loosening from ceiling to disjointness in
    # check 1 cannot silently become a no-op: a segment placed ABOVE the
    # window is legal and must NOT be reported, while one placed INSIDE it
    # must be.
    above = dict(wg_segs); above["PROBE_ABOVE"] = (0xC000, 0xC0FF)
    inside = dict(wg_segs); inside["PROBE_INSIDE"] = (0xA800, 0xA8FF)
    p_above = [x for x in check_layout(above, (0xA000, 0xAF3F), regions, equates)
               if "PROBE_ABOVE" in x]
    p_inside = [x for x in check_layout(inside, (0xA000, 0xAF3F), regions, equates)
                if "PROBE_INSIDE" in x]
    print(f"  {'PASS' if not p_above else 'FAIL'}  self-test: a segment at "
          "$C000-$C0FF (above the window) is NOT flagged"
          + ("" if not p_above else f" — {p_above}"))
    print(f"  {'PASS' if p_inside else 'FAIL'}  self-test: a segment at "
          "$A800-$A8FF (inside the window) IS flagged")
    ok = ok and not p_above and bool(p_inside)
    print(f"  {'PASS' if ok else 'FAIL'}  self-test: blob BSS at "
          f"$4000-$4F3F (the #80 layout) trips the checker "
          f"({len(problems)} violation(s))")
    # And a layout that is only *harmlessly* wrong must still trip: a BSS
    # parked at $C000 misses every WG segment but is not where the cfg
    # says, so consumers composing against §13.7 would be lied to.
    stray = check_layout(wg_segs, (0xC000, 0xCF3F), regions, equates)
    ok2 = any("not inside the IP65_BSS reservation" in p for p in stray)
    print(f"  {'PASS' if ok2 else 'FAIL'}  self-test: blob BSS parked at "
          "$C000 (misses everything, wrong window) still trips")
    # Equate drift alone must trip too (the link asserts' blind spot).
    drift = dict(equates)
    drift[EQ_BASE] = 0x9000
    ok3 = any(EQ_BASE in p for p in
              check_layout(wg_segs, (0xA000, 0xAF3F), regions, drift))
    print(f"  {'PASS' if ok3 else 'FAIL'}  self-test: {EQ_BASE} disagreeing "
          "with the map trips")
    return ok and ok2 and ok3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="print every violation the alarm proof raises "
                         "(the proof itself always runs)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    print("test_ip65_bss_guard.py — issue #80 structural guard")
    build_ip65()
    for path in (WG_MAP_PATH, IP65_MAP_PATH, CFG_PATH, LABELS_PATH):
        if not os.path.exists(path):
            print(f"FATAL: missing {path}")
            return 1
    assert_ip65_build()

    wg_segs, blob_bss, regions, equates = measured_inputs()
    print(f"  blob BSS (ip65-build/ip65-c64.map)  {_hx(*blob_bss)}  "
          f"{blob_bss[1] - blob_bss[0] + 1} B")
    print(f"  {IP65_BSS_REGION} reservation (cfg)         "
          f"{_hx(*regions.get(IP65_BSS_REGION, (0, 0)))}")
    print(f"  {EQ_BASE} = {equates[EQ_BASE]}  {EQ_SIZE} = {equates[EQ_SIZE]} "
          "(labels.txt)")
    top = max(hi for _, hi in wg_segs.values())
    print(f"  highest WG segment end (build/wireguard.map)  ${top:04X} "
          f"over {len(wg_segs)} segments")
    if args.verbose:
        for name, (lo, hi) in sorted(wg_segs.items(), key=lambda kv: kv[1][0]):
            print(f"      {name:<28s} {_hx(lo, hi)}")

    problems = check_layout(wg_segs, blob_bss, regions, equates)
    failed = 0
    if problems:
        failed += 1
        print(f"  FAIL  layout: {len(problems)} violation(s)")
        for p in problems:
            print(f"        - {p}")
    else:
        print("  PASS  layout: every WG segment is below IP65_BSS and disjoint "
              "from the measured blob BSS; the blob is inside its "
              "reservation; the §13.7 equates match the map")

    # The alarm proof always runs: a guard whose alarm was never proven is
    # the thing #80 taught us not to trust. Cheap — pure functions on parsed
    # data. --self-test only adds the per-violation detail.
    if not self_test(wg_segs, regions, equates, args.verbose or args.self_test):
        failed += 1

    print(f"\n{'PASS' if not failed else 'FAIL'}: ip65 BSS guard "
          f"({failed} failing group(s))")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
