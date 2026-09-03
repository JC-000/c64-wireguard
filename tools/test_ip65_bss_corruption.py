#!/usr/bin/env python3
"""test_ip65_bss_corruption.py — issue #80: ip65's BSS overwrites our code.

WHAT THIS PROVED
================

The vendored ip65 blob used to be linked with its BSS at ``$4000``
(``ip65-build/ip65.cfg``), inside ``MAIN_AREA_LO`` ($32F0-$7FFF) on top of
application code. ip65's ``eth_inp`` / ``eth_outp`` frame buffers live in
that BSS, so the moment the driver moved an ethernet frame it wrote
network bytes over the ChaCha20-Poly1305 implementation and the
transport path. Measured on the ethernet VICE rig with this probe: ONE
DHCP exchange overwrote 1017 bytes.

Two memory maps in this repo (``README.md`` and the header comment of
``cfg/c64-wireguard-ip65.cfg``) claimed ip65's BSS lived at
``$A000-$BFFF``. #79 corrected the prose; this test measured the thing
the prose was hiding.

STATUS: #80 IS FIXED — the blob is relinked at $A000, the consumer cfg
reserves IP65_BSS, and src/net/ip65/ip65_blob.s carries link-time asserts.
There is therefore no loaded WG byte inside the blob's BSS to watch, and
this runtime probe has nothing to measure. The separation is now asserted
STRUCTURALLY, in the gate, by tools/test_ip65_bss_guard.py — which also
reads the blob's own map (ip65-build/ip65-c64.map), the one input the
link-time asserts cannot see. When this probe finds no overlap it defers
to that guard and passes on its verdict rather than exiting FATAL as it
did when the overlap was expected to exist.

Should a relink ever put the blob's BSS back over loaded content, this
probe becomes live again automatically: it derives the overlap from the
maps, boots the PRG on the rig, presses 'I' and diffs RAM against the
PRG after DHCP.

METHOD (when there IS an overlap)
=================================

1. Derive the overlap from the two map files, never from constants here.
2. Take each surviving span's expected bytes from ``build/wireguard.prg``
   itself (one contiguous stream; address -> offset is
   ``2 + addr - load_address``).
3. Boot under an ethernet-capable VICE with the RR-Net cart, wait for
   ``boot_ready``, confirm every span still MATCHES the PRG (a baseline
   mismatch is a hard failure — the rest would be meaningless).
4. Press ``I`` (``do_net_init`` -> ip65 init + DHCP), wait for
   ``net_initialized``, re-read and diff.
5. Assert NO span diverged.

RIG
===

tools/vice_eth_rig.py: the feth/pcap rig (one privileged setup per boot,
done outside this test) and an ethernet-capable ``x64sc``
(``$VICE_ETHERNET_BIN`` / ``--vice-bin``). Missing prerequisites SKIP
(exit 77). ``warp`` stays off — warp breaks ip65's DHCP.

Usage::

    python3 tools/test_ip65_bss_corruption.py [--verbose]

    C64_SKIP_BUILD=1   reuse build/wireguard.prg (default: make BACKEND=ip65)

Exit codes: 0 PASS / 1 FAIL / 77 SKIP (rig absent).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    CFG_PATH, DEFAULT_VICE_BIN, DHCP_TIMEOUT, IP65_MAP_PATH, LABELS_PATH,
    PRG_PATH, WG_MAP_PATH, EthVice, assert_ip65_build, build_ip65, log,
    parse_cfg_memory, parse_cfg_segment_types, parse_map_segments, press_key,
    read_span, screen_text, skip_if_rig_down, wait_boot_ready,
    wait_net_initialized,
)

SETTLE_SECONDS = 10.0

VERBOSE = False


def vlog(msg: str) -> None:
    if VERBOSE:
        print(msg, flush=True)


# ============================================================================
# Deriving the overlap from the build, not from constants
# ============================================================================

class Span:
    """One checkable overlap: a WG segment's intersection with ip65's BSS."""

    def __init__(self, name: str, start: int, end: int, expected: bytes):
        self.name, self.start, self.end, self.expected = name, start, end, expected

    def __len__(self) -> int:
        return self.end - self.start + 1


def derive_spans() -> tuple[list[Span], tuple[int, int], dict]:
    """Compute the overlapping spans and their expected post-LOAD bytes."""
    ip65_segs = parse_map_segments(IP65_MAP_PATH)
    if "BSS" not in ip65_segs:
        raise RuntimeError(f"{IP65_MAP_PATH}: no BSS segment")
    bss_lo, bss_hi = ip65_segs["BSS"]

    wg_segs = parse_map_segments(WG_MAP_PATH)
    seg_types = parse_cfg_segment_types(CFG_PATH)
    regions = parse_cfg_memory(CFG_PATH)

    raw = open(PRG_PATH, "rb").read()
    load = raw[0] | (raw[1] << 8)
    body = raw[2:]
    img_lo, img_hi = load, load + len(body) - 1

    spans: list[Span] = []
    skipped: list[str] = []
    for name, (lo, hi) in sorted(wg_segs.items(), key=lambda kv: kv[1][0]):
        o_lo, o_hi = max(lo, bss_lo), min(hi, bss_hi)
        if o_lo > o_hi:
            continue
        kind = seg_types.get(name, "?")
        if kind == "bss":
            # Zero-filled in the PRG but written by the app at runtime by
            # design — a divergence here proves nothing about ip65.
            skipped.append(f"{name} (type=bss)")
            continue
        if o_lo < img_lo or o_hi > img_hi:
            skipped.append(f"{name} (outside the PRG image)")
            continue
        expected = body[o_lo - load: o_hi - load + 1]
        spans.append(Span(name, o_lo, o_hi, expected))

    info = {
        "bss": (bss_lo, bss_hi),
        "image": (img_lo, img_hi),
        "regions": regions,
        "skipped": skipped,
        "types": seg_types,
    }
    return spans, (bss_lo, bss_hi), info


# ============================================================================
# Comparison + reporting
# ============================================================================

def compare(tr, spans: list[Span]) -> dict[str, tuple[bytes, list[int]]]:
    """{span name: (bytes read, indexes that diverge from the PRG)}."""
    result = {}
    for s in spans:
        got = read_span(tr, s.start, s.end)
        bad = [i for i in range(len(s.expected)) if got[i] != s.expected[i]]
        result[s.name] = (got, bad)
    return result


def report(spans: list[Span], result: dict, phase: str) -> int:
    """Print a per-span verdict; return the number of corrupted spans."""
    corrupted = 0
    for s in spans:
        got, bad = result[s.name]
        if not bad:
            log(f"  {phase} {s.name:<26s} ${s.start:04X}-${s.end:04X} "
                f"{len(s):5d} B  clean")
            continue
        corrupted += 1
        i = bad[0]
        addr = s.start + i
        log(f"  {phase} {s.name:<26s} ${s.start:04X}-${s.end:04X} "
            f"{len(s):5d} B  {len(bad)} BYTES DIVERGED")
        log(f"       first divergence at ${addr:04X}")
        lo = max(0, i - (i % 8))
        chunk = slice(lo, min(len(s.expected), lo + 16))
        log(f"       PRG  ${s.start + lo:04X}: {s.expected[chunk].hex(' ')}")
        log(f"       RAM  ${s.start + lo:04X}: {got[chunk].hex(' ')}")
        runs, run_start, prev = [], bad[0], bad[0]
        for j in bad[1:]:
            if j != prev + 1:
                runs.append((run_start, prev))
                run_start = j
            prev = j
        runs.append((run_start, prev))
        shown = ", ".join(f"${s.start + a:04X}-${s.start + b:04X}"
                          for a, b in runs[:6])
        more = "" if len(runs) <= 6 else f" (+{len(runs) - 6} more)"
        log(f"       diverged ranges: {shown}{more}")
    return corrupted


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN),
        help="ethernet-capable x64sc (default: $VICE_ETHERNET_BIN or "
             f"{DEFAULT_VICE_BIN})")
    ap.add_argument("--port", type=int, default=0,
                    help="binary monitor port (default: allocate one)")
    ap.add_argument("--dhcp-timeout", type=float, default=DHCP_TIMEOUT)
    args = ap.parse_args()
    VERBOSE = args.verbose

    log("test_ip65_bss_corruption.py — issue #80")
    log("")

    skip_if_rig_down(args.vice_bin)

    build_ip65()
    for path in (PRG_PATH, LABELS_PATH, WG_MAP_PATH, IP65_MAP_PATH, CFG_PATH):
        if not os.path.exists(path):
            log(f"FATAL: missing {path}")
            return 1
    assert_ip65_build()

    spans, (bss_lo, bss_hi), info = derive_spans()
    log("=== Overlap derived from the build ===")
    log(f"  ip65 BSS (ip65-build/ip65-c64.map)   ${bss_lo:04X}-${bss_hi:04X}"
        f"  {bss_hi - bss_lo + 1} bytes")
    for region, (lo, hi) in sorted(info["regions"].items(), key=lambda kv: kv[1]):
        if max(lo, bss_lo) <= min(hi, bss_hi):
            log(f"  overlaps WG region {region} (${lo:04X}-${hi:04X})")
    log(f"  PRG image (build/wireguard.prg)      ${info['image'][0]:04X}-"
        f"${info['image'][1]:04X}")
    if not spans:
        # #80 is fixed: nothing of ours is loaded inside the blob's BSS, so
        # there is nothing a runtime diff could catch. The separation is a
        # link-level fact and tools/test_ip65_bss_guard.py asserts it (in
        # the gate) from the blob's own map — run it here and pass on its
        # verdict rather than calling an absence of overlap a FATAL.
        log("  no loaded WG segment overlaps ip65's BSS — deferring to the "
            "structural guard (tools/test_ip65_bss_guard.py)")
        import test_ip65_bss_guard as guard
        problems = guard.check_layout(*guard.measured_inputs())
        if problems:
            log("FAIL: the structural guard reports:")
            for p in problems:
                log(f"  - {p}")
            return 1
        log("PASS: link-level separation holds (blob BSS inside IP65_BSS, "
            "disjoint from every WG segment); no runtime probe needed.")
        return 0
    total = 0
    for s in spans:
        log(f"  checking {s.name:<26s} ${s.start:04X}-${s.end:04X}  "
            f"{len(s):5d} bytes  (type={info['types'].get(s.name, '?')})")
        total += len(s)
    for note in info["skipped"]:
        vlog(f"  not checked: {note}")
    log(f"  {len(spans)} spans, {total} bytes of loaded content inside "
        "ip65's BSS")
    log("")

    labels = Labels.from_file(LABELS_PATH)
    t0 = time.monotonic()
    with EthVice(args.vice_bin, port=args.port) as vice:
        tr = vice.tr
        if not wait_boot_ready(tr, labels):
            log("FATAL: boot_ready never set")
            log(screen_text(tr))
            return 1
        log(f"  boot complete (+{time.monotonic() - t0:.0f}s)")
        log("")

        log("=== Baseline: RAM vs PRG, before any network activity ===")
        base = compare(tr, spans)
        if report(spans, base, "BASE"):
            log("")
            log("FAIL: spans already diverge from the PRG before ip65 has "
                "moved a single frame.")
            log("  That is NOT the #80 defect — it means the load image, the "
                "map parsing, or")
            log("  boot-time self-modifying code disagrees with this test's "
                "premise. The rest")
            log("  of the run would be meaningless, so it is not attempted.")
            return 1
        log("  baseline clean — every checked byte matches the PRG")
        log("")

        log("=== Driving network init ('I' -> do_net_init -> DHCP) ===")
        if not press_key(tr, "I"):
            log("FATAL: the C64 never consumed the keystroke")
            return 1
        outcome, text = wait_net_initialized(tr, labels, args.dhcp_timeout)
        if outcome == "ok":
            log(f"  network up (+{time.monotonic() - t0:.0f}s): "
                f"{text[text.find('NETWORK READY'):][:60].strip()}")
        elif outcome == "timeout":
            log(f"  network init neither succeeded nor reported failure "
                f"within {args.dhcp_timeout:.0f}s")
        else:
            log(f"  network init reported: {outcome}")
        vlog(text)

        # ip65 keeps handling frames from main_loop's net_poll; give it a
        # moment of ordinary running so the measurement is not a race
        # against the last DHCP packet.
        settle_end = time.monotonic() + SETTLE_SECONDS
        while time.monotonic() < settle_end:
            tr.resume()
            time.sleep(1.0)
        log("")

        log("=== After network activity: RAM vs PRG ===")
        post = compare(tr, spans)
        corrupted = report(spans, post, "POST")
        log("")

        if corrupted:
            damaged = sum(len(post[s.name][1]) for s in spans)
            log(f"FAIL: {damaged} bytes of loaded program content inside "
                f"ip65's BSS were overwritten")
            log(f"      across {corrupted} of {len(spans)} checked segments.")
            log("      ip65's frame buffers are writing over application "
                "code — issue #80.")
            return 1
        if outcome != "ok":
            log("INCONCLUSIVE (reported as FAIL): nothing was corrupted, but "
                "network init did")
            log("      not complete either, so ip65 may never have moved a "
                "frame. Check the rig")
            log("      (dnsmasq on feth1, no second VICE on feth0) and rerun.")
            return 1
        log("PASS: DHCP completed and no loaded byte inside ip65's BSS "
            "was disturbed.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
