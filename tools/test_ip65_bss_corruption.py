#!/usr/bin/env python3
"""test_ip65_bss_corruption.py — issue #80: ip65's BSS overwrites our code.

WHAT THIS PROVES
================

The vendored ip65 blob is linked with its BSS at ``$4000`` (see
``ip65-build/ip65.cfg``: ``BSS: file = "", start = $4000, size = $2000``).
Our own ip65-backend link script puts ``MAIN_AREA_LO`` at ``$32F0-$7FFF``
and routes code and read-only data into it.  The two overlap.  ip65's
``eth_inp`` / ``eth_outp`` frame buffers live in that BSS, so the moment
the driver moves an ethernet frame it writes network bytes over
application code — including part of the ChaCha20-Poly1305
implementation the tunnel's encryption depends on.

Two memory maps in this repo (``README.md`` and the header comment of
``cfg/c64-wireguard-ip65.cfg``) claimed ip65's BSS lived at
``$A000-$BFFF``.  #79 corrected the prose; this test measures the thing
the prose was hiding.

METHOD
======

1. Derive the overlap from the two map files, never from constants here.
   ``ip65-build/ip65-c64.map`` gives ip65's BSS extent; ``build/wireguard.map``
   gives our segment layout; ``cfg/c64-wireguard-ip65.cfg`` gives each
   segment's type so ``type = bss`` segments (legitimately written at
   runtime) are excluded.  Hardcoding the numbers is exactly the failure
   mode #80 is about — a memory map believed rather than measured.
2. Take each surviving span's expected bytes from ``build/wireguard.prg``
   itself.  The PRG is one contiguous stream (``$0801-$9FFF``, every
   region ``fill = yes``), so address -> offset is
   ``2 + addr - load_address`` and the post-LOAD contents of any loaded
   address are known exactly.
3. Boot the PRG under an ethernet-capable VICE with the RR-Net cart
   active, wait for ``boot_ready``, and confirm every span still MATCHES
   the PRG.  A baseline mismatch means something else is wrong and the
   rest of the run would be meaningless, so that is a hard failure.
4. Press ``I`` (``do_net_init`` -> ``net_init`` -> ip65 init + DHCP) so
   the driver starts moving frames, wait for DHCP, then re-read and diff.
5. Assert NO span diverged.

CURRENT STATUS: THIS TEST FAILS ON MASTER — that is the point.  It
demonstrates #80 today and becomes the regression guard once the blob's
BSS is relinked outside every WG-claimed region.  It is deliberately NOT
in ``tools/run_regression.py``; a known-failing entry there would take
the gate off 22/22.  Add it to the gate as part of fixing #80.

RIG
===

Needs the macOS feth/pcap rig (one privileged setup per boot, done
outside this test) and an ethernet-capable ``x64sc``.  Stock macOS VICE
gates the pcap rawnet driver on euid 0 and Homebrew's bottle is built
without networking at all — it starts, serves the binary monitor and
attaches no BPF device, so ethernet tests pass against dead silence
(c64-test-harness#144).  ``$VICE_ETHERNET_BIN`` (or ``--vice-bin``) must
name a build that can actually do it.  Every rig prerequisite is checked
up front and a missing one SKIPs (exit 77) rather than failing
confusingly.

``warp`` MUST stay off: warp compresses ip65's DHCP retry budget below
dnsmasq's OFFER latency and DHCP fails every time.  Runs are therefore
honest-speed — budget ~25 s to boot and up to ~120 s for DHCP.

Usage::

    python3 tools/test_ip65_bss_corruption.py [--verbose]

    C64_SKIP_BUILD=1   reuse build/wireguard.prg (default: make BACKEND=ip65)

Exit codes: 0 PASS / 1 FAIL / 77 SKIP (rig absent).
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, ScreenGrid  # noqa: E402
from c64_test_harness.backends.vice_binary import BinaryViceTransport  # noqa: E402
from c64_test_harness.backends.vice_lifecycle import (  # noqa: E402
    ViceConfig, ViceProcess, bpf_capture_available,
)
from c64_test_harness.backends.vice_manager import PortAllocator  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
WG_MAP_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.map")
IP65_MAP_PATH = os.path.join(PROJECT_ROOT, "ip65-build", "ip65-c64.map")
CFG_PATH = os.path.join(PROJECT_ROOT, "cfg", "c64-wireguard-ip65.cfg")

# The rig from c64-https' tools/rig-up-macos.sh: an feth pair, the host
# on feth1, VICE's pcap driver on feth0, dnsmasq serving DHCP on feth1.
HOST_IP = "10.0.65.1"
ETH_IFACE = "feth0"
DNSMASQ_PIDFILE = "/tmp/c64-rig-dnsmasq.pid"
DEFAULT_VICE_BIN = os.path.expanduser("~/opt/vice-eth/bin/x64sc")

# KERNAL keyboard queue — see tools/wg_c64_input.py for the full mechanics.
# Bytes first, count last: the IRQ scan reads the count to decide whether
# the queue is live.
KBD_BUFFER = 0x0277
KBD_COUNT = 0x00C6

BOOT_TIMEOUT = 180.0
DHCP_TIMEOUT = 120.0
SETTLE_SECONDS = 10.0

# do_net_init's own strings (src/wg/strings.s), matched on screen.
NET_OK_NEEDLE = "LISTENING ON PORT"
NET_FAIL_NEEDLES = ("NET INIT FAILED", "DHCP FAILED", "LISTEN FAILED")

VERBOSE = False


def log(msg: str) -> None:
    print(msg, flush=True)


def vlog(msg: str) -> None:
    if VERBOSE:
        print(msg, flush=True)


# ============================================================================
# Rig preflight
# ============================================================================

def rig_problems(vice_bin: str) -> list[str]:
    """Return missing-prerequisite messages; empty means the rig is up."""
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["not macOS — this rig is the feth/pcap one from "
                "c64-https' tools/rig-up-macos.sh"]
    if not os.path.exists(vice_bin):
        problems.append(
            f"{vice_bin} missing — an ethernet-capable x64sc is required "
            "(stock macOS VICE gates pcap on euid 0; Homebrew's bottle has "
            "networking compiled out entirely — c64-test-harness#144). "
            "Set VICE_ETHERNET_BIN or pass --vice-bin.")
    if not bpf_capture_available():
        # Both nodes need world rw; the perms reset on reboot.
        modes = []
        for node in ("/dev/bpf0", "/dev/bpf1"):
            try:
                m = os.stat(node).st_mode
                modes.append(f"{node} {'rw' if (m & stat.S_IROTH and m & stat.S_IWOTH) else 'not world-rw'}")
            except FileNotFoundError:
                modes.append(f"{node} missing")
        problems.append("no usable /dev/bpf node (" + ", ".join(modes) + ")")
    r = subprocess.run(["ifconfig", ETH_IFACE], capture_output=True, text=True)
    if r.returncode != 0:
        problems.append(f"{ETH_IFACE} missing")
    r = subprocess.run(["ifconfig", "feth1"], capture_output=True, text=True)
    if r.returncode != 0 or f"inet {HOST_IP} " not in r.stdout:
        problems.append(f"feth1 missing or not at {HOST_IP}")
    # Another VICE on feth0 is a hard conflict: every ip65 instance uses
    # the same default MAC, so a leftover instance is a live duplicate-MAC
    # node eating the DHCP traffic this test depends on. Other projects'
    # x64sc processes NOT on feth0 share this bench — never touch those.
    r = subprocess.run(["pgrep", "-fl", f"ethernetioif {ETH_IFACE}"],
                       capture_output=True, text=True)
    if r.stdout.strip():
        problems.append(
            f"another VICE is already attached to {ETH_IFACE} "
            f"(duplicate-MAC conflict):\n      {r.stdout.strip()}")
    try:
        pid = int(open(DNSMASQ_PIDFILE).read().strip())
        os.kill(pid, 0)
    except PermissionError:
        pass  # EPERM == the root-owned process exists; rig is up
    except (OSError, ValueError):
        problems.append(f"rig dnsmasq not running ({DNSMASQ_PIDFILE} "
                        "stale or absent) — no DHCP server on the wire")
    return problems


# ============================================================================
# Deriving the overlap from the build, not from constants
# ============================================================================

_SEG_ROW = re.compile(
    r"^(\S+)\s+([0-9A-Fa-f]{6})\s+([0-9A-Fa-f]{6})\s+([0-9A-Fa-f]{6})\s")


def parse_map_segments(path: str) -> dict[str, tuple[int, int]]:
    """Parse an ld65 map's `Segment list:` into {name: (start, end)}.

    `end` is inclusive, as printed.  Zero-size segments are dropped: ld65
    prints them with end == start - 1 under the six-digit format, which
    would otherwise read as a one-byte span.
    """
    out: dict[str, tuple[int, int]] = {}
    with open(path) as fh:
        lines = fh.read().splitlines()
    try:
        i = lines.index("Segment list:")
    except ValueError:
        raise RuntimeError(f"{path}: no 'Segment list:' section")
    for line in lines[i + 1:]:
        if line.startswith("Name") or line.startswith("---") or not line.strip():
            if out and not line.strip():
                break
            continue
        m = _SEG_ROW.match(line)
        if not m:
            break
        name, start, end, size = m.group(1), int(m.group(2), 16), \
            int(m.group(3), 16), int(m.group(4), 16)
        if size:
            out[name] = (start, end)
    if not out:
        raise RuntimeError(f"{path}: parsed no segments")
    return out


def parse_cfg_segment_types(path: str) -> dict[str, str]:
    """{segment name: ld65 type} from the cfg's SEGMENTS block."""
    text = open(path).read()
    m = re.search(r"^SEGMENTS\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        raise RuntimeError(f"{path}: no SEGMENTS block")
    types: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        hit = re.match(r"(\w+)\s*:\s*(.*);", line)
        if not hit:
            continue
        t = re.search(r"\btype\s*=\s*(\w+)", hit.group(2))
        if t:
            types[hit.group(1)] = t.group(1)
    if not types:
        raise RuntimeError(f"{path}: parsed no segment types")
    return types


def parse_cfg_memory(path: str) -> dict[str, tuple[int, int]]:
    """{region: (start, end inclusive)} from the cfg's MEMORY block."""
    text = open(path).read()
    m = re.search(r"^MEMORY\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        raise RuntimeError(f"{path}: no MEMORY block")
    out: dict[str, tuple[int, int]] = {}
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        hit = re.match(r"(\w+)\s*:\s*(.*);", line)
        if not hit:
            continue
        s = re.search(r"\bstart\s*=\s*\$([0-9A-Fa-f]+)", hit.group(2))
        z = re.search(r"\bsize\s*=\s*\$([0-9A-Fa-f]+)", hit.group(2))
        if s and z:
            start, size = int(s.group(1), 16), int(z.group(1), 16)
            out[hit.group(1)] = (start, start + size - 1)
    return out


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
# VICE plumbing
# ============================================================================

def connect(port: int, proc: ViceProcess, timeout: float = 30.0) -> BinaryViceTransport:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return BinaryViceTransport(port=port)
        except Exception as e:  # noqa: BLE001
            last = e
            if proc._proc is not None and proc._proc.poll() is not None:
                raise RuntimeError(
                    f"VICE on port {port} exited early — is {proc.config.executable} "
                    "really ethernet-capable?") from e
            time.sleep(0.25)
    raise RuntimeError(f"could not reach VICE's binary monitor on {port}: {last}")


def wait_boot_ready(tr, labels: Labels, timeout: float) -> bool:
    """Poll boot_ready, resuming between reads.

    The binary monitor auto-pauses the CPU on every command, so a poll
    loop that never resumes leaves the machine frozen and looks exactly
    like a hang.  boot_ready (not the "Q=QUIT" banner) is the true
    boot-complete marker — see tools/vice_util.py and issue #55.
    """
    addr = labels["boot_ready"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1) == b"\x01":
            return True
        tr.resume()
        time.sleep(1.0)
    return False


def press_key(tr, char: str, timeout: float = 15.0) -> bool:
    """Type one key into the KERNAL queue, resuming between polls."""
    def drained() -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if tr.read_memory(KBD_COUNT, 1)[0] == 0:
                return True
            tr.resume()
            time.sleep(0.1)
        return False

    if not drained():
        return False
    tr.write_memory(KBD_BUFFER, char.encode("ascii"))
    tr.write_memory(KBD_COUNT, bytes([1]))
    tr.resume()
    return drained()


def read_span(tr, start: int, end: int) -> bytes:
    """Read [start, end] via DMA in monitor-friendly chunks."""
    out = bytearray()
    addr, remaining = start, end - start + 1
    while remaining:
        n = min(256, remaining)
        out += tr.read_memory(addr, n)
        addr += n
        remaining -= n
    return bytes(out)


def screen_text(tr) -> str:
    return ScreenGrid.from_transport(tr).continuous_text().upper()


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
        # The contiguous run containing the first divergence, so the
        # report says how much of the segment went, not just where.
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
# Build
# ============================================================================

def build_ip65() -> None:
    if os.environ.get("C64_SKIP_BUILD"):
        log("C64_SKIP_BUILD set — reusing build/wireguard.prg")
        return
    log("=== make clean && make BACKEND=ip65 ===")
    for cmd in (["make", "clean"], ["make", "BACKEND=ip65"]):
        r = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout[-2000:])
            sys.stderr.write(r.stderr[-2000:])
            raise SystemExit(f"build failed: {' '.join(cmd)}")


def assert_ip65_build() -> None:
    """Refuse to run against a UCI build — the blob would not be linked in."""
    with open(WG_MAP_PATH) as fh:
        text = fh.read()
    if "ip65_blob.o" not in text:
        raise SystemExit(
            "FATAL: build/wireguard.map has no ip65_blob.o — this is not a "
            "BACKEND=ip65 build. Run `make clean && make BACKEND=ip65` (or "
            "unset C64_SKIP_BUILD).")


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

    problems = rig_problems(args.vice_bin)
    if problems:
        log("SKIP: ethernet rig not ready:")
        for p in problems:
            log(f"    - {p}")
        log("  The rig needs one privileged setup per boot and is not created "
            "here;")
        log("  see c64-https' tools/rig-up-macos.sh (feth pair + dnsmasq + "
            "bpf perms).")
        return 77

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
        log("FATAL: no loaded WG segment overlaps ip65's BSS — nothing to "
            "test. If the blob has been relinked, this test should be "
            "rewritten to assert the separation at link time instead.")
        return 1
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

    allocator = PortAllocator(port_range_start=6570, port_range_end=6590)
    port = args.port or allocator.allocate()
    if not args.port:
        res = allocator.take_socket(port)
        if res is not None:
            res.close()

    config = ViceConfig(
        prg_path=PRG_PATH,
        port=port,
        # Load-bearing: warp compresses ip65's DHCP retry budget below
        # dnsmasq's OFFER latency and DHCP fails every single time.
        warp=False,
        ntsc=True,
        sound=False,
        minimize=True,
        ethernet=True,
        ethernet_mode="rrnet",
        ethernet_interface=ETH_IFACE,
        ethernet_driver="pcap",
        ethernet_executable=args.vice_bin,
        # The BPF nodes are world-rw on this rig, so no sudo wrapper.
        run_as_root=False,
        # The default build is REU=1; boot's reu_mul_init needs the REU
        # to be there or the tables are built from hardware that is not.
        extra_args=["-reu", "-reusize", "512"],
    )

    proc = ViceProcess(config)
    proc.start()
    log(f"=== VICE pid={proc._proc.pid if proc._proc else '?'} port={port} "
        f"iface={ETH_IFACE} (warp OFF) ===")

    tr = None
    rc = 1
    t0 = time.monotonic()
    try:
        tr = connect(port, proc)
        if not wait_boot_ready(tr, labels, BOOT_TIMEOUT):
            log(f"FATAL: boot_ready never set within {BOOT_TIMEOUT:.0f}s")
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
        deadline = time.monotonic() + args.dhcp_timeout
        outcome, text = None, ""
        while time.monotonic() < deadline:
            tr.resume()
            time.sleep(2.0)
            text = screen_text(tr)
            if NET_OK_NEEDLE in text:
                outcome = "ok"
                break
            hit = [n for n in NET_FAIL_NEEDLES if n in text]
            if hit:
                outcome = hit[0]
                break
        if outcome == "ok":
            log(f"  network up (+{time.monotonic() - t0:.0f}s): "
                f"{text[text.find('NETWORK READY'):][:60].strip()}")
        elif outcome:
            log(f"  network init reported: {outcome}")
        else:
            log(f"  network init neither succeeded nor reported failure "
                f"within {args.dhcp_timeout:.0f}s")
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
            log("      Expected until the blob's BSS is relinked outside "
                "every WG-claimed region.")
            rc = 1
        elif outcome != "ok":
            log("INCONCLUSIVE (reported as FAIL): nothing was corrupted, but "
                "network init did")
            log("      not complete either, so ip65 may never have moved a "
                "frame. Check the rig")
            log("      (dnsmasq on feth1, no second VICE on feth0) and rerun.")
            rc = 1
        else:
            log("PASS: DHCP completed and no loaded byte inside ip65's BSS "
                "was disturbed.")
            rc = 0
        return rc
    finally:
        if tr is not None:
            try:
                tr.close()
            except Exception:  # noqa: BLE001
                pass
        proc.stop()
        if not args.port:
            allocator.release(port)


if __name__ == "__main__":
    sys.exit(main())
