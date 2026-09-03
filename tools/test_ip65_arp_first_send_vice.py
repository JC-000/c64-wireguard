#!/usr/bin/env python3
"""test_ip65_arp_first_send_vice.py — the first send to an off-subnet peer (#120).

OPT-IN, BRIDGED ethernet-VICE only. Exit 77 (skipped) when the rig is not
up. Deliberately NOT registered in tools/run_regression.py: it needs a real
NIC on a real LAN, a pcap-capable x64sc and world-rw BPF nodes, none of
which the gate can assume.

WHAT IT PROVES
==============

ip65 does not queue a datagram whose next-hop MAC it does not know: it
emits an ARP request and returns carry set (ip65/arp.s arp_lookup, whose
own doc-comment tells the caller to "call arp_lookup again" later).
``src/net/ip65/net.s:net_udp_send`` propagates that carry faithfully, and
``session_initiate`` treats carry set as a fatal handshake failure. For an
OFF-SUBNET peer the next hop is the gateway, so this fires on the very
first send after ``net_init`` and the first handshake can never succeed
(issue #120).

Three measurements, all on a C64 that holds a real DHCP lease on the real
LAN, with a tcpdump tap on the NIC VICE injects through:

  FIRST SEND    with the ARP cache proven cold, one call to net_udp_send
  (RED)         towards an off-subnet destination must return C=0 and must
                put exactly one UDP datagram on the wire with the right
                source and destination ports. On the unfixed tree it
                returns C=1 and the wire stays empty.

  RECOVERY      pump net_poll, send again: C=0 and the datagram appears.
  (both trees)  This is the control. It passes on the unfixed tree too, and
                that is the point — it proves the tap, the ports, the
                destination and the send path are all sound, so the RED
                above is the defect and not a broken rig. If THIS fails the
                run is inconclusive, not red.

  BUDGET        point the send at an ON-SUBNET address that nothing
  (both trees)  answers, so ARP can never resolve. The call must RETURN
                with C=1 — a bounded wait that never returns is the failure
                mode a retry loop introduces — and it must return inside
                the ceiling. The elapsed time is the discriminator between
                the trees and is always logged: ~0 s unfixed (no retry at
                all), ~the implementer's budget once the retry exists.

STRUCTURAL, NOT TEXTUAL
=======================

"ARP rows" is read out of ip65's own ``arp_cache`` over DMA, not counted
from tcpdump. The address is derived from ip65-build/ip65-c64.map — the
exported ``arp_ip`` plus its 4 bytes, which is where ``arp_cache:`` sits in
ip65/ip65/arp.s — never hard-coded. That derivation is self-validating: a
wrong address can only ever read zeroes, and the recovery phase REQUIRES
the gateway's row to appear, so a bad address fails loudly instead of
reporting a comfortable "0 rows" forever. The cache lives in the blob's
BSS at $A000, which src/boot.s banks BASIC out of, so the monitor's
CPU-view read really is RAM.

Three optional labels sharpen this once the fix exports them, and are
probed rather than assumed so the unfixed tree simply reports them SKIPPED:

  net_last_error       $00 after a successful send; NET_ERR_IP65_WAIT_TIMEOUT
                       after the unresolvable one, and specifically NOT
                       NET_ERR_TIMEBASE_STOPPED, which would mean the budget
                       was spent counting attempts because the jiffy clock
                       was not ticking — an elapsed figure that is then an
                       accident of loop cost rather than a bound. Both codes
                       are cross-checked against the tree's own ca65 equates.
  ip65_send_attempts   ip65_udp_send calls made by the last net_udp_send.
                       This is the sharper red: with the cache proven cold,
                       a first send that succeeds in ONE call was not
                       carried by the retry loop, and a "fix" that merely
                       pre-warmed ARP somewhere else would satisfy both C=0
                       and a populated cache while leaving this at 1.
  ip65_send_pump       must read 0 after every net_udp_send returns, the
                       give-up path included; a leaked flag silently deafens
                       the receive callback.

RANDOMISED PER RUN (seeded, logged): the payload bytes and length, and the
UDP source port. ``--seed`` / ``TEST_SEED`` reproduce a run.

NOTHING IS SENT AT THE C64 while a send is in flight, deliberately: the
retry loop's pump drops inbound UDP (the caller may still be holding
udp_recv_buf), so a suite that echoed into a budget window would be
measuring a documented design decision and calling it a regression.

WHAT THIS CANNOT COVER: nothing here is UCI. VICE has no Ultimate command
interface ($DF1D reads $FF), so the ip65 backend is the only one this
suite speaks about; the UCI adapter blocks until the firmware has taken
the datagram and has no equivalent of this defect.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, jsr, read_bytes, write_bytes  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    DEFAULT_VICE_BIN, IP65_MAP_PATH, LABELS_PATH, PRG_PATH, SKIP_EXIT,
    EthVice, Tap, assert_ip65_build, boot_and_net_init, bpf_capture_available,
    build_ip65, c64_ip, log, parse_map_exports, selftest_classifier,
)

# Cloudflare WARP, the endpoint issue #120 was measured against. Any
# off-subnet address works — the mechanism is entirely about the next hop
# being the gateway — and nothing here needs a reply, so a TEST-NET address
# such as 198.51.100.42 is an equally valid --dest.
DEFAULT_DEST = "162.159.192.1:2408"

DEFAULT_IFACE = "en4"
DEFAULT_BUDGET = 2.0          # the ~2 s the issue proposes for the retry

# Scratch past jsr()'s own $0334 trampoline and below screen RAM, matching
# tools/test_ip65_udp_echo_vice.py so the two suites cannot collide.
SEND_TRAMP = 0x0370
CARRY = 0x0360
RTS_SCRATCH = 0x0368          # a lone RTS: the jsr() timing floor

ARP_CACHE_ROWS = 8            # ip65/ip65/arp.s: ac_size
ARP_ROW_LEN = 10              # 6 MAC + 4 IP; ac_mac = 0, ac_ip = 6

# §13.2 error codes the ip65 adapter reports once it has a net_last_error.
# These are cross-checked against the tree's own ca65 equates at run time
# (see equate_from_sources) so a renumbering cannot leave the suite quietly
# asserting a stale value.
NET_ERR_TIMEBASE_STOPPED = 0x01
NET_ERR_IP65_WAIT_TIMEOUT = 0x48

WIRE_SETTLE = 2.0
POLL_CALLS = 120              # net_poll calls used to pump one ARP exchange

VERBOSE = False
results: list[tuple[bool, str]] = []


def vlog(msg: str) -> None:
    if VERBOSE:
        log(msg)


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    log(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if detail and (not ok or VERBOSE):
        for line in detail.splitlines():
            log(f"        {line}")
    return bool(ok)


def inconclusive(reason: str) -> None:
    """Stop without a verdict: the rig, not the code under test, is at fault."""
    log("")
    log("INCONCLUSIVE — the control measurement failed, so nothing can be")
    log("said about the first send:")
    for line in reason.splitlines():
        log(f"    {line}")
    sys.exit(SKIP_EXIT)


# ============================================================================
# ARP line classifier (pure, self-tested — see selftest_arp())
# ============================================================================

_ARP_REQUEST = re.compile(
    r"ARP,\s+Request who-has (\d+\.\d+\.\d+\.\d+) tell (\d+\.\d+\.\d+\.\d+)")
_ARP_REPLY = re.compile(
    r"ARP,\s+Reply (\d+\.\d+\.\d+\.\d+) is-at ([0-9a-fA-F:]{11,17})")


def classify_arp_line(line: str):
    """("request", who_has, tell) | ("reply", ip, mac) | (None, None, None)."""
    m = _ARP_REQUEST.search(line)
    if m:
        return "request", m.group(1), m.group(2)
    m = _ARP_REPLY.search(line)
    if m:
        return "reply", m.group(1), m.group(2)
    return None, None, None


#: Real captured shapes, kept beside the classifier so a regex edit that
#: stops recognising one fails loudly. The first two are quoted verbatim
#: from issue #120's own capture.
ARP_CASES = [
    ("13:50:01.348916 ARP, Request who-has 10.43.23.1 tell 10.43.23.225",
     ("request", "10.43.23.1", "10.43.23.225")),
    ("13:50:01.349200 ARP, Reply 10.43.23.1 is-at 8c:30:66:f4:83:ef",
     ("reply", "10.43.23.1", "8c:30:66:f4:83:ef")),
    ("13:50:01.349200 ARP, Reply 10.43.23.1 is-at 8c:30:66:f4:83:ef, "
     "length 46", ("reply", "10.43.23.1", "8c:30:66:f4:83:ef")),
    # A UDP row must not be mistaken for either arm.
    ("13:50:02.856753 IP 10.43.23.225.51820 > 162.159.192.1.2408: UDP, "
     "length 148", (None, None, None)),
    ("tcpdump: listening on en4, link-type EN10MB (Ethernet)",
     (None, None, None)),
]


def selftest_arp() -> list[str]:
    """The alarm proof for every "ARP rows: 0"-shaped claim made from the tap."""
    bad = []
    for line, want in ARP_CASES:
        got = classify_arp_line(line)
        if got != want:
            bad.append(f"classifier said {got!r}, expected {want!r}, for: "
                       f"{line.strip()[:90]}")
    return bad


def arp_lines(tap: Tap, upto: int | None = None) -> list[tuple[str, str, str]]:
    with tap._lock:
        raw = list(tap.raw[:upto] if upto is not None else tap.raw)
    out = []
    for line in raw:
        kind, a, b = classify_arp_line(line)
        if kind:
            out.append((kind, a, b))
    return out


# ============================================================================
# Bridged rig preflight
# ============================================================================

def iface_inet(iface: str) -> tuple[str, str] | None:
    """(address, netmask-as-dotted) of *iface*, or None."""
    r = subprocess.run(["ifconfig", iface], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    if "status: active" not in r.stdout and "RUNNING" not in r.stdout:
        return None
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)",
                  r.stdout)
    if not m:
        return None
    mask = int(m.group(2), 16)
    dotted = ".".join(str((mask >> s) & 0xFF) for s in (24, 16, 8, 0))
    return m.group(1), dotted


def bridged_rig_problems(vice_bin: str, iface: str) -> list[str]:
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["not macOS — this suite drives VICE's pcap driver on a real NIC"]
    if not os.path.exists(vice_bin):
        problems.append(
            f"{vice_bin} missing — an ethernet-capable x64sc is required "
            "(stock macOS VICE gates pcap on euid 0; Homebrew's bottle has "
            "networking compiled out — c64-test-harness#144). Set "
            "VICE_ETHERNET_BIN or pass --vice-bin.")
    if not bpf_capture_available():
        problems.append("/dev/bpf0 or /dev/bpf1 is not world read-write — "
                        "VICE cannot open a pcap handle unelevated")
    inet = iface_inet(iface)
    if inet is None:
        problems.append(f"{iface} is missing, down, or has no IPv4 address — "
                        "bridged mode needs a WIRED NIC on a real LAN with a "
                        "DHCP server (see docs/vice-eth-nat.md for why Wi-Fi "
                        "is not usable)")
    r = subprocess.run(["pgrep", "-fl", f"ethernetioif {iface}"],
                       capture_output=True, text=True)
    if r.stdout.strip():
        problems.append(
            f"another VICE is already attached to {iface} (every ip65 "
            f"instance uses the same default MAC, so it is a live "
            f"duplicate-MAC node):\n      {r.stdout.strip()}")
    return problems


def ping_silent(ip: str, timeout_s: int = 1) -> bool:
    r = subprocess.run(["ping", "-c", "1", "-W", str(timeout_s * 1000), ip],
                       capture_output=True, text=True)
    return r.returncode == 0


def arp_known(ip: str) -> bool:
    """True iff the HOST resolved a real MAC for *ip*.

    A failed ping leaves macOS holding an "(incomplete)" entry — which is
    exactly the proof we want, not an entry — so the presence of a row is
    not the signal; the presence of a MAC in it is.
    """
    r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
    if r.returncode != 0 or "no entry" in r.stdout:
        return False
    return bool(re.search(r"at ([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}\b", r.stdout))


def pick_blackhole(subnet_prefix: str, avoid: set[str]) -> str | None:
    """An ON-SUBNET address that nothing answers — ARP can never resolve it.

    Probed, never assumed: a host that replies would make the budget
    measurement a measurement of a successful send.
    """
    for last in range(250, 199, -1):
        cand = f"{subnet_prefix}.{last}"
        if cand in avoid:
            continue
        subprocess.run(["arp", "-d", cand], capture_output=True, text=True)
        if ping_silent(cand):
            continue
        if arp_known(cand):
            continue
        return cand
    return None


# ============================================================================
# C64 side
# ============================================================================

def blob_var(tr, L, offset: int, length: int) -> bytes:
    """Read *length* bytes through the blob's variable-address table.

    ip65-build/ip65_stub.s publishes a table of pointers after the jump
    table: +32 cfg_ip, +36 cfg_gateway, +34 cfg_netmask.
    """
    base = L["ip65_blob_start"]
    ptr = tr.read_memory(base + offset, 2)
    return tr.read_memory(ptr[0] | (ptr[1] << 8), length)


def dotted(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def arp_cache_addr() -> int:
    """arp_cache, derived from ip65's own map — never a constant.

    ip65/ip65/arp.s declares ``arp_ip: .res 4`` immediately followed by
    ``arp_cache:``, and arp_ip is exported. The derivation is checked by
    the recovery phase, which requires the gateway's row to turn up here.
    """
    exports = parse_map_exports(IP65_MAP_PATH)
    if "arp_ip" not in exports:
        raise SystemExit(f"FATAL: {IP65_MAP_PATH} exports no arp_ip — the "
                         "vendored ip65 changed shape; re-derive arp_cache")
    return exports["arp_ip"] + 4


def arp_rows(tr, cache: int) -> list[tuple[str, str]]:
    """Occupied (ip, mac) rows of ip65's ARP cache, read over DMA."""
    raw = tr.read_memory(cache, ARP_CACHE_ROWS * ARP_ROW_LEN)
    out = []
    for i in range(ARP_CACHE_ROWS):
        row = raw[i * ARP_ROW_LEN:(i + 1) * ARP_ROW_LEN]
        ip, mac = row[6:10], row[0:6]
        if any(ip):
            out.append((dotted(ip), ":".join(f"{b:02x}" for b in mac)))
    return out


def equate_from_sources(name: str) -> int | None:
    """The value of a ca65 ``name = $XX`` equate, searched across src/.

    Used to cross-check this file's copies of the §13.2 error codes against
    the tree being tested: a renumbering must break the suite loudly rather
    than leave it asserting a value the code no longer emits.
    """
    root = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "src")
    pat = re.compile(rf"^\s*{re.escape(name)}\s*=\s*\$([0-9A-Fa-f]+)", re.M)
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith((".inc", ".s")):
                continue
            try:
                m = pat.search(open(os.path.join(dirpath, fn)).read())
            except OSError:
                continue
            if m:
                return int(m.group(1), 16)
    return None


def opt_byte(tr, L, name: str) -> int | None:
    """One byte at an OPTIONAL label — None when the build does not export it."""
    return read_bytes(tr, L[name], 1)[0] if name in L else None


def install_send_tramp(tr, L) -> None:
    buf = L["udp_recv_buf"]
    ns = L["net_udp_send"]
    code = bytes([
        0xA9, buf & 0xFF,                       # LDA #<buf
        0xA2, buf >> 8,                         # LDX #>buf
        0x20, ns & 0xFF, ns >> 8,               # JSR net_udp_send
        0x08, 0x68, 0x29, 0x01,                 # PHP PLA AND #1
        0x8D, CARRY & 0xFF, CARRY >> 8,         # STA CARRY
        0x60,                                   # RTS
    ])
    write_bytes(tr, SEND_TRAMP, code)
    write_bytes(tr, RTS_SCRATCH, bytes([0x60]))


def set_dest(tr, L, ip: str, port: int) -> None:
    octets = bytes(int(o) for o in ip.split("."))
    write_bytes(tr, L["net_udp_dest_ip"], octets)
    # net_abi.inc §13.1: net_udp_dest_port is BIG-endian.
    write_bytes(tr, L["net_udp_dest_port"], bytes([port >> 8, port & 0xFF]))


def set_source_port(tr, L, port: int) -> None:
    # wg_local_port is the one little-endian port cell (src/wg/data.s).
    write_bytes(tr, L["wg_local_port"], struct.pack("<H", port))


def send_once(tr, L, payload: bytes, timeout: float) -> tuple[int, float]:
    """One net_udp_send. Returns (carry, wall seconds spent inside the call).

    jsr() sets a monitor checkpoint and lets the CPU RUN to it, so the wall
    clock across the call is honest 6510 time (VICE is at 1 MHz here — warp
    is off for the whole run, see vice_eth_rig's module doc).
    """
    write_bytes(tr, L["udp_recv_buf"], payload)
    write_bytes(tr, L["net_udp_send_len"], struct.pack("<H", len(payload)))
    write_bytes(tr, CARRY, b"\xFF")
    t0 = time.monotonic()
    jsr(tr, SEND_TRAMP, timeout=timeout)
    elapsed = time.monotonic() - t0
    return read_bytes(tr, CARRY, 1)[0], elapsed


def timing_floor(tr) -> float:
    """What a jsr() to a bare RTS costs — the noise floor of send_once()."""
    samples = []
    for _ in range(5):
        t0 = time.monotonic()
        jsr(tr, RTS_SCRATCH, timeout=10.0)
        samples.append(time.monotonic() - t0)
    return sum(samples) / len(samples)


def pump(tr, L, calls: int = POLL_CALLS) -> None:
    """Run ip65_process *calls* times so an ARP reply gets processed."""
    for _ in range(calls):
        jsr(tr, L["net_poll"], timeout=10.0)


def prg_fingerprint(path: str) -> str:
    data = open(path, "rb").read()
    return (f"{os.path.basename(path)} {len(data)} bytes "
            f"sha256={hashlib.sha256(data).hexdigest()[:16]} "
            f"load=${data[0] | (data[1] << 8):04X}")


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--iface", default=os.environ.get("C64_ETH_IFACE",
                                                      DEFAULT_IFACE),
                    help="the real NIC VICE binds by pcap name (default en4)")
    ap.add_argument("--dest", default=DEFAULT_DEST,
                    help="OFF-SUBNET destination IP:PORT (default Cloudflare "
                         "WARP, as measured in issue #120)")
    ap.add_argument("--blackhole", default=None,
                    help="on-subnet address nothing answers; probed if unset")
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET,
                    help="the implementer's ARP-retry budget in seconds "
                         f"(default {DEFAULT_BUDGET})")
    ap.add_argument("--seed", type=int,
                    default=int(os.environ.get("TEST_SEED", "0")) or None)
    ap.add_argument("--arp-cache-addr", type=lambda s: int(s, 0), default=None,
                    help="override the arp_cache address derived from the "
                         "ip65 map. FOR THE ALARM PROOF ONLY: pointing it at "
                         "the wrong address must make the control's "
                         "'arp_cache holds the gateway' check FAIL, which is "
                         "how we know a comfortable 'rows: 0' is evidence "
                         "and not an artefact of reading the wrong bytes.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    rng = random.Random(seed)
    log(f"=== test_ip65_arp_first_send_vice (issue #120) seed={seed} ===")
    log(f"    reproduce with: --seed {seed}")

    dest_ip, dest_port = args.dest.rsplit(":", 1)
    dest_port = int(dest_port)

    # ---- preflight -------------------------------------------------------
    bad = selftest_arp()
    if bad:
        log("FATAL: the ARP line classifier is broken, so every ARP count "
            "below would be meaningless:")
        for b in bad:
            log(f"    {b}")
        return 1
    log(f"  ARP classifier self-test: {len(ARP_CASES)} shapes OK")
    bad = selftest_classifier()
    if bad:
        log("FATAL: the UDP/fragment classifier is broken:")
        for b in bad:
            log(f"    {b}")
        return 1
    log("  UDP/fragment classifier self-test: OK")

    problems = bridged_rig_problems(args.vice_bin, args.iface)
    if problems:
        log("SKIP: bridged ethernet rig not ready:")
        for p in problems:
            log(f"    - {p}")
        return SKIP_EXIT

    host_ip, host_mask = iface_inet(args.iface)
    prefix = ".".join(host_ip.split(".")[:3])
    log(f"  {args.iface} host {host_ip}/{host_mask}")

    if dest_ip.startswith(prefix + "."):
        log(f"FATAL: --dest {dest_ip} is ON the {prefix}.0/24 subnet — this "
            "suite needs an OFF-subnet destination so the next hop is the "
            "gateway")
        return 1

    # ---- build -----------------------------------------------------------
    build_ip65()
    assert_ip65_build()
    log(f"  PRG: {prg_fingerprint(PRG_PATH)}")
    L = Labels.from_file(LABELS_PATH)
    cache = arp_cache_addr()
    if args.arp_cache_addr is not None:
        log(f"  ALARM PROOF: arp_cache forced to ${args.arp_cache_addr:04X} "
            f"instead of the derived ${cache:04X}")
        cache = args.arp_cache_addr
    log(f"  arp_cache = ${cache:04X} (ip65 map: arp_ip ${cache - 4:04X} + 4)")
    # Optional observability the ip65 adapter grows with the #120 fix. Each
    # is probed, never assumed: on the unfixed tree the label is absent and
    # the assertions that use it say so instead of failing for the wrong
    # reason.
    have_err = "net_last_error" in L
    have_attempts = "ip65_send_attempts" in L
    have_pump = "ip65_send_pump" in L
    for name, present in (("net_last_error", have_err),
                          ("ip65_send_attempts", have_attempts),
                          ("ip65_send_pump", have_pump)):
        state = ("exported" if present else
                 "ABSENT — its assertions are SKIPPED on this build")
        log(f"  {name}: {state}")
    for cname, mine in (("NET_ERR_IP65_WAIT_TIMEOUT",
                         NET_ERR_IP65_WAIT_TIMEOUT),
                        ("NET_ERR_TIMEBASE_STOPPED",
                         NET_ERR_TIMEBASE_STOPPED)):
        found = equate_from_sources(cname)
        if found is None:
            log(f"  {cname}: not defined in src/ — this suite expects "
                f"${mine:02X}")
        elif found != mine:
            log(f"FATAL: {cname} is ${found:02X} in src/ but this suite "
                f"asserts ${mine:02X}. The codes were renumbered; update "
                f"the suite rather than letting it assert a dead value.")
            return 1
        else:
            log(f"  {cname} = ${mine:02X}, agreed with src/")

    # ---- tap up BEFORE the machine boots ---------------------------------
    # Everything the C64 ever emits is in the capture, so "the cache was
    # cold" is a claim about the whole run, not about a window.
    bpf = (f"arp or (udp and (port 67 or port 68 or port {dest_port}))")
    rc = 1
    with Tap(bpf, iface=args.iface) as tap:
        with EthVice(args.vice_bin, iface=args.iface) as vice:
            tr = vice.tr
            boot_and_net_init(tr, L)
            c64 = c64_ip(tr, L)
            gw = dotted(blob_var(tr, L, 36, 4))
            mask = dotted(blob_var(tr, L, 34, 4))
            log(f"  C64 lease: {c64}/{mask} gw {gw}")

            if not c64.startswith(prefix + ".") or c64 == host_ip:
                inconclusive(f"the C64 leased {c64}, which is not a fresh "
                             f"address on {prefix}.0/24 — is VICE really "
                             f"bridged onto {args.iface}?")
            if not gw.startswith(prefix + "."):
                inconclusive(f"gateway {gw} is not on {prefix}.0/24")

            blackhole = args.blackhole or pick_blackhole(
                prefix, {host_ip, gw, c64, "10.43.23.81", "10.43.23.99"})
            if blackhole is None:
                inconclusive("could not find an unused on-subnet address for "
                             "the budget phase; pass --blackhole")
            log(f"  blackhole (on-subnet, unanswered): {blackhole}")

            install_send_tramp(tr, L)
            floor = timing_floor(tr)
            log(f"  jsr() timing floor: {floor * 1000:.0f} ms")

            sport = rng.randrange(49152, 65536)
            set_source_port(tr, L, sport)
            n = rng.randrange(64, 201)
            payload = bytes(rng.randrange(256) for _ in range(n - 4)) + b"ARP>"
            log(f"  randomised: sport={sport} payload={len(payload)} B "
                f"(suffix {payload[-4:]!r})")

            # ---- cold-cache precondition ---------------------------------
            log("")
            log(f"=== Phase 1: the FIRST send to {dest_ip}:{dest_port} "
                "(off-subnet) ===")
            rows_before = arp_rows(tr, cache)
            gw_before = [r for r in rows_before if r[0] == gw]
            arp_before = arp_lines(tap)
            asked_for_gw = [a for a in arp_before
                            if a[0] == "request" and a[1] == gw and a[2] == c64]
            gw_spoke = [a for a in arp_before
                        if (a[0] == "reply" and a[1] == gw)
                        or (a[0] == "request" and a[2] == gw)]
            udp_before = tap.udp(src=c64, dst=dest_ip)
            log(f"  ip65 arp_cache rows before: {len(rows_before)} "
                f"{rows_before if rows_before else ''}")
            if gw_before or gw_spoke:
                inconclusive(
                    "the ARP cache was NOT cold at the first send: "
                    f"gateway rows in ip65's cache = {gw_before}, ARP frames "
                    f"from the gateway seen before the send = {len(gw_spoke)}. "
                    "Something on the LAN warmed it (a router that ARPs its "
                    "clients will). Re-run; if it persists, the LAN cannot "
                    "host this measurement.")
            check(not gw_before and not asked_for_gw and not udp_before,
                  "precondition: ARP cache cold for the gateway and no prior "
                  "traffic from the C64 to the destination",
                  f"cache rows for {gw}: {gw_before}\n"
                  f"who-has {gw} tell {c64}: {len(asked_for_gw)}\n"
                  f"UDP {c64} -> {dest_ip}: {len(udp_before)}")

            # ---- THE RED -------------------------------------------------
            ceiling = max(8.0, args.budget * 4)
            set_dest(tr, L, dest_ip, dest_port)
            mark_udp = len(tap.udp(src=c64, dst=dest_ip))
            carry1, took1 = send_once(tr, L, payload,
                                      timeout=max(30.0, args.budget * 10))
            time.sleep(WIRE_SETTLE)
            sent1 = tap.udp(src=c64, dst=dest_ip)[mark_udp:]
            rows_after1 = arp_rows(tr, cache)
            log(f"  send attempt 1: carry={carry1} in {took1:.2f}s   "
                f"arp_cache rows: {len(rows_after1)}   "
                f"datagrams: {len(sent1)}")

            check(carry1 == 0,
                  f"attempt 1 (cold ARP cache, off-subnet {dest_ip}) returned "
                  f"C=0",
                  f"net_udp_send returned C={carry1}. ip65 emitted an ARP "
                  f"request for the next hop ({gw}) and reported failure "
                  f"instead of resolving and sending; session_initiate turns "
                  f"this into HANDSHAKE SEND FAILED, so the first handshake "
                  f"can never succeed (issue #120).")
            check(len(sent1) == 1,
                  "attempt 1 put exactly one UDP datagram on the wire",
                  f"tap saw {len(sent1)} datagram(s) from {c64} to {dest_ip} "
                  f"during attempt 1; expected exactly 1 of "
                  f"{len(payload)} bytes")
            if sent1:
                d = sent1[0]
                check(d.sport == sport and d.dport == dest_port
                      and d.length == len(payload),
                      "attempt 1's datagram carried the right ports and length",
                      f"saw {d.src}:{d.sport} -> {d.dst}:{d.dport} "
                      f"len {d.length}; expected {c64}:{sport} -> "
                      f"{dest_ip}:{dest_port} len {len(payload)}")
            check(any(r[0] == gw for r in rows_after1),
                  "attempt 1 left the gateway resolved in ip65's arp_cache",
                  f"rows: {rows_after1}")
            check(took1 <= ceiling,
                  f"attempt 1 finished inside the budget ceiling "
                  f"({ceiling:.1f}s)",
                  f"took {took1:.2f}s — resolving one next hop on a LAN is a "
                  f"milliseconds job; a first send that eats the whole retry "
                  f"budget is stalling the handshake, not fixing it")
            if have_err:
                err = opt_byte(tr, L, "net_last_error")
                check(err == 0,
                      "net_last_error is $00 after a successful first send",
                      f"net_last_error = ${err:02X}")
            if have_attempts:
                att = opt_byte(tr, L, "ip65_send_attempts")
                # Sharper than the arp_cache row: a "fix" that pre-warmed ARP
                # somewhere else entirely would satisfy C=0 and a populated
                # cache, but it would leave attempts at 1. This asserts that
                # the RETRY is what carried the send.
                check(att is not None and att > 1,
                      "attempt 1 actually went round the retry loop "
                      "(ip65_send_attempts > 1)",
                      f"ip65_send_attempts = {att} — with the cache proven "
                      "cold, one ip65_udp_send call cannot have sent this")
            if have_pump:
                check(opt_byte(tr, L, "ip65_send_pump") == 0,
                      "ip65_send_pump is clear after net_udp_send returns",
                      "a leaked pump flag silently deafens the receive "
                      "callback")

            # ---- the control: recovery -----------------------------------
            log("")
            log("=== Phase 2: control — pump net_poll, send again ===")
            pump(tr, L)
            mark_udp = len(tap.udp(src=c64, dst=dest_ip))
            carry2, took2 = send_once(tr, L, payload, timeout=30.0)
            time.sleep(WIRE_SETTLE)
            sent2 = tap.udp(src=c64, dst=dest_ip)[mark_udp:]
            rows_after2 = arp_rows(tr, cache)
            arp_all = arp_lines(tap)
            req = [a for a in arp_all
                   if a[0] == "request" and a[1] == gw and a[2] == c64]
            rep = [a for a in arp_all if a[0] == "reply" and a[1] == gw]
            log(f"  send attempt 2: carry={carry2} in {took2:.2f}s   "
                f"arp_cache rows: {len(rows_after2)}   "
                f"datagrams: {len(sent2)}")
            log(f"  ARP at the tap: {len(req)} request(s) who-has {gw} tell "
                f"{c64}, {len(rep)} reply/replies {gw} is-at "
                f"{rep[0][2] if rep else '-'}")

            ok_ctrl = True
            ok_ctrl &= check(carry2 == 0,
                             "control: a send with the cache warm returns C=0",
                             f"C={carry2} — the send path itself is broken, "
                             "which is not what #120 is about")
            ok_ctrl &= check(len(sent2) == 1,
                             "control: that send put exactly one datagram on "
                             "the wire",
                             f"tap saw {len(sent2)}")
            ok_ctrl &= check(bool(req) and bool(rep),
                             "control: the ARP request/reply pair for the "
                             "gateway appears at the tap",
                             f"requests={len(req)} replies={len(rep)}")
            ok_ctrl &= check(any(r[0] == gw for r in rows_after2),
                             "control: ip65's arp_cache holds the gateway",
                             f"rows: {rows_after2}\n"
                             f"(if this NEVER fills, arp_cache=${cache:04X} "
                             f"is the wrong address and every row count above "
                             f"is meaningless)")
            if have_attempts:
                att2 = opt_byte(tr, L, "ip65_send_attempts")
                ok_ctrl &= check(att2 == 1,
                                 "control: a warm-cache send takes exactly "
                                 "one ip65_udp_send call",
                                 f"ip65_send_attempts = {att2} — the retry "
                                 "loop should not engage when ARP is already "
                                 "resolved")
            if have_pump:
                ok_ctrl &= check(opt_byte(tr, L, "ip65_send_pump") == 0,
                                 "control: ip65_send_pump is clear after the "
                                 "warm send returns")
            ok_ctrl &= check(tap.fragments() == 0,
                             "control: nothing was torn by IP fragmentation",
                             "\n".join(tap.frags[:5]))
            if not ok_ctrl:
                inconclusive("the warm-cache control did not pass; the tap, "
                             "the lease or the send path is at fault, so the "
                             "first-send result above cannot be attributed to "
                             "the defect.")

            # ---- the budget ----------------------------------------------
            log("")
            log(f"=== Phase 3: the retry budget is BOUNDED "
                f"(on-subnet {blackhole}, unanswered) ===")
            set_dest(tr, L, blackhole, dest_port)
            hung = False
            try:
                carry3, took3 = send_once(tr, L, payload,
                                          timeout=max(45.0, args.budget * 20))
            except Exception as exc:  # noqa: BLE001 — a hang is the point
                hung, carry3, took3 = True, -1, float("nan")
                log(f"  send attempt 3 NEVER RETURNED: {type(exc).__name__}: "
                    f"{exc}")
            else:
                log(f"  send attempt 3: carry={carry3} in {took3:.2f}s "
                    f"(budget {args.budget:.1f}s, ceiling {ceiling:.1f}s, "
                    f"jsr floor {floor:.2f}s)")
            check(not hung,
                  "an unresolvable on-subnet destination RETURNS rather than "
                  "hanging",
                  "net_udp_send never came back — an unbounded ARP retry is "
                  "the failure mode a retry loop introduces, and it wedges "
                  "the whole application")
            if not hung:
                check(carry3 == 1,
                      "an unresolvable destination reports failure (C=1)",
                      f"C={carry3} — a send that could not resolve its next "
                      "hop must not claim success")
                check(took3 <= ceiling,
                      f"it returned inside the ceiling ({ceiling:.1f}s)",
                      f"took {took3:.2f}s")
                log(f"  MEASURED retry budget: {took3:.2f}s "
                    f"(floor {floor:.2f}s) — ~0 means no retry loop is "
                    f"present; ~{args.budget:.1f}s means the bounded wait is "
                    f"real")
                if have_attempts:
                    att3 = opt_byte(tr, L, "ip65_send_attempts")
                    check(att3 is not None and att3 > 1,
                          "the unresolvable send went round the retry loop "
                          "(ip65_send_attempts > 1)",
                          f"ip65_send_attempts = {att3}")
                if have_pump:
                    check(opt_byte(tr, L, "ip65_send_pump") == 0,
                          "ip65_send_pump is clear after the FAILING send "
                          "returns too",
                          "the give-up path is the one most likely to leak "
                          "the flag")
                if have_err:
                    err = opt_byte(tr, L, "net_last_error")
                    check(err == NET_ERR_IP65_WAIT_TIMEOUT,
                          f"net_last_error is "
                          f"NET_ERR_IP65_WAIT_TIMEOUT (${NET_ERR_IP65_WAIT_TIMEOUT:02X}) "
                          f"after an unresolvable send",
                          f"net_last_error = ${err:02X} — a failure the "
                          "consumer cannot see is invisible to every "
                          "structural probe (issue #120, #116)")
                    check(err != NET_ERR_TIMEBASE_STOPPED,
                          "the wall-clock bound engaged, rather than the "
                          "attempt-count backstop "
                          f"(net_last_error != ${NET_ERR_TIMEBASE_STOPPED:02X})",
                          f"net_last_error = ${err:02X} = "
                          "NET_ERR_TIMEBASE_STOPPED: the jiffy clock at "
                          "$A0-$A2 never advanced, so the budget was spent "
                          "by counting attempts, not by measuring time. The "
                          "elapsed figure above is then an accident of "
                          "loop cost, not a bound.")

            # ---- report --------------------------------------------------
            log("")
            passed = sum(1 for ok, _ in results if ok)
            log(f"=== {passed}/{len(results)} checks passed (seed {seed}) ===")
            for ok, label in results:
                if not ok:
                    log(f"    FAILED: {label}")
            if VERBOSE:
                log("--- capture ---")
                for line in tap.raw:
                    log(f"    {line}")
            rc = 0 if passed == len(results) else 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
