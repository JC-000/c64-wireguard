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
  ip65_recv_dropped    inbound datagrams discarded during a pump. 0 on the
                       happy path, where nothing is aimed at the C64; and
                       NON-ZERO in the budget phase, where one datagram is
                       deliberately landed inside the pump window. That
                       counter exists so the cost of the inbound disarm is
                       observable, so a suite that never moved it would
                       leave the design unproven.

net_init must also clear ip65_send_attempts. Checked last, because
re-running net_init tears the stack down, and only after asserting the
counter was non-zero going in — a reset from 0 to 0 proves nothing.

RANDOMISED PER RUN (seeded, logged): the payload bytes and length, the UDP
source port, and the mid-pump probe's bytes (a disjoint high alphabet).
``--seed`` / ``TEST_SEED`` reproduce a run.

THE ONLY THING SENT AT THE C64 is that one mid-pump probe, and only in the
budget phase. It is aimed at ip65_listen_port read from the adapter, never
at an assumed port, and the assertion is made only when the host's send
timestamp actually falls inside the call: if it lands late, the run says
so and does not assert.

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
import socket
import struct
import tempfile
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, jsr, read_bytes, write_bytes  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    DEFAULT_VICE_BIN, IP65_MAP_PATH, LABELS_PATH, PRG_PATH, SKIP_EXIT,
    EthVice, assert_ip65_build, boot_and_net_init, build_ip65, c64_ip,
    classify_tcpdump_line,
    libpcap_node_note, log, parse_map_exports, selftest_classifier,
    selftest_map_parsers, vice_holders, vice_rawnet_problems,
)

# Cloudflare WARP, the endpoint issue #120 was measured against. Any
# off-subnet address works — the mechanism is entirely about the next hop
# being the gateway — and nothing here needs a reply, so a TEST-NET address
# such as 198.51.100.42 is an equally valid --dest.
DEFAULT_DEST = "162.159.192.1:2408"

DEFAULT_IFACE = "en4"
# 30 jiffies ~= 0.5 s, the budget after adversarial review. arp_lookup
# retransmits every 100 ms, so 0.5 s still covers five attempts, and it cuts
# the inbound-deafness window fourfold on the eviction path where Type 4
# loss actually bites. The issue's original ~2 s is superseded.
DEFAULT_BUDGET = 0.5

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
# Defined and exported so a redefinition is a hard assembler error, but
# deliberately never emitted. Seeing it in net_last_error is a bug in the
# adapter, not an expected value.
NET_ERR_IP65_UDP_SEND = 0x47

WIRE_SETTLE = 2.0
POLL_CALLS = 120              # net_poll calls used to pump one ARP exchange

VERBOSE = False
results: list[tuple[bool, str]] = []

#: Set only when the ip65_recv_dropped INCREMENT was actually asserted, i.e.
#: a datagram was proven on the wire inside the pump window. Its zero case is
#: asserted twice and that is NOT coverage: a counter that reads 0 when
#: nothing was dropped is satisfied equally by a counter that can never move.
#: This project already has that failure on record — a passing assertion
#: coinciding with the truth rather than testing it — so the summary says so
#: on every run rather than leaving the count to imply otherwise.
drop_increment_asserted = False


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


def arp_lines(tap, upto: int | None = None) -> list[tuple[str, str, str]]:
    raw = tap.text_lines()
    if upto is not None:
        raw = raw[:upto]
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
    # VICE's own gate — a rawnet-capable binary and archdep_rawnet_capability
    # — not libpcap's /dev/bpf* permissions. See vice_rawnet_problems for why
    # the difference matters (harness c3fe7aa).
    problems += vice_rawnet_problems(vice_bin, "pcap")
    note = libpcap_node_note()
    if note:
        problems.append(note)
    inet = iface_inet(iface)
    if inet is None:
        problems.append(f"{iface} is missing, down, or has no IPv4 address — "
                        "bridged mode needs a WIRED NIC on a real LAN with a "
                        "DHCP server (see docs/vice-eth-nat.md for why Wi-Fi "
                        "is not usable)")
    # Match the EMULATOR, not the string. `pgrep -f "ethernetioif en4"` also
    # matches any shell whose own command line mentions it — a `pgrep` in a
    # wait loop matches itself, and this preflight then reports a busy rig
    # against a rig that is idle (measured while writing this suite). Require
    # an x64sc binary in argv[0] and drop our own process tree.
    holders = vice_holders(iface)
    if holders:
        problems.append(
            f"another VICE is already attached to {iface} (every ip65 "
            f"instance uses the same default MAC, so it is a live "
            f"duplicate-MAC node):\n      " + "\n      ".join(holders))
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


class WireTap:
    """ONE tcpdump. Frames for bytes, and tcpdump's own text for classifying.

    ONE BPF HANDLE IS THE WHOLE POINT. This bench has exactly four world-rw
    /dev/bpf nodes (bpf0-bpf3; bpf4+ are root-only) and they are shared by
    every lane. VICE's pcap driver needs one, so a suite that opens two
    leaves one spare for the entire rest of the machine — and when the
    fourth is gone, VICE's eth_init fails, ip65_init returns carry set, and
    the C64 prints NET INIT FAILED. That is not a network problem and looks
    nothing like one. MEASURED: two concurrent tcpdumps plus VICE on en4
    gave "cannot open BPF device /dev/bpf4: Permission denied" and three
    consecutive runs died at network init. An earlier draft of this suite
    ran a second live capture for payload bytes and caused exactly that.

    So: one live ``tcpdump -w`` writing a pcap file (``-U``, packet
    buffered, so records land as they arrive), and two readers of that one
    file:

      frames()      parsed here, giving UDP payload and whole-IP-packet
                    BYTES — what the packet-identity and content checks need.
      text_lines()  ``tcpdump -r`` run OFFLINE against the same file. It
                    opens no BPF device, and it produces exactly the line
                    shapes classify_tcpdump_line and classify_arp_line are
                    proven against, so the counting, fragment and ARP arms
                    keep resting on the classifiers that have alarm proofs
                    rather than on a hand-rolled decoder.
    """

    _GLOBAL = 24
    _REC = 16

    def __init__(self, bpf_filter: str, iface: str):
        # Same fragment clause the shared Tap appends: a datagram torn by IP
        # fragmentation must still be captured so it can be counted.
        self.filter = f"({bpf_filter}) or (ip[6:2] & 0x1fff != 0)"
        self.iface = iface
        fd, self.path = tempfile.mkstemp(prefix="wg120-", suffix=".pcap")
        os.close(fd)
        self._proc: subprocess.Popen | None = None

    def __enter__(self) -> "WireTap":
        self._proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-n", "-U", "-s", "0",
             "-w", self.path, self.filter],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            line = self._proc.stderr.readline()
            if "listening on" in line:
                return self
            if not line and self._proc.poll() is not None:
                break
        raise RuntimeError(f"tcpdump did not start listening on {self.iface}")

    def __exit__(self, *exc) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    # -- frames (bytes) ---------------------------------------------------

    def frames(self) -> list[tuple[str, int, str, int, bytes, bytes]]:
        """Every UDP record in the capture so far, decoded to bytes.

        Re-reads the whole file; these captures are a handful of packets.
        A partial trailing record (tcpdump mid-write) is simply not yet
        complete and is skipped, not mis-parsed.
        """
        try:
            with open(self.path, "rb") as fh:
                buf = fh.read()
        except OSError:
            return []
        if len(buf) < self._GLOBAL:
            return []
        magic = buf[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            return []
        out = []
        off = self._GLOBAL
        while off + self._REC <= len(buf):
            _s, _u, incl, _orig = struct.unpack(
                endian + "IIII", buf[off:off + self._REC])
            off += self._REC
            if off + incl > len(buf):
                break                       # record still being written
            rec = parse_frame(buf[off:off + incl])
            off += incl
            if rec:
                out.append(rec)
        return out

    def matching(self, src: str, dst: str, dport: int):
        return [f for f in self.frames()
                if f[0] == src and f[2] == dst and f[3] == dport]

    # -- text (classified by the proven classifiers) ----------------------

    def text_lines(self) -> list[str]:
        """``tcpdump -r`` over the same file. Offline: opens no BPF device."""
        r = subprocess.run(
            ["tcpdump", "-r", self.path, "-n", "-q"],
            capture_output=True, text=True)
        return r.stdout.splitlines()

    @property
    def raw(self) -> list[str]:
        return self.text_lines()

    def udp(self, src: str | None = None, dst: str | None = None,
            dport: int | None = None) -> list:
        recs = []
        for line in self.text_lines():
            kind, value = classify_tcpdump_line(line)
            if kind == "udp":
                recs.append(value)
        return [r for r in recs
                if (src is None or r.src == src)
                and (dst is None or r.dst == dst)
                and (dport is None or r.dport == dport)]

    @property
    def frags(self) -> list[str]:
        out = []
        for line in self.text_lines():
            kind, value = classify_tcpdump_line(line)
            if kind == "frag":
                out.append(value)
        return out

    def fragments(self) -> int:
        return len(self.frags)


def parse_frame(frame: bytes):
    """One Ethernet frame -> (src, sport, dst, dport, payload, ip) or None.

    The whole IP packet is carried too (index 5). ip65 hardcodes the IP ID
    to $1234 for every UDP packet (ip65/ip65/udp.s:330) and
    ip_create_packet skips the ID field, so failed attempts consume no IDs
    and nothing in the header varies per attempt — which makes a
    byte-identical comparison between the RETRY path and the direct path a
    legitimate assertion rather than a flaky one.
    """
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None                         # not IPv4 over Ethernet
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None                         # not UDP
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    sport, dport, ulen = struct.unpack(">HHH", udp[0:6])
    return src, sport, dst, dport, udp[8:8 + max(0, ulen - 8)], ip


def selftest_payload_parser() -> list[str]:
    """Alarm proof for parse_frame: a hand-built frame it must decode.

    Without this, "the bytes matched" could be a claim resting on a parser
    that never returned anything at all — an empty list is not a mismatch.
    """
    payload = bytes(range(0, 40))
    udp = struct.pack(">HHHH", 51820, 2408, 8 + len(payload), 0) + payload
    ip = (bytes([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0])
          + bytes([10, 43, 23, 225]) + bytes([162, 159, 192, 1]) + udp)
    frame = b"\x00" * 12 + b"\x08\x00" + ip
    got = parse_frame(frame)
    if got is None:
        return ["parse_frame returned None for a valid UDP frame"]
    src, sport, dst, dport, body, ip_raw = got
    bad = []
    if (src, sport, dst, dport) != ("10.43.23.225", 51820,
                                    "162.159.192.1", 2408):
        bad.append(f"parse_frame decoded the wrong header: {got[:4]}")
    if body != payload:
        bad.append(f"parse_frame decoded {len(body)} payload bytes, "
                   f"expected {len(payload)}")
    if ip_raw != ip:
        bad.append(f"parse_frame returned {len(ip_raw)} IP bytes, expected "
                   f"{len(ip)} — the packet-identity check compares these, "
                   "so an empty or truncated slice would make two packets "
                   "look equal for the wrong reason")
    if parse_frame(b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 40) is not None:
        bad.append("parse_frame accepted a non-IPv4 frame")
    return bad


class MidPumpSender(threading.Thread):
    """Fire one UDP datagram AT the C64 *delay* seconds from now.

    The point is to land it inside a net_udp_send that is spinning in its
    ARP retry pump, so the adapter's documented disarm — inbound UDP is
    discarded while the caller may still be holding udp_recv_buf — actually
    executes and ip65_recv_dropped moves. Without this the counter is a
    design claim no test has exercised.

    The destination port is read from the adapter's own ip65_listen_port,
    never assumed: this suite randomises wg_local_port after net_init, so
    the registered listener is NOT on the port the sends go out from.
    """

    def __init__(self, dst_ip: str, dst_port: int, delay: float,
                 payload: bytes, src_ip: str | None = None):
        super().__init__(daemon=True)
        self.dst = (dst_ip, dst_port)
        # This Mac is dual-homed on 10.43.23.0/24 (Wi-Fi en0 .99 and the
        # wired en4 .182). The route to the C64 goes via en4 today, but
        # binding the source address pins the frame to the interface the
        # tap is on rather than trusting that.
        self.src_ip = src_ip
        self.delay = delay
        self.payload = payload
        self.sent_at: float | None = None
        self.error: str | None = None

    def run(self) -> None:
        time.sleep(self.delay)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if self.src_ip:
                s.bind((self.src_ip, 0))
            s.sendto(self.payload, self.dst)
            self.sent_at = time.monotonic()
            s.close()
        except OSError as exc:
            self.error = str(exc)


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


def send_once(tr, L, payload: bytes, timeout: float,
              on_before_jsr=None) -> tuple[int, float]:
    """One net_udp_send. Returns (carry, wall seconds spent inside the call).

    jsr() sets a monitor checkpoint and lets the CPU RUN to it, so the wall
    clock across the call is honest 6510 time (VICE is at 1 MHz here — warp
    is off for the whole run, see vice_eth_rig's module doc).
    """
    write_bytes(tr, L["udp_recv_buf"], payload)
    write_bytes(tr, L["net_udp_send_len"], struct.pack("<H", len(payload)))
    write_bytes(tr, CARRY, b"\xFF")
    # Staging is several monitor round trips. Anything timed against the
    # CALL must start here, after them, or it races the setup instead of
    # the send — which is how the mid-pump probe kept landing late.
    if on_before_jsr is not None:
        on_before_jsr()
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
    for label, fn in (("payload parser", selftest_payload_parser),
                      ("ld65 map parsers", selftest_map_parsers)):
        bad = fn()
        if bad:
            log(f"FATAL: the {label} self-test failed, so anything it "
                "reports below would be meaningless:")
            for b in bad:
                log(f"    {b}")
            return 1
        log(f"  {label} self-test: OK")

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
    else:
        log(f"  arp_cache = ${cache:04X} "
            f"(ip65 map: arp_ip ${cache - 4:04X} + 4)")
    # Optional observability the ip65 adapter grows with the #120 fix. Each
    # is probed, never assumed: on the unfixed tree the label is absent and
    # the assertions that use it say so instead of failing for the wrong
    # reason.
    have_err = "net_last_error" in L
    have_attempts = "ip65_send_attempts" in L
    have_pump = "ip65_send_pump" in L
    have_dropped = "ip65_recv_dropped" in L
    for name, present in (("net_last_error", have_err),
                          ("ip65_send_attempts", have_attempts),
                          ("ip65_send_pump", have_pump),
                          ("ip65_recv_dropped", have_dropped)):
        state = ("exported" if present else
                 "ABSENT — its assertions are SKIPPED on this build")
        log(f"  {name}: {state}")
    for cname, mine in (("NET_ERR_IP65_WAIT_TIMEOUT",
                         NET_ERR_IP65_WAIT_TIMEOUT),
                        ("NET_ERR_TIMEBASE_STOPPED",
                         NET_ERR_TIMEBASE_STOPPED),
                        ("NET_ERR_IP65_UDP_SEND", NET_ERR_IP65_UDP_SEND)):
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
    # 51820 is wg_local_port as built, which is the port net_udp_listen
    # registers during net_init — the mid-pump probe is aimed there and
    # MUST be captured, or the drop-counter assertion would rest on an
    # unproven premise (that the datagram reached the C64 at all).
    bpf = (f"arp or (udp and (port 67 or port 68 or port {dest_port} "
           f"or port 51820))")
    rc = 1
    with WireTap(bpf, args.iface) as tap:
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
            # The AUTHORITATIVE cold signal is ip65's own cache, not the tap.
            # A real LAN's router broadcasts ARP requests of its own, and
            # ip65's arp_process caches the SENDER of any ARP frame it sees
            # (ip65/ip65/arp.s), so those can warm the gateway row without the
            # C64 ever asking for it. When that happens the defect genuinely
            # cannot fire and there is no verdict to give.
            if gw_before:
                inconclusive(
                    "the ARP cache was NOT cold at the first send: ip65's "
                    f"arp_cache already holds {gw_before} for the gateway. "
                    f"Something on the LAN warmed it ({len(gw_spoke)} ARP "
                    "frame(s) from the gateway crossed the tap before the "
                    "send, and a router that ARPs its clients will do that). "
                    "Re-run; if it persists, this LAN cannot host the "
                    "measurement.")
            if gw_spoke:
                log(f"  note: {len(gw_spoke)} ARP frame(s) from {gw} crossed "
                    "the tap before the send, but ip65's cache holds no "
                    "gateway row, so the cache is cold on the signal that "
                    "decides the outcome")
            check(not gw_before and not asked_for_gw and not udp_before,
                  "precondition: ARP cache cold for the gateway and no prior "
                  "traffic from the C64 to the destination",
                  f"cache rows for {gw}: {gw_before}\n"
                  f"who-has {gw} tell {c64}: {len(asked_for_gw)}\n"
                  f"UDP {c64} -> {dest_ip}: {len(udp_before)}")

            # ---- THE RED -------------------------------------------------
            ceiling = max(2.0, args.budget * 3)
            set_dest(tr, L, dest_ip, dest_port)
            mark_udp = len(tap.udp(src=c64, dst=dest_ip))
            mark_bytes = len(tap.matching(c64, dest_ip, dest_port))
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
            # BYTES, not just presence and length. ip65/ip.s:322 destroys the
            # outbound frame during the ARP lookup, so a fix that RESUMED
            # into the half-built packet instead of rebuilding it would emit
            # a right-sized datagram full of wrong bytes and every check
            # above would still pass.
            body1 = tap.matching(c64, dest_ip, dest_port)[mark_bytes:]
            check(len(body1) == 1 and body1[0][4] == payload,
                  "attempt 1's datagram carried the staged bytes EXACTLY",
                  f"captured {len(body1)} payload(s); "
                  + (f"first differs at byte "
                     f"{next((i for i, (a, b) in enumerate(zip(body1[0][4], payload)) if a != b), 'n/a')} "
                     f"({len(body1[0][4])} B on the wire vs "
                     f"{len(payload)} B staged)" if body1 else "none to compare")
                  + " — a resume-based fix reuses the frame ip65 already "
                    "destroyed doing the ARP lookup (ip65/ip.s:322)")
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
            if have_dropped:
                drop1 = opt_byte(tr, L, "ip65_recv_dropped")
                check(drop1 == 0,
                      "nothing was discarded during the first send "
                      "(ip65_recv_dropped still reads 0 — this does NOT "
                      "exercise the increment)",
                      f"ip65_recv_dropped = {drop1}; nothing was sent at the "
                      "C64 during this send, so the pump had no inbound "
                      "datagram to discard")

            # ---- the control: recovery -----------------------------------
            log("")
            log("=== Phase 2: control — pump net_poll, send again ===")
            pump(tr, L)
            mark_udp = len(tap.udp(src=c64, dst=dest_ip))
            mark_bytes = len(tap.matching(c64, dest_ip, dest_port))
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
            body2 = tap.matching(c64, dest_ip, dest_port)[mark_bytes:]
            ok_ctrl &= check(len(body2) == 1 and body2[0][4] == payload,
                             "control: the warm send's bytes on the wire are "
                             "the staged bytes",
                             f"captured {len(body2)} payload(s)")
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
            if have_dropped:
                # Cumulative since net_init, so this covers phases 1 AND 2.
                drop2 = opt_byte(tr, L, "ip65_recv_dropped")
                ok_ctrl &= check(drop2 == 0,
                                 "control: nothing was discarded during "
                                 "either cold-ARP send (still 0 — this does "
                                 "NOT exercise the increment)",
                                 f"ip65_recv_dropped = {drop2}; the counter "
                                 "is cumulative, so a non-zero here means "
                                 "real inbound traffic was discarded and the "
                                 "phase-3 delta would be confounded")
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

            # Land one datagram INSIDE the retry pump, so the documented
            # disarm actually executes and ip65_recv_dropped moves. The
            # listener's port comes from the adapter's own ip65_listen_port:
            # wg_local_port was randomised AFTER net_init, so the registered
            # port is not the one the sends go out from.
            injector = None
            drop_before3 = opt_byte(tr, L, "ip65_recv_dropped") or 0
            if have_dropped:
                # LITTLE-endian: net_udp_listen stages `lda wg_local_port /
                # ldx wg_local_port+1` and ip65's udp_add_listener takes A as
                # the LOW byte. Decoding this big-endian would aim the probe
                # at a byte-swapped port and produce exactly a silent
                # "counter never moved" — which is #118's bug (a peer on
                # 51820 $CA6C sent to 27850 $6CCA) wearing a different hat.
                # Both decodings are logged so the right one is eyeballable
                # against the tap.
                lp = read_bytes(tr, L["ip65_listen_port"], 2)
                listen_port = lp[0] | (lp[1] << 8)
                swapped_port = lp[1] | (lp[0] << 8)
                log(f"  ip65_listen_port raw {lp.hex()} -> LE {listen_port} "
                    f"(${listen_port:04X}); BE would be {swapped_port} "
                    f"(${swapped_port:04X})")
                # A listener that was never registered means no callback and
                # no counter, for a completely different reason than the one
                # this phase reports.
                listening = opt_byte(tr, L, "ip65_listening")
                check(listening == 1,
                      "a listener is registered before the mid-pump probe "
                      "(ip65_listening == 1)",
                      f"ip65_listening = {listening} — with no registered "
                      "port, ip65's udp_process takes its @drop leg without "
                      "ever calling net_udp_recv_cb, so ip65_recv_dropped "
                      "could not move whatever the pump did")
                if listen_port == 0:
                    log("  note: ip65_listen_port is 0 — no listener to aim "
                        "at, so the mid-pump arrival is NOT attempted")
                else:
                    probe = (bytes(rng.randrange(0x80, 0x100)
                                   for _ in range(28)) + b"MIDP")
                    # Warm the HOST's ARP for the C64 — and it has to be
                    # done WHILE THE C64 IS EXECUTING. Under jsr() takeover
                    # the 6510 is halted between monitor commands, so a ping
                    # sent at any other moment is never answered: ip65 is
                    # polled, and nothing polls while the machine is stopped.
                    # Measured: with the probe socket bound, an unwarmed
                    # send fails outright with EHOSTUNREACH; unbound, it is
                    # silently queued behind an ARP that resolves after the
                    # send window has closed. Either way the counter goes
                    # unexercised. So: ping from a thread while the main
                    # thread runs net_poll, which is the only window in
                    # which the C64 can answer.
                    warm = threading.Thread(
                        target=subprocess.run,
                        args=(["ping", "-c", "4", "-i", "0.3", "-W", "400",
                               c64],),
                        kwargs={"capture_output": True}, daemon=True)
                    warm.start()
                    pump(tr, L, calls=250)
                    warm.join(timeout=5.0)
                    if not arp_known(c64):
                        log(f"  note: the host still has no MAC for {c64} "
                            "after warming during a net_poll burst — the "
                            "probe cannot be delivered inside the window and "
                            "the counter will go unasserted")
                    else:
                        log(f"  host ARP warm for {c64}")
                    mark_probe = len(tap.matching(host_ip, c64, listen_port))
                    injector = MidPumpSender(c64, listen_port,
                                             args.budget * 0.2, probe,
                                             src_ip=host_ip)
                    log(f"  mid-pump probe: {len(probe)} B at {c64}:"
                        f"{listen_port} (ip65_listen_port), fired "
                        f"{args.budget * 0.2:.2f}s into the send")

            hung = False
            t_send_start = time.monotonic()
            try:
                carry3, took3 = send_once(
                    tr, L, payload, timeout=max(45.0, args.budget * 20),
                    on_before_jsr=(injector.start if injector else None))
            except Exception as exc:  # noqa: BLE001 — a hang is the point
                hung, carry3, took3 = True, -1, float("nan")
                log(f"  send attempt 3 NEVER RETURNED: {type(exc).__name__}: "
                    f"{exc}")
                t_send_end = time.monotonic()
            else:
                t_send_end = time.monotonic()
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
                # The BAND, not just the ceiling. A ceiling alone is satisfied
                # by a tree with no retry loop at all (0.00 s), which is
                # exactly the unfixed tree. The floor half is what says the
                # bounded wait is REAL.
                floor_want = args.budget * 0.5
                check(took3 >= floor_want,
                      f"the bounded wait actually happened "
                      f"(>= {floor_want:.2f}s, half the {args.budget:.2f}s "
                      f"budget)",
                      f"took {took3:.2f}s — a send that gives up in ~0 s "
                      "never entered the retry loop, which is the unfixed "
                      "tree's behaviour")
                log(f"  MEASURED retry budget: {took3:.2f}s in "
                    f"[{floor_want:.2f}, {ceiling:.1f}] "
                    f"(jsr floor {floor:.3f}s) — ~0 means no retry loop is "
                    f"present; ~{args.budget:.2f}s means the bounded wait is "
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
                if injector is not None:
                    injector.join(timeout=5.0)
                    drop3 = opt_byte(tr, L, "ip65_recv_dropped")
                    # ON THE WIRE, not just handed to sendto(). A counter
                    # that did not move proves nothing unless the datagram
                    # demonstrably reached the C64 while the send was still
                    # running; otherwise the "failure" is the host's, and
                    # asserting on it would be asserting on an unproven
                    # premise.
                    seen = tap.matching(host_ip, c64, listen_port)[mark_probe:]
                    on_wire = any(f[4] == probe for f in seen)
                    landed = (injector.sent_at is not None
                              and injector.error is None
                              and injector.sent_at <= t_send_end
                              and on_wire)
                    if not on_wire and injector.error is None:
                        log(f"  mid-pump probe NEVER REACHED THE WIRE inside "
                            f"the window (tap saw {len(seen)} datagram(s) to "
                            f"{c64}:{listen_port}) — the counter is NOT "
                            f"asserted; this is a host-side miss, not a "
                            f"finding about ip65_recv_dropped")
                    if injector.error:
                        log(f"  mid-pump probe FAILED TO SEND: "
                            f"{injector.error} — the counter is NOT asserted")
                    elif not landed:
                        log(f"  mid-pump probe was sent but AFTER the call had "
                            f"already returned (send ran {took3:.2f}s) — the "
                            f"arrival was not inside the pump, so the counter "
                            f"is NOT asserted. ip65_recv_dropped = {drop3}")
                    else:
                        # DISTINGUISH THE THREE OUTCOMES. A bare "counter is
                        # 0" does not say which happened, and two of the
                        # three are not the implementer's bug:
                        #   dropped   -> counter moved; the disarm engaged.
                        #   delivered -> the probe is sitting in udp_recv_buf,
                        #                so the callback ran LIVE and the
                        #                disarm did NOT engage during the
                        #                pump. Different defect, opposite
                        #                sign.
                        #   unseen    -> on the wire but nowhere in the C64,
                        #                so ip65 never processed the frame at
                        #                all (eth_rx starving behind the
                        #                loop's own ARP broadcasts is the
                        #                candidate).
                        rdy = opt_byte(tr, L, "udp_recv_ready")
                        rlen_b = read_bytes(tr, L["udp_recv_len"], 2)
                        rlen = rlen_b[0] | (rlen_b[1] << 8)
                        rbuf = read_bytes(tr, L["udp_recv_buf"], len(probe))
                        delivered = rbuf == probe
                        log(f"  after the send: udp_recv_ready={rdy} "
                            f"udp_recv_len={rlen} "
                            f"probe bytes in udp_recv_buf: {delivered}")
                        if delivered:
                            log("  DIAGNOSIS: the probe was DELIVERED, not "
                                "dropped. This suite drives net_udp_send "
                                "through jsr() with the CPU parked between "
                                "monitor commands — NO main loop is running "
                                "— so nothing called net_poll between the "
                                "send returning and this read. The datagram "
                                "therefore cannot have been taken in "
                                "legitimately after the call, and a live "
                                "callback DURING the pump is the only "
                                "explanation left. Bring this to the "
                                "implementer: it is a finding about the "
                                "DISARM, of the opposite sign to a broken "
                                "counter. (Under a driver that DOES let the "
                                "main loop run, the same reading would mean "
                                "only that the frame was polled in late, "
                                "which is no defect at all.)")
                        elif drop3 == drop_before3:
                            log("  DIAGNOSIS: the probe is neither counted "
                                "nor in udp_recv_buf — it reached the wire "
                                "but ip65 never processed the frame. First "
                                "hypothesis is VICE's rawnet receive path "
                                "under a CPU spinning inside the retry loop, "
                                "NOT eth_rx starvation: the loop calls "
                                "ip65_process every iteration and, for an "
                                "on-subnet destination, arp_lookup only "
                                "transmits every 100 ms, so it is far more "
                                "receive-hungry than transmit-heavy. Not a "
                                "backend bug without more work.")
                        globals()["drop_increment_asserted"] = True
                        check(drop3 is not None and drop3 > drop_before3,
                              "a datagram arriving DURING the pump is counted "
                              "in ip65_recv_dropped",
                              f"ip65_recv_dropped = {drop3} (was "
                              f"{drop_before3}; the counter is cumulative and "
                              f"saturates at $FF) after a datagram "
                              f"was delivered to {c64}:{listen_port} "
                              f"{injector.sent_at - t_send_start:.2f}s into a "
                              f"{took3:.2f}s send. The counter exists so the "
                              "cost of the inbound disarm is observable; a "
                              "zero here means the drop path is not counting, "
                              "or the datagram never reached ip65.")
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
                          "NET_ERR_TIMEBASE_STOPPED. On a healthy LAN this "
                          "is the stopped-clock DETECTOR MISFIRING, not a "
                          "flake: it fires when 256 retry iterations show a "
                          "zero jiffy delta, and that 256 rests on a static "
                          "cycle argument with no rig behind it. REPORT IT "
                          "rather than re-running — the constant is the "
                          "thing to suspect. The elapsed figure above is "
                          "then an accident of loop cost, not a bound.")
                    check(err != NET_ERR_IP65_UDP_SEND,
                          f"net_last_error is not ${NET_ERR_IP65_UDP_SEND:02X} "
                          "(NET_ERR_IP65_UDP_SEND, defined but never emitted)",
                          f"net_last_error = ${err:02X}: this code exists so "
                          "a redefinition is an assembler error and is "
                          "deliberately never written. Seeing it is a bug in "
                          "the adapter.")

            # ---- net_init resets the counter -----------------------------
            # LAST, because re-running net_init tears the stack down: it
            # re-inits ip65 and drops the listener. Nothing after this can
            # use the network.
            if have_attempts:
                log("")
                log("=== Phase 4: net_init clears ip65_send_attempts ===")
                before = opt_byte(tr, L, "ip65_send_attempts")
                jsr(tr, L["net_init"], timeout=30.0)
                after = opt_byte(tr, L, "ip65_send_attempts")
                log(f"  ip65_send_attempts: {before} -> {after} across "
                    f"net_init")
                check(before is not None and before > 0,
                      "the counter was non-zero going in (so the reset is "
                      "actually observable)",
                      f"ip65_send_attempts = {before} before net_init — a "
                      "reset from 0 to 0 proves nothing")
                check(after == 0,
                      "net_init clears ip65_send_attempts",
                      f"ip65_send_attempts = {after} after net_init; a "
                      "counter that survives a re-init reports the previous "
                      "run's send to the next one")

            # ---- report --------------------------------------------------
            log("")
            passed = sum(1 for ok, _ in results if ok)
            log(f"=== {passed}/{len(results)} checks passed (seed {seed}) ===")
            if have_dropped and not drop_increment_asserted:
                log("")
                log("COVERAGE GAP — ip65_recv_dropped's INCREMENT was never "
                    "exercised in this run.")
                log("  Its zero case is asserted twice above. That is not "
                    "coverage: a counter that")
                log("  reads 0 when nothing was dropped is satisfied just as "
                    "well by a counter that")
                log("  can never move at all. The increment path has not "
                    "executed here, and a green")
                log("  count above must not be read as saying otherwise.")
                log("  Cause: under jsr() takeover the 6510 is HALTED between "
                    "monitor commands and")
                log("  ip65 is polled, so the host's ARP for the C64 goes "
                    "unanswered and the probe")
                log("  cannot be delivered inside the ~0.5 s window. Covering "
                    "it needs a driver that")
                log("  lets the app's main loop run — a different suite "
                    "shape, not a knob here.")
                log("")
                log("  HOW TO COVER IT, for whoever builds that suite. Do NOT "
                    "aim at the first send")
                log("  after net_init: that window opens once per boot, so a "
                    "probe that misses cannot")
                log("  be retried, and it overlaps the retry-loop assertions "
                    "this suite already makes.")
                log("  Aim at an EVICTION window instead. ip65's arp_cache is "
                    "an 8-entry MRU list and")
                log("  arp_process's @request leg jumps straight into "
                    "ac_add_source (ip65/ip65/arp.s),")
                log("  which shifts every row down ten bytes and inserts at "
                    "the top, dropping the last.")
                log("  That leg does NOT call findip first — only arp_add, on "
                    "the reply path, dedupes —")
                log("  so eight ARP requests for the C64's address evict the "
                    "gateway row even when they")
                log("  all come from the SAME sender. One host can do it "
                    "alone with raw ARP frames.")
                log("  The next send to an off-subnet peer then goes cold "
                    "mid-session, with the app's")
                log("  main loop running, and the window is reopenable on "
                    "demand until the probe lands.")
                log("  That is also the window where the drop COSTS "
                    "something: WireGuard retransmits")
                log("  handshake initiations but not Type 4 transport data, "
                    "so a datagram discarded")
                log("  during an eviction pump is simply gone — which is why "
                    "the counter exists.")
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
