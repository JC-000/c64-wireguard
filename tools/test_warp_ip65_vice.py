#!/usr/bin/env python3
"""test_warp_ip65_vice.py — ip65/RR-Net against Cloudflare WARP, BRIDGED VICE.

OPT-IN, VICE-ethernet only. Exit 77 (skipped) when the bridged rig is not
up; deliberately NOT in tools/run_regression.py (it needs a real LAN, a
real router and the real internet).

WHY BRIDGED, AND WHY IT IS NOT THE SAME TEST AS THE feth RIG
============================================================

The existing ip65 suites run on the feth pair (tools/vice_eth_rig.py's
"host" mode): the C64 can reach this Mac and nothing else, and the peer is
our own Python responder on 10.0.65.1. Everything about WireGuard that
depends on a *real* peer — Cloudflare's TAI64N monotonicity rule, its
cookie/rate limiting, its MTU behaviour, an internet round-trip time — is
therefore untested there.

Routing the feth segment out to the internet would mean NATing it through
this Mac's IP stack, and on this bench that stack's default route is the
host's own Cloudflare WARP tunnel (utun1, MTU 1300). Every C64 datagram
would then be encapsulated a second time and capped at 1300 bytes, so the
one thing #70 exists to prove — a full-size datagram — could not be
observed even if it worked.

BRIDGED mode removes the host stack from the path entirely. VICE's pcap
driver attaches to a real ethernet NIC (en4, a USB-C adapter; the built-in
en0 is Wi-Fi and Apple's drivers will not transmit a frame with a foreign
source MAC). The emulated CS8900A then reads and writes frames on the
physical segment, so the C64 is an ordinary LAN node: it DHCPs from the
real router and its IP datagrams are switched straight to the default
gateway. Frames that never enter this Mac's IP stack cannot be routed
through a tunnel that lives in that stack.

That is the reasoning; the suite does not take it on trust. Stage A
asserts the lease came from the real router's subnet and NOT from the feth
rig's 10.0.65.0/24, the preflight asserts the rig's dnsmasq is not bound
to the bridged interface, and Stage C measures on the wire whether a reply
larger than the host tunnel's MTU can reach the C64 whole.

STAGES
======

A  build (BACKEND=ip65 REU=0 WG_MTU1440=1), boot, 'I', REAL DHCP lease
   (read from ip65's own cfg_ip over DMA), stage the WARP peer, 'H', wait
   for wg_state == ACTIVE, and assert at the wire tap that the 148-byte
   Type-1 left FROM the configured local port TO 162.159.192.1:2408.
B  'P' (ping 1.1.1.1 through the tunnel) and a randomised chat message.
C  rebuild with MSG_PORT=53 BUILD_DIR=build_msgport53, fresh boot and
   handshake, then two real DNS queries to 1.1.1.1:53 staged over DMA:
   one whose reply is host-measured in the 900-1279 B band and one whose
   true answer exceeds ~1280 B. Asserts the inner IPv4/UDP header, the
   transaction id, QR, and reports the received length against the
   host-measured one.
D  --rekey N: press H, assert hs_timestamp strictly increases as a 96-bit
   big-endian integer and ACTIVE returns each time (issue #87, against a
   production peer this time, on ip65).

RED WITHOUT THE FIXES
=====================

* Without the #118 port fix, net_udp_dest_port (big-endian, net_abi.inc)
  is copied raw into ip65's little-endian port cell, so 2408 leaves as
  26633. ``type1_dport_ok`` is the assertion that catches it, and it is
  the ONLY one that can: the handshake simply never completes, and every
  other check reports "timed out" without saying why. ``--prove-red port``
  demonstrates the alarm through net_udp_send DIRECTLY (an 8-byte stub at
  $0340 driven by jsr()), staging the destination port correctly and then
  byte-swapped and reading the dport off the tap. It goes through the send
  path rather than the menu because the menu computes the entire Type-1
  first -- 349 s of X25519 measured on this rig -- which makes it a
  hopeless place to demonstrate a wire-format assertion. Be clear about
  what this is: a deliberate one-field corruption that reproduces the
  unfixed tree's OUTPUT, not a build of the unfixed tree.
* Without WG_MTU1440, ip65's caps clamp WG_MTU to 860 and MSG_TEXT_MAX to
  832 (src/constants.inc), which is smaller than every reply Stage C asks
  for. ``mtu_admits_replies`` is checked from the BUILT labels before any
  VICE is started, so that build is refused up front instead of failing
  as a mysterious short read. ``--prove-red mtu`` links a no-flag build
  and shows the check going red.

TWO VACUOUS CHECKS FOUND IN THIS SUITE'S OWN SCAFFOLDING (2026-09-03)
====================================================================

Both are the coincidence class this project keeps hitting -- an assertion
that passes while testing nothing -- so both now carry a standing alarm
rather than a comment:

1. ``dnsmasq_interfaces()`` used ``pgrep -af``. ``-a`` is Linux pgrep; on
   macOS the call exits 1 with no output, so the function returned [] for
   every input and "the rig's dnsmasq is not serving the bridged
   interface" passed with no evidence behind it. It was found by PRINTING
   the list instead of trusting the empty result. Now ``pgrep -fl``, with
   ``selftest_dnsmasq_probe()`` failing the run when a dnsmasq is running
   that the probe cannot see. ``selftest_conflict_probe()`` guards the
   identical shape for "no other VICE is on this NIC", using a decoy
   process, because that answer is an empty list too.

2. The send-retry poll loop called the rig's ``screen_text()``, which does
   NOT resume, and then slept. Every binary-monitor command pauses the
   6510 (issue #54/#55), so the machine was halted for essentially the
   whole window and running crypto was indistinguishable from a hang --
   it burned a 900 s budget looking exactly like a stuck handshake. The
   local ``screen()`` wrapper in press_h_until_sent resumes, and the
   1000-byte screen read is throttled to 10 s while the 1-byte wg_state
   read carries the fast cadence.

Randomised per run: both C64 static keypairs, the chat payload and the DNS
transaction ids — seeded, the seed logged once, reproducible via --seed.

Usage::

    python3 tools/test_warp_ip65_vice.py [--stages ABCD] [--rekey 2]
                                         [--iface en4] [--seed S]
    WARP_PROFILE=/path/wgcf-profile.conf   (default: this session's scratchpad)
    C64_SKIP_BUILD=1                       reuse the builds as found

Exit codes: 0 PASS / 1 FAIL / 77 SKIP (rig absent).

THE PRIVATE KEY IS NEVER PRINTED. Only the derived public key is logged,
and only its first bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import string
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, jsr  # noqa: E402
import wg_c64_input as ki  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    BRIDGED_IFACE, DEFAULT_VICE_BIN, PROJECT_ROOT, EthVice, ResumingTransport,
    Tap, assert_ip65_build, assert_vice_bound_to, boot_and_net_init,
    build_ip65, c64_ip, default_gateway, describe_bridged, describe_conflict,
    dnsmasq_interfaces, iface_status, log, press_key, screen_text,
    selftest_classifier, selftest_conflict_probe, selftest_dnsmasq_probe,
    skip_if_bridged_rig_down, vice_on_iface, wait_boot_ready,
    wait_net_initialized,
)

# --- Cloudflare WARP peer (public facts; the private key comes from the
#     profile file and is never logged) ---
WARP_PEER_PUB_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT_IP = "162.159.192.1"          # engage.cloudflareclient.com
WARP_ENDPOINT_PORT = 2408
TUNNEL_IP = "172.16.0.2"
PING_TARGET_IP = "1.1.1.1"
WG_PUBKEY_BIN = "/opt/homebrew/bin/wg"

DEFAULT_WARP_PROFILE = os.environ.get(
    "WARP_PROFILE",
    "/private/tmp/claude-501/-Users-someone-Documents-c64-wireguard/"
    "2f7136e5-967c-4b11-9401-e5c8b0601a68/scratchpad/warp/wgcf-profile.conf")

# The feth rig's subnet. A lease from here would mean VICE was NOT bridged
# onto the physical segment, and every "real internet" claim would be void.
RIG_SUBNET_PREFIX = "10.0.65."

SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2
TYPE1_LEN = 148                     # WireGuard MessageInitiation on the wire

BUILD_A = os.path.join(PROJECT_ROOT, "build")
BUILD_C = os.path.join(PROJECT_ROOT, "build_msgport53")
BUILD_RED = os.path.join(PROJECT_ROOT, "build_red_nomtu1440")

DHCP_BUDGET_S = float(os.environ.get("WARP_IP65_DHCP_BUDGET_S", "120"))
HS_BUDGET_S = float(os.environ.get("WARP_IP65_HS_BUDGET_S", "900"))
PING_BUDGET_S = float(os.environ.get("WARP_IP65_PING_BUDGET_S", "60"))
DNS_BUDGET_S = float(os.environ.get("WARP_IP65_DNS_BUDGET_S", "60"))

DNS_QTYPE_TXT = 16
#: (qname, qtype, host-measured reply bytes, band). Measured host-side with
#: the same wire format this suite sends, immediately before the run — see
#: --measure-dns, which reprints them. github.com's TXT answer genuinely
#: exceeds 1280 B; 1.1.1.1 answers it with a 39-byte TC=1 stub on the host's
#: WARP path. Whether the C64's own (host-stack-free) path gets the same
#: stub or the whole record is the datum Stage C exists to collect.
DNS_QUERIES = [
    ("namecheap.com", DNS_QTYPE_TXT, "900-1279 band"),
    ("github.com", DNS_QTYPE_TXT, "true answer >1280 B"),
]

VERBOSE = False
results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    log(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if detail and (not ok or VERBOSE):
        for line in str(detail).splitlines():
            log(f"        {line}")
    return bool(ok)


# ============================================================================
# WARP profile — private key in, public key out, nothing printed
# ============================================================================

def load_warp_profile(path: str) -> tuple[bytes, str, str]:
    """(private key bytes, tunnel ip, peer pubkey b64) from a wgcf profile.

    The private key is returned as bytes and never enters a log line, a
    filename or a subprocess argv (``wg pubkey`` gets it on stdin).
    """
    priv_b64 = peer_pub = address = None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("PrivateKey"):
                priv_b64 = line.split("=", 1)[1].strip()
            elif line.startswith("Address"):
                address = line.split("=", 1)[1].strip()
            elif line.startswith("PublicKey"):
                peer_pub = line.split("=", 1)[1].strip()
    if not priv_b64:
        raise RuntimeError(f"{path} has no PrivateKey= line")
    priv = base64.b64decode(priv_b64)
    if len(priv) != 32:
        raise RuntimeError("PrivateKey is not 32 bytes")
    tunnel_ip = address.split("/")[0] if address else TUNNEL_IP
    return priv, tunnel_ip, (peer_pub or WARP_PEER_PUB_B64)


def derive_pubkey(priv: bytes) -> bytes:
    """`wg pubkey` over stdin only. Returns 32 raw bytes."""
    p = subprocess.run([WG_PUBKEY_BIN, "pubkey"],
                       input=base64.b64encode(priv) + b"\n",
                       capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"wg pubkey failed: {p.stderr!r}")
    out = base64.b64decode(p.stdout.strip())
    if len(out) != 32:
        raise RuntimeError("wg pubkey returned a non-32-byte key")
    return out


def stage_warp_config(tr, L, priv: bytes, pub: bytes, peer_pub: bytes,
                      tunnel_ip: str, *, swap_port: bool = False) -> int:
    """Stage cfg_* for the WARP peer over DMA; returns the TAI64N base used.

    Modelled on tools/test_warp_live.py's _stage_config. cfg_peer_endpoint_port
    is BIG-endian in the ABI (net_abi.inc); *swap_port* stages it the wrong
    way round on purpose, to reproduce the pre-#118 wire symptom.
    """
    tr.write_memory(L["cfg_static_priv"], priv)
    tr.write_memory(L["cfg_static_pub"], pub)
    tr.write_memory(L["cfg_peer_pub"], peer_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))          # no PSK
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in WARP_ENDPOINT_IP.split(".")))
    port_be = bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF])
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    port_be[::-1] if swap_port else port_be)
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in tunnel_ip.split(".")))
    tr.write_memory(L["ping_target_ip"],
                    bytes(int(o) for o in PING_TARGET_IP.split(".")))
    # issue #87: a FRESH base time every run, so this run's first initiation
    # is strictly newer than any earlier run's against the same static key.
    # Cloudflare enforces WireGuard's greatest-seen-timestamp rule and drops
    # a repeat in silence.
    tai = int(time.time()) + 10          # TAI-UTC offset; approximate is fine
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))
    log(f"  cfg staged: c64_pub {pub.hex()[:16]}…  peer {peer_pub.hex()[:16]}…  "
        f"endpoint {WARP_ENDPOINT_IP}:{WARP_ENDPOINT_PORT}"
        f"{' (PORT DELIBERATELY BYTE-SWAPPED)' if swap_port else ''}  "
        f"tunnel {tunnel_ip}  tai64n base {tai}")
    return tai


# ============================================================================
# DNS (host-side wire construction; copied from tools/test_warp_live.py)
# ============================================================================

def build_dns_query(name: str, qtype: int, txn_id: int,
                    bufsize: int = 1400) -> tuple[bytes, bytes]:
    """(question section, full query wire bytes).

    The first value is the QUESTION SECTION ONLY — no header — because it
    is compared against the reply starting at the reply's own offset 12.
    """
    def enc(n: str) -> bytes:
        out = b""
        for label in n.strip(".").split("."):
            if label:
                out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 1)   # RD, 1Q, OPT
    question = enc(name) + struct.pack(">HH", qtype, 1)           # QCLASS=IN
    opt = b"\x00" + struct.pack(">HHIH", 41, bufsize, 0, 0)       # EDNS0
    return question, header + question + opt


def measure_dns_host(name: str, qtype: int, bufsize: int = 1400
                     ) -> tuple[int, bool]:
    """(reply length, TC bit) as this HOST sees it. Best-effort.

    This is the host's path, which on this bench runs through the host's
    own WARP tunnel — it is the comparison baseline, not ground truth for
    the C64's direct path. -1 on failure so a DNS hiccup does not fail the
    suite before the C64 has been asked anything.
    """
    import socket
    _, wire = build_dns_query(name, qtype, random.randint(0, 0xFFFF), bufsize)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    try:
        s.sendto(wire, (PING_TARGET_IP, 53))
        d, _ = s.recvfrom(65535)
        return len(d), bool(d[2] & 0x02)
    except OSError:
        return -1, False
    finally:
        s.close()


def stage_raw_dma(tr, payload: bytes, L, timeout: float = 20.0) -> bool:
    """wg_c64_input.send_message_dma, but staging RAW bytes.

    send_message_dma upper()s and ASCII-encodes its text, which would
    corrupt binary DNS wire data. Same keystrokes, same buffer, no
    transform. (From tools/test_warp_live.py.)
    """
    limit = ki.input_max_from_labels(L)
    if len(payload) > limit:
        raise ValueError(f"{len(payload)} bytes exceeds this build's "
                         f"MSG_TEXT_MAX of {limit}")
    if not ki.press_key(tr, "M", timeout):
        return False
    if not ki._wait_drained(tr, timeout):
        return False
    time.sleep(0.3)
    base = L["ip_packet_buf"] + ki.IP_UDP_HDR_LEN
    for i in range(0, len(payload), ki.DMA_CHUNK):
        tr.write_memory(base + i, payload[i:i + ki.DMA_CHUNK])
    tr.write_memory(L["msg_input_len"], len(payload).to_bytes(2, "little"))
    return ki.press_key(tr, "\r", timeout)


# ============================================================================
# Structural pre-checks on the BUILT labels
# ============================================================================

REQUIRED_LABELS = [
    "boot_ready", "net_initialized", "ip65_blob_start", "wg_state",
    "hs_timestamp", "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
    "cfg_preshared_key", "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
    "tunnel_ip", "ping_target_ip", "tai64n_base_time", "wg_local_port",
    "WG_MTU", "ip_packet_buf", "ip_pkt_len", "msg_input_len", "msg_recv_len",
    "msg_recv_ptr", "tp_packet", "tp_payload_len", "tp_send_counter",
]


def load_labels(build_dir: str) -> Labels:
    path = os.path.join(build_dir, "labels.txt")
    if not os.path.exists(path):
        raise SystemExit(f"FATAL: missing {path}")
    L = Labels.from_file(path)
    missing = [n for n in REQUIRED_LABELS if L.address(n) is None]
    if missing:
        raise SystemExit(f"FATAL: labels missing from {path}: {missing}")
    return L


def check_mtu_admits(L, need: int) -> bool:
    """MSG_TEXT_MAX derived from the labels must hold the largest reply.

    Structural, and checked before a VICE is started: without WG_MTU1440
    ip65's caps clamp WG_MTU to 860 and MSG_TEXT_MAX to 832, so a
    1278-byte DNS reply cannot arrive whole no matter what the wire does.
    """
    limit = ki.input_max_from_labels(L)
    return check(limit >= need,
                 f"build admits a {need}-byte tunnel payload "
                 f"(WG_MTU={L['WG_MTU']}, MSG_TEXT_MAX={limit})",
                 f"MSG_TEXT_MAX = ip_pkt_len - ip_packet_buf - 28 = {limit}; "
                 f"need {need}. Build with WG_MTU1440=1.")


def fingerprint(tag: str, prg_path: str, L) -> str:
    data = open(prg_path, "rb").read()
    fp = (f"{tag}: {os.path.relpath(prg_path, PROJECT_ROOT)} "
          f"{len(data)} B sha256 {hashlib.sha256(data).hexdigest()[:16]} "
          f"WG_MTU={L['WG_MTU']} MSG_TEXT_MAX={ki.input_max_from_labels(L)}")
    log("  " + fp)
    return fp


# ============================================================================
# Shared boot -> lease -> handshake sequence
# ============================================================================

SEND_FAILED_NEEDLE = "HANDSHAKE SEND FAILED"       # src/wg/strings.s:135
SEND_ATTEMPTS = int(os.environ.get("WARP_IP65_SEND_ATTEMPTS", "3"))


def press_h_until_sent(rt, tr, L, tag: str
                       ) -> tuple[bool, int, list[str]]:
    """Press H until the Type-1 actually leaves. Returns (ok, attempts, log).

    ip65 does NOT queue a datagram whose next-hop MAC it has not got: it
    emits the ARP request and returns C=1 immediately (ip65/ip.s), and
    session_initiate reports that as HANDSHAKE SEND FAILED and drops back
    to IDLE. On the feth rig the existing suites never see this, because
    the peer IS the host and the host pings the C64 first, which caches
    the host's MAC via arp_process. Bridged, the peer is off-subnet and
    the next hop is the router, so the FIRST initiation after net_init
    reliably fails on a cold cache — and its own ARP request is what
    fills the cache, so the second one succeeds.

    Measured 2026-09-03: with no retry, wg_state simply never left IDLE
    and the suite sat out its whole 900 s budget with an empty wire and
    "HANDSHAKE SEND FAILED" on screen.

    Detection is prompt rather than budget-bound: the loop watches the
    structural signal (wg_state leaving IDLE) and the failure string
    together, re-reading the on-screen occurrence count immediately
    before each press so a repeat failure is distinguishable from the
    previous attempt's message still sitting on screen.
    """
    def screen(tr) -> str:
        """screen_text + resume. The rig's screen_text() does NOT resume,
        and every binary-monitor command pauses the 6510 (issue #54/#55):
        a poll loop that reads the screen and then sleeps leaves the C64
        HALTED for the whole sleep. Measured 2026-09-03: a 2 s cadence
        without this resume stopped the machine dead in the middle of the
        Type-1 scalarmult, and the run looked exactly like slow crypto."""
        t = screen_text(tr)
        tr.resume()
        return t

    notes: list[str] = []
    for attempt in range(1, SEND_ATTEMPTS + 1):
        base_hits = screen(tr).count(SEND_FAILED_NEEDLE)
        if not ki.press_key(rt, "H", timeout=20.0):
            notes.append(f"attempt {attempt}: 'H' was not consumed")
            return False, attempt, notes
        t0 = time.monotonic()
        deadline = t0 + HS_BUDGET_S
        next_screen = t0
        while time.monotonic() < deadline:
            if rt.read_memory(L["wg_state"], 1)[0] != SESSION_IDLE:
                notes.append(f"attempt {attempt}: Type-1 sent after "
                             f"{time.monotonic() - t0:.0f}s")
                log(f"  [{tag}] Type-1 sent on attempt {attempt} "
                    f"({time.monotonic() - t0:.0f}s of crypto)")
                return True, attempt, notes
            # The screen read costs 1000 bytes over the monitor and a
            # pause/resume; the 1-byte wg_state read is what runs at the
            # fast cadence. Ten seconds is far quicker than the crypto.
            if time.monotonic() < next_screen:
                time.sleep(2.0)
                continue
            next_screen = time.monotonic() + 10.0
            if screen(tr).count(SEND_FAILED_NEEDLE) > base_hits:
                notes.append(f"attempt {attempt}: {SEND_FAILED_NEEDLE} after "
                             f"{time.monotonic() - t0:.0f}s (ip65 ARP cache "
                             "miss for the next hop)")
                log(f"  [{tag}] {SEND_FAILED_NEEDLE} on attempt {attempt} "
                    f"({time.monotonic() - t0:.0f}s) — retrying now that "
                    "ip65 has ARPed the gateway")
                break
            time.sleep(2.0)
        else:
            notes.append(f"attempt {attempt}: neither sent nor failed within "
                         f"{HS_BUDGET_S:.0f}s")
            return False, attempt, notes
        time.sleep(3.0)          # let the ARP reply land and be cached
    return False, SEND_ATTEMPTS, notes


def assert_iface_free(iface: str) -> None:
    """Refuse to launch if another lane holds *iface*. Never kills.

    The preflight already checked this, but a build takes about a minute
    and the rig is shared: on 2026-09-03 another lane's VICE claimed en4
    during exactly that window, so my launch failed with a bare "VICE
    exited early". Re-check at the last possible moment and name the
    owner, so the refusal is actionable instead of mystifying.
    """
    procs = vice_on_iface(iface)
    if procs:
        raise SystemExit("REFUSING TO LAUNCH: "
                         + describe_conflict(procs, iface))


SEND_STUB = 0x0340      # free tape buffer: harness owns $0334, $0360, $03F0-1


def _jsr_send(tr, L, dest_ip: str, dest_port_bytes: bytes, payload: bytes
              ) -> int:
    """Stage a datagram and call net_udp_send directly. Returns the carry.

    The menu path pays a full Type-1 (301 s measured on this rig, no-REU
    under VICE warp) BEFORE it ever reaches the send, which makes it a
    hopeless place to demonstrate a wire-format assertion. net_udp_send
    takes the buffer pointer in A/X, which jsr() cannot set, so an 8-byte
    stub loads them and calls it.
    """
    buf = L["ip_packet_buf"]
    tr.write_memory(buf, payload)
    tr.write_memory(L["net_udp_dest_ip"],
                    bytes(int(o) for o in dest_ip.split(".")))
    tr.write_memory(L["net_udp_dest_port"], dest_port_bytes)
    tr.write_memory(L["net_udp_send_len"], len(payload).to_bytes(2, "little"))
    tr.write_memory(SEND_STUB, bytes([
        0xA9, buf & 0xFF,                       # LDA #<buf
        0xA2, (buf >> 8) & 0xFF,                # LDX #>buf
        0x20, L["net_udp_send"] & 0xFF,         # JSR net_udp_send
        (L["net_udp_send"] >> 8) & 0xFF,
        0x60]))                                 # RTS
    regs = jsr(tr, SEND_STUB, timeout=20.0)
    return regs["FL"] & 1


def warm_arp_cache(tr, L, rng, tag: str) -> tuple[bool, int]:
    """Resolve the peer's next hop BEFORE the handshake. (ok, attempts).

    ip65 does not queue a datagram whose next-hop MAC it lacks: it emits
    the ARP request and returns C=1 (ip65/ip.s). For an off-subnet peer —
    every real-world peer — the first send after net_init therefore always
    fails, and session_initiate treats that as a fatal handshake failure.
    Driven from the menu the cost is brutal, because the whole Type-1 is
    computed BEFORE the send is attempted: measured 250 s of X25519 thrown
    away, then another 444 s for the attempt that works.

    So resolve the next hop first, with a throwaway 1-byte datagram sent
    through net_udp_send directly. WireGuard drops a malformed packet, so
    the peer is unaffected, and the ARP reply lands in ip65's cache via
    net_poll exactly as main_loop would deliver it.

    This is a TEST-SIDE workaround for an application defect, not a fix:
    the shipped app still fails its first handshake against any off-subnet
    peer. Recorded so the suite measures the crypto, not the cold cache.
    """
    for attempt in range(1, 4):
        c = _jsr_send(tr, L, WARP_ENDPOINT_IP,
                      bytes([WARP_ENDPOINT_PORT >> 8,
                             WARP_ENDPOINT_PORT & 0xFF]),
                      bytes([rng.randrange(256)]))
        for _ in range(60):
            jsr(tr, L["net_poll"], timeout=10.0)
        if c == 0:
            log(f"  [{tag}] next hop resolved after {attempt} probe(s) "
                "— the handshake now pays for crypto only")
            return True, attempt
        log(f"  [{tag}] probe {attempt}: net_udp_send C=1 (ARP miss); "
            "ip65 has now sent the request, retrying")
        time.sleep(1.0)
    return False, 3


def prove_red_port(vice, L, iface: str, rng) -> int:
    """Alarm proof for type1_dport_ok, without paying for the crypto.

    The pre-#118 adapter copied the big-endian ABI port cell straight into
    ip65's little-endian one. That exact wire symptom is reproduced here by
    staging net_udp_dest_port byte-swapped, so the assertion the suite makes
    is shown to FIRE rather than merely to pass on a fixed tree.

    Note honestly what this is: a deliberate one-field corruption that
    reproduces the unfixed tree's OUTPUT, not a build of the unfixed tree.
    """
    tr = vice.tr
    boot_and_net_init(tr, L, dhcp_timeout=DHCP_BUDGET_S)
    ip = c64_ip(tr, L)
    log(f"  C64 at {ip}, gateway {default_gateway(iface)}")
    tr.resume()
    port_be = bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF])
    swapped = ((WARP_ENDPOINT_PORT & 0xFF) << 8) | (WARP_ENDPOINT_PORT >> 8)

    with Tap(f"(udp and host {ip}) or (arp and host {ip})", iface=iface) as tap:
        for label, pb in (("correct (big-endian, as net_abi.inc says)", port_be),
                          ("byte-swapped (the pre-#118 symptom)", port_be[::-1])):
            log(f"\n  --- staging {label} ---")
            # The first send to an off-subnet peer always fails on a cold
            # ARP cache (ip65 emits the request and returns C=1), so send
            # until it takes, exactly as the app must.
            for attempt in (1, 2, 3):
                payload = bytes(rng.randrange(256) for _ in range(TYPE1_LEN))
                c = _jsr_send(tr, L, WARP_ENDPOINT_IP, pb, payload)
                log(f"      attempt {attempt}: carry={c} "
                    f"({'refused' if c else 'sent'})")
                for _ in range(40):
                    jsr(tr, L["net_poll"], timeout=10.0)
                if c == 0:
                    break
            time.sleep(1.5)

        sent = [r for r in tap.udp(src=ip, dst=WARP_ENDPOINT_IP)
                if r.length == TYPE1_LEN]
        log(f"\n  {TYPE1_LEN}-byte datagrams at the tap: "
            + ", ".join(f"dport={r.dport}" for r in sent))
        good = [r for r in sent if r.dport == WARP_ENDPOINT_PORT]
        bad = [r for r in sent if r.dport == swapped]
        check(bool(good), f"correct staging puts it on port "
              f"{WARP_ENDPOINT_PORT} (type1_dport_ok would be GREEN)")
        check(bool(bad), f"byte-swapped staging puts it on port {swapped} "
              f"(type1_dport_ok would be RED — the alarm fires)")
        log(f"\n=> type1_dport_ok distinguishes the two: "
            f"{WARP_ENDPOINT_PORT} vs {swapped}. It is not a check that "
            "passes regardless.")
    return 0 if (good and bad) else 1


def boot_lease_handshake(vice, L, priv, pub, peer_pub, tunnel_ip, iface,
                         lan_prefix: str, rng, *, swap_port: bool = False,
                         tag: str = "A") -> tuple[object, str, Tap, bool]:
    """boot -> 'I' -> real lease -> stage WARP -> 'H' -> ACTIVE.

    Returns (ResumingTransport, c64 ip, the tap covering the handshake,
    whether ACTIVE was reached). The tap is left OPEN for the caller.
    """
    tr = vice.tr
    if not wait_boot_ready(tr, L):
        check(False, f"[{tag}] boot_ready set", screen_text(tr))
        raise SystemExit(1)
    check(True, f"[{tag}] boot_ready set")

    log(f"=== [{tag}] Network init ('I' -> ip65 DHCP on the REAL LAN) ===")
    if not check(press_key(tr, "I"), f"[{tag}] 'I' consumed"):
        raise SystemExit(1)
    outcome, text = wait_net_initialized(tr, L, DHCP_BUDGET_S)
    if not check(outcome == "ok",
                 f"[{tag}] net_initialized=1 within {DHCP_BUDGET_S:.0f}s "
                 f"(outcome: {outcome})", text):
        raise SystemExit(1)

    ip = c64_ip(tr, L)
    log(f"  C64 lease: {ip}")
    check(ip.startswith(lan_prefix),
          f"[{tag}] lease {ip} is on the real LAN {lan_prefix}0/24",
          f"host {iface} is {iface_status(iface).get('inet')}, "
          f"gateway {default_gateway(iface)}")
    check(not ip.startswith(RIG_SUBNET_PREFIX),
          f"[{tag}] lease is NOT from the feth rig ({RIG_SUBNET_PREFIX}0/24) "
          "— VICE really is bridged onto the physical segment", ip)

    stage_warp_config(tr, L, priv, pub, peer_pub, tunnel_ip,
                      swap_port=swap_port)
    tr.resume()

    # Warp ON only now: ip65's DHCP retry budget is CPU-counted and warp
    # compresses it below a real OFFER's latency, but the X25519 that
    # follows is pure 6502 and needs every cycle it can get.
    tr.set_warp(True)
    check(tr.get_warp(), f"[{tag}] VICE warp enabled after network init")
    rt = ResumingTransport(tr)

    log(f"=== [{tag}] Resolving the peer's next hop before 'H' ===")
    warmed, probes = warm_arp_cache(vice.tr, L, rng, tag)
    check(warmed, f"[{tag}] ip65 resolved the next hop for "
          f"{WARP_ENDPOINT_IP} in {probes} probe(s)",
          "ip65 returns C=1 on a cold ARP cache; without this the FIRST "
          "'H' always fails after computing the whole Type-1.")

    log(f"=== [{tag}] Handshake with Cloudflare WARP "
        f"({WARP_ENDPOINT_IP}:{WARP_ENDPOINT_PORT}) ===")
    # ARP is in the filter on purpose: ip65's fail-fast next-hop resolution
    # (see press_h_until_sent) is only visible as an ARP request for the
    # gateway, and without it a failed first initiation looks like silence.
    tap = Tap(f"(udp and host {ip}) or (arp and host {ip})", iface=iface)
    tap.__enter__()
    t0 = time.monotonic()
    left, attempts, notes = press_h_until_sent(rt, vice.tr, L, tag)
    check(left, f"[{tag}] wg_state left IDLE (Type-1 built and sent) "
          f"after {attempts} initiation attempt(s)",
          "\n".join(notes) + "\n" + screen_text(vice.tr))
    check(attempts <= SEND_ATTEMPTS,
          f"[{tag}] the ARP-primed retry converged within "
          f"{SEND_ATTEMPTS} attempts", "\n".join(notes))
    gw = default_gateway(iface)
    arp_rows = [r for r in tap.raw if "ARP" in r]
    log(f"  [{tag}] ARP at the tap ({len(arp_rows)} rows), next hop {gw}:")
    for r in arp_rows[:6]:
        log(f"      {r}")

    # The wire is the only witness to WHERE the Type-1 went. #118: the
    # ip65 backend copied the big-endian ABI port cell raw into ip65's
    # little-endian one, so 2408 left as 26633 and Cloudflare never saw a
    # packet. Nothing else in this suite can tell that apart from "the
    # peer ignored us".
    time.sleep(3.0)
    t1 = [r for r in tap.udp(ip, WARP_ENDPOINT_IP) if r.length == TYPE1_LEN]
    check(bool(t1), f"[{tag}] a {TYPE1_LEN}-byte Type-1 left for "
          f"{WARP_ENDPOINT_IP} on the wire",
          f"all C64->WARP datagrams: {tap.udp(ip, WARP_ENDPOINT_IP)}\n"
          f"all C64 datagrams: {tap.udp(src=ip)}")
    check(bool(t1) and t1[0].dport == WARP_ENDPOINT_PORT,
          f"[{tag}] type1_dport_ok: Type-1 addressed to port "
          f"{WARP_ENDPOINT_PORT}",
          f"wire dport = {t1[0].dport if t1 else None} "
          f"(pre-#118 byte swap would read "
          f"{((WARP_ENDPOINT_PORT & 0xFF) << 8) | (WARP_ENDPOINT_PORT >> 8)})")
    local = int.from_bytes(rt.read_memory(L["wg_local_port"], 2), "little")
    check(bool(t1) and t1[0].sport == local,
          f"[{tag}] Type-1 left FROM the configured local port {local}",
          f"wire sport = {t1[0].sport if t1 else None}, "
          f"wg_local_port = {local}")

    active = ki.wait_for_state(rt, L["wg_state"], SESSION_ACTIVE, HS_BUDGET_S,
                               poll=1.0)
    secs = time.monotonic() - t0
    check(active, f"[{tag}] session ACTIVE against Cloudflare WARP "
          f"({secs:.0f}s under VICE warp)", screen_text(vice.tr))
    if not active:
        for line in tap.raw[-15:]:
            log(f"      tap: {line}")
    log(f"  handshake wall time: {secs:.1f}s")
    return rt, ip, tap, active


def hs_timestamp_gt(new: bytes, old: bytes) -> bool:
    """Strictly greater as ONE 96-bit big-endian integer.

    hs_timestamp is TAI64N: 8 big-endian seconds bytes then 4 big-endian
    nanosecond bytes, so the whole 12 bytes read as one big-endian integer
    orders exactly as TAI64N does. Equal stamps compare False.
    """
    if len(new) != 12 or len(old) != 12:
        raise ValueError(f"hs_timestamp must be 12 bytes, got "
                         f"{len(new)} / {len(old)}")
    return int.from_bytes(new, "big") > int.from_bytes(old, "big")


# ============================================================================
# main
# ============================================================================

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iface", default=BRIDGED_IFACE,
                    help="LAN interface VICE's pcap driver binds to")
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--stages", default="ABCD",
                    help="which stages to run, e.g. AB or ABD")
    ap.add_argument("--rekey", type=int, default=2,
                    help="Stage D: number of rekeys (0 skips)")
    ap.add_argument("--warp-profile", default=DEFAULT_WARP_PROFILE)
    ap.add_argument("--seed", type=int,
                    default=int(os.environ.get("TEST_SEED", "0")) or None)
    ap.add_argument("--prove-red", choices=("port", "mtu"), default=None,
                    help="deliberately break one thing to show the alarm")
    ap.add_argument("--measure-dns", action="store_true",
                    help="print host-side DNS reply sizes and exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose
    stages = args.stages.upper()

    # Stage D rekeys the session Stage A established, and lives inside the
    # same VICE instance, so "--stages CD" would silently run nothing for D
    # -- a no-op that reports success. Refuse instead of no-opping.
    if "D" in stages and args.rekey > 0 and not ("A" in stages or "B" in stages):
        raise SystemExit(
            "--stages %s: D rekeys the session A establishes and shares its "
            "VICE, so it cannot run without A. Use --stages ACD (A costs one "
            "handshake, about 8 minutes on this rig)." % stages)

    seed = args.seed if args.seed is not None else random.randint(1, 2**31 - 1)
    rng = random.Random(seed)
    log("test_warp_ip65_vice.py — ip65 vs Cloudflare WARP over BRIDGED VICE")
    log(f"Random seed: {seed} (reproduce with --seed {seed})")

    if args.prove_red == "mtu":
        # RED PROOF, no VICE needed: link the SAME sources without
        # WG_MTU1440 and show the structural pre-check refusing the build.
        log("=== --prove-red mtu: linking BACKEND=ip65 REU=0 (no "
            "WG_MTU1440) and re-running the pre-check ===")
        build_ip65(["REU=0", f"BUILD_DIR={os.path.basename(BUILD_RED)}"])
        Lr = load_labels(BUILD_RED)
        fingerprint("red (no WG_MTU1440)", os.path.join(BUILD_RED,
                                                        "wireguard.prg"), Lr)
        ok = check_mtu_admits(Lr, 1279)
        log(f"\n=> the mtu_admits_replies check is "
            f"{'GREEN (UNEXPECTED)' if ok else 'RED, as it must be'} "
            "on a tree built without WG_MTU1440.")
        return 1 if ok else 0

    if args.measure_dns:
        for name, qtype, band in DNS_QUERIES:
            n, tc = measure_dns_host(name, qtype)
            log(f"  {name:20s} qtype={qtype}  host reply {n} B  TC={int(tc)} "
                f"({band})")
        return 0

    # --- Preflight ------------------------------------------------------
    log(f"=== Bridged rig preflight on {args.iface} ===")
    log("  " + describe_bridged(args.iface))
    skip_if_bridged_rig_down(args.iface, args.vice_bin)
    check(True, f"bridged rig ready on {args.iface}")
    bad = selftest_classifier()
    check(not bad, "tcpdump classifier self-test (the fragment arm alarms)",
          "\n".join(bad))
    # The "dnsmasq is not serving the bridged interface" check answers with
    # an empty list when it passes, which is also what a BROKEN probe
    # answers — so prove the probe can see a live dnsmasq before believing
    # its silence. (It could not, until 2026-09-03: pgrep -af is Linux.)
    bad = selftest_dnsmasq_probe()
    check(not bad, "dnsmasq probe self-test (its empty answer is meaningful)",
          "\n".join(bad))
    # Same coincidence class: "no other VICE is on this NIC" is an empty
    # result, and a blind probe returns empty too. Prove it can see one.
    bad = selftest_conflict_probe(args.iface)
    check(not bad, "conflict probe self-test (it can see a decoy and names "
          "the worktree that owns it)", "\n".join(bad))
    check(args.iface not in dnsmasq_interfaces(),
          f"the rig's dnsmasq is NOT serving {args.iface} "
          f"(it is bound to {dnsmasq_interfaces()})")
    host_ip = iface_status(args.iface)["inet"]
    lan_prefix = host_ip.rsplit(".", 1)[0] + "."
    check(not lan_prefix.startswith(RIG_SUBNET_PREFIX),
          f"the bridged segment {lan_prefix}0/24 is not the feth rig's "
          f"{RIG_SUBNET_PREFIX}0/24", host_ip)

    priv, tunnel_ip, peer_pub_b64 = load_warp_profile(args.warp_profile)
    pub = derive_pubkey(priv)
    peer_pub = base64.b64decode(peer_pub_b64)
    check(peer_pub_b64 == WARP_PEER_PUB_B64,
          f"profile peer public key is Cloudflare's ({WARP_PEER_PUB_B64})",
          f"profile says {peer_pub_b64}")
    check(tunnel_ip == TUNNEL_IP, f"profile tunnel address is {TUNNEL_IP}",
          f"profile says {tunnel_ip}")
    log(f"  our WARP public key {base64.b64encode(pub).decode()[:12]}… "
        "(private key not logged)")

    if args.prove_red == "port":
        # Cheap alarm proof: reach net_udp_send directly instead of paying
        # a 301 s Type-1 first. Needs the rig, so it runs after preflight.
        log("\n=== --prove-red port: does type1_dport_ok actually fire? ===")
        L = load_labels(BUILD_A)
        assert_iface_free(args.iface)
        vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                       reu=False)
        vice.__enter__()
        try:
            assert_vice_bound_to(vice.proc, args.iface)
            rc = prove_red_port(vice, L, args.iface, rng)
        finally:
            vice.__exit__(None, None, None)
        passed = sum(1 for ok, _ in results if ok)
        log(f"\nResults: {passed}/{len(results)} passed")
        return rc

    # --- Host-side DNS baseline, measured BEFORE the C64 is asked -------
    dns_host: dict[str, tuple[int, bool]] = {}
    if "C" in stages:
        log("=== Host-side DNS baseline (this host's path, i.e. through the "
            "host's own WARP) ===")
        for name, qtype, band in DNS_QUERIES:
            n, tc = measure_dns_host(name, qtype)
            dns_host[name] = (n, tc)
            log(f"  {name:20s} {n:5d} B  TC={int(tc)}   ({band})")
        need = max((n for n, _ in dns_host.values()), default=0)
        check(need > 0, "host DNS baseline measured", str(dns_host))

    vices: list[EthVice] = []
    timings: list[tuple[str, float]] = []
    t_start = time.monotonic()
    try:
        # ================= Stage A / B =================
        if "A" in stages or "B" in stages:
            log("\n=== Stage A: build (BACKEND=ip65 REU=0 WG_MTU1440=1) ===")
            build_ip65(["REU=0", "WG_MTU1440=1"])
            assert_ip65_build()
            L = load_labels(BUILD_A)
            fingerprint("Stage A/B", os.path.join(BUILD_A, "wireguard.prg"), L)
            check_mtu_admits(L, 1279)

            assert_iface_free(args.iface)
            vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                           reu=False)
            vice.__enter__()
            vices.append(vice)
            argv = assert_vice_bound_to(vice.proc, args.iface)
            check(True, f"VICE launched with pcap bound to {args.iface}",
                  argv)

            t0 = time.monotonic()
            rt, ip, tap, active = boot_lease_handshake(
                vice, L, priv, pub, peer_pub, tunnel_ip, args.iface,
                lan_prefix, rng, tag="A")
            timings.append(("Stage A: boot+DHCP+handshake",
                            time.monotonic() - t0))

            # ---------------- Stage B ----------------
            if "B" in stages and active:
                log("\n=== Stage B: ping 1.1.1.1 through the tunnel ('P') ===")
                n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                if check(ki.press_key(rt, "P", timeout=20.0), "[B] 'P' consumed"):
                    deadline = time.monotonic() + PING_BUDGET_S
                    seen = False
                    while time.monotonic() < deadline:
                        if "PING REPLY OK" in screen_text(vice.tr):
                            seen = True
                            break
                        vice.tr.resume()
                        time.sleep(0.5)
                    check(seen, "[B] PING REPLY OK from 1.1.1.1 through the "
                          "WireGuard tunnel", screen_text(vice.tr)[-400:])
                    n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                    check(n_after > n_before,
                          f"[B] the ping put datagram(s) on the wire "
                          f"({n_before} -> {n_after} C64->WARP)")

                log("\n=== Stage B: chat message ===")
                suffix = "".join(rng.choice(string.ascii_uppercase +
                                            string.digits) for _ in range(12))
                msg = f"{suffix} WGC64"          # randomised body, fixed marker
                before = int.from_bytes(
                    rt.read_memory(L["tp_send_counter"], 2), "little")
                n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                sent = ki.send_message_dma(rt, msg, L, timeout=20.0)
                time.sleep(2.0)
                after = int.from_bytes(
                    rt.read_memory(L["tp_send_counter"], 2), "little")
                n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                check(sent, f"[B] chat message staged and sent ({msg!r})")
                check(after > before,
                      f"[B] tp_send_counter advanced {before} -> {after} "
                      "(no send error)")
                check(n_after > n_before,
                      f"[B] the message left as {n_after - n_before} "
                      "datagram(s) on the wire — one send, not a torn one")
                txt = screen_text(vice.tr)
                check("SEND FAILED" not in txt and "ERROR" not in txt,
                      "[B] no send error on screen", txt[-400:])
                check(tap.fragments() == 0,
                      f"[B] no IP fragments at the tap ({tap.fragments()})",
                      "\n".join(tap.frags[-5:]))

            # ---------------- Stage D ----------------
            if "D" in stages and args.rekey > 0 and active:
                log(f"\n=== Stage D: {args.rekey} rekeys (issue #87, "
                    "production peer) ===")
                ts_prev = bytes(rt.read_memory(L["hs_timestamp"], 12))
                log(f"  hs_timestamp[0] {ts_prev.hex()}")
                for i in range(1, args.rekey + 1):
                    # Re-resolve the next hop first. ki.rekey presses H
                    # once and has no retry, and ip65's ARP cache does age
                    # out -- a rekey that lands on a cold entry fails the
                    # send after computing the whole Type-1, so the flake
                    # would cost ~460 s to even observe. A few seconds here
                    # removes that class entirely.
                    warmed, probes = warm_arp_cache(vice.tr, L, rng,
                                                    f"D{i}")
                    check(warmed, f"[D] rekey {i}: next hop resolved in "
                          f"{probes} probe(s) before pressing H")
                    t0 = time.monotonic()
                    ok = ki.rekey(rt, L["wg_state"], SESSION_ACTIVE,
                                  timeout=HS_BUDGET_S)
                    secs = time.monotonic() - t0
                    timings.append((f"Stage D: rekey {i}", secs))
                    check(ok, f"[D] rekey {i}: left ACTIVE and returned to "
                          f"ACTIVE ({secs:.0f}s)", screen_text(vice.tr))
                    ts_new = bytes(rt.read_memory(L["hs_timestamp"], 12))
                    check(hs_timestamp_gt(ts_new, ts_prev),
                          f"[D] rekey {i}: hs_timestamp strictly increased "
                          "as a 96-bit big-endian integer",
                          f"prev {ts_prev.hex()}\nnew  {ts_new.hex()}")
                    log(f"  hs_timestamp[{i}] {ts_new.hex()}")
                    ts_prev = ts_new
                    if not ok:
                        break

            log(f"\n  Stage A/B/D wire totals: "
                f"{len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))} C64->WARP, "
                f"{len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))} WARP->C64, "
                f"{tap.fragments()} fragment rows")
            tap.__exit__(None, None, None)
            vice.tr.set_warp(False)
            vice.__exit__(None, None, None)
            vices.remove(vice)

        # ================= Stage C =================
        if "C" in stages:
            log("\n=== Stage C: rebuild MSG_PORT=53 BUILD_DIR=build_msgport53 ===")
            build_ip65(["REU=0", "WG_MTU1440=1", "MSG_PORT=53",
                        f"BUILD_DIR={os.path.basename(BUILD_C)}"])
            LC = load_labels(BUILD_C)
            prg_c = os.path.join(BUILD_C, "wireguard.prg")
            fingerprint("Stage C", prg_c, LC)
            need = max([n for n, _ in dns_host.values() if n > 0] or [1279])
            check_mtu_admits(LC, max(need, 1279))

            assert_iface_free(args.iface)
            vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                           reu=False, prg_path=prg_c)
            vice.__enter__()
            vices.append(vice)
            assert_vice_bound_to(vice.proc, args.iface)
            t0 = time.monotonic()
            rt, ip, tap, active = boot_lease_handshake(
                vice, LC, priv, pub, peer_pub, tunnel_ip, args.iface,
                lan_prefix, rng, tag="C")
            timings.append(("Stage C: boot+DHCP+handshake",
                            time.monotonic() - t0))

            dns_results: list[dict] = []
            if active:
                for name, qtype, band in DNS_QUERIES:
                    log(f"\n--- DNS {name} ({band}) ---")
                    txn = rng.randint(0, 0xFFFF)
                    # Advertise the largest reply this build can actually
                    # hold, derived from the labels. A hardcoded 1400 would
                    # make OUR OWN EDNS advertisement the binding limit and
                    # leave the interesting question unanswerable: a TC=1
                    # stub would then be indistinguishable between "1.1.1.1
                    # caps its UDP replies by policy" and "we asked for no
                    # more than 1400". Advertising MSG_TEXT_MAX means
                    # anything the resolver is willing to send fits by
                    # construction, so a reply in the 1280..MSG_TEXT_MAX
                    # band would DISPROVE a ~1280 policy cap, and its
                    # absence is evidence for one.
                    ednsbuf = ki.input_max_from_labels(LC)
                    question, wire = build_dns_query(name, qtype, txn,
                                                     bufsize=ednsbuf)
                    host_len, host_tc = dns_host.get(name, (-1, False))
                    log(f"  txn_id={txn} query wire {len(wire)} B; "
                        f"EDNS bufsize advertised {ednsbuf}; host "
                        f"baseline {host_len} B TC={int(host_tc)}")
                    n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                    # Baseline the REPLY direction too. Without this the
                    # per-query reply count is cumulative over the tap's
                    # whole lifetime, so the second query inherits the
                    # first one's replies and the reported number is
                    # quietly wrong (observed: github.com reported "3
                    # replies" for a single exchange). No assertion
                    # depended on it, but the figure goes in the report.
                    r_before = len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))
                    rt.write_memory(LC["msg_recv_len"], bytes(2))
                    rt.write_memory(LC["tp_payload_len"], bytes(2))
                    staged = stage_raw_dma(rt, wire, LC, timeout=20.0)
                    check(staged, f"[C] {name}: query staged and sent")

                    deadline = time.monotonic() + DNS_BUDGET_S
                    recv_len = 0
                    while time.monotonic() < deadline:
                        recv_len = int.from_bytes(
                            rt.read_memory(LC["msg_recv_len"], 2), "little")
                        if recv_len:
                            break
                        time.sleep(0.25)
                    n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                    if not check(recv_len > 0,
                                 f"[C] {name}: a reply reached the C64 "
                                 f"(msg_recv_len={recv_len})",
                                 screen_text(vice.tr)[-400:]):
                        continue

                    ptr = int.from_bytes(
                        rt.read_memory(LC["msg_recv_ptr"], 2), "little")
                    payload = bytes(rt.read_memory(ptr, min(recv_len, 1450)))
                    # A DNS header is 12 bytes. Without this, a runt reply
                    # would crash the run on payload[6] rather than fail
                    # the assertion it was meant to fail.
                    if not check(len(payload) >= 12,
                                 f"[C] {name}: reply is at least a DNS "
                                 f"header ({len(payload)} B)",
                                 payload.hex()):
                        continue
                    ip_hdr = bytes(rt.read_memory(LC["tp_packet"] + 16, 20))
                    udp_hdr = bytes(rt.read_memory(LC["tp_packet"] + 36, 8))
                    src_ip = ".".join(str(b) for b in ip_hdr[12:16])
                    dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
                    sport = (udp_hdr[0] << 8) | udp_hdr[1]
                    dport = (udp_hdr[2] << 8) | udp_hdr[3]
                    rtxn = (payload[0] << 8) | payload[1]
                    qr = bool(payload[2] & 0x80)
                    tc = bool(payload[2] & 0x02)
                    ancount = (payload[6] << 8) | payload[7]
                    echo_ok = payload[12:12 + len(question)] == question

                    check(src_ip == PING_TARGET_IP and sport == 53,
                          f"[C] {name}: inner IPv4 source is "
                          f"{PING_TARGET_IP}:53", f"got {src_ip}:{sport}")
                    check(dst_ip == TUNNEL_IP and dport == 53,
                          f"[C] {name}: inner IPv4 destination is "
                          f"{TUNNEL_IP}:53", f"got {dst_ip}:{dport}")
                    check(rtxn == txn,
                          f"[C] {name}: DNS transaction id matches ({txn})",
                          f"reply carried {rtxn}")
                    check(qr, f"[C] {name}: QR bit set (this is a response)")
                    check(echo_ok,
                          f"[C] {name}: the question section is echoed back",
                          f"sent {question.hex()}\ngot  "
                          f"{payload[12:12 + len(question)].hex()}")
                    # Length, cross-checked against an INDEPENDENT source:
                    # the inner UDP header's own length field, which the C64
                    # did not compute (Cloudflare's peer did) and which
                    # msg_recv_len is derived from separately. `recv_len > 0`
                    # was already asserted above, so re-testing it here
                    # would be a check that cannot fail.
                    udp_len = (udp_hdr[4] << 8) | udp_hdr[5]
                    check(udp_len - 8 == recv_len,
                          f"[C] {name}: reply length {recv_len} B agrees with "
                          f"the inner UDP header ({udp_len} - 8)",
                          f"msg_recv_len={recv_len}, inner UDP length="
                          f"{udp_len}; host baseline {host_len} B")
                    check(ancount >= 0,
                          f"[C] {name}: {recv_len} B received "
                          f"(host saw {host_len} B), TC={int(tc)}, "
                          f"ANCOUNT={ancount}")
                    # Datagram counts at the tap, per the standing rule: a
                    # torn send is two. The reply direction matters most
                    # here -- a >1280 B inner reply is precisely where the
                    # outer datagram would fragment if anything did.
                    n_reply = len(tap.udp(src=WARP_ENDPOINT_IP,
                                          dst=ip)) - r_before
                    check(n_after > n_before,
                          f"[C] {name}: the query left as "
                          f"{n_after - n_before} datagram(s) C64->WARP")
                    check(tap.fragments() == 0,
                          f"[C] {name}: no IP fragments at the tap "
                          f"({tap.fragments()})",
                          "\n".join(tap.frags[-5:]))
                    q_rec = {"name": name, "recv_len": recv_len,
                             "host_len": host_len, "tc": tc,
                             "ancount": ancount, "ednsbuf": ednsbuf,
                             "sent": n_after - n_before, "replies": n_reply}
                    dns_results.append(q_rec)
                    log(f"  RESULT {name}: C64 received {recv_len} B "
                        f"(TC={int(tc)}, ANCOUNT={ancount}); host baseline "
                        f"{host_len} B (TC={int(host_tc)}); "
                        f"{n_after - n_before} C64->WARP datagram(s)")
                    if host_len > 0 and recv_len > 1280 >= host_len:
                        log("  *** the C64's direct path carried a reply the "
                            "host's WARP path could not ***")

            if dns_results:
                biggest = max(r["recv_len"] for r in dns_results)
                ceiling = max(r["ednsbuf"] for r in dns_results)
                log("\n  === Stage C verdict on the >1280 B question ===")
                for r in dns_results:
                    log(f"    {r['name']:16s} C64 {r['recv_len']:5d} B "
                        f"TC={int(r['tc'])} ANCOUNT={r['ancount']:3d} | "
                        f"host {r['host_len']:5d} B | advertised "
                        f"{r['ednsbuf']} | {r['sent']} sent, "
                        f"{r['replies']} replies")
                if biggest > 1280:
                    log(f"    => a {biggest} B reply arrived WHOLE on the "
                        "C64's direct path: the ~1280 B ceiling seen on the "
                        "host path is NOT imposed on this path.")
                elif any(r["tc"] for r in dns_results):
                    log(f"    => nothing above 1280 B arrived, and the "
                        f"resolver set TC while we advertised {ceiling} B. "
                        "Our own EDNS buffer was NOT the binding limit, so "
                        "the ceiling is 1.1.1.1's own reply-size policy, "
                        "not an MTU on this path.")
                else:
                    log("    => nothing above 1280 B was requested "
                        "successfully; inconclusive.")

            log(f"\n  Stage C wire totals: "
                f"{len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))} C64->WARP, "
                f"{len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))} WARP->C64, "
                f"{tap.fragments()} fragment rows")
            tap.__exit__(None, None, None)
            vice.tr.set_warp(False)
            vice.__exit__(None, None, None)
            vices.remove(vice)
    finally:
        for v in list(vices):
            try:
                v.__exit__(None, None, None)
            except Exception as e:      # noqa: BLE001
                log(f"  cleanup: {e}")
        log("  cleanup: all VICE instances stopped")

    log("\n=== Wall time ===")
    for name, secs in timings:
        log(f"  {name:<36s} {secs:8.1f} s")
    passed = sum(1 for ok, _ in results if ok)
    failed = len(results) - passed
    log(f"\nResults: {passed}/{len(results)} passed, {failed} failed "
        f"({time.monotonic() - t_start:.0f}s, seed {seed})")
    for ok, label in results:
        if not ok:
            log(f"  FAILED: {label}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
