#!/usr/bin/env python3
"""test_ip65_rrnet_hw.py — ip65 / RR-Net on REAL HARDWARE, proven from the wire.

OPT-IN. Not in tools/run_regression.py: it needs a physical RR-Net cartridge,
a dedicated NIC and a rig script run under sudo. Exit 0 PASS / 1 FAIL /
77 SKIP (rig absent or device lock busy).

WHY THIS SUITE EXISTS
=====================

Every ip65 result this project has produced has been on emulation. The
bridged-VICE Cloudflare WARP handshake, the MTU-1440 work, the #118 port
fix, all of it — and one note in our records claimed an ip65 fix was
"proven on hardware" when it was the Ethernet VICE rig. This is the first
run against a real CS8900a.

    [ U64E + real RR-Net (CS8900a, 10baseT) ]
                 |  cable, no switch, two stations
    [ Mac USB-Ethernet NIC en4 = 10.0.66.1/24 ]
                 |
        dnsmasq (DHCP) + this suite's in-process WireGuard responder

The addressing above is read from tools/rig-up-rrnet-macos.sh at import,
not copied: that subnet moved off 10.0.65.0/24 (which the feth rig owns)
mid-development, and a second copy of it here would have gone stale
without failing.

Note what the topology means: the ip65 data path never touches the UCI
firmware. $DF1B-$DF1F is not in it. The device's firmware version, the
$16 chunked-write spike, the multi-block SOCKET_READ reassembly — none of
that is exercised here. This is an independent network stack, and that is
the point: it is the only backend whose correctness has never been
observed outside an emulator.

THE THING THIS RIG CAN DO THAT NO PREVIOUS ONE COULD
====================================================

A direct cable with exactly two stations makes a packet capture COMPLETE.
There is no switch to hide unicast, no third party to add noise, and
nothing on the segment we did not put there. So Stage W asserts from the
WIRE rather than from device memory:

  * the DHCP exchange really happened (DISCOVER/OFFER/REQUEST/ACK, from
    the C64's MAC, offering the address the C64 later reports);
  * the handshake frames are well-formed WireGuard — a 148-byte type 1
    out, a 92-byte type 2 back, in that order;
  * transport packets are type 4 in both directions;
  * THE PLAINTEXT WE SENT IS ABSENT FROM EVERY CAPTURED FRAME;
  * the same plaintext, sent twice, produces different ciphertext.

That last pair is a materially stronger claim than a DMA read can make,
and it is why this run is worth the rig.

VERDICTS ARE NOT DECIDED HERE
=============================

Every pass/fail about the wire, the lease, the MAC, the handshake and the
transport comes from tools/ip65_hw_checks.py, which is device-free and
has its own unit suite. This file gathers bytes and orchestrates; it does
not decide. That split is not bureaucracy — a hardware tool's checkers
cannot be red/greened without a device, so they ship unproven, and this
project has already found a tool cited for two days as a control whose
verification function was defined and never called.

An earlier version of this file carried its own decoder and leak search.
It is deleted, not deprecated. Four cases were MEASURED where it returned
GREEN on a capture that contained the plaintext:

    plaintext torn across two IP fragments      -> reported absent
    plaintext byte-reversed                     -> reported absent
    capture taken without -s 0                  -> reported absent
    cfg_mac == ip65 default 00:80:10:00:51:00   -> accepted

The third is the one that matters operationally: sudo is not available to
this process, so the capture is started by hand in --capture external
mode, and that is exactly where a missing -s0 slips in. A truncated
capture makes "the plaintext is absent from every frame" structurally
true and completely meaningless. The library refuses such a file instead
of searching it.

A NULL WITH NO CONTROL IS NOT A RESULT
======================================

Absence is still never claimed on its own:

  1. ``selftest_library()`` feeds the IMPORTED checker a capture whose
     payload IS the secret and requires a FAIL, a clean one and requires
     a PASS, an empty needle set and an empty capture and requires both
     to fail. It also proves check_c64_originated rejects a capture
     holding only the Mac's own frames — a powered-off C64 must not pass.
     If any of that is wrong the run stops before the device is touched.
  2. THE LIVE CONTROL. After the tunnel exchange the host sends a
     CLEARTEXT UDP datagram to the C64 carrying a sentinel of the same
     alphabet and length as the secrets, on a port nothing listens to.
     The wire stage asserts the sentinel IS found before it will report
     the secrets as absent; without that hit the absence result is
     recorded INCONCLUSIVE, not green.

THERE IS NO $DE00 CARTRIDGE-PRESENCE CHECK, AND THERE MUST NOT BE
================================================================

An earlier draft read $DE00 over DMA and required it to be non-zero.
That check cannot work: on Cartridge Preference = Auto it reads zeros,
after a run_prg DMA load it reads zeros, with no cartridge at all it
reads zeros. But the reason to delete it is stronger than an ambiguity,
and it is MEASURED: from the host, that window IS OPEN BUS. It does not
reflect writes (wrote 5a a5 3c c3…, read back 92 92 92…), and it does not
even agree with ITSELF between consecutive reads in one session with
nothing running — f7 f7 f7…, then 00 8d 8d 8d…, then f0 f0 f0…, while a
known RAM address at $0340 round-trips exactly. Across three observers
the reported values are 0a, 3c 00 00…, cc, 92, f7, 8d and f0: seven
observations, no two agreeing, one floating bus.

So a host-side check on $DE00 is not merely ambiguous, it is
NON-DETERMINISTIC — it would pass or fail at random and, over enough
runs, do both. (Conditions: U64E 601A96, fw 4011c97c / fpga 125, Auto, no
PRG, BASIC prompt, cartridge present with link up; n=1 write test, n=4
reads.) An earlier version of this file asserted "a working cartridge
reads $0A $0A $0A"; that is FALSE and is recorded here so nobody builds
on it.

The only valid presence check runs on the 6510 — which is what the
bench-health control is: "INIT DRIVER: OK" is the cs8900a EISA probe at
PP $0000 answering ($630E), executed by the CPU on the real bus.

RANDOMISED PER RUN
==================

The C64 static keypair, both transport payloads and the cleartext
sentinel, all drawn from a seeded stream. The seed is logged once and
replays with --seed.

WHAT WE DO NOT ASSUME
=====================

* NOT UCI timings. The user measured cartridge-port I/O throttling this
  path to about 1.7x from 1 MHz to 48 MHz, against the 14.5x-51.7x the
  UCI backend sees. Every budget here is generous and every duration is
  MEASURED AND REPORTED, so the next run has numbers instead of guesses.
* NOT the reason test_warp_live.py::_net_init_ip65 gives for running 'I'
  at 1 MHz. Its comment (:1697-1703) says ip65's DHCP and ARP "time out
  with CPU-counted delay loops calibrated for a 1 MHz 6510". THAT IS
  WRONG, and this suite does not repeat it. Both bound on ``timer_read``,
  i.e. the jiffy, i.e. REAL TIME: ip65/ip65/dhcp.s:147-161 reads the
  timer's high byte and spins until it changes ("this will tick over
  after about 1/4 of a second"), and ip65/ip65/arp.s imports and uses the
  same call. Raising the CPU clock does not shorten any of those waits.

  The real unknown is a different one, and it is the reason CPU speed is
  a declared axis here rather than a constant: whether the U64 times
  CS8900a register cycles at $DE00-$DE0F correctly when the 6510 runs at
  48 MHz. Nobody has measured that. Doing everything at 1 MHz to be safe
  would mean reporting "ip65 validated on hardware" while never once
  testing the speed every live tool defaults to — so --speeds runs the
  cheap I/O-only control at both clocks and says which held.
* NOT that the first 'H' will send. ip65 does not queue a datagram whose
  next-hop MAC it has not got: it emits the ARP request and returns C=1,
  which surfaces as HANDSHAKE SEND FAILED. press_h_until_sent retries.

MAC ADDRESSES: WHY set_cs8900a_mac IS THE WRONG TOOL HERE
=========================================================

c64_test_harness.ethernet.set_cs8900a_mac programs the chip's IA
registers at PacketPage $0158 directly. Under VICE that sticks. On this
rig it does not, and the reason is in ip65/drivers/cs8900a.s: the
driver's own ``reset`` path WRITES the IA registers from its internal
``mac`` table every time eth_init runs, which is on every 'I'. Anything
we poke into $0158 before boot is overwritten a second later.

Worse, poking $DE02/$DE04 while the C64 is running is a live race: those
are the PPPtr/PPData registers ip65 is itself using, and a DMA write
between ip65's own pointer set and data read corrupts whatever operation
was in flight, with no error anywhere.

So this suite does it the other way round:

  --mac observe   (default) read the MAC ip65 actually adopted, from
                  cfg_mac in the blob's own variable table, and assert
                  the SAME six bytes are the ethernet source address of
                  the DHCP frames on the wire. That is a memory-versus-
                  wire agreement check, which is stronger than a
                  read-back of a register we just wrote.
  --mac AA:BB:..  additionally patch the driver's ``mac`` table in RAM
                  before 'I', so eth_init's reset path programs OUR
                  address. Best effort and reported as such: on an RR-Net
                  MK3 the init path reads the card's EEPROM and
                  overwrites that table (cs8900a.s ``copy``), in which
                  case the patch is discarded. The suite reports which
                  happened; the wire agreement assertion holds either way.
                  This particular cartridge is measured at ip65's built-in
                  00:0e:3a:64:64:64, which means the EEPROM path does NOT
                  fire here and the patch should take — but the rig also
                  pins a static DHCP lease to that address, so changing it
                  drops the C64 onto a pool address as a side effect.

Usage::

    # 1. bring the rig up (needs sudo, once per session)
    sudo bash tools/rig-up-rrnet-macos.sh en4
    # 2. start the capture (needs sudo; --capture auto does it for you
    #    when sudo is passwordless, otherwise run this yourself)
    sudo tcpdump -i en4 -n -s0 -U -w /tmp/rrnet.pcap
    # 3. run
    python3 tools/test_ip65_rrnet_hw.py --capture external

Exit codes: 0 PASS / 1 FAIL / 77 SKIP.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import random
import re
import socket
import string
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, dump_screen, probe_u64,
)
from c64_test_harness.execute import run_prg_via_sys  # noqa: E402
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz,
)

import ip65_hw_checks as hw  # noqa: E402
import wg_c64_input as ki  # noqa: E402
from wg_responder.responder import WireGuardResponder  # noqa: E402

log = logging.getLogger("ip65_hw")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# --- the rig -------------------------------------------------------------
#
# tools/rig-up-rrnet-macos.sh is the SINGLE SOURCE OF TRUTH for the segment's
# addressing, and it is read here rather than copied. That is not tidiness:
# the script's subnet moved from 10.0.65.0/24 to 10.0.66.0/24 while this file
# was being written, to stop it colliding with the feth rig's 10.0.65.1. A
# suite carrying its own copy of that constant would have kept preflighting a
# subnet nobody serves, reported "rig down", and sent someone to debug a
# cable. Anything the script stops defining raises here instead of silently
# falling back to a stale value.
DEFAULT_IFACE = os.environ.get("RRNET_IFACE", "en4")
RIG_SCRIPT = PROJECT_ROOT / "tools" / "rig-up-rrnet-macos.sh"


def _rig_const(name: str) -> str:
    """Read a top-level `NAME=value` assignment out of the rig script."""
    try:
        text = RIG_SCRIPT.read_text()
    except OSError as exc:
        raise SystemExit(f"FATAL: cannot read {RIG_SCRIPT}: {exc}")
    m = re.search(rf"^{name}=([^\s#]+)\s*$", text, re.M)
    if not m:
        raise SystemExit(
            f"FATAL: {RIG_SCRIPT} no longer defines {name}=. This suite reads "
            f"the segment's addressing from the rig script so the two cannot "
            f"drift apart; update both together.")
    return m.group(1)


HOST_IP = _rig_const("HOST_IP")                     # the Mac / WireGuard peer
RIG_SUBNET_PREFIX = HOST_IP.rsplit(".", 1)[0] + "."
# The rig pins the C64 to a static lease keyed on ip65's default MAC
# (00:0e:3a:64:64:64 — the OUI of Cirrus Logic plus the __C64__ suffix baked
# into ip65/drivers/cs8900a.s). Its presence is itself a fact about this
# cartridge: it means the driver's `reset` path programs the chip from that
# table, i.e. this is NOT an RR-Net MK3 whose EEPROM would override it.
C64_MAC_PINNED = _rig_const("C64_MAC")
C64_IP_PINNED = _rig_const("C64_IP")
DNSMASQ_PIDFILE = _rig_const("PIDFILE")
DNSMASQ_LEASEFILE = _rig_const("LEASEFILE")
DNSMASQ_LOGFILE = _rig_const("LOGFILE")
DEFAULT_PCAP = "/tmp/rrnet.pcap"

DEFAULT_HOST = os.environ.get("U64_HOST", "10.43.23.81")

# WireGuard. The C64 both listens and sends on 51820 (src/constants.inc
# wg_default_port, latched into wg_local_port by src/boot.s), so the
# responder binds the same port on the host side.
WG_PORT = 51820
TUNNEL_IP = "172.16.0.2"          # the C64's inner address
SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2
TYPE1_LEN, TYPE2_LEN = 148, 92
MSG_TYPE_INITIATION, MSG_TYPE_RESPONSE, MSG_TYPE_TRANSPORT = 1, 2, 4

# A port with no ip65 listener: the cleartext control datagram must reach
# the wire and be ignored by the C64 (ip65 registers exactly one listener,
# on 51820, and udp_process drops everything else).
CONTROL_PORT = 9

# ip65 blob variable table (ip65-build/ip65_stub.s): 2-byte address each,
# starting at blob base + 30.
BLOB_VAR_CFG_MAC = 30
BLOB_VAR_CFG_IP = 32
BLOB_VAR_CFG_NETMASK = 34
BLOB_VAR_CFG_GATEWAY = 36

# CS8900a driver descriptor (ip65/drivers/cs8900a.s): a 3-byte "eth"
# signature, a 1-byte API version, then the 6-byte MAC.
DRIVER_SIGNATURE = b"\x65\x74\x68\x01"
DRIVER_MAC_OFFSET = len(DRIVER_SIGNATURE)

# Budgets. Deliberately generous: cartridge-port I/O is measured at only
# ~1.7x from 1 MHz to 48 MHz on this path, so UCI-derived numbers do not
# transfer. Every one of these is reported as a MEASURED duration too.
BOOT_BUDGET_S = float(os.environ.get("RRNET_BOOT_BUDGET_S", "90"))
NET_INIT_BUDGET_S = float(os.environ.get("RRNET_NET_INIT_BUDGET_S", "180"))
# NOTE: there is deliberately no flat HS_BUDGET_S constant. See
# handshake_budget(), which DERIVES it from the clock; a single inherited
# number is how a slow-but-working handshake becomes a false FAIL.
TRANSPORT_BUDGET_S = float(os.environ.get("RRNET_TRANSPORT_BUDGET_S", "120"))
SEND_ATTEMPTS = int(os.environ.get("RRNET_SEND_ATTEMPTS", "3"))
TURBO_SETTLE_S = 3.0
LOCK_TIMEOUT_S = float(os.environ.get("RRNET_LOCK_TIMEOUT_S", "300"))

SEND_FAILED_NEEDLE = "HANDSHAKE SEND FAILED"       # src/wg/strings.s

REQUIRED_LABELS = (
    "boot_ready", "net_initialized", "wg_state", "cfg_static_priv",
    "cfg_static_pub", "cfg_peer_pub", "cfg_preshared_key",
    "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port", "tunnel_ip",
    "ping_target_ip", "tai64n_base_time", "hs_timestamp",
    "ip65_blob_start", "ip_packet_buf", "ip_pkt_len", "msg_input_len",
    "msg_recv_ptr", "msg_recv_len", "msg_port", "tp_recv_counter",
    # The byte that says WHICH step failed. Without it a Stage A timeout is
    # indistinguishable between "the cartridge is not on the bus" ($41) and
    # "dnsmasq did not answer" ($42) — two failures with completely
    # different owners, at the same 180-second timeout.
    "net_last_error", "ip65_recv_dropped", "ip65_send_attempts",
    # ip65's net_udp_listen READS this cell and ignores A/X, unlike the UCI
    # adapter where A/X is the ABI. Asserting it turns "we avoided a known
    # false pass by construction" into "we assert we avoided it".
    "wg_local_port",
)

#: Wire port ip65 must be listening on after 'I' (src/constants.inc
#: wg_default_port, latched by src/boot.s:401-406 before net_udp_listen).
EXPECTED_LOCAL_PORT = 51820

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

#: The wire assertions. THESE ARE THE CLAIM OF THE RUN — everything a DMA
#: read can tell us is available without a capture, and the reason this rig
#: exists is the ones below. So a run that SKIPPED any of them has not
#: evaluated its own headline, and must not exit 0.
#:
#: The path that made this urgent: --capture auto, sudo wants a password,
#: fall back to external, file absent, "continuing WITHOUT a capture", all
#: six recorded SKIP, exit 0. The only machine-readable output said PASS
#: about "the plaintext we sent is absent from every captured frame" when
#: nothing had been looked at. Same for --capture off, for a pcap the
#: decoder refuses (the missing -s0 case), and for an empty window.
WIRE_CHECKS = (
    "the capture brackets this run's events",
    "frames on the cable came FROM the C64, not just from the Mac",
    "the C64's MAC is on the wire",
    "the handshake completed at both ends",
    "CONTROL: the cleartext sentinel IS found on the wire",
    "no plaintext appears anywhere in the capture",
    "identical plaintext produced different ciphertext",
)
results: list[tuple[str, str, str]] = []       # (status, label, detail)
VERBOSE = False


def check(ok: bool, label: str, detail: str = "") -> bool:
    """Record a PASS/FAIL. Returns *ok* so it can gate a following step."""
    status = PASS if ok else FAIL
    results.append((status, label, str(detail)))
    log.info("  %s  %s", status, label)
    if detail and (not ok or VERBOSE):
        for line in str(detail).splitlines():
            log.info("        %s", line)
    return bool(ok)


def verdict(v, label: str) -> bool:
    """Record an ip65_hw_checks.Verdict as this suite's PASS/FAIL.

    Verdict logic lives in tools/ip65_hw_checks.py and this suite only
    orchestrates: it gathers bytes off the wire and out of the C64 and
    hands them over. Two checkers, one tested and one not, is the exact
    shape this review has been eliminating, so nothing here re-decides
    anything the library has decided.
    """
    detail = v.reason
    if v.evidence:
        detail += "\n" + "\n".join(f"{k}: {val}"
                                    for k, val in sorted(v.evidence.items()))
    # INCONCLUSIVE IS NOT FAILURE, and for the leak check the difference is
    # the whole message. Rendering it as FAIL puts
    # "FAIL  no plaintext appears anywhere in the capture" on the summary
    # line, which an operator reads as PLAINTEXT ON THE CABLE — the exact
    # opposite of what happened, which is that nothing could be determined.
    # It still must not be green: skipped() is non-evidence and, for a wire
    # check, blocks a zero exit (see WIRE_CHECKS).
    if getattr(v, "inconclusive", False):
        skipped(label, detail)
        return False
    return check(bool(v.ok), label, detail)


def skipped(label: str, why: str) -> None:
    """Record a check that was NOT performed.

    Kept distinct from PASS on purpose. A skipped wire assertion is the
    single most dangerous thing this suite could round up: the whole
    claim of the run is "we watched the wire", and a capture that never
    started must never be summarised as agreement.
    """
    results.append((SKIP, label, why))
    log.warning("  %s  %s — %s", SKIP, label, why)


# ==========================================================================
# pcap reading — classic libpcap, EN10MB, no dependencies
# ==========================================================================

LINKTYPE_EN10MB = 1

# NOTE: this file used to carry its own Frame/read_pcap/frames_containing/
# encode_needles decoder and leak search. They are GONE, not deprecated.
# rg-ip65's tools/ip65_hw_checks.py measured four cases where the local
# version returned GREEN on a capture that contained the plaintext —
# plaintext torn across two IP fragments, plaintext byte-reversed, a
# capture taken without -s0, and ip65's shipped cfg_mac default — so
# keeping both would have left one tested leak-checker and one untested
# one in the same repo. Only the synthetic-capture BUILDERS survive here,
# and only as test fixtures for the library.


def _synthetic_pcap(frames: list[bytes]) -> bytes:
    """A classic little-endian EN10MB pcap carrying *frames*, for selftests."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                65535, LINKTYPE_EN10MB))
    for i, raw in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(raw), len(raw))
        out += raw
    return bytes(out)


def _synthetic_udp(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str,
                   sport: int, dport: int, payload: bytes) -> bytes:
    """A minimal ethernet/IPv4/UDP frame, for selftests and the wire control."""
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = (bytes([0x45, 0x00]) + struct.pack(">H", total)
          + b"\x00\x00\x00\x00" + bytes([64, 17]) + b"\x00\x00"
          + bytes(int(o) for o in src_ip.split("."))
          + bytes(int(o) for o in dst_ip.split(".")))
    return dst_mac + src_mac + b"\x08\x00" + ip + udp


# NOTE: this file briefly carried a wire_forms() helper that supplied the
# shifted-PETSCII form (0x41-0x5A -> 0xC1-0xDA) as an extra needle, because
# ip65_hw_checks.petscii_form only folded lowercase and _search_forms
# skipped any form equal to the exact one — so for our uppercase payload
# alphabet the petscii branch was dead and a shifted leak read as clean
# (measured: cfd5d4d3... reported "no plaintext in 1 reassembled
# datagrams"). rg-ip65 has since added petscii_shifted_form to
# _search_forms, verified here against the same capture, so the
# compensation is deleted rather than left to report every leak twice.


def selftest_library() -> list[str]:
    """Prove the IMPORTED checker fires before we trust its silence.

    The verdicts are rg-ip65's, but an absence result from an instrument
    nobody watched fail is not evidence, so this feeds theirs captures
    whose answers are known. It has already earned its place twice: it
    caught `check_plaintext_absent` gaining a required `c64_mac` argument
    and the shifted-PETSCII gap being closed, both between one run of this
    file and the next, and stopped the suite instead of letting it call a
    changed API against hardware.
    """
    bad: list[str] = []
    c64, mac = b"\x00\x0e\x3a\x64\x64\x64", b"\xc0\x56\x27\xb1\x16\x38"
    secret = b"THISISTHESECRET42"
    shifted = bytes((b + 0x80) if 0x41 <= b <= 0x5A else b for b in secret)

    def cap(payload: bytes, src: bytes = c64):
        return hw.parse_pcap(_synthetic_pcap([
            _synthetic_udp(src, mac, "10.0.66.200", HOST_IP, WG_PORT,
                           WG_PORT,
                           bytes([MSG_TYPE_TRANSPORT]) + bytes(15) + payload),
        ]))

    cases = [
        ("a payload that IS the secret", cap(secret), False),
        ("the secret SHIFTED into PETSCII $C1-$DA", cap(shifted), False),
        ("the secret BYTE-REVERSED", cap(secret[::-1]), False),
        ("a clean payload", cap(b"\xAA" * 40), True),
        ("a capture holding only the MAC's frames", cap(b"\xAA" * 40, mac),
         False),
    ]
    for what, frames, want_ok in cases:
        v = hw.check_plaintext_absent(frames, {"secret": secret},
                                      c64_mac=c64)
        if bool(v.ok) != want_ok:
            bad.append(f"check_plaintext_absent returned ok={v.ok} for "
                       f"{what} (expected {want_ok}): {v.reason}")
    if hw.check_plaintext_absent(cap(b"\xAA" * 40), {}, c64_mac=c64).ok:
        bad.append("check_plaintext_absent PASSED with no needles supplied; "
                   "a leak check with nothing to find always passes")
    if hw.check_plaintext_absent([], {"secret": secret}, c64_mac=c64).ok:
        bad.append("check_plaintext_absent PASSED on an EMPTY capture")
    # The CONTROL must key on findings, never on `not ok`: a capture with
    # a silent C64 and NO sentinel returns ok=False with findings=[], and
    # reading that as "the sentinel was found" would unlock the absence
    # checks on the emptiest corpus available.
    quiet = hw.check_plaintext_absent(cap(b"\xAA" * 40, mac),
                                      {"sentinel": b"NOTPRESENTANYWHERE"},
                                      c64_mac=c64)
    if quiet.ok:
        bad.append("a silent-C64 capture with no sentinel reported ok=True")
    if quiet.evidence.get("findings"):
        bad.append(f"check_plaintext_absent reported findings for a needle "
                   f"that is not in the capture: "
                   f"{quiet.evidence.get('findings')}")
    v = hw.check_c64_originated(cap(b"\xAA" * 40), c64, mac, min_frames=1)
    if not v.ok:
        bad.append(f"check_c64_originated failed on a frame that IS from "
                   f"the C64: {v.reason}")
    v = hw.check_c64_originated(cap(b"\xAA" * 40, mac), c64, mac,
                                min_frames=1)
    if v.ok:
        bad.append("check_c64_originated PASSED on a capture containing only "
                   "the Mac's own frames — a powered-off C64 would pass")
    return bad


# ==========================================================================
# Rig preflight — host side, no device, no lock
# ==========================================================================

def iface_state(iface: str) -> dict:
    p = subprocess.run(["ifconfig", iface], capture_output=True, text=True)
    if p.returncode != 0:
        return {"exists": False}
    text = p.stdout
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", text)
    media = re.search(r"media: ([^\n]+)", text)
    return {
        "exists": True,
        "inet": m.group(1) if m else None,
        "active": "status: active" in text,
        "media": media.group(1).strip() if media else "",
        "ether": (re.search(r"\bether ([0-9a-f:]{17})", text).group(1)
                  if re.search(r"\bether ([0-9a-f:]{17})", text) else None),
    }


def rig_problems(iface: str) -> list[str]:
    """Why the rig is not usable, or [] if it is."""
    bad = []
    st = iface_state(iface)
    if not st.get("exists"):
        return [f"no such interface: {iface}"]
    if not st.get("active"):
        bad.append(f"{iface} is not 'status: active' — cable unplugged, or "
                   f"the C64 is off (a CS8900a only lights the link when the "
                   f"cartridge has power)")
    if st.get("inet") != HOST_IP:
        bad.append(f"{iface} holds {st.get('inet')}, expected {HOST_IP} — run "
                   f"`sudo bash tools/rig-up-rrnet-macos.sh {iface}`")
    if st.get("media") and "10baseT" not in st["media"]:
        bad.append(f"{iface} negotiated '{st['media']}', not 10baseT — an "
                   f"RR-Net (CS8900a) is 10 Mbps only, so this is probably "
                   f"the wrong NIC")
    if not os.path.exists(DNSMASQ_PIDFILE):
        bad.append(f"no {DNSMASQ_PIDFILE} — dnsmasq is not serving DHCP on "
                   f"this segment, and src/boot.s do_net_init RETURNS on a "
                   f"DHCP failure (there is no static-IP path)")
    else:
        try:
            pid = int(open(DNSMASQ_PIDFILE).read().strip())
            os.kill(pid, 0)
        except (ValueError, ProcessLookupError, PermissionError, OSError) as e:
            if not isinstance(e, PermissionError):
                bad.append(f"{DNSMASQ_PIDFILE} exists but the process is gone "
                           f"({e!r}) — a stale pidfile, rig is down")
    return bad


def selftest_rig_probe(iface: str) -> list[str]:
    """Prove rig_problems() can actually say no.

    Its answer for a healthy rig is an EMPTY LIST, and an empty list is
    also what a probe returns when it is silently broken — the exact
    shape that made this project's dnsmasq check vacuous. So: feed it an
    interface that certainly does not exist and require a complaint.
    """
    fake = "en_nonexistent_zz"
    if not rig_problems(fake):
        return [f"rig_problems({fake!r}) reported no problems for an "
                f"interface that does not exist — its empty list is not "
                f"evidence of a healthy rig"]
    return []


def dhcp_lease_for(mac: bytes) -> Optional[str]:
    """The IP dnsmasq leased to *mac*, from its leasefile, or None."""
    want = ":".join(f"{b:02x}" for b in mac)
    try:
        for line in open(DNSMASQ_LEASEFILE):
            parts = line.split()
            if len(parts) >= 3 and parts[1].lower() == want:
                return parts[2]
    except FileNotFoundError:
        return None
    return None


# ==========================================================================
# Packet capture
# ==========================================================================

class Capture:
    """The tcpdump on the segment, however it got started.

    Three modes, and the difference matters for what may be CLAIMED:

      auto      start it here with `sudo -n`. Works only where sudo does
                not want a password.
      external  someone else started it (the usual case on this bench —
                sudo prompts). We assert the file exists and GROWS across
                the run rather than trusting that it is the right one.
      off       no capture. Every wire assertion is recorded SKIP, never
                PASS.
    """

    def __init__(self, mode: str, iface: str, path: str):
        self.mode = mode
        self.iface = iface
        self.path = path
        self.proc: Optional[subprocess.Popen] = None
        self.started_size: Optional[int] = None
        #: Wall-clock at which THIS run's events begin. Frames older than
        #: this are a previous session's and are excluded — see stop().
        self.t_start: Optional[float] = None
        self.t_end: Optional[float] = None
        self.note = ""

    @property
    def command(self) -> str:
        return (f"sudo tcpdump -i {self.iface} -n -s0 -U -w {self.path}")

    def start(self) -> bool:
        if self.mode == "off":
            self.note = "capture disabled (--capture off)"
            return False
        if self.mode == "auto":
            if subprocess.run(["sudo", "-n", "true"],
                              capture_output=True).returncode != 0:
                self.note = ("sudo needs a password, so this process cannot "
                             "start tcpdump; falling back to --capture "
                             "external")
                log.warning("%s", self.note)
                self.mode = "external"
            else:
                try:
                    os.path.exists(self.path) and os.unlink(self.path)
                except OSError:
                    pass
                self.proc = subprocess.Popen(
                    ["sudo", "-n", "tcpdump", "-i", self.iface, "-n", "-s0",
                     "-U", "-w", self.path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                time.sleep(2.0)          # let it open the file and attach
                if self.proc.poll() is not None:
                    err = (self.proc.stderr.read() or b"").decode(errors="replace")
                    self.note = f"tcpdump exited immediately: {err.strip()}"
                    log.error("%s", self.note)
                    self.proc = None
                    return False
                self.note = f"started by this process: {self.command}"
                log.info("capture %s", self.note)
        if self.mode == "external":
            if not os.path.exists(self.path):
                self.note = (f"{self.path} does not exist — start the capture "
                             f"first:\n    {self.command}")
                log.error("%s", self.note)
                return False
            self.note = f"external capture at {self.path}"
        self.started_size = os.path.getsize(self.path)
        # THE BRACKET. In --capture external (the mode we actually use,
        # because sudo is blocked) the file is NOT ours and may already
        # hold a previous session's traffic; nothing truncates it. Parsing
        # the whole file would then score an earlier run's frames as this
        # run's evidence — including, in the worst case, an earlier run's
        # successful handshake. So the run's start time is recorded here
        # and every frame is filtered against it in stop().
        self.t_start = time.time()
        # When the CAPTURE started, which is NOT when the run started. On
        # this rig tcpdump is hand-started (sudo is unavailable to this
        # process) and has been running for minutes, so every lead-in frame
        # legitimately predates the run. Feeding the run's start time to a
        # bracket check would fire "capture-started-before-the-run" on a
        # perfectly good capture. The tap's own start time is the honest
        # reference; the run window is a separate thing, used to choose the
        # SEARCH CORPUS, not to judge the capture.
        self.capture_started_at = self._tcpdump_started_at() or self.t_start
        if self.started_size > 24:
            log.warning("%s already holds %d bytes of capture. Frames older "
                        "than now (%.3f) will be EXCLUDED — this run is "
                        "scored only on what follows.", self.path,
                        self.started_size, self.t_start)
        return True

    def _tcpdump_started_at(self) -> Optional[float]:
        """Epoch seconds at which the tcpdump writing our pcap started."""
        try:
            pids = subprocess.run(["pgrep", "-f", f"tcpdump.*{self.path}"],
                                  capture_output=True, text=True).stdout.split()
            if not pids:
                return None
            out = subprocess.run(["ps", "-o", "lstart=", "-p", pids[0]],
                                 capture_output=True, text=True).stdout.strip()
            if not out:
                return None
            import datetime
            started = datetime.datetime.strptime(out, "%a %b %d %H:%M:%S %Y")
            log.info("tcpdump (pid %s) started at %s", pids[0], out)
            return started.timestamp()
        except Exception as exc:                              # noqa: BLE001
            log.warning("could not determine tcpdump start time: %s", exc)
            return None

    def stop(self) -> Optional[str]:
        """Flush and return the pcap path, or None if there is nothing usable."""
        self.t_end = time.time()
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:                 # pragma: no cover
                self.proc.kill()
            time.sleep(0.5)
        if self.mode == "off" or self.started_size is None:
            return None
        if not os.path.exists(self.path):
            return None
        size = os.path.getsize(self.path)
        if size <= self.started_size:
            log.error("capture file %s did not grow (%d -> %d bytes): it is "
                      "not watching this segment, or tcpdump is buffering "
                      "without -U", self.path, self.started_size, size)
            return None
        log.info("capture: %s grew %d -> %d bytes", self.path,
                 self.started_size, size)
        return self.path


# ==========================================================================
# The host-side WireGuard peer, in process
# ==========================================================================

class HostPeer:
    """A patient WireGuard responder we can also ASSERT against.

    tools/wg_responder/server.py is the interactive version; this drives
    the same WireGuardResponder from a thread so the suite can check
    decrypted content directly instead of scraping the server's stdout.
    Patience is the whole point: a real `wg` gives up long before the C64
    finishes its X25519, and on this rig the cartridge port throttles the
    path further.
    """

    def __init__(self, priv: bytes, c64_pub: bytes, bind_ip: str = HOST_IP,
                 port: int = WG_PORT):
        self.responder = WireGuardResponder(priv, c64_pub)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, port))
        self.sock.settimeout(0.5)
        self._lock = threading.Lock()       # noise state is MUTABLE
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.peer_addr: Optional[tuple] = None
        self.received: list[bytes] = []      # decrypted plaintexts, in order
        self.type1_seen = 0
        self.type2_sent = 0
        self.type4_in = 0
        self.errors: list[str] = []

    def __enter__(self) -> "HostPeer":
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self.sock.close()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                continue
            self.peer_addr = addr
            try:
                if data[0] == MSG_TYPE_INITIATION:
                    self.type1_seen += 1
                    with self._lock:
                        reply = self.responder.handle_initiation(data)
                    self.sock.sendto(reply, addr)
                    self.type2_sent += 1
                    log.info("peer: type-1 (%d B) from %s -> type-2 (%d B)",
                             len(data), addr, len(reply))
                elif data[0] == MSG_TYPE_TRANSPORT:
                    self.type4_in += 1
                    with self._lock:
                        pt = self.responder.decrypt_transport(data)
                    self.received.append(pt)
                    log.info("peer: type-4 (%d B) -> %d B plaintext",
                             len(data), len(pt))
                else:
                    self.errors.append(f"unexpected type 0x{data[0]:02x} "
                                       f"({len(data)} B) from {addr}")
            except Exception as exc:                          # noqa: BLE001
                self.errors.append(f"{type(exc).__name__}: {exc}")
                log.error("peer: %s: %s", type(exc).__name__, exc)

    @property
    def handshake_complete(self) -> bool:
        return bool(self.responder.handshake_complete)

    def wait_for_plaintext(self, timeout: float) -> Optional[bytes]:
        """The next plaintext to arrive, or None. Consumes it."""
        deadline = time.monotonic() + timeout
        start = len(self.received)
        while time.monotonic() < deadline:
            if len(self.received) > start:
                return self.received[start]
            time.sleep(0.2)
        return None

    def send_tunnel(self, payload: bytes, msg_port: int,
                    dst_ip: str = TUNNEL_IP) -> int:
        """Encrypt *payload* inside the IPv4/UDP framing the C64 parses.

        src/wg/ip_build.s udp_tunnel_parse requires protocol 17 and a
        destination port equal to msg_port; it reads the payload from
        offset 28 and its length from the inner UDP length field. It does
        NOT check addresses or checksums — but we build both correctly,
        because a suite that only works against a lenient parser proves
        less than one that would also satisfy a strict one.
        """
        if self.peer_addr is None:
            raise RuntimeError("no peer address learned yet: the C64 has not "
                               "sent us anything")
        inner = self._tunnel_packet(payload, msg_port, dst_ip)
        with self._lock:
            pkt = self.responder.encrypt_transport(inner)
        self.sock.sendto(pkt, self.peer_addr)
        return len(pkt)

    @staticmethod
    def _tunnel_packet(payload: bytes, msg_port: int, dst_ip: str) -> bytes:
        udp = struct.pack(">HHHH", msg_port, msg_port, 8 + len(payload), 0)
        total = 20 + len(udp) + len(payload)
        hdr = bytearray(bytes([0x45, 0x00]) + struct.pack(">H", total)
                        + b"\x00\x00\x40\x00" + bytes([64, 17]) + b"\x00\x00"
                        + bytes(int(o) for o in HOST_IP.split("."))
                        + bytes(int(o) for o in dst_ip.split(".")))
        csum = 0
        for i in range(0, 20, 2):
            csum += (hdr[i] << 8) | hdr[i + 1]
        while csum >> 16:
            csum = (csum & 0xFFFF) + (csum >> 16)
        struct.pack_into(">H", hdr, 10, (~csum) & 0xFFFF)
        return bytes(hdr) + udp + payload


def send_cleartext_control(c64_ip: str, token: bytes) -> bool:
    """Put *token* on the wire IN THE CLEAR, as the control for absence.

    Sent from the rig address to a port ip65 has no listener on, so the
    C64 drops it in udp_process and nothing on the machine is disturbed.
    Its whole job is to be FOUND by the same search that must not find
    the tunnel payload — without it, "the secret is absent" is equally
    consistent with a search that can find nothing at all.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((HOST_IP, 0))
        for _ in range(3):              # a 10baseT segment can drop one
            s.sendto(token, (c64_ip, CONTROL_PORT))
            time.sleep(0.2)
        s.close()
        return True
    except OSError as exc:
        log.error("cleartext control datagram failed: %s", exc)
        return False


# ==========================================================================
# Device helpers
# ==========================================================================

CAT_CART = "C64 and Cartridge Settings"
ITEM_CART_PREF = "Cartridge Preference"


def sample_de00(tr, run: dict, when: str) -> str:
    """Record the host-side $DE00..$DE0F window. DATA, NEVER A CHECK.

    This gates nothing and can fail nothing. It exists because three
    observers have now reported three different patterns for this window
    on the same cartridge, and a later measurement showed it is OPEN BUS:
    it does not reflect writes and does not agree with itself between
    consecutive reads (0a, 3c 00 00..., cc, 92, f7, 8d, f0 across three
    observers). Nobody has a table of what it actually does across states.
    Sampling it at four points costs one DMA read each and would let the
    harness lane's doc state the real behaviour instead of one observer's
    snapshot of a floating bus.

    It is emphatically not a presence test. A value that three careful
    people read differently is not a discriminator, and any checker keyed
    on one of those patterns is keyed on a coincidence. Presence is
    established on the 6510 — by ip65's own EISA probe (PPPtr=$0000,
    PPData==$630E), which is what "INIT DRIVER: OK" in the bench-health
    control reports.
    """
    try:
        window = bytes(tr.read_memory(0xDE00, 16)).hex(" ")
    except Exception as exc:                                  # noqa: BLE001
        window = f"unread: {exc}"
    run.setdefault("de00_window", {})[when] = window
    log.info("$DE00..$DE0F [%s]: %s   (DATA ONLY — gates nothing)",
             when, window)
    return window


def read_ip65_diag(tr, L, tag: str, run: dict,
                   level: int = logging.ERROR) -> dict:
    """Read ip65's own failure diagnostics. Call at EVERY failure.

    Addresses come from labels.txt (Labels raises on a missing symbol)
    rather than being hardcoded: $78A7/$78A9/$78AA are right for the
    current build and would be silently wrong after a relink.

    THE CODES ARE NOT DECODED HERE. Naming them is a verdict, and verdicts
    live in tools/ip65_hw_checks.py; this returns the raw bytes. What is
    worth recording is why the byte matters: net_last_error is the ONLY
    thing that separates a cartridge that is not on the bus from a DHCP
    server that did not answer, and both present as the same Stage A
    timeout.

    One value is worth flagging even without a decoder: $47
    (NET_ERR_IP65_UDP_SEND) is RESERVED AND NEVER EMITTED — it exists so
    the number cannot be quietly reused (#120). If it ever appears, the
    conclusion is a bug in our own adapter, not a network fault. An
    earlier version of the brief described $47 as "send failed", which
    would have sent someone to debug the cable.
    """
    out = {}
    for name in ("net_last_error", "ip65_recv_dropped", "ip65_send_attempts"):
        try:
            out[name] = tr.read_memory(L[name], 1)[0]
        except Exception as exc:                              # noqa: BLE001
            out[name] = f"unread: {exc}"
    run.setdefault("ip65_diag", {})[tag] = out
    log.log(level, "[%s] ip65 diagnostics: net_last_error=$%02X "
            "ip65_recv_dropped=%s ip65_send_attempts=%s",
              tag,
              out["net_last_error"] if isinstance(out["net_last_error"], int)
              else 0, out["ip65_recv_dropped"], out["ip65_send_attempts"])
    if out.get("net_last_error") == 0x47:
        log.error("[%s] net_last_error is $47, which NOTHING IN THE BUILD "
                  "EMITS (reserved, #120). This is a defect in our adapter, "
                  "not a network failure — do not go and check the cable.",
                  tag)
    return out


def load_prg_verified(tr, prg: bytes, tag: str, run: dict) -> bool:
    """Load a PRG the way run_prg_via_sys does, but VERIFY it before SYS.

    Two separate reasons this is not just `run_prg_via_sys`:

    * `client.run_prg`'s DMA load DROPS the external cartridge
      (c64_test_harness/execute.py:806-825, issue #211): the loaded program
      reads the whole $DE00 window as zeros while Cartridge Preference
      still reports "External". Stock ip65 then fails its EISA probe, the
      combo driver falls through to the ETH64 adaptor, that fails too, and
      the screen says NET INIT FAILED. That failure looks exactly like "our
      backend does not work on real silicon" — a confident wrong conclusion
      manufactured by our own loader. So: SYS, never DMA-run.
    * `run_prg_via_sys` writes through memory.write_bytes, which chunks at
      84 bytes and so never reaches the SocketDMA fast path (min 8192).
      This PRG is ~39 kB, i.e. roughly 460 sequential unverified REST
      writes. A torn load then gets SYS'd and fails as something else
      entirely — most likely as a network fault, since that is the first
      thing the program does. Verifying the image is the difference
      between "the load was fine and ip65 failed" and not knowing.

    The load wall-clock is outside BOOT_BUDGET_S, which measures from SYS.
    """
    from c64_test_harness.execute import parse_basic_sys_address
    from c64_test_harness.keyboard import send_text
    from c64_test_harness.memory import write_bytes
    from c64_test_harness.screen import wait_for_text

    sys_addr = parse_basic_sys_address(prg)
    if sys_addr is None:
        raise RuntimeError(f"{tag}: no SYS token in the PRG's BASIC stub")
    load_addr = prg[0] | (prg[1] << 8)
    body = prg[2:]

    tr.reset()
    if wait_for_text(tr, "READY.", timeout=30.0, poll_interval=0.3,
                     verbose=False) is None:
        raise RuntimeError(f"{tag}: machine never reached READY.")
    t_ready = time.monotonic()
    t0 = time.monotonic()
    write_bytes(tr, load_addr, body)
    # THE HEAD GOES LAST. MEASURED on this device (three trials, 2026-09-05):
    # writing a PRG body straight through from $0801 leaves $0801/$0802
    # reading back as 00 00 while all 6084 remaining bytes are byte-exact.
    # It is not a torn write and not a delayed clear — the first 84-byte
    # chunk lands correctly when written ALONE (verified), and an immediate
    # read after the full sequence already shows 00 00. Something zeroes
    # those two bytes during the rest of the sequence. Rewriting them
    # afterwards makes them stick, and so does writing the tail first.
    #
    # Those two bytes are the BASIC next-line pointer, which SYS<addr> does
    # not use — which is why this has gone unnoticed in run_prg_via_sys,
    # where the program runs correctly regardless. Rewriting the head is
    # two bytes and makes the image genuinely byte-exact, which is better
    # than teaching the verifier to tolerate a difference: a check that
    # accepts "these two bytes may be wrong" accepts them being wrong for
    # some OTHER reason too.
    if len(body) > 2:
        tr.write_memory(load_addr, body[:2])
    load_s = time.monotonic() - t0

    # AND RE-VERIFY THE HEAD PAST THE POST-RESET WINDOW. MEASURED: a single
    # zeroing event hits $0801/$0802 between ~2 s and ~5 s after READY. is
    # drawn, INDEPENDENTLY OF ANY WRITE — stamping $DEAD there and waiting
    # 8 s with no write at all yields 00 00. So a head that reads back
    # intact BEFORE the event fires is not yet safe, and this loader only
    # survived by accident: a 39 kB body takes 34 s to write, so its head
    # rewrite landed long past the window. A SMALL PRG would have been
    # silently corrupted. Waiting past the window and re-checking is what
    # actually makes it safe, rather than the rewrite alone.
    POST_RESET_SETTLE_S = 7.0
    remaining = POST_RESET_SETTLE_S - (time.monotonic() - t_ready)
    if remaining > 0:
        time.sleep(remaining)
    for attempt in (1, 2, 3):
        head = bytes(tr.read_memory(load_addr, min(2, len(body))))
        if head == body[:2]:
            break
        log.warning("%s: head at $%04X reads %s, expected %s — rewriting "
                    "(attempt %d)", tag, load_addr, head.hex(" "),
                    body[:2].hex(" "), attempt)
        tr.write_memory(load_addr, body[:2])
        time.sleep(1.0)

    back = bytes(tr.read_memory(load_addr, len(body)))
    want = hashlib.sha256(body).hexdigest()
    got = hashlib.sha256(back).hexdigest()
    run.setdefault("loads", {})[tag] = {
        "load_addr": f"${load_addr:04X}", "bytes": len(body),
        "sys": sys_addr, "seconds": round(load_s, 1),
        "sha256_expected": want, "sha256_readback": got,
    }
    if got != want:
        first = next((i for i, (a, b) in enumerate(zip(body, back)) if a != b),
                     min(len(body), len(back)))
        check(False, f"the {tag} image loaded into RAM intact",
              f"sha256 mismatch after {len(body)} bytes over ~"
              f"{len(body) // 84 + 1} unverified 84-byte REST writes; first "
              f"difference at offset {first} (${load_addr + first:04X}). "
              f"SYS was NOT typed — a torn image would have failed later as "
              f"a network fault.")
        return False
    check(True, f"the {tag} image loaded into RAM intact",
          f"{len(body)} B at ${load_addr:04X} in {load_s:.1f}s, sha256 "
          f"{got[:16]}… verified by read-back before SYS{sys_addr}")
    send_text(tr, f"SYS{sys_addr}\r")
    return True


def _config_value(payload) -> Optional[str]:
    """Current value of a config item from the REST envelope.

    MEASURED SHAPE (2026-09-05): get_config_item returns the WHOLE
    envelope, not the item —

        {"C64 and Cartridge Settings":
            {"Cartridge Preference":
                {"current": "External",
                 "values": ["Auto", "Internal", "External", "Manual"],
                 "default": "Auto"}},
         "errors": []}

    The method's name promises a value and it returns data; the gap
    between those cost a teardown restore on run 1, which read None and
    therefore had nothing to write back. Filed as c64-test-harness#214.
    The known path is tried first and the generic descent is kept as a
    fallback so a firmware that nests differently still works.
    """
    if not isinstance(payload, dict):
        return None
    try:
        got = payload[CAT_CART][ITEM_CART_PREF]["current"]
        if isinstance(got, str):
            return got
    except (KeyError, TypeError):
        pass
    for key in ("current", "value", "val"):
        if isinstance(payload.get(key), str):
            return payload[key]
    for v in payload.values():
        if isinstance(v, dict):
            got = _config_value(v)
            if got is not None:
                return got
    return None


def _config_allowed(payload) -> list:
    """The item's enum of permitted values, or []."""
    try:
        vals = payload[CAT_CART][ITEM_CART_PREF]["values"]
        return list(vals) if isinstance(vals, list) else []
    except (KeyError, TypeError):
        return []


def _config_default(payload) -> Optional[str]:
    try:
        got = payload[CAT_CART][ITEM_CART_PREF]["default"]
        return got if isinstance(got, str) else None
    except (KeyError, TypeError):
        return None


def set_cartridge_external(client, run: dict) -> Optional[str]:
    """Put `Cartridge Preference` on External. Returns the value to restore.

    REFUSES TO SET WHAT IT COULD NOT READ BACK. A failed read used to let
    the PUT proceed, which is precisely how a run changes something it
    cannot restore — and on a device three lanes share, that is how state
    leaks between them. If the read does not yield a string that appears
    in the item's own `values` enum, no PUT is issued and the caller is
    expected to fail the run: a run that cannot restore the bench should
    not disturb it.

    Volatile — reverts to Auto on reboot — so it is set per run rather
    than once, and the harness's snapshot_state does not cover it (it
    covers `Cartridge`, the preset, which is a different item), so
    restoring it is ours to do.
    """
    before = client.get_config_item(CAT_CART, ITEM_CART_PREF)
    log.info("%s raw payload: %r", ITEM_CART_PREF, before)
    errors = before.get("errors") if isinstance(before, dict) else None
    if errors:
        raise RuntimeError(
            f"reading {ITEM_CART_PREF!r} returned errors {errors!r}; refusing "
            f"to set a value we could not read back")
    prev = _config_value(before)
    allowed = _config_allowed(before)
    default = _config_default(before)
    run["cartridge_preference_before"] = prev
    run["cartridge_preference_values"] = allowed
    if prev is None or (allowed and prev not in allowed):
        enum = allowed or "its enum"
        raise RuntimeError(
            f"could not read {ITEM_CART_PREF!r} as one of {enum} (got "
            f"{prev!r}). NOT setting it: a run that cannot restore the "
            f"bench must not disturb it.")

    client.set_config_item(CAT_CART, ITEM_CART_PREF, "External")
    time.sleep(1.0)
    now = _config_value(client.get_config_item(CAT_CART, ITEM_CART_PREF))
    run["cartridge_preference_set"] = now
    log.info("%s: %r -> %r (NOT proof the cartridge is visible — only the "
             "6510 can establish that; see stage_bench_health)",
             ITEM_CART_PREF, prev, now)

    # What to hand back. If the value was ALREADY External we cannot tell a
    # deliberate setting from an earlier run's leaked one — run 1 of this
    # suite left exactly that, by setting External and then failing to
    # restore it. Restoring External in that case would perpetuate the leak
    # for ever, so fall back to the item's own declared default.
    restore_to = prev
    if prev == "External" and default and default != "External":
        restore_to = default
        log.warning("%s already read %r, which is what this run sets — that "
                    "is indistinguishable from an earlier run leaking it "
                    "(run 1 of this suite did exactly that). Restoring the "
                    "device's declared default %r instead.",
                    ITEM_CART_PREF, prev, default)
    run["cartridge_preference_restore_to"] = restore_to
    return restore_to


def load_labels(build_dir: Path) -> Labels:
    path = build_dir / "labels.txt"
    if not path.exists():
        raise SystemExit(f"FATAL: missing {path}")
    L = Labels.from_file(str(path))
    missing = [n for n in REQUIRED_LABELS if L.address(n) is None]
    if missing:
        raise SystemExit(f"FATAL: labels missing from {path}: {missing}")
    return L


def assert_ip65_build(build_dir: Path) -> None:
    """Refuse a UCI build up front: the blob would not be linked in.

    Structural, from the map, before the device is touched. Running the
    UCI PRG on this rig would fail in a way that looks like an RR-Net
    fault — it would talk to $DF1B and never emit a frame — and that is
    the misdiagnosis this whole run exists to avoid making.
    """
    mapfile = build_dir / "wireguard.map"
    if not mapfile.exists():
        raise SystemExit(f"FATAL: {mapfile} missing; build first")
    if "ip65_blob.o" not in mapfile.read_text():
        raise SystemExit(
            f"FATAL: {mapfile} has no ip65_blob.o — this is not a BACKEND=ip65 "
            f"build. Rebuild: make clean && make BACKEND=ip65 REU=0 WG_MTU1440=1")


def build_ip65(build_dir: Path, extra: list[str] | None = None) -> dict:
    """make clean && make BACKEND=ip65 REU=0 ...; returns the fingerprint.

    A gate run leaves build/ as the ip65 DEFAULT already, but rebuilding
    explicitly is the only way to know what is in there: this tree is
    shared and CA65FLAGS staleness across a BACKEND/REU switch has bitten
    us before.
    """
    args = ["make", "BACKEND=ip65", "REU=0", "WG_MTU1440=1"] + (extra or [])
    log.info("building: %s", " ".join(args))
    subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, check=True,
                   capture_output=True)
    p = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"FATAL: build failed:\n{p.stdout[-3000:]}\n"
                         f"{p.stderr[-3000:]}")
    return fingerprint(build_dir)


def fingerprint(build_dir: Path) -> dict:
    prg = build_dir / "wireguard.prg"
    data = prg.read_bytes()
    L = load_labels(build_dir)
    fp = {
        "prg": str(prg.relative_to(PROJECT_ROOT)),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "WG_MTU": L["WG_MTU"],
        "MSG_TEXT_MAX": ki.input_max_from_labels(L),
    }
    log.info("PRG %s  %d B  sha256 %s  WG_MTU=%d  MSG_TEXT_MAX=%d",
             fp["prg"], fp["bytes"], fp["sha256"], fp["WG_MTU"],
             fp["MSG_TEXT_MAX"])
    return fp


def blob_var(tr, L, offset: int, length: int) -> bytes:
    """Read a variable through the ip65 blob's own address table.

    Going through the table rather than a hardcoded address keeps this
    structural: if the blob is relinked, the table moves with it and this
    still reads the right cell.
    """
    base = L["ip65_blob_start"]
    ptr = bytes(tr.read_memory(base + offset, 2))
    addr = ptr[0] | (ptr[1] << 8)
    if not (0x0200 <= addr <= 0xFFF0):
        raise RuntimeError(f"ip65 variable table at ${base + offset:04X} holds "
                           f"${addr:04X}, which is not a plausible address — "
                           f"the blob layout has changed or nothing is loaded")
    return bytes(tr.read_memory(addr, length))


def read_cfg_ip(tr, L) -> str:
    return ".".join(str(b) for b in blob_var(tr, L, BLOB_VAR_CFG_IP, 4))


def read_cfg_mac(tr, L) -> bytes:
    return blob_var(tr, L, BLOB_VAR_CFG_MAC, 6)


def fmt_mac(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def parse_mac(text: str) -> bytes:
    parts = re.split(r"[:-]", text.strip())
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"MAC must have 6 octets: {text!r}")
    return bytes(int(p, 16) for p in parts)


def find_driver_mac_addr(tr) -> Optional[int]:
    """Address of the CS8900a driver's own MAC table in RAM, or None.

    Resolved from ip65-build/ip65-c64.map (`_cs8900a`, the module
    descriptor, at an ABSOLUTE address because the blob is linked at its
    load address) and then VERIFIED by reading the 4-byte "eth" + API
    version signature that precedes the MAC in ip65/drivers/cs8900a.s. If
    the signature is not there, the offset assumption is wrong and this
    returns None rather than patching six arbitrary bytes of a running
    network stack.
    """
    mapfile = PROJECT_ROOT / "ip65-build" / "ip65-c64.map"
    if not mapfile.exists():
        return None
    m = re.search(r"\b_cs8900a\s+([0-9A-Fa-f]{6})\b", mapfile.read_text())
    if not m:
        return None
    desc = int(m.group(1), 16)
    sig = bytes(tr.read_memory(desc, len(DRIVER_SIGNATURE)))
    if sig != DRIVER_SIGNATURE:
        log.warning("_cs8900a at $%04X does not start with the expected "
                    "'eth'+apiver signature (found %s) — NOT patching", desc,
                    sig.hex())
        return None
    return desc + DRIVER_MAC_OFFSET


def wait_for_byte(tr, addr: int, want: int, timeout: float,
                  poll: float = 0.5) -> tuple[bool, float]:
    """(reached, seconds). Reads are DMA, so they do not halt the 6510 —
    unlike VICE's monitor, where a poll loop stops the machine dead."""
    t0 = time.monotonic()
    deadline = t0 + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1)[0] == want:
            return True, time.monotonic() - t0
        time.sleep(poll)
    return False, time.monotonic() - t0


def set_turbo_checked(client, mhz: int) -> int:
    set_turbo_mhz(client, mhz)
    time.sleep(TURBO_SETTLE_S)
    actual = get_turbo_mhz(client)
    if actual != mhz:
        raise RuntimeError(f"turbo did not stick: asked {mhz} MHz, device "
                           f"reports {actual}")
    log.info("clock confirmed at %d MHz", actual)
    return actual


def stage_config(tr, L, priv: bytes, pub: bytes, peer_pub: bytes) -> int:
    """Stage cfg_* for the rig's own responder. Returns the TAI64N base."""
    tr.write_memory(L["cfg_static_priv"], priv)
    tr.write_memory(L["cfg_static_pub"], pub)
    tr.write_memory(L["cfg_peer_pub"], peer_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in HOST_IP.split(".")))
    # BIG-endian in the ABI (src/net_abi.inc). Issue #118 was this field
    # reaching ip65's little-endian port cell unswapped, which sent every
    # frame to a byte-swapped port and made the handshake simply never
    # complete, with nothing on screen to say why.
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    bytes([WG_PORT >> 8, WG_PORT & 0xFF]))
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in TUNNEL_IP.split(".")))
    tr.write_memory(L["ping_target_ip"],
                    bytes(int(o) for o in HOST_IP.split(".")))
    tai = int(time.time()) + 10
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))
    log.info("cfg staged: peer %s:%d  tunnel %s  tai64n base %d",
             HOST_IP, WG_PORT, TUNNEL_IP, tai)
    return tai


# --- the bench-health control -------------------------------------------
#
# Stock ip65, static IP, one ping. If this does not work, the bench is
# wrong and NOTHING about our build can be concluded from a failure — which
# is worth two minutes to learn instead of an hour misattributing a failed
# WireGuard run.
PINGSTATIC_DIR = Path("/Users/someone/Documents/c64-test-harness/"
                      ".claude/scratch/rrnet-ip65")
PINGSTATIC_PRG = PINGSTATIC_DIR / "pingstatic-1066.prg"
PINGSTATIC_IP = "10.0.66.200"      # static, and the same address the rig pins


#: A ~29-byte 6502 stub: enable the RR clockport, set PPPtr = $0000, read
#: PPData and stash it. The CS8900a answers $630E there — the EISA product
#: identifier, and the exact predicate ip65's own driver uses before it
#: will initialise (ip65/drivers/cs8900a.s init).
#:
#: IT MUST RUN ON THE 6510. A host-side read of $DE00 never reaches the
#: cartridge — this run alone produced uniform $a5 and uniform $ff for that
#: window in identical states, and run 1 gave different values again.
PROBE_ADDR = 0x0340          # cassette buffer; SYS 832
PROBE_RESULT = 0x03F0        # end of the cassette buffer, clear of the stub
PROBE_POISON = b"\x5A\xA5"   # so "never ran" != "read zeros"
CS8900A_PROBE = bytes([
    0xAD, 0x01, 0xDE,        # lda $DE01      ; RR clockport enable
    0x09, 0x01,              # ora #$01
    0x8D, 0x01, 0xDE,        # sta $DE01
    0xA9, 0x00,              # lda #$00
    0x8D, 0x02, 0xDE,        # sta $DE02      ; PPPtr lo = $00
    0x8D, 0x03, 0xDE,        # sta $DE03      ; PPPtr hi = $00
    0xAD, 0x04, 0xDE,        # lda $DE04      ; PPData lo
    0x8D, PROBE_RESULT & 0xFF, PROBE_RESULT >> 8,
    0xAD, 0x05, 0xDE,        # lda $DE05      ; PPData hi
    0x8D, (PROBE_RESULT + 1) & 0xFF, (PROBE_RESULT + 1) >> 8,
    0x60,                    # rts
])


def probe_cs8900a(tr, run: dict, *, reset_first: bool = False) -> Optional[int]:
    """PPData after PPPtr=$0000, read BY THE 6510. None if it did not run.

    Driven with SYS from the BASIC prompt rather than the harness's jsr():
    jsr() is typed for the VICE binary monitor and, per c64-test-harness
    #183/#184, abandons the IRQ frame and leaves I SET — which would stop
    the jiffy for the rest of the session and break the very pingstatic
    timing this control exists to measure. SYS returns to BASIC cleanly.

    The result cell is poisoned first, so "the stub never ran" is
    distinguishable from "the stub read zeros" — which matters, because
    zeros are three different conditions and none of them is "no
    cartridge".
    """
    from c64_test_harness.keyboard import send_text
    from c64_test_harness.screen import wait_for_text
    # NO RESET BY DEFAULT, and the ordering is the reason. Run 3 called this
    # with its own reset, immediately before load_prg_verified's reset, and
    # both new checks failed "not-read": SYS832 was typed about a second
    # after READY., which is INSIDE the 2-5 s post-reset window the $0801
    # trials measured — the same window that eats a write to $0801. The
    # second failure was worse: two resets a second apart, and the 48 MHz
    # ping control then failed where it had passed in run 2.
    #
    # So the probe now runs AFTER the control has pinged, in the BASIC
    # session pingstatic returns to (it ends in exit_to_basic). No extra
    # reset, no early SYS, and the CPU has demonstrably been talking to the
    # chip already.
    if reset_first:
        tr.reset()
        if wait_for_text(tr, "READY.", timeout=30.0, poll_interval=0.3,
                         verbose=False) is None:
            log.warning("cs8900a probe: never reached READY.")
            return None
        time.sleep(6.0)          # clear of the measured post-reset window
    tr.write_memory(PROBE_RESULT, PROBE_POISON)
    tr.write_memory(PROBE_ADDR, CS8900A_PROBE)
    back = bytes(tr.read_memory(PROBE_ADDR, len(CS8900A_PROBE)))
    if back != CS8900A_PROBE:
        log.warning("cs8900a probe: stub did not land at $%04X", PROBE_ADDR)
        return None
    got = PROBE_POISON
    for attempt in (1, 2):
        send_text(tr, f"SYS{PROBE_ADDR}\r")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            got = bytes(tr.read_memory(PROBE_RESULT, 2))
            if got != PROBE_POISON:
                break
            time.sleep(0.25)
        if got != PROBE_POISON:
            break
        log.warning("cs8900a probe: result cell still poisoned after "
                    "SYS%d (attempt %d)", PROBE_ADDR, attempt)
    if got == PROBE_POISON:
        log.warning("cs8900a probe: SYS%d never ran", PROBE_ADDR)
        return None
    pid = got[0] | (got[1] << 8)
    run.setdefault("cs8900a_product_id", {})[f"$%04X" % PROBE_ADDR] = \
        f"${pid:04X}"
    log.info("cs8900a product id read ON THE 6510: $%04X (expect $630E)", pid)
    return pid


def stage_bench_health(tr, client, run: dict, mhz: int) -> bool:
    """Run the known-good stock-ip65 ping control at *mhz*.

    BE HONEST ABOUT WHAT THIS PROVES. Three separate limits, and none of
    them is papered over in the report:

    1. Only the 169.254 variant of this build has a measured result behind
       it (2-3 ms round trips on this silicon, 2026-09-05).
       pingstatic-1066.prg is the same generator re-targeted at 10.0.66.x
       and has never been on the wire. A FAILURE here is therefore
       ambiguous between "the bench is wrong" and "the re-target is
       wrong", and this says so rather than picking one. Note also that
       the file matters: .../pingstatic.prg is the 169.254 build and
       running THAT one here reports "bench broken" when the bench is fine.
    2. IT DOES NOT COVER THE SAME DRIVER PATH WE USE. pingstatic links
       c64rrnet.lib, which is cs8900a only. Our blob links ip65_c64.lib =
       rr-net.o + eth64.o + c64combo.o, i.e. the COMBO wrapper, whose
       init_adaptor/eth_rx/eth_tx are self-modifying code in .data. A
       fault in the combo glue passes this control and fails our build.
       That is a real gap, and a green control is not cover for it.
    3. A combo failure is itself ambiguous: the wrapper probes cs8900a
       first and silently falls through to lan91c96/ETH64 before
       reporting, so "NET INIT FAILED" on our build does not by itself
       say which adaptor failed. net_last_error ($41) narrows it.
    """
    log.info("--- bench-health control: stock ip65 ping at %d MHz ---", mhz)
    key = f"bench_health_{mhz}mhz"
    if not PINGSTATIC_PRG.exists():
        skipped(f"bench-health control passed at {mhz} MHz",
                f"{PINGSTATIC_PRG} not found")
        return False
    set_turbo_checked(client, mhz)
    if not load_prg_verified(tr, PINGSTATIC_PRG.read_bytes(),
                             f"pingstatic@{mhz}MHz", run):
        run[key] = {"error": "the control image did not load intact"}
        return False
    deadline = time.monotonic() + 60.0
    text = ""
    while time.monotonic() < deadline:
        text = screen_text(tr)
        if "MS" in text or "FAILED" in text:
            break
        time.sleep(1.0)
    m = re.search(r"PINGING\s+([\d.]+)\D+(\d+)\s*MS", text)
    driver_ok = "INIT DRIVER: OK" in text
    # THE WHOLE SCREEN, not a tail. text[-200:] is the last five rows, and
    # pingstatic prints its result near the TOP — so the tail showed
    # "READY." and truncated the one line that says WHY it failed. A
    # diagnostic that cuts off the diagnosis is worse than none.
    run[key] = {"driver_ok": driver_ok,
                "ms": int(m.group(2)) if m else None,
                "screen": " ".join(text.split())}
    check(driver_ok, f"stock ip65 found the RR-Net at {mhz} MHz "
                     f"(INIT DRIVER: OK)",
          f"WHOLE screen: {' '.join(text.split())!r}. FAILED here means the cs8900a "
          f"EISA probe at PP $0000 did not return $630E — no cartridge, or "
          f"the combo driver fell through to the ETH64 adaptor.")
    ok = check(m is not None,
               f"stock ip65 ping round-tripped at {mhz} MHz",
               f"expected 'PINGING <ip> <n> MS'; WHOLE screen "
               f"{' '.join(text.split())!r}. A failure here is AMBIGUOUS between a bad "
               f"bench and a bad re-target: only the 169.254 variant of "
               f"this build has ever been measured on the wire.")
    if m:
        log.info("bench health at %d MHz: %s ms round trip to %s",
                 mhz, m.group(2), m.group(1))
    # The 6510-side identification, AFTER the ping: pingstatic ends in
    # exit_to_basic, so the machine is at the prompt with the cartridge
    # already initialised and no extra reset is needed.
    product_id = probe_cs8900a(tr, run)
    run.setdefault("product_id", {})[str(mhz)] = product_id
    verdict(hw.check_cs8900a_identified(product_id),
            f"the CS8900a identified itself on the 6510 at {mhz} MHz")
    verdict(hw.check_bench_health(bool(m), replies=1 if m else 0,
                                  rtt_ms=[float(m.group(2))] if m else (),
                                  product_id=product_id,
                                  control=PINGSTATIC_PRG.name),
            f"bench health at {mhz} MHz (library verdict)")
    return ok


# --- budgets, derived rather than inherited -------------------------------
#
# MEASURED ANCHOR (tools bench, 2026-08-15, no-REU build): a full handshake
# takes 49 s at 48 MHz, and that build scales 51.7x from 1 MHz — so 1 MHz is
# about 2530 s, roughly 42 minutes.
#
# THE ASSUMPTION, STATED: that anchor is from the UCI backend, and it is
# reused here because the handshake is overwhelmingly X25519, which is pure
# CPU and never touches the cartridge port. The user's ~1.7x figure is a
# cartridge-port I/O throttle, and it applies to a handful of ~150-byte
# frames, not to the scalar multiplications. If that reasoning is wrong the
# budget is wrong, so every run reports the duration it MEASURED alongside
# the budget it was given.
#
# Inheriting HS_POLL_TIMEOUT = 120.0 (a UCI number) would have made a 1 MHz
# run a false FAIL reading as "ip65 is broken on hardware" — the worst
# outcome available, because we would have believed it.
_HS_ANCHOR_48MHZ_S = 49.0
_NO_REU_SCALING_1_TO_48 = 51.7
_HS_MARGIN = 4.0


def handshake_budget(mhz: int) -> tuple[float, str]:
    """(seconds, the reasoning) to allow for a handshake at *mhz*."""
    env = os.environ.get("RRNET_HS_BUDGET_S")
    if env:
        return float(env), f"RRNET_HS_BUDGET_S={env} (explicit override)"
    speedup = 1.0 + (_NO_REU_SCALING_1_TO_48 - 1.0) * (mhz - 1) / 47.0
    expected = _HS_ANCHOR_48MHZ_S * _NO_REU_SCALING_1_TO_48 / max(speedup, 1.0)
    budget = max(600.0, expected * _HS_MARGIN)
    why = (f"{expected:.0f}s expected at {mhz} MHz (49 s measured at 48 MHz, "
           f"no-REU build, scaled by the measured 51.7x 1->48 MHz factor), "
           f"x{_HS_MARGIN:.0f} margin -> {budget:.0f}s")
    return budget, why


def screen_text(tr) -> str:
    from c64_test_harness import ScreenGrid
    return ScreenGrid.from_transport(tr).continuous_text()


def press_h_until_sent(tr, L, budget_s: float
                       ) -> tuple[bool, int, float, list[str]]:
    """Press H until the Type-1 leaves. (ok, attempts, seconds, notes).

    ip65 does not queue a datagram whose next-hop MAC it lacks: it emits
    the ARP request and returns C=1 immediately (ip65/ip.s), which
    session_initiate reports as HANDSHAKE SEND FAILED before dropping
    back to IDLE. Here the peer is on-subnet and the host has not
    necessarily spoken first, so a cold ARP cache on the first attempt is
    expected, not exceptional — and that first attempt's own ARP request
    is what fills the cache.

    The structural signal (wg_state leaving IDLE) carries the fast poll;
    the screen is read rarely and only to distinguish "still doing
    crypto" from "failed and went back to IDLE", which look identical in
    wg_state alone.
    """
    notes: list[str] = []
    t_start = time.monotonic()
    for attempt in range(1, SEND_ATTEMPTS + 1):
        base_hits = screen_text(tr).count(SEND_FAILED_NEEDLE)
        if not ki.press_key(tr, "H", timeout=20.0):
            notes.append(f"attempt {attempt}: 'H' was never consumed")
            return False, attempt, time.monotonic() - t_start, notes
        t0 = time.monotonic()
        deadline = t0 + budget_s
        next_screen = t0 + 15.0
        while time.monotonic() < deadline:
            if tr.read_memory(L["wg_state"], 1)[0] != SESSION_IDLE:
                dt = time.monotonic() - t0
                notes.append(f"attempt {attempt}: type-1 sent after {dt:.0f}s")
                log.info("type-1 sent on attempt %d (%.0fs of crypto)",
                         attempt, dt)
                return True, attempt, time.monotonic() - t_start, notes
            if time.monotonic() >= next_screen:
                next_screen = time.monotonic() + 15.0
                if screen_text(tr).count(SEND_FAILED_NEEDLE) > base_hits:
                    dt = time.monotonic() - t0
                    notes.append(f"attempt {attempt}: {SEND_FAILED_NEEDLE} "
                                 f"after {dt:.0f}s (ip65 ARP cache miss for "
                                 f"the next hop)")
                    log.warning("%s on attempt %d (%.0fs) — retrying now that "
                                "ip65 has ARPed the peer", SEND_FAILED_NEEDLE,
                                attempt, dt)
                    break
            time.sleep(1.0)
        else:
            notes.append(f"attempt {attempt}: neither sent nor failed within "
                         f"{budget_s:.0f}s")
            return False, attempt, time.monotonic() - t_start, notes
        time.sleep(3.0)                 # let the ARP reply land and cache
    return False, SEND_ATTEMPTS, time.monotonic() - t_start, notes


def read_msg_recv(tr, L) -> tuple[int, bytes]:
    """(length, bytes) of the last inbound tunnel payload the C64 parsed.

    Read from msg_recv_len / msg_recv_ptr, which udp_tunnel_parse sets —
    not from the screen. The screen is 40x25 and scrolls, PETSCII, and
    (issue #129) carries whatever control characters the peer sent; the
    buffer is the thing the C64 actually decrypted.
    """
    n = int.from_bytes(bytes(tr.read_memory(L["msg_recv_len"], 2)), "little")
    ptr = int.from_bytes(bytes(tr.read_memory(L["msg_recv_ptr"], 2)), "little")
    if n == 0 or not (0x0200 <= ptr <= 0xFFF0):
        return n, b""
    return n, bytes(tr.read_memory(ptr, min(n, 1500)))


# ==========================================================================
# Stages
# ==========================================================================

def stage_boot_and_dhcp(tr, client, L, args, run: dict) -> bool:
    """A: run the PRG, program/observe the MAC, 'I' at 1 MHz, real lease."""
    log.info("--- Stage A: boot, MAC, DHCP ---")
    # run_prg_via_sys, NEVER client.run_prg: run_prg's DMA load DROPS the
    # external cartridge (c64_test_harness/execute.py:806-825, issue #211).
    # The program it loads then reads the whole $DE00 window as zeros while
    # Cartridge Preference still reports "External" — so the config lies,
    # stock ip65 reports INIT DRIVER: FAILED, and it looks like a dead
    # cartridge rather than a loader artefact.
    if not load_prg_verified(tr, (PROJECT_ROOT / args.build /
                                  "wireguard.prg").read_bytes(),
                             "wireguard", run):
        return False
    sample_de00(tr, run, "3-after-load-via-SYS")
    ok, secs = wait_for_byte(tr, L["boot_ready"], 1, BOOT_BUDGET_S)
    run["boot_seconds"] = round(secs, 1)
    if not check(ok, "boot_ready reached 1",
                 f"{secs:.1f}s of a {BOOT_BUDGET_S:.0f}s budget"):
        read_ip65_diag(tr, L, "boot", run)
        dump_screen(tr, label="rrnet-boot")
        return False

    # MAC. Patch BEFORE 'I': eth_init's reset path programs the chip's IA
    # registers from this table, so after 'I' it is too late, and writing
    # $DE02/$DE04 while ip65 runs would race its own PPPtr.
    run["mac_mode"] = "observe" if args.mac is None else fmt_mac(args.mac)
    if args.mac is not None:
        addr = find_driver_mac_addr(tr)
        if addr is None:
            skipped("driver MAC table patched",
                    "could not resolve/verify _cs8900a in "
                    "ip65-build/ip65-c64.map; running with the driver's own "
                    "address")
            run["mac_patch"] = "unresolved"
        else:
            tr.write_memory(addr, args.mac)
            back = bytes(tr.read_memory(addr, 6))
            check(back == args.mac, "driver MAC table patched in RAM",
                  f"${addr:04X} now reads {fmt_mac(back)}")
            run["mac_patch"] = {"addr": f"${addr:04X}",
                                "written": fmt_mac(args.mac)}

    set_turbo_checked(client, 1)
    # NOT because of CPU-counted delay loops — ip65's DHCP and ARP bound on
    # timer_read, the jiffy, i.e. real time (dhcp.s:147-161, arp.s). That
    # rationale is inherited from test_warp_live.py:1697-1703 and is WRONG.
    # 1 MHz here is now only conservatism about cartridge-port register
    # timing, and even that is weaker than it was: the bench control pings
    # successfully at 48 MHz on this rig, so the CS8900a is addressable at
    # full speed. Kept at 1 MHz because DHCP is not what we are testing.
    log.info("pressing I at 1 MHz (conservative: ip65's DHCP/ARP waits are "
             "jiffy-bound, NOT CPU-counted, so the clock does not shorten "
             "them; this is about cartridge-port register timing only)")
    if not check(ki.press_key(tr, "I", timeout=20.0), "'I' consumed"):
        return False
    ok, secs = wait_for_byte(tr, L["net_initialized"], 1, NET_INIT_BUDGET_S,
                             poll=1.0)
    run["net_init_seconds"] = round(secs, 1)
    if not check(ok, "net_initialized reached 1 (net_init + DHCP + listen)",
                 f"{secs:.1f}s of a {NET_INIT_BUDGET_S:.0f}s budget; "
                 f"src/boot.s do_net_init sets it only after all three "
                 f"succeeded"):
        read_ip65_diag(tr, L, "net_init", run)
        dump_screen(tr, label="rrnet-net-init")
        return False
    log.info("net_initialized in %.1fs at 1 MHz", secs)
    sample_de00(tr, run, "4-after-net-init")

    # ip65's net_udp_listen READS wg_local_port and ignores A/X (unlike the
    # UCI adapter, where A/X is the ABI). We reach it through the menu, so
    # boot.s:401-406 latches the port first and the port-0 false pass
    # cannot occur — but asserting it beats relying on that.
    port = int.from_bytes(bytes(tr.read_memory(L["wg_local_port"], 2)),
                          "little")
    run["wg_local_port"] = port
    if not check(port == EXPECTED_LOCAL_PORT,
                 f"ip65 is listening on port {EXPECTED_LOCAL_PORT}",
                 f"wg_local_port reads {port}. Zero means net_udp_listen "
                 f"bound port 0 and returned C=0 anyway — it reports "
                 f"success and then silently drops every reply."):
        read_ip65_diag(tr, L, "wg_local_port", run)

    ip = read_cfg_ip(tr, L)
    mac = read_cfg_mac(tr, L)
    run["c64_ip"] = ip
    run["c64_mac"] = fmt_mac(mac)
    log.info("ip65 reports cfg_ip=%s cfg_mac=%s", ip, fmt_mac(mac))
    # THE LEASE CHECK IS THE LIBRARY'S, and it must be: cfg_ip is NOT zero
    # before DHCP. ip65/ip65/config.s:18 ships it as 192.168.1.64, with the
    # zeroed variant commented out on the next line — so "read cfg_ip,
    # assert non-zero, conclude DHCP worked" passes with the cable
    # unplugged. My own version tested the subnet prefix and excluded the
    # default only by luck. check_dhcp_lease rejects the shipped default,
    # 0.0.0.0, and 169.254/16 by value, with distinct reasons.
    verdict(hw.check_dhcp_lease(bytes(int(o) for o in ip.split(".")),
                                subnet=RIG_SUBNET_PREFIX.rstrip("."),
                                host_ip=HOST_IP, expect_ip=C64_IP_PINNED),
            f"DHCP lease is the pinned {C64_IP_PINNED} (read from cfg_ip)")
    if args.mac is None:
        # The rig pins a static lease on this exact MAC. If ip65 adopts a
        # different one the --dhcp-host entry simply does not match, the C64
        # silently gets a pool address instead, and every capture keyed on
        # the pinned address stops lining up — a quiet divergence rather
        # than an error.
        check(fmt_mac(mac) == C64_MAC_PINNED.lower(),
              f"cfg_mac is the address the rig pins ({C64_MAC_PINNED})",
              f"ip65 adopted {fmt_mac(mac)}; tools/rig-up-rrnet-macos.sh "
              f"reserves {C64_IP_PINNED} for {C64_MAC_PINNED} via "
              f"--dhcp-host. A mismatch means the static lease did not "
              f"apply and this run took a pool address.")
    if args.mac is not None:
        took = mac == args.mac
        # Not a FAIL: an RR-Net MK3 legitimately overrides this from its
        # own EEPROM (cs8900a.s `copy`). Report which happened.
        log.info("requested MAC %s, ip65 adopted %s — %s", fmt_mac(args.mac),
                 fmt_mac(mac),
                 "patch took" if took else
                 "OVERRIDDEN by the card (RR-Net MK3 EEPROM path)")
        run["mac_patch_took"] = took

    lease = dhcp_lease_for(mac)
    run["dnsmasq_lease"] = lease
    if lease is None:
        skipped("dnsmasq leased this MAC the address the C64 reports",
                f"no entry for {fmt_mac(mac)} in {DNSMASQ_LEASEFILE}")
    else:
        check(lease == ip,
              "dnsmasq's lease matches the address ip65 reports",
              f"leasefile says {lease}, cfg_ip says {ip}")
    return True


def stage_handshake(tr, client, L, peer: HostPeer, args, run: dict) -> bool:
    """B: raise the clock, press H, reach ACTIVE."""
    log.info("--- Stage B: handshake ---")
    set_turbo_checked(client, args.turbo)
    run["turbo_mhz"] = args.turbo
    budget, why = handshake_budget(args.turbo)
    log.info("handshake budget: %s", why)
    run["handshake_budget"] = {"seconds": budget, "reasoning": why}
    ok, attempts, secs, notes = press_h_until_sent(tr, L, budget)
    run["handshake_send"] = {"ok": ok, "attempts": attempts,
                             "seconds": round(secs, 1), "notes": notes}
    if not check(ok, "type-1 left the C64", "\n".join(notes)):
        read_ip65_diag(tr, L, "type1_never_sent", run)
        dump_screen(tr, label="rrnet-type1-never-sent")
        return False

    active, secs = wait_for_byte(tr, L["wg_state"], SESSION_ACTIVE,
                                 budget, poll=1.0)
    run["to_active_seconds"] = round(secs, 1)
    run["wg_state"] = tr.read_memory(L["wg_state"], 1)[0]
    if not check(active, "wg_state reached ACTIVE",
                 f"{secs:.1f}s after the type-1; wg_state is "
                 f"{run['wg_state']} (0=IDLE 1=HS_SENT 2=ACTIVE)"):
        read_ip65_diag(tr, L, "never_active", run)
        dump_screen(tr, label="rrnet-never-active")
        return False
    log.info("ACTIVE after %.1fs at %d MHz", secs, args.turbo)
    check(peer.handshake_complete,
          "the host responder also considers the handshake complete",
          f"type1_seen={peer.type1_seen} type2_sent={peer.type2_sent}")
    check(peer.type1_seen >= 1 and peer.type2_sent >= 1,
          "exactly one type-1 was answered with a type-2",
          f"type1_seen={peer.type1_seen} type2_sent={peer.type2_sent}")
    run["hs_timestamp"] = bytes(tr.read_memory(L["hs_timestamp"], 12)).hex()
    return True


def stage_transport(tr, L, peer: HostPeer, rng, run: dict) -> dict:
    """C: content-verified data C64 -> Mac and Mac -> C64.

    Payloads are randomised per run (seeded) because a fixed string can
    be satisfied by a stale buffer, a previous run's residue, or a test
    that matches its own constant somewhere it should not.
    """
    log.info("--- Stage C: bidirectional transport ---")
    out: dict = {}
    msg_port = int.from_bytes(bytes(tr.read_memory(L["msg_port"], 2)), "big")
    out["msg_port"] = msg_port
    log.info("msg_port read from the running build: %d", msg_port)

    def token(n: int) -> str:
        alphabet = string.ascii_uppercase + string.digits
        return "".join(rng.choice(alphabet) for _ in range(n))

    # --- C64 -> Mac ---
    secret_out = token(24)
    out["c64_to_host_payload"] = secret_out
    log.info("C64 -> host payload: %s", secret_out)
    sent_ok = ki.send_message_dma(tr, secret_out, L, timeout=30.0)
    check(sent_ok, "'M' + payload + RETURN accepted by the C64")
    pt = peer.wait_for_plaintext(TRANSPORT_BUDGET_S)
    if pt is None:
        check(False, "host decrypted a type-4 from the C64",
              f"nothing arrived within {TRANSPORT_BUDGET_S:.0f}s; "
              f"type4_in={peer.type4_in} peer_errors={peer.errors}")
    else:
        from wg_responder.server import strip_tunnel_headers
        bodies = [strip_tunnel_headers(x) for x in peer.received]
        out["c64_to_host_received"] = [b[:64].hex() for b in bodies]
        verdict(hw.check_transport_c64_to_mac(bodies,
                                              secret_out.encode("ascii")),
                "the payload the C64 sent arrived intact and DECRYPTED")

    # --- Mac -> C64 ---
    secret_in = token(20)
    out["host_to_c64_payload"] = secret_in
    log.info("host -> C64 payload: %s", secret_in)
    before = bytes(tr.read_memory(L["tp_recv_counter"], 8))
    n = peer.send_tunnel(secret_in.encode("ascii"), msg_port)
    log.info("sent %d-byte type-4 to the C64", n)
    got = b""
    deadline = time.monotonic() + TRANSPORT_BUDGET_S
    while time.monotonic() < deadline:
        length, buf = read_msg_recv(tr, L)
        if length == len(secret_in) and buf[:length] == secret_in.encode():
            got = buf[:length]
            break
        time.sleep(0.5)
    after = bytes(tr.read_memory(L["tp_recv_counter"], 8))
    out["tp_recv_counter"] = {"before": before.hex(), "after": after.hex()}
    length, buf = read_msg_recv(tr, L)
    verdict(hw.check_transport_mac_to_c64(buf or None, length or None,
                                          secret_in.encode("ascii")),
            "the C64 decrypted the host's payload and stored it byte-exact")
    check(int.from_bytes(after, "little") > int.from_bytes(before, "little"),
          "tp_recv_counter advanced",
          f"{int.from_bytes(before, 'little')} -> "
          f"{int.from_bytes(after, 'little')}")

    # --- ip65's own counters, ON THE GREEN PATH ---
    # read_ip65_diag is called from failure branches only, so a fully green
    # run never looked at these. A run could report PASS across the board
    # with ip65_recv_dropped = 57 and net_last_error = $48, and nothing
    # would say so. The library owns the verdicts; note its guard that a
    # zero drop counter is not evidence unless the send counter moved,
    # which is exactly the vacuous shape this suite keeps finding.
    diag = read_ip65_diag(tr, L, "after-transport", run, level=logging.INFO)
    nle = diag.get("net_last_error")
    verdict(hw.decode_net_last_error(nle if isinstance(nle, int) else None),
            "net_last_error is clear after transport")
    # NO expect_sends, AND THAT IS THE POINT.
    #
    # I first passed `peer.type4_in + 1` here, reasoning that supplying a
    # floor would clear the library's "this zero is not evidence" note.
    # BOTH HALVES OF THAT WERE WRONG.
    #
    # 1. ip65_send_attempts is PER-SEND, not cumulative: src/net/ip65/net.s
    #    stores $01 into it at the top of EVERY net_udp_send, and its BSS
    #    comment says so explicitly, contrasting it with ip65_recv_dropped
    #    which IS cumulative since net_init. So the counter reads 1 on a
    #    healthy run and a floor of 7 would have FAILED every good run.
    # 2. Worse, the note was right and I was trying to make it go away.
    #    ip65_recv_dropped is incremented ONLY under ip65_send_pump
    #    (net.s, the callback disarm), and the pump is exactly what makes
    #    send_attempts exceed 1. On a warm-cache run the pump never fires,
    #    so the drop counter HAS NO OPPORTUNITY TO MOVE and its zero is
    #    genuinely weak evidence. Proving it needs a cold or evicted ARP
    #    cache, which is a different test and does not belong here.
    #
    # So the zero stays a weak assertion and the library keeps saying so.
    # Adjusting an assertion until a caveat disappears is the same shape as
    # every vacuous check this suite exists to catch — it just happened to
    # be me doing it.
    verdict(hw.check_net_counters(
                diag.get("ip65_recv_dropped") if isinstance(
                    diag.get("ip65_recv_dropped"), int) else None,
                diag.get("ip65_send_attempts") if isinstance(
                    diag.get("ip65_send_attempts"), int) else None),
            "ip65 dropped no inbound frames (weak: see the verdict's note)")
    # Recorded as DATA, not scored: 1 = the ARP cache was warm and nothing
    # was retried; >1 = the #120 ARP-pump path fired, which is informative
    # rather than a failure.
    log.info("ip65_send_attempts = %s (per-send: 1 = warm ARP cache, "
             ">1 = the #120 pump path fired)", diag.get("ip65_send_attempts"))

    # --- the same plaintext twice, for the ciphertext-variance claim ---
    repeat = token(16)
    out["repeated_payload"] = repeat
    out["repeated_sent"] = 0
    for i in (1, 2):
        if not ki.send_message_dma(tr, repeat, L, timeout=30.0):
            check(False, f"repeat message {i} accepted by the C64")
            break
        if peer.wait_for_plaintext(TRANSPORT_BUDGET_S) is None:
            check(False, f"repeat message {i} reached the host")
            break
        out["repeated_sent"] = i
    else:
        check(True, "the same plaintext was sent twice (for the wire stage)")
    return out


def stage_wire(cap, run: dict, transport: dict) -> None:
    """W: the wire, decided ENTIRELY by tools/ip65_hw_checks.py.

    This function reads a file, filters it to this run's time window and
    calls the library. It decides nothing. Four leak-check gaps were
    measured in the local implementation this replaces — plaintext torn
    across two IP fragments, plaintext byte-reversed, a capture taken
    without -s0, and ip65's shipped cfg_mac default — and each returned
    GREEN on a capture that contained the plaintext. They are not patched
    here; the checker that handles all four is imported instead, because
    two leak-checkers in one repo, one tested and one not, is the shape
    this review exists to remove.
    """
    log.info("--- Stage W: the wire ---")
    wire_checks = list(WIRE_CHECKS)
    path = cap.stop()
    if not path:
        for label in wire_checks:
            skipped(label, cap.note or "no packet capture for this run")
        return
    try:
        frames_all = hw.parse_pcap(open(path, "rb").read(), strict=True)
    except hw.PcapError as exc:
        # Refusing the file is the point. A capture we cannot decode must
        # not read as "no leak found" — and a capture taken WITHOUT -s0 is
        # exactly that shape: truncated frames make "the plaintext is
        # absent from every frame" structurally true and meaningless.
        for label in wire_checks:
            skipped(label, f"{path} refused by the decoder: {exc}")
        return
    except Exception as exc:                                  # noqa: BLE001
        for label in wire_checks:
            skipped(label, f"{path} unreadable: {exc}")
        return

    # --- the bracket ---
    t0, t1 = cap.t_start or 0.0, cap.t_end or time.time()
    frames = [f for f in frames_all if f.ts >= t0]
    run["capture_window"] = {
        "path": path, "frames_in_file": len(frames_all),
        "frames_in_window": len(frames),
        "excluded_before_start": len(frames_all) - len(frames),
        "t_start": t0, "t_end": t1,
    }
    log.info("capture: %d frames in %s, %d within this run's window "
             "(%d older excluded)", len(frames_all), path, len(frames),
             len(frames_all) - len(frames))
    if not frames:
        for label in wire_checks:
            skipped(label, f"{path} holds {len(frames_all)} frames but NONE "
                           f"inside this run's window — the capture was not "
                           f"running while the events happened")
        return
    # THE BRACKET IS CHECKED OVER THE UNFILTERED FILE. Checking it over
    # `frames` would be a tautology: the filter's whole job is to remove
    # frames outside the window, so a check handed the filtered list can
    # only ever pass. An earlier version of this function did exactly that
    # and its green said nothing at all.
    verdict(hw.check_capture_bracket(frames_all,
                                     started_at=cap.capture_started_at,
                                     ended_at=t1, path=path),
            "the capture brackets this run's events")

    c64_mac = bytes.fromhex(run["c64_mac"].replace(":", "")) \
        if run.get("c64_mac") else b""
    host_mac = bytes.fromhex(run["host_mac"].replace(":", "")) \
        if run.get("host_mac") else b""

    c64_originated = None
    if c64_mac and host_mac:
        c64_frames = [f for f in frames if bytes(f.eth_src) == c64_mac]
        c64_bytes = sum(len(f.raw) for f in c64_frames)
        run["capture_window"]["frames_from_c64"] = len(c64_frames)
        run["capture_window"]["bytes_from_c64"] = c64_bytes
        # C64-sourced bytes FIRST. Total captured bytes is the misleading
        # number on a two-station cable: the Mac's own chatter fills it.
        log.info("capture: %d bytes in %d frames FROM THE C64 (of %d frames "
                 "total in window)", c64_bytes, len(c64_frames), len(frames))
        c64_originated = hw.check_c64_originated(frames, c64_mac, host_mac,
                                                 min_frames=1)
        verdict(c64_originated,
                "frames on the cable came FROM the C64, not just from the Mac")
        verdict(hw.check_mac_on_wire(frames, c64_mac, host_mac),
                "the C64's MAC is on the wire")
    else:
        for label in ("frames on the cable came FROM the C64, not just from "
                      "the Mac", "the C64's MAC is on the wire"):
            skipped(label, "the C64 or host MAC was never read")

    verdict(hw.check_handshake_complete(run.get("wg_state"),
                                        bool(run.get("peer", {})
                                             .get("handshake_complete")),
                                        frames=frames, c64_mac=c64_mac or None),
            "the handshake completed at both ends")

    # --- the control, then the absence ---
    sentinel = run.get("cleartext_sentinel")
    control_ok = False
    if not sentinel:
        skipped("CONTROL: the cleartext sentinel IS found on the wire",
                "no cleartext control datagram was sent")
    else:
        found = hw.check_plaintext_absent(frames,
                                          {"sentinel":
                                           sentinel.encode("ascii")},
                                          c64_mac=c64_mac or None)
        # KEYED ON findings, NOT on `not found.ok`. The verdict is False
        # for two different reasons — the sentinel was found (what we
        # want) and INCONCLUSIVE (too few C64 datagrams) — and `not ok`
        # cannot tell them apart. MEASURED: a capture where the C64 is
        # silent AND the sentinel is absent returns ok=False with
        # findings=[], so `not ok` would report the control as PASSED and
        # unlock the two absence checks on the emptiest possible corpus.
        # That is the vacuous pass this control exists to prevent, so it
        # must not be reintroduced by the control itself.
        hits = [f for f in (found.evidence.get("findings") or [])
                if f.get("label") == "sentinel"]
        control_ok = check(
            bool(hits),
            "CONTROL: the cleartext sentinel IS found on the wire",
            f"{len(hits)} finding(s): {hits}. Verdict text: {found.reason}. "
            f"The sentinel went out in the clear to "
            f"{run.get('c64_ip')}:{CONTROL_PORT}, same alphabet and length "
            f"as the secrets. If the searcher cannot find THIS, its silence "
            f"about the secrets means nothing.")

    # ASCII only: _search_forms covers exact, petscii, petscii-shifted and
    # reversed itself now, so extra needles would report each leak twice.
    needles = {nm: val.encode("ascii") for nm, val in (
        ("c64_to_host", transport.get("c64_to_host_payload")),
        ("host_to_c64", transport.get("host_to_c64_payload")),
        ("repeated", transport.get("repeated_payload")),
    ) if val}
    # --- IDENTICAL PLAINTEXT -> DIFFERENT CIPHERTEXT ---
    # The docstring calls this half of the reason the rig is worth using,
    # and it was never implemented: `repeated_payload` was only a third
    # leak needle, and the "sent twice" PASS in Stage C had no consumer at
    # all. Implemented rather than deleted, because it is cheap here and it
    # is the one claim in this suite that would catch nonce or keystream
    # reuse — a real cryptographic failure that every other check passes
    # straight over.
    #
    # The comparison is over the CIPHERTEXT BODY (past the 16-byte type-4
    # header, which carries a counter that differs by construction and
    # would make any two datagrams look distinct for free).
    label_cv = "identical plaintext produced different ciphertext"
    if not c64_mac:
        skipped(label_cv, "the C64's MAC was never read, so outbound "
                          "datagrams cannot be told from the Mac's")
    elif transport.get("repeated_sent", 0) < 2:
        skipped(label_cv,
                f"the repeated payload went out "
                f"{transport.get('repeated_sent', 0)} time(s), not 2 — with "
                f"no two datagrams carrying the SAME plaintext, distinct "
                f"ciphertext is expected for free and proves nothing")
    else:
        bodies = [d.udp_payload[16:] for d in hw.reassemble(frames)
                  if d.dport == WG_PORT and len(d.udp_payload) > 16
                  and d.udp_payload[0] == MSG_TYPE_TRANSPORT
                  and c64_mac in [bytes(m) for m in d.eth_srcs]]
        dupes = len(bodies) - len(set(bodies))
        check(bool(bodies) and dupes == 0, label_cv,
              f"{len(bodies)} type-4 ciphertext bodies from the C64, "
              f"{len(set(bodies))} distinct ({dupes} repeated). The same "
              f"{len(transport.get('repeated_payload', ''))}-character "
              f"plaintext was sent twice this run, so two of these decrypt "
              f"to identical bytes — equal ciphertext would mean the nonce "
              f"or the key stream repeated.")

    if not needles:
        skipped("no plaintext appears anywhere in the capture",
                "no payload was ever sent")
    elif c64_originated is not None and not c64_originated.ok:
        # The library's guards (non-empty needles, frames, datagrams) say
        # nothing about the C64. A capture holding only the Mac's traffic
        # passes them all, so "no plaintext found" would be true and
        # meaningless. Absence is only evidence about a machine that spoke.
        skipped("no plaintext appears anywhere in the capture",
                f"INCONCLUSIVE: {c64_originated.reason}. A capture the C64 "
                f"never contributed a byte to cannot show a leak from it.")
    elif not control_ok:
        skipped("no plaintext appears anywhere in the capture",
                "the cleartext control was not found, so an absence result "
                "here is INCONCLUSIVE rather than green")
    else:
        verdict(hw.check_plaintext_absent(frames, needles,
                                          c64_mac=c64_mac or None),
                "no plaintext appears anywhere in the capture")


# ==========================================================================
# main
# ==========================================================================

def summarise() -> int:
    npass = sum(1 for s, _, _ in results if s == PASS)
    nfail = sum(1 for s, _, _ in results if s == FAIL)
    nskip = sum(1 for s, _, _ in results if s == SKIP)
    log.info("=" * 72)
    for status, label, detail in results:
        log.info("%-4s  %s", status, label)
        if status != PASS and detail:
            for line in detail.splitlines():
                log.info("        %s", line)
    log.info("=" * 72)
    log.info("%d passed, %d failed, %d skipped (of %d checks)",
             npass, nfail, nskip, len(results))
    if nskip:
        log.warning("%d checks were SKIPPED and are NOT evidence of anything.",
                    nskip)
    if nfail:
        return 1
    blocking = [label for status, label, _ in results
                if status == SKIP and label in WIRE_CHECKS]
    if blocking:
        log.error("=" * 72)
        log.error("EXIT 77 (INCONCLUSIVE): %d WIRE assertion(s) were never "
                  "evaluated:", len(blocking))
        for label in blocking:
            log.error("    %s", label)
        log.error("Nothing failed, but the claims this rig exists to make "
                  "were not made. A zero exit here would report PASS about "
                  "evidence nobody looked at.")
        log.error("=" * 72)
        return 77
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    global VERBOSE
    p = argparse.ArgumentParser(
        description="ip65 / RR-Net end-to-end on real hardware, verified "
                    "from a packet capture.")
    p.add_argument("--host", default=DEFAULT_HOST,
                   help="Ultimate 64 control address (REST/DMA). This is the "
                        "Ultimate's OWN ethernet and is unrelated to the "
                        "RR-Net data path under test.")
    p.add_argument("--iface", default=DEFAULT_IFACE,
                   help="the Mac NIC cabled to the RR-Net (default en4)")
    p.add_argument("--turbo", type=int, default=48,
                   help="clock the handshake runs at. The budget is DERIVED "
                        "from it (handshake_budget), never inherited.")
    p.add_argument("--speeds", default="1,48",
                   type=lambda s: [int(x) for x in s.split(",") if x.strip()],
                   help="clocks to run the stock-ip65 ping control at, "
                        "comma-separated (default 1,48). This is how CPU "
                        "speed is a declared axis: the open question is "
                        "whether the U64 times CS8900a register cycles at "
                        "$DE00 correctly at 48 MHz, and a ping answers it in "
                        "seconds without confounding it with crypto time.")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default="build", help="build directory to run")
    p.add_argument("--skip-build", action="store_true",
                   help="run what is already in --build (its sha256 is still "
                        "reported)")
    p.add_argument("--capture", choices=("auto", "external", "off"),
                   default="auto",
                   help="auto: start tcpdump with `sudo -n`, falling back to "
                        "external if sudo wants a password. external: a "
                        "capture is already running to --pcap. off: no wire "
                        "stage (its checks are recorded SKIP).")
    p.add_argument("--pcap", default=DEFAULT_PCAP)
    p.add_argument("--mac", type=parse_mac, default=None, metavar="AA:BB:..",
                   help="patch ip65's CS8900a driver MAC table before 'I'. "
                        "Default is to OBSERVE the address ip65 adopts and "
                        "assert it against the wire, which is the stronger "
                        "check; see the module docstring for why "
                        "set_cs8900a_mac is not used here. NOTE that the rig "
                        "pins a static DHCP lease to ip65's default MAC, so "
                        "changing it also drops the C64 onto a pool address.")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    VERBOSE = args.verbose

    seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)
    rng = random.Random(seed)
    log.info("Random seed: %d (reproduce with --seed %d)", seed, seed)
    run: dict = {"seed": seed, "iface": args.iface, "host": args.host}
    # The Mac's own MAC. check_c64_originated needs BOTH to tell a C64
    # frame from a Mac frame — and on a two-station cable a frame from a
    # third MAC means the capture is not of this segment at all.
    _st = iface_state(args.iface)
    if _st.get("ether"):
        run["host_mac"] = _st["ether"]

    # --- self-tests first: prove the alarms can sound, before anything ---
    log.info("--- self-tests (proving the checks can fail) ---")
    for name, bad in (("ip65_hw_checks leak/origin alarms",
                       selftest_library()),
                      ("rig probe", selftest_rig_probe(args.iface))):
        if bad:
            log.error("SELF-TEST FAILED (%s):", name)
            for b in bad:
                log.error("    %s", b)
            log.error("Refusing to run: a suite whose own detectors are "
                      "broken would report confident nonsense.")
            return 1
        log.info("  ok  %s self-test", name)

    # --- rig preflight (host only) ---
    problems = rig_problems(args.iface)
    if problems:
        log.error("RIG DOWN — skipping (exit 77):")
        for pr in problems:
            log.error("    %s", pr)
        log.error("Bring it up with: sudo bash tools/rig-up-rrnet-macos.sh %s",
                  args.iface)
        return 77
    log.info("rig up on %s: %s", args.iface, iface_state(args.iface))

    # --- build ---
    build_dir = PROJECT_ROOT / args.build
    if args.skip_build:
        run["build"] = fingerprint(build_dir)
    else:
        run["build"] = build_ip65(build_dir)
    assert_ip65_build(build_dir)
    L = load_labels(build_dir)
    check(True, f"BACKEND=ip65 build confirmed structurally "
                f"(ip65_blob.o in wireguard.map), sha256 "
                f"{run['build']['sha256'][:16]}…")

    # --- keys, randomised per run ---
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    c64_priv = bytes(rng.getrandbits(8) for _ in range(32))
    c64_pub = (X25519PrivateKey.from_private_bytes(c64_priv).public_key()
               .public_bytes(Encoding.Raw, PublicFormat.Raw))
    host_priv = bytes(rng.getrandbits(8) for _ in range(32))
    host_pub = (X25519PrivateKey.from_private_bytes(host_priv).public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw))
    log.info("c64 static pub %s… / host static pub %s… (private keys are "
             "never logged)", c64_pub.hex()[:16], host_pub.hex()[:16])

    # --- capture BEFORE the device boots, so DHCP is in it ---
    cap = Capture(args.capture, args.iface, args.pcap)
    if not cap.start():
        log.warning("continuing WITHOUT a capture: %s", cap.note)
    run["capture"] = {"mode": cap.mode, "note": cap.note, "path": args.pcap}

    probe = probe_u64(args.host)
    if not probe.reachable:
        log.error("device %s not reachable: %s", args.host, probe.error)
        cap.stop()
        return 1
    log.info("probe: %s", probe)

    lock = DeviceLock(args.host)
    try:
        lock.acquire_or_raise(timeout=LOCK_TIMEOUT_S)
    except DeviceLockTimeout as exc:
        log.error("DeviceLock busy after %.0fs: %s — another lane has the "
                  "device; doing nothing rather than racing it",
                  LOCK_TIMEOUT_S, exc)
        cap.stop()
        return 77

    client = None
    cart_prev: Optional[str] = None
    transport: dict = {}
    try:
        client = Ultimate64Client(host=args.host, timeout=30.0)
        tr = Ultimate64Transport(host=args.host, timeout=30.0, client=client)
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner wedged: %s — recovering", exc)
            recover(client)
            runner_health_check(client)
        # REU off: this is a REU=0 build, and inheriting another lane's REU
        # attachment is exactly the kind of state that makes a failure look
        # like ours.
        set_reu(client, False)
        time.sleep(0.5)

        # 1. Cartridge Preference = External. Volatile (reverts to Auto on
        #    reboot) so it is set per run, and the previous value is kept
        #    for teardown — the harness's snapshot_state does NOT cover
        #    this item, only `Cartridge`, which is the preset.
        sample_de00(tr, run, "1-before-External")
        cart_prev = set_cartridge_external(client, run)
        sample_de00(tr, run, "2-after-External")

        # 2. Bench health FIRST, at every requested clock, before our build
        #    is loaded at all. Stock ip65 on this silicon is the control: if
        #    it cannot ping, the bench is wrong and nothing about our build
        #    can be concluded from a later failure.
        #
        #    Running it at BOTH clocks is what makes CPU speed a declared
        #    axis cheaply. The open question is whether the U64 times
        #    CS8900a register cycles at $DE00 correctly at 48 MHz, and a
        #    ping answers that in seconds — it is pure cartridge-port I/O
        #    with no crypto. Answering the same question with a 1 MHz
        #    handshake would cost 2.8 hours of a shared device (see
        #    handshake_budget) and confound the two variables.
        health = {}
        for mhz in args.speeds:
            health[mhz] = stage_bench_health(tr, client, run, mhz)
        run["bench_health"] = {str(k): v for k, v in health.items()}
        if not any(health.values()):
            raise RuntimeError(
                f"the stock-ip65 ping control failed at every requested "
                f"clock {args.speeds}. The bench is wrong, or the 10.0.66 "
                f"re-target of pingstatic is wrong — those are NOT "
                f"distinguishable from here, because only the 169.254 "
                f"variant has ever been measured on the wire. Stopping "
                f"rather than running our build and misattributing it.")
        if not health.get(args.turbo, False):
            log.warning("the control did NOT pass at %d MHz, the clock the "
                        "handshake will use. Continuing, but a failure below "
                        "is confounded with cartridge-port timing at that "
                        "clock — say so in the report.", args.turbo)

        with HostPeer(host_priv, c64_pub) as peer:
            log.info("host responder listening on %s:%d", HOST_IP, WG_PORT)
            if not stage_boot_and_dhcp(tr, client, L, args, run):
                raise RuntimeError("Stage A failed; later stages cannot mean "
                                   "anything without a lease")
            stage_config(tr, L, c64_priv, c64_pub, host_pub)
            if stage_handshake(tr, client, L, peer, args, run):
                transport = stage_transport(tr, L, peer, rng, run)
                # INTO THE ARTIFACT. stage_transport's result was passed to
                # stage_wire and then dropped, so the JSON — the thing most
                # likely to outlive the log — carried the sentinel but NOT
                # the two randomised payloads, the msg_port, the receive
                # counters or what the host actually decrypted. An auditor
                # holding only the JSON could not re-verify the headline
                # absence claim, because the needles it was made with were
                # only ever prose in a log line.
                run["transport"] = transport
                # The control goes on the wire LAST, so it cannot be mistaken
                # for part of the tunnel exchange, and while the capture is
                # certainly still running.
                # THE SENTINEL IS CONDITIONAL, and that is load-bearing.
                # Sent unconditionally it manufactures the very corpus that
                # makes the search look meaningful: if the C64 wedges after
                # DHCP, the Mac's own ARP/mDNS/dnsmasq chatter plus this
                # datagram satisfies every guard in check_plaintext_absent,
                # the control is found, and BOTH absence checks pass on a
                # capture the C64 never contributed a byte to. So it goes on
                # the wire only once the responder has actually decrypted
                # something from the C64.
                if peer.type4_in > 0:
                    sentinel = "".join(
                        rng.choice(string.ascii_uppercase + string.digits)
                        for _ in range(24))
                    run["cleartext_sentinel"] = sentinel
                    if send_cleartext_control(run["c64_ip"],
                                              sentinel.encode()):
                        log.info("cleartext control sentinel on the wire: %s "
                                 "(sent because the C64 has transmitted: "
                                 "%d type-4 decrypted)", sentinel,
                                 peer.type4_in)
                    else:
                        run.pop("cleartext_sentinel", None)
                else:
                    log.warning("NOT sending the cleartext sentinel: the "
                                "responder has decrypted nothing from the "
                                "C64, so a found sentinel would only prove "
                                "the Mac can talk to itself. The absence "
                                "checks will record INCONCLUSIVE.")
            if peer.errors:
                log.warning("host responder recorded %d error(s): %s",
                            len(peer.errors), peer.errors[:5])
            run["peer"] = {"handshake_complete": peer.handshake_complete,
                           "type1_seen": peer.type1_seen,
                           "type2_sent": peer.type2_sent,
                           "type4_in": peer.type4_in,
                           "errors": peer.errors}
    except Exception as exc:                                  # noqa: BLE001
        log.error("run aborted: %s: %s", type(exc).__name__, exc)
        check(False, "the run completed without aborting", f"{exc}")
    finally:
        # Restore, and restore on the ABORT path too — that is the path
        # where it matters most, and the one where "restore" statements
        # chained onto a successful teardown quietly do not run. Clock and
        # REU in one try, the reset in its own: the reset is what leaves
        # the command interface idle for whoever has the device next, and
        # it must happen even when the clock restore is what failed.
        if client is not None:
            try:
                set_turbo_mhz(client, 1)
                time.sleep(1.0)
                actual = get_turbo_mhz(client)
                set_reu(client, False)
                log.info("restore: turbo=%d MHz (restored=%s), REU off",
                         actual, actual == 1)
                run["restored_mhz"] = actual
            except Exception as exc:                          # noqa: BLE001
                log.error("clock/REU restore FAILED: %s — the device is "
                          "shared, check it before you walk away", exc)
            try:
                if cart_prev:
                    client.set_config_item(CAT_CART, ITEM_CART_PREF, cart_prev)
                    log.info("restore: %s back to %r", ITEM_CART_PREF,
                             cart_prev)
            except Exception as exc:                          # noqa: BLE001
                log.error("could not restore %s to %r: %s — the device is "
                          "shared and this item is not covered by the "
                          "harness's snapshot_state", ITEM_CART_PREF,
                          cart_prev, exc)
            try:
                client.reset()
                time.sleep(1.0)
                log.info("restore: C64 reset")
            except Exception as exc:                          # noqa: BLE001
                log.error("reset FAILED: %s — our PRG may still be running "
                          "and driving the command interface for the next "
                          "lane", exc)
        lock.release()
        log.info("device lock released")

    # stage_wire owns cap.stop(): the capture must be flushed and the run
    # window closed in one place, so the bracket it filters on is the same
    # object that recorded the start.
    stage_wire(cap, run, transport)

    import json
    log.info("RUN:\n%s", json.dumps(run, indent=2, default=str))
    return summarise()


if __name__ == "__main__":
    sys.exit(main())
