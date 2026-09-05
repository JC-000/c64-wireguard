#!/usr/bin/env python3
"""test_ip65_udp_echo_vice.py — ip65 datagram sizes on the wire (issue #70).

OPT-IN, VICE-ethernet only. Exit 77 (skipped) when the feth/pcap rig is
not up; deliberately NOT in tools/run_regression.py.

WHAT IT PROVES
==============

The ip65 backend advertises NET_UDP_SEND_MAX = NET_UDP_RECV_MAX = 1472 and
the WG_MTU1440=1 build raises this consumer's WG_DATAGRAM_CAP to match, so
WG_MTU becomes 1440. That is a claim about the WIRE, and the only honest
check is at a wire tap:

  OUTBOUND  for each datagram size in SIZES, stage a payload of
            size - 32 bytes and run the REAL transport_send (the WG_MTU
            gate + transport_encrypt + session_stage_dest + ip65's
            net_udp_send, unstubbed) towards a UDP echo host on feth1.
            tcpdump on feth1 must see EXACTLY ONE UDP datagram of exactly
            that size from the C64 per send — a torn send is two, and a
            clamped send is the wrong length. The host decrypts it with
            the staged key (a valid Type-4 of all the bytes) and the
            plaintext must be absent from the wire bytes.
  INBOUND   the echo host answers each accepted send with a reply of
            1452 or 1472 bytes drawn from a DISJOINT byte alphabet.
            The C64 must deliver it WHOLE: udp_recv_len == reply length
            AND udp_recv_buf[:len] == the reply bytes (the request
            alphabet cannot satisfy this, so an echo cannot pass).
            Every reply is also counted at the tap.

WHICH INVOCATION IS THE RED ONE
===============================

Both invocations are GREEN when the tree is correct, because each asserts
what its own build promises:

  python3 tools/test_ip65_udp_echo_vice.py              (WG_MTU1440=0)
      WG_MTU 860. 888-892 must go out whole; 893/1452/1472 must be
      REFUSED by transport_send's 16-bit gate — C=1, tp_packet_len
      untouched, send counter unconsumed, nothing on the wire. A build
      that accepted them would be claiming a capacity it does not have.
      NOTE this arm now builds with WG_MTU1440=0 SPELLED OUT: since
      v1.2.0 the knob defaults to 1 under BACKEND=ip65, so a bare
      `make BACKEND=ip65` is the 1440 build.

  python3 tools/test_ip65_udp_echo_vice.py --mtu1440    (WG_MTU1440=1,
      i.e. the ip65 DEFAULT build and the shipped RR-Net artifact)
      WG_MTU 1440. ALL SEVEN sizes must go out as exactly one datagram.

Both expectations are derived from the BUILD's own exported WG_MTU, so
what this suite actually discriminates is the build's CLAIM against the
WIRE. The reproducible RED is therefore:

    C64_SKIP_BUILD=1 python3 tools/test_ip65_udp_echo_vice.py

over a tree whose labels.txt says WG_MTU = 1440 but whose backend cannot
deliver it — a knob that raised the equates without raising
WG_DATAGRAM_CAP, a transport_send gate left at 860, a torn or clamped
send. Every size is then expected to go out whole and the shortfall is
named per size. That is the failure this suite exists to catch; whether
the Makefile has the knob at all is test_build_mtu1440.py's job.

Historical red, for the record: on master fa5b11a — before the #70 port
fix and under this suite's pre-#118 unconditional "must send" assertion —
the default build scored 42/52, the 893/1452/1472 rows refused by the 860
gate and every accepted datagram leaving for a byte-swapped destination
port (src/net/ip65/net.s copied the big-endian net_udp_dest_port raw into
ip65's little-endian cell). The port assertion below still guards that.

Sizes are UDP payload sizes on the wire, i.e. Type-4 datagram sizes:
888/889/891/892 sit at the old UCI ceiling, 893 is the first byte past
it, 1452 is the largest datagram the U64 firmware could once take, 1472
is the IPv4 1500-byte MTU ceiling (1500 - 20 - 8).

HOW THE C64 IS DRIVEN
=====================

DHCP needs honest speed and the real main loop ('I' via the KERNAL queue,
warp OFF — see tools/vice_eth_rig.py). Once net_initialized is set, the
suite takes the machine over with the harness's jsr() trampoline: from
then on main_loop never runs again, so udp_recv_buf cannot be consumed by
session_handle_packet between the reply arriving and this test reading
it, and every net_poll is one we issued. The CPU is paused between
calls; frames wait in the BPF buffer.

ip65 fails a send whose destination is not in its ARP cache (it emits
the ARP request and returns C=1, ip65/ip.s), so the suite warms the
cache with a throwaway datagram on a side port before the sweep.

Randomised per run: the request payload bytes, the reply bytes, the
echo port and the session key/index/counter — seeded, the seed logged
once and reproducible via --seed / $TEST_SEED. Fixed markers only as a
suffix.

Usage::

    python3 tools/test_ip65_udp_echo_vice.py [--mtu1440] [--seed S] [--verbose]

    C64_SKIP_BUILD=1   reuse build/wireguard.prg as found
    --mtu1440          build with WG_MTU1440=1 (default: plain BACKEND=ip65)

Exit codes: 0 PASS / 1 FAIL / 77 SKIP (rig absent).
"""

from __future__ import annotations

import argparse
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

from c64_test_harness import Labels, jsr, read_bytes, write_bytes  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    CLASSIFIER_CASES, DEFAULT_VICE_BIN, HOST_IP, LABELS_PATH, PRG_PATH,
    EthVice, Tap, assert_ip65_build, boot_and_net_init, build_ip65, c64_ip,
    log, selftest_classifier, skip_if_rig_down,
)

SIZES = (888, 889, 891, 892, 893, 1452, 1472)      # datagram (UDP payload)
REPLY_SIZES = (1452, 1472)
WG_DATA_OVERHEAD = 32
T4_HDR_LEN = 16

# Disjoint byte alphabets: a reply that merely echoed the request could
# never satisfy the inbound check.
REQUEST_BYTE_ALPHABET = bytes(range(0x00, 0x80))
REPLY_BYTE_ALPHABET = bytes(range(0x80, 0x100))
REQUEST_SUFFIX = b"C64>"      # fixed markers only as a suffix
REPLY_SUFFIX = b"\xF0\xF0\xF0\xF0"

# Scratch past jsr()'s own $0334 trampoline and below screen RAM.
TRAMP = 0x0340        # JSR transport_send; PHP; PLA; AND #1; STA CARRY; RTS
CARRY = 0x0360
SEND_TRAMP = 0x0370   # JSR net_udp_send; PHP; PLA; AND #1; STA CARRY; RTS

WIRE_SETTLE = 2.0     # seconds to let tcpdump print a line
RECV_POLLS = 200      # net_poll calls to wait for one inbound datagram

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


# ============================================================================
# Payloads
# ============================================================================

def _payload(n: int, rng: random.Random) -> bytes:
    body = bytes(rng.choice(REQUEST_BYTE_ALPHABET) for _ in range(n - len(REQUEST_SUFFIX)))
    return body + REQUEST_SUFFIX


def _reply(n: int, rng: random.Random) -> bytes:
    body = bytes(rng.choice(REPLY_BYTE_ALPHABET) for _ in range(n - len(REPLY_SUFFIX)))
    return body + REPLY_SUFFIX


# ============================================================================
# Echo host
# ============================================================================

def swapped(port: int) -> int:
    return ((port & 0xFF) << 8) | (port >> 8)


class EchoHost:
    """UDP sockets on HOST_IP:port AND HOST_IP:swapped(port).

    The second socket is a DIAGNOSTIC, not a tolerance. The datagram's
    destination port is asserted separately per size; listening on the
    byte-swapped port too means a backend that swaps the port (ip65 on
    master, measured 2026-09-03: staged $B7 $99 arrived at 0x99B7) still
    gets its sizes, content and replies measured instead of every later
    check failing for the one upstream reason. Each received datagram
    records which port it landed on.
    """

    def __init__(self, port: int):
        self.port = port
        self.socks: dict[int, socket.socket] = {}
        for p in (port, swapped(port)):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST_IP, p))
            s.setblocking(False)
            self.socks[p] = s
        self.reply: bytes | None = None
        self.received: list[tuple[bytes, tuple[str, int], int]] = []
        self._stop = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        import select
        while not self._stop:
            try:
                ready, _, _ = select.select(list(self.socks.values()), [], [], 0.2)
            except (OSError, ValueError):
                break
            for s in ready:
                try:
                    data, addr = s.recvfrom(65535)
                except OSError:
                    continue
                port = s.getsockname()[1]
                with self._lock:
                    self.received.append((data, addr, port))
                    reply = self.reply
                if reply is not None:
                    s.sendto(reply, addr)

    def take(self) -> list[tuple[bytes, tuple[str, int], int]]:
        with self._lock:
            out, self.received = self.received, []
            return out

    def close(self) -> None:
        self._stop = True
        for s in self.socks.values():
            s.close()


# ============================================================================
# C64 side
# ============================================================================

def install_trampolines(tr, L) -> None:
    ts = L["transport_send"]
    code = bytes([
        0x20, ts & 0xFF, ts >> 8,                       # JSR transport_send
        0x08, 0x68, 0x29, 0x01,                         # PHP PLA AND #1
        0x8D, CARRY & 0xFF, CARRY >> 8,                 # STA CARRY
        0x60,                                           # RTS
    ])
    write_bytes(tr, TRAMP, code)
    # The park loop jsr()'s trampoline falls into after its NOPs: $0334
    # JSR/NOP/NOP then $0339 JMP $0339, so resume() spins here harmlessly.
    write_bytes(tr, PARK, bytes([0x4C, PARK & 0xFF, PARK >> 8]))


def set_dest(tr, L, ip: str, port: int) -> None:
    write_bytes(tr, L["net_udp_dest_ip"], bytes(int(o) for o in ip.split(".")))
    # Big-endian, like cfg_peer_endpoint_port (ip65 wants network order).
    write_bytes(tr, L["net_udp_dest_port"], bytes([port >> 8, port & 0xFF]))
    # session_stage_dest copies wg_peer_ip/port -> net_udp_dest_* before a
    # transport send, so stage the peer too.
    write_bytes(tr, L["wg_peer_ip"], bytes(int(o) for o in ip.split(".")))
    write_bytes(tr, L["wg_peer_port"], bytes([port >> 8, port & 0xFF]))


def raw_send_ax(tr, L, payload: bytes) -> int:
    """net_udp_send with A/X = udp_recv_buf, via its own trampoline.

    transport_send loads A/X itself; net_udp_send takes the buffer in
    A/X, and jsr() does not preload registers, so the trampoline does.
    """
    buf = L["udp_recv_buf"]
    ns = L["net_udp_send"]
    code = bytes([
        0xA9, buf & 0xFF,                               # LDA #<buf
        0xA2, buf >> 8,                                 # LDX #>buf
        0x20, ns & 0xFF, ns >> 8,                       # JSR net_udp_send
        0x08, 0x68, 0x29, 0x01,                         # PHP PLA AND #1
        0x8D, CARRY & 0xFF, CARRY >> 8,                 # STA CARRY
        0x60,                                           # RTS
    ])
    write_bytes(tr, SEND_TRAMP, code)
    write_bytes(tr, buf, payload)
    write_bytes(tr, L["net_udp_send_len"], struct.pack("<H", len(payload)))
    write_bytes(tr, CARRY, b"\x00")
    jsr(tr, SEND_TRAMP, timeout=30.0)
    return read_bytes(tr, CARRY, 1)[0]


PARK = 0x0339         # JMP $0339: where the CPU spins when we let it run


def run_free(tr, secs: float) -> None:
    """Let the emulator RUN for *secs* with the CPU parked in JMP $0339.

    VICE services the CS8900a from its own clock alarms: TX frames are
    flushed and pcap is polled for RX only while the emulation advances.
    After jsr() the CPU is paused at the trampoline, so a send that
    returned C=0 has not necessarily left the machine and a reply cannot
    arrive. Measured 2026-09-03: with the CPU paused between calls the
    wire tap saw NOTHING for five accepted sends. Resuming into the park
    loop (written by install_trampolines) lets the NIC breathe without
    main_loop ever running again.
    """
    tr.resume()
    time.sleep(secs)


def net_poll(tr, L) -> None:
    run_free(tr, 0.05)
    jsr(tr, L["net_poll"], timeout=30.0)


def clear_recv(tr, L) -> None:
    write_bytes(tr, L["udp_recv_ready"], b"\x00")
    write_bytes(tr, L["udp_recv_len"], b"\x00\x00")


def wait_recv(tr, L, polls: int = RECV_POLLS) -> tuple[int, bytes] | None:
    """net_poll until udp_recv_ready; returns (len, bytes) or None."""
    for _ in range(polls):
        net_poll(tr, L)
        if read_bytes(tr, L["udp_recv_ready"], 1)[0]:
            n = int.from_bytes(read_bytes(tr, L["udp_recv_len"], 2), "little")
            data = bytes(read_bytes(tr, L["udp_recv_buf"], n)) if n else b""
            return n, data
    return None


def warm_arp(tr, L, port: int) -> bool:
    """Make ip65 resolve the host's MAC: send, poll, retry until C=0."""
    for attempt in range(12):
        c = raw_send_ax(tr, L, b"ARP?")
        run_free(tr, 0.3)
        if c == 0:
            vlog(f"  ARP warm: send accepted on attempt {attempt + 1}")
            return True
        for _ in range(25):
            net_poll(tr, L)
    return False


def transport_send(tr, L, payload: bytes, key: bytes, recv_idx: bytes,
                   counter: int) -> tuple[int, int]:
    """Stage payload + session and JSR transport_send. Returns (C, tp_packet_len)."""
    buf = L["udp_recv_buf"]      # 1500 B staging area, also the recv target
    write_bytes(tr, L["hs_transport_send"], key)
    write_bytes(tr, L["tp_peer_recv_idx"], recv_idx)
    write_bytes(tr, L["tp_send_counter"], struct.pack("<Q", counter))
    write_bytes(tr, buf, payload)
    write_bytes(tr, L["tp_payload_ptr"], struct.pack("<H", buf))
    write_bytes(tr, L["tp_payload_len"], struct.pack("<H", len(payload)))
    write_bytes(tr, L["tp_packet_len"], b"\xEE\xEE")
    write_bytes(tr, CARRY, b"\x00")
    jsr(tr, TRAMP, timeout=60.0)
    c = read_bytes(tr, CARRY, 1)[0]
    tp_len = int.from_bytes(read_bytes(tr, L["tp_packet_len"], 2), "little")
    return c, tp_len


# ============================================================================
# The sweep
# ============================================================================

def draw_port(rng: random.Random) -> int:
    """A port whose byte-swap is also bindable and distinct.

    EchoHost binds both `port` and `swapped(port)` (see its docstring),
    so the draw has to exclude two families that would crash the run
    rather than measure anything — roughly 2% of seeds:

      * low byte 0-3  -> swapped(port) < 1024, a privileged port:
                         PermissionError on bind as uid 501.
      * low byte == high byte -> swapped(port) == port: the second bind
                         is the same address and fails EADDRINUSE.

    Also keeps side_port (= port + 1, the ARP warm-up) out of the pair so
    the warm-up datagrams cannot be counted by the sweep's tap filter.
    """
    while True:
        p = rng.randint(40000, 60000)
        alt = swapped(p)
        if alt >= 1024 and alt != p and p + 1 != alt:
            return p


def run_sweep(tr, L, rng: random.Random, mtu: int) -> None:
    c64 = c64_ip(tr, L)
    port = draw_port(rng)
    side_port = port + 1
    log(f"  C64 at {c64} (ip65 cfg_ip); echo host {HOST_IP}:{port} "
        f"(+ byte-swap diagnostic :{swapped(port)}); "
        f"ARP warm-up on :{side_port}")

    local_port = int.from_bytes(read_bytes(tr, L["wg_local_port"], 2), "little")
    log(f"  C64 listening on wg_local_port {local_port}")

    key = bytes(rng.randint(0, 255) for _ in range(32))
    recv_idx = bytes(rng.randint(0, 255) for _ in range(4))
    counter = rng.randint(0, 0xFFFF)
    aead = ChaCha20Poly1305(key)

    install_trampolines(tr, L)
    alt = swapped(port)
    with Tap(f"udp port {port} or udp port {alt}") as tap:
        host = EchoHost(port)
        try:
            # --- ARP warm-up on the side port (not counted by the tap filter) ---
            set_dest(tr, L, HOST_IP, side_port)
            if not check(warm_arp(tr, L, side_port),
                         "ip65 resolved the host's MAC (ARP warm-up send accepted)"):
                return
            set_dest(tr, L, HOST_IP, port)
            clear_recv(tr, L)

            reply_cycle = list(REPLY_SIZES)
            rng.shuffle(reply_cycle)
            sent_ok = 0
            for i, size in enumerate(SIZES):
                payload = _payload(size - WG_DATA_OVERHEAD, rng)
                reply_len = reply_cycle[i % len(reply_cycle)]
                reply = _reply(reply_len, rng)
                host.reply = reply
                host.take()
                before_out = len(tap.udp(c64, HOST_IP))
                before_in = len(tap.udp(HOST_IP, c64))
                clear_recv(tr, L)
                expected_refusal = size - WG_DATA_OVERHEAD > mtu

                log(f"\n--- {size}-byte datagram ({size - WG_DATA_OVERHEAD}-byte "
                    f"payload) -> reply {reply_len} ---")
                c, tp_len = transport_send(tr, L, payload, key, recv_idx,
                                           counter)
                counter_after = int.from_bytes(
                    read_bytes(tr, L["tp_send_counter"], 8), "little")
                run_free(tr, WIRE_SETTLE)      # NIC flushes only while running
                outs = tap.udp(c64, HOST_IP)[before_out:]

                if expected_refusal:
                    # On a build whose WG_MTU cannot carry this payload, the
                    # REFUSAL is the correct behaviour and therefore the PASS:
                    # transport_send's 16-bit gate must return C=1 and nothing
                    # may reach the wire. Asserting C=0 here regardless (as
                    # this suite did until the #118 review) made a plain run
                    # fail four checks by construction on the default build,
                    # which trains the reader to expect red. The red proof for
                    # the knob lives in running this suite WITHOUT --mtu1440
                    # against a tree that claims 1440: see the header.
                    check(c == 1,
                          f"{size}: refused (C=1) — {size - WG_DATA_OVERHEAD} "
                          f"B payload is over this build's WG_MTU {mtu}",
                          f"C={c}: accepted a payload this build cannot carry")
                    check(not outs,
                          f"{size}: nothing reached the wire after the refusal",
                          f"tap (dport, len) after this send: {outs}")
                    check(tp_len == 0xEEEE,
                          f"{size}: tp_packet_len untouched (no encrypt ran)",
                          f"tp_packet_len = {tp_len}")
                    check(counter_after == counter,
                          f"{size}: send counter not consumed by a refusal",
                          f"{counter} -> {counter_after}")
                    continue

                ok = check(c == 0,
                           f"{size}: transport_send accepted (C=0)",
                           f"C=1: refused by the WG_MTU gate — this build's "
                           f"WG_MTU is {mtu}, the payload is "
                           f"{size - WG_DATA_OVERHEAD}")
                check(len(outs) == 1 and outs[0].length == size,
                      f"{size}: tap saw EXACTLY one {size}-byte datagram "
                      f"C64->host", f"tap rows after this send: {outs}; "
                      f"fragments so far: {tap.fragments()}")
                if not ok:
                    continue
                # The destination port is staged big-endian in wg_peer_port,
                # exactly as cfg_peer_endpoint_port stores it (net_abi.inc:
                # net_udp_dest_port is big-endian; the UCI backend swaps on
                # push). A datagram at swapped(port) is the ip65 backend
                # copying it raw into ip65's little-endian udp_send_dest_port.
                check(bool(outs) and outs[0].dport == port,
                      f"{size}: datagram went to the staged port {port} "
                      f"(not byte-swapped {alt})",
                      f"wire dport = {outs[0].dport if outs else None}: "
                      "src/net/ip65/net.s copies net_udp_dest_port raw into "
                      "ip65's LITTLE-endian udp_send_dest_port")
                # wg_local_port is the one LITTLE-endian port cell in the
                # tree; a byte-order slip there would flip send and listen
                # together and leave every size/content check green.
                check(bool(outs) and outs[0].sport == local_port,
                      f"{size}: datagram left FROM the listening port "
                      f"{local_port}",
                      f"wire sport = {outs[0].sport if outs else None}")
                sent_ok += 1
                check(tp_len == size, f"{size}: tp_packet_len == {size}",
                      f"got {tp_len}")
                check(counter_after == counter + 1,
                      f"{size}: send counter advanced", f"{counter} -> {counter_after}")

                got = host.take()
                check(len(got) == 1 and len(got[0][0]) == size,
                      f"{size}: echo host received one {size}-byte datagram",
                      f"host got {[(len(d), p) for d, _, p in got]}")
                if got:
                    pkt = got[0][0]
                    nonce = b"\x00" * 4 + struct.pack("<Q", counter)
                    try:
                        plain = aead.decrypt(nonce, pkt[T4_HDR_LEN:], None)
                    except Exception as exc:                  # noqa: BLE001
                        plain, why = None, f"decrypt raised {type(exc).__name__}"
                    else:
                        why = "host AEAD accepts the C64's ciphertext+tag"
                    check(plain == payload and pkt[0] == 4
                          and pkt[4:8] == recv_idx,
                          f"{size}: a valid Type-4 of all {size} bytes "
                          f"(decrypts to the staged payload)", why)
                    check(payload[:32] not in pkt,
                          f"{size}: plaintext absent from the wire bytes")
                counter += 1

                # --- the reply, delivered whole ---
                got_in = wait_recv(tr, L)
                time.sleep(0.5)
                ins = tap.udp(HOST_IP, c64)[before_in:]
                check(len(ins) == 1 and ins[0].length == reply_len,
                      f"{size}: tap saw exactly one {reply_len}-byte reply "
                      "host->C64", f"tap rows: {ins}")
                if got_in is None:
                    check(False, f"{size}: C64 received the {reply_len}-byte "
                          "reply", f"udp_recv_ready never set in {RECV_POLLS} "
                          "net_poll calls")
                    continue
                n, data = got_in
                check(n == reply_len,
                      f"{size}: udp_recv_len == {reply_len} (whole datagram)",
                      f"udp_recv_len = {n}")
                check(data == reply,
                      f"{size}: udp_recv_buf[:{reply_len}] == the reply bytes "
                      "(reply alphabet, not an echo)",
                      f"first diff at "
                      f"{next((k for k in range(min(len(data), len(reply))) if data[k] != reply[k]), 'none')}"
                      f"; got {len(data)} B")
            check(tap.fragments() == 0, "no IP fragments seen on the tap",
                  f"{tap.fragments()} fragment rows")
            log(f"\n  {sent_ok}/{len(SIZES)} sizes accepted by transport_send "
                f"(build WG_MTU {mtu})")
        finally:
            host.close()
            if VERBOSE:
                for line in tap.raw[-40:]:
                    log(f"      tap: {line}")


# ============================================================================
# main
# ============================================================================

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--mtu1440", action="store_true",
                    help="build with WG_MTU1440=1 (ignored under C64_SKIP_BUILD)")
    ap.add_argument("--seed", type=int,
                    default=int(os.environ.get("TEST_SEED", "0")) or None)
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    VERBOSE = args.verbose

    seed = args.seed if args.seed is not None else random.randint(1, 2**31 - 1)
    rng = random.Random(seed)
    log("test_ip65_udp_echo_vice.py — issue #70 (ip65 datagram sizes)")
    log(f"Random seed: {seed} (reproduce with --seed {seed})")

    bad = selftest_classifier()
    check(not bad, "wire-tap fragment classifier passes its alarm proof "
          f"({len(CLASSIFIER_CASES)} captured line shapes)", "\n".join(bad))
    if bad:
        return 1

    skip_if_rig_down(args.vice_bin)

    # WG_MTU1440 defaults to 1 under BACKEND=ip65 (v1.2.0 ships RR-Net
    # at 1440 only), so the 860 arm must spell the opt-out out — a bare
    # `make BACKEND=ip65` is the 1440 build now.
    build_ip65(["WG_MTU1440=1"] if args.mtu1440 else ["WG_MTU1440=0"])
    for path in (PRG_PATH, LABELS_PATH):
        if not os.path.exists(path):
            log(f"FATAL: missing {path}")
            return 1
    assert_ip65_build()
    L = Labels.from_file(LABELS_PATH)
    required = ["boot_ready", "net_initialized", "ip65_blob_start",
                "transport_send", "net_udp_send", "net_poll", "udp_recv_buf",
                "udp_recv_len", "udp_recv_ready", "net_udp_send_len",
                "net_udp_dest_ip", "net_udp_dest_port", "wg_peer_ip",
                "wg_peer_port", "hs_transport_send", "tp_peer_recv_idx",
                "tp_send_counter", "tp_payload_ptr", "tp_payload_len",
                "tp_packet_len", "WG_MTU"]
    required.append("wg_local_port")
    missing = [n for n in required if L.address(n) is None]
    if missing:
        log(f"FATAL: labels missing: {missing}")
        return 1
    mtu = L["WG_MTU"]
    import hashlib
    log(f"  PRG sha256 {hashlib.sha256(open(PRG_PATH, 'rb').read()).hexdigest()}"
        f"  WG_MTU={mtu} NET_UDP_SEND_MAX={L['NET_UDP_SEND_MAX']} "
        f"NET_UDP_RECV_MAX={L['NET_UDP_RECV_MAX']}")

    t0 = time.monotonic()
    with EthVice(args.vice_bin, port=args.port) as vice:
        tr = vice.tr
        boot_and_net_init(tr, L)
        log("")
        log("=== Taking the machine over (jsr trampoline; main_loop is done) ===")
        run_sweep(tr, L, rng, mtu)

    passed = sum(1 for ok, _ in results if ok)
    failed = len(results) - passed
    log(f"\nResults: {passed}/{len(results)} passed, {failed} failed "
        f"({time.monotonic() - t0:.0f}s, seed {seed})")
    if failed:
        for ok, label in results:
            if not ok:
                log(f"  - {label}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
