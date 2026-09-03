#!/usr/bin/env python3
"""test_ip65_listener_leak.py — issue #84: ip65's net_udp_close never closed.

WHAT THIS PROVES
================

``net_udp_close`` in ``src/net/ip65/net.s`` was, on master ``875a841``::

    net_udp_close:
            clc
            rts

justified by a comment saying ip65's UDP is connectionless and there is "no
firmware-side socket handle to abandon".  The first clause is true and the
conclusion does not follow: the same sentence names the thing that leaks.
``udp_add_listener`` claims one entry in a **four**-entry table
(``ip65/ip65/udp.s``: ``udp_cbmax = 4``), keyed by port, and
``udp_remove_listener`` is the call that hands it back — reachable through
the blob's jump table at ``ip65_base + 15``.  Nothing in the tree had ever
called it.

So the shipped ``wireguard-rrnet-*.prg`` leaked a table entry per listen and
reported success having done nothing.  This test drives that table directly
and asserts the difference.

METHOD
======

1. Boot the BACKEND=ip65 PRG under an ethernet-capable VICE with RR-Net, and
   press ``I`` so ``do_net_init`` runs the real path: ``ip65_init`` (which
   zeroes ``udp_cbcount``), DHCP, then ``net_udp_listen``.
2. Locate ``udp_cbcount`` inside the blob's BSS.  It is a module-private
   ``.bss`` symbol, so it is not in the map; its address is DERIVED from the
   exported ``udp_send_len`` plus the byte layout declared in the vendored
   ``ip65/ip65/udp.s``, and then CHECKED against the machine — it must read
   exactly 1 after do_net_init's single listen.  A derivation that lands on
   the wrong byte fails here rather than silently measuring nothing.
3. Cycle A — same port, the case the app actually hits: call
   ``net_udp_close`` then ``net_udp_listen`` on ``wg_local_port``, five
   times.  ``udp_add_listener`` REFUSES a port already in the table (its
   ``@busy`` leg), so on master the second listen fails outright.
4. Cycle B — four distinct ports, the exhaustion case the issue names:
   listen/close on ports P..P+4.  On master each listen consumes a slot the
   close does not return, so the fifth is refused with the table full.
5. Cycle C — the #84 handshake deadline, end to end on a real backend.  The
   UCI half cannot be hardware-verified right now, but the part that is
   backend-independent — ``timer_check`` reaching HS_SENT at all, and
   ``session_reset`` handing the backend's resource back — is driven here
   against a real ip65 listener slot: arm the deadline, enter HS_SENT, wind
   ``session_start_jiffy`` back past 90 s, and watch the slot come back.
   Cycle C does not exist on master (``timer_handshake_start`` and
   ``hs_timer_armed`` are new), so it is only meaningful on this branch.
6. Cycle D — ``net_udp_send``'s two new edges: that it reports C=1 when it
   cannot reclaim a listener (the edge ``session_initiate``'s new failure
   path depends on), and that it does not touch the blob's table before
   ``ip65_init`` has ever run.  Also branch-only.

Both cycles are driven by a trampoline that captures the carry, so the
verdict is the routine's own return value, not an inference from screen text.

RUNNING IT AGAINST THE UNFIXED TREE
===================================

Cycles A and B use only symbols that exist on master ``875a841``, so the
committed file can be checked out onto an unfixed tree and watched to fail::

    git checkout 875a841
    git checkout <branch> -- tools/test_ip65_listener_leak.py
    make clean && make BACKEND=ip65
    C64_SKIP_BUILD=1 python3 tools/test_ip65_listener_leak.py

Cycles C and D need routines and state that #84 introduces; on such a tree
they SKIP with an explanation rather than aborting the run.  That split is
deliberate.  A regression test nobody can point at the broken code is not
evidence — this project has twice had green suites over broken code, and the
defence adopted is that the test must be SEEN to fail.

CURRENT STATUS: this test FAILS on master ``875a841`` and passes on the #84
branch.  It was run in both states — see the PR.  It is deliberately NOT in
``tools/run_regression.py``: it needs the privileged feth/pcap rig, which is
absent on most machines, and the gate is a 22/22 count that a SKIP would
muddy.  Same placement as ``tools/test_ip65_bss_corruption.py``.

RIG
===

Identical to ``tools/test_ip65_bss_corruption.py`` — the macOS feth/pcap rig
(one privileged setup per boot, done outside this test) plus an
ethernet-capable ``x64sc`` named by ``$VICE_ETHERNET_BIN``.  ``warp`` MUST
stay off: it compresses ip65's DHCP retry budget below dnsmasq's OFFER
latency and DHCP fails every time.  Budget ~25 s to boot and up to ~120 s
for DHCP.

Usage::

    python3 tools/test_ip65_listener_leak.py [--verbose]

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
    ViceConfig, ViceProcess,
)
# bpf_capture_available used to come from vice_lifecycle. The harness
# DELETED it in c3fe7aa ("ask whether VICE can get rawnet, not whether
# /dev/bpf* is open"), so this import had been raising ImportError and this
# suite could not start at all. Ask VICE's own gate instead.
from vice_eth_rig import (  # noqa: E402
    libpcap_node_note, vice_rawnet_problems,
)
from c64_test_harness.backends.vice_manager import PortAllocator  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
WG_MAP_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.map")
IP65_MAP_PATH = os.path.join(PROJECT_ROOT, "ip65-build", "ip65-c64.map")
UDP_SRC_PATH = os.path.join(PROJECT_ROOT, "ip65", "ip65", "udp.s")

HOST_IP = "10.0.65.1"
ETH_IFACE = "feth0"
DNSMASQ_PIDFILE = "/tmp/c64-rig-dnsmasq.pid"
DEFAULT_VICE_BIN = os.path.expanduser("~/opt/vice-eth/bin/x64sc")

KBD_BUFFER = 0x0277
KBD_COUNT = 0x00C6

# Trampoline: JSR target / LDA #0 / ROL A / STA carry_slot / NOP <- breakpoint.
# The harness's execute.jsr() cannot report the carry (read_registers has no
# flags), and the carry IS the contract for every routine under test here.
TRAMPOLINE_ADDR = 0x0334
CARRY_SLOT = 0x0340

BOOT_TIMEOUT = 180.0
DHCP_TIMEOUT = 120.0

NET_OK_NEEDLE = "LISTENING ON PORT"
NET_FAIL_NEEDLES = ("NET INIT FAILED", "DHCP FAILED", "LISTEN FAILED")

# Labels each part of the run needs.
#
# Split deliberately, and this split is load-bearing. Cycles A and B are the
# LEAK DEMONSTRATION and must be runnable against the unfixed tree — a
# regression test nobody can watch fail is not evidence of anything, and this
# project has twice shipped green suites over broken code. Every symbol they
# touch exists on master 875a841.
#
# Cycles C and D exercise routines and state that #84 INTRODUCES, so on an
# unfixed tree those labels are legitimately absent. Missing them SKIPS the
# cycle with an explanation; it must never abort the run, or the file could
# only ever be pointed at the tree it was written to pass on.
REQUIRED_LABELS = ["boot_ready", "wg_local_port", "net_udp_listen",
                   "net_udp_close"]
CYCLE_C_LABELS = ["wg_state", "hs_timer_armed", "session_start_jiffy",
                  "timer_check", "timer_handshake_start"]
CYCLE_D_LABELS = ["net_udp_send", "ip65_listening", "ip65_listen_port",
                  "net_udp_dest_ip", "net_udp_dest_port", "net_udp_send_len"]

VERBOSE = False


def log(msg: str) -> None:
    print(msg, flush=True)


def vlog(msg: str) -> None:
    if VERBOSE:
        print(msg, flush=True)


# ============================================================================
# Rig preflight (same prerequisites as test_ip65_bss_corruption.py)
# ============================================================================

def rig_problems(vice_bin: str) -> list[str]:
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["not macOS — this rig is the feth/pcap one from "
                "c64-https' tools/rig-up-macos.sh"]
    problems += vice_rawnet_problems(vice_bin)
    note = libpcap_node_note()
    if note:
        problems.append(note)
    r = subprocess.run(["ifconfig", ETH_IFACE], capture_output=True, text=True)
    if r.returncode != 0:
        problems.append(f"{ETH_IFACE} missing")
    r = subprocess.run(["ifconfig", "feth1"], capture_output=True, text=True)
    if r.returncode != 0 or f"inet {HOST_IP} " not in r.stdout:
        problems.append(f"feth1 missing or not at {HOST_IP}")
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
        pass
    except (OSError, ValueError):
        problems.append(f"rig dnsmasq not running ({DNSMASQ_PIDFILE} "
                        "stale or absent) — no DHCP server on the wire")
    return problems


# ============================================================================
# Locating udp_cbcount without hardcoding it
# ============================================================================

def map_symbol(path: str, name: str) -> int:
    """Find `name` in an ld65 map's exports table and return its address."""
    text = open(path).read()
    m = re.search(rf"(?m)^.*?\b{re.escape(name)}\s+([0-9A-Fa-f]{{6}})\s", text)
    if not m:
        raise RuntimeError(f"{path}: no symbol {name}")
    return int(m.group(1), 16)


def derive_udp_cbcount() -> tuple[int, int]:
    """Return (udp_cbcount address, udp_cbmax).

    ``udp_cbcount`` is module-private, so it is not exported and not in the
    map.  It IS at a fixed offset from ``udp_send_len``, which is exported,
    by the ``.bss`` declaration order in the vendored ``ip65/ip65/udp.s``::

        udp_send_len: .res 2
        udp_cbmax = 4
        udp_cbveclo:  .res udp_cbmax
        udp_cbvechi:  .res udp_cbmax
        udp_cbportlo: .res udp_cbmax
        udp_cbporthi: .res udp_cbmax
        udp_cbcount:  .res 1

    Both halves are read from the tree rather than typed in here: the
    address from ``ip65-build/ip65-c64.map``, the layout from ``udp.s``.  The
    result is then verified against the running machine before it is trusted
    (see check_derivation).
    """
    src = open(UDP_SRC_PATH).read()
    m = re.search(r"^udp_cbmax\s*=\s*(\d+)", src, re.M)
    if not m:
        raise RuntimeError(f"{UDP_SRC_PATH}: no udp_cbmax")
    cbmax = int(m.group(1))

    # Confirm the declaration order this arithmetic depends on.
    order = re.findall(r"^(udp_send_len|udp_cbveclo|udp_cbvechi|udp_cbportlo|"
                       r"udp_cbporthi|udp_cbcount):", src, re.M)
    expected = ["udp_send_len", "udp_cbveclo", "udp_cbvechi",
                "udp_cbportlo", "udp_cbporthi", "udp_cbcount"]
    if order != expected:
        raise RuntimeError(
            f"{UDP_SRC_PATH}: .bss declaration order changed ({order}); "
            "the udp_cbcount derivation below is no longer valid")

    base = map_symbol(IP65_MAP_PATH, "udp_send_len")
    return base + 2 + 4 * cbmax, cbmax


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
    addr = labels["boot_ready"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1) == b"\x01":
            return True
        tr.resume()
        time.sleep(1.0)
    return False


def press_key(tr, char: str, timeout: float = 15.0) -> bool:
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


def screen_text(tr) -> str:
    return ScreenGrid.from_transport(tr).continuous_text().upper()


def call_carry(tr, addr: int, timeout: float = 20.0, *,
               a: int | None = None, x: int | None = None) -> int:
    """JSR `addr` and return its carry (0 or 1).

    execute.jsr() cannot do this — read_registers exposes PC/A/X/Y/SP and no
    flags — and the carry is the entire contract of net_udp_listen and
    net_udp_close, so inferring it from side effects would be testing
    something else.
    """
    lo, hi = addr & 0xFF, (addr >> 8) & 0xFF
    clo, chi = CARRY_SLOT & 0xFF, (CARRY_SLOT >> 8) & 0xFF
    code = bytes([
        0x20, lo, hi,        # JSR addr
        0xA9, 0x00,          # LDA #$00
        0x2A,                # ROL A          -> A = carry
        0x8D, clo, chi,      # STA CARRY_SLOT
        0xEA,                # NOP            <- breakpoint
        0xEA,                # NOP
    ])
    tr.write_memory(TRAMPOLINE_ADDR, code)
    tr.write_memory(CARRY_SLOT, b"\xAA")      # poison: proves the store ran
    bp_addr = TRAMPOLINE_ADDR + 9
    bp_id = tr.set_checkpoint(bp_addr)
    try:
        regs = {"PC": TRAMPOLINE_ADDR}
        if a is not None:
            regs["A"] = a
        if x is not None:
            regs["X"] = x
        tr.set_registers(regs)
        tr.resume()
        tr.wait_for_stopped(timeout=timeout)
        after = tr.read_registers()
        if after.get("PC") != bp_addr:
            raise RuntimeError(
                f"call to ${addr:04X} did not return: stopped at "
                f"${after.get('PC', 0):04X}, expected ${bp_addr:04X}")
    finally:
        tr.delete_checkpoint(bp_id)
    got = tr.read_memory(CARRY_SLOT, 1)[0]
    if got not in (0, 1):
        raise RuntimeError(
            f"carry slot held ${got:02X} after calling ${addr:04X} — the "
            "trampoline did not run to completion")
    return got


def set_port(tr, addr: int, port: int) -> None:
    """wg_local_port is little-endian (net.s does lda lo / ldx hi)."""
    tr.write_memory(addr, bytes([port & 0xFF, (port >> 8) & 0xFF]))


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
    with open(WG_MAP_PATH) as fh:
        text = fh.read()
    if "ip65_blob.o" not in text:
        raise SystemExit(
            "FATAL: build/wireguard.map has no ip65_blob.o — this is not a "
            "BACKEND=ip65 build. Run `make clean && make BACKEND=ip65` (or "
            "unset C64_SKIP_BUILD).")


# ============================================================================
# The two cycles
# ============================================================================

def cycle_same_port(tr, L, cbcount_addr: int, rounds: int) -> list[str]:
    """close/listen on the app's own port, `rounds` times.

    This is the case the application actually hits: every teardown path added
    by #84 calls net_udp_close, and the next net_udp_send re-listens.
    udp_add_listener refuses a port already in the table, so a close that
    does nothing makes the very next listen fail.
    """
    failures = []
    port = int.from_bytes(tr.read_memory(L["wg_local_port"], 2), "little")
    log(f"--- Cycle A: close/listen on the app's own port {port}, "
        f"{rounds} rounds ---")
    for i in range(1, rounds + 1):
        c_close = call_carry(tr, L["net_udp_close"])
        n_after_close = tr.read_memory(cbcount_addr, 1)[0]
        c_listen = call_carry(tr, L["net_udp_listen"])
        n_after_listen = tr.read_memory(cbcount_addr, 1)[0]
        log(f"  round {i}: close C={c_close} udp_cbcount={n_after_close} | "
            f"listen C={c_listen} udp_cbcount={n_after_listen}")
        if c_close != 0:
            failures.append(f"A{i}: net_udp_close returned C=1")
        if n_after_close != 0:
            failures.append(
                f"A{i}: udp_cbcount={n_after_close} after close, expected 0 "
                "— the slot was not released")
        if c_listen != 0:
            failures.append(
                f"A{i}: net_udp_listen returned C=1 — the table still holds "
                f"port {port}, so the re-listen was refused")
        if n_after_listen != 1:
            failures.append(
                f"A{i}: udp_cbcount={n_after_listen} after listen, expected 1")
    return failures


def cycle_distinct_ports(tr, L, cbcount_addr: int, cbmax: int,
                         first_port: int) -> list[str]:
    """listen/close on cbmax+1 DISTINCT ports — the exhaustion case.

    On master every listen consumes a slot the close does not return, so the
    (cbmax+1)th listen is refused with IP65_ERROR_LISTENER_NOT_AVAILABLE.
    """
    failures = []
    rounds = cbmax + 1
    log(f"--- Cycle B: listen/close on {rounds} DISTINCT ports from "
        f"{first_port} (udp_cbmax={cbmax}) ---")

    # Clear the slate first. Cycle A leaves the app's own port registered,
    # and this cycle counts live entries — starting at 1 would make every
    # reading below one too high. On master this close does nothing, so the
    # slate does NOT clear, and the very first round reports it.
    call_carry(tr, L["net_udp_close"])
    n0 = tr.read_memory(cbcount_addr, 1)[0]
    log(f"  slate cleared: udp_cbcount={n0} (expected 0)")
    if n0 != 0:
        failures.append(
            f"B/pre: udp_cbcount={n0} after the slate-clearing close, "
            "expected 0 — nothing was released")

    for i in range(rounds):
        port = first_port + i
        set_port(tr, L["wg_local_port"], port)
        c_listen = call_carry(tr, L["net_udp_listen"])
        n_after_listen = tr.read_memory(cbcount_addr, 1)[0]
        c_close = call_carry(tr, L["net_udp_close"])
        n_after_close = tr.read_memory(cbcount_addr, 1)[0]
        log(f"  port {port}: listen C={c_listen} udp_cbcount={n_after_listen} | "
            f"close C={c_close} udp_cbcount={n_after_close}")
        if c_listen != 0:
            failures.append(
                f"B/{port}: net_udp_listen returned C=1 — the {cbmax}-entry "
                "table is exhausted by slots earlier closes did not return")
        if n_after_listen != 1:
            failures.append(
                f"B/{port}: udp_cbcount={n_after_listen} after listen, "
                "expected 1 (one live listener at a time)")
        if c_close != 0:
            failures.append(f"B/{port}: net_udp_close returned C=1")
        if n_after_close != 0:
            failures.append(
                f"B/{port}: udp_cbcount={n_after_close} after close, "
                "expected 0")
    return failures


SESSION_IDLE = 0
SESSION_HS_SENT = 1
HS_TIMEOUT_JIFFIES = 5400          # src/wg/timer.s: 90 s at 60 Hz


def read_jiffy(tr) -> int:
    """The KERNAL jiffy clock as one 24-bit value ($A0 hi, $A1 mid, $A2 lo)."""
    b = tr.read_memory(0xA0, 3)
    return (b[0] << 16) | (b[1] << 8) | b[2]


def cycle_handshake_deadline(tr, L, cbcount_addr: int) -> list[str]:
    """The #84 handshake deadline, end to end on a real backend.

    The UCI half of #84 cannot be hardware-verified right now, but the part
    that is backend-independent — timer_check reaching HS_SENT at all, and
    session_reset handing the backend's resource back — can be driven here,
    and the resource it hands back is a real ip65 listener slot.

    Sequence: claim a listener, arm the deadline, enter HS_SENT, confirm a
    timer_check BEFORE the deadline changes nothing, wind session_start_jiffy
    back past 90 s, and confirm the next timer_check drops to IDLE, disarms,
    and RETURNS THE SLOT.
    """
    failures = []
    log("--- Cycle C: the #84 handshake deadline releases the resource ---")

    # Precondition: a live listener on the app's port, as after do_net_init.
    set_port(tr, L["wg_local_port"], 51820)
    if call_carry(tr, L["net_udp_listen"]) != 0:
        return ["C: could not re-establish a listener to start from"]
    n = tr.read_memory(cbcount_addr, 1)[0]
    log(f"  listener claimed: udp_cbcount={n}")
    if n != 1:
        failures.append(f"C: udp_cbcount={n} after listen, expected 1")

    # Arm the deadline the way session_initiate does, then enter HS_SENT.
    call_carry(tr, L["timer_handshake_start"])
    tr.write_memory(L["wg_state"], bytes([SESSION_HS_SENT]))
    armed = tr.read_memory(L["hs_timer_armed"], 1)[0]
    log(f"  armed: hs_timer_armed={armed}, wg_state=HS_SENT")
    if armed != 1:
        failures.append(
            f"C: hs_timer_armed={armed} after timer_handshake_start, "
            "expected 1")

    # Before the deadline: timer_check must do nothing at all.
    call_carry(tr, L["timer_check"])
    st = tr.read_memory(L["wg_state"], 1)[0]
    n = tr.read_memory(cbcount_addr, 1)[0]
    log(f"  timer_check before the deadline: wg_state={st} udp_cbcount={n}")
    if st != SESSION_HS_SENT:
        failures.append(
            f"C: wg_state={st} after an early timer_check, expected "
            f"{SESSION_HS_SENT} — the deadline fired too soon")
    if n != 1:
        failures.append(
            f"C: udp_cbcount={n} after an early timer_check, expected 1")

    # Wind the initiation timestamp back past the deadline. The saved buffer
    # is [hi, mid, lo], the same order as $A0-$A2.
    target = (read_jiffy(tr) - (HS_TIMEOUT_JIFFIES + 600)) & 0xFFFFFF
    tr.write_memory(L["session_start_jiffy"],
                    bytes([(target >> 16) & 0xFF, (target >> 8) & 0xFF,
                           target & 0xFF]))
    log(f"  session_start_jiffy wound back to ${target:06X} "
        f"(> {HS_TIMEOUT_JIFFIES} jiffies = 90 s ago)")

    call_carry(tr, L["timer_check"])
    st = tr.read_memory(L["wg_state"], 1)[0]
    armed = tr.read_memory(L["hs_timer_armed"], 1)[0]
    n = tr.read_memory(cbcount_addr, 1)[0]
    txt = screen_text(tr)
    log(f"  timer_check after the deadline: wg_state={st} "
        f"hs_timer_armed={armed} udp_cbcount={n}")
    if st != SESSION_IDLE:
        failures.append(
            f"C: wg_state={st} after the deadline, expected "
            f"{SESSION_IDLE} (IDLE) — session_reset did not run")
    if armed != 0:
        failures.append(
            f"C: hs_timer_armed={armed} after the deadline, expected 0")
    if n != 0:
        failures.append(
            f"C: udp_cbcount={n} after the deadline, expected 0 — the "
            "teardown did not return the listener slot, which is the entire "
            "point of #84")
    if "HANDSHAKE TIMEOUT" not in txt:
        failures.append(
            "C: 'HANDSHAKE TIMEOUT' never reached the screen")
    else:
        log("  screen shows HANDSHAKE TIMEOUT")
    return failures


def cycle_send_needs_a_listener(tr, L, cbcount_addr: int,
                                cbmax: int) -> list[str]:
    """net_udp_send's two new edges: reclaim-or-fail, and the cold-boot guard.

    session_initiate now takes a failure path when net_udp_send reports C=1
    rather than advancing to HS_SENT with nothing on the wire.  Driving
    session_initiate itself is not practical here — it runs the full X25519
    initiation, which is ~100 minutes under a non-warp VICE — so what is
    measured is the edge that branch depends on: that net_udp_send really
    does report C=1 when it cannot reclaim a listener, and that it does NOT
    touch the blob's table before ip65_init has ever run.
    """
    failures = []
    log("--- Cycle D: net_udp_send's listener edges ---")

    # Point the send somewhere ARP can actually resolve. The guard leg below
    # lets the send through by design, and ip65's udp_send goes out via ARP —
    # aimed at 0.0.0.0 it would sit in the driver rather than return.
    tr.write_memory(L["net_udp_dest_ip"], bytes([10, 0, 65, 1]))   # the rig host
    tr.write_memory(L["net_udp_dest_port"], bytes([0xCA, 0x2C]))   # 51820, BE
    tr.write_memory(L["net_udp_send_len"], bytes([4, 0]))

    # (1) Cold-boot guard: no listener held AND none ever claimed. The send
    # must not reach udp_add_listener, whose index comes from an
    # uninitialised udp_cbcount before ip65_init.
    tr.write_memory(L["ip65_listening"], bytes([0]))
    tr.write_memory(L["ip65_listen_port"], bytes([0, 0]))
    before = tr.read_memory(cbcount_addr, 1)[0]
    call_carry(tr, L["net_udp_send"], a=0x00, x=0x10, timeout=45.0)
    after = tr.read_memory(cbcount_addr, 1)[0]
    log(f"  never-listened guard: udp_cbcount {before} -> {after} "
        "(must not change)")
    if after != before:
        failures.append(
            f"D: udp_cbcount {before} -> {after} with ip65_listen_port=0 — "
            "the send reached udp_add_listener on a table it must not touch")

    # (2) Reclaim-or-fail: we have listened before, hold nothing now, and the
    # table is full, so the re-listen cannot succeed and the send must say so.
    for i in range(cbmax):
        set_port(tr, L["wg_local_port"], 51840 + i)
        call_carry(tr, L["net_udp_listen"])
        tr.write_memory(L["ip65_listening"], bytes([0]))   # forget the claim
    n = tr.read_memory(cbcount_addr, 1)[0]
    log(f"  table filled to udp_cbcount={n} (udp_cbmax={cbmax})")
    if n != cbmax:
        failures.append(
            f"D: could not fill the table — udp_cbcount={n}, expected {cbmax}")

    set_port(tr, L["wg_local_port"], 51820)
    tr.write_memory(L["ip65_listening"], bytes([0]))
    tr.write_memory(L["ip65_listen_port"], bytes([0x2C, 0xCA]))  # 51820, LE
    c = call_carry(tr, L["net_udp_send"], a=0x00, x=0x10)
    log(f"  send with no listener and a full table: C={c} (expected 1)")
    if c != 1:
        failures.append(
            f"D: net_udp_send returned C={c} when it could not reclaim a "
            "listener — session_initiate's new failure path would never be "
            "taken, and the app would send while permanently deaf")
    return failures


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--rounds", type=int, default=5,
                    help="cycle A rounds (default 5, > udp_cbmax)")
    ap.add_argument("--dhcp-timeout", type=float, default=DHCP_TIMEOUT)
    args = ap.parse_args()
    VERBOSE = args.verbose

    log("test_ip65_listener_leak.py — issue #84")
    log("")

    problems = rig_problems(args.vice_bin)
    if problems:
        log("SKIP: ethernet rig not ready:")
        for p in problems:
            log(f"    - {p}")
        log("  The rig needs one privileged setup per boot and is not created "
            "here; see c64-https' tools/rig-up-macos.sh.")
        return 77

    build_ip65()
    for path in (PRG_PATH, LABELS_PATH, WG_MAP_PATH, IP65_MAP_PATH, UDP_SRC_PATH):
        if not os.path.exists(path):
            log(f"FATAL: missing {path}")
            return 1
    assert_ip65_build()

    cbcount_addr, cbmax = derive_udp_cbcount()
    log("=== ip65 listener table, located from the build ===")
    log(f"  udp_send_len (ip65-c64.map)  ${map_symbol(IP65_MAP_PATH, 'udp_send_len'):04X}")
    log(f"  udp_cbmax    (ip65/ip65/udp.s)  {cbmax}")
    log(f"  udp_cbcount  (derived)       ${cbcount_addr:04X}")
    log("")

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if n not in labels]
    if missing:
        log(f"FATAL: labels.txt is missing {missing} — these exist on every "
            "tree this test can meaningfully run against, so something is "
            "wrong with the build rather than with the code under test.")
        return 1
    missing_c = [n for n in CYCLE_C_LABELS if n not in labels]
    missing_d = [n for n in CYCLE_D_LABELS if n not in labels]

    have = REQUIRED_LABELS + \
        ([] if missing_c else CYCLE_C_LABELS) + \
        ([] if missing_d else CYCLE_D_LABELS)
    L = {n: labels[n] for n in have}
    for n in have:
        vlog(f"  label {n:<22s} ${L[n]:04X}")

    unfixed = bool(missing_c or missing_d)
    if unfixed:
        log("=== This tree does not carry the #84 fix ===")
        if missing_c:
            log(f"  cycle C (handshake deadline) SKIPPED — no {missing_c}")
        if missing_d:
            log(f"  cycle D (net_udp_send edges)  SKIPPED — no {missing_d}")
        log("  Those symbols are introduced by #84, so their absence is")
        log("  expected here rather than a fault. Cycles A and B ARE the leak")
        log("  demonstration and run against any tree — they are what should")
        log("  be seen failing on master 875a841.")
        log("")

    allocator = PortAllocator(port_range_start=6570, port_range_end=6590)
    port = args.port or allocator.allocate()
    if not args.port:
        res = allocator.take_socket(port)
        if res is not None:
            res.close()

    config = ViceConfig(
        prg_path=PRG_PATH,
        port=port,
        warp=False,          # load-bearing: warp breaks ip65's DHCP
        ntsc=True,
        sound=False,
        minimize=True,
        ethernet=True,
        ethernet_mode="rrnet",
        ethernet_interface=ETH_IFACE,
        ethernet_driver="pcap",
        ethernet_executable=args.vice_bin,
        run_as_root=False,
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

        log("=== Driving network init ('I' -> ip65_init + DHCP + listen) ===")
        if not press_key(tr, "I"):
            log("FATAL: the C64 never consumed the keystroke")
            return 1
        deadline = time.monotonic() + args.dhcp_timeout
        ok = False
        while time.monotonic() < deadline:
            txt = screen_text(tr)
            if NET_OK_NEEDLE in txt:
                ok = True
                break
            if any(n in txt for n in NET_FAIL_NEEDLES):
                log("FATAL: do_net_init reported failure:")
                log(txt)
                return 1
            tr.resume()
            time.sleep(1.0)
        if not ok:
            log(f"FATAL: no '{NET_OK_NEEDLE}' within {args.dhcp_timeout:.0f}s")
            log(screen_text(tr))
            return 1
        log(f"  network up (+{time.monotonic() - t0:.0f}s)")
        log("")

        # --- Check the derivation before trusting it --------------------
        log("=== Verifying the udp_cbcount derivation against the machine ===")
        n = tr.read_memory(cbcount_addr, 1)[0]
        log(f"  ${cbcount_addr:04X} reads {n} after do_net_init's single listen")
        if n != 1:
            log("FATAL: expected exactly 1. Either the address derived from "
                "udp_send_len + the udp.s layout is wrong — in which case "
                "everything below would be measuring an unrelated byte — or "
                "do_net_init did not register a listener at all. Not "
                "proceeding.")
            return 1
        log("  derivation confirmed")
        log("")

        failures = cycle_same_port(tr, L, cbcount_addr, args.rounds)
        log("")
        failures += cycle_distinct_ports(tr, L, cbcount_addr, cbmax, 51830)
        log("")
        if missing_c:
            log("--- Cycle C: SKIPPED (no #84 handshake deadline in this "
                "build) ---")
            log("")
        else:
            failures += cycle_handshake_deadline(tr, L, cbcount_addr)
            log("")
        if missing_d:
            log("--- Cycle D: SKIPPED (no #84 listener bookkeeping in this "
                "build) ---")
            log("")
        else:
            failures += cycle_send_needs_a_listener(tr, L, cbcount_addr, cbmax)
            log("")

        if failures:
            log(f"FAIL: {len(failures)} assertion(s)")
            for f in failures:
                log(f"  - {f}")
            log("")
            if unfixed:
                log("This is the EXPECTED result on master 875a841: "
                    "net_udp_close is `clc / rts`, so no slot is ever "
                    "returned. Cycle A shows the close reporting success "
                    "with udp_cbcount stuck at 1 and every re-listen refused; "
                    f"cycle B shows the {cbmax}-entry table filling until a "
                    "new port cannot be registered at all.")
            rc = 1
        else:
            ran = "A/B" if unfixed else "A/B/C/D"
            log(f"PASS ({ran}): every close returned its slot "
                "(udp_cbcount 1 -> 0), every re-listen succeeded, and neither "
                "the same-port nor the distinct-port cycle exhausted the "
                f"{cbmax}-entry table.")
            if unfixed:
                log("NOTE: this tree lacks the #84 symbols, yet cycles A and "
                    "B passed. That should be impossible — investigate before "
                    "trusting this result.")
                rc = 1
            else:
                rc = 0
    finally:
        try:
            if tr is not None:
                tr.close()
        except Exception:  # noqa: BLE001
            pass
        proc.stop()
    return rc


if __name__ == "__main__":
    sys.exit(main())
