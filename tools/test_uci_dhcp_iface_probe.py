#!/usr/bin/env python3
"""tools/test_uci_dhcp_iface_probe.py — red/green for the WiFi-only "DHCP FAILED".

The defect
----------
`src/net/uci/net.s` `net_dhcp_acquire` sent GET_IPADDR for interface 0 and
nothing else. On a U64E whose firmware registers ethernet as interface 0
(always, cable or not) and WiFi as interface 1, a box on WiFi only reads
0.0.0.0 from index 0 and boots to "DHCP FAILED" while the firmware holds a
perfectly good lease on index 1 (live run 2026-10-04, fw 3a1ff9ff).

What this suite runs, and why not VICE
--------------------------------------
VICE has no UCI ($DF1D reads $FF), so `net_dhcp_acquire` never gets past
its first wait there. This suite runs the REAL assembled routine out of the
real `build/wireguard.prg` (BACKEND=uci) on tools/uci/mos6502.py — the same
interpreter tools/test_uci_short_read_drop.py proves byte-exact against
hashlib every gate run — against a model of $DF1C-$DF1F that answers
NET_CMD_GET_IPADDR the way the firmware's network_target.cc does:

    index >= interface count  -> EMPTY reply, status "82,PARAMETER(S) OUT OF RANGE"
    interface pointer is NULL -> EMPTY reply, status "83,INTERFACE NOT AVAILABLE"
    otherwise                 -> 12-byte IP/mask/gw reply, status "00,OK"

The transport ERROR bit ($DF1C bit 3) is NOT how the firmware reports
those: in command_protocol.vhd it means "PUSH_CMD while not idle"
(error_busy) and the pushed command is DROPPED. The model does exactly
that, so an adapter that forgets to ACK a reply is caught on its NEXT
command, at the wire tap, not inferred. A second out-of-range mode
(`errbit`) additionally raises the ERROR bit, for adapters ported from code
that assumed it (c64-https net.s); both modes must come out the same.

The model knows nothing about what `net_dhcp_acquire` ought to conclude:
it serves per-interface records and logs every command byte pushed. The
assertions are on `net_local_ip`, `net_last_error`, the carry, the command
log and the device's final state — never on screen text.

Speed is an axis: device latencies are wall-clock (µs) and CIA1 TOD runs at
10 Hz of wall time, both converted at the CPU clock under test, so a 48 MHz
run sees the reply staged proportionally LATER than a 1 MHz run does. The
lease-found cases run at every speed in --mhz (default 1,48); the cases
that legitimately spend whole seconds of TOD budget run at 1 MHz only,
because 1 s at 48 MHz is 48 M interpreted cycles.

HARDWARE-ONLY (cannot be shown here): that fw 3a1ff9ff really numbers WiFi
as interface 1 and answers index 0 with 0.0.0.0. That is the live run's
observation, and the boot proof on the device is the authority for it.

Usage:
    python3 tools/test_uci_dhcp_iface_probe.py [--seed N] [--mhz 1,48]
                                               [--build DIR] [--only CASE]
Env:
    C64_SKIP_BUILD=1   use build/ as-is (must be a BACKEND=uci tree)
    TEST_SEED=N        same as --seed
    UCI_DHCP_TURBO_MHZ comma list, same as --mhz
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.mos6502 import Mos6502, CpuBudgetExceeded  # noqa: E402

# --- UCI registers (src/net/uci/uci_regs.inc) --------------------------------
UCI_DEVICE, UCI_STATUS, UCI_CMD_DATA = 0xDF1B, 0xDF1C, 0xDF1D
UCI_RESP_DATA, UCI_STATUS_DATA = 0xDF1E, 0xDF1F
UCI_ID_VALUE = 0xC9
STAT_DATA_AV, STAT_STAT_AV, STAT_ERROR, STAT_CMD_BUSY = 0x80, 0x40, 0x08, 0x01
STATE_IDLE, STATE_BUSY, STATE_DATA_LAST = 0x00, 0x10, 0x20
CTRL_PUSH_CMD, CTRL_NEXT_DATA, CTRL_ABORT, CTRL_CLR_ERR = 0x01, 0x02, 0x04, 0x08

TARGET_NETWORK = 0x03
NET_CMD_GET_INTERFACE_COUNT = 0x02      # network_target.h
NET_CMD_GET_IPADDR = 0x05
ALLOWED_COMMANDS = {NET_CMD_GET_IPADDR, NET_CMD_GET_INTERFACE_COUNT}

# Firmware status lines (network_target.cc / command_intf.cc), verbatim.
ST_OK = b"00,OK"
ST_INVALID = b"81,INVALID PARAMS"
ST_OUT_OF_RANGE = b"82,PARAMETER(S) OUT OF RANGE"
ST_NOT_AVAILABLE = b"83,INTERFACE NOT AVAILABLE"
ST_UNKNOWN = b"21,UNKNOWN COMMAND"

# net_last_error codes (src/net/uci/uci_errors.inc)
ERR_OK, ERR_NO_IP, ERR_WAIT_TIMEOUT = 0x00, 0x83, 0x89

CIA_TOD_TENTHS, CIA_TOD_SEC, CIA_TOD_MIN, CIA_TOD_HOUR = 0xDC08, 0xDC09, 0xDC0A, 0xDC0B

# Every full run emits exactly this many named checks; a case that silently
# stops running is a hard error, not a smaller denominator.
CHECKS_PER_SPEED = 10           # cases A + B at each --mhz
CHECKS_FIXED = 30               # everything that runs once
RANDOM_TOPOLOGIES = 6

# A routine that has to probe and give up may spend its TOD budgets; one
# that is still running after this much simulated wall time is a hang.
HANG_BUDGET_S = 30.0


def fingerprint(path: Path) -> str:
    raw = path.read_bytes()
    return (f"sha256={hashlib.sha256(raw).hexdigest()} ({len(raw)} B) "
            f"mtime={datetime.fromtimestamp(path.stat().st_mtime).isoformat(' ', 'seconds')}")


def build_uci_tree() -> None:
    """`make clean && make BACKEND=uci` — registered SERIAL in the gate."""
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set — skipping build")
        return
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", "BACKEND=uci"], capture_output=True,
                       text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        raise SystemExit(f"FATAL: make BACKEND=uci failed:\n{r.stderr}")


def load_symbols(build: Path) -> dict:
    """Every symbol from the ld65 --dbgfile (labels.txt has exports only)."""
    syms: dict[str, int] = {}
    pat = re.compile(r'name="([^"]+)"[^\n]*?,val=0x([0-9A-Fa-f]+)')
    for line in (build / "wireguard.dbg").read_text().splitlines():
        if line.startswith("sym\t"):
            m = pat.search(line)
            if m:
                syms.setdefault(m.group(1), int(m.group(2), 16))
    return syms


def load_labels(build: Path) -> dict:
    """labels.txt (`al C:XXXX .name`) — the exported addresses."""
    out = {}
    for line in (build / "labels.txt").read_text().splitlines():
        m = re.match(r"al C:([0-9A-Fa-f]{4}) \.(\S+)", line)
        if m:
            out.setdefault(m.group(2), int(m.group(1), 16))
    return out


# =============================================================================
# Model of the Ultimate's network target behind $DF1C-$DF1F
# =============================================================================
class IfaceUci:
    """GET_IPADDR per interface, timed in wall-clock microseconds.

    `ifaces[i]` is a 12-byte IP/mask/gw record, or None for an interface
    the firmware counts but cannot resolve ("83,INTERFACE NOT AVAILABLE").
    Index >= len(ifaces) is out of range. `oor_mode` "status" is the real
    firmware (status line only); "errbit" also raises the ERROR bit.
    `wedge_push=k`: the k-th accepted PUSH_CMD (0-based) is never accepted —
    CMD_BUSY stays set for ever. `stuck` : STATE reads Busy from power-on.
    """

    def __init__(self, ifaces, *, mhz, oor_mode="status", accept_us=400,
                 stage_us=1800, wedge_push=None, stuck=False):
        self.ifaces = list(ifaces)
        self.mhz = mhz
        self.oor_mode = oor_mode
        self.accept_cyc = int(accept_us * mhz)
        self.stage_cyc = int(stage_us * mhz)
        self.wedge_push = wedge_push
        self.cycles = 0
        self.state = STATE_BUSY if stuck else STATE_IDLE
        self.stuck = stuck
        self.cmd_busy = 0
        self.error = 0
        self.cmd = bytearray()
        self.resp, self.resp_pos = b"", 0
        self.stat, self.stat_pos = b"", 0
        self._due = []                      # [(cycle, fn)]
        self.commands: list[bytes] = []     # accepted pushes, in order
        self.dropped: list[bytes] = []      # pushes refused (error_busy)
        self.unread_on_ack = 0              # reply bytes thrown away by DATA_ACC

    # -- time ------------------------------------------------------------
    def sync(self, cycles):
        self.cycles = cycles
        while self._due and cycles >= self._due[0][0]:
            _, fn = self._due.pop(0)
            fn()

    def _at(self, delay, fn):
        self._due.append((self.cycles + delay, fn))
        self._due.sort(key=lambda e: e[0])

    # -- protocol --------------------------------------------------------
    def _reply_for(self, cmd: bytes):
        if len(cmd) < 2 or cmd[0] != TARGET_NETWORK:
            return b"", ST_UNKNOWN, False
        op = cmd[1]
        if op == NET_CMD_GET_INTERFACE_COUNT:
            return bytes([len(self.ifaces)]), ST_OK, False
        if op == NET_CMD_GET_IPADDR:
            if len(cmd) != 3:
                return b"", ST_INVALID, False
            idx = cmd[2]
            if idx >= len(self.ifaces):
                return b"", ST_OUT_OF_RANGE, self.oor_mode == "errbit"
            rec = self.ifaces[idx]
            if rec is None:
                return b"", ST_NOT_AVAILABLE, False
            return bytes(rec), ST_OK, False
        return b"", ST_UNKNOWN, False

    def _push(self):
        cmd = bytes(self.cmd)
        self.cmd = bytearray()
        if self.state != STATE_IDLE or self.cmd_busy:
            # command_protocol.vhd: `else error_busy <= '1'` — dropped.
            self.error = 1
            self.dropped.append(cmd)
            return
        n = len(self.commands)
        self.commands.append(cmd)
        self.cmd_busy = 1
        self.state = STATE_BUSY
        if self.wedge_push is not None and n == self.wedge_push:
            return                          # a wedged firmware task
        self._at(self.accept_cyc, self._accept)

        def stage():
            data, status, errbit = self._reply_for(cmd)
            self.resp, self.resp_pos = data, 0
            self.stat, self.stat_pos = status, 0
            self.state = STATE_DATA_LAST
            if errbit:
                self.error = 1
        self._pending_stage = stage

    def _accept(self):
        self.cmd_busy = 0                   # STATE stays Busy until staged
        self._at(self.stage_cyc, self._pending_stage)

    def status(self):
        s = self.state | (STAT_ERROR if self.error else 0) | self.cmd_busy
        if self.resp_pos < len(self.resp):
            s |= STAT_DATA_AV
        if self.stat_pos < len(self.stat):
            s |= STAT_STAT_AV
        return s

    def read(self, addr):
        if addr == UCI_STATUS:
            return self.status()
        if addr == UCI_CMD_DATA:
            return UCI_ID_VALUE
        if addr == UCI_RESP_DATA:
            if self.resp_pos < len(self.resp):
                self.resp_pos += 1
                return self.resp[self.resp_pos - 1]
            return 0xFF
        if addr == UCI_STATUS_DATA:
            if self.stat_pos < len(self.stat):
                self.stat_pos += 1
                return self.stat[self.stat_pos - 1]
            return 0xFF
        return 0x00

    def write(self, addr, value):
        if addr == UCI_CMD_DATA:
            if len(self.cmd) < 896:
                self.cmd.append(value)
            return
        if addr != UCI_STATUS:
            return
        if value & CTRL_CLR_ERR:
            self.error = 0
        if value & CTRL_ABORT:
            if not self.stuck:
                self.state = STATE_IDLE
            self.cmd_busy = 0 if not self.stuck else self.cmd_busy
            self.resp, self.stat = b"", b""
            self._due = []
        if value & CTRL_NEXT_DATA:
            if self.state == STATE_DATA_LAST:
                self.unread_on_ack += len(self.resp) - self.resp_pos
                self.state = STATE_IDLE
                self.resp, self.resp_pos = b"", 0
                self.stat, self.stat_pos = b"", 0
        if value & CTRL_PUSH_CMD:
            self._push()

    # -- verdict helpers ---------------------------------------------------
    def ipaddr_indices(self):
        return [c[2] for c in self.commands
                if len(c) >= 3 and c[:2] == bytes([TARGET_NETWORK, NET_CMD_GET_IPADDR])]

    def foreign_commands(self):
        return [c for c in self.commands
                if len(c) < 2 or c[0] != TARGET_NETWORK or c[1] not in ALLOWED_COMMANDS
                or (c[1] == NET_CMD_GET_IPADDR and len(c) != 3)]

    def is_idle(self):
        return (self.state == STATE_IDLE and not self.cmd_busy and not self.error
                and self.resp_pos >= len(self.resp) and self.stat_pos >= len(self.stat))

    def describe(self):
        return (f"state=${self.state:02X} busy={self.cmd_busy} err={self.error} "
                f"resp_left={len(self.resp) - self.resp_pos} "
                f"stat_left={len(self.stat) - self.stat_pos} "
                f"cmds={[c.hex() for c in self.commands]} "
                f"dropped={[c.hex() for c in self.dropped]}")


class Tod:
    """CIA1 TOD at 10 Hz of WALL time, i.e. mhz*100_000 CPU cycles per tenth."""

    def __init__(self, mhz):
        self.per_tenth = int(mhz * 100_000)
        self.cycles = 0
        self.latched = None

    def _now(self):
        t = self.cycles // self.per_tenth
        return (t % 10, (t // 10) % 60, (t // 600) % 60, ((t // 36000) % 12) + 1)

    def read(self, addr):
        now = self.latched if self.latched is not None else self._now()
        if addr == CIA_TOD_HOUR:
            self.latched = self._now()
            return self.latched[3]
        if addr == CIA_TOD_TENTHS:
            self.latched = None
            return now[0]
        if addr == CIA_TOD_SEC:
            return now[1]
        if addr == CIA_TOD_MIN:
            return now[2]
        return 0x00


class Run:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Machine:
    REQUIRED = ("net_dhcp_acquire", "net_local_ip", "net_last_error",
                "uci_status_buf", "uci_status_leading_code")

    def __init__(self, build: Path):
        raw = (build / "wireguard.prg").read_bytes()
        self.load_addr, self.image = raw[0] | (raw[1] << 8), raw[2:]
        self.sym = load_symbols(build)
        self.labels = load_labels(build)
        missing = [n for n in self.REQUIRED if n not in self.sym]
        if missing:
            raise SystemExit(f"FATAL: symbol(s) {missing} not in wireguard.dbg "
                             f"— is this a BACKEND=uci build?")
        # Structural cross-check: the routine the suite drives is the one the
        # linker EXPORTED under that name, not merely a dbg-file symbol.
        for n in ("net_dhcp_acquire", "net_local_ip", "net_last_error"):
            if self.labels.get(n) != self.sym[n]:
                raise SystemExit(f"FATAL: labels.txt {n}={self.labels.get(n)} "
                                 f"disagrees with wireguard.dbg ${self.sym[n]:04X}")

    def fresh_mem(self):
        mem = bytearray(0x10000)
        mem[self.load_addr:self.load_addr + len(self.image)] = self.image
        return mem

    def call(self, device, *, mhz, mem=None, ip_witness=b"\x00\x00\x00\x00",
             err_witness=0x00, resp_poison=None, entry=None):
        s = self.sym
        mem = self.fresh_mem() if mem is None else mem
        tod = Tod(mhz)

        def io_read(addr):
            tod.cycles = cpu.cycles
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                return device.read(addr)
            if 0xDC00 <= addr <= 0xDCFF:
                return tod.read(addr)
            return 0xFF

        def io_write(addr, value):
            tod.cycles = cpu.cycles
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                device.write(addr, value)

        cpu = Mos6502(mem, io_read, io_write)
        cpu.cycles = device.cycles          # time is continuous across calls
        mem[s["net_local_ip"]:s["net_local_ip"] + 4] = ip_witness
        mem[s["net_last_error"]] = err_witness
        if resp_poison is not None:
            a = s["uci_ipaddr_resp"]
            mem[a:a + len(resp_poison)] = resp_poison
        hung = None
        start = cpu.cycles
        try:
            cpu.call(entry if entry is not None else s["net_dhcp_acquire"],
                     max_cycles=int(HANG_BUDGET_S * mhz * 1_000_000))
        except CpuBudgetExceeded as exc:
            hung = str(exc)
        device.sync(cpu.cycles)
        return Run(
            carry=cpu.c, a=cpu.a, hung=hung, mem=mem,
            ip=bytes(mem[s["net_local_ip"]:s["net_local_ip"] + 4]),
            err=mem[s["net_last_error"]],
            seconds=(cpu.cycles - start) / (mhz * 1_000_000),
            device=device,
        )


# =============================================================================
class Result:
    def __init__(self):
        self.passed = self.failed = 0
        self.names: list[str] = []
        self.failures: list[str] = []

    def check(self, ok, name, detail=""):
        self.names.append(name)
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            self.failures.append(name)
            print(f"  FAIL  {name}\n        {detail}")
        return ok


def rand_lease(rng):
    """A non-zero 12-byte IP/mask/gw record; first octet never 0."""
    ip = bytes([rng.randrange(1, 224)] + [rng.randrange(256) for _ in range(3)])
    return ip + bytes([255, 255, 255, 0]) + ip[:3] + bytes([rng.randrange(1, 255)])


ZERO = bytes(12)


def fmt_ip(b):
    return ".".join(str(x) for x in b)


def _common(res, tag, r, *, want_indices=None, want_prefix=None, idle=True):
    d = r.device
    res.check(r.hung is None, f"{tag}/returns",
              f"net_dhcp_acquire did not return within {HANG_BUDGET_S:.0f} s "
              f"of simulated wall time: {r.hung}")
    got = d.ipaddr_indices()
    if want_indices is not None:
        res.check(got == want_indices, f"{tag}/command-log",
                  f"GET_IPADDR interface bytes at the wire tap were {got}, "
                  f"want exactly {want_indices}. {d.describe()}")
    if want_prefix is not None:
        res.check(got[:len(want_prefix)] == want_prefix and not d.foreign_commands(),
                  f"{tag}/command-log",
                  f"GET_IPADDR interface bytes at the wire tap were {got}, want "
                  f"them to begin {want_prefix} (foreign commands: "
                  f"{[c.hex() for c in d.foreign_commands()]})")
    if idle:
        res.check(d.is_idle() and not d.dropped, f"{tag}/uci-idle-and-acked",
                  f"UCI not returned to idle, or a command was dropped as "
                  f"PUSH-while-busy: {d.describe()}")


# =============================================================================
# Cases
# =============================================================================
def case_fidelity(ctx, res):
    """The interpreter executes a known routine out of this PRG correctly."""
    m, rng = ctx["m"], ctx["rng"]
    code = rng.randrange(10, 100)
    mem = m.fresh_mem()
    buf = m.sym["uci_status_buf"]
    mem[buf:buf + 3] = f"{code:02d},".encode()
    dev = IfaceUci([], mhz=1)
    r = m.call(dev, mhz=1, mem=mem, entry=m.sym["uci_status_leading_code"])
    res.check(r.a == code and r.hung is None, "F/interpreter-parses-status-code",
              f"uci_status_leading_code on '{code:02d},' returned A={r.a}")


def case_wifi_only(ctx, res, mhz):
    """A: ethernet (0) reads 0.0.0.0, WiFi (1) holds the lease."""
    m, rng = ctx["m"], ctx["rng"]
    lease = rand_lease(rng)
    witness = bytes(rng.randrange(1, 256) for _ in range(4))
    dev = IfaceUci([ZERO, lease], mhz=mhz, oor_mode=rng.choice(["status", "errbit"]))
    # net_last_error starts at $00, as net_init leaves it on the boot path:
    # a stale $83 from the interface-0 probe is then the only way to fail.
    r = m.call(dev, mhz=mhz, ip_witness=witness, err_witness=0x00)
    tag = f"A@{mhz}MHz/wifi-only"
    res.check(r.carry == 0, f"{tag}/carry-clear",
              f"C={r.carry}, net_last_error=${r.err:02X} — a WiFi-only box "
              f"reports DHCP FAILED while interface 1 holds {fmt_ip(lease[:4])}")
    res.check(r.ip == lease[:4], f"{tag}/net_local_ip-is-iface1-lease",
              f"net_local_ip={fmt_ip(r.ip)}, want {fmt_ip(lease[:4])} (interface 1)")
    res.check(r.err == ERR_OK, f"{tag}/net_last_error-cleared",
              f"net_last_error=${r.err:02X} beside a successful acquire")
    _common(res, tag, r, want_indices=[0, 1])


def case_ethernet(ctx, res, mhz):
    """B: interface 0 has a lease -> used, interface 1 NEVER queried."""
    m, rng = ctx["m"], ctx["rng"]
    lease0, lease1 = rand_lease(rng), rand_lease(rng)
    dev = IfaceUci([lease0, lease1], mhz=mhz)
    r = m.call(dev, mhz=mhz, err_witness=0x00)
    tag = f"B@{mhz}MHz/ethernet"
    res.check(r.carry == 0 and r.ip == lease0[:4], f"{tag}/iface0-lease-used",
              f"C={r.carry} net_local_ip={fmt_ip(r.ip)}, want C=0 "
              f"{fmt_ip(lease0[:4])} (interface 0; interface 1 had "
              f"{fmt_ip(lease1[:4])})")
    _common(res, tag, r, want_indices=[0], idle=False)
    res.check(r.device.is_idle() and not r.device.dropped,
              f"{tag}/uci-idle-and-acked", r.device.describe())


def case_no_lease(ctx, res):
    """C: every registered interface reads 0.0.0.0 -> C=1, NO_IP."""
    m, rng = ctx["m"], ctx["rng"]
    dev = IfaceUci([ZERO, ZERO], mhz=1)
    r = m.call(dev, mhz=1, err_witness=0xEE)
    tag = "C/no-lease-anywhere"
    res.check(r.carry == 1, f"{tag}/carry-set", f"C={r.carry} ip={fmt_ip(r.ip)}")
    res.check(r.err == ERR_NO_IP, f"{tag}/net_last_error-NO_IP",
              f"net_last_error=${r.err:02X}, want ${ERR_NO_IP:02X} "
              f"(UCI_ERR_NO_IP: interfaces exist, none has a lease)")
    _common(res, tag, r, want_prefix=[0, 1])


def case_out_of_range(ctx, res, mode):
    """D: index 1 is out of range (no WiFi registered) -> skipped cleanly,
    UCI drained + ACKed, and the NEXT command on the same machine works."""
    m, rng = ctx["m"], ctx["rng"]
    dev = IfaceUci([ZERO], mhz=1, oor_mode=mode)
    r = m.call(dev, mhz=1, err_witness=0xEE)
    tag = f"D/{mode}/out-of-range-iface1"
    res.check(r.carry == 1 and r.err == ERR_NO_IP, f"{tag}/C1-NO_IP",
              f"C={r.carry} net_last_error=${r.err:02X}, want C=1 "
              f"${ERR_NO_IP:02X}: the only real interface had no lease; "
              f"an out-of-range index is the end of the list, not a fault")
    _common(res, tag, r, want_prefix=[0, 1])
    # The next command works: the lease arrives, call again on the SAME
    # memory and the SAME device. A probe that left the UCI un-ACKed gets
    # its next PUSH dropped (error_busy) and is caught right here.
    lease = rand_lease(rng)
    dev.ifaces[0] = lease
    before = len(dev.commands)
    r2 = m.call(dev, mhz=1, mem=r.mem, err_witness=0xEE)
    res.check(r2.carry == 0 and r2.ip == lease[:4] and not dev.dropped
              and dev.ipaddr_indices()[before:before + 1] == [0],
              f"{tag}/next-command-works",
              f"second acquire: C={r2.carry} ip={fmt_ip(r2.ip)} want "
              f"{fmt_ip(lease[:4])}; {dev.describe()}")


def case_empty_reply_is_not_a_lease(ctx, res):
    """E: an EMPTY reply ("83,INTERFACE NOT AVAILABLE", or out of range)
    must never be read as a lease out of whatever the response buffer held.

    The buffer is poisoned with a random non-zero record first. An adapter
    that copies uci_ipaddr_resp without checking how many bytes arrived
    reports the poison as its address.
    """
    m, rng = ctx["m"], ctx["rng"]
    if "uci_ipaddr_resp" not in m.sym:
        for n in ("E/empty-reply-then-lease", "E/empty-reply-only"):
            res.check(False, n, "uci_ipaddr_resp not in wireguard.dbg — the "
                      "suite cannot poison the response buffer")
        return
    poison = rand_lease(rng)
    lease = rand_lease(rng)
    while lease[:4] == poison[:4]:
        lease = rand_lease(rng)
    dev = IfaceUci([None, lease], mhz=1)
    r = m.call(dev, mhz=1, resp_poison=poison)
    res.check(r.carry == 0 and r.ip == lease[:4], "E/empty-reply-then-lease",
              f"C={r.carry} net_local_ip={fmt_ip(r.ip)}, want "
              f"{fmt_ip(lease[:4])} from interface 1"
              + (" — that is the POISONED stale buffer" if r.ip == poison[:4] else ""))
    dev = IfaceUci([None], mhz=1)
    r = m.call(dev, mhz=1, resp_poison=poison)
    res.check(r.carry == 1 and r.ip != poison[:4], "E/empty-reply-only",
              f"C={r.carry} net_local_ip={fmt_ip(r.ip)} (poison "
              f"{fmt_ip(poison[:4])}): no interface answered with a record")


def case_wedge(ctx, res):
    """F/G/H: a wedged FPGA/firmware task bails with C=1 and $89, bounded."""
    m = ctx["m"]
    # F: the very first PUSH is never accepted.
    dev = IfaceUci([ZERO, rand_lease(ctx["rng"])], mhz=1, wedge_push=0)
    r = m.call(dev, mhz=1, err_witness=0xEE)
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_WAIT_TIMEOUT,
              "F/wedge-on-iface0-push/C1-WAIT_TIMEOUT",
              f"hung={r.hung} C={r.carry} net_last_error=${r.err:02X} "
              f"after {r.seconds:.1f} s; want C=1 ${ERR_WAIT_TIMEOUT:02X} "
              f"(the push never completed, so nothing after it is meaningful)")
    res.check(len(dev.commands) == 1 and not dev.dropped,
              "F/wedge-on-iface0-push/no-further-commands",
              f"pushes after the wedge: {dev.describe()}")
    res.check(r.seconds <= 7.0, "F/wedge-on-iface0-push/bounded",
              f"took {r.seconds:.2f} s simulated; the wait budget is 5 s")
    # G: interface 0 answers 0.0.0.0, the probe of interface 1 wedges.
    dev = IfaceUci([ZERO, rand_lease(ctx["rng"])], mhz=1, wedge_push=1)
    r = m.call(dev, mhz=1, err_witness=0xEE)
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_WAIT_TIMEOUT,
              "G/wedge-on-iface1-push/C1-WAIT_TIMEOUT",
              f"hung={r.hung} C={r.carry} net_last_error=${r.err:02X} "
              f"after {r.seconds:.1f} s; {dev.describe()}")
    res.check(dev.ipaddr_indices() == [0, 1] and not dev.dropped,
              "G/wedge-on-iface1-push/stops-at-the-wedge",
              f"{dev.describe()}")
    # H: STATE stuck Busy from the start: nothing may be pushed at all.
    dev = IfaceUci([rand_lease(ctx["rng"])], mhz=1, stuck=True)
    r = m.call(dev, mhz=1, err_witness=0xEE)
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_WAIT_TIMEOUT
              and not dev.commands and not dev.dropped,
              "H/state-stuck/no-push-C1-WAIT_TIMEOUT",
              f"hung={r.hung} C={r.carry} net_last_error=${r.err:02X} "
              f"{dev.describe()}")


def case_random(ctx, res):
    """R: seeded random topologies of one or two interfaces."""
    m, rng = ctx["m"], ctx["rng"]
    for i in range(RANDOM_TOPOLOGIES):
        n = rng.choice([1, 2])
        ifaces = [rand_lease(rng) if rng.random() < 0.5 else ZERO for _ in range(n)]
        mode = rng.choice(["status", "errbit"])
        want = next((x[:4] for x in ifaces if x != ZERO), None)
        want_idx = next((k for k, x in enumerate(ifaces) if x != ZERO), None)
        dev = IfaceUci(ifaces, mhz=1, oor_mode=mode,
                       accept_us=rng.randrange(50, 2000),
                       stage_us=rng.randrange(100, 8000))
        r = m.call(dev, mhz=1, err_witness=0x00)
        shape = "[" + ",".join("lease" if x != ZERO else "0.0.0.0" for x in ifaces) + f"] {mode}"
        if want is not None:
            ok = (r.carry == 0 and r.ip == want and r.err == ERR_OK
                  and dev.ipaddr_indices() == list(range(want_idx + 1)))
        else:
            ok = (r.carry == 1 and r.err == ERR_NO_IP
                  and dev.ipaddr_indices()[:n] == list(range(n)))
        ok = ok and dev.is_idle() and not dev.dropped and r.hung is None
        res.check(ok, f"R{i}/random-topology",
                  f"{shape}: C={r.carry} ip={fmt_ip(r.ip)} err=${r.err:02X} "
                  f"want {fmt_ip(want) if want else 'C=1 $83'}; {dev.describe()}")


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default=None)
    p.add_argument("--mhz", default=os.environ.get("UCI_DHCP_TURBO_MHZ", "1,48"))
    p.add_argument("--only", default=None, help="case letter: F A B C D E W R")
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    speeds = [int(x) for x in str(args.mhz).split(",") if x.strip()]

    if args.build is None:
        build_uci_tree()
    build = Path(args.build).resolve() if args.build else PROJECT_ROOT / "build"
    prg = build / "wireguard.prg"
    if not prg.exists() or not (build / "wireguard.dbg").exists():
        print(f"FATAL: {prg} / wireguard.dbg missing — run `make BACKEND=uci`")
        return 2
    print(f"prg:   {prg}\n       {fingerprint(prg)}")
    m = Machine(build)
    print(f"net_dhcp_acquire=${m.sym['net_dhcp_acquire']:04X} "
          f"net_local_ip=${m.sym['net_local_ip']:04X} "
          f"net_last_error=${m.sym['net_last_error']:04X}  speeds={speeds} MHz")

    ctx = {"m": m, "rng": random.Random(seed)}
    res = Result()
    plan = [("F", lambda: case_fidelity(ctx, res))]
    for mhz in speeds:
        plan.append(("A", lambda mhz=mhz: case_wifi_only(ctx, res, mhz)))
        plan.append(("B", lambda mhz=mhz: case_ethernet(ctx, res, mhz)))
    plan += [("C", lambda: case_no_lease(ctx, res)),
             ("D", lambda: case_out_of_range(ctx, res, "status")),
             ("D", lambda: case_out_of_range(ctx, res, "errbit")),
             ("E", lambda: case_empty_reply_is_not_a_lease(ctx, res)),
             ("W", lambda: case_wedge(ctx, res)),
             ("R", lambda: case_random(ctx, res))]
    for key, fn in plan:
        if args.only and args.only != key:
            continue
        fn()

    if len(set(res.names)) != len(res.names):
        print("FATAL: duplicate check names — the denominator is not an identity")
        return 2
    total = res.passed + res.failed
    expected = CHECKS_FIXED + CHECKS_PER_SPEED * len(speeds)
    print(f"\nResults: {res.passed} passed, {res.failed} failed — {total} checks")
    if res.failures:
        print("FAILED: " + ", ".join(res.failures))
    if not args.only and total != expected:
        print(f"FATAL: {total} checks ran, expected exactly {expected}.")
        return 2
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
