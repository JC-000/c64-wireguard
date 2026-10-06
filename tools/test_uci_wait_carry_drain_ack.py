#!/usr/bin/env python3
"""tools/test_uci_wait_carry_drain_ack.py — red/green for issues #150 and #148.

The two defects
---------------
#150. `uci_push_wait` returns C=1 with net_last_error = UCI_ERR_WAIT_TIMEOUT
($89) when CMD_BUSY never clears within its TOD budget. At `net_udp_close`,
`uci_udp_connect` and `net_poll` the carry was ignored and control fell into
`uci_check_err`, which re-diagnosed the timeout from whatever the transport
ERROR bit said at that moment: ERROR set -> the path's own code ($82 / $84 /
$86); ERROR clear -> the "command completed" path ($88 from connect's empty
id read; C=0 from close). Expected, from #150: C=1 and $89, with the ERROR
bit both SET and CLEAR at the moment of the timeout.

#148. A transaction is closed by ONE DATA_ACC, the accept that returns
command_protocol.vhd's state machine to idle. When a wait or drain times out
after the PUSH_CMD, nobody accepts the reply — and it may not even exist yet:
the firmware writes HANDSHAKE_ACCEPT_COMMAND only after parse_command
returns, then copy_result stages the reply (command_intf.cc run_task), so a
command that outlives the C64's budget completes AFTER the caller has given
up, into STATE 10 (or 11 for a multi-block reply). That reply is an ORPHAN.
Left alone it wrecks the next command: a PUSH_CMD outside STATE 00 is
dropped (`else error_busy <= '1'`) while the command bytes written before it
still advanced `command_pointer` (command-slot writes are not state-gated),
and only the firmware's accept of a command rewinds that pointer — so the
NEXT accepted command arrives with the dropped one's bytes in front of it.
(An accept issued at the timed-out exit cannot help: in STATE 01 the accept
arm is gated off, command_protocol.vhd `state(1) = '1'`.)

What this suite asserts
-----------------------
P (#150, every push site x err0/err1): C=1 and $89; the site's own
  bookkeeping; then the firmware completes LATE (the orphan), and the next
  call must accept the orphan at its gate — the $DF1C <- $02 write trapped,
  for that transaction, before the next command's first byte, which must be
  written in STATE 00 — and land: `uci_udp_connect` after an orphan opens
  the socket and the SOCKET_WRITE puts exactly ONE datagram on the wire;
  a `net_poll` after an orphan delivers its datagram and the SOCKET_WRITE
  after it is a SOCKET_WRITE, not a READ with a write glued on.
D (#148, every drain-timeout exit, plain and chunked send, close, DHCP):
  C=1 and $89, the orphan cleared before the next command, next commands land.
M Data More orphans: a k-block orphan is accepted block by block at the gate
  and the next commands land — also when each VALIDATE_MORE lands long
  before the firmware clears DATA_ACC; one that never ends returns $89
  within the gate's single budget, writing no command byte, not hanging.
L `net_poll` @len_bad: a drain that times out behind an over-long header
  still reports $8A (UCI_ERR_LONG_READ), not the drain's $89.

The ERROR axis (err0/err1). error_busy is written only at :150 (CLR_ERR),
:159 (a REFUSED push) and :301 (reset); an accepted push never latches it
and the firmware cannot set it. So:
  P err1 — error_busy was left set by an earlier/foreign refused push BEFORE
           the call (sticky across our later accepted push). On a tree whose
           idle gate clears it (1c67912+) ERROR is clear again by the time
           the push times out, so err1 and err0 meet the SAME timeout; what
           err1 still distinguishes is whether the gate cleared it at all:
           without that, the stale bit makes the NEXT command's
           uci_check_err blame itself ($84 / $86). Those six next-* checks
           are the guard's only killers.
  D *-err-* — foreign software pushes WHILE our transaction is in flight;
           that push is refused and latches error_busy after our gate, so
           uci_check_err takes the post-push ERROR branch.

Reachability, per check class (counts per speed; printed at the end too):
  CONTROL     F, S (fixed), CTRL — the model and the instrument.
  REACHABLE   P (push-timeout orphans), M finite Data More chains: firmware
              latency past the 5 s budget. Reachable; how often is
              HARDWARE-ONLY.
  REACHABLE-1MHZ  L: a drain that outruns 5 s needs > ~440 B undrained at
              1 MHz (~11.2 ms per fenced byte), which an over-long SOCKET_READ
              can leave; modelled here by a stuck queue.
  DEFENSIVE-STATUS  D/*-status (7 sites): IMPOSSIBLE in the RTL —
              status_length is 8 bits (:235) and the pointer saturates at
              base+255 (:183-185); 255 B x ~11.2 ms = ~2.85 s < 5 s.
  DEFENSIVE-ERRBRANCH  D/sb-err-resp, D/sp-err-resp: the post-push ERROR
              branches ($85 / uci_send_part's) are unreachable by our own
              code behind the gate; only a foreign push mid-transaction gets
              there.
  DEFENSIVE-RESP  D/sb-ok-resp, sp-done-resp, sp-more-resp, close-resp,
              dhcp-resp: resp-drain stalls on replies of <= 12 B need
              response_length > 895 (pointer saturation) — firmware fault.
  DEFENSIVE-FAULT  M/more-forever: a Data More chain that never ends.
The DEFENSIVE checks pin what the adapter does if the impossible happens;
they are NOT evidence that the reachable behaviour works.

What runs, and why not VICE
---------------------------
VICE has no UCI ($DF1D reads $FF). This suite executes the REAL routines out
of the REAL `wireguard.prg` — a `make BACKEND=uci` tree AND a
`make BACKEND=uci UCI_CHUNKED_WRITE=1` tree — on tools/uci/mos6502.py,
against `RtlUci`, a model of $DF1C-$DF1F written from 1541ultimate's
fpga/io/command_interface/vhdl_source/command_protocol.vhd and
software/io/command_interface/command_intf.cc:

  * status = DATA_AV | STAT_AV | STATE | ERROR | CMD_BUSY; DATA_AV/STAT_AV
    only while state(1)='1' (Data Last/More) and abort is clear.
  * command-slot writes append at command_pointer whatever the state,
    saturating at 895; only the firmware's ACCEPT_COMMAND rewinds it.
  * PUSH_CMD: STATE 00 -> 01 + CMD_BUSY; otherwise error_busy, command
    dropped, pointer NOT rewound.
  * firmware: parse_command (does the work, emits the datagram) ->
    ACCEPT_COMMAND (CMD_BUSY clears, pointer rewound) -> copy_result
    (VALIDATE_LAST -> 10, VALIDATE_MORE -> 11).
  * DATA_ACC only in state(1)='1' (in 01 it is a no-op): 10 -> 00;
    11 -> 01 with handshake_in(1) (status bit 1, DATA_ACC) <= state(0).
    The firmware runs on the RISING edge of DATA_ACC only: get_more_data ->
    copy_result (VALIDATE_* -> 1x) and only THEN HANDSHAKE_ACCEPT_NEXTDATA
    clears DATA_ACC (command_intf.cc run_task). An accept in that window
    (1x with DATA_ACC still 1) makes no edge, so the next block is never
    requested. M/3-block-acc-window stretches that window to 20-40 ms,
    several polls wide at either speed.

Stall injection, selectable per transaction phase, TOD advancing throughout:
  push       — parse_command outlives the budget: CMD_BUSY never clears
               while the caller waits; the firmware completes when the test
               says so (after the call returned) -> an orphan in 10.
  push-more  — likewise, completing as k Data More blocks then Data Last.
  push-more-forever — completing as Data More that never ends.
  resp       — DATA_AV never clears (response length beyond the pointer's
               reach, so the pointer saturates short of it).
  status     — STAT_AV never clears, likewise.
and the ERROR axis described above.

Speed axis. CIA1 TOD is wall time at the CPU clock under test (mhz*100 000
cycles per tenth); device latencies are wall-clock µs converted the same
way. Every case runs at each speed in --mhz (default 1,48). TOD runs at
the 1 MHz rate (100 000 cycles per tenth) ONLY while an injected stall is
active or the interface is QUIESCENT (nothing scheduled in the firmware,
nothing for the CPU to read, STATE != 00 — the next change can only come
from a C64 write). Either way a 5 s budget costs 5 M interpreted cycles at
48 MHz rather than 240 M. Neither state changes by itself, so nothing in
it depends on polls per tenth; a correct gate leaves the quiescent state
within one poll, and every healthy phase — push, accept, staging, block
copies, drains with data present, follow-up commands — keeps its 48 MHz
timing. Runtime: ~3-4 min GREEN; a broken tree is similar.

Randomised: payload bytes, lengths, socket id, peer address/port, inbound
datagrams, Data More chain lengths and device latencies come from a seeded
RNG (seed on the first line; reproduce with --seed / TEST_SEED). Outbound
payload bytes are drawn from $00-$7F, inbound from $80-$FF, so an echo
cannot pass a reply check.

HARDWARE-ONLY: how often firmware latency outruns the budget (the
REACHABLE class). The DEFENSIVE classes are answered by the RTL above.

Usage:
    python3 tools/test_uci_wait_carry_drain_ack.py [--seed N] [--mhz 1,48]
        [--build DIR --build-chunked DIR] [--only GROUP]
Env:
    C64_SKIP_BUILD=1     do not build; requires --build and --build-chunked
    TEST_SEED=N          same as --seed
    UCI_WAIT_TURBO_MHZ   comma list, same as --mhz
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.mos6502 import Mos6502, CpuBudgetExceeded  # noqa: E402

# --- UCI registers (src/net/uci/uci_regs.inc) --------------------------------
UCI_STATUS, UCI_CMD_DATA = 0xDF1C, 0xDF1D
UCI_RESP_DATA, UCI_STATUS_DATA = 0xDF1E, 0xDF1F
UCI_ID_VALUE = 0xC9
STAT_DATA_AV, STAT_STAT_AV, STAT_ERROR, STAT_CMD_BUSY = 0x80, 0x40, 0x08, 0x01
STAT_DATA_ACC = 0x02                    # handshake_in(1): accepted, firmware not done
STATE_IDLE, STATE_BUSY, STATE_DATA_LAST, STATE_DATA_MORE = 0x00, 0x10, 0x20, 0x30
CTRL_PUSH_CMD, CTRL_NEXT_DATA, CTRL_ABORT, CTRL_CLR_ERR = 0x01, 0x02, 0x04, 0x08

TARGET_NETWORK = 0x03
CMD_GET_IFACE_COUNT, CMD_GET_IPADDR = 0x02, 0x05
CMD_UDP_CONNECT, CMD_SOCKET_CLOSE = 0x08, 0x09
CMD_SOCKET_READ, CMD_SOCKET_WRITE, CMD_WRITE_CHUNK = 0x10, 0x11, 0x16
CMD_BUF_MAX = 895                       # c_cmd_if_command_buffer_end, saturating
READ_CHUNK_MAX = 1472                   # UCI_READ_CHUNK_MAX
PART_MAX = 888                          # UCI_CHUNK_PART_MAX
PLAIN_SEND_MAX = 892                    # NET_UDP_SEND_MAX without the flag

ST_OK = b"00,OK"
ST_UNKNOWN = b"21,UNKNOWN COMMAND"
ST_INVALID = b"81,INVALID PARAMS"

# net_last_error codes (src/net/uci/uci_errors.inc)
ERR_WAIT_TIMEOUT, ERR_LONG_READ = 0x89, 0x8A
WAIT_BUDGET_TENTHS = 50                 # UCI_WAIT_IDLE_BUDGET_TENTHS

CIA_TOD_TENTHS, CIA_TOD_SEC, CIA_TOD_MIN, CIA_TOD_HOUR = 0xDC08, 0xDC09, 0xDC0A, 0xDC0B
STALL_CYCLES_PER_TENTH = 100_000        # TOD rate while a stall is active

SEND_BUF = 0xC000                       # free RAM in a BACKEND=uci image
HANG_BUDGET_S = 40.0                    # simulated wall time before "hung"

PUSH_SITES = ("close", "connect", "poll")
PLAIN_DRAIN_SITES = ("sb-err-resp", "sb-err-status", "sb-ok-resp", "sb-ok-status",
                     "close-resp", "close-status", "dhcp-resp", "dhcp-status")
CHUNK_DRAIN_SITES = ("sp-err-resp", "sp-err-status", "sp-done-resp",
                     "sp-done-status", "sp-more-resp", "sp-more-status")
CHECKS_PER_PUSH = {"close": 4, "connect": 4, "poll": 5}
CHECKS_PER_DRAIN_RUN = 5
CHECKS_PER_CONTROL = 3                  # per build per speed
CHECKS_MORE = 8                         # M group per speed
CHECKS_LENBAD = 4                       # L group per speed
CHECKS_FIXED = 3                        # fidelity + two structural


def check_class(name):
    """Reachability class of a check name (see the module docstring)."""
    g = name.split("/")[0]
    if g in ("F", "S", "CTRL"):
        return "CONTROL"
    if g == "P":
        return "REACHABLE"
    if g == "L":
        return "REACHABLE-1MHZ"
    if g == "M":
        return "DEFENSIVE-FAULT" if name.startswith("M/more-forever") else "REACHABLE"
    site = name.split("/")[1].split("@")[0]
    if site.endswith("-status"):
        return "DEFENSIVE-STATUS"
    if "-err-" in site:
        return "DEFENSIVE-ERRBRANCH"
    return "DEFENSIVE-RESP"


def checks_expected(n_speeds):
    push = 2 * sum(CHECKS_PER_PUSH.values())
    drain = (len(PLAIN_DRAIN_SITES) + len(CHUNK_DRAIN_SITES)) * CHECKS_PER_DRAIN_RUN
    per = push + drain + 2 * CHECKS_PER_CONTROL + CHECKS_MORE + CHECKS_LENBAD
    return CHECKS_FIXED + n_speeds * per


def fingerprint(path: Path) -> str:
    raw = path.read_bytes()
    return (f"sha256={hashlib.sha256(raw).hexdigest()} ({len(raw)} B) "
            f"mtime={datetime.fromtimestamp(path.stat().st_mtime).isoformat(' ', 'seconds')}")


# =============================================================================
# Build (registered SERIAL in the gate: it mutates build/)
# =============================================================================
def _make(*args):
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", *args], capture_output=True, text=True,
                       cwd=PROJECT_ROOT)
    if r.returncode != 0 or not (PROJECT_ROOT / "build" / "wireguard.prg").exists():
        raise SystemExit(f"FATAL: make {' '.join(args)} failed (rc={r.returncode}):\n"
                         f"{r.stderr[-3000:]}")


def build_both(dest: Path):
    out = {}
    for name, args in (("plain", ["BACKEND=uci"]),
                       ("chunked", ["BACKEND=uci", "UCI_CHUNKED_WRITE=1"])):
        print(f"Building: make clean && make {' '.join(args)}")
        _make(*args)
        d = dest / name
        d.mkdir(parents=True)
        for f in ("wireguard.prg", "wireguard.dbg", "labels.txt"):
            shutil.copy2(PROJECT_ROOT / "build" / f, d / f)
        out[name] = d
    return out


def restore_default_tree():
    print("Restoring the default build tree: make clean && make")
    _make()
    print(f"  restored: {fingerprint(PROJECT_ROOT / 'build' / 'wireguard.prg')}")


def load_symbols(build: Path) -> dict:
    syms: dict[str, int] = {}
    pat = re.compile(r'name="([^"]+)"[^\n]*?,val=0x([0-9A-Fa-f]+)')
    for line in (build / "wireguard.dbg").read_text().splitlines():
        if line.startswith("sym\t"):
            m = pat.search(line)
            if m:
                syms.setdefault(m.group(1), int(m.group(2), 16))
    return syms


def load_labels(build: Path) -> dict:
    out = {}
    for line in (build / "labels.txt").read_text().splitlines():
        m = re.match(r"al C:([0-9A-Fa-f]{4}) \.(\S+)", line)
        if m:
            out.setdefault(m.group(2), int(m.group(1), 16))
    return out


# =============================================================================
# RTL model of $DF1C-$DF1F + the firmware's network target
# =============================================================================
class Stall:
    """Which transaction stalls, and in which phase.

    `match(cmd)` selects the transaction by its command bytes (first match
    only). `more`: Data More blocks before the last (push-more). `err`:
    FOREIGN software issues a PUSH_CMD while this transaction is in flight;
    the FPGA refuses it (:159) and error_busy latches — the only way the
    RTL sets it. Used by the D/*-err-* sites to reach the post-push ERROR
    branches, which our own code cannot reach behind its gate.
    """

    def __init__(self, match, phase, err=0, more=0, race=False):
        self.match, self.phase, self.err, self.more = match, phase, err, more
        self.race = race                # VALIDATE_MORE lands long before
                                        # ACCEPT_NEXTDATA clears DATA_ACC
        self.tx = None                  # transaction index it hit
        self.cmd = None
        self.released = False


class RtlUci:
    def __init__(self, *, mhz, rng, sid, stall=None):
        self.mhz = mhz
        self.rng = rng
        self.sid = sid
        self.stall = stall
        self.cycles = 0
        self.seq = itertools.count()
        self.state = STATE_IDLE
        self.cmd_busy = 0
        self.data_acc = 0                   # handshake_in(1)
        self.error = 0
        self.foreign_pushes = 0
        self.abort = 0
        self.cmd_buf = bytearray()
        self.resp, self.resp_ptr, self.resp_stuck = b"", 0, False
        self.stat, self.stat_ptr, self.stat_stuck = b"", 0, False
        self._due = []
        self.accepted: list[bytes] = []     # commands the firmware accepted
        self.dropped: list[bytes] = []      # pushes refused (error_busy)
        self.accepts: list[tuple] = []      # (tx, seq) of each data-state DATA_ACC
        self.wire: list[bytes] = []         # datagrams emitted
        self.inbound: list[bytes] = []      # datagrams queued for SOCKET_READ
        self.cur_tx = None                  # tx whose reply is staged
        self._more_left = 0
        self._forever = False
        self._parts = None                  # $16 assembly
        self.first_byte = None              # (seq, state, busy) — armed by watch()
        self._watching = False
        self.lease = bytes([10, rng.randrange(256), rng.randrange(256),
                            rng.randrange(1, 255)]) + bytes([255, 255, 255, 0]) + bytes(4)

    # ---- time ------------------------------------------------------------
    def us(self, n):
        return int(n * self.mhz)

    def sync(self, cycles):
        self.cycles = cycles
        while self._due and cycles >= self._due[0][0]:
            _, _, fn = self._due.pop(0)
            fn()

    def _at(self, delay, fn):
        self._due.append((self.cycles + delay, next(self.seq), fn))
        self._due.sort(key=lambda e: (e[0], e[1]))

    def stalling(self):
        """True while TOD should tick at the 1 MHz rate: an injected stall,
        or a QUIESCENT interface — nothing scheduled in the firmware, no
        byte for the CPU to read, STATE != 00 — where the next change can
        only come from a C64 write. A correct gate leaves that state within
        one poll; a broken tree spins in it for its whole budget, which at
        48 MHz would cost 240 M interpreted cycles per timeout."""
        if (not self._due and self.state != STATE_IDLE
                and not self.status() & (STAT_DATA_AV | STAT_STAT_AV)):
            return True
        s = self.stall
        if s is None or s.tx is None:
            return False
        if s.phase == "push-more-forever" and s.released:
            return True                     # the injected fault never ends
        if s.released:
            return False
        if s.phase.startswith("push"):
            return bool(self.cmd_busy)
        return self.resp_stuck or self.stat_stuck

    def release(self):
        """The fault ends. A stuck queue now ends where its pointer is; a
        command stuck in parse_command COMPLETES NOW — after its caller gave
        up — and its reply is staged for nobody: the orphan."""
        s = self.stall
        if s is None or s.released:
            return
        s.released = True
        if self.resp_stuck:
            self.resp, self.resp_stuck = self.resp[:self.resp_ptr], False
        if self.stat_stuck:
            self.stat, self.stat_stuck = self.stat[:self.stat_ptr], False
        if s.phase.startswith("push") and s.tx is not None and self.cmd_busy:
            self._complete(s.cmd, hit=True)

    # ---- firmware network target (network_target.cc, as this repo uses it)
    def _reply(self, cmd: bytes):
        if len(cmd) < 2 or cmd[0] != TARGET_NETWORK:
            return b"", ST_UNKNOWN
        op = cmd[1]
        if op == CMD_GET_IFACE_COUNT:
            return b"\x01", ST_OK
        if op == CMD_GET_IPADDR:
            return self.lease, ST_OK
        if op == CMD_UDP_CONNECT:
            return bytes([self.sid]), ST_OK
        if op == CMD_SOCKET_CLOSE:
            return b"", ST_OK
        if op == CMD_SOCKET_WRITE:
            data = cmd[3:]
            self.wire.append(bytes(data))
            n = len(data)
            return bytes([n & 0xFF, n >> 8]), ST_OK
        if op == CMD_WRITE_CHUNK:
            if len(cmd) < 7:
                return b"", ST_INVALID
            off = cmd[3] | (cmd[4] << 8)
            total = cmd[5] | (cmd[6] << 8)
            data = cmd[7:]
            if off == 0:
                self._parts = (total, bytearray())
            if self._parts is None or self._parts[0] != total \
                    or len(self._parts[1]) != off or off + len(data) > total:
                self._parts = None
                return b"", ST_INVALID
            self._parts[1].extend(data)
            if off + len(data) == total:
                self.wire.append(bytes(self._parts[1]))
                self._parts = None
                return bytes([total & 0xFF, total >> 8]), ST_OK
            return b"", ST_OK
        if op == CMD_SOCKET_READ:
            if self.inbound:
                d = self.inbound.pop(0)
                return bytes([len(d) & 0xFF, len(d) >> 8]) + d, ST_OK
            return b"\xff\xff", ST_OK           # measured no-data sentinel
        return b"", ST_UNKNOWN

    def _push(self):
        if self.state != STATE_IDLE:
            self.error = 1                      # error_busy; dropped, pointer kept
            self.dropped.append(bytes(self.cmd_buf))
            return
        self.state, self.cmd_busy = STATE_BUSY, 1
        cmd = bytes(self.cmd_buf)
        s = self.stall
        hit = s is not None and s.tx is None and s.match(cmd)
        if hit:
            s.tx, s.cmd = len(self.accepted), cmd
            if s.phase.startswith("push"):
                return                          # parse_command still running
        self._at(self.us(self.rng.randrange(100, 900)),
                 lambda: self._complete(cmd, hit))

    def _complete(self, cmd, hit):
        """parse_command returned: ACCEPT_COMMAND, then copy_result."""
        data, status = self._reply(cmd)
        tx = len(self.accepted)
        self.accepted.append(cmd)
        self.cmd_buf = bytearray()              # HANDSHAKE_ACCEPT_COMMAND
        self.cmd_busy = 0
        phase = self.stall.phase if hit else None
        if hit and self.stall.err and not phase.startswith("push"):
            self.foreign_refused_push()         # STATE is still 01 here

        def validate():
            self.resp, self.resp_ptr = data, 0
            self.stat, self.stat_ptr = status, 0
            self.resp_stuck = phase == "resp"
            self.stat_stuck = phase == "status"
            self.cur_tx = tx
            if phase in ("push-more", "push-more-forever"):
                self._more_left = self.stall.more
                self._forever = phase == "push-more-forever"
                self.state = STATE_DATA_MORE
            else:
                self.state = STATE_DATA_LAST
        if hit and (self.stall.err or phase.startswith("push")):
            validate()                          # staged by the next status read
        else:
            self._at(self.us(self.rng.randrange(2, 40)), validate)

    def foreign_refused_push(self):
        """Another program writes PUSH_CMD ($01 to $DF1C) while STATE != 00:
        command_protocol.vhd :152-160 refuses it and sets error_busy, and
        does nothing else (no pointer move, no state change)."""
        assert self.state != STATE_IDLE, "a push from 00 would be ACCEPTED"
        self.foreign_pushes += 1
        self.error = 1

    def latch_stale_error(self):
        """error_busy is written only at :150 (clear), :159 (refused push)
        and :301 (reset), and is sticky across later accepted pushes. This
        models a refused push by earlier or foreign software having left it
        set before the call under test — not a state our own push creates."""
        self.foreign_pushes += 1
        self.error = 1

    def _data_accepted(self):
        """run_task on CMD_DATA_ACCEPTED (the rising edge of handshake_in(1)):
        get_more_data + copy_result (VALIDATE_*), and only THEN
        HANDSHAKE_ACCEPT_NEXTDATA clears handshake_in(1) (command_intf.cc)."""
        self._next_block()
        race = self.stall is not None and self.stall.race
        window = self.rng.randrange(20000, 40000) if race else self.rng.randrange(1, 6)
        self._at(self.us(window), self._accept_nextdata)

    def _accept_nextdata(self):
        self.data_acc = 0

    def _next_block(self):
        """get_more_data -> copy_result: stage the next block."""
        self.resp = bytes(self.rng.randrange(0x80, 0x100)
                          for _ in range(self.rng.randrange(1, 64)))
        self.resp_ptr, self.stat, self.stat_ptr = 0, b"", 0
        if self._forever or self._more_left > 1:
            self._more_left -= 1
            self.state = STATE_DATA_MORE
        else:
            self.state = STATE_DATA_LAST

    def _firmware_abort(self):
        # HANDSHAKE_RESET ($87): bit 0 rewinds the pointer and clears
        # handshake_in(0), bit 1 clears handshake_in(1), bit 2 the abort
        # bit, bit 7 forces STATE 00.
        self.state, self.cmd_busy, self.abort = STATE_IDLE, 0, 0
        self.data_acc = 0
        self.cmd_buf = bytearray()
        self.resp, self.stat = b"", b""
        self.resp_stuck = self.stat_stuck = False

    # ---- bus ---------------------------------------------------------------
    def _data_state(self):
        return bool(self.state & 0x20) and not self.abort

    def status(self):
        s = (self.state | (STAT_ERROR if self.error else 0) | self.cmd_busy
             | (STAT_DATA_ACC if self.data_acc else 0))
        if self._data_state() and (self.resp_ptr < len(self.resp) or self.resp_stuck):
            s |= STAT_DATA_AV
        if self._data_state() and (self.stat_ptr < len(self.stat) or self.stat_stuck):
            s |= STAT_STAT_AV
        return s

    def read(self, addr):
        if addr == UCI_STATUS:
            return self.status()
        if addr == UCI_CMD_DATA:
            return UCI_ID_VALUE
        if addr == UCI_RESP_DATA:
            v = self.resp[self.resp_ptr] if self.resp_ptr < len(self.resp) else 0
            if self.resp_ptr < len(self.resp):
                self.resp_ptr += 1
            return v if self._data_state() else 0
        if addr == UCI_STATUS_DATA:
            v = self.stat[self.stat_ptr] if self.stat_ptr < len(self.stat) else 0
            if self.stat_ptr < len(self.stat):
                self.stat_ptr += 1
            return v if self._data_state() else 0
        return 0

    def write(self, addr, value):
        seq = next(self.seq)
        if addr == UCI_CMD_DATA:
            if self._watching and self.first_byte is None:
                self.first_byte = (seq, self.state, self.cmd_busy)
            if len(self.cmd_buf) < CMD_BUF_MAX:
                self.cmd_buf.append(value)
            return
        if addr != UCI_STATUS:
            return
        if value & CTRL_CLR_ERR:
            self.error = 0
        if value & CTRL_PUSH_CMD:
            self._push()
        if value & CTRL_NEXT_DATA and self.state & 0x20:
            # command_protocol.vhd: handshake_in(1) <= state(0); state(1) <= 0.
            # The firmware is interrupted on the RISING edge of handshake_in(1)
            # only, so an accept while it is still set requests nothing.
            self.accepts.append((self.cur_tx, seq))
            more = self.state == STATE_DATA_MORE
            rising = more and not self.data_acc
            self.data_acc = 1 if more else 0
            self.state = STATE_BUSY if more else STATE_IDLE
            self.resp, self.resp_ptr, self.stat, self.stat_ptr = b"", 0, b"", 0
            self.resp_stuck = self.stat_stuck = False
            if rising:
                self._at(self.us(self.rng.randrange(20, 200)), self._data_accepted)
        if value & CTRL_ABORT and not self.abort:
            self.abort = 1
            self._at(self.us(200), self._firmware_abort)

    def watch(self):
        """Trap the next command's first command-slot byte."""
        self._watching, self.first_byte = True, None

    def describe(self):
        return (f"state=${self.state:02X} busy={self.cmd_busy} "
                f"data_acc={self.data_acc} err={self.error} "
                f"cmd_ptr={len(self.cmd_buf)} accepted={len(self.accepted)} "
                f"dropped={len(self.dropped)} accepts(tx)={[t for t, _ in self.accepts]} "
                f"wire={len(self.wire)}")


class Tod:
    """CIA1 TOD, 10 Hz of wall time at the CPU clock under test; at the 1 MHz
    rate while the device reports an injected stall (see the module doc)."""

    def __init__(self, mhz, device):
        self.per_tenth = mhz * 100_000
        self.dev = device
        self.last = None
        self.tenths = 0.0
        self.latched = None

    def advance(self, cycles):
        if self.last is None:
            self.last = cycles
        rate = (STALL_CYCLES_PER_TENTH if self.dev.stalling()
                else self.per_tenth)
        self.tenths += (cycles - self.last) / rate
        self.last = cycles

    def _now(self):
        t = int(self.tenths)
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
        return 0


class Run:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Machine:
    REQUIRED = ("net_udp_send", "net_udp_close", "net_poll", "net_last_error",
                "net_dhcp_acquire",
                "uci_socket_open", "uci_socket_id", "net_udp_send_len",
                "net_udp_dest_ip", "net_udp_dest_port", "udp_recv_ready",
                "udp_recv_len", "udp_recv_buf", "uci_status_leading_code",
                "uci_status_buf")
    EXPORTED = ("net_udp_send", "net_udp_close", "net_poll", "net_last_error",
                "net_dhcp_acquire", "uci_socket_open", "uci_socket_id",
                "udp_recv_buf")

    def __init__(self, build: Path, flavour: str):
        self.flavour = flavour
        raw = (build / "wireguard.prg").read_bytes()
        self.load_addr, self.image = raw[0] | (raw[1] << 8), raw[2:]
        self.sym = load_symbols(build)
        self.labels = load_labels(build)
        missing = [n for n in self.REQUIRED if n not in self.sym]
        if missing:
            raise SystemExit(f"FATAL: {flavour}: symbol(s) {missing} not in "
                             f"wireguard.dbg — is this a BACKEND=uci build?")
        for n in self.EXPORTED:
            if self.labels.get(n) != self.sym[n]:
                raise SystemExit(f"FATAL: {flavour}: labels.txt {n}="
                                 f"{self.labels.get(n)} disagrees with "
                                 f"wireguard.dbg ${self.sym[n]:04X}")
        end = self.load_addr + len(self.image)
        if end > SEND_BUF:
            raise SystemExit(f"FATAL: image ends ${end:04X}, over the test's "
                             f"send buffer at ${SEND_BUF:04X}")
        self.mem = bytearray(0x10000)
        self.mem[self.load_addr:end] = self.image

    def socket(self, sid, ip, port, opened=True):
        s, m = self.sym, self.mem
        m[s["uci_socket_open"]] = 1 if opened else 0
        m[s["uci_socket_id"]] = sid if opened else 0
        m[s["net_udp_dest_ip"]:s["net_udp_dest_ip"] + 4] = ip
        m[s["net_udp_dest_port"]] = port >> 8             # big-endian (net.s)
        m[s["net_udp_dest_port"] + 1] = port & 0xFF
        m[s["udp_recv_ready"]] = 0

    def call(self, device, entry, *, mhz, a=0, x=0, err_witness=0xEE):
        s, mem = self.sym, self.mem
        tod = Tod(mhz, device)

        def io_read(addr):
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                return device.read(addr)
            if 0xDC00 <= addr <= 0xDCFF:
                tod.advance(cpu.cycles)
                return tod.read(addr)
            return 0xFF

        def io_write(addr, value):
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                device.write(addr, value)

        cpu = Mos6502(mem, io_read, io_write)
        cpu.cycles = device.cycles
        tod.last = device.cycles
        tod.tenths = getattr(device, "_tod_tenths", 0.0)
        t0 = tod.tenths
        cpu.a, cpu.x = a, x
        mem[s["net_last_error"]] = err_witness
        hung = None
        try:
            cpu.call(s[entry] if isinstance(entry, str) else entry,
                     max_cycles=int(HANG_BUDGET_S * mhz * 1_000_000))
        except CpuBudgetExceeded as exc:
            hung = str(exc)
        device.sync(cpu.cycles)
        tod.advance(cpu.cycles)
        device._tod_tenths = tod.tenths
        return Run(carry=cpu.c, a=cpu.a, hung=hung, err=mem[s["net_last_error"]],
                   tenths=tod.tenths - t0)

    def send(self, device, payload, *, mhz):
        s, mem = self.sym, self.mem
        mem[SEND_BUF:SEND_BUF + len(payload)] = payload
        mem[s["net_udp_send_len"]] = len(payload) & 0xFF
        mem[s["net_udp_send_len"] + 1] = len(payload) >> 8
        return self.call(device, "net_udp_send", mhz=mhz,
                         a=SEND_BUF & 0xFF, x=SEND_BUF >> 8)

    def recv(self):
        s, mem = self.sym, self.mem
        n = mem[s["udp_recv_len"]] | (mem[s["udp_recv_len"] + 1] << 8)
        return mem[s["udp_recv_ready"]], bytes(mem[s["udp_recv_buf"]:s["udp_recv_buf"] + n])


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


def out_payload(rng, lo, hi):
    return bytes(rng.randrange(0x00, 0x80) for _ in range(rng.randrange(lo, hi + 1)))


def in_payload(rng, lo, hi):
    return bytes(rng.randrange(0x80, 0x100) for _ in range(rng.randrange(lo, hi + 1)))


def peer(rng):
    return (rng.randrange(1, 255), bytes([rng.randrange(1, 224), rng.randrange(256),
                                          rng.randrange(256), rng.randrange(1, 255)]),
            rng.randrange(1024, 65536))


def write_cmds(flavour, sid, payload):
    """The command bytes a correct adapter puts on the bus for one datagram."""
    if flavour == "plain":
        return [bytes([TARGET_NETWORK, CMD_SOCKET_WRITE, sid]) + payload]
    out, off, total = [], 0, len(payload)
    while off < total:
        part = payload[off:off + PART_MAX]
        out.append(bytes([TARGET_NETWORK, CMD_WRITE_CHUNK, sid, off & 0xFF, off >> 8,
                          total & 0xFF, total >> 8]) + part)
        off += len(part)
    return out


def read_cmd(sid):
    return bytes([TARGET_NETWORK, CMD_SOCKET_READ, sid,
                  READ_CHUNK_MAX & 0xFF, READ_CHUNK_MAX >> 8])


def connect_cmd(ip, port):
    """UDP_CONNECT: port lo, port hi, dotted-decimal host, NUL (net.s)."""
    host = ".".join(str(b) for b in ip).encode()
    return bytes([TARGET_NETWORK, CMD_UDP_CONNECT, port & 0xFF, port >> 8]) + host + b"\0"


def is_op(*ops):
    return lambda c: len(c) >= 2 and c[0] == TARGET_NETWORK and c[1] in ops


def check_orphan_cleared(res, tag, dev, tx):
    """The orphaned reply of transaction `tx` was accepted ($DF1C <- $02 in a
    data state, trapped) BEFORE the next command's first byte, and that byte
    was written in STATE 00 with CMD_BUSY clear — i.e. at a rewound pointer."""
    fb = dev.first_byte
    acc = [q for t, q in dev.accepts if t == tx]
    ok = (tx is not None and fb is not None and bool(acc) and acc[-1] < fb[0]
          and fb[1] == STATE_IDLE and fb[2] == 0)
    res.check(ok, f"{tag}/orphan-accepted-before-next-command",
              f"orphan tx={tx}: DATA_ACCs for it at seq {acc}; next command's "
              f"first byte {'never written' if fb is None else f'at seq {fb[0]} in STATE ${fb[1]:02X} busy={fb[2]}'}"
              f" (want an accept before it and STATE $00). {dev.describe()}")


def follow_poll_send(ctx, res, m, dev, mhz, tag, sid, orphan_tx):
    """A SOCKET_READ that must deliver a staged inbound datagram, then a
    SOCKET_WRITE that must land whole. 2 checks (+1 orphan check)."""
    rng = ctx["rng"]
    inbound = in_payload(rng, 1, 600)
    dev.inbound.append(inbound)
    m.mem[m.sym["udp_recv_ready"]] = 0
    a0, d0 = len(dev.accepted), len(dev.dropped)
    dev.watch()
    r = m.call(dev, "net_poll", mhz=mhz)
    if orphan_tx is not False:
        check_orphan_cleared(res, tag, dev, orphan_tx)
    ready, got = m.recv()
    res.check(r.hung is None and r.carry == 0 and ready == 1 and got == inbound
              and dev.accepted[a0:] == [read_cmd(sid)] and len(dev.dropped) == d0,
              f"{tag}/next-poll-lands",
              f"follow-up net_poll: hung={r.hung} C={r.carry} err=${r.err:02X} "
              f"ready={ready} got {len(got)} B (want {len(inbound)} B "
              f"{'equal' if got == inbound else 'DIFFERENT'}); accepted since="
              f"{[c[:8].hex() for c in dev.accepted[a0:]]} want "
              f"[{read_cmd(sid).hex()}]; dropped since={len(dev.dropped) - d0}. "
              f"{dev.describe()}")
    payload = out_payload(rng, 1, 300)
    a0, d0, w0 = len(dev.accepted), len(dev.dropped), len(dev.wire)
    r = m.send(dev, payload, mhz=mhz)
    want = write_cmds(m.flavour, sid, payload)
    got_cmds = dev.accepted[a0:]
    res.check(r.hung is None and r.carry == 0 and got_cmds == want
              and len(dev.dropped) == d0 and dev.wire[w0:] == [payload],
              f"{tag}/next-send-lands",
              f"follow-up net_udp_send of {len(payload)} B: hung={r.hung} "
              f"C={r.carry} err=${r.err:02X}; accepted {len(got_cmds)} cmd(s) "
              f"{[(len(c), c[:6].hex()) for c in got_cmds]} want "
              f"{[(len(c), c[:6].hex()) for c in want]}; dropped since="
              f"{len(dev.dropped) - d0}; datagrams on the wire since="
              f"{len(dev.wire) - w0} (want exactly 1, equal to the payload). "
              f"{dev.describe()}")


def follow_connect_send(ctx, res, m, dev, mhz, tag, sid, ip, port, orphan_tx):
    """No socket open: net_udp_send must UDP_CONNECT, then SOCKET_WRITE —
    both landing whole — and leave the socket open. 2 checks."""
    rng = ctx["rng"]
    m.socket(sid, ip, port, opened=False)
    payload = out_payload(rng, 1, 300)
    a0, d0, w0 = len(dev.accepted), len(dev.dropped), len(dev.wire)
    dev.watch()
    r = m.send(dev, payload, mhz=mhz)
    check_orphan_cleared(res, tag, dev, orphan_tx)
    want = [connect_cmd(ip, port)] + write_cmds(m.flavour, sid, payload)
    got_cmds = dev.accepted[a0:]
    opened = m.mem[m.sym["uci_socket_open"]]
    res.check(r.hung is None and r.carry == 0 and got_cmds == want and opened == 1
              and m.mem[m.sym["uci_socket_id"]] == sid
              and len(dev.dropped) == d0 and dev.wire[w0:] == [payload],
              f"{tag}/next-connect-and-send-land",
              f"follow-up net_udp_send (socket closed) of {len(payload)} B: "
              f"hung={r.hung} C={r.carry} err=${r.err:02X} socket_open={opened}; "
              f"accepted {[(len(c), c[:8].hex()) for c in got_cmds]} want "
              f"{[(len(c), c[:8].hex()) for c in want]}; dropped since="
              f"{len(dev.dropped) - d0}; datagrams since={len(dev.wire) - w0} "
              f"(want exactly 1, the payload). {dev.describe()}")


# =============================================================================
# Cases
# =============================================================================
def case_fidelity(ctx, res):
    """The interpreter executes a known routine out of this PRG correctly."""
    m, rng = ctx["plain"], ctx["rng"]
    code = rng.randrange(10, 100)
    buf = m.sym["uci_status_buf"]
    m.mem[buf:buf + 3] = f"{code:02d},".encode()
    dev = RtlUci(mhz=1, rng=rng, sid=1)
    r = m.call(dev, "uci_status_leading_code", mhz=1)
    res.check(r.a == code and r.hung is None, "F/interpreter-parses-status-code",
              f"uci_status_leading_code on '{code:02d},' returned A={r.a}")


def case_structural(ctx, res):
    """The two trees are the two flavours: uci_send_part is EXPORTED only by
    the chunked build (net.s exports it under UCI_CHUNKED_WRITE)."""
    p, c = ctx["plain"], ctx["chunked"]
    res.check("uci_send_part" not in p.labels, "S/plain-tree-has-no-uci_send_part",
              f"labels.txt of the plain tree exports uci_send_part "
              f"${p.labels.get('uci_send_part', 0):04X}")
    res.check("uci_send_part" in c.labels and c.labels["uci_send_part"]
              == c.sym.get("uci_send_part"), "S/chunked-tree-exports-uci_send_part",
              "labels.txt of the chunked tree lacks uci_send_part")


def case_control(ctx, res, flavour, mhz):
    """No stall: a send, then a poll, then a send. Proves the model drives a
    full transaction and that its accept trap sees ONE per transaction."""
    rng = ctx["rng"]
    m = Machine(ctx["builds"][flavour], flavour)
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid)
    hi = 1200 if flavour == "chunked" else PLAIN_SEND_MAX
    payload = out_payload(rng, 1, hi)
    r = m.send(dev, payload, mhz=mhz)
    want = write_cmds(flavour, sid, payload)
    tag = f"CTRL/{flavour}@{mhz}MHz"
    res.check(r.carry == 0 and r.hung is None and dev.accepted == want
              and dev.wire == [payload]
              and [t for t, _ in dev.accepts] == list(range(len(want)))
              and not dev.dropped,
              f"{tag}/healthy-send-one-accept-per-transaction",
              f"C={r.carry} err=${r.err:02X} hung={r.hung}; {len(payload)} B; "
              f"accepted {[(len(c), c[:6].hex()) for c in dev.accepted]} "
              f"want {[(len(c), c[:6].hex()) for c in want]}; {dev.describe()}")
    follow_poll_send(ctx, res, m, dev, mhz, tag, sid, orphan_tx=False)


def case_push_stall(ctx, res, site, err, mhz):
    """#150: CMD_BUSY never clears at this site's push while the caller
    waits; the command completes afterwards — an orphan. err=1: error_busy
    was already latched by an earlier refused push when the call began."""
    rng = ctx["rng"]
    m = Machine(ctx["builds"]["plain"], "plain")
    sid, ip, port = peer(rng)
    tag = f"P/{site}/err{err}@{mhz}MHz"
    m.socket(sid, ip, port)
    if site == "close":
        stall = Stall(is_op(CMD_SOCKET_CLOSE), "push")
        dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
        if err:
            dev.latch_stale_error()
        r = m.call(dev, "net_udp_close", mhz=mhz)
        opened = m.mem[m.sym["uci_socket_open"]]
        res.check(r.hung is None and opened == 0 and m.mem[m.sym["uci_socket_id"]] == 0
                  and stall.tx is not None,
                  f"{tag}/bookkeeping-cleared",
                  f"uci_socket_open={opened} uci_socket_id="
                  f"{m.mem[m.sym['uci_socket_id']]} after a wedged close (net.s: "
                  f"'cleared regardless'); stall hit={stall.tx is not None} hung={r.hung}")
    elif site == "connect":
        m.socket(sid, ip, port, opened=False)
        stall = Stall(is_op(CMD_UDP_CONNECT), "push")
        dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
        if err:
            dev.latch_stale_error()
        r = m.send(dev, out_payload(rng, 1, 300), mhz=mhz)
        opened = m.mem[m.sym["uci_socket_open"]]
        writes = [c for c in dev.accepted + dev.dropped + [bytes(dev.cmd_buf)]
                  if is_op(CMD_SOCKET_WRITE, CMD_WRITE_CHUNK)(c)]
        res.check(r.hung is None and opened == 0 and not writes and not dev.wire
                  and stall.tx is not None,
                  f"{tag}/no-socket-no-write",
                  f"uci_socket_open={opened}, writes={len(writes)}, "
                  f"datagrams={len(dev.wire)}, stall hit={stall.tx is not None}")
    else:
        stall = Stall(is_op(CMD_SOCKET_READ), "push")
        dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
        if err:
            dev.latch_stale_error()
        dev.inbound.append(in_payload(rng, 1, 200))
        r = m.call(dev, "net_poll", mhz=mhz)
        ready = m.mem[m.sym["udp_recv_ready"]]
        res.check(r.hung is None and ready == 0 and stall.tx is not None,
                  f"{tag}/nothing-delivered",
                  f"udp_recv_ready={ready} after a wedged SOCKET_READ; "
                  f"stall hit={stall.tx is not None}; hung={r.hung}")
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_WAIT_TIMEOUT,
              f"{tag}/C1-WAIT_TIMEOUT",
              f"C={r.carry} net_last_error=${r.err:02X} (want C=1 "
              f"${ERR_WAIT_TIMEOUT:02X}: CMD_BUSY never cleared; ERROR "
              f"{'latched by an earlier refused push' if err else 'clear'} "
              f"before the call) hung={r.hung}; "
              f"{dev.describe()}")
    dev.release()                           # the firmware completes: orphan
    if site == "poll":
        m.socket(sid, ip, port)
        follow_poll_send(ctx, res, m, dev, mhz, tag, sid, stall.tx)
    else:
        follow_connect_send(ctx, res, m, dev, mhz, tag, sid, ip, port, stall.tx)


def drain_plan(site, rng):
    """(flavour, phase, err, payload, matcher) for one drain-timeout site."""
    flavour = "chunked" if site.startswith("sp-") else "plain"
    phase = "resp" if site.endswith("-resp") else "status"
    err = 1 if "-err-" in site else 0
    payload = None
    if site.startswith("sp-more"):
        payload = out_payload(rng, PART_MAX + 1, 1472)

        def match(c):                   # the FIRST, non-completing part
            return is_op(CMD_WRITE_CHUNK)(c) and c[3:5] == b"\0\0"
    elif flavour == "chunked":
        payload = out_payload(rng, 1, 400)
        match = is_op(CMD_WRITE_CHUNK)
    elif site.startswith("close"):
        match = is_op(CMD_SOCKET_CLOSE)
    elif site.startswith("dhcp"):
        match = is_op(CMD_GET_IFACE_COUNT)
    else:
        payload = out_payload(rng, 1, 400)
        match = is_op(CMD_SOCKET_WRITE)
    return flavour, phase, err, payload, match


def case_drain_stall(ctx, res, site, mhz):
    """#148: a drain times out mid-transaction at this exit."""
    rng = ctx["rng"]
    flavour, phase, err, payload, match = drain_plan(site, rng)
    m = Machine(ctx["builds"][flavour], flavour)
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    stall = Stall(match, phase, err)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
    tag = f"D/{site}@{mhz}MHz"
    if site.startswith("close"):
        r = m.call(dev, "net_udp_close", mhz=mhz)
    elif site.startswith("dhcp"):
        r = m.call(dev, "net_dhcp_acquire", mhz=mhz)
    else:
        r = m.send(dev, payload, mhz=mhz)
    res.check(stall.tx is not None and r.hung is None, f"{tag}/stall-reached",
              f"the {phase} stall never armed (tx={stall.tx}) or the call hung "
              f"({r.hung}); {dev.describe()}")
    res.check(r.carry == 1 and r.err == ERR_WAIT_TIMEOUT, f"{tag}/C1-WAIT_TIMEOUT",
              f"C={r.carry} net_last_error=${r.err:02X}, want C=1 "
              f"${ERR_WAIT_TIMEOUT:02X}; {dev.describe()}")
    dev.release()
    # close clears the socket bookkeeping and dhcp runs before one exists:
    # model the re-connect by restoring it, so the follow-up is the same
    # SOCKET_READ + SOCKET_WRITE at every site.
    m.socket(sid, ip, port)
    follow_poll_send(ctx, res, m, dev, mhz, tag, sid, stall.tx)


def case_more(ctx, res, mhz):
    """Data More orphans: a SOCKET_READ wedged at its push completes as a
    multi-block reply after net_poll gave up."""
    rng = ctx["rng"]
    m = Machine(ctx["builds"]["plain"], "plain")
    # (a) k blocks, then Data Last: the gate must accept every one.
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    k = rng.randrange(2, 5)
    stall = Stall(is_op(CMD_SOCKET_READ), "push-more", 0, more=k)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
    dev.inbound.append(in_payload(rng, 1, 200))
    m.call(dev, "net_poll", mhz=mhz)
    dev.release()
    follow_poll_send(ctx, res, m, dev, mhz, f"M/more-{k}-blocks@{mhz}MHz", sid, stall.tx)
    # (b) the same with VALIDATE_MORE landing 20-40 ms before the
    # firmware's ACCEPT_NEXTDATA clears DATA_ACC: an accept in that window
    # requests nothing (no rising edge) and strands the chain in 01.
    m = Machine(ctx["builds"]["plain"], "plain")
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    stall = Stall(is_op(CMD_SOCKET_READ), "push-more", 0, more=2, race=True)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
    m.call(dev, "net_poll", mhz=mhz)
    dev.release()
    follow_poll_send(ctx, res, m, dev, mhz, f"M/3-block-acc-window@{mhz}MHz",
                     sid, stall.tx)
    # (c) Data More that never ends: bounded $89 at the gate, no byte written.
    m = Machine(ctx["builds"]["plain"], "plain")
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    stall = Stall(is_op(CMD_SOCKET_READ), "push-more-forever", 0)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
    m.call(dev, "net_poll", mhz=mhz)
    dev.release()
    a0, d0 = len(dev.accepted), len(dev.dropped)
    dev.watch()
    r = m.call(dev, "net_poll", mhz=mhz)
    tag = f"M/more-forever@{mhz}MHz"
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_WAIT_TIMEOUT
              and r.tenths <= WAIT_BUDGET_TENTHS + 10,
              f"{tag}/C1-WAIT_TIMEOUT-within-one-budget",
              f"net_poll behind a never-ending Data More orphan: hung={r.hung} "
              f"C={r.carry} err=${r.err:02X} after {r.tenths:.1f} TOD tenths "
              f"(want C=1 ${ERR_WAIT_TIMEOUT:02X} within {WAIT_BUDGET_TENTHS}+10). "
              f"{dev.describe()}")
    res.check(dev.first_byte is None and len(dev.accepted) == a0
              and len(dev.dropped) == d0,
              f"{tag}/no-command-byte-written",
              f"first command byte={dev.first_byte}, accepted since="
              f"{len(dev.accepted) - a0}, dropped since={len(dev.dropped) - d0}: "
              f"a command was written into a non-idle interface. {dev.describe()}")


def case_lenbad(ctx, res, mhz):
    """net_poll @len_bad: header over UCI_READ_CHUNK_MAX (not $FFFF), and the
    drain that follows times out. $8A is the cause; $89 must not hide it."""
    rng = ctx["rng"]
    m = Machine(ctx["builds"]["plain"], "plain")
    sid, ip, port = peer(rng)
    m.socket(sid, ip, port)
    stall = Stall(is_op(CMD_SOCKET_READ), "resp", 0)
    dev = RtlUci(mhz=mhz, rng=rng, sid=sid, stall=stall)
    claim = rng.randrange(READ_CHUNK_MAX + 1, 0xFFFF)
    body = in_payload(rng, 1, 64)
    dev.inbound.append(body)
    orig = dev._reply

    def lying_reply(cmd):                   # over-long header, then the body
        data, st = orig(cmd)
        if is_op(CMD_SOCKET_READ)(cmd) and len(data) > 2:
            data = bytes([claim & 0xFF, claim >> 8]) + data[2:]
        return data, st
    dev._reply = lying_reply
    r = m.call(dev, "net_poll", mhz=mhz)
    tag = f"L/len_bad-drain-timeout@{mhz}MHz"
    res.check(r.hung is None and r.carry == 1 and r.err == ERR_LONG_READ
              and stall.tx is not None and m.mem[m.sym["udp_recv_ready"]] == 0,
              f"{tag}/C1-LONG_READ",
              f"header ${claim:04X} with DATA_AV stuck: C={r.carry} "
              f"err=${r.err:02X} (want ${ERR_LONG_READ:02X}) ready="
              f"{m.mem[m.sym['udp_recv_ready']]} hung={r.hung}; {dev.describe()}")
    dev._reply = orig
    dev.release()
    follow_poll_send(ctx, res, m, dev, mhz, tag, sid, stall.tx)


# =============================================================================
def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default=None, help="BACKEND=uci tree (plain)")
    p.add_argument("--build-chunked", default=None,
                   help="BACKEND=uci UCI_CHUNKED_WRITE=1 tree")
    p.add_argument("--mhz", default=os.environ.get("UCI_WAIT_TURBO_MHZ", "1,48"))
    p.add_argument("--only", default=None, help="group: F S CTRL P D M L")
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    speeds = [int(x) for x in str(args.mhz).split(",") if x.strip()]

    tmp = None
    built = False
    try:
        if args.build and args.build_chunked:
            builds = {"plain": Path(args.build).resolve(),
                      "chunked": Path(args.build_chunked).resolve()}
        elif os.environ.get("C64_SKIP_BUILD"):
            print("FATAL: C64_SKIP_BUILD=1 needs --build and --build-chunked "
                  "(this suite runs two tree states)")
            return 2
        else:
            tmp = Path(tempfile.mkdtemp(prefix="uci_wait_carry_"))
            built = True
            builds = build_both(tmp)
        for name, d in builds.items():
            prg = d / "wireguard.prg"
            if not prg.exists() or not (d / "wireguard.dbg").exists():
                print(f"FATAL: {prg} / wireguard.dbg missing")
                return 2
            print(f"prg[{name}]: {prg}\n       {fingerprint(prg)}")
        ctx = {"builds": builds, "rng": random.Random(seed),
               "plain": Machine(builds["plain"], "plain"),
               "chunked": Machine(builds["chunked"], "chunked")}
        print(f"speeds={speeds} MHz")
        res = Result()

        plan = [("F", lambda: case_fidelity(ctx, res)),
                ("S", lambda: case_structural(ctx, res))]
        for mhz in speeds:
            for fl in ("plain", "chunked"):
                plan.append(("CTRL", lambda fl=fl, mhz=mhz: case_control(ctx, res, fl, mhz)))
            for site in PUSH_SITES:
                for err in (1, 0):
                    plan.append(("P", lambda s=site, e=err, mhz=mhz:
                                 case_push_stall(ctx, res, s, e, mhz)))
            for site in PLAIN_DRAIN_SITES + CHUNK_DRAIN_SITES:
                plan.append(("D", lambda s=site, mhz=mhz: case_drain_stall(ctx, res, s, mhz)))
            plan.append(("M", lambda mhz=mhz: case_more(ctx, res, mhz)))
            plan.append(("L", lambda mhz=mhz: case_lenbad(ctx, res, mhz)))
        for key, fn in plan:
            if args.only and args.only != key:
                continue
            fn()

        if len(set(res.names)) != len(res.names):
            print("FATAL: duplicate check names — the denominator is not an identity")
            return 2
        total = res.passed + res.failed
        expected = checks_expected(len(speeds))
        print(f"\nResults: {res.passed} passed, {res.failed} failed — {total} checks "
              f"(seed {seed})")
        for cls in ("CONTROL", "REACHABLE", "REACHABLE-1MHZ", "DEFENSIVE-STATUS",
                    "DEFENSIVE-ERRBRANCH", "DEFENSIVE-RESP", "DEFENSIVE-FAULT"):
            n = sum(1 for x in res.names if check_class(x) == cls)
            f = sum(1 for x in res.failures if check_class(x) == cls)
            print(f"  {cls:20s} {n - f:3d}/{n:3d} passed")
        if res.failures:
            print("FAILED: " + ", ".join(res.failures))
        if not args.only and total != expected:
            print(f"FATAL: {total} checks ran, expected exactly {expected}.")
            return 2
        return 0 if res.failed == 0 else 1
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
        if built:
            restore_default_tree()


if __name__ == "__main__":
    sys.exit(main())
