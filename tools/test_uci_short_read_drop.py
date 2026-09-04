#!/usr/bin/env python3
"""tools/test_uci_short_read_drop.py — red/green for issue #130.

The defect
----------
`src/net/uci/net.s` `@block_end`: when a response block drains with
`uci_poll_rem` still non-zero, STATE $30 (Data More) and $10 (Command Busy)
are handled, and EVERYTHING ELSE — $20 Data Last and $00 Idle — falls
through to `@done_data`, which sets `udp_recv_ready` and returns C=0 with
`udp_recv_len` still holding the FULL announced length from the 2-byte
header. The caller is handed a full length over a partially filled buffer.
In the tunnel the Poly1305 tag is then read out of the middle of the
ciphertext and the AEAD fails — issue #128's "inbound decrypt size band".

Why this is a host-side simulation and not VICE
-----------------------------------------------
VICE does not emulate the Ultimate Command Interface at all: $DF1D reads
$FF, so `net_init` fails with $81 (that is the whole of what
tools/test_uci_backend_stub.py can prove) and the multi-block SOCKET_READ
path is unreachable there. There is no VICE build of this test, and saying
so is more useful than a VICE test that proves something else.

What runs here instead is the REAL assembled `net_poll`, out of the real
`build/wireguard.prg`, on an NMOS 6502 interpreter (tools/uci/mos6502.py),
against a model of the $DF1C-$DF1F register interface. The model is written
from the FPGA/firmware protocol as documented in src/net/uci/uci_regs.inc
(command_protocol.vhd's four STATE values, DATA_ACC's queue reset, the
895-byte response block) and it does NOT know what the right answer is: it
serves a scripted number of bytes and then declares a scripted STATE. What
`net_poll` does with that is the subject.

The interpreter is not taken on trust. Case 0 executes BLAKE2s out of the
same PRG over randomised inputs and requires byte-exact agreement with
hashlib, then corrupts one message byte and requires the comparison to
alarm.

TWO causes, one signature
-------------------------
`poison_stop == 893` under a full announced length has TWO causes at
@block_end, and the fix has to tell them apart:

  1. the reply genuinely ended with bytes outstanding (case 5) — drop it
  2. the CONTINUATION was staged inside the fence (case 10) — drain it

@byte_loop reaches @block_end only when DATA_AV read clear; @block_end
reads UCI_STATUS a SECOND time one `uci_fence` later, and a block staged
in between is announced by DATA_AV and STATE in the SAME register, so
STATE reads $20 Data Last with a full block still in the FIFO. Cause 2
therefore produces exactly the #128/#130 evidence from a reply that was
never short, and a fix that only adds an error exit converts it from
silent corruption into silent packet loss. Case 10 is red on the unfixed
tree AND on that naive fix; the fix must test DATA_AV before it decides
anything from STATE.

What is proven here and what still needs the device
---------------------------------------------------
Proven here: that `net_poll` delivers a short read as a full-length
datagram (RED), that it must instead drop it with a distinct error
(GREEN), that a clamping "fix" is rejected, that a complete reply whose
continuation lands inside the fence is still delivered, and that the
$FFFF sentinel, the $8A over-claim and the $89 wedge are unchanged.

NOT proven here: that the firmware really does present $20/$00 with bytes
outstanding. That is the hardware premise, and it is already measured —
`poison_stop == 893` on eleven failing queries at five announced lengths,
never another value, and 1008/1247/1338 each both failed and succeeded in
one run (issue #130). The hardware run after the fix must show: on every
DELIVERED datagram `poison_stop == udp_recv_len`, and every short read
surfacing as the new error code with `udp_recv_ready` still 0.

Randomisation
-------------
Announced lengths, payload bytes, truncation points, the socket id, the
peer address and the device's staging delays are all drawn from one seeded
RNG; the seed is printed and reproducible with `--seed`/`TEST_SEED`. The
payload is forced to differ from the poison at every offset (see
`_payload_for`) so a coincidence cannot move the measured stop, and the
fixed values in the suite (the five hardware-observed announced lengths)
are added to a randomised set rather than replacing it.

Usage:
    python3 tools/test_uci_short_read_drop.py [--seed S] [--build DIR]
                                              [--tree DIR] [--only CASE]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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

# Every run emits exactly this many named checks. A case that silently
# stops running is then a hard error rather than a smaller denominator
# nobody notices. Update deliberately when adding one.
EXPECTED_CHECKS = 72

# --- UCI register map (src/net/uci/uci_regs.inc) -----------------------------
UCI_DEVICE, UCI_STATUS, UCI_CMD_DATA = 0xDF1B, 0xDF1C, 0xDF1D
UCI_RESP_DATA, UCI_STATUS_DATA = 0xDF1E, 0xDF1F
UCI_ID_VALUE = 0xC9
STAT_DATA_AV, STAT_STAT_AV, STAT_STATE = 0x80, 0x40, 0x30
STAT_ERROR, STAT_CMD_BUSY = 0x08, 0x01
STATE_IDLE, STATE_BUSY, STATE_DATA_LAST, STATE_DATA_MORE = 0x00, 0x10, 0x20, 0x30
CTRL_PUSH_CMD, CTRL_NEXT_DATA, CTRL_ABORT, CTRL_CLR_ERR = 0x01, 0x02, 0x04, 0x08

CMD_SOCKET_READ = 0x10
TARGET_NETWORK = 0x03
READ_CHUNK_MAX = 1472
NO_DATA_SENTINEL = 0xFFFF

# Response-block geometry. command_protocol.vhd freezes the buffer pointer
# at 895, so a block carries 895 bytes; block 1 spends 2 of them on the
# length header, leaving 893 of payload — which is exactly the
# `poison_stop` measured on all eleven failing hardware queries.
BLOCK_BYTES = 895
FIRST_BLOCK_PAYLOAD = BLOCK_BYTES - 2
assert FIRST_BLOCK_PAYLOAD == 893

# --- CIA1 TOD ---------------------------------------------------------------
CIA_TOD_TENTHS, CIA_TOD_SEC, CIA_TOD_MIN, CIA_TOD_HOUR = 0xDC08, 0xDC09, 0xDC0A, 0xDC0B
CIA_CRB = 0xDC0F
CYCLES_PER_TENTH = 100_000          # 1 MHz

# Error codes already allocated at the tree this suite was written against
# (src/net/uci/uci_errors.inc + src/net_abi.inc). The code the fix mints
# must not be one of these — that is what "distinct" means, and it is
# checked structurally rather than hardcoded, so this suite does not have
# to guess which value the implementer picked.
KNOWN_ERROR_CODES = {
    0x00, 0x01, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x8A, 0x8C, 0x8D, 0x8E,
}
ERR_WAIT_TIMEOUT = 0x89
ERR_LONG_READ = 0x8A

# The five announced lengths at which hardware saw the failure (issue #130).
HARDWARE_BAND = (1008, 1109, 1191, 1247, 1338)


# =============================================================================
# Build artefacts
# =============================================================================
def fingerprint(path: Path) -> str:
    raw = path.read_bytes()
    return (f"sha256={hashlib.sha256(raw).hexdigest()} ({len(raw)} B) "
            f"mtime={datetime.fromtimestamp(path.stat().st_mtime).isoformat(' ', 'seconds')}")


def build_uci_tree() -> None:
    """`make clean && make BACKEND=uci` in the project tree.

    This suite needs a BACKEND=uci build, which is not the tree the gate's
    pool leaves behind, so it is registered in run_regression.py's
    SERIAL_TESTS alongside tools/test_uci_backend_stub.py — the runner
    strips C64_SKIP_BUILD for those and restores the default build when
    they are done. Skipped entirely when --build names a tree, because then
    the caller is pointing this at a build it made itself and rebuilding
    would be the "two versions in one sweep" failure.
    """
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set — skipping build")
        return
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", "BACKEND=uci"], capture_output=True,
                       text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        raise SystemExit(f"FATAL: make BACKEND=uci failed:\n{r.stderr}")


def load_symbols(build: Path) -> dict:
    """Every symbol, exported or not, from the ld65 --dbgfile listing.

    labels.txt carries only `.export`ed names, and three of the addresses
    this suite needs (`uci_poll_rem`, `uci_socket_open`, `b2s_*`) are
    internal. Reading them out of the debug file is structural; the
    alternative in tools/test_uci_backend_stub.py is "uci_socket_id + 1",
    which is a positional guess that a reorder in data.s would silently
    invalidate.
    """
    dbg = build / "wireguard.dbg"
    syms: dict[str, int] = {}
    pat = re.compile(r'name="([^"]+)"[^\n]*?,val=0x([0-9A-Fa-f]+)')
    for line in dbg.read_text().splitlines():
        if not line.startswith("sym\t"):
            continue
        m = pat.search(line)
        if m:
            syms.setdefault(m.group(1), int(m.group(2), 16))
    return syms


def load_prg(build: Path) -> tuple[int, bytes]:
    raw = (build / "wireguard.prg").read_bytes()
    return raw[0] | (raw[1] << 8), raw[2:]


def discover_new_error_code(tree: Path):
    """The code minted by the fix: any UCI_ERR_*/NET_ERR_* not already known.

    Returns (name, value) or None. Parsed out of the tree's own registry so
    the suite adapts to whatever the implementer allocated instead of
    hardcoding a value the two of us would have to agree on out of band.
    """
    text = (tree / "src" / "net" / "uci" / "uci_errors.inc").read_text()
    found = {}
    for name, val in re.findall(
            r"^((?:UCI|NET)_ERR_[A-Z0-9_]+)\s*=\s*\$([0-9A-Fa-f]{2})\b",
            text, re.M):
        found[name] = int(val, 16)
    new = {n: v for n, v in found.items() if v not in KNOWN_ERROR_CODES}
    if len(new) != 1:
        return None if not new else sorted(new.items())[0]
    return next(iter(new.items()))


# =============================================================================
# The simulated Ultimate Command Interface
# =============================================================================
class UciDevice:
    """A model of $DF1B-$DF1F driven by a script, not by expectations.

    It knows the register protocol (STATE, DATA_AV, STAT_AV, DATA_ACC's
    queue reset, the error bit) and nothing about what net_poll ought to
    conclude. A scenario says how many payload bytes to actually hand over
    and which STATE to present when it stops; the adapter's verdict is what
    the suite measures.

    Timing is in CPU cycles so the bounded waits in uci_cmd.s are exercised
    for real: PUSH_CMD asserts CMD_BUSY, which clears after `accept_cycles`
    with STATE still 01, and each block becomes visible `stage_cycles`
    later — the same two windows uci_wait_not_busy and
    uci_wait_reply_staged were written for.
    """

    def __init__(self, *, announced, payload, blocks, final_state,
                 accept_cycles, stage_cycles, status_line=b"",
                 wedge=False, more_after_last=False,
                 stage_on_status_read=None):
        self.announced = announced          # what the 2-byte header claims
        self.payload = payload              # what is actually handed over
        self.blocks = blocks                # list[bytes], block 1 incl. header
        self.final_state = final_state      # STATE presented when data runs out
        # True: the last block handed over is presented as Data More, so the
        # C64 ACKs it and asks for a continuation that never comes — the
        # firmware then presents `final_state` out of Command Busy. False:
        # the last block is presented as Data Last with bytes still
        # outstanding. Both are ways STATE lands on $20/$00 with
        # uci_poll_rem non-zero; they enter @block_end by different routes.
        self.more_after_last = more_after_last
        # When set to k, the continuation block becomes visible immediately
        # AFTER the k-th UCI_STATUS read that follows the DATA_ACC, instead
        # of after a cycle delay. That places the staging inside a window a
        # cycle delay can only hit by luck: @byte_loop reads STATUS, sees
        # DATA_AV clear and falls into @block_end, which reads STATUS AGAIN
        # one uci_fence later. A block staged between those two reads is
        # announced by DATA_AV and STATE together, in one register.
        self.stage_on_status_read = stage_on_status_read
        self._stage_countdown = None
        self._pending_index = None
        self.accept_cycles = accept_cycles
        self.stage_cycles = list(stage_cycles)
        self.status_line = status_line
        self.wedge = wedge

        self.cycles = 0
        self.state = STATE_IDLE
        self.cmd_busy = 0
        self.error = 0
        self.cmd = bytearray()
        self.resp = b""
        self.resp_pos = 0
        self.stat = b""
        self.stat_pos = 0
        self.block_index = -1
        self._due = None                    # (cycle, action)
        self.log = []                       # structural trace, for diagnosis
        self.bytes_served = 0
        self.commands_seen = []

    # -- time -------------------------------------------------------------
    def sync(self, cycles):
        self.cycles = cycles
        while self._due is not None and cycles >= self._due[0]:
            _, action = self._due
            self._due = None
            action()

    def _at(self, delay, action):
        self._due = (self.cycles + delay, action)

    def _delay(self, n):
        return self.stage_cycles[min(n, len(self.stage_cycles) - 1)]

    # -- command handling --------------------------------------------------
    def _push_cmd(self):
        cmd = bytes(self.cmd)
        self.cmd = bytearray()
        self.commands_seen.append(cmd)
        self.cmd_busy = 1
        self.state = STATE_BUSY
        self.log.append(("push", cmd.hex()))
        self._at(self.accept_cycles, self._accept)

    def _accept(self):
        # HANDSHAKE_ACCEPT_COMMAND: CMD_BUSY drops, STATE stays 01 until
        # copy_result() has staged a block.
        self.cmd_busy = 0
        self.log.append(("accept", None))
        self._at(self._delay(0), lambda: self._stage(0))

    def _stage(self, index):
        if index >= len(self.blocks):
            # Nothing more to hand over: present the scripted terminal
            # STATE with the data queue empty. When that STATE is $20/$00
            # while the header promised more, this is the #130 condition.
            self.state = self.final_state
            self.resp, self.resp_pos = b"", 0
            self.stat, self.stat_pos = self.status_line, 0
            self.log.append(("exhausted", f"state=${self.state:02X}"))
            return
        self.block_index = index
        self.resp = self.blocks[index]
        self.resp_pos = 0
        last = (index == len(self.blocks) - 1)
        terminal = last and not self.more_after_last
        self.state = STATE_DATA_LAST if terminal else STATE_DATA_MORE
        if terminal:
            self.stat, self.stat_pos = self.status_line, 0
        self.log.append(("stage", f"block={index} len={len(self.resp)} "
                                  f"state=${self.state:02X}"))

    def _data_acc(self):
        # Register API v1.1 §2.4.1: DATA_ACC also aborts and resets both
        # queues. On a Data More block it additionally asks for the next
        # one, which the FPGA signals by dropping STATE to 01 while the
        # firmware task stages it.
        if self.state == STATE_DATA_MORE:
            self.state = STATE_BUSY
            self.resp, self.resp_pos = b"", 0
            nxt = self.block_index + 1
            self.log.append(("data_acc", f"continue -> block {nxt}"))
            if self.wedge:
                self._due = None            # never staged: a wedged task
                return
            if self.stage_on_status_read is not None:
                self._stage_countdown = self.stage_on_status_read
                self._pending_index = nxt
                return
            self._at(self._delay(nxt), lambda: self._stage(nxt))
        else:
            self.state = STATE_IDLE
            self.resp, self.resp_pos = b"", 0
            self.stat, self.stat_pos = b"", 0
            self.log.append(("data_acc", "release -> idle"))

    # -- register access ---------------------------------------------------
    def status(self):
        s = self.state | (self.error and STAT_ERROR) | self.cmd_busy
        if self.resp_pos < len(self.resp):
            s |= STAT_DATA_AV
        if self.stat_pos < len(self.stat):
            s |= STAT_STAT_AV
        return s

    def read(self, addr):
        if addr == UCI_STATUS:
            s = self.status()
            if self._stage_countdown is not None:
                self._stage_countdown -= 1
                if self._stage_countdown <= 0:
                    idx, self._pending_index = self._pending_index, None
                    self._stage_countdown = None
                    self._stage(idx)
            return s
        if addr == UCI_CMD_DATA:            # $DF1D reads as the ID byte
            return UCI_ID_VALUE
        if addr == UCI_RESP_DATA:
            if self.resp_pos < len(self.resp):
                b = self.resp[self.resp_pos]
                self.resp_pos += 1
                self.bytes_served += 1
                return b
            return 0xFF                     # empty FIFO: open bus
        if addr == UCI_STATUS_DATA:
            if self.stat_pos < len(self.stat):
                b = self.stat[self.stat_pos]
                self.stat_pos += 1
                return b
            return 0xFF
        if addr == UCI_DEVICE:
            return 0x00
        raise AssertionError(f"read of unmodelled UCI register ${addr:04X}")

    def write(self, addr, value):
        if addr == UCI_CMD_DATA:
            if len(self.cmd) < BLOCK_BYTES:
                self.cmd.append(value)
            return
        if addr == UCI_DEVICE:
            return
        if addr == UCI_STATUS:              # CONTROL
            if value & CTRL_CLR_ERR:
                self.error = 0
            if value & CTRL_ABORT:
                self.state = STATE_IDLE
                self.resp, self.stat = b"", b""
                self._due = None
            if value & CTRL_NEXT_DATA:
                self._data_acc()
            if value & CTRL_PUSH_CMD:
                self._push_cmd()
            return
        raise AssertionError(f"write to unmodelled UCI register ${addr:04X}")


class Cia1Tod:
    """Just enough CIA1 for the wall-clock budgets in uci_cmd.s.

    TENTHS advances every CYCLES_PER_TENTH cycles; reading HOUR latches the
    whole time and reading TENTHS releases it, which is the order every
    wait in uci_cmd.s uses. Nothing else about the CIA is modelled.
    """

    def __init__(self):
        self.latched = None
        self.cycles = 0

    def _now(self):
        t = self.cycles // CYCLES_PER_TENTH
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

    def write(self, addr, value):
        pass                                # TOD is free-running here


# =============================================================================
# One net_poll cycle
# =============================================================================
class PollResult:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Machine:
    def __init__(self, build: Path, mod):
        self.load_addr, self.image = load_prg(build)
        self.sym = load_symbols(build)
        self.mod = mod                      # tools/test_warp_live.py
        for name in ("net_poll", "udp_recv_buf", "udp_recv_len",
                     "udp_recv_ready", "net_last_error", "uci_read_hdr",
                     "uci_socket_id", "uci_poll_rem", "uci_socket_open",
                     "net_udp_dest_ip", "net_udp_dest_port"):
            if name not in self.sym:
                raise SystemExit(f"FATAL: symbol {name!r} not in wireguard.dbg")
        self.buf_cap = self.sym["udp_recv_len"] - self.sym["udp_recv_buf"]

    def poll(self, device, *, socket_id, seed_error=0x00, poison=None,
             max_cycles=400_000_000):
        s = self.sym
        mem = bytearray(0x10000)
        mem[self.load_addr:self.load_addr + len(self.image)] = self.image
        cia = Cia1Tod()

        def io_read(addr):
            cia.cycles = cpu.cycles
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                return device.read(addr)
            if 0xDC00 <= addr <= 0xDCFF:
                return cia.read(addr)
            return 0xFF

        def io_write(addr, value):
            cia.cycles = cpu.cycles
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                device.write(addr, value)
                return
            if 0xDC00 <= addr <= 0xDCFF:
                cia.write(addr, value)
                return

        cpu = Mos6502(mem, io_read, io_write)
        mem[s["uci_socket_open"]] = 1
        mem[s["uci_socket_id"]] = socket_id
        mem[s["udp_recv_ready"]] = 0
        mem[s["net_last_error"]] = seed_error
        mem[s["udp_recv_len"]] = 0
        mem[s["udp_recv_len"] + 1] = 0
        if poison is not None:
            mem[s["udp_recv_buf"]:s["udp_recv_buf"] + len(poison)] = poison

        hung = None
        try:
            cpu.call(s["net_poll"], max_cycles=max_cycles)
        except CpuBudgetExceeded as exc:
            hung = str(exc)
        buf = bytes(mem[s["udp_recv_buf"]:s["udp_recv_buf"] + self.buf_cap])
        return PollResult(
            carry=cpu.c,
            ready=mem[s["udp_recv_ready"]],
            recv_len=mem[s["udp_recv_len"]] | (mem[s["udp_recv_len"] + 1] << 8),
            error=mem[s["net_last_error"]],
            poll_rem=mem[s["uci_poll_rem"]] | (mem[s["uci_poll_rem"] + 1] << 8),
            hdr=mem[s["uci_read_hdr"]] | (mem[s["uci_read_hdr"] + 1] << 8),
            buf=buf,
            stop=self.mod.poison_stop(buf, poison) if poison else None,
            cycles=cpu.cycles,
            instructions=cpu.instructions,
            hung=hung,
            device=device,
        )


# =============================================================================
# Scenario construction
# =============================================================================
def _payload_for(rng, n, poison):
    """`n` random bytes that differ from the poison at EVERY offset.

    Without this the last written byte coincides with the poison with
    probability 1/251, `poison_stop`'s backward scan extends the surviving
    run by one, and the measured stop reads one below the truth. A real
    datagram is ciphertext and the same coincidence exists there — it is
    handled by classify_recv_buffer's tolerance, not by pretending it
    cannot happen — but here it would be noise in an exact assertion.
    """
    out = bytearray(rng.randrange(256) for _ in range(n))
    for i in range(n):
        while out[i] == poison[i]:
            out[i] = (out[i] + 1) & 0xFF
    return bytes(out)


def build_blocks(announced, payload):
    """Split a header + payload into 895-byte response blocks."""
    stream = bytes([announced & 0xFF, (announced >> 8) & 0xFF]) + payload
    return [stream[i:i + BLOCK_BYTES] for i in range(0, len(stream), BLOCK_BYTES)] \
        or [b""]


def make_device(rng, *, announced, delivered_payload, final_state,
                truncate_after=None, wedge=False, status_line=b"",
                more_after_last=False, stage_on_status_read=None):
    """A device that announces `announced` and hands over `delivered_payload`.

    `truncate_after` caps how many blocks are ever staged; whatever remains
    of the payload is simply never handed over, and the scripted
    `final_state` is presented instead. That is the shape the firmware
    presents in #130 — the adapter's reaction is what is under test.
    """
    blocks = build_blocks(announced, delivered_payload)
    if truncate_after is not None:
        blocks = blocks[:truncate_after]
    stage = [rng.randrange(3_000, 60_000) for _ in range(len(blocks) + 2)]
    return UciDevice(
        announced=announced,
        payload=delivered_payload,
        blocks=blocks,
        final_state=final_state,
        accept_cycles=rng.randrange(2_000, 40_000),
        stage_cycles=stage,
        status_line=status_line,
        wedge=wedge,
        more_after_last=more_after_last,
        stage_on_status_read=stage_on_status_read,
    )


# =============================================================================
# Result bookkeeping (same identity discipline as
# tools/test_warp_instrument_unit.py)
# =============================================================================
class Result:
    def __init__(self):
        self.passed = self.failed = self.skipped = 0
        self.names: list[str] = []

    def check(self, ok, name, detail=""):
        self.names.append(name)
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}\n        {detail}")

    def skip(self, name, why):
        self.names.append(name)
        self.passed += 1
        self.skipped += 1
        print(f"  SKIP  {name}  ({why})")


# =============================================================================
# Cases
# =============================================================================
def case0_interpreter_fidelity(ctx, res):
    """The interpreter is proven, not assumed, before anything rests on it.

    BLAKE2s out of the same PRG over randomised inputs, byte-exact against
    hashlib — roughly a million instructions across the full addressing-mode
    set. Then one message byte is corrupted and the comparison must alarm,
    so a vacuously-passing equality is ruled out.

    Lengths stay under 256 on purpose: blake2s_update tests `b2s_remain`
    with an 8-bit `lda/bne`, so 256 bytes is read as zero and the routine
    returns without hashing anything. That is a property of the 6502 code,
    not of this interpreter (the interpreter is how it was found), and no
    caller in this project hashes that much.
    """
    print("\n[case 0] the interpreter is faithful to the real 6502 code")
    m, rng = ctx["machine"], ctx["rng"]
    s = m.sym
    need = ("blake2s_hash_oneshot", "b2s_data_ptr", "b2s_remain", "b2s_hash")
    if any(n not in s for n in need):
        for nm in ("blake2s-agrees", "corruption-alarms"):
            res.skip("case0/" + nm, "blake2s symbols absent from this build")
        return
    scratch = 0xB000                        # above the PRG, below the I/O window
    agreed = []
    for _ in range(6):
        n = rng.randrange(1, 256)
        msg = bytes(rng.randrange(256) for _ in range(n))
        got = _blake2s_on_6502(m, scratch, msg)
        agreed.append((n, got == hashlib.blake2s(msg, digest_size=32).digest()))
    res.check(all(ok for _, ok in agreed), "case0/blake2s-agrees",
              f"BLAKE2s executed on the interpreter disagreed with hashlib "
              f"at lengths {[n for n, ok in agreed if not ok]}; every "
              f"assertion in this suite runs on that interpreter")
    # Detector proof: corrupt one byte and require disagreement.
    msg = bytearray(rng.randrange(256) for _ in range(rng.randrange(8, 200)))
    clean = _blake2s_on_6502(m, scratch, bytes(msg))
    i = rng.randrange(len(msg))
    msg[i] ^= 1 << rng.randrange(8)
    dirty = _blake2s_on_6502(m, scratch, bytes(msg))
    res.check(clean != dirty, "case0/corruption-alarms",
              "flipping one bit of the message left the digest unchanged — "
              "the equality above is not actually observing the computation")


def _blake2s_on_6502(m, scratch, msg):
    mem = bytearray(0x10000)
    mem[m.load_addr:m.load_addr + len(m.image)] = m.image
    mem[scratch:scratch + len(msg)] = msg
    s = m.sym
    mem[s["b2s_data_ptr"]] = scratch & 0xFF
    mem[s["b2s_data_ptr"] + 1] = scratch >> 8
    mem[s["b2s_remain"]] = len(msg) & 0xFF
    mem[s["b2s_remain"] + 1] = len(msg) >> 8
    cpu = Mos6502(mem, lambda a: 0xFF, lambda a, v: None)
    cpu.a = 32
    cpu.call(s["blake2s_hash_oneshot"], max_cycles=50_000_000)
    return bytes(mem[s["b2s_hash"]:s["b2s_hash"] + 32])


def case1_full_read(ctx, res):
    """REGRESSION GUARD: genuine full-length reads still work, at both shapes.

    BOTH a single-block and a MULTI-block read are exercised on every run,
    and that is not redundancy: @block_end is only ever reached when a
    block drains with bytes outstanding, so a single-block read never
    visits the code being changed. A fix that broke the Data More
    continuation — the #70 reassembly — would pass a suite that happened to
    draw a small datagram, which is the shape of bug this whole
    investigation exists because of.
    """
    print("\n[case 1] complete reads are still delivered, single- and multi-block")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    draws = [
        # Two blocks or more: the continuation path.
        ("multi-block", rng.randrange(FIRST_BLOCK_PAYLOAD + 1,
                                      READ_CHUNK_MAX + 1)),
        # One block: never reaches @block_end at all. The exact 893-byte
        # boundary is drawn sometimes, because that is the size at which a
        # truncation and a complete read look alike by block count.
        ("single-block", rng.choice([rng.randrange(1, FIRST_BLOCK_PAYLOAD),
                                     FIRST_BLOCK_PAYLOAD])),
    ]
    for tag, n in draws:
        pre = f"case1/{tag}"
        payload = _payload_for(rng, n, poison)
        dev = make_device(rng, announced=n, delivered_payload=payload,
                          final_state=STATE_IDLE)
        r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison)
        print(f"        [{tag}] announced={n} blocks={len(dev.blocks)} "
              f"served={dev.bytes_served} carry={r.carry} ready={r.ready} "
              f"recv_len={r.recv_len} stop={r.stop} err=${r.error:02X}")
        res.check(r.hung is None, f"{pre}/returns", r.hung or "")
        res.check(r.ready == 1, f"{pre}/delivered",
                  f"a complete {n}-byte datagram in {len(dev.blocks)} "
                  f"block(s) was not delivered (udp_recv_ready={r.ready}, "
                  f"net_last_error=${r.error:02X}, C={r.carry})")
        res.check(r.carry == 0, f"{pre}/carry-clear",
                  f"C={r.carry} on a good read")
        res.check(r.error == 0x00, f"{pre}/no-error",
                  f"net_last_error=${r.error:02X} on a complete read")
        res.check(r.recv_len == n, f"{pre}/length",
                  f"udp_recv_len={r.recv_len}, announced {n}")
        res.check(r.buf[:n] == payload, f"{pre}/bytes-exact",
                  "the delivered bytes are not the bytes the device served")
        res.check(r.stop == n, f"{pre}/poison-stop-equals-len",
                  f"poison_stop={r.stop} but udp_recv_len={r.recv_len}: the "
                  "invariant the hardware run must show on every delivered "
                  "datagram")
        res.check(r.buf[n:] == poison[n:], f"{pre}/tail-untouched",
                  "bytes past the datagram were written")

    # Detector proof for the byte-exact and stop checks: one corrupted byte
    # in what the device serves must move the verdict.
    n = draws[0][1]
    payload = _payload_for(rng, n, poison)
    bad = bytearray(payload)
    bad[rng.randrange(len(bad))] ^= 0xFF
    dev2 = make_device(rng, announced=n, delivered_payload=bytes(bad),
                       final_state=STATE_IDLE)
    r2 = m.poll(dev2, socket_id=rng.randrange(1, 250), poison=poison)
    res.check(r2.buf[:n] != payload, "case1/detector-fires",
              "corrupting one served byte did not change the delivered "
              "buffer — case1/*/bytes-exact is not observing the copy")


def case2_no_data_sentinel(ctx, res):
    """REGRESSION GUARD: $FFFF is 'nothing pending', never an error (§13.2).

    net_last_error is pre-seeded with a witness value so 'untouched' is an
    observation and not a coincidence with zero.
    """
    print("\n[case 2] the $FFFF no-data sentinel stays a non-error")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    witness = rng.choice([0x5B, 0x6C, 0x7D, 0x4E])   # not an allocated code
    dev = make_device(rng, announced=NO_DATA_SENTINEL, delivered_payload=b"",
                      final_state=STATE_IDLE)
    r = m.poll(dev, socket_id=rng.randrange(1, 250), seed_error=witness,
               poison=poison)
    print(f"        hdr=${r.hdr:04X} carry={r.carry} ready={r.ready} "
          f"err=${r.error:02X} (witness ${witness:02X}) stop={r.stop}")
    res.check(r.hung is None, "case2/returns", r.hung or "")
    res.check(r.carry == 0, "case2/carry-clear",
              f"C={r.carry}: an idle poll is not a backend error")
    res.check(r.ready == 0, "case2/nothing-delivered",
              f"udp_recv_ready={r.ready} with no datagram pending")
    res.check(r.error == witness, "case2/error-untouched",
              f"net_last_error moved ${witness:02X} -> ${r.error:02X} on an "
              "idle poll; §13.2 says no data is never an error")
    res.check(r.stop == 0, "case2/buffer-untouched",
              f"poison_stop={r.stop} on a poll that received nothing")


def case3_over_claim(ctx, res):
    """REGRESSION GUARD: a genuine over-claim still raises $8A and drops."""
    print("\n[case 3] an over-claimed length still raises $8A")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    announced = rng.randrange(READ_CHUNK_MAX + 1, 0xFFFF)
    dev = make_device(rng, announced=announced,
                      delivered_payload=_payload_for(rng, 200, poison),
                      final_state=STATE_IDLE)
    r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison)
    print(f"        announced={announced} carry={r.carry} ready={r.ready} "
          f"err=${r.error:02X} stop={r.stop}")
    res.check(r.hung is None, "case3/returns", r.hung or "")
    res.check(r.error == ERR_LONG_READ, "case3/long-read-code",
              f"net_last_error=${r.error:02X}, expected $8A for an announced "
              f"{announced} against a cap of {READ_CHUNK_MAX}")
    res.check(r.carry == 1, "case3/carry-set", f"C={r.carry}")
    res.check(r.ready == 0, "case3/nothing-delivered",
              f"udp_recv_ready={r.ready} after an over-claim")
    res.check(r.stop == 0, "case3/buffer-untouched",
              f"poison_stop={r.stop}: bytes were copied under a length that "
              "was rejected")


def case4_wedged_continuation(ctx, res):
    """REGRESSION GUARD: a continuation that never arrives is still $89.

    This is the neighbouring branch of the one being fixed. It already
    exits with an error and must keep doing so with the SAME code — a fix
    that folded the wedge into the new code would lose the distinction
    between "the firmware stopped answering" and "the reply ended short".
    """
    print("\n[case 4] a wedged continuation still times out with $89")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    announced = rng.randrange(900, 1473)
    payload = _payload_for(rng, announced, poison)
    dev = make_device(rng, announced=announced, delivered_payload=payload,
                      final_state=STATE_BUSY, wedge=True)
    r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison)
    print(f"        announced={announced} carry={r.carry} ready={r.ready} "
          f"err=${r.error:02X} stop={r.stop} rem={r.poll_rem}")
    res.check(r.hung is None, "case4/returns",
              r.hung or "" if r.hung else "")
    res.check(r.error == ERR_WAIT_TIMEOUT, "case4/wait-timeout-code",
              f"net_last_error=${r.error:02X}, expected $89")
    res.check(r.carry == 1, "case4/carry-set", f"C={r.carry}")
    res.check(r.ready == 0, "case4/nothing-delivered",
              f"udp_recv_ready={r.ready} after a wedged continuation")


def case5_short_read(ctx, res):
    """THE BUG. A reply that ends with bytes outstanding must be DROPPED.

    Four checks per draw, and they do different jobs:

      dropped / error-code / carry-set
          fail on the unfixed tree (which delivers with C=0 and no error)
          AND on a clamping implementation (which delivers a trimmed
          length with C=0 and no error). These are what pin the fix to
          "drop", not merely to "not the current bug".

      len-matches-bytes
          the delivered-datagram invariant: if anything IS delivered, its
          length must equal what was actually written. Fails on the
          unfixed tree; a clamping implementation satisfies it. It is here
          because it is the invariant the hardware run reports.
    """
    print("\n[case 5] a short reply is dropped, not delivered")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    code_name, code = ctx["new_code"] or (None, None)
    poison = mod.poison_pattern(m.buf_cap)

    # Three distinct routes to the same @block_end decision, so the fix
    # cannot be a patch on one of them:
    #   after-ack/data-last  block 1 is Data More, we ACK it, and the
    #                        continuation resolves to Data Last with nothing
    #                        in the queue (the measured hardware shape)
    #   after-ack/idle       same, resolving to Idle
    #   immediate/data-last  block 1 is presented as Data Last outright,
    #                        with the header still promising more
    band = rng.sample(HARDWARE_BAND, 2)
    draws = [
        # `more_after_last` True means the block we hand over is announced as
        # Data More, so the adapter ACKs and waits; `final_state` is what the
        # firmware then presents with an empty queue.
        ("after-ack-data-last", band[0], FIRST_BLOCK_PAYLOAD,
         STATE_DATA_LAST, True),
        ("after-ack-idle", band[1], FIRST_BLOCK_PAYLOAD, STATE_IDLE, True),
        # A length outside the five hardware numbers, so this case is not a
        # restatement of them.
        ("immediate-data-last", rng.randrange(896, READ_CHUNK_MAX + 1),
         FIRST_BLOCK_PAYLOAD, STATE_DATA_LAST, False),
        # A stop in the MIDDLE of a continuation block, so the fix cannot be
        # a special case for the 893-byte boundary.
        ("mid-block", rng.randrange(1200, READ_CHUNK_MAX + 1),
         FIRST_BLOCK_PAYLOAD + rng.randrange(1, 200), STATE_DATA_LAST, False),
    ]
    rng.shuffle(draws)

    for tag, announced, delivered_n, final_state, more_after_last in draws:
        payload = _payload_for(rng, announced, poison)
        served = payload[:delivered_n]
        blocks_to_stage = 1 if delivered_n <= FIRST_BLOCK_PAYLOAD else 2
        dev = make_device(rng, announced=announced,
                          delivered_payload=served,
                          final_state=final_state,
                          more_after_last=more_after_last,
                          truncate_after=blocks_to_stage)
        r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison)
        pre = f"case5/{tag}"
        print(f"        [{tag}] announced={announced} served={delivered_n} "
              f"final_state=${final_state:02X} -> carry={r.carry} "
              f"ready={r.ready} recv_len={r.recv_len} stop={r.stop} "
              f"err=${r.error:02X} rem={r.poll_rem}")
        res.check(r.hung is None, f"{pre}/returns", r.hung or "")
        res.check(r.ready == 0, f"{pre}/dropped",
                  f"udp_recv_ready={r.ready}: the device offered "
                  f"{delivered_n} of the {announced} bytes it announced, "
                  f"{r.stop} of them were written into udp_recv_buf, and the "
                  f"datagram was DELIVERED anyway with udp_recv_len="
                  f"{r.recv_len}. The {announced - r.stop} bytes past offset "
                  f"{r.stop} are whatever the previous cycle left there. A "
                  f"truncated datagram is unrecoverable on a datagram socket "
                  f"— it must be dropped, not delivered and not trimmed.")
        res.check(code is not None and r.error == code,
                  f"{pre}/error-code",
                  (f"net_last_error=${r.error:02X}, but no distinct code is "
                   "declared in src/net/uci/uci_errors.inc — a dropped "
                   "datagram needs a name of its own"
                   if code is None else
                   f"net_last_error=${r.error:02X}, expected "
                   f"{code_name}=${code:02X}"))
        # Independent of the registry: whatever the code is, it must not be
        # one of the neighbouring verdicts. $00 is "nothing was noticed",
        # $89 is "the firmware stopped answering" and $8A is "the firmware
        # claimed too much" — none of them is "the reply ended short", and
        # an operator reading a log cannot act on a conflated one.
        res.check(r.error not in (0x00, ERR_WAIT_TIMEOUT, ERR_LONG_READ),
                  f"{pre}/distinct-from-neighbours",
                  f"net_last_error=${r.error:02X} is "
                  + {0x00: "$00 (no error raised at all)",
                     ERR_WAIT_TIMEOUT: "$89, the wedged-continuation code",
                     ERR_LONG_READ: "$8A, the over-claim code"}.get(
                      r.error, "a neighbouring code"))
        res.check(r.carry == 1, f"{pre}/carry-set",
                  f"C={r.carry}: a dropped datagram is a backend error exit")
        res.check(r.ready == 0 or r.recv_len == r.stop,
                  f"{pre}/len-matches-bytes",
                  f"delivered with udp_recv_len={r.recv_len} but only "
                  f"{r.stop} bytes were written this cycle")
        res.check(r.stop <= delivered_n, f"{pre}/no-over-copy",
                  f"poison_stop={r.stop} exceeds the {delivered_n} bytes the "
                  "device served")


def case6_no_stale_delivery(ctx, res):
    """A dropped datagram must not be delivered by the NEXT idle poll.

    'udp_recv_ready stays 0' is only worth something if it stays 0. This
    runs the short read and then an ordinary empty poll on the same
    machine state and requires nothing to surface.
    """
    print("\n[case 6] the dropped datagram does not surface on a later poll")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    announced = rng.choice(HARDWARE_BAND)
    payload = _payload_for(rng, announced, poison)
    sid = rng.randrange(1, 250)

    # Poll 1: the short read.
    dev = make_device(rng, announced=announced,
                      delivered_payload=payload[:FIRST_BLOCK_PAYLOAD],
                      final_state=STATE_DATA_LAST, truncate_after=1,
                      more_after_last=True)
    r1 = m.poll(dev, socket_id=sid, poison=poison)
    # Poll 2: nothing pending. Fresh machine, but carrying poll 1's
    # udp_recv_* forward is the point, so seed them from r1.
    dev2 = make_device(rng, announced=NO_DATA_SENTINEL, delivered_payload=b"",
                       final_state=STATE_IDLE)
    r2 = m.poll(dev2, socket_id=sid, poison=poison)
    print(f"        poll1 ready={r1.ready} len={r1.recv_len} | "
          f"poll2 ready={r2.ready} len={r2.recv_len}")
    res.check(r1.ready == 0 and r2.ready == 0, "case6/never-ready",
              f"udp_recv_ready was {r1.ready} after the short read and "
              f"{r2.ready} after the following idle poll; a consumer gates "
              "on that flag and would read udp_recv_len="
              f"{r2.recv_len or r1.recv_len} over a partial buffer")
    res.check(r2.carry == 0, "case6/idle-poll-not-an-error",
              f"C={r2.carry} on a poll with nothing pending")


def case7_idle_polls_never_error(ctx, res):
    """A run of ordinary idle polls must leave net_last_error alone.

    Turning idle polls into errors would be catastrophic — net_poll is
    called on every main-loop tick and almost every call has no datagram —
    and it is exactly the failure mode a narrow test of case 5 would miss.
    """
    print("\n[case 7] a run of idle polls raises nothing")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    witness = 0x3C
    outcomes = []
    for _ in range(4):
        dev = make_device(rng, announced=NO_DATA_SENTINEL,
                          delivered_payload=b"", final_state=STATE_IDLE)
        r = m.poll(dev, socket_id=rng.randrange(1, 250), seed_error=witness,
                   poison=poison)
        outcomes.append((r.carry, r.ready, r.error))
    res.check(all(c == 0 and rd == 0 and e == witness
                  for c, rd, e in outcomes), "case7/idle-polls-clean",
              f"idle polls produced {outcomes}; expected (0, 0, "
              f"${witness:02X}) throughout")


def case8_zero_length_read(ctx, res):
    """REGRESSION GUARD: an announced length of zero is 'no datagram'.

    A header of $0000 takes the `@len_ok` / `bne @have_data` path, not the
    sentinel path, so it is a separate exit from case 2 and a fix that
    keyed off "uci_poll_rem is zero" in the wrong place could break it.
    """
    print("\n[case 8] a zero-length read is not a datagram and not an error")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    witness = 0x2D
    dev = make_device(rng, announced=0, delivered_payload=b"",
                      final_state=STATE_IDLE)
    r = m.poll(dev, socket_id=rng.randrange(1, 250), seed_error=witness,
               poison=poison)
    print(f"        hdr=${r.hdr:04X} carry={r.carry} ready={r.ready} "
          f"err=${r.error:02X}")
    res.check(r.carry == 0 and r.ready == 0 and r.error == witness,
              "case8/zero-length-clean",
              f"C={r.carry} ready={r.ready} err=${r.error:02X}; expected "
              f"C=0 ready=0 err=${witness:02X}")


def case9_command_is_wellformed(ctx, res):
    """The device saw a real SOCKET_READ — the simulation is being driven.

    Structural, not textual: the exact command bytes net_poll pushed are
    compared against the $03 $10 <socket id> <cap lo> <cap hi> form. If
    this fails, every other case in the suite is measuring a machine that
    never asked for anything.
    """
    print("\n[case 9] net_poll really issues SOCKET_READ")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    sid = rng.randrange(1, 250)
    dev = make_device(rng, announced=NO_DATA_SENTINEL, delivered_payload=b"",
                      final_state=STATE_IDLE)
    m.poll(dev, socket_id=sid, poison=poison)
    want = bytes([TARGET_NETWORK, CMD_SOCKET_READ, sid,
                  READ_CHUNK_MAX & 0xFF, READ_CHUNK_MAX >> 8])
    got = dev.commands_seen[0] if dev.commands_seen else b""
    print(f"        pushed {got.hex() or '(nothing)'} want {want.hex()}")
    res.check(got == want, "case9/socket-read-command",
              f"net_poll pushed {got.hex()!r}, expected {want.hex()!r}")


def case10_staged_inside_the_fence(ctx, res):
    """A continuation that lands INSIDE the fence must be drained, not dropped.

    @byte_loop reaches @block_end only when DATA_AV read clear. @block_end
    then reads UCI_STATUS a SECOND time, one uci_fence (~5400 cycles at
    1 MHz, ~113 us at 48 MHz) later, and today it looks only at bits 5..4.
    A block staged in that window is announced by DATA_AV and STATE in the
    SAME register: STATE reads $20 Data Last with a full block sitting in
    the FIFO. Reading that as "the reply ended short" is wrong twice over —
    on the unfixed tree it delivers 893 bytes under the full announced
    length (the #130 signature, from a reply that was never short), and
    under a fix that only adds an error exit it DROPS a complete datagram.

    So this case is RED on the unfixed tree and RED on a naive drop-fix,
    and it is the reason the fix has to re-check DATA_AV before it decides
    anything from STATE.

    The staging is placed deterministically (immediately after the first
    STATUS read following the DATA_ACC) rather than by a cycle delay,
    because a delay hits this window only by luck — it was found by luck,
    at one seed out of three.
    """
    print("\n[case 10] a continuation staged inside the fence is drained")
    m, rng, mod = ctx["machine"], ctx["rng"], ctx["mod"]
    poison = mod.poison_pattern(m.buf_cap)
    n = rng.randrange(FIRST_BLOCK_PAYLOAD + 1, READ_CHUNK_MAX + 1)
    payload = _payload_for(rng, n, poison)
    dev = make_device(rng, announced=n, delivered_payload=payload,
                      final_state=STATE_IDLE, stage_on_status_read=1)
    r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison)
    print(f"        announced={n} blocks={len(dev.blocks)} "
          f"served={dev.bytes_served} carry={r.carry} ready={r.ready} "
          f"recv_len={r.recv_len} stop={r.stop} err=${r.error:02X} "
          f"rem={r.poll_rem}")
    res.check(r.hung is None, "case10/returns", r.hung or "")
    res.check(r.ready == 1 and r.carry == 0, "case10/delivered",
              f"a COMPLETE {n}-byte reply was not delivered "
              f"(ready={r.ready}, C={r.carry}, err=${r.error:02X}). The "
              "second block was staged between @byte_loop's DATA_AV read "
              "and @block_end's STATE read, so STATE reads Data Last with "
              "a full block still in the FIFO.")
    res.check(r.stop == n, "case10/all-bytes-copied",
              f"poison_stop={r.stop} of {n}: the staged block was never "
              "drained")
    res.check(r.recv_len == n, "case10/length", f"udp_recv_len={r.recv_len}")
    res.check(r.buf[:n] == payload, "case10/bytes-exact",
              "the delivered bytes are not the bytes the device served")
    res.check(r.error == 0x00, "case10/no-error",
              f"net_last_error=${r.error:02X} on a complete reply")


# =============================================================================
def load_warp_live():
    """Reuse test_warp_live.py's poison machinery rather than rebuild it."""
    path = PROJECT_ROOT / "tools" / "test_warp_live.py"
    spec = importlib.util.spec_from_file_location("warp_live_poison", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, path


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default=None,
                   help="directory holding wireguard.prg + wireguard.dbg")
    p.add_argument("--tree", default=None,
                   help="source tree whose uci_errors.inc defines the codes")
    p.add_argument("--only", default=None)
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    if args.build is None:
        build_uci_tree()
    build = Path(args.build).resolve() if args.build else PROJECT_ROOT / "build"
    tree = Path(args.tree).resolve() if args.tree else PROJECT_ROOT
    prg = build / "wireguard.prg"
    if not prg.exists() or not (build / "wireguard.dbg").exists():
        print(f"FATAL: {prg} (and wireguard.dbg) not found — "
              "run `make BACKEND=uci` first")
        return 2

    # Every run stamps what it actually loaded. Two versions of a file
    # inside one sweep has already cost this investigation a false alarm.
    print(f"prg:   {prg}\n       {fingerprint(prg)}")
    print(f"tree:  {tree}")
    net_s = tree / "src" / "net" / "uci" / "net.s"
    print(f"net.s: {fingerprint(net_s)}")
    mod, mod_path = load_warp_live()
    print(f"poison machinery from {mod_path}\n       {fingerprint(mod_path)}")

    new_code = discover_new_error_code(tree)
    if new_code:
        print(f"short-read error code: {new_code[0]} = ${new_code[1]:02X} "
              "(from the tree's own registry)")
    else:
        print("short-read error code: NONE minted in uci_errors.inc")

    machine = Machine(build, mod)
    print(f"udp_recv_buf=${machine.sym['udp_recv_buf']:04X} "
          f"capacity={machine.buf_cap} "
          f"net_poll=${machine.sym['net_poll']:04X} "
          f"uci_poll_rem=${machine.sym['uci_poll_rem']:04X}")

    ctx = {"machine": machine, "rng": rng, "mod": mod, "new_code": new_code}
    res = Result()
    cases = {
        "0": case0_interpreter_fidelity,
        "9": case9_command_is_wellformed,
        "1": case1_full_read,
        "2": case2_no_data_sentinel,
        "3": case3_over_claim,
        "4": case4_wedged_continuation,
        "5": case5_short_read,
        "6": case6_no_stale_delivery,
        "7": case7_idle_polls_never_error,
        "8": case8_zero_length_read,
        "10": case10_staged_inside_the_fence,
    }
    for key, fn in cases.items():
        if args.only and args.only != key:
            continue
        fn(ctx, res)

    total = res.passed + res.failed
    if len(set(res.names)) != len(res.names):
        dupes = sorted({n for n in res.names if res.names.count(n) > 1})
        print(f"\nFATAL: duplicate check names {dupes} — the denominator is "
              "not a stable identity")
        return 2
    real = res.passed - res.skipped
    print(f"\nResults: {real} passed, {res.failed} failed, "
          f"{res.skipped} skipped — {total} checks total")
    if not args.only and total != EXPECTED_CHECKS:
        print(f"FATAL: {total} checks ran, expected exactly {EXPECTED_CHECKS}. "
              "A moving denominator makes two runs incomparable.")
        return 2
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
