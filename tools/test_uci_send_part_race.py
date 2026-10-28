#!/usr/bin/env python3
"""tools/test_uci_send_part_race.py — red/green for issue #186: the chunked
send's non-completing part decides on ONE unlatched $DF1C read.

The defect
----------
Under `make BACKEND=uci UCI_CHUNKED_WRITE=1` every datagram leaves as
NET_CMD_WRITE_SOCKET_CHUNK ($16) parts. For a NON-COMPLETING part
`uci_send_part` (@sp_more) takes ONE read of UCI_STATUS, tests DATA_AV, and
then drains: uci_drain_resp and uci_drain_status each take one more read and
exit on the first one that shows their bit clear. $DF1C is an unlatched FPGA
register, so those reads can

  * land on the 01 -> 10 VALIDATE edge and tear ($30 / $00),
  * see STATE 10 with DATA_AV / STAT_AV one FPGA clock late ($20),
  * or simply be taken while STATE is still 01 (CMD_BUSY clears at
    HANDSHAKE_ACCEPT_COMMAND, the reply is staged afterwards:
    uci_wait_reply_staged's header).

A refused part (`81` / `82` status line) whose status line is missed is
reported as QUEUED (C=0): the datagram is silently truncated, and the reply
that arrives late is left in the FIFO for the NEXT command's orphan clear to
eat. PR #184 (tools/test_uci_status_tear.py) did this for net_poll's
@block_end and the idle gate; this is the same sweep for the send path.

What is swept
-------------
The $DF1C-$DF1F model and tap are tools/test_uci_status_tear.py's TapDevice
(imported, unchanged). SendDevice adds the firmware side of $16: it parses
each pushed command, stages the reply after CMD_BUSY drops, and logs

  * every PART at the wire (offset, announced total, bytes) and every
    DATAGRAM it would emit (a completing part whose parts cover the total) —
    a torn send is TWO datagrams or a datagram with a hole, so datagrams are
    counted, not compared;
  * every NEXT_DATA with the STATE it landed in and the reply bytes it threw
    away (an ack in STATE 01 is gated off by the FPGA and does nothing).

One forked child per (UCI_STATUS read, transient value) receives a one-sample
$30 / $00 / $20 at that read and finishes the send on its own — the same
fork-at-every-read sweep as the receive-path suite, every index, never only
the one the author expects to matter. Reads where the true value differs
from the previous read's true value are tagged EDGE (a stable register
cannot tear); edge reads must be green, off-edge reds must sit at the
OFF_EDGE_RESIDUAL sites (a ceiling, measured by this sweep).

The reply is staged under several schedules because WHEN it appears relative
to CMD_BUSY is the firmware's latency, not the C64 code's: `edge+K` stages
it right after the K-th UCI_STATUS read following CMD_BUSY dropping (K = 0:
already staged when CMD_BUSY drops), `delay` after a random cycle delay.

Scenarios (all multi-part ones are 889..1087 bytes: part 0 = the clamp, part
1 = the completing part):
  refuse    part 0 is refused with `81,..` / `82,..`: the send must return
            C=1 / $85 after exactly ONE command, emit NO datagram, and leave
            nothing behind;
  queued    SYNTHETIC: real firmware always sends a status line on a
            non-final part, so this shape never occurs on hardware; kept
            because it is harmless. Part 0 answers with no status line at
            all (the documented "no reply") and part 1 completes: C=0, two parts, one datagram, byte
            exact;
  queued00  same with a `00,..` status line on part 0;
  single    one completing part: the completing path's reads swept too.
  connectRefused / connectOk / close
            uci_udp_connect (a `85` refusal staged late must be OPEN_REFUSED
            $8D, not $88 after the 1 s budget) and net_udp_close (its reply
            consumed, not orphaned): the same STATE-01 sites as the send,
            in the default build too.
  refuseR   as refuse, but the refusal ALSO stages two RESP_DATA bytes (the
            firmware's reply shape was not characterised on the bench): they
            must land in uci_write_resp with uci_resp_count == 2, as the
            routine's header promises;
Verdict per child: C / error as above, parts on the wire, datagrams, the
datagram's bytes, no ack in STATE 01, no ack that discarded unread reply
bytes, exactly one ack per part, no push dropped, and the device left IDLE
with nothing pending (no ORPHAN).

Also
----
* bound: from the first push on, STATUS alternates $30/$20 forever. The send
  must return $89 / C=1 after ONE command, within BOUND_SECONDS of emulated
  time at 1 MHz and TURBO MHz and within BOUND_STATUS_READS UCI_STATUS reads
  at the wire tap (so a cap that is merely huge goes red, not only a spin).
* interpreter fidelity (BLAKE2s vs hashlib + one-bit corruption alarm).
* detector: a verdict computed against a payload with one bit flipped, and
  against a device that emitted a duplicate datagram, must come out broken.

VICE cannot run any of this: it does not emulate the UCI ($DF1D reads $FF).
What this cannot prove is the hardware premise (that the tear/lag occurs at
the 01 -> 10 edge of a $16 reply, and whether the firmware ever stages a
part's reply after CMD_BUSY drops) and the `$16` firmware itself, which is
GideonZ/1541ultimate#807 spike firmware only.

Randomisation: the datagram lengths and bytes (top half of the byte range
only: the replies are ASCII, so an echo cannot satisfy a reply check), the
socket id, status texts and codes, staging delays and the per-index fork
order come from one seeded RNG; the seed is printed first and reproducible
with `--seed` / TEST_SEED.

Build: `make clean && make BACKEND=uci UCI_CHUNKED_WRITE=1` unless --build is
given or C64_SKIP_BUILD is set, so it is a SERIAL suite
(tools/run_regression.py restores the default build afterwards).

Usage:
    python3 tools/test_uci_send_part_race.py [--seed S] [--build DIR]
        [--tree DIR] [--mhz M] [--turbo-mhz M] [--jobs N] [--only CASE]
Env: TEST_SEED, UCI_SEND_RACE_MHZ (default 1), UCI_SEND_RACE_TURBO_MHZ (48).
"""
from __future__ import annotations

import argparse
import os
import pickle
import random
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.mos6502 import Mos6502, CpuBudgetExceeded  # noqa: E402
import test_uci_short_read_drop as rig  # noqa: E402
import test_uci_status_tear as tear  # noqa: E402
from test_uci_short_read_drop import (  # noqa: E402
    STATE_IDLE, STATE_BUSY, STATE_DATA_LAST, ERR_WAIT_TIMEOUT, Cia1Tod,
    Result, PollResult,
)
from test_uci_status_tear import TapDevice, site_names  # noqa: E402

EXPECTED_CHECKS = 202

ERR_SEND_FAIL = 0x85
ERR_OPEN_REFUSED = 0x8D
ERR_SHORT_WRITE = 0x87
CMD_SOCKET_WRITE_CHUNK = 0x16
CMD_UDP_CONNECT = 0x08
CMD_SOCKET_CLOSE = 0x09
PART_MAX = 888          # net.s asserts UCI_CHUNK_PART_MAX <= 888

TRANSIENTS = tear.TRANSIENTS

# Off-edge (stable register, so no physical tear) one-sample transients that
# still break a send once the fix is in. Measured by this sweep, kept as a
# CEILING (hardening a site shrinks the red set and stays green; a NEW site
# turns this red):
#   uci_drain_status@dst_loop  a STAT_AV-clear sample MID-line (reads 2..n of
#                              the status line, on a register that is not
#                              changing) cuts the drain short and the ack
#                              discards the rest. A first read on the edge is
#                              NOT in this class: edge reads are held green.
#   uci_wait_reply_staged@wrs_loop
#                              any non-$10 sample while STATE is stably 01
#                              ends the wait early — the same residual the
#                              receive-path suite (OFF_EDGE_RESIDUAL in
#                              tools/test_uci_status_tear.py) records.
OFF_EDGE_RESIDUAL = {"uci_drain_status@dst_loop",
                     "uci_wait_reply_staged@wrs_loop"}

BOUND_SECONDS = 3.0
# Wire-tap ceiling on UCI_STATUS reads from the first flickering read to the
# send's return. The fix spends ~11 (push_wait, check_err, reply_staged, the
# 8-read settle cap); 24 leaves room for a cap up to ~2x without rewriting
# this and still catches a cap that is merely huge.
BOUND_STATUS_READS = 24
SWEEP_BUDGET_SECONDS = 30.0


# =============================================================================
# The firmware side of $16
# =============================================================================
class SendDevice(TapDevice):
    """TapDevice + the firmware's handling of NET_CMD_WRITE_SOCKET_CHUNK.

    plan[i] is None (part i is accepted) or (status line, RESP_DATA bytes) of
    its refusal (RESP_DATA may be empty: the firmware's refusal reply was not
    characterised on the bench, so both shapes are swept). A
    non-completing accepted part answers `queued_status` (b"" = no line, the
    documented "no reply") with NO RESP_DATA; a completing accepted part
    answers the 2-byte total and `ok_status`. The reply is staged as STATE
    10 after `stage_mode`: ("edge", K) or ("delay", cycles).
    """

    def __init__(self, *, plan=(), queued_status=b"", ok_status=b"",
                 stage_mode, accept_cycles, simple_reply=None, **kw):
        super().__init__(announced=0, payload=b"", blocks=[b""],
                         final_state=STATE_IDLE, accept_cycles=accept_cycles,
                         stage_cycles=[0], **kw)
        self.plan = list(plan)
        self.queued_status = queued_status
        self.ok_status = ok_status
        self.stage_mode = stage_mode
        # (RESP_DATA, status line) answered to UDP_CONNECT ($08) /
        # SOCKET_CLOSE ($09); None for the chunked-write scenarios.
        self.simple_reply = simple_reply
        self.simple_cmds = []       # command bytes of every connect/close
        self.parts = []             # (offset, total, bytes) per accepted push
        self.datagrams = []         # bytes of every datagram emitted
        self.bad_cmds = []
        self.ack_detail = []        # (state, unread_resp, unread_stat)
        self._cur = None
        self._asm = None

    # -- push ---------------------------------------------------------------
    def _push_cmd(self):
        if self.state != STATE_IDLE:
            # command_protocol.vhd: a push outside Idle is dropped and sets
            # error_busy; the bytes already written stay in the buffer.
            self.dropped_pushes += 1
            self.error = 1
            self.log.append(("push-dropped", f"state=${self.state:02X}"))
            return
        cmd = bytes(self.cmd)
        self.cmd = bytearray()
        self.commands_seen.append(cmd)
        if self.simple_reply is not None and len(cmd) >= 2 \
                and cmd[0] == 0x03 and cmd[1] in (CMD_UDP_CONNECT,
                                                  CMD_SOCKET_CLOSE):
            self.simple_cmds.append(cmd)
            self._cur = None
        elif (len(cmd) < 7 or cmd[0] != 0x03
                or cmd[1] != CMD_SOCKET_WRITE_CHUNK):
            self.bad_cmds.append(cmd[:8].hex())
            self._cur = None
        else:
            off = cmd[3] | (cmd[4] << 8)
            total = cmd[5] | (cmd[6] << 8)
            self._cur = (cmd[2], off, total, cmd[7:])
            self.parts.append((off, total, cmd[7:]))
        self.cmd_busy = 1
        self.state = STATE_BUSY
        self._at(self.accept_cycles, self._accept)

    def _accept(self):
        self.cmd_busy = 0               # STATE stays 01 until staged
        kind, val = self.stage_mode
        if kind == "edge":
            if val == 0:
                self._stage_reply()
            else:
                self._stage_countdown = val
                self._pending_index = 0
        else:
            self._at(val, self._stage_reply)

    def _stage(self, index):            # UciDevice.read's countdown hook
        self._stage_reply()

    def _stage_reply(self):
        idx = len(self.parts) - 1
        resp, stat = b"", b""
        if self.simple_reply is not None and self._cur is None \
                and self.simple_cmds:
            resp, stat = self.simple_reply
        elif self._cur is None:
            stat = b"21,UNKNOWN COMMAND"
        else:
            _sid, off, total, data = self._cur
            refusal = self.plan[idx] if idx < len(self.plan) else None
            completing = off + len(data) == total
            if refusal is not None:
                stat, resp = refusal
            else:
                if self._asm is None:
                    self._asm = [None] * total
                self._asm[off:off + len(data)] = list(data)
                if completing:
                    if None in self._asm:
                        stat = b"82,PARAMETER(S) OUT OF RANGE"
                    else:
                        self.datagrams.append(bytes(self._asm))
                        resp = bytes([total & 0xFF, total >> 8])
                        stat = self.ok_status
                else:
                    stat = self.queued_status
        self.state = STATE_DATA_LAST
        self.resp, self.resp_pos = resp, 0
        self.stat, self.stat_pos = stat, 0
        self.log.append(("stage", f"part={idx} resp={len(resp)} "
                                  f"stat={stat!r}"))

    def _data_acc(self):
        self.ack_detail.append((self.state, len(self.resp) - self.resp_pos,
                                len(self.stat) - self.stat_pos))
        if self.state == STATE_BUSY or self.state == STATE_IDLE:
            return                      # gated off in 01 (:163); nothing in 00
        self.state = STATE_IDLE
        self.resp, self.resp_pos = b"", 0
        self.stat, self.stat_pos = b"", 0

    def orphan(self):
        """What a send leaves behind: [] when the device is quiescent."""
        left = []
        if self.state != STATE_IDLE:
            left.append(f"state=${self.state:02X}")
        if self._due is not None or self._stage_countdown is not None:
            left.append("reply-still-to-be-staged")
        if self.resp_pos < len(self.resp):
            left.append(f"resp-unread={len(self.resp) - self.resp_pos}")
        if self.stat_pos < len(self.stat):
            left.append(f"stat-unread={len(self.stat) - self.stat_pos}")
        return left


class SendMachine(tear.TapMachine):
    """TapMachine.poll's CPU/CIA wiring, calling net_udp_send (send) or
    uci_udp_connect / net_udp_close (cmd)."""

    def send(self, device, *, socket_id, payload, mhz, max_cycles):
        return self._run(device, "net_udp_send", socket_id=socket_id,
                         payload=payload, mhz=mhz, max_cycles=max_cycles)

    def cmd(self, device, entry, *, socket_id, socket_open, dest, mhz,
            max_cycles):
        return self._run(device, entry, socket_id=socket_id, payload=b"",
                         mhz=mhz, max_cycles=max_cycles,
                         socket_open=socket_open, dest=dest)

    def _run(self, device, entry, *, socket_id, payload, mhz, max_cycles,
             socket_open=1, dest=None):
        s = self.sym
        mem = bytearray(0x10000)
        mem[self.load_addr:self.load_addr + len(self.image)] = self.image
        cia = Cia1Tod()
        per_tenth = int(rig.CYCLES_PER_TENTH * mhz)

        def io_read(addr):
            cia.cycles = cpu.cycles * rig.CYCLES_PER_TENTH // per_tenth
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                return device.read(addr)
            if 0xDC00 <= addr <= 0xDCFF:
                return cia.read(addr)
            return 0xFF

        def io_write(addr, value):
            if 0xDF1B <= addr <= 0xDF1F:
                device.sync(cpu.cycles)
                device.write(addr, value)

        cpu = Mos6502(mem, io_read, io_write)
        device.cpu = cpu
        src = s["udp_recv_buf"]
        mem[src:src + len(payload)] = payload
        mem[s["uci_socket_open"]] = socket_open
        mem[s["uci_socket_id"]] = socket_id
        mem[s["net_last_error"]] = 0
        if dest is not None:
            ip, port = dest
            mem[s["net_udp_dest_ip"]:s["net_udp_dest_ip"] + 4] = bytes(ip)
            mem[s["net_udp_dest_port"]] = port >> 8       # big-endian
            mem[s["net_udp_dest_port"] + 1] = port & 0xFF
        mem[s["net_udp_send_len"]] = len(payload) & 0xFF
        mem[s["net_udp_send_len"] + 1] = len(payload) >> 8
        cpu.a, cpu.x = src & 0xFF, src >> 8
        hung = None
        try:
            cpu.call(s[entry], max_cycles=max_cycles)
        except CpuBudgetExceeded as exc:
            hung = str(exc)
        wr = s["uci_write_resp"]
        return PollResult(carry=cpu.c, error=mem[s["net_last_error"]],
                          cycles=cpu.cycles, hung=hung,
                          socket_open=mem[s["uci_socket_open"]],
                          socket_id=mem[s["uci_socket_id"]],
                          resp_count=mem[s["uci_resp_count"]],
                          write_resp=bytes(mem[wr:wr + 2]))


# =============================================================================
# Scenarios and the verdict
# =============================================================================
class Scenario:
    def __init__(self, tag, payload, sid, make_dev, *, kind, pushes,
                 err=0x00, residual=None, values=None, want_resp=None):
        self.tag, self.payload, self.sid = tag, payload, sid
        self.make_dev, self.kind, self.pushes, self.err = (
            make_dev, kind, pushes, err)
        self.residual = OFF_EDGE_RESIDUAL if residual is None else residual
        self.values = values or dict(TRANSIENTS)
        # RESP_DATA bytes a refused part staged: uci_send_part's header says
        # they are captured into uci_write_resp / uci_resp_count for the host.
        self.want_resp = want_resp

    def run(self, machine, dev, mhz, max_cycles):
        return machine.send(dev, socket_id=self.sid, payload=self.payload,
                            mhz=mhz, max_cycles=max_cycles)

    def judge(self, r, dev):
        return verdict(r, dev, self)


class CmdScenario(Scenario):
    """UDP_CONNECT / SOCKET_CLOSE against the same device. kind:
    connect-ok, connect-refused, close."""

    def __init__(self, tag, kind, make_dev, *, sid, dest, **kw):
        super().__init__(tag, b"", sid, make_dev, kind=kind, pushes=0, **kw)
        self.dest = dest

    def run(self, machine, dev, mhz, max_cycles):
        entry = "net_udp_close" if self.kind == "close" else "uci_udp_connect"
        return machine.cmd(dev, entry,
                           socket_id=self.sid if self.kind == "close" else 0,
                           socket_open=1 if self.kind == "close" else 0,
                           dest=self.dest, mhz=mhz, max_cycles=max_cycles)

    def judge(self, r, dev):
        why = []
        if r.hung:
            why.append("HUNG")
        k = self.kind
        want_c, want_err = {"connect-ok": (0, 0x00),
                            "connect-refused": (1, ERR_OPEN_REFUSED),
                            "close": (0, 0x00)}[k]
        if r.carry != want_c or r.error != want_err:
            why.append(f"wrong-outcome(C={r.carry},err=${r.error:02X}, want "
                       f"C={want_c} err=${want_err:02X})")
        if len(dev.simple_cmds) != 1:
            why.append(f"commands-on-wire={len(dev.simple_cmds)}!=1")
        elif k != "close":
            c = dev.simple_cmds[0]
            want = bytes([0x03, CMD_UDP_CONNECT, self.dest[1] & 0xFF,
                          self.dest[1] >> 8]) + (
                ".".join(map(str, self.dest[0])).encode() + b"\x00")
            if c != want:
                why.append(f"connect-cmd-differs({c.hex()})")
        if k == "connect-ok" and (r.socket_id != self.sid or r.hung):
            why.append(f"socket-id=${r.socket_id:02X} want ${self.sid:02X}")
        if k == "connect-refused" and r.socket_open:
            why.append("socket_open-set-after-refusal")
        if k == "close" and (r.socket_open or r.socket_id):
            why.append("socket-state-not-cleared")
        bad_ack = [a for a in dev.ack_detail if a[0] == STATE_BUSY]
        if bad_ack:
            why.append(f"ack-in-STATE-01 x{len(bad_ack)} (gated off: reply "
                       f"not yet staged)")
        lost = [a for a in dev.ack_detail
                if a[0] == STATE_DATA_LAST and (a[1] or a[2])]
        if lost:
            why.append(f"ack-discarded-reply(resp={lost[0][1]},"
                       f"stat={lost[0][2]})")
        fired = [a for a in dev.ack_detail if a[0] == STATE_DATA_LAST]
        if len(fired) != 1:
            why.append(f"effective-acks={len(fired)}!=1")
        if dev.dropped_pushes:
            why.append(f"push-dropped x{dev.dropped_pushes}")
        left = dev.orphan()
        if left:
            why.append("ORPHAN(" + ",".join(left) + ")")
        return why


def verdict(r, dev, sc):
    """Every reason this send is not the correct outcome; [] means green."""
    why = []
    if r.hung:
        why.append("HUNG")
    if sc.kind == "ok":
        if r.carry != 0 or r.error != 0x00:
            why.append(f"not-sent(C={r.carry},err=${r.error:02X})")
    elif r.carry != 1 or r.error != sc.err:
        why.append(f"refusal-reported-as-sent?(C={r.carry},"
                   f"err=${r.error:02X}, want C=1 err=${sc.err:02X})")
    if sc.want_resp is not None and not r.hung and (
            r.resp_count != len(sc.want_resp)
            or r.write_resp != sc.want_resp):
        why.append(f"staged-resp-not-captured(count={r.resp_count},"
                   f"bytes={r.write_resp.hex()}, want {sc.want_resp.hex()})")
    if len(dev.parts) != sc.pushes:
        why.append(f"parts-on-wire={len(dev.parts)}!={sc.pushes}")
    if dev.bad_cmds:
        why.append(f"malformed-cmd {dev.bad_cmds[0]}")
    want_dg = [sc.payload] if sc.kind == "ok" else []
    if dev.datagrams != want_dg:
        why.append(f"datagrams={len(dev.datagrams)} want {len(want_dg)}"
                   + ("" if len(dev.datagrams) != len(want_dg) else
                      " (bytes differ)"))
    bad_ack = [a for a in dev.ack_detail if a[0] == STATE_BUSY]
    if bad_ack:
        why.append(f"ack-in-STATE-01 x{len(bad_ack)} (gated off: reply "
                   f"not yet staged)")
    lost = [a for a in dev.ack_detail
            if a[0] == STATE_DATA_LAST and (a[1] or a[2])]
    if lost:
        why.append(f"ack-discarded-reply(resp={lost[0][1]},stat={lost[0][2]})")
    # An ack in STATE 00 does nothing (a spurious idle-gate ack is
    # harmless); one that fired in STATE 10 must be exactly one per part —
    # a second is an orphan eaten by a later command's gate.
    fired = [a for a in dev.ack_detail if a[0] == STATE_DATA_LAST]
    if len(fired) != len(dev.parts):
        why.append(f"effective-acks={len(fired)}!=parts={len(dev.parts)}")
    if dev.dropped_pushes:
        why.append(f"push-dropped x{dev.dropped_pushes}")
    left = dev.orphan()
    if left:
        why.append("ORPHAN(" + ",".join(left) + ")")
    return why


def schedules(rng, kinds):
    d = rng.randrange(3_000, 60_000)
    allk = {f"e{k}": ("edge", k) for k in range(7)}
    allk["d"] = ("delay", d)
    return [(k, allk[k]) for k in kinds]


def build_scenarios(rng, part_max):
    sid = rng.randrange(1, 250)
    accept = rng.randrange(2_000, 12_000)

    def top_half(n):
        return bytes(rng.randrange(0x80, 0x100) for _ in range(n))

    def text(n):
        return bytes(rng.randrange(0x41, 0x5B) for _ in range(n))

    out = []

    def add(group, kinds, n, plan, queued, ok, kind, pushes, err=0x00,
            want_resp=None):
        payload = top_half(n)
        for sk, mode in schedules(rng, kinds):
            def mk(mode=mode):
                return SendDevice(plan=plan, queued_status=queued,
                                  ok_status=ok, stage_mode=mode,
                                  accept_cycles=accept)
            out.append(Scenario(f"{group}{n}/{sk}", payload, sid, mk,
                                kind=kind, pushes=pushes, err=err,
                                want_resp=want_resp))

    def refusal(with_resp):
        line = (b"%02d," % rng.choice((81, 82))) + text(rng.randrange(8, 24))
        return (line, bytes(rng.randrange(0x00, 0x80) for _ in range(2))
                if with_resp else b"")

    n_ref = rng.randrange(part_max + 1, part_max + 200)
    add("refuse", ("e0", "e1", "e2", "e3", "e4", "e5", "e6", "d"), n_ref,
        [refusal(False), None], b"", b"00,OK", "refuse", 1, err=ERR_SEND_FAIL)
    n_rr = rng.randrange(part_max + 1, part_max + 200)
    rr = refusal(True)
    add("refuseR", ("e0", "e2", "e3", "e4", "e5", "d"), n_rr,
        [rr, None], b"", b"00,OK", "refuse", 1, err=ERR_SEND_FAIL,
        want_resp=rr[1])
    n_q = rng.randrange(part_max + 1, part_max + 200)
    add("queued", ("e0", "e2", "e4", "e5", "d"), n_q, [None, None], b"",
        b"00,OK", "ok", 2)
    n_q0 = rng.randrange(part_max + 1, part_max + 200)
    add("queued00", ("e0", "e4", "e5", "d"), n_q0, [None, None],
        b"00," + text(rng.randrange(4, 16)), b"00,OK", "ok", 2)
    n_s = rng.randrange(1, 200)
    add("single", ("e1", "e3", "e5", "d"), n_s, [None], b"",
        b"00," + text(6), "ok", 1)
    # UDP_CONNECT and SOCKET_CLOSE: default-build sites of the same class
    # (the reply is staged by copy_result AFTER CMD_BUSY clears).
    def cmd_group(group, kind, kinds, reply):
        ip = tuple(rng.randrange(1, 255) for _ in range(4))
        dest = (ip, rng.randrange(1024, 65000))
        csid = rng.randrange(1, 250)
        for sk, mode in schedules(rng, kinds):
            def mk(mode=mode):
                return SendDevice(simple_reply=reply, stage_mode=mode,
                                  accept_cycles=accept)
            out.append(CmdScenario(f"{group}/{sk}", kind, mk, sid=csid,
                                   dest=dest))

    cmd_group("connectRefused", "connect-refused",
              ("e0", "e1", "e2", "e3", "e4", "e5", "e6", "d"),
              (b"", b"85," + text(rng.randrange(8, 24))))
    sock = rng.randrange(1, 250)
    cmd_group("connectOk", "connect-ok", ("e0", "e3", "e5", "d"),
              (bytes([sock]), b"00," + text(6)))
    for sc in out:
        if sc.tag.startswith("connectOk"):
            sc.sid = sock           # the id the firmware hands back
    cmd_group("close", "close", ("e0", "e2", "e4", "e5", "e6", "d"),
              (b"", b"00," + text(6)))
    return out


# =============================================================================
# The forking sweep
# =============================================================================
def sweep(machine, sc, rng, mhz, jobs):
    """Clean send + one forked child per (status read, transient value).

    Returns (clean_result, clean_device, rows) with rows
    (index, value_name, pc, true, edge, why).
    """
    dev = sc.make_dev()
    order_rng = random.Random(rng.randrange(2 ** 32))
    live = {}
    rows_raw = []
    child = {}
    max_cycles = int(SWEEP_BUDGET_SECONDS * mhz * 1_000_000)

    def reap_one():
        pid, _status = os.wait()
        idx, name, rfd = live.pop(pid)
        data = b""
        while True:
            chunk = os.read(rfd, 65536)
            if not chunk:
                break
            data += chunk
        os.close(rfd)
        rows_raw.append((idx, name, pickle.loads(data) if data else
                         {"why": ["CHILD-DIED"]}))

    def fork_at(idx):
        names = list(sc.values)
        order_rng.shuffle(names)
        for name in names:
            while len(live) >= jobs:
                reap_one()
            rfd, wfd = os.pipe()
            sys.stdout.flush()
            pid = os.fork()
            if pid == 0:
                os.close(rfd)
                dev.on_status_read = None
                dev.inject = (idx, sc.values[name])
                child["ctx"] = (idx, name, wfd)
                return
            os.close(wfd)
            live[pid] = (idx, name, rfd)

    dev.on_status_read = fork_at
    r = sc.run(machine, dev, mhz, max_cycles)
    if "ctx" in child:
        idx, name, wfd = child["ctx"]
        try:
            payload = {"why": sc.judge(r, dev)}
        except Exception as exc:     # noqa: BLE001 — reported, not swallowed
            payload = {"why": [f"CHILD-EXC {exc!r}"]}
        os.write(wfd, pickle.dumps(payload))
        os.close(wfd)
        os._exit(0)
    while live:
        reap_one()

    trues = [t for _pc, t, _s in dev.status_log]
    rows = []
    for idx, name, res in sorted(rows_raw):
        pc, true, _ = dev.status_log[idx]
        edge = idx > 0 and trues[idx] != trues[idx - 1]
        rows.append((idx, name, pc, true, edge, list(res["why"])))
    return r, dev, rows


def run_scenario(ctx, res, sc):
    m, rng = ctx["machine"], ctx["rng"]
    r, dev, rows = sweep(m, sc, rng, ctx["mhz"], ctx["jobs"])
    clean_why = sc.judge(r, dev)
    edges = [i for i in range(1, len(dev.status_log))
             if dev.status_log[i][1] != dev.status_log[i - 1][1]]
    print(f"  [{sc.tag}] clean: reads={len(dev.status_log)} "
          f"parts={[(o, t, len(b)) for o, t, b in dev.parts]} "
          f"cmds={len(dev.simple_cmds)} datagrams={len(dev.datagrams)} C={r.carry} err=${r.error:02X} "
          f"| children={len(rows)} | edges at "
          + ", ".join(f"#{i}(${dev.status_log[i - 1][1]:02X}->"
                      f"${dev.status_log[i][1]:02X})" for i in edges))
    tag = sc.tag
    # NOT a model-validity control: for a reply staged late (e5+, delay) the
    # clean send IS the defect — the reply arrives after the C64 stopped
    # looking, no tear needed — so this is red on the unfixed tree there.
    # Model validity is established by the prompt schedules that pass on
    # every build and by the detector checks.
    res.check(not clean_why, f"clean/{tag}",
              f"the clean send (no transient) is not the expected outcome: "
              f"{clean_why}")
    swept = sorted({row[0] for row in rows})
    want = list(range(len(dev.status_log)))
    res.check(swept == want and len(rows) == len(want) * len(sc.values),
              f"swept-every-index/{tag}",
              f"children ran at {len(swept)} indices, the clean run made "
              f"{len(want)} reads; rows={len(rows)}")
    red, lines = tear.summarise(rows, ctx["site"], sc.tag)
    for line in lines:
        print(line)
    edge_red = [row for row in red if row[4]]
    print(f"  [{sc.tag}] red {len(red)}/{len(rows)} "
          f"(at EDGE reads: {len(edge_red)})")
    res.check(not edge_red, f"edge-green/{tag}",
              f"{len(edge_red)} transient(s) on a read where the true "
              f"STATUS changed broke the send — see RED ... EDGE")
    off_sites = {ctx["site"](row[2]) for row in red if not row[4]}
    print(f"  [{sc.tag}] off-edge red sites: {sorted(off_sites) or '-'}")
    res.check(off_sites <= sc.residual, f"off-edge-residual/{tag}",
              f"off-edge transients broke the send at "
              f"{sorted(off_sites - sc.residual)}, outside the measured "
              f"residual {sorted(sc.residual)}")
    return r, dev


# =============================================================================
# Cases
# =============================================================================
def case_sweep(ctx, res):
    print("\n[sweep] one-sample transient at every UCI_STATUS read of a "
          "chunked send")
    m, rng = ctx["machine"], ctx["rng"]
    scenarios = build_scenarios(rng, PART_MAX)
    first = None
    for sc in scenarios:
        r, dev = run_scenario(ctx, res, sc)
        if first is None:
            first = (sc, r, dev)
        if sc.tag.startswith("refuse") and not sc.tag.startswith("refuseR") \
                and sc.tag.endswith("/e0"):
            # The clamp, read off the wire rather than from the symbol.
            res.check(dev.parts and len(dev.parts[0][2]) == PART_MAX
                      and dev.parts[0][0] == 0
                      and dev.parts[0][1] == len(sc.payload),
                      "wire/part0-is-the-888-clamp",
                      f"part 0 on the wire: "
                      f"{[(o, t, len(b)) for o, t, b in dev.parts]}")
    # Detector proofs against a CLEAN send of the first scenario.
    sc = scenarios[0]
    dev = sc.make_dev()
    r = m.send(dev, socket_id=sc.sid, payload=sc.payload, mhz=ctx["mhz"],
               max_cycles=int(SWEEP_BUDGET_SECONDS * ctx["mhz"] * 1e6))
    ok_sc = next(s for s in scenarios if s.kind == "ok")
    dev_ok = ok_sc.make_dev()
    r_ok = m.send(dev_ok, socket_id=ok_sc.sid, payload=ok_sc.payload,
                  mhz=ctx["mhz"],
                  max_cycles=int(SWEEP_BUDGET_SECONDS * ctx["mhz"] * 1e6))
    bad = bytearray(ok_sc.payload)
    bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
    fake = Scenario(ok_sc.tag, bytes(bad), ok_sc.sid, None, kind="ok",
                    pushes=ok_sc.pushes)
    res.check(verdict(r_ok, dev_ok, ok_sc) == []
              and verdict(r_ok, dev_ok, fake) != [],
              "detector/one-flipped-byte-is-red",
              "a verdict against a payload with one flipped bit came out "
              "green (or the control was not green) — the datagram "
              "comparison is not observing what crossed the wire")
    dev_ok.datagrams.append(dev_ok.datagrams[0])
    res.check(any(w.startswith("datagrams=2") for w in
                  verdict(r_ok, dev_ok, ok_sc)),
              "detector/duplicate-datagram-is-red",
              "a second emitted datagram was not counted — the wire tap "
              "is comparing content, not counting")
    # And a refusal reported as sent must be red.
    res.check(verdict(PollResult(carry=0, error=0, cycles=0, hung=None),
                      dev, sc) != [],
              "detector/refusal-as-queued-is-red",
              "C=0 / err=0 on a refused part came out green")


def case_bound(ctx, res):
    """STATUS never settles: alternating $30/$20 with DATA_AV clear."""
    print("\n[bound] a STATUS that never settles must end in $89, not spin "
          "or report queued")
    m, rng = ctx["machine"], ctx["rng"]
    n = rng.randrange(PART_MAX + 1, PART_MAX + 200)
    payload = bytes(rng.randrange(0x80, 0x100) for _ in range(n))
    phases = [0, 1]
    rng.shuffle(phases)
    for mhz, phase in [(mz, ph) for mz in sorted({ctx["mhz"], ctx["turbo_mhz"]})
                       for ph in phases]:
        dev = SendDevice(plan=[None, None], queued_status=b"",
                         ok_status=b"00,OK", stage_mode=("edge", 0),
                         accept_cycles=rng.randrange(2_000, 12_000))
        start = []
        bound = int(BOUND_SECONDS * mhz * 1_000_000)

        def flicker(idx, true, dev=dev, start=start, bound=bound, phase=phase):
            if not dev.parts:
                return true
            if not start:
                start.append((idx, dev.cpu.cycles))
            elif dev.cpu.cycles - start[0][1] > bound:
                raise CpuBudgetExceeded(
                    f"still polling STATUS {BOUND_SECONDS} s after it began "
                    f"to flicker (pc=${dev.cpu.pc:04X})")
            return (0x30, 0x20)[(idx - start[0][0] + phase) & 1]
        dev.override = flicker
        r = m.send(dev, socket_id=rng.randrange(1, 250), payload=payload,
                   mhz=mhz,
                   max_cycles=int(SWEEP_BUDGET_SECONDS * mhz * 1e6))
        flick_reads = len(dev.status_log) - start[0][0] if start else 0
        flick_cyc = r.cycles - start[0][1] if start else 0
        print(f"  [{mhz:g} MHz] phase={phase} hung={'yes' if r.hung else 'no'} "
              f"err=${r.error:02X} C={r.carry} parts={len(dev.parts)} "
              f"datagrams={len(dev.datagrams)} flicker: reads={flick_reads} "
              f"cycles={flick_cyc} ({flick_cyc / (mhz * 1e6) * 1e3:.2f} ms)")
        tag = f"bound/{mhz:g}MHz/phase{phase}"
        res.check(bool(start), f"{tag}/flicker-reached",
                  "the send never pushed, so the flicker was never applied "
                  "— the case is vacuous")
        res.check(r.hung is None, f"{tag}/returns",
                  f"net_udp_send did not return within {BOUND_SECONDS} s of "
                  f"emulated time at {mhz:g} MHz after STATUS began to "
                  f"flicker: {r.hung}")
        res.check(r.hung is None and flick_reads <= BOUND_STATUS_READS,
                  f"{tag}/status-reads",
                  f"{flick_reads} UCI_STATUS reads after STATUS began to "
                  f"flicker (ceiling {BOUND_STATUS_READS}"
                  f"{', and it never returned' if r.hung else ''})")
        res.check(r.error == ERR_WAIT_TIMEOUT and r.carry == 1
                  and len(dev.parts) == 1 and not dev.datagrams,
                  f"{tag}/wait-timeout",
                  f"err=${r.error:02X} C={r.carry} parts={len(dev.parts)} "
                  f"datagrams={len(dev.datagrams)}; expected $89, C=1 after "
                  f"ONE command, no datagram")


def case_interpreter(ctx, res):
    rig.case0_interpreter_fidelity(ctx, res)


def build_chunked_tree():
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set — skipping build")
        return
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", "BACKEND=uci", "UCI_CHUNKED_WRITE=1"],
                       capture_output=True, text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        raise SystemExit(f"FATAL: make BACKEND=uci UCI_CHUNKED_WRITE=1 "
                         f"failed:\n{r.stderr}")


# =============================================================================
def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default=None)
    p.add_argument("--tree", default=None)
    p.add_argument("--mhz", type=float,
                   default=float(os.environ.get("UCI_SEND_RACE_MHZ", "1")))
    p.add_argument("--turbo-mhz", type=float,
                   default=float(os.environ.get("UCI_SEND_RACE_TURBO_MHZ",
                                                "48")))
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    p.add_argument("--only", choices=("interp", "sweep", "bound"))
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    if args.build is None:
        build_chunked_tree()
    build = Path(args.build).resolve() if args.build else PROJECT_ROOT / "build"
    tree = Path(args.tree).resolve() if args.tree else PROJECT_ROOT
    prg = build / "wireguard.prg"
    if not prg.exists() or not (build / "wireguard.dbg").exists():
        print(f"FATAL: {prg} (and wireguard.dbg) not found — run "
              "`make BACKEND=uci UCI_CHUNKED_WRITE=1` first")
        return 2
    print(f"prg:   {prg}\n       {rig.fingerprint(prg)}")
    net_s = tree / "src" / "net" / "uci" / "net.s"
    print(f"net.s: {net_s}\n       {rig.fingerprint(net_s)}")
    labels = (build / "labels.txt").read_text().splitlines()
    if not any(l.split()[-1:] == [".uci_send_part"] for l in labels):
        print("FATAL: uci_send_part is not in labels.txt — this is not a "
              "UCI_CHUNKED_WRITE=1 build")
        return 2
    print(f"speed: sweeps at {args.mhz} MHz, bound at {args.mhz} and "
          f"{args.turbo_mhz} MHz; {args.jobs} jobs")
    mod, _ = rig.load_warp_live()
    machine = SendMachine(build, mod)
    if machine.sym.get("UCI_CHUNK_PART_MAX") != PART_MAX:
        print(f"FATAL: UCI_CHUNK_PART_MAX is "
              f"{machine.sym.get('UCI_CHUNK_PART_MAX')}, not {PART_MAX}")
        return 2
    site = site_names((build / "wireguard.dbg").read_text().splitlines())

    ctx = {"machine": machine, "rng": rng, "mod": mod, "mhz": args.mhz,
           "turbo_mhz": args.turbo_mhz, "jobs": max(1, args.jobs),
           "site": site}
    res = Result()
    cases = {"interp": case_interpreter, "sweep": case_sweep,
             "bound": case_bound}
    for key, fn in cases.items():
        if args.only and args.only != key:
            continue
        t0 = time.monotonic()
        fn(ctx, res)
        print(f"  ({key}: {time.monotonic() - t0:.0f} s wall)")

    total = res.passed + res.failed
    if len(set(res.names)) != len(res.names):
        print("FATAL: duplicate check names")
        return 2
    print(f"\nResults: {res.passed - res.skipped} passed, {res.failed} failed, "
          f"{res.skipped} skipped — {total} checks total")
    if not args.only and total != EXPECTED_CHECKS:
        print(f"FATAL: {total} checks ran, expected exactly {EXPECTED_CHECKS}")
        return 2
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
