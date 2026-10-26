#!/usr/bin/env python3
"""tools/test_uci_status_tear.py — red/green for a torn UCI_STATUS read.

The defect
----------
$DF1C (UCI_STATUS) is a live, unlatched register. When the firmware
validates the LAST block of a reply, STATE (bits 5..4) goes 01 -> 10 in one
clock, so a 6510 read that lands on the edge can return 11 ($30 — measured on
hardware) or 00. DATA_AV (bit 7) follows one FPGA clock late, so a clean
STATE=10 read with DATA_AV clear ($20) can also occur for one clock.

`net_poll`'s @block_end makes its whole decision from ONE read:

  torn $30           -> @block_more -> uci_ack on a REAL Data Last block: the
                        FIFO is reset and the datagram is gone
  torn $00 / lag $20 -> @block_short: a complete datagram is dropped ($8F)

How the transient is placed
---------------------------
The transient is a single SAMPLE, not a state: the model below (the same
$DF1C-$DF1F model tools/test_uci_short_read_drop.py uses, unchanged) keeps
its own state and timing, and on exactly one UCI_STATUS read the value the
CPU sees is replaced. Every read before and after it returns the true value.

The read index is counted by the MODEL, at the wire tap — never derived from
the assembly — and the transient is swept across EVERY index a reply
generates, not just the one the author expects to matter. To make that
affordable the sweep forks: one clean poll runs to completion, and at every
UCI_STATUS read it forks one child per transient value; the child receives
the bad sample at that read and finishes the poll on its own. So a child is
byte-for-byte the clean run up to its index, by construction.

Reads are also tagged EDGE when the true value at that read differs from the
true value at the read before it. That is where a tear is physically
possible (a stable register cannot tear), and those indices are reported
separately, so a red at a non-edge index is visible as such rather than
being confused with the hardware mechanism.

Schedules
---------
A multi-block reply (893 + n payload bytes, block 2 = Data Last) is staged
under several schedules, because WHICH read lands on the 01 -> 10 edge is a
property of the firmware's latency, not of the C64 code:

  edge+K   block 2 is staged right after the K-th UCI_STATUS read following
           our DATA_ACC on block 1, so the edge is on read K+1. K = 1 puts it
           on @block_end's deciding read at 5cc16f9; K = 2 puts it on the
           second read of the rejected "discard one sample" diff.
  delay    block 2 is staged after a randomised cycle delay (the existing
           suite's default model).

edge+1 is swept over EVERY index. The others are swept from the first
DATA_ACC onwards: up to that write the model's state and every served value
are identical across schedules (the suite asserts that prefix equality from
the logs rather than assuming it), so re-sweeping the prefix would rerun
identical children. A short single-block reply is swept over every index.

Verdict per child: delivered with C=0, $00 error, udp_recv_len == announced,
bytes exact, poison_stop == announced, the same number of NEXT_DATA writes
as the clean run, and no NEXT_DATA written while a staged block still had
unread bytes (the destructive ack).

Per schedule the suite then requires: every child at an EDGE read is green
(edge-green), and every red child at a non-edge read sits at one of the
OFF_EDGE_RESIDUAL sites (a ceiling — see its comment). Every red child is
printed either way, with its read index, call site (from wireguard.dbg),
true value and the reasons, so the full every-index table is in the log.

Also
----
* control: the clean poll of every schedule must be green on every build.
* bound: from the first DATA_ACC on, STATUS alternates $30/$20 forever
  (DATA_AV clear, phase randomised). A fix must leave with $89 inside
  BOUND_SECONDS of emulated time at both 1 MHz and TURBO MHz — a spin is
  caught as a budget overrun, never as a hang of this process.
* interpreter fidelity: tools/test_uci_short_read_drop.py's case 0 (BLAKE2s
  out of the same PRG against hashlib, plus a one-bit corruption alarm).
* detector: a verdict computed against a payload with one byte flipped must
  come out broken.

VICE cannot run any of this: it does not emulate the UCI at all ($DF1D
reads $FF), so the SOCKET_READ path is unreachable there. What this cannot
prove is the hardware premise itself — that the tear occurs at the rate it
does; that is measured on hardware ($30 observed), not here.

Randomisation: announced lengths, payload bytes, the socket id, the staging
delays, the bound case's phase and the per-index transient fork order come
from one seeded RNG; the seed is printed first and reproducible with
`--seed` / TEST_SEED.

Usage:
    python3 tools/test_uci_status_tear.py [--seed S] [--build DIR] [--tree DIR]
                                          [--mhz M] [--turbo-mhz M]
                                          [--jobs N] [--only CASE]
Env: TEST_SEED, UCI_TEAR_MHZ (default 1), UCI_TEAR_TURBO_MHZ (default 48).
"""
from __future__ import annotations

import argparse
import os
import pickle
import random
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.mos6502 import Mos6502, CpuBudgetExceeded  # noqa: E402
import test_uci_short_read_drop as rig  # noqa: E402
from test_uci_short_read_drop import (  # noqa: E402
    UCI_STATUS, CTRL_NEXT_DATA, STATE_IDLE, STATE_DATA_LAST,
    STATE_DATA_MORE, FIRST_BLOCK_PAYLOAD, READ_CHUNK_MAX, ERR_WAIT_TIMEOUT,
    Cia1Tod, Machine, PollResult, Result, UciDevice, make_device,
    _payload_for,
)

EXPECTED_CHECKS = 43

# (a) torn high on the 01 -> 10 edge, (b) torn low, (c) STATE settled but
# DATA_AV one FPGA clock late. All three have DATA_AV clear.
TRANSIENTS = {"a:$30-torn": 0x30, "b:$00-torn": 0x00, "c:$20-lag": 0x20}

EDGE_SCHEDULES = (1, 2, 3, 4)

# Where a one-sample transient on a STABLE register (no edge at that read,
# so not a physical tear) still breaks a delivery once @block_end is fixed.
# Measured by the every-index sweep, not derived from the source, and kept
# as a ceiling rather than an expected set: a later change that hardens one
# of these sites shrinks the red set and stays green, a NEW site turns this
# red. Each one, at 5cc16f9 and at the fix:
#   uci_wait_idle@wi_loop      $30/$20 on an idle device -> one extra
#                              NEXT_DATA (harmless in the model; counted)
#   uci_wait_reply_staged@wrs_loop
#                              any non-$10 sample while STATE is stably 01
#                              ends the wait early; @hdr_loop then sees no
#                              DATA_AV and @hdr_none drops the reply with
#                              C=0 and no error
#   net_poll@hdr_loop          a DATA_AV-clear sample over a staged block:
#                              the same @hdr_none drop
OFF_EDGE_RESIDUAL = {"uci_wait_idle@wi_loop",
                     "uci_wait_reply_staged@wrs_loop",
                     "net_poll@hdr_loop"}
BOUND_SECONDS = 3.0
# A sweep child may legitimately sit out a TOD budget (<= 5 s); anything
# past this is reported as HUNG rather than waited for.
SWEEP_BUDGET_SECONDS = 30.0


# =============================================================================
# The model, plus a tap
# =============================================================================
class TapDevice(UciDevice):
    """UciDevice with a wire tap on UCI_STATUS and NEXT_DATA, and a sample
    override. The underlying model's state machine is not touched: the
    transient replaces what the CPU SEES on one read, nothing else."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.cpu = None
        self.status_log = []        # (pc, true, served) per UCI_STATUS read
        self.acks = []              # (state, unread, status_index) per NEXT_DATA
        self.inject = None          # (index, value)
        self.override = None        # callable(index, true) -> served
        self.on_status_read = None  # fork hook

    def _read_pc(self):
        # Every UCI_STATUS read in this PRG is an absolute-mode load; at the
        # moment of the bus access the interpreter's PC is past the 3-byte
        # instruction. Checked against the image, not assumed.
        pc = (self.cpu.pc - 3) & 0xFFFF
        mem = self.cpu.mem
        if (mem[pc + 1], mem[pc + 2]) != (UCI_STATUS & 0xFF, UCI_STATUS >> 8):
            raise AssertionError(f"UCI_STATUS read not from an absolute "
                                 f"operand near ${self.cpu.pc:04X}")
        return pc

    def read(self, addr):
        if addr != UCI_STATUS:
            return super().read(addr)
        idx = len(self.status_log)
        true = super().read(addr)
        if self.on_status_read is not None:
            self.on_status_read(idx)
        served = true
        if self.inject is not None and self.inject[0] == idx:
            served = self.inject[1]
        if self.override is not None:
            served = self.override(idx, true)
        self.status_log.append((self._read_pc(), true, served))
        return served

    def write(self, addr, value):
        if addr == UCI_STATUS and value & CTRL_NEXT_DATA:
            self.acks.append((self.state, len(self.resp) - self.resp_pos,
                              len(self.status_log)))
        super().write(addr, value)


class TapMachine(Machine):
    """Machine.poll with the CPU handed to the tap and a CIA TOD that ticks
    at `mhz` (a tenth of a second is mhz * 100 000 cycles)."""

    def poll(self, device, *, socket_id, poison, mhz, max_cycles):
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
        mem[s["uci_socket_open"]] = 1
        mem[s["uci_socket_id"]] = socket_id
        mem[s["udp_recv_ready"]] = 0
        mem[s["net_last_error"]] = 0
        if "uci_short_read_state" in s:
            mem[s["uci_short_read_state"]] = rig.STATE_WITNESS
        mem[s["udp_recv_buf"]:s["udp_recv_buf"] + len(poison)] = poison
        hung = None
        try:
            cpu.call(s["net_poll"], max_cycles=max_cycles)
        except CpuBudgetExceeded as exc:
            hung = str(exc)
        buf = bytes(mem[s["udp_recv_buf"]:s["udp_recv_buf"] + self.buf_cap])
        return PollResult(
            carry=cpu.c, ready=mem[s["udp_recv_ready"]],
            recv_len=mem[s["udp_recv_len"]] | (mem[s["udp_recv_len"] + 1] << 8),
            error=mem[s["net_last_error"]], buf=buf,
            stop=self.mod.poison_stop(buf, poison),
            cycles=cpu.cycles, instructions=cpu.instructions, hung=hung)


def site_names(sym_lines):
    """pc -> 'scope@local' using every label in the dbg file."""
    labels = []
    by_id = {}
    for line in sym_lines:
        if not line.startswith("sym\t") or "type=lab" not in line:
            continue
        f = dict(kv.split("=", 1) for kv in line.split("\t")[1].split(","))
        by_id[f["id"]] = f
    for f in by_id.values():
        name = f["name"].strip('"')
        local = name.startswith("@")
        if local and f.get("parent") in by_id:
            name = by_id[f["parent"]]["name"].strip('"') + name
        labels.append((int(f["val"], 16), local, name))
    labels.sort()

    def lookup(pc):
        best = "?"
        for addr, _local, name in labels:
            if addr > pc:
                break
            best = name
        return best
    return lookup


# =============================================================================
# Scenarios
# =============================================================================
class Scenario:
    def __init__(self, tag, n, payload, poison, socket_id, make_dev,
                 sweep_from_first_ack):
        self.tag, self.n, self.payload, self.poison = tag, n, payload, poison
        self.socket_id, self.make_dev = socket_id, make_dev
        self.sweep_from_first_ack = sweep_from_first_ack


def build_scenarios(rng, mod, buf_cap):
    poison = mod.poison_pattern(buf_cap)
    n = rng.randrange(FIRST_BLOCK_PAYLOAD + 1, READ_CHUNK_MAX + 1)
    payload = _payload_for(rng, n, poison)
    sid = rng.randrange(1, 250)
    accept = rng.randrange(2_000, 40_000)
    first = rng.randrange(3_000, 60_000)
    delay = rng.randrange(3_000, 60_000)

    def multi(stage_on=None, cont_delay=None):
        def mk():
            d = make_device(random.Random(0), announced=n,
                            delivered_payload=payload,
                            final_state=STATE_IDLE,
                            stage_on_status_read=stage_on)
            dev = TapDevice(announced=d.announced, payload=d.payload,
                            blocks=d.blocks, final_state=d.final_state,
                            accept_cycles=accept,
                            stage_cycles=[first, cont_delay or delay],
                            stage_on_status_read=stage_on)
            return dev
        return mk

    out = [Scenario(f"multi{n}/edge+{k}", n, payload, poison, sid,
                    multi(stage_on=k), sweep_from_first_ack=(k != 1))
           for k in EDGE_SCHEDULES]
    out.append(Scenario(f"multi{n}/delay{delay}", n, payload, poison, sid,
                        multi(), sweep_from_first_ack=True))
    ns = rng.randrange(1, 65)
    ps = _payload_for(rng, ns, poison)

    def single():
        d = make_device(random.Random(0), announced=ns, delivered_payload=ps,
                        final_state=STATE_IDLE)
        return TapDevice(announced=d.announced, payload=d.payload,
                         blocks=d.blocks, final_state=d.final_state,
                         accept_cycles=accept, stage_cycles=[first, delay])
    out.append(Scenario(f"single{ns}", ns, ps, poison, sid, single,
                        sweep_from_first_ack=False))
    return out


def verdict(r, dev, sc, clean_acks):
    """Every reason this poll is not a correct delivery; [] means green."""
    why = []
    if r.hung:
        why.append("HUNG")
    if r.ready != 1 or r.carry != 0 or r.error != 0x00:
        why.append(f"not-delivered(ready={r.ready},C={r.carry},"
                   f"err=${r.error:02X})")
    if r.recv_len != sc.n:
        why.append(f"len={r.recv_len}")
    if r.buf[:sc.n] != sc.payload:
        why.append("bytes-differ")
    if r.stop != sc.n:
        why.append(f"stop={r.stop}")
    destructive = [a for a in dev.acks
                   if a[0] in (STATE_DATA_LAST, STATE_DATA_MORE) and a[1] > 0]
    if destructive:
        why.append(f"ack-on-unread-block(state=${destructive[0][0]:02X},"
                   f"unread={destructive[0][1]})")
    if clean_acks is not None and len(dev.acks) != clean_acks:
        why.append(f"acks={len(dev.acks)}!={clean_acks}")
    return why


# =============================================================================
# The forking sweep
# =============================================================================
def sweep(machine, sc, rng, mhz, jobs):
    """Clean poll + one forked child per (status read, transient value).

    Returns (clean_result, clean_device, rows) where rows are
    (index, value_name, pc, true, edge, why).
    """
    dev = sc.make_dev()
    order_rng = random.Random(rng.randrange(2 ** 32))
    live = {}                       # pid -> (idx, name, rfd)
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
        if sc.sweep_from_first_ack and not dev.acks:
            return
        names = list(TRANSIENTS)
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
                dev.inject = (idx, TRANSIENTS[name])
                child["ctx"] = (idx, name, wfd)
                return              # the child finishes the poll from here
            os.close(wfd)
            live[pid] = (idx, name, rfd)

    dev.on_status_read = fork_at
    r = machine.poll(dev, socket_id=sc.socket_id, poison=sc.poison, mhz=mhz,
                     max_cycles=max_cycles)
    if "ctx" in child:
        idx, name, wfd = child["ctx"]
        try:
            payload = {"why": verdict(r, dev, sc, None),
                       "acks": len(dev.acks), "err": r.error,
                       "ready": r.ready, "stop": r.stop}
        except Exception as exc:     # noqa: BLE001 — reported, not swallowed
            payload = {"why": [f"CHILD-EXC {exc!r}"]}
        os.write(wfd, pickle.dumps(payload))
        os.close(wfd)
        os._exit(0)
    while live:
        reap_one()

    clean_acks = len(dev.acks)
    trues = [t for _pc, t, _s in dev.status_log]
    rows = []
    for idx, name, res in sorted(rows_raw):
        why = list(res["why"])
        if "acks" in res and res["acks"] != clean_acks:
            why.append(f"acks={res['acks']}!={clean_acks}")
        pc, true, _ = dev.status_log[idx]
        edge = idx > 0 and trues[idx] != trues[idx - 1]
        rows.append((idx, name, pc, true, edge, why))
    return r, dev, rows


def summarise(rows, site_of, label):
    """Compress red rows into (value, site, true, edge, why) runs."""
    red = [row for row in rows if row[5]]
    lines = []
    for vname in TRANSIENTS:
        mine = [row for row in red if row[1] == vname]
        runs = []
        for idx, _n, pc, true, edge, why in mine:
            key = (site_of(pc), true, edge, "; ".join(why))
            if runs and runs[-1][0] == key and runs[-1][2] == idx - 1:
                runs[-1][2] = idx
            else:
                runs.append([key, idx, idx])
        for (site, true, edge, why), lo, hi in runs:
            span = f"{lo}" if lo == hi else f"{lo}-{hi}"
            lines.append(f"    RED {label} {vname:<11} read#{span:<9} "
                         f"{site:<34} true=${true:02X}"
                         f"{' EDGE' if edge else '     '}  {why}")
    return red, lines


# =============================================================================
# Cases
# =============================================================================
def case_sweeps(ctx, res):
    print("\n[sweep] one-sample transient at every UCI_STATUS read")
    m, rng = ctx["machine"], ctx["rng"]
    scenarios = build_scenarios(rng, ctx["mod"], m.buf_cap)
    prefix_ref = None
    for sc in scenarios:
        r, dev, rows = sweep(m, sc, rng, ctx["mhz"], ctx["jobs"])
        clean_why = verdict(r, dev, sc, len(dev.acks))
        edges = [i for i in range(1, len(dev.status_log))
                 if dev.status_log[i][1] != dev.status_log[i - 1][1]]
        print(f"  [{sc.tag}] clean: reads={len(dev.status_log)} "
              f"acks={len(dev.acks)} ready={r.ready} len={r.recv_len} "
              f"err=${r.error:02X} | children={len(rows)} | edges at "
              + ", ".join(f"#{i}(${dev.status_log[i - 1][1]:02X}->"
                          f"${dev.status_log[i][1]:02X} "
                          f"{ctx['site'](dev.status_log[i][0])})"
                          for i in edges))
        res.check(not clean_why, f"control/{sc.tag.split('/')[-1] if 'multi' in sc.tag else 'single'}",
                  f"the clean poll (no transient) is not a correct delivery: "
                  f"{clean_why}")
        # The prefix the from-first-ack schedules skip must really be
        # identical: same PCs, same true values, same served values.
        if sc.tag.startswith("multi"):
            first_ack = dev.acks[0][2] if dev.acks else len(dev.status_log)
            prefix = dev.status_log[:first_ack]
            if prefix_ref is None:
                prefix_ref = prefix
            elif sc.sweep_from_first_ack:
                res.check(prefix == prefix_ref,
                          f"prefix-identical/{sc.tag.split('/')[-1]}",
                          "the reads before the first DATA_ACC differ from "
                          "edge+1's, so skipping them is not justified")
        swept = sorted({row[0] for row in rows})
        first_ack = dev.acks[0][2] if dev.acks else len(dev.status_log)
        want = list(range(first_ack if sc.sweep_from_first_ack else 0,
                          len(dev.status_log)))
        res.check(swept == want and len(rows) == len(want) * len(TRANSIENTS),
                  f"swept-every-index/{sc.tag.split('/')[-1] if 'multi' in sc.tag else 'single'}",
                  f"children ran at {len(swept)} indices, the clean run made "
                  f"{len(want)} reads in range; rows={len(rows)}")
        red, lines = summarise(rows, ctx["site"], sc.tag)
        for line in lines:
            print(line)
        edge_red = [row for row in red if row[4]]
        print(f"  [{sc.tag}] red {len(red)}/{len(rows)} "
              f"(at EDGE reads: {len(edge_red)})")
        ctx["sweep_rows"].append((sc, rows))
        tag = sc.tag.split("/")[-1] if "multi" in sc.tag else "single"
        res.check(not edge_red, f"edge-green/{tag}",
                  f"{len(edge_red)} transient(s) on a read where the true "
                  f"STATUS changed broke the delivery — see RED ... EDGE")
        off_sites = {ctx["site"](row[2]) for row in red if not row[4]}
        print(f"  [{sc.tag}] off-edge red sites: {sorted(off_sites) or '-'}")
        res.check(off_sites <= OFF_EDGE_RESIDUAL,
                  f"off-edge-residual/{tag}",
                  f"off-edge transients broke the delivery at "
                  f"{sorted(off_sites - OFF_EDGE_RESIDUAL)}, outside the "
                  f"measured residual {sorted(OFF_EDGE_RESIDUAL)}")
    # Detector proof: the verdict must see one flipped payload byte.
    sc = scenarios[0]
    dev = sc.make_dev()
    r = m.poll(dev, socket_id=sc.socket_id, poison=sc.poison, mhz=ctx["mhz"],
               max_cycles=int(SWEEP_BUDGET_SECONDS * ctx["mhz"] * 1e6))
    bad = bytearray(sc.payload)
    bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
    fake = Scenario(sc.tag, sc.n, bytes(bad), sc.poison, sc.socket_id,
                    None, False)
    res.check(verdict(r, dev, fake, len(dev.acks)) != [],
              "detector/one-flipped-byte-is-red",
              "a verdict against a payload with one flipped bit came out "
              "green — the byte-exact comparison is not observing the copy")


def case_bound(ctx, res):
    """STATUS never settles: alternating $30/$20 with DATA_AV clear."""
    print("\n[bound] a STATUS that never settles must end in $89, not spin")
    m, rng = ctx["machine"], ctx["rng"]
    poison = ctx["mod"].poison_pattern(m.buf_cap)
    n = rng.randrange(FIRST_BLOCK_PAYLOAD + 1, READ_CHUNK_MAX + 1)
    payload = _payload_for(rng, n, poison)
    # Both phases, in a seeded order: which value the first flickering read
    # returns decides which wrong turn an unguarded @block_end takes (at
    # 5cc16f9: $30 first -> ack/re-read forever, $20 first -> $8F).
    phases = [0, 1]
    rng.shuffle(phases)
    for mhz, phase in [(mz, ph) for mz in sorted({ctx["mhz"], ctx["turbo_mhz"]})
                       for ph in phases]:
        d = make_device(rng, announced=n, delivered_payload=payload,
                        final_state=STATE_IDLE)
        dev = TapDevice(announced=d.announced, payload=d.payload,
                        blocks=d.blocks, final_state=d.final_state,
                        accept_cycles=d.accept_cycles,
                        stage_cycles=d.stage_cycles)
        start = []                  # (status index, cpu cycle) of flicker
        bound = int(BOUND_SECONDS * mhz * 1_000_000)

        def flicker(idx, true, dev=dev, start=start, bound=bound,
                    phase=phase):
            if not dev.acks:
                return true
            if not start:
                start.append((idx, dev.cpu.cycles))
            elif dev.cpu.cycles - start[0][1] > bound:
                # Stop the CPU here rather than let a spin run to the sweep
                # budget: poll() reports it as hung.
                raise CpuBudgetExceeded(
                    f"still polling STATUS {BOUND_SECONDS} s after it began "
                    f"to flicker (pc=${dev.cpu.pc:04X})")
            return (0x30, 0x20)[(idx - start[0][0] + phase) & 1]
        dev.override = flicker
        r = m.poll(dev, socket_id=rng.randrange(1, 250), poison=poison,
                   mhz=mhz, max_cycles=int(SWEEP_BUDGET_SECONDS * mhz * 1e6))
        flick_reads = len(dev.status_log) - start[0][0] if start else 0
        flick_cyc = r.cycles - start[0][1] if start else 0
        print(f"  [{mhz:g} MHz] phase={phase} hung={'yes' if r.hung else 'no'} "
              f"err=${r.error:02X} C={r.carry} ready={r.ready} "
              f"flicker: reads={flick_reads} cycles={flick_cyc} "
              f"({flick_cyc / (mhz * 1e6) * 1e3:.2f} ms) "
              f"acks-after={len(dev.acks) - 1}")
        res.check(bool(start), f"bound/{mhz:g}MHz/phase{phase}/flicker-reached",
                  "the poll never reached the first DATA_ACC, so the "
                  "flicker was never applied — the case is vacuous")
        res.check(r.hung is None, f"bound/{mhz:g}MHz/phase{phase}/returns",
                  f"net_poll did not return within {BOUND_SECONDS} s of "
                  f"emulated time at {mhz:g} MHz after STATUS began to "
                  f"flicker: {r.hung}")
        res.check(r.error == ERR_WAIT_TIMEOUT and r.carry == 1
                  and r.ready == 0, f"bound/{mhz:g}MHz/phase{phase}/wait-timeout",
                  f"err=${r.error:02X} C={r.carry} ready={r.ready}; "
                  f"expected $89, C=1, nothing delivered")


def case_interpreter(ctx, res):
    rig.case0_interpreter_fidelity(ctx, res)


# =============================================================================
def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--build", default=None)
    p.add_argument("--tree", default=None)
    p.add_argument("--mhz", type=float,
                   default=float(os.environ.get("UCI_TEAR_MHZ", "1")))
    p.add_argument("--turbo-mhz", type=float,
                   default=float(os.environ.get("UCI_TEAR_TURBO_MHZ", "48")))
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    p.add_argument("--only", choices=("interp", "sweep", "bound"))
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    if args.build is None:
        rig.build_uci_tree()
    build = Path(args.build).resolve() if args.build else PROJECT_ROOT / "build"
    tree = Path(args.tree).resolve() if args.tree else PROJECT_ROOT
    prg = build / "wireguard.prg"
    if not prg.exists() or not (build / "wireguard.dbg").exists():
        print(f"FATAL: {prg} (and wireguard.dbg) not found — run "
              "`make BACKEND=uci` first")
        return 2
    print(f"prg:   {prg}\n       {rig.fingerprint(prg)}")
    net_s = tree / "src" / "net" / "uci" / "net.s"
    print(f"net.s: {net_s}\n       {rig.fingerprint(net_s)}")
    print(f"speed: sweeps at {args.mhz} MHz, bound at {args.mhz} and "
          f"{args.turbo_mhz} MHz; {args.jobs} jobs")
    mod, _ = rig.load_warp_live()
    machine = TapMachine(build, mod)
    site = site_names((build / "wireguard.dbg").read_text().splitlines())

    ctx = {"machine": machine, "rng": rng, "mod": mod, "mhz": args.mhz,
           "turbo_mhz": args.turbo_mhz, "jobs": max(1, args.jobs),
           "site": site, "sweep_rows": []}
    res = Result()
    cases = {"interp": case_interpreter, "sweep": case_sweeps,
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
