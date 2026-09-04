#!/usr/bin/env python3
"""tools/test_warp_instrument_unit.py — red/green tests for the INSTRUMENT,
`tools/test_warp_live.py` Stage C (issue #128).

Why a test of a test
--------------------
The headline #128 result ("inbound replies of 1049-1187 B always fail AEAD,
9/9") was retracted as an instrument artifact. Nothing in Stage C had ever
been observed failing, so nothing could flag it. This suite supplies the
missing assertions: it runs the REAL `run_stage_c()` against a simulated
device whose behaviour is scripted, so the ground truth of every trial is
known here in the test, and the tool's verdict can be compared to it.

Nothing is asserted by matching log text. Every assertion is on the
structured per-query records `run_stage_c()` returns, compared against the
script that produced them. (Case 2 is precisely about a verdict derived
from screen text; a test that scraped text to prove it would be the same
mistake wearing a different hat.)

The simulated device is not a mock of the tool's expectations: it is a
64 KiB RAM plus a 25x40 screen, and the tool reads it through the ordinary
`read_memory` / `read_screen_codes` transport surface. The tool cannot tell
it apart from hardware, which is the point — every defect below is reached
through the tool's own code path.

Cases
  1  STALE STATE      nothing arrives; the previous trial's udp_recv_* are
                      still in RAM and get reported as this trial's.
  2a PEER SCROLLS     a printed inbound payload longer than the screen
     THE MARKER OFF   scrolls "MSG>" away; `screen.split("MSG>")[-1]`
                      silently degrades to the WHOLE dump.
  2b PEER MOVES       a short printed payload containing "MSG>" relocates
     THE MARKER       the split point INTO peer-controlled bytes.
                      Both score a peer-supplied "DECRYPT FAILED" as an
                      AEAD failure of ours. Both reach the screen through
                      `display_payload` (src/wg/session.s:634), which
                      prints peer bytes through the #129 printable filter
                      and does NOT touch msg_recv_len — so the tool sees
                      recv_len == 0 and evaluates the scrape. The premise
                      is proven on a real 6510 in
                      tools/test_warp_instrument_vice.py.
  3  UNMEASURED SIZE  a reply arrives at a size other than the table's;
                      the tool reports the table constant and flags
                      nothing, disproving the claim at test_warp_live.py
                      :217-219 that a drift "shows up as a mismatch".
  5  ORDER CONFOUND   the executed sweep ladder is monotonic in size and
                      the small control appears once, so size is perfectly
                      confounded with sweep position.

(Case 4, cause conflation, is a firmware property and lives in
tools/test_warp_instrument_vice.py.)

Every byte this fake peer puts on the wire is drawn from a seeded RNG and
the seed is logged; the fixed markers are suffixes only. The reply alphabet
is uppercase+digits and disjoint from the tool's lowercase DNS question
names, so an echo of the request cannot satisfy a reply assertion.

Usage:
    python3 tools/test_warp_instrument_unit.py [--seed S] [-v]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import random
import string
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness.encoding.screen_codes import SCREEN_CODE_TABLE  # noqa: E402

# Either build works: this suite exercises the Stage C QUERY LOOP, which is
# backend-independent. Prefer the msg_port 53 tree the live tool uses, fall
# back to the default build so the suite runs in the regression gate on
# whatever tree the gate leaves behind (no build of its own, no device).
# The suite emits exactly this many named checks on EVERY run, whichever
# branch each case takes and whichever instrument it is pointed at — a
# branch that does not apply still emits its names as skips. Pinned so a
# case that silently stops running is a hard error, not a smaller
# denominator nobody notices.
EXPECTED_CHECKS = 42

LABELS_CANDIDATES = (
    PROJECT_ROOT / "build_msgport53" / "labels.txt",
    PROJECT_ROOT / "build" / "labels.txt",
)

SCREEN_COLS, SCREEN_ROWS = 40, 25
SCREEN_BASE = 0x0400
SCREEN_SIZE = SCREEN_COLS * SCREEN_ROWS
BLANK_CODE = 0x20               # screen code for space
CURSOR_LINE_PTR = 0x00D1        # KERNAL pointer to the current screen line
CURSOR_COL = 0x00D3             # KERNAL cursor column within that line
KBD_BUFFER, KBD_COUNT = 0x0277, 0x00C6

# Reply alphabet, disjoint from the lowercase DNS names the tool sends, so
# a reply assertion can never be satisfied by an echo of the request.
REPLY_ALPHABET = string.ascii_uppercase + string.digits

# WireGuard Type-4 framing: 16-byte header + payload + 16-byte Poly1305 tag,
# so tp_payload_len == udp_recv_len - 32 on every datagram that reaches
# @replay_ok. IP+UDP is the header of the packet INSIDE the tunnel.
WG_OVERHEAD = 32
IP_UDP_HDR = 28

# Screen code -> ASCII is many-to-one; take the FIRST code for each glyph so
# the fake writes the same codes a C64 would for plain uppercase text.
_ASCII_TO_CODE: dict[str, int] = {}
for _code, _ch in enumerate(SCREEN_CODE_TABLE):
    _ASCII_TO_CODE.setdefault(_ch, _code)


# =============================================================================
# The simulated device
# =============================================================================
class Trial:
    """One scripted inbound outcome, and hence one trial's ground truth.

    Exactly one of the outcomes is true of any trial, and the assertions
    read these fields rather than re-deriving them from the tool's own
    output.
    """

    def __init__(self, *, arrives: bytes | None = None,
                 printed: bytes | None = None,
                 rejected: bool = False,
                 announced: int | None = None,
                 written: int | None = None,
                 type_byte: int = 4,
                 cause: int | None = None,
                 keepalive: bool = False,
                 marker: bytes | None = None,
                 marker_len: int = 200,
                 echo_anchor: bool = False):
        # announced -> what udp_recv_len says arrived
        # written   -> how many bytes the firmware actually copied; below
        #              announced models a truncated multi-block read, which
        #              is what the poison fill exists to measure
        # keepalive -> the device sent one of its own inside the window
        self.announced = announced
        self.written = written
        self.type_byte = type_byte
        self.cause = cause
        self.keepalive = keepalive
        # marker -> the device composes the printed payload itself, so the
        # injection is aligned against the REAL cursor column
        self.marker = marker
        self.marker_len = marker_len
        # echo_anchor -> the peer replays the tool's own per-query anchor
        # token back at it, which is the worst case for any marker-based
        # scrape: the peer then owns the marker as well as the text.
        self.echo_anchor = echo_anchor
        if marker is not None:
            self.printed = b""
        # arrives  -> udp_tunnel_parse matched: msg_recv_len set, payload
        #             printed after "MSG: ".
        # printed  -> decrypted but NOT a matching tunnel reply, so
        #             display_payload prints it after "RECV: " and leaves
        #             msg_recv_len at zero (src/wg/session.s:392, 439).
        # rejected -> transport_decrypt returned $ff; DECRYPT FAILED printed.
        # none of the three -> silence: nothing came back at all.
        self.arrives = arrives
        self.printed = printed
        self.rejected = rejected

    @property
    def reply_len(self) -> int | None:
        """The size that actually landed, or None if nothing did."""
        if self.arrives is not None:
            return len(self.arrives)
        if self.printed is not None:
            return len(self.printed)
        return None

    @property
    def device_rejected(self) -> bool:
        return self.rejected


class FakeDevice:
    """64 KiB of RAM with a REAL screen-RAM model, driven by a per-trial script.

    Screen RAM at $0400 is the single source of truth, and the KERNAL cursor
    pointer ($D1/$D2) and column ($D3) are maintained, because the fixed
    instrument writes screen RAM and those cursor bytes directly (its
    per-query anchor). A fake that kept its own text rows would let the
    anchor "work" without ever proving it lands where the C64's next
    character goes.

    A trial is applied when the tool presses RETURN (the send), which is
    exactly when a real device would start being able to answer.
    """

    screen_cols = SCREEN_COLS
    screen_rows = SCREEN_ROWS

    def __init__(self, labels: dict, trials: list, rng: random.Random):
        self.mem = bytearray(0x10000)
        self.L = labels
        self.trials = trials
        self.rng = rng
        self.sent = 0
        self.screen_reads: list = []
        self.mem[SCREEN_BASE:SCREEN_BASE + SCREEN_SIZE] = \
            bytes([BLANK_CODE]) * SCREEN_SIZE
        self._set_cursor(SCREEN_ROWS - 1, 0)
        self.mem[labels["boot_ready"]] = 1
        self.mem[labels["wg_state"]] = 2          # SESSION_ACTIVE
        self.recv_area = labels["ip_packet_buf"] + 0x0400
        self.mem[labels["msg_recv_ptr"]] = self.recv_area & 0xFF
        self.mem[labels["msg_recv_ptr"] + 1] = self.recv_area >> 8

    # --- transport surface -------------------------------------------------
    def read_memory(self, addr: int, length: int) -> bytes:
        if addr == KBD_COUNT:
            return bytes(length)              # the C64 ate the queue
        return bytes(self.mem[addr:addr + length])

    def write_memory(self, addr: int, data: bytes) -> None:
        if addr == KBD_BUFFER and data[:1] == b"\r":
            self._send()
            return
        if addr == KBD_BUFFER and data[:1] == b"M":
            self._print("MSG> ", newline=False)
            return
        if addr == KBD_BUFFER and data[:1] == b"H":
            # The handshake completes: _stage_config has just written
            # SESSION_IDLE, so ACTIVE has to be (re)asserted here or the
            # tool is waiting on a machine that never handshakes.
            self.mem[self.L["wg_state"]] = 2
            return
        self.mem[addr:addr + len(data)] = data

    def read_screen_codes(self) -> list:
        self.screen_reads.append((self.sent, self.rows()))
        return list(self.mem[SCREEN_BASE:SCREEN_BASE + SCREEN_SIZE])

    def resume(self) -> None:
        pass

    # --- screen ------------------------------------------------------------
    def rows(self) -> list:
        """The screen as text, decoded from screen RAM (ground truth)."""
        out = []
        for r in range(SCREEN_ROWS):
            base = SCREEN_BASE + r * SCREEN_COLS
            out.append("".join(SCREEN_CODE_TABLE[b] for b in
                               self.mem[base:base + SCREEN_COLS]))
        return out

    def _cursor(self):
        line = int.from_bytes(self.mem[CURSOR_LINE_PTR:CURSOR_LINE_PTR + 2],
                              "little")
        return (line - SCREEN_BASE) // SCREEN_COLS, self.mem[CURSOR_COL]

    def _set_cursor(self, row: int, col: int) -> None:
        line = SCREEN_BASE + row * SCREEN_COLS
        self.mem[CURSOR_LINE_PTR:CURSOR_LINE_PTR + 2] = \
            line.to_bytes(2, "little")
        self.mem[CURSOR_COL] = col

    def _print(self, text: str, newline: bool = True) -> None:
        row, col = self._cursor()
        for ch in text:
            if ch == "\n" or col >= SCREEN_COLS:
                row, col = self._newline(row)
                if ch == "\n":
                    continue
            self.mem[SCREEN_BASE + row * SCREEN_COLS + col] = \
                _ASCII_TO_CODE.get(ch.upper(), BLANK_CODE)
            col += 1
        if newline:
            row, col = self._newline(row)
        self._set_cursor(row, col)

    def _newline(self, row: int):
        if row < SCREEN_ROWS - 1:
            return row + 1, 0
        # scroll one row
        top = SCREEN_BASE + SCREEN_COLS
        self.mem[SCREEN_BASE:SCREEN_BASE + SCREEN_SIZE - SCREEN_COLS] = \
            self.mem[top:SCREEN_BASE + SCREEN_SIZE]
        last = SCREEN_BASE + SCREEN_SIZE - SCREEN_COLS
        self.mem[last:last + SCREEN_COLS] = bytes([BLANK_CODE]) * SCREEN_COLS
        return SCREEN_ROWS - 1, 0

    # --- the device's answer to a send -------------------------------------
    def _send(self) -> None:
        idx, self.sent = self.sent, self.sent + 1
        trial = self.trials[idx] if idx < len(self.trials) else Trial()
        L = self.L
        cause_addr = L.get("tp_reject_cause")
        # Our own send always advances tp_send_counter by exactly one; a
        # scripted keepalive advances it again, which is how the fixed tool
        # detects contamination.
        self._bump_send_counter(1 + (1 if trial.keepalive else 0))
        if trial.keepalive:
            self.mem[L["tp_payload_len"]:L["tp_payload_len"] + 2] = bytes(2)
            self.mem[L["tp_packet_len"]:L["tp_packet_len"] + 2] = \
                (32).to_bytes(2, "little")
            self._print("KEEPALIVE")
        if trial.arrives is not None:
            body = trial.arrives
            inner = len(body) + IP_UDP_HDR      # the tunnelled IP/UDP packet
            self._land_datagram(inner + WG_OVERHEAD, trial)
            self._decrypt_ok(inner)
            self.mem[self.recv_area:self.recv_area + len(body)] = body
            self.mem[L["msg_recv_len"]:L["msg_recv_len"] + 2] = \
                len(body).to_bytes(2, "little")
            self._set_cause(cause_addr, 0)
            self._print("MSG: ", newline=False)
            self._print(body.decode("ascii", "replace"))
        elif trial.printed is not None or trial.marker is not None:
            body = (trial.printed if trial.marker is None
                    else self._compose_injection(trial))
            self._land_datagram(len(body) + WG_OVERHEAD, trial)
            # transport_decrypt SUCCEEDED — the window advanced — but
            # udp_tunnel_parse did not match, so display_payload prints the
            # peer's bytes and msg_recv_len is NOT touched.
            self._decrypt_ok(len(body))
            self.mem[L["tp_packet"] + 16:L["tp_packet"] + 16 + len(body)] = body
            self.mem[L["tp_payload_len"]:L["tp_payload_len"] + 2] = \
                len(body).to_bytes(2, "little")
            self._set_cause(cause_addr, 0)
            self._print("RECV: ", newline=False)
            self._print(body.decode("ascii", "replace"))
        elif trial.rejected:
            n = trial.announced or self.rng.randrange(600, 1400)
            self._land_datagram(n, trial)
            # A reject does NOT advance the replay window and does NOT set
            # msg_recv_len; tp_packet_len IS set (session.s writes it from
            # udp_recv_len before the jsr).
            self.mem[L["tp_packet_len"]:L["tp_packet_len"] + 2] = \
                n.to_bytes(2, "little")
            if not trial.keepalive:
                self.mem[L["tp_payload_len"]:L["tp_payload_len"] + 2] = \
                    max(0, n - 32).to_bytes(2, "little")
            self._set_cause(cause_addr, trial.cause or 5)
            self._print("DECRYPT FAILED")
        # silence: nothing written, nothing printed — and, crucially,
        # nothing CLEARED either. That is the real device's behaviour and
        # the whole of case 1.

    def _compose_injection(self, trial) -> bytes:
        """Seeded filler carrying trial.marker aligned to a screen-row start.

        Built HERE, not in the test, because only the device knows the
        cursor column at the moment the peer's bytes are printed — and the
        fixed tool changed it (a 10-character anchor now precedes
        display_payload's "RECV: "). A marker that straddles a 40-column
        wrap is not a contiguous substring of the screen, so an unaligned
        injection would make the tool look safe for a reason that has
        nothing to do with the defect. A peer choosing its own padding
        aligns trivially; the firmware's own messages start at column 0.
        """
        row, col = self._cursor()
        start = (col + len("RECV: ")) % SCREEN_COLS
        marker = trial.marker
        if trial.echo_anchor:
            # Read the token straight off the glass: it was stamped at the
            # start of the cursor's row moments ago. A real peer cannot do
            # this, which is the point — this is the worst case, and what
            # matters is that it costs the attacker a REFUSAL, not a false
            # verdict.
            base = SCREEN_BASE + row * SCREEN_COLS
            marker = "".join(
                SCREEN_CODE_TABLE[b] for b in self.mem[base:base + col]
            ).strip().encode() or marker
            self.echoed_anchor = marker.decode()
        n = trial.marker_len
        limit = max(0, n - len(marker))
        off = 0
        while off + SCREEN_COLS <= limit:
            off += SCREEN_COLS
        off += (SCREEN_COLS - start) % SCREEN_COLS
        while off > limit:
            off -= SCREEN_COLS
        off = max(off, 0)
        head = "".join(self.rng.choice(REPLY_ALPHABET)
                       for _ in range(off)).encode()
        tail = "".join(self.rng.choice(REPLY_ALPHABET)
                       for _ in range(max(0, n - off - len(marker)))).encode()
        return head + marker + tail

    def _bump_send_counter(self, n: int) -> None:
        a = self.L["tp_send_counter"]
        v = int.from_bytes(self.mem[a:a + 8], "little") + n
        self.mem[a:a + 8] = (v & ((1 << 64) - 1)).to_bytes(8, "little")

    def _decrypt_ok(self, payload_len: int) -> None:
        # payload_len is tp_payload_len = udp_recv_len - WG_OVERHEAD, which
        # transport.s writes at @replay_ok before any decrypt happens.
        """Model the ONLY unambiguous success signal transport_decrypt
        leaves: the replay window advances (transport.s @advance_done /
        @just_set_bit run on the success path and on no reject path)."""
        L = self.L
        a = L["rw_counter_max"]
        v = int.from_bytes(self.mem[a:a + 8], "little") + 1
        self.mem[a:a + 8] = v.to_bytes(8, "little")
        idx = v & 0x7FF
        self.mem[L["rw_bitmap"] + (idx >> 3)] |= 1 << (idx & 7)
        self.mem[L["tp_packet_len"]:L["tp_packet_len"] + 2] = \
            (payload_len + WG_OVERHEAD).to_bytes(2, "little")
        self.mem[L["tp_payload_len"]:L["tp_payload_len"] + 2] = \
            payload_len.to_bytes(2, "little")

    def _set_cause(self, addr, value: int) -> None:
        """Model transport_decrypt's cause byte, on builds that have one.

        Silence leaves it alone: the tool poisons it before each send, so
        an untouched byte means transport_decrypt never ran this trial.
        """
        if addr is not None:
            self.mem[addr] = value

    def _land_datagram(self, announced: int, trial) -> None:
        """Write what an inbound datagram leaves in udp_recv_*.

        *announced* is the header total the adapter reports; `trial.written`
        is how many bytes the firmware actually COPIED. They differ on a
        truncated multi-block read, which is the case the poison fill exists
        to measure — so the fake writes exactly `written` bytes and leaves
        the tool's poison standing beyond them.
        """
        L = self.L
        n = announced if trial.announced is None else trial.announced
        self.mem[L["udp_recv_len"]:L["udp_recv_len"] + 2] = \
            n.to_bytes(2, "little")
        written = n if trial.written is None else trial.written
        ctr = int.from_bytes(
            self.mem[L["rw_counter_max"]:L["rw_counter_max"] + 8],
            "little") + 1
        head = (bytes([trial.type_byte, 0, 0, 0])
                + bytes(self.rng.randrange(256) for _ in range(4))
                + ctr.to_bytes(8, "little"))
        body = head + bytes(self.rng.randrange(256)
                            for _ in range(max(0, written - 16)))
        self.mem[L["udp_recv_buf"]:L["udp_recv_buf"] + len(body)] = body
        self.written_last = written


class FakeClient:
    def __init__(self) -> None:
        self.runs = 0

    def run_prg(self, prg_bytes: bytes) -> None:
        self.runs += 1


# =============================================================================
# Driving the real run_stage_c
# =============================================================================
def tool_fingerprint() -> str:
    """sha256 + size + mtime of the instrument this run actually loaded.

    Printed on every run because "which copy of the file was that?" has
    already cost this investigation one disputed result. A run's output
    should carry the identity of the code it describes.
    """
    path = PROJECT_ROOT / "tools" / "test_warp_live.py"
    raw = path.read_bytes()
    return (f"{path}\n         sha256={hashlib.sha256(raw).hexdigest()} "
            f"({len(raw)} B) mtime="
            f"{datetime.fromtimestamp(path.stat().st_mtime).isoformat(' ', 'seconds')}")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "warp_live_under_test", PROJECT_ROOT / "tools" / "test_warp_live.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def drive(mod, labels: dict, trials: list[Trial], rng: random.Random,
          seed: int, backend: str, prg: Path, **kw):
    """Run the tool's Stage C against the scripted device.

    Returns (result, device) — the device so a case can check its own
    ground truth (what it put on the glass) rather than inferring it from
    the tool's output.
    """
    dev = FakeDevice(labels, trials, rng)
    saved = (mod.PRG_C, mod.DNS_TIMEOUT, mod.BOOT_TIMEOUT,
             mod.HS_POLL_TIMEOUT, mod._net_init_ip65)
    mod.PRG_C = prg
    mod.DNS_TIMEOUT = 0.4        # nothing arrives late in the simulator
    mod.BOOT_TIMEOUT = 2.0
    mod.HS_POLL_TIMEOUT = 5.0
    # DHCP + turbo are a device concern and not what is under test here;
    # stubbing them is what lets an ip65 tree drive the same query loop.
    mod._net_init_ip65 = lambda tr, client, L, turbo, result: True
    try:
        r = mod.run_stage_c(dev, FakeClient(), labels,
                            bytes(32), bytes(32), bytes(32), seed,
                            backend=backend, turbo_mhz=48, **kw)
        return r, dev
    finally:
        (mod.PRG_C, mod.DNS_TIMEOUT, mod.BOOT_TIMEOUT,
         mod.HS_POLL_TIMEOUT, mod._net_init_ip65) = saved


def rand_body(rng: random.Random, n: int, suffix: bytes = b"") -> bytes:
    """n bytes of seeded filler, with any fixed marker as a SUFFIX only."""
    fill = "".join(rng.choice(REPLY_ALPHABET)
                   for _ in range(max(0, n - len(suffix))))
    return fill.encode() + suffix


# "MSG> " (the prompt) then "RECV: " (display_payload's header) precede the
# peer's bytes on the row they start on.
PRINT_START_COL = len("MSG> ") + len("RECV: ")


def injected_body(rng: random.Random, n: int, marker: bytes,
                  start_col: int = PRINT_START_COL) -> bytes:
    """Seeded filler carrying *marker* aligned to a screen-row boundary.

    A 40-column screen wraps, and a marker that straddles a wrap is not a
    contiguous substring of the dump — so an unaligned injection would make
    the tool look safe for a reason that has nothing to do with the defect.
    A peer choosing its own padding aligns trivially, and the firmware's own
    messages start at column 0 anyway, so alignment is the realistic case,
    not a special one. The marker is still the only fixed text: everything
    around it is drawn from the seeded RNG.
    """
    # Latest row-aligned offset that still leaves room for the marker: a
    # marker placed early in a payload longer than the screen scrolls off
    # with everything else, which would test nothing.
    limit = max(0, n - len(marker))
    offset = 0
    while offset + SCREEN_COLS <= limit:
        offset += SCREEN_COLS
    offset += (SCREEN_COLS - start_col) % SCREEN_COLS
    while offset > limit:
        offset -= SCREEN_COLS
    offset = max(offset, 0)
    head = "".join(rng.choice(REPLY_ALPHABET) for _ in range(offset)).encode()
    tail_len = max(0, n - len(head) - len(marker))
    tail = "".join(rng.choice(REPLY_ALPHABET)
                   for _ in range(tail_len)).encode()
    return head + marker + tail


def recv_len_of(q: dict) -> int:
    """The reply length this trial observed, under either field name.

    The fixed tool renamed `reply_recv_len` to `observed_reply_len` (None
    when nothing arrived); accept both so the suite scores the old and the
    new instrument identically.
    """
    if "reply_recv_len" in q:
        return q["reply_recv_len"] or 0
    return q.get("observed_reply_len") or 0


def snapshots_for(dev, query: int) -> list:
    """Every screen the tool read while scoring *query* (0-based).

    Snapshots are tagged with the number of sends that had happened when
    they were taken, so a premise is checked against the screen THAT query
    was verdicted from — not the end-of-run screen, which the next query's
    anchor has already blanked.
    """
    return [rows for sent, rows in dev.screen_reads if sent == query + 1]


def rows_contain(dev: "FakeDevice", text: str, read: int = 0) -> bool:
    """True when *text* sits unbroken on a row of a screen the tool read
    while scoring query *read*.

    This reads the FAKE device's own state — the test's ground truth about
    what it put on the glass — never the tool's verdict.
    """
    snaps = snapshots_for(dev, read)
    if not snaps:
        snaps = [dev.rows()]
    return any(text in row for rows in snaps for row in rows)


# =============================================================================
# Cases
# =============================================================================
class Result:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.names: list[str] = []
        self.notes: list[str] = []

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        self.names.append(name)
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}\n        {detail}")

    def skip(self, name: str, why: str) -> None:
        """A check that could not apply to THIS instrument, still counted.

        Every case emits a FIXED set of named checks whichever branch it
        takes, so the denominator is a property of the suite and not of the
        draw or the tree. A moving denominator makes two runs
        incomparable and is exactly how a case that silently stopped
        running would hide.
        """
        self.names.append(name)
        self.passed += 1
        self.skipped += 1
        print(f"  SKIP  {name}  ({why})")


def case1_stale_state(mod, labels, rng, seed, res: Result, ctx) -> None:
    """Trial 2 receives nothing; trial 1's udp_recv_* are still in RAM."""
    print("\n[case 1] stale receive state reported as this trial's")
    trials = [
        Trial(arrives=rand_body(rng, rng.randrange(900, 1300))),  # q0: real
        Trial(),                                                  # q1: silence
    ]
    r, _dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    q = r["queries"]
    res.check(len(q) == 2, "case1/ladder", f"expected 2 queries, got {len(q)}")
    if len(q) < 2:
        for nm in ("ground-truth-silent", "no-stale-type4", "no-stale-len",
                   "silence-is-not-a-reject", "arrival-detected-when-it-did"):
            res.skip("case1/" + nm, "the ladder did not produce two queries")
        return
    silent = q[1]
    res.check(recv_len_of(silent) == 0, "case1/ground-truth-silent",
              f"trial 2 was scripted silent but reply_recv_len="
              f"{recv_len_of(silent)}")
    res.check(silent.get("type4_ok") is not True, "case1/no-stale-type4",
              "nothing arrived on this trial, yet the tool reports "
              f"type4_ok={silent.get('type4_ok')!r} from recv_head="
              f"{silent.get('recv_head')!r} — that is the PREVIOUS trial's "
              f"datagram (udp_recv_len={silent.get('udp_recv_len')!r}) "
              "scored as this one's")
    res.check(silent.get("udp_recv_len") in (0, None), "case1/no-stale-len",
              f"udp_recv_len={silent.get('udp_recv_len')!r} on a trial where "
              "nothing arrived; the tool clears only msg_recv_len and "
              "tp_payload_len (test_warp_live.py:845-846)")
    # ARRIVED vs NEVER ARRIVED, host-side and at zero device bytes. The
    # poison fill makes this decidable: udp_recv_buf is pre-filled with a
    # position-dependent pattern before every send, so a header still equal
    # to the poison means the receive path wrote nothing this cycle. Before
    # the poison there was no such signal — a silent trial and a rejected
    # one were the same state — and that is half of what made #128's
    # failure side uninterpretable. Pinned here so it cannot regress
    # quietly, and because it is the reason no device-side cause byte is
    # needed to tell those two apart.
    name = silent.get("reject_cause_name")
    if name is None:
        res.check(False, "case1/silence-is-not-a-reject",
                  "this instrument does not classify at all, so a query "
                  "where nothing arrived is indistinguishable from one that "
                  "was rejected")
    else:
        res.check(silent.get("reject_cause") is None
                  and silent.get("decrypt_failed") is not True
                  and "no-datagram" in str(name),
                  "case1/silence-is-not-a-reject",
                  "nothing arrived, so the query must classify as "
                  "no-datagram-arrived; got "
                  f"cause={silent.get('reject_cause')!r} name={name!r} "
                  f"decrypt_failed={silent.get('decrypt_failed')!r} "
                  f"arrived={(silent.get('reject_detail') or {}).get('arrived')!r}")
    got = q[0]
    res.check((got.get("reject_detail") or {}).get("arrived") is not False,
              "case1/arrival-detected-when-it-did",
              "a reply DID arrive on trial 1 but the instrument says "
              "arrived=False, so the poison rule is not detecting arrival at "
              "all and the silence check above passes vacuously")


def case2a_marker_scrolled_off(mod, labels, rng, seed, res: Result, ctx) -> None:
    """A printed peer payload longer than the screen removes the marker."""
    print("\n[case 2a] peer payload longer than the screen")
    # display_payload path: decrypts, prints, leaves msg_recv_len at 0.
    # 1278 bytes is ~32 rows on a 25-row screen, so whatever per-query
    # marker the tool relies on — the old "MSG>" prompt or the new random
    # anchor — is scrolled away before the screen is read.
    trials = [Trial(marker=b"DECRYPT FAILED", marker_len=1278)]
    r, dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    q = r["queries"][0]
    res.check(recv_len_of(q) == 0, "case2a/ground-truth-recvlen",
              "premise broken: display_payload must leave msg_recv_len at 0")
    res.check(rows_contain(dev, "DECRYPT FAILED"), "case2a/premise-injected",
              "premise broken: the peer's marker did not land unbroken on a "
              "screen row, so nothing was injected to detect")
    _screen_and_structure(res, r, q, "case2a",
                          "the marker was scrolled off a 25-row screen")


def _screen_and_structure(res, r, q, tag: str, how: str) -> None:
    """The two halves of case 2, asserted separately.

    They are separate because the fixed instrument fixes exactly one of
    them, and a single combined assertion would report the surviving half
    as the fixed one's failure.
    """
    # (a) the SCREEN half: a peer must not be able to make the screen say
    #     this query failed. Either the window is refused (unscored) or it
    #     is scored and clean; scoring it as a failure is the defect.
    scored = q.get("screen_anchor_ok")
    if scored is None:                      # pre-fix tool: no anchor at all
        res.check(q.get("decrypt_failed") is not True, tag + "/screen-half",
                  "the pre-anchor tool scraped the screen for its verdict and "
                  f"reports decrypt_failed={q.get('decrypt_failed')!r}; {how}")
        res.skip(tag + "/unscored-is-explicit",
                 "this instrument has no anchor, so there is no unscored "
                 "state to be explicit about")
    else:
        res.check(q.get("screen_decrypt_failed") is not True,
                  tag + "/screen-half",
                  "no reject happened, yet the screen verdict is "
                  f"screen_decrypt_failed={q.get('screen_decrypt_failed')!r} "
                  f"(anchor_ok={scored}); {how}")
        res.check(scored is True or q.get("screen_unscored_reason"),
                  tag + "/unscored-is-explicit",
                  "the screen could not be scored and the record does not say "
                  f"why: screen_anchor_ok={scored!r}, keys={sorted(q)}")
    # (b) the STRUCTURAL half: the datagram DECRYPTED (the replay window
    #     advanced), so no reject cause applies to it at all.
    before, after = q.get("rw_counter_max_before"), q.get("rw_counter_max_after")
    if before is None or after is None:
        window = ("this instrument does not sample the replay window, so it "
                  "has no way to tell a successful decrypt from a reject")
    else:
        window = (f"the replay window advanced from {before} to {after}, "
                  "which ONLY the success path in transport.s does "
                  "(@advance_done / @just_set_bit run on no reject path)")
    res.check(q.get("decrypt_failed") is not True, tag + "/no-false-positive",
              "this datagram DECRYPTED and was printed by display_payload — "
              f"{window} — yet the tool reports "
              f"decrypt_failed={q.get('decrypt_failed')!r} "
              f"cause={q.get('reject_cause')!r} "
              f"({q.get('reject_cause_name')!r})")


def case2b_marker_relocated(mod, labels, rng, seed, res: Result, ctx) -> None:
    """A short printed payload containing the marker moves the split point."""
    print("\n[case 2b] peer payload supplies the scrape marker itself")
    # Short enough that the query's own marker is still on screen — the peer
    # wins anyway against split()[-1], because it takes the LAST occurrence
    # and the peer's copy is printed BELOW the prompt.
    trials = [Trial(marker=b"MSG> DECRYPT FAILED", marker_len=200)]
    r, dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    q = r["queries"][0]
    res.check(recv_len_of(q) == 0, "case2b/ground-truth-recvlen",
              "premise broken: display_payload must leave msg_recv_len at 0")
    res.check(rows_contain(dev, "MSG> DECRYPT FAILED"),
              "case2b/premise-injected",
              "premise broken: the peer's marker did not land unbroken on a "
              "screen row, so nothing was injected to detect")
    _screen_and_structure(res, r, q, "case2b",
                          "the peer supplied the split marker itself, so it "
                          "controls the region's BOUNDARY, not just its "
                          "content")


def case2c_peer_supplies_the_anchor(mod, labels, rng, seed, res: Result,
                                    ctx) -> None:
    """The peer replays the tool's OWN per-query anchor token back at it."""
    print("\n[case 2c] peer replays the per-query anchor token")
    trials = [Trial(marker=b"DECRYPT FAILED", marker_len=200,
                    echo_anchor=True)]
    r, dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    q = r["queries"][0]
    tok = getattr(dev, "echoed_anchor", None)
    if not q.get("screen_anchor") or not tok:
        for nm in ("premise-injected", "not-scored-as-failure",
                   "anchor-duplicate-refused"):
            res.skip("case2c/" + nm,
                     "this instrument has no per-query anchor to attack")
        return
    res.check(rows_contain(dev, tok), "case2c/premise-injected",
              f"premise broken: the replayed token {tok!r} did not land on a "
              "row, so nothing was injected to detect")
    # The peer owning the marker must cost it a REFUSAL, never a verdict.
    res.check(q.get("screen_decrypt_failed") is not True,
              "case2c/not-scored-as-failure",
              "a peer that replays the anchor must not be able to produce a "
              f"screen verdict; got screen_decrypt_failed="
              f"{q.get('screen_decrypt_failed')!r} "
              f"anchor_ok={q.get('screen_anchor_ok')!r}")
    res.check(q.get("screen_anchor_ok") is False,
              "case2c/anchor-duplicate-refused",
              "the token is on the screen twice — once stamped, once from "
              "the peer — so the window after it is ambiguous and must be "
              f"refused; screen_anchor_ok={q.get('screen_anchor_ok')!r}")


def case3_unmeasured_size(mod, labels, rng, seed, res: Result, ctx) -> None:
    """A reply of the wrong size is reported as the table's size."""
    print("\n[case 3] size reported from the table, not from what arrived")
    actual = rng.randrange(820, 900)          # table says namecheap = 1278
    trials = [Trial(arrives=rand_body(rng, actual)), Trial()]
    r, _dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    got, silent = r["queries"][0], r["queries"][1]
    expected = got.get("expected_reply_len", got.get("dig_measured"))
    res.check(recv_len_of(got) == actual, "case3/ground-truth-arrived",
              f"scripted a {actual} B reply, tool saw {recv_len_of(got)}")
    res.check(got.get("size_mismatch") is True, "case3/mismatch-flagged",
              f"a {actual} B reply arrived where the table says {expected} B, "
              "and no field in the query record flags the disagreement — "
              "disproving the claim at test_warp_live.py:217-219 that a "
              "drifted entry 'shows up as a mismatch rather than a wrong "
              f"conclusion'. record keys: {sorted(got)}")
    res.check(got.get("observed_reply_len") == actual, "case3/size-measured",
              "no field carries the size that actually arrived; "
              f"observed_reply_len={got.get('observed_reply_len')!r}")
    # Not "the size field is absent" — that would pass vacuously today.
    # The tool must SAY, per trial, that nothing was observed, so a reader
    # cannot mistake the surviving table constant for a measurement.
    res.check(silent.get("reply_observed") is False, "case3/no-size-on-failure",
              "on a trial where nothing arrived the record must state so "
              f"explicitly; reply_observed={silent.get('reply_observed')!r} "
              f"while dig_measured={silent.get('dig_measured')!r} is still "
              "reported — a hardcoded constant standing in for a measurement")


def case6_unscored_absorption(mod, labels, rng, seed, res: Result,
                              ctx) -> None:
    """An unscored query must not be absorbable as a pass."""
    print("\n[case 6] an unscored query cannot be counted as a pass")
    # Query 1 scrolls its own anchor away (unscorable); query 2 is silent.
    trials = [Trial(marker=b"DECRYPT FAILED", marker_len=1278), Trial()]
    r, _dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=1)
    unscored = r.get("unscored_queries")
    if unscored is None:
        res.check(False, "case6/unscored-list-exists",
                  "the instrument has no notion of an unscored query, so a "
                  "screen it could not attribute is indistinguishable from a "
                  "clean one")
        for nm in ("unscored-recorded", "unscored-is-none-not-false",
                   "unscored-reaches-exit-code"):
            res.skip("case6/" + nm, "no unscored_queries list to inspect")
        return
    res.skip("case6/unscored-list-exists",
             "present — the branch that asserts its absence does not apply")
    res.check(len(unscored) >= 1, "case6/unscored-recorded",
              f"query 1 scrolled its anchor away but unscored_queries is "
              f"{unscored!r}")
    q0 = r["queries"][0]
    # The three-valued distinction is the whole lesson: not-failed and
    # could-not-tell must not collapse.
    res.check(q0.get("screen_decrypt_failed") is None,
              "case6/unscored-is-none-not-false",
              "an unscorable screen must read None, not False — False is a "
              "measurement and would be counted as a clean query; got "
              f"{q0.get('screen_decrypt_failed')!r}")
    # And it must reach the process's verdict, not just a log line.
    errs = mod.stage_errors({"C": r})
    res.check(bool(errs), "case6/unscored-reaches-exit-code",
              "unscored_queries is populated but nothing consumes it: "
              "stage_errors() returned "
              f"{errs!r}, so main() exits 0 with "
              f"{len(unscored)} unattributable quer(y/ies) buried in the "
              "results. A downstream count of 'queries that did not report a "
              "failure' silently absorbs them as passes — which is the exact "
              "shape of the defect this whole investigation is about")


def case7_poison_stop(mod, labels, rng, seed, res: Result, ctx) -> None:
    """poison_stop must separate truncation from corruption ANYWHERE."""
    print("\n[case 7] poison_stop truncation-vs-corruption discrimination")
    tool_block = getattr(mod, "UCI_FIRST_BLOCK_PAYLOAD", None)
    if not hasattr(mod, "poison_stop"):
        res.check(False, "case7/forensics-exist",
                  "this instrument has no poison fill, so a short read and a "
                  "corrupted full read are the same observation")
        for nm in ("stops-measured", "off-boundary-not-called-genuine",
                   "full-write-called-genuine",
                   "boundary-and-off-boundary-differ",
                   "independent-of-the-assumed-boundary"):
            res.skip("case7/" + nm, "no poison fill to measure with")
        return
    res.check(True, "case7/forensics-exist")

    # Announced 1306 B; three ways the buffer can end up wrong.
    announced = 1306
    off_boundary = 1000          # a truncation NOWHERE near 893
    trials = [
        Trial(rejected=True, announced=announced, written=tool_block),
        Trial(rejected=True, announced=announced, written=off_boundary),
        Trial(rejected=True, announced=announced),          # full write
    ]
    r, _dev = drive(mod, labels, trials, rng, seed, **ctx, large_repeats=3)
    got = [q.get("block_forensics", {}) for q in r["queries"][:3]]
    stops = [f.get("poison_stop") for f in got]
    res.check(stops == [tool_block, off_boundary, announced],
              "case7/stops-measured",
              f"poison_stop should read {[tool_block, off_boundary, announced]}"
              f" for a short read at the assumed block boundary, a short read "
              f"at {off_boundary}, and a full write; got {stops}")
    verdicts = [f.get("poison_verdict") for f in got]
    # The verdict for the OFF-boundary truncation must name the real number
    # and must NOT claim the datagram was fully received. This is what makes
    # the hardware run independent of whether 893 is the true boundary.
    res.check(verdicts[1] is not None
              and str(off_boundary) in str(verdicts[1])
              and "fully-received" not in str(verdicts[1]),
              "case7/off-boundary-not-called-genuine",
              "a truncation at an offset other than the ASSUMED block "
              f"boundary must be reported at its measured offset, not as a "
              f"complete datagram; verdict was {verdicts[1]!r}")
    res.check("fully-received" in str(verdicts[2]),
              "case7/full-write-called-genuine",
              "a full-length write must be reported as fully received, so a "
              f"tag mismatch on it can be called genuine; got {verdicts[2]!r}")
    res.check(verdicts[0] != verdicts[1],
              "case7/boundary-and-off-boundary-differ",
              f"the two truncations are reported identically: {verdicts[0]!r}")
    # The 893 constant must be a LABEL on one case, never the thing that
    # decides truncated-vs-genuine. Prove it: nothing about the off-boundary
    # trial's classification changed when the assumed boundary moved.
    res.check(got[1].get("poison_stop") == off_boundary,
              "case7/independent-of-the-assumed-boundary",
              "the off-boundary truncation's measured stop must not depend "
              f"on UCI_FIRST_BLOCK_PAYLOAD={tool_block}")


def case7b_poison_collision(mod, labels, rng, seed, res: Result, ctx) -> None:
    """A full write whose tail coincides with the poison must not read short.

    Arithmetic on the tool's own functions over the REAL geometry:
    udp_recv_buf is poisoned to CAPACITY, so a full write's surviving tail
    already runs from udp_len to the end of the buffer and a tail-length
    rule cannot see the coincidence. Only a rule on `udp_len - stop` can.
    """
    print("\n[case 7b] poison collision at the tail of a full write")
    if not hasattr(mod, "poison_pattern"):
        for nm in ("clean-full-write", "tail-collision-not-misread",
                   "real-truncation-survives", "host-aead-outranks-poison",
                   "tolerance-is-meaningful"):
            res.skip("case7b/" + nm, "no poison fill in this instrument")
        return
    cap, n = 1500, 1306
    pat = mod.poison_pattern(cap)

    def buffer_with(tail_coincidence: int) -> bytes:
        """A FULL write of n bytes whose last *tail_coincidence* bytes
        happen to equal the poison, with the poison intact beyond n."""
        body = bytearray(rng.randrange(256) for _ in range(n))
        for i in range(n):
            while body[i] == pat[i]:
                body[i] = rng.randrange(256)
        for i in range(n - tail_coincidence, n):
            body[i] = pat[i]
        return bytes(body) + pat[n:cap]

    clean = mod.classify_recv_buffer(buffer_with(0), None, n, poison=pat)
    res.check(clean.get("poison_stop") == n, "case7b/clean-full-write",
              f"a full write must read poison_stop == {n}; got "
              f"{clean.get('poison_stop')!r}")
    one = mod.classify_recv_buffer(buffer_with(1), None, n, poison=pat)
    res.check(one.get("poison_stop") == n, "case7b/tail-collision-not-misread",
              "a FULL write whose last byte happens to equal the poison "
              f"reads poison_stop={one.get('poison_stop')!r} instead of {n}, "
              "so a genuine tag mismatch is reported as a partial write — "
              "the worst direction for this error to point")
    # The tolerance must not swallow a truncation worth seeing.
    big = mod.classify_recv_buffer(buffer_with(0)[:893] + pat[893:cap],
                                   None, n, poison=pat)
    res.check(big.get("poison_stop") == 893, "case7b/real-truncation-survives",
              "a block-boundary truncation must still be reported at its "
              f"offset; got {big.get('poison_stop')!r}")
    # And the host AEAD must outrank the scan when they disagree.
    over = mod.classify_recv_buffer(buffer_with(20), None, n, poison=pat,
                                    host_tag_verifies=True)
    res.check(over.get("poison_aead_override") is True
              and "fully-received" in str(over.get("poison_verdict")),
              "case7b/host-aead-outranks-poison",
              "when the host Poly1305 VERIFIES, every announced byte was "
              "present and the poison scan must not be allowed to call it a "
              f"partial write; verdict was {over.get('poison_verdict')!r}")
    # Characterise the tolerance across EVERY collision depth rather than
    # asserting the constant. Depths below the threshold must read as a full
    # write; depths at or above it must be believed. Deterministic — the
    # collision is constructed, not waited for — so this is a complete
    # statement about the rule, not a sample of it.
    mr = getattr(mod, "POISON_MIN_RUN", 1)
    mod_n = getattr(mod, "POISON_MOD", 256)
    below = {d: mod.classify_recv_buffer(buffer_with(d), None, n,
                                         poison=pat).get("poison_stop")
             for d in range(1, mr)}
    at_or_above = {d: mod.classify_recv_buffer(buffer_with(d), None, n,
                                               poison=pat).get("poison_stop")
                   for d in (mr, mr + 1, mr + 8)}
    wrong_below = {d: v for d, v in below.items() if v != n}
    wrong_above = {d: v for d, v in at_or_above.items() if v != n - d}
    res.check(not wrong_below and not wrong_above and mr >= 8,
              "case7b/tolerance-is-meaningful",
              f"POISON_MIN_RUN={mr}. Collision depths that were NOT read as a "
              f"full write: {wrong_below}; depths at/above the threshold not "
              f"read at their true stop: {wrong_above}")
    print(f"        tolerance characterised: collision depths 1..{mr - 1} all "
          f"read poison_stop={n} (full write); depths {mr}, {mr + 1}, "
          f"{mr + 8} all read their true stop")
    print(f"        residual false-partial rate: a RANDOM tail must coincide "
          f"for >= {mr} bytes, (1/{mod_n})^{mr} = {(1.0 / mod_n) ** mr:.3e} "
          f"per rejected trial (was 1/256 = 3.906e-03)")


def case5_order_confound(mod, labels, rng, seed, res: Result, ctx) -> None:
    """Sweep position is perfectly confounded with reply size."""
    print("\n[case 5] sweep ladder ordering")
    trials = [Trial() for _ in range(64)]
    r, _dev = drive(mod, labels, trials, rng, seed, **ctx,
                    large_repeats=1, reply_sweep=1)
    if r.get("ladder"):
        # The fixed tool publishes the ladder structurally; assert on that
        # rather than on a band string, which is prose.
        sizes = [e["expected_reply_len"] for e in r["ladder"]]
    else:
        rungs = [q for q in r["queries"]
                 if str(q.get("band", "")).startswith("SWEEP")]
        sizes = [q.get("expected_reply_len", q.get("dig_measured"))
                 for q in rungs]
    res.check(len(sizes) >= 4, "case5/ladder-present",
              f"expected a sweep ladder, got {sizes}")
    if len(sizes) < 4:
        for nm in ("not-monotonic", "control-repeated", "control-separated"):
            res.skip("case5/" + nm, "no ladder to inspect")
        return
    monotonic = all(b >= a for a, b in zip(sizes, sizes[1:]))
    res.check(not monotonic, "case5/not-monotonic",
              f"the executed ladder is in monotonic size order {sizes}: "
              "sweep position and reply size move together, so any effect "
              "of position (session age, counter, replay-window state) is "
              "indistinguishable from an effect of size")
    # The control is whichever rung the instrument NOMINATES as its control,
    # not simply the smallest — an instrument may reasonably pick a mid-size
    # rung so the control is comparable to the sizes under test. Fall back
    # to the smallest when nothing is nominated.
    nominated = getattr(mod, "SWEEP_CONTROL", None)
    control = nominated[1] if nominated else min(sizes)
    positions = [i for i, v in enumerate(sizes) if v == control]
    res.check(len(positions) >= 2, "case5/control-repeated",
              f"the control ({control} B) appears {len(positions)}x in "
              f"{sizes}; a control that runs once, first, cannot separate "
              "drift over the run from size")
    # Repetition is not enough: three consecutive control rungs sample one
    # moment of the run, not three.
    spread = (max(positions) - min(positions)) if len(positions) >= 2 else 0
    res.check(spread >= len(sizes) // 2, "case5/control-separated",
              f"the control's positions {positions} span {spread} of "
              f"{len(sizes)} rungs; they must be SEPARATED across the run or "
              "they measure the same moment three times")


# =============================================================================
def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--only", default=None,
                   help="run one case: 1, 2a, 2b, 3 or 5")
    args = p.parse_args(argv)

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("TEST_SEED") or random.randrange(2 ** 32))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    labels_path = next((p for p in LABELS_CANDIDATES if p.exists()), None)
    if labels_path is None:
        print("FATAL: no labels.txt in " +
              " or ".join(str(p.parent) for p in LABELS_CANDIDATES) +
              " — run `make` first")
        return 2
    print(f"instrument: {tool_fingerprint()}")
    mod = load_tool()
    labels = dict(mod.Labels.from_file(str(labels_path)))
    # detect_backend refuses a current ip65 tree: issue #120 gave the ip65
    # adapter its own `net_last_error`, and the tool still treats that label
    # as proof of a uci build (tools/test_warp_live.py:251-269). That is a
    # separate defect in the same tool — it makes `--backend ip65` exit 2 on
    # every ip65 build — and it is not this suite's subject, so fall back
    # rather than refuse to run.
    try:
        backend = mod.detect_backend(labels)
    except ValueError:
        backend = "uci" if "uci_send_part" in labels else "ip65"
        print(f"note: detect_backend refused these labels; using {backend} "
              "(see tools/test_warp_live.py:251-269)")
    prg = labels_path.parent / "wireguard.prg"
    print(f"labels: {labels_path} (backend={backend}, "
          f"tp_reject_cause={'present' if 'tp_reject_cause' in labels else 'ABSENT'})")
    ctx = {"backend": backend, "prg": prg}

    res = Result()
    cases = {
        "1": case1_stale_state,
        "2a": case2a_marker_scrolled_off,
        "2b": case2b_marker_relocated,
        "3": case3_unmeasured_size,
        "2c": case2c_peer_supplies_the_anchor,
        "5": case5_order_confound,
        "6": case6_unscored_absorption,
        "7": case7_poison_stop,
        "7b": case7b_poison_collision,
    }
    for key, fn in cases.items():
        if args.only and args.only != key:
            continue
        fn(mod, labels, rng, seed, res, ctx)

    total = res.passed + res.failed
    if len(set(res.names)) != len(res.names):
        dupes = sorted({n for n in res.names if res.names.count(n) > 1})
        print(f"\nFATAL: duplicate check names {dupes} — the denominator is "
              "not a stable identity")
        return 2
    real = res.passed - res.skipped
    # Passed and skipped lead; the total follows. A skip increments `passed`
    # so the denominator stays a fixed identity (see EXPECTED_CHECKS), but
    # this is a suite whose whole subject is that a clean-looking report is
    # not the same as a correct one, so the line must not read as N passes
    # to someone scanning it. Skips are named individually above.
    print(f"\nResults: {real} passed, {res.failed} failed, "
          f"{res.skipped} skipped (branch not applicable to this "
          f"instrument) — {total} checks total")
    if not args.only and total != EXPECTED_CHECKS:
        print(f"FATAL: {total} checks ran, expected exactly "
              f"{EXPECTED_CHECKS}. A moving denominator makes two runs "
              "incomparable and is how a case that silently stopped running "
              "hides. Update EXPECTED_CHECKS deliberately when adding one.")
        return 2
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
