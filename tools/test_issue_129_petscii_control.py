#!/usr/bin/env python3
"""test_issue_129_petscii_control.py — a peer must not be able to drive the display.

Issue #129. ``session_handle_packet``'s ``@t4_udp`` branch prints the inner
UDP payload of a decrypted Type 4 packet through KERNAL CHROUT with
``zp_tmp1 = 0`` — "no printable filter". CHROUT does not print PETSCII
control codes, it EXECUTES them, so every byte a peer puts in a chat message
is a display command: $93 clears the screen, $13 homes the cursor, $12 turns
reverse video on, $0E/$8E swap the character set, $90-$9F change the text
colour (including to black-on-black). ``display_payload``, twelve lines away
in the same file, does the identical job with ``zp_tmp1 = 1``.

THE ORACLE IS AN IDENTITY, NOT A KEYWORD. With the filter on, every byte
outside $20..$7E is emitted as '.', so delivering a payload P is
byte-for-byte indistinguishable from delivering ``expected(P)`` — P with each
control byte replaced by '.'. Both are the same number of CHROUT calls with
the same effect on the machine. So the test delivers BOTH from a restored,
identical display state and requires the full observable state afterwards to
match exactly:

    screen RAM ($0400-$07E7), colour RAM ($D800-$DBE7, low nybble),
    the cursor ($D1/$D2 line pointer, $D3 column, $D6 row, $F3/$F4),
    the reverse flag ($C7), quote mode ($D4), insert count ($D8),
    the line-link table ($D9-$F2), the current colour ($0286),
    the shift-lock ($0291), and VIC $D011/$D016/$D018/$D020/$D021/$D022-4.

Nothing here reads a log line, and no assertion can be satisfied by text that
merely happens to be near the payload on screen: the comparison is against a
second run of the real firmware on the real display state.

Randomisation (standing project rule): the benign filler, the payload length,
which control codes are embedded, how many, and where, and the screen prefill
marker are all drawn from a seeded RNG; the seed is logged once and replayable
with --seed. The filler alphabet excludes '"' on purpose — a quote character
puts CHROUT into quote mode, where control codes are DISPLAYED as reverse
graphics instead of executed, which would hide the very bug under test. The
only fixed text is a short marker at the END of the payload, used solely as
the liveness check that the print path ran at all.

Self-check (--selfcheck / TEST_129_SELFCHECK=1) corrupts one byte of the
expected payload. On a fixed tree the normal run passes and the corrupted run
must fail; that is the proof that this comparison is sensitive to a single
byte of display state rather than passing vacuously.

VICE-only by construction, and no hardware is needed or wanted: the whole
mechanism is KERNAL CHROUT and the VIC, both of which VICE models exactly.
Nothing here touches UCI ($DF1D), so there is no hardware-only half.

Usage:
    python3 tools/test_issue_129_petscii_control.py [--seed S] [--trials N]
                                                    [--verbose] [--selfcheck]
"""

import hashlib
import os
import random
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

SCREEN = 0x0400
COLOUR = 0xD800
SCREEN_LEN = 1000
COLS = 40

# Zero page display state owned by the KERNAL screen editor. $C6 (keyboard
# queue length) is deliberately excluded: it is harness scratch.
ZP_LO, ZP_HI = 0x00C7, 0x00F4          # inclusive
ZP_LEN = ZP_HI - ZP_LO + 1

# Bytes in that range that no CHROUT can move but that the machine does:
# $CB is the live keyboard matrix code, $CD the cursor blink countdown.
ZP_VOLATILE = {0x00CB, 0x00CD}

PLOT_TRAMPOLINE = 0x0350               # CLC / LDX row / LDY col / JSR $FFF0 / RTS
PLOT_ROW, PLOT_COL = 5, 0

# The full dangerous set named in issue #129, all of which are outside
# $20..$7E and therefore all of which the filter must swallow.
CTRL_CODES = (
    [0x05, 0x0E, 0x11, 0x12, 0x13, 0x14, 0x1C, 0x1D, 0x1E, 0x1F, 0x81, 0x8E]
    + list(range(0x90, 0xA0))
)

# A subset whose effect on the observable state is unmistakable, so that every
# randomised trial is guaranteed to be able to go red rather than depending on
# the draw: clear screen, home, reverse on, and the pure colour changes.
CTRL_HIGH_IMPACT = [0x93, 0x13, 0x12, 0x90, 0x96, 0x9E, 0x9F, 0x05, 0x1C, 0x1E]

# Printable filler. '"' ($22) is excluded (quote mode masks the bug) and '.'
# ($2E) is excluded so a filler byte can never be confused with a filtered
# control byte in the diff output.
FILLER = bytes(b for b in range(0x20, 0x7F) if b not in (0x22, 0x2E))

# Screen codes safe to prefill with (letters and digits), so a $93 wipe to
# spaces is unmistakable.
PREFILL_CODES = list(range(0x01, 0x1B)) + list(range(0x30, 0x3A))

MARKER = b"WG129END"                   # suffix only; liveness, not the oracle


# ============================================================================
# Packet construction
# ============================================================================

def inner_udp(port, text):
    """A minimal IPv4+UDP datagram carrying *text* to *port*."""
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack('>H', 28 + len(text))
    ip[8] = 64
    ip[9] = 17                          # UDP
    ip[12:16] = b'\x0a\x00\x00\x02'
    ip[16:20] = b'\x0a\x00\x00\x01'
    udp = bytearray(8)
    udp[0:2] = struct.pack('>H', port)
    udp[2:4] = struct.pack('>H', port)
    udp[4:6] = struct.pack('>H', 8 + len(text))
    return bytes(ip) + bytes(udp) + text


def make_payload(rng):
    """Return (dangerous, expected, codes) for one trial.

    *dangerous* is what the peer sends; *expected* is what a correctly
    filtered CHROUT stream is indistinguishable from.
    """
    body_len = rng.randint(24, 96)
    body = bytearray(rng.choice(FILLER) for _ in range(body_len))

    n_codes = rng.randint(1, 5)
    positions = rng.sample(range(body_len), n_codes)
    codes = [rng.choice(CTRL_HIGH_IMPACT)] + [
        rng.choice(CTRL_CODES) for _ in range(n_codes - 1)]
    rng.shuffle(codes)

    dangerous = bytearray(body)
    for pos, code in zip(positions, codes):
        dangerous[pos] = code
    expected = bytearray(dangerous)
    for pos in positions:
        expected[pos] = ord('.')

    return (bytes(dangerous) + MARKER, bytes(expected) + MARKER,
            sorted((p, c) for p, c in zip(positions, codes)))


# ============================================================================
# Display state capture / restore
# ============================================================================

def capture(transport):
    """Read every piece of display state a PETSCII control code can move."""
    zp = bytearray(read_bytes(transport, ZP_LO, ZP_LEN))
    for addr in ZP_VOLATILE:
        zp[addr - ZP_LO] = 0
    scr = bytes(read_bytes(transport, SCREEN, SCREEN_LEN))
    col = bytes(b & 0x0F for b in read_bytes(transport, COLOUR, SCREEN_LEN))
    page = bytes(read_bytes(transport, 0x0286, 1))          # current colour
    page += bytes(read_bytes(transport, 0x0288, 1))         # screen page
    lock = bytes(read_bytes(transport, 0x0291, 1))
    vic = bytes(read_bytes(transport, 0xD011, 1))[0] & 0x7F  # mask raster bit 8
    vic = bytes([vic]) + bytes(read_bytes(transport, 0xD016, 1))
    vic += bytes(read_bytes(transport, 0xD018, 1))
    vic += bytes(read_bytes(transport, 0xD020, 5))          # $D020-$D024
    return {
        "zp": bytes(zp), "screen": scr, "colour": col,
        "page": page, "lock": lock, "vic": vic,
    }


def normalise_cursor(transport):
    """Disable the KERNAL cursor blink and undo any half-applied blink.

    The blink XORs $80 into the screen code under the cursor from the IRQ, so
    without this a screen comparison is a coin flip on where the machine was
    paused. With $CC non-zero the KERNAL's IRQ skips the blink block entirely
    ($CD and $CF are then never touched either).
    """
    cc, cd, ce, cf = read_bytes(transport, 0x00CC, 4)
    if cf:                                  # a reversed char is on screen now
        line = int.from_bytes(read_bytes(transport, 0x00D1, 2), 'little')
        col = read_bytes(transport, 0x00D3, 1)[0]
        write_bytes(transport, line + col, bytes([ce]))
        write_bytes(transport, 0x00CF, bytes([0]))
    write_bytes(transport, 0x00CC, bytes([1]))


def plot_cursor(transport, row, col):
    """Move the cursor via KERNAL PLOT so every derived pointer stays sane."""
    write_bytes(transport, PLOT_TRAMPOLINE, bytes([
        0x18,                       # CLC
        0xA2, row,                  # LDX #row
        0xA0, col,                  # LDY #col
        0x20, 0xF0, 0xFF,           # JSR $FFF0
        0x60,                       # RTS
    ]))
    jsr(transport, PLOT_TRAMPOLINE)


class DisplayState:
    """A captured display state that can be written back byte for byte."""

    def __init__(self, transport):
        self.transport = transport
        self.prefill_screen = bytes(SCREEN_LEN)
        self.prefill_colour = bytes(SCREEN_LEN)
        self.zp = bytes(read_bytes(transport, ZP_LO, ZP_LEN))
        self.colour_reg = bytes(read_bytes(transport, 0x0286, 1))
        self.lock = bytes(read_bytes(transport, 0x0291, 1))
        self.d016 = bytes(read_bytes(transport, 0xD016, 1))
        self.d018 = bytes(read_bytes(transport, 0xD018, 1))
        self.d020_24 = bytes(read_bytes(transport, 0xD020, 5))

    def set_prefill(self, code, colour):
        """Choose the screen/colour image every restore() writes back."""
        self.prefill_screen = bytes([code]) * SCREEN_LEN
        self.prefill_colour = bytes([colour]) * SCREEN_LEN

    def restore(self):
        t = self.transport
        write_bytes(t, SCREEN, self.prefill_screen)
        write_bytes(t, COLOUR, self.prefill_colour)
        write_bytes(t, ZP_LO, self.zp)
        write_bytes(t, 0x0286, self.colour_reg)
        write_bytes(t, 0x0291, self.lock)
        write_bytes(t, 0xD016, self.d016)
        write_bytes(t, 0xD018, self.d018)
        write_bytes(t, 0xD020, self.d020_24)


# ============================================================================
# Diffing
# ============================================================================

ZP_NAMES = {
    0xC7: "reverse flag $C7", 0xCC: "cursor enable $CC",
    0xD0: "input-from-screen $D0", 0xD1: "cursor line ptr $D1",
    0xD2: "cursor line ptr $D2", 0xD3: "cursor column $D3",
    0xD4: "quote mode $D4", 0xD5: "line length $D5",
    0xD6: "cursor row $D6", 0xD8: "insert count $D8",
    0xF3: "colour line ptr $F3", 0xF4: "colour line ptr $F4",
}


def describe_zp_diff(a, b):
    out = []
    for i, (x, y) in enumerate(zip(a["zp"], b["zp"])):
        if x != y:
            addr = ZP_LO + i
            name = ZP_NAMES.get(addr, f"line-link ${addr:02X}"
                                if 0xD9 <= addr <= 0xF2 else f"${addr:02X}")
            out.append(f"{name}: ${x:02X} -> ${y:02X}")
    return out


def describe_mem_diff(name, a, b, limit=6):
    diffs = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y]
    if not diffs:
        return []
    shown = ", ".join(
        f"{name}[{i}] (row {i // COLS} col {i % COLS}) ${x:02X}->${y:02X}"
        for i, x, y in diffs[:limit])
    return [f"{len(diffs)} of {len(a)} {name} cells differ: {shown}"
            + (" ..." if len(diffs) > limit else "")]


VIC_NAMES = ["$D011", "$D016", "$D018", "$D020 border", "$D021 background",
             "$D022", "$D023", "$D024"]


def describe_vic_diff(a, b):
    return [f"VIC {VIC_NAMES[i]}: ${x:02X} -> ${y:02X}"
            for i, (x, y) in enumerate(zip(a["vic"], b["vic"])) if x != y]


def describe(a, b):
    """Full ordered diff between the expected-render and dangerous states."""
    out = []
    out += describe_vic_diff(a, b)
    if a["page"][0] != b["page"][0]:
        out.append(f"text colour $0286: ${a['page'][0]:02X} -> "
                   f"${b['page'][0]:02X}")
    if a["page"][1] != b["page"][1]:
        out.append(f"screen page $0288: ${a['page'][1]:02X} -> "
                   f"${b['page'][1]:02X}")
    if a["lock"] != b["lock"]:
        out.append(f"shift lock $0291: ${a['lock'][0]:02X} -> "
                   f"${b['lock'][0]:02X}")
    out += describe_zp_diff(a, b)
    out += describe_mem_diff("screen", a["screen"], b["screen"])
    out += describe_mem_diff("colour", a["colour"], b["colour"])
    return out


def screen_text(codes):
    out = []
    for b in codes:
        c = b & 0x7F
        if c == 32:
            out.append(" ")
        elif 1 <= c <= 26:
            out.append(chr(c + 64))
        elif 33 <= c <= 63:
            out.append(chr(c))
        else:
            out.append(".")
    return "".join(out)


# ============================================================================
# The test
# ============================================================================

def run_trials(transport, labels, rng, trials, selfcheck):
    passed = failed = 0

    port = 9999
    recv_key = bytes(rng.randrange(256) for _ in range(32))
    receiver_idx = bytes(rng.randrange(256) for _ in range(4))

    write_bytes(transport, labels["msg_port"],
                bytes([(port >> 8) & 0xFF, port & 0xFF]))
    write_bytes(transport, labels["hs_transport_recv"], recv_key)
    write_bytes(transport, labels["tp_peer_recv_idx"], receiver_idx)
    write_bytes(transport, labels["wg_state"], bytes([2]))       # ACTIVE

    counter = [0]

    def deliver(inner):
        counter[0] += 1
        c = counter[0]
        nonce = b'\x00' * 4 + struct.pack('<Q', c)
        ct_tag = ChaCha20Poly1305(recv_key).encrypt(nonce, inner, None)
        pkt = (struct.pack('<I', 4) + receiver_idx
               + struct.pack('<Q', c) + ct_tag)
        write_bytes(transport, labels["udp_recv_buf"], pkt)
        write_bytes(transport, labels["udp_recv_len"],
                    struct.pack('<H', len(pkt)))
        write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
        jsr(transport, labels["session_handle_packet"], timeout=180.0)

    def reset_replay():
        write_bytes(transport, labels["tp_recv_counter"], bytes(8))
        if "rw_counter_max" in labels:
            write_bytes(transport, labels["rw_counter_max"], bytes(8))
        if "rw_bitmap" in labels:
            write_bytes(transport, labels["rw_bitmap"], bytes(256))
        counter[0] = 0

    reset_replay()

    normalise_cursor(transport)
    plot_cursor(transport, PLOT_ROW, PLOT_COL)

    # Captured ONCE, with the cursor parked well clear of the bottom of the
    # screen: every delivery below starts from this exact image, so the two
    # halves of a trial cannot drift apart (and nothing ever scrolls).
    state = DisplayState(transport)

    for trial in range(1, trials + 1):
        prefill_code = rng.choice(PREFILL_CODES)
        prefill_colour = rng.randrange(1, 16)
        state.set_prefill(prefill_code, prefill_colour)

        dangerous, expected, codes = make_payload(rng)
        if selfcheck:
            # Deliberate one-byte corruption of the reference render. On a
            # fixed tree this MUST turn the trial red; that is the proof the
            # comparison is sensitive rather than vacuous.
            i = rng.randrange(len(expected) - len(MARKER))
            expected = (expected[:i]
                        + bytes([FILLER[(expected[i] + 1) % len(FILLER)]])
                        + expected[i + 1:])

        code_desc = ", ".join(f"${c:02X}@{p}" for p, c in codes)

        state.restore()
        deliver(inner_udp(port, expected))
        ref = capture(transport)

        state.restore()
        deliver(inner_udp(port, dangerous))
        got = capture(transport)

        # --- liveness: the print path actually ran -------------------------
        # Without this the whole trial could pass by both deliveries being
        # rejected identically before reaching @t4_udp.
        recv_len = int.from_bytes(
            read_bytes(transport, labels["msg_recv_len"], 2), 'little')
        text = screen_text(ref["screen"])
        if recv_len == len(expected) and MARKER.decode() in text:
            passed += 1
            if VERBOSE:
                print(f"  PASS [trial {trial}] reference render reached "
                      f"@t4_udp (msg_recv_len={recv_len}, marker on screen)")
        else:
            failed += 1
            print(f"  FAIL [trial {trial}] the reference delivery never "
                  f"reached the display path: msg_recv_len={recv_len} "
                  f"(expected {len(expected)}), marker on screen="
                  f"{MARKER.decode() in text} — the state comparison below "
                  f"is not meaningful")

        # --- the oracle ----------------------------------------------------
        diffs = describe(ref, got)
        if not diffs:
            passed += 1
            if VERBOSE:
                print(f"  PASS [trial {trial}] {len(dangerous)}B payload with "
                      f"control codes {code_desc} left the display state "
                      f"identical to its filtered render")
        else:
            failed += 1
            print(f"  FAIL [trial {trial}] a peer's control codes "
                  f"[{code_desc}] in a {len(dangerous)}B message CHANGED the "
                  f"display state; a filtered render of the same message "
                  f"must be indistinguishable. {len(diffs)} difference(s):")
            for d in diffs[:10]:
                print(f"         - {d}")
            if len(diffs) > 10:
                print(f"         - ... and {len(diffs) - 10} more")

        # --- named consequences, so a red run says WHAT the peer did -------
        checks = [
            ("screen RAM does not match the filtered render",
             sum(1 for a, b in zip(ref["screen"], got["screen"]) if a != b)
             <= 0),
            ("the text colour $0286 was changed by the peer",
             ref["page"][0] == got["page"][0]),
            ("the character set / VIC $D018 was switched by the peer",
             ref["vic"][2] == got["vic"][2]),
            ("the border/background $D020/$D021 were changed by the peer",
             ref["vic"][3:5] == got["vic"][3:5]),
            ("reverse video $C7 was turned on by the peer",
             ref["zp"][0xC7 - ZP_LO] == got["zp"][0xC7 - ZP_LO]),
            ("the cursor was moved by the peer",
             ref["zp"][0xD1 - ZP_LO:0xD3 - ZP_LO + 1]
             == got["zp"][0xD1 - ZP_LO:0xD3 - ZP_LO + 1]
             and ref["zp"][0xD6 - ZP_LO] == got["zp"][0xD6 - ZP_LO]),
        ]
        for what, ok in checks:
            if ok:
                passed += 1
            else:
                failed += 1
                print(f"  FAIL [trial {trial}] {what}")

        # A clear-screen is worth calling by name: it is the loudest of the
        # bunch and the easiest to read off the two captures.
        ref_marks = ref["screen"].count(prefill_code)
        got_marks = got["screen"].count(prefill_code)
        if got_marks >= ref_marks:
            passed += 1
            if VERBOSE:
                print(f"  PASS [trial {trial}] untouched screen preserved "
                      f"({got_marks} prefill cells, reference {ref_marks})")
        else:
            failed += 1
            print(f"  FAIL [trial {trial}] the peer blanked the screen: "
                  f"{ref_marks} prefill cells survived the filtered render "
                  f"but only {got_marks} survived the raw one "
                  f"({ref_marks - got_marks} cells lost)")

    return passed, failed


def main():
    global VERBOSE

    seed = None
    trials = 4
    selfcheck = bool(os.environ.get("TEST_129_SELFCHECK"))
    if os.environ.get("TEST_SEED"):
        seed = int(os.environ["TEST_SEED"])

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1]); i += 2
        elif args[i] == "--trials" and i + 1 < len(args):
            trials = int(args[i + 1]); i += 2
        elif args[i] == "--verbose":
            VERBOSE = True; i += 1
        elif args[i] == "--selfcheck":
            selfcheck = True; i += 1
        else:
            i += 1

    if seed is None:
        seed = random.randrange(2 ** 32)
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    if selfcheck:
        print("SELF-CHECK MODE: the reference render is corrupted by one "
              "byte; a correct tree MUST report this run as FAILED.")

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    with open(PRG_PATH, "rb") as f:
        prg = f.read()
    print(f"PRG: {PRG_PATH} {len(prg)} bytes "
          f"sha256={hashlib.sha256(prg).hexdigest()[:16]}")

    labels = Labels.from_file(LABELS_PATH)
    required = [
        "session_handle_packet", "udp_tunnel_parse", "display_payload",
        "wg_state", "udp_recv_buf", "udp_recv_len", "udp_recv_ready",
        "hs_transport_recv", "tp_peer_recv_idx", "tp_recv_counter",
        "msg_port", "msg_recv_len", "boot_ready",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if binary_wait_for_boot_ready(transport, labels, timeout=180.0) is None:
            print("FATAL: boot_ready never set")
            sys.exit(1)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        if read_bytes(transport, 0x0288, 1)[0] != 0x04:
            print("FATAL: screen is not at $0400; this suite assumes it")
            sys.exit(1)

        print(f"VICE ready, running {trials} trials...")
        passed, failed = run_trials(transport, labels, rng, trials, selfcheck)
        mgr.release(inst)

    total = passed + failed
    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'=' * 60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
