#!/usr/bin/env python3
"""test_multipart_chunk_split.py — the chunked ($16) send path really SPLITS,
and the split reassembles to exactly one datagram, in VICE.

WHAT IS ALREADY COVERED ELSEWHERE, AND WHY THAT IS NOT THIS.
tools/test_chunked_send_boundary.py stubs net_udp_send AT ITS LABEL, so it
proves transport_send's 1440/1441 MTU gate and never enters the part loop —
under that stub a 1472-byte datagram and a 60-byte one look identical.
tools/test_mtu.py drives transport_encrypt/decrypt at 16-bit lengths and
stops above net_udp_send. tools/test_uci_udp_echo_live.py needs hardware.
So until this file, NOTHING anywhere ran src/net/uci/net.s's `@part_loop`
or uci_send_part's clamp: the 2026-09-03 Cloudflare WARP interop run sent
nothing above 148 bytes, which is one part, so the $16 opcode was exercised
and its REASSEMBLY was not.

WHAT VICE CAN AND CANNOT SEE. VICE has no UCI: $DF1D is open bus and $DF1C
reads $FF, so nothing the adapter pushes reaches a firmware and there is no
wire to tap. What VICE *can* see is the adapter's own command stream, which
is where the split lives. Every $16 part header goes out through
uci_put_byte, so stubbing the UCI PRIMITIVES (uci_wait_idle, uci_begin_cmd,
uci_put_byte, uci_push_wait, uci_check_err, uci_read_resp_bytes,
uci_drain_resp, uci_drain_status, uci_ack) — and NOT net_udp_send or
uci_send_part, which are the code under test — leaves the real 16-bit clamp,
the real offset advance and the real byte-push loop running, with their
output captured in C64 RAM. From that we read, per part:

    $16, socket_id, off_lo, off_hi, total_lo, total_hi

which is the whole claim: how many parts, at what offsets, announcing what
total. "One datagram on the wire" is exactly "every part announces the same
total and the offsets tile [0, total) once"; the firmware emits on the part
that completes the announced total.

Byte-exactness needs the payload too. The push loop's sink is a single
`STA UCI_CMD_DATA`, and this suite finds it WITHOUT pattern-matching the
PRG: it snapshots UCI_CODE, runs one send, and diffs — the only bytes that
move are the self-modified source operand of `LDA $ffff,y`, which locates
the store three bytes later. The located bytes are then VERIFIED to be
`8D 1D DF` before anything is patched; if they are not, that is a hard FAIL,
not a skip. Only then is the 3-byte sink replaced with a 3-byte JSR to a
capture routine. The clamp, the offsets, the counters and the announced
totals all remain the DUT's.

Hardware-only, NOT tested here: that the firmware's $16 handler actually
concatenates the parts, that the datagram leaves the NIC once, and that a
peer authenticates it. `tools/test_warp_live.py --multipart N` is that test.

Build-tree mutator: needs `make BACKEND=uci UCI_CHUNKED_WRITE=1`, so it is
registered in tools/run_regression.py under SERIAL_TESTS and restores the
default build on exit.

Usage:
    python3 tools/test_multipart_chunk_split.py [--seed S] [--verbose]

Env:
    C64_SKIP_BUILD=1   use the tree as found (must be a chunked uci build)
    TEST_SEED=N        same as --seed
"""

from __future__ import annotations

import os
import random
import string
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
sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools"))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# --- values this suite refuses to take on trust -----------------------------
# Every one of these is re-derived from the BUILT tree (labels.txt, the
# linker map, or the DUT's own behaviour) and checked against these
# expectations, so a build that moves one fails loudly instead of silently
# retargeting the test.
EXPECT_PART_MAX = 888             # 895-byte command buffer - 7-byte $16 header
EXPECT_MTU = 1440
EXPECT_SEND_MAX = 1472
EXPECT_OVERHEAD = 32              # Type-4 header (16) + Poly1305 tag (16)
IP_UDP_HDR_LEN = 28               # inner IPv4 (20) + UDP (8)
UCI_CMD_SOCKET_WRITE_CHUNK = 0x16
UCI_CMD_DATA = 0xDF1D
STA_ABS = 0x8D                    # STA $nnnn
LDA_ABS_Y = 0xB9                  # LDA $nnnn,Y

# --- C64 scratch ------------------------------------------------------------
# $C000-$CFFF is free RAM in this build (the linker map ends at $9E8C) and
# this suite uses none of the harness's uci_* code builders, so its
# $C000-$C87D block is not in play.
CAPBUF = 0xC000                   # captured payload bytes (up to 1472)
STUBS = 0xC600                    # stub bodies, jumped to from the real labels
HDRBUF = 0xC700                   # captured uci_put_byte stream
HDRBUF_LEN = 0x80
YSAVE = 0xC780
TRAMP_SEND = 0xC7A0               # LDA/LDX ptr; JSR net_udp_send; capture C
TRAMP_MSG = 0xC7C0                # do_message_input's tail: build + send
CARRY = 0xC7F0

VERBOSE = False
results: list[tuple[bool, str]] = []


def check(ok, label, detail=""):
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail and (not ok or VERBOSE) else ""))
    return bool(ok)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build():
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set -- using the tree as found")
        return False
    print("Building: make clean && make BACKEND=uci UCI_CHUNKED_WRITE=1")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", "BACKEND=uci", "UCI_CHUNKED_WRITE=1"],
                       capture_output=True, text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(f"Build failed:\n{r.stdout}\n{r.stderr}")
        sys.exit(1)
    return True


def restore_default_tree():
    print("Restoring the default build tree: make clean && make")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make"], capture_output=True, text=True,
                       cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(f"WARNING: default rebuild failed:\n{r.stderr}")


def uci_code_span():
    """(start, end_exclusive) of the UCI_CODE segment, from the linker map.

    The map is a build artefact, not a constant: a segment that moves moves
    the snapshot window with it.
    """
    path = os.path.join(PROJECT_ROOT, "build", "wireguard.map")
    in_segments = False
    with open(path) as f:
        for line in f:
            if line.startswith("Segment list:"):
                in_segments = True
                continue
            if in_segments and line.startswith("Modules list:"):
                break
            parts = line.split()
            if in_segments and len(parts) == 5 and parts[0] == "UCI_CODE":
                return int(parts[1], 16), int(parts[2], 16) + 1
    raise RuntimeError(f"UCI_CODE not found in the segment list of {path}")


# ---------------------------------------------------------------------------
# 6502 stubs
# ---------------------------------------------------------------------------
def lo(a):
    return a & 0xFF


def hi(a):
    return (a >> 8) & 0xFF


def _capture_stub(base, buf):
    """STA buf,advancing; RTS. Preserves A, X, Y and the carry."""
    return bytes([
        STA_ABS, lo(buf), hi(buf),           # +0 STA buf      (SMC operand)
        0xEE, lo(base + 1), hi(base + 1),    # +3 INC +1
        0xD0, 0x03,                          # +6 BNE +3
        0xEE, lo(base + 2), hi(base + 2),    # +8 INC +2
        0x60,                                # +11 RTS
    ])


def _read_resp_stub(base, L):
    """uci_read_resp_bytes replacement: store net_udp_send_len (the announced
    total) at (uci_resp_dst) and report uci_resp_count = 2.

    Faithful to what the firmware answers on a completing part, so the DUT's
    own written-count comparison is exercised rather than bypassed.
    """
    dst = L["uci_resp_dst"]
    ln = L["net_udp_send_len"]
    cnt = L["uci_resp_count"]
    s1 = base + 24                            # operand of the first STA abs,Y
    s2 = base + 31                            # operand of the second
    return bytes([
        0xAD, lo(dst), hi(dst),               # +0  LDA uci_resp_dst
        0x8D, lo(s1), hi(s1),                 # +3  STA s1
        0x8D, lo(s2), hi(s2),                 # +6  STA s2
        0xAD, lo(dst + 1), hi(dst + 1),       # +9  LDA uci_resp_dst+1
        0x8D, lo(s1 + 1), hi(s1 + 1),         # +12 STA s1+1
        0x8D, lo(s2 + 1), hi(s2 + 1),         # +15 STA s2+1
        0xA0, 0x00,                           # +18 LDY #0
        0xAD, lo(ln), hi(ln),                 # +20 LDA net_udp_send_len
        0x99, 0xFF, 0xFF,                     # +23 STA $ffff,Y   (SMC)
        0xC8,                                 # +26 INY
        0xAD, lo(ln + 1), hi(ln + 1),         # +27 LDA net_udp_send_len+1
        0x99, 0xFF, 0xFF,                     # +30 STA $ffff,Y   (SMC)
        0xA9, 0x02,                           # +33 LDA #2
        0x8D, lo(cnt), hi(cnt),               # +35 STA uci_resp_count
        0x60,                                 # +38 RTS
    ])


def install_stubs(transport, L):
    """Write the stub bodies, then JMP each real UCI primitive at them.

    Returns the address of the uci_put_byte capture stub (its SMC operand is
    the header-capture write pointer).
    """
    at = STUBS
    blobs = {}

    def place(name, body):
        nonlocal at
        blobs[name] = at
        write_bytes(transport, at, body)
        at += len(body) + 1

    place("put_byte", _capture_stub(at, HDRBUF))
    place("payload", _capture_stub(at, CAPBUF))
    place("read_resp", _read_resp_stub(at, L))
    place("clc_rts", bytes([0x18, 0x60]))
    place("rts", bytes([0x60]))
    place("drain_status", bytes([                    # uci_status_seen = 0
        0xA9, 0x00,
        0x8D, lo(L["uci_status_seen"]), hi(L["uci_status_seen"]),
        0x18, 0x60,
    ]))

    wiring = {
        "uci_wait_idle": "clc_rts",
        "uci_begin_cmd": "rts",
        "uci_put_byte": "put_byte",
        "uci_push_wait": "clc_rts",
        "uci_check_err": "clc_rts",
        "uci_read_resp_bytes": "read_resp",
        "uci_drain_resp": "clc_rts",
        "uci_drain_status": "drain_status",
        "uci_ack": "rts",
    }
    for label, blob in wiring.items():
        tgt = blobs[blob]
        write_bytes(transport, L[label], bytes([0x4C, lo(tgt), hi(tgt)]))
    return blobs


def reset_hdr_capture(transport, put_byte_stub):
    write_bytes(transport, put_byte_stub + 1,
                bytes([lo(HDRBUF), hi(HDRBUF)]))
    write_bytes(transport, HDRBUF, bytes(HDRBUF_LEN))


def read_hdr_capture(transport, put_byte_stub):
    ptr = int.from_bytes(read_bytes(transport, put_byte_stub + 1, 2), "little")
    n = ptr - HDRBUF
    if n <= 0 or n > HDRBUF_LEN:
        return n, b""
    return n, bytes(read_bytes(transport, HDRBUF, n))


def parse_parts(raw):
    """Split a captured uci_put_byte stream into 6-byte $16 part headers.

    Returns (list of dicts, leftover byte count). Structural: it does not
    assume how many parts there were, it reads them out.
    """
    parts = []
    for i in range(0, len(raw) - len(raw) % 6, 6):
        f = raw[i:i + 6]
        parts.append({
            "cmd": f[0],
            "socket": f[1],
            "offset": f[2] | (f[3] << 8),
            "total": f[4] | (f[5] << 8),
        })
    return parts, len(raw) % 6


# ---------------------------------------------------------------------------
# Trampolines
# ---------------------------------------------------------------------------
def install_trampolines(transport, L):
    nus = L["net_udp_send"]
    write_bytes(transport, TRAMP_SEND, bytes([
        0xA9, 0x00, 0xA2, 0x00,              # LDA #<buf / LDX #>buf (patched)
        0x20, lo(nus), hi(nus),              # JSR net_udp_send
        0x08, 0x68, 0x29, 0x01,              # PHP PLA AND #1
        0x8D, lo(CARRY), hi(CARRY),          # STA CARRY
        0x60,
    ]))
    utb = L["udp_tunnel_build"]
    ts = L["transport_send"]
    ipb = L["ip_packet_buf"]
    ipl = L["ip_pkt_len"]
    tpp = L["tp_payload_ptr"]
    tpl = L["tp_payload_len"]
    write_bytes(transport, TRAMP_MSG, bytes([
        0x20, lo(utb), hi(utb),              # JSR udp_tunnel_build
        0xA9, lo(ipb),                       # LDA #<ip_packet_buf
        0x8D, lo(tpp), hi(tpp),              # STA tp_payload_ptr
        0xA9, hi(ipb),                       # LDA #>ip_packet_buf
        0x8D, lo(tpp + 1), hi(tpp + 1),      # STA tp_payload_ptr+1
        0xAD, lo(ipl), hi(ipl),              # LDA ip_pkt_len
        0x8D, lo(tpl), hi(tpl),              # STA tp_payload_len
        0xAD, lo(ipl + 1), hi(ipl + 1),      # LDA ip_pkt_len+1
        0x8D, lo(tpl + 1), hi(tpl + 1),      # STA tp_payload_len+1
        0x20, lo(ts), hi(ts),                # JSR transport_send
        0x08, 0x68, 0x29, 0x01,              # PHP PLA AND #1
        0x8D, lo(CARRY), hi(CARRY),          # STA CARRY
        0x60,
    ]))


def call_net_udp_send(transport, L, put_byte_stub, buf, length):
    write_bytes(transport, TRAMP_SEND + 1, bytes([lo(buf)]))
    write_bytes(transport, TRAMP_SEND + 3, bytes([hi(buf)]))
    write_bytes(transport, L["net_udp_send_len"],
                struct.pack("<H", length))
    write_bytes(transport, L["uci_socket_open"], bytes([1]))
    write_bytes(transport, L["net_last_error"], bytes([0]))
    write_bytes(transport, CARRY, bytes([0xEE]))
    reset_hdr_capture(transport, put_byte_stub)
    jsr(transport, TRAMP_SEND, timeout=600.0)
    carry = read_bytes(transport, CARRY, 1)[0]
    err = read_bytes(transport, L["net_last_error"], 1)[0]
    n, raw = read_hdr_capture(transport, put_byte_stub)
    return carry, err, raw


def expected_parts(total, part_max):
    return -(-total // part_max)


def describe(parts):
    return ", ".join(f"off={p['offset']} total={p['total']}" for p in parts)


# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------
def group_splitting(transport, L, put_byte_stub, rng, part_max):
    """The part loop, driven straight at net_udp_send with a random datagram
    of a chosen length. Length is chosen at the DATAGRAM level here — this is
    where the 888 cap actually bites."""
    print("\n=== the $16 part loop splits at the command-buffer cap ===")
    buf = L["udp_recv_buf"]
    socket_id = rng.randint(1, 250)
    write_bytes(transport, L["uci_socket_id"], bytes([socket_id]))

    for total in (60, part_max - 1, part_max, part_max + 1,
                  EXPECT_SEND_MAX - 1, EXPECT_SEND_MAX):
        want = expected_parts(total, part_max)
        payload = bytes(rng.randrange(256) for _ in range(total))
        write_bytes(transport, buf, payload)
        carry, err, raw = call_net_udp_send(transport, L, put_byte_stub,
                                            buf, total)
        parts, leftover = parse_parts(raw)
        print(f"\n--- {total}-byte datagram (expect {want} part"
              f"{'' if want == 1 else 's'}) ---")
        check(carry == 0, f"{total} B: net_udp_send returns C=0",
              f"carry={carry} net_last_error=${err:02X}")
        check(leftover == 0,
              f"{total} B: command stream is a whole number of $16 headers",
              f"{len(raw)} captured bytes, {leftover} left over")
        # DIAGNOSTIC, not independent evidence: the offset-tiling check
        # below encodes the part count, so this can only ever agree with it.
        # Kept for failure-message quality ("got 1: off=0 total=889" reads
        # better than a list mismatch) — do not count it when judging how
        # much of the split is actually covered.
        check(len(parts) == want,
              f"{total} B: exactly {want} part(s) issued",
              f"got {len(parts)}: {describe(parts)}")
        check(all(p["cmd"] == UCI_CMD_SOCKET_WRITE_CHUNK for p in parts),
              f"{total} B: every part carries opcode $16",
              f"opcodes {[hex(p['cmd']) for p in parts]}")
        # Weakly independent: this can only fail if `lda uci_socket_id`
        # broke, which the single-part case would catch too. Its one real
        # contribution is that EVERY part names the same socket — a part
        # that lost the binding mid-datagram is invisible to the payload
        # capture, which never sees the header stream.
        check(all(p["socket"] == socket_id for p in parts),
              f"{total} B: every part names socket {socket_id}",
              f"sockets {[p['socket'] for p in parts]}")
        check(all(p["total"] == total for p in parts),
              f"{total} B: every part announces the SAME total {total} "
              f"(this is what makes it ONE datagram)",
              f"totals {[p['total'] for p in parts]}")
        want_offsets = [i * part_max for i in range(want)]
        check([p["offset"] for p in parts] == want_offsets,
              f"{total} B: offsets tile [0,{total}) once: {want_offsets}",
              f"got {[p['offset'] for p in parts]}")
        lengths = [(parts[i + 1]["offset"] if i + 1 < len(parts) else total)
                   - parts[i]["offset"] for i in range(len(parts))]
        check(all(0 < n <= part_max for n in lengths) and sum(lengths) == total,
              f"{total} B: part lengths {lengths} are <= {part_max} and sum "
              f"to {total}")


def locate_push_store(transport, before, after, span):
    """Find the push loop's `STA UCI_CMD_DATA` from the SMC footprint.

    The only self-modification inside uci_send_part is the source operand of
    `LDA $ffff,y`, patched to net_udp_send_ptr + offset before each part. So
    the bytes that CHANGED across a send locate it; the store is the next
    instruction. Returns (store_addr, diagnostics).
    """
    start = span[0]
    moved = [start + i for i in range(len(before)) if before[i] != after[i]]
    if len(moved) != 2 or moved[1] != moved[0] + 1:
        return None, (f"expected exactly one 2-byte SMC operand to move in "
                      f"UCI_CODE, got {len(moved)} changed byte(s) at "
                      f"{[hex(a) for a in moved][:8]}")
    opnd = moved[0]
    if after[opnd - 1 - start] != LDA_ABS_Y:
        return None, (f"byte before the moved operand is "
                      f"${after[opnd - 1 - start]:02X}, not ${LDA_ABS_Y:02X} "
                      f"(LDA abs,Y) — this is not the push loop's source")
    store = opnd + 2
    got = bytes(after[store - start:store - start + 3])
    want = bytes([STA_ABS, lo(UCI_CMD_DATA), hi(UCI_CMD_DATA)])
    if got != want:
        return None, (f"instruction after `LDA $nnnn,Y` at ${store:04X} is "
                      f"{got.hex()}, not {want.hex()} (STA ${UCI_CMD_DATA:04X})")
    return store, f"push sink at ${store:04X}, source operand at ${opnd:04X}"


def group_bytes(transport, L, put_byte_stub, rng, part_max, store, capture):
    """With the sink redirected to a capture routine: the bytes the parts
    push, concatenated, ARE the datagram — no gap, no overlap, no reorder.

    Only the 3-byte sink is replaced (`STA $DF1D` -> `JSR capture`, same
    width). The clamp, the offsets, the 16-bit countdown and the announced
    totals are all still the adapter's own code.
    """
    print("\n=== the parts concatenate to the datagram, byte for byte ===")
    buf = L["udp_recv_buf"]
    write_bytes(transport, store,
                bytes([0x20, lo(capture), hi(capture)]))
    for total in (part_max + 1, EXPECT_SEND_MAX):
        payload = bytes(rng.randrange(256) for _ in range(total))
        write_bytes(transport, buf, payload)
        write_bytes(transport, capture + 1, bytes([lo(CAPBUF), hi(CAPBUF)]))
        write_bytes(transport, CAPBUF, bytes(total))
        carry, err, raw = call_net_udp_send(transport, L, put_byte_stub,
                                            buf, total)
        parts, _ = parse_parts(raw)
        end = int.from_bytes(read_bytes(transport, capture + 1, 2), "little")
        pushed = end - CAPBUF
        got = bytes(read_bytes(transport, CAPBUF, total)) if 0 < pushed else b""
        print(f"\n--- {total}-byte datagram, {len(parts)} parts ---")
        check(carry == 0, f"{total} B: C=0", f"net_last_error=${err:02X}")
        check(pushed == total,
              f"{total} B: exactly {total} payload bytes pushed across all "
              f"parts", f"pushed {pushed}")
        diff = next((i for i in range(min(len(got), len(payload)))
                     if got[i] != payload[i]), None)
        check(got == payload,
              f"{total} B: the pushed bytes are the datagram, byte-exact",
              f"first difference at byte {diff}" if diff is not None
              else f"lengths {len(got)} vs {len(payload)}")


def stage_and_send_message(transport, L, put_byte_stub, text):
    """do_message_input's tail: stage text at ip_packet_buf+28, then
    udp_tunnel_build + transport_send, exactly as boot.s does it.

    The declared length is len(text) even when that is more than the buffer
    holds — that is the case the DUT's clamp exists for — but only what fits
    is written, so the host never scribbles past ip_packet_buf.
    """
    ipb = L["ip_packet_buf"]
    room = (L["ip_pkt_len"] - ipb) - IP_UDP_HDR_LEN
    staged = text[:room]
    for i in range(0, len(staged), 256):
        write_bytes(transport, ipb + IP_UDP_HDR_LEN + i, staged[i:i + 256])
    write_bytes(transport, L["zp_ptr1"],
                struct.pack("<H", ipb + IP_UDP_HDR_LEN))
    write_bytes(transport, L["zp_tmp1"], struct.pack("<H", len(text)))
    write_bytes(transport, L["uci_socket_open"], bytes([1]))
    write_bytes(transport, L["net_last_error"], bytes([0]))
    write_bytes(transport, CARRY, bytes([0xEE]))
    reset_hdr_capture(transport, put_byte_stub)
    jsr(transport, TRAMP_MSG, timeout=600.0)
    carry = read_bytes(transport, CARRY, 1)[0]
    err = read_bytes(transport, L["net_last_error"], 1)[0]
    ipl = int.from_bytes(read_bytes(transport, L["ip_pkt_len"], 2), "little")
    dgram = int.from_bytes(read_bytes(transport, L["tp_packet_len"], 2),
                           "little")
    n, raw = read_hdr_capture(transport, put_byte_stub)
    return carry, err, ipl, dgram, raw


def group_end_to_end(transport, L, put_byte_stub, rng, part_max, msg_text_max):
    """The whole staged-message path a `--multipart N` run takes: a padded
    DNS query of N bytes -> udp_tunnel_build -> transport_send -> parts."""
    print("\n=== a staged EDNS0-padded DNS query crosses the cap ===")
    import test_warp_live as w

    key = bytes(rng.randrange(256) for _ in range(32))
    recv_idx = bytes(rng.randrange(256) for _ in range(4))
    write_bytes(transport, L["hs_transport_send"], key)
    write_bytes(transport, L["tp_peer_recv_idx"], recv_idx)

    # The cap bites on the OUTER datagram, so the interesting inner lengths
    # are the ones that put the datagram at 888 and 889 — NOT N=888/889.
    split_n = part_max - IP_UDP_HDR_LEN - EXPECT_OVERHEAD
    for n, why in ((split_n, f"datagram exactly {part_max}: still ONE part"),
                   (split_n + 1, f"datagram {part_max + 1}: TWO parts"),
                   (msg_text_max, "the MSG_TEXT_MAX ceiling")):
        tok = "".join(rng.choice(string.ascii_lowercase) for _ in range(10))
        txn = rng.randrange(0x10000)
        question, wire = w.build_padded_dns_query(
            f"{tok}.cloudflare.com", w.DNS_QTYPE_TXT, txn, n)
        outer, want_parts = w.datagram_parts(n)
        counter = rng.randrange(0xFFFF)
        write_bytes(transport, L["tp_send_counter"], struct.pack("<Q", counter))

        print(f"\n--- inner {n} B -> datagram {outer} B ({why}) ---")
        check(len(wire) == n, f"builder produced exactly {n} bytes",
              f"got {len(wire)}")
        carry, err, ipl, dgram, raw = stage_and_send_message(
            transport, L, put_byte_stub, wire)
        parts, leftover = parse_parts(raw)
        check(carry == 0, f"inner {n}: transport_send C=0",
              f"carry={carry} net_last_error=${err:02X}")
        check(ipl == n + IP_UDP_HDR_LEN,
              f"inner {n}: udp_tunnel_build set ip_pkt_len = "
              f"{n + IP_UDP_HDR_LEN}", f"got {ipl}")
        check(dgram == outer,
              f"inner {n}: the datagram is {outer} B — datagram_parts()'s "
              f"arithmetic matches the C64's", f"tp_packet_len = {dgram}")
        check(len(parts) == want_parts and leftover == 0,
              f"inner {n}: {want_parts} part(s), as datagram_parts() says",
              f"got {len(parts)}: {describe(parts)}")
        check(all(p["total"] == outer for p in parts),
              f"inner {n}: all parts announce total {outer}",
              f"totals {[p['total'] for p in parts]}")
        # The datagram really carries OUR query: decrypt it and dig the DNS
        # message back out of the inner IP/UDP packet.
        pkt = bytes(read_bytes(transport, L["tp_packet"], dgram)) if dgram else b""
        plain = None
        detail = ""
        if len(pkt) == outer:
            nonce = b"\x00" * 4 + struct.pack("<Q", counter)
            try:
                plain = ChaCha20Poly1305(key).decrypt(nonce, pkt[16:], None)
            except Exception as exc:                              # noqa: BLE001
                detail = f"decrypt raised {type(exc).__name__}"
        check(plain is not None and plain[IP_UDP_HDR_LEN:] == wire,
              f"inner {n}: the datagram decrypts to our exact query bytes",
              detail or "plaintext tail differs from the staged query")
        check(plain is not None and plain[9] == 17
              and int.from_bytes(plain[2:4], "big") == n + IP_UDP_HDR_LEN,
              f"inner {n}: inner IPv4 header says UDP, total length "
              f"{n + IP_UDP_HDR_LEN}",
              (f"proto={plain[9]} totlen={int.from_bytes(plain[2:4],'big')}")
              if plain else "no plaintext")
        check(wire[:32] not in pkt,
              f"inner {n}: the query is NOT in the datagram in clear")

    # The ceiling itself: one byte more and the DUT clamps.
    tok = "".join(rng.choice(string.ascii_lowercase) for _ in range(10))
    _, wire = w.build_padded_dns_query(f"{tok}.cloudflare.com",
                                       w.DNS_QTYPE_TXT, rng.randrange(0x10000),
                                       msg_text_max + 1)
    print(f"\n--- inner {msg_text_max + 1} B: one over MSG_TEXT_MAX ---")
    carry, err, ipl, dgram, raw = stage_and_send_message(
        transport, L, put_byte_stub, wire)
    check(ipl == msg_text_max + IP_UDP_HDR_LEN,
          f"udp_tunnel_build CLAMPS {msg_text_max + 1} to MSG_TEXT_MAX "
          f"{msg_text_max} (ip_pkt_len {msg_text_max + IP_UDP_HDR_LEN})",
          f"ip_pkt_len = {ipl}; a build whose MSG_TEXT_MAX is not "
          f"{msg_text_max} would land elsewhere")


# ---------------------------------------------------------------------------
def _run(rng):
    labels = Labels.from_file(LABELS_PATH)
    L = dict(labels)
    required = [
        "net_udp_send", "net_udp_send_len", "net_udp_send_ptr", "net_last_error",
        "uci_send_part", "uci_socket_id", "uci_socket_open", "uci_wait_idle",
        "uci_begin_cmd", "uci_put_byte", "uci_push_wait", "uci_check_err",
        "uci_read_resp_bytes", "uci_drain_resp", "uci_drain_status", "uci_ack",
        "uci_status_seen", "uci_resp_dst", "uci_resp_count", "udp_recv_buf",
        "transport_send", "udp_tunnel_build", "tp_packet", "tp_packet_len",
        "tp_payload_ptr", "tp_payload_len", "tp_send_counter",
        "tp_peer_recv_idx", "hs_transport_send", "ip_packet_buf", "ip_pkt_len",
        "zp_ptr1", "zp_tmp1", "boot_ready",
    ]
    missing = [n for n in required if n not in L]
    if missing:
        print(f"FATAL: missing label(s): {missing}\n"
              f"       This suite needs `make BACKEND=uci UCI_CHUNKED_WRITE=1`; "
              f"uci_send_part exists only under that flag.")
        sys.exit(1)

    print("\n=== the tree under test ===")
    mtu = L.get("WG_MTU")
    send_max = L.get("NET_UDP_SEND_MAX")
    overhead = L.get("WG_DATA_OVERHEAD")
    msg_text_max = L["ip_pkt_len"] - L["ip_packet_buf"] - IP_UDP_HDR_LEN
    check(mtu == EXPECT_MTU, f"WG_MTU == {EXPECT_MTU}", f"labels say {mtu}")
    check(send_max == EXPECT_SEND_MAX,
          f"NET_UDP_SEND_MAX == {EXPECT_SEND_MAX}", f"labels say {send_max}")
    check(overhead == EXPECT_OVERHEAD,
          f"WG_DATA_OVERHEAD == {EXPECT_OVERHEAD}", f"labels say {overhead}")
    check(msg_text_max == (mtu or 0) - IP_UDP_HDR_LEN,
          f"MSG_TEXT_MAX == WG_MTU - {IP_UDP_HDR_LEN} == {msg_text_max} "
          f"(ip_pkt_len - ip_packet_buf - {IP_UDP_HDR_LEN})")
    span = uci_code_span()
    print(f"  UCI_CODE ${span[0]:04X}-${span[1] - 1:04X}, "
          f"MSG_TEXT_MAX={msg_text_max}")

    # The part cap is not exported; derive it from the DUT below and check it
    # against EXPECT_PART_MAX rather than assuming either way.
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if binary_wait_for_boot_ready(transport, labels, timeout=180.0) is None:
            print("FATAL: boot_ready never set")
            mgr.release(inst)
            sys.exit(1)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        blobs = install_stubs(transport, L)
        install_trampolines(transport, L)
        put_byte_stub = blobs["put_byte"]
        write_bytes(transport, L["uci_status_seen"], bytes([0]))

        # --- derive the part cap from the DUT, then pin it ------------------
        print("\n=== the part cap, measured from the adapter ===")
        buf = L["udp_recv_buf"]
        write_bytes(transport, buf, bytes(rng.randrange(256)
                                          for _ in range(EXPECT_SEND_MAX)))
        before = bytes(read_bytes(transport, span[0], span[1] - span[0]))
        _, _, raw = call_net_udp_send(transport, L, put_byte_stub, buf,
                                      EXPECT_SEND_MAX)
        after = bytes(read_bytes(transport, span[0], span[1] - span[0]))
        parts, _ = parse_parts(raw)
        measured = parts[1]["offset"] if len(parts) > 1 else None
        check(measured == EXPECT_PART_MAX,
              f"the adapter's first part is {EXPECT_PART_MAX} bytes "
              f"(895-byte command buffer - 7-byte $16 header)",
              f"second part starts at offset {measured} "
              f"({describe(parts)})")
        # Every group below drives its lengths from the PINNED cap, not from
        # `measured`: a suite that retargets itself at whatever the adapter
        # happens to do cannot fail when the adapter is wrong.
        part_max = EXPECT_PART_MAX

        store, why = locate_push_store(transport, before, after, span)
        check(store is not None,
              "the push loop's STA UCI_CMD_DATA located by its SMC footprint",
              why)

        group_splitting(transport, L, put_byte_stub, rng, part_max)
        if store is not None:
            group_bytes(transport, L, put_byte_stub, rng, part_max, store,
                        blobs["payload"])
            # Put the sink back before anything else runs.
            write_bytes(transport, store,
                        bytes([STA_ABS, lo(UCI_CMD_DATA), hi(UCI_CMD_DATA)]))
        group_end_to_end(transport, L, put_byte_stub, rng, part_max,
                         msg_text_max)
        mgr.release(inst)

    failed = [l for ok, l in results if not ok]
    print(f"\nResults: {len(results) - len(failed)}/{len(results)} passed, "
          f"{len(failed)} failed")
    for l in failed:
        print(f"  FAILED: {l}")
    return 1 if failed else 0


def main():
    global VERBOSE
    args = sys.argv[1:]
    seed = int(os.environ.get("TEST_SEED", random.randrange(2 ** 32)))
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        else:
            i += 1
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    os.chdir(PROJECT_ROOT)
    built = build()
    try:
        rc = _run(rng)
    finally:
        if built:
            restore_default_tree()
    sys.exit(rc)


if __name__ == "__main__":
    main()
