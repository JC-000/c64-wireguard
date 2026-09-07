#!/usr/bin/env python3
"""test_msg_port_default.py — the DEFAULT build's message port on the wire.

Issue #113. ``msg_port`` is stored big-endian: ``src/wg/ip_build.s`` copies
byte 0 into the wire-FIRST byte of the inner UDP src and dst ports
(``ip_packet_buf+20/+22``) and compares inbound the same way. The default
literal was ``.word $270f``, which ca65 emits low-byte-first as ``$0F $27``,
so the untouched build put ``$0F27`` = 3879 on the wire while README, the
Makefile knob and the source comment all said 9999.

WHY IT SURVIVED EVERY EXISTING TEST. ``tools/test_phase7.py``'s
``test_udp_build`` is thorough about this packet — but it OVERWRITES
``msg_port`` with a randomised big-endian port before every call, so it
proves the copy is faithful and can never see the default. Every other
suite that touches ``msg_port`` writes it first too, and the C64 uses the
same bytes for src port, dst port and the inbound filter, so the machine is
self-consistent whatever they say. The untested thing was the one thing
nobody wrote: the value the PRG ships with.

THE ORACLE IS THE DOCUMENTED NUMBER, NOT THE IMAGE. This suite deliberately
does NOT read ``msg_port`` and check the wire matches it — that is the
tautology the defect hid behind for two releases (a build storing 3879
passes such a check perfectly). It asserts the literal 9999, the port
README:88 promises and a peer would be configured for.

Three readings, checked independently:

  1. the STORED bytes, read from the running machine at ``msg_port``:
     must be $27 $0F, i.e. big-endian 9999;
  2. the WIRE bytes, read out of ``ip_packet_buf`` after calling
     ``udp_tunnel_build`` with ``msg_port`` UNTOUCHED: both the src port
     (bytes 20-21) and the dst port (bytes 22-23) must be 9999;
  3. the INBOUND filter: ``udp_tunnel_parse`` must ACCEPT a packet addressed
     to 9999 and REJECT one addressed to 3879 — the old wire port, which is
     the specific way a half-fix would show up. Both directions are checked,
     so the test cannot pass by rejecting everything.

Reading 2 is the one that matters (only the wire says what a peer sees), but
1 and 3 name the failure: 1 alone would be satisfied by a build whose copy
was then broken, and 3 alone by a filter that agrees with a wrong wire.

Randomisation (standing project rule): the payload text, its length, the
tunnel/target IPs, and the source port of the inbound packet in reading 3
are drawn from a seeded RNG, logged and replayable with --seed. The port
under test is fixed by construction — it is the constant being asserted.

Only meaningful for a build that did not override the port: with
``make MSG_PORT=<n>`` the expectation becomes <n> and is taken from the
environment, so the suite still runs rather than silently passing.

VICE-only: nothing here touches the network backend.

Usage:
    python3 tools/test_msg_port_default.py [--seed S] [--verbose]
"""

import hashlib
import os
import random
import struct
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# The documented default (README:88, Makefile MSG_PORT). NOT read from the
# build: see the docstring.
DOCUMENTED_PORT = 9999
# What the defect put on the wire instead ($270f byte-swapped). Used as the
# must-be-REJECTED port in reading 3, and named in the failure messages.
DEFECT_PORT = 3879

IP_HDR_LEN = 20
UDP_HDR_LEN = 8

_passed = 0
_failed = 0


def check(ok, what, detail=""):
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  PASS  {what}")
    else:
        _failed += 1
        print(f"  FAIL  {what}")
        if detail:
            print(f"          {detail}")
    return ok


def expected_port():
    """The port this build should carry: the default, or the MSG_PORT override."""
    env = os.environ.get("MSG_PORT")
    if env:
        return int(env), True
    return DOCUMENTED_PORT, False


def build_packet(transport, L, text, src_ip, dst_ip):
    """Call udp_tunnel_build WITHOUT touching msg_port; return the packet."""
    write_bytes(transport, L["tunnel_ip"], src_ip)
    write_bytes(transport, L["ping_target_ip"], dst_ip)
    write_bytes(transport, L["input_buffer"], text)
    write_bytes(transport, L["zp_ptr1"], struct.pack("<H", L["input_buffer"]))
    # 16-bit length in zp_tmp1/zp_tmp2 (§13.3); the high byte must be zeroed
    # or stale residue clamps the length to MSG_TEXT_MAX.
    write_bytes(transport, L["zp_tmp1"], struct.pack("<H", len(text)))
    jsr(transport, L["udp_tunnel_build"])
    total = IP_HDR_LEN + UDP_HDR_LEN + len(text)
    return bytes(read_bytes(transport, L["ip_packet_buf"], total))


def parse_accepts(transport, L, dst_port, src_port, payload):
    """Stage an inner packet at tp_packet+16 for udp_tunnel_parse; A == 0?"""
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 17                                   # protocol = UDP
    struct.pack_into(">H", ip, 2, 20 + 8 + len(payload))
    udp = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0)
    write_bytes(transport, L["tp_packet"] + 16, bytes(ip) + udp + payload)
    # Issue #97 bound: the parser refuses to hand out more than this packet
    # actually decrypted, so tp_payload_len must describe the staged bytes or
    # every packet is rejected and reading 3 would pass vacuously.
    write_bytes(transport, L["tp_payload_len"],
                struct.pack("<H", IP_HDR_LEN + UDP_HDR_LEN + len(payload)))
    regs = jsr(transport, L["udp_tunnel_parse"])
    return regs.get("A") == 0


def main():
    global _failed
    seed = None
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
    if seed is None:
        seed = random.randrange(2 ** 32)
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    port, overridden = expected_port()
    print(f"Expecting on-wire port {port}"
          + (" (from the MSG_PORT override)" if overridden
             else " (the documented default)"))

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        r = subprocess.run(["make"], capture_output=True, text=True,
                           cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            sys.exit(1)

    with open(PRG_PATH, "rb") as f:
        prg = f.read()
    print(f"PRG: {PRG_PATH} {len(prg)} bytes "
          f"sha256={hashlib.sha256(prg).hexdigest()[:16]}")

    labels = Labels.from_file(LABELS_PATH)
    required = ["msg_port", "udp_tunnel_build", "udp_tunnel_parse",
                "ip_packet_buf", "tp_packet", "tunnel_ip", "ping_target_ip",
                "input_buffer", "zp_ptr1", "zp_tmp1", "msg_recv_len",
                "tp_payload_len",
                "boot_ready"]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing label(s): {missing}")
        sys.exit(1)
    L = {n: labels.address(n) for n in required}

    want = struct.pack(">H", port)

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

        # --- 1. the stored bytes -------------------------------------------
        print("\n=== 1. msg_port as the PRG ships it ===")
        stored = bytes(read_bytes(transport, L["msg_port"], 2))
        check(stored == want,
              f"msg_port holds {want.hex()} = big-endian {port}",
              f"reads {stored.hex()} = {int.from_bytes(stored, 'big')} "
              f"big-endian / {int.from_bytes(stored, 'little')} little-endian"
              + (f" — this is issue #113: $270f emitted low-byte-first"
                 if stored == struct.pack("<H", DOCUMENTED_PORT) else ""))

        # --- 2. the wire, msg_port UNTOUCHED -------------------------------
        print("\n=== 2. the port udp_tunnel_build puts on the wire ===")
        for trial in range(3):
            text_len = rng.randint(1, 40)
            text = bytes(rng.randint(0x20, 0x7E) for _ in range(text_len))
            src_ip = bytes(rng.randint(1, 254) for _ in range(4))
            dst_ip = bytes(rng.randint(1, 254) for _ in range(4))
            pkt = build_packet(transport, L, text, src_ip, dst_ip)
            sport, dport = pkt[20:22], pkt[22:24]
            check(sport == want,
                  f"[{text_len} B] inner UDP src port == {port}",
                  f"wire carries {sport.hex()} = "
                  f"{int.from_bytes(sport, 'big')}")
            check(dport == want,
                  f"[{text_len} B] inner UDP dst port == {port}",
                  f"wire carries {dport.hex()} = "
                  f"{int.from_bytes(dport, 'big')}")
            # Guard against a vacuous pass: the packet must be the real one.
            check(pkt[28:28 + text_len] == text,
                  f"[{text_len} B] the packet checked is the one just built",
                  "payload mismatch — udp_tunnel_build did not run")

        # --- 3. the inbound filter -----------------------------------------
        print("\n=== 3. udp_tunnel_parse accepts the documented port ===")
        payload = bytes(rng.randint(0x20, 0x7E) for _ in range(rng.randint(1, 32)))
        good_src = rng.randint(1024, 65534)
        check(parse_accepts(transport, L, port, good_src, payload),
              f"a packet addressed to {port} is ACCEPTED")
        wrong = DEFECT_PORT if port != DEFECT_PORT else DOCUMENTED_PORT
        check(not parse_accepts(transport, L, wrong, good_src, payload),
              f"a packet addressed to {wrong} is REJECTED",
              f"the filter still matches the pre-#113 wire port {wrong}")

        mgr.release(inst)

    total = _passed + _failed
    print(f"\n{'=' * 60}")
    print(f"Results: {_passed}/{total} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)


if __name__ == "__main__":
    main()
