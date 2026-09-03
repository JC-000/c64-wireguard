#!/usr/bin/env python3
"""test_chunked_send_boundary.py — transport_send's MTU gate under
UCI_CHUNKED_WRITE=1 (issue #70), in VICE.

The flag build raises the datagram cap to 1472 (the firmware's chunked
SOCKET_WRITE, GideonZ/1541ultimate#807) and therefore WG_MTU to 1440. The
one piece of that which VICE can see is the 16-bit compare at the top of
transport_send (src/wg/transport.s): a payload of WG_MTU+1 must come back
C=1 BEFORE anything touches the network, and a payload of exactly WG_MTU
must be encrypted and handed to net_udp_send as one 1472-byte datagram.

VICE has no UCI, so net_udp_send is STUBBED at its label with a routine
that records A/X and counts calls, then RTS. That makes "before any net
call" a counted fact rather than an inference from the carry.

Build-tree mutator: it needs `make BACKEND=uci UCI_CHUNKED_WRITE=1`, so
tools/run_regression.py lists it under SERIAL_TESTS. With C64_SKIP_BUILD
it runs against whatever tree is there — and reports, as a failed check
rather than an exception, when that tree is not a flag build (the
chunk-path label absent, or WG_MTU still 860).

Usage:
    python3 tools/test_chunked_send_boundary.py [--seed S] [--verbose]
"""

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

CHUNK_PATH_LABEL = "uci_send_part"
EXPECT_MTU = 1440                 # 1472 - 32 (Type-4 header + Poly1305 tag)
WG_DATA_OVERHEAD = 32
T4_HDR_LEN = 16

# Scratch, all past jsr()'s own trampoline at $0334 and below screen RAM.
TRAMP = 0x0340        # JSR transport_send; PHP; PLA; AND #1; STA CARRY; RTS
CARRY = 0x0360
STUB_CALLS = 0x0361   # incremented by the net_udp_send stub
STUB_A = 0x0362       # A on entry to the stub (buffer lo)
STUB_X = 0x0363       # X on entry to the stub (buffer hi)

VERBOSE = False
results = []


def check(ok, label, detail=""):
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail and (not ok or VERBOSE) else ""))
    return ok


def build():
    if os.environ.get("C64_SKIP_BUILD"):
        print("C64_SKIP_BUILD set -- using the tree as found")
        return
    print("Building: make clean && make BACKEND=uci UCI_CHUNKED_WRITE=1")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make", "BACKEND=uci", "UCI_CHUNKED_WRITE=1"],
                       capture_output=True, text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(f"Build failed:\n{r.stdout}\n{r.stderr}")
        sys.exit(1)


def tree_mtu(labels):
    """WG_MTU of the tree: the exported equate when present, else the
    distance ip_packet_buf -> ip_pkt_len (data.s declares them adjacent,
    ip_packet_buf being `.res WG_MTU`)."""
    exported = labels.address("WG_MTU")
    if exported is not None:
        return exported, "WG_MTU label"
    return (labels["ip_pkt_len"] - labels["ip_packet_buf"],
            "ip_pkt_len - ip_packet_buf (WG_MTU not exported)")


def install_stub_and_trampoline(transport, labels):
    stub = bytes([
        0x8D, STUB_A & 0xFF, STUB_A >> 8,           # STA STUB_A
        0x8E, STUB_X & 0xFF, STUB_X >> 8,           # STX STUB_X
        0xEE, STUB_CALLS & 0xFF, STUB_CALLS >> 8,   # INC STUB_CALLS
        0x60,                                       # RTS
    ])
    write_bytes(transport, labels["net_udp_send"], stub)
    ts = labels["transport_send"]
    tramp = bytes([
        0x20, ts & 0xFF, ts >> 8,                   # JSR transport_send
        0x08, 0x68, 0x29, 0x01,                     # PHP PLA AND #1
        0x8D, CARRY & 0xFF, CARRY >> 8,             # STA CARRY
        0x60,                                       # RTS
    ])
    write_bytes(transport, TRAMP, tramp)


def call_transport_send(transport, labels, payload, key, recv_idx, counter):
    """Stage *payload* in udp_recv_buf (1500 B) and JSR transport_send.

    Returns (carry, stub_calls, stub_ax, tp_packet_len, net_udp_send_len,
    send_counter_after).
    """
    buf = labels["udp_recv_buf"]
    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], recv_idx)
    write_bytes(transport, labels["tp_send_counter"], struct.pack('<Q', counter))
    write_bytes(transport, buf, payload)
    write_bytes(transport, labels["tp_payload_ptr"], struct.pack('<H', buf))
    write_bytes(transport, labels["tp_payload_len"],
                struct.pack('<H', len(payload)))
    # Sentinels: anything the routine leaves untouched must still read them.
    write_bytes(transport, labels["tp_packet_len"], b'\xEE\xEE')
    write_bytes(transport, labels["net_udp_send_len"], b'\xDD\xDD')
    write_bytes(transport, CARRY, bytes(4))          # CARRY, CALLS, A, X

    jsr(transport, TRAMP, timeout=180.0)

    scratch = bytes(read_bytes(transport, CARRY, 4))
    tp_len = int.from_bytes(read_bytes(transport, labels["tp_packet_len"], 2),
                            'little')
    send_len = int.from_bytes(
        read_bytes(transport, labels["net_udp_send_len"], 2), 'little')
    ctr = int.from_bytes(read_bytes(transport, labels["tp_send_counter"], 8),
                         'little')
    return scratch[0], scratch[1], scratch[2] | (scratch[3] << 8), \
        tp_len, send_len, ctr


def run_tests(transport, labels, rng, mtu):
    key = bytes(rng.randint(0, 255) for _ in range(32))
    recv_idx = bytes(rng.randint(0, 255) for _ in range(4))

    print(f"\n--- {EXPECT_MTU + 1}-byte payload: refused before any net call ---")
    payload = bytes(rng.randint(0, 255) for _ in range(EXPECT_MTU + 1))
    counter = rng.randint(0, 0xFFFF)
    c, calls, ax, tp_len, send_len, ctr = call_transport_send(
        transport, labels, payload, key, recv_idx, counter)
    check(c == 1, f"{EXPECT_MTU + 1} bytes -> C=1",
          f"carry={c} (tree WG_MTU={mtu})")
    check(calls == 0, "net_udp_send NOT called",
          f"stub call count = {calls}")
    check(tp_len == 0xEEEE, "tp_packet_len untouched (no encrypt ran)",
          f"tp_packet_len = {tp_len}")
    check(ctr == counter, "send counter not consumed",
          f"tp_send_counter {counter} -> {ctr}")

    def accept_case(size, why):
        print(f"\n--- {size}-byte payload: accepted, one {size + WG_DATA_OVERHEAD}"
              f"-byte datagram ({why}) ---")
        payload = bytes(rng.randint(0, 255) for _ in range(size))
        counter = rng.randint(0, 0xFFFF)
        c, calls, ax, tp_len, send_len, ctr = call_transport_send(
            transport, labels, payload, key, recv_idx, counter)
        check(c == 0, f"{size} bytes -> C=0",
              f"carry={c}" if c == 0 else
              f"carry={c}: a {size}-byte payload is rejected — the tree's "
              f"WG_MTU is {mtu}, not {size}"
              + (" (UCI_CHUNKED_WRITE=1 not in effect)"
                 if size == EXPECT_MTU else ""))
        check(calls == 1, "net_udp_send called exactly once",
              f"stub call count = {calls}")
        expect_dgram = size + WG_DATA_OVERHEAD
        check(send_len == expect_dgram,
              f"net_udp_send_len == {expect_dgram}", f"got {send_len}")
        check(tp_len == expect_dgram, f"tp_packet_len == {expect_dgram}",
              f"got {tp_len}")
        check(ax == labels["tp_packet"], "net_udp_send got A/X = tp_packet",
              f"A/X = ${ax:04X}, tp_packet = ${labels['tp_packet']:04X}")
        check(ctr == counter + 1, "send counter advanced by one",
              f"{counter} -> {ctr}")
        if c == 0 and tp_len == expect_dgram:
            pkt = bytes(read_bytes(transport, labels["tp_packet"], tp_len))
            nonce = b'\x00' * 4 + struct.pack('<Q', counter)
            try:
                plain = ChaCha20Poly1305(key).decrypt(
                    nonce, pkt[T4_HDR_LEN:], None)
            except Exception as exc:                      # noqa: BLE001
                plain = None
                detail = f"decrypt raised {type(exc).__name__}"
            else:
                detail = "Python AEAD accepts the C64's ciphertext+tag"
            check(plain == payload and pkt[0] == 4 and pkt[4:8] == recv_idx,
                  f"the datagram is a valid Type-4 of all {size} bytes",
                  detail)
            # Not encrypted-in-name-only: the plaintext must be absent.
            check(payload[:32] not in pkt, "plaintext absent from the datagram")

    accept_case(EXPECT_MTU, "the #70 boundary")
    if mtu != EXPECT_MTU:
        # The tree is not a flag build, so the case above is red by
        # construction. Prove the stub and trampoline themselves work at
        # this tree's own MTU, so the red above is attributable to the
        # MTU and not to this harness.
        accept_case(mtu, "harness self-check at this tree's WG_MTU")


def main():
    global VERBOSE
    args = sys.argv[1:]
    seed = 1472
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
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    os.chdir(PROJECT_ROOT)
    built = not os.environ.get("C64_SKIP_BUILD")
    try:
        build()
        _run(rng)
    finally:
        if built:
            restore_default_tree()


def restore_default_tree():
    """Leave build/ as a plain `make` would.

    This is the LAST serial suite in tools/run_regression.py; without this
    every gate run left a flag-build PRG behind and the next C64_SKIP_BUILD
    user silently tested UCI_CHUNKED_WRITE=1. Only when we built: with
    C64_SKIP_BUILD the tree was not ours to touch.
    """
    print("Restoring the default build tree: make clean && make")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(["make"], capture_output=True, text=True,
                       cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(f"WARNING: default rebuild failed:\n{r.stderr}")


def _run(rng):
    labels = Labels.from_file(LABELS_PATH)
    required = ["transport_send", "net_udp_send", "tp_packet", "tp_packet_len",
                "tp_payload_ptr", "tp_payload_len", "tp_send_counter",
                "tp_peer_recv_idx", "hs_transport_send", "udp_recv_buf",
                "net_udp_send_len", "ip_packet_buf", "ip_pkt_len", "boot_ready"]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing label(s): {missing} (built with BACKEND=uci?)")
        sys.exit(1)

    print("\n--- the tree is a UCI_CHUNKED_WRITE=1 build ---")
    mtu, src = tree_mtu(labels)
    chunk = labels.address(CHUNK_PATH_LABEL)
    check(chunk is not None, f"{CHUNK_PATH_LABEL} linked",
          f"{CHUNK_PATH_LABEL} at ${chunk:04X}" if chunk is not None else
          f"{CHUNK_PATH_LABEL} absent from labels.txt — this tree was not "
          f"built with UCI_CHUNKED_WRITE=1 (or the Makefile ignores the flag)")
    check(mtu == EXPECT_MTU, f"WG_MTU == {EXPECT_MTU}",
          f"WG_MTU = {mtu} via {src}")
    check(labels.address("NET_UDP_SEND_MAX") == EXPECT_MTU + WG_DATA_OVERHEAD,
          f"NET_UDP_SEND_MAX == {EXPECT_MTU + WG_DATA_OVERHEAD}",
          f"NET_UDP_SEND_MAX label = {labels.address('NET_UDP_SEND_MAX')}")

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
        install_stub_and_trampoline(transport, labels)
        run_tests(transport, labels, rng, mtu)
        mgr.release(inst)

    failed = [l for ok, l in results if not ok]
    print(f"\nResults: {len(results) - len(failed)}/{len(results)} passed, "
          f"{len(failed)} failed")
    for l in failed:
        print(f"  FAILED: {l}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
