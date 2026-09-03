#!/usr/bin/env python3
"""test_wg_responder_timestamp.py — the bench responder enforces WireGuard's
greatest-seen TAI64N rule (issue #87). No C64, no VICE; milliseconds.

A conformant responder drops a handshake initiation whose 12-byte TAI64N
timestamp is <= the greatest it has already ACCEPTED from that peer's static
key. Until #87 our responder accepted anything, which is why a C64 that sends
the same timestamp on every initiation handshook happily on the bench and
would be dropped by real WireGuard after its first handshake.

Checks (each with a fresh initiator ephemeral, so only the timestamp repeats):
    R1  identical timestamp twice           -> second rejected
    R2  the C64's literal #87 shape,
        base||00000001, twice               -> second rejected
    R3  +1 ns accepted; repeat rejected; lower rejected; +1 s accepted;
        higher seconds with LOWER nanos accepted  (integer compare, not
        per-field)
    R4  a rejected initiation leaves the live session untouched: Type-4 in
        both directions still decrypts with the session that was accepted
    R5  server.py on a loopback socket: two identical-timestamp initiations
        produce exactly ONE Type-2 datagram at the wire

RED on the unmodified responder: R1, R2, R3 (the two rejections), R4, R5.

Usage:
    python3 tools/test_wg_responder_timestamp.py [--seed S] [--verbose]
"""
from __future__ import annotations

import os
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from noise.connection import NoiseConnection, Keypair  # noqa: E402

from wg_responder.keys import generate_keypair  # noqa: E402
from wg_responder.responder import (  # noqa: E402
    CONSTRUCTION, IDENTIFIER,
    MSG_TYPE_INITIATION, MSG_TYPE_RESPONSE, MSG_TYPE_TRANSPORT,
    NOISE_MSG1_LEN, T1_OFF_MAC1, T1_TOTAL, T2_HDR_LEN, T2_TOTAL,
    T4_HDR_LEN, NOISE_MSG2_LEN,
    WireGuardResponder, _compute_mac1, _mac1_key,
)
from wg_responder import server as wg_server  # noqa: E402

VERBOSE = False
TAI64_EPOCH = 0x4000000000000000


class Results:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail):
        self.rows.append((name, bool(ok), detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    def summary(self):
        bad = [r for r in self.rows if not r[1]]
        print("\n" + "=" * 72)
        print(f"Results: {len(self.rows) - len(bad)}/{len(self.rows)} passed, "
              f"{len(bad)} failed")
        if bad:
            print("\nFAILED:")
            for n, _, d in bad:
                print(f"  {n}: {d}")
        print("=" * 72)
        return len(bad)


# ── initiator side ─────────────────────────────────────────────────────────

def new_initiator(init_priv, resp_pub, psk):
    n = NoiseConnection.from_name(CONSTRUCTION)
    n.set_prologue(IDENTIFIER)
    n.set_psks(psk=psk)
    n.set_keypair_from_private_bytes(Keypair.STATIC, init_priv)
    n.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, resp_pub)
    n.set_as_initiator()
    n.start_handshake()
    return n


def build_type1(init_noise, resp_pub, tai64n, rng):
    """Type-1 carrying exactly *tai64n* (12 bytes), fresh sender index."""
    assert len(tai64n) == 12
    payload = bytes(init_noise.write_message(tai64n))
    assert len(payload) == NOISE_MSG1_LEN
    sender_idx = rng.getrandbits(32)
    hdr = bytes([MSG_TYPE_INITIATION, 0, 0, 0]) + struct.pack("<I", sender_idx)
    body = hdr + payload
    assert len(body) == T1_OFF_MAC1
    mac1 = _compute_mac1(body, _mac1_key(resp_pub))
    pkt = body + mac1 + bytes(16)
    assert len(pkt) == T1_TOTAL
    return pkt, sender_idx


def finish_initiator(init_noise, type2):
    assert len(type2) == T2_TOTAL and type2[0] == MSG_TYPE_RESPONSE
    init_noise.read_message(type2[T2_HDR_LEN:T2_HDR_LEN + NOISE_MSG2_LEN])
    assert init_noise.handshake_finished
    return struct.unpack_from("<I", type2, 4)[0]       # responder's index


def type4_from_initiator(init_noise, plaintext, receiver_idx, counter):
    ct = bytes(init_noise.encrypt(plaintext))
    return (bytes([MSG_TYPE_TRANSPORT, 0, 0, 0]) + struct.pack("<I", receiver_idx)
            + struct.pack("<Q", counter) + ct)


def ts_bytes(secs, nanos):
    return struct.pack(">QI", secs, nanos)


def try_initiation(responder, init_priv, resp_pub, psk, tai64n, rng):
    """Returns (accepted: bool, type2_or_exception, initiator_noise)."""
    n = new_initiator(init_priv, resp_pub, psk)
    pkt, _ = build_type1(n, resp_pub, tai64n, rng)
    try:
        t2 = responder.handle_initiation(pkt)
    except ValueError as exc:            # TimestampReplayError is a ValueError
        return False, exc, n
    return True, t2, n


def describe(accepted, what):
    if accepted:
        return f"ACCEPTED ({len(what)}-byte Type-2 returned)"
    return f"rejected: {type(what).__name__}: {what}"


# ── cases ─────────────────────────────────────────────────────────────────

def fresh_keys():
    rp, rpub = generate_keypair()
    ip, ipub = generate_keypair()
    return (bytes.fromhex(rp), bytes.fromhex(rpub),
            bytes.fromhex(ip), bytes.fromhex(ipub), os.urandom(32))


def r1_identical(res, rng):
    rpriv, rpub, ipriv, ipub, psk = fresh_keys()
    resp = WireGuardResponder(rpriv, ipub, psk)
    ts = ts_bytes(TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000),
                  rng.randrange(1_000_000_000))
    ok1, w1, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    ok2, w2, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    res.check("R1: first initiation accepted", ok1, describe(ok1, w1))
    res.check("R1: second initiation with an IDENTICAL timestamp is rejected",
              not ok2, f"ts={ts.hex()}; second was {describe(ok2, w2)}")


def r2_c64_shape(res, rng):
    rpriv, rpub, ipriv, ipub, psk = fresh_keys()
    resp = WireGuardResponder(rpriv, ipub, psk)
    base = TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000)
    ts = ts_bytes(base, 1)                       # base_time || 00000001
    ok1, w1, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    ok2, w2, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    res.check("R2: base||00000001 accepted once", ok1, describe(ok1, w1))
    res.check("R2: base||00000001 again (what the C64 sends on every rekey) is rejected",
              not ok2, f"ts={ts.hex()}; second was {describe(ok2, w2)}")


def r3_ordering(res, rng):
    rpriv, rpub, ipriv, ipub, psk = fresh_keys()
    resp = WireGuardResponder(rpriv, ipub, psk)
    secs = TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000)
    nanos = rng.randrange(1, 999_000_000)
    steps = [
        ("A = (s, n)",                 ts_bytes(secs, nanos),          True),
        ("A + 1 ns",                   ts_bytes(secs, nanos + 1),      True),
        ("A + 1 ns repeated",          ts_bytes(secs, nanos + 1),      False),
        ("A (lower than greatest)",    ts_bytes(secs, nanos),          False),
        ("A + 1 s, same nanos",        ts_bytes(secs + 1, nanos + 1),  True),
        ("A + 2 s, nanos = 0 (higher secs, LOWER nanos)",
                                       ts_bytes(secs + 2, 0),          True),
        ("A + 1 s again (lower secs, higher nanos)",
                                       ts_bytes(secs + 1, 999_999_999), False),
    ]
    for label, ts, want in steps:
        ok, what, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
        res.check(f"R3: {label} -> {'accepted' if want else 'rejected'}",
                  ok == want, f"ts={ts.hex()}; {describe(ok, what)}")


def r4_session_survives_rejection(res, rng):
    rpriv, rpub, ipriv, ipub, psk = fresh_keys()
    resp = WireGuardResponder(rpriv, ipub, psk)
    ts = ts_bytes(TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000), 7)
    ok, t2, live = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    res.check("R4: session established", ok, describe(ok, t2))
    if not ok:
        return
    resp_idx = finish_initiator(live, t2)

    # Replay with the same timestamp — must be rejected AND change nothing.
    ok2, w2, _ = try_initiation(resp, ipriv, rpub, psk, ts, rng)
    res.check("R4: replayed timestamp rejected", not ok2, describe(ok2, w2))

    marker = bytes(rng.randrange(256) for _ in range(rng.randrange(8, 40)))
    try:
        got = resp.decrypt_transport(type4_from_initiator(live, marker, resp_idx, 0))
        fwd = got == marker
        fwd_detail = f"decrypted {got.hex()} == sent {marker.hex()}"
    except Exception as exc:                       # noqa: BLE001
        fwd, fwd_detail = False, f"{type(exc).__name__}: {exc}"
    res.check("R4: initiator -> responder Type-4 still decrypts after the rejection",
              fwd, fwd_detail)

    reply = bytes(rng.randrange(256) for _ in range(rng.randrange(8, 40)))
    try:
        pkt = resp.encrypt_transport(reply)
        back = bytes(live.decrypt(pkt[T4_HDR_LEN:]))
        rev = back == reply and struct.unpack_from("<I", pkt, 4)[0] != 0
        rev_detail = f"initiator decrypted {back.hex()} == sent {reply.hex()}"
    except Exception as exc:                       # noqa: BLE001
        rev, rev_detail = False, f"{type(exc).__name__}: {exc}"
    res.check("R4: responder -> initiator Type-4 still decrypts after the rejection",
              rev, rev_detail)


def r5_server_wire(res, rng):
    """server.py's own loop: count Type-2 datagrams at the wire."""
    rpriv, rpub, ipriv, ipub, psk = fresh_keys()
    resp = WireGuardResponder(rpriv, ipub, psk)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    threading.Thread(target=wg_server.run_server,
                     args=("127.0.0.1", port, resp), kwargs={"interactive": False},
                     daemon=True, name="wg-server-under-test").start()
    time.sleep(0.3)

    ts = ts_bytes(TAI64_EPOCH + rng.randrange(1_600_000_000, 2_000_000_000), 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    replies = []
    for i in range(2):
        n = new_initiator(ipriv, rpub, psk)
        pkt, _ = build_type1(n, rpub, ts, rng)
        sock.sendto(pkt, ("127.0.0.1", port))
        try:
            d, _ = sock.recvfrom(65535)
            replies.append(d)
        except socket.timeout:
            pass
    # Drain anything late, so a slow second reply is still counted.
    sock.settimeout(1.0)
    try:
        while True:
            d, _ = sock.recvfrom(65535)
            replies.append(d)
    except socket.timeout:
        pass
    sock.close()
    t2s = [d for d in replies if d and d[0] == MSG_TYPE_RESPONSE]
    res.check("R5: server.py answers two identical-timestamp initiations with exactly ONE Type-2",
              len(t2s) == 1 and len(replies) == 1,
              f"{len(t2s)} Type-2 datagram(s) of {len(replies)} received for ts={ts.hex()}")


def main():
    global VERBOSE
    args = sys.argv[1:]
    VERBOSE = "--verbose" in args
    seed = int(os.environ.get("TEST_SEED", random.randrange(2 ** 31)))
    for i, a in enumerate(args):
        if a == "--seed":
            seed = int(args[i + 1])
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    res = Results()
    print("--- R1 ---"); r1_identical(res, rng)
    print("--- R2 ---"); r2_c64_shape(res, rng)
    print("--- R3 ---"); r3_ordering(res, rng)
    print("--- R4 ---"); r4_session_survives_rejection(res, rng)
    print("--- R5 ---"); r5_server_wire(res, rng)
    sys.exit(1 if res.summary() else 0)


if __name__ == "__main__":
    main()
