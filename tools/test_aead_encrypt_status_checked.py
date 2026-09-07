#!/usr/bin/env python3
"""test_aead_encrypt_status_checked.py — a failed aead_encrypt must not ship a packet.

c64-ChaCha20-Poly1305 v0.11.0 gave `aead_encrypt` a return convention
(AEAD_OK=$00 / AEAD_ERR_DOMAIN=$01) and a domain guard at both AEAD entry
points. On rejection it returns EARLY HAVING WRITTEN NOTHING — neither
ciphertext nor `poly1305_tag`.

c64-wireguard's three DECRYPT sites check A and fail closed. Its three
ENCRYPT sites (src/wg/handshake.s, src/wg/transport.s) ignore A entirely
and unconditionally copy `poly1305_tag` into the outgoing packet. When
aead_encrypt refuses, that tag is the PREVIOUS packet's, and the payload
region still holds the plaintext the consumer copied in before the call.
The consumer therefore emits a packet containing PLAINTEXT under a STALE
TAG, and reports success.

WHY THIS IS NOT A VACUOUS TEST.
The accepted domain (ptr + len <= $10000) is a superset of everything WG
sends, so the bug is unreachable through normal paths today — safe by
accident, not by construction. A test asserting "we never send
out-of-domain input" would pass today AND keep passing if the caller
check were added or removed, which is exactly the guard-that-depends-on-
the-author's-imagined-failure shape. So leg 2 does not assert the input
predicate: it injects the library's own documented failure return at the
seam and asserts on the BYTES THE CONSUMER WOULD PUT ON THE WIRE. Leg 3
re-runs the same call without the injection and requires the opposite
verdict, so the predicate is proven to discriminate in both directions.

Legs
  1  library_domain_guard   Real out-of-domain call to the real
                            aead_encrypt: A=$01 and poly1305_tag is
                            byte-identical to the previous call's tag.
                            Establishes that "stale tag" is a real state,
                            not a hypothesis. RED on the pre-bump pin
                            (chacha v0.9.0 has no guard and no status).
  2  consumer_ignores_A     aead_encrypt stubbed to its documented
                            failure return; transport_encrypt must not
                            present a packet.  <-- the RED leg
  3  control_no_stub        Same inputs, real aead_encrypt: a packet IS
                            presented, with a fresh tag and real
                            ciphertext.

RANDOMISATION: keys, counters, receiver indexes and both payloads come
from a seeded RNG (logged, reproducible via --seed / TEST_SEED). The two
payloads are drawn from DISJOINT alphabets — leg 1's/leg 2's first
packet from 'A'-'Z', the second from 'a'-'z' — so a stale or echoed
buffer cannot satisfy a check meant for the other one. A fixed marker is
appended as a SUFFIX only.

VICE-ONLY, and complete for this gap: everything here is CPU and RAM.
Nothing touches $DF1D/UCI, the REU or the wire, so there is no
hardware-only leg. (It is nonetheless worth running once on the U64 at
turbo through the standard backend-agnostic path, because
transport_encrypt's 16-bit copy loop is speed-sensitive; that would be a
separate suite, not this one.)

Usage:
    python3 tools/test_aead_encrypt_status_checked.py [--seed S]
"""

import os
import random
import struct
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, read_bytes, write_bytes, jsr,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vice_util import binary_wait_for_boot_ready   # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

AEAD_OK = 0x00
AEAD_ERR_DOMAIN = 0x01

# Disjoint alphabets, so a stale buffer can never satisfy the other leg's check.
ALPHA_FIRST = bytes(range(0x41, 0x5B))    # 'A'-'Z'
ALPHA_SECOND = bytes(range(0x61, 0x7B))   # 'a'-'z'
MARKER_FIRST = b"#1"                      # fixed, SUFFIX only
MARKER_SECOND = b"#2"

# Out-of-domain by exactly one byte over the boundary the library documents
# (ptr + len <= $10000 accepted). $FF00 + $0200 = $10100.
OOD_PTR = 0xFF00
OOD_LEN = 0x0200


def _acc(regs):
    """Accumulator out of jsr()'s register dict, whatever it calls the key."""
    for k in ("a", "A", "acc", "ac"):
        if k in regs:
            return regs[k] & 0xFF
    raise KeyError(f"no accumulator in jsr() result: {sorted(regs)}")


def _payload(rng, alphabet, marker, n):
    body = bytes(rng.choice(alphabet) for _ in range(n - len(marker)))
    return body + marker


def _encrypt_once(transport, labels, rng, alphabet, marker, size):
    """Drive transport_encrypt end to end; return (payload, packet_len, packet)."""
    key = bytes(rng.randrange(256) for _ in range(32))
    recv_idx = bytes(rng.randrange(256) for _ in range(4))
    counter = rng.randrange(0, 0xFFFF)
    payload = _payload(rng, alphabet, marker, size)

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], recv_idx)
    write_bytes(transport, labels["tp_send_counter"], struct.pack("<Q", counter))
    write_bytes(transport, labels["input_buffer"], payload)
    write_bytes(transport, labels["tp_payload_ptr"], struct.pack("<H", labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], struct.pack("<H", size))

    jsr(transport, labels["transport_encrypt"], timeout=60.0)

    pkt_len = int.from_bytes(read_bytes(transport, labels["tp_packet_len"], 2), "little")
    pkt = read_bytes(transport, labels["tp_packet"], min(pkt_len, 16 + size + 16)) if pkt_len else b""
    return payload, pkt_len, pkt


def leg1_library_domain_guard(transport, labels, rng):
    """The library really does refuse and really does leave the old tag behind."""
    print("\n--- leg 1: library domain guard leaves a STALE poly1305_tag ---")
    failed = 0

    size = rng.randrange(16, 200)
    payload = _payload(rng, ALPHA_FIRST, MARKER_FIRST, size)
    write_bytes(transport, labels["aead_key"], bytes(rng.randrange(256) for _ in range(32)))
    write_bytes(transport, labels["aead_nonce"], bytes(rng.randrange(256) for _ in range(12)))
    write_bytes(transport, labels["aead_aad_len"], bytes([0]))
    write_bytes(transport, labels["input_buffer"], payload)
    write_bytes(transport, labels["aead_data_ptr"], struct.pack("<H", labels["input_buffer"]))
    write_bytes(transport, labels["aead_data_len"], struct.pack("<H", size))

    regs = jsr(transport, labels["aead_encrypt"], timeout=60.0)
    a_ok = _acc(regs)
    tag1 = read_bytes(transport, labels["poly1305_tag"], 16)
    if a_ok != AEAD_OK:
        print(f"  FAIL in-domain aead_encrypt (ptr=${labels['input_buffer']:04X} len={size}, "
              f"sum=${labels['input_buffer'] + size:05X} <= $10000) returned A=${a_ok:02X}, "
              f"expected AEAD_OK ($00). The guard is rejecting traffic WG actually sends.")
        failed += 1
    else:
        print(f"  ok  in-domain call returned A=$00, tag={tag1.hex()}")

    # Now out of domain by one byte over the boundary.
    write_bytes(transport, labels["aead_data_ptr"], struct.pack("<H", OOD_PTR))
    write_bytes(transport, labels["aead_data_len"], struct.pack("<H", OOD_LEN))
    regs = jsr(transport, labels["aead_encrypt"], timeout=60.0)
    a_ood = _acc(regs)
    tag2 = read_bytes(transport, labels["poly1305_tag"], 16)

    if a_ood != AEAD_ERR_DOMAIN:
        print(f"  FAIL out-of-domain aead_encrypt (ptr=${OOD_PTR:04X} len=${OOD_LEN:04X}, "
              f"sum=${OOD_PTR + OOD_LEN:05X} > $10000) returned A=${a_ood:02X}, expected "
              f"AEAD_ERR_DOMAIN ($01). Either the pinned chacha20poly1305 predates v0.11.0's "
              f"SPEC §14.1 guard, or the guard's boundary moved.")
        failed += 1
    elif tag2 != tag1:
        print(f"  FAIL out-of-domain call returned $01 but poly1305_tag CHANGED: "
              f"{tag1.hex()} -> {tag2.hex()}. The library documents 'NOTHING written'; if it "
              f"writes a tag on the reject path, leg 2's stale-tag consequence is a different bug.")
        failed += 1
    else:
        print(f"  ok  out-of-domain call returned A=$01 and left poly1305_tag byte-identical "
              f"({tag2.hex()}) — a caller that copies it unconditionally ships the PREVIOUS tag")

    return (1 if failed == 0 else 0), failed


def _run_second_encrypt(transport, labels, rng, stub):
    """Second encrypt, optionally with aead_encrypt stubbed to its failure return."""
    addr = labels["aead_encrypt"]
    saved = read_bytes(transport, addr, 3)
    if stub:
        # The library's own documented failure return: LDA #AEAD_ERR_DOMAIN / RTS.
        # Injected at the seam rather than reached through an input, because no
        # WG input can reach it — see the module docstring.
        write_bytes(transport, addr, bytes([0xA9, AEAD_ERR_DOMAIN, 0x60]))
    try:
        size = rng.randrange(16, 200)
        return _encrypt_once(transport, labels, rng, ALPHA_SECOND, MARKER_SECOND, size)
    finally:
        if stub:
            write_bytes(transport, addr, saved)
            back = read_bytes(transport, addr, 3)
            assert back == saved, (
                f"FATAL: failed to restore aead_encrypt at ${addr:04X}: "
                f"wrote {saved.hex()}, read back {back.hex()}")


def leg2_consumer_ignores_A(transport, labels, rng, state):
    """RED leg: the consumer emits a stale-tag plaintext packet and calls it success."""
    print("\n--- leg 2: transport_encrypt must not present a packet when aead_encrypt fails ---")
    failed = 0

    p1, len1, pkt1 = _encrypt_once(transport, labels, rng, ALPHA_FIRST, MARKER_FIRST,
                                   rng.randrange(16, 200))
    if len1 != 32 + len(p1):
        print(f"  FAIL setup: first (healthy) encrypt produced tp_packet_len={len1}, expected "
              f"{32 + len(p1)}. Cannot establish a known previous tag; leg aborted.")
        return 0, 1
    tag1 = pkt1[16 + len(p1):16 + len(p1) + 16]
    state["tag1"] = tag1
    print(f"  setup first packet: {len(p1)} B payload, tag={tag1.hex()}")

    p2, len2, pkt2 = _run_second_encrypt(transport, labels, rng, stub=True)

    presented = len2 == 32 + len(p2)
    tag2 = pkt2[16 + len(p2):16 + len(p2) + 16] if presented else b""
    body2 = pkt2[16:16 + len(p2)] if presented else b""

    if presented and tag2 == tag1:
        detail = ""
        if body2 == p2:
            detail = (" and the payload region is the CLEARTEXT the consumer copied in "
                      "(aead_encrypt wrote no ciphertext)")
        print(f"  FAIL fail-open: aead_encrypt returned AEAD_ERR_DOMAIN ($01) having written "
              f"nothing, and transport_encrypt still presented a complete packet — "
              f"tp_packet_len={len2} (= 32 + {len(p2)}), tag={tag2.hex()} which is "
              f"BYTE-IDENTICAL to the previous packet's tag{detail}. A returns its status in A "
              f"and the three encrypt sites (handshake.s, transport.s) never test it.")
        failed += 1
    elif presented:
        print(f"  FAIL presented a packet on a failed encrypt (tp_packet_len={len2}); tag "
              f"{tag2.hex()} differs from the previous {tag1.hex()}, so it is not the stale-tag "
              f"shape, but a packet built on a refused encrypt must not be presented at all.")
        failed += 1
    else:
        print(f"  ok  no packet presented (tp_packet_len={len2}) — the caller checked A")

    return (1 if failed == 0 else 0), failed


def leg3_control_no_stub(transport, labels, rng, state):
    """Control arm: without the injection the same call must succeed normally."""
    print("\n--- leg 3: control — same call, real aead_encrypt ---")
    failed = 0
    tag1 = state.get("tag1")

    p2, len2, pkt2 = _run_second_encrypt(transport, labels, rng, stub=False)
    if len2 != 32 + len(p2):
        print(f"  FAIL control arm produced tp_packet_len={len2}, expected {32 + len(p2)}. "
              f"Leg 2's 'no packet presented' verdict is then stuck-on and proves nothing.")
        return 0, 1

    tag2 = pkt2[16 + len(p2):16 + len(p2) + 16]
    body2 = pkt2[16:16 + len(p2)]
    if tag1 is not None and tag2 == tag1:
        print(f"  FAIL control arm's tag {tag2.hex()} equals the earlier packet's tag — "
              f"leg 2's stale-tag predicate cannot distinguish healthy from failed.")
        failed += 1
    if body2 == p2:
        print(f"  FAIL control arm's payload region is byte-identical to the plaintext — "
              f"aead_encrypt did not encrypt, so leg 2's cleartext detail is meaningless here.")
        failed += 1
    if failed == 0:
        print(f"  ok  packet presented, fresh tag {tag2.hex()}, payload region is ciphertext")
    return (1 if failed == 0 else 0), failed


def main():
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1]); i += 2
        else:
            i += 1
    if os.environ.get("TEST_SEED"):
        seed = int(os.environ["TEST_SEED"])
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, capture_output=True, check=False)
        r = subprocess.run(["make"], cwd=PROJECT_ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
            sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    required = ["aead_encrypt", "poly1305_tag", "aead_data_ptr", "aead_data_len",
                "aead_key", "aead_nonce", "aead_aad_len", "transport_encrypt",
                "tp_packet", "tp_packet_len", "tp_payload_ptr", "tp_payload_len",
                "tp_send_counter", "tp_peer_recv_idx", "hs_transport_send", "input_buffer"]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing from build/labels.txt: {missing}")
        sys.exit(1)

    # Attach an REU. The default build is REU=1, and without one every DMA in
    # reu_mul_init goes unconfirmed ($DF00 reads open bus) — the machine boots
    # with x25519_reu_fault set and garbage multiply rows. Nothing in THIS
    # suite touches fe25519, but booting a knowingly faulted machine to test
    # something else is how a suite ends up measuring the wrong thing; and
    # once the §8.2 fault is surfaced at boot, such a machine will not boot at
    # all. Same two flags tools/test_fe25519.py already passes.
    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                     extra_args=["-reu", "-reusize", "512"])
    passed = failed = 0
    state = {}
    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        t = inst.transport
        if binary_wait_for_boot_ready(t, labels, timeout=300.0) is None:
            print("FATAL: boot_ready never set")
            mgr.release(inst)
            sys.exit(1)
        write_bytes(t, 0x0339, bytes([0x4C, 0x39, 0x03]))

        for leg in (lambda: leg1_library_domain_guard(t, labels, rng),
                    lambda: leg2_consumer_ignores_A(t, labels, rng, state),
                    lambda: leg3_control_no_stub(t, labels, rng, state)):
            p, f = leg()
            passed += p
            failed += f

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}\nResults: {passed}/{total} legs passed, {failed} failed\n{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
