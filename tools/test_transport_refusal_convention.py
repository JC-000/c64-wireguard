#!/usr/bin/env python3
"""test_transport_refusal_convention.py — both refusal exits of
transport_encrypt must agree on ONE postcondition.

transport_encrypt has two ways to refuse:

  * counter exhausted  (tp_send_counter+7 >= REJECT_COUNTER_B7), and
  * aead_encrypt out of domain (SPEC §14.1 AEAD_ERR_DOMAIN).

They must be indistinguishable to a caller that only looks at the
contract: C=1 and tp_packet_len=0. The counter exit returns at step 0,
BEFORE the type-4 header is written and before the plaintext is copied,
so on refusal tp_packet still holds the previous fully-built packet.
A caller that reads a stale tp_packet_len and sends puts an exact byte
replay of the last datagram on the wire — self-consistent, so it
authenticates; a conformant peer drops it on the already-seen counter.
The real damage is upward: counter exhaustion becomes invisible.

NOT A REACHABLE BUG. REJECT_COUNTER_B7 = $10 puts real exhaustion past
2^60 sends, and REKEY_COUNTER_B7 = $0F rekeys long before that. And
transport_send, the only in-tree caller, does branch on carry. This
suite demonstrates a CONSEQUENCE of the convention, on the one live
surface there is: transport_encrypt is .export-ed, and host tools jsr()
it directly and read tp_packet_len afterwards.

The counter exit is driven by poking the counter. The AEAD exit is
unreachable from a real payload (the domain is
aead_data_ptr + aead_data_len <= $10000, and transport_send's MTU guard
refuses long before tp_packet+16+len could pass $10000), so it is driven
by stubbing aead_encrypt's entry with `lda #AEAD_ERR_DOMAIN / rts` — the
library's documented refusal, which writes nothing. The stub is proven
load-bearing in both directions: the same call succeeds before it is
installed and again after it is removed.

Usage:
    python3 tools/test_transport_refusal_convention.py [--seed S] [--verbose]

VICE-only (needs jsr()/register reads). Nothing here is hardware-specific;
there is no U64 coverage gap to declare.
"""

import os
import random
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, RoutineHung,
)
from c64_test_harness.transport import TransportError
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REJECT_COUNTER_B7 = 0x10        # src/constants.inc
AEAD_ERR_DOMAIN = 0x01          # libs/chacha20poly1305 §14.1
FLAG_C = 0x01

# Disjoint alphabets for the packet that is really encrypted (A) and the
# one a fall-through would have encrypted instead (B), so the two payloads
# can never coincide whatever the seed. NOTE this cannot be turned into a
# "no B byte appears in tp_packet" check: tp_packet is mostly ciphertext
# and tag, which span the whole byte range, and B's plaintext is encrypted
# in place before the buffer is readable either way. The real assertion is
# byte-equality against the snapshot read back before the refusal.
ALPHABET_A = list(range(0x01, 0x80))
ALPHABET_B = list(range(0x80, 0x100))


def py_encrypt(key, counter_val, plaintext):
    nonce = b"\x00" * 4 + struct.pack("<Q", counter_val)
    ct_and_tag = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return ct_and_tag[:-16], ct_and_tag[-16:]


class Check:
    """Assertion bookkeeping that prints the observed value on failure."""

    def __init__(self):
        self.passed = 0
        self.failed = 0

    def eq(self, label, got, want, fmt=str):
        if got == want:
            self.passed += 1
            if VERBOSE:
                print(f"  PASS {label}: {fmt(got)}")
        else:
            self.failed += 1
            print(f"  FAIL {label}: got {fmt(got)}, expected {fmt(want)}")

    def true(self, label, cond, detail=""):
        if cond:
            self.passed += 1
            if VERBOSE:
                print(f"  PASS {label}")
        else:
            self.failed += 1
            print(f"  FAIL {label}{': ' + detail if detail else ''}")


def _report(chk):
    total = chk.passed + chk.failed
    print(f"\n{'=' * 60}")
    print(f"Results: {chk.passed}/{total} passed, {chk.failed} failed")
    print(f"{'=' * 60}")
    return 0 if chk.failed == 0 else 1


def hexs(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else str(b)


# ============================================================================
# Machine-state helpers
# ============================================================================

def stage_payload(transport, labels, rng, alphabet, size):
    """Write a random payload at input_buffer and point tp_payload_* at it."""
    payload = bytes(rng.choice(alphabet) for _ in range(size))
    write_bytes(transport, labels["input_buffer"], payload)
    write_bytes(transport, labels["tp_payload_ptr"],
                struct.pack("<H", labels["input_buffer"]))
    write_bytes(transport, labels["tp_payload_len"], struct.pack("<H", size))
    return payload


def read_u16(transport, addr):
    return int.from_bytes(read_bytes(transport, addr, 2), "little")


def send_one_real_packet(transport, labels, rng, chk, tag):
    """Encrypt a genuine packet and ASSERT it landed.

    This is the precondition the whole suite rests on: without it,
    tp_packet_len is zero-filled BSS at cold start and every later
    `tp_packet_len == 0` passes on the initial value rather than on
    anything the routine did.

    Returns (payload, packet_bytes, packet_len).
    """
    key = bytes(rng.randrange(256) for _ in range(32))
    recv_idx = bytes(rng.randrange(256) for _ in range(4))
    counter_val = rng.randrange(0, 0x10000)
    size = rng.randrange(24, 96)

    write_bytes(transport, labels["hs_transport_send"], key)
    write_bytes(transport, labels["tp_peer_recv_idx"], recv_idx)
    write_bytes(transport, labels["tp_send_counter"],
                struct.pack("<Q", counter_val))
    payload = stage_payload(transport, labels, rng, ALPHABET_A, size)

    regs = jsr(transport, labels["transport_encrypt"], timeout=60.0)

    pkt_len = read_u16(transport, labels["tp_packet_len"])
    chk.eq(f"[precondition {tag}] tp_packet_len after a real encrypt",
           pkt_len, 32 + size)
    chk.eq(f"[precondition {tag}] C clear on the success path",
           regs["FL"] & FLAG_C, 0)
    if pkt_len != 32 + size:
        return payload, b"", pkt_len

    packet = read_bytes(transport, labels["tp_packet"], pkt_len)
    py_ct, py_tag = py_encrypt(key, counter_val, payload)
    chk.eq(f"[precondition {tag}] tp_packet is a real type-4 datagram",
           packet, struct.pack("<I", 4) + recv_idx
           + struct.pack("<Q", counter_val) + py_ct + py_tag, hexs)
    return payload, packet, pkt_len


def refusal_postcondition(transport, labels, regs, chk, tag):
    """The postcondition BOTH refusal exits owe. Returns the tuple observed."""
    carry = regs["FL"] & FLAG_C
    lo = read_bytes(transport, labels["tp_packet_len"], 1)[0]
    hi = read_bytes(transport, labels["tp_packet_len"] + 1, 1)[0]
    chk.eq(f"[{tag}] C=1 (convention pin, see docstring)", carry, FLAG_C)
    chk.eq(f"[{tag}] tp_packet_len lo", lo, 0)
    chk.eq(f"[{tag}] tp_packet_len hi", hi, 0)
    return (carry, lo, hi)


# ============================================================================
# Tests
# ============================================================================

def test_counter_exhaustion(transport, labels, rng, chk):
    """Counter exhausted: refuse without leaving the previous packet armed."""
    payload_a, packet_a, len_a = send_one_real_packet(
        transport, labels, rng, chk, "counter")
    if not packet_a:
        return None

    # Exhaust: high byte of the 64-bit send counter at the reject threshold.
    write_bytes(transport, labels["tp_send_counter"] + 7,
                bytes([REJECT_COUNTER_B7]))

    # Stage a DIFFERENT payload from the disjoint alphabet. If the routine
    # fell through, this is what it would have encrypted.
    payload_b = stage_payload(transport, labels, rng, ALPHABET_B,
                              rng.randrange(24, 96))

    regs = jsr(transport, labels["transport_encrypt"], timeout=60.0)
    post = refusal_postcondition(transport, labels, regs, chk,
                                 "counter exhaustion")

    chk.eq("[counter exhaustion] tp_encrypt_error",
           read_bytes(transport, labels["tp_encrypt_error"], 1)[0], 1)

    # What a fall-through would emit: tp_packet byte-unchanged, i.e. an
    # exact replay of packet A. Asserted against the bytes READ BACK before
    # the refusal, not against anything this test wrote into tp_packet.
    after = read_bytes(transport, labels["tp_packet"], len_a)
    chk.eq("[counter exhaustion] tp_packet byte-unchanged", after, packet_a,
           hexs)

    # ...and the same refusal through transport_send, the in-tree caller.
    # This is the assertion that dies if `bcs @too_long` is ever deleted.
    write_bytes(transport, labels["tp_send_counter"] + 7,
                bytes([REJECT_COUNTER_B7]))
    stage_payload(transport, labels, rng, ALPHABET_B, rng.randrange(24, 96))
    try:
        regs = jsr(transport, labels["transport_send"], timeout=30.0,
                   recover_on_timeout=True)
    except RoutineHung as e:
        chk.true("[transport_send] returns on a refused encrypt", False,
                 f"transport_send hung (recovered={e.recovered}) — it did "
                 f"not branch on the refusal")
        return post
    except TransportError as e:
        # A transport_send that does not branch on the refusal walks into the
        # backend with a zero-length packet; on ip65 that JAMs the 6510. Count
        # it rather than letting it escape as a traceback — the machine is
        # unusable from here, so the remaining tests cannot run.
        chk.true("[transport_send] returns on a refused encrypt", False,
                 f"the 6510 did not survive the call: {e}")
        raise SystemExit(_report(chk))
    chk.eq("[transport_send] C=1 propagated to the caller",
           regs["FL"] & FLAG_C, FLAG_C)
    chk.eq("[transport_send] tp_packet_len", read_u16(
        transport, labels["tp_packet_len"]), 0)
    return post


def test_aead_refusal(transport, labels, rng, chk):
    """AEAD out of domain: the SAME postcondition, both ways."""
    aead = labels["aead_encrypt"]
    original = read_bytes(transport, aead, 3)

    # Direction 1: without the stub the identical call SUCCEEDS. Establishes
    # that whatever happens next is the stub's doing.
    payload_a, packet_a, len_a = send_one_real_packet(
        transport, labels, rng, chk, "aead")
    if not packet_a:
        return None

    stage_payload(transport, labels, rng, ALPHABET_B, rng.randrange(24, 96))
    write_bytes(transport, aead,
                bytes([0xA9, AEAD_ERR_DOMAIN, 0x60]))  # lda #$01 / rts
    chk.eq("[aead] stub installed at aead_encrypt",
           read_bytes(transport, aead, 3), bytes([0xA9, AEAD_ERR_DOMAIN, 0x60]),
           hexs)

    regs = jsr(transport, labels["transport_encrypt"], timeout=60.0)
    post = refusal_postcondition(transport, labels, regs, chk, "aead refusal")

    # Direction 2: remove the stub and the same call succeeds again. Without
    # this the refusal could be anything about the machine's state.
    write_bytes(transport, aead, original)
    chk.eq("[aead] aead_encrypt restored by read-back",
           read_bytes(transport, aead, 3), original, hexs)
    send_one_real_packet(transport, labels, rng, chk, "aead-restored")
    return post


def test_exits_agree(post_counter, post_aead, chk):
    """Set equality, both directions: neither exit may have a postcondition
    the other lacks. A guard written only against the failure its author had
    in mind is the class this project has a standing note about."""
    chk.true("both refusal exits reached", post_counter is not None
             and post_aead is not None)
    if post_counter is None or post_aead is None:
        return
    chk.eq("refusal postcondition (C, len_lo, len_hi) is identical across "
           "both exits", post_counter, post_aead)


# ============================================================================

def main():
    global VERBOSE
    args = sys.argv[1:]
    seed = None
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
    if seed is None:
        env = os.environ.get("TEST_SEED")
        seed = int(env) if env else random.randrange(2 ** 32)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    rng = random.Random(seed)

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        for f in ["wireguard.prg", "labels.txt"]:
            p = os.path.join(PROJECT_ROOT, "build", f)
            if os.path.exists(p):
                os.remove(p)
        r = subprocess.run(["make"], capture_output=True, text=True,
                           cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    labels = Labels.from_file(LABELS_PATH)
    for name in ("transport_encrypt", "transport_send", "aead_encrypt",
                 "tp_packet", "tp_packet_len", "tp_send_counter",
                 "tp_encrypt_error", "tp_payload_ptr", "tp_payload_len",
                 "tp_peer_recv_idx", "hs_transport_send", "input_buffer"):
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    chk = Check()

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if binary_wait_for_boot_ready(transport, labels, timeout=180.0) is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("\n--- counter-exhaustion exit ---")
        post_counter = test_counter_exhaustion(transport, labels, rng, chk)
        print("\n--- AEAD-refusal exit ---")
        post_aead = test_aead_refusal(transport, labels, rng, chk)
        print("\n--- the two exits agree ---")
        test_exits_agree(post_counter, post_aead, chk)

        mgr.release(inst)

    sys.exit(_report(chk))


if __name__ == "__main__":
    main()
