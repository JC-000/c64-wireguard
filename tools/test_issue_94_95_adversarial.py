#!/usr/bin/env python3
"""test_issue_94_95_adversarial.py — regression suite for issues #94 / #95.

Lineage: this began as an independent adversarial RED BASELINE against master
46a0c99, where all 11 expectations were met *because the bugs were present*.
It has been INVERTED for the #94 fix — T1/T2/T3/T6/T7/S1/S3 now assert the
guards hold — so the suite is RED on 46a0c99 and GREEN on the fix.

  #94  a forged Type 3 (cookie reply) was accepted without validating the
       receiver index, and its handler was dispatched in every wg_state, so
       one 64-byte unauthenticated datagram tore down a live session and
       spent 3 X25519 scalarmults rebuilding an initiation.
  #95  a forged Type 2 poisons hs_c/hs_h.  NOT fixed here; T4/T5/S2 record
       its measured status (the "no timeout" clause is false, the "no retry"
       clause is true and deliberate).

Three guards are under test, and they are independent:

  (a) src/wg/cookie.s    receiver_index (udp_recv_buf+4..7) == hs_sender_idx
                         (wireguard-go device/receive.go indexTable.Lookup;
                          wireguard-linux-compat wg_index_hashtable_lookup)
  (b) src/wg/cookie.s    hs_mac1_valid != 0
                         (wireguard-go cookie.go ConsumeReply's hasLastMAC1)
  (c) src/wg/session.s   the Type 3 dispatch only runs in SESSION_HS_SENT

Every rejection assertion is paired with an ACCEPTANCE control that strips
exactly one precondition, so "reject everything" cannot pass: T1, T2 and T3
each re-issue the identical packet with the guard satisfied and require the
handler to accept it (A=0, cookie plaintext recovered) or to be entered.

Fast group (seconds; this is what run_regression.py runs):
  T1  post-load window: hs_mac1_valid=0 with an all-zero AAD and index ->
      rejected; accepted once hs_mac1_valid is set        -> guard (b)
  T2  receiver_index mismatch rejected (all four bytes checked), matching
      index accepted                                      -> guard (a)
  T3  a Type 3 with BOTH cookie.s preconditions satisfied does not reach the
      handler body while ACTIVE, but does in HS_SENT      -> guard (c)
  T4  timer_check tears an over-deadline HS_SENT down to IDLE        (#95)
  T5  nothing re-initiates afterwards                                (#95)
  T6  guard (c) per state: IDLE no, HS_SENT yes, ACTIVE no
  T7  a fully valid Type 3 arriving in ACTIVE leaves wg_state, cookie_valid
      and the AAD untouched — the headline #94 claim, inverted.  Bounded
      timeout: on a regression session_initiate runs for hours, so this
      fails by TimeoutError rather than hanging the gate.

Slow group (--slow; each runs hs_process_response or hs_create_initiation,
i.e. 2-3 X25519 scalarmults, hours each under VICE warp):
  S1  T7 again with an unbounded timeout, so a regression is measured
      rather than timed out                                          (#94)
  S2  forged Type 2 in HS_SENT -> hs_c/hs_h mutated, state IDLE      (#95)
  S3  the escalation hinge: a blocked kill does NOT regenerate the AAD, so
      there is no fresh mac1 on the wire to build the next forgery from

Usage:
    python3 tools/test_issue_94_95_adversarial.py [--slow] [--only NAME]
"""

import hashlib
import os
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from c64_test_harness.transport import TimeoutError as HarnessTimeoutError
from vice_util import binary_wait_for_boot_ready

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

TRAMPOLINE = 0x0340
RESULT_SLOT = 0x0360
IDLE_LOOP = 0x0339

SENTINEL = b'\x5A' * 16

# hs_process_response / hs_create_initiation are multi-hour under VICE warp.
SLOW_TIMEOUT = 25000.0

# T7 must not inherit that. On the fixed tree nothing expensive runs, so this
# completes in milliseconds; on a regressed tree session_initiate starts and
# T7 fails by TimeoutError inside the gate's per-suite budget.
T7_TIMEOUT = 300.0


# ---------------------------------------------------------------------------
# XChaCha20-Poly1305 (lifted verbatim from tools/test_phase7.py)
# ---------------------------------------------------------------------------

def rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl32(s[b] ^ s[c], 7)


def hchacha20_py(key_32, nonce_16):
    state = list(struct.unpack('<16I', b'expand 32-byte k' + key_32 + nonce_16))
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)
    return (struct.pack('<4I', state[0], state[1], state[2], state[3]) +
            struct.pack('<4I', state[12], state[13], state[14], state[15]))


def xchacha20poly1305_encrypt(key, nonce_24, plaintext, aad):
    subkey = hchacha20_py(key, nonce_24[:16])
    return ChaCha20Poly1305(subkey).encrypt(
        b'\x00\x00\x00\x00' + nonce_24[16:24], plaintext, aad)


def forge_type3(peer_pub, mac1, receiver_index, cookie_plain, nonce_24):
    """Build a Type 3 cookie reply from PUBLIC material only.

    Inputs the attacker needs: the responder's static public key (peer_pub,
    not secret) and the 16-byte mac1 of an initiation we sent (readable off
    the wire).  No private key, no session key, no genuine cookie.
    """
    cookie_key = hashlib.blake2s(b"cookie--" + peer_pub, digest_size=32).digest()
    ct_tag = xchacha20poly1305_encrypt(cookie_key, nonce_24, cookie_plain, mac1)
    pkt = bytearray(64)
    pkt[0] = 3
    pkt[4:8] = receiver_index
    pkt[8:32] = nonce_24
    pkt[32:48] = ct_tag[:16]
    pkt[48:64] = ct_tag[16:]
    return bytes(pkt)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.rows = []

    def record(self, name, ok, detail):
        self.rows.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    def summary(self):
        bad = [r for r in self.rows if not r[1]]
        print(f"\n{'='*72}")
        print(f"{len(self.rows) - len(bad)}/{len(self.rows)} expectations met")
        print(f"{'='*72}")
        return len(bad)


def call_capturing_a(transport, addr, timeout=60.0):
    """JSR addr; STA RESULT_SLOT; RTS  -> returns the A register."""
    write_bytes(transport, TRAMPOLINE, bytes([
        0x20, addr & 0xFF, addr >> 8,
        0x8D, RESULT_SLOT & 0xFF, RESULT_SLOT >> 8,
        0x60,
    ]))
    write_bytes(transport, RESULT_SLOT, b'\xAA')   # poison: proves the store ran
    jsr(transport, TRAMPOLINE, timeout=timeout)
    return read_bytes(transport, RESULT_SLOT, 1)[0]


def read_jiffies(transport):
    """$A0 = hi, $A1 = mid, $A2 = lo."""
    hi, mid, lo = read_bytes(transport, 0x00A0, 3)
    return (hi << 16) | (mid << 8) | lo


def jiffies_bytes(v):
    v &= 0xFFFFFF
    return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def set_mac1_valid(transport, labels, value):
    """Set guard (b)'s flag, tolerating a tree where it does not exist yet.

    hs_mac1_valid is introduced by the #94 fix. Deliberately NOT in REQUIRED:
    aborting on the missing label would turn the pre-fix run into a startup
    error instead of a measurable red baseline. T1a reports its absence as
    the failure it is; everything else then runs and reports on its own terms.
    """
    if labels.address("hs_mac1_valid") is None:
        return
    write_bytes(transport, labels["hs_mac1_valid"], bytes([value]))


def deliver(transport, labels, pkt, state, timeout=120.0):
    """Put `pkt` in udp_recv_buf, set wg_state, run session_handle_packet."""
    write_bytes(transport, labels["wg_state"], bytes([state]))
    write_bytes(transport, labels["udp_recv_buf"], bytes(pkt))
    write_bytes(transport, labels["udp_recv_len"], struct.pack('<H', len(pkt)))
    write_bytes(transport, labels["udp_recv_ready"], bytes([1]))
    jsr(transport, labels["session_handle_packet"], timeout=timeout)


# ---------------------------------------------------------------------------
# T1 — guard (b): the post-load window, where the AAD is a public constant
# ---------------------------------------------------------------------------

def t1_post_load_window(transport, labels, res):
    """hs_packet is declared bss, but the PRG spans the file gap that covers
    APP_BSS and ld65 fills it, so at load hs_packet+116 (the cookie-reply AAD)
    and hs_sender_idx are sixteen and four ZERO bytes — values an attacker who
    has observed nothing at all can encrypt against.  Guard (b) is the only
    thing standing in that window, because guard (a) compares against an index
    that is itself the well-known zero.

    This must run FIRST: it is the only test that reads the machine's genuine
    boot state, and its own control then sets hs_mac1_valid.
    """
    aad = bytes(read_bytes(transport, labels["hs_packet"] + 116, 16))
    idx = bytes(read_bytes(transport, labels["hs_sender_idx"], 4))
    have_flag = labels.address("hs_mac1_valid") is not None
    flag = read_bytes(transport, labels["hs_mac1_valid"], 1)[0] if have_flag \
        else None
    res.record(
        "T1a boot state is the known-constant window, guard (b) present",
        aad == b'\x00' * 16 and idx == b'\x00' * 4 and flag == 0,
        f"hs_packet+116={aad.hex()} hs_sender_idx={idx.hex()} "
        + (f"hs_mac1_valid={flag}" if have_flag
           else "hs_mac1_valid: SYMBOL ABSENT — guard (b) is not implemented"),
    )

    # The attacker knows cfg_peer_pub (it is a public key) and nothing else.
    peer_pub = bytes(range(32))
    write_bytes(transport, labels["cfg_peer_pub"], peer_pub)

    cookie_plain = bytes(range(0x80, 0x90))
    pkt = forge_type3(peer_pub, b'\x00' * 16, b'\x00' * 4,
                      cookie_plain, bytes(range(24)))

    write_bytes(transport, labels["cookie_buf"], SENTINEL)
    write_bytes(transport, labels["cookie_valid"], bytes([0]))
    write_bytes(transport, labels["udp_recv_buf"], pkt)
    a = call_capturing_a(transport, labels["cookie_handle_type3"], timeout=120.0)
    valid = read_bytes(transport, labels["cookie_valid"], 1)[0]
    buf = bytes(read_bytes(transport, labels["cookie_buf"], 16))
    res.record(
        "T1b off-path forgery rejected before anything changes",
        a == 0xFF and valid == 0 and buf == SENTINEL,
        f"A={a:#04x} cookie_valid={valid} cookie_buf untouched={buf == SENTINEL}",
    )

    # ACCEPTANCE CONTROL — the ONLY thing that changes is hs_mac1_valid.
    # Without it T1b is vacuous: a build that rejected every Type 3, or a
    # forgery this script built wrongly, would look exactly like a fix.
    set_mac1_valid(transport, labels, 1)
    write_bytes(transport, labels["cookie_buf"], SENTINEL)
    write_bytes(transport, labels["cookie_valid"], bytes([0]))
    write_bytes(transport, labels["udp_recv_buf"], pkt)
    a = call_capturing_a(transport, labels["cookie_handle_type3"], timeout=120.0)
    valid = read_bytes(transport, labels["cookie_valid"], 1)[0]
    got = bytes(read_bytes(transport, labels["cookie_buf"], 16))
    res.record(
        "T1c control: identical packet accepted once hs_mac1_valid is set",
        a == 0 and valid == 1 and got == cookie_plain,
        f"A={a:#04x} cookie_valid={valid} "
        f"plaintext_recovered={got == cookie_plain}",
    )


# ---------------------------------------------------------------------------
# T2 — guard (a): cookie_handle_type3 must check receiver_index
# ---------------------------------------------------------------------------

def t2_receiver_index_checked(transport, labels, res):
    peer_pub = bytes(range(32))
    mac1 = bytes(range(0x40, 0x50))
    our_idx = bytes([0xAA, 0xBB, 0xCC, 0xDD])       # hs_sender_idx
    cookie_plain = bytes(range(0x80, 0x90))

    write_bytes(transport, labels["cfg_peer_pub"], peer_pub)
    write_bytes(transport, labels["hs_packet"] + 116, mac1)
    write_bytes(transport, labels["hs_sender_idx"], our_idx)
    set_mac1_valid(transport, labels, 1)             # guard (b) satisfied

    def attempt(recv_idx):
        pkt = forge_type3(peer_pub, mac1, recv_idx, cookie_plain,
                          bytes(range(24)))
        write_bytes(transport, labels["cookie_buf"], SENTINEL)
        write_bytes(transport, labels["cookie_valid"], bytes([0]))
        write_bytes(transport, labels["udp_recv_buf"], pkt)
        a = call_capturing_a(transport, labels["cookie_handle_type3"],
                             timeout=120.0)
        valid = read_bytes(transport, labels["cookie_valid"], 1)[0]
        buf = bytes(read_bytes(transport, labels["cookie_buf"], 16))
        return a, valid, buf

    a, valid, buf = attempt(bytes([0x11, 0x22, 0x33, 0x44]))
    res.record(
        "T2a wholly wrong receiver_index rejected",
        a == 0xFF and valid == 0 and buf == SENTINEL,
        f"receiver_index=11223344 vs hs_sender_idx={our_idx.hex()}: "
        f"A={a:#04x} cookie_valid={valid} "
        f"cookie_buf untouched={buf == SENTINEL} (untouched means the reject "
        f"lands before the ciphertext copy, i.e. before any crypto is paid)",
    )

    # Every byte must be compared. A one-byte compare would still pass T2a.
    for i in range(4):
        bad = bytearray(our_idx)
        bad[i] ^= 0x01
        a, valid, _ = attempt(bytes(bad))
        res.record(
            f"T2b one-byte mismatch at receiver_index[{i}] rejected",
            a == 0xFF and valid == 0,
            f"{bytes(bad).hex()} vs {our_idx.hex()}: A={a:#04x} "
            f"cookie_valid={valid}",
        )

    # ACCEPTANCE CONTROL — same packet, matching index.
    a, valid, got = attempt(our_idx)
    res.record(
        "T2c control: matching receiver_index accepted",
        a == 0 and valid == 1 and got == cookie_plain,
        f"A={a:#04x} cookie_valid={valid} "
        f"plaintext_recovered={got == cookie_plain} (so the rejections above "
        f"are the index check, not a broken AEAD)",
    )


# ---------------------------------------------------------------------------
# T3 — guard (c): the Type 3 dispatch is gated on wg_state
# ---------------------------------------------------------------------------

def _t3_packet(transport, labels):
    """A Type 3 with BOTH cookie.s preconditions satisfied and a corrupt tag.

    Satisfying (a) and (b) is the point: whatever stops this packet cannot be
    guard (a) or (b), so T3/T6 measure guard (c) alone.  The corrupt tag means
    that even on the unfixed tree the handler returns $FF and session.s
    @cookie_fail rts's without running session_initiate, so the test costs
    milliseconds in both worlds.
    """
    peer_pub = bytes(range(32))
    mac1 = bytes(range(0x40, 0x50))
    our_idx = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    write_bytes(transport, labels["cfg_peer_pub"], peer_pub)
    write_bytes(transport, labels["hs_packet"] + 116, mac1)
    write_bytes(transport, labels["hs_sender_idx"], our_idx)
    set_mac1_valid(transport, labels, 1)

    pkt = bytearray(forge_type3(peer_pub, mac1, our_idx,
                                bytes(range(0x80, 0x90)), bytes(range(24))))
    ciphertext = bytes(pkt[32:48])
    pkt[48] ^= 0xFF                      # corrupt the tag -> AEAD must reject
    return bytes(pkt), ciphertext


def t3_dispatch_gated_in_active(transport, labels, res):
    """Does session_handle_packet reach cookie_handle_type3's BODY?

    cookie_buf is loaded with a sentinel; the handler overwrites it with the
    packet ciphertext (src/wg/cookie.s, the copy at @copy_edata) BEFORE
    aead_decrypt, so the sentinel answers "was the body entered?" on its own.
    """
    pkt, ciphertext = _t3_packet(transport, labels)

    def dispatch(state):
        write_bytes(transport, labels["cookie_buf"], SENTINEL)
        write_bytes(transport, labels["cookie_valid"], bytes([0]))
        deliver(transport, labels, pkt, state)
        return (bytes(read_bytes(transport, labels["cookie_buf"], 16)),
                read_bytes(transport, labels["wg_state"], 1)[0])

    after, state = dispatch(2)                                   # ACTIVE
    res.record(
        "T3a Type 3 does NOT reach the handler body while ACTIVE",
        after == SENTINEL and state == 2,
        f"cookie_buf stayed {after[:4].hex()}.. "
        f"(sentinel intact={after == SENTINEL}), wg_state = {state} "
        f"(2 = session untouched)",
    )

    # ACCEPTANCE CONTROL — identical packet, identical preconditions, only
    # wg_state differs. Without this, T3a would also pass on a build that had
    # simply broken the Type 3 dispatch outright.
    after, state = dispatch(1)                                   # HS_SENT
    res.record(
        "T3b control: the same packet DOES reach the body in HS_SENT",
        after == ciphertext and state == 1,
        f"cookie_buf {SENTINEL[:4].hex()}.. -> {after[:4].hex()}.. "
        f"(== packet ciphertext: {after == ciphertext}); wg_state = {state} "
        f"(1 = the corrupt tag sent it down @cookie_fail, as designed)",
    )

    # Control: a Type 4 in HS_SENT must NOT reach the transport path — shows
    # the sentinel technique detects a gate when one is present.
    write_bytes(transport, labels["cookie_buf"], SENTINEL)
    t4 = bytearray(48)
    t4[0] = 4
    deliver(transport, labels, bytes(t4), 1, timeout=60.0)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    res.record(
        "T3c control: Type 4 IS gated in HS_SENT",
        state == 1,
        f"wg_state {state} (1 = unchanged, gate held)",
    )


# ---------------------------------------------------------------------------
# T4 — #95 "no timeout": is HS_SENT really unbounded?
# ---------------------------------------------------------------------------

def t4_handshake_deadline(transport, labels, res):
    write_bytes(transport, labels["wg_state"], bytes([1]))       # HS_SENT
    write_bytes(transport, labels["hs_timer_armed"], bytes([1]))

    now = read_jiffies(transport)
    # 6000 jiffies = 100 s > HS_TIMEOUT_JIFFIES (5400 = 90 s)
    write_bytes(transport, labels["session_start_jiffy"],
                jiffies_bytes(now - 6000))

    jsr(transport, labels["timer_check"], timeout=60.0)

    state = read_bytes(transport, labels["wg_state"], 1)[0]
    armed = read_bytes(transport, labels["hs_timer_armed"], 1)[0]
    fired = (state == 0 and armed == 0)
    res.record(
        "T4 HS_SENT past the 90 s deadline is reclaimed",
        fired,
        f"elapsed 6000 jiffies (100 s): wg_state 1 -> {state}, "
        f"hs_timer_armed 1 -> {armed}"
        + ("  -> #95's 'no timeout' clause is FALSE"
           if fired else "  -> no timeout fired; #95's clause holds"),
    )

    # Negative control: inside the deadline nothing happens.
    write_bytes(transport, labels["wg_state"], bytes([1]))
    write_bytes(transport, labels["hs_timer_armed"], bytes([1]))
    now = read_jiffies(transport)
    write_bytes(transport, labels["session_start_jiffy"],
                jiffies_bytes(now - 600))          # 10 s, well inside 90 s
    jsr(transport, labels["timer_check"], timeout=60.0)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    res.record(
        "T4c control: inside the deadline HS_SENT survives",
        state == 1,
        f"elapsed 600 jiffies (10 s): wg_state = {state} (1 = survived)",
    )


# ---------------------------------------------------------------------------
# T5 — #95 "no retry": after the deadline, does anything re-initiate?
# ---------------------------------------------------------------------------

def t5_no_automatic_retry(transport, labels, res):
    write_bytes(transport, labels["wg_state"], bytes([0]))       # IDLE
    write_bytes(transport, labels["hs_timer_armed"], bytes([0]))
    before = bytes(read_bytes(transport, labels["hs_packet"], 16))

    for _ in range(50):
        jsr(transport, labels["timer_check"], timeout=30.0)

    state = read_bytes(transport, labels["wg_state"], 1)[0]
    after = bytes(read_bytes(transport, labels["hs_packet"], 16))
    stuck = (state == 0 and after == before)
    res.record(
        "T5 no automatic retry out of IDLE",
        stuck,
        f"50 x timer_check: wg_state = {state}, "
        f"hs_packet unchanged={after == before}"
        + ("  -> #95's 'no retry' clause is TRUE (and is a documented"
           " design choice at src/wg/timer.s)" if stuck else ""),
    )


# ---------------------------------------------------------------------------
# T6 — guard (c) in every state, not just ACTIVE
# ---------------------------------------------------------------------------

def t6_type3_gated_in_every_state(transport, labels, res):
    pkt, ciphertext = _t3_packet(transport, labels)

    for state, label, expect_entered in ((0, "IDLE", False),
                                         (1, "HS_SENT", True),
                                         (2, "ACTIVE", False)):
        write_bytes(transport, labels["cookie_buf"], SENTINEL)
        write_bytes(transport, labels["cookie_valid"], bytes([0]))
        deliver(transport, labels, pkt, state)
        entered = bytes(read_bytes(transport, labels["cookie_buf"], 16)) \
            != SENTINEL
        res.record(
            f"T6 Type 3 reaches cookie_handle_type3 in {label}: "
            f"{'yes' if expect_entered else 'no'}",
            entered == expect_entered,
            f"wg_state={state}: handler entered = {entered} "
            f"(expected {expect_entered})",
        )


# ---------------------------------------------------------------------------
# T7 — the headline #94 claim, inverted: one packet must NOT kill a session
# ---------------------------------------------------------------------------

def _valid_type3_for_active(transport, labels):
    """A Type 3 that is valid in EVERY respect the code can check: correct
    receiver_index, hs_mac1_valid set, intact tag.  On the unfixed tree this
    is exactly the packet that ran session_initiate from ACTIVE.
    """
    peer_pub = bytes(range(32))
    mac1 = bytes(range(0x40, 0x50))
    our_idx = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    write_bytes(transport, labels["cfg_peer_pub"], peer_pub)
    write_bytes(transport, labels["hs_packet"] + 116, mac1)
    write_bytes(transport, labels["hs_sender_idx"], our_idx)
    set_mac1_valid(transport, labels, 1)
    write_bytes(transport, labels["hs_resp_pub"], bytes(range(64, 96)))
    write_bytes(transport, labels["cookie_valid"], bytes([0]))
    write_bytes(transport, labels["cookie_buf"], SENTINEL)
    pkt = forge_type3(peer_pub, mac1, our_idx, bytes(range(0x80, 0x90)),
                      bytes(range(24)))
    return pkt, mac1


def _active_session_survives(transport, labels, res, tag, timeout):
    pkt, mac1 = _valid_type3_for_active(transport, labels)
    try:
        deliver(transport, labels, pkt, 2, timeout=timeout)
    except (HarnessTimeoutError, TimeoutError) as exc:
        res.record(
            f"{tag} forged Type 3 leaves an ACTIVE session alone",
            False,
            f"session_handle_packet did not return within {timeout:.0f}s "
            f"({exc}) — on the unfixed tree this is session_initiate running "
            f"3 X25519 scalarmults, i.e. the bug",
        )
        return

    state = read_bytes(transport, labels["wg_state"], 1)[0]
    valid = read_bytes(transport, labels["cookie_valid"], 1)[0]
    buf = bytes(read_bytes(transport, labels["cookie_buf"], 16))
    aad = bytes(read_bytes(transport, labels["hs_packet"] + 116, 16))
    res.record(
        f"{tag} forged Type 3 leaves an ACTIVE session alone",
        state == 2 and valid == 0 and buf == SENTINEL,
        f"wg_state = {state} (2 = ACTIVE, survived), cookie_valid = {valid}, "
        f"cookie_buf untouched = {buf == SENTINEL}",
    )
    # The escalation hinge: no fresh initiation means no fresh mac1 on the
    # wire, so an observer gains nothing to build the next forgery from.
    res.record(
        f"{tag} the AAD is not regenerated (escalation chain broken)",
        aad == mac1,
        f"hs_packet+116 {mac1.hex()} -> {aad.hex()} (unchanged={aad == mac1})",
    )


def t7_active_session_survives_fast(transport, labels, res):
    _active_session_survives(transport, labels, res, "T7", T7_TIMEOUT)


# ---------------------------------------------------------------------------
# S1 — as T7, but paying in full for the regression path if it exists  (SLOW)
# ---------------------------------------------------------------------------

def s1_active_session_survives_slow(transport, labels, res):
    print("    (on a REGRESSED tree this runs session_initiate: 3x X25519"
          " under VICE warp, expect hours. On a fixed tree: milliseconds.)")
    _active_session_survives(transport, labels, res, "S1", SLOW_TIMEOUT)


# ---------------------------------------------------------------------------
# S2 — #95 core: does a forged Type 2 destroy hs_c / hs_h?   (SLOW)
# ---------------------------------------------------------------------------

def s2_forged_type2_destroys_chain(transport, labels, res):
    c_sentinel = bytes([(i * 7 + 1) & 0xFF for i in range(32)])
    h_sentinel = bytes([(i * 11 + 3) & 0xFF for i in range(32)])
    our_idx = bytes([0xAA, 0xBB, 0xCC, 0xDD])

    write_bytes(transport, labels["hs_c"], c_sentinel)
    write_bytes(transport, labels["hs_h"], h_sentinel)
    write_bytes(transport, labels["hs_sender_idx"], our_idx)
    write_bytes(transport, labels["hs_ephem_priv"], bytes(range(32)))
    write_bytes(transport, labels["hs_static_priv"], bytes(range(32, 64)))
    write_bytes(transport, labels["wg_state"], bytes([1]))       # HS_SENT
    write_bytes(transport, labels["hs_timer_armed"], bytes([1]))
    jsr(transport, labels["timer_handshake_start"], timeout=30.0)

    # A forged Type 2: 92 bytes of attacker-chosen material.  receiver_index
    # is deliberately NOT hs_sender_idx.  Nothing here is authenticated.
    forged = bytearray(92)
    forged[0] = 2
    forged[4:8] = bytes([0xDE, 0xAD, 0xBE, 0xEF])    # responder's sender_index
    forged[8:12] = bytes([0x99, 0x99, 0x99, 0x99])   # receiver_index: WRONG
    forged[12:44] = bytes([(i * 3 + 5) & 0xFF for i in range(32)])  # ephemeral
    forged[44:60] = b'\xFF' * 16                     # bogus AEAD tag

    print("    (running hs_process_response: 2x X25519 under VICE warp,"
          " expect hours)")
    deliver(transport, labels, bytes(forged), 1, timeout=SLOW_TIMEOUT)

    c_after = bytes(read_bytes(transport, labels["hs_c"], 32))
    h_after = bytes(read_bytes(transport, labels["hs_h"], 32))
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    armed = read_bytes(transport, labels["hs_timer_armed"], 1)[0]

    res.record(
        "S2 forged Type 2 mutates hs_c before the AEAD rejects it",
        c_after != c_sentinel,
        f"hs_c {c_sentinel[:8].hex()} -> {c_after[:8].hex()} "
        f"(changed={c_after != c_sentinel}) — #95, still open",
    )
    res.record(
        "S2 forged Type 2 mutates hs_h before the AEAD rejects it",
        h_after != h_sentinel,
        f"hs_h {h_sentinel[:8].hex()} -> {h_after[:8].hex()} "
        f"(changed={h_after != h_sentinel}) — #95, still open",
    )
    res.record(
        "S2 resulting wg_state",
        True,
        f"wg_state = {state} (0 = IDLE via session_reset; #95 claims it stays"
        f" at 1 = HS_SENT), hs_timer_armed = {armed}",
    )


# ---------------------------------------------------------------------------
# S3 — #94 escalation, inverted: a blocked kill emits nothing new  (SLOW)
# ---------------------------------------------------------------------------

def s3_escalation_chain_broken(transport, labels, res):
    """On 46a0c99 each kill made the C64 build and emit a FRESH Type 1 whose
    mac1 a passive observer read off the wire — precisely the AAD for the next
    forgery, so the DoS was self-sustaining at 3 scalarmults per 64-byte
    attacker packet.  Assert the hinge is gone: nothing is emitted, so the AAD
    the attacker already has stays the only one, and a second forgery built
    from it is stopped by the same guards.
    """
    pkt, mac1_a = _valid_type3_for_active(transport, labels)
    print("    (on a REGRESSED tree kill #1 runs session_initiate: 3x X25519)")
    deliver(transport, labels, pkt, 2, timeout=SLOW_TIMEOUT)

    mac1_b = bytes(read_bytes(transport, labels["hs_packet"] + 116, 16))
    res.record(
        "S3 the blocked kill does not regenerate the AAD",
        mac1_b == mac1_a,
        f"hs_packet+116 {mac1_a.hex()} -> {mac1_b.hex()} "
        f"(unchanged={mac1_b == mac1_a}: no fresh Type 1 went on the wire)",
    )

    # A second attempt, in ACTIVE, from the AAD the observer already holds.
    write_bytes(transport, labels["cookie_valid"], bytes([0]))
    write_bytes(transport, labels["cookie_buf"], SENTINEL)
    pkt2 = forge_type3(bytes(range(32)), mac1_b,
                       bytes(read_bytes(transport, labels["hs_sender_idx"], 4)),
                       bytes(range(0x20, 0x30)), bytes(range(100, 124)))
    deliver(transport, labels, pkt2, 2, timeout=SLOW_TIMEOUT)
    state = read_bytes(transport, labels["wg_state"], 1)[0]
    valid = read_bytes(transport, labels["cookie_valid"], 1)[0]
    res.record(
        "S3 kill #2 blocked as well",
        state == 2 and valid == 0,
        f"wg_state = {state} (2 = still ACTIVE), cookie_valid = {valid}",
    )


# ---------------------------------------------------------------------------

FAST = [
    ("T1", t1_post_load_window),          # must stay first: reads boot state
    ("T2", t2_receiver_index_checked),
    ("T3", t3_dispatch_gated_in_active),
    ("T4", t4_handshake_deadline),
    ("T5", t5_no_automatic_retry),
    ("T6", t6_type3_gated_in_every_state),
    ("T7", t7_active_session_survives_fast),
]
SLOW = [
    ("S1", s1_active_session_survives_slow),
    ("S2", s2_forged_type2_destroys_chain),
    ("S3", s3_escalation_chain_broken),
]

REQUIRED = [
    "session_handle_packet", "session_reset", "session_initiate",
    "cookie_handle_type3", "cookie_buf", "cookie_valid",
    "timer_check", "timer_handshake_start", "hs_timer_armed",
    "session_start_jiffy", "wg_state", "hs_c", "hs_h", "hs_packet",
    "hs_sender_idx", "hs_ephem_priv", "hs_static_priv",
    "hs_resp_pub", "cfg_peer_pub", "udp_recv_buf", "udp_recv_len",
    "udp_recv_ready",
]


def main():
    args = sys.argv[1:]
    slow = "--slow" in args
    only = None
    if "--only" in args:
        only = args[args.index("--only") + 1]

    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        cmd = ["make"]
        # Honour C64_REU the way the live tools do: the #94 fix adds 33 bytes
        # of APP_CODE, which at REU=1 pushes MAIN_AREA_LO past the align=$100
        # boundary and overflows it by 42 bytes (issue #103). REU=0 links.
        if os.environ.get("C64_REU") is not None:
            cmd.append(f"REU={os.environ['C64_REU']}")
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
            sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing from {LABELS_PATH}: {missing}")
        sys.exit(1)
    print(f"Labels OK ({len(REQUIRED)} required)")

    groups = list(FAST) + (list(SLOW) if slow else [])
    if only:
        groups = [g for g in groups if g[0] == only]
        if not groups:
            print(f"FATAL: no group named {only}")
            sys.exit(1)

    res = Results()
    # REU cartridge + post-takeover reu_mul_init, as tools/test_type2_slow.py
    # does.  A REU=1 build without these gets open-bus garbage out of
    # fe25519's REU row fetches.  Harmless on a REU=0 build (the label is
    # absent and the cartridge simply goes unused).
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if binary_wait_for_boot_ready(transport, labels, timeout=300.0) is None:
            print("FATAL: boot_ready never set")
            sys.exit(1)
        write_bytes(transport, IDLE_LOOP, bytes([0x4C, 0x39, 0x03]))
        if "reu_mul_init" in labels:
            jsr(transport, labels["reu_mul_init"], timeout=180.0)
        print("VICE ready.\n")

        for name, fn in groups:
            print(f"--- {name} ---")
            fn(transport, labels, res)
            print()

        mgr.release(inst)

    sys.exit(1 if res.summary() else 0)


if __name__ == "__main__":
    main()
