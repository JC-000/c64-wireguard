#!/usr/bin/env python3
"""test_replay_window.py -- Sliding window replay protection tests.

Tests the 2048-bit sliding window replay protection in transport_decrypt.
Verifies acceptance/rejection of packets based on counter values, duplicates,
out-of-order delivery, and window boundary conditions.

Usage:
    python3 tools/test_replay_window.py [--seed S] [--verbose]
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

VERBOSE = False


# ============================================================================
# Python reference helpers
# ============================================================================

def py_encrypt(key, counter_val, plaintext):
    """Encrypt using ChaCha20-Poly1305 with WireGuard transport nonce."""
    nonce = b'\x00' * 4 + struct.pack('<Q', counter_val)
    aead = ChaCha20Poly1305(key)
    ct_and_tag = aead.encrypt(nonce, plaintext, None)
    return ct_and_tag[:-16], ct_and_tag[-16:]


def build_type4_packet(receiver_idx, counter_val, key, plaintext):
    """Build a complete Type 4 packet using Python crypto."""
    ct, tag = py_encrypt(key, counter_val, plaintext)
    header = struct.pack('<I', 4)
    header += receiver_idx
    header += struct.pack('<Q', counter_val)
    return header + ct + tag


def reset_recv_state(transport, labels):
    """Reset all receive/replay state."""
    write_bytes(transport, labels["tp_recv_counter"], bytes(8))
    write_bytes(transport, labels["rw_counter_max"], bytes(8))
    write_bytes(transport, labels["rw_bitmap"], bytes(256))


def send_and_check(transport, labels, key, counter_val, plaintext,
                   expect_accept, desc):
    """Send a packet and check whether it was accepted or rejected.

    Accept/reject is read from ``transport_decrypt``'s own return value
    (A = 0 success, A = $FF failure), not inferred from side effects, and
    cross-checked against what the packet actually did:

      * an accepted counter must be recorded in the bitmap, or the next
        copy of it would be accepted too;
      * the plaintext must appear at ``tp_packet+16`` if and only if the
        packet was accepted.  ``tp_packet+16`` is pre-stamped with a
        sentinel before every call, so "the payload was delivered a second
        time" -- the actual harm in #86 -- is observed rather than argued.

    The plaintext half is decisive only for rejections that happen before
    the AEAD runs, which is every rejection this suite produces: all its
    packets carry valid tags, so the only rejections are replay-window
    rejections, and those return before the ciphertext is ever copied.

    Inference cannot see the bug in #86.  The old check treated "counter
    was <= old max and rw_counter_max did not move" as proof of a
    rejection -- but rw_counter_max never moves for a counter below the
    max whether it was accepted or rejected, so every replay of an old
    counter passed unconditionally.  Test 10 below was written to catch
    exactly this defect and could not fail.

    Returns (passed, failed) tuple.
    """
    packet = build_type4_packet(b'\x01\x00\x00\x00', counter_val, key,
                                plaintext)
    write_bytes(transport, labels["udp_recv_buf"], packet)
    write_bytes(transport, labels["udp_recv_len"],
                struct.pack('<H', len(packet)))

    # Read rw_counter_max before decrypt to detect changes
    old_max = read_bytes(transport, labels["rw_counter_max"], 8)

    # Stamp the in-place decrypt buffer so payload delivery is observable.
    sentinel = bytes((0xA5 ^ i) & 0xFF for i in range(len(plaintext)))
    write_bytes(transport, labels["tp_packet"] + 16, sentinel)

    # For within-window packets, check the specific bitmap bit
    counter_low11 = counter_val & 0x7FF
    byte_offset = counter_low11 >> 3
    bit_index = counter_low11 & 7

    regs = jsr(transport, labels["transport_decrypt"], timeout=60.0)
    accepted = (regs["A"] == 0)
    delivered = (read_bytes(transport, labels["tp_packet"] + 16,
                            len(plaintext)) == plaintext)

    # Check result: read rw_counter_max and the bitmap bit
    new_max = read_bytes(transport, labels["rw_counter_max"], 8)
    bm_byte = read_bytes(transport, labels["rw_bitmap"] + byte_offset, 1)[0]
    bit_set = bool(bm_byte & (1 << bit_index))

    # Determine if accepted: either max advanced or bitmap bit got set
    expected_max = struct.pack('<Q', counter_val)
    new_max_val = int.from_bytes(new_max, 'little')
    old_max_val = int.from_bytes(old_max, 'little')

    if accepted == expect_accept:
        # Side-effect cross-check: an accepted counter must be recorded
        # in the bitmap, or the next copy of it would be accepted too.
        if accepted and not bit_set:
            print(f"  FAIL {desc}: accepted but bitmap bit not set "
                  f"(counter={counter_val}, byte={byte_offset}, "
                  f"bit={bit_index})")
            return 0, 1
        if delivered != accepted:
            print(f"  FAIL {desc}: transport_decrypt returned "
                  f"${regs['A']:02X} but the plaintext was "
                  f"{'delivered' if delivered else 'not delivered'} to "
                  f"tp_packet+16 (counter={counter_val})")
            return 0, 1
        if VERBOSE:
            print(f"  PASS {desc}")
        return 1, 0

    print(f"  FAIL {desc}: expected "
          f"{'accept' if expect_accept else 'reject'} but transport_decrypt "
          f"returned ${regs['A']:02X} ({'accept' if accepted else 'reject'})")
    print(f"    counter={counter_val}, old_max={old_max_val}, "
          f"new_max={new_max_val}, bitmap byte {byte_offset} bit "
          f"{bit_index} = {int(bit_set)}, plaintext "
          f"{'DELIVERED' if delivered else 'not delivered'}")
    return 0, 1


# ============================================================================
# Test groups
# ============================================================================

def test_sequential_accepted(transport, labels, key, plaintext):
    """Test 1: Sequential packets 0,1,2,3 all accepted."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for i in range(4):
        p, f = send_and_check(transport, labels, key, i, plaintext,
                              True, f"sequential: counter={i} accepted")
        passed += p
        failed += f

    return passed, failed


def test_duplicate_rejected(transport, labels, key, plaintext):
    """Test 2: Duplicate packet rejected."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept counter=0
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "dup: counter=0 first accepted")
    passed += p
    failed += f

    # Reject counter=0 again
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "dup: counter=0 second rejected")
    passed += p
    failed += f

    return passed, failed


def test_out_of_order_accepted(transport, labels, key, plaintext):
    """Test 3: Out-of-order within window accepted."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Send 0, 5, 3
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "ooo: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 5, plaintext,
                          True, "ooo: counter=5 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 3, plaintext,
                          True, "ooo: counter=3 accepted (within window)")
    passed += p
    failed += f

    return passed, failed


def test_out_of_order_replay_rejected(transport, labels, key, plaintext):
    """Test 4: Out-of-order replay rejected."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for c in [0, 5, 3]:
        p, f = send_and_check(transport, labels, key, c, plaintext,
                              True, f"ooo-replay setup: counter={c}")
        passed += p
        failed += f

    # Now counter=3 again should be rejected
    p, f = send_and_check(transport, labels, key, 3, plaintext,
                          False, "ooo-replay: counter=3 duplicate rejected")
    passed += p
    failed += f

    return passed, failed


def test_large_gap_advances(transport, labels, key, plaintext):
    """Test 5: Large gap advances window."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "gap: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 2000, plaintext,
                          True, "gap: counter=2000 accepted (big jump)")
    passed += p
    failed += f

    # Verify rw_counter_max is 2000
    max_val = int.from_bytes(
        read_bytes(transport, labels["rw_counter_max"], 8), 'little')
    if max_val == 2000:
        passed += 1
        if VERBOSE:
            print("  PASS gap: rw_counter_max=2000")
    else:
        failed += 1
        print(f"  FAIL gap: rw_counter_max={max_val}, expected 2000")

    return passed, failed


def test_old_outside_window_rejected(transport, labels, key, plaintext):
    """Test 6: Old packets outside window rejected after big advance."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept counter=0
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "outside: counter=0 accepted")
    passed += p
    failed += f

    # Advance to counter=2048 (delta=2048 from 0, so 0 is now outside window)
    p, f = send_and_check(transport, labels, key, 2048, plaintext,
                          True, "outside: counter=2048 accepted")
    passed += p
    failed += f

    # Counter=0 should now be rejected (delta=2048 from max, outside window)
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "outside: counter=0 rejected (outside window)")
    passed += p
    failed += f

    return passed, failed


def test_edge_delta_2047_accepted(transport, labels, key, plaintext):
    """Test 7: Edge case delta=2047 is accepted (within window)."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Set max to 2047 by sending counter=2047
    p, f = send_and_check(transport, labels, key, 2047, plaintext,
                          True, "edge-2047: counter=2047 accepted")
    passed += p
    failed += f

    # Send counter=0: delta = 2047 - 0 = 2047, should be within window
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "edge-2047: counter=0 accepted (delta=2047)")
    passed += p
    failed += f

    return passed, failed


def test_edge_delta_2048_rejected(transport, labels, key, plaintext):
    """Test 8: Edge case delta=2048 is rejected (outside window)."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Set max to 2048 by sending counter=2048
    p, f = send_and_check(transport, labels, key, 2048, plaintext,
                          True, "edge-2048: counter=2048 accepted")
    passed += p
    failed += f

    # Send counter=0: delta = 2048 - 0 = 2048, should be outside window
    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          False, "edge-2048: counter=0 rejected (delta=2048)")
    passed += p
    failed += f

    return passed, failed


def test_backfill_pattern(transport, labels, key, plaintext):
    """Test 9: Backfill pattern -- accept then reject duplicate."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    p, f = send_and_check(transport, labels, key, 0, plaintext,
                          True, "backfill: counter=0 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 100, plaintext,
                          True, "backfill: counter=100 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 50, plaintext,
                          True, "backfill: counter=50 accepted")
    passed += p
    failed += f

    p, f = send_and_check(transport, labels, key, 50, plaintext,
                          False, "backfill: counter=50 duplicate rejected")
    passed += p
    failed += f

    return passed, failed


def test_window_advance_preserves_old_bits(transport, labels, key, plaintext):
    """Test 10: Window advance preserves bits of previously seen packets."""
    passed = failed = 0
    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    # Accept 0, 1, 2
    for c in [0, 1, 2]:
        p, f = send_and_check(transport, labels, key, c, plaintext,
                              True, f"preserve: counter={c} accepted")
        passed += p
        failed += f

    # Advance to 5
    p, f = send_and_check(transport, labels, key, 5, plaintext,
                          True, "preserve: counter=5 accepted (advance)")
    passed += p
    failed += f

    # Counter=1 should still be rejected (bit preserved from earlier)
    p, f = send_and_check(transport, labels, key, 1, plaintext,
                          False, "preserve: counter=1 rejected (already seen)")
    passed += p
    failed += f

    return passed, failed


def bitmap_bit(bitmap, position):
    """Return the bitmap bit (0/1) recording counter *position*."""
    position &= 0x7FF
    return (bitmap[position >> 3] >> (position & 7)) & 1


def test_sequential_traffic_replays_rejected(transport, labels, key,
                                             plaintext):
    """Test 11 (#86): ordinary sequential traffic must stay protected.

    Receive counters 0..7 in order, then replay every one of them.  All
    eight replays must be rejected.

    This is the case that shows the severity without reading the
    algorithm.  Each advance of a single counter cleared the whole byte
    the previous counter lived in, so only the current rw_counter_max
    stayed protected -- a 2048-counter window behaving as a window of
    one.  On master 0..6 are each accepted a second time and their
    payloads delivered again; only counter 7, the newest, is rejected.
    """
    passed = failed = 0

    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for counter in range(8):
        p, f = send_and_check(transport, labels, key, counter, plaintext,
                              True, f"sequential-8: counter={counter} "
                                    f"accepted")
        passed += p
        failed += f

    for counter in range(8):
        p, f = send_and_check(transport, labels, key, counter, plaintext,
                              False, f"sequential-8: counter={counter} "
                                     f"replay rejected (window is 2048, "
                                     f"max is 7)")
        passed += p
        failed += f

    return passed, failed


def test_advance_across_bitmap_wraparound(transport, labels, key, plaintext):
    """Test 13 (#86): the bit walk must wrap byte 255 -> byte 0 correctly.

    The bitmap is 256 bytes covering 2048 counters, so position 2047 is the
    last bit of byte 255 and position 2048 is bit 0 of byte 0. The clearing
    walk relies on Y wrapping naturally at 256 to follow that.

    Reached through the packet path only -- no direct write to
    rw_counter_max. A fresh window cannot get here in one step, because any
    counter high enough to put the cursor near 2047 is also more than 256
    away from 0, so the shift takes @clear_all. But the FIRST packet moves
    the cursor, and the ones after it can then take small shifts:

        2040  shift 2040 -> @clear_all, max = 2040, bit 2040 set
        2041  shift 1    -> first bit walk;  byte 255 = $03
        2050  shift 9    -> clears 2042..2050, crossing byte 255 -> byte 0

    That matters beyond tidiness: it demonstrates a real peer can produce
    this state, rather than asserting on one the protocol might never reach.

    Expected end state, derived from the sequence above and confirmed on
    both trees: byte 255 = $03 (2040 and 2041 preserved -- both at or below
    old_max and inside the window), byte 0 = $04 (the stale bits cleared
    through the wrap, 2050's own bit set).
    """
    passed = failed = 0

    reset_recv_state(transport, labels)
    write_bytes(transport, labels["hs_transport_recv"], key)

    for counter, note in ((2040, "shift 2040 -> @clear_all"),
                          (2041, "shift 1 -> first bit walk")):
        p, f = send_and_check(transport, labels, key, counter, plaintext,
                              True, f"wrap: counter={counter} accepted "
                                    f"({note})")
        passed += p
        failed += f

    # SYNTHETIC, and deliberately so. Bits 2048/2049 belong to the previous
    # lap of the window; reaching one genuinely needs 2048+ counters, which
    # no test here can afford. Without them set, "the advance cleared
    # forward across the wrap" would pass on an implementation that clears
    # nothing forward at all -- the same vacuity that let #86 survive a
    # green suite. Bit 2050 is included so the whole 9-bit range must be
    # cleared before 2050's own bit is re-set.
    #
    # The asymmetry is real and worth naming: the packet route buys
    # reachability for the PRESERVATION half (byte 255) and cannot buy it
    # for the FORWARD half (byte 0). A labelled synthetic preload is the
    # only way to give that assertion teeth.
    write_bytes(transport, labels["rw_bitmap"], bytes([0x07]))

    p, f = send_and_check(transport, labels, key, 2050, plaintext, True,
                          "wrap: counter=2050 accepted (shift 9, crosses "
                          "byte 255 -> byte 0)")
    passed += p
    failed += f

    if f == 0:
        bitmap = read_bytes(transport, labels["rw_bitmap"], 256)

        if bitmap[255] == 0x03:
            passed += 1
            if VERBOSE:
                print("  PASS wrap: byte 255 = $03, counters 2040 and 2041 "
                      "preserved")
        else:
            failed += 1
            print(f"  FAIL wrap: byte 255 = ${bitmap[255]:02X}, expected $03 "
                  f"-- counters 2040 and 2041 are at/below old_max and still "
                  f"inside the window, so whichever bit was dropped is now "
                  f"replayable")

        if bitmap[0] == 0x04:
            passed += 1
            if VERBOSE:
                print("  PASS wrap: byte 0 = $04, stale bits cleared through "
                      "the wrap and 2050 recorded")
        else:
            failed += 1
            print(f"  FAIL wrap: byte 0 = ${bitmap[0]:02X}, expected $04 -- "
                  f"the walk did not clear the preloaded stale bits across "
                  f"the byte 255 -> 0 boundary, or did not record 2050")

    # --- functional: both preserved counters must refuse a replay ---
    for counter in (2040, 2041):
        p, f = send_and_check(transport, labels, key, counter, plaintext,
                              False, f"wrap-replay: counter={counter} replay "
                                     f"rejected (max is 2050)")
        passed += p
        failed += f

    return passed, failed


def test_replay_after_advance_all_residues(transport, labels, key, plaintext):
    """Test 11 (#86): advancing the window must not erase what it has seen.

    Receive n, receive a later counter, replay n -- the replay must be
    rejected.  The advance used to clear whole BYTES starting at the byte
    holding (old_max+1); that byte also holds the bits of
    (old_max+1) & ~7 .. old_max, counters already received and still
    inside the 2048 window.

    All eight residues of n mod 8 are covered rather than a sample:
    residue 7 is the single case the byte-clearing code got right (n and
    n+1 fall in different bytes), so a sampled test can miss the defect
    entirely.
    """
    passed = failed = 0

    for residue in range(8):
        n = 16 + residue          # inside the window, off the origin
        reset_recv_state(transport, labels)
        write_bytes(transport, labels["hs_transport_recv"], key)

        p, f = send_and_check(transport, labels, key, n, plaintext, True,
                              f"residue {residue}: counter={n} accepted")
        passed += p
        failed += f

        p, f = send_and_check(transport, labels, key, n + 1, plaintext, True,
                              f"residue {residue}: counter={n + 1} accepted "
                              f"(advances the window past {n})")
        passed += p
        failed += f

        p, f = send_and_check(transport, labels, key, n, plaintext, False,
                              f"residue {residue}: counter={n} replay "
                              f"rejected")
        passed += p
        failed += f

    return passed, failed


def test_advance_clears_exact_range(transport, labels, key, plaintext):
    """Test 12 (#86): the advance must clear exactly (old_max, new_max].

    The bitmap is preloaded with all-ones -- "every counter in the window
    has been seen" -- and the window is then advanced by `shift` from
    max = 0.  Reading the bitmap back separates the two defects:

      * bit 0 records counter 0, which is at old_max and still inside the
        window.  Clearing the whole start byte erases it.
      * bits 1..shift-1 are the newly exposed range and must be cleared.
        The old count was (shift + 7) >> 3 with the carry out of the ADC
        discarded, so shift 249..255 wrapped to a count of 0 and cleared
        nothing at all while rw_counter_max advanced anyway -- leaving
        ~2048-old bits to reject legitimate packets later.

    Bits above `shift` are deliberately not asserted: clearing forward of
    new_max is harmless (those counters cannot have been received), so
    requiring them to survive would pin an implementation detail rather
    than the property.
    """
    passed = failed = 0

    for shift in (1, 2, 3, 7, 8, 9, 128,
                  248, 249, 250, 251, 252, 253, 254, 255):
        reset_recv_state(transport, labels)
        write_bytes(transport, labels["hs_transport_recv"], key)
        write_bytes(transport, labels["rw_bitmap"], b"\xff" * 256)

        p, f = send_and_check(transport, labels, key, shift, plaintext, True,
                              f"exact-range shift={shift}: accepted")
        passed += p
        failed += f
        if f:
            continue

        bitmap = read_bytes(transport, labels["rw_bitmap"], 256)

        if bitmap_bit(bitmap, 0):
            passed += 1
            if VERBOSE:
                print(f"  PASS exact-range shift={shift}: counter 0 still "
                      f"recorded")
        else:
            failed += 1
            print(f"  FAIL exact-range shift={shift}: the advance erased "
                  f"counter 0's bit -- it is at old_max and still inside "
                  f"the window, so counter 0 is now replayable")

        stale = [pos for pos in range(1, shift) if bitmap_bit(bitmap, pos)]
        if not stale:
            passed += 1
            if VERBOSE:
                print(f"  PASS exact-range shift={shift}: newly exposed "
                      f"range cleared")
        else:
            failed += 1
            print(f"  FAIL exact-range shift={shift}: {len(stale)} of "
                  f"{shift - 1} newly exposed positions still set "
                  f"(first {stale[:8]}) -- stale bits will reject "
                  f"legitimate packets")

        if bitmap_bit(bitmap, shift):
            passed += 1
            if VERBOSE:
                print(f"  PASS exact-range shift={shift}: new counter "
                      f"recorded")
        else:
            failed += 1
            print(f"  FAIL exact-range shift={shift}: the accepted counter "
                  f"was not recorded in the bitmap")

    return passed, failed


# ============================================================================
# Main
# ============================================================================

def run_tests(transport, labels, seed):
    """Run all sliding window test groups."""
    rng = random.Random(seed)
    total_passed = total_failed = 0

    key = bytes(rng.randint(0, 255) for _ in range(32))
    plaintext = b"REPLAY WINDOW TEST"

    write_bytes(transport, labels["hs_transport_recv"], key)

    groups = [
        ("sequential accepted",
         lambda: test_sequential_accepted(transport, labels, key, plaintext)),
        ("duplicate rejected",
         lambda: test_duplicate_rejected(transport, labels, key, plaintext)),
        ("out-of-order accepted",
         lambda: test_out_of_order_accepted(transport, labels, key, plaintext)),
        ("out-of-order replay rejected",
         lambda: test_out_of_order_replay_rejected(transport, labels, key,
                                                    plaintext)),
        ("large gap advances",
         lambda: test_large_gap_advances(transport, labels, key, plaintext)),
        ("old outside window rejected",
         lambda: test_old_outside_window_rejected(transport, labels, key,
                                                   plaintext)),
        ("edge: delta=2047 accepted",
         lambda: test_edge_delta_2047_accepted(transport, labels, key,
                                                plaintext)),
        ("edge: delta=2048 rejected",
         lambda: test_edge_delta_2048_rejected(transport, labels, key,
                                                plaintext)),
        ("backfill pattern",
         lambda: test_backfill_pattern(transport, labels, key, plaintext)),
        ("window advance preserves old bits",
         lambda: test_window_advance_preserves_old_bits(transport, labels, key,
                                                         plaintext)),
        ("#86: sequential traffic 0..7, every replay rejected",
         lambda: test_sequential_traffic_replays_rejected(transport, labels,
                                                          key, plaintext)),
        ("#86: replay after advance rejected (all 8 residues)",
         lambda: test_replay_after_advance_all_residues(transport, labels, key,
                                                        plaintext)),
        ("#86: advance across the bitmap wraparound (byte 255 -> 0)",
         lambda: test_advance_across_bitmap_wraparound(transport, labels, key,
                                                       plaintext)),
        ("#86: advance clears exactly (old_max, new_max]",
         lambda: test_advance_clears_exact_range(transport, labels, key,
                                                 plaintext)),
    ]

    for name, test_fn in groups:
        print(f"\n--- {name} ---")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
            print(f"  {p} passed, {f} failed")
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            total_failed += 1

    return total_passed, total_failed


def main():
    args = sys.argv[1:]
    seed = 4242
    global VERBOSE
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

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        # Only clean ACME outputs, not ip65 binary (may not be rebuildable)
        build_dir = os.path.join(PROJECT_ROOT, "build")
        for f in ["wireguard.prg", "labels.txt"]:
            p = os.path.join(build_dir, f)
            if os.path.exists(p):
                os.remove(p)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)

    # Verify required labels exist
    # All of these are exported on master too, so this file runs unchanged
    # against the unfixed tree — nothing here is gated on a branch-only symbol.
    required = ["rw_bitmap", "rw_counter_max", "rw_bit_mask",
                "transport_decrypt", "tp_recv_counter", "tp_recv_counter_tmp",
                "hs_transport_recv", "udp_recv_buf", "udp_recv_len",
                "tp_packet"]
    for name in required:
        addr = labels.address(name)
        if addr is None:
            print(f"FATAL: label '{name}' not found")
            sys.exit(1)
        if VERBOSE:
            print(f"  label '{name}' = ${addr:04X}")

    # Launch VICE
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")

        transport = inst.transport
        grid = binary_wait_for_boot_ready(transport, labels, timeout=180.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)

        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))

        print("VICE ready, running tests...")

        passed, failed = run_tests(transport, labels, seed)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
