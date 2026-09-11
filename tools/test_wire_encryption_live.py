#!/usr/bin/env python3
"""Prove the tunnel actually encrypts, on live hardware.

    U64_ALLOW_MUTATE=1 python3.13 tools/test_wire_encryption_live.py --host <ip>

Issue #70 (1472-byte datagrams): build once, then never let the tool rebuild
— the handshake tool's _build_uci would replace a chunked build with the
plain one unless C64_SKIP_BUILD=1 (or C64_UCI_CHUNKED_WRITE=1) is set::

    make clean && make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
    C64_SKIP_BUILD=1 U64_ALLOW_MUTATE=1 \\
        python3.13 tools/test_wire_encryption_live.py --host <ip>

Sections 1b and 4b then send each boundary size exactly once (outbound
text 828..1412 -> datagrams 888..1472, inbound 860..1440 chars) and COUNT
datagrams at the wire tap. The fingerprint line the handshake tool logs
names the send path (uci_send_part present or absent) before the PRG is
sent; read it.

Until now the evidence that traffic was encrypted was INDIRECT: the host's
noise.decrypt() succeeded, and ChaCha20-Poly1305 only yields plaintext plus a
valid tag to someone holding the session key, so cleartext on the wire would
have thrown instead of decoding. That is real evidence but it is an argument,
not a test — it never asserted that the plaintext is ABSENT from the bytes on
the wire, that repeated plaintext produces different ciphertext, or that
tampering is rejected. This does.

WHY THE RESPONDER SOCKET IS A VALID WIRE TAP: we are the peer. The datagram
handed to decrypt_transport is byte-for-byte what the C64 transmitted, before
any interpretation. No pcap or elevated privileges are needed to inspect the
real thing; a capture would only add visibility of OTHER ports, which matters
for the disclosure below rather than for the encryption claim.

A NULL WITH NO CONTROL IS NOT A RESULT (issue #147): every "the marker is
ABSENT" assertion below is produced by wire_plaintext_search together with a
POSITIVE CONTROL from the same searcher, over the counterfactual datagram --
this datagram's own header with its own cleartext body -- which the searcher
must FIND. If the search is blind, encodes the needle the way the host holds
it rather than the way the wire carries it, or examines an empty buffer, the
control goes red while the absence claims stay green, and that divergence is
the evidence. The searcher also selftests before the device is touched; a
failing selftest aborts the run rather than emitting absence PASSes.

DISCLOSED CONTROL-PLANE LEAK, so nobody reads a PASS here as more than it is:
this test types the C64's line by writing its KERNAL keyboard queue over the
Ultimate's REST/DMA interface, which is plain HTTP. That text therefore does
cross the LAN in the clear on port 80 on its way IN, and the same is true of
the staged private keys in every tool here. That is the test harness's control
plane, not the tunnel. What is asserted below is strictly about the WireGuard
UDP port. A human typing at the C64's own keyboard has no such exposure.
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import wg_c64_input                                          # noqa: E402
import wire_plaintext_search as wps                          # noqa: E402

# Issue #147: every absence claim below goes through wps.absence_and_control,
# which pairs it with a positive control run by the SAME searcher over the
# counterfactual cleartext datagram. Re-exported so the offline suite can
# assert identity rather than a look-alike copy.
absence_and_control = wps.absence_and_control


def _absence_pair(datagram, body, needles, prefix, **kw):
    """wps.absence_and_control, with a refusal turned into scored FAILs.

    The searcher REFUSES a search it cannot perform -- a torn or
    header-only datagram, a needle longer than the bytes captured -- and
    that refusal must not end a hardware session in a traceback. It is a
    real failure (something was expected on the wire and was not there in
    a searchable form), so it lands as two FAILs whose labels say the
    absence was NOT ASSERTED, rather than as an absence PASS or a crash.
    """
    try:
        return wps.absence_and_control(datagram, body, needles, prefix, **kw)
    except (wps.VacuousSearchError, TypeError) as exc:
        why = f"{type(exc).__name__}: {exc}"
        return [
            (False, f"{prefix}the plaintext search was possible at all", why),
            (False, f"{prefix}marker ABSENT from the datagram on the wire",
             "NOT ASSERTED: the search refused as vacuous, so this run "
             "makes no claim either way"),
        ]

# Distinct per direction so a hit can never be attributed to the wrong one.
import os as _os

# Standing directive (2026-09-03): red/green tests that send data across the
# wire must randomise their initial words/payload per run, seeded and
# reproducible via --seed/TEST_SEED, so a fixed string cannot be gamed by
# something left over from a previous run. Applied here to the three items
# that actually send content: the keyboard-typed message (MARKER_C64,
# section 1), the outbound size probes (1b) and the inbound probes (4b).
# REQUEST_ALPHABET/REPLY_ALPHABET are disjoint so an echo of a C64->host
# message can never satisfy a host->C64 assertion or vice versa. Both are
# restricted to uppercase letters because the screen-RAM check in
# `_screen_text` only converts screen codes 1-26 -> A-Z and 32 -> space;
# anything else would print as '.' and never match.
REQUEST_ALPHABET = "ABCDEFGHIJKLM"    # C64 -> host (MARKER_C64, OUT probes)
REPLY_ALPHABET = "NOPQRSTUVWXYZ"      # host -> C64 (IN probes)
assert not (set(REQUEST_ALPHABET) & set(REPLY_ALPHABET))

_WORD_LEN_RANGE = (4, 7)
_SUFFIX_LEN = 8

SEED: int | None = None    # set by main() before build_probe()'s hook runs


def resolve_seed(cli_seed: int | None) -> int:
    """--seed wins; else TEST_SEED env; else a fresh random seed."""
    if cli_seed is not None:
        return cli_seed
    env = os.environ.get("TEST_SEED")
    if env:
        return int(env)
    return random.SystemRandom().randint(0, 2**32 - 1)


def random_words(seed: int, alphabet: str, min_len: int = 20) -> str:
    """Deterministic-per-seed leading words, space-separated, drawn only
    from *alphabet*. Same seed -> identical string; a different seed ->
    a different one. Seeded with a plain int (never a str/tuple hash,
    which PYTHONHASHSEED randomises per process) so --seed/TEST_SEED
    actually reproduces a run.
    """
    rng = random.Random(seed)
    out: list[str] = []
    while len(out) < min_len:
        if out:
            out.append(" ")
        out.extend(rng.choice(alphabet)
                   for _ in range(rng.randint(*_WORD_LEN_RANGE)))
    return "".join(out)


def random_suffix(seed: int, alphabet: str, length: int = _SUFFIX_LEN) -> str:
    """`length` random chars from *alphabet*, for a fixed-format marker
    suffix (e.g. ``END <8 random chars>``) that a hardcoded prior-run
    string cannot satisfy."""
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


def _random_filler(rng: random.Random, alphabet: str, length: int) -> str:
    """Exactly *length* chars shaped as random space-separated words."""
    out: list[str] = []
    while len(out) < length:
        if out:
            out.append(" ")
        out.extend(rng.choice(alphabet)
                   for _ in range(rng.randint(*_WORD_LEN_RANGE)))
    return "".join(out[:length])


def _sized(marker: str, tail: str, alphabet: str, rng: random.Random) -> str:
    """WIRE_MSG_LEN pads a marker with filler to that many chars (832 =
    MSG_TEXT_MAX drives the full-size tunnel path); unset keeps it short.

    The filler is drawn from *alphabet*, not from the whole A-Z. It used to
    be the fixed string "ABCDEFGHIJKLMNOPQRSTUVWXY " -- whose first thirteen
    letters ARE REQUEST_ALPHABET -- so under WIRE_MSG_LEN the host->C64
    marker carried the C64's own alphabet and the disjointness this file
    claims (an echo can never satisfy a reply check) did not hold in exactly
    the full-size configuration the knob exists for. It is also seeded now,
    like every other byte this tool puts on the wire.
    """
    n = int(_os.environ.get("WIRE_MSG_LEN", "0"))
    if n <= len(marker) + len(tail) + 1:
        return marker
    body = _random_filler(rng, alphabet, n - len(marker) - len(tail) - 2)
    return f"{marker} {body} {tail}"


def _build_marker_c64(seed: int) -> str:
    """Keyboard-typed message (section 1): random leading words plus a
    fixed-format END suffix carrying 8 random chars, so neither half can
    be satisfied by a string a previous run already used. WIRE_MSG_LEN
    still pads with additional random filler when set, matching the
    historical full-size-tunnel-path knob.
    """
    words = random_words(seed + 1, REQUEST_ALPHABET)
    suffix = random_suffix(seed + 2, REQUEST_ALPHABET)
    marker = f"{words} END {suffix}"
    n = int(_os.environ.get("WIRE_MSG_LEN", "0"))
    if n <= len(marker) + 1:
        return marker
    pad_rng = random.Random(seed + 3)
    body = _random_filler(pad_rng, REQUEST_ALPHABET, n - len(marker) - 1)
    return f"{marker} {body}"


# Placeholder until main() resolves the seed and calls _build_marker_c64;
# build_probe()'s inner `probe()` reads this as a module global at call
# time, which is after main() has set it.
MARKER_C64: str | None = None


def _build_marker_host(seed: int) -> str:
    """Section 2/3's host->C64 message: seeded, like MARKER_C64, so the
    fixed `QUASAR...` string of earlier revisions cannot be satisfied by
    whatever a previous run left on the screen. REPLY_ALPHABET keeps it
    disjoint from anything the C64 sends, so an echo can never pass it.
    """
    words = random_words(seed + 4, REPLY_ALPHABET)
    return _sized(f"{words} END {random_suffix(seed + 5, REPLY_ALPHABET)}",
                  f"END {random_suffix(seed + 6, REPLY_ALPHABET)}",
                  REPLY_ALPHABET, random.Random(seed + 11))


def _build_marker_tamper(seed: int) -> str:
    """Section 4's forged-packet payload; must not appear on the screen."""
    return (f"{random_words(seed + 7, REPLY_ALPHABET)} END "
            f"{random_suffix(seed + 8, REPLY_ALPHABET)}")


def _build_marker_alive(seed: int) -> str:
    """Section 4's post-forgery liveness message; MUST appear."""
    return (f"{random_words(seed + 9, REPLY_ALPHABET)} END "
            f"{random_suffix(seed + 10, REPLY_ALPHABET)}")


MARKER_HOST: str | None = None
MARKER_TAMPER: str | None = None
MARKER_ALIVE: str | None = None

T4_HDR_LEN = 16     # type(1) + reserved(3) + receiver_idx(4) + counter(8)
IP_UDP_HDR_LEN = 28 # inner IPv4 + UDP framing that udp_tunnel_build adds
# A message of N text chars leaves the C64 as ONE datagram of N + 60 bytes:
# 28 inner headers + 16 Type-4 header + 16 Poly1305 tag.
OUTBOUND_OVERHEAD = IP_UDP_HDR_LEN + T4_HDR_LEN + 16

# Issue #70 size probe. Outbound text sizes chosen so the DATAGRAM lands on
# the firmware's chunked-write boundaries (text + 60): 888 = one full part,
# 889/891/892/893 straddle the plain 892 cap, 1452/1472 are two-part sends
# with 1472 the datagram cap. Inbound sizes straddle the old MTU (860/861)
# and end at the new receive ceiling (1420 -> 1452 B, 1440 -> 1472 B).
# Each size is sent exactly once, so a hit can only come from its own send.
OUTBOUND_TEXT_SIZES = (828, 829, 831, 832, 833, 1392, 1412)
INBOUND_TEXT_SIZES = (860, 861, 1420, 1440)
END_MARKER_LEN = 40     # last 40 chars of every inbound message, unique per size


def partition_outbound_sizes(text_max: int, sizes=OUTBOUND_TEXT_SIZES):
    """Split the outbound sizes into (run, skipped) for a build whose
    MSG_TEXT_MAX is *text_max*.

    A size the build cannot stage is SKIPPED, not failed: on the default
    build MSG_TEXT_MAX is 832, so 833/1392/1412 are simply not this
    build's claim — failing them would turn the shipped build's clean run
    into 9/12 for no defect. The summary reports the skip count so a
    flag-build run (0 skipped) stays distinguishable from a default one.
    """
    run = tuple(n for n in sizes if n <= text_max)
    skipped = tuple(n for n in sizes if n > text_max)
    return run, skipped
INBOUND_WINDOW = 4.0    # seconds for the C64 to poll, decrypt and print


def _sized_text(prefix: str, n: int, seed: int, alphabet: str) -> str:
    """Exactly n chars: random leading words, then a fixed-format END tail
    carrying the size plus 8 random chars from *alphabet* (e.g. ``END 0888
    QDXKMZLR``) so neither the body nor the tail can be satisfied by a
    string a previous run already used. Deterministic per (seed, n,
    prefix) via plain-int seeding, so --seed/TEST_SEED reproduces a run.

    The tail is what the screen check looks for: a 1420-char message scrolls
    a 1000-char screen, so only its END can be expected to be visible.
    Callers additionally assert the WHOLE text (random body + tail)
    byte-for-byte, so the random part is checked for length AND content,
    not merely presence.
    """
    tag = 1 if prefix == "OUT" else 2
    rng = random.Random((seed + n * 97 + tag * 7919) & 0xFFFFFFFF)
    suffix = "".join(rng.choice(alphabet) for _ in range(_SUFFIX_LEN))
    tail = f"END {n:04d} {suffix}".ljust(END_MARKER_LEN, "Z")
    assert len(tail) == END_MARKER_LEN
    head = f"{prefix} SIZE {n:04d} "
    body_len = n - len(head) - len(tail)
    assert body_len >= 0, f"{n} is too short for the markers"
    body = _random_filler(rng, alphabet, body_len)
    text = head + body + tail
    assert len(text) == n
    return text

results: list[tuple[bool, str]] = []


class _WireTap:
    """Socket proxy: records every datagram the responder's recv loop pulls.

    Installed as ``rt._sock``; the thread looks the attribute up on every
    iteration, so the swap takes effect at the next recvfrom. Only
    ``recvfrom`` is intercepted, everything else is delegated.
    """

    def __init__(self, inner):
        self._inner = inner
        self.datagrams: list[bytes] = []

    def recvfrom(self, n: int):
        data, src = self._inner.recvfrom(n)
        self.datagrams.append(bytes(data))
        return data, src

    def __getattr__(self, name):
        return getattr(self._inner, name)


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((ok, label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail else ""), flush=True)
    return ok


def _screen_text(tr) -> str:
    """Read the C64's screen RAM and decode it to ASCII.

    Screen codes, not PETSCII: 1-26 are A-Z. Used to prove the C64 DECRYPTED
    something, which is the other half of the claim — absence of plaintext on
    the wire is only interesting if the far end still receives the message.
    """
    scr = bytes(tr.read_memory(0x0400, 1000))
    out = []
    for b in scr:
        if b == 32:
            out.append(" ")
        elif 1 <= b <= 26:
            out.append(chr(b + 64))
        elif 33 <= b <= 63:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def build_probe():
    from test_uci_handshake_live import (
        ascii_to_petscii, petscii_to_ascii, strip_tunnel_headers,
    )

    def probe(tr, L, rt, responder) -> int:
        # Tap the raw inbound datagrams. The responder thread calls this on
        # every Type-4, so we see the wire bytes AND what they decrypt to,
        # paired, without touching the thread's logic.
        seen: list[tuple[bytes, bytes]] = []
        original_decrypt = responder.decrypt_transport

        def tapped(pkt):
            plain = original_decrypt(pkt)
            seen.append((bytes(pkt), bytes(plain)))
            return plain

        responder.decrypt_transport = tapped

        # Tap BELOW decrypt as well: the responder thread reads its socket
        # through `rt._sock` on every iteration, so wrapping that object
        # counts every datagram the C64 emits before any interpretation. A
        # torn two-part send is two datagrams here even though its second
        # half is not a Type-4 and never reaches `tapped`.
        tap = _WireTap(rt._sock)
        rt._sock = tap

        has_chunk = "uci_send_part" in L
        text_max = wg_c64_input.input_max_from_labels(L)
        print(f"\n  build: uci_send_part={'present' if has_chunk else 'ABSENT'}"
              f" -> {'chunked 1472' if has_chunk else 'plain 892'} send path,"
              f" MSG_TEXT_MAX={text_max}", flush=True)

        print("\n=== 1. C64 -> host: is the plaintext on the wire? ===",
              flush=True)
        if not wg_c64_input.send_message(tr, MARKER_C64):
            return check(False, "C64 accepted the keystrokes") and 1

        pair = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and pair is None:
            time.sleep(0.3)
            for raw, plain in seen:
                shown = petscii_to_ascii(strip_tunnel_headers(plain))
                if MARKER_C64 in shown:
                    pair = (raw, plain, shown)
                    break

        if pair is None:
            check(False, "C64's message arrived at all",
                  f"{len(seen)} Type-4s seen, none containing the marker")
        else:
            raw, plain, shown = pair
            print(f"  datagram {len(raw)}B, ciphertext starts "
                  f"{raw[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}", flush=True)
            # `plain` is what this very datagram decrypted to: the bytes a
            # C64 that skipped transport_send's encrypt would have put on
            # the wire behind the same header. The control requires the
            # absence check to FAIL there.
            for ok, label, detail in _absence_pair(
                    raw, plain, {"marker_c64": MARKER_C64}, ""):
                check(ok, label, detail)
            check(MARKER_C64 in shown,
                  "same datagram DECRYPTS to the marker",
                  f"decrypted: {shown.strip()!r}")
            # The AEAD tag is what makes the decrypt meaningful rather than a
            # guess: ciphertext is plaintext length + 16.
            check(len(raw) == T4_HDR_LEN + len(plain) + 16,
                  "length accounts for a 16-byte Poly1305 tag",
                  f"{len(raw)} == {T4_HDR_LEN} hdr + {len(plain)} plain + 16 tag")

        print("\n=== 1b. C64 -> host at the chunked-write boundaries (#70) ===",
              flush=True)
        # The keyboard path above stays as the one human-shaped message;
        # these are DMA-staged (wg_c64_input.send_message_dma) because a
        # 1412-character line cannot be typed ten keys at a time. Same
        # do_message_input -> udp_tunnel_build -> transport_send path.
        run_sizes, skipped_sizes = partition_outbound_sizes(text_max)
        for n in skipped_sizes:
            print(f"  SKIP  [out {n}] {n + OUTBOUND_OVERHEAD}-byte datagram: "
                  f"above this build's MSG_TEXT_MAX={text_max} "
                  f"(not a claim of the {'chunked' if has_chunk else 'plain'}"
                  f" build)", flush=True)
        for n in run_sizes:
            text = _sized_text("OUT", n, SEED, REQUEST_ALPHABET)
            tail = text[-END_MARKER_LEN:]
            expect_dgram = n + OUTBOUND_OVERHEAD
            base_w, base_s = len(tap.datagrams), len(seen)
            try:
                accepted = wg_c64_input.send_message_dma(tr, text, L)
            except ValueError as exc:
                # Cannot happen after the partition above; if it does, the
                # helper and the labels disagree, which IS a failure.
                check(False, f"[out {n}] {expect_dgram}-byte datagram: "
                      f"text fits this build", str(exc))
                continue
            if not check(accepted, f"[out {n}] C64 accepted the staged line"):
                continue
            # Wait for the decrypt of THIS message (its tail is unique),
            # then a grace period so a straggling second fragment is counted.
            pair, deadline = None, time.monotonic() + 30
            while time.monotonic() < deadline and pair is None:
                time.sleep(0.2)
                for raw, plain in seen[base_s:]:
                    shown = petscii_to_ascii(strip_tunnel_headers(plain))
                    if tail in shown:
                        pair = (raw, shown, plain)
                        break
            time.sleep(1.0)
            wire = tap.datagrams[base_w:]
            check(len(wire) == 1,
                  f"[out {n}] exactly ONE datagram on the wire",
                  f"{len(wire)} datagram(s), lengths {[len(d) for d in wire]}")
            if not wire:
                continue
            raw = wire[0]
            check(len(raw) == expect_dgram,
                  f"[out {n}] datagram is {expect_dgram} B (text + 60)",
                  f"got {len(raw)} B")
            # Same two needles as before (tail AND head), now through the
            # controlled searcher. Counterfactual body: this message's own
            # decrypted bytes when we caught them, else the PETSCII the
            # C64 would have emitted for this exact text.
            if pair is not None:
                body, body_src = pair[2], "this datagram's decrypted bytes"
            else:
                body, body_src = (ascii_to_petscii(text),
                                  "host-side PETSCII of the staged text "
                                  "(no decrypt captured)")
            for ok, label, detail in _absence_pair(
                    raw, body, {"tail": tail, "head": text[:64]},
                    f"[out {n}] ", body_source=body_src):
                check(ok, label, detail)
            if pair is None:
                check(False, f"[out {n}] the datagram DECRYPTS to the text",
                      f"{len(seen) - base_s} Type-4(s) decrypted, none "
                      f"carrying this message's tail")
            else:
                check(pair[1] == text,
                      f"[out {n}] the datagram DECRYPTS to the text",
                      f"decrypted {len(pair[1])} chars"
                      + ("" if pair[1] == text else
                         f", first difference at "
                         f"{next((i for i in range(min(len(pair[1]), n)) if pair[1][i] != text[i]), min(len(pair[1]), n))}"))

        print("\n=== 2. host -> C64: same question, our direction ===",
              flush=True)
        pkt1 = responder.encrypt_transport(ascii_to_petscii(MARKER_HOST))
        rt.send_raw(pkt1)
        print(f"  datagram {len(pkt1)}B, ciphertext starts "
              f"{pkt1[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}", flush=True)
        for ok, label, detail in _absence_pair(
                pkt1, ascii_to_petscii(MARKER_HOST),
                {"marker_host": MARKER_HOST}, "[host->C64] ",
                body_source="the exact bytes handed to encrypt_transport"):
            check(ok, label, detail)
        time.sleep(4.0)
        check(MARKER_HOST in _screen_text(tr),
              "the C64 DECRYPTED it (text present in its screen RAM)")

        print("\n=== 3. does identical plaintext repeat on the wire? ===",
              flush=True)
        pkt2 = responder.encrypt_transport(ascii_to_petscii(MARKER_HOST))
        rt.send_raw(pkt2)
        check(pkt1[T4_HDR_LEN:] != pkt2[T4_HDR_LEN:],
              "identical plaintext yields DIFFERENT ciphertext",
              "nonce/counter advances, so the stream is not a fixed keystream")
        check(pkt1[8:16] != pkt2[8:16],
              "the counter field advanced",
              f"{int.from_bytes(pkt1[8:16],'little')} -> "
              f"{int.from_bytes(pkt2[8:16],'little')}")
        time.sleep(3.0)

        print("\n=== 4. is the C64 authenticating, or just decrypting? ===",
              flush=True)
        # Flip one ciphertext bit. A cipher without integrity would hand the
        # C64 corrupted plaintext and it would print something; Poly1305 means
        # it must reject the packet outright.
        good = bytearray(responder.encrypt_transport(
            ascii_to_petscii(MARKER_TAMPER)))
        good[T4_HDR_LEN + 4] ^= 0x01
        rt.send_raw(bytes(good))
        time.sleep(4.0)
        check(MARKER_TAMPER not in _screen_text(tr),
              "C64 REJECTED a packet with one flipped ciphertext bit")

        # And prove the rejection did not wedge the session.
        alive = MARKER_ALIVE
        rt.send_raw(responder.encrypt_transport(ascii_to_petscii(alive)))
        time.sleep(4.0)
        check(alive in _screen_text(tr),
              "session still works after the forgery was rejected")

        print("\n=== 4b. host -> C64 at the receive boundaries (#70) ===",
              flush=True)
        # Inbound is bounded by udp_recv_buf/tp_packet (1500 B) and by what
        # the adapter's SOCKET_READ hands back, not by WG_MTU: 1440 text
        # chars arrive as a 1472-byte datagram, the receive ceiling.
        # tp_payload_len is what session_handle_packet decrypted, read over
        # DMA; the screen check is the human-visible half. Sizes are unique,
        # so the previous message's length can never satisfy this one's.
        tp_len_addr = L["tp_payload_len"]
        for n in INBOUND_TEXT_SIZES:
            text = _sized_text("IN", n, SEED, REPLY_ALPHABET)
            tail = text[-END_MARKER_LEN:]
            pkt = responder.encrypt_transport(ascii_to_petscii(text))
            check(len(pkt) == n + T4_HDR_LEN + 16,
                  f"[in {n}] datagram we transmit is {n + T4_HDR_LEN + 16} B",
                  f"got {len(pkt)} B")
            for ok, label, detail in _absence_pair(
                    pkt, ascii_to_petscii(text), {"tail": tail},
                    f"[in {n}] ",
                    body_source="the exact bytes handed to encrypt_transport"):
                check(ok, label, detail)
            rt.send_raw(pkt)
            got_len, deadline = -1, time.monotonic() + INBOUND_WINDOW
            while time.monotonic() < deadline:
                got_len = int.from_bytes(
                    bytes(tr.read_memory(tp_len_addr, 2)), "little")
                if got_len == n:
                    break
                time.sleep(0.1)
            check(got_len == n,
                  f"[in {n}] tp_payload_len == {n} within {INBOUND_WINDOW:.0f} s",
                  f"last read {got_len}")
            on_screen = False
            while time.monotonic() < deadline + 1.0 and not on_screen:
                on_screen = tail in _screen_text(tr)
                if not on_screen:
                    time.sleep(0.2)
            check(on_screen,
                  f"[in {n}] the 40-char END marker is in screen RAM",
                  f"looked for {tail!r}")

        print("\n=== 5. what IS in the clear, by design ===", flush=True)
        if seen:
            raw = seen[-1][0]
            print(f"  Type-4 header (cleartext by WireGuard's design): "
                  f"{raw[:T4_HDR_LEN].hex(' ')}", flush=True)
            print(f"    type=0x{raw[0]:02x} receiver_idx="
                  f"0x{int.from_bytes(raw[4:8],'little'):08x} "
                  f"counter={int.from_bytes(raw[8:16],'little')}", flush=True)
            print("  Everything after those 16 bytes is ciphertext+tag.",
                  flush=True)

        failed = [label for ok, label in results if not ok]
        print("\n" + "=" * 60, flush=True)
        print(f"{len(results) - len(failed)}/{len(results)} checks passed; "
              f"{len(skipped_sizes)} outbound size(s) skipped "
              f"{list(skipped_sizes)} (MSG_TEXT_MAX={text_max}, "
              f"{'chunked' if has_chunk else 'plain'} build)", flush=True)
        for label in failed:
            print(f"  FAILED: {label}", flush=True)
        print("=" * 60, flush=True)
        return 1 if failed else 0

    return probe


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("U64_HOST"))
    p.add_argument("--turbo", type=int, default=48)
    p.add_argument("--seed", type=int, default=None,
                   help="Reproduce a prior run's randomised messages "
                        "(else TEST_SEED env, else a fresh random seed)")
    args = p.parse_args()
    if not args.host:
        print("ERROR: pass --host <ip> or set U64_HOST", file=sys.stderr)
        return 2

    global SEED, MARKER_C64, MARKER_HOST, MARKER_TAMPER, MARKER_ALIVE
    SEED = resolve_seed(args.seed)
    print(f"Random seed: {SEED} (reproduce with --seed {SEED} or "
          f"TEST_SEED={SEED})", flush=True)
    MARKER_C64 = _build_marker_c64(SEED)
    MARKER_HOST = _build_marker_host(SEED)
    MARKER_TAMPER = _build_marker_tamper(SEED)
    MARKER_ALIVE = _build_marker_alive(SEED)

    # A null with no control is not a result (issue #147). The searcher
    # every absence claim below runs through is proven able to FIND
    # plaintext, and to REFUSE a vacuous search, BEFORE the device is
    # touched -- a blind searcher would otherwise report a clean tunnel.
    print("\n=== 0. searcher selftest (before the device is touched) ===",
          flush=True)
    rows = wps.selftest()
    for ok, label, detail in rows:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}"
              + (f"\n          {detail}" if detail else ""), flush=True)
    bad = [label for ok, label, _ in rows if not ok]
    if bad:
        print(f"ABORT: the plaintext searcher failed its own selftest "
              f"({len(bad)} check(s): {bad}); every absence assertion in "
              f"this tool would be meaningless. Device NOT touched.",
              file=sys.stderr)
        return 2

    os.environ.setdefault("U64_ALLOW_MUTATE", "1")

    # ── PIN THE BUILD AND THE REU. Issue #98.
    #
    # This tool used to pass neither, so it inherited C64_REU=1 from
    # test_uci_udp_echo_live and --reu on from test_uci_handshake_live, and
    # its default invocation was REU + REU-attached + 48 MHz. Every green
    # this tool ever recorded was obtained by an operator overriding that,
    # so its passing history described what its operators typed, not what
    # the tool does. Someone running it plainly got a different arm from
    # the one the greens were measured on, and nothing said so.
    #
    # WHY REU=0 IS THE DEFAULT, and what the reason is NOT. It is no longer
    # "the REU arm is broken". #69's fault does not reproduce on firmware
    # 4011c97c: measured 2026-09-07, the REU arm at 48 MHz completed two
    # full WireGuard handshakes against Cloudflare WARP with 20/20 DNS
    # queries decrypted, zero decrypt_failed, and x25519_reu_fault reading
    # $00 at both 1 MHz and 48 MHz. A separating run with the pre-settle
    # library pins on the same firmware was 3/3 green, 6/6 handshakes, zero
    # InvalidTag — so the FIRMWARE, not the settle, accounts for #69.
    #
    # 6/6 bounds an intermittent fault loosely; it does not exclude one,
    # and #69's original signature was intermittent. This comment does not
    # say the settle was unnecessary.
    #
    # The reason is SPEED, and it is measured: a controlled A/B with the
    # same tool, peer, clock and day, differing only in build, reached
    # SESSION_ACTIVE in 89.0 s with REU=1 and 47.7 s with REU=0. REU is
    # ~1.9x SLOWER at turbo — the REU's DMA is a floor that does not scale
    # with the CPU clock, so the onchip path overtakes it above ~1 MHz.
    # A default that takes twice as long for no measured benefit is the
    # wrong default.
    #
    # C64_SKIP_BUILD=1 still wins if the caller wants the tree as it
    # stands, and an operator wanting the REU arm sets C64_REU=1 and passes
    # --reu on. Both are then VISIBLE in the banner below.
    os.environ.setdefault("C64_REU", "0")
    reu_env = os.environ["C64_REU"]
    reu_arg = "on" if reu_env == "1" else "off"

    # State the configuration this run is actually under, in the run's own
    # output. #98's second point: a green that does not record its arm
    # cannot be told apart from a green measured on a different one. The
    # PRG fingerprint guard in test_uci_handshake_live then refuses the
    # combinations that cannot work, so a mismatch between this banner and
    # the built image is a skip rather than a wrong result.
    print(f"Configuration: C64_REU={reu_env} (--reu {reu_arg}) "
          f"turbo={args.turbo} MHz"
          + ("  [C64_SKIP_BUILD=1: using the tree as it stands]"
             if os.environ.get("C64_SKIP_BUILD") == "1" else ""),
          flush=True)

    # WARN, DO NOT REFUSE — and say why, because #98 proposed a refusal.
    #
    # The measurement that reopened this arm is FIRMWARE-CONDITIONAL: #69
    # failed on fw 3.15 and does not reproduce on fw 4011c97c. An operator
    # still on the older firmware who asks for REU=1 gets #69 back, and a
    # refusal is what #98 wanted for exactly that person.
    #
    # A refusal is nonetheless the wrong instrument here, for two reasons
    # that are about what we can honestly encode:
    #
    #   * We have two firmware data points and no boundary between them. A
    #     refusal has to name a predicate ("fw >= 3.15"), and the only one
    #     we could write would refuse 4011c97c — a combination measured
    #     WORKING. A guard that refuses a working configuration teaches
    #     operators to bypass guards, which costs more than this buys.
    #   * The exposure a refusal was protecting has mostly gone anyway: the
    #     default is now REU=0, so reaching this arm takes a deliberate
    #     C64_REU=1. That is someone who has chosen the REU path, not
    #     someone who fell into it, and the failure is loud (InvalidTag /
    #     a handshake that never completes) rather than silent.
    #
    # So: name #69, name the firmware the null was measured on, and let
    # them proceed. If the boundary is ever established, this becomes a
    # refusal keyed on it.
    if reu_arg == "on" and args.turbo > 1:
        print(f"WARNING: REU build with the REU attached at {args.turbo} MHz "
              f"is issue #69's combination. It FAILED on fw 3.15 and did NOT "
              f"reproduce on fw 4011c97c (2026-09-07: 2 handshakes, 20/20 "
              f"DNS decrypted, zero decrypt_failed; a pre-settle separating "
              f"run was 6/6 green there). 6/6 bounds an intermittent fault "
              f"loosely, it does not exclude one. Check your firmware "
              f"before reading an InvalidTag here as a regression in "
              f"something you changed. C64_REU=0 is the default and is "
              f"~1.9x faster at turbo besides.", flush=True)

    import test_uci_handshake_live as live
    live.post_session_hook = build_probe()
    # No teardown wrapper here any more: live.main() now runs the shared
    # teardown INSIDE its own locked region before releasing (see
    # test_uci_handshake_live.post_session_teardown). Doing it again here
    # meant two resets and a second lock cycle for the same result. The
    # reasoning that put it here still holds — this tool runs a full
    # WireGuard session and holds a UDP socket only a reset closes, issue
    # #134 — it is just satisfied one layer down now. If this tool ever
    # sets post_session_teardown = False, it owns its own teardown again.
    return live.main(["--chat", "--host", args.host,
                      "--turbo", str(args.turbo), "--reu", reu_arg])


if __name__ == "__main__":
    sys.exit(main())
