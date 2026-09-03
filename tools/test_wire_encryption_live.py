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


def _sized(marker: str, tail: str) -> str:
    """WIRE_MSG_LEN pads a marker with filler to that many chars (832 =
    MSG_TEXT_MAX drives the full-size tunnel path); unset keeps it short."""
    n = int(_os.environ.get("WIRE_MSG_LEN", "0"))
    if n <= len(marker) + len(tail) + 1:
        return marker
    filler = "ABCDEFGHIJKLMNOPQRSTUVWXY "
    body = (filler * (n // len(filler) + 1))[: n - len(marker) - len(tail) - 2]
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
MARKER_HOST = _sized("QUASAR EIGHT NINE SIXTY", "END QUASAR")
MARKER_TAMPER = "MUTANT PACKET SHOULD NOT APPEAR"

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

        marker_bytes = MARKER_C64.encode("ascii")
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
            check(marker_bytes not in raw,
                  "marker ABSENT from the datagram on the wire",
                  f"datagram {len(raw)}B, ciphertext starts "
                  f"{raw[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}")
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
                        pair = (raw, shown)
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
            check(tail.encode("ascii") not in raw
                  and text[:64].encode("ascii") not in raw,
                  f"[out {n}] marker ABSENT from the datagram")
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
        check(MARKER_HOST.encode("ascii") not in pkt1,
              "marker ABSENT from the datagram we transmit",
              f"datagram {len(pkt1)}B, ciphertext starts "
              f"{pkt1[T4_HDR_LEN:T4_HDR_LEN+16].hex(' ')}")
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
        alive = "STILL ALIVE AFTER TAMPER"
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
            check(tail.encode("ascii") not in pkt,
                  f"[in {n}] marker ABSENT from the datagram we transmit")
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

    global SEED, MARKER_C64
    SEED = resolve_seed(args.seed)
    print(f"Random seed: {SEED} (reproduce with --seed {SEED} or "
          f"TEST_SEED={SEED})", flush=True)
    MARKER_C64 = _build_marker_c64(SEED)

    os.environ.setdefault("U64_ALLOW_MUTATE", "1")
    import test_uci_handshake_live as live
    live.post_session_hook = build_probe()
    try:
        return live.main(["--chat", "--host", args.host,
                          "--turbo", str(args.turbo)])
    finally:
        try:
            from c64_test_harness.backends.ultimate64_client import Ultimate64Client
            from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz
            set_turbo_mhz(Ultimate64Client(args.host), 1)
        except Exception:                                     # noqa: BLE001
            pass


if __name__ == "__main__":
    sys.exit(main())
