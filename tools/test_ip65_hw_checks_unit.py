#!/usr/bin/env python3
"""tools/test_ip65_hw_checks_unit.py — proof that the ip65/RR-Net hardware
validation is CAPABLE OF FAILING.

The risk this suite exists to eliminate
=======================================
The ip65/RR-Net backend is about to be validated on real hardware for the
first time; every prior ip65 result in this project came from an emulator.
The failure mode to fear is not "the hardware run fails". It is "the
hardware run passes and means nothing" -- and this project has that on
record: a tool cited for two days as proving the raw path byte-exact had a
verification function that was defined and never called, and a main() that
returned 0 unconditionally. Unplugging the responder did not change its
verdict.

So for every verdict tools/ip65_hw_checks.py reaches, this suite feeds it a
KNOWN-BAD input off-device and requires it to fail, with the failure text
printed. No hardware, no VICE, no build, no DeviceLock. Milliseconds.

WHAT MAKES THE RED CASES EVIDENCE, NOT DECORATION
=================================================
It is easy to write a defect so exotic that no real tool would have had it.
Every red case here is paired with a NAIVE checker -- the plausible
implementation, several of them lifted in shape from code already in this
tree -- and the case asserts BOTH halves:

    the naive checker PASSES the bad input   (the trap is live: this is
                                              what a hardware run would
                                              have reported as green)
    the real checker FAILS it                (the alarm sounds)

If a naive arm ever stops passing, that assertion goes red and says the
trap is no longer live, rather than quietly leaving a red case that proves
nothing. The naive arms are named `naive_*` below and each one carries the
tree reference for the shape it imitates.

Structure over text, everywhere: verdicts are read from Verdict.ok and
Verdict.evidence, never by matching Verdict.reason.

RANDOMISATION
=============
Everything that crosses the synthetic wire -- plaintexts, ciphertexts,
MACs, the lease address, the payload lengths -- is drawn from a seeded RNG
whose seed is printed on the first line and reproducible with --seed. The
request and reply alphabets are DISJOINT (uppercase+digits vs lowercase),
so an echo of the request can never satisfy a reply assertion, and case 3d
proves the payloads differ between two seeds, which is what makes a
fixed-string check provably wrong rather than merely inelegant.

Usage:
    python3 tools/test_ip65_hw_checks_unit.py [--seed S] [--only N] [-v]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import random
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# --self-check copies this file into a tempdir, so `__file__`'s parent's
# parent is that tempdir's parent and NOT the repo. Two checks read real
# tree files (src/net/ip65/net.s, build/labels.txt); inferring the root from
# the file's own location made them SKIP in every mutant run including the
# baseline -- 184 passed / 0 failed / 2 skipped, with a headline that still
# read "0 failed". A silent skip inside the harness that certifies the other
# checks is worth more than one in an ordinary test, so the root is now
# passed in explicitly, the same way the module under test already is.
PROJECT_ROOT = Path(os.environ.get(
    "IP65_PROJECT_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

#: Set by _run_against in the mutation child. A skip is the right answer for
#: a developer running this standalone without a built tree; inside a
#: mutation run it narrows the very denominator the run is measuring, so
#: there it is a failure instead.
IN_MUTATION_RUN = os.environ.get("IP65_MUTATION_CHILD") == "1"

# The module under test is loaded BY PATH, not by name. --self-check re-runs
# this suite against a mutated copy in a temporary directory, and a plain
# `import ip65_hw_checks` would find the real tools/ copy first (this file
# puts tools/ at the front of sys.path) -- every mutant would then survive
# by importing the unmutated module, and the self-check would report a
# perfect score while testing nothing. Which is the exact class of defect
# this suite exists to catch, so it does not get to have it.
_CHECKS_PATH = Path(os.environ.get(
    "IP65_CHECKS_MODULE", PROJECT_ROOT / "tools" / "ip65_hw_checks.py"))
if not _CHECKS_PATH.exists():                 # a copy run outside tools/
    _CHECKS_PATH = Path(__file__).resolve().parent / "ip65_hw_checks.py"
_spec = importlib.util.spec_from_file_location("ip65_hw_checks_under_test",
                                               _CHECKS_PATH)
if _spec is None or _spec.loader is None:              # pragma: no cover
    sys.exit(f"cannot load the checker module from {_CHECKS_PATH}")
C = importlib.util.module_from_spec(_spec)
# @dataclass resolves annotations through sys.modules[cls.__module__], so a
# module executed outside the import system must be registered there first.
sys.modules[_spec.name] = C
_spec.loader.exec_module(C)

#: Fixed identity. Every case emits exactly these names on every run,
#: whichever branch it takes, so two runs are comparable and a case that
#: silently stopped running is a hard error rather than a smaller
#: denominator nobody notices. Update deliberately when adding a check.
EXPECTED_CHECKS = 195

# Disjoint alphabets: an echo of a request can never satisfy a reply check.
REQ_ALPHABET = string.ascii_uppercase + string.digits
REPLY_ALPHABET = string.ascii_lowercase

# The rig, from tools/rig-up-rrnet-macos.sh. 10.0.66/24, not 10.0.65/24: the
# VICE feth rig already owns 10.0.65.1. Taken from the library so the suite
# and the checkers cannot drift apart.
HOST_IP = C.RIG_HOST_IP
RIG_SUBNET = C.RIG_SUBNET
HOST_MAC = C.RIG_HOST_MAC
C64_IP = C.RIG_C64_IP
C64_MAC = C.RIG_C64_MAC
WG_PORT = 51820

VERBOSE = False


def vlog(msg: str) -> None:
    if VERBOSE:
        print(f"      {msg}")


# ===========================================================================
# Synthetic wire
# ===========================================================================
def rand_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def rand_text(rng: random.Random, n: int, alphabet: str) -> bytes:
    return "".join(rng.choice(alphabet) for _ in range(n)).encode("ascii")


def rand_mac(rng: random.Random) -> bytes:
    """A locally-administered unicast MAC: bit 1 set, bit 0 (multicast) clear."""
    first = (rng.randrange(256) & 0xFE) | 0x02
    return bytes([first] + [rng.randrange(256) for _ in range(5)])


def ip4(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def _ip_checksum(hdr: bytes) -> int:
    total = 0
    for i in range(0, len(hdr), 2):
        total += struct.unpack(">H", hdr[i:i + 2])[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth_frame(src: bytes, dst: bytes, ethertype: int, body: bytes,
              *, pad_to: int = 0, pad: bytes = b"") -> bytes:
    """One Ethernet frame. `pad` supplies the padding bytes explicitly so a
    test can put something in them (the Etherleak shape)."""
    frame = bytes(dst) + bytes(src) + struct.pack(">H", ethertype) + body
    if pad_to and len(frame) < pad_to:
        need = pad_to - len(frame)
        filler = (pad + b"\x00" * need)[:need] if pad else b"\x00" * need
        frame += filler
    return frame


def ip_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes,
           *, ip_id: int = 0x1234, frag_off: int = 0, more_frags: bool = False,
           raw_ip_payload: bytes | None = None) -> bytes:
    """An IPv4 packet carrying UDP, or a bare fragment of one.

    `raw_ip_payload` bypasses UDP framing so a non-first fragment (which has
    no UDP header of its own) can be built.
    """
    if raw_ip_payload is None:
        udp = struct.pack(">HHHH", sport, dport, len(payload) + 8, 0) + payload
    else:
        udp = raw_ip_payload
    total = 20 + len(udp)
    flags = (0x2000 if more_frags else 0) | (frag_off // 8)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, ip_id, flags, 64,
                      C.IPPROTO_UDP, 0) + ip4(src_ip) + ip4(dst_ip)
    hdr = hdr[:10] + struct.pack(">H", _ip_checksum(hdr)) + hdr[12:]
    return hdr + udp


def arp_frame(src_mac: bytes, sender_ip: str, target_ip: str,
              *, trailer: bytes = b"") -> bytes:
    body = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + bytes(src_mac)
            + ip4(sender_ip) + b"\x00" * 6 + ip4(target_ip) + trailer)
    return eth_frame(src_mac, b"\xff" * 6, C.ETHERTYPE_ARP, body)


def icmp_echo(src_ip: str, dst_ip: str, kind: int, ident: int, seq: int,
              data: bytes) -> bytes:
    """An IPv4 packet carrying one ICMP echo request or reply."""
    icmp = struct.pack(">BBHHH", kind, 0, 0, ident, seq) + data
    total = 20 + len(icmp)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0, 64,
                      C.IPPROTO_ICMP, 0) + ip4(src_ip) + ip4(dst_ip)
    hdr = hdr[:10] + struct.pack(">H", _ip_checksum(hdr)) + hdr[12:]
    return hdr + icmp


def arp_op_frame(src_mac: bytes, dst_mac: bytes, op: int, sender_mac: bytes,
                 sender_ip: str, target_ip: str) -> bytes:
    body = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + bytes(sender_mac)
            + ip4(sender_ip) + b"\x00" * 6 + ip4(target_ip))
    return eth_frame(src_mac, dst_mac, C.ETHERTYPE_ARP, body)


def build_pcap(frames: list[bytes], *, snaplen_clip: int = 0,
               linktype: int = 1, t0: float = 1_700_000_000.0) -> bytes:
    """A real classic pcap, little-endian, microsecond timestamps.

    `snaplen_clip` writes records whose captured length is less than the
    original length -- what `tcpdump` without `-s 0` produces.
    """
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                262144, linktype))
    for i, f in enumerate(frames):
        incl = min(len(f), snaplen_clip) if snaplen_clip else len(f)
        out += struct.pack("<IIII", int(t0) + i // 1000,
                           (i % 1000) * 1000, incl, len(f))
        out += f[:incl]
    return bytes(out)


def cap(frames: list[bytes], **kw) -> list[C.Frame]:
    return C.parse_pcap(build_pcap(frames, **kw))


def wg_type4(rng: random.Random, body_len: int) -> bytes:
    """A plausible WireGuard Type-4 datagram of pure random bytes.

    Random, not zeros: a leak search over an all-zero payload could not
    tell a working search from one that always returns "not found".
    """
    return (b"\x04\x00\x00\x00" + rand_bytes(rng, 4) + rand_bytes(rng, 8)
            + rand_bytes(rng, body_len) + rand_bytes(rng, 16))


# ===========================================================================
# The NAIVE checkers -- the plausible implementations the red cases indict.
# Each returns True for "looks fine to me".
# ===========================================================================
def naive_parse_frame(frame: bytes):
    """VERBATIM in shape from tools/test_ip65_arp_first_send_vice.py:583.

    Returns (src, sport, dst, dport, payload, ip) or None. Note what is
    absent: the Ethernet source MAC, and any frame that is not IPv4/UDP.
    """
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    sport, dport, ulen = struct.unpack(">HHH", udp[0:6])
    return src, sport, dst, dport, udp[8:8 + max(0, ulen - 8)], ip


def naive_plaintext_absent(raw_frames: list[bytes], needle: bytes) -> bool:
    """Search each frame's UDP payload for the plaintext. The obvious tool."""
    for f in raw_frames:
        rec = naive_parse_frame(f)
        if rec and needle in rec[4]:
            return False
    return True


def naive_plaintext_at_zero(raw_frames: list[bytes], needle: bytes) -> bool:
    """Compare the head of each payload -- 'is the payload our plaintext?'."""
    for f in raw_frames:
        rec = naive_parse_frame(f)
        if rec and rec[4][:len(needle)] == needle:
            return False
    return True


def naive_plaintext_concat(raw_frames: list[bytes], needle: bytes) -> bool:
    """Gather every UDP payload, glue them together, search once. Wrong."""
    blob = b"".join(rec[4] for rec in
                    (naive_parse_frame(f) for f in raw_frames) if rec)
    return needle not in blob


def naive_saw_wireguard_traffic(raw_frames: list[bytes], port: int) -> bool:
    """'We saw WireGuard traffic on the cable.' Says nothing about who sent it."""
    for f in raw_frames:
        rec = naive_parse_frame(f)
        if rec and (rec[3] == port or rec[1] == port):
            return True
    return False


def naive_handshake_from_responder(responder_complete: bool) -> bool:
    """The responder's own view, which is the easy one to have."""
    return responder_complete


def naive_transport_by_count(received: list[bytes]) -> bool:
    """'We got a datagram back', with no look at what was in it."""
    return len(received) > 0


def naive_mac_to_c64_by_send(host_sent: bool) -> bool:
    """'The Mac sent it', with nothing read back from the C64."""
    return host_sent


def naive_lease_nonzero(cfg_ip: bytes | None) -> bool:
    """'cfg_ip is non-zero, so we have a lease.' ip65 ships it non-zero."""
    return cfg_ip is not None and any(cfg_ip)


def naive_lease_from_leasefile(lease_file_lines: list[str]) -> bool:
    """'dnsmasq recorded a lease.' That is a fact about our DHCP server."""
    return any(line.strip() for line in lease_file_lines)


def naive_mac_readback(written: bytes, read_back: bytes) -> bool:
    """Write the MAC, read it back through the same path, call it proven."""
    return bytes(written) == bytes(read_back)


# ===========================================================================
# Bookkeeping (the tools/test_warp_instrument_unit.py contract)
# ===========================================================================
class Result:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.names: list[str] = []

    def check(self, ok: bool, name: str, detail: str = "") -> None:
        self.names.append(name)
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}\n        {detail}")

    def skip(self, name: str, why: str) -> None:
        """A check that could not apply, still counted in the denominator.

        Refuses to skip inside a mutation run: see IN_MUTATION_RUN.
        """
        if IN_MUTATION_RUN:
            self.check(False, name,
                       f"cannot skip inside a mutation run ({why}); the "
                       "denominator the run is measuring must be whole")
            return
        self.names.append(name)
        self.passed += 1
        self.skipped += 1
        print(f"  SKIP  {name}  ({why})")

    def alarm(self, verdict: C.Verdict, name: str, *, naive_ok: bool,
              naive_name: str, form: str | None = None) -> None:
        """A red case: the naive checker passes, the real one fails.

        Both halves are asserted, and the real checker's failure text is
        printed so the report can quote it.
        """
        self.check(naive_ok, f"{name}/trap-is-live",
                   f"the naive check ({naive_name}) already REFUSES this input, "
                   "so the case no longer demonstrates a live trap")
        self.check(not verdict.ok, f"{name}/alarm",
                   f"the real check PASSED a known-bad input: {verdict.reason}")
        if verdict.ok:
            print(f"        evidence: {verdict.evidence}")
        else:
            print(f"        alarm text: {verdict.reason}")
        if form is not None:
            forms = {f["form"] for f in verdict.evidence.get("findings", [])}
            self.check(form in forms, f"{name}/form",
                       f"expected a {form!r} finding, got {sorted(forms)}")


# ===========================================================================
# Case 1 — plaintext absence on the wire
# ===========================================================================
def case1_plaintext(rng: random.Random, res: Result) -> None:
    print("\n[case 1] plaintext absence: the strongest claim the run can make")
    c64_mac = rand_mac(rng)
    secret = rand_text(rng, 40, REQ_ALPHABET)
    needles = {"outbound-chat": secret}

    # -- 1a clean capture: ciphertext only -------------------------------
    clean = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                       ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                              wg_type4(rng, rng.randrange(100, 400))))
             for _ in range(4)]
    clean += [eth_frame(HOST_MAC, c64_mac, C.ETHERTYPE_IPV4,
                        ip_udp(HOST_IP, C64_IP, WG_PORT, 51820,
                               wg_type4(rng, rng.randrange(100, 400))))
              for _ in range(3)]
    v = C.check_plaintext_absent(cap(clean), needles, c64_mac=c64_mac)
    res.check(v.ok, "case1a/clean-capture-passes",
              f"a capture with no plaintext was rejected: {v.reason}")
    res.check(v.evidence.get("datagrams") == 7, "case1a/searched-everything",
              f"searched {v.evidence.get('datagrams')} datagrams, staged 7 — "
              "a green verdict from an instrument that searched less than the "
              "whole capture is the vacuous pass this suite exists to prevent")

    # ALARM PROOF for the green case: corrupt one datagram by overwriting a
    # window with the plaintext. Same capture, one change, must go red.
    at = rng.randrange(0, 3)
    body = bytearray(clean[at])
    off = 14 + 20 + 8 + 10
    body[off:off + len(secret)] = secret
    corrupted = list(clean)
    corrupted[at] = bytes(body)
    v2 = C.check_plaintext_absent(cap(corrupted), needles, c64_mac=c64_mac)
    res.check(not v2.ok, "case1a/one-byte-corruption-alarms",
              "the SAME capture with the plaintext spliced into one datagram "
              "still passed — the green verdict above is unconditional")
    if not v2.ok:
        print(f"        alarm text: {v2.reason}")

    # -- 1b plaintext at offset 0 of the payload -------------------------
    f = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                   ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, secret))]
    v = C.check_plaintext_absent(cap(f), needles, c64_mac=c64_mac)
    res.check(not v.ok, "case1b/plain-at-offset-0",
              "plaintext sent in the clear was not detected")
    res.check(not naive_plaintext_absent(f, secret), "case1b/naive-agrees",
              "the naive substring search missed the simplest possible leak, "
              "which means this suite's naive arm is broken, not the trap")

    # -- 1c plaintext at a one-byte offset -------------------------------
    shifted = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                         ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                                b"\x04" + secret + rand_bytes(rng, 16)))]
    res.alarm(C.check_plaintext_absent(cap(shifted), needles, c64_mac=c64_mac),
              "case1c/one-byte-offset",
              naive_ok=naive_plaintext_at_zero(shifted, secret),
              naive_name="compare payload[:n] to the plaintext",
              form="exact")

    # -- 1d plaintext torn across two fragments of ONE datagram ----------
    half = len(secret) // 2
    # The first fragment's IP payload must be a multiple of 8 bytes: the IP
    # fragment offset field counts 8-byte units, so 8 (UDP header) + len(pre)
    # + half has to divide by 8 or the second fragment lands misaligned and
    # this case would be testing a malformed capture rather than a leak.
    pre = rand_bytes(rng, (-(8 + half)) % 8 or 8)
    frag_id = rng.randrange(0x1000, 0xF000)
    first_payload = struct.pack(">HHHH", 51820, WG_PORT,
                                8 + len(pre) + len(secret), 0) + pre + secret[:half]
    torn = [
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 0, 0, b"", ip_id=frag_id,
                         more_frags=True, raw_ip_payload=first_payload)),
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 0, 0, b"", ip_id=frag_id,
                         frag_off=len(first_payload),
                         raw_ip_payload=secret[half:])),
    ]
    res.alarm(C.check_plaintext_absent(cap(torn), needles, c64_mac=c64_mac),
              "case1d/split-across-fragments",
              naive_ok=naive_plaintext_absent(torn, secret),
              naive_name="per-frame substring search",
              form="exact")

    # -- 1e halves in two UNRELATED datagrams ----------------------------
    # DECISION: this COUNTS, as a `partial` finding. Each datagram carries a
    # 20-byte contiguous run of the secret; that is a recoverable leak on its
    # own terms, and it is found without ever concatenating the capture.
    apart = [
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                         rand_bytes(rng, 12) + secret[:half], ip_id=0x2001)),
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                         secret[half:] + rand_bytes(rng, 12), ip_id=0x2002)),
    ]
    res.alarm(C.check_plaintext_absent(cap(apart), needles, c64_mac=c64_mac),
              "case1e/halves-in-two-datagrams",
              naive_ok=naive_plaintext_absent(apart, secret),
              naive_name="per-frame search for the WHOLE plaintext",
              form="partial")

    # -- 1f junction artifact: must NOT alarm ----------------------------
    # DECISION: this does NOT count. A 12-byte secret whose first 6 bytes end
    # one datagram and whose last 6 start an unrelated one was never on the
    # cable as a recoverable secret; it exists only in the concatenation. A
    # checker that reports it cries wolf at every packet boundary, and a
    # checker that cries wolf gets switched off.
    short = rand_text(rng, 12, REQ_ALPHABET)
    junction = [
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                         rand_bytes(rng, 20) + short[:6], ip_id=0x3001)),
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                         short[6:] + rand_bytes(rng, 20), ip_id=0x3002)),
    ]
    v = C.check_plaintext_absent(cap(junction), {"short": short}, c64_mac=c64_mac)
    res.check(v.ok, "case1f/junction-is-not-a-leak",
              f"reported a leak that exists only across a packet boundary: {v.reason}")
    res.check(not naive_plaintext_concat(junction, short),
              "case1f/concat-would-cry-wolf",
              "the concatenating checker did NOT false-alarm here, so this case "
              "no longer demonstrates why concatenation is wrong")

    # -- 1g reversed -----------------------------------------------------
    rev = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                     ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                            rand_bytes(rng, 6) + secret[::-1]))]
    res.alarm(C.check_plaintext_absent(cap(rev), needles, c64_mac=c64_mac),
              "case1g/reversed",
              naive_ok=naive_plaintext_absent(rev, secret),
              naive_name="forward-only substring search",
              form="reversed")

    # -- 1h PETSCII form of a lowercase plaintext ------------------------
    lower = rand_text(rng, 24, REPLY_ALPHABET)
    petscii = C.petscii_form(lower)
    res.check(petscii != lower, "case1h/petscii-differs",
              "the PETSCII form of a lowercase payload equalled the ASCII form, "
              "so this case cannot distinguish the two searches")
    pet_frames = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                            ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                                   rand_bytes(rng, 4) + petscii))]
    res.alarm(C.check_plaintext_absent(cap(pet_frames), {"chat": lower}, c64_mac=c64_mac),
              "case1h/petscii-encoded",
              naive_ok=naive_plaintext_absent(pet_frames, lower),
              naive_name="search for the host-side ASCII bytes only",
              form="petscii")

    # -- 1i Etherleak: the secret in the Ethernet pad --------------------
    tiny = ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, rand_bytes(rng, 4))
    padded = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4, tiny,
                        pad_to=14 + len(tiny) + len(secret), pad=secret)]
    res.alarm(C.check_plaintext_absent(cap(padded), needles, c64_mac=c64_mac),
              "case1i/in-the-ethernet-pad",
              naive_ok=naive_plaintext_absent(padded, secret),
              naive_name="search the UDP payload only (trims at the IP length)",
              form="pad")

    # -- 1j the secret in an ARP frame -----------------------------------
    arp = [arp_frame(c64_mac, C64_IP, HOST_IP, trailer=secret)]
    res.alarm(C.check_plaintext_absent(cap(arp + clean), needles, c64_mac=c64_mac),
              "case1j/in-a-non-ip-frame",
              naive_ok=naive_plaintext_absent(arp + clean, secret),
              naive_name="a decoder that returns None for anything but IPv4",
              form="nonip")

    # -- 1k an empty capture is not a clean bill of health ---------------
    v = C.check_plaintext_absent([], needles, c64_mac=c64_mac)
    res.check(not v.ok, "case1k/empty-capture-refused",
              "an EMPTY capture passed the leak check — 'we found no plaintext' "
              "from an instrument that saw nothing is how the retracted raw-path "
              "tool read as green with the responder unplugged")
    if not v.ok:
        print(f"        alarm text: {v.reason}")
    v = C.check_plaintext_absent(cap(clean), {}, c64_mac=c64_mac)
    res.check(not v.ok, "case1k/no-needles-refused",
              "a leak check with nothing to search for returned OK")

    # -- 1l a snaplen-clipped capture is refused -------------------------
    clipped = build_pcap(clean, snaplen_clip=60)
    try:
        C.parse_pcap(clipped)
        res.check(False, "case1l/truncated-capture-refused",
                  "a capture written without `-s 0` parsed happily; every byte "
                  "past the snaplen is invisible to the search and the verdict "
                  "would be green for the wrong reason")
    except C.PcapError as exc:
        res.check(True, "case1l/truncated-capture-refused")
        print(f"        alarm text: {exc}")
    naive_clip = C.parse_pcap(clipped, strict=False)
    res.check(naive_plaintext_absent([f.raw for f in naive_clip], secret),
              "case1l/clipped-search-would-pass",
              "the clipped capture did not read as clean, so this case no longer "
              "shows why truncation must be refused")


# ===========================================================================
# Case 17 — ip65_send_attempts is PER-SEND, and the drop counter can only
#           move while the pump is running
# ===========================================================================
def case17_send_attempts_semantics(rng: random.Random, res: Result) -> None:
    """The two counters have different lifetimes, and it decides both checks.

    Verified in the tree, not inferred:

      src/net/ip65/net.s:382-383   net_udp_send stores $01 into
                                   ip65_send_attempts at the TOP OF EVERY
                                   SEND. It describes the LAST send, not the
                                   run.
      net.s:982-989 (BSS)          "1 = the ARP cache was warm and nothing
                                   was retried; >1 is the #120 path having
                                   fired", and ip65_recv_dropped is
                                   "CUMULATIVE since net_init, unlike
                                   ip65_send_attempts which is per-send".
      net_arp_pump (net.s:659-731) the only place that increments it past 1,
                                   and it holds ip65_send_pump = 1 for the
                                   duration.
      net_udp_recv_cb (:758-765)   increments ip65_recv_dropped ONLY when
                                   ip65_send_pump is set.

    So the drop counter can move ONLY while the pump runs, and the pump
    running is exactly what makes send_attempts exceed 1.
    """
    print("\n[case 17] ip65_send_attempts is per-send, not a run total")

    # A healthy warm-cache send: attempts == 1, the pump never ran, so the
    # drop counter had NO OPPORTUNITY to move and its zero is not evidence.
    v = C.check_net_counters(0, 1, expect_sends=1)
    res.check(v.ok, "case17a/warm-send-is-not-a-failure",
              f"a warm-cache send was reported as a failure: {v.reason}")
    res.check(v.evidence.get("drop_counter_proven") is False,
              "case17a/warm-send-does-not-prove-the-drop-counter",
              "send_attempts == 1 means the ARP cache was warm and the pump "
              "never ran; net_udp_recv_cb increments ip65_recv_dropped ONLY "
              "while ip65_send_pump is set, so nothing in this run could have "
              "been dropped. Reporting the counter as PROVEN here claims the "
              "opposite of the truth, and suppresses the note — a missing "
              "caveat reads as 'not checked', a suppressed one reads as "
              "evidence")
    res.check("unproven_note" in v.evidence,
              "case17a/the-note-survives",
              "the caveat is not in the evidence, so a caller that logs "
              "evidence rather than the reason string loses it entirely")

    # The pump DID fire: attempts > 1. Now the counter had an opportunity.
    v2 = C.check_net_counters(0, 3, expect_sends=1)
    res.check(v2.ok and v2.evidence.get("drop_counter_proven") is True,
              "case17b/pump-fired-proves-the-opportunity",
              f"send_attempts == 3 is the #120 pump path having fired, which is "
              f"the only thing that can move the drop counter: {v2.reason}")
    res.check("unproven_note" not in v2.evidence,
              "case17b/no-note-once-proven",
              "the caveat is still attached to a run in which the counter "
              "demonstrably had its opportunity")
    res.check(v.reason != v2.reason, "case17b/two-distinct-reports",
              "a proven and an unproven zero read identically")

    # FIVE sends, all warm. ip65_send_attempts still reads 1, because every
    # net_udp_send overwrites it. A check that compares it to the number of
    # sends the run made fails a perfectly healthy run, every time.
    v = C.check_net_counters(0, 1, expect_sends=5)
    res.check(v.ok, "case17c/five-warm-sends-is-not-a-shortfall",
              "a run of five warm-cache sends was failed for 'ip65_send_attempts "
              "is 1, fewer than the 5 sends this run made'. That byte is stored "
              "as $01 at the top of EVERY net_udp_send (net.s:382-383), so it "
              "reads 1 after five successful sends and the comparison is a "
              "guaranteed false alarm")

    # Zero attempts means net_udp_send never ran at all.
    v = C.check_net_counters(0, 0, expect_sends=1)
    res.check(not v.ok, "case17d/no-send-at-all-is-a-failure",
              "ip65_send_attempts == 0 means net_udp_send never reached its "
              "store, i.e. no send happened, and that passed")

    # A drop is a drop whatever the attempt count.
    v = C.check_net_counters(4, 1)
    res.check(not v.ok, "case17d/drops-still-fail",
              "four dropped datagrams passed because the pump was not proven")


# ===========================================================================
# Case 14 — THE EMPTY CORPUS: absence proven about traffic that never existed
# ===========================================================================
def naive_absence_guards(frames, needles) -> bool:
    """The guard set this function shipped with: needles non-empty, frames
    non-empty, datagrams non-empty, no findings. None of them involve the
    C64, and all four are satisfied by a capture of the Mac alone."""
    if not needles or not any(needles.values()):
        return False
    dgs = C.reassemble(frames)
    if not frames or not dgs:
        return False
    return not C.find_plaintext(dgs, frames, needles)


def case14_empty_corpus(rng: random.Random, res: Result) -> None:
    print("\n[case 14] absence claimed about a corpus with no C64 in it")
    secret = rand_text(rng, 40, REQ_ALPHABET)
    sentinel = rand_text(rng, 24, REQ_ALPHABET)
    needles = {"outbound-chat": secret}

    # The cartridge was dropped, or the C64 wedged after DHCP. It transmits
    # NOTHING. The Mac still emits its own chatter, dnsmasq traffic and --
    # unconditionally -- the cleartext sentinel. Frames, datagrams and a
    # findable sentinel all present; not one byte from the C64.
    mac_only = [
        eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(HOST_IP, C64_IP, WG_PORT, 51820, wg_type4(rng, 300)))
        for _ in range(6)]
    mac_only.append(eth_frame(HOST_MAC, b"\xff" * 6, C.ETHERTYPE_IPV4,
                              ip_udp(HOST_IP, "255.255.255.255", 68, 67,
                                     rand_bytes(rng, 200))))
    mac_only.append(eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                              ip_udp(HOST_IP, C64_IP, 4000, 80, sentinel)))
    frames = cap(mac_only)

    # The sentinel IS findable in this capture: the searcher demonstrably
    # works. That is exactly what made the missing guard look already-solved.
    res.check(len(C.find_plaintext(C.reassemble(frames), frames,
                                   {"sentinel": sentinel})) > 0,
              "case14a/sentinel-control-is-live",
              "the cleartext sentinel is not findable in this capture, so it "
              "cannot stand in for the control that made the gap invisible")

    v = C.check_plaintext_absent(frames, needles, c64_mac=C64_MAC)
    res.check(naive_absence_guards(frames, needles),
              "case14b/old-guards-would-pass",
              "the shipped guard set (needles, frames, datagrams, no findings) "
              "already refuses this capture, so this case no longer reproduces "
              "the defect")
    res.check(not v.ok, "case14b/mac-only-capture-is-not-a-pass",
              "a capture containing ZERO bytes from the C64 passed the strongest "
              "claim the wire stage makes")
    res.check(v.status == "inconclusive", "case14b/reported-as-inconclusive",
              f"status was {v.status!r}; 'we looked and it was clean' and 'we "
              "could not look' must not collapse — the second is not a tunnel "
              "failure and must not be reported as one")
    res.check(v.evidence.get("c64_bytes") == 0
              and v.evidence.get("c64_datagrams") == 0,
              "case14b/evidence-counts-c64-bytes",
              f"evidence said c64_bytes={v.evidence.get('c64_bytes')} for a "
              "capture with no C64 frames in it")
    res.check(v.evidence.get("bytes_all_sources", 0) > 0,
              "case14b/total-bytes-still-reported",
              "the all-sources byte count vanished; it is still worth logging, "
              "it just must not lead")
    print(f"        alarm text: {v.reason}")

    # Omitting c64_mac must not inherit the old behaviour by default.
    v = C.check_plaintext_absent(frames, needles)
    res.check(v.status == "inconclusive", "case14c/no-c64-mac-is-inconclusive",
              f"status {v.status!r}: an unwired caller got a verdict instead of "
              "being told the discrimination never happened")

    # A leak is still a leak when the Mac carried it: the corpus guard must
    # not mask a finding.
    leaky = list(mac_only)
    leaky.append(eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                           ip_udp(HOST_IP, C64_IP, WG_PORT, 51820,
                                  rand_bytes(rng, 8) + secret)))
    v = C.check_plaintext_absent(cap(leaky), needles, c64_mac=C64_MAC)
    res.check(v.status == "fail", "case14d/leak-outranks-inconclusive",
              f"status {v.status!r}: our plaintext was on the cable and the "
              "verdict reported only that the corpus was thin")

    # The C64 spoke, but only DHCP and ARP -- it never used the tunnel.
    no_tunnel = mac_only + [
        arp_op_frame(C64_MAC, HOST_MAC, C.ARP_REPLY, C64_MAC, C64_IP, HOST_IP),
        eth_frame(C64_MAC, b"\xff" * 6, C.ETHERTYPE_IPV4,
                  ip_udp("0.0.0.0", "255.255.255.255", 68, 67,
                         rand_bytes(rng, 200)))]
    v = C.check_plaintext_absent(cap(no_tunnel), needles, c64_mac=C64_MAC,
                                 require_type4_port=WG_PORT)
    res.check(v.status == "inconclusive", "case14e/spoke-but-not-through-the-tunnel",
              f"status {v.status!r}: the C64 sent DHCP and ARP and no Type-4, so "
              "nothing searched was tunnel traffic, and the run still claimed the "
              "tunnel leaked nothing")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    # And the healthy shape still passes.
    healthy = mac_only + [
        eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, wg_type4(rng, 200)))
        for _ in range(3)]
    v = C.check_plaintext_absent(cap(healthy), needles, c64_mac=C64_MAC,
                                 require_type4_port=WG_PORT)
    res.check(v.ok and v.evidence.get("c64_type4_datagrams") == 3,
              "case14f/real-run-still-passes",
              f"a run with three Type-4 datagrams from the C64 was rejected: "
              f"{v.reason}")


# ===========================================================================
# Case 15 — the shifted PETSCII block
# ===========================================================================
def case15_shifted_petscii(rng: random.Random, res: Result) -> None:
    print("\n[case 15] the shifted-letter block, which uppercase payloads hide")
    c64_mac = C64_MAC
    secret = rand_text(rng, 32, REQ_ALPHABET)      # uppercase+digits, as on the rig
    needles = {"outbound-chat": secret}

    # The premise: for an UPPERCASE payload the case-folding form returns the
    # needle unchanged, so its search branch is dead and only the shifted
    # form can catch a leak that left the machine in the other block.
    res.check(C.petscii_form(secret) == secret,
              "case15a/case-folding-form-is-dead-here",
              "petscii_form changed an uppercase payload, so this case is not "
              "reproducing the rig's alphabet")
    shifted = C.petscii_shifted_form(secret)
    res.check(shifted != secret and len(shifted) == len(secret),
              "case15a/shifted-form-differs",
              f"the shifted form is not distinct from the ASCII bytes: "
              f"{shifted[:8]!r} vs {secret[:8]!r}")
    letters = [b for b in secret if 0x41 <= b <= 0x5A]
    res.check(all(0xC1 <= b <= 0xDA for b, o in zip(shifted, secret)
                  if 0x41 <= o <= 0x5A) and letters,
              "case15a/letters-land-in-c1-da",
              "shifted letters did not land in $C1-$DA, the block a C64 emits "
              "in the other case mode")

    leaked = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                        ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                               rand_bytes(rng, 6) + shifted))]
    res.alarm(C.check_plaintext_absent(cap(leaked), needles, c64_mac=c64_mac),
              "case15b/shifted-petscii-leak",
              naive_ok=naive_plaintext_absent(leaked, secret),
              naive_name="search the host-side ASCII bytes and the case-folded "
                         "form only",
              form="petscii-shifted")


# ===========================================================================
# Case 16 — the CS8900a identifies itself, on the 6510
# ===========================================================================
def case16_cs8900a(rng: random.Random, res: Result) -> None:
    print("\n[case 16] cartridge presence is a 6510 question, not a DMA read")
    v = C.check_cs8900a_identified(C.CS8900A_PRODUCT_ID)
    res.check(v.ok, "case16a/product-id-identifies-the-chip",
              f"the CS8900a's own EISA product ID was rejected: {v.reason}")

    # $0A0A is what a HOST-SIDE read_memory of $DE00 returns, in every state.
    v = C.check_cs8900a_identified(C.HOST_PATH_DE00_WORD)
    res.check(v.evidence.get("diagnosis") == "read-from-the-host-side",
              "case16b/host-path-value-refused",
              f"diagnosed as {v.evidence.get('diagnosis')!r}. $0A0A is not a "
              "wrong chip, it is a read taken from the wrong SIDE of the "
              "machine, and telling an operator to suspect the cartridge is the "
              "opposite of the right advice")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    # Zeros: Auto, post-run_prg, or no cartridge. Three causes, one reading.
    v = C.check_cs8900a_identified(0)
    res.check(v.status == "inconclusive"
              and v.evidence.get("diagnosis") == "unidentified-zeros",
              "case16c/zeros-are-unidentified",
              f"status {v.status!r}: zeros cover Cartridge Preference = Auto, "
              "post-run_prg and no cartridge at all, so they cannot be reported "
              "as any one of them")
    v = C.check_cs8900a_identified(None)
    res.check(v.status == "inconclusive", "case16d/unread-is-inconclusive",
              f"status {v.status!r} for a product ID that was never read")
    v = C.check_cs8900a_identified(0x1234)
    res.check(v.status == "fail" and v.evidence.get("diagnosis") == "wrong-chip",
              "case16e/wrong-chip-fails",
              f"a foreign product ID: status {v.status!r}, diagnosis "
              f"{v.evidence.get('diagnosis')!r}")

    # Folded into bench health: the control alone leaves the two faults joined.
    v = C.check_bench_health(True, replies=3, rtt_ms=[2.1, 2.4],
                             product_id=C.CS8900A_PRODUCT_ID)
    res.check(v.ok and v.evidence.get("chip_identified") is True,
              "case16f/bench-plus-chip-passes", f"rejected a good bench: {v.reason}")
    v = C.check_bench_health(True, replies=3, rtt_ms=[2.1],
                             product_id=C.HOST_PATH_DE00_WORD)
    res.check(not v.ok, "case16f/bench-green-chip-unidentified",
              "the ping control passing carried a green verdict past a chip that "
              "never identified itself")
    v = C.check_bench_health(True, replies=3, rtt_ms=[2.1])
    res.check(v.ok and v.evidence.get("chip_identified") is False
              and "caveat_chip" in v.evidence,
              "case16g/chip-not-asked-is-marked-unproven",
              "a bench-health pass with no chip identification did not record "
              "that a cartridge fault and a driver fault are still joined")


# ===========================================================================
# Case 2 — handshake completion
# ===========================================================================
def case2_handshake(rng: random.Random, res: Result) -> None:
    print("\n[case 2] whose state says the handshake completed")
    c64_mac = rand_mac(rng)
    frames = cap([eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                            ip_udp(C64_IP, HOST_IP, 51820, WG_PORT,
                                   wg_type4(rng, 100)))])
    host_only = cap([eth_frame(HOST_MAC, c64_mac, C.ETHERTYPE_IPV4,
                               ip_udp(HOST_IP, C64_IP, WG_PORT, 51820,
                                      wg_type4(rng, 100)))])

    v = C.check_handshake_complete(C.WG_STATE_ACTIVE, True, frames=frames,
                                   c64_mac=c64_mac)
    res.check(v.ok, "case2a/both-ends-active", f"rejected a good run: {v.reason}")

    res.alarm(C.check_handshake_complete(C.WG_STATE_HS_SENT, True),
              "case2b/c64-wedged-at-hs-sent",
              naive_ok=naive_handshake_from_responder(True),
              naive_name="read the responder's view only")

    res.alarm(C.check_handshake_complete(C.WG_STATE_IDLE, True),
              "case2c/c64-never-left-idle",
              naive_ok=naive_handshake_from_responder(True),
              naive_name="read the responder's view only")

    res.alarm(C.check_handshake_complete(None, True),
              "case2d/wg-state-never-read",
              naive_ok=naive_handshake_from_responder(True),
              naive_name="read the responder's view only")

    res.alarm(C.check_handshake_complete(C.WG_STATE_ACTIVE, True,
                                         frames=host_only, c64_mac=c64_mac),
              "case2e/active-but-no-c64-frame",
              naive_ok=naive_saw_wireguard_traffic(
                  [f.raw for f in host_only], WG_PORT),
              naive_name="'we saw WireGuard traffic on the cable'")

    v = C.check_handshake_complete(C.WG_STATE_ACTIVE, False)
    res.check(not v.ok, "case2f/responder-disagrees",
              "the responder said the handshake did not complete and the check "
              "passed on the C64's word alone")


# ===========================================================================
# Case 3 — bidirectional transport
# ===========================================================================
def case3_transport(rng: random.Random, res: Result, seed: int) -> None:
    print("\n[case 3] bidirectional transport, by content")
    req = rand_text(rng, rng.randrange(24, 64), REQ_ALPHABET)
    reply = rand_text(rng, rng.randrange(24, 64), REPLY_ALPHABET)
    res.check(not (set(req) & set(reply)), "case3/alphabets-disjoint",
              "the request and reply alphabets overlap, so an echo of the "
              "request could satisfy a reply assertion")

    # -- C64 -> Mac ------------------------------------------------------
    v = C.check_transport_c64_to_mac([rand_bytes(rng, 20), req], req)
    res.check(v.ok, "case3a/c64-to-mac-exact", f"rejected a good run: {v.reason}")

    # No naive arm here on purpose: counting datagrams DOES catch an empty
    # list, so claiming a live trap would be a false claim. The check is
    # still asserted, because "the C64 sent nothing" is the outcome a first
    # hardware run is most likely to produce.
    v = C.check_transport_c64_to_mac([], req)
    res.check(not v.ok, "case3b/c64-sent-nothing",
              "an empty set of decrypted payloads passed the C64->Mac check")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    corrupt = bytearray(req)
    at = rng.randrange(len(corrupt))
    corrupt[at] ^= 0x01
    res.alarm(C.check_transport_c64_to_mac([bytes(corrupt)], req),
              "case3c/wrong-content-same-length",
              naive_ok=naive_transport_by_count([bytes(corrupt)]),
              naive_name="count the datagrams the responder decrypted")

    # A payload from a DIFFERENT seed must not satisfy this run's check --
    # which is what makes a fixed-string assertion provably wrong here.
    other = random.Random(seed ^ 0x5A5A5A5A)
    other_req = rand_text(other, len(req), REQ_ALPHABET)
    res.check(other_req != req, "case3d/payload-varies-with-seed",
              "two different seeds produced the same payload; the randomisation "
              "is not doing anything and a fixed string would pass")
    res.alarm(C.check_transport_c64_to_mac([other_req], req),
              "case3d/other-seed-payload-rejected",
              naive_ok=naive_transport_by_count([other_req]),
              naive_name="count the datagrams the responder decrypted")

    # -- Mac -> C64 ------------------------------------------------------
    v = C.check_transport_mac_to_c64(reply + b"\xaa" * 8, len(reply), reply)
    res.check(v.ok, "case3e/mac-to-c64-exact", f"rejected a good run: {v.reason}")

    res.alarm(C.check_transport_mac_to_c64(None, None, reply),
              "case3f/c64-buffer-never-read",
              naive_ok=naive_mac_to_c64_by_send(True),
              naive_name="'the Mac sent it'")

    # A stale buffer still holding the previous message: the CONTENT is
    # right and the recorded length is not, which is the shape of a receive
    # that never happened this round.
    res.alarm(C.check_transport_mac_to_c64(reply, 0, reply),
              "case3g/stale-buffer-zero-length",
              naive_ok=(reply[:len(reply)] == reply),
              naive_name="compare the buffer content and ignore the length")

    res.alarm(C.check_transport_mac_to_c64(req, len(req), reply),
              "case3h/echo-cannot-pass-as-reply",
              naive_ok=naive_transport_by_count([req]),
              naive_name="count the datagrams that came back")

    # The buffer holds our reply and NOTHING ELSE, but the C64 says it
    # received far more than that. Slicing to the recorded length yields the
    # reply and a content-only comparison passes; the length is the only
    # thing that says the receive path did not do what it claims.
    res.alarm(C.check_transport_mac_to_c64(reply, len(reply) + 140, reply),
              "case3i/length-overstates-the-buffer",
              naive_ok=(reply[:len(reply) + 140] == reply),
              naive_name="slice to the recorded length and compare")

    # An unread buffer whose recorded length happens to match. The guard on
    # `c64_plaintext is None` is the only thing between this and a TypeError
    # inside the checker, and a checker that raises here is a checker whose
    # verdict for the run is "crashed", not "failed".
    try:
        v = C.check_transport_mac_to_c64(None, len(reply), reply)
        res.check(not v.ok, "case3j/unread-buffer-with-matching-length",
                  "an unread receive buffer passed because its recorded length "
                  "happened to match")
        if not v.ok:
            print(f"        alarm text: {v.reason}")
    except Exception as exc:                       # noqa: BLE001
        res.check(False, "case3j/unread-buffer-with-matching-length",
                  f"the check RAISED instead of returning a verdict: "
                  f"{type(exc).__name__}: {exc}")


# ===========================================================================
# Case 4 — the DHCP lease
# ===========================================================================
def case4_dhcp(rng: random.Random, res: Result) -> None:
    print("\n[case 4] the DHCP lease, read from ip65's own cfg_ip")
    leased = ip4(f"10.0.66.{rng.randrange(10, 60)}")

    v = C.check_dhcp_lease(leased, subnet=RIG_SUBNET, host_ip=HOST_IP)
    res.check(v.ok, "case4a/real-lease-passes", f"rejected a good lease: {v.reason}")

    # THE ONE THAT MATTERS. ip65/ip65/config.s:18 ships cfg_ip = 192.168.1.64.
    default_ip = bytes(C.IP65_DEFAULT_CFG_IP)
    res.alarm(C.check_dhcp_lease(default_ip, subnet=RIG_SUBNET, host_ip=HOST_IP),
              "case4b/ip65-build-time-default",
              naive_ok=naive_lease_nonzero(default_ip),
              naive_name="'cfg_ip is non-zero, so we have a lease'")

    # And the same state, judged from the dnsmasq lease file instead: the
    # file says our server handed out an address; it cannot say ip65 stored
    # one. Both naive arms pass; the real check fails on cfg_ip.
    lease_lines = [f"1700000000 {':'.join('%02x' % b for b in rand_mac(rng))} "
                   f"{C64_IP} c64 *"]
    res.check(naive_lease_from_leasefile(lease_lines),
              "case4b/leasefile-would-pass",
              "the dnsmasq lease file arm did not pass, so this case no longer "
              "shows why the lease file is the wrong source")

    res.alarm(C.check_dhcp_lease(None, subnet=RIG_SUBNET),
              "case4c/cfg-ip-never-read",
              naive_ok=naive_lease_from_leasefile(lease_lines),
              naive_name="read the dnsmasq lease file")

    # The default must be rejected BY VALUE, with no subnet to lean on: a
    # caller that omits `subnet`, or a rig renumbered onto 192.168.1/24,
    # must still not read ip65's build-time constant as a lease.
    v = C.check_dhcp_lease(default_ip)
    res.check(not v.ok, "case4h/default-rejected-without-a-subnet",
              "with no subnet supplied, ip65's build-time cfg_ip 192.168.1.64 "
              "was accepted as a DHCP lease")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    for name, addr, why in (
            ("case4d/all-zero", b"\x00\x00\x00\x00", "0.0.0.0"),
            ("case4e/link-local", ip4("169.254.7.9"), "IPv4LL, which the C64 does not do"),
            ("case4f/off-subnet", ip4("192.168.9.9"), "not on the rig subnet"),
            ("case4g/host-address", ip4(HOST_IP), "the Mac's own address")):
        v = C.check_dhcp_lease(addr, subnet=RIG_SUBNET, host_ip=HOST_IP)
        res.check(not v.ok, name, f"accepted {why} as a lease")
        if not v.ok:
            print(f"        alarm text: {v.reason}")


# ===========================================================================
# Case 5 — the CS8900a MAC
# ===========================================================================
def case5_mac(rng: random.Random, res: Result) -> None:
    print("\n[case 5] the CS8900a MAC, seen on the cable")
    c64_mac = rand_mac(rng)
    both = cap([
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, wg_type4(rng, 64))),
        eth_frame(HOST_MAC, c64_mac, C.ETHERTYPE_IPV4,
                  ip_udp(HOST_IP, C64_IP, WG_PORT, 51820, wg_type4(rng, 64))),
    ])
    mac_only_raw = [
        eth_frame(HOST_MAC, c64_mac, C.ETHERTYPE_IPV4,
                  ip_udp(HOST_IP, C64_IP, WG_PORT, 51820, wg_type4(rng, 64)))
        for _ in range(5)]
    mac_only = cap(mac_only_raw)

    v = C.check_mac_on_wire(both, c64_mac, HOST_MAC)
    res.check(v.ok, "case5a/mac-on-the-wire", f"rejected a good run: {v.reason}")

    # The capture is all Mac-originated: the C64 was wedged, or unplugged.
    res.alarm(C.check_mac_on_wire(mac_only, c64_mac, HOST_MAC),
              "case5b/only-mac-originated-frames",
              naive_ok=naive_mac_readback(c64_mac, c64_mac),
              naive_name="write the MAC, read it back through the same path")

    res.alarm(C.check_mac_on_wire(both, bytes(C.IP65_DEFAULT_CFG_MAC), HOST_MAC),
              "case5c/ip65-default-cfg-mac",
              naive_ok=naive_mac_readback(C.IP65_DEFAULT_CFG_MAC,
                                          C.IP65_DEFAULT_CFG_MAC),
              naive_name="write the MAC, read it back through the same path")

    # A machine that never read the cartridge's address emits frames whose
    # SOURCE is ip65's build-time cfg_mac. Those frames are genuinely on the
    # wire, so the wire check alone is satisfied -- the value rejection has
    # to stand on its own.
    default_mac = bytes(C.IP65_DEFAULT_CFG_MAC)
    unprogrammed = cap([
        eth_frame(default_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, wg_type4(rng, 64)))
        for _ in range(3)])
    v = C.check_mac_on_wire(unprogrammed, default_mac, HOST_MAC)
    res.check(not v.ok, "case5g/default-mac-actually-on-the-wire",
              "frames carrying ip65's build-time cfg_mac 00:80:10:00:51:00 as "
              "their source satisfied the check; the wire arm alone cannot "
              "tell a programmed CS8900a from an unprogrammed one")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    for name, mac, why in (
            ("case5d/all-zero", b"\x00" * 6, "an unprogrammed MAC"),
            ("case5e/broadcast", b"\xff" * 6, "the broadcast address"),
            ("case5f/multicast-source", b"\x01\x02\x03\x04\x05\x06",
             "a multicast address, illegal as a source")):
        v = C.check_mac_on_wire(both, mac, HOST_MAC)
        res.check(not v.ok, name, f"accepted {why} as the C64's MAC")
        if not v.ok:
            print(f"        alarm text: {v.reason}")


# ===========================================================================
# Case 6 — the two-station trap
# ===========================================================================
def case6_two_stations(rng: random.Random, res: Result) -> None:
    print("\n[case 6] two stations on the cable, and the Mac is one of them")
    c64_mac = rand_mac(rng)
    third = rand_mac(rng)
    while third == c64_mac or third == HOST_MAC:
        third = rand_mac(rng)

    mac_only_raw = [
        eth_frame(HOST_MAC, c64_mac, C.ETHERTYPE_IPV4,
                  ip_udp(HOST_IP, C64_IP, WG_PORT, 51820, wg_type4(rng, 64)))
        for _ in range(6)]
    good_raw = mac_only_raw + [
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, wg_type4(rng, 64)))
        for _ in range(3)]
    third_raw = good_raw + [
        eth_frame(third, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp("10.0.66.99", HOST_IP, 51820, WG_PORT, wg_type4(rng, 64)))]

    v = C.check_c64_originated(cap(good_raw), c64_mac, HOST_MAC,
                               min_frames=3, udp_port=WG_PORT)
    res.check(v.ok, "case6a/both-stations-present", f"rejected a good run: {v.reason}")
    res.check(v.evidence.get("from_c64") == 3 and v.evidence.get("from_host") == 6,
              "case6a/counted-by-source",
              f"source split was {v.evidence.get('from_c64')}/"
              f"{v.evidence.get('from_host')}, staged 3/6")

    # THE TRAP: six WireGuard datagrams on the cable, none from the C64.
    res.alarm(C.check_c64_originated(cap(mac_only_raw), c64_mac, HOST_MAC,
                                     min_frames=1, udp_port=WG_PORT),
              "case6b/mac-talking-to-itself",
              naive_ok=naive_saw_wireguard_traffic(mac_only_raw, WG_PORT),
              naive_name="'the capture contains WireGuard traffic'")

    res.alarm(C.check_c64_originated(cap(third_raw), c64_mac, HOST_MAC,
                                     min_frames=1, udp_port=WG_PORT),
              "case6c/a-third-station",
              naive_ok=naive_saw_wireguard_traffic(third_raw, WG_PORT),
              naive_name="'the capture contains WireGuard traffic'")

    v = C.check_c64_originated(cap(good_raw), c64_mac, c64_mac, min_frames=1)
    res.check(not v.ok, "case6d/same-mac-both-ends-refused",
              "the C64 and the Mac were given the same MAC and the check still "
              "claimed to have discriminated between them")


# ===========================================================================
# Case 7 — the instrument's own instrument
# ===========================================================================
def case7_selftest(rng: random.Random, res: Result) -> None:
    print("\n[case 7] the synthetic wire, and the parser that reads it")
    c64_mac, secret = rand_mac(rng), rand_text(rng, 24, REQ_ALPHABET)
    raw = [eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                     ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, secret)),
           arp_frame(c64_mac, C64_IP, HOST_IP)]
    blob = build_pcap(raw)
    frames = C.parse_pcap(blob)

    res.check(len(frames) == 2, "case7a/frame-count",
              f"parsed {len(frames)} frames from a 2-frame capture")
    res.check(len(frames) == 2 and bytes(frames[0].eth_src) == c64_mac
              and bytes(frames[0].eth_dst) == HOST_MAC,
              "case7a/eth-addresses-survive",
              "the Ethernet addresses did not survive the parse — every source "
              "discrimination in this module rests on them")
    res.check(len(frames) == 2 and frames[0].udp_payload == secret,
              "case7a/udp-payload-exact",
              "the UDP payload came back different from the bytes staged")
    res.check(len(frames) == 2 and frames[1].ethertype == C.ETHERTYPE_ARP,
              "case7a/arp-not-dropped",
              "the ARP frame was dropped; the decoder already in this tree does "
              "exactly that, which is the defect case 1j is about")

    # A corrupted magic must raise, not silently yield zero frames.
    bad = bytearray(blob)
    bad[1] ^= 0xFF
    try:
        C.parse_pcap(bytes(bad))
        res.check(False, "case7b/corrupt-magic-raises",
                  "a corrupted pcap header parsed as an empty capture, which "
                  "reads identically to 'no plaintext found'")
    except C.PcapError as exc:
        res.check(True, "case7b/corrupt-magic-raises")
        print(f"        alarm text: {exc}")

    # And the synthetic captures must be REAL pcaps, not merely something our
    # own parser accepts. tcpdump -r opens no BPF device, so this is safe to
    # run anywhere and needs no privilege.
    if shutil.which("tcpdump") is None:
        res.skip("case7c/tcpdump-agrees", "tcpdump not on PATH")
    else:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            out = subprocess.run(["tcpdump", "-r", path, "-n", "-q"],
                                 capture_output=True, text=True, timeout=20)
            lines = [ln for ln in out.stdout.splitlines() if "IP" in ln or "ARP" in ln]
            res.check(len(lines) == 2, "case7c/tcpdump-agrees",
                      f"tcpdump read {len(lines)} packets from a 2-packet synthetic "
                      f"capture (rc={out.returncode}): {out.stderr.strip()[:200]}")
            vlog(f"tcpdump: {lines}")
        finally:
            os.unlink(path)

    # Reassembly identity: two fragments must come back as the original bytes.
    body = rand_bytes(rng, 400)
    udp = struct.pack(">HHHH", 51820, WG_PORT, 8 + len(body), 0) + body
    fid = 0x4321
    frag = cap([
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 0, 0, b"", ip_id=fid,
                         more_frags=True, raw_ip_payload=udp[:208])),
        eth_frame(c64_mac, HOST_MAC, C.ETHERTYPE_IPV4,
                  ip_udp(C64_IP, HOST_IP, 0, 0, b"", ip_id=fid,
                         frag_off=208, raw_ip_payload=udp[208:])),
    ])
    dgs = C.reassemble(frag)
    res.check(len(dgs) == 1 and dgs[0].data == udp and dgs[0].complete,
              "case7d/fragments-reassemble",
              f"reassembled {len(dgs)} datagrams; bytes "
              f"{'match' if dgs and dgs[0].data == udp else 'DIFFER'}")
    res.check(len(dgs) == 1 and dgs[0].udp_payload == body,
              "case7d/reassembled-udp-payload",
              "the reassembled UDP payload differs from the staged bytes")


# ===========================================================================
# Case 8 — net_last_error, the byte that separates a dropped cartridge
#          from a DHCP problem
# ===========================================================================
def naive_error_nonzero_is_bad(value: int | None) -> bool:
    """'Zero is fine, non-zero is a network error.' True, and useless: it
    cannot tell $41 from $42, which lead to opposite conclusions."""
    return value == 0


def case8_net_last_error(rng: random.Random, res: Result) -> None:
    print("\n[case 8] net_last_error: $41 and $42 mean opposite things")
    v = C.decode_net_last_error(0x00)
    res.check(v.ok, "case8a/zero-is-no-error", f"$00 was reported bad: {v.reason}")

    init, dhcp = C.decode_net_last_error(0x41), C.decode_net_last_error(0x42)
    res.check(not init.ok and not dhcp.ok, "case8b/both-are-failures",
              "an error code decoded as a pass")
    # The point of the decoder is that these two do NOT collapse together.
    res.check(init.evidence.get("name") != dhcp.evidence.get("name")
              and init.evidence.get("meaning") != dhcp.evidence.get("meaning"),
              "case8b/init-and-dhcp-are-distinguished",
              f"$41 and $42 decoded to the same thing: "
              f"{init.evidence.get('name')} / {dhcp.evidence.get('name')} — they "
              "are 'our loader dropped the cartridge' and 'dnsmasq is not "
              "answering', which look identical on the screen and lead to "
              "opposite actions")
    res.check(naive_error_nonzero_is_bad(0x41) == naive_error_nonzero_is_bad(0x42),
              "case8b/naive-conflates-them",
              "the naive 'non-zero is an error' arm already distinguishes them, "
              "so this case no longer shows why a decoder is needed")
    print(f"        $41 -> {init.reason[:88]}")
    print(f"        $42 -> {dhcp.reason[:88]}")

    # $47 is defined and exported so the number stays allocated, and is NEVER
    # emitted; seeing it is a defect in the adapter, not a send failure.
    v = C.decode_net_last_error(0x47)
    res.check(not v.ok and v.evidence.get("name") == "NET_ERR_IP65_UDP_SEND",
              "case8c/reserved-code-flagged",
              f"$47 decoded as {v.evidence.get('name')} / ok={v.ok}; it is "
              "RESERVED and never emitted (src/net/ip65/net.s:126)")
    if not v.ok:
        print(f"        alarm text: {v.reason[:100]}")

    v = C.decode_net_last_error(0x43)
    res.check(not v.ok, "case8d/foreign-code-flagged",
              "$43 is c64-https's NET_ERR_IP65_DNS, which our adapter never "
              "emits, and it decoded as acceptable")
    v = C.decode_net_last_error(0xFF)
    res.check(not v.ok, "case8e/unregistered-code-refused",
              "a code absent from src/net_abi.inc's registry decoded as fine")
    v = C.decode_net_last_error(None)
    res.check(not v.ok, "case8f/unread-error-byte-refused",
              "net_last_error not being read at all passed")

    # The table is cross-checked against the TREE, not trusted.
    net_s = PROJECT_ROOT / "src" / "net" / "ip65" / "net.s"
    if not net_s.exists():
        res.skip("case8g/table-agrees-with-the-tree", f"{net_s} not present")
    else:
        v = C.net_error_table(net_s.read_text())
        res.check(v.ok, "case8g/table-agrees-with-the-tree",
                  f"the decoder's table has drifted from the tree's own "
                  f"equates: {v.reason}")
        vlog(f"equates: {v.evidence.get('in_source')}")
    renumbered = "NET_ERR_IP65_DHCP          = $52\nNET_ERR_IP65_INIT = $41\n"
    res.alarm(C.net_error_table(renumbered), "case8h/renumbering-detected",
              naive_ok=naive_error_nonzero_is_bad(0x00),
              naive_name="a decoder with the table typed in and never checked")
    v = C.net_error_table("; nothing but a comment\n")
    res.check(not v.ok, "case8i/empty-source-refused",
              "a cross-check against a source with no equates in it passed "
              "vacuously, which is the shape of every check in this file that "
              "was ever wrong")

    v = C.check_net_counters(3, 5, expect_sends=5)
    res.check(not v.ok, "case8j/drops-are-a-failure",
              "ip65_recv_dropped of 3 passed")
    v = C.check_net_counters(0, 5, expect_sends=5)
    res.check(v.ok and v.evidence.get("drop_counter_proven") is True,
              "case8j/zero-drops-with-sends-proven",
              f"a clean run was rejected or left unproven: {v.reason}")
    v = C.check_net_counters(0, 0)
    res.check(v.ok and v.evidence.get("drop_counter_proven") is False,
              "case8k/zero-drops-alone-is-unproven",
              "a drop counter reading zero in a run that sent nothing was "
              "reported as proven; a counter that can never move reads zero too")
    # WAS "case8k/fewer-sends-than-we-made", which required this to FAIL.
    # That assertion encoded the wrong model: it read ip65_send_attempts as a
    # run total, so it demanded a false alarm on a healthy multi-send run.
    # net_udp_send stores $01 at the top of every call (net.s:382-383), so
    # 2 attempts after 5 sends means the last send retried twice and the four
    # before it were warm — an ordinary, correct run. Case 17 owns the
    # semantics now; this one is kept as the positive control that the
    # corrected reading does not fail it.
    v = C.check_net_counters(0, 2, expect_sends=5)
    res.check(v.ok and v.evidence.get("drop_counter_proven") is True,
              "case8k/last-send-retried-in-a-multi-send-run",
              f"a run of five sends whose last one retried was rejected: "
              f"{v.reason}")

    # The ADDRESSES come from the build, never from a constant. $78A7/$78A9/
    # $78AA are where these sit in build/labels.txt today; a tool that typed
    # them in reads unrelated RAM the day the build moves and reports it as
    # net_last_error with a straight face.
    labels_path = PROJECT_ROOT / "build" / "labels.txt"
    fake = {"net_last_error": 0x78A7, "ip65_send_attempts": 0x78A9,
            "ip65_recv_dropped": 0x78AA}
    v = C.resolve_symbols(fake)
    res.check(v.ok and v.evidence["found"]["net_last_error"] == "$78A7",
              "case8l/symbols-resolved-from-labels",
              f"resolution failed on a complete label set: {v.reason}")
    res.alarm(C.resolve_symbols({"net_last_error": 0x78A7}),
              "case8l/missing-symbol-is-fatal",
              naive_ok=(0x78A7 == 0x78A7),
              naive_name="a hardcoded $78A7 that never asks the build")
    v = C.resolve_symbols(fake, names=())
    res.check(not v.ok, "case8m/no-symbols-requested-refused",
              "resolving an empty symbol list succeeded vacuously")
    # NOTE ON WHAT PROVES THIS ONE. case8m is an assertion about the TREE --
    # does the build in build/ actually export the three diagnostic bytes --
    # not about library behaviour, so no mutation of ip65_hw_checks.py can
    # be uniquely caught by it, and its absence from the kill credits is
    # expected rather than a gap. What proves its alarm is
    # case8l/missing-symbol-is-fatal, which feeds resolve_symbols a label set
    # that lacks two of the three and requires the refusal.
    if not labels_path.exists():
        res.skip("case8m/this-tree-exports-them", f"{labels_path} not present")
    else:
        labels = {}
        for line in labels_path.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "al" and parts[2].startswith("."):
                labels[parts[2][1:]] = int(parts[1].split(":")[1], 16)
        v = C.resolve_symbols(labels)
        if not v.ok and "uci_send_part" in labels:
            # The gate leaves build/ as whichever backend ran last. A UCI
            # build has no ip65 diagnostics to export, and that is not a
            # defect. This is the ONLY reason this check skips, and it is
            # decided by a positive UCI marker rather than by the absence
            # this check is about -- otherwise the skip would swallow the
            # very failure it is here to find.
            res.skip("case8m/this-tree-exports-them",
                     f"{labels_path.parent.name}/ is a UCI build")
        else:
            res.check(v.ok, "case8m/this-tree-exports-them",
                      f"the ip65 build in {labels_path.parent.name}/ does not "
                      f"export the diagnostic bytes: {v.reason}")
        vlog(f"resolved: {v.evidence.get('found')}")


# ===========================================================================
# Case 9 — the capture bracket
# ===========================================================================
def naive_capture_parses(blob: bytes) -> bool:
    """'The file exists and decodes, so we have a capture of this run.'"""
    try:
        return len(C.parse_pcap(blob)) > 0
    except C.PcapError:
        return False


def case9_capture_bracket(rng: random.Random, res: Result) -> None:
    print("\n[case 9] the capture has to be OF this run")
    started = 1_700_000_000.0 + rng.randrange(0, 10_000)
    raw = [eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                     ip_udp(C64_IP, HOST_IP, 51820, WG_PORT, wg_type4(rng, 64)))
           for _ in range(5)]

    fresh = C.parse_pcap(build_pcap(raw, t0=started + 1))
    v = C.check_capture_bracket(fresh, started, started + 60)
    res.check(v.ok, "case9a/in-window-passes", f"rejected a live capture: {v.reason}")

    # A pcap left over from an earlier session: every frame predates the run.
    stale_blob = build_pcap(raw, t0=started - 7200)
    stale = C.parse_pcap(stale_blob)
    res.alarm(C.check_capture_bracket(stale, started, started + 60,
                                      path="/tmp/rrnet.pcap"),
              "case9b/stale-capture-rejected",
              naive_ok=naive_capture_parses(stale_blob),
              naive_name="'the file exists and decodes'")

    # A capture that was running before the run started and never truncated.
    mixed = C.parse_pcap(build_pcap(raw, t0=started - 600))
    mixed += C.parse_pcap(build_pcap(raw, t0=started + 2))
    res.alarm(C.check_capture_bracket(mixed, started, started + 60),
              "case9c/untruncated-capture-rejected",
              naive_ok=len(mixed) > 0,
              naive_name="'there are frames in the file'")

    v = C.check_capture_bracket([], started, started + 60)
    res.check(not v.ok, "case9d/empty-capture-rejected",
              "a capture with no frames was dated successfully")
    v = C.check_capture_bracket(fresh, started + 60, started)
    res.check(not v.ok, "case9e/inverted-window-rejected",
              "a run whose end precedes its start was accepted")

    # Every frame POSTDATES the window. Only the "nothing inside" branch can
    # see this one -- the "frames predate the run" branch is empty here --
    # and it is the shape a capture reused from a later run takes, or a
    # capture whose clock is hours off.
    future = C.parse_pcap(build_pcap(raw, t0=started + 7200))
    fv = C.check_capture_bracket(future, started, started + 60)
    res.alarm(fv, "case9f/capture-from-after-the-window",
              naive_ok=naive_capture_parses(build_pcap(raw, t0=started + 7200)),
              naive_name="'the file exists and decodes'")
    # The diagnosis, not just the verdict: "no frame is inside the window" is
    # a different fact from "fewer frames inside than we asked for", and a
    # caller that lowered min_inside to 0 must still be told the first one.
    res.check(fv.evidence.get("diagnosis") == "no-frame-inside-the-window",
              "case9f/diagnosis-is-categorical",
              f"diagnosed as {fv.evidence.get('diagnosis')!r}; a capture with "
              "NOTHING from this run in it is categorically stale, not merely "
              "short of a threshold")
    res.check(not C.check_capture_bracket(future, started, started + 60,
                                          min_inside=0).ok,
              "case9g/stale-rejected-even-with-min-inside-0",
              "with min_inside=0 a capture containing no frame from this run "
              "was accepted; the threshold is about how much traffic we "
              "require, never about whether the file is ours")


# ===========================================================================
# Case 10 — echo replies PAIRED, never counted
# ===========================================================================
def naive_replies_arrived(frames, minimum: int = 1) -> bool:
    """'N echo replies arrived in the window.' Scores its best result on the
    stale-queue flush, which is the broken case."""
    return sum(1 for f in frames if f.icmp_type == C.ICMP_ECHO_REPLY) >= minimum


def case10_echo_pairing(rng: random.Random, res: Result) -> None:
    print("\n[case 10] echo replies paired by (id, seq), not counted")
    ident = rng.randrange(1, 0xFFFF)
    bodies = {seq: rand_bytes(rng, 32) for seq in range(1, 5)}

    good: list[bytes] = []
    for seq, body in bodies.items():
        good.append(eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                              icmp_echo(C64_IP, HOST_IP, C.ICMP_ECHO_REQUEST,
                                        ident, seq, body)))
        good.append(eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                              icmp_echo(HOST_IP, C64_IP, C.ICMP_ECHO_REPLY,
                                        ident, seq, body)))
    v = C.check_echo_replies_matched(cap(good), c64_mac=C64_MAC,
                                     host_mac=HOST_MAC, min_pairs=4)
    res.check(v.ok, "case10a/matched-pairs-pass", f"rejected a healthy run: {v.reason}")
    res.check(v.evidence.get("pairs") == 4, "case10a/paired-by-id-and-seq",
              f"paired {v.evidence.get('pairs')} of 4 staged exchanges")

    # THE ONE THAT MATTERS. Nine replies from earlier attempts flush at once
    # when an ARP finally resolves, and none answers anything this run sent.
    stale_ident = (ident + 1) & 0xFFFF
    burst = [eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                       icmp_echo(HOST_IP, C64_IP, C.ICMP_ECHO_REPLY,
                                 stale_ident, seq, rand_bytes(rng, 32)))
             for seq in range(1, 10)]
    burst.insert(0, eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                              icmp_echo(C64_IP, HOST_IP, C.ICMP_ECHO_REQUEST,
                                        ident, 1, bodies[1])))
    res.alarm(C.check_echo_replies_matched(cap(burst), c64_mac=C64_MAC,
                                           host_mac=HOST_MAC, min_pairs=1),
              "case10b/stale-queue-flush",
              naive_ok=naive_replies_arrived(cap(burst), 9),
              naive_name="count the replies that arrived in the window")

    # Requests went out; nothing came back.
    silent = [f for f in good if C.parse_pcap(build_pcap([f]))[0].icmp_type
              == C.ICMP_ECHO_REQUEST]
    # No naive arm: counting DOES catch zero replies, so claiming a live trap
    # would be a false claim. Asserted anyway — it is the likeliest outcome.
    v = C.check_echo_replies_matched(cap(silent), c64_mac=C64_MAC,
                                     host_mac=HOST_MAC, min_pairs=1)
    res.check(not v.ok, "case10c/requests-with-no-replies",
              "four requests with nothing coming back passed")
    if not v.ok:
        print(f"        alarm text: {v.reason}")

    # A reply whose echo data is not a reflection of the request.
    seq = 2
    tampered = [
        eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(C64_IP, HOST_IP, C.ICMP_ECHO_REQUEST, ident, seq,
                            bodies[seq])),
        eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(HOST_IP, C64_IP, C.ICMP_ECHO_REPLY, ident, seq,
                            rand_bytes(rng, 32))),
    ]
    res.alarm(C.check_echo_replies_matched(cap(tampered), c64_mac=C64_MAC,
                                           host_mac=HOST_MAC, min_pairs=1),
              "case10d/reply-does-not-echo-the-request",
              naive_ok=naive_replies_arrived(cap(tampered)),
              naive_name="count the replies that arrived in the window")

    # ONE genuine exchange plus the nine stale ones. This is the realistic
    # shape, and it is the only one that isolates the pairing: min_pairs is
    # satisfied by the real pair, so a checker that merely required enough
    # pairs would pass while nine replies on the wire answered nothing.
    mixed = [
        eth_frame(C64_MAC, HOST_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(C64_IP, HOST_IP, C.ICMP_ECHO_REQUEST, ident, 3,
                            bodies[3])),
        eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(HOST_IP, C64_IP, C.ICMP_ECHO_REPLY, ident, 3,
                            bodies[3])),
    ] + burst[1:]
    res.alarm(C.check_echo_replies_matched(cap(mixed), c64_mac=C64_MAC,
                                           host_mac=HOST_MAC, min_pairs=1),
              "case10f/one-real-pair-hides-a-stale-burst",
              naive_ok=naive_replies_arrived(cap(mixed)),
              naive_name="count the replies that arrived in the window")

    # The Mac pinging ITSELF must not manufacture a pair on a segment where
    # it plays every other role already.
    selfping = [
        eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(HOST_IP, HOST_IP, C.ICMP_ECHO_REQUEST, ident, 9,
                            bodies[1])),
        eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                  icmp_echo(HOST_IP, HOST_IP, C.ICMP_ECHO_REPLY, ident, 9,
                            bodies[1])),
    ]
    res.alarm(C.check_echo_replies_matched(cap(selfping), c64_mac=C64_MAC,
                                           host_mac=HOST_MAC, min_pairs=1),
              "case10e/mac-pinging-itself",
              naive_ok=naive_replies_arrived(cap(selfping)),
              naive_name="count the replies that arrived in the window")


# ===========================================================================
# Case 11 — ARP is evidence
# ===========================================================================
def case11_arp(rng: random.Random, res: Result) -> None:
    print("\n[case 11] ARP tells a dead C64 from a held reply queue")
    exchange = [
        arp_op_frame(HOST_MAC, b"\xff" * 6, C.ARP_REQUEST, HOST_MAC,
                     HOST_IP, C64_IP),
        arp_op_frame(C64_MAC, HOST_MAC, C.ARP_REPLY, C64_MAC, C64_IP, HOST_IP),
    ]
    udp_only = [eth_frame(HOST_MAC, C64_MAC, C.ETHERTYPE_IPV4,
                          ip_udp(HOST_IP, C64_IP, WG_PORT, 51820,
                                 wg_type4(rng, 64))) for _ in range(4)]

    v = C.check_arp_exchange(cap(exchange + udp_only), c64_mac=C64_MAC,
                             host_mac=HOST_MAC, c64_ip=C64_IP, host_ip=HOST_IP)
    res.check(v.ok, "case11a/exchange-seen", f"rejected a resolved segment: {v.reason}")
    res.check(v.evidence.get("c64_replies_for_itself") == 1,
              "case11a/c64-answered-for-itself",
              f"counted {v.evidence.get('c64_replies_for_itself')} ARP replies "
              "from the C64, staged 1")

    # No ARP at all: the decoder already in this tree drops every ARP frame,
    # so a checker built on it can never reach this question.
    res.alarm(C.check_arp_exchange(cap(udp_only), c64_mac=C64_MAC,
                                   host_mac=HOST_MAC, c64_ip=C64_IP,
                                   host_ip=HOST_IP),
              "case11b/no-arp-at-all",
              naive_ok=all(naive_parse_frame(f) is None or True for f in udp_only),
              naive_name="a decoder that returns None for every non-IPv4 frame")

    # ARP present, but the Mac talking to itself: three requests, no answer.
    unanswered = [arp_op_frame(HOST_MAC, b"\xff" * 6, C.ARP_REQUEST, HOST_MAC,
                               HOST_IP, C64_IP) for _ in range(3)]
    res.alarm(C.check_arp_exchange(cap(unanswered), c64_mac=C64_MAC,
                                   host_mac=HOST_MAC, c64_ip=C64_IP,
                                   host_ip=HOST_IP),
              "case11c/arp-but-none-from-the-c64",
              naive_ok=len(unanswered) > 0,
              naive_name="'there are ARP frames in the capture'")

    # The two failures must not collapse into one message. "No ARP frames at
    # all" points at the tap's filter; "ARP frames, none from the C64" points
    # at the C64. An operator does different things about each.
    r1 = C.check_arp_exchange(cap(udp_only), c64_mac=C64_MAC, host_mac=HOST_MAC,
                              c64_ip=C64_IP, host_ip=HOST_IP)
    r2 = C.check_arp_exchange(cap(unanswered), c64_mac=C64_MAC,
                              host_mac=HOST_MAC, c64_ip=C64_IP, host_ip=HOST_IP)
    res.check(r1.evidence.get("diagnosis") == "no-arp-frames"
              and r2.evidence.get("diagnosis") == "no-arp-from-the-c64",
              "case11d/two-distinct-arp-diagnoses",
              "'no ARP at all' and 'ARP but none from the C64' produced the "
              "same diagnosis; the first indicts the tap, the second the C64")


# ===========================================================================
# Case 12 — ip65's shipped config, and the pinned lease
# ===========================================================================
def case12_config_and_pin(rng: random.Random, res: Result) -> None:
    print("\n[case 12] ip65 ships every config field non-zero")
    leased = ip4(C64_IP)
    netmask = bytes(C.IP65_DEFAULT_CFG_NETMASK)     # also the correct value here
    gateway = ip4(HOST_IP)

    v = C.check_ip65_config_written(leased, netmask, gateway, C64_MAC)
    res.check(v.ok, "case12a/all-written", f"rejected a configured stack: {v.reason}")
    res.check(v.evidence.get("default_but_not_decisive") == ["cfg_netmask"],
              "case12a/netmask-reported-not-asserted",
              f"netmask handling: {v.evidence.get('default_but_not_decisive')} — "
              "255.255.255.0 is BOTH ip65's shipped default and the correct "
              "leased value here, so it can never be evidence either way and "
              "must not be asserted on")

    for name, args_, why in (
            ("case12b/cfg-ip-default",
             (bytes(C.IP65_DEFAULT_CFG_IP), netmask, gateway, C64_MAC),
             "cfg_ip still 192.168.1.64"),
            ("case12c/cfg-gateway-default",
             (leased, netmask, bytes(C.IP65_DEFAULT_CFG_GATEWAY), C64_MAC),
             "cfg_gateway still 192.168.1.1"),
            ("case12d/cfg-mac-default",
             (leased, netmask, gateway, bytes(C.IP65_DEFAULT_CFG_MAC)),
             "cfg_mac still 00:80:10:00:51:00, i.e. eth_init never ran")):
        v = C.check_ip65_config_written(*args_)
        res.check(not v.ok, name, f"accepted a stack with {why}")
        if not v.ok:
            print(f"        alarm text: {v.reason}")

    # The pinned lease. A POOL address is not an error anywhere else, but it
    # means the --dhcp-host reservation did not match.
    pool = ip4(f"10.0.66.{rng.randrange(10, 60)}")
    res.alarm(C.check_dhcp_lease(pool, subnet=RIG_SUBNET, host_ip=HOST_IP,
                                 expect_ip=C64_IP),
              "case12e/pool-address-not-the-pin",
              naive_ok=naive_lease_nonzero(pool),
              naive_name="'cfg_ip is non-zero, so we have a lease'")

    v = C.check_dhcp_lease(ip4(C64_IP), subnet=RIG_SUBNET, host_ip=HOST_IP,
                           expect_ip=C64_IP)
    res.check(v.ok, "case12e/pinned-address-passes",
              f"rejected the pinned {C64_IP}: {v.reason}")

    # Three failures that mean three different things must not collapse into
    # one message: an operator acts on the difference.
    reasons = [C.check_dhcp_lease(bytes(C.IP65_DEFAULT_CFG_IP), subnet=RIG_SUBNET,
                                  expect_ip=C64_IP).reason,
               C.check_dhcp_lease(b"\x00\x00\x00\x00", subnet=RIG_SUBNET,
                                  expect_ip=C64_IP).reason,
               C.check_dhcp_lease(pool, subnet=RIG_SUBNET, expect_ip=C64_IP).reason]
    res.check(len(set(reasons)) == 3, "case12f/three-distinct-diagnoses",
              "the shipped default, 0.0.0.0 and a pool address produced "
              f"{len(set(reasons))} distinct messages, not 3 — they mean "
              "'DHCP never ran', 'no lease' and 'the reservation did not match'")


# ===========================================================================
# Case 13 — the bench-health control
# ===========================================================================
def case13_bench_health(rng: random.Random, res: Result) -> None:
    print("\n[case 13] the bench-health control, and what it does NOT prove")
    v = C.check_bench_health(True, replies=3, rtt_ms=[2.1, 2.4, 3.0])
    res.check(v.ok, "case13a/healthy-bench", f"rejected a healthy bench: {v.reason}")
    # A green control must not be over-read: it links c64rrnet.lib, our blob
    # links the combo wrapper, and a fault in the combo glue passes here.
    res.check(C.BENCH_CONTROL_CAVEAT in v.reason
              and v.evidence.get("caveat") == C.BENCH_CONTROL_CAVEAT,
              "case13a/caveat-travels-with-the-pass",
              "the PASS does not carry the driver-path caveat in its own text, "
              "so a green control can be read as 'our driver works' when it "
              "shares no driver path with our build at all")

    v = C.check_bench_health(False, replies=0)
    res.check(not v.ok, "case13b/failed-control-gates-the-run",
              "a failed bench control did not fail the check")
    v = C.check_bench_health(None)
    res.check(not v.ok, "case13c/control-not-run",
              "the control never having been run passed")
    v = C.check_bench_health(True, replies=0)
    res.check(not v.ok, "case13d/success-without-a-reply",
              "the control reported success with zero replies and was believed; "
              "a control that passes without an answer is not a control")
    v = C.check_bench_health(True, replies=2, rtt_ms=[2.0, 900.0])
    res.check(not v.ok, "case13e/implausible-rtt",
              "a 900 ms round trip passed on silicon that does 2-3 ms")

    # "Never run" and "ran and failed" are different facts. Collapsing them
    # turns "we forgot the control" into "the bench is broken", and the
    # operator then goes looking for a hardware fault that is not there.
    not_run = C.check_bench_health(None)
    failed = C.check_bench_health(False, replies=0)
    res.check(not_run.reason != failed.reason
              and not_run.evidence.get("ping_ok") is None
              and failed.evidence.get("ping_ok") is False,
              "case13f/not-run-differs-from-failed",
              "a control that was never run and a control that failed produced "
              "the same diagnosis")


# ===========================================================================
# --self-check — the alarm proof for the ALARMS
# ===========================================================================
#: One deliberate defect in tools/ip65_hw_checks.py per entry, as a literal
#: source substitution. Each is a plausible implementation, not a random
#: byte flip: the shapes a hurried checker actually takes. Running
#: `--self-check` applies each in a temporary copy of the module, re-runs
#: this whole suite against it, and requires the suite to go RED and to name
#: which checks caught it. A mutant that SURVIVES is a defect this suite
#: cannot see, and is reported as a failure.
#:
#: This is the answer to "the cases pass, but would they ever fail?" -- the
#: question nobody asked of the raw-path tool that returned 0 unconditionally
#: for two days.
#:
#: AND ITS LIMIT, which is worth knowing before trusting a score here.
#: Mutation testing proves a check discriminates SOMETHING. It cannot prove
#: it discriminates the RIGHT thing. This suite has the case on record: the
#: mutant that replaced check_net_counters' drop_counter_proven expression
#: with a bare `True` passed for weeks while the expression itself was
#: wrong -- `> 0` where `> 1` was meant. The two differ only when
#: send_attempts == 1, the healthy warm-cache case, and no mutant had
#: thought to vary it. A mutant now pins that boundary
#: (counters/proven-at-greater-than-zero), but the general lesson stands: a
#: mutant kills a defect someone imagined. Reading the tree is what finds
#: the ones nobody did.
MUTANTS: dict[str, tuple[str, str]] = {
    "leak/compares-at-offset-0": (
        "at = hay.find(pat)\n        while at >= 0:",
        "at = 0 if hay.startswith(pat) else -1\n        while at >= 0:"),
    "leak/no-reassembly": (
        "        if f.is_fragmented:", "        if False:"),
    "leak/forward-only": (
        '("reversed", needle[::-1])', '("reversed", needle)'),
    "leak/ascii-only": (
        '("petscii", petscii_form(needle)),', '("petscii", needle),'),
    "leak/ip-payload-only": (
        "    for f in frames:\n        src = _fmt_mac(f.eth_src)",
        "    for f in []:\n        src = _fmt_mac(f.eth_src)"),
    "leak/empty-capture-is-clean": (
        '    if not frames:\n        return Verdict(False, "the capture is empty',
        '    if not frames:\n        return Verdict(True, "the capture is empty'),
    "pcap/accepts-snaplen-truncation": (
        "        if incl < orig and strict:", "        if False:"),
    "handshake/responder-view-only": (
        "    if c64_wg_state != WG_STATE_ACTIVE:", "    if False:"),
    "handshake/accepts-unread-wg-state": (
        '    if c64_wg_state is None:\n        return Verdict(False, "wg_state was never read',
        '    if c64_wg_state is None:\n        return Verdict(True, "wg_state was never read'),
    "transport/outbound-by-count": (
        "    for i, got in enumerate(received):\n        if got == expected:",
        "    for i, got in enumerate(received):\n        if True:"),
    "transport/inbound-ignores-length": (
        "    if c64_len != len(expected):", "    if False:"),
    "transport/inbound-accepts-unread-buffer": (
        "    if c64_plaintext is None or c64_len is None:",
        "    if False and c64_plaintext is None:"),
    "lease/non-zero-is-enough": (
        "    if octets == IP65_DEFAULT_CFG_IP:", "    if False:"),
    "lease/any-subnet": (
        "    if subnet is not None:", "    if False:"),
    "mac/never-looks-at-the-wire": (
        "    if len(seen) < min_frames:", "    if False:"),
    "mac/accepts-ip65-default": (
        "    if tuple(mac) == IP65_DEFAULT_CFG_MAC:", "    if False:"),
    "source/ignores-eth-src": (
        "        if src == c64_mac:",
        "        if src == c64_mac or src == host_mac:"),
    "source/tolerates-a-third-station": (
        "    if s.other:", "    if False:"),
    "error/conflates-init-and-dhcp": (
        "    name, meaning = NET_ERRORS[value]",
        '    name, meaning = ("NET_ERR", "a network error")'),
    "error/reserved-code-accepted": (
        "    if value in NET_ERRORS_RESERVED:", "    if False:"),
    "error/unregistered-code-accepted": (
        '        return Verdict(False, f"${value:02X} is not in the '
        'net_last_error registry "',
        '        return Verdict(True, f"${value:02X} is not in the '
        'net_last_error registry "'),
    # A table entry renumbered away from the tree. ONLY case8g can see this:
    # it is the check that compares the decoder's table against the tree's
    # own equates, and $46 appears in the real net.s but in neither of the
    # synthetic sources case8h and case8i use. Added because case8g had never
    # been exercised by the mutation harness at all -- it was skipping in
    # every mutant run -- so its power against a real defect was unmeasured
    # even after the skip was fixed. Present is not the same as proven.
    "error/table-entry-renumbered-off-the-tree": (
        '    0x46: ("NET_ERR_IP65_UDP_LISTEN", "udp_add_listener failed"),',
        '    0x56: ("NET_ERR_IP65_UDP_LISTEN", "udp_add_listener failed"),'),
    "error/table-not-cross-checked": (
        "    drift = {n: (known.get(n), v) for n, v in found.items() "
        "if known.get(n) != v}",
        "    drift = {}"),
    # The exact defect two reviewers found: `> 0` is true on every send that
    # happened at all, so it reports the drop counter as proven precisely on
    # the warm-cache runs where it is proven least, and SUPPRESSES the note.
    "counters/proven-at-greater-than-zero": (
        'ev["drop_counter_proven"] = send_attempts > 1',
        'ev["drop_counter_proven"] = send_attempts > 0'),
    "counters/zero-drops-claimed-proven": (
        'ev["drop_counter_proven"] = send_attempts > 1',
        'ev["drop_counter_proven"] = True'),
    # Reading the per-send byte as a run total: a guaranteed false alarm on
    # every healthy multi-send run.
    "counters/per-send-byte-read-as-cumulative": (
        "    if expect_sends is not None and expect_sends >= 1 and send_attempts < 1:",
        "    if expect_sends is not None and send_attempts < expect_sends:"),
    "counters/note-dropped-from-evidence": (
        '    ev["unproven_note"] = note', '    _dropped = note'),
    "bracket/stale-capture-accepted": (
        "    if not inside:", "    if False:"),
    "bracket/untruncated-capture-accepted": (
        "    if before:", "    if False:"),
    "echo/counts-instead-of-pairing": (
        "    if audit.unmatched_replies:", "    if False:"),
    "echo/ignores-the-echo-payload": (
        "    bad = [p.key for p in audit.pairs if not p.payload_matches]",
        "    bad = []"),
    "echo/accepts-requests-from-any-station": (
        "            if c64_mac is not None and bytes(f.eth_src) != bytes(c64_mac):",
        "            if False:"),
    "arp/accepts-a-capture-with-no-arp": (
        "    if not arps:", "    if False:"),
    "arp/accepts-arp-with-none-from-the-c64": (
        "    if not (c64_answered or c64_asked):", "    if False:"),
    "config/ignores-the-shipped-defaults": (
        "    if still_default:", "    if False:"),
    "lease/ignores-the-pinned-address": (
        "    if expect_ip is not None and _fmt_ip(octets) != expect_ip:",
        "    if False:"),
    "bench/green-control-drops-the-caveat": (
        'f". CAVEAT: {BENCH_CONTROL_CAVEAT}", ev)',
        '".", ev)'),
    "bench/control-not-run-is-fine": (
        "    if ping_ok is None:", "    if False and ping_ok is None:"),
    "bench/success-without-a-reply": (
        "    if replies < 1:", "    if False:"),
    "symbols/missing-symbol-tolerated": (
        "    if missing:", "    if False:"),
    "symbols/empty-request-accepted": (
        "    if not names:", "    if False and not names:"),
    # The two blockers found after the first merge attempt. Neither may
    # regress: an absence claim that does not know whether the C64 spoke,
    # and a leak search that cannot see the shifted-letter block our
    # uppercase payload alphabet leaves entirely to it.
    "absence/no-c64-origin-guard": (
        "    if len(c64_dgs) < min_c64_datagrams:", "    if False:"),
    "absence/missing-c64-mac-is-a-pass": (
        "        return Verdict(False,\n"
        "                       \"no C64 MAC was supplied",
        "        return Verdict(True,\n"
        "                       \"no C64 MAC was supplied"),
    "absence/no-type4-requirement": (
        "    if require_type4_port is not None and not type4:", "    if False:"),
    "verdict/third-state-collapsed-into-fail": (
        '        if not self.status:\n'
        '            self.status = "pass" if self.ok else "fail"',
        '        if True:\n'
        '            self.status = "pass" if self.ok else "fail"'),
    "leak/no-shifted-petscii": (
        '("petscii-shifted", petscii_shifted_form(needle)),',
        '("petscii-shifted", needle),'),
    "chip/host-path-value-accepted": (
        "    if product_id == HOST_PATH_DE00_WORD:", "    if False:"),
    "chip/zeros-are-absence": (
        '        ev["diagnosis"] = "unidentified-zeros"',
        '        ev["diagnosis"] = "no-cartridge"'),
    "bench/chip-failure-does-not-block": (
        "    if product_id is not None and not chip.ok:", "    if False:"),
}


def _run_against(module_src: str, seed: int) -> tuple[int, list[str]]:
    """Re-run THIS suite against a temporary copy of a mutated checker."""
    import re
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "ip65_hw_checks.py").write_text(module_src)
        shutil.copy(Path(__file__).resolve(), d / "suite.py")
        proc = subprocess.run(
            [sys.executable, str(d / "suite.py"), "--seed", str(seed)],
            capture_output=True, text=True, timeout=120,
            env={**os.environ,
                 "IP65_CHECKS_MODULE": str(d / "ip65_hw_checks.py"),
                 "IP65_PROJECT_ROOT": str(PROJECT_ROOT),
                 "IP65_MUTATION_CHILD": "1"})
        skips = re.findall(r"^  SKIP  (\S+)", proc.stdout, re.M)
        return (proc.returncode,
                re.findall(r"^  FAIL  (\S+)", proc.stdout, re.M), skips)


def self_check(seed: int) -> int:
    src = _CHECKS_PATH.read_text()
    print(f"\n[--self-check] {len(MUTANTS)} deliberate defects in "
          f"{_CHECKS_PATH.name}, each must turn this suite red")
    rc, fails, skips = _run_against(src, seed)
    if rc != 0:
        print(f"  FATAL  the unmutated baseline is already red ({fails}); "
              "no mutant result would mean anything")
        return 2
    if skips:
        print(f"  FATAL  the baseline skipped {skips} inside the mutation "
              "harness. Every mutant below would be measured against a "
              "denominator missing those checks, and the headline would still "
              "read '0 failed'")
        return 2
    print("  baseline (unmutated) is green, with no skipped checks")
    survived, missing = [], []
    for name, (old, new) in MUTANTS.items():
        if old not in src:
            print(f"  FAIL  {name}\n        the anchor text is no longer in "
                  "the module; the defect was never introduced, so its result "
                  "below would be a lie")
            missing.append(name)
            continue
        rc, fails, skips = _run_against(src.replace(old, new, 1), seed)
        if skips:
            print(f"  FAIL  {name}\n        the mutant run skipped {skips}; "
                  "its verdict was reached with checks missing")
            survived.append(name)
            continue
        if rc == 0:
            print(f"  FAIL  {name}\n        SURVIVED — this suite cannot see "
                  "that defect")
            survived.append(name)
        else:
            print(f"  PASS  {name}  (killed by {len(fails)}: {', '.join(fails[:3])}"
                  f"{'...' if len(fails) > 3 else ''})")
    bad = len(survived) + len(missing)
    print(f"\nResults: {len(MUTANTS) - bad} killed, {len(survived)} survived, "
          f"{len(missing)} not applied — {len(MUTANTS)} mutants total")
    return 0 if bad == 0 else 1


# ===========================================================================
def stamp(path: Path) -> str:
    data = path.read_bytes()
    return (f"{path} sha256={hashlib.sha256(data).hexdigest()[:16]} "
            f"mtime={time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(path.stat().st_mtime))} "
            f"bytes={len(data)}")


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--only", default=None,
                    help="run one case: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--self-check", action="store_true",
                    help="mutate the checker module 18 ways and require this "
                         "suite to go red for every one")
    args = ap.parse_args()
    VERBOSE = args.verbose

    seed = args.seed if args.seed is not None else \
        int(os.environ.get("TEST_SEED", random.randrange(1 << 30)))
    print(f"seed={seed}   (reproduce with --seed {seed})")
    print(f"loaded {stamp(_CHECKS_PATH)}")
    print(f"suite  {stamp(Path(__file__).resolve())}")
    rng = random.Random(seed)

    if args.self_check:
        return self_check(seed)

    res = Result()
    cases = {
        "1": lambda: case1_plaintext(rng, res),
        "2": lambda: case2_handshake(rng, res),
        "3": lambda: case3_transport(rng, res, seed),
        "4": lambda: case4_dhcp(rng, res),
        "5": lambda: case5_mac(rng, res),
        "6": lambda: case6_two_stations(rng, res),
        "7": lambda: case7_selftest(rng, res),
        "8": lambda: case8_net_last_error(rng, res),
        "9": lambda: case9_capture_bracket(rng, res),
        "10": lambda: case10_echo_pairing(rng, res),
        "11": lambda: case11_arp(rng, res),
        "12": lambda: case12_config_and_pin(rng, res),
        "13": lambda: case13_bench_health(rng, res),
        "14": lambda: case14_empty_corpus(rng, res),
        "17": lambda: case17_send_attempts_semantics(rng, res),
        "15": lambda: case15_shifted_petscii(rng, res),
        "16": lambda: case16_cs8900a(rng, res),
    }
    for key, fn in cases.items():
        if args.only and args.only != key:
            continue
        fn()

    total = res.passed + res.failed
    if len(set(res.names)) != len(res.names):
        dupes = sorted({n for n in res.names if res.names.count(n) > 1})
        print(f"\nFATAL: duplicate check names {dupes} — the denominator is not "
              "a stable identity")
        return 2
    real = res.passed - res.skipped
    print(f"\nResults: {real} passed, {res.failed} failed, {res.skipped} skipped "
          f"— {total} checks total")
    if not args.only and total != EXPECTED_CHECKS:
        print(f"FATAL: {total} checks ran, expected exactly {EXPECTED_CHECKS}. "
              "A moving denominator makes two runs incomparable and is how a "
              "case that silently stopped running hides. Update EXPECTED_CHECKS "
              "deliberately when adding one.")
        return 2
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
