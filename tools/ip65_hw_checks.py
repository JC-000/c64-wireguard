#!/usr/bin/env python3
"""tools/ip65_hw_checks.py — the ASSERTIONS for the ip65/RR-Net hardware run.

Why this is a separate module
=============================
Everything the first-ever ip65 hardware validation claims has to be decided
by a function that can be fed a KNOWN-BAD input off-device and observed to
fail. This project has already shipped a tool that was cited for two days
as "the raw path is clean, verified byte-for-byte" whose verification
function was defined and never called and whose main() returned 0
unconditionally: unplug the responder and it still passed. A green result
on a first-ever hardware path is exactly the result nobody re-reads.

So the verdicts live here, as pure functions over bytes, and
tools/test_ip65_hw_checks_unit.py proves each one alarms. The hardware
tool supplies the pcap and the DMA reads; it does not decide anything.

Every function returns a Verdict. `ok` is the verdict, `reason` is for
humans, and `evidence` is the structured record the caller should log --
callers must branch on `ok`, never on `reason`.

THE TOPOLOGY THIS IS WRITTEN FOR
================================
    [ C64 + RR-Net (CS8900a) ] <--- cable, no switch ---> [ Mac NIC en4 ]

There are exactly TWO stations on that segment and the Mac is one of them.
A capture "containing WireGuard traffic" therefore proves nothing at all
about the C64: the Mac's own outbound frames satisfy it. Every wire
assertion here discriminates BY ETHERNET SOURCE ADDRESS, and a frame from
a third MAC is a hard failure rather than an ignorable oddity -- on a
two-station cable it means the capture is not of the segment we think.

TRAPS THAT ARE ALREADY IN THE TREE
==================================
* ip65/ip65/config.s:18 -- `cfg_ip` is initialised to 192.168.1.64, NOT to
  zeros (the zero line right below it is commented out). "We got a lease"
  cannot be "cfg_ip is non-zero": that is true before DHCP runs at all.
  Same for `cfg_mac` at config.s:17, which is 00:80:10:00:51:00.
* tools/test_ip65_arp_first_send_vice.py:583 `parse_frame()` -- the pcap
  decoder most likely to be copied -- returns IP/UDP fields only and DROPS
  the Ethernet source MAC, so nothing built on it can tell a C64 frame from
  a Mac frame. It also returns None for anything that is not IPv4, which
  silently discards ARP.
"""
from __future__ import annotations

import hashlib
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

# ---------------------------------------------------------------------------
# ip65 build-time defaults. Present so a check can REJECT them: reading one
# of these back means the code that was supposed to overwrite it did not run.
# ip65/ip65/config.s:17-18.
# ---------------------------------------------------------------------------
IP65_DEFAULT_CFG_IP = (192, 168, 1, 64)
IP65_DEFAULT_CFG_NETMASK = (255, 255, 255, 0)
IP65_DEFAULT_CFG_GATEWAY = (192, 168, 1, 1)
IP65_DEFAULT_CFG_MAC = (0x00, 0x80, 0x10, 0x00, 0x51, 0x00)

# ---------------------------------------------------------------------------
# The rig, from tools/rig-up-rrnet-macos.sh. 10.0.66/24 and not 10.0.65/24:
# the VICE feth rig already owns 10.0.65.1 and the two would collide.
# ---------------------------------------------------------------------------
RIG_HOST_IP = "10.0.66.1"
RIG_HOST_MAC = bytes.fromhex("c05627b11638")        # the Mac's en4
RIG_C64_IP = "10.0.66.200"                          # pinned via dhcp-host
RIG_C64_MAC = bytes.fromhex("000e3a646464")         # ip65's MAC on this card
RIG_SUBNET = "10.0.66.0"
RIG_POOL = ("10.0.66.10", "10.0.66.60")

#: src/wg/data.s:727 -- wg_state: 0=IDLE, 1=HS_SENT, 2=ACTIVE.
WG_STATE_IDLE = 0
WG_STATE_HS_SENT = 1
WG_STATE_ACTIVE = 2

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_ICMP = 1
IPPROTO_UDP = 17

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

ARP_REQUEST = 1
ARP_REPLY = 2

#: A run of plaintext shorter than this inside one datagram is not reported
#: as a partial leak. Payloads are drawn from a random alphabet, so a run of
#: 8 arising by chance is astronomically unlikely; below that the report
#: would be noise from short common substrings.
PARTIAL_RUN_MIN = 8


class PcapError(ValueError):
    """The capture is not a thing we can decide anything from."""


# ===========================================================================
# Verdicts
# ===========================================================================
@dataclass
class Verdict:
    """A verdict with THREE states, not two.

    "we looked and it was clean" and "we could not look" are different
    facts, and collapsing them is how an absence claim gets made about an
    empty corpus. `status` is "pass", "fail" or "inconclusive"; `ok` is true
    only for "pass", so an inconclusive verdict FAILS CLOSED for any caller
    that branches on `ok` alone, while a caller that wants to say so can
    read `status`. An inconclusive verdict that also read as a pass would
    defeat the whole point, so that combination is refused at construction.
    """
    ok: bool
    reason: str
    evidence: dict = field(default_factory=dict)
    status: str = ""

    def __post_init__(self) -> None:
        if not self.status:
            self.status = "pass" if self.ok else "fail"
        if self.status not in ("pass", "fail", "inconclusive"):
            raise ValueError(f"unknown verdict status {self.status!r}")
        if self.status != "pass" and self.ok:
            raise ValueError("a verdict that is not a pass must not read as ok")
        if self.status == "pass" and not self.ok:
            raise ValueError("a passing verdict must read as ok")

    @property
    def inconclusive(self) -> bool:
        return self.status == "inconclusive"

    def __bool__(self) -> bool:      # pragma: no cover - convenience only
        return self.ok


def _fmt_mac(mac: bytes | Sequence[int]) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def _fmt_ip(ip: bytes | Sequence[int]) -> str:
    return ".".join(str(b) for b in ip)


# ===========================================================================
# pcap decoding -- keeps the Ethernet header
# ===========================================================================
@dataclass
class Frame:
    index: int
    ts: float
    eth_src: bytes
    eth_dst: bytes
    ethertype: int
    raw: bytes                 # the whole captured frame, Ethernet header included
    # IPv4 fields; None for ARP and anything else.
    ip_src: bytes | None = None
    ip_dst: bytes | None = None
    ip_proto: int | None = None
    ip_id: int | None = None
    frag_off: int | None = None       # in BYTES, not 8-byte units
    more_frags: bool = False
    ip_payload: bytes = b""           # everything after the IP header
    sport: int | None = None
    dport: int | None = None
    udp_payload: bytes = b""          # only for a first/unfragmented UDP frame
    # ICMP echo, decoded because the bench-health control is a ping and its
    # replies have to be PAIRED to requests, not counted (see pair_echoes).
    icmp_type: int | None = None
    icmp_id: int | None = None
    icmp_seq: int | None = None
    icmp_data: bytes = b""
    # ARP, decoded because on this rig ARP is EVIDENCE, not noise: macOS
    # queues replies against a stale neighbour entry and flushes the whole
    # backlog the instant an ARP resolves, so "no ping replies" and "the C64
    # is dead" are different states that only the ARP exchange separates.
    arp_op: int | None = None
    arp_sender_mac: bytes | None = None
    arp_sender_ip: bytes | None = None
    arp_target_ip: bytes | None = None

    @property
    def is_first_fragment(self) -> bool:
        return self.frag_off == 0

    @property
    def is_fragmented(self) -> bool:
        return bool(self.more_frags) or bool(self.frag_off)


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # us, little endian
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # ns, little endian
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # us, big endian
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # ns, big endian
}


def parse_pcap(data: bytes, *, strict: bool = True) -> list[Frame]:
    """Decode a classic pcap (link type EN10MB) into Frames.

    Unlike the decoder in test_ip65_arp_first_send_vice.py this KEEPS the
    Ethernet header, and it returns ARP and other ethertypes rather than
    dropping them -- both are load-bearing here: the source MAC is how a
    C64 frame is told from a Mac frame, and DHCP/ARP are how the lease and
    the CS8900a MAC show up on the wire at all.

    A truncated trailing record (tcpdump mid-write) is skipped, not
    mis-parsed. Anything else wrong with the file raises PcapError when
    `strict`: a capture we cannot decode must not read as "no leak found".
    """
    if len(data) < 24:
        raise PcapError(f"capture is {len(data)} bytes, shorter than a pcap header")
    magic = data[:4]
    if magic not in _PCAP_MAGICS:
        raise PcapError(f"not a pcap file (magic {magic.hex()}); pcapng is not supported")
    endian, ts_div = _PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1 and strict:
        raise PcapError(f"link type {linktype} is not EN10MB(1); "
                        "there is no Ethernet header to read a MAC from")
    frames: list[Frame] = []
    off, idx = 24, 0
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > 262144:
            raise PcapError(f"record {idx} claims {incl} captured bytes")
        if off + incl > len(data):
            break                        # still being written
        raw = data[off:off + incl]
        off += incl
        if incl < orig and strict:
            raise PcapError(
                f"record {idx} is TRUNCATED ({incl} of {orig} bytes on the wire) "
                "-- tcpdump was run without `-s 0`; a plaintext search over a "
                "snaplen-clipped capture cannot see the end of a datagram")
        f = _decode_frame(idx, sec + frac / ts_div, raw)
        idx += 1
        if f is not None:
            frames.append(f)
    return frames


def _decode_frame(index: int, ts: float, raw: bytes) -> Frame | None:
    if len(raw) < 14:
        return None
    dst, src = raw[0:6], raw[6:12]
    etype = struct.unpack(">H", raw[12:14])[0]
    body = raw[14:]
    if etype == 0x8100 and len(body) >= 4:       # 802.1Q; unwrap one tag
        etype = struct.unpack(">H", body[2:4])[0]
        body = body[4:]
    f = Frame(index=index, ts=ts, eth_src=src, eth_dst=dst,
              ethertype=etype, raw=raw)
    if etype == ETHERTYPE_ARP:
        _decode_arp(f)
        return f
    if etype != ETHERTYPE_IPV4 or len(body) < 20:
        return f
    ihl = (body[0] & 0x0F) * 4
    if ihl < 20 or len(body) < ihl:
        return f
    total = struct.unpack(">H", body[2:4])[0]
    # Trust the IP total-length field over the captured length: Ethernet pads
    # short frames to 60 bytes, and that padding is NOT datagram content. A
    # searcher that included it would report bytes the sender never chose.
    if 20 <= total <= len(body):
        body = body[:total]
    flags_frag = struct.unpack(">H", body[6:8])[0]
    f.ip_id = struct.unpack(">H", body[4:6])[0]
    f.more_frags = bool(flags_frag & 0x2000)
    f.frag_off = (flags_frag & 0x1FFF) * 8
    f.ip_proto = body[9]
    f.ip_src, f.ip_dst = body[12:16], body[16:20]
    f.ip_payload = body[ihl:]
    if f.ip_proto == IPPROTO_UDP and f.frag_off == 0 and len(f.ip_payload) >= 8:
        sport, dport, ulen = struct.unpack(">HHH", f.ip_payload[0:6])
        f.sport, f.dport = sport, dport
        f.udp_payload = f.ip_payload[8:8 + max(0, ulen - 8)]
    elif f.ip_proto == IPPROTO_ICMP and f.frag_off == 0 and len(f.ip_payload) >= 8:
        f.icmp_type = f.ip_payload[0]
        if f.icmp_type in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY):
            f.icmp_id, f.icmp_seq = struct.unpack(">HH", f.ip_payload[4:8])
            f.icmp_data = f.ip_payload[8:]
    return f


def _decode_arp(f: Frame) -> None:
    """ARP fields, in place. Only the IPv4-over-Ethernet shape."""
    body = f.raw[14:]
    if len(body) < 28:
        return
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", body[0:8])
    if (htype, ptype, hlen, plen) != (1, ETHERTYPE_IPV4, 6, 4):
        return
    f.arp_op = op
    f.arp_sender_mac = body[8:14]
    f.arp_sender_ip = body[14:18]
    f.arp_target_ip = body[24:28]


# ===========================================================================
# IP fragment reassembly
# ===========================================================================
@dataclass
class Datagram:
    """One IP datagram, with every frame that carried it.

    `data` is the reassembled IP payload (the UDP header included when
    proto 17). `eth_srcs` is every Ethernet source that contributed --
    normally one; more than one means something is wrong with the capture
    and the caller should treat the datagram as unattributable.
    """
    key: tuple
    data: bytes
    frame_indices: list[int]
    eth_srcs: list[bytes]
    ip_src: bytes
    ip_dst: bytes
    ip_proto: int
    complete: bool
    sport: int | None = None
    dport: int | None = None

    @property
    def udp_payload(self) -> bytes:
        if self.ip_proto != IPPROTO_UDP or len(self.data) < 8:
            return b""
        ulen = struct.unpack(">H", self.data[4:6])[0]
        return self.data[8:8 + max(0, ulen - 8)] if ulen >= 8 else self.data[8:]


def reassemble(frames: Iterable[Frame]) -> list[Datagram]:
    """Group IPv4 fragments into datagrams, in first-frame order.

    Fragmentation is why a plaintext search must not be per-frame: a
    datagram torn into two frames puts half the secret in each, and a
    per-frame substring search finds neither half. It is also why the
    search must not be over a blind concatenation of the whole capture --
    that invents matches across the junction between unrelated datagrams.
    Reassembling first is the only treatment that is both complete and
    free of junction artifacts.
    """
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for f in frames:
        if f.ethertype != ETHERTYPE_IPV4 or f.ip_proto is None:
            continue
        if f.is_fragmented:
            key = (bytes(f.ip_src or b""), bytes(f.ip_dst or b""),
                   f.ip_proto, f.ip_id)
        else:
            # UNFRAGMENTED DATAGRAMS ARE NEVER GROUPED, whatever their IP ID.
            # ip65 hardcodes the ID to $1234 for every UDP packet it sends
            # (ip65/ip65/udp.s:330), so keying on (src, dst, proto, id) alone
            # would fuse EVERY C64 datagram in the capture into one buffer --
            # which both loses datagrams (later ones overwrite earlier ones at
            # offset 0) and manufactures exactly the cross-datagram junction
            # matches this module refuses to report. Measured: seven staged
            # datagrams came back as two.
            key = ("whole", f.index)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"pieces": [], "srcs": [], "idx": [],
                               "last_seen": False, "sport": None, "dport": None,
                               "ip_src": bytes(f.ip_src or b""),
                               "ip_dst": bytes(f.ip_dst or b""),
                               "proto": f.ip_proto}
            order.append(key)
        g["pieces"].append((f.frag_off or 0, f.ip_payload))
        g["idx"].append(f.index)
        if bytes(f.eth_src) not in g["srcs"]:
            g["srcs"].append(bytes(f.eth_src))
        if not f.more_frags:
            g["last_seen"] = True
        if f.frag_off == 0:
            g["sport"], g["dport"] = f.sport, f.dport
    out: list[Datagram] = []
    for key in order:
        g = groups[key]
        pieces = sorted(g["pieces"], key=lambda p: p[0])
        buf = bytearray()
        complete = g["last_seen"]
        for off, payload in pieces:
            if off != len(buf):
                complete = False
                if off > len(buf):
                    buf.extend(b"\x00" * (off - len(buf)))
                buf[off:off + len(payload)] = payload
                continue
            buf.extend(payload)
        out.append(Datagram(key=key, data=bytes(buf), frame_indices=g["idx"],
                            eth_srcs=g["srcs"], ip_src=g["ip_src"],
                            ip_dst=g["ip_dst"], ip_proto=g["proto"],
                            complete=complete, sport=g["sport"],
                            dport=g["dport"]))
    return out


# ===========================================================================
# Plaintext leak search
# ===========================================================================
def petscii_form(needle: bytes) -> bytes:
    """The bytes a C64 would put on the wire for this ASCII text.

    PETSCII folds ASCII a-z (0x61-0x7A) onto 0x41-0x5A, so a LOWERCASE
    plaintext leaves the machine as different bytes from the ones the host
    staged. A leak checker that searched only the host-side ASCII form
    would look straight past it. Uppercase and digits are unchanged, which
    is why the wire alphabets in the tests are uppercase: there the two
    forms coincide and the search is not doing extra work for show.
    """
    out = bytearray(needle)
    for i, b in enumerate(out):
        if 0x61 <= b <= 0x7A:
            out[i] = b - 0x20
    return bytes(out)


def petscii_shifted_form(needle: bytes) -> bytes:
    """The SHIFTED-letter block: the other encoding the same letters take.

    A C64 emits letters in one of two PETSCII blocks depending on the case
    mode in force: $41-$5A, and $C1-$DA for the shifted set. Our payload
    alphabet is UPPERCASE, so `petscii_form` (which only folds lowercase
    onto uppercase) returns the needle unchanged and its search branch is
    dead on this rig -- a leak that left the machine in the shifted block
    would not be found by any of the other three forms. This is the form
    tools/test_ip65_rrnet_hw.encode_needles covers, and it must not be lost
    when that tool moves onto this library.
    """
    folded = petscii_form(needle)
    return bytes((b + 0x80) if 0x41 <= b <= 0x5A else b for b in folded)


def _longest_run(hay: bytes, needle: bytes) -> tuple[int, int]:
    """(length, offset-in-needle) of the longest needle substring in hay."""
    best, best_at = 0, -1
    n = len(needle)
    for start in range(n):
        if n - start <= best:
            break
        lo, hi = best + 1, n - start
        found = 0
        while lo <= hi:                       # longest match starting here
            mid = (lo + hi) // 2
            if needle[start:start + mid] in hay:
                found, lo = mid, mid + 1
            else:
                hi = mid - 1
        if found > best:
            best, best_at = found, start
    return best, best_at


@dataclass
class Finding:
    form: str                # exact | petscii | reversed | partial | pad | nonip
    where: str               # "datagram" | "frame"
    datagram: int            # index into the reassembled list, -1 for frame hits
    frames: list[int]
    offset: int              # byte offset within whatever was searched
    length: int
    eth_src: str
    label: str               # which named plaintext leaked


def _search_forms(hay: bytes, needle: bytes) -> list[tuple[str, int, int]]:
    """(form, offset, length) for every full appearance of `needle` in `hay`."""
    out: list[tuple[str, int, int]] = []
    seen: set[int] = set()
    for form, pat in (("exact", needle),
                      ("petscii", petscii_form(needle)),
                      ("petscii-shifted", petscii_shifted_form(needle)),
                      ("reversed", needle[::-1])):
        if form != "exact" and pat == needle:
            continue                          # same bytes, already searched
        at = hay.find(pat)
        while at >= 0:
            if at not in seen:
                seen.add(at)
                out.append((form, at, len(pat)))
            at = hay.find(pat, at + 1)
    return out


def find_plaintext(datagrams: Sequence[Datagram],
                   frames: Sequence[Frame],
                   needles: dict[str, bytes],
                   *, partial_min: int = PARTIAL_RUN_MIN) -> list[Finding]:
    """Every appearance of a named plaintext, in datagrams AND in raw frames.

    WHAT IS SEARCHED, and why each part is not optional:

      reassembled datagrams   IP fragments are put back together first. A
                    plaintext torn across two fragments of ONE datagram puts
                    half the secret in each frame, and a per-frame substring
                    search finds neither half. It was one datagram on the
                    cable and the whole secret was on the cable in order, so
                    it counts, and reassembly is what makes it findable.
                    Reassembly is also why the search is NOT run over a
                    concatenation of the capture: concatenating manufactures
                    a match at every junction between packets that never
                    touched each other.
      Ethernet padding   the bytes AFTER the IP total length in a frame the
                    NIC padded up to 60. The sender did not choose them, and
                    that is exactly why they matter: a driver that pads from
                    an uncleared buffer publishes whatever was there
                    (the Etherleak class). Trimming to the IP length -- which
                    a datagram-only search must do to report honest offsets
                    -- would look straight past it, so the pad is searched
                    separately, as form "pad".
      non-IPv4 frames   ARP and anything else, whole. The decoder this
                    project already has (test_ip65_arp_first_send_vice.py
                    :583) returns None for these, so a checker built on it
                    cannot see a secret carried in one. Form "nonip".

    FORMS, and the choice of which count:

      exact     the staged bytes at ANY offset. Any offset at all -- a
                checker that compared payload[:n] would miss a leak
                displaced by one byte of header, which is the shape a real
                off-by-one leak takes.
      petscii   the same text in the encoding the 6510 actually emits (see
                petscii_form). COUNTS: it is our secret, readable.
      reversed  the staged bytes backwards. COUNTS. On a 6502 a descending
                index copy loop is ordinary code, so a reversed buffer is a
                plausible bug, not a curiosity -- and reversed plaintext on
                the cable is recoverable by anyone holding the capture. For
                a random payload of 16+ bytes a chance match is not a risk.
      partial   the longest run of the plaintext inside ONE datagram, when
                at least `partial_min` bytes, so a dribbling leak is
                visible. Per datagram, never across datagrams: a run that
                exists only by joining two unrelated packets is not on the
                wire in any recoverable sense, and searching for it is what
                produces junction false positives. A checker that cries
                wolf gets switched off, and then it protects nothing.
    """
    findings: list[Finding] = []
    for di, dg in enumerate(datagrams):
        hay = dg.data
        src = _fmt_mac(dg.eth_srcs[0]) if dg.eth_srcs else "??"
        for label, needle in needles.items():
            if not needle:
                continue
            hits = _search_forms(hay, needle)
            for form, at, ln in hits:
                findings.append(Finding(form, "datagram", di, list(dg.frame_indices),
                                        at, ln, src, label))
            if hits:
                continue                       # already a full leak here
            run, at_in_needle = _longest_run(hay, needle)
            if partial_min <= run < len(needle):
                frag = needle[at_in_needle:at_in_needle + run]
                findings.append(Finding("partial", "datagram", di,
                                        list(dg.frame_indices), hay.find(frag),
                                        run, src, label))
    for f in frames:
        src = _fmt_mac(f.eth_src)
        if f.ethertype == ETHERTYPE_IPV4 and f.ip_proto is not None:
            body = f.raw[14:]
            if len(body) < 4:
                continue
            total = struct.unpack(">H", body[2:4])[0]
            hay, base, form = body[total:], 14 + total, "pad"
            if not hay:
                continue
        else:
            hay, base, form = f.raw[14:], 14, "nonip"
            if not hay:
                continue
        for label, needle in needles.items():
            if not needle:
                continue
            for _f, at, ln in _search_forms(hay, needle):
                findings.append(Finding(form, "frame", -1, [f.index],
                                        base + at, ln, src, label))
    return findings


def check_plaintext_absent(frames: Sequence[Frame],
                           needles: dict[str, bytes],
                           *, c64_mac: bytes | None = None,
                           min_c64_datagrams: int = 1,
                           require_type4_port: int | None = None,
                           partial_min: int = PARTIAL_RUN_MIN) -> Verdict:
    """No named plaintext appears anywhere in the capture -- IF the C64 spoke.

    THE EMPTY-CORPUS TRAP, which this function had and which is the whole
    reason for the `c64_mac` argument. Guarding "there are frames", "there
    are datagrams" and "there are needles" says nothing about the C64. On a
    two-station cable where the Mac is DHCP server, peer, capturer AND the
    sender of the cleartext sentinel, a run in which the cartridge was
    dropped or the C64 wedged after DHCP still produces frames, datagrams
    and a findable sentinel -- so the searcher looks fine and finds no
    plaintext, because there is no C64 traffic to find it in. The strongest
    sentence a wire stage can print, "the plaintext never appeared on the
    wire", is then true of an empty corpus.

    The sentinel control proves the SEARCHER works. It proves nothing about
    whether the C64 spoke. Only the Ethernet source address does that.

    So with no C64-sourced datagrams the verdict is INCONCLUSIVE: not a
    pass, and not a failure of the tunnel either. `Verdict.ok` is False, so
    a caller that branches on `ok` fails closed; `Verdict.status` says
    which. Passing no `c64_mac` at all is likewise inconclusive rather than
    a pass, so an unwired caller cannot inherit the old behaviour by
    omission.

    `require_type4_port` tightens it further: a C64 that sent only DHCP and
    ARP has spoken, but not through the tunnel, and a leak claim about the
    tunnel needs at least one Type-4 datagram from the C64 to have been
    searched.
    """
    if not needles or not any(needles.values()):
        return Verdict(False, "no plaintext was supplied to search for -- a leak "
                              "check with nothing to find always passes",
                       {"needles": sorted(needles)})
    if not frames:
        return Verdict(False, "the capture is empty; nothing was searched",
                       {"frames": 0, "datagrams": 0}, status="inconclusive")
    dgs = reassemble(frames)
    if not dgs:
        return Verdict(False,
                       f"capture holds {len(frames)} frames and no IP datagrams; "
                       "the tunnel carried nothing to search",
                       {"frames": len(frames), "datagrams": 0},
                       status="inconclusive")

    if c64_mac is None:
        c64_dgs: list[Datagram] = []
        c64_bytes = 0
    else:
        want = bytes(c64_mac)
        c64_dgs = [d for d in dgs if want in [bytes(m) for m in d.eth_srcs]]
        c64_bytes = sum(len(d.data) for d in c64_dgs)
    type4 = [d for d in c64_dgs
             if (require_type4_port is None
                 or d.dport == require_type4_port or d.sport == require_type4_port)
             and d.udp_payload[:1] == b"\x04"]

    # C64-sourced first, deliberately. A run with 20 KB of Mac chatter and
    # nothing from the C64 used to report "no plaintext in N datagrams
    # (20000 B)" -- a number that reads most convincing exactly when the
    # corpus is emptiest.
    ev = {"c64_datagrams": len(c64_dgs), "c64_bytes": c64_bytes,
          "c64_type4_datagrams": len(type4),
          "c64_mac": None if c64_mac is None else _fmt_mac(c64_mac),
          "frames": len(frames), "datagrams": len(dgs),
          "bytes_all_sources": sum(len(d.data) for d in dgs),
          "needles": {k: len(v) for k, v in needles.items()}}

    findings = find_plaintext(dgs, frames, needles, partial_min=partial_min)
    ev["findings"] = [f.__dict__ for f in findings]
    # A leak is a leak whoever carried it: report it before any
    # inconclusive verdict about corpus size, because finding our plaintext
    # in a Mac-sourced frame is still our plaintext on the cable.
    if findings:
        first = findings[0]
        return Verdict(False,
                       f"plaintext {first.label!r} on the wire as {first.form} "
                       f"({first.length} B at offset {first.offset} of "
                       f"{first.where} {first.datagram if first.where == 'datagram' else first.frames}, "
                       f"frames {first.frames}, from {first.eth_src})", ev)

    if c64_mac is None:
        return Verdict(False,
                       "no C64 MAC was supplied, so nothing distinguished the "
                       "C64's frames from the Mac's. On this cable the Mac is "
                       "DHCP server, peer, capturer and sentinel sender, and a "
                       "capture of the Mac alone would reach this line looking "
                       "exactly like a clean run", ev, status="inconclusive")
    if len(c64_dgs) < min_c64_datagrams:
        return Verdict(False,
                       f"INCONCLUSIVE: {len(c64_dgs)} datagrams from the C64 "
                       f"({_fmt_mac(c64_mac)}), needed {min_c64_datagrams}. The "
                       f"{len(dgs)} datagrams searched carry "
                       f"{ev['bytes_all_sources']} B, of which {c64_bytes} B came "
                       "from the C64 -- absence of our plaintext in someone "
                       "else's traffic is not evidence about ours",
                       ev, status="inconclusive")
    if require_type4_port is not None and not type4:
        return Verdict(False,
                       f"INCONCLUSIVE: the C64 sent {len(c64_dgs)} datagrams but "
                       f"no Type-4 on UDP {require_type4_port}; it spoke on the "
                       "wire without speaking through the tunnel, so nothing "
                       "searched here is tunnel traffic", ev, status="inconclusive")
    return Verdict(True,
                   f"no plaintext in {c64_bytes} B from the C64 across "
                   f"{len(c64_dgs)} datagrams ({len(type4)} Type-4); "
                   f"{ev['bytes_all_sources']} B searched in total over "
                   f"{len(frames)} frames", ev)


# ===========================================================================
# Who sent it: the two-station discrimination
# ===========================================================================
@dataclass
class SourceSplit:
    c64: list[Frame]
    host: list[Frame]
    other: list[Frame]
    broadcast_only: list[Frame] = field(default_factory=list)


def split_by_source(frames: Sequence[Frame], c64_mac: bytes,
                    host_mac: bytes) -> SourceSplit:
    c64_mac, host_mac = bytes(c64_mac), bytes(host_mac)
    s = SourceSplit([], [], [])
    for f in frames:
        src = bytes(f.eth_src)
        if src == c64_mac:
            s.c64.append(f)
        elif src == host_mac:
            s.host.append(f)
        else:
            s.other.append(f)
    return s


def check_c64_originated(frames: Sequence[Frame], c64_mac: bytes,
                         host_mac: bytes, *, min_frames: int = 1,
                         udp_port: int | None = None) -> Verdict:
    """At least `min_frames` frames on this cable came FROM the C64.

    THE TRAP THIS EXISTS FOR. There are two stations on the segment and the
    Mac is one of them. "The capture contains WireGuard traffic" is
    satisfied in full by the Mac's own retransmissions to a C64 that is
    wedged, powered off, or not plugged in. Only the Ethernet source
    address separates the two, and it is precisely the field the decoder
    this project already has drops on the floor.

    A frame from a THIRD MAC fails the check rather than being ignored: on
    a two-station cable it means the capture is not of the segment under
    test (wrong interface, a switch, a VM bridge), so no count taken from
    it means what the caller thinks.
    """
    if bytes(c64_mac) == bytes(host_mac):
        return Verdict(False, "c64_mac and host_mac are the same address -- the "
                              "discrimination is vacuous", {})
    s = split_by_source(frames, c64_mac, host_mac)
    ev = {"c64_mac": _fmt_mac(c64_mac), "host_mac": _fmt_mac(host_mac),
          "from_c64": len(s.c64), "from_host": len(s.host),
          "from_other": len(s.other),
          "other_macs": sorted({_fmt_mac(f.eth_src) for f in s.other})}
    if s.other:
        return Verdict(False,
                       f"{len(s.other)} frames from unexpected MACs {ev['other_macs']} "
                       "-- this is not a two-station capture", ev)
    if udp_port is not None:
        matching = [f for f in s.c64
                    if f.dport == udp_port or f.sport == udp_port]
        ev["from_c64_on_port"] = len(matching)
        if len(matching) < min_frames:
            return Verdict(False,
                           f"only {len(matching)} frames from the C64 on UDP "
                           f"{udp_port} (needed {min_frames}); the Mac sent "
                           f"{len(s.host)}", ev)
        return Verdict(True, f"{len(matching)} frames from the C64 on UDP {udp_port}", ev)
    if len(s.c64) < min_frames:
        return Verdict(False,
                       f"only {len(s.c64)} frames from the C64 (needed {min_frames}); "
                       f"the Mac sent {len(s.host)} -- a capture of the Mac talking "
                       "to itself would look exactly like this", ev)
    return Verdict(True, f"{len(s.c64)} frames from the C64, {len(s.host)} from the Mac", ev)


# ===========================================================================
# Handshake completion
# ===========================================================================
def check_handshake_complete(c64_wg_state: int | None,
                             responder_complete: bool,
                             *, frames: Sequence[Frame] | None = None,
                             c64_mac: bytes | None = None) -> Verdict:
    """BOTH ends must say the handshake completed.

    The responder's own view is not enough. A responder that received a
    valid initiation and sent a response records a completed handshake
    whether or not the C64 ever processed the response -- and the C64 stuck
    at HS_SENT is exactly the failure a first hardware run is likely to
    hit. `c64_wg_state` must be the byte read from src/wg/data.s:727 over
    DMA; None means the read did not happen and is a failure, not a pass.
    """
    ev = {"c64_wg_state": c64_wg_state, "responder_complete": bool(responder_complete),
          "active_value": WG_STATE_ACTIVE}
    if c64_wg_state is None:
        return Verdict(False, "wg_state was never read from the C64; the responder's "
                              "view alone cannot see a wedged initiator", ev)
    if not responder_complete:
        return Verdict(False, "the responder did not complete the handshake", ev)
    if c64_wg_state != WG_STATE_ACTIVE:
        name = {WG_STATE_IDLE: "IDLE", WG_STATE_HS_SENT: "HS_SENT"}.get(
            c64_wg_state, f"unknown({c64_wg_state})")
        return Verdict(False,
                       f"the responder completed but the C64's wg_state is {name} "
                       f"({c64_wg_state}), not ACTIVE ({WG_STATE_ACTIVE})", ev)
    if frames is not None and c64_mac is not None:
        from_c64 = [f for f in frames if bytes(f.eth_src) == bytes(c64_mac)]
        ev["frames_from_c64"] = len(from_c64)
        if not from_c64:
            return Verdict(False, "both ends claim ACTIVE but the capture holds no "
                                  "frame from the C64's MAC at all", ev)
    return Verdict(True, "wg_state == ACTIVE on the C64 and the responder agrees", ev)


# ===========================================================================
# Bidirectional transport
# ===========================================================================
def check_transport_c64_to_mac(received: Sequence[bytes],
                               expected: bytes) -> Verdict:
    """The responder decrypted EXACTLY the bytes the C64 was told to send.

    Content, not a count. The payload is randomised per run under a logged
    seed, so this cannot be satisfied by a fixed string, and the request
    alphabet is disjoint from the reply alphabet, so it cannot be satisfied
    by an echo of the reply either.
    """
    ev = {"expected_len": len(expected), "received_count": len(received),
          "received_lens": [len(r) for r in received]}
    if not expected:
        return Verdict(False, "no expected payload was staged", ev)
    if not received:
        return Verdict(False, "the responder decrypted nothing from the C64", ev)
    for i, got in enumerate(received):
        if got == expected:
            ev["match_index"] = i
            return Verdict(True, f"the responder decrypted the staged {len(expected)} "
                                 f"byte payload (datagram {i} of {len(received)})", ev)
    best = max(received, key=lambda r: sum(a == b for a, b in zip(r, expected)))
    same = sum(a == b for a, b in zip(best, expected))
    ev["closest_len"] = len(best)
    ev["closest_matching_bytes"] = same
    ev["closest_prefix"] = best[:32].hex()
    ev["expected_prefix"] = expected[:32].hex()
    return Verdict(False,
                   f"none of the {len(received)} decrypted payloads equals the staged "
                   f"one; closest is {len(best)} B with {same}/{len(expected)} bytes "
                   "in common", ev)


def check_transport_mac_to_c64(c64_plaintext: bytes | None,
                               c64_len: int | None,
                               expected: bytes) -> Verdict:
    """The C64 DECRYPTED the reply -- read back from its own buffer over DMA.

    "The Mac sent it" and "the C64 received a datagram" are both weaker
    claims than this one and neither is accepted here: the whole inbound
    path (receive, replay window, ChaCha20-Poly1305 open) is between them.
    `c64_len` is the length the C64 itself recorded; it must agree with the
    staged length, so a buffer left full of a previous message cannot pass
    on its content alone.
    """
    ev = {"expected_len": len(expected), "c64_len": c64_len,
          "c64_prefix": (c64_plaintext or b"")[:32].hex(),
          "expected_prefix": expected[:32].hex()}
    if not expected:
        return Verdict(False, "no expected reply was staged", ev)
    if c64_plaintext is None or c64_len is None:
        return Verdict(False, "the C64's receive buffer was never read; 'the Mac sent "
                              "it' is not evidence that the C64 decrypted it", ev)
    if c64_len != len(expected):
        return Verdict(False, f"the C64 recorded {c64_len} received bytes, staged "
                              f"{len(expected)}", ev)
    got = c64_plaintext[:c64_len]
    if got != expected:
        same = sum(a == b for a, b in zip(got, expected))
        ev["matching_bytes"] = same
        return Verdict(False, f"the C64's {c64_len} decrypted bytes differ from the "
                              f"staged reply ({same}/{len(expected)} in common)", ev)
    return Verdict(True, f"the C64 decrypted the staged {len(expected)} byte reply", ev)


# ===========================================================================
# DHCP lease
# ===========================================================================
def check_dhcp_lease(cfg_ip: bytes | None, *, subnet: str | None = None,
                     host_ip: str | None = None,
                     expect_ip: str | None = None) -> Verdict:
    """A lease was issued, read from ip65's OWN cfg_ip over DMA.

    Load-bearing because src/boot.s's do_net_init RETURNS on DHCP failure
    and never reaches net_udp_listen: with no lease there is no listener
    and every later check is about a machine that is not on the network.

    IT MUST BE cfg_ip, NOT THE dnsmasq LEASE FILE. A lease in dnsmasq's
    file says our DHCP server answered; it says nothing about whether ip65
    parsed the reply and stored it. Reading the file tests our server.

    AND IT MUST NOT BE "NON-ZERO". ip65/ip65/config.s:18 initialises cfg_ip
    to 192.168.1.64 at build time -- the zeroed alternative on the next
    line is commented out -- so a non-zero test is already satisfied before
    dhcp_init runs. The build-time default is rejected by value, as is
    0.0.0.0, 255.255.255.255, loopback, multicast and 169.254/16 (the C64
    does not do IPv4LL, so a link-local address here means something else
    wrote the field).
    """
    ev = {"cfg_ip": _fmt_ip(cfg_ip) if cfg_ip else None, "subnet": subnet,
          "host_ip": host_ip}
    if cfg_ip is None:
        return Verdict(False, "cfg_ip was never read from the C64", ev)
    if len(cfg_ip) != 4:
        return Verdict(False, f"cfg_ip read back {len(cfg_ip)} bytes, expected 4", ev)
    octets = tuple(cfg_ip)
    if octets == (0, 0, 0, 0):
        return Verdict(False, "cfg_ip is 0.0.0.0 -- no lease", ev)
    if octets == IP65_DEFAULT_CFG_IP:
        return Verdict(False,
                       f"cfg_ip is {_fmt_ip(octets)}, ip65's BUILD-TIME DEFAULT "
                       "(ip65/ip65/config.s:18) -- dhcp_init did not overwrite it, "
                       "so no lease was parsed", ev)
    if octets[0] == 127:
        return Verdict(False, f"cfg_ip is loopback {_fmt_ip(octets)}", ev)
    if octets[0] >= 224:
        return Verdict(False, f"cfg_ip is multicast/reserved {_fmt_ip(octets)}", ev)
    if octets == (255, 255, 255, 255):
        return Verdict(False, "cfg_ip is the broadcast address", ev)
    if octets[0] == 169 and octets[1] == 254:
        return Verdict(False,
                       f"cfg_ip is link-local {_fmt_ip(octets)}; the C64 does not "
                       "do IPv4LL, so this is not a DHCP lease", ev)
    if host_ip is not None and _fmt_ip(octets) == host_ip:
        return Verdict(False, f"cfg_ip is the HOST's address {host_ip}", ev)
    if subnet is not None:
        want = subnet.split(".")[:3]
        if [str(o) for o in octets[:3]] != want:
            return Verdict(False,
                           f"cfg_ip {_fmt_ip(octets)} is not on the rig subnet "
                           f"{'.'.join(want)}.0/24", ev)
    if expect_ip is not None and _fmt_ip(octets) != expect_ip:
        return Verdict(False,
                       f"cfg_ip is {_fmt_ip(octets)}, not the pinned {expect_ip}. "
                       "The rig reserves that address for the C64's MAC with "
                       "--dhcp-host; a POOL address here means the reservation "
                       "did not match, which is a quiet divergence rather than "
                       "an error and makes every capture keyed on the pinned "
                       "address stop lining up", ev)
    return Verdict(True, f"ip65 holds a lease: cfg_ip = {_fmt_ip(octets)}", ev)


def check_ip65_config_written(cfg_ip: bytes | None, cfg_netmask: bytes | None,
                              cfg_gateway: bytes | None,
                              cfg_mac: bytes | None) -> Verdict:
    """None of ip65's four config fields still holds its build-time constant.

    ip65/ip65/config.s:17-20 ships every one of them non-zero:

        cfg_mac      00:80:10:00:51:00
        cfg_ip       192.168.1.64        (the zeroed variant on :19 is
                                          COMMENTED OUT)
        cfg_netmask  255.255.255.0
        cfg_gateway  192.168.1.1

    So "the field is populated" is true of a machine that never brought the
    network up at all, and on this rig 255.255.255.0 is ALSO the correct
    leased netmask -- which is why the netmask alone can never be evidence
    and is reported here rather than asserted. A cfg_mac still reading the
    default means eth_init never ran; it is not a MAC value to check against
    the wire, it is the absence of one.
    """
    fields = {
        "cfg_ip": (cfg_ip, IP65_DEFAULT_CFG_IP, True),
        "cfg_netmask": (cfg_netmask, IP65_DEFAULT_CFG_NETMASK, False),
        "cfg_gateway": (cfg_gateway, IP65_DEFAULT_CFG_GATEWAY, True),
        "cfg_mac": (cfg_mac, IP65_DEFAULT_CFG_MAC, True),
    }
    ev, still_default, unread, ambiguous = {}, [], [], []
    for name, (got, default, decisive) in fields.items():
        if got is None:
            unread.append(name)
            ev[name] = None
            continue
        ev[name] = (_fmt_mac(got) if len(got) == 6 else _fmt_ip(got))
        if tuple(got) == tuple(default):
            (still_default if decisive else ambiguous).append(name)
    ev["still_default"] = still_default
    ev["default_but_not_decisive"] = ambiguous
    if unread:
        return Verdict(False, f"never read from the C64: {', '.join(unread)}", ev)
    if still_default:
        plural = "s" if len(still_default) == 1 else ""
        return Verdict(False,
                       f"{', '.join(still_default)} still hold{plural} ip65's "
                       "BUILD-TIME constants (ip65/ip65/config.s:17-20), so the "
                       "code that was supposed to overwrite them did not run", ev)
    note = ""
    if ambiguous:
        note = (f" ({', '.join(ambiguous)} equals the shipped default, but that "
                "is also the correct value here, so it is reported and not asserted)")
    return Verdict(True, "ip65's config fields were all written at run time" + note, ev)


# ===========================================================================
# The CS8900a MAC
# ===========================================================================
def check_mac_on_wire(frames: Sequence[Frame], c64_mac: bytes,
                      host_mac: bytes, *, min_frames: int = 1) -> Verdict:
    """The C64's MAC is on the CABLE, not merely in a register we wrote.

    Reading the MAC back out of the CS8900a through the same path that
    wrote it proves the register round-trips; it does not prove a frame
    ever left the cartridge carrying it. The honest check is that frames
    with that Ethernet SOURCE address were captured on the segment.

    Rejects the all-zero MAC, the broadcast MAC, a multicast source (bit 0
    of the first octet -- illegal as a source address), and ip65's
    build-time cfg_mac default 00:80:10:00:51:00 (ip65/ip65/config.s:17),
    which is what the field still reads if ip65_init never asked the driver
    for the cartridge's real address.
    """
    ev = {"c64_mac": _fmt_mac(c64_mac), "host_mac": _fmt_mac(host_mac)}
    mac = bytes(c64_mac)
    if len(mac) != 6:
        return Verdict(False, f"MAC is {len(mac)} bytes, expected 6", ev)
    if mac == b"\x00" * 6:
        return Verdict(False, "the C64's MAC is 00:00:00:00:00:00 -- never programmed", ev)
    if mac == b"\xff" * 6:
        return Verdict(False, "the C64's MAC is the broadcast address", ev)
    if mac[0] & 0x01:
        return Verdict(False, f"{_fmt_mac(mac)} has the multicast bit set; it cannot "
                              "be a station's source address", ev)
    if tuple(mac) == IP65_DEFAULT_CFG_MAC:
        return Verdict(False,
                       f"the C64's MAC is {_fmt_mac(mac)}, ip65's BUILD-TIME DEFAULT "
                       "(ip65/ip65/config.s:17) -- eth_init never ran, so this is "
                       "the ABSENCE of a MAC rather than a MAC to check", ev)
    if mac == bytes(host_mac):
        return Verdict(False, "the C64's MAC equals the Mac's; the discrimination "
                              "would be vacuous", ev)
    seen = [f for f in frames if bytes(f.eth_src) == mac]
    ev["frames_with_that_source"] = len(seen)
    ev["sources_seen"] = sorted({_fmt_mac(f.eth_src) for f in frames})
    if len(seen) < min_frames:
        return Verdict(False,
                       f"{_fmt_mac(mac)} is the C64's MAC but appears as the Ethernet "
                       f"SOURCE of only {len(seen)} captured frames (needed "
                       f"{min_frames}); sources seen: {ev['sources_seen']}", ev)
    return Verdict(True, f"{len(seen)} frames on the cable carry the C64's MAC "
                         f"{_fmt_mac(mac)} as their source", ev)


# ===========================================================================
# ICMP echo: PAIR replies to requests, never count them
# ===========================================================================
@dataclass
class EchoPair:
    key: tuple[int, int]            # (identifier, sequence)
    request_frame: int
    reply_frame: int
    rtt_ms: float
    payload_matches: bool


@dataclass
class EchoAudit:
    pairs: list[EchoPair]
    unanswered: list[tuple[int, int]]      # requests with no reply
    unmatched_replies: list[tuple[int, int]]   # replies matching no request


def pair_echoes(frames: Sequence[Frame], *, c64_mac: bytes | None = None,
                host_mac: bytes | None = None) -> EchoAudit:
    """Pair ICMP echo replies to requests by IDENTIFIER AND SEQUENCE.

    COUNTING REPLIES PASSES ON THE FAILURE. macOS queues replies against a
    stale neighbour entry and flushes the whole backlog in a single
    millisecond the instant an ARP resolves. A window that counts "N replies
    arrived" therefore scores its best result on exactly the broken case: a
    burst of nine stale replies from earlier attempts, none of them an
    answer to anything this run sent. Only the (id, seq) pair ties a reply
    to a request, and a reply matching no OUTSTANDING request is evidence of
    the stale-queue condition rather than of health.

    Requests are taken from frames whose Ethernet source is the C64 (when
    `c64_mac` is given), so the Mac pinging itself cannot manufacture pairs.
    """
    requests: dict[tuple[int, int], Frame] = {}
    audit = EchoAudit([], [], [])
    replied: set[tuple[int, int]] = set()
    for f in frames:
        if f.icmp_type is None or f.icmp_id is None or f.icmp_seq is None:
            continue
        key = (f.icmp_id, f.icmp_seq)
        if f.icmp_type == ICMP_ECHO_REQUEST:
            if c64_mac is not None and bytes(f.eth_src) != bytes(c64_mac):
                continue                  # not a request THIS C64 sent
            requests.setdefault(key, f)
        elif f.icmp_type == ICMP_ECHO_REPLY:
            req = requests.get(key)
            if req is None or key in replied:
                audit.unmatched_replies.append(key)
                continue
            if host_mac is not None and bytes(f.eth_src) != bytes(host_mac):
                audit.unmatched_replies.append(key)
                continue
            replied.add(key)
            audit.pairs.append(EchoPair(
                key, req.index, f.index, (f.ts - req.ts) * 1000.0,
                f.icmp_data == req.icmp_data))
    audit.unanswered = [k for k in requests if k not in replied]
    return audit


def check_echo_replies_matched(frames: Sequence[Frame], *,
                               c64_mac: bytes, host_mac: bytes,
                               min_pairs: int = 1) -> Verdict:
    """Every accepted reply answers a request this run sent, and enough did.

    Three separate ways to fail, kept separate because they mean different
    things: no pairs at all (nothing got through), unmatched replies (the
    stale-queue flush -- traffic on the wire that looks like success and is
    not), and a paired reply whose echo data differs from the request's (a
    reply that is not a reflection of what we sent).
    """
    audit = pair_echoes(frames, c64_mac=c64_mac, host_mac=host_mac)
    ev = {"pairs": len(audit.pairs),
          "keys": [p.key for p in audit.pairs],
          "unanswered": audit.unanswered,
          "unmatched_replies": audit.unmatched_replies,
          "rtt_ms": [round(p.rtt_ms, 2) for p in audit.pairs],
          "reply_frames_total": sum(1 for f in frames
                                    if f.icmp_type == ICMP_ECHO_REPLY)}
    if audit.unmatched_replies:
        return Verdict(False,
                       f"{len(audit.unmatched_replies)} echo replies match no "
                       f"outstanding request from this run {audit.unmatched_replies[:5]} "
                       "-- the shape of a queued backlog flushing when an ARP "
                       "resolved, which a checker that counted replies would "
                       "have scored as its best result", ev)
    if len(audit.pairs) < min_pairs:
        return Verdict(False,
                       f"only {len(audit.pairs)} request/reply pairs (needed "
                       f"{min_pairs}); {ev['reply_frames_total']} reply frames were "
                       f"on the wire and {len(audit.unanswered)} requests went "
                       "unanswered", ev)
    bad = [p.key for p in audit.pairs if not p.payload_matches]
    if bad:
        return Verdict(False, f"replies {bad} do not echo the request payload", ev)
    return Verdict(True, f"{len(audit.pairs)} echo replies paired to this run's "
                         f"requests by (id, seq), none unmatched", ev)


# ===========================================================================
# ARP — evidence, not noise
# ===========================================================================
def check_arp_exchange(frames: Sequence[Frame], *, c64_mac: bytes,
                       host_mac: bytes, c64_ip: str,
                       host_ip: str) -> Verdict:
    """The two stations resolved each other, and the C64 answered for itself.

    Load-bearing on this rig because macOS holds replies against a stale
    neighbour entry: without the ARP exchange in the capture, "no replies
    came back" is indistinguishable from "the C64 is dead", and those lead
    to opposite conclusions. The decoder most likely to be reused here
    (tools/test_ip65_arp_first_send_vice.py:583) returns None for every
    non-IPv4 frame, so it cannot see any of this.

    `evidence["diagnosis"]`: "no-arp-frames" (nothing resolved, or the tap's
    filter dropped ARP -- look at the tap), "no-arp-from-the-c64" (the
    segment resolved around a C64 that said nothing -- look at the C64), or
    "ok". Two failures that read alike and call for opposite investigations.
    """
    arps = [f for f in frames if f.ethertype == ETHERTYPE_ARP and f.arp_op]
    want_c64, want_host = ip4_bytes(c64_ip), ip4_bytes(host_ip)
    host_asked = [f for f in arps
                  if f.arp_op == ARP_REQUEST
                  and bytes(f.eth_src) == bytes(host_mac)
                  and bytes(f.arp_target_ip or b"") == want_c64]
    c64_answered = [f for f in arps
                    if f.arp_op == ARP_REPLY
                    and bytes(f.eth_src) == bytes(c64_mac)
                    and bytes(f.arp_sender_ip or b"") == want_c64]
    c64_asked = [f for f in arps
                 if f.arp_op == ARP_REQUEST
                 and bytes(f.eth_src) == bytes(c64_mac)
                 and bytes(f.arp_target_ip or b"") == want_host]
    ev = {"arp_frames": len(arps), "host_requests_for_c64": len(host_asked),
          "c64_replies_for_itself": len(c64_answered),
          "c64_requests_for_host": len(c64_asked)}
    if not arps:
        ev["diagnosis"] = "no-arp-frames"
        return Verdict(False,
                       "no ARP frames in the capture at all. Either the tap "
                       "filtered them out or nothing resolved -- and without "
                       "them a silent wire cannot be told from a dead C64", ev)
    if not (c64_answered or c64_asked):
        ev["diagnosis"] = "no-arp-from-the-c64"
        return Verdict(False,
                       f"{len(arps)} ARP frames, none of them FROM the C64 "
                       f"({_fmt_mac(c64_mac)}): it neither answered for "
                       f"{c64_ip} nor asked for {host_ip}", ev)
    ev["diagnosis"] = "ok"
    return Verdict(True, f"ARP resolved: {len(c64_answered)} replies and "
                         f"{len(c64_asked)} requests from the C64", ev)


def ip4_bytes(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


# ===========================================================================
# net_last_error — the byte that separates a dropped cartridge from DHCP
# ===========================================================================
#: src/net_abi.inc:106-152 is the canonical registry; src/net/ip65/net.s
#: carries the equates this build actually assembles. Retyped here ONLY as
#: the value `net_error_table()` cross-checks the tree against -- a
#: renumbering must be a loud failure, not a decoder that keeps naming the
#: old meaning.
NET_ERRORS: dict[int, tuple[str, str]] = {
    0x00: ("NET_ERR_NONE", "no error"),
    0x01: ("NET_ERR_TIMEBASE_STOPPED",
           "the CIA1 TOD was never started, so every bounded wait is unbounded"),
    0x41: ("NET_ERR_IP65_INIT",
           "ip65_init failed: the cartridge was not found or eth_init refused. "
           "OUR LOADER DROPPED THE CARTRIDGE -- not a network problem"),
    0x42: ("NET_ERR_IP65_DHCP",
           "dhcp_init failed: no lease. The C64 is alive and the DHCP SERVER "
           "is not answering -- the opposite conclusion from $41, and the two "
           "look identical on the screen"),
    0x46: ("NET_ERR_IP65_UDP_LISTEN", "udp_add_listener failed"),
    0x48: ("NET_ERR_IP65_WAIT_TIMEOUT", "the ARP/wait budget was exhausted"),
    0x49: ("NET_ERR_IP65_UDP_UNBIND", "udp_remove_listener failed"),
}

#: Defined and exported by src/net/ip65/net.s so the value cannot be quietly
#: reused (#120), but NEVER EMITTED. Seeing one of these in net_last_error is
#: a defect in the adapter, not the condition the name describes.
NET_ERRORS_RESERVED: dict[int, str] = {
    0x47: ("NET_ERR_IP65_UDP_SEND is RESERVED and never emitted; the adapter "
           "defines and exports it only so the number stays allocated"),
}

#: Allocated in the registry to c64-https, which shares the family range. Our
#: adapter never writes them, so one appearing means the byte did not come
#: from where the caller thinks.
NET_ERRORS_FOREIGN: dict[int, str] = {
    0x43: "NET_ERR_IP65_DNS", 0x44: "NET_ERR_IP65_CONNECT",
    0x45: "NET_ERR_IP65_SEND",
}


def net_error_table(net_s_source: str | None = None) -> Verdict:
    """Cross-check NET_ERRORS against the tree's own ca65 equates.

    A decoder that keeps naming a value the assembler has since moved is
    worse than no decoder: it produces a confident wrong diagnosis of the
    one byte the operator is going to act on. Pass the text of
    src/net/ip65/net.s; every `NET_ERR_x = $yy` there must agree.
    """
    if net_s_source is None:
        return Verdict(False, "no source supplied to cross-check the table against",
                       {})
    found: dict[str, int] = {}
    for line in net_s_source.splitlines():
        line = line.split(";")[0]
        if "=" not in line or "NET_ERR_" not in line:
            continue
        name, _, val = line.partition("=")
        name, val = name.strip(), val.strip()
        if not name.startswith("NET_ERR_") or not val.startswith("$"):
            continue
        try:
            found[name] = int(val[1:], 16)
        except ValueError:
            continue
    known = {n: v for v, (n, _) in NET_ERRORS.items() if v}
    known.update({"NET_ERR_IP65_UDP_SEND": 0x47})
    ev = {"in_source": found, "in_table": known}
    if not found:
        return Verdict(False, "no NET_ERR_ equates found in the source supplied; "
                              "the cross-check would pass vacuously", ev)
    drift = {n: (known.get(n), v) for n, v in found.items() if known.get(n) != v}
    ev["drift"] = drift
    if drift:
        return Verdict(False, f"net_last_error codes have MOVED in the tree: "
                              f"{drift} (table value, source value)", ev)
    return Verdict(True, f"{len(found)} NET_ERR_ equates agree with the table", ev)


def decode_net_last_error(value: int | None) -> Verdict:
    """Decode the byte, and say what it means for WHERE to look next."""
    ev = {"value": value, "hex": None if value is None else f"${value:02X}"}
    if value is None:
        return Verdict(False, "net_last_error was never read; on any failure it "
                              "is the first byte to consult", ev)
    if value in NET_ERRORS_RESERVED:
        name = "NET_ERR_IP65_UDP_SEND"
        ev["name"] = name
        return Verdict(False, f"${value:02X} {name}: {NET_ERRORS_RESERVED[value]}",
                       ev)
    if value in NET_ERRORS_FOREIGN:
        ev["name"] = NET_ERRORS_FOREIGN[value]
        return Verdict(False,
                       f"${value:02X} is {NET_ERRORS_FOREIGN[value]}, allocated to "
                       "c64-https in the shared family range. Our ip65 adapter "
                       "never emits it, so this byte did not come from where the "
                       "caller thinks", ev)
    if value not in NET_ERRORS:
        return Verdict(False, f"${value:02X} is not in the net_last_error registry "
                              "(src/net_abi.inc); an unregistered code cannot be "
                              "acted on", ev)
    name, meaning = NET_ERRORS[value]
    ev["name"], ev["meaning"] = name, meaning
    if value == 0:
        return Verdict(True, "net_last_error is $00 (no error)", ev)
    return Verdict(False, f"${value:02X} {name}: {meaning}", ev)


def check_net_counters(recv_dropped: int | None, send_attempts: int | None,
                       *, expect_sends: int | None = None) -> Verdict:
    """ip65_recv_dropped and ip65_send_attempts, read alongside the error byte.

    THE TWO COUNTERS HAVE DIFFERENT LIFETIMES, and getting that wrong makes
    this function report the opposite of the property it names. From the
    tree, not inferred:

      ip65_send_attempts   PER-SEND. net_udp_send stores $01 into it at the
                           top of EVERY call (src/net/ip65/net.s:382-383),
                           so it describes the LAST send and never the run.
                           net_arp_pump is the only thing that increments it
                           further (net.s:659-731), so 1 means the ARP cache
                           was warm and nothing was retried, and >1 means the
                           #120 pump path fired. The BSS comment at
                           net.s:982-989 says exactly this.
      ip65_recv_dropped    CUMULATIVE since net_init, and moved ONLY by
                           net_udp_recv_cb's disarm branch (net.s:758-765),
                           which is gated on ip65_send_pump -- a flag only
                           net_arp_pump ever sets.

    So the drop counter can move only while the pump runs, and the pump
    running is exactly what pushes send_attempts past 1. `send_attempts > 1`
    is therefore the condition under which a zero here is evidence.

    WHY `> 0` WOULD BE WORSE THAN A WRONG BOOLEAN. Every send that happened
    at all leaves the byte >= 1, so `> 0` reports the drop counter as PROVEN
    precisely on the healthy warm-cache runs where it is proven least -- and
    what it suppresses is the note. A missing caveat reads as "not checked";
    a suppressed one reads as evidence.

    THE FLAG UNDER-CLAIMS ON PURPOSE, and the next reader should know why
    rather than try to satisfy it. Because send_attempts describes only the
    LAST send, a run whose pump fired on an earlier send but not the final
    one reads 1 here even though the drop counter did have its opportunity.
    True therefore means "proven"; False means "not proven", never
    "disproven". And on a healthy warm-cache run the flag is unreachable BY
    CONSTRUCTION -- the pump only fires on a send that already failed -- so
    the note simply stands on those runs. That is the honest state of
    affairs. Do not feed the function a number to clear it.

    `expect_sends` is the number of sends the run made. It CANNOT be
    validated against ip65_send_attempts -- comparing them would fail every
    healthy multi-send run, because five warm sends leave the byte reading 1
    -- so it is used only to require that the byte shows a send happened at
    all, and is otherwise recorded as context.
    """
    ev = {"ip65_recv_dropped": recv_dropped, "ip65_send_attempts": send_attempts,
          "sends_this_run": expect_sends, "drop_counter_proven": False,
          "send_attempts_is_per_send": True}
    if recv_dropped is None or send_attempts is None:
        return Verdict(False, "ip65_recv_dropped / ip65_send_attempts were not "
                              "read; they are the context the error byte is "
                              "interpreted in", ev)
    if expect_sends is not None and expect_sends >= 1 and send_attempts < 1:
        return Verdict(False,
                       f"the run made {expect_sends} sends but ip65_send_attempts "
                       "is 0, so net_udp_send never reached the store at the top "
                       "of itself -- no send happened", ev)
    ev["drop_counter_proven"] = send_attempts > 1
    if recv_dropped:
        return Verdict(False, f"ip65 dropped {recv_dropped} received datagrams", ev)
    attempts = (f"{send_attempts} send attempts on the last send"
                + (" (the #120 ARP pump fired)" if send_attempts > 1
                   else " (warm ARP cache, nothing retried)"))
    if ev["drop_counter_proven"]:
        return Verdict(True, f"no drops, {attempts}", ev)
    # The note goes to BOTH the reason and the evidence: a caller that logs
    # structured evidence rather than the prose must not silently lose the
    # one sentence that says the zero above is not evidence.
    note = ("nothing in this run proves the drop counter can move, so its zero "
            "is not evidence: ip65_recv_dropped is incremented only by "
            "net_udp_recv_cb's disarm branch, which runs only while "
            "net_arp_pump holds ip65_send_pump set, and send_attempts == "
            f"{send_attempts} says the pump did not fire on the last send")
    ev["unproven_note"] = note
    return Verdict(True, f"no drops, {attempts} (NOTE: {note})", ev)


# ===========================================================================
# The capture bracket — a pcap has to be OF this run
# ===========================================================================
def check_capture_bracket(frames: Sequence[Frame], started_at: float,
                          ended_at: float, *, path: str | None = None,
                          min_inside: int = 1,
                          slack_s: float = 2.0) -> Verdict:
    """The capture was taken during this run, not left over from a previous one.

    In external-capture mode nothing truncates the file and nothing asserts
    it was created by this run, so `stage_wire` will happily parse a pcap
    from an earlier session and report agreement about traffic that predates
    the build under test. Timestamps are the only thing in the file that
    ties it to a run.

    `evidence["diagnosis"]` is a stable machine-readable code the caller
    branches on -- "inverted-window", "empty", "no-frame-inside-the-window",
    "capture-started-before-the-run", "too-few-frames-inside", "ok". These
    are separate codes because they call for separate actions: a stale file
    is a different mistake from a tap that was already running.

    `slack_s` absorbs ordinary clock skew between tcpdump's timestamps and
    this process's wall clock; it is not a licence for a stale file, which
    misses by minutes or hours rather than seconds.
    """
    ev = {"path": path, "frames": len(frames), "started_at": started_at,
          "ended_at": ended_at, "slack_s": slack_s}
    if ended_at < started_at:
        ev["diagnosis"] = "inverted-window"
        return Verdict(False, "the run's end time precedes its start time", ev)
    if not frames:
        ev["diagnosis"] = "empty"
        return Verdict(False, "the capture is empty; there is nothing to date", ev)
    lo, hi = started_at - slack_s, ended_at + slack_s
    stamps = [f.ts for f in frames]
    inside = [t for t in stamps if lo <= t <= hi]
    before = [t for t in stamps if t < lo]
    after = [t for t in stamps if t > hi]
    ev.update({"inside": len(inside), "before": len(before), "after": len(after),
               "first_ts": min(stamps), "last_ts": max(stamps)})
    if not inside:
        ev["diagnosis"] = "no-frame-inside-the-window"
        gap = started_at - max(stamps)
        return Verdict(False,
                       f"every one of the {len(frames)} frames falls OUTSIDE this "
                       f"run's window; the newest predates the run by {gap:.0f}s. "
                       "This is a stale capture from an earlier session, and "
                       "parsing it would report agreement about traffic that has "
                       "nothing to do with the build under test", ev)
    if before:
        ev["diagnosis"] = "capture-started-before-the-run"
        return Verdict(False,
                       f"{len(before)} of {len(frames)} frames predate the run "
                       f"window (oldest by {started_at - min(before):.0f}s); the "
                       "capture was not truncated before it started", ev)
    if len(inside) < min_inside:
        ev["diagnosis"] = "too-few-frames-inside"
        return Verdict(False, f"only {len(inside)} frames inside the run window "
                              f"(needed {min_inside})", ev)
    ev["diagnosis"] = "ok"
    return Verdict(True, f"all {len(frames)} frames fall inside the run window "
                         f"({len(inside)} checked)", ev)


# ===========================================================================
# Bench health — a control that proves the BENCH, not our driver path
# ===========================================================================
#: The control's build links c64rrnet.lib (cs8900a only). Our blob links
#: ip65_c64.lib, whose COMBO wrapper (rr-net.o eth64.o c64combo.o) has
#: self-modifying init_adaptor/eth_rx/eth_tx living in .data. The two do not
#: share a driver path, so a fault in the combo glue passes the control and
#: fails our build. Carried in the verdict's own text so a green control
#: cannot be read as "our driver works".
BENCH_CONTROL_CAVEAT = (
    "this control links c64rrnet.lib (cs8900a only) while our blob links "
    "ip65_c64.lib's COMBO wrapper (rr-net.o eth64.o c64combo.o, self-modifying "
    "init_adaptor/eth_rx/eth_tx in .data) -- it proves the BENCH, not our "
    "driver path, and a fault in the combo glue passes here and fails there")


#: The CS8900a's EISA product identifier, read on the 6510 as PPData after
#: PPPtr = $0000. ip65's own driver checks exactly this before it will
#: initialise, so it is a POSITIVE identification of the chip rather than an
#: absence-of-zeros heuristic.
CS8900A_PRODUCT_ID = 0x630E

#: What a HOST-SIDE read_memory of $DE00 returns. That path never reaches
#: the cartridge in ANY state -- it is this value with a working cartridge,
#: with no cartridge, and on `Cartridge Preference = Auto` alike -- so it
#: carries no information about presence whatsoever. Recorded here so a
#: caller who supplies it by mistake is told, rather than believed.
HOST_PATH_DE00_WORD = 0x0A0A


def check_cs8900a_identified(product_id: int | None) -> Verdict:
    """The CS8900a identified itself, ON THE 6510.

    `product_id` must be PPData read after writing PPPtr = $0000, EXECUTED
    ON THE 6510. It must NOT come from a host-side `read_memory` of $DE00:
    that path never reaches the cartridge in any state and returns $0A
    regardless of the truth, so a check built on it is constant and
    authoritative and wrong.

    Zero is equally useless as evidence of absence: `Cartridge Preference =
    Auto`, "after run_prg" and "no cartridge at all" all read the window as
    zeros on the 6510 too. One observation, three causes -- so zero is
    reported as UNIDENTIFIED rather than as "no cartridge".

    `evidence["diagnosis"]`: "read-from-the-host-side", "unidentified-zeros",
    "wrong-chip", "not-read", "ok". The first two are the ones that must not
    collapse into "wrong chip": one says the operator read the wrong side of
    the machine, the other says the card may be fine and the preference is
    on Auto. Neither is a fault in the cartridge.
    """
    ev = {"product_id": product_id,
          "expected": f"${CS8900A_PRODUCT_ID:04X}"}
    if product_id is None:
        ev["diagnosis"] = "not-read"
        return Verdict(False, "the CS8900a product ID was not read; without it a "
                              "cartridge fault and a driver fault look the same",
                       ev, status="inconclusive")
    ev["read"] = f"${product_id:04X}"
    if product_id == HOST_PATH_DE00_WORD:
        ev["diagnosis"] = "read-from-the-host-side"
        return Verdict(False,
                       f"${product_id:04X} is what a HOST-SIDE read_memory of "
                       "$DE00 returns. That path never reaches the cartridge in "
                       "any state, so this value is the same with a working "
                       "card, with no card and on Auto -- it must be read on the "
                       "6510", ev)
    if product_id == 0:
        ev["diagnosis"] = "unidentified-zeros"
        return Verdict(False,
                       "the $DE00 window reads as zeros. That is Cartridge "
                       "Preference = Auto, or post-run_prg, or no cartridge at "
                       "all -- three causes behind one observation, so this is "
                       "'unidentified', not 'absent'", ev, status="inconclusive")
    if product_id != CS8900A_PRODUCT_ID:
        ev["diagnosis"] = "wrong-chip"
        return Verdict(False, f"PPData reads ${product_id:04X}, not the CS8900a's "
                              f"EISA product ID ${CS8900A_PRODUCT_ID:04X}", ev)
    ev["diagnosis"] = "ok"
    return Verdict(True, f"the CS8900a identified itself: PPData = "
                         f"${product_id:04X}", ev)


def check_bench_health(ping_ok: bool | None, *, replies: int = 0,
                       rtt_ms: Sequence[float] = (),
                       max_rtt_ms: float = 50.0,
                       product_id: int | None = None,
                       control: str = "pingstatic-1066.prg") -> Verdict:
    """The static-IP ping control succeeded, so the bench itself is sound.

    Gates the whole run: if this fails, the cable, the NIC, the cartridge or
    the rig is wrong and NOTHING about our build can be concluded from
    anything downstream. Cartridge presence is part of what it proves --
    there is no valid host-side DMA test for that, because `Cartridge
    Preference = Auto`, `after run_prg`, and `no cartridge at all` all read
    $DE00 as zeros, so one observation covers four states and a checker
    built on it would be authoritative and wrong.
    """
    ev = {"control": control, "ping_ok": ping_ok, "replies": replies,
          "rtt_ms": list(rtt_ms), "caveat": BENCH_CONTROL_CAVEAT}
    if ping_ok is None:
        return Verdict(False, f"the bench-health control {control} was not run; "
                              "without it a failure downstream cannot be "
                              "attributed to our build at all", ev)
    if not ping_ok:
        return Verdict(False, f"the bench-health control {control} FAILED "
                              f"({replies} replies): the bench is wrong, and "
                              "nothing about our build can be concluded from this "
                              "run", ev)
    if replies < 1:
        return Verdict(False, f"{control} reported success with {replies} replies; "
                              "a control that passes without an answer is not a "
                              "control", ev)
    slow = [r for r in rtt_ms if r > max_rtt_ms]
    if slow:
        return Verdict(False, f"{control} replied, but {len(slow)} round trips "
                              f"exceeded {max_rtt_ms} ms {slow[:5]} -- this "
                              "silicon does 2-3 ms first try", ev)
    # The chip identification, when supplied, separates a cartridge fault
    # from a driver fault: the control passing AND the chip naming itself is
    # a stronger statement than either alone.
    chip = check_cs8900a_identified(product_id)
    ev["chip"] = chip.evidence
    ev["chip_status"] = chip.status
    ev["chip_identified"] = chip.ok
    if product_id is not None and not chip.ok:
        return Verdict(False, f"{control} passed but the CS8900a did not identify "
                              f"itself: {chip.reason}", ev, status=chip.status)
    if product_id is None:
        ev["caveat_chip"] = ("the CS8900a was not asked to identify itself, so a "
                             "cartridge fault and a driver fault are still "
                             "indistinguishable here")
    return Verdict(True, f"{control}: {replies} replies"
                         + (f", {min(rtt_ms):.1f}-{max(rtt_ms):.1f} ms" if rtt_ms else "")
                         + f". CAVEAT: {BENCH_CONTROL_CAVEAT}", ev)


# ===========================================================================
# Symbol addresses come from the BUILD, never from a constant here
# ===========================================================================
#: The diagnostic bytes the caller reads over DMA. Names only -- the
#: addresses are whatever THIS build put them at.
DIAG_SYMBOLS = ("net_last_error", "ip65_send_attempts", "ip65_recv_dropped")


def resolve_symbols(labels: dict, names: Sequence[str] = DIAG_SYMBOLS) -> Verdict:
    """Addresses for `names` out of the build's own labels.txt.

    $78A7 / $78A9 / $78AA are where these three sit in the ip65 build in
    build/labels.txt today, and that is exactly why they are not written
    down here: they move with the build, and a hardware tool that reads a
    stale address gets a byte of unrelated RAM and reports it as
    net_last_error with a straight face. A missing symbol is a hard failure
    -- an absent diagnostic is not the same as a clean one.
    """
    ev = {"requested": list(names)}
    if not names:
        return Verdict(False, "no symbols requested; the resolution would be "
                              "vacuous", ev)
    missing = [n for n in names if n not in labels]
    found = {n: labels[n] for n in names if n in labels}
    ev["found"] = {n: f"${a:04X}" for n, a in found.items()}
    ev["missing"] = missing
    if missing:
        return Verdict(False,
                       f"this build does not export {', '.join(missing)}; the "
                       "diagnostic bytes cannot be read, and a run that skips "
                       "them silently is a run with no way to tell a dropped "
                       "cartridge from a DHCP failure", ev)
    return Verdict(True, f"resolved {len(found)} symbols from the build's labels: "
                         + ", ".join(f"{n}=${a:04X}" for n, a in found.items()), ev)


# ===========================================================================
# Provenance — what state of the work produced this output
# ===========================================================================
def _git(repo: Path, *args: str) -> str | None:
    """A git command, or None if git or the repo is not there."""
    try:
        r = subprocess.run(("git", "-C", str(repo)) + args,
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    # rstrip("\n") and NOT strip(): `git status --porcelain` encodes the
    # status in the first two COLUMNS, so " M tools/x.py" begins with a
    # space, and a leading strip() eats it -- the path then parses one
    # character short ("ools/x.py"), matches nothing, and the stamp reports
    # a dirty worktree while failing to notice that one of the dirty files
    # is its own input. Measured: dirty_files=['racked.txt'].
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


def provenance(paths: Sequence[Path | str], *, repo: Path | str | None = None) -> dict:
    """Which COMMIT, and whether the worktree was dirty, produced this run.

    A file hash identifies that FILE. It does not identify the state of the
    work, and today four separate exchanges turned on that difference: one
    of two stamped files was unchanged across three commits, so quoting its
    hash back looked like a statement about the tree and was not.

    THE DIRTY MARKER MATTERS MORE THAN THE COMMIT. Three of those four were
    a clean-versus-dirty question rather than a which-commit question, and
    on a tree several lanes are writing to, a run over a dirty worktree
    silently attributes someone else's edits to your freeze. So `dirty` is
    reported for the whole worktree AND the loaded files are checked
    individually: a run whose own inputs are modified is not a run of the
    commit it names, and says so.

    Loaded paths are reported with their hashes whether or not they are
    inside the repo. Running a frozen copy out of a scratchpad against a
    PROJECT_ROOT pointing at the repo is a legitimate configuration and an
    extremely confusing one to read afterwards, so it is called out rather
    than left to be inferred.
    """
    root = Path(repo) if repo is not None else Path.cwd()
    commit = _git(root, "rev-parse", "--short", "HEAD")
    toplevel = _git(root, "rev-parse", "--show-toplevel")
    porcelain = _git(root, "status", "--porcelain") if commit else None
    out: dict = {
        "repo": toplevel,
        "commit": commit,
        "dirty": None if porcelain is None else bool(porcelain.strip()),
        "dirty_files": [],
        "untracked": [],
        "loaded_untracked": [],
        "loaded": [],
        "loaded_outside_repo": [],
        "loaded_modified": [],
        "note": "" if commit else
                "not a git repository, or git unavailable -- this output "
                "cannot be tied to a commit",
    }
    changed: set[str] = set()
    untracked: set[str] = set()
    if porcelain:
        for line in porcelain.splitlines():
            name = line[3:].strip()
            if "->" in name:                      # a rename: take the target
                name = name.split("->")[-1].strip()
            if not name:
                continue
            # TRACKED CHANGES AND UNTRACKED FILES ARE SEPARATED because they
            # are different facts and only one of them usually means
            # anything. Editor caches and tool config sit untracked in this
            # tree permanently, so a marker that reads DIRTY on every single
            # run is a marker a reader learns to skip -- and then it is not
            # there for the run that matters. An untracked file is still
            # reported, and is a hard warning when it is one of OUR INPUTS:
            # a loaded file that is untracked is not in the commit at all.
            (untracked if line.startswith("??") else changed).add(name)
        out["dirty_files"] = sorted(changed)
        out["untracked"] = sorted(untracked)
    for p in paths:
        p = Path(p)
        try:
            data = p.read_bytes()
            entry = {
                "path": str(p),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%S",
                                       time.localtime(p.stat().st_mtime)),
            }
        except OSError as exc:
            out["loaded"].append({"path": str(p), "error": str(exc)})
            continue
        rel = None
        if toplevel:
            try:
                rel = str(p.resolve().relative_to(Path(toplevel).resolve()))
            except ValueError:
                rel = None
        entry["repo_relative"] = rel
        if toplevel and rel is None:
            out["loaded_outside_repo"].append(str(p))
        if rel is not None and rel in changed:
            out["loaded_modified"].append(rel)
        if rel is not None and any(rel == u or rel.startswith(u.rstrip("/") + "/")
                                   for u in untracked):
            out["loaded_untracked"].append(rel)
        out["loaded"].append(entry)
    return out


def format_provenance(prov: dict) -> list[str]:
    """The stamp, as lines to print. Cannot be read halfway.

    The commit and the dirty state are on ONE line, so a reader who takes in
    only the first line of the stamp still cannot come away with a commit
    and no idea whether the worktree was clean.
    """
    lines: list[str] = []
    if prov.get("commit"):
        tracked = len(prov.get("dirty_files") or [])
        untracked_n = len(prov.get("untracked") or [])
        if prov.get("dirty") is None:
            state = "worktree state UNKNOWN"
        elif tracked:
            state = (f"DIRTY ({tracked} tracked paths modified"
                     + (f", {untracked_n} untracked)" if untracked_n else ")"))
        elif untracked_n:
            state = f"tracked tree CLEAN ({untracked_n} untracked paths)"
        else:
            state = "CLEAN"
        lines.append(f"provenance: {prov['commit']} {state}   repo={prov.get('repo')}")
    else:
        lines.append(f"provenance: NO COMMIT -- {prov.get('note')}")
    for entry in prov.get("loaded", []):
        if "error" in entry:
            lines.append(f"  loaded !! {entry['path']}: {entry['error']}")
            continue
        where = entry.get("repo_relative") or entry["path"]
        lines.append(f"  loaded {where}  sha256={entry['sha256'][:16]} "
                     f"bytes={entry['bytes']} mtime={entry['mtime']}")
    for p in prov.get("loaded_outside_repo", []):
        lines.append(f"  !! {p} is OUTSIDE {prov.get('repo')} -- this run did not "
                     "load the repo's copy")
    for rel in prov.get("loaded_modified", []):
        lines.append(f"  !! {rel} is MODIFIED in the worktree -- this run is NOT "
                     f"of {prov.get('commit')}")
    for rel in prov.get("loaded_untracked", []):
        lines.append(f"  !! {rel} is UNTRACKED -- it is not in "
                     f"{prov.get('commit')} at all")
    return lines
