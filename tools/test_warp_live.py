#!/usr/bin/env python3
"""tools/test_warp_live.py — Real-peer WireGuard interop test against
Cloudflare WARP (issue #70 / #87).

Drives the C64 through its OWN menu (boot.s: I/H/P/M), not a host-side
trampoline: after `run_prg` + boot_ready, cfg_* is staged directly over DMA
(bypassing WG.CFG, which is not read on hardware), then 'I' (net init/DHCP/
listen), 'H' (handshake) and 'P'/'M' (ping / message) are typed via the
KERNAL keyboard queue exactly as a person at the keyboard would, so this
exercises the real do_handshake / do_ping / do_message_input paths against
a REAL WireGuard responder (Cloudflare WARP), not the project's own patient
Python responder.

WARP profile: pass the path to a wgcf-style profile (`[Interface]
PrivateKey=...`, `Address = .../32`, `[Peer] PublicKey = ...`) via the
WARP_PROFILE environment variable. The private key is read from that file
at run time and is NEVER written to this repo, a log line, or stdout —
only its derived X25519 public key (via `wg pubkey`) is used and logged.

Stages:
  A — msg_port=9999 build: stage config, press I, H; poll wg_state for
      SESSION_ACTIVE (real Cloudflare Type-2). Records handshake wall time.
  B — ping (P) through the tunnel to 1.1.1.1, then a keyboard chat message
      (M) to the same target (no reply expected).
  R — (--rekey N, default 0) after Stage B, on the SAME session, press H
      (menu rekey) N times in sequence. Recording hs_timestamp[0..11]
      (label `hs_timestamp`, a 12-byte big-endian TAI64N: 8-byte seconds
      then 4-byte nanoseconds) BEFORE the press is processed is not
      possible from the host, so each attempt instead waits for wg_state
      to LEAVE ACTIVE first (do_handshake finishes building the Type-1,
      and hence the new hs_timestamp, before session_initiate stores
      SESSION_HS_SENT — see wg_c64_input.rekey's docstring) and reads
      hs_timestamp then, asserting it is a strictly greater 96-bit integer
      than the previous initiation's. It then waits (<=120s at 48MHz) for
      wg_state to return to ACTIVE and asserts that too. Both are real
      `assert` statements: on failure they raise, which is deliberate —
      against Cloudflare WARP this is the exact #87 scenario, where the
      unfixed firmware's second handshake NEVER reaches ACTIVE because
      Cloudflare silently drops the repeated/stale timestamp. So on master
      this stage is RED BY CONSTRUCTION, not a soft failure, and the
      result carries `rekey_expected_red_on_unfixed: true`. Skipped
      (recorded, not attempted) when --rekey 0 (the default) or when
      Stage A/B never reached ACTIVE.
  C — msg_port=53 build: a FRESH run_prg + FRESH handshake (new tai64n
      base time), then two real DNS queries (host-crafted wire bytes,
      staged raw over DMA into the message-input path) to 1.1.1.1:53 —
      one sized to land under the single-block boundary, one aimed at
      Cloudflare's 1280-byte WARP MTU — asserting the decrypted inbound
      reply's IP/UDP header and DNS transaction ID/question section.
      With --multipart N, Stage C sends a THIRD query, padded with an
      EDNS0 padding option (RFC 7830 code 12) to N bytes of inner
      payload, so the outer datagram is 28 + N + 32 bytes and crosses
      the 888-byte $16 part cap: the firmware must reassemble two parts
      into one datagram. This is the case the 2026-09-03 interop run did
      NOT cover — everything it sent (148-byte handshake, ~40-byte DNS)
      fitted in a single part, so it proved the opcode dispatches and
      nothing about reassembly. A reply proves reassembly was BYTE-EXACT
      without trusting any of our own assertions: WireGuard authenticates
      the whole datagram with Poly1305, so a dropped, overlapped or
      corrupted part fails the tag at the peer and nothing comes back.
      The tool refuses a value that would not actually split.

  D — restore 1 MHz / REU off, assert by read-back, release the lock.

Backends (`--backend {uci,ip65}`, default uci — issue #70):
  The tool never builds. It reads the BUILT backend structurally from each
  labels.txt BEFORE any run_prg and refuses (exit 2) when that disagrees
  with --backend: ip65 <=> `ip65_blob_start` present AND neither
  `uci_send_part` nor `net_last_error` present; uci <=> the reverse.
  Under uci the run is exactly what it was before --backend existed.
  Under ip65 (RR-Net):
    * get_uci_enabled/enable_uci are skipped (the C64 side never talks
      UCI); set_reu(False) and the turbo target are kept.
    * `net_last_error` is a UCI-adapter label and does not exist, so every
      read of it is gated on the backend. The post-'I' `sleep(1.0)` +
      net_last_error read becomes a poll of `net_initialized` (src/boot.s
      do_net_init sets it to 1 only after net_init + DHCP + UDP listen all
      succeeded), with a budget of WARP_NET_INIT_BUDGET_S seconds (env,
      default 120) — DHCP against a real server at 1 MHz is slow.
    * The clock is raised to --turbo only AFTER net_initialized (settle
      3 s, asserted by read-back), never before 'I': see _net_init_ip65
      for why DHCP under ip65 has to run at 1 MHz.
  Stage A PRG (ip65, into build/):
      make BACKEND=ip65 REU=0 WG_MTU1440=1
  Stage C PRG (ip65, msg_port 53 into build_msgport53/ — its own tree,
  own lib/ archives and own flag stamp, so no `make clean` is needed and
  a plain `make clean` must NOT precede it: that would wipe build/, the
  Stage A PRG):
      make BACKEND=ip65 REU=0 WG_MTU1440=1 MSG_PORT=53 BUILD_DIR=build_msgport53
  Both builds are required up front: a missing build_msgport53/labels.txt
  exits 2 before any device call.
  Exit code: 0 only when no stage recorded an error; a stage that fails
  (e.g. Stage A never ACTIVE) is logged, the remaining stages still run,
  and the process exits 1.
  Every stage logs a PRG fingerprint line (sha256, backend, WG_MTU read
  structurally as ip_pkt_len - ip_packet_buf, uci_send_part present?,
  reu_mul_init present?) so the log says which binary actually ran.

Run::

    WARP_PROFILE=/path/to/wgcf-profile.conf U64_HOST=10.43.23.81 \\
        /Users/someone/.local/bin/python3 tools/test_warp_live.py
    ... --backend ip65        # RR-Net build, see "Backends" above
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import random
import string
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, dump_screen, enable_uci,
    get_uci_enabled, probe_u64, wait_for_text,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz,
)

import wg_c64_input as ki  # noqa: E402
from u64_firmware import log_build  # noqa: E402

log = logging.getLogger("warp_live")
logging.basicConfig(level=logging.INFO,
                     format="%(asctime)s %(levelname)s %(message)s")

DEFAULT_HOST = "10.43.23.81"
WG_PUBKEY_BIN = "/opt/homebrew/bin/wg"

# --- Cloudflare WARP peer (fixed by the task; NOT the private key) ---
WARP_PEER_PUB_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT_IP = "162.159.192.1"          # engage.cloudflareclient.com
WARP_ENDPOINT_PORT = 2408
TUNNEL_IP = "172.16.0.2"
PING_TARGET_IP = "1.1.1.1"

SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2

PRG_A = PROJECT_ROOT / "build" / "wireguard.prg"                  # msg_port 9999
LABELS_A = PROJECT_ROOT / "build" / "labels.txt"
PRG_C = PROJECT_ROOT / "build_msgport53" / "wireguard.prg"        # msg_port 53
LABELS_C = PROJECT_ROOT / "build_msgport53" / "labels.txt"

HS_POLL_TIMEOUT = 120.0
PING_TIMEOUT = 10.0
DNS_TIMEOUT = 10.0
BOOT_TIMEOUT = 60.0

# ip65 only: how long 'I' (net_init + DHCP + listen, at 1 MHz) may take
# before net_initialized must read 1. Env-overridable for slow DHCP servers.
NET_INIT_BUDGET_S = float(os.environ.get("WARP_NET_INIT_BUDGET_S", "120"))
TURBO_SETTLE_S = 3.0

DNS_QTYPE_TXT = 16

# WRITE_SOCKET_CHUNK ($16) carries a 7-byte header, so ONE part holds at most
# 888 payload bytes (not 892/890 — reusing the plain-SOCKET_WRITE constant
# overflows silently; GideonZ/1541ultimate#807). A datagram above this is what
# makes the send path SPLIT, which is the point of --multipart: the 2026-09-03
# interop run sent nothing above the 148-byte handshake, so it exercised the
# $16 opcode but never its reassembly.
UCI_CHUNK_PART_MAX = 888
WG_DATA_OVERHEAD = 32          # Type-4 header (16) + Poly1305 tag (16)
IP_UDP_HDR = 28
EDNS_OPT_PADDING = 12          # RFC 7830 option code

# The control query's inner length: padded exactly like the multi-part one
# but sized so the outer datagram stays inside a single part. Derived, not
# picked: cap - IP/UDP header - WireGuard overhead, minus a small margin.
CONTROL_INNER_LEN = UCI_CHUNK_PART_MAX - IP_UDP_HDR - WG_DATA_OVERHEAD - 28

# The padded queries do NOT go to 1.1.1.1. Measured from this host on
# 2026-09-03, sending EDNS0-filled queries straight to each resolver:
#
#   resolver          512 B   829 B   1000 B   padded 800/1000 (3 tries)
#   1.1.1.1 (CF)      reply   DROP    DROP     -
#   8.8.8.8 (Google)  reply   DROP    DROP     -
#   9.9.9.9 (Quad9)   reply   reply   reply    1/3, 1/3  <- too flaky
#   208.67.222.222    reply   reply   reply    3/3, 3/3  <- chosen
#
# Quad9 answers a large padded query only about a third of the time, which
# is enough to make the CONTROL rung read as a failure of OUR stack when it
# is the resolver's. OpenDNS is reliable at both sizes, so the control is a
# comparison rather than noise.
#
# Cloudflare's resolver silently drops REQUESTS over ~512 bytes, so it can
# never answer a query big enough to need two $16 parts (>= 829 B inner) —
# which is why the first attempt at this test produced two silent queries
# and proved nothing. The WireGuard peer is still Cloudflare WARP: the
# datagram must pass ITS Poly1305 before anything is forwarded to Quad9, so
# the oracle property is unchanged. Only the inner destination moves.
MULTIPART_RESOLVER_IP = "208.67.222.222"

# A SMALL query to the same resolver, same construction: proves the tunnel
# reaches it at all. WARP is known to intercept DNS, and without this rung
# silence from the padded pair cannot be told apart from "this resolver is
# unreachable through the tunnel".
SMALL_PROBE_LEN = 200

# Each rung is sent this many times. The inbound path is INTERMITTENT here
# (a 1278 B reply failed to decrypt in 2 of 4 runs on 2026-09-03, and the
# 800 B control answered in 1 of 2), so a single observation distinguishes
# nothing: what is wanted is a RATE per rung, not an anecdote.
MULTIPART_REPEATS = 3

BACKENDS = ("uci", "ip65")


# =============================================================================
# Backend detection — structural, from the BUILT labels, never from --backend
# =============================================================================
class BackendMismatch(RuntimeError):
    """labels.txt describes a different backend than --backend asked for."""


def detect_backend(L) -> str:
    """'ip65' or 'uci' from label PRESENCE only (any Mapping[str, int]).

    ip65 <=> the RR-Net blob is linked (`ip65_blob_start`) and neither
    UCI-adapter label is: `uci_send_part` (chunked send, UCI_CHUNKED_WRITE=1
    only) or `net_last_error` (the UCI adapter's error byte, every uci
    build). uci <=> exactly the reverse. Anything else raises ValueError so
    a half-matching labels file is refused rather than guessed.
    """
    has_blob = "ip65_blob_start" in L
    has_uci = ("uci_send_part" in L) or ("net_last_error" in L)
    if has_blob and not has_uci:
        return "ip65"
    if has_uci and not has_blob:
        return "uci"
    raise ValueError(
        f"labels match neither backend: ip65_blob_start={has_blob} "
        f"uci_send_part={'uci_send_part' in L} "
        f"net_last_error={'net_last_error' in L}")


def load_labels_for_backend(labels_path: Path, backend: str) -> dict:
    """Labels.from_file + detect_backend; raises BackendMismatch on disagreement.

    Called before the device is touched (no probe, no lock, no run_prg), so
    a wrong --backend, or a build/ left over from the other backend, is
    refused up front.
    """
    L = dict(Labels.from_file(str(labels_path)))
    try:
        found = detect_backend(L)
    except ValueError as exc:
        raise BackendMismatch(
            f"requested --backend {backend} but {labels_path} is neither "
            f"a uci nor an ip65 build ({exc})") from exc
    if found != backend:
        raise BackendMismatch(
            f"requested --backend {backend} but {labels_path} is a {found} "
            f"build (ip65_blob_start={'ip65_blob_start' in L}, "
            f"uci_send_part={'uci_send_part' in L}, "
            f"net_last_error={'net_last_error' in L}) — rebuild with "
            f"BACKEND={backend} or pass --backend {found}")
    return L


def _fingerprint(tag: str, prg_bytes: bytes, L: dict, backend: str) -> dict:
    """Log + return which binary this stage is about to run (mirrors
    test_uci_handshake_live's fingerprint): sha256, backend, WG_MTU read
    structurally (ip_packet_buf is .res WG_MTU and ip_pkt_len follows it),
    and whether the chunked-send / REU-multiply entry points are linked."""
    sha = hashlib.sha256(prg_bytes).hexdigest()
    has_chunk = "uci_send_part" in L
    has_reu_init = "reu_mul_init" in L
    mtu = (L["ip_pkt_len"] - L["ip_packet_buf"]
           if "ip_pkt_len" in L and "ip_packet_buf" in L else -1)
    log.info("%s PRG fingerprint: sha256=%s (%d B) backend=%s WG_MTU=%d "
             "uci_send_part=%s reu_mul_init=%s -> %s build, %s",
             tag, sha, len(prg_bytes), backend, mtu, has_chunk, has_reu_init,
             "REU" if has_reu_init else "onchip/REU=0",
             "chunked UCI send (1472 B datagrams)" if has_chunk
             else ("ip65 native send" if backend == "ip65"
                   else "plain UCI send (892 B datagrams)"))
    return {"sha256": sha, "size": len(prg_bytes), "backend": backend,
            "wg_mtu": mtu, "uci_send_part": has_chunk,
            "reu_mul_init": has_reu_init}


# =============================================================================
# WARP profile / key handling — the private key never leaves this function
# except as bytes handed straight to `wg pubkey` over stdin.
# =============================================================================
def _load_warp_profile(path: str) -> tuple[bytes, str, str]:
    """Returns (c64_priv_32B, tunnel_ip, resp_pub_b64). Never logs the key."""
    priv_b64 = None
    address = None
    peer_pub = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("PrivateKey"):
                priv_b64 = line.split("=", 1)[1].strip()
            elif line.startswith("Address"):
                address = line.split("=", 1)[1].strip().split(",")[0].strip()
            elif line.startswith("PublicKey"):
                peer_pub = line.split("=", 1)[1].strip()
    if not priv_b64:
        raise RuntimeError("WARP_PROFILE has no PrivateKey= line")
    if peer_pub != WARP_PEER_PUB_B64:
        log.warning("profile PublicKey %s != expected %s — using profile's",
                    peer_pub, WARP_PEER_PUB_B64)
    import base64
    priv = base64.b64decode(priv_b64)
    assert len(priv) == 32
    tunnel_ip = (address.split("/")[0] if address else TUNNEL_IP)
    return priv, tunnel_ip, (peer_pub or WARP_PEER_PUB_B64)


def _derive_pubkey(priv: bytes) -> bytes:
    """wg pubkey < priv, over stdin only. Returns 32 raw bytes."""
    import base64
    p = subprocess.run([WG_PUBKEY_BIN, "pubkey"],
                       input=base64.b64encode(priv) + b"\n",
                       capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"wg pubkey failed: {p.stderr!r}")
    return base64.b64decode(p.stdout.strip())


# =============================================================================
# DNS query construction (host-side, pure wire format)
# =============================================================================
def build_dns_query(name: str, qtype: int, txn_id: int,
                    bufsize: int = 1400) -> bytes:
    def enc_name(n: str) -> bytes:
        out = b""
        for label in n.strip(".").split("."):
            if label:
                out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 1)  # RD=1, 1 Q, 1 ARCOUNT (OPT)
    question = enc_name(name) + struct.pack(">HH", qtype, 1)     # QCLASS=IN
    opt = b"\x00" + struct.pack(">HHIH", 41, bufsize, 0, 0)      # root name, TYPE=OPT
    # NOTE (post-run fix): first return value is the QUESTION SECTION ONLY
    # (no header) — it is compared against reply bytes starting at the
    # reply's own offset 12, so it must not carry this query's 12-byte
    # header. An earlier version returned header+question here, which made
    # every "question_echo_ok" check compare the wrong 12 bytes and always
    # read False on hardware even though the actual DNS exchange (txn_id
    # match, QR=1, correct ANCOUNT, correct IP/port) was fully correct.
    return question, header + question + opt


def build_padded_dns_query(name: str, qtype: int, txn_id: int,
                           total_len: int, bufsize: int = 1400):
    """A DNS query padded to EXACTLY `total_len` bytes with an EDNS0 padding
    option (RFC 7830, option code 12), to push one datagram over the 888-byte
    chunk part cap and force a genuine multi-part $16 write.

    Padding octets are zero, as RFC 7830 requires, so the per-run
    randomisation this project demands of wire payloads lives in the QNAME
    label and the transaction id — both chosen by the caller — not here.

    Returns (question_section, wire_bytes), the same shape as
    build_dns_query, so the reply checks are identical for a padded and an
    unpadded query. Raises rather than silently emitting a SHORTER packet
    than asked for: a quietly-too-small query would stop testing the split
    while still passing every reply assertion.
    """
    question, base = build_dns_query(name, qtype, txn_id, bufsize=bufsize)
    pad_total = total_len - len(base)
    if pad_total < 4:
        raise ValueError(
            f"total_len={total_len} leaves {pad_total} bytes for the padding "
            f"option; need >= 4 (2 code + 2 length) on top of the "
            f"{len(base)}-byte unpadded query")
    pad_len = pad_total - 4
    opt_rdata = struct.pack(">HH", EDNS_OPT_PADDING, pad_len) + bytes(pad_len)
    wire = base[:-11] + b"\x00" + struct.pack(
        ">HHIH", 41, bufsize, 0, len(opt_rdata)) + opt_rdata
    if len(wire) != total_len:
        raise AssertionError(
            f"padded query is {len(wire)} bytes, asked for {total_len}")
    return question, wire


def datagram_parts(inner_len: int) -> tuple:
    """(outer datagram length, number of $16 parts) for an inner IP payload.

    Derived, not assumed: outer = IP/UDP header + inner + WireGuard Type-4
    overhead, split into ceil(outer / 888) parts. Logged with every
    --multipart run so the claim "this was multi-part" is arithmetic the
    reader can check, not an assertion about invisible behaviour.
    """
    outer = IP_UDP_HDR + inner_len + WG_DATA_OVERHEAD
    return outer, -(-outer // UCI_CHUNK_PART_MAX)


def stage_raw_dma(tr: Ultimate64Transport, payload: bytes, L: dict,
                  timeout: float = 30.0) -> bool:
    """Like wg_c64_input.send_message_dma but stages RAW bytes (no ASCII
    upper()/encode() transform), for binary DNS wire data."""
    limit = ki.input_max_from_labels(L)
    if len(payload) > limit:
        raise ValueError(f"{len(payload)} bytes exceeds this build's "
                         f"MSG_TEXT_MAX of {limit}")
    if not ki.press_key(tr, "M", timeout):
        return False
    if not ki._wait_drained(tr, timeout):
        return False
    time.sleep(0.3)
    base = L["ip_packet_buf"] + ki.IP_UDP_HDR_LEN
    for i in range(0, len(payload), ki.DMA_CHUNK):
        tr.write_memory(base + i, payload[i:i + ki.DMA_CHUNK])
    tr.write_memory(L["msg_input_len"], len(payload).to_bytes(2, "little"))
    return ki.press_key(tr, "\r", timeout)


# =============================================================================
# Device-side helpers
# =============================================================================
def _wait_boot_ready(tr: Ultimate64Transport, L: dict, timeout: float = BOOT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    addr = L["boot_ready"]
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1)[0] == 1:
            log.info("boot complete — boot_ready=1")
            return
        time.sleep(0.25)
    raise RuntimeError(f"boot_ready never set within {timeout}s")


def _stage_config(tr: Ultimate64Transport, L: dict, c64_priv: bytes,
                  c64_pub: bytes, resp_pub: bytes, tunnel_ip: str,
                  ping_target_ip: str) -> int:
    """Stage cfg_* over DMA; returns the tai64n base time used."""
    tr.write_memory(L["cfg_static_priv"], c64_priv)
    tr.write_memory(L["cfg_static_pub"], c64_pub)
    tr.write_memory(L["cfg_peer_pub"], resp_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))  # no PSK
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in WARP_ENDPOINT_IP.split(".")))
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF]))
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in tunnel_ip.split(".")))
    tr.write_memory(L["ping_target_ip"],
                    bytes(int(o) for o in ping_target_ip.split(".")))
    # issue #87: stage the CURRENT unix time as the TAI64N base every run,
    # so this run's first initiation is strictly newer than any prior run's
    # against the same static key (Cloudflare enforces monotonicity).
    tai = int(time.time()) + 10  # TAI-UTC offset (approximate is fine)
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))
    log.info("cfg staged: c64_pub=%s... resp_pub=%s... peer=%s:%d tai64=%d",
             c64_pub.hex()[:8], resp_pub.hex()[:8], WARP_ENDPOINT_IP,
             WARP_ENDPOINT_PORT, tai)
    return tai


def _set_turbo_checked(client: Ultimate64Client, mhz: int,
                       settle: float = TURBO_SETTLE_S) -> int:
    """set_turbo_mhz + settle + read-back; raises if the clock did not stick."""
    set_turbo_mhz(client, mhz)
    time.sleep(settle)
    actual = get_turbo_mhz(client)
    if actual != mhz:
        raise RuntimeError(f"turbo did not stick: requested {mhz} MHz, "
                           f"device reports {actual}")
    log.info("turbo confirmed stuck at %d MHz", actual)
    return actual


def _net_init_ip65(tr: Ultimate64Transport, client: Ultimate64Client,
                   L: dict, turbo_mhz: int, result: dict) -> bool:
    """ip65 replacement for "press I, sleep 1 s, read net_last_error".

    Runs 'I' at 1 MHz, polls `net_initialized` (boot.s do_net_init stores 1
    only after net_init + DHCP + UDP listen all succeeded) within
    NET_INIT_BUDGET_S, and only THEN raises the clock to *turbo_mhz*.

    Why DHCP has to happen at 1 MHz: the ip65 blob is the RR-Net (CS8900A)
    driver plus its own ARP/DHCP state machines, and those time out with
    CPU-counted delay loops and retry counters calibrated for a 1 MHz 6510.
    At 48 MHz every such wait expires ~48x sooner than the wire — a real
    DHCP server's DISCOVER/OFFER round trip has not even started when ip65
    gives up — and the RR-Net's cartridge-port register accesses are only
    specified at the stock bus timing. The crypto is what needs the turbo,
    and it starts at 'H', so the clock goes up between 'I' completing and
    'H'. (The UCI adapter has none of this: the firmware does DHCP, the C64
    only talks to $DF1B-$DF1F, and its waits are CIA-TOD bounded.)

    Returns False with result["error"] set when net_initialized never
    reads 1 (screen dumped); raises if the clock does not stick.
    """
    _set_turbo_checked(client, 1)
    if not ki.press_key(tr, "I", timeout=20.0):
        result["error"] = "press I (net init) not consumed"
        return False
    t0 = time.monotonic()
    up = ki.wait_for_state(tr, L["net_initialized"], 1, NET_INIT_BUDGET_S,
                           poll=1.0)
    result["net_init_seconds"] = round(time.monotonic() - t0, 1)
    result["net_initialized"] = up
    if not up:
        result["error"] = (f"net_initialized never set within "
                           f"{NET_INIT_BUDGET_S:.0f}s of pressing I "
                           f"(ip65 net_init/DHCP/listen failed; screen dumped)")
        log.error(result["error"])
        dump_screen(tr, label="ip65-net-init-timeout")
        return False
    log.info("after I: net_initialized=1 in %.1fs (ip65, at 1 MHz)",
             result["net_init_seconds"])
    _set_turbo_checked(client, turbo_mhz)
    return True


def _dump_failure(tr: Ultimate64Transport, L: dict, tag: str,
                  backend: Optional[str] = None) -> None:
    # net_last_error is a UCI-adapter label: gate the read on the backend
    # (detected from the labels when the caller did not pass it).
    backend = backend or detect_backend(L)
    if backend == "uci":
        err = tr.read_memory(L["net_last_error"], 1)[0]
        log.error("[%s] net_last_error=$%02X", tag, err)
    else:
        log.error("[%s] backend=%s (no net_last_error)", tag, backend)
    for name, n in (("hs_h", 32), ("hs_c", 32), ("hs_resp_packet", 92),
                    ("hs_ephem_pub", 32)):
        if name in L:
            log.error("[%s] %s = %s", tag, name,
                      bytes(tr.read_memory(L[name], n)).hex())
    dump_screen(tr, label=tag)


def run_stage_ab(tr: Ultimate64Transport, client: Ultimate64Client, L: dict,
                 c64_priv: bytes, c64_pub: bytes, resp_pub: bytes,
                 seed: int, backend: str = "uci", turbo_mhz: int = 48,
                 prg_path: Path = PRG_A) -> dict:
    result: dict = {"stage": "A/B"}
    prg_bytes = prg_path.read_bytes()
    result["prg"] = _fingerprint("Stage A", prg_bytes, L, backend)
    client.run_prg(prg_bytes)
    _wait_boot_ready(tr, L)

    _stage_config(tr, L, c64_priv, c64_pub, resp_pub, TUNNEL_IP, PING_TARGET_IP)

    if backend == "ip65":
        # 'I' at 1 MHz, poll net_initialized, THEN turbo — see _net_init_ip65.
        if not _net_init_ip65(tr, client, L, turbo_mhz, result):
            return result
    else:
        if not ki.press_key(tr, "I", timeout=20.0):
            result["error"] = "press I (net init) not consumed"
            return result
        time.sleep(1.0)  # net_init/DHCP read/listen — fast, but let it settle
        err = tr.read_memory(L["net_last_error"], 1)[0]
        log.info("after I: net_last_error=$%02X", err)

    if not ki.press_key(tr, "H", timeout=20.0):
        result["error"] = "press H (handshake) not consumed"
        return result

    t0 = time.monotonic()
    active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE, HS_POLL_TIMEOUT, poll=1.0)
    elapsed = time.monotonic() - t0
    state = tr.read_memory(L["wg_state"], 1)[0]
    result["handshake_seconds"] = round(elapsed, 1)
    result["wg_state_final"] = state
    result["active"] = active

    if not active:
        _dump_failure(tr, L, "stageA-handshake", backend)
        return result

    log.info("Stage A: ACTIVE in %.1fs", elapsed)

    # --- Stage B: ping ---
    if not ki.press_key(tr, "P", timeout=15.0):
        result["ping_error"] = "press P not consumed"
    else:
        grid = wait_for_text(tr, "PING REPLY OK", timeout=PING_TIMEOUT, verbose=False)
        result["ping_reply"] = grid is not None
        if grid is None:
            dump_screen(tr, label="stageB-ping-timeout")

    # --- Stage B: chat message (no reply expected) ---
    suffix = "".join(random.choice(string.ascii_uppercase + string.digits)
                     for _ in range(8))
    msg_text = f"HELLO {suffix}"
    before = int.from_bytes(tr.read_memory(L["tp_send_counter"], 2), "little") \
        if "tp_send_counter" in L else None
    ok = ki.send_message_dma(tr, msg_text, L, timeout=15.0)
    time.sleep(0.5)
    # net_last_error exists only in the UCI adapter — gated on backend.
    err_after = (tr.read_memory(L["net_last_error"], 1)[0]
                 if backend == "uci" else None)
    after = int.from_bytes(tr.read_memory(L["tp_send_counter"], 2), "little") \
        if "tp_send_counter" in L else None
    result["message_sent_keypress_ok"] = ok
    result["message_text"] = msg_text
    result["tp_send_counter_before"] = before
    result["tp_send_counter_after"] = after
    result["net_last_error_after_message"] = (
        f"${err_after:02X}" if err_after is not None else None)
    return result


def hs_timestamp_gt(new: bytes, old: bytes) -> bool:
    """True iff *new* is a strictly greater 96-bit TAI64N than *old*.

    hs_timestamp is 12 bytes big-endian: [0..7] seconds, [8..11]
    nanoseconds, each field itself big-endian (src/wg/handshake.s,
    src/wg/tai64n.s). Treating the whole 12 bytes as ONE big-endian
    integer is exactly the right comparison — the 8 seconds bytes sit at
    the high end and the 4 nanosecond bytes at the low end, so seconds
    dominate and nanoseconds only break a tie, which is TAI64N ordering.
    Strict: two identical stamps compare False, never True.
    """
    if len(new) != 12 or len(old) != 12:
        raise ValueError(
            f"hs_timestamp must be 12 bytes, got {len(new)} / {len(old)}")
    return int.from_bytes(new, "big") > int.from_bytes(old, "big")


def run_stage_rekey(tr: Ultimate64Transport, L: dict, n: int,
                    initial_ts: bytes, out: dict) -> None:
    """Press H (rekey) *n* times in sequence, mutating *out* in place.

    See the module docstring's Stage R for the read-timing rationale and
    why this stage is RED BY CONSTRUCTION on unfixed firmware against
    Cloudflare WARP (issue #87). Both invariants below are real `assert`
    statements — on failure they raise AssertionError, which propagates
    out of this call. *out* is mutated as we go (not just returned) so the
    caller still has per-attempt data — including wall time, logged via
    `log.info` before each assert — even when a later attempt raises.
    """
    out["stage"] = "rekey"
    out["rekey_expected_red_on_unfixed"] = True
    out["attempts"] = []
    prev_ts = initial_ts
    for i in range(1, n + 1):
        attempt: dict = {"index": i}
        out["attempts"].append(attempt)
        t0 = time.monotonic()

        pressed = ki.press_key(tr, "H", timeout=15.0)
        attempt["press_ok"] = pressed
        assert pressed, f"rekey {i}: press H (rekey) not consumed"

        left = ki.wait_while_state(tr, L["wg_state"], SESSION_ACTIVE,
                                   HS_POLL_TIMEOUT, poll=1.0)
        attempt["left_active"] = left
        if not left:
            _dump_failure(tr, L, f"rekey-{i}-no-leave")
        assert left, (f"rekey {i}: wg_state never left ACTIVE within "
                      f"{HS_POLL_TIMEOUT}s of pressing H")

        # do_handshake has finished building the new Type-1 (and hence the
        # new hs_timestamp) by the time wg_state leaves ACTIVE — see
        # wg_c64_input.rekey's docstring — so this read cannot still be
        # looking at the PREVIOUS session's timestamp.
        new_ts = bytes(tr.read_memory(L["hs_timestamp"], 12))
        attempt["hs_timestamp_prev_hex"] = prev_ts.hex()
        attempt["hs_timestamp_new_hex"] = new_ts.hex()
        increased = hs_timestamp_gt(new_ts, prev_ts)
        attempt["hs_timestamp_increased"] = increased
        if not increased:
            log.error("rekey %d: hs_timestamp did not increase: "
                     "prev=%s new=%s", i, prev_ts.hex(), new_ts.hex())
        assert increased, (
            f"rekey {i}: hs_timestamp {new_ts.hex()} is not strictly "
            f"greater than the previous initiation's {prev_ts.hex()}")

        active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE,
                                   HS_POLL_TIMEOUT, poll=1.0)
        elapsed = time.monotonic() - t0
        attempt["active"] = active
        attempt["handshake_seconds"] = round(elapsed, 1)
        log.info("rekey %d: hs_timestamp_increased=%s active=%s (%.1fs)",
                i, increased, active, elapsed)
        if not active:
            _dump_failure(tr, L, f"rekey-{i}-no-return")
        # issue #87: against Cloudflare WARP, THIS is the assertion
        # expected to fail on unfixed firmware — Cloudflare silently drops
        # the repeated/stale timestamp, the Type-2 response never arrives,
        # and wg_state never returns to ACTIVE.
        assert active, (
            f"rekey {i}: wg_state never returned to ACTIVE within "
            f"{HS_POLL_TIMEOUT}s — issue #87 on unfixed firmware")

        prev_ts = new_ts

    out["all_increased"] = all(a["hs_timestamp_increased"] for a in out["attempts"])
    out["all_active"] = all(a["active"] for a in out["attempts"])


def run_stage_c(tr: Ultimate64Transport, client: Ultimate64Client, L: dict,
                c64_priv: bytes, c64_pub: bytes, resp_pub: bytes,
                seed: int, backend: str = "uci", turbo_mhz: int = 48,
                multipart: int = 0) -> dict:
    result: dict = {"stage": "C"}
    prg_bytes = PRG_C.read_bytes()
    result["prg"] = _fingerprint("Stage C", prg_bytes, L, backend)
    client.run_prg(prg_bytes)
    _wait_boot_ready(tr, L)

    _stage_config(tr, L, c64_priv, c64_pub, resp_pub, TUNNEL_IP, PING_TARGET_IP)

    if backend == "ip65":
        # Fresh run_prg, fresh DHCP: back to 1 MHz for 'I', turbo after.
        if not _net_init_ip65(tr, client, L, turbo_mhz, result):
            return result
    else:
        if not ki.press_key(tr, "I", timeout=20.0):
            result["error"] = "press I (net init) not consumed"
            return result
        time.sleep(1.0)

    if not ki.press_key(tr, "H", timeout=20.0):
        result["error"] = "press H (handshake) not consumed"
        return result

    t0 = time.monotonic()
    active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE, HS_POLL_TIMEOUT, poll=1.0)
    elapsed = time.monotonic() - t0
    result["handshake_seconds"] = round(elapsed, 1)
    result["active"] = active
    if not active:
        _dump_failure(tr, L, "stageC-handshake", backend)
        return result
    log.info("Stage C: ACTIVE in %.1fs", elapsed)

    random.seed(seed)
    queries = [
        ("namecheap.com", DNS_QTYPE_TXT, 1278, "900-1279 band", None, None),
        ("github.com", DNS_QTYPE_TXT, 1928, "targets >1280 (Cloudflare WARP MTU)", None, None),
    ]
    if multipart:
        # Three rungs x MULTIPART_REPEATS, differing ONLY in size, so each
        # adjacent pair isolates exactly one variable:
        #   REACHABILITY  small  -> does the tunnel reach this resolver?
        #   CONTROL       large, ONE part  -> will it answer a big datagram?
        #   MULTI-PART    large, TWO parts -> does reassembly survive?
        # Silence first appearing at MULTI-PART is the only pattern that
        # implicates reassembly; silence at rung 1 means the vehicle is
        # dead and nothing was tested. Repeats because the path is
        # intermittent: one observation distinguishes nothing.
        # Names are randomised per query (seeded, logged) so no reply can
        # come from a cache; the padding octets stay zero per RFC 7830.
        for _ in range(MULTIPART_REPEATS):
            for size, label, want in (
                    (SMALL_PROBE_LEN, "REACHABILITY", 1),
                    (CONTROL_INNER_LEN, "CONTROL single-part", 1),
                    (multipart, "MULTI-PART", 2)):
                tk = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
                queries.append((f"{tk}.cloudflare.com", DNS_QTYPE_TXT, 0,
                                f"{label}: {size} B inner -> {MULTIPART_RESOLVER_IP}",
                                size, want))
    result["queries"] = []
    for name, qtype, dig_size, band, pad_to, want_parts in queries:
        txn_id = random.randint(0, 0xFFFF)
        target = MULTIPART_RESOLVER_IP if pad_to else PING_TARGET_IP
        if pad_to:
            # ping_target_ip is read when each packet is built, so a DMA
            # write here retargets the NEXT query without a re-handshake.
            tr.write_memory(L["ping_target_ip"],
                            bytes(int(o) for o in target.split(".")))
            question, wire = build_padded_dns_query(name, qtype, txn_id, pad_to)
            outer, parts = datagram_parts(len(wire))
            # The CONTROL must be exactly one part and the TEST at least
            # two: the pair is the whole experiment, so a size that does not
            # produce the intended split makes the comparison meaningless.
            bad = (parts != 1 if want_parts == 1 else parts < 2)
            if bad:
                result["error"] = (
                    f"padded query of {pad_to} B inner yields a {outer}-byte "
                    f"datagram = {parts} part(s), wanted "
                    f"{'exactly 1 (control)' if want_parts == 1 else '>= 2 (test)'}"
                    f": the control/test pair would prove nothing")
                log.error("%s", result["error"])
                return result
            log.info("DNS query %s TXT txn_id=%d wire_len=%d -> outer datagram "
                     "%d B = %d parts of <=%d (%s)", name, txn_id, len(wire),
                     outer, parts, UCI_CHUNK_PART_MAX, band)
        else:
            question, wire = build_dns_query(name, qtype, txn_id, bufsize=1400)
            outer, parts = datagram_parts(len(wire))
            log.info("DNS query %s %s txn_id=%d wire_len=%d dig_measured=%d (%s)",
                     name, {16: "TXT"}.get(qtype, qtype), txn_id, len(wire),
                     dig_size, band)

        # Clear the receive markers so we can tell a NEW reply apart.
        tr.write_memory(L["msg_recv_len"], bytes(2))
        tr.write_memory(L["tp_payload_len"], bytes(2))

        staged = stage_raw_dma(tr, wire, L, timeout=15.0)
        q = {"name": name, "qtype": qtype, "txn_id": txn_id,
            "inner_target": target,
            "wire_len": len(wire), "dig_measured": dig_size, "band": band,
            "outer_datagram_len": outer, "uci_parts": parts,
            "multipart": bool(pad_to), "staged_ok": staged}

        # Recorded per query so a silent reply can be told apart from a send
        # that never left: "no reply" and "never sent" look identical in
        # msg_recv_len alone.
        try:
            q["net_last_error"] = "$%02X" % tr.read_memory(L["net_last_error"], 1)[0]
            q["tp_send_counter"] = int.from_bytes(
                tr.read_memory(L["tp_send_counter"], 2), "little")
        except Exception as exc:                      # noqa: BLE001
            q["telemetry_error"] = repr(exc)

        deadline = time.monotonic() + DNS_TIMEOUT
        recv_len = 0
        while time.monotonic() < deadline:
            recv_len = int.from_bytes(tr.read_memory(L["msg_recv_len"], 2), "little")
            if recv_len:
                break
            time.sleep(0.25)
        q["reply_recv_len"] = recv_len

        if recv_len:
            recv_ptr = int.from_bytes(tr.read_memory(L["msg_recv_ptr"], 2), "little")
            dns_payload = bytes(tr.read_memory(recv_ptr, min(recv_len, 1450)))
            ip_hdr = bytes(tr.read_memory(L["tp_packet"] + 16, 20))
            udp_hdr = bytes(tr.read_memory(L["tp_packet"] + 16 + 20, 8))
            src_ip = ".".join(str(b) for b in ip_hdr[12:16])
            dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
            src_port = (udp_hdr[0] << 8) | udp_hdr[1]
            dst_port = (udp_hdr[2] << 8) | udp_hdr[3]
            reply_txn = (dns_payload[0] << 8) | dns_payload[1] if len(dns_payload) >= 2 else None
            qr_bit = bool(dns_payload[2] & 0x80) if len(dns_payload) >= 3 else None
            ancount = (dns_payload[6] << 8) | dns_payload[7] if len(dns_payload) >= 8 else None
            question_echo_ok = dns_payload[12:12 + len(question)] == question \
                if len(dns_payload) >= 12 + len(question) else False
            q.update({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "txn_id_match": reply_txn == txn_id,
                "qr_bit": qr_bit, "ancount": ancount,
                "question_echo_ok": question_echo_ok,
                "src_ip_ok": src_ip == target,
                "dst_ip_ok": dst_ip == TUNNEL_IP,
                "ports_ok": src_port == 53 and dst_port == 53,
            })
        else:
            dump_screen(tr, label=f"stageC-dns-timeout-{name}")
        result["queries"].append(q)
        if pad_to:
            tr.write_memory(L["ping_target_ip"],
                            bytes(int(o) for o in PING_TARGET_IP.split(".")))
    return result


# =============================================================================
# main
# =============================================================================
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("U64_HOST", DEFAULT_HOST))
    p.add_argument("--turbo", type=int, default=48)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--rekey", type=int, default=0, metavar="N",
                   help="After Stage B, press H (rekey) N times in "
                        "sequence, asserting hs_timestamp strictly "
                        "increases and wg_state returns to ACTIVE each "
                        "time (issue #87). RED BY CONSTRUCTION (raises) "
                        "against Cloudflare WARP on unfixed firmware.")
    p.add_argument("--multipart", type=int, default=0, metavar="N",
                   help="Stage C also sends a DNS query padded (EDNS0 option "
                        "12) to N bytes of inner payload, so the outer "
                        "datagram crosses the 888-byte $16 part cap and the "
                        "firmware must REASSEMBLE it. A reply proves that "
                        "reassembly was byte-exact: WireGuard authenticates "
                        "the whole datagram, so a dropped, overlapped or "
                        "corrupted part fails Poly1305 at the peer and "
                        "nothing comes back. Try 1000. 0 (default) = off.")
    p.add_argument("--backend", choices=BACKENDS, default="uci",
                   help="Which backend the PRGs in build/ and "
                        "build_msgport53/ were built for (issue #70). "
                        "Verified structurally from each labels.txt before "
                        "any run_prg; a mismatch exits 2. Default uci; "
                        "ip65 skips the UCI enable, polls net_initialized "
                        "after I and raises the clock only after DHCP.")
    p.add_argument("--labels", default=str(LABELS_A), metavar="PATH",
                   help="Stage A labels.txt (default build/labels.txt); "
                        "the PRG beside it is what Stage A runs. Stage C "
                        "always uses build_msgport53/.")
    args = p.parse_args(argv)

    seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)
    log.info("Random seed: %d (reproduce with --seed %d)", seed, seed)

    profile_path = os.environ.get("WARP_PROFILE")
    if not profile_path:
        log.error("WARP_PROFILE env var not set (path to wgcf profile)")
        return 2
    c64_priv, tunnel_ip, resp_pub_b64 = _load_warp_profile(profile_path)
    c64_pub = _derive_pubkey(c64_priv)
    import base64
    resp_pub = base64.b64decode(resp_pub_b64)
    log.info("c64 static pub (derived, safe to log): %s", base64.b64encode(c64_pub).decode())
    log.info("peer pub: %s", resp_pub_b64)

    # Backend check from the BUILT labels of BOTH stages, before the device
    # is touched (no probe, no lock, no run_prg on a mismatch or a missing
    # Stage C build).
    labels_a = Path(args.labels)
    prg_a = labels_a.parent / "wireguard.prg"
    try:
        # Stage A first: a wrong --backend is the more fundamental error and
        # must be the one reported, even when Stage C is not built yet.
        L_A = load_labels_for_backend(labels_a, args.backend)
        if not LABELS_C.exists():
            log.error("Stage C build missing: %s — build it first: make "
                      "BACKEND=%s REU=0 %s MSG_PORT=53 "
                      "BUILD_DIR=build_msgport53",
                      LABELS_C, args.backend,
                      "WG_MTU1440=1" if args.backend == "ip65"
                      else "UCI_CHUNKED_WRITE=1")
            return 2
        L_C = load_labels_for_backend(LABELS_C, args.backend)
    except BackendMismatch as exc:
        log.error("backend mismatch: %s", exc)
        return 2
    log.info("backend=%s confirmed from %s and %s", args.backend, labels_a,
             LABELS_C)

    probe = probe_u64(args.host)
    if not probe.reachable:
        log.error("device %s not reachable: %s", args.host, probe.error)
        return 1
    log.info("probe: %s", probe)
    # Build IDENTITY from /v1/info (read-only, pre-lock). Not a gate: the
    # chunked send path's $8E is the behavioural check — see u64_firmware.
    log_build(args.host, log)

    lock = DeviceLock(args.host)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        log.error("DeviceLock acquire failed: %s", e)
        return 77

    results: dict = {"seed": seed}
    turbo_restored = False
    reu_restored = False
    client = None
    try:
        client = Ultimate64Client(host=args.host, timeout=30.0)
        tr = Ultimate64Transport(host=args.host, timeout=30.0, client=client)

        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner wedged: %s — recovering", exc)
            recover(client)
            runner_health_check(client)

        if args.backend == "uci":
            if not get_uci_enabled(client):
                enable_uci(client)
                time.sleep(0.5)

        set_reu(client, False)
        log.warning("REU DETACHED (REU=0 build)")
        time.sleep(0.5)
        if args.backend == "uci":
            set_turbo_mhz(client, args.turbo)
            time.sleep(3.0)  # settle
            actual = get_turbo_mhz(client)
            if actual != args.turbo:
                log.error("turbo did not stick: requested %d, device reports %d",
                          args.turbo, actual)
                return 1
            log.info("turbo confirmed stuck at %d MHz", actual)
        else:
            # ip65: NOT here. DHCP must run at 1 MHz; each stage raises the
            # clock itself once net_initialized reads 1 (_net_init_ip65).
            log.info("ip65: turbo %d MHz deferred until after net_initialized",
                     args.turbo)

        # --- Stage A/B --- (L_A was loaded + backend-checked above)
        ab = run_stage_ab(tr, client, L_A, c64_priv, c64_pub, resp_pub, seed,
                          backend=args.backend, turbo_mhz=args.turbo,
                          prg_path=prg_a)
        results["stage_ab"] = ab

        # --- Stage R: rekey (issue #87) ---
        if args.rekey > 0:
            rekey_result: dict = {"stage": "rekey",
                                  "rekey_expected_red_on_unfixed": True,
                                  "attempts": []}
            results["stage_rekey"] = rekey_result
            if not ab.get("active"):
                rekey_result["skipped"] = "stage A/B did not reach ACTIVE"
                log.warning("skipping rekey stage: Stage A/B never reached "
                          "ACTIVE")
            else:
                initial_ts = bytes(tr.read_memory(L_A["hs_timestamp"], 12))
                try:
                    run_stage_rekey(tr, L_A, args.rekey, initial_ts,
                                    rekey_result)
                except AssertionError as exc:
                    import json as _json
                    log.error(
                        "rekey stage FAILED (issue #87; expected on "
                        "unfixed firmware against Cloudflare WARP): %s\n"
                        "RESULTS SO FAR:\n%s", exc,
                        _json.dumps(results, indent=2, default=str))
                    raise

        # --- Stage C ---
        c = run_stage_c(tr, client, L_C, c64_priv, c64_pub, resp_pub, seed,
                        backend=args.backend, turbo_mhz=args.turbo,
                        multipart=args.multipart)
        results["stage_c"] = c

    finally:
        # Stage D: restore 1 MHz / REU off, asserted by read-back. In
        # `finally` (not after the try body) so a raise anywhere above —
        # notably Stage R's assertions, which are expected to raise on
        # unfixed firmware (issue #87) — still leaves the device restored
        # for whoever has it next.
        if client is not None:
            try:
                set_turbo_mhz(client, 1)
                time.sleep(1.0)
                actual1 = get_turbo_mhz(client)
                turbo_restored = (actual1 == 1)
                set_reu(client, False)
                reu_restored = True
                log.info("restore: turbo=%d MHz (restored=%s) REU off",
                        actual1, turbo_restored)
            except Exception as exc:                              # noqa: BLE001
                log.error("Stage D restore failed: %s", exc)
        lock.release()
        log.info("lock released")

    import json
    log.info("RESULTS:\n%s", json.dumps(results, indent=2, default=str))
    failed = stage_errors(results)
    if failed:
        log.error("FAILED: %s", "; ".join(failed))
        return 1
    return 0


def stage_errors(results: dict) -> list[str]:
    """Every 'error'/'ping_error' any stage recorded, as 'stage: text'.

    main() keeps running the remaining stages after a failure (Stage C is
    a fresh run_prg and still informative when Stage A never went ACTIVE)
    but must not exit 0 with the failure buried in RESULTS.
    """
    out = []
    for key, stage in results.items():
        if not isinstance(stage, dict):
            continue
        for k in ("error", "ping_error"):
            if stage.get(k):
                out.append(f"{key}: {stage[k]}")
    return out


if __name__ == "__main__":
    sys.exit(main())
