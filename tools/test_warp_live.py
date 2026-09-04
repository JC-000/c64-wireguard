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

INSTRUMENT (issue #128 — read this before trusting a Stage C number):
  The first #128 result ("inbound replies of 1049-1187 B always fail AEAD,
  9/9") was RETRACTED as an instrument artefact, and every item below is a
  named defect that produced it.  What Stage C records per query now:

    * receive state is CLEARED before every send — msg_recv_len,
      tp_payload_len, tp_packet_len and udp_recv_len zeroed, udp_recv_buf
      POISONED — and the whole thing is VERIFIED by read-back
      (`recv_state_fresh`).  Before this, only the first two were cleared,
      so `type4_ok`/`recv_head`/`udp_recv_len` on a failing trial could
      belong to the PREVIOUS datagram or to the handshake.
    * `reject_cause` — WHICH cause fired.  1..5 are transport_decrypt's,
      numbered exactly as src/wg/session.s:449-453 (1 type byte, 2 counter
      byte 7 >= $10, 3 replay/duplicate, 4 udp_recv_len < 32, 5 Poly1305
      tag); 6 and 7 are host-side buckets for "the datagram never reached
      transport_decrypt" and "it never reached @replay_ok", which have to
      be excluded before 5 can be called a residual at all.
      `decrypt_failed` is that structural verdict, not a screen scrape.
    * `observed_reply_len` / `observed_datagram_len` — what actually
      ARRIVED, recorded on failures too, never falling back to the table
      constant; `size_mismatch` compares it with `expected_reply_len`.
    * `block_forensics.poison_stop` — how far the firmware actually WROTE.
      udp_recv_buf is pre-filled with a position-dependent pattern, so the
      first offset from which it still matches is the copy stop: 893 means
      the second UCI response block never landed, udp_recv_len means every
      announced byte is this cycle's.  A truncated multi-block read copies
      the Poly1305 tag out of the middle of the ciphertext
      (src/wg/transport.s:562-573) and is otherwise indistinguishable from a
      real tag mismatch, so without this `reject_cause` 5 is not a residual.
      Diffing against the previous capture cannot do it alone: byte i of
      that buffer holds whatever the last datagram to REACH offset i wrote,
      which after one long early datagram is coherent old ciphertext, not
      zeros.
    * `host_aead_check` — on every reject, the peer's AEAD is re-run ON THE
      HOST over the bytes the C64 holds.  Verifies => the buffer is intact
      and the device rejected something it should have accepted; fails =>
      the bytes are wrong and `poison_stop` says where they stopped.  The
      session receive key is read for this, used in memory and never
      stored, logged or returned.
    * `keepalive_in_window` / `tp_send_counter_delta` — the 10 s keepalive
      (src/wg/timer.s:186-200) zeroes tp_payload_len and sends an empty
      Type 4, and it fires inside the receive window of any query that does
      NOT answer quickly.  So it contaminates only the failures, which
      manufactures a difference between them and the successes.  Any query
      where the counter moved by more than this tool's own one send has its
      tp_payload_len marked untrustworthy, and bucket 7 is suppressed.
    * `wg_state` before AND after every query, plus seconds since the
      handshake and the 120 s/180 s boundaries as booleans.
      session_handle_packet's @type4 gates on SESSION_ACTIVE and returns
      SILENTLY otherwise (src/wg/session.s:332-336), so a session that
      expires mid-sweep drops inbound Type 4s with no message and no
      counter — indistinguishable from a decrypt failure unless wg_state is
      sampled, which it never was.
    * `screen_anchor_ok` — the screen is read only AFTER a per-query random
      anchor stamped into screen RAM.  When the anchor is gone (the query
      scrolled >= 25 rows) the query is NOT scored from the screen: it is
      logged at ERROR and listed in `unscored_queries`.  The old
      `screen.split("MSG>")[-1]` fell back to the WHOLE screen when the
      marker had scrolled off, which scored stale text from earlier queries.
    * the size ladder is SHUFFLED under the run's logged seed and the small
      control is re-run at three separated rungs, so reply size is no longer
      rank-correlated with elapsed time, tp_send_counter, replay-window
      state or a resolver rate limiter.  `tp_send_counter` and
      `rw_counter_max` are recorded per query as the covariates.

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
    DeviceLock, DeviceLockTimeout, Labels, ScreenGrid, dump_screen, enable_uci,
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

# Inbound sizes to sweep, as (name, measured reply size). EDNS bufsize does
# NOT work as a size knob: a resolver answers a query it cannot fit with a
# 42-byte TC=1 stub, so sweeping bufsize sweeps nothing (measured — every
# size from 400 to 1200 returned 42 bytes). Real names with known TXT reply
# sizes do work. Sizes measured host-side against 1.1.1.1 on 2026-09-04 and
# may drift as those records change. These numbers are the EXPECTATION, not
# the measurement: each query records `observed_reply_len` (what actually
# arrived, on failures too) and `size_mismatch` (True iff both are known and
# disagree, logged at ERROR). Until 2026-09-04 nothing compared the two — the
# expectation was logged and stored and never checked — which is why #128's
# band edges were assumptions about sizes that had never been measured on a
# failing trial.
#
# The ladder deliberately brackets 893 — the first SOCKET_READ block payload,
# hence where multi-block reassembly begins.
REPLY_SWEEP_NAMES = (
    ("github.com", 39),        # single block, known good
    ("facebook.com", 476),     # single block
    ("slack.com", 948),        # FIRST size above the 893-byte block boundary
    ("bitbucket.org", 1049),
    ("paypal.com", 1131),
    ("google.com", 1187),
    ("namecheap.com", 1278),   # the size that fails ~55% of the time
)

# Each rung is sent this many times. The inbound path is INTERMITTENT here
# (a 1278 B reply failed to decrypt in 2 of 4 runs on 2026-09-03, and the
# 800 B control answered in 1 of 2), so a single observation distinguishes
# nothing: what is wanted is a RATE per rung, not an anecdote.
MULTIPART_REPEATS = 3

# The SMALL control rung, re-run at several SEPARATED positions in the
# shuffled ladder (issue #128 item 7). One 476 B reply at rung 2 could not
# separate "small replies are fine" from "early queries are fine": the sweep
# ran strictly ascending, so size was rank-correlated with elapsed time,
# tp_send_counter, replay-window state and session age. Rungs are 1-based
# positions in the EXECUTED ladder.
SWEEP_CONTROL = ("facebook.com", 476)
SWEEP_CONTROL_RUNGS = (1, 4, 8)

BACKENDS = ("uci", "ip65")

# =============================================================================
# Instrument constants (issue #128)
# =============================================================================
# transport_decrypt (src/wg/transport.s:403-786) has ONE failure exit shared
# by five causes, numbered here exactly as src/wg/session.s:449-453 numbers
# them; classify_reject() below reproduces the firmware's checks IN THE SAME
# ORDER, host-side, from state this tool cleared before the send.
#
# 6 and 7 are HOST-SIDE buckets with no firmware counterpart, and they exist
# because "AEAD by elimination" is only a residual if everything that could
# have short-circuited the path is excluded first:
#   6 — session_handle_packet's @type4 gates on wg_state == SESSION_ACTIVE
#       and returns SILENTLY otherwise (src/wg/session.s:332-336). The 180 s
#       expiry in src/wg/timer.s resets to IDLE, so a sweep that outlives a
#       session drops every inbound Type 4 with no message and no counter.
#       udp_recv_len is written by net_poll BEFORE any WireGuard processing,
#       so a non-zero udp_recv_len proves the datagram ARRIVED and nothing
#       more.
#   7 — tp_payload_len is written at @replay_ok (transport.s:511-522) BEFORE
#       the underflow branch and before aead_decrypt. A zero there means
#       execution never reached step 4, which excludes causes 4 AND 5
#       outright. Reporting 5 in that case is the original #128 error in a
#       new place.
REJECT_TYPE_BYTE = 1        # udp_recv_buf[0] != 4
REJECT_COUNTER_LIMIT = 2    # udp_recv_buf[15] >= $10
REJECT_REPLAY = 3           # outside the 2048 window, or bit already set
REJECT_UNDERFLOW = 4        # udp_recv_len < 32
REJECT_AEAD_TAG = 5         # Poly1305 mismatch — the RESIDUAL, by elimination
REJECT_STATE_GATE = 6       # host-only: never reached transport_decrypt
REJECT_UNREACHED_STEP4 = 7  # host-only: reached it, never reached @replay_ok
REJECT_CAUSE_NAMES = {
    REJECT_TYPE_BYTE: "type-byte-not-4",
    REJECT_COUNTER_LIMIT: "counter-byte7-limit",
    REJECT_REPLAY: "replay-window-reject",
    REJECT_UNDERFLOW: "length-underflow",
    REJECT_AEAD_TAG: "aead-tag-residual",
    REJECT_STATE_GATE: "dropped-at-state-gate",
    REJECT_UNREACHED_STEP4: "unreached-transport-decrypt-step4",
}
REJECT_COUNTER_B7 = 0x10        # src/constants.inc:50
REPLAY_WINDOW_BITS = 2048       # rw_bitmap is 256 bytes = 2048 positions
WG_TYPE4 = 4

# The FIRST UCI SOCKET_READ response block's payload. A reply above this
# needs a second block, which is where multi-block reassembly begins — and
# where src/net/uci/net.s:1366 can fall through to @done_data with
# udp_recv_len still holding the ANNOUNCED total over a partially filled
# buffer. Nothing corrects the length, so the caller would see a full-length
# datagram whose tail is whatever the PREVIOUS datagram left there: correct
# udp_recv_len, net_last_error $00, no error flag, contents wrong. That is
# why the forensics below straddle this offset specifically.
UCI_FIRST_BLOCK_PAYLOAD = 893
RECV_BUF_CAP_FALLBACK = 1500
# A run of trailing zeros this long inside the ANNOUNCED datagram is treated
# as fill rather than ciphertext: a well-formed datagram ends in its 16-byte
# Poly1305 tag, so 16 zero bytes there is a 2^-128 coincidence.
ZERO_FILL_MIN_RUN = 16
# Bump when classify_recv_buffer()'s rule changes, so a verdict in an old log
# is never read under a newer rule's meaning.
RECV_FORENSICS_RULE = "provisional-2026-09-04"

# Screen RAM / KERNAL cursor, for the per-query scrape anchor (item 6).
SCREEN_BASE = 0x0400
SCREEN_COLS = 40
SCREEN_ROWS = 25
SCREEN_SIZE = SCREEN_COLS * SCREEN_ROWS
SCREEN_BLANK_CODE = 0x20        # screen code for space
CURSOR_LINE_PTR = 0x00D1        # KERNAL: pointer to the current screen line
CURSOR_COL = 0x00D3             # KERNAL: cursor column within that line
ANCHOR_LEN = 10
DECRYPT_FAIL_TEXT = "DECRYPT FAILED"        # src/wg/strings.s:88
# The two headers the firmware prints IMMEDIATELY BEFORE peer-supplied bytes:
# msg_recv_hdr (src/wg/strings.s:102) from @t4_udp, and recv_data_msg (:90)
# from display_payload. Everything after the first of them in a query's
# window was written by the PEER, through the #129 printable filter, and is
# therefore attacker-chosen text — including, if it likes, "DECRYPT FAILED".
PEER_CONTENT_HEADERS = ("MSG: ", "RECV: ")
SESSION_STATE_MSGS = ("SESSION EXPIRED", "REKEY NEEDED")  # strings.s:113-115
KEEPALIVE_TEXT = "KEEPALIVE"                # src/wg/strings.s:117

# The 10 s keepalive (src/wg/timer.s:186-200) sends an EMPTY Type 4 and, to
# do it, zeroes tp_payload_len, sets tp_packet_len to 32 via
# transport_encrypt, bumps tp_send_counter and prints "KEEPALIVE". A query
# that gets no reply sits in the DNS_TIMEOUT window for longer than that, so
# the keepalive fires INSIDE the measurement window and overwrites exactly
# the fields a failure is diagnosed from — while a query that answers in
# ~1.5 s reads the true values. That asymmetry manufactures a difference
# between failing and succeeding trials out of nothing, so every query
# records the counter delta and any query where it advanced by more than the
# one send this tool made is flagged: tp_payload_len is then the KEEPALIVE's
# zero, not evidence about the reply.
TP_SEND_PER_QUERY = 1

# Receive-state fields ZEROED before EVERY send, with the width to zero.
# udp_recv_buf is not among them: it is POISONED instead — see below.
#
# net_last_error joined this set on 2026-09-04 and it is NOT cosmetic.
# net_poll never zeroes it on a success path — it is written only when
# something fails — so it is a LATCH, not a per-poll reading. Leave it and
# the failure mode is the one this whole branch exists to stamp out: trial N
# short-reads and sets $8F, trial N+1 succeeds and touches nothing, the tool
# reads $8F afterwards and attributes it to N+1. Every "which trial failed"
# conclusion drawn from an uncleared latch is unattributable. Clearing it
# also gives the read a real meaning: a non-zero value AFTER the query was
# necessarily written BY the query.
RECV_STATE_CLEARED = (
    ("msg_recv_len", 2),
    ("tp_payload_len", 2),
    ("tp_packet_len", 2),
    ("udp_recv_len", 2),
    ("net_last_error", 1),
)

# UCI-only diagnostic (src/net/uci/net.s): (UCI_STATUS & $30) | $80 latched
# at net_poll's $8F short-read exit — $A0 Data Last, $80 Idle, $00 never
# written. Same latch problem as net_last_error, so it is cleared and
# verified per query too; absent on ip65 builds, hence the label guard at
# the clear site rather than membership in the tuple above.
SHORT_READ_STATE_LABEL = "uci_short_read_state"
SHORT_READ_STATE_NAMES = {0x80: "IDLE ($00)", 0xA0: "DATA_LAST ($20)"}


def describe_short_read_state(raw):
    """Render uci_short_read_state for a report line.

    $00 is "never written", NOT Idle — the whole point of bit 7. Anything
    else with bit 7 clear predates the self-describing encoding or is a
    stale/garbled read, and is reported as such rather than guessed at.
    """
    if raw is None:
        return None
    if raw == 0x00:
        return "not written"
    if not raw & 0x80:
        return f"UNEXPECTED ${raw:02X} (bit 7 clear)"
    return SHORT_READ_STATE_NAMES.get(raw, f"UNKNOWN ${raw:02X}")

# POISON FILL. udp_recv_buf is filled with a position-dependent pattern
# before every query, so the offset at which the firmware STOPPED writing is
# a single subtraction afterwards:
#
#     stop = min{ i : B[i:] == P[i:] }
#
# Neither zeroing the buffer nor diffing it against the previous query's
# capture can decide this on its own. udp_recv_buf is zero-filled at load,
# but thereafter byte i holds whatever the most recent datagram that REACHED
# offset i wrote — so after one long datagram early in a run, a later
# truncated read leaves coherent-looking mid-ciphertext from that older,
# longer packet in the gap. Not zeros, and not the immediately preceding
# packet either. A stale tail and a fresh tail are both just bytes.
#
# The pattern makes them separable: a byte matching the poison by accident
# is 1-in-256, and the stop test requires EVERY remaining byte to match, so
# a false "stopped here" is ~2^-8 per byte of tail.
# The pattern is the 1541ultimate lane's, adopted verbatim from
# tests/e2e/io/command_interface/net_target_test.py (`pattern()` /
# `run_offset()`): P[i] = (i + seed) % 251. 251 is prime and below 256, so a
# run of surviving bytes FIXES the offset it started at for any payload
# shorter than 251*251 — "wrong data" becomes "wrong data starting at offset
# N", which is the number this whole run hinges on. The old
# (i * $9D + $5A) & $FF was equally uniform but not self-locating.
POISON_MOD = 251
POISON_SEED = 0x5A
# A tail is only accepted as "the firmware stopped here" when at least this
# many consecutive bytes survived. One coincidental byte at the very end
# used to read a FULL write as `partial-write-stopped-at-(len-1)` with
# probability 1/256 per rejected trial (~9% over a 24-rung run), and it
# pointed in the worst possible direction: it manufactured "truncated".
# Requiring a run makes a false stop (1/251)^16 ~ 1e-38.
#
# The trade-off, stated because it is real: a genuine truncation SHORTER
# than this is now reported as a full write. A block-boundary truncation is
# hundreds of bytes, so this costs nothing we are looking for.
POISON_MIN_RUN = 16

# OPTIONAL device-side cause byte. No build has it today and this tool does
# not require one — reject_cause is derived host-side precisely so that no
# .s change is needed — but a build that exports `tp_reject_cause` is read
# here for nothing, and gives the host derivation an independent check.
# POISONED, not zeroed: 0 is the firmware's SUCCESS code, so a zero read
# back could not be told from "transport_decrypt never ran this trial".
DEVICE_CAUSE_LABEL = "tp_reject_cause"
DEVICE_CAUSE_POISON = 0xAA
# Every failing size observed so far (1008, 1109, 1191, 1247, 1338) is two
# UCI response blocks, so there is ONE expected truncation offset for all of
# them rather than a per-size value.
EXPECTED_TRUNCATION_STOP = UCI_FIRST_BLOCK_PAYLOAD


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
                  timeout: float = 30.0, anchor: Optional[str] = None,
                  anchor_out: Optional[dict] = None) -> bool:
    """Like wg_c64_input.send_message_dma but stages RAW bytes (no ASCII
    upper()/encode() transform), for binary DNS wire data.

    *anchor*, when given, is stamped into screen RAM by
    :func:`place_screen_anchor` in the one window where it is safe and
    meaningful — after 'M' has printed its prompt and the payload is staged,
    but before RETURN is pressed, so every character the C64 prints for this
    exchange lands after it. The report (token, row, whether it was placed,
    the pre-blank screen text) is merged into *anchor_out*.

    A failure to place the anchor does NOT abort the send: the query still
    runs and is still classified structurally. It is recorded as
    ``placed: False`` so the caller refuses to SCORE it from the screen —
    silently scoring an unanchored screen is the defect being fixed.
    """
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
    if anchor is not None:
        report: dict = {"token": anchor, "placed": False}
        try:
            report.update(place_screen_anchor(tr, anchor))
            report["placed"] = True
        except Exception as exc:                              # noqa: BLE001
            report["error"] = repr(exc)
            log.error("screen anchor %s could NOT be placed (%r) — this "
                      "query will not be scored from the screen",
                      anchor, exc)
        if anchor_out is not None:
            anchor_out.update(report)
    return ki.press_key(tr, "\r", timeout)


# =============================================================================
# Instrument (issue #128): receive-state hygiene, reject-cause
# discrimination, block forensics, and an ANCHORED screen scrape.
#
# Everything here exists because the retracted #128 result
# ("1049-1187 B always fail AEAD, 9/9") was produced by an instrument that
# could not tell five reject causes apart, never measured the size of a
# failing trial, scraped a screen the failure itself had scrambled, and ran
# its sizes in ascending order. Each helper below closes one of those.
# =============================================================================
# src/wg/timer.s: REKEY_JIFFIES = 7200 and EXPIRE_JIFFIES = 10800 at 60 Hz.
# Expiry calls session_reset -> IDLE, after which session_handle_packet's
# @type4 drops every inbound Type 4 silently. Recorded per query so those
# boundaries are visible in the output without the reader doing arithmetic.
# NOTE the direction of the inequality: the jiffy clock stops advancing while
# IRQs are masked (long crypto), so wall-clock elapsed is an UPPER bound on
# what the device counted. Crossing these is NECESSARY for an expiry, not
# sufficient — which is why wg_state itself is sampled, not inferred.
WG_REKEY_SECONDS = 120
WG_EXPIRE_SECONDS = 180


class AnchorError(RuntimeError):
    """The per-query screen anchor is not on the screen exactly once, so
    nothing read from that screen can be attributed to this query."""


def _new_anchor_token(n: int = ANCHOR_LEN) -> str:
    """A fresh uppercase token, drawn from the run's SEEDED random stream so
    a --seed replay stamps the same anchors in the same order."""
    return "".join(random.choice(string.ascii_uppercase) for _ in range(n))


def _anchor_screen_codes(token: str) -> bytes:
    """PETSCII SCREEN codes for *token* (not PETSCII, not ASCII): 'A'-'Z' are
    $01-$1A and '0'-'9' are $30-$39 in the uppercase character set."""
    out = bytearray()
    for ch in token:
        if "A" <= ch <= "Z":
            out.append(ord(ch) - ord("A") + 1)
        elif "0" <= ch <= "9":
            out.append(ord(ch))
        else:
            raise ValueError(f"anchor token {token!r} contains {ch!r}, which "
                             f"is not A-Z or 0-9")
    return bytes(out)


def place_screen_anchor(tr: Ultimate64Transport, token: str) -> dict:
    """Blank the screen and stamp *token* at the start of the cursor's row.

    Why not the old ``screen.split("MSG>")[-1]``:

    * ``"MSG> "`` (src/wg/strings.s:101) is the INPUT PROMPT and ``"MSG: "``
      (:103) is the per-reply header — different strings, and the scrape
      keyed on the prompt, which is a whole-query window, not a per-reply
      one.
    * ``str.split`` returns the WHOLE string when the separator is absent,
      so a query whose own output scrolled its prompt off the 25-row screen
      silently fell back to scoring every earlier query's text as well. The
      #129 filter did not change that: ~1187 now-guaranteed-printable
      characters still scroll ~30 rows.
    * peer bytes reach the screen, so a DNS TXT record containing the
      literal text "DECRYPT FAILED" is a clean false positive against any
      whole-screen search.

    The blank is what removes stale text; the token is what proves the
    window read back is THIS query's. It is placed at the cursor's own row
    (not row 0) because the cursor is usually near the bottom and row 0
    would scroll away on the first newline, and the cursor column is pushed
    past it so the C64's next character lands after the token rather than
    over it. Both are safe here: the row was just blanked, and the program
    is parked in read_input_line's GETIN loop printing nothing.

    :raises AnchorError: when the KERNAL cursor pointer is not a valid
        screen-RAM row start, i.e. when the anchor cannot be trusted to be
        where this function claims. The caller must then refuse to score.
    """
    codes = _anchor_screen_codes(token)
    if len(codes) >= SCREEN_COLS:
        raise AnchorError(f"anchor {token!r} does not fit in a "
                          f"{SCREEN_COLS}-column row")
    grid = ScreenGrid.from_transport(tr)
    before = grid.continuous_text()
    tr.write_memory(SCREEN_BASE, bytes([SCREEN_BLANK_CODE]) * SCREEN_SIZE)
    line = int.from_bytes(bytes(tr.read_memory(CURSOR_LINE_PTR, 2)), "little")
    col = bytes(tr.read_memory(CURSOR_COL, 1))[0]
    off = line - SCREEN_BASE
    if not (0 <= off < SCREEN_SIZE) or off % SCREEN_COLS:
        raise AnchorError(
            f"KERNAL cursor line pointer $D1/$D2 = ${line:04X} is not the "
            f"start of a row in screen RAM ${SCREEN_BASE:04X}.."
            f"${SCREEN_BASE + SCREEN_SIZE - 1:04X}; the anchor cannot be "
            f"placed where this query's output will follow it")
    tr.write_memory(line, codes)
    tr.write_memory(CURSOR_COL, bytes([len(codes)]))
    return {"row": off // SCREEN_COLS, "cursor_col_before": col,
            "screen_before": before}


def read_after_anchor(tr: Ultimate64Transport, token: str) -> tuple:
    """``(text_after_anchor, whole_screen)`` — or raise.

    Reads the screen as ONE wrap-free string (``continuous_text``), so a
    message split across a 40-column boundary is still found; the old code
    searched ``dump_screen``'s row-numbered output, in which a wrapped
    "DECRYPT FAILED" cannot match at all.

    :raises AnchorError: when the token is absent (this query printed 25+
        rows and scrolled it away, or the anchor never landed) or present
        more than once. Either way the window is not this query's, and the
        caller MUST record the query as unscored rather than fall back to
        the whole screen — that fallback is the #128 false-positive path.
    """
    grid = ScreenGrid.from_transport(tr)
    ct = grid.continuous_text()
    idx = ct.find(token)
    if idx < 0:
        raise AnchorError(
            f"screen anchor {token!r} is NOT on the screen: this query's "
            f"output scrolled it away (>= {SCREEN_ROWS} rows) or it was "
            f"never stamped, so no text on this screen can be attributed "
            f"to this query")
    if ct.find(token, idx + 1) >= 0:
        raise AnchorError(f"screen anchor {token!r} appears more than once; "
                          f"the window after it is ambiguous")
    return ct[idx + len(token):], ct


def _recv_buf_capacity(L: dict) -> int:
    """How many bytes udp_recv_buf holds, read STRUCTURALLY from the labels
    (udp_recv_len is the field immediately after it) rather than assumed."""
    span = 0
    try:
        span = int(L["udp_recv_len"]) - int(L["udp_recv_buf"])
    except Exception:                                         # noqa: BLE001
        span = 0
    if 512 <= span <= 4096:
        return span
    log.warning("udp_recv_buf capacity not derivable from the labels "
                "(span=%d); falling back to %d", span, RECV_BUF_CAP_FALLBACK)
    return RECV_BUF_CAP_FALLBACK


def poison_pattern(n: int, seed: int = POISON_SEED) -> bytes:
    """``P[i] = (i + seed) % 251`` — the fill whose survival marks bytes the
    firmware did not write this cycle, and which identifies its own offset.

    From GideonZ/1541ultimate `tests/e2e/io/command_interface/net_target_test.py`
    (`pattern()`), adopted so both lanes read the same bytes the same way.
    """
    return bytes((i + seed) % POISON_MOD for i in range(n))


def poison_run_offset(chunk: bytes, seed: int = POISON_SEED) -> Optional[int]:
    """Where *chunk* started inside :func:`poison_pattern`, or None.

    The counterpart of the firmware lane's `run_offset()`. A surviving run
    that reports an offset OTHER than where it was found means the buffer
    holds poison from a different position — i.e. something moved bytes, not
    merely failed to write them.
    """
    if not chunk:
        return None
    start = (chunk[0] - seed) % POISON_MOD
    for index, byte in enumerate(chunk):
        if byte != (start + seed + index) % POISON_MOD:
            return None
    return start


def poison_stop(buf: bytes, pattern: bytes) -> int:
    """``min{ i : buf[i:] == pattern[i:] }`` — how far the firmware wrote.

    0 means nothing arrived; udp_recv_len means the whole announced
    datagram was written this cycle, so a tag mismatch on it is GENUINE; a
    value at a response-block boundary means the copy stopped there, i.e.
    the next block never landed.

    This is the raw scan and it has no tolerance of its own. The tolerance
    lives in :func:`classify_recv_buffer`, because it can only be applied
    where the ANNOUNCED length is known: udp_recv_buf is poisoned to its
    full capacity, so the surviving tail of a perfectly full write already
    runs from ``udp_len`` to the end of the buffer, and one coincidental
    byte merely extends that run by one. A tail-length rule here cannot see
    the difference; a rule on ``udp_len - stop`` can.
    """
    n = min(len(buf), len(pattern))
    i = n
    while i > 0 and buf[i - 1] == pattern[i - 1]:
        i -= 1
    return i


def verify_poly1305_host(buf: bytes, udp_len: int,
                         recv_key: Optional[bytes]) -> dict:
    """Re-run the peer's AEAD on the host over the bytes the C64 holds.

    This is what splits the last two candidates apart:
      * tag VERIFIES here  -> the buffer is intact, so the reject came from
        the on-device AEAD, not from the bytes.
      * tag FAILS here     -> the bytes are wrong, and the poison stop says
        where they stopped being written.

    *recv_key* is the session's receive key. It is used in memory and never
    returned, logged or stored — the result carries a verdict only. Callers
    must not put it anywhere either.
    """
    out: dict = {"checked": False}
    if recv_key is None or len(recv_key) != 32:
        out["verdict"] = "not-checkable (no receive key)"
        return out
    if udp_len < 32 or udp_len > len(buf):
        out["verdict"] = "not-checkable (length out of range)"
        return out
    try:
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305,
        )
    except Exception as exc:                                  # noqa: BLE001
        out["verdict"] = "not-checkable (no cryptography module: %r)" % exc
        return out
    nonce = b"\x00\x00\x00\x00" + bytes(buf[8:16])
    body = bytes(buf[16:udp_len])          # ciphertext || 16-byte tag
    out["checked"] = True
    out["nonce_counter"] = int.from_bytes(buf[8:16], "little")
    try:
        pt = ChaCha20Poly1305(recv_key).decrypt(nonce, body, b"")
    except Exception:                                         # noqa: BLE001
        out["tag_verifies"] = False
        out["verdict"] = ("tag FAILS host-side: the bytes in udp_recv_buf "
                          "are not what the peer sent")
        return out
    out["tag_verifies"] = True
    out["plaintext_len"] = len(pt)
    out["verdict"] = ("tag VERIFIES host-side: the buffer is intact, so the "
                      "device rejected a datagram it should have accepted")
    return out


def _clear_recv_state(tr: Ultimate64Transport, L: dict,
                      poison: Optional[bytes] = None) -> tuple:
    """Zero every receive-state field this tool later reads, and VERIFY it.

    Returns ``(all_verified, per-field detail)``. Until 2026-09-04 only
    msg_recv_len and tp_payload_len were cleared, so udp_recv_len,
    udp_recv_buf's header and tp_packet_len read back after a failing trial
    could belong to the PREVIOUS datagram or to the handshake — which is
    what made ``type4_ok`` and ``recv_head`` unattributable, and what makes
    the reject-cause discrimination possible now that it is fixed.

    Clearing tp_packet_len is safe on the send path: transport_encrypt
    writes it (transport.s:368-375) before transport_send reads it.

    udp_recv_buf is POISONED rather than zeroed when *poison* is given: a
    zeroed buffer cannot tell a byte the firmware wrote from one it did not,
    because zero is a perfectly ordinary ciphertext byte, while the poison
    pattern makes the copy stop readable directly. The read-back is a full
    comparison, not a spot check, so ``recv_state_fresh`` is a measurement.
    """
    detail: dict = {}
    ok = True
    for name, width in RECV_STATE_CLEARED:
        try:
            tr.write_memory(L[name], bytes(width))
            back = bytes(tr.read_memory(L[name], width))
            detail[name] = (back == bytes(width))
        except Exception as exc:                              # noqa: BLE001
            detail[name] = repr(exc)
        ok = ok and detail[name] is True
    if poison is not None:
        try:
            tr.write_memory(L["udp_recv_buf"], poison)
            back = bytes(tr.read_memory(L["udp_recv_buf"], len(poison)))
            detail["udp_recv_buf_poison"] = (back == poison)
        except Exception as exc:                              # noqa: BLE001
            detail["udp_recv_buf_poison"] = repr(exc)
        ok = ok and detail["udp_recv_buf_poison"] is True
    if SHORT_READ_STATE_LABEL in L:
        try:
            tr.write_memory(L[SHORT_READ_STATE_LABEL], b"\x00")
            detail[SHORT_READ_STATE_LABEL] = (
                bytes(tr.read_memory(L[SHORT_READ_STATE_LABEL], 1)) == b"\x00")
        except Exception as exc:                              # noqa: BLE001
            detail[SHORT_READ_STATE_LABEL] = repr(exc)
        ok = ok and detail[SHORT_READ_STATE_LABEL] is True
    if DEVICE_CAUSE_LABEL in L:
        try:
            tr.write_memory(L[DEVICE_CAUSE_LABEL],
                            bytes([DEVICE_CAUSE_POISON]))
            detail[DEVICE_CAUSE_LABEL] = (
                bytes(tr.read_memory(L[DEVICE_CAUSE_LABEL], 1))[0]
                == DEVICE_CAUSE_POISON)
        except Exception as exc:                              # noqa: BLE001
            detail[DEVICE_CAUSE_LABEL] = repr(exc)
        ok = ok and detail[DEVICE_CAUSE_LABEL] is True
    return ok, detail


def _read_session_state(tr: Ultimate64Transport, L: dict) -> dict:
    """wg_state / rekey_pending / tp_send_counter / replay window, in one go.

    Read BEFORE the send as well as after: wg_state can change mid-query
    (the 180 s expiry, a rekey), and rw_counter_max/rw_bitmap must be the
    window as it stood when the datagram was processed — a successful
    decrypt advances both, so reading them only afterwards measures the
    wrong thing.

    udp_recv_ready is READ here and deliberately NOT in RECV_STATE_CLEARED:
    zeroing it would discard a datagram the C64 had already staged and not
    yet consumed, which is a change to what the device does rather than a
    measurement of it.
    """
    out: dict = {}
    fields = [("wg_state", 1), ("rekey_pending", 1), ("udp_recv_ready", 1),
              ("tp_send_counter", 2), ("net_last_error", 1)]
    # UCI-only: the STATE that produced a $8F. Appended rather than made
    # unconditional so an ip65 run does not record a spurious read error for
    # a label that backend never exports.
    if SHORT_READ_STATE_LABEL in L:
        fields.append((SHORT_READ_STATE_LABEL, 1))
    for name, width in fields:
        try:
            out[name] = int.from_bytes(bytes(tr.read_memory(L[name], width)),
                                       "little")
        except Exception as exc:                              # noqa: BLE001
            out[name] = None
            out[name + "_error"] = repr(exc)
    try:
        out["rw_counter_max"] = int.from_bytes(
            bytes(tr.read_memory(L["rw_counter_max"], 8)), "little")
        out["rw_bitmap"] = bytes(tr.read_memory(L["rw_bitmap"], 256))
    except Exception as exc:                                  # noqa: BLE001
        out["rw_counter_max"] = None
        out["rw_bitmap"] = None
        out["rw_probe_error"] = repr(exc)
    return out


def classify_reject(head: bytes, udp_len: Optional[int], msg_recv_len: int,
                    tp_packet_len: Optional[int],
                    tp_payload_len: Optional[int],
                    wg_state_before: Optional[int],
                    wg_state_after: Optional[int],
                    rw_counter_max: Optional[int],
                    rw_bitmap: Optional[bytes],
                    keepalive_suspected: bool = False,
                    poison_head: bytes = bytes(16),
                    rw_counter_max_before: Optional[int] = None,
                    rw_counter_max_after: Optional[int] = None) -> tuple:
    """Which reject cause fired, host-side, with NO device code change.

    Returns ``(cause, name, detail)`` with *cause* one of the REJECT_*
    constants or ``None``. The five firmware causes are evaluated in the
    order transport.s evaluates them, because the firmware stops at the
    first one that fires and so must this:

      1  udp_recv_buf[0] != 4                      transport.s:405-409
      2  udp_recv_buf[15] >= $10                   transport.s:421-425
      3  replay window / duplicate bit             transport.s:427-505
      4  udp_recv_len < 32                         transport.s:507-521
      5  Poly1305 tag mismatch                     transport.s:600-604

    Cause 5 is the RESIDUAL, and a residual is only sound once everything
    that could short-circuit the path is excluded — hence the two host-side
    buckets that precede it:

      6  wg_state was not SESSION_ACTIVE, or tp_packet_len stayed 0 while a
         datagram had arrived. @type4 gates on ACTIVE and returns silently
         (session.s:332-336), and tp_packet_len is written from udp_recv_len
         immediately AFTER that gate and immediately BEFORE the jsr, so
         zero-with-a-datagram means transport_decrypt was never called.
      7  tp_payload_len stayed 0 (or disagrees with udp_recv_len - 32) with
         causes 1-3 all passing. tp_payload_len is written at @replay_ok
         BEFORE the underflow branch and before aead_decrypt, so zero there
         would exclude causes 4 and 5 outright — BUT ONLY IF the field is
         this query's. The 10 s keepalive zeroes tp_payload_len itself, and
         it fires inside the receive window of any query that does not
         answer quickly, so *keepalive_suspected* (tp_send_counter advanced
         by more than this tool's own send) SUPPRESSES bucket 7 entirely.
         Reading a keepalive's zero as "the decrypt never ran" is the same
         class of error as reading a scraped screen as "AEAD failed".

    Both are why this function may NOT simply report 5 for "arrived, no
    message, nothing else matched": that is exactly the inference #128 was
    retracted for.

    *rw_counter_max* / *rw_bitmap* must be the PRE-send values.
    """
    detail: dict = {
        "udp_recv_len": udp_len, "tp_packet_len": tp_packet_len,
        "tp_payload_len": tp_payload_len, "msg_recv_len": msg_recv_len,
        "wg_state_before": wg_state_before, "wg_state_after": wg_state_after,
    }
    # "arrived" means the receive path wrote something this cycle. With the
    # buffer poisoned rather than zeroed, that is "the header differs from
    # the poison", not "the header is non-zero".
    arrived = bool(udp_len) or bytes(head[:16]) != bytes(poison_head[:16])
    detail["arrived"] = arrived
    if not arrived:
        return None, "no-datagram-arrived", detail
    if msg_recv_len:
        return None, "accepted", detail

    # ACCEPTED BUT NOT A TUNNEL REPLY, and therefore NOT a reject at all.
    #
    # transport_decrypt advances the replay window ONLY on its success path:
    # @advance_done and @just_set_bit (transport.s) are reached after
    # aead_decrypt returns 0, and NO reject path reaches either. So a window
    # that moved across this query is proof the decrypt SUCCEEDED — even
    # though msg_recv_len is zero, which happens whenever udp_tunnel_parse
    # does not match and session.s falls through to display_payload
    # (session.s:392-393, :439): a peer keepalive, an ICMP echo request, a
    # reply on an unexpected port.
    #
    # Without this the datagram falls all the way through causes 1-4 and is
    # reported as the cause-5 residual — i.e. as a Poly1305 tag mismatch.
    # That is EXACTLY the inference #128 was retracted for, rebuilt in the
    # structural derivation, and it would have fired on the very run meant
    # to settle the question. The residual is only sound once everything
    # that can produce "arrived, no message" without a reject is excluded,
    # and this was the missing one.
    if (rw_counter_max_before is not None and rw_counter_max_after is not None
            and rw_counter_max_after > rw_counter_max_before):
        detail["rw_counter_max_advanced"] = [rw_counter_max_before,
                                             rw_counter_max_after]
        return None, "accepted-not-a-tunnel-reply", detail

    # 6 — did the datagram even reach transport_decrypt? This TAKES
    # PRECEDENCE over all five firmware causes, deliberately: none of them
    # ran if @type4's gate returned first, so attributing the query to any
    # of them (5 above all) would be the retracted #128 inference again.
    detail["type_byte"] = head[0]
    state_gate = []
    if wg_state_before is not None and wg_state_before != SESSION_ACTIVE:
        state_gate.append(f"wg_state was {wg_state_before} before the query")
    if wg_state_after is not None and wg_state_after != SESSION_ACTIVE:
        state_gate.append(f"wg_state was {wg_state_after} after the query")
    if tp_packet_len == 0:
        # A keepalive inside the window would have set this to 32, not 0, so
        # a zero here is still "the receive path never wrote it". wg_state
        # remains the primary evidence; this is the corroboration.
        state_gate.append("tp_packet_len stayed 0 although a datagram arrived")
    if state_gate:
        detail["state_gate_evidence"] = state_gate
        return (REJECT_STATE_GATE, REJECT_CAUSE_NAMES[REJECT_STATE_GATE],
                detail)

    # 1 — the type byte.
    if head[0] != WG_TYPE4:
        return REJECT_TYPE_BYTE, REJECT_CAUSE_NAMES[REJECT_TYPE_BYTE], detail

    # 2 — counter byte 7 limit.
    counter = int.from_bytes(head[8:16], "little")
    detail["recv_counter"] = counter
    if head[15] >= REJECT_COUNTER_B7:
        return (REJECT_COUNTER_LIMIT, REJECT_CAUSE_NAMES[REJECT_COUNTER_LIMIT],
                detail)

    # 3 — sliding window, reproducing transport.s:427-505 exactly.
    if rw_counter_max is None or rw_bitmap is None:
        detail["replay"] = "not evaluated (pre-send window unavailable)"
    else:
        detail["rw_counter_max"] = rw_counter_max
        if counter > rw_counter_max:
            detail["replay"] = "new-high-counter"
        elif (rw_counter_max >> 16) != (counter >> 16):
            detail["replay"] = "high-bytes-differ -> delta >= 65536"
            return REJECT_REPLAY, REJECT_CAUSE_NAMES[REJECT_REPLAY], detail
        else:
            delta = (rw_counter_max - counter) & 0xFFFF
            detail["replay_delta"] = delta
            if counter < rw_counter_max and delta >= REPLAY_WINDOW_BITS:
                detail["replay"] = "outside the 2048-counter window"
                return REJECT_REPLAY, REJECT_CAUSE_NAMES[REJECT_REPLAY], detail
            idx = counter & 0x7FF
            byte_off, bit = idx >> 3, idx & 7
            detail["bitmap_byte"] = byte_off
            detail["bitmap_bit"] = bit
            if byte_off < len(rw_bitmap) and (rw_bitmap[byte_off] >> bit) & 1:
                detail["replay"] = "duplicate: bitmap bit already set"
                return REJECT_REPLAY, REJECT_CAUSE_NAMES[REJECT_REPLAY], detail
            detail["replay"] = "inside the window, bit clear"

    # 4 — underflow.
    if udp_len is not None and udp_len < 32:
        return (REJECT_UNDERFLOW, REJECT_CAUSE_NAMES[REJECT_UNDERFLOW],
                detail)

    # 7 — did execution reach step 4 at all? Only askable when the field is
    # uncontaminated: see the docstring, and TP_SEND_PER_QUERY.
    detail["keepalive_suspected"] = keepalive_suspected
    if (tp_payload_len is not None and udp_len is not None
            and not keepalive_suspected):
        expected_payload = (udp_len - 32) & 0xFFFF
        detail["expected_tp_payload_len"] = expected_payload
        if tp_payload_len != expected_payload:
            detail["step4_evidence"] = (
                f"tp_payload_len is {tp_payload_len}, not udp_recv_len - 32 "
                f"({expected_payload}); @replay_ok never ran, so causes 4 "
                f"and 5 are both excluded")
            return (REJECT_UNREACHED_STEP4,
                    REJECT_CAUSE_NAMES[REJECT_UNREACHED_STEP4], detail)

    # 5 — the residual, and only now.
    return REJECT_AEAD_TAG, REJECT_CAUSE_NAMES[REJECT_AEAD_TAG], detail


def classify_recv_buffer(buf: bytes, prev_buf: Optional[bytes],
                         udp_len: int,
                         block: int = UCI_FIRST_BLOCK_PAYLOAD,
                         poison: Optional[bytes] = None,
                         host_tag_verifies: Optional[bool] = None) -> dict:
    """TRUNCATION vs CORRUPTION for one inbound datagram.

    A short multi-block SOCKET_READ and a genuine Poly1305 mismatch are
    indistinguishable from the reject alone: a short udp_recv_len makes
    transport_decrypt copy the tag out of the middle of the ciphertext
    (transport.s:562-573), so the tag check fails either way. What separates
    them is WHAT IS IN THE BUFFER.

    PRIMARY rule — the POISON STOP. *poison* is the pattern
    _clear_recv_state wrote into udp_recv_buf before the send, so the first
    offset from which the buffer still matches it is exactly how far the
    firmware wrote. ``stop == udp_len`` means every announced byte is this
    cycle's, so a tag mismatch on it is genuine; ``stop == 893`` means the
    copy stopped at the first UCI response block.

    SECONDARY — the same windows as before, kept because they cost one read
    and they corroborate: the 64 bytes straddling the block boundary, the
    last 32 bytes of the announced datagram, and the longest identical
    suffix shared with the PREVIOUS capture (reported as
    ``baseline_verdict`` once the poison rule is available).

    Why the baseline diff alone is NOT enough, and why "expect zeros" is
    wrong: udp_recv_buf is zero-filled at load, but from then on byte i
    holds whatever the most recent datagram that reached offset i wrote. One
    long datagram early in a run leaves coherent mid-ciphertext in the gap
    of every later truncated read — not zeros, and not the immediately
    preceding packet either. That is why the poison is written instead of
    relying on what happened to be there.

    The rule is versioned (RECV_FORENSICS_RULE); replace the body, bump the
    constant, and old logs stay readable under the rule they were made with.
    """
    out: dict = {"rule": RECV_FORENSICS_RULE, "block_size": block,
                 "announced_len": udp_len, "buffer_len": len(buf)}

    # --- PRIMARY rule: the poison stop. Single-shot and unambiguous. ----
    if poison is not None:
        stop = poison_stop(buf, poison)
        out["poison_stop_raw"] = stop
        # THE TOLERANCE. The scan walks backwards while bytes match, and
        # udp_recv_buf is poisoned to capacity, so a full write's surviving
        # tail already runs from udp_len to the end of the buffer. ONE
        # coincidental byte at buf[udp_len-1] extends it by one and turns
        # "fully received, so a tag mismatch is genuine" into "partial
        # write" — under the old (i*$9D+$5A) pattern that was 1/256 per
        # rejected trial, ~9% over a 24-rung run, and it pointed at the
        # conclusion we are trying hardest not to reach by accident.
        #
        # So a shortfall INSIDE the announced datagram is only believed
        # when at least POISON_MIN_RUN bytes of it survived. False positive
        # rate: (1/251)^16 ~ 1e-38. Cost, stated because it is real: a
        # genuine truncation of fewer than 16 bytes now reads as a full
        # write. A response-block truncation is hundreds of bytes short.
        if udp_len and 0 < udp_len - stop < POISON_MIN_RUN:
            out["poison_short_tail_ignored"] = udp_len - stop
            stop = udp_len
        out["poison_stop"] = stop
        if stop == 0:
            out["poison_verdict"] = "nothing-written"
        elif udp_len and stop == udp_len:
            out["poison_verdict"] = ("fully-received: every announced byte "
                                     "was written this cycle, so a tag "
                                     "mismatch on it is GENUINE")
        elif stop == EXPECTED_TRUNCATION_STOP:
            out["poison_verdict"] = ("truncated-at-block-boundary: the copy "
                                     "stopped at the first response block")
        else:
            out["poison_verdict"] = "partial-write-stopped-at-%d" % stop
        out["poison_stop_is_block_multiple"] = (stop % block == 0)
        # Where the surviving tail SAYS it came from. Equal to `stop` means
        # the poison at that offset was simply never overwritten. Anything
        # else means bytes MOVED, which no short read can do.
        if 0 < stop < len(buf):
            off = poison_run_offset(buf[stop:stop + 64])
            out["poison_tail_offset"] = off
            out["poison_tail_self_consistent"] = (
                off is None or off == stop % POISON_MOD)
        # INDEPENDENT CHECK. If the host re-ran the peer's Poly1305 over
        # this buffer and the tag VERIFIED, then every byte of the announced
        # datagram was present and correct — whatever the poison scan said.
        # A tag verifying over a truncated buffer is a 2^-128 event, so this
        # outranks the poison rule rather than merely corroborating it.
        if host_tag_verifies is True and stop != udp_len:
            out["poison_verdict_before_aead"] = out["poison_verdict"]
            out["poison_verdict"] = (
                "fully-received (host Poly1305 VERIFIES over the announced "
                "%d bytes, so every byte was present; the poison scan's "
                "stop of %d is a coincidence, not a short write)"
                % (udp_len, stop))
            out["poison_aead_override"] = True
        out["verdict"] = out["poison_verdict"]

    def _baseline(verdict: str) -> None:
        """The pre-poison rule's answer: authoritative only when there is no
        poison to read, corroboration otherwise."""
        out["baseline_verdict" if poison is not None else "verdict"] = verdict

    lo = max(0, min(block - 32, len(buf)))
    hi = max(lo, min(block + 32, len(buf)))
    out["straddle_offset"] = lo
    out["straddle_hex"] = buf[lo:hi].hex()
    if 32 <= udp_len <= len(buf):
        out["tail32_offset"] = udp_len - 32
        out["tail32_hex"] = buf[udp_len - 32:udp_len].hex()
        out["tail32_is_zero"] = buf[udp_len - 32:udp_len] == bytes(32)
    else:
        out["tail32_offset"] = None
        out["tail32_hex"] = None
        out["tail32_is_zero"] = None
    n = len(buf)
    if udp_len <= 0 or udp_len > n:
        _baseline("no-datagram")
        out["residue_start"] = None
        out["truncation_offset"] = None
        return out

    # Zero-fill is invisible to the baseline diff — zeros differ from the
    # previous datagram just as fresh bytes do — so it is measured on its
    # own: the run of zero bytes ending at the ANNOUNCED length. A
    # well-formed datagram ends in its 16-byte Poly1305 tag, so a run this
    # long is a 2^-128 coincidence, not ciphertext.
    z = udp_len
    while z > 0 and buf[z - 1] == 0:
        z -= 1
    out["trailing_zero_run"] = udp_len - z

    # The baseline diff: the longest identical SUFFIX shared with the
    # previous query's buffer is the region the firmware did not write this
    # time. Where it begins BELOW the announced length is the truncation
    # point.
    if prev_buf is None or len(prev_buf) != n:
        out["residue_start"] = None
        m = None
    else:
        m = n
        while m > 0 and buf[m - 1] == prev_buf[m - 1]:
            m -= 1
        out["residue_start"] = m
        out["residue_len"] = n - m

    if m is not None and m < udp_len:
        stale = buf[m:udp_len]
        out["stale_bytes_inside_announced"] = len(stale)
        out["stale_is_zero"] = (stale == bytes(len(stale)))
        out["truncation_offset"] = m
        _baseline("truncated-zero-fill" if out["stale_is_zero"]
                  else "truncated-previous-datagram-residue")
    elif out["trailing_zero_run"] >= ZERO_FILL_MIN_RUN:
        out["truncation_offset"] = z
        _baseline("truncated-zero-fill")
    elif m is None:
        out["truncation_offset"] = None
        _baseline("no-baseline")
        return out
    else:
        out["truncation_offset"] = None
        _baseline("no-truncation-detected")
        return out

    cut = out["truncation_offset"]
    out["truncation_at_block_multiple"] = (cut % block == 0)
    out["truncation_over_block"] = round(cut / block, 3)
    # Kept under their old names so an existing reader of this dict does not
    # silently see None where it used to see the residue transition.
    out["residue_start_is_block_multiple"] = out["truncation_at_block_multiple"]
    out["residue_start_over_block"] = out["truncation_over_block"]
    return out


def _record_unscored(result: dict, q: dict, rung: int, name: str, why: str,
                     needed: bool) -> None:
    """Mark one query as NOT scorable from the screen, loudly.

    This is the whole point of item 6: the previous code fell back to the
    WHOLE screen when its marker was missing and scored the query anyway,
    which is how text printed by an EARLIER query became this query's
    verdict. There is no fallback here. ``screen_decrypt_failed`` is left
    None — not False — because "we could not look" and "we looked and it was
    not there" are different facts and only one of them is a measurement.

    *needed* distinguishes the two ways the anchor goes missing:
      * a query that got a big reply printed 25+ rows and scrolled the
        anchor away. Its verdict came from msg_recv_len, the screen was
        never needed, so this is a WARNING.
      * a query that got NOTHING has no other corroboration for the
        structural reject cause, so losing the screen loses the
        cross-check: ERROR.
    """
    q["screen_anchor_ok"] = False
    q["screen_decrypt_failed"] = None
    q["screen_unscored_reason"] = why
    (log.error if needed else log.warning)(
        "rung %d (%s): SCREEN ANCHOR ABSENT (%s) — this query is NOT scored "
        "from the screen%s", rung, name, why,
        "; the structural reject cause has no independent corroboration"
        if needed else " (a reply arrived, so the screen was not the "
                       "instrument for this one)")
    result["unscored_queries"].append(
        {"rung": rung, "name": name, "why": why,
         "screen_was_the_instrument": needed})


def shuffle_ladder(ladder: list, insert_control: bool,
                   rungs: tuple = SWEEP_CONTROL_RUNGS,
                   control: tuple = SWEEP_CONTROL,
                   attempts: int = 64) -> list:
    """Shuffle the size ladder and plant the small control at *rungs*.

    Uses the module-level ``random``, which run_stage_c has already seeded
    with the run's logged seed, so ``--seed N`` replays the same order.

    A shuffle can come out sorted, and a sorted ladder is precisely the
    confound this exists to break, so the draw is REJECTED and repeated
    while the executed size sequence is monotonically non-decreasing. When
    every rung is the same size that is unavoidable and not a confound, so
    the first draw is taken.
    """
    out = list(ladder)

    def _with_control(seq: list) -> list:
        cand = list(seq)
        if insert_control:
            for pos in sorted(rungs):
                if 1 <= pos <= len(cand) + 1:
                    cand.insert(pos - 1, control)
        return cand

    for _ in range(attempts):
        random.shuffle(out)
        cand = _with_control(out)
        sizes = [size for _, size in cand]
        if len(set(sizes)) < 2:
            return cand
        if any(b < a for a, b in zip(sizes, sizes[1:])):
            return cand
    raise RuntimeError(
        f"could not draw a non-ascending ladder in {attempts} attempts; "
        f"refusing to run a sweep whose order is confounded with size")




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
                multipart: int = 0, large_repeats: int = 1,
                reply_sweep: int = 0) -> dict:
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
    # Scale with the clock: the handshake is CPU-bound, so a fixed 120 s
    # budget silently becomes a failure at any speed below 48 MHz. A 16 MHz
    # run timed out at 120.9 s with the Type-2 response already received and
    # wg_state = HS_SENT — a measurement artefact that reads exactly like a
    # broken handshake.
    hs_budget = HS_POLL_TIMEOUT * max(1.0, 48.0 / max(1, turbo_mhz))
    active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE, hs_budget, poll=1.0)
    elapsed = time.monotonic() - t0
    result["handshake_seconds"] = round(elapsed, 1)
    result["active"] = active
    if not active:
        _dump_failure(tr, L, "stageC-handshake", backend)
        return result
    log.info("Stage C: ACTIVE in %.1fs", elapsed)

    random.seed(seed)
    # --- Item 7 (issue #128): break the order/size confound -------------
    # This list used to run the 1278 B rung FIRST and then walk
    # REPLY_SWEEP_NAMES strictly ASCENDING, each rung's repeats back to
    # back. Everything that drifts with TIME was therefore rank-correlated
    # with SIZE:
    #   * session age — the 180 s expiry in src/wg/timer.s resets to IDLE,
    #     after which session_handle_packet's @type4 drops every inbound
    #     Type 4 SILENTLY (src/wg/session.s:332-336). An ascending sweep
    #     that outlives one session renders that as "the big sizes fail",
    #     with the run recovering at the end when a rekey completes. That is
    #     the exact shape #128 reported.
    #   * tp_send_counter and the replay window's rw_counter_max;
    #   * the resolver's rate limiter — N back-to-back lookups of ONE name,
    #     rate-limited once, give N/N "failures" for that size alone.
    # So the ladder is SHUFFLED under the run's logged seed (reproducible
    # with --seed) and the small control is re-run at three separated rungs
    # instead of only rung 2. The SIZES are unchanged; only the order in
    # which they are visited, which is the entire point.
    ladder: list = [("namecheap.com", 1278)] * max(1, large_repeats)
    if reply_sweep:
        ladder += [(nm, expect) for nm, expect in REPLY_SWEEP_NAMES
                   for _ in range(reply_sweep)]
    ladder = shuffle_ladder(ladder, insert_control=bool(reply_sweep))
    result["ladder"] = [{"rung": i + 1, "name": nm, "expected_reply_len": exp}
                        for i, (nm, exp) in enumerate(ladder)]
    log.info("ladder (shuffled under seed %d): %s", seed,
             ", ".join("%d:%s~%d" % (i + 1, nm, exp)
                       for i, (nm, exp) in enumerate(ladder)))
    queries = [(nm, DNS_QTYPE_TXT, exp,
                "LADDER rung %d: %s ~%d B reply" % (i + 1, nm, exp),
                None, None, 1400)
               for i, (nm, exp) in enumerate(ladder)]
    queries += [
        ("github.com", DNS_QTYPE_TXT, 1928, "targets >1280 (Cloudflare WARP MTU)", None, None, 1400),
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
                                size, want, 1400))
    result["queries"] = []
    result["unscored_queries"] = []
    result["forensics_rule"] = RECV_FORENSICS_RULE
    recv_cap = _recv_buf_capacity(L)
    poison = poison_pattern(recv_cap)
    prev_recv_buf: Optional[bytes] = None
    t_active = time.monotonic()
    for rung, (name, qtype, dig_size, band, pad_to, want_parts,
               bufsize) in enumerate(queries, 1):
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
            question, wire = build_dns_query(name, qtype, txn_id, bufsize=bufsize)
            outer, parts = datagram_parts(len(wire))
            log.info("DNS query %s %s txn_id=%d wire_len=%d expected_reply=%d (%s)",
                     name, {16: "TXT"}.get(qtype, qtype), txn_id, len(wire),
                     dig_size, band)

        # --- Item 3: clear ALL receive state, VERIFIED by read-back -----
        # Until 2026-09-04 only msg_recv_len and tp_payload_len were
        # cleared, so udp_recv_len, the Type-4 header in udp_recv_buf and
        # tp_packet_len could all be the PREVIOUS datagram's or the
        # handshake's. Everything item 4 reads back depends on this.
        fresh, clear_detail = _clear_recv_state(tr, L, poison=poison)
        if not fresh:
            log.error("rung %d (%s): receive state did NOT clear (%s) — "
                      "what is read back may belong to an earlier datagram",
                      rung, name, clear_detail)

        # The PRE-send state. wg_state is sampled here AND after the receive
        # window because it can change mid-query, and a change across the
        # query is itself the finding: a session that expired mid-sweep
        # drops inbound Type 4s with no message, no counter and no trace.
        # rw_counter_max/rw_bitmap must be the window as it stood when the
        # reply was processed, so they are read BEFORE the send — a
        # successful decrypt advances both.
        pre = _read_session_state(tr, L)
        since_active = round(time.monotonic() - t_active, 1)

        anchor_token = _new_anchor_token()
        anchor_rep: dict = {}
        staged = stage_raw_dma(tr, wire, L, timeout=15.0,
                               anchor=anchor_token, anchor_out=anchor_rep)
        screen_before = anchor_rep.pop("screen_before", "")

        q = {
            "rung": rung,
            "name": name, "qtype": qtype, "txn_id": txn_id,
            "inner_target": target,
            "wire_len": len(wire),
            "expected_reply_len": dig_size,
            "dig_measured": dig_size,           # legacy key, same value
            "band": band,
            "outer_datagram_len": outer, "uci_parts": parts,
            "multipart": bool(pad_to), "staged_ok": staged,
            "recv_state_fresh": fresh, "recv_state_clear": clear_detail,
            "seconds_since_handshake": since_active,
            "past_rekey_threshold": since_active >= WG_REKEY_SECONDS,
            "past_expiry_threshold": since_active >= WG_EXPIRE_SECONDS,
            "wg_state_before": pre.get("wg_state"),
            "rekey_pending_before": pre.get("rekey_pending"),
            "udp_recv_ready_before": pre.get("udp_recv_ready"),
            "tp_send_counter_before": pre.get("tp_send_counter"),
            "rw_counter_max_before": pre.get("rw_counter_max"),
            "net_last_error_before": pre.get("net_last_error"),
            "screen_anchor": anchor_rep,
        }
        # Anything the C64 printed between the previous query's screen read
        # and this query's blank would otherwise be lost, so
        # place_screen_anchor captures the screen BEFORE blanking it and
        # both halves are searched for the two session-state messages.
        q["session_msgs_before_query"] = sorted(
            m for m in SESSION_STATE_MSGS if m in screen_before)

        # VIC snapshot BEFORE the exchange. src/wg/vic_boost.s touches ONLY
        # $D011 bit 4 (DEN) and documents that screen contents survive
        # blanking untouched; nothing in this program writes $D020/$D021 at
        # all. So a change in the border or background colour is not a
        # display artefact, it is a WRITE THAT SHOULD NOT EXIST — the same
        # signature as #62, where net_poll trusted a returned length and
        # copied ~18 KB through $D000, leaving packet bytes in the VIC
        # registers. Reported by the user watching the screen during this
        # investigation; worth capturing rather than taking on trust.
        try:
            vic_before = bytes(tr.read_memory(0xD011, 1)) + \
                bytes(tr.read_memory(0xD020, 2))
        except Exception:                                     # noqa: BLE001
            vic_before = None

        t_sent = time.monotonic()
        deadline = t_sent + DNS_TIMEOUT
        recv_len = 0
        while time.monotonic() < deadline:
            recv_len = int.from_bytes(tr.read_memory(L["msg_recv_len"], 2), "little")
            if recv_len:
                break
            time.sleep(0.25)
        t_reply = time.monotonic()
        q["receive_window_s"] = round(t_reply - t_sent, 2)

        # --- Items 4/5/8: probe EVERY query, AS EARLY AS POSSIBLE --------
        # The old `if dig_size >= 400` gate meant the multipart rungs (which
        # carry dig_size 0) were never probed at all, and that a reply that
        # came back SHORT was never measured — which is why the band edges
        # in #128 were assumptions rather than measurements.
        #
        # tp_payload_len is read FIRST and the delay is recorded: the 10 s
        # keepalive zeroes that field, so every second between the reply and
        # the read is a second in which the value can stop being this
        # query's. The VIC snapshot used to sit in front of these reads and
        # now follows them, for the same reason.
        buf: Optional[bytes] = None
        udp_len: Optional[int] = None
        tp_packet_len: Optional[int] = None
        tp_payload_len: Optional[int] = None
        try:
            tp_payload_len = int.from_bytes(
                bytes(tr.read_memory(L["tp_payload_len"], 2)), "little")
            q["probe_delay_s"] = round(time.monotonic() - t_reply, 2)
            tp_packet_len = int.from_bytes(
                bytes(tr.read_memory(L["tp_packet_len"], 2)), "little")
            udp_len = int.from_bytes(
                bytes(tr.read_memory(L["udp_recv_len"], 2)), "little")
            q["observed_datagram_len"] = udp_len
            q["udp_recv_len"] = udp_len                 # legacy key
            q["tp_payload_len"] = tp_payload_len
            q["tp_packet_len"] = tp_packet_len
            buf = bytes(tr.read_memory(L["udp_recv_buf"], recv_cap))
            q["recv_head"] = buf[:16].hex()
            q["type4_ok"] = buf[0] == WG_TYPE4 and buf[1:4] == b"\x00\x00\x00"
            q["recv_counter"] = int.from_bytes(buf[8:16], "little")
            q["recv_buf_sha256"] = hashlib.sha256(buf).hexdigest()
        except Exception as exc:                              # noqa: BLE001
            q["len_probe_error"] = repr(exc)

        try:
            vic_after = bytes(tr.read_memory(0xD011, 1)) + \
                bytes(tr.read_memory(0xD020, 2))
            if vic_before is not None:
                q["vic_d011_d020_d021_before"] = vic_before.hex()
                q["vic_d011_d020_d021_after"] = vic_after.hex()
                # $D011 legitimately changes (vic_boost blanks); the COLOUR
                # registers never should.
                q["vic_colour_changed"] = vic_before[1:] != vic_after[1:]
        except Exception as exc:                              # noqa: BLE001
            q["vic_probe_error"] = repr(exc)

        post = _read_session_state(tr, L)
        q["wg_state_after"] = post.get("wg_state")
        q["wg_state_changed"] = (pre.get("wg_state") != post.get("wg_state"))
        q["rekey_pending_after"] = post.get("rekey_pending")
        q["udp_recv_ready_after"] = post.get("udp_recv_ready")
        q["tp_send_counter_after"] = post.get("tp_send_counter")
        q["rw_counter_max_after"] = post.get("rw_counter_max")
        q["net_last_error"] = post.get("net_last_error")
        # $8F (UCI_ERR_SHORT_READ) says net_poll dropped a datagram that
        # ended short of its announced length; this byte says WHICH terminal
        # STATE produced it, which decides between a zero-length final block
        # ($A0 Data Last) and a firmware abort/reset ($80 Idle). Meaningful
        # only alongside the $8F, and only because both were cleared before
        # the send — see RECV_STATE_CLEARED.
        srs = post.get(SHORT_READ_STATE_LABEL)
        q[SHORT_READ_STATE_LABEL] = srs
        q[SHORT_READ_STATE_LABEL + "_name"] = describe_short_read_state(srs)
        # Keepalive contamination. This tool makes exactly ONE send per
        # query, so a larger delta means the device sent something of its
        # own inside the receive window — the 10 s keepalive — and every
        # field that keepalive writes (tp_payload_len to 0, tp_packet_len to
        # 32) is ITS value, not this query's. The bias is not random: a
        # failing query waits out DNS_TIMEOUT and a succeeding one returns
        # in ~1.5 s, so only the failures get contaminated, which fabricates
        # a difference between them.
        before_ctr = pre.get("tp_send_counter")
        after_ctr = post.get("tp_send_counter")
        if before_ctr is None or after_ctr is None:
            q["tp_send_counter_delta"] = None
            q["keepalive_in_window"] = None
        else:
            delta = (after_ctr - before_ctr) & 0xFFFF
            q["tp_send_counter_delta"] = delta
            q["keepalive_in_window"] = delta > TP_SEND_PER_QUERY
        q["tp_payload_len_trustworthy"] = (q["keepalive_in_window"] is False)
        if q["keepalive_in_window"]:
            log.warning("rung %d (%s): tp_send_counter advanced by %s in a "
                        "%.1f s window — a keepalive fired inside it, so "
                        "tp_payload_len=%s is the KEEPALIVE's value and is "
                        "not evidence about this reply", rung, name,
                        q["tp_send_counter_delta"], q["receive_window_s"],
                        tp_payload_len)
        if post.get("wg_state") != SESSION_ACTIVE:
            log.error("rung %d (%s): wg_state is %s, NOT ACTIVE(%d) — inbound "
                      "Type 4 is dropped silently at session.s:332 in this "
                      "state, so nothing about this query is evidence about "
                      "decryption", rung, name, post.get("wg_state"),
                      SESSION_ACTIVE)

        # --- Item 5: the ARRIVED length, on failures too ----------------
        q["reply_observed"] = bool(recv_len)
        q["observed_reply_len"] = recv_len if recv_len else None
        expected = dig_size or None
        if q["observed_reply_len"] is None or expected is None:
            q["size_mismatch"] = None
        else:
            q["size_mismatch"] = q["observed_reply_len"] != expected
            if q["size_mismatch"]:
                msg = ("rung %d (%s): reply is %d B but the table says %d B "
                       "— the table entry has drifted or the reply was "
                       "truncated; the size axis of this trial is the "
                       "MEASURED one" % (rung, name, recv_len, expected))
                log.error("%s", msg)
                result.setdefault("size_mismatches", []).append(msg)
        if udp_len and expected:
            q["expected_datagram_len"] = IP_UDP_HDR + expected + WG_DATA_OVERHEAD
            q["datagram_len_matches_expected"] = (
                udp_len == q["expected_datagram_len"])

        # --- Item 4: WHICH reject cause, not a boolean ------------------
        if buf is not None:
            cause, cause_name, cause_detail = classify_reject(
                head=buf[:16], udp_len=udp_len, msg_recv_len=recv_len,
                tp_packet_len=tp_packet_len, tp_payload_len=tp_payload_len,
                wg_state_before=pre.get("wg_state"),
                wg_state_after=post.get("wg_state"),
                rw_counter_max=pre.get("rw_counter_max"),
                rw_bitmap=pre.get("rw_bitmap"),
                keepalive_suspected=bool(q["keepalive_in_window"]),
                poison_head=poison[:16],
                rw_counter_max_before=pre.get("rw_counter_max"),
                rw_counter_max_after=post.get("rw_counter_max"))
            q["reject_cause"] = cause
            q["reject_cause_name"] = cause_name
            q["reject_detail"] = cause_detail
            q["decrypt_failed"] = cause is not None
            if cause is not None:
                log.info("rung %d (%s): REJECT cause %d (%s)", rung, name,
                         cause, cause_name)
            # A build that exports a device-side cause byte gets read for
            # free and cross-checked. Absent — every build today — nothing
            # here runs and the host derivation stands alone.
            if DEVICE_CAUSE_LABEL in L:
                try:
                    raw = bytes(tr.read_memory(L[DEVICE_CAUSE_LABEL], 1))[0]
                except Exception as exc:                      # noqa: BLE001
                    q["device_reject_cause_error"] = repr(exc)
                else:
                    q["device_reject_cause_raw"] = "$%02X" % raw
                    dev = None if raw == DEVICE_CAUSE_POISON else raw
                    q["device_reject_cause"] = dev
                    if dev in REJECT_CAUSE_NAMES and cause in (1, 2, 3, 4, 5):
                        q["device_cause_agrees"] = (dev == cause)
                        if not q["device_cause_agrees"]:
                            log.error("rung %d (%s): device says cause %d, "
                                      "host derivation says %d — the host "
                                      "rule is wrong somewhere", rung, name,
                                      dev, cause)
            # The strongest single check, and it needs nothing from the
            # device beyond the buffer read just done: re-run the peer's
            # AEAD on the host over the bytes the C64 actually holds. The
            # session receive key is read fresh each query (a rekey changes
            # it), used in memory, and NEVER stored, logged or returned —
            # only the verdict is.
            #
            # It runs BEFORE the block forensics, not after, because its
            # answer OUTRANKS the poison scan: a tag that verifies proves
            # every announced byte was present, which no coincidence in the
            # poison tail can contradict.
            tag_verifies: Optional[bool] = None
            if cause is not None and udp_len:
                try:
                    recv_key = bytes(tr.read_memory(L["hs_transport_recv"], 32))
                except Exception as exc:                      # noqa: BLE001
                    recv_key = None
                    q["aead_key_read_error"] = repr(exc)
                q["host_aead_check"] = verify_poly1305_host(
                    buf, udp_len, recv_key)
                del recv_key
                tag_verifies = q["host_aead_check"].get("tag_verifies")

            # --- Item 8: truncation vs corruption ----------------------
            q["block_forensics"] = classify_recv_buffer(
                buf, prev_recv_buf, udp_len or 0, poison=poison,
                host_tag_verifies=tag_verifies)
            prev_recv_buf = buf
            if q.get("host_aead_check"):
                log.info("rung %d (%s): host-side AEAD says %s; poison stop "
                         "%s of %s", rung, name,
                         q["host_aead_check"].get("verdict"),
                         q["block_forensics"].get("poison_stop"), udp_len)
        else:
            q["reject_cause"] = None
            q["reject_cause_name"] = "unclassified (receive buffer unreadable)"
            q["decrypt_failed"] = None

        # --- Item 6: anchored screen scrape -----------------------------
        q["screen_anchor_ok"] = False
        q["screen_decrypt_failed"] = None
        if anchor_rep.get("placed"):
            try:
                after, _full = read_after_anchor(tr, anchor_token)
                q["screen_anchor_ok"] = True
                # The anchor proves the window is THIS query's. It does not
                # prove the firmware wrote what is in it. Peer bytes reach
                # the screen through @t4_udp and display_payload, so a DNS
                # TXT record containing the literal text "DECRYPT FAILED" —
                # or the anchor token, or anything else — is printed
                # verbatim after one of PEER_CONTENT_HEADERS. Searching the
                # whole window lets the peer author this instrument's
                # reading, which is the #128 defect with a new marker.
                #
                # So the window is cut at the first peer-content header and
                # only the firmware's own half is searched. Nothing is lost:
                # within one packet the peer-print paths and @decrypt_fail
                # are mutually exclusive — a packet whose bytes were printed
                # is a packet that decrypted.
                cuts = [after.find(h) for h in PEER_CONTENT_HEADERS]
                cuts = [c for c in cuts if c >= 0]
                cut = min(cuts) if cuts else len(after)
                firmware_half = after[:cut]
                q["screen_peer_region_from"] = cut if cuts else None
                q["screen_peer_region_len"] = len(after) - cut
                q["screen_decrypt_failed"] = (
                    DECRYPT_FAIL_TEXT in firmware_half)
                q["screen_decrypt_fail_count"] = firmware_half.count(
                    DECRYPT_FAIL_TEXT)
                # Kept visible, and deliberately NOT part of any verdict: a
                # peer echoing the failure string is worth seeing in the log
                # exactly once, as evidence about the peer.
                q["screen_decrypt_fail_in_peer_region"] = (
                    DECRYPT_FAIL_TEXT in after[cut:])
                if q["screen_decrypt_fail_in_peer_region"]:
                    log.warning("rung %d (%s): the PEER's own bytes contain "
                                "%r. It is excluded from the screen verdict "
                                "(it sits after %r); reporting it because a "
                                "peer that sends this string is either "
                                "unlucky or probing the instrument.",
                                rung, name, DECRYPT_FAIL_TEXT,
                                PEER_CONTENT_HEADERS)
                q["screen_after_anchor"] = " ".join(after.split())[:300]
                q["session_msgs_this_query"] = sorted(
                    m for m in SESSION_STATE_MSGS if m in after)
                # An INDEPENDENT keepalive detector: timer.s prints
                # "KEEPALIVE" right after the send, so the screen confirms
                # (or contradicts) what tp_send_counter's delta says.
                q["screen_keepalive_in_window"] = KEEPALIVE_TEXT in after
            except Exception as exc:                          # noqa: BLE001
                _record_unscored(result, q, rung, name, repr(exc),
                                 needed=not recv_len)
        else:
            _record_unscored(result, q, rung, name,
                             anchor_rep.get("error", "anchor was not placed"),
                             needed=not recv_len)

        # The screen and the structural verdict must AGREE: every one of
        # transport_decrypt's five causes prints decrypt_fail_msg, and
        # nothing else does. A disagreement means one of the two
        # instruments is wrong, which is worth more than either reading.
        if q["screen_anchor_ok"] and q["decrypt_failed"] is not None:
            q["screen_agrees_with_reject_cause"] = (
                bool(q["screen_decrypt_failed"]) == bool(q["decrypt_failed"]))
            if not q["screen_agrees_with_reject_cause"]:
                log.error("rung %d (%s): the screen says DECRYPT FAILED=%s "
                          "but the structural analysis says %s (%s) — one of "
                          "these instruments is wrong; do not report either "
                          "as a result", rung, name,
                          q["screen_decrypt_failed"], q["decrypt_failed"],
                          q["reject_cause_name"])

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
    p.add_argument("--reply-sweep", type=int, default=0, metavar="N",
                   help="Sweep the INBOUND reply size, N attempts per size, "
                        "over REPLY_SWEEP_NAMES — real names with known TXT "
                        "reply sizes, NOT EDNS bufsize (a resolver answers a "
                        "query it cannot fit with a 42-byte TC=1 stub, so "
                        "sweeping bufsize sweeps nothing: measured, every "
                        "size from 400 to 1200 returned 42 bytes). The "
                        "ladder is shuffled under the run seed and the small "
                        "control is re-run at three separated rungs, so a "
                        "result is not confounded with elapsed time, session "
                        "age or a resolver rate limiter.")
    p.add_argument("--large-repeats", type=int, default=1, metavar="N",
                   help="Repeat the 1278-byte-reply DNS query N times in "
                        "Stage C and report a per-attempt success/DECRYPT "
                        "FAILED rate. The inbound decrypt intermittent "
                        "(2 of 4 runs, 2026-09-03) needs a rate, not an "
                        "anecdote; contention from an unserialised lane is "
                        "the leading alternative explanation.")
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
        # Build identity, INSIDE the lock: a /v1/info read taken while
        # another lane is mid-rewrite returns a coherent-looking value from
        # a half-applied state, and nothing raises.
        log_build(args.host, log)
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
                        multipart=args.multipart,
                        large_repeats=args.large_repeats,
                        reply_sweep=args.reply_sweep)
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
                # Reset the C64. Restoring the CLOCK and the REU is not
                # restoring the MACHINE: our PRG is still running and still
                # driving the command interface, so the next lane inherits
                # an interface that holds a reply and goes straight back to
                # Command Busy. Measured 2026-09-03 by the firmware lane,
                # who lost two runs to it: `release()` and `abort_to_idle()`
                # both returned True and the status snapped back, because
                # nothing was stuck — something was actively driving it. A
                # reset cleared it to $00 Idle first try.
                #
                # This never bites US: run_prg resets on the way IN. It bites
                # whoever goes next, and it presents as THEIR suite being
                # broken rather than as our leftover state — the expensive
                # shape, the same one as 1.1.1.1's silent >512 B request drop.
                client.reset()
                time.sleep(1.0)
                log.info("restore: C64 reset — command interface left idle "
                         "for the next lane")
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
        # A query whose screen could not be attributed is not a passing
        # query, it is an ABSENT measurement — and `screen_decrypt_failed`
        # is None rather than False precisely so the two cannot be
        # confused. That care is wasted if the distinction reaches nothing:
        # a reader counting "queries that did not report a failure" absorbs
        # them as clean, which is the shape of the defect this whole
        # instrument rewrite exists to prevent. Surfacing them here is what
        # makes the None mean something to the process, not just to a log.
        unscored = stage.get("unscored_queries")
        if unscored:
            rungs = ", ".join(
                str(u.get("rung", "?")) if isinstance(u, dict) else str(u)
                for u in unscored)
            out.append(
                f"{key}: {len(unscored)} quer(y/ies) could not be attributed "
                f"to their own screen (rungs {rungs}); their screen verdict "
                f"is UNKNOWN, not clean")
    return out


if __name__ == "__main__":
    sys.exit(main())
