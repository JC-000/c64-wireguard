; =============================================================================
; src/constants.inc — ca65 equates aggregator.
;
; This file is the historical inclusion point for every WG .s module. As of
; the Phase C library-ingestion refactor it is a thin shim that pulls in
; two focused headers:
;
;   src/zp_config.inc   — zero-page slot allocation (`.ifndef`-guarded so
;                         each slot can be relocated at assemble time via
;                         `ca65 --asm-define <slot>=<addr> ...`). Mirrors
;                         the c64-nist-curves/src/zp_config.s pattern.
;
;   src/hw_constants.inc — C64 hardware register + KERNAL equates. Fixed
;                          by the architecture; no relocation guards.
;
; The remainder of this file is WG-specific protocol/algorithm constants
; that don't fit either header. Modules continue to .include "constants.inc"
; unchanged — no per-module call-site churn was needed for this refactor.
;
; The mirror file src/constants.asm (ACME build) has been retired with the
; ACME pipeline; see git log for the migration history.
;
; Pure equates, no code emitted. Safe to .include at the top of any
; ca65 source file.
; =============================================================================

.include "zp_config.inc"
.include "hw_constants.inc"

; --- BLAKE2s constants ---
blake2s_block_size = 64
blake2s_hash_size  = 32
blake2s_rounds     = 10

; --- General constants ---
max_input_len   = 255

; --- ip65 ZP overlap zone and jump-table equates live in
;     src/net/ip65/ip65_symbols.inc. Do NOT define them here too — ca65
;     rejects duplicate equates. Modules that need those symbols should
;     .include "net/ip65/ip65_symbols.inc" (in addition to constants.inc).

; --- WireGuard protocol constants ---
wg_default_port     = 51820
WG_ICMP_ID          = $c640
IP_PROTO_ICMP       = 1
IP_PROTO_UDP        = 17

; Key rotation counter thresholds
REJECT_COUNTER_B7   = $10
REKEY_COUNTER_B7    = $0F

; --- Tunnel MTU -------------------------------------------------------------
; The largest inner payload this implementation can carry in one WireGuard
; Type-4 datagram. A datagram on the wire is payload + WG_DATA_OVERHEAD.
;
; 861 = UCI_READ_CHUNK_MAX (893) - WG_DATA_OVERHEAD (32). See that constant
; for why 893 and not 894 (894 is a firmware hang on 3.14d).
;
; CORRECTED 2026-08-26. This was 480, documented here and in the README as a
; measured "hardware ceiling" of 512 - 32. That was WRONG, and the error was
; ours in an instructive way: the 512 came from this project's own Phase 3
; MVP choice of UCI_READ_CHUNK_MAX, and having only ever ASKED for 512 we
; measured that we only ever RECEIVED 512, then concluded the firmware could
; not do more. The one larger request tested (1024) failed, which looked like
; confirmation — but 1024 is above the real 894 cap and was being rejected
; with `82,PARAMETER(S) OUT OF RANGE` on the STATUS channel, which this
; adapter drains without reading. Both the measurement and the rejection were
; correct; the inference joining them was not. Root-caused upstream by
; chrisgleissner on GideonZ/1541ultimate#802.
;
; Re-measured on our own U64E (fw 3.14d, 2026-08-26): datagrams of 512, 600,
; 700, 800, 861 and 893 bytes all arrive WHOLE in a single net_poll, header
; reporting the true length, net_last_error $00.
;
; WHAT REMAINS TRUE. A standard 1420-byte MTU is still unreachable:
;   * one READ_SOCKET can deliver at most 893 B, and a datagram larger than
;     the request is truncated with the remainder DISCARDED, not queued —
;     so multi-read reassembly cannot recover it;
;   * 1472 B is the largest datagram that reaches the device at all, because
;     lwIP is built with IP_REASSEMBLY = 0 (device-wide, not a UCI matter).
; Reading a 1420 B packet whole needs Data More support on the network
; target, which the firmware does not implement.
;
; COST AT STOCK SPEED, worth knowing before raising this further. Every byte
; of a read carries a uci_fence, and the C64-Ultimate-conformant fence
; (UCI_FENCE_INNER = 217, §13.6) is ~5.45 ms at 1 MHz. An 893-byte read is
; therefore several seconds of wall clock at stock speed — measured: the
; 10 s per-step budget in tools/test_uci_udp_size_probe.py had to be raised
; to 45 s for the large sizes to complete at 1 MHz. At 48 MHz it is
; negligible. This is a real tension between §13.6 conformance and the
; no-REU/1 MHz story, and it scales with WG_MTU.
;
; PEERS MUST BE CONFIGURED WITH MTU = 861 (see README).
WG_DATA_OVERHEAD    = 32        ; 16 B Type-4 header + 16 B Poly1305 tag
WG_MTU              = 861       ; = 893 - WG_DATA_OVERHEAD
