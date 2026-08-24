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
; WHY 480 AND NOT WIREGUARD'S USUAL 1420: the UCI firmware's SOCKET_READ
; TRUNCATES an oversized datagram rather than splitting it (fw 3.14d clamps
; 600-1280-byte requests to 512 and returns $FFFF for >=1500), so the tail of
; anything larger than UCI_READ_CHUNK_MAX is lost and the packet fails AEAD.
; The loss is SILENT: nothing on either side reports it.
;
; This is INBOUND-only in origin. Outbound is chunked by net_udp_send and
; could carry ~1468, but MTU is configured per-peer at both ends, so a peer
; left at the 1420 default will answer our large packets with large packets
; we then drop. We therefore pin both directions to the value we can
; actually receive, so a mismatch fails loudly at the sender instead of
; vanishing at the receiver.
;
; PEERS MUST BE CONFIGURED WITH MTU = 480 (see README).
;
; NOT NECESSARILY A PERMANENT CEILING. Whether the firmware queues the
; remainder of an oversized datagram for a subsequent read (in which case
; multi-read reassembly could restore a standard MTU) or discards it has
; NOT been measured. tools/test_uci_udp_size_probe.py exists to settle
; exactly that question. Issue #46.
WG_DATA_OVERHEAD    = 32        ; 16 B Type-4 header + 16 B Poly1305 tag
WG_MTU              = 480       ; = 512 - WG_DATA_OVERHEAD
