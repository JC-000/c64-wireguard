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
