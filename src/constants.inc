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
; DERIVED, NOT PINNED (c64-lib-contract SPEC v0.12.0 §13.3, consumer
; obligation). The number comes from the selected backend's net_caps.inc
; (src/net/$(BACKEND)/net_caps.inc, picked by the Makefile's -I path — §13.3
; requires backend selection to select the include path too): a Type-4
; datagram has to fit both the largest datagram the backend can SEND whole
; and the largest it can RECEIVE whole, so
;
;     WG_MTU = min(NET_UDP_SEND_MAX, NET_UDP_RECV_MAX) - WG_DATA_OVERHEAD
;
; Today (UCI, U64E fw 3.14d): min(892, 1472) - 32 = 860, SEND-bound. The
; receive side already takes 1472, so the only thing that moves this number
; is the send ceiling: a firmware WRITE_SOCKET_MORE (chunked push, filed as
; GideonZ/1541ultimate#806) would lift NET_UDP_SEND_MAX to ~1440 and this
; equate follows it with no edit here. Under ip65 both caps are 1472 and
; WG_MTU is 1440. Every length on the path is 16-bit (contract §13.3), so
; nothing else in the tree needs to change when the caps do.
;
; HISTORY. This was 480, documented as a measured "hardware ceiling" of
; 512 - 32. The 512 was this project's own Phase 3 MVP read size; having
; only ever ASKED for 512 we only ever received 512 and called it a limit
; (the one larger request tried, 1024, was above the then-real 894 cap and
; was rejected on the STATUS channel this adapter drains unread). Root-caused
; upstream by chrisgleissner on GideonZ/1541ultimate#802. Then 861 = 893 - 32
; (read-bound), until the send side was measured on 2026-08-27: a 1452-byte
; SOCKET_WRITE leaves the C64 as 800 + 652 bytes, two torn datagrams. The
; send ceiling is 892 and it is the binding one.
;
; COST AT STOCK SPEED. Every byte of a read carries a uci_fence, and the
; C64-Ultimate-conformant fence (UCI_FENCE_INNER = 217, §13.6) is ~5.45 ms
; at 1 MHz, so a full-size read is seconds of wall clock at 1 MHz and
; negligible at 48 MHz. It scales with WG_MTU.
;
; PEERS MUST BE CONFIGURED WITH MTU = WG_MTU (see README).
.include "net_caps.inc"
WG_DATA_OVERHEAD    = 32        ; 16 B Type-4 header + 16 B Poly1305 tag

; WG_DATAGRAM_CAP is THIS CONSUMER's ceiling, independent of the backend: the
; largest Type-4 datagram the RAM budget can hold. ip_packet_buf + msg_input_buf
; + udp_recv_buf must fit MAIN_AREA_HI; at 892 they leave ~137 B (UCI map,
; 2026-08-27). The ip65 backend advertises 1472/1472 and would otherwise derive
; a 1440 MTU whose buffers overflow HI by ~1 KB. Raising this — e.g. once the
; UCI send side reaches 1440 via WRITE_SOCKET_MORE (GideonZ/1541ultimate#802) —
; means sharing msg_input_buf with ip_packet_buf (build in place), not just
; editing the number: the §13.8 asserts and the linker will refuse otherwise.
WG_DATAGRAM_CAP     = 892
; WG_NET_UDP_MAX = min(NET_UDP_SEND_MAX, NET_UDP_RECV_MAX, WG_DATAGRAM_CAP)
.if NET_UDP_SEND_MAX < NET_UDP_RECV_MAX
WG_NET_BACKEND_MAX  = NET_UDP_SEND_MAX
.else
WG_NET_BACKEND_MAX  = NET_UDP_RECV_MAX
.endif
.if WG_DATAGRAM_CAP < WG_NET_BACKEND_MAX
WG_NET_UDP_MAX      = WG_DATAGRAM_CAP
.else
WG_NET_UDP_MAX      = WG_NET_BACKEND_MAX
.endif
WG_MTU              = WG_NET_UDP_MAX - WG_DATA_OVERHEAD
.assert WG_MTU + WG_DATA_OVERHEAD <= NET_UDP_SEND_MAX, error, "WG_MTU + overhead exceeds NET_UDP_SEND_MAX"
.assert WG_MTU + WG_DATA_OVERHEAD <= NET_UDP_RECV_MAX, error, "WG_MTU + overhead exceeds NET_UDP_RECV_MAX"
.assert WG_MTU >= 576 - 28, error, "WG_MTU below the IPv4 minimum-reassembly datagram; peers cannot be configured this low"

; §13.8: the consumer's receive buffer must hold the backend's published
; receive guarantee; src/contract_asserts.s fails the build if it does not,
; instead of overrunning at runtime. Held at the classic 1500 rather than
; exactly NET_UDP_RECV_MAX: the 28 bytes buy nothing, and tools/test_mtu.py
; drives full 1500-byte Type-4 datagrams (1468-byte payloads) straight into
; udp_recv_buf to exercise the 16-bit transport path above the tunnel MTU.
UDP_RECV_BUF_SIZE   = 1500

; Inner IP/UDP framing carried inside a Type-4 payload (udp_tunnel_build).
; The tunnel text payload is what is left of WG_MTU after these headers.
IP_HDR_LEN          = 20
UDP_HDR_LEN         = 8
IP_UDP_HDR_LEN      = IP_HDR_LEN + UDP_HDR_LEN
MSG_TEXT_MAX        = WG_MTU - IP_UDP_HDR_LEN
