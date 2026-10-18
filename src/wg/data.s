; =============================================================================
; wg/data.s - Mutable buffers and working data (ca65 port of src/data.asm)
;
; This module is the authoritative owner of every mutable buffer that the
; WireGuard system uses: crypto state, handshake state, transport state,
; config, cookies, lookup tables. Every ca65 module in src/crypto/ and
; src/wg/ that references these labels imports them from here.
;
; No logic changes vs data.asm; mechanical ACME -> ca65 translation only.
;
; Segment layout:
;   CRYPTO_RODATA : constant lookup tables (sqtab2_lo/hi, rw_bit_mask)
;   APP_DATA      : initialised application data (msg_port, ip_hdr_template,
;                   config_filename, b2s_out_len default)
;   CRYPTO_BSS    : uninitialised crypto scratch (b2s_*, kdf_*, hmac_*,
;                   input_buffer)
;   APP_BSS       : uninitialised app state (hs_*, tp_*, wg_*, cfg_*,
;                   cookie_*, udp_*, rw_*, tunnel/ping/msg/disk/net state)
;
; The ChaCha20/Poly1305/AEAD state (cc20_*, poly_*, aead_*) and the
; fe25519/X25519 buffers (fe_*, x25_*, mul_dma_lo/hi, ...) are owned by the
; sibling archives. Until 2026-10-18 this file also carried the legacy
; in-tree copies for the USE_*_SIBLING=0 build, including the page-aligned
; mul_dma_lo/hi REU DMA targets and their issue #104 constant-time
; alignment asserts; that build was retired under issue #69. The shipped
; mul_dma_lo/hi/carry live in LIB_X25519_DATA and are asserted page-aligned
; by libs/x25519/src/mul_stage.s:83-85.
; =============================================================================

.include "constants.inc"

; =============================================================================
; Exports - every label other ca65 modules may reference
; =============================================================================

; --- General I/O buffers ---
.export input_buffer
.export input_length

; --- BLAKE2s state ---
.export b2s_h
.export b2s_v
.export b2s_block
.export b2s_t
.export b2s_t1
.export b2s_f
.export b2s_buf_len
.export b2s_out_len
.export b2s_hash
.export b2s_tmp0
.export b2s_tmp1

; --- BLAKE2s HMAC working area ---
.export hmac_ipad
.export hmac_opad
.export hmac_inner_hash

; --- KDF working area ---
.export kdf_out1
.export kdf_out2
.export kdf_out3
.export kdf_prk
.export kdf_input_ptr
.export kdf_input_len

; --- HMAC input pointer/length ---
.export hmac_key_ptr
.export hmac_key_len
.export hmac_data_ptr
.export hmac_data_len

; --- ChaCha20 / Poly1305 / AEAD state ---
; Owned by c64-ChaCha20-Poly1305/src/lib/data_lib.s (the archive exports
; cc20_*, poly_*, aead_* at its own addresses, with cc20_work/cc20_keystream
; pinned to ZP $40 via the sibling's zp_config.s).

; --- fe25519 / X25519 / fe25519-mul support ---
; Owned by the c64-x25519 archive, in its own §4 segment LIB_X25519_DATA,
; which the cfgs route into LOADER with align = $100. fe_wide is ZP $40 in
; the sibling.

; --- Quarter-square table sqtab2_lo / sqtab2_hi ---
; DEAD DATA, kept deliberately. These were used only by the mult66
; micro-multiply in the retired in-tree src/crypto/fe25519.s (issue #69,
; 2026-10-18). The c64-x25519 sibling uses its own sqr_lo/sqr_hi and does
; NOT import sqtab2_*. They stay emitted solely so retiring the legacy
; build left the shipped PRGs byte-identical; removing them is a separate
; layout change (every later CRYPTO_RODATA/MAIN_AREA_LO byte moves).
.export sqtab2_lo
.export sqtab2_hi

; --- Handshake state ---
.export hs_c
.export hs_h
.export hs_static_priv
.export hs_static_pub
.export hs_resp_pub
.export hs_ephem_priv
.export hs_ephem_pub
.export hs_dh_result
.export hs_sender_idx
.export hs_timestamp
.export hs_mac1_key
.export hs_packet
.export hs_resp_packet
.export hs_transport_send
.export hs_transport_recv
.export hs_preshared_key
.export hs_mac1_valid

; --- Network buffers ---
.export zp_save_buf
.export udp_recv_buf
.export udp_recv_len
.export udp_recv_src_ip
.export udp_recv_src_port
.export udp_recv_ready
.export net_udp_dest_ip
.export net_udp_dest_port
.export wg_peer_ip
.export wg_peer_port
.export wg_local_port
.export net_initialized
.export boot_ready

; --- Transport state ---
.export tp_send_counter
.export tp_recv_counter
.export tp_recv_counter_tmp
.export tp_peer_recv_idx
.export tp_payload_ptr
.export tp_payload_len
.export tp_packet
.export tp_packet_len
.export tp_encrypt_error

; --- Replay window state ---
.export rw_bitmap
.export rw_counter_max
.export rw_bit_mask
.export rw_shift_lo
.export rw_shift_hi
.export rw_new_counter

; --- Session state ---
.export wg_state

; --- Configuration buffers ---
.export cfg_static_priv
.export cfg_static_pub
.export cfg_peer_pub
.export cfg_peer_endpoint_ip
.export cfg_peer_endpoint_port
.export cfg_preshared_key

; --- Tunnel config ---
.export tunnel_ip
.export ping_target_ip

; --- ICMP ---
.export ping_seq
.export ip_cksum_result

; --- Messaging ---
.export msg_port
.export msg_input_len
.export msg_recv_ptr
.export msg_recv_len

; --- IP packet buffer / header template ---
.export ip_packet_buf
.export ip_pkt_len
.export ip_hdr_template

; --- Cookie state ---
.export cookie_buf
.export cookie_nonce
.export cookie_valid

; --- Timer state ---
.export session_start_jiffy
.export last_send_jiffy
.export rekey_pending
.export hs_timer_armed

; --- TAI64N timestamp state ---
.export tai64n_base_time
.export tai64n_init_jiffy
.export tai64n_seq
.export tai64n_last
.export tai64n_init_base

; --- Disk I/O ---
.export config_filename
.export config_filename_len
.export disk_line_buf
.export disk_line_len


; =============================================================================
; CRYPTO_RODATA - constant lookup tables (read-only at runtime)
; =============================================================================
.segment "CRYPTO_RODATA"


; --- mult66 second quarter-square table ---
; sqtab2[0] = 0
; sqtab2[n] = floor((256-n)^2 / 4) - 1  for n=1..255
; The -1 compensates for carry being clear in the negative-difference path
;
; Dead since the in-tree fe25519.s was retired (issue #69); kept for PRG
; byte identity — see the export block above.
sqtab2_lo:
        .byte 0
        .repeat 255, i
                .byte <((((256-(i+1))*(256-(i+1)))/4) - 1)
        .endrepeat

sqtab2_hi:
        .byte 0
        .repeat 255, i
                .byte >((((256-(i+1))*(256-(i+1)))/4) - 1)
        .endrepeat


; Bit mask lookup (index 0-7 -> bit mask)
rw_bit_mask:
        .byte $01,$02,$04,$08,$10,$20,$40,$80


; =============================================================================
; APP_DATA - initialised application data (loaded with specific values,
;            but may be modified at runtime; linker treats as read-only in
;            terms of file layout, but the C64 has RAM here)
; =============================================================================
.segment "APP_DATA"

; --- IPv4 header template ---
ip_hdr_template:
        .byte $45               ; version=4, IHL=5
        .byte $00               ; DSCP/ECN
        .byte $00, $00          ; total length (filled per packet)
        .byte $00, $00          ; identification
        .byte $40, $00          ; flags: DF=1, frag offset=0
        .byte $40               ; TTL=64
        .byte $00               ; protocol (filled per packet)
        .byte $00, $00          ; header checksum (filled per packet)
        .byte $00,$00,$00,$00   ; src IP (filled per packet)
        .byte $00,$00,$00,$00   ; dst IP (filled per packet)

; --- Messaging default UDP port (9999, BIG-endian in memory) ---
; Initialised here because callers (ip_build) read msg_port directly without
; a runtime setup hook. ACME data.asm initialised it with !word $270f.
;
; BIG-endian is the convention, and it is the CONSUMERS' — not a claim made
; only by this comment. src/wg/ip_build.s copies byte 0 to the wire-FIRST
; byte of both UDP ports (msg_port -> ip_packet_buf+20/+22, msg_port+1 ->
; +21/+23, :296-305) and compares inbound the same way (:409-413), matching
; the UDP-length field's high-byte-at-lower-offset handling beside it. Every
; host tool that writes this word writes it big-endian too, and
; tools/test_ip65_rrnet_hw.py:2195 reads it back as int.from_bytes(..., "big").
;
; Issue #113: the ONE thing that disagreed was the default literal. ca65 emits
; `.word $270f` as $0F,$27 (low,high), so the untouched default reached the
; wire as $0F27 = 3879 while every document said 9999. The defect was the
; constant's byte order, NOT the copy — the copy agrees with the wire, with
; the inbound filter, with the MSG_PORT override and with every host tool, and
; is also the only side that would cost 6502 code to change.
;
; Fixed by giving the default the SAME `.byte >MSG_PORT, <MSG_PORT` form the
; override already used, so there is one code path and the byte order is
; written once. MSG_PORT reaches ca65 only when overridden (the Makefile omits
; -D at the default so an unadorned build stays byte-identical to a tree
; without the knob), so the default value is spelled here rather than made to
; depend on the flag being passed.
;
; This changes the default build's on-wire port from 3879 to 9999. Anyone who
; had configured a peer for 3879 BY OBSERVATION must move it to 9999.
.ifndef MSG_PORT
MSG_PORT = 9999
.endif
msg_port:
        .byte >MSG_PORT, <MSG_PORT

; --- Disk I/O ---
config_filename:
        .byte "WG.CFG"
config_filename_len = * - config_filename


; =============================================================================
; CRYPTO_BSS - uninitialised crypto scratch
; =============================================================================
.segment "CRYPTO_BSS"

; --- General input buffer (used by crypto drivers for assorted data) ---
input_buffer:
        .res 256, 0            ; general input buffer (max 255 bytes + length)

input_length:
        .res 1                 ; length of data in input_buffer

; --- BLAKE2s state (RFC 7693) ---
; hash state h[0..7] - 8 x 32-bit words = 32 bytes (little-endian)
b2s_h:
        .res 32, 0

; working vector v[0..15] - 16 x 32-bit words = 64 bytes
b2s_v:
        .res 64, 0

; message block m[0..15] - 16 x 32-bit words = 64 bytes
; (also used as block buffer for update)
b2s_block:
        .res 64, 0

; counter t[0..1] - 2 x 32-bit words = 8 bytes
b2s_t:
        .res 4, 0              ; t0 (low 32 bits of byte count)
b2s_t1:
        .res 4, 0              ; t1 (high 32 bits of byte count)

; finalization flag
b2s_f:
        .res 1                 ; 0 = not final, $FF = final block

; bytes buffered in current block
b2s_buf_len:
        .res 1

; output hash length (1-32); default 32. MUST be initialised because
; blake2s_init XORs this value into h[0] without writing it first, and
; hs_mix_hash calls blake2s_init without setting b2s_out_len. The ACME
; build declared this as `!byte 32` and relied on the PRG emitting the
; default byte. We replicate that here via `.byte 32` in APP_DATA.
.segment "APP_DATA"
b2s_out_len:
        .byte 32
.segment "CRYPTO_BSS"

; BLAKE2s output buffer (32 bytes)
b2s_hash:
        .res 32, 0

; --- BLAKE2s temporaries for G function ---
; 4 word32 temporaries for the G mixing function
b2s_tmp0:
        .res 4, 0
b2s_tmp1:
        .res 4, 0

; --- BLAKE2s HMAC working area ---
; HMAC needs inner/outer key pads (64 bytes each)
hmac_ipad:
        .res 64, 0
hmac_opad:
        .res 64, 0

; HMAC intermediate hash result
hmac_inner_hash:
        .res 32, 0

; --- KDF working area ---
; kdf_1/2/3 outputs (up to 3 x 32 bytes = 96 bytes)
kdf_out1:
        .res 32, 0
kdf_out2:
        .res 32, 0
kdf_out3:
        .res 32, 0

; HMAC key storage for KDF
kdf_prk:
        .res 32, 0

; --- KDF input pointer and length ---
kdf_input_ptr:
        .res 2                 ; pointer to KDF input data
kdf_input_len:
        .res 1                 ; length of KDF input data

; --- HMAC input pointer and length ---
hmac_key_ptr:
        .res 2                 ; pointer to HMAC key
hmac_key_len:
        .res 1                 ; HMAC key length
hmac_data_ptr:
        .res 2                 ; pointer to HMAC data
hmac_data_len:
        .res 1                 ; HMAC data length




; =============================================================================
; APP_BSS - uninitialised application state
; =============================================================================
.segment "APP_BSS"

; --- Handshake state ---
hs_c:
        .res 32, 0             ; chaining key
hs_h:
        .res 32, 0             ; hash
hs_static_priv:
        .res 32, 0             ; our static private key
hs_static_pub:
        .res 32, 0             ; our static public key
hs_resp_pub:
        .res 32, 0             ; responder's static public key
hs_ephem_priv:
        .res 32, 0             ; ephemeral private key
hs_ephem_pub:
        .res 32, 0             ; ephemeral public key
hs_dh_result:
        .res 32, 0             ; DH output (temp)
hs_sender_idx:
        .res 4, 0              ; sender index
hs_timestamp:
        .res 12, 0             ; TAI64N timestamp
hs_mac1_key:
        .res 32, 0             ; precomputed MAC1 key
hs_packet:
        .res 148, 0            ; outgoing Type 1 packet
hs_resp_packet:
        .res 92, 0             ; incoming Type 2 packet
hs_transport_send:
        .res 32, 0             ; transport send key
hs_transport_recv:
        .res 32, 0             ; transport recv key
hs_preshared_key:
        .res 32, 0             ; PSK for handshake (copied from cfg)
hs_mac1_valid:
        .res 1                 ; 1 = hs_packet+116 holds the MAC1 of an
                               ; initiation WE actually built (issue #94).
                               ; This is the equivalent of wireguard-go's
                               ; CookieChecker mac2.hasLastMAC1: a cookie
                               ; reply is AEAD-bound to that MAC1 as AAD, so
                               ; before the first initiation the AAD is a
                               ; value everybody knows. "Uninitialised" here
                               ; means "sixteen zero bytes when the program
                               ; starts", not "unpredictable" -- by ld65's
                               ; region fill where APP_BSS is plain
                               ; file-backed, and by boot.s's cold-segment
                               ; zero-fill where it is overlaid on
                               ; LIB_X25519_INIT_CODE (#107). Measured both
                               ; ways; the observable does not change.
                               ; Set once by hs_create_initiation; like
                               ; upstream's flag it is never cleared.

; --- Network buffers ---
zp_save_buf:
        .res 26, 0             ; ZP save area ($02-$1B)
udp_recv_buf:
        .res UDP_RECV_BUF_SIZE, 0   ; incoming UDP packet buffer (§13.8: >= NET_UDP_RECV_MAX)
udp_recv_len:
        .res 2                 ; length of received packet
udp_recv_src_ip:
        .res 4, 0              ; source IP of received packet
udp_recv_src_port:
        .res 2                 ; source port of received packet (big-endian)
udp_recv_ready:
        .res 1                 ; 0=no packet, 1=packet waiting
; --- §13.1 ABI-owned UDP destination -----------------------------------
; The backend reads THESE, not wg_peer_*. A network adapter reaching into
; the WireGuard session layer's own state is a layering inversion (§13.1):
; it makes the adapter unusable by any other consumer and ties the backend
; to this application's variable names. session_stage_dest copies the peer
; into these cells before each net_udp_send.
;
; Order is load-bearing: session_stage_dest copies ip+port as ONE 6-byte
; loop, and session.s carries link-time asserts that each port directly
; follows its ip. Do not insert anything between these four labels.
net_udp_dest_ip:
        .res 4, 0              ; destination IP, caller-set before net_udp_send
net_udp_dest_port:
        .res 2                 ; destination port, big-endian (as wg_peer_port)

wg_peer_ip:
        .res 4, 0              ; WireGuard peer IP address
wg_peer_port:
        .res 2                 ; WireGuard peer port (usually 51820)
wg_local_port:
        .res 2                 ; our listening port
net_initialized:
        .res 1                 ; 0=not initialized, 1=network ready
boot_ready:
        .res 1                 ; 0=boot in progress, 1=table build complete (issue #55)

; --- Transport state ---
tp_send_counter:
        .res 8, 0              ; 64-bit send counter (LE)
tp_recv_counter:
        .res 8, 0              ; next minimum accepted recv counter (LE)
tp_recv_counter_tmp:
        .res 8, 0              ; temp for incoming counter
tp_peer_recv_idx:
        .res 4, 0              ; peer's sender index
tp_payload_ptr:
        .res 2                 ; pointer to plaintext data
tp_payload_len:
        .res 2                 ; 16-bit payload length (up to 1500)
tp_packet:
        .res 1500, 0           ; Type 4 packet buffer (MTU-sized)
.assert WG_MTU + WG_DATA_OVERHEAD <= 1500, error, "tp_packet smaller than a full Type-4 datagram"
.assert NET_UDP_RECV_MAX <= 1500, error, "tp_packet smaller than the backend's NET_UDP_RECV_MAX"
tp_packet_len:
        .res 2                 ; total packet length
tp_encrypt_error:
        .res 1                 ; 1 = encrypt rejected (counter exhausted)

; --- Replay window state ---
rw_bitmap:
        .res 256, 0            ; 2048-bit sliding window bitmap
rw_counter_max:
        .res 8, 0              ; highest accepted counter (64-bit LE)

; Temporaries for replay window computation
rw_shift_lo:
        .res 1                 ; low byte of shift amount
rw_shift_hi:
        .res 1                 ; high byte of shift amount
rw_new_counter:
        .res 1                 ; flag: 1 = received > max (new high counter)

; --- Session state ---
wg_state:
        .res 1                 ; 0=IDLE, 1=HS_SENT, 2=ACTIVE

; --- Configuration buffers ---
cfg_static_priv:
        .res 32, 0             ; static private key
cfg_static_pub:
        .res 32, 0             ; static public key
cfg_peer_pub:
        .res 32, 0             ; peer's public key
cfg_peer_endpoint_ip:
        .res 4, 0              ; peer endpoint IP
cfg_peer_endpoint_port:
        .res 2                 ; peer endpoint port
cfg_preshared_key:
        .res 32, 0             ; PSK from config file (zeros = no PSK)

; --- Phase 7: Tunnel config ---
tunnel_ip:
        .res 4, 0              ; our tunnel IP address
ping_target_ip:
        .res 4, 0              ; ping target IP

; --- ICMP ---
ping_seq:
        .res 2                 ; ICMP echo sequence number
ip_cksum_result:
        .res 2                 ; IP checksum scratch

; --- Messaging (msg_port is in APP_DATA; remaining msg_* state is mutable) ---
; Sized from the tunnel MTU (constants.inc), never from literals: a message
; is text + 28 bytes of IP/UDP framing and the whole thing must fit in one
; Type-4 payload, so the packet buffer is exactly WG_MTU and the text is at
; most MSG_TEXT_MAX = WG_MTU - 28. All lengths are 16-bit (contract §13.3).
;
; THERE IS NO SEPARATE KEYBOARD BUFFER (issue #70). read_input_line types
; straight into ip_packet_buf + IP_UDP_HDR_LEN, i.e. where udp_tunnel_build
; would have copied the text to anyway; with source == destination that
; byte-forward copy is an identity and the 28-byte header is prepended in
; place. This is what makes a 1472-byte datagram fit: a private
; msg_input_buf of MSG_TEXT_MAX bytes overflowed APP_BSS by ~1 KB at
; WG_MTU = 1440. Nothing touches ip_packet_buf while a line is being typed
; (main_loop is blocked inside read_input_line), and the MSG_TEXT_MAX clamp
; in read_input_line keeps the text inside the WG_MTU-byte buffer.
msg_input_len:
        .res 2                 ; input length (16-bit)
msg_recv_ptr:
        .res 2                 ; pointer to received message text
msg_recv_len:
        .res 2                 ; received message length (16-bit)

; --- IP packet buffer ---
ip_packet_buf:
        .res WG_MTU, 0         ; outgoing IP packet (28 B headers + MSG_TEXT_MAX)
ip_pkt_len:
        .res 2                 ; IP packet length (16-bit)
.assert WG_MTU = IP_UDP_HDR_LEN + MSG_TEXT_MAX, error, "MSG_TEXT_MAX must be WG_MTU - IP_UDP_HDR_LEN: the text is typed in place inside ip_packet_buf"

; --- Cookie state ---
cookie_buf:
        .res 32, 0             ; decrypted cookie (16B used)
cookie_nonce:
        .res 24, 0             ; cookie nonce scratch
cookie_valid:
        .res 1                 ; 1 = valid cookie available

; --- Timer state ---
session_start_jiffy:
        .res 3, 0              ; session start time ($A0-$A2 format)
last_send_jiffy:
        .res 3, 0              ; last packet send time
rekey_pending:
        .res 1                 ; 1 = rekey initiated
hs_timer_armed:
        .res 1                 ; 1 = an initiation WE sent is being timed
                               ; (issue #84). Set by timer_handshake_start,
                               ; cleared by timer_session_start and
                               ; session_reset. Gating the handshake timeout
                               ; on this rather than on wg_state alone means
                               ; a caller that pokes wg_state = HS_SENT
                               ; directly — every VICE suite does — does not
                               ; get a deadline measured from a jiffy
                               ; snapshot nobody took.

; --- TAI64N timestamp state ---
tai64n_base_time:
        .res 8, 0              ; base Unix time from config (big-endian)
tai64n_init_jiffy:
        .res 3, 0              ; jiffy clock snapshot at tai64n_init
tai64n_seq:
        .res 4, 0              ; monotonic sub-second sequence counter (big-endian)
tai64n_last:
        .res 12, 0             ; last timestamp tai64n_now emitted (#87 guard);
                               ; zero at cold start only — tai64n_init keeps it
tai64n_init_base:
        .res 8, 0              ; tai64n_base_time as of the last tai64n_init;
                               ; tai64n_sync re-anchors only when it differs

; --- Disk I/O line buffer ---
disk_line_buf:
        .res 66, 0             ; line buffer for config reading
disk_line_len:
        .res 1                 ; current line length
