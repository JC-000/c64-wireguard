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
;   CRYPTO_RODATA : constant lookup tables (fe_p prime, sqtab2_lo/hi,
;                   mul38_lo/hi_tab, x25_basepoint, rw_bit_mask)
;   APP_DATA      : initialised application data (msg_port, ip_hdr_template,
;                   config_filename, b2s_out_len default)
;   CRYPTO_BSS    : uninitialised crypto scratch (cc20_*, poly_*, b2s_*,
;                   aead_*, fe_*, x25_*, mul_*, kdf_*, hmac_*, input_buffer)
;   APP_BSS       : uninitialised app state (hs_*, tp_*, wg_*, cfg_*,
;                   cookie_*, udp_*, rw_*, tunnel/ping/msg/disk/net state)
;
; Page-aligned buffers:
;   mul_dma_lo / mul_dma_hi : MUST be page-aligned; REU DMA targets used
;   with absolute,Y lookups where #<buf is assumed to be zero.
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

; --- ChaCha20 state ---
.export cc20_state
.export cc20_work
.export cc20_keystream
.export cc20_key
.export cc20_nonce
.export cc20_counter
.export cc20_remain_hi

; --- Poly1305 state ---
.export poly_h
.export poly_r
.export poly_s
.export poly_product
.export poly1305_tag

; --- AEAD state ---
.export aead_key
.export aead_nonce
.export aead_aad_ptr
.export aead_aad_len
.export aead_data_ptr
.export aead_data_len
.export aead_tag
.export aead_scratch

; --- fe25519 field arithmetic ---
.export fe_wide
.export fe_tmp1
.export fe_tmp2
.export fe_tmp3
.export fe_tmp4
.export fe_p

; --- Squaring / multiplication support ---
.export mul_src2_buf
.export mul_cached_a
.export mul_dma_lo
.export mul_dma_hi
.export sqtab2_lo
.export sqtab2_hi
.export mul38_lo_tab
.export mul38_hi_tab

; --- X25519 state ---
.export x25_scalar
.export x25_u
.export x25_result
.export x25_x2
.export x25_z2
.export x25_x3
.export x25_z3
.export x25_a
.export x25_b
.export x25_da
.export x25_cb
.export x25_e
.export x25_basepoint

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

; --- Network buffers ---
.export zp_save_buf
.export udp_recv_buf
.export udp_recv_len
.export udp_recv_src_ip
.export udp_recv_src_port
.export udp_recv_ready
.export wg_peer_ip
.export wg_peer_port
.export wg_local_port
.export net_initialized

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
.export msg_input_buf
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

; --- TAI64N timestamp state ---
.export tai64n_base_time
.export tai64n_init_jiffy
.export tai64n_seq

; --- Disk I/O ---
.export config_filename
.export config_filename_len
.export disk_line_buf
.export disk_line_len


; =============================================================================
; CRYPTO_RODATA - constant lookup tables (read-only at runtime)
; =============================================================================
.segment "CRYPTO_RODATA"

; p = 2^255 - 19 in little-endian
fe_p:
        .byte $ed
        .res 30, $ff
        .byte $7f

; --- mult66 second quarter-square table ---
; sqtab2[0] = 0
; sqtab2[n] = floor((256-n)^2 / 4) - 1  for n=1..255
; The -1 compensates for carry being clear in the negative-difference path
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

; --- mul_by_38 lookup tables ---
; mul38_lo_tab[i] = low byte of (i * 38)
; mul38_hi_tab[i] = high byte of (i * 38)
mul38_lo_tab:
        .byte 0
        .repeat 255, i
                .byte <((i+1) * 38)
        .endrepeat

mul38_hi_tab:
        .byte 0
        .repeat 255, i
                .byte >((i+1) * 38)
        .endrepeat

; X25519 generator (constant): u = 9
x25_basepoint:
        .byte 9
        .res 31, 0

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

; --- Messaging default UDP port ($270f = 9999, big-endian in memory) ---
; Initialised here because callers (ip_build) read msg_port directly without
; a runtime setup hook. ACME data.asm initialised it with !word $270f.
msg_port:
        .word $270f

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

; --- ChaCha20 state (RFC 7539) ---
; Initial state: 16 x 32-bit words = 64 bytes
cc20_state:
        .res 64, 0

; Working state during block computation
cc20_work:
        .res 64, 0

; Generated keystream for XOR
cc20_keystream:
        .res 64, 0

; 256-bit key
cc20_key:
        .res 32, 0

; 96-bit nonce
cc20_nonce:
        .res 12, 0

; 32-bit block counter
cc20_counter:
        .res 4, 0

; High byte of cc20_remain for 16-bit length support
cc20_remain_hi:
        .res 1

; --- Poly1305 state ---
; 130-bit accumulator (17 bytes for carry room)
poly_h:
        .res 17, 0

; Clamped key part r (16 bytes)
poly_r:
        .res 16, 0

; Key part s (added at end)
poly_s:
        .res 16, 0

; Multiplication scratch (33 bytes for 17x16 product)
poly_product:
        .res 33, 0

; Output tag (16 bytes)
poly1305_tag:
        .res 16, 0

; --- AEAD state ---
aead_key:
        .res 32, 0
aead_nonce:
        .res 12, 0
aead_aad_ptr:
        .res 2
aead_aad_len:
        .res 1
aead_data_ptr:
        .res 2
aead_data_len:
        .res 2                 ; 16-bit data length for MTU up to 1500
aead_tag:
        .res 16, 0

; Poly1305 padding/length block scratch (16 bytes)
aead_scratch:
        .res 16, 0

; --- fe25519 field arithmetic ---
fe_wide:
        .res 64, 0             ; 512-bit product from multiply
fe_tmp1:
        .res 32, 0             ; temporary field element 1
fe_tmp2:
        .res 32, 0             ; temporary field element 2
fe_tmp3:
        .res 32, 0             ; temporary field element 3
fe_tmp4:
        .res 32, 0             ; temporary field element 4

; --- Squaring support buffers ---
mul_src2_buf:
        .res 32, 0             ; absolute copy of src for fast indexed access
mul_cached_a:
        .res 1                 ; cached a[i] for inner loop

; --- REU DMA target buffers (page-aligned for LDA abs,Y without penalty) ---
; The inner product lookups `lda mul_dma_lo,y` / `lda mul_dma_hi,y` assume
; these start on page boundaries (low byte = 0).
.align 256
mul_dma_lo:
        .res 256, 0            ; DMA target: lo bytes of a*b for current a
mul_dma_hi:
        .res 256, 0            ; DMA target: hi bytes of a*b for current a

; --- X25519 state (mutable ladder working buffers) ---
x25_scalar:
        .res 32, 0             ; clamped scalar
x25_u:
        .res 32, 0             ; input u-coordinate
x25_result:
        .res 32, 0             ; output u-coordinate
x25_x2:
        .res 32, 0             ; Montgomery ladder state
x25_z2:
        .res 32, 0
x25_x3:
        .res 32, 0
x25_z3:
        .res 32, 0
x25_a:
        .res 32, 0             ; ladder temporaries
x25_b:
        .res 32, 0
x25_da:
        .res 32, 0
x25_cb:
        .res 32, 0
x25_e:
        .res 32, 0


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

; --- Network buffers ---
zp_save_buf:
        .res 26, 0             ; ZP save area ($02-$1B)
udp_recv_buf:
        .res 1500, 0           ; incoming UDP packet buffer (MTU-sized)
udp_recv_len:
        .res 2                 ; length of received packet
udp_recv_src_ip:
        .res 4, 0              ; source IP of received packet
udp_recv_src_port:
        .res 2                 ; source port of received packet (big-endian)
udp_recv_ready:
        .res 1                 ; 0=no packet, 1=packet waiting
wg_peer_ip:
        .res 4, 0              ; WireGuard peer IP address
wg_peer_port:
        .res 2                 ; WireGuard peer port (usually 51820)
wg_local_port:
        .res 2                 ; our listening port
net_initialized:
        .res 1                 ; 0=not initialized, 1=network ready

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
msg_input_buf:
        .res 40, 0             ; keyboard input buffer
msg_input_len:
        .res 1                 ; input length
msg_recv_ptr:
        .res 2                 ; pointer to received message text
msg_recv_len:
        .res 1                 ; received message length

; --- IP packet buffer ---
ip_packet_buf:
        .res 80, 0             ; outgoing IP packet
ip_pkt_len:
        .res 1                 ; IP packet length

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

; --- TAI64N timestamp state ---
tai64n_base_time:
        .res 8, 0              ; base Unix time from config (big-endian)
tai64n_init_jiffy:
        .res 3, 0              ; jiffy clock snapshot at tai64n_init
tai64n_seq:
        .res 4, 0              ; monotonic sub-second sequence counter (big-endian)

; --- Disk I/O line buffer ---
disk_line_buf:
        .res 66, 0             ; line buffer for config reading
disk_line_len:
        .res 1                 ; current line length
