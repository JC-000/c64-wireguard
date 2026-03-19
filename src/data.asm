; =============================================================================
; data.asm - Mutable buffers and working data
; =============================================================================

; --- General I/O buffers ---
input_buffer:
        !fill 256, 0           ; general input buffer (max 255 bytes + length)

input_length:
        !byte 0                ; length of data in input_buffer

; --- BLAKE2s state (RFC 7693) ---
; hash state h[0..7] - 8 x 32-bit words = 32 bytes (little-endian)
b2s_h:
        !fill 32, 0

; working vector v[0..15] - 16 x 32-bit words = 64 bytes
b2s_v:
        !fill 64, 0

; message block m[0..15] - 16 x 32-bit words = 64 bytes
; (also used as block buffer for update)
b2s_block:
        !fill 64, 0

; counter t[0..1] - 2 x 32-bit words = 8 bytes
b2s_t:
        !fill 4, 0             ; t0 (low 32 bits of byte count)
b2s_t1:
        !fill 4, 0             ; t1 (high 32 bits of byte count)

; finalization flag
b2s_f:
        !byte 0                ; 0 = not final, $FF = final block

; bytes buffered in current block
b2s_buf_len:
        !byte 0

; output hash length (1-32)
b2s_out_len:
        !byte 32               ; default 32 bytes

; BLAKE2s output buffer (32 bytes)
b2s_hash:
        !fill 32, 0

; --- BLAKE2s temporaries for G function ---
; 4 word32 temporaries for the G mixing function
b2s_tmp0:
        !fill 4, 0
b2s_tmp1:
        !fill 4, 0

; --- BLAKE2s HMAC working area ---
; HMAC needs inner/outer key pads (64 bytes each)
hmac_ipad:
        !fill 64, 0
hmac_opad:
        !fill 64, 0

; HMAC intermediate hash result
hmac_inner_hash:
        !fill 32, 0

; --- KDF working area ---
; kdf_1/2/3 outputs (up to 3 x 32 bytes = 96 bytes)
kdf_out1:
        !fill 32, 0
kdf_out2:
        !fill 32, 0
kdf_out3:
        !fill 32, 0

; HMAC key storage for KDF
kdf_prk:
        !fill 32, 0

; --- KDF input pointer and length ---
kdf_input_ptr:
        !word 0                ; pointer to KDF input data
kdf_input_len:
        !byte 0                ; length of KDF input data

; --- HMAC input pointer and length ---
hmac_key_ptr:
        !word 0                ; pointer to HMAC key
hmac_key_len:
        !byte 0                ; HMAC key length
hmac_data_ptr:
        !word 0                ; pointer to HMAC data
hmac_data_len:
        !byte 0                ; HMAC data length

; --- ChaCha20 state (RFC 7539) ---
; Initial state: 16 x 32-bit words = 64 bytes
cc20_state:
        !fill 64, 0

; Working state during block computation
cc20_work:
        !fill 64, 0

; Generated keystream for XOR
cc20_keystream:
        !fill 64, 0

; 256-bit key
cc20_key:
        !fill 32, 0

; 96-bit nonce
cc20_nonce:
        !fill 12, 0

; 32-bit block counter
cc20_counter:
        !fill 4, 0

; --- Poly1305 state ---
; 130-bit accumulator (17 bytes for carry room)
poly_h:
        !fill 17, 0

; Clamped key part r (16 bytes)
poly_r:
        !fill 16, 0

; Key part s (added at end)
poly_s:
        !fill 16, 0

; Multiplication scratch (33 bytes for 17x16 product)
poly_product:
        !fill 33, 0

; Output tag (16 bytes)
poly1305_tag:
        !fill 16, 0

; --- AEAD state ---
aead_key:
        !fill 32, 0
aead_nonce:
        !fill 12, 0
aead_aad_ptr:
        !word 0
aead_aad_len:
        !byte 0
aead_data_ptr:
        !word 0
aead_data_len:
        !byte 0
aead_tag:
        !fill 16, 0

; Poly1305 padding/length block scratch (16 bytes)
aead_scratch:
        !fill 16, 0

; --- fe25519 field arithmetic ---
fe_wide:
        !fill 64, 0            ; 512-bit product from multiply
fe_tmp1:
        !fill 32, 0            ; temporary field element 1
fe_tmp2:
        !fill 32, 0            ; temporary field element 2
fe_tmp3:
        !fill 32, 0            ; temporary field element 3
fe_tmp4:
        !fill 32, 0            ; temporary field element 4

; p = 2^255 - 19 in little-endian
fe_p:
        !byte $ed
        !fill 30, $ff
        !byte $7f

; --- X25519 state ---
x25_scalar:
        !fill 32, 0            ; clamped scalar
x25_u:
        !fill 32, 0            ; input u-coordinate
x25_result:
        !fill 32, 0            ; output u-coordinate
x25_x2:
        !fill 32, 0            ; Montgomery ladder state
x25_z2:
        !fill 32, 0
x25_x3:
        !fill 32, 0
x25_z3:
        !fill 32, 0
x25_a:
        !fill 32, 0            ; ladder temporaries
x25_b:
        !fill 32, 0
x25_da:
        !fill 32, 0
x25_cb:
        !fill 32, 0
x25_e:
        !fill 32, 0
x25_basepoint:
        !byte 9
        !fill 31, 0

; --- Handshake state ---
hs_c:
        !fill 32, 0            ; chaining key
hs_h:
        !fill 32, 0            ; hash
hs_static_priv:
        !fill 32, 0            ; our static private key
hs_static_pub:
        !fill 32, 0            ; our static public key
hs_resp_pub:
        !fill 32, 0            ; responder's static public key
hs_ephem_priv:
        !fill 32, 0            ; ephemeral private key
hs_ephem_pub:
        !fill 32, 0            ; ephemeral public key
hs_dh_result:
        !fill 32, 0            ; DH output (temp)
hs_sender_idx:
        !fill 4, 0             ; sender index
hs_timestamp:
        !fill 12, 0            ; TAI64N timestamp
hs_mac1_key:
        !fill 32, 0            ; precomputed MAC1 key
hs_packet:
        !fill 148, 0           ; outgoing Type 1 packet
hs_resp_packet:
        !fill 92, 0            ; incoming Type 2 packet
hs_transport_send:
        !fill 32, 0            ; transport send key
hs_transport_recv:
        !fill 32, 0            ; transport recv key
hs_preshared_key:
        !fill 32, 0            ; PSK for handshake (copied from cfg)

; --- Network buffers ---
zp_save_buf:
        !fill 26, 0            ; ZP save area ($02-$1B)
udp_recv_buf:
        !fill 256, 0           ; incoming UDP packet buffer
udp_recv_len:
        !word 0                ; length of received packet
udp_recv_src_ip:
        !fill 4, 0             ; source IP of received packet
udp_recv_ready:
        !byte 0                ; 0=no packet, 1=packet waiting
wg_peer_ip:
        !fill 4, 0             ; WireGuard peer IP address
wg_peer_port:
        !word 0                ; WireGuard peer port (usually 51820)
wg_local_port:
        !word 0                ; our listening port
net_initialized:
        !byte 0                ; 0=not initialized, 1=network ready

; --- Transport state ---
tp_send_counter:
        !fill 8, 0             ; 64-bit send counter (LE)
tp_recv_counter:
        !fill 8, 0             ; next minimum accepted recv counter (LE)
tp_recv_counter_tmp:
        !fill 8, 0             ; temp for incoming counter
tp_peer_recv_idx:
        !fill 4, 0             ; peer's sender index
tp_payload_ptr:
        !word 0                ; pointer to plaintext data
tp_payload_len:
        !byte 0                ; payload length (max ~220)
tp_packet:
        !fill 256, 0           ; Type 4 packet buffer
tp_packet_len:
        !word 0                ; total packet length
tp_encrypt_error:
        !byte 0                ; 1 = encrypt rejected (counter exhausted)

; --- Session state ---
wg_state:
        !byte 0                 ; 0=IDLE, 1=HS_SENT, 2=ACTIVE

; --- Configuration buffers ---
cfg_static_priv:
        !fill 32, 0             ; static private key
cfg_static_pub:
        !fill 32, 0             ; static public key
cfg_peer_pub:
        !fill 32, 0             ; peer's public key
cfg_peer_endpoint_ip:
        !fill 4, 0              ; peer endpoint IP
cfg_peer_endpoint_port:
        !word 0                 ; peer endpoint port
cfg_preshared_key:
        !fill 32, 0            ; PSK from config file (zeros = no PSK)

; --- Phase 7: Tunnel config ---
tunnel_ip:
        !fill 4, 0              ; our tunnel IP address
ping_target_ip:
        !fill 4, 0              ; ping target IP

; --- ICMP ---
ping_seq:
        !word 0                  ; ICMP echo sequence number
ip_cksum_result:
        !word 0                  ; IP checksum scratch

; --- Messaging ---
msg_port:
        !word $270f              ; message UDP port (9999, big-endian)
msg_input_buf:
        !fill 40, 0             ; keyboard input buffer
msg_input_len:
        !byte 0                 ; input length
msg_recv_ptr:
        !word 0                  ; pointer to received message text
msg_recv_len:
        !byte 0                 ; received message length

; --- IP packet buffer ---
ip_packet_buf:
        !fill 80, 0             ; outgoing IP packet
ip_pkt_len:
        !byte 0                 ; IP packet length

; --- IPv4 header template ---
ip_hdr_template:
        !byte $45               ; version=4, IHL=5
        !byte $00               ; DSCP/ECN
        !byte $00, $00          ; total length (filled per packet)
        !byte $00, $00          ; identification
        !byte $40, $00          ; flags: DF=1, frag offset=0
        !byte $40               ; TTL=64
        !byte $00               ; protocol (filled per packet)
        !byte $00, $00          ; header checksum (filled per packet)
        !byte $00,$00,$00,$00   ; src IP (filled per packet)
        !byte $00,$00,$00,$00   ; dst IP (filled per packet)

; --- Cookie state ---
cookie_buf:
        !fill 32, 0             ; decrypted cookie (16B used)
cookie_nonce:
        !fill 24, 0             ; cookie nonce scratch
cookie_valid:
        !byte 0                 ; 1 = valid cookie available

; --- Timer state ---
session_start_jiffy:
        !fill 3, 0              ; session start time ($A0-$A2 format)
last_send_jiffy:
        !fill 3, 0              ; last packet send time
rekey_pending:
        !byte 0                 ; 1 = rekey initiated

; --- Disk I/O ---
config_filename:
        !text "WG.CFG"
config_filename_len = * - config_filename
disk_line_buf:
        !fill 66, 0             ; line buffer for config reading
disk_line_len:
        !byte 0                 ; current line length
