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
