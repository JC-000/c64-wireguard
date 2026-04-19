; =============================================================================
; blake2s.s - BLAKE2s-256 hash function (RFC 7693)
;
; Little-endian 32-bit words, 64-byte blocks, 10 rounds
; Supports both keyed and unkeyed modes
;
; API:
;   blake2s_init      - Initialize state (A = output length, X = key length)
;                       Key data must be at input_buffer if X > 0
;   blake2s_update    - Process data (b2s_data_ptr/b2s_remain set by caller)
;   blake2s_final     - Finalize hash; output in b2s_hash
; =============================================================================

.include "constants.inc"

; --- Public entry points ---
.export blake2s_init
.export blake2s_update
.export blake2s_final
.export blake2s_hash_oneshot

; --- Shared constant tables (kept exported; no sibling lib, but other WG
;     modules may reference them in future) ---
.export blake2s_iv
.export blake2s_sigma

; --- word32 primitives (now in src/crypto/word32.s) ---
.import add32_to_dst
.import xor32_in_place
.import rotr32_16
.import rotr32_12
.import rotr32_8
.import rotr32_7

; --- External mutable state (defined in src/data.asm) ---
.import b2s_h
.import b2s_v
.import b2s_block
.import b2s_t
.import b2s_t1
.import b2s_f
.import b2s_buf_len
.import b2s_out_len
.import b2s_hash
.import input_buffer

; =============================================================================
; Constant tables (read-only)
; =============================================================================
.segment "CRYPTO_RODATA"

; --- BLAKE2s IV (RFC 7693 Section 2.6) ---
; SHA-256 fractional parts of square roots of first 8 primes
blake2s_iv:
        ; IV[0] = 0x6A09E667 (little-endian: 67 E6 09 6A)
        .byte $67, $e6, $09, $6a
        ; IV[1] = 0xBB67AE85
        .byte $85, $ae, $67, $bb
        ; IV[2] = 0x3C6EF372
        .byte $72, $f3, $6e, $3c
        ; IV[3] = 0xA54FF53A
        .byte $3a, $f5, $4f, $a5
        ; IV[4] = 0x510E527F
        .byte $7f, $52, $0e, $51
        ; IV[5] = 0x9B05688C
        .byte $8c, $68, $05, $9b
        ; IV[6] = 0x1F83D9AB
        .byte $ab, $d9, $83, $1f
        ; IV[7] = 0x5BE0CD19
        .byte $19, $cd, $e0, $5b

; --- BLAKE2s sigma permutation schedule (10 rounds x 16 entries) ---
; Each entry is an index 0-15 into the message block m[]
blake2s_sigma:
        ;        0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
        .byte    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15  ; round 0
        .byte   14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3  ; round 1
        .byte   11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4  ; round 2
        .byte    7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8  ; round 3
        .byte    9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13  ; round 4
        .byte    2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9  ; round 5
        .byte   12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11  ; round 6
        .byte   13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10  ; round 7
        .byte    6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5  ; round 8
        .byte   10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0  ; round 9

; --- G call indices: 8 calls x (a, b, c, d) ---
blake2s_g_indices:
        ; column step
        .byte  0,  4,  8, 12   ; G0
        .byte  1,  5,  9, 13   ; G1
        .byte  2,  6, 10, 14   ; G2
        .byte  3,  7, 11, 15   ; G3
        ; diagonal step
        .byte  0,  5, 10, 15   ; G4
        .byte  1,  6, 11, 12   ; G5
        .byte  2,  7,  8, 13   ; G6
        .byte  3,  4,  9, 14   ; G7

; =============================================================================
; Internal mutable state (uninitialised BSS)
; =============================================================================
.segment "CRYPTO_BSS"

b2s_copy_count:
        .res 1

; --- G function internal pointers ---
b2s_va_ptr:     .res 2
b2s_vb_ptr:     .res 2
b2s_vc_ptr:     .res 2
b2s_vd_ptr:     .res 2
b2s_mx_ptr:     .res 2
b2s_my_ptr:     .res 2

; =============================================================================
; Code
; =============================================================================
.segment "CRYPTO_CODE"

; =============================================================================
; blake2s_init - Initialize BLAKE2s state
;
; Input: b2s_out_len = output length (1-32), pre-set by caller
;        b2s_key_len = key length (0 = unkeyed, 1-32 = keyed), pre-set
;        If keyed, key data must already be at input_buffer
; =============================================================================
blake2s_init:
        ; zero counter and flags
        lda #0
        sta b2s_t
        sta b2s_t+1
        sta b2s_t+2
        sta b2s_t+3
        sta b2s_t1
        sta b2s_t1+1
        sta b2s_t1+2
        sta b2s_t1+3
        sta b2s_f
        sta b2s_buf_len

        ; h[0..7] = IV[0..7]
        ldx #31
:       lda blake2s_iv,x
        sta b2s_h,x
        dex
        bpl :-

        ; h[0] ^= 0x01010000 ^ (kk << 8) ^ nn
        ; In little-endian at b2s_h:
        ;   byte 0 (LSB) ^= nn (output length)
        ;   byte 1 ^= kk (key length)
        ;   byte 2 ^= 0x01
        ;   byte 3 ^= 0x01
        lda b2s_h
        eor b2s_out_len
        sta b2s_h
        lda b2s_h+1
        eor b2s_key_len
        sta b2s_h+1
        lda b2s_h+2
        eor #$01               ; fanout = 1
        sta b2s_h+2
        lda b2s_h+3
        eor #$01               ; depth = 1
        sta b2s_h+3

        ; if keyed, process key as first block (padded with zeros)
        lda b2s_key_len
        beq @init_done

        ; copy key to block buffer, zero-pad to 64 bytes
        ldx #63
        lda #0
:       sta b2s_block,x
        dex
        bpl :-

        ldx #0
        ldy b2s_key_len
:       lda input_buffer,x
        sta b2s_block,x
        inx
        dey
        bne :-

        ; mark block as full (64 bytes buffered)
        lda #64
        sta b2s_buf_len

@init_done:
        rts

; =============================================================================
; blake2s_update - Feed data into BLAKE2s
;
; Input: b2s_data_ptr = pointer to data
;        b2s_remain   = number of bytes to process (0-255)
;
; If the block buffer becomes full AND there's more data, compress it.
; Always keep the last block in the buffer for finalization.
; =============================================================================
blake2s_update:
@loop_top:
        lda b2s_remain
        bne @has_data
        rts                    ; nothing to do

@has_data:
        ; if buffer is full and we have new data, compress first
        lda b2s_buf_len
        cmp #64
        bne @fill_buf

        ; compress current full block (not final)
        jsr blake2s_increment_counter
        jsr blake2s_compress
        lda #0
        sta b2s_buf_len

@fill_buf:
        ; bytes to copy = min(remain, 64 - buf_len)
        lda #64
        sec
        sbc b2s_buf_len        ; A = space in buffer
        cmp b2s_remain
        bcc :+                 ; if space < remain, use space
        lda b2s_remain         ; otherwise use remain
:
        ; A = bytes to copy
        sta b2s_copy_count
        beq @loop_top

        ; copy from (b2s_data_ptr) to b2s_block+buf_len
        ldy #0                 ; source index
        ldx b2s_buf_len        ; dest index
@copy:
        lda (b2s_data_ptr),y
        sta b2s_block,x
        iny
        inx
        dec b2s_copy_count
        bne @copy

        ; update buf_len
        stx b2s_buf_len

        ; advance data_ptr by Y bytes
        tya
        clc
        adc b2s_data_ptr
        sta b2s_data_ptr
        bcc :+
        inc b2s_data_ptr+1
:
        ; remain -= bytes copied
        tya
        sta zp_tmp1
        lda b2s_remain
        sec
        sbc zp_tmp1
        sta b2s_remain

        ; loop if more data
        jmp @loop_top

; =============================================================================
; blake2s_final - Finalize BLAKE2s hash
;
; Pads remaining block with zeros, sets final flag, compresses.
; Output goes to b2s_hash (b2s_out_len bytes).
; =============================================================================
blake2s_final:
        ; increment counter by buf_len
        jsr blake2s_increment_counter

        ; zero-pad block from buf_len to 64
        ldx b2s_buf_len
        cpx #64
        beq @no_pad
        lda #0
:       sta b2s_block,x
        inx
        cpx #64
        bne :-
@no_pad:

        ; set final flag
        lda #$ff
        sta b2s_f

        ; compress final block
        jsr blake2s_compress

        ; copy h[0..out_len-1] to b2s_hash
        ldx #0
        ldy b2s_out_len
:       lda b2s_h,x
        sta b2s_hash,x
        inx
        dey
        bne :-

        rts

; =============================================================================
; blake2s_increment_counter - Add buf_len to 64-bit counter t
; =============================================================================
blake2s_increment_counter:
        clc
        lda b2s_t
        adc b2s_buf_len
        sta b2s_t
        lda b2s_t+1
        adc #0
        sta b2s_t+1
        lda b2s_t+2
        adc #0
        sta b2s_t+2
        lda b2s_t+3
        adc #0
        sta b2s_t+3
        ; carry into t1
        lda b2s_t1
        adc #0
        sta b2s_t1
        lda b2s_t1+1
        adc #0
        sta b2s_t1+1
        lda b2s_t1+2
        adc #0
        sta b2s_t1+2
        lda b2s_t1+3
        adc #0
        sta b2s_t1+3
        rts

; =============================================================================
; blake2s_compress - BLAKE2s compression function
;
; Initialize working vector v[0..15], run 10 rounds of mixing,
; then XOR v[0..7] ^ v[8..15] into h[0..7].
; =============================================================================
blake2s_compress:
        ; v[0..7] = h[0..7]
        ldx #31
:       lda b2s_h,x
        sta b2s_v,x
        dex
        bpl :-

        ; v[8..11] = IV[0..3]
        ldx #0
:       lda blake2s_iv,x
        sta b2s_v+32,x
        inx
        cpx #16
        bne :-

        ; v[12] = IV[4] ^ t0
        ldx #0
:       lda blake2s_iv+16,x
        eor b2s_t,x
        sta b2s_v+48,x
        inx
        cpx #4
        bne :-

        ; v[13] = IV[5] ^ t1
        ldx #0
:       lda blake2s_iv+20,x
        eor b2s_t1,x
        sta b2s_v+52,x
        inx
        cpx #4
        bne :-

        ; v[14] = IV[6] ^ f0 (f0 = 0x00000000 or 0xFFFFFFFF)
        lda b2s_f
        sta zp_tmp1            ; 0 or $FF
        ldx #0
:       lda blake2s_iv+24,x
        eor zp_tmp1
        sta b2s_v+56,x
        inx
        cpx #4
        bne :-

        ; v[15] = IV[7] ^ f1 (f1 = 0, no last-node flag)
        ldx #0
:       lda blake2s_iv+28,x
        sta b2s_v+60,x
        inx
        cpx #4
        bne :-

        ; --- 10 rounds of mixing ---
        lda #0
        sta b2s_round
@round_loop:
        ; compute sigma table offset for this round
        lda b2s_round
        asl
        asl
        asl
        asl                    ; * 16
        sta b2s_i              ; sigma base offset

        ; Column step:
        ; G(v, 0, 4,  8, 12, m[sigma[0]],  m[sigma[1]])
        ; G(v, 1, 5,  9, 13, m[sigma[2]],  m[sigma[3]])
        ; G(v, 2, 6, 10, 14, m[sigma[4]],  m[sigma[5]])
        ; G(v, 3, 7, 11, 15, m[sigma[6]],  m[sigma[7]])
        ;
        ; Diagonal step:
        ; G(v, 0, 5, 10, 15, m[sigma[8]],  m[sigma[9]])
        ; G(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]])
        ; G(v, 2, 7,  8, 13, m[sigma[12]], m[sigma[13]])
        ; G(v, 3, 4,  9, 14, m[sigma[14]], m[sigma[15]])

        ; We encode each G call's (a,b,c,d) indices and sigma offsets
        ; Use a lookup table for the 8 G calls per round

        ldx #0                 ; G call index (0-7)
@g_loop:
        stx b2s_offset         ; save G call index

        ; get a,b,c,d indices from table
        txa
        asl
        asl                    ; * 4
        tay

        ; set up v[a], v[b], v[c], v[d] pointers
        ; each v element = 4 bytes, so v[i] is at b2s_v + i*4
        lda blake2s_g_indices,y
        asl
        asl                    ; * 4
        clc
        adc #<b2s_v
        sta b2s_va_ptr
        lda #>b2s_v
        adc #0
        sta b2s_va_ptr+1

        lda blake2s_g_indices+1,y
        asl
        asl
        clc
        adc #<b2s_v
        sta b2s_vb_ptr
        lda #>b2s_v
        adc #0
        sta b2s_vb_ptr+1

        lda blake2s_g_indices+2,y
        asl
        asl
        clc
        adc #<b2s_v
        sta b2s_vc_ptr
        lda #>b2s_v
        adc #0
        sta b2s_vc_ptr+1

        lda blake2s_g_indices+3,y
        asl
        asl
        clc
        adc #<b2s_v
        sta b2s_vd_ptr
        lda #>b2s_v
        adc #0
        sta b2s_vd_ptr+1

        ; get sigma indices for x and y (2 per G call)
        lda b2s_offset         ; G call index
        asl                    ; * 2
        clc
        adc b2s_i              ; + round's sigma base
        tay

        ; x = m[sigma[2*g]]
        lda blake2s_sigma,y
        asl
        asl                    ; * 4 (word offset in block)
        clc
        adc #<b2s_block
        sta b2s_mx_ptr
        lda #>b2s_block
        adc #0
        sta b2s_mx_ptr+1

        ; y = m[sigma[2*g+1]]
        iny
        lda blake2s_sigma,y
        asl
        asl
        clc
        adc #<b2s_block
        sta b2s_my_ptr
        lda #>b2s_block
        adc #0
        sta b2s_my_ptr+1

        ; call G mixing function
        jsr blake2s_g

        ldx b2s_offset
        inx
        cpx #8
        beq :+
        jmp @g_loop
:
        ; next round
        inc b2s_round
        lda b2s_round
        cmp #blake2s_rounds
        beq :+
        jmp @round_loop
:

        ; --- XOR v[0..7] ^ v[8..15] into h[0..7] ---
        ldx #31
:       lda b2s_h,x
        eor b2s_v,x
        eor b2s_v+32,x
        sta b2s_h,x
        dex
        bpl :-

        rts

; =============================================================================
; blake2s_g - G mixing function
;
; Uses pointers set up by blake2s_compress:
;   b2s_va_ptr, b2s_vb_ptr, b2s_vc_ptr, b2s_vd_ptr = v[a], v[b], v[c], v[d]
;   b2s_mx_ptr, b2s_my_ptr = m[x], m[y]
;
; G(a, b, c, d, x, y):
;   a = a + b + x
;   d = (d ^ a) >>> 16
;   c = c + d
;   b = (b ^ c) >>> 12
;   a = a + b + y
;   d = (d ^ a) >>> 8
;   c = c + d
;   b = (b ^ c) >>> 7
; =============================================================================
blake2s_g:
        ; --- Step 1: a = a + b + x ---
        lda b2s_va_ptr
        sta w32_dst
        lda b2s_va_ptr+1
        sta w32_dst+1
        lda b2s_vb_ptr
        sta w32_src1
        lda b2s_vb_ptr+1
        sta w32_src1+1
        jsr add32_to_dst       ; a += b

        lda b2s_mx_ptr
        sta w32_src1
        lda b2s_mx_ptr+1
        sta w32_src1+1
        lda b2s_va_ptr
        sta w32_dst
        lda b2s_va_ptr+1
        sta w32_dst+1
        jsr add32_to_dst       ; a += x

        ; --- Step 2: d = (d ^ a) >>> 16 ---
        lda b2s_vd_ptr
        sta w32_dst
        lda b2s_vd_ptr+1
        sta w32_dst+1
        lda b2s_va_ptr
        sta w32_src1
        lda b2s_va_ptr+1
        sta w32_src1+1
        jsr xor32_in_place     ; d ^= a
        jsr rotr32_16          ; d >>>= 16

        ; --- Step 3: c = c + d ---
        lda b2s_vc_ptr
        sta w32_dst
        lda b2s_vc_ptr+1
        sta w32_dst+1
        lda b2s_vd_ptr
        sta w32_src1
        lda b2s_vd_ptr+1
        sta w32_src1+1
        jsr add32_to_dst       ; c += d

        ; --- Step 4: b = (b ^ c) >>> 12 ---
        lda b2s_vb_ptr
        sta w32_dst
        lda b2s_vb_ptr+1
        sta w32_dst+1
        lda b2s_vc_ptr
        sta w32_src1
        lda b2s_vc_ptr+1
        sta w32_src1+1
        jsr xor32_in_place     ; b ^= c
        jsr rotr32_12          ; b >>>= 12

        ; --- Step 5: a = a + b + y ---
        lda b2s_va_ptr
        sta w32_dst
        lda b2s_va_ptr+1
        sta w32_dst+1
        lda b2s_vb_ptr
        sta w32_src1
        lda b2s_vb_ptr+1
        sta w32_src1+1
        jsr add32_to_dst       ; a += b

        lda b2s_my_ptr
        sta w32_src1
        lda b2s_my_ptr+1
        sta w32_src1+1
        lda b2s_va_ptr
        sta w32_dst
        lda b2s_va_ptr+1
        sta w32_dst+1
        jsr add32_to_dst       ; a += y

        ; --- Step 6: d = (d ^ a) >>> 8 ---
        lda b2s_vd_ptr
        sta w32_dst
        lda b2s_vd_ptr+1
        sta w32_dst+1
        lda b2s_va_ptr
        sta w32_src1
        lda b2s_va_ptr+1
        sta w32_src1+1
        jsr xor32_in_place     ; d ^= a
        jsr rotr32_8           ; d >>>= 8

        ; --- Step 7: c = c + d ---
        lda b2s_vc_ptr
        sta w32_dst
        lda b2s_vc_ptr+1
        sta w32_dst+1
        lda b2s_vd_ptr
        sta w32_src1
        lda b2s_vd_ptr+1
        sta w32_src1+1
        jsr add32_to_dst       ; c += d

        ; --- Step 8: b = (b ^ c) >>> 7 ---
        lda b2s_vb_ptr
        sta w32_dst
        lda b2s_vb_ptr+1
        sta w32_dst+1
        lda b2s_vc_ptr
        sta w32_src1
        lda b2s_vc_ptr+1
        sta w32_src1+1
        jsr xor32_in_place     ; b ^= c
        jsr rotr32_7           ; b >>>= 7

        rts

; =============================================================================
; blake2s_hash_oneshot - Hash a single message
;
; Input: b2s_data_ptr = pointer to data
;        b2s_remain   = byte count
;        A = output length (1-32)
; Output: b2s_hash (A bytes)
; =============================================================================
blake2s_hash_oneshot:
        sta b2s_out_len
        lda #0
        sta b2s_key_len
        jsr blake2s_init
        jsr blake2s_update
        jsr blake2s_final
        rts
