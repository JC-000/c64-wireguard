; =============================================================================
; chacha20.asm - ChaCha20 stream cipher (RFC 7539/8439)
;
; State layout: 16 x 32-bit words = 64 bytes (little-endian)
;   words[0-3]   = "expand 32-byte k" constants
;   words[4-11]  = 256-bit key
;   word[12]     = 32-bit block counter
;   words[13-15] = 96-bit nonce
;
; Uses ZP pointers w32_src1/w32_dst for word32 operations.
; =============================================================================

; --- ChaCha20 constants ("expand 32-byte k" as LE uint32 words) ---
cc20_constants:
        !byte $65, $78, $70, $61     ; 0x61707865 "expa" (LE)
        !byte $6e, $64, $20, $33     ; 0x3320646e "nd 3" (LE)
        !byte $32, $2d, $62, $79     ; 0x79622d32 "2-by" (LE)
        !byte $74, $65, $20, $6b     ; 0x6b206574 "te k" (LE)

; --- Quarter-round index table ---
; 8 quarter-rounds per double-round: 4 columns + 4 diagonals
; Each entry: 4 indices (a, b, c, d) into state words
cc20_qr_table:
        ; Column rounds
        !byte  0,  4,  8, 12          ; QR(0, 4, 8, 12)
        !byte  1,  5,  9, 13          ; QR(1, 5, 9, 13)
        !byte  2,  6, 10, 14          ; QR(2, 6, 10, 14)
        !byte  3,  7, 11, 15          ; QR(3, 7, 11, 15)
        ; Diagonal rounds
        !byte  0,  5, 10, 15          ; QR(0, 5, 10, 15)
        !byte  1,  6, 11, 12          ; QR(1, 6, 11, 12)
        !byte  2,  7,  8, 13          ; QR(2, 7, 8, 13)
        !byte  3,  4,  9, 14          ; QR(3, 4, 9, 14)

; =============================================================================
; chacha20_init - Initialize ChaCha20 state
;
; Reads key from cc20_key (32 bytes) and nonce from cc20_nonce (12 bytes).
; Sets counter from cc20_counter (4 bytes).
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_init:
        ; Copy constants to state[0..15] (16 bytes = words 0-3)
        ldx #15
@copy_const:
        lda cc20_constants,x
        sta cc20_state,x
        dex
        bpl @copy_const

        ; Copy key to state[16..47] (32 bytes = words 4-11)
        ldx #31
@copy_key:
        lda cc20_key,x
        sta cc20_state+16,x
        dex
        bpl @copy_key

        ; Copy counter to state[48..51] (4 bytes = word 12)
        ldx #3
@copy_ctr:
        lda cc20_counter,x
        sta cc20_state+48,x
        dex
        bpl @copy_ctr

        ; Copy nonce to state[52..63] (12 bytes = words 13-15)
        ldx #11
@copy_nonce:
        lda cc20_nonce,x
        sta cc20_state+52,x
        dex
        bpl @copy_nonce
        rts

; =============================================================================
; chacha20_quarter_round - Perform one quarter-round on cc20_work
;
; Input: cc20_qr_idx = index into cc20_qr_table (0, 4, 8, ... 28)
;        pointing to 4 byte indices (a, b, c, d)
;
; Quarter-round operations:
;   a += b; d ^= a; d <<<= 16
;   c += d; b ^= c; b <<<= 12
;   a += b; d ^= a; d <<<= 8
;   c += d; b ^= c; b <<<= 7
;
; Clobbers: A, X, Y
; =============================================================================

; Macro-like helper: set w32_dst to cc20_work + word_index*4
; Input: X = table offset for desired index position
; Output: w32_dst points to cc20_work[table[X]*4]
!macro cc20_set_dst .tbl_off {
        ldx cc20_qr_idx
        lda cc20_qr_table+.tbl_off,x
        asl
        asl                    ; *4 for byte offset
        clc
        adc #<cc20_work
        sta w32_dst
        lda #>cc20_work
        adc #0
        sta w32_dst+1
}

; Set w32_src1 to cc20_work + word_index*4
!macro cc20_set_src1 .tbl_off {
        ldx cc20_qr_idx
        lda cc20_qr_table+.tbl_off,x
        asl
        asl
        clc
        adc #<cc20_work
        sta w32_src1
        lda #>cc20_work
        adc #0
        sta w32_src1+1
}

chacha20_quarter_round:
        ; --- a += b ---
        +cc20_set_src1 1       ; src1 = &work[b]
        +cc20_set_dst 0        ; dst = &work[a]
        jsr add32_to_dst

        ; --- d ^= a ---
        +cc20_set_src1 0       ; src1 = &work[a]
        +cc20_set_dst 3        ; dst = &work[d]
        jsr xor32_in_place

        ; --- d <<<= 16 ---
        ; w32_dst already points to d
        jsr rotr32_16          ; rotr16 = rotl16 (same for 32-bit)

        ; --- c += d ---
        +cc20_set_src1 3       ; src1 = &work[d]
        +cc20_set_dst 2        ; dst = &work[c]
        jsr add32_to_dst

        ; --- b ^= c ---
        +cc20_set_src1 2       ; src1 = &work[c]
        +cc20_set_dst 1        ; dst = &work[b]
        jsr xor32_in_place

        ; --- b <<<= 12 ---
        jsr rotl32_12

        ; --- a += b ---
        +cc20_set_src1 1       ; src1 = &work[b]
        +cc20_set_dst 0        ; dst = &work[a]
        jsr add32_to_dst

        ; --- d ^= a ---
        +cc20_set_src1 0       ; src1 = &work[a]
        +cc20_set_dst 3        ; dst = &work[d]
        jsr xor32_in_place

        ; --- d <<<= 8 ---
        jsr rotl32_8

        ; --- c += d ---
        +cc20_set_src1 3       ; src1 = &work[d]
        +cc20_set_dst 2        ; dst = &work[c]
        jsr add32_to_dst

        ; --- b ^= c ---
        +cc20_set_src1 2       ; src1 = &work[c]
        +cc20_set_dst 1        ; dst = &work[b]
        jsr xor32_in_place

        ; --- b <<<= 7 ---
        jsr rotl32_7

        rts

; =============================================================================
; chacha20_block - Generate one 64-byte keystream block
;
; 1. Copy state → work
; 2. 10 double-rounds (20 rounds total)
; 3. Add initial state back to work
; 4. Copy work → keystream
; 5. Increment counter in state
;
; Output: cc20_keystream filled with 64 bytes
; Clobbers: A, X, Y
; =============================================================================
chacha20_block:
        ; 1. Copy state → work (64 bytes)
        ldx #63
@copy_to_work:
        lda cc20_state,x
        sta cc20_work,x
        dex
        bpl @copy_to_work

        ; 2. 10 double-rounds
        lda #10
        sta cc20_round
@double_round:
        ; 8 quarter-rounds per double-round (4 column + 4 diagonal)
        lda #0
        sta cc20_qr_idx
@qr_loop:
        jsr chacha20_quarter_round
        lda cc20_qr_idx
        clc
        adc #4                 ; next QR entry (4 bytes per entry)
        sta cc20_qr_idx
        cmp #32                ; 8 QRs * 4 bytes = 32
        bcc @qr_loop

        dec cc20_round
        bne @double_round

        ; 3. Add initial state back: work[i] += state[i] for each word
        ldx #0                 ; word index (0..15)
@add_state:
        ; Set pointers for add32_to_dst: dst = &work[x*4], src1 = &state[x*4]
        txa
        asl
        asl                    ; *4
        clc
        adc #<cc20_work
        sta w32_dst
        lda #>cc20_work
        adc #0
        sta w32_dst+1

        txa
        asl
        asl
        clc
        adc #<cc20_state
        sta w32_src1
        lda #>cc20_state
        adc #0
        sta w32_src1+1

        txa
        pha                    ; save word counter
        jsr add32_to_dst
        pla
        tax
        inx
        cpx #16
        bcc @add_state

        ; 4. Copy work → keystream (64 bytes)
        ldx #63
@copy_keystream:
        lda cc20_work,x
        sta cc20_keystream,x
        dex
        bpl @copy_keystream

        ; 5. Increment counter in state (word 12, bytes 48-51)
        inc cc20_state+48
        bne @ctr_done
        inc cc20_state+49
        bne @ctr_done
        inc cc20_state+50
        bne @ctr_done
        inc cc20_state+51
@ctr_done:
        rts

; =============================================================================
; chacha20_encrypt - Encrypt/decrypt data using ChaCha20 stream
;
; Inputs:
;   cc20_data_ptr ($16-$17) = pointer to plaintext/ciphertext (in-place XOR)
;   cc20_remain ($18) = number of bytes to process (low byte)
;   cc20_remain_hi = high byte of byte count (16-bit total)
;   State must already be initialized via chacha20_init
;
; The function generates keystream blocks and XORs them with the data.
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_encrypt:
        ; Check if anything to do (16-bit)
        lda cc20_remain
        ora cc20_remain_hi
        beq @enc_done          ; nothing to do

@next_block:
        ; Generate a keystream block
        jsr chacha20_block

        ; Determine how many bytes to XOR from this block: min(remain, 64)
        lda cc20_remain_hi
        bne @full              ; > 255 remaining, definitely 64
        lda cc20_remain
        cmp #64
        bcc @partial           ; < 64 bytes remaining
@full:
        lda #64                ; full block
@partial:
        sta cc20_buf_pos       ; bytes to XOR this iteration
        tax                    ; X = count

        ; XOR keystream with data
        ldy #0
@xor_loop:
        lda (cc20_data_ptr),y
        eor cc20_keystream,y
        sta (cc20_data_ptr),y
        iny
        dex
        bne @xor_loop

        ; Advance data pointer
        clc
        lda cc20_data_ptr
        adc cc20_buf_pos
        sta cc20_data_ptr
        lda cc20_data_ptr+1
        adc #0
        sta cc20_data_ptr+1

        ; 16-bit subtract processed bytes from remaining
        lda cc20_remain
        sec
        sbc cc20_buf_pos
        sta cc20_remain
        lda cc20_remain_hi
        sbc #0
        sta cc20_remain_hi

        ; Check if done (16-bit)
        ora cc20_remain
        bne @next_block        ; more bytes to process

@enc_done:
        rts
