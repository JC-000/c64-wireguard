; =============================================================================
; word32.asm - 32-bit word operations (little-endian)
;
; All operations use zero-page pointers:
;   w32_src1 / w32_src2 = source operands
;   w32_dst = destination
;
; BLAKE2s uses little-endian words: byte[0] = LSB, byte[3] = MSB
; =============================================================================

; =============================================================================
; add32 - 32-bit addition: (w32_dst) = (w32_src1) + (w32_src2)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
add32:
        clc
        ldy #0
        lda (w32_src1),y
        adc (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        adc (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        adc (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        adc (w32_src2),y
        sta (w32_dst),y
        rts

; =============================================================================
; add32_to_dst - 32-bit add-in-place: (w32_dst) += (w32_src1)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
add32_to_dst:
        clc
        ldy #0
        lda (w32_dst),y
        adc (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        adc (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        adc (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        adc (w32_src1),y
        sta (w32_dst),y
        rts

; =============================================================================
; xor32 - 32-bit XOR: (w32_dst) = (w32_src1) ^ (w32_src2)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
xor32:
        ldy #0
        lda (w32_src1),y
        eor (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        eor (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        eor (w32_src2),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        eor (w32_src2),y
        sta (w32_dst),y
        rts

; =============================================================================
; xor32_in_place - 32-bit XOR in place: (w32_dst) ^= (w32_src1)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
xor32_in_place:
        ldy #0
        lda (w32_dst),y
        eor (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        eor (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        eor (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        eor (w32_src1),y
        sta (w32_dst),y
        rts

; =============================================================================
; rotr32_16 - Rotate right 32 bits by 16 (swap byte pairs)
; Little-endian: [b0 b1 b2 b3] >>> 16 = [b2 b3 b0 b1]
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotr32_16:
        ldy #0
        lda (w32_dst),y        ; b0
        pha
        ldy #2
        lda (w32_dst),y        ; b2
        ldy #0
        sta (w32_dst),y        ; pos0 = b2
        pla                    ; old b0
        ldy #2
        sta (w32_dst),y        ; pos2 = b0

        ldy #1
        lda (w32_dst),y        ; b1
        pha
        ldy #3
        lda (w32_dst),y        ; b3
        ldy #1
        sta (w32_dst),y        ; pos1 = b3
        pla                    ; old b1
        ldy #3
        sta (w32_dst),y        ; pos3 = b1
        rts

; =============================================================================
; rotr32_8 - Rotate right 32 bits by 8 (byte rotate right)
; Little-endian: [b0 b1 b2 b3] >>> 8 = [b1 b2 b3 b0]
;
; Think of it as: the value shifts right 8 bits, so the old LSB byte (b0)
; wraps to the MSB position (byte 3).
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotr32_8:
        ldy #0
        lda (w32_dst),y        ; save b0
        pha
        ldy #1
        lda (w32_dst),y        ; b1
        ldy #0
        sta (w32_dst),y        ; pos0 = b1
        ldy #2
        lda (w32_dst),y        ; b2
        ldy #1
        sta (w32_dst),y        ; pos1 = b2
        ldy #3
        lda (w32_dst),y        ; b3
        ldy #2
        sta (w32_dst),y        ; pos2 = b3
        pla                    ; old b0
        ldy #3
        sta (w32_dst),y        ; pos3 = b0
        rts

; =============================================================================
; rotr32_12 - Rotate right 32 bits by 12
; = rotr_8 then rotr_4
;
; rotr_4 on little-endian [b0 b1 b2 b3]:
;   new_b0 = (b0 >> 4) | (b1 << 4)
;   new_b1 = (b1 >> 4) | (b2 << 4)
;   new_b2 = (b2 >> 4) | (b3 << 4)
;   new_b3 = (b3 >> 4) | (b0 << 4)   [wrap]
;
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotr32_12:
        jsr rotr32_8
        ; fall through to rotr32_4

; rotr32_4 - Rotate right 32 bits by 4
rotr32_4:
        ; save b0 low nibble for wrap-around
        ldy #0
        lda (w32_dst),y
        asl
        asl
        asl
        asl                    ; b0_low << 4 (for wrapping into b3 high)
        sta zp_tmp1            ; save wrap value

        ; b0 = (b0 >> 4) | (b1 << 4)
        ldy #0
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        sta zp_tmp2            ; b0 >> 4
        ldy #1
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        ora zp_tmp2
        ldy #0
        sta (w32_dst),y

        ; b1 = (b1 >> 4) | (b2 << 4)
        ldy #1
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        sta zp_tmp2
        ldy #2
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        ora zp_tmp2
        ldy #1
        sta (w32_dst),y

        ; b2 = (b2 >> 4) | (b3 << 4)
        ldy #2
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        sta zp_tmp2
        ldy #3
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        ora zp_tmp2
        ldy #2
        sta (w32_dst),y

        ; b3 = (b3 >> 4) | (b0_low << 4)  [wrap from saved value]
        ldy #3
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        ora zp_tmp1            ; wrapped b0 low nibble
        sta (w32_dst),y
        rts

; =============================================================================
; rotr32_7 - Rotate right 32 bits by 7
; = rotr_8 then rotl_1
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotr32_7:
        jsr rotr32_8
        ; fall through to rotl32_1

; rotl32_1 - Rotate left 32 bits by 1
rotl32_1:
        ; Little-endian left shift: start from LSB (byte 0)
        clc
        ldy #0
        lda (w32_dst),y
        rol
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        rol
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        rol
        sta (w32_dst),y
        iny
        lda (w32_dst),y
        rol
        sta (w32_dst),y
        ; carry = old MSB, wraps to bit 0 of byte 0
        bcc +
        ldy #0
        lda (w32_dst),y
        ora #$01
        sta (w32_dst),y
+
        rts

; =============================================================================
; rotl32_8 - Rotate left 32 bits by 8 (byte rotate left)
; Little-endian: [b0 b1 b2 b3] <<< 8 = [b3 b0 b1 b2]
;
; value <<< 8 = value * 256 mod 2^32:
;   new byte[0] = b3, byte[1] = b0, byte[2] = b1, byte[3] = b2
;
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotl32_8:
        ldy #3
        lda (w32_dst),y        ; save b3
        pha
        ldy #2
        lda (w32_dst),y        ; b2
        ldy #3
        sta (w32_dst),y        ; pos3 = b2
        ldy #1
        lda (w32_dst),y        ; b1
        ldy #2
        sta (w32_dst),y        ; pos2 = b1
        ldy #0
        lda (w32_dst),y        ; b0
        ldy #1
        sta (w32_dst),y        ; pos1 = b0
        pla                    ; old b3
        ldy #0
        sta (w32_dst),y        ; pos0 = b3
        rts

; =============================================================================
; rotl32_4 - Rotate left 32 bits by 4 (nibble shift left)
;
; Each byte: new_b[i] = (b[i] << 4) | (b[i-1] >> 4), with wrap
; In LE: new_b0 = (b0 << 4) | (b3 >> 4)  [wrap from MSB byte]
;        new_b1 = (b1 << 4) | (b0 >> 4)
;        new_b2 = (b2 << 4) | (b1 >> 4)
;        new_b3 = (b3 << 4) | (b2 >> 4)
;
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotl32_4:
        ; save b3 high nibble for wrap-around into b0
        ldy #3
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr                    ; b3 >> 4 (for wrapping into b0 low)
        sta zp_tmp1            ; save wrap value

        ; b3 = (b3 << 4) | (b2 >> 4)
        ldy #3
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        sta zp_tmp2            ; b3 << 4
        ldy #2
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        ora zp_tmp2
        ldy #3
        sta (w32_dst),y

        ; b2 = (b2 << 4) | (b1 >> 4)
        ldy #2
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        sta zp_tmp2
        ldy #1
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        ora zp_tmp2
        ldy #2
        sta (w32_dst),y

        ; b1 = (b1 << 4) | (b0 >> 4)
        ldy #1
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        sta zp_tmp2
        ldy #0
        lda (w32_dst),y
        lsr
        lsr
        lsr
        lsr
        ora zp_tmp2
        ldy #1
        sta (w32_dst),y

        ; b0 = (b0 << 4) | (b3 >> 4)  [wrap from saved value]
        ldy #0
        lda (w32_dst),y
        asl
        asl
        asl
        asl
        ora zp_tmp1            ; wrapped b3 high nibble
        sta (w32_dst),y
        rts

; =============================================================================
; rotl32_12 - Rotate left 32 bits by 12 = rotl_8 + rotl_4
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotl32_12:
        jsr rotl32_8
        jmp rotl32_4           ; tail call

; =============================================================================
; rotr32_1 - Rotate right 32 bits by 1
; Little-endian right shift: start from MSB (byte 3)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotr32_1:
        clc
        ldy #3
        lda (w32_dst),y
        ror
        sta (w32_dst),y
        dey
        lda (w32_dst),y
        ror
        sta (w32_dst),y
        dey
        lda (w32_dst),y
        ror
        sta (w32_dst),y
        dey
        lda (w32_dst),y
        ror
        sta (w32_dst),y
        ; carry = old LSB, wraps to bit 7 of byte 3
        bcc +
        ldy #3
        lda (w32_dst),y
        ora #$80
        sta (w32_dst),y
+
        rts

; =============================================================================
; rotl32_7 - Rotate left 32 bits by 7 = rotl_8 - rotr_1 = rotl_8 then rotr_1
; Preserves: X
; Clobbers: A, Y
; =============================================================================
rotl32_7:
        jsr rotl32_8
        jmp rotr32_1           ; tail call

; =============================================================================
; copy32 - Copy 4 bytes: (w32_dst) = (w32_src1)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
copy32:
        ldy #0
        lda (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        sta (w32_dst),y
        iny
        lda (w32_src1),y
        sta (w32_dst),y
        rts

; =============================================================================
; zero32 - Zero 4 bytes at (w32_dst)
; Preserves: X
; Clobbers: A, Y
; =============================================================================
zero32:
        lda #0
        ldy #0
        sta (w32_dst),y
        iny
        sta (w32_dst),y
        iny
        sta (w32_dst),y
        iny
        sta (w32_dst),y
        rts
