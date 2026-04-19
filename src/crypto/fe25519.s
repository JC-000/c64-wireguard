; =============================================================================
; fe25519.s - Field arithmetic mod p = 2^255 - 19  (ca65 port)
;
; 32-byte little-endian field elements.
; Uses ZP pointers fe25519_src1, fe25519_src2, fe25519_dst for operands
; (aliased to existing fe_src1/fe_src2/fe_dst ZP slots).
; Reuses mul_8x8 and sqtab from poly1305 for multiplication.
;
; Key design:
;   - Little-endian throughout (matches 6502 carry propagation and X25519 wire)
;   - DEX/DEY for all carry-dependent loops (CPX/CPY clobber carry)
;   - Reduction mod p: 2^256 ≡ 38 mod p, so multiply overflow by 38 and add
; =============================================================================

.include "constants.inc"

; --- Public ABI aliases for fe25519 ZP pointer slots ---
; The underlying ZP addresses are defined in constants.inc as fe_src1/fe_src2/fe_dst.
; The fe25519_src1/src2/dst ABI-aligned aliases live in src/exports.s
; so they're also emitted to labels.txt for the test harness.

; --- Public entry points ---
.export fe25519_copy
.export fe25519_zero
.export fe25519_one
.export fe25519_add
.export fe25519_sub
.export fe25519_cmp_p
.export fe25519_reduce_final
.export fe25519_reduce_wide
.export fe25519_cswap
.export fe25519_mul
.export fe25519_sqr
.export fe25519_mul_a24
.export fe25519_inv
.export reu_mul_init
.export reu_fetch_mul_row

; --- Imports ---
; Multiplication primitives and tables from poly1305 / data.
.import mul_8x8
.import mul_dma_lo
.import mul_dma_hi
.import mul_src2_buf
.import mul_cached_a
.import sqtab_lo
.import sqtab_hi
.import sqtab2_lo
.import sqtab2_hi
.import mul38_lo_tab
.import mul38_hi_tab
.import poly_prod_lo
.import poly_prod_hi
.import fe_wide
.import fe_tmp1
.import fe_tmp2
.import fe_tmp3
.import fe_p
.import x25_a
.import x25_b
.import x25_da
.import x25_cb

.segment "CRYPTO_CODE"

; =============================================================================
; fe25519_copy - Copy 32 bytes: (fe_dst) = (fe_src1)
; Clobbers: A, Y
; =============================================================================
fe25519_copy:
        ldy #31
@loop:
        lda (fe_src1),y
        sta (fe_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fe25519_zero - Zero 32 bytes at (fe_dst)
; Clobbers: A, Y
; =============================================================================
fe25519_zero:
        lda #0
        ldy #31
@loop:
        sta (fe_dst),y
        dey
        bpl @loop
        rts

; =============================================================================
; fe25519_one - Set (fe_dst) = 1 (LE: byte 0 = 1, rest 0)
; Clobbers: A, Y
; =============================================================================
fe25519_one:
        jsr fe25519_zero
        lda #1
        ldy #0
        sta (fe_dst),y
        rts

; =============================================================================
; fe25519_add - (fe_dst) = (fe_src1) + (fe_src2) mod p
;
; 32-byte addition with carry, then conditional subtract p if >= p.
; Clobbers: A, X, Y
; =============================================================================
fe25519_add:
        clc
        ldy #0
        ldx #32
@add_loop:
        lda (fe_src1),y
        adc (fe_src2),y
        sta (fe_dst),y
        iny
        dex                    ; DEX doesn't affect carry
        bne @add_loop
        bcs @must_reduce       ; carry out → result >= 2^256 > p

        ; Check if result >= p
        jsr fe25519_cmp_p
        bcc @done

@must_reduce:
        sec
        ldy #0
        ldx #32
@sub_p:
        lda (fe_dst),y
        sbc fe_p,y
        sta (fe_dst),y
        iny
        dex
        bne @sub_p

@done:
        rts

; =============================================================================
; fe25519_sub - (fe_dst) = (fe_src1) - (fe_src2) mod p
;
; 32-byte subtraction. If borrow, add p.
; Clobbers: A, X, Y
; =============================================================================
fe25519_sub:
        sec
        ldy #0
        ldx #32
@sub_loop:
        lda (fe_src1),y
        sbc (fe_src2),y
        sta (fe_dst),y
        iny
        dex
        bne @sub_loop
        bcs @done              ; no borrow → done

        ; Borrow: add p
        clc
        ldy #0
        ldx #32
@add_p:
        lda (fe_dst),y
        adc fe_p,y
        sta (fe_dst),y
        iny
        dex
        bne @add_p

@done:
        rts

; =============================================================================
; fe25519_cmp_p - Compare (fe_dst) with p
;
; C=1 if (fe_dst) >= p, C=0 if < p
; Clobbers: A, Y
; =============================================================================
fe25519_cmp_p:
        ldy #31
@cmp_loop:
        lda (fe_dst),y
        cmp fe_p,y
        bcc @less
        bne @greater
        dey
        bpl @cmp_loop
        sec                    ; equal → >= p
        rts
@less:
        clc
        rts
@greater:
        sec
        rts

; =============================================================================
; fe25519_reduce_final - Canonical reduction of (fe_dst) to [0, p-1]
; Clobbers: A, X, Y
; =============================================================================
fe25519_reduce_final:
        jsr fe25519_cmp_p
        bcc @done

        sec
        ldy #0
        ldx #32
@sub_p:
        lda (fe_dst),y
        sbc fe_p,y
        sta (fe_dst),y
        iny
        dex
        bne @sub_p

@done:
        rts

; =============================================================================
; fe25519_cswap - Constant-time conditional swap of (fe_src1) and (fe_src2)
;
; Input: A = swap mask (0x00 = no swap, 0xFF = swap)
; Clobbers: A, X, Y
;
; Self-modifying code: patches absolute,Y addresses into the inner loop
; to replace indirect-indexed (zp),Y loads/stores (4-5 cyc vs 5-6 cyc each).
; Eliminates redundant re-read of src1 by keeping value in X register.
; Unrolled 4x to reduce loop overhead (32 bytes / 4 = 8 iterations).
;
; Per byte: lda abs,Y(4) + tax(2) + eor abs,Y(4) + and zp(3) + sta zp(3)
;           + txa(2) + eor zp(3) + sta abs,Y(5) + lda abs,Y(4) + eor zp(3)
;           + sta abs,Y(5) = 38 cycles/byte
; Old: 49 cycles/byte (indirect-indexed + redundant re-read)
; Savings: ~11 cyc/byte * 32 bytes * 512 calls = ~180k cycles
; =============================================================================
fe25519_cswap:
        sta fe_carry           ; save mask

        ; Patch src1 address into lda/sta abs,Y instructions (8 patches)
        lda fe_src1
        sta @ld_a1+1
        sta @st_a1+1
        sta @ld_a2+1
        sta @st_a2+1
        sta @ld_a3+1
        sta @st_a3+1
        sta @ld_a4+1
        sta @st_a4+1
        lda fe_src1+1
        sta @ld_a1+2
        sta @st_a1+2
        sta @ld_a2+2
        sta @st_a2+2
        sta @ld_a3+2
        sta @st_a3+2
        sta @ld_a4+2
        sta @st_a4+2

        ; Patch src2 address into eor/lda/sta abs,Y instructions (12 patches)
        lda fe_src2
        sta @eor_b1+1
        sta @ld_b1+1
        sta @st_b1+1
        sta @eor_b2+1
        sta @ld_b2+1
        sta @st_b2+1
        sta @eor_b3+1
        sta @ld_b3+1
        sta @st_b3+1
        sta @eor_b4+1
        sta @ld_b4+1
        sta @st_b4+1
        lda fe_src2+1
        sta @eor_b1+2
        sta @ld_b1+2
        sta @st_b1+2
        sta @eor_b2+2
        sta @ld_b2+2
        sta @st_b2+2
        sta @eor_b3+2
        sta @ld_b3+2
        sta @st_b3+2
        sta @eor_b4+2
        sta @ld_b4+2
        sta @st_b4+2

        ldy #31
@loop:
        ; --- Byte at Y ---
@ld_a1: lda $ffff,y            ; a[y]           (patched)
        tax                    ; X = a[y]
@eor_b1:eor $ffff,y            ; a[y] ^ b[y]    (patched)
        and fe_carry           ; diff
        sta fe_loop            ; save diff
        txa                    ; A = a[y]
        eor fe_loop            ; a[y] ^ diff
@st_a1: sta $ffff,y            ; store new a[y]  (patched)
@ld_b1: lda $ffff,y            ; b[y]           (patched)
        eor fe_loop            ; b[y] ^ diff
@st_b1: sta $ffff,y            ; store new b[y]  (patched)

        dey

        ; --- Byte at Y ---
@ld_a2: lda $ffff,y
        tax
@eor_b2:eor $ffff,y
        and fe_carry
        sta fe_loop
        txa
        eor fe_loop
@st_a2: sta $ffff,y
@ld_b2: lda $ffff,y
        eor fe_loop
@st_b2: sta $ffff,y

        dey

        ; --- Byte at Y ---
@ld_a3: lda $ffff,y
        tax
@eor_b3:eor $ffff,y
        and fe_carry
        sta fe_loop
        txa
        eor fe_loop
@st_a3: sta $ffff,y
@ld_b3: lda $ffff,y
        eor fe_loop
@st_b3: sta $ffff,y

        dey

        ; --- Byte at Y ---
@ld_a4: lda $ffff,y
        tax
@eor_b4:eor $ffff,y
        and fe_carry
        sta fe_loop
        txa
        eor fe_loop
@st_a4: sta $ffff,y
@ld_b4: lda $ffff,y
        eor fe_loop
@st_b4: sta $ffff,y

        dey
        bpl @loop
        rts

; =============================================================================
; fe25519_mul - (fe_dst) = (fe_src1) * (fe_src2) mod p
;
; Combined REU DMA table lookup + 2x inner loop unroll.
; Each outer iteration: DMA fetches 512-byte mul row for src1[i],
; then inner loop does direct table lookup (mul_dma_lo/hi,Y) instead of
; mult66 quarter-square. Inner loop unrolled 2x to reduce branch overhead.
;
; Clobbers: A, X, Y
; =============================================================================
fe25519_mul:
        ; 1. Zero the 64-byte product buffer
        ldx #63
        lda #0
@zero_wide:
        sta fe_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src2 to absolute buffer (needed for indexed access)
        ldy #31
@copy_src2:
        lda (fe_src2),y
        sta mul_src2_buf,y
        dey
        bpl @copy_src2

        ; 3. Schoolbook multiply with REU DMA lookup + self-mod accumulation
        lda #0
        sta fe_mul_i
@mul_outer:
        ldy fe_mul_i
        lda (fe_src1),y
        bne @nonzero_i
        jmp @skip_zero
@nonzero_i:
        sta mul_cached_a       ; cache src1[i] for inner loop

        ; DMA the multiplication row for src1[i] from REU
        jsr reu_fetch_mul_row

        ; Self-mod: patch accumulation addresses to base = fe_wide + i
        ; Patch BOTH copies of the unrolled inner loop
        lda #<fe_wide
        clc
        adc fe_mul_i           ; A = low byte of (fe_wide + i)
        sta @accum_ld1+1
        sta @accum_st1+1
        sta @accum_ld1_b+1
        sta @accum_st1_b+1
        lda #>fe_wide
        adc #0                 ; handle page crossing
        sta @accum_ld1+2
        sta @accum_st1+2
        sta @accum_ld1_b+2
        sta @accum_st1_b+2
        ; For +1 accesses (high byte of product), base is fe_wide + i + 1
        lda #<(fe_wide+1)
        clc
        adc fe_mul_i
        sta @accum_ld2+1
        sta @accum_st2+1
        sta @accum_ld2_b+1
        sta @accum_st2_b+1
        lda #>(fe_wide+1)
        adc #0
        sta @accum_ld2+2
        sta @accum_st2+2
        sta @accum_ld2_b+2
        sta @accum_st2_b+2

        lda #0
        sta fe_mul_j

        ; ===== UNROLLED 2x INNER LOOP =====
        ; First copy processes j, second copy processes j+1
        ; Loop exit check only after second copy

@mul_inner:
        ; --- First copy: process src2[j] ---
        ldx fe_mul_j
        ldy mul_src2_buf,x     ; Y = src2[j]
        beq @next_j_first      ; skip if zero

        ; --- REU table lookup: mul_cached_a * Y ---
        lda mul_dma_lo,y       ; lo byte of product  (4 cycles)
        sta poly_prod_lo
        lda mul_dma_hi,y       ; hi byte of product  (4 cycles)
        sta poly_prod_hi

        ; Add 16-bit product to fe_wide[i+j]
        ldx fe_mul_j

        clc
@accum_ld1:
        lda fe_wide,x          ; patched to fe_wide+i base
        adc poly_prod_lo
@accum_st1:
        sta fe_wide,x
@accum_ld2:
        lda fe_wide+1,x        ; patched to fe_wide+i+1 base
        adc poly_prod_hi
@accum_st2:
        sta fe_wide+1,x
        bcc @next_j_first

        ; Propagate carry (rare path)
        lda fe_mul_i
        clc
        adc fe_mul_j
        clc
        adc #2
        tax
@prop_carry_a:
        cpx #64
        bcs @next_j_first
        sec
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        inx
        bcs @prop_carry_a

@next_j_first:
        inc fe_mul_j           ; advance j, no exit check

        ; --- Second copy: process src2[j+1] ---
        ldx fe_mul_j
        ldy mul_src2_buf,x     ; Y = src2[j]
        beq @next_j            ; skip if zero

        ; --- REU table lookup: mul_cached_a * Y ---
        lda mul_dma_lo,y       ; lo byte of product  (4 cycles)
        sta poly_prod_lo
        lda mul_dma_hi,y       ; hi byte of product  (4 cycles)
        sta poly_prod_hi

        ; Add 16-bit product to fe_wide[i+j]
        ldx fe_mul_j

        clc
@accum_ld1_b:
        lda fe_wide,x          ; patched to fe_wide+i base
        adc poly_prod_lo
@accum_st1_b:
        sta fe_wide,x
@accum_ld2_b:
        lda fe_wide+1,x        ; patched to fe_wide+i+1 base
        adc poly_prod_hi
@accum_st2_b:
        sta fe_wide+1,x
        bcc @next_j

        ; Propagate carry (rare path)
        lda fe_mul_i
        clc
        adc fe_mul_j
        clc
        adc #2
        tax
@prop_carry_b:
        cpx #64
        bcs @next_j
        sec
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        inx
        bcs @prop_carry_b

@next_j:
        inc fe_mul_j
        lda fe_mul_j
        cmp #32
        bcs @skip_zero
        jmp @mul_inner

@skip_zero:
        inc fe_mul_i
        lda fe_mul_i
        cmp #32
        bcs @mul_done
        jmp @mul_outer
@mul_done:

        ; 4. Reduce mod p
        jsr fe25519_reduce_wide

        ; Copy result to (fe_dst)
        ldy #31
@copy_result:
        lda fe_wide,y
        sta (fe_dst),y
        dey
        bpl @copy_result

        jsr fe25519_reduce_final
        rts

; =============================================================================
; fe25519_reduce_wide - Reduce fe_wide[0..63] mod p into fe_wide[0..31]
;
; fe_wide[32..63] * 38 + fe_wide[0..31], with second pass for overflow.
; Clobbers: A, X, Y
; =============================================================================
fe25519_reduce_wide:
        ; First pass: fe_wide[0..31] += fe_wide[32..63] * 38
        lda #0
        sta fe_carry
        ldx #0
@reduce1:
        ldy fe_wide+32,x       ; Y = byte value (table index)
        beq @reduce1_zero

        ; Table lookup: Y * 38
        lda mul38_lo_tab,y
        sta poly_prod_lo
        lda mul38_hi_tab,y
        sta poly_prod_hi

        ; Add product + running carry to fe_wide[x]
        clc
        lda poly_prod_lo
        adc fe_carry
        sta fe_carry
        lda poly_prod_hi
        adc #0
        sta fe_mul_j           ; high = product_hi + carry overflow

        clc
        lda fe_wide,x
        adc fe_carry
        sta fe_wide,x
        lda fe_mul_j
        adc #0
        sta fe_carry

        inx
        cpx #32
        bcc @reduce1
        jmp @reduce1_check

@reduce1_zero:
        ; byte is 0; just add running carry
        clc
        lda fe_wide,x
        adc fe_carry
        sta fe_wide,x
        lda #0
        adc #0
        sta fe_carry
        inx
        cpx #32
        bcc @reduce1

@reduce1_check:
        ; If carry remains, multiply by 38 and add to bottom
        lda fe_carry
        beq @done
        tay                    ; Y = carry value
        lda mul38_lo_tab,y
        sta poly_prod_lo
        lda mul38_hi_tab,y
        sta poly_prod_hi

        clc
        lda fe_wide
        adc poly_prod_lo
        sta fe_wide
        lda fe_wide+1
        adc poly_prod_hi
        sta fe_wide+1
        bcc @done
        ldx #2
@prop2:
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        bcc @done
        inx
        cpx #32
        bcc @prop2

        ; Extremely rare: yet another overflow
        clc
        lda fe_wide
        adc #38
        sta fe_wide
        ldx #1
@prop3:
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        bcc @done
        inx
        cpx #32
        bcc @prop3

@done:
        rts

; =============================================================================
; fe25519_sqr - (fe_dst) = (fe_src1)^2 mod p
;
; Dedicated squaring: exploits symmetry a[i]*a[j] = a[j]*a[i].
; Uses mult66 indirect-indexed multiply + self-modifying accumulation
; (same technique as fe25519_mul). Cross terms added twice to fuse doubling.
; 1. Cross terms: accumulate 2*a[i]*a[j] for i < j  (inline mult66, shift-before-accum)
; 2. Diagonal: add a[i]^2 at position 2*i            (inline mult66)
; 3. Reduce mod p
;
; Clobbers: A, X, Y
; =============================================================================
fe25519_sqr:
        ; 1. Zero the 64-byte product buffer
        ldx #63
        lda #0
@zero_wide:
        sta fe_wide,x
        dex
        bpl @zero_wide

        ; 2. Copy src1 to absolute buffer (src1==src2 for squaring)
        ldy #31
@copy_src:
        lda (fe_src1),y
        sta mul_src2_buf,y
        dey
        bpl @copy_src

        ; 3. Set up ZP pointers for mult66 indirect-indexed multiply
        lda #>sqtab_lo
        sta lmul0+1
        lda #>sqtab_hi
        sta lmul1+1

        ; 4. Cross terms with mult66 + self-mod, shift-before-accumulate
        lda #0
        sta fe_mul_i
@sqr_outer:
        ldy fe_mul_i
        lda (fe_src1),y
        bne @sqr_nonzero_i
        jmp @sqr_skip_i
@sqr_nonzero_i:
        sta mul_cached_a       ; cache a[i] for inner loop

        ; Self-mod: patch accumulation addresses to base = fe_wide + i
        lda #<fe_wide
        clc
        adc fe_mul_i           ; A = low byte of (fe_wide + i)
        sta @sqr_accum_ld1+1
        sta @sqr_accum_st1+1
        lda #>fe_wide
        adc #0                 ; handle page crossing
        sta @sqr_accum_ld1+2
        sta @sqr_accum_st1+2
        ; For +1 accesses (high byte of product)
        lda #<(fe_wide+1)
        clc
        adc fe_mul_i
        sta @sqr_accum_ld2+1
        sta @sqr_accum_st2+1
        lda #>(fe_wide+1)
        adc #0
        sta @sqr_accum_ld2+2
        sta @sqr_accum_st2+2

        ; Set up ZP pointer low byte = a[i] once per outer loop
        lda mul_cached_a
        sta lmul0              ; lmul0 = sqtab_lo + a[i]
        sta lmul1              ; lmul1 = sqtab_hi + a[i]

        ; j starts at i+1
        lda fe_mul_i
        clc
        adc #1
        sta fe_mul_j

@sqr_inner:
        ldx fe_mul_j
        ldy mul_src2_buf,x     ; Y = a[j]
        bne @sqr_nonzero_j     ; skip if zero
        jmp @sqr_next_j
@sqr_nonzero_j:

        ; --- mult66 inline: a[i] * a[j] ---
        tya                    ; A = a[j]
        sec
        sbc mul_cached_a       ; A = a[j] - a[i]
        tax                    ; X = difference (or wrapped)

        ; (lmul0),Y = sqtab_lo[a[i] + a[j]]
        lda (lmul0),y
        bcc @sqr_neg_diff      ; branch if a[j] < a[i]

        ; Positive difference path (carry SET):
        sbc sqtab_lo,x
        sta poly_prod_lo
        lda (lmul1),y
        sbc sqtab_hi,x
        sta poly_prod_hi
        jmp @sqr_accum

@sqr_neg_diff:
        ; Negative difference path (carry CLEAR):
        sbc sqtab2_lo,x
        sta poly_prod_lo
        lda (lmul1),y
        sbc sqtab2_hi,x
        sta poly_prod_hi
        ; --- END mult66 ---

@sqr_accum:
        ; Double the product (shift-before-accumulate replaces second addition)
        asl poly_prod_lo
        rol poly_prod_hi
        lda #0
        adc #0                 ; A = carry from ROL (0 or 1)
        sta poly_carry         ; save 17th bit

        ; Single addition of doubled product to fe_wide[i+j]
        ldx fe_mul_j

        clc
@sqr_accum_ld1:
        lda fe_wide,x          ; patched to fe_wide+i base
        adc poly_prod_lo
@sqr_accum_st1:
        sta fe_wide,x
@sqr_accum_ld2:
        lda fe_wide+1,x        ; patched to fe_wide+i+1 base
        adc poly_prod_hi
@sqr_accum_st2:
        sta fe_wide+1,x

        ; Capture accumulation carry and combine with shift carry
        lda #0
        adc poly_carry         ; A = accum_carry + shift_carry (0, 1, or 2)
        beq @sqr_next_j        ; if both zero, skip

        ; Add combined carries to fe_wide[i+j+2]
        ldx fe_mul_i
        tay                    ; Y = combined carry value
        txa
        clc
        adc fe_mul_j
        clc
        adc #2
        tax
        tya                    ; A = combined carry value
        clc
        adc fe_wide,x
        sta fe_wide,x
        bcc @sqr_next_j
        ; Propagate further carries
@sqr_prop1:
        inx
        cpx #64
        bcs @sqr_next_j
        sec
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        bcs @sqr_prop1

@sqr_next_j:
        inc fe_mul_j
        lda fe_mul_j
        cmp #32
        bcs @sqr_skip_i
        jmp @sqr_inner

@sqr_skip_i:
        inc fe_mul_i
        lda fe_mul_i
        cmp #31                ; i goes 0..30 (j needs room for i+1)
        bcs @sqr_cross_done
        jmp @sqr_outer
@sqr_cross_done:

        ; 5. Add diagonal terms: a[i]^2 at position 2*i (inline mult66)
        ;    For self-multiply: diff=0, sqtab[0]=0, so result = sqtab[2*a[i]]
        ;    With lmul0 = a[i], Y = a[i]: (lmul0),Y = sqtab[2*a[i]]
        lda #0
        sta fe_mul_i
@diag_outer:
        ldy fe_mul_i
        lda (fe_src1),y
        beq @diag_skip         ; skip if a[i] == 0

        ; Set up mult66 pointers for self-multiply
        sta lmul0              ; lmul0 low = a[i]
        sta lmul1              ; lmul1 low = a[i]
        tay                    ; Y = a[i]

        ; (lmul0),Y = sqtab_lo[a[i] + a[i]] = sqtab_lo[2*a[i]]
        ; (lmul1),Y = sqtab_hi[a[i] + a[i]] = sqtab_hi[2*a[i]]
        ; diff = 0, sqtab[0] = 0, no subtraction needed
        lda (lmul0),y          ; lo byte of a[i]^2
        sta poly_prod_lo
        lda (lmul1),y          ; hi byte of a[i]^2
        sta poly_prod_hi

        ; Add to fe_wide[2*i]
        lda fe_mul_i
        asl                    ; A = 2*i
        tax

        clc
        lda fe_wide,x
        adc poly_prod_lo
        sta fe_wide,x
        inx
        lda fe_wide,x
        adc poly_prod_hi
        sta fe_wide,x
        bcc @diag_skip

        ; Propagate carry
@diag_prop:
        inx
        cpx #64
        bcs @diag_skip
        sec
        lda fe_wide,x
        adc #0
        sta fe_wide,x
        bcs @diag_prop

@diag_skip:
        inc fe_mul_i
        lda fe_mul_i
        cmp #32
        bcs @sqr_reduce
        jmp @diag_outer

@sqr_reduce:
        ; 6. Reduce mod p (same as fe25519_mul)
        jsr fe25519_reduce_wide

        ; Copy result to (fe_dst)
        ldy #31
@copy_result_sqr:
        lda fe_wide,y
        sta (fe_dst),y
        dey
        bpl @copy_result_sqr

        jsr fe25519_reduce_final
        rts

; =============================================================================
; fe25519_mul_a24 - (fe_dst) = (fe_src1) * 121665 mod p
;
; 121665 = $01DB41 (3 bytes LE: $41, $DB, $01)
; Clobbers: A, X, Y
; =============================================================================
fe25519_mul_a24:
        ; Zero fe_wide[0..34]
        ldx #34
        lda #0
@zero:
        sta fe_wide,x
        dex
        bpl @zero

        ldx #0                 ; i = 0
@outer:
        stx fe_mul_i

        ldy fe_mul_i
        lda (fe_src1),y
        beq @skip_zero_a24

        ; src1[i] * $41 → add at offset i
        ldx #$41
        jsr mul_8x8
        ldx fe_mul_i
        clc
        lda fe_wide,x
        adc poly_prod_lo
        sta fe_wide,x
        lda fe_wide+1,x
        adc poly_prod_hi
        sta fe_wide+1,x
        bcc :+
        inc fe_wide+2,x
        bne :+
        inc fe_wide+3,x
:
        ; src1[i] * $DB → add at offset i+1
        ldy fe_mul_i
        lda (fe_src1),y
        ldx #$db
        jsr mul_8x8
        ldx fe_mul_i
        clc
        lda fe_wide+1,x
        adc poly_prod_lo
        sta fe_wide+1,x
        lda fe_wide+2,x
        adc poly_prod_hi
        sta fe_wide+2,x
        bcc :+
        inc fe_wide+3,x
        bne :+
        inc fe_wide+4,x
:
        ; src1[i] * $01 → add at offset i+2
        ldy fe_mul_i
        lda (fe_src1),y
        ldx fe_mul_i
        clc
        adc fe_wide+2,x
        sta fe_wide+2,x
        bcc :+
        inc fe_wide+3,x
        bne :+
        inc fe_wide+4,x
:
@skip_zero_a24:
        ldx fe_mul_i
        inx
        cpx #32
        bcc @outer

        ; Reduce: fe_wide[32..34] * 38 → add to fe_wide[0..31]
        lda fe_wide+32
        beq @r_b33
        ldx #38
        jsr mul_8x8
        clc
        lda fe_wide
        adc poly_prod_lo
        sta fe_wide
        lda fe_wide+1
        adc poly_prod_hi
        sta fe_wide+1
        bcc @r_b33
        ldx #2
@prop_b32:
        inc fe_wide,x
        bne @r_b33
        inx
        cpx #32
        bcc @prop_b32

@r_b33:
        lda fe_wide+33
        beq @r_b34
        ldx #38
        jsr mul_8x8
        clc
        lda fe_wide+1
        adc poly_prod_lo
        sta fe_wide+1
        lda fe_wide+2
        adc poly_prod_hi
        sta fe_wide+2
        bcc @r_b34
        ldx #3
@prop_b33:
        inc fe_wide,x
        bne @r_b34
        inx
        cpx #32
        bcc @prop_b33

@r_b34:
        lda fe_wide+34
        beq @r_done_a24
        ldx #38
        jsr mul_8x8
        clc
        lda fe_wide+2
        adc poly_prod_lo
        sta fe_wide+2
        lda fe_wide+3
        adc poly_prod_hi
        sta fe_wide+3
        bcc @r_done_a24
        ldx #4
@prop_b34:
        inc fe_wide,x
        bne @r_done_a24
        inx
        cpx #32
        bcc @prop_b34

@r_done_a24:
        ; Copy to (fe_dst)
        ldy #31
@copy_a24:
        lda fe_wide,y
        sta (fe_dst),y
        dey
        bpl @copy_a24

        jsr fe25519_reduce_final
        rts

; =============================================================================
; fe25519_inv - (fe_dst) = (fe_src1)^(p-2) mod p  (Fermat's little theorem)
;
; p-2 = 2^255 - 21
;
; Addition chain from ref10 (djb):
;   ~253 squarings + 11 multiplications
;
; Buffer allocation:
;   fe_tmp1 = z (original input, kept throughout)
;   fe_tmp2 = t (working accumulator)
;   fe_tmp3 = general scratch
;   x25_a   = z11 (saved for final multiply)
;   x25_b   = z_10_0 (saved for z_20_0 and z_50_0)
;   x25_da  = z_50_0 (saved for z_100_0 and z_250_0)
;   x25_cb  = z_100_0 (saved for z_200_0)
;
; Clobbers: A, X, Y, all fe_* ZP vars
; =============================================================================
fe25519_inv:
        ; Save original destination pointer
        lda fe_dst
        sta fe_inv_dst
        lda fe_dst+1
        sta fe_inv_dst+1

        ; Save z to fe_tmp1
        lda #<fe_tmp1
        sta fe_dst
        lda #>fe_tmp1
        sta fe_dst+1
        jsr fe25519_copy        ; fe_tmp1 = z

        ; --- z2 = z^2 → fe_tmp2 ---
        lda #<fe_tmp1
        sta fe_src1
        lda #>fe_tmp1
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_sqr         ; fe_tmp2 = z^2

        ; --- z4 = z2^2 → fe_tmp3 ---
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_dst
        lda #>fe_tmp3
        sta fe_dst+1
        jsr fe25519_sqr         ; fe_tmp3 = z^4

        ; --- z8 = z4^2 → fe_tmp3 ---
        lda #<fe_tmp3
        sta fe_src1
        lda #>fe_tmp3
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_dst
        lda #>fe_tmp3
        sta fe_dst+1
        jsr fe25519_sqr         ; fe_tmp3 = z^8

        ; --- z9 = z8 * z → fe_tmp3 ---
        lda #<fe_tmp3
        sta fe_src1
        lda #>fe_tmp3
        sta fe_src1+1
        lda #<fe_tmp1
        sta fe_src2
        lda #>fe_tmp1
        sta fe_src2+1
        lda #<fe_tmp3
        sta fe_dst
        lda #>fe_tmp3
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp3 = z^9

        ; --- z11 = z9 * z2 → x25_a (saved for final step) ---
        lda #<fe_tmp3
        sta fe_src1
        lda #>fe_tmp3
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_src2
        lda #>fe_tmp2
        sta fe_src2+1
        lda #<x25_a
        sta fe_dst
        lda #>x25_a
        sta fe_dst+1
        jsr fe25519_mul         ; x25_a = z^11

        ; --- z22 = z11^2 → fe_tmp2 ---
        lda #<x25_a
        sta fe_src1
        lda #>x25_a
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_sqr         ; fe_tmp2 = z^22

        ; --- z_5_0 = z22 * z9 = z^31 → fe_tmp2 ---
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_src2
        lda #>fe_tmp3
        sta fe_src2+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp2 = z^(2^5-1)

        ; --- Save z_5_0 to fe_tmp3, square 5x, multiply ---
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_dst
        lda #>fe_tmp3
        sta fe_dst+1
        jsr fe25519_copy        ; fe_tmp3 = z_5_0

        lda #5
        jsr fe_inv_sqrn_tmp2    ; fe_tmp2 = z_5_0^(2^5)

        ; --- z_10_0 = fe_tmp2 * fe_tmp3 → x25_b (saved) ---
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_src2
        lda #>fe_tmp3
        sta fe_src2+1
        lda #<x25_b
        sta fe_dst
        lda #>x25_b
        sta fe_dst+1
        jsr fe25519_mul         ; x25_b = z^(2^10-1)

        ; --- z_20_0: copy z_10_0 to tmp2, square 10x, multiply with z_10_0 ---
        lda #<x25_b
        sta fe_src1
        lda #>x25_b
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_copy        ; fe_tmp2 = z_10_0

        lda #10
        jsr fe_inv_sqrn_tmp2    ; fe_tmp2 = z_10_0^(2^10)

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_b
        sta fe_src2
        lda #>x25_b
        sta fe_src2+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp2 = z^(2^20-1)

        ; --- z_40_0: square 20x, multiply with z_20_0 ---
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_dst
        lda #>fe_tmp3
        sta fe_dst+1
        jsr fe25519_copy        ; fe_tmp3 = z_20_0

        lda #20
        jsr fe_inv_sqrn_tmp2    ; fe_tmp2 = z_20_0^(2^20)

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp3
        sta fe_src2
        lda #>fe_tmp3
        sta fe_src2+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp2 = z^(2^40-1)

        ; --- z_50_0: square 10x, multiply with z_10_0 → x25_da (saved) ---
        lda #10
        jsr fe_inv_sqrn_tmp2    ; fe_tmp2 = z_40_0^(2^10)

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_b
        sta fe_src2
        lda #>x25_b
        sta fe_src2+1
        lda #<x25_da
        sta fe_dst
        lda #>x25_da
        sta fe_dst+1
        jsr fe25519_mul         ; x25_da = z^(2^50-1)

        ; --- z_100_0: copy z_50_0 to tmp2, square 50x, multiply → x25_cb (saved) ---
        lda #<x25_da
        sta fe_src1
        lda #>x25_da
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_copy

        lda #50
        jsr fe_inv_sqrn_tmp2

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_da
        sta fe_src2
        lda #>x25_da
        sta fe_src2+1
        lda #<x25_cb
        sta fe_dst
        lda #>x25_cb
        sta fe_dst+1
        jsr fe25519_mul         ; x25_cb = z^(2^100-1)

        ; --- z_200_0: copy z_100_0 to tmp2, square 100x, multiply ---
        lda #<x25_cb
        sta fe_src1
        lda #>x25_cb
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_copy

        lda #100
        jsr fe_inv_sqrn_tmp2

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_cb
        sta fe_src2
        lda #>x25_cb
        sta fe_src2+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp2 = z^(2^200-1)

        ; --- z_250_0: square 50x, multiply with z_50_0 ---
        lda #50
        jsr fe_inv_sqrn_tmp2

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_da
        sta fe_src2
        lda #>x25_da
        sta fe_src2+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_mul         ; fe_tmp2 = z^(2^250-1)

        ; --- Final: square 5x, multiply with z11 ---
        lda #5
        jsr fe_inv_sqrn_tmp2    ; fe_tmp2 = z^((2^250-1)*2^5) = z^(2^255-32)

        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<x25_a
        sta fe_src2
        lda #>x25_a
        sta fe_src2+1
        ; Restore caller's original fe_dst (saved at entry).
        lda fe_inv_dst
        sta fe_dst
        lda fe_inv_dst+1
        sta fe_dst+1
        jsr fe25519_mul         ; (original fe_dst) = z^(2^255-21) = z^(p-2)

        rts

; =============================================================================
; fe_inv_sqrn_tmp2 - Square fe_tmp2 in place N times
;
; Input: A = number of squarings
; Clobbers: A, X, Y, fe_src1, fe_src2, fe_dst
; =============================================================================
fe_inv_sqrn_tmp2:
        sta fe_inv_sqr_cnt
@loop:
        lda #<fe_tmp2
        sta fe_src1
        lda #>fe_tmp2
        sta fe_src1+1
        lda #<fe_tmp2
        sta fe_dst
        lda #>fe_tmp2
        sta fe_dst+1
        jsr fe25519_sqr
        dec fe_inv_sqr_cnt
        bne @loop
        rts

; =============================================================================
; REU multiplication table routines
; =============================================================================

; =============================================================================
; reu_mul_init - Generate 256 full multiplication rows and stash in REU
;
; For each a = 0..255, computes a*b for b = 0..255 and stashes:
;   256 lo bytes at REU offset a*512
;   256 hi bytes at REU offset a*512+256
;
; Uses mul_dma_lo/mul_dma_hi as staging buffers.
; Uses mul_8x8 (requires sqtab to be initialized first).
; Clobbers: A, X, Y
; =============================================================================
reu_mul_init:
        lda #0
        sta reu_init_a         ; outer counter (multiplier a)

@outer:
        ; For current a, compute a*b for all b=0..255
        lda #0
        sta reu_init_b         ; inner counter (multiplicand b)

@inner:
        lda reu_init_a
        ldx reu_init_b
        jsr mul_8x8            ; poly_prod_lo/hi = a * b

        ldx reu_init_b
        lda poly_prod_lo
        sta mul_dma_lo,x
        lda poly_prod_hi
        sta mul_dma_hi,x

        inc reu_init_b
        bne @inner             ; loop b = 0..255

        ; Stash lo table (256 bytes) to REU at offset a*512
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo         ; REU offset low = 0
        lda reu_init_a
        asl                    ; A = a * 2 (high byte of offset)
        sta reu_reu_hi
        lda #0
        adc #0                 ; carry into bank if a >= 128
        sta reu_bank
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl      ; both addresses increment
        lda #%10110000         ; execute + autoload + STASH (C64->REU)
        sta reu_command

        ; Stash hi table (256 bytes) to REU at offset a*512+256
        lda #<mul_dma_hi
        sta reu_c64_lo
        lda #>mul_dma_hi
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        lda reu_init_a
        asl                    ; a*2 (carry = bit 7 of a)
        lda #0
        adc #0                 ; bank = a >> 7
        sta reu_bank
        lda reu_init_a
        asl                    ; a*2
        ora #1                 ; +1 for hi page (a*2 is even, so OR works)
        sta reu_reu_hi
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl
        lda #%10110000         ; execute + autoload + STASH
        sta reu_command

        inc reu_init_a
        beq @init_done         ; if wrapped to 0, done
        jmp @outer
@init_done:
        ; Pre-configure constant REU registers for fetch routine
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #2
        sta reu_len_hi         ; length high = 2 (512 bytes)
        rts

; =============================================================================
; reu_fetch_mul_row - DMA a multiplication table row from REU to C64
;
; Input: A = multiplier value (0-255) in mul_cached_a
; Fetches 512 bytes: 256 lo bytes to mul_dma_lo, 256 hi bytes to mul_dma_hi
; Clobbers: A
; =============================================================================
reu_fetch_mul_row:
        lda mul_cached_a
        asl                    ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #0
        adc #0                 ; bank = carry from shift
        sta reu_bank
        lda #%10110001         ; execute + autoload + FETCH (REU->C64)
        sta reu_command
        rts

; =============================================================================
; Module-local BSS (mutable state owned by this file)
; =============================================================================
.segment "CRYPTO_BSS"

; Saved destination pointer for fe25519_inv
fe_inv_dst:     .res 2

; Squaring counter for fe_inv_sqrn_tmp2
fe_inv_sqr_cnt: .res 1

; REU mul_init counters
reu_init_a:     .res 1
reu_init_b:     .res 1
