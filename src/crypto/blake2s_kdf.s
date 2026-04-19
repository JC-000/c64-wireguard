; =============================================================================
; blake2s_kdf.s - HMAC-BLAKE2s + WireGuard KDF functions
;
; HMAC-BLAKE2s(key, data) = BLAKE2s(opad || BLAKE2s(ipad || data))
;   where ipad = key XOR 0x36 (padded to 64 bytes)
;         opad = key XOR 0x5c (padded to 64 bytes)
;
; WireGuard KDF (HKDF-like):
;   blake2s_kdf_1(C, input) -> T1
;   blake2s_kdf_2(C, input) -> T1, T2
;   blake2s_kdf_3(C, input) -> T1, T2, T3
;
; where:
;   PRK = HMAC(C, input)
;   T1 = HMAC(PRK, 0x01)
;   T2 = HMAC(PRK, T1 || 0x02)
;   T3 = HMAC(PRK, T2 || 0x03)
; =============================================================================

.include "constants.inc"

.export hmac_blake2s
.export blake2s_kdf_1
.export blake2s_kdf_2
.export blake2s_kdf_3

.import blake2s_init
.import blake2s_update
.import blake2s_final

; Shared data buffers defined in data module
.import b2s_hash
.import hmac_ipad
.import hmac_opad
.import hmac_inner_hash
.import hmac_key_ptr
.import hmac_key_len
.import hmac_data_ptr
.import hmac_data_len
.import kdf_out1
.import kdf_out2
.import kdf_out3
.import kdf_prk
.import kdf_input_ptr
.import kdf_input_len

; =============================================================================
; hmac_blake2s - Compute HMAC-BLAKE2s-256
;
; Input: hmac_key_ptr/hmac_key_len = key
;        hmac_data_ptr/hmac_data_len = data
; Output: b2s_hash (32 bytes)
;
; Clobbers: hmac_ipad, hmac_opad, hmac_inner_hash, all BLAKE2s state
; =============================================================================
.segment "CRYPTO_CODE"

hmac_blake2s:
        ; --- Build ipad and opad ---
        ; zero both pads
        ldx #63
        lda #0
:       sta hmac_ipad,x
        sta hmac_opad,x
        dex
        bpl :-

        ; copy key into both pads (if key > 64 bytes, should hash first,
        ; but BLAKE2s keys are <= 32 bytes so this never happens)
        ; load key pointer into zero page for indirect addressing
        lda hmac_key_ptr
        sta zp_ptr1
        lda hmac_key_ptr+1
        sta zp_ptr1+1
        ldy #0
        ldx hmac_key_len
        beq @pads_xored        ; zero-length key = all zeros
@copy_key:
        lda (zp_ptr1),y
        sta hmac_ipad,y
        sta hmac_opad,y
        iny
        dex
        bne @copy_key

@pads_xored:
        ; XOR ipad with 0x36, opad with 0x5c
        ldx #63
:       lda hmac_ipad,x
        eor #$36
        sta hmac_ipad,x
        lda hmac_opad,x
        eor #$5c
        sta hmac_opad,x
        dex
        bpl :-

        ; --- Inner hash: BLAKE2s(ipad || data) ---
        lda #32
        ldx #0                 ; unkeyed
        jsr blake2s_init

        ; feed ipad (64 bytes)
        lda #<hmac_ipad
        sta b2s_data_ptr
        lda #>hmac_ipad
        sta b2s_data_ptr+1
        lda #64
        sta b2s_remain
        jsr blake2s_update

        ; feed data
        lda hmac_data_ptr
        sta b2s_data_ptr
        lda hmac_data_ptr+1
        sta b2s_data_ptr+1
        lda hmac_data_len
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ; save inner hash
        ldx #31
:       lda b2s_hash,x
        sta hmac_inner_hash,x
        dex
        bpl :-

        ; --- Outer hash: BLAKE2s(opad || inner_hash) ---
        lda #32
        ldx #0
        jsr blake2s_init

        ; feed opad (64 bytes)
        lda #<hmac_opad
        sta b2s_data_ptr
        lda #>hmac_opad
        sta b2s_data_ptr+1
        lda #64
        sta b2s_remain
        jsr blake2s_update

        ; feed inner hash (32 bytes)
        lda #<hmac_inner_hash
        sta b2s_data_ptr
        lda #>hmac_inner_hash
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ; result is in b2s_hash
        rts

; =============================================================================
; blake2s_kdf_1 - WireGuard KDF with 1 output
;
; Input: kdf_input_ptr/kdf_input_len = input data
;        b2s_hash (on entry) = chaining key C (32 bytes)
;        (or: caller sets hmac_key_ptr to C)
; Convention: Caller places C at kdf_prk before calling,
;             or uses the pointer-based interface below.
;
; Output: kdf_out1 = T1 (32 bytes)
;         kdf_prk = new PRK (internal, 32 bytes)
; =============================================================================

; Helper: set up HMAC key from kdf_prk (32 bytes)
kdf_set_hmac_key_prk:
        lda #<kdf_prk
        sta hmac_key_ptr
        lda #>kdf_prk
        sta hmac_key_ptr+1
        lda #32
        sta hmac_key_len
        rts

; =============================================================================
; blake2s_kdf_1 - KDF producing 1 output
; Input: kdf_prk = chaining key C (32 bytes)
;        kdf_input_ptr/kdf_input_len = input
; Output: kdf_out1 = T1, kdf_prk = new PRK
; =============================================================================
blake2s_kdf_1:
        ; PRK = HMAC(C, input)
        jsr kdf_set_hmac_key_prk
        lda kdf_input_ptr
        sta hmac_data_ptr
        lda kdf_input_ptr+1
        sta hmac_data_ptr+1
        lda kdf_input_len
        sta hmac_data_len
        jsr hmac_blake2s

        ; save PRK
        ldx #31
:       lda b2s_hash,x
        sta kdf_prk,x
        dex
        bpl :-

        ; T1 = HMAC(PRK, 0x01)
        jsr kdf_set_hmac_key_prk
        lda #<kdf_counter_1
        sta hmac_data_ptr
        lda #>kdf_counter_1
        sta hmac_data_ptr+1
        lda #1
        sta hmac_data_len
        jsr hmac_blake2s

        ; copy to kdf_out1
        ldx #31
:       lda b2s_hash,x
        sta kdf_out1,x
        dex
        bpl :-

        rts

; =============================================================================
; blake2s_kdf_2 - KDF producing 2 outputs
; Input: same as blake2s_kdf_1
; Output: kdf_out1 = T1, kdf_out2 = T2, kdf_prk = new PRK
; =============================================================================
blake2s_kdf_2:
        ; get T1 first
        jsr blake2s_kdf_1

        ; T2 = HMAC(PRK, T1 || 0x02)
        ; Build T1 || 0x02 in kdf_hmac_buf (33 bytes)
        ldx #31
:       lda kdf_out1,x
        sta kdf_hmac_buf,x
        dex
        bpl :-
        lda #$02
        sta kdf_hmac_buf+32

        jsr kdf_set_hmac_key_prk
        lda #<kdf_hmac_buf
        sta hmac_data_ptr
        lda #>kdf_hmac_buf
        sta hmac_data_ptr+1
        lda #33
        sta hmac_data_len
        jsr hmac_blake2s

        ldx #31
:       lda b2s_hash,x
        sta kdf_out2,x
        dex
        bpl :-

        rts

; =============================================================================
; blake2s_kdf_3 - KDF producing 3 outputs
; Input: same as blake2s_kdf_1
; Output: kdf_out1 = T1, kdf_out2 = T2, kdf_out3 = T3, kdf_prk = new PRK
; =============================================================================
blake2s_kdf_3:
        ; get T1 and T2 first
        jsr blake2s_kdf_2

        ; T3 = HMAC(PRK, T2 || 0x03)
        ldx #31
:       lda kdf_out2,x
        sta kdf_hmac_buf,x
        dex
        bpl :-
        lda #$03
        sta kdf_hmac_buf+32

        jsr kdf_set_hmac_key_prk
        lda #<kdf_hmac_buf
        sta hmac_data_ptr
        lda #>kdf_hmac_buf
        sta hmac_data_ptr+1
        lda #33
        sta hmac_data_len
        jsr hmac_blake2s

        ldx #31
:       lda b2s_hash,x
        sta kdf_out3,x
        dex
        bpl :-

        rts

; --- KDF counter bytes ---
.segment "CRYPTO_RODATA"

kdf_counter_1:  .byte $01
kdf_counter_2:  .byte $02
kdf_counter_3:  .byte $03

; --- KDF HMAC input buffer (T_prev || counter, 33 bytes max) ---
.segment "CRYPTO_BSS"

kdf_hmac_buf:
        .res 33, 0
