; =============================================================================
; aead.asm - ChaCha20-Poly1305 AEAD (RFC 7539 §2.8)
;
; Encrypt: derive OTK, encrypt plaintext, compute tag
; Decrypt: derive OTK, verify tag, decrypt ciphertext
;
; Interface (set in memory before call):
;   aead_key      (32 bytes) — symmetric key
;   aead_nonce    (12 bytes) — nonce
;   aead_aad_ptr  (2 bytes)  — pointer to AAD
;   aead_aad_len  (1 byte)   — AAD length (0-255)
;   aead_data_ptr (2 bytes)  — pointer to plaintext/ciphertext
;   aead_data_len (2 bytes)  — data length (16-bit, up to 1500)
;
; Output:
;   Ciphertext written in-place at aead_data_ptr
;   aead_tag (16 bytes) — authentication tag
;   A register: 0 = success (decrypt), nonzero = auth failure
; =============================================================================

; =============================================================================
; aead_encrypt - ChaCha20-Poly1305 authenticated encryption
;
; 1. Derive Poly1305 OTK using ChaCha20 block with counter=0
; 2. Encrypt plaintext with ChaCha20 starting at counter=1
; 3. Compute Poly1305 tag over (AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths)
;
; Clobbers: A, X, Y
; =============================================================================
aead_encrypt:
        ; --- 1. Derive Poly1305 OTK ---
        jsr aead_derive_otk

        ; --- 2. Encrypt plaintext with ChaCha20 (counter=1) ---
        lda #1
        sta cc20_counter
        lda #0
        sta cc20_counter+1
        sta cc20_counter+2
        sta cc20_counter+3
        jsr aead_setup_chacha   ; set up key/nonce/counter in cc20 state
        jsr chacha20_init

        ; Set up encryption pointers
        lda aead_data_ptr
        sta cc20_data_ptr
        lda aead_data_ptr+1
        sta cc20_data_ptr+1
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        jsr chacha20_encrypt

        ; --- 3. Compute Poly1305 tag ---
        jsr aead_compute_tag
        rts

; =============================================================================
; aead_decrypt - ChaCha20-Poly1305 authenticated decryption
;
; 1. Derive Poly1305 OTK
; 2. Compute expected tag over (AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths)
; 3. Verify tag (constant-time comparison)
; 4. If valid, decrypt ciphertext
;
; Output: A = 0 if tag valid, nonzero if tag mismatch
; Clobbers: A, X, Y
; =============================================================================
aead_decrypt:
        ; --- 1. Derive Poly1305 OTK ---
        jsr aead_derive_otk

        ; --- 2. Compute expected tag (over ciphertext, not plaintext) ---
        jsr aead_compute_tag

        ; --- 3. Verify tag ---
        jsr aead_verify_tag
        bne @auth_fail          ; A != 0 means tag mismatch

        ; --- 4. Decrypt ciphertext with ChaCha20 (counter=1) ---
        lda #1
        sta cc20_counter
        lda #0
        sta cc20_counter+1
        sta cc20_counter+2
        sta cc20_counter+3
        jsr aead_setup_chacha
        jsr chacha20_init

        lda aead_data_ptr
        sta cc20_data_ptr
        lda aead_data_ptr+1
        sta cc20_data_ptr+1
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        jsr chacha20_encrypt    ; XOR = decrypt

        lda #0                  ; success
        rts

@auth_fail:
        lda #$ff               ; failure
        rts

; =============================================================================
; aead_derive_otk - Derive Poly1305 one-time key
;
; ChaCha20 block with counter=0, take first 32 bytes as OTK
; First 16 → poly_r, next 16 → poly_s
; Then initialize Poly1305 state
;
; Clobbers: A, X, Y
; =============================================================================
aead_derive_otk:
        ; Set counter = 0
        lda #0
        sta cc20_counter
        sta cc20_counter+1
        sta cc20_counter+2
        sta cc20_counter+3

        ; Set up ChaCha20 with key/nonce
        jsr aead_setup_chacha
        jsr chacha20_init
        jsr chacha20_block      ; generate 64-byte keystream

        ; Copy first 16 bytes → poly_r
        ldx #15
@copy_r:
        lda cc20_keystream,x
        sta poly_r,x
        dex
        bpl @copy_r

        ; Copy bytes 16-31 → poly_s
        ldx #15
@copy_s:
        lda cc20_keystream+16,x
        sta poly_s,x
        dex
        bpl @copy_s

        ; Initialize Poly1305 (clamp r, zero h, build sqtab)
        jsr poly1305_init
        rts

; =============================================================================
; aead_setup_chacha - Copy aead_key→cc20_key, aead_nonce→cc20_nonce
;
; Also copies cc20_counter (already set by caller).
; Clobbers: A, X
; =============================================================================
aead_setup_chacha:
        ldx #31
@copy_key:
        lda aead_key,x
        sta cc20_key,x
        dex
        bpl @copy_key

        ldx #11
@copy_nonce:
        lda aead_nonce,x
        sta cc20_nonce,x
        dex
        bpl @copy_nonce
        rts

; =============================================================================
; aead_compute_tag - Compute Poly1305 tag for AEAD construction
;
; Poly1305 over: AAD ‖ pad16(AAD) ‖ ciphertext ‖ pad16(CT) ‖ len(AAD) ‖ len(CT)
; where pad16 pads to 16-byte boundary and lengths are 8-byte little-endian
;
; All data is processed as full 16-byte Poly1305 blocks with hibit=1.
; Partial data at the end of AAD or CT is zero-padded to fill a complete block.
;
; Clobbers: A, X, Y
; =============================================================================
aead_compute_tag:
        ; --- Process AAD ---
        lda aead_aad_len
        beq @skip_aad
        sta cc20_remain
        lda #0
        sta cc20_remain_hi      ; AAD length is always <= 255
        lda aead_aad_ptr
        sta zp_ptr1
        lda aead_aad_ptr+1
        sta zp_ptr1+1
        jsr aead_process_padded

@skip_aad:
        ; --- Process ciphertext (16-bit length) ---
        lda aead_data_len
        ora aead_data_len+1
        beq @skip_ct
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        lda aead_data_ptr
        sta zp_ptr1
        lda aead_data_ptr+1
        sta zp_ptr1+1
        jsr aead_process_padded

@skip_ct:
        ; --- Process lengths block (16 bytes) ---
        ; Build: aad_len as 8-byte LE ‖ data_len as 8-byte LE
        ldx #15
        lda #0
@zero_len:
        sta aead_scratch,x
        dex
        bpl @zero_len

        lda aead_aad_len
        sta aead_scratch        ; low byte of AAD length (rest is 0)
        lda aead_data_len
        sta aead_scratch+8      ; low byte of CT length
        lda aead_data_len+1
        sta aead_scratch+9      ; high byte of CT length

        ; Process as one 16-byte block with hibit=1
        lda #<aead_scratch
        sta zp_ptr1
        lda #>aead_scratch
        sta zp_ptr1+1
        lda #1
        jsr poly1305_block

        ; Finalize tag
        jsr poly1305_final
        rts

; =============================================================================
; aead_process_padded - Process data as Poly1305 blocks, zero-padding last block
;
; Input: zp_ptr1 = data pointer
;        cc20_remain = length low byte, cc20_remain_hi = length high byte
; All blocks processed with hibit=1. Last partial block is zero-padded to 16.
;
; Clobbers: A, X, Y
; =============================================================================
aead_process_padded:
@next_block:
        ; Check if done (16-bit)
        lda cc20_remain
        ora cc20_remain_hi
        beq @done

        ; Check if >= 16 bytes remain
        lda cc20_remain_hi
        bne @full_block         ; > 255 remaining, definitely >= 16
        lda cc20_remain
        cmp #16
        bcc @partial            ; < 16 bytes left

@full_block:
        ; Full 16-byte block with hibit=1
        lda #1
        jsr poly1305_block

        ; Advance pointer by 16
        clc
        lda zp_ptr1
        adc #16
        sta zp_ptr1
        lda zp_ptr1+1
        adc #0
        sta zp_ptr1+1

        ; 16-bit subtract 16
        lda cc20_remain
        sec
        sbc #16
        sta cc20_remain
        lda cc20_remain_hi
        sbc #0
        sta cc20_remain_hi
        jmp @next_block

@partial:
        ; Copy remaining bytes to scratch, zero-pad to 16
        ldx #15
        lda #0
@zero_scratch:
        sta aead_scratch,x
        dex
        bpl @zero_scratch

        ldy #0
        ldx cc20_remain
@copy_partial:
        lda (zp_ptr1),y
        sta aead_scratch,y
        iny
        dex
        bne @copy_partial

        ; Process zero-padded block with hibit=1
        lda #<aead_scratch
        sta zp_ptr1
        lda #>aead_scratch
        sta zp_ptr1+1
        lda #1
        jsr poly1305_block

@done:
        rts

; =============================================================================
; aead_verify_tag - Constant-time comparison of computed vs provided tag
;
; Compares poly1305_tag with aead_tag (16 bytes)
; Output: A = 0 if equal, nonzero if different
;
; Clobbers: A, X
; =============================================================================
aead_verify_tag:
        lda #0
        sta poly_carry          ; zero the accumulator
        ldx #15
@cmp_loop:
        lda poly1305_tag,x
        eor aead_tag,x
        ora poly_carry          ; accumulate differences
        sta poly_carry
        dex
        bpl @cmp_loop
        lda poly_carry          ; 0 = match, nonzero = mismatch
        rts
