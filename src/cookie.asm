; =============================================================================
; cookie.asm - Type 3 cookie reply handling (XChaCha20-Poly1305)
;
; Type 3 packet format (64 bytes in udp_recv_buf):
;   [0-3]   type=3, reserved
;   [4-7]   receiver_index (our sender_idx)
;   [8-31]  nonce (24 bytes)
;   [32-47] encrypted cookie (16 bytes)
;   [48-63] Poly1305 tag (16 bytes)
;
; Interface:
;   hchacha20           - HChaCha20 subkey derivation
;   cookie_handle_type3 - process Type 3 cookie reply
;   hs_set_mac2         - compute MAC2 from cookie and set in hs_packet
; =============================================================================

; Cookie label for key derivation
wg_cookie_label:
        !text "cookie--"

; =============================================================================
; hchacha20 - HChaCha20 subkey derivation
;
; Like ChaCha20 block function but extracts words 0-3 and 12-15
; from the working state (without adding initial state back).
;
; Input: cc20_key (32B key), cc20_counter (nonce[0..3]),
;        cc20_nonce (nonce[4..15])
; Output: cc20_key (32B subkey)
; Clobbers: A, X, Y, cc20_state, cc20_work
; =============================================================================
hchacha20:
        ; Set up state via chacha20_init
        jsr chacha20_init

        ; Copy cc20_state → cc20_work (64 bytes)
        ldx #63
@hc_copy:
        lda cc20_state,x
        sta cc20_work,x
        dex
        bpl @hc_copy

        ; Run 10 double-rounds (20 rounds total)
        lda #10
        sta cc20_round
@hc_dr:
        lda #0
        sta cc20_qr_idx
@hc_qr:
        jsr chacha20_quarter_round
        lda cc20_qr_idx
        clc
        adc #4
        sta cc20_qr_idx
        cmp #32
        bcc @hc_qr
        dec cc20_round
        bne @hc_dr

        ; Extract subkey: work[0..15] → cc20_key[0..15]
        ldx #15
@hc_out1:
        lda cc20_work,x
        sta cc20_key,x
        dex
        bpl @hc_out1

        ; Extract subkey: work[48..63] → cc20_key[16..31]
        ldx #15
@hc_out2:
        lda cc20_work+48,x
        sta cc20_key+16,x
        dex
        bpl @hc_out2

        rts

; =============================================================================
; cookie_handle_type3 - Process Type 3 cookie reply
;
; 1. Derive cookie_key = BLAKE2s-256("cookie--" || cfg_peer_pub)
; 2. HChaCha20(cookie_key, nonce[0..15]) → subkey
; 3. XChaCha20-Poly1305 decrypt cookie with subkey + nonce[16..23]
;    AAD = mac1 from last sent initiation (hs_packet+116, 16 bytes)
;
; Input: udp_recv_buf has Type 3 packet
; Output: A=0 success (cookie_buf filled, cookie_valid=1), A=$FF fail
; Clobbers: everything
; =============================================================================
cookie_handle_type3:
        ; 1. Derive cookie_key = BLAKE2s("cookie--" || cfg_peer_pub)
        lda #32
        ldx #0                  ; unkeyed
        jsr blake2s_init

        lda #<wg_cookie_label
        sta b2s_data_ptr
        lda #>wg_cookie_label
        sta b2s_data_ptr+1
        lda #8
        sta b2s_remain
        jsr blake2s_update

        lda #<cfg_peer_pub
        sta b2s_data_ptr
        lda #>cfg_peer_pub
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ; 2. Copy b2s_hash → cc20_key (cookie decryption key)
        ldx #31
@copy_key:
        lda b2s_hash,x
        sta cc20_key,x
        dex
        bpl @copy_key

        ; 3. HChaCha20 setup: nonce[0..3] → cc20_counter, nonce[4..15] → cc20_nonce
        ldx #3
@copy_cnt:
        lda udp_recv_buf+8,x
        sta cc20_counter,x
        dex
        bpl @copy_cnt

        ldx #11
@copy_nce:
        lda udp_recv_buf+12,x
        sta cc20_nonce,x
        dex
        bpl @copy_nce

        jsr hchacha20           ; cc20_key now has 32-byte subkey

        ; 4. Set up AEAD decrypt
        ; aead_key = cc20_key (subkey)
        ldx #31
@copy_akey:
        lda cc20_key,x
        sta aead_key,x
        dex
        bpl @copy_akey

        ; aead_nonce: 4 zero bytes + nonce[16..23]
        ldx #3
        lda #0
@zero_an:
        sta aead_nonce,x
        dex
        bpl @zero_an

        ldx #7
@copy_an:
        lda udp_recv_buf+24,x
        sta aead_nonce+4,x
        dex
        bpl @copy_an

        ; AAD = mac1 from last sent initiation (hs_packet+116, 16 bytes)
        lda #<(hs_packet+116)
        sta aead_aad_ptr
        lda #>(hs_packet+116)
        sta aead_aad_ptr+1
        lda #16
        sta aead_aad_len

        ; Copy encrypted cookie to cookie_buf for in-place decrypt
        ldx #15
@copy_edata:
        lda udp_recv_buf+32,x
        sta cookie_buf,x
        dex
        bpl @copy_edata

        ; aead_data_ptr → cookie_buf, len = 16
        lda #<cookie_buf
        sta aead_data_ptr
        lda #>cookie_buf
        sta aead_data_ptr+1
        lda #16
        sta aead_data_len
        lda #0
        sta aead_data_len+1

        ; Copy tag from packet
        ldx #15
@copy_tag:
        lda udp_recv_buf+48,x
        sta aead_tag,x
        dex
        bpl @copy_tag

        ; 5. Decrypt
        jsr aead_decrypt
        cmp #0
        bne @fail

        ; Success: cookie_buf has 16-byte decrypted cookie
        lda #1
        sta cookie_valid
        lda #0
        rts

@fail:
        lda #$ff
        rts

; =============================================================================
; hs_set_mac2 - Compute MAC2 from cookie and store in hs_packet+132
;
; MAC2 = BLAKE2s-128(cookie_buf, hs_packet[0..131])
; (keyed BLAKE2s, 16-byte output, key = cookie_buf)
;
; Output: hs_packet+132..147 = MAC2
; Side effect: clears cookie_valid
; Clobbers: A, X, Y, BLAKE2s state
; =============================================================================
hs_set_mac2:
        ; Copy cookie_buf to input_buffer for keyed init
        ldx #15
@copy_cookie:
        lda cookie_buf,x
        sta input_buffer,x
        dex
        bpl @copy_cookie

        ; Keyed BLAKE2s: output=16, key=16
        lda #16
        ldx #16
        stx b2s_key_len
        sta b2s_out_len
        jsr blake2s_init

        ; Feed hs_packet[0..131] (132 bytes)
        lda #<hs_packet
        sta b2s_data_ptr
        lda #>hs_packet
        sta b2s_data_ptr+1
        lda #132
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ; Copy b2s_hash[0..15] → hs_packet+132
        ldx #15
@copy_mac2:
        lda b2s_hash,x
        sta hs_packet+132,x
        dex
        bpl @copy_mac2

        ; Clear cookie_valid
        lda #0
        sta cookie_valid
        rts
