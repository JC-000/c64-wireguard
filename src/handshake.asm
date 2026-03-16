; =============================================================================
; handshake.asm - WireGuard IKpsk2 Noise Handshake (Initiator)
;
; Generates 148-byte Type 1 initiation packet.
; Parses 92-byte Type 2 response and derives transport keys.
;
; Uses BLAKE2s, HMAC-BLAKE2s, KDF, ChaCha20-Poly1305 AEAD, X25519.
;
; Handshake flow (initiator):
;   1. hs_init: initialize C, H from construction + responder pubkey
;   2. Generate ephemeral keypair
;   3. Mix ephemeral public key into hash
;   4. KDF with ephemeral DH
;   5. AEAD encrypt static public key
;   6. KDF with static DH
;   7. AEAD encrypt timestamp
;   8. Compute MAC1
;
; Interface:
;   hs_static_priv  (32 bytes) — our static private key
;   hs_static_pub   (32 bytes) — our static public key
;   hs_resp_pub     (32 bytes) — responder's static public key
;   hs_ephem_priv   (32 bytes) — ephemeral private key (caller provides)
;   hs_sender_idx   (4 bytes)  — sender index
;   hs_timestamp    (12 bytes) — TAI64N timestamp
;
; Output:
;   hs_packet       (148 bytes) — Type 1 initiation packet
;   hs_c            (32 bytes)  — final chaining key (for response processing)
;   hs_h            (32 bytes)  — final hash
; =============================================================================

; --- Precomputed Noise constants ---

; C_init = BLAKE2s("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
wg_c_init:
        !byte $60, $e2, $6d, $ae, $f3, $27, $ef, $c0
        !byte $2e, $c3, $35, $e2, $a0, $25, $d2, $d0
        !byte $16, $eb, $42, $06, $f8, $72, $77, $f5
        !byte $2d, $38, $d1, $98, $8b, $78, $cd, $36

; H_init = BLAKE2s(C_init || "WireGuard v1 zx2c4 Jason@zx2c4.com")
wg_h_init:
        !byte $22, $11, $b3, $61, $08, $1a, $c5, $66
        !byte $69, $12, $43, $db, $45, $8a, $d5, $32
        !byte $2d, $9c, $6c, $66, $22, $93, $e8, $b7
        !byte $0e, $e1, $9c, $65, $ba, $07, $9e, $f3

; MAC1 label
wg_mac1_label:
        !text "mac1----"

; =============================================================================
; hs_init - Initialize handshake state
;
; Sets C = C_init
; Computes H = BLAKE2s(H_init || responder_pub)
; Precomputes mac1_key = BLAKE2s(label || responder_pub)
;
; Input: hs_resp_pub (32 bytes)
; Output: hs_c, hs_h, hs_mac1_key
; Clobbers: A, X, Y, BLAKE2s state
; =============================================================================
hs_init:
        ; C = C_init
        ldx #31
@copy_c:
        lda wg_c_init,x
        sta hs_c,x
        dex
        bpl @copy_c

        ; H = BLAKE2s(H_init || responder_pub)
        lda #32
        ldx #0                 ; unkeyed
        jsr blake2s_init

        lda #<wg_h_init
        sta b2s_data_ptr
        lda #>wg_h_init
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        lda #<hs_resp_pub
        sta b2s_data_ptr
        lda #>hs_resp_pub
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ; Copy result to hs_h
        ldx #31
@copy_h:
        lda b2s_hash,x
        sta hs_h,x
        dex
        bpl @copy_h

        ; mac1_key = BLAKE2s("mac1----" || responder_pub)
        lda #32
        ldx #0
        jsr blake2s_init

        lda #<wg_mac1_label
        sta b2s_data_ptr
        lda #>wg_mac1_label
        sta b2s_data_ptr+1
        lda #8
        sta b2s_remain
        jsr blake2s_update

        lda #<hs_resp_pub
        sta b2s_data_ptr
        lda #>hs_resp_pub
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        ldx #31
@copy_mac1:
        lda b2s_hash,x
        sta hs_mac1_key,x
        dex
        bpl @copy_mac1

        rts

; =============================================================================
; hs_mix_hash - Mix data into handshake hash
;
; H = BLAKE2s(H || data)
;
; Input: zp_ptr1 = pointer to data, b2s_remain = length
; Output: hs_h updated
; Clobbers: A, X, Y, BLAKE2s state
; =============================================================================
hs_mix_hash:
        ; Save data pointer and length (BLAKE2s init will reset state)
        lda zp_ptr1
        pha
        lda zp_ptr1+1
        pha
        lda b2s_remain
        pha

        lda #32
        ldx #0
        jsr blake2s_init

        ; Feed H (32 bytes)
        lda #<hs_h
        sta b2s_data_ptr
        lda #>hs_h
        sta b2s_data_ptr+1
        lda #32
        sta b2s_remain
        jsr blake2s_update

        ; Feed data
        pla
        sta b2s_remain
        pla
        sta b2s_data_ptr+1
        pla
        sta b2s_data_ptr
        jsr blake2s_update

        jsr blake2s_final

        ; Copy to hs_h
        ldx #31
@copy:
        lda b2s_hash,x
        sta hs_h,x
        dex
        bpl @copy
        rts

; =============================================================================
; hs_create_initiation - Build complete 148-byte Type 1 packet
;
; Requires all inputs set: hs_static_priv, hs_static_pub, hs_resp_pub,
;   hs_ephem_priv, hs_sender_idx, hs_timestamp
;
; Steps:
;   1. hs_init (C, H, mac1_key)
;   2. Generate ephemeral public key
;   3. Packet header + copy e_pub
;   4. mix_hash(e_pub) + kdf_1(C, e_pub)
;   5. DH(ephem_priv, resp_pub) + kdf_2
;   6. AEAD encrypt static_pub
;   7. mix_hash(encrypted_static)
;   8. DH(static_priv, resp_pub) + kdf_2
;   9. AEAD encrypt timestamp
;   10. mix_hash(encrypted_timestamp)
;   11. MAC1 + zeros for MAC2
;
; Output: hs_packet (148 bytes)
; Clobbers: everything
; =============================================================================
hs_create_initiation:
        ; --- 1. Initialize C, H, mac1_key ---
        jsr hs_init

        ; --- 2. Generate ephemeral public key ---
        ; x25519_base(ephem_priv) → ephem_pub
        ldx #31
@copy_epriv:
        lda hs_ephem_priv,x
        sta x25_scalar,x
        dex
        bpl @copy_epriv
        jsr x25519_base        ; x25_result = ephem_pub

        ; Copy result to hs_ephem_pub
        ldx #31
@copy_epub:
        lda x25_result,x
        sta hs_ephem_pub,x
        dex
        bpl @copy_epub

        ; --- 3. Packet header ---
        lda #1                 ; type = 1 (initiator)
        sta hs_packet
        lda #0
        sta hs_packet+1        ; reserved
        sta hs_packet+2
        sta hs_packet+3

        ; sender index (4 bytes at offset 4)
        ldx #3
@copy_idx:
        lda hs_sender_idx,x
        sta hs_packet+4,x
        dex
        bpl @copy_idx

        ; unencrypted_ephemeral (32 bytes at offset 8)
        ldx #31
@copy_e:
        lda hs_ephem_pub,x
        sta hs_packet+8,x
        dex
        bpl @copy_e

        ; --- 4. mix_hash(e_pub, 32) ---
        lda #<hs_ephem_pub
        sta zp_ptr1
        lda #>hs_ephem_pub
        sta zp_ptr1+1
        lda #32
        sta b2s_remain
        jsr hs_mix_hash

        ; kdf_1(C, e_pub): C gets updated, kdf_out1 = new C
        ; Save C to kdf_prk, set input to e_pub
        ldx #31
@save_c1:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c1

        lda #<hs_ephem_pub
        sta kdf_input_ptr
        lda #>hs_ephem_pub
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_1

        ; Update C from kdf_out1
        ldx #31
@upd_c1:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c1

        ; --- 5. DH(ephem_priv, resp_pub) ---
        ldx #31
@copy_ep2:
        lda hs_ephem_priv,x
        sta x25_scalar,x
        lda hs_resp_pub,x
        sta x25_u,x
        dex
        bpl @copy_ep2
        jsr x25519_clamp
        jsr x25519_scalarmult  ; x25_result = DH

        ; Copy DH result to hs_dh_result
        ldx #31
@copy_dh1:
        lda x25_result,x
        sta hs_dh_result,x
        dex
        bpl @copy_dh1

        ; kdf_2(C, dh_result) → new C + encryption key
        ldx #31
@save_c2:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c2

        lda #<hs_dh_result
        sta kdf_input_ptr
        lda #>hs_dh_result
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_2

        ; C = kdf_out1
        ldx #31
@upd_c2:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c2
        ; kdf_out2 = encryption key for static

        ; --- 6. AEAD encrypt static_pub (32 bytes + 16 tag) ---
        ; key = kdf_out2, nonce = 0, AAD = hs_h, plaintext = hs_static_pub
        ldx #31
@copy_key1:
        lda kdf_out2,x
        sta aead_key,x
        dex
        bpl @copy_key1

        ; Zero nonce
        ldx #11
        lda #0
@zero_nonce1:
        sta aead_nonce,x
        dex
        bpl @zero_nonce1

        ; AAD = hs_h
        lda #<hs_h
        sta aead_aad_ptr
        lda #>hs_h
        sta aead_aad_ptr+1
        lda #32
        sta aead_aad_len

        ; Copy static_pub to packet area for in-place encryption
        ldx #31
@copy_spub:
        lda hs_static_pub,x
        sta hs_packet+40,x
        dex
        bpl @copy_spub

        ; Data = packet[40..71] (32 bytes of static_pub)
        lda #<(hs_packet+40)
        sta aead_data_ptr
        lda #>(hs_packet+40)
        sta aead_data_ptr+1
        lda #32
        sta aead_data_len

        jsr aead_encrypt

        ; Copy tag to packet[72..87]
        ldx #15
@copy_tag1:
        lda poly1305_tag,x
        sta hs_packet+72,x
        dex
        bpl @copy_tag1

        ; --- 7. mix_hash(encrypted_static, 48) ---
        lda #<(hs_packet+40)
        sta zp_ptr1
        lda #>(hs_packet+40)
        sta zp_ptr1+1
        lda #48
        sta b2s_remain
        jsr hs_mix_hash

        ; --- 8. DH(static_priv, resp_pub) ---
        ldx #31
@copy_sp2:
        lda hs_static_priv,x
        sta x25_scalar,x
        lda hs_resp_pub,x
        sta x25_u,x
        dex
        bpl @copy_sp2
        jsr x25519_clamp
        jsr x25519_scalarmult

        ldx #31
@copy_dh2:
        lda x25_result,x
        sta hs_dh_result,x
        dex
        bpl @copy_dh2

        ; kdf_2(C, dh_result) → new C + key
        ldx #31
@save_c3:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c3

        lda #<hs_dh_result
        sta kdf_input_ptr
        lda #>hs_dh_result
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_2

        ldx #31
@upd_c3:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c3

        ; --- 9. AEAD encrypt timestamp (12 bytes + 16 tag) ---
        ldx #31
@copy_key2:
        lda kdf_out2,x
        sta aead_key,x
        dex
        bpl @copy_key2

        ldx #11
        lda #0
@zero_nonce2:
        sta aead_nonce,x
        dex
        bpl @zero_nonce2

        lda #<hs_h
        sta aead_aad_ptr
        lda #>hs_h
        sta aead_aad_ptr+1
        lda #32
        sta aead_aad_len

        ; Copy timestamp to packet area for in-place encryption
        ldx #11
@copy_ts:
        lda hs_timestamp,x
        sta hs_packet+88,x
        dex
        bpl @copy_ts

        lda #<(hs_packet+88)
        sta aead_data_ptr
        lda #>(hs_packet+88)
        sta aead_data_ptr+1
        lda #12
        sta aead_data_len

        jsr aead_encrypt

        ; Copy tag to packet[100..115]
        ldx #15
@copy_tag2:
        lda poly1305_tag,x
        sta hs_packet+100,x
        dex
        bpl @copy_tag2

        ; --- 10. mix_hash(encrypted_timestamp, 28) ---
        lda #<(hs_packet+88)
        sta zp_ptr1
        lda #>(hs_packet+88)
        sta zp_ptr1+1
        lda #28
        sta b2s_remain
        jsr hs_mix_hash

        ; --- 11. MAC1 ---
        jsr hs_compute_mac1

        ; Copy MAC1 to packet[116..131]
        ldx #15
@copy_mac1:
        lda b2s_hash,x
        sta hs_packet+116,x
        dex
        bpl @copy_mac1

        ; MAC2: use cookie if available, else zeros
        lda cookie_valid
        beq @zero_mac2
        jsr hs_set_mac2
        jmp @mac2_done
@zero_mac2:
        ldx #15
        lda #0
@clr_mac2:
        sta hs_packet+132,x
        dex
        bpl @clr_mac2
@mac2_done:

        rts

; =============================================================================
; hs_compute_mac1 - Compute MAC1 for packet
;
; MAC1 = BLAKE2s-128(mac1_key, packet[0..115])
; (BLAKE2s keyed with mac1_key, output truncated to 16 bytes)
;
; Output: b2s_hash[0..15] = MAC1 (16 bytes)
; Clobbers: A, X, Y, BLAKE2s state
; =============================================================================
hs_compute_mac1:
        ; Keyed BLAKE2s with 16-byte output
        ; Copy mac1_key to input_buffer for keyed init
        ldx #31
@copy_key:
        lda hs_mac1_key,x
        sta input_buffer,x
        dex
        bpl @copy_key

        lda #16                ; output length = 16 (truncated)
        ldx #32                ; key length = 32
        stx b2s_key_len
        sta b2s_out_len
        jsr blake2s_init

        ; Feed packet[0..115] (116 bytes)
        lda #<hs_packet
        sta b2s_data_ptr
        lda #>hs_packet
        sta b2s_data_ptr+1
        lda #116
        sta b2s_remain
        jsr blake2s_update

        jsr blake2s_final

        rts

; =============================================================================
; hs_process_response - Process Type 2 response and derive transport keys
;
; Input: hs_resp_packet (92 bytes), hs_c, hs_h from initiation
; Output: hs_transport_send, hs_transport_recv (32 bytes each)
;         A = 0 on success, nonzero on AEAD failure
;
; Response format (92 bytes):
;   [0..3]   type=2, reserved
;   [4..7]   sender_index (responder's)
;   [8..11]  receiver_index (our sender_index)
;   [12..43] unencrypted_ephemeral (responder's e_pub)
;   [44..59] encrypted_nothing (AEAD tag only, 0 bytes + 16 tag)
;   [60..75] mac1
;   [76..91] mac2
;
; Clobbers: everything
; =============================================================================
hs_process_response:
        ; mix_hash(resp_e_pub, 32)
        lda #<(hs_resp_packet+12)
        sta zp_ptr1
        lda #>(hs_resp_packet+12)
        sta zp_ptr1+1
        lda #32
        sta b2s_remain
        jsr hs_mix_hash

        ; kdf_1(C, resp_e_pub)
        ldx #31
@save_c1:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c1

        lda #<(hs_resp_packet+12)
        sta kdf_input_ptr
        lda #>(hs_resp_packet+12)
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_1

        ldx #31
@upd_c1:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c1

        ; DH(ephem_priv, resp_e_pub)
        ldx #31
@copy1:
        lda hs_ephem_priv,x
        sta x25_scalar,x
        lda hs_resp_packet+12,x
        sta x25_u,x
        dex
        bpl @copy1
        jsr x25519_clamp
        jsr x25519_scalarmult

        ; kdf_1(C, dh_result)
        ldx #31
@save_c2:
        lda hs_c,x
        sta kdf_prk,x
        lda x25_result,x
        sta hs_dh_result,x
        dex
        bpl @save_c2

        lda #<hs_dh_result
        sta kdf_input_ptr
        lda #>hs_dh_result
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_1

        ldx #31
@upd_c2:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c2

        ; DH(static_priv, resp_e_pub)
        ldx #31
@copy2:
        lda hs_static_priv,x
        sta x25_scalar,x
        lda hs_resp_packet+12,x
        sta x25_u,x
        dex
        bpl @copy2
        jsr x25519_clamp
        jsr x25519_scalarmult

        ; kdf_1(C, dh_result)
        ldx #31
@save_c3:
        lda hs_c,x
        sta kdf_prk,x
        lda x25_result,x
        sta hs_dh_result,x
        dex
        bpl @save_c3

        lda #<hs_dh_result
        sta kdf_input_ptr
        lda #>hs_dh_result
        sta kdf_input_ptr+1
        lda #32
        sta kdf_input_len
        jsr kdf_1

        ldx #31
@upd_c3:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c3

        ; AEAD decrypt empty message (verify tag)
        ; kdf_2(C, empty) → C + key
        ldx #31
@save_c4:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c4

        lda #<hs_hs_empty
        sta kdf_input_ptr
        lda #>hs_hs_empty
        sta kdf_input_ptr+1
        lda #0
        sta kdf_input_len
        jsr kdf_2

        ldx #31
@upd_c4:
        lda kdf_out1,x
        sta hs_c,x
        dex
        bpl @upd_c4

        ; Verify AEAD tag (empty plaintext, 16-byte tag at packet[44..59])
        ldx #31
@copy_key:
        lda kdf_out2,x
        sta aead_key,x
        dex
        bpl @copy_key

        ldx #11
        lda #0
@zero_nonce:
        sta aead_nonce,x
        dex
        bpl @zero_nonce

        ; AAD = hs_h, data_len = 0
        lda #<hs_h
        sta aead_aad_ptr
        lda #>hs_h
        sta aead_aad_ptr+1
        lda #32
        sta aead_aad_len
        lda #0
        sta aead_data_len
        ; Need to set expected tag
        ldx #15
@copy_tag:
        lda hs_resp_packet+44,x
        sta aead_tag,x
        dex
        bpl @copy_tag

        ; Use a dummy data pointer
        lda #<hs_dh_result
        sta aead_data_ptr
        lda #>hs_dh_result
        sta aead_data_ptr+1

        jsr aead_decrypt
        cmp #0
        bne @auth_fail

        ; mix_hash(encrypted_nothing, 16)
        lda #<(hs_resp_packet+44)
        sta zp_ptr1
        lda #>(hs_resp_packet+44)
        sta zp_ptr1+1
        lda #16
        sta b2s_remain
        jsr hs_mix_hash

        ; Derive transport keys: kdf_2(C, empty) → send_key, recv_key
        ldx #31
@save_c5:
        lda hs_c,x
        sta kdf_prk,x
        dex
        bpl @save_c5

        lda #<hs_hs_empty
        sta kdf_input_ptr
        lda #>hs_hs_empty
        sta kdf_input_ptr+1
        lda #0
        sta kdf_input_len
        jsr kdf_2

        ; Transport send key = kdf_out1, recv key = kdf_out2
        ldx #31
@copy_transport:
        lda kdf_out1,x
        sta hs_transport_send,x
        lda kdf_out2,x
        sta hs_transport_recv,x
        dex
        bpl @copy_transport

        lda #0                 ; success
        rts

@auth_fail:
        lda #$ff               ; failure
        rts

; Empty input for KDF calls with no input data
hs_hs_empty:
        !byte 0
