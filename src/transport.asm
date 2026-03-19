; =============================================================================
; transport.asm - WireGuard Type 4 transport data packets
;
; Encrypt outgoing payloads and decrypt incoming payloads using transport
; keys derived during Noise handshake.
;
; Type 4 packet format:
;   [0-3]   type = $04, $00, $00, $00 (LE u32 = 4)
;   [4-7]   receiver_index (4 bytes, LE)
;   [8-15]  counter (8 bytes, LE u64)
;   [16+]   encrypted payload + 16-byte Poly1305 tag
;
; AEAD nonce: 4 zero bytes + 8-byte counter = 12 bytes
; AEAD AAD: empty (0 bytes) for transport
; AEAD key: hs_transport_send (encrypt) or hs_transport_recv (decrypt)
; =============================================================================

; =============================================================================
; transport_init - Initialize transport state from handshake
;
; Zeros send/recv counters, copies peer's sender_index from response packet.
; Call after hs_process_response succeeds.
;
; Input: hs_resp_packet (92 bytes) — Type 2 response
; Output: tp_send_counter, tp_recv_counter zeroed
;         tp_peer_recv_idx = hs_resp_packet[4..7]
; Clobbers: A, X
; =============================================================================
transport_init:
        ; zero send counter (8 bytes)
        lda #0
        ldx #7
@zero_send:
        sta tp_send_counter,x
        dex
        bpl @zero_send

        ; zero recv counter (8 bytes)
        ldx #7
@zero_recv:
        sta tp_recv_counter,x
        dex
        bpl @zero_recv

        ; zero replay window bitmap (256 bytes)
        ldx #0
@zero_bm:
        sta rw_bitmap,x
        inx
        bne @zero_bm

        ; zero replay window counter max (8 bytes)
        ldx #7
@zero_rwmax:
        sta rw_counter_max,x
        dex
        bpl @zero_rwmax

        ; zero new-counter flag
        sta rw_new_counter

        ; copy peer's sender_index from response packet[4..7]
        ldx #3
@copy_idx:
        lda hs_resp_packet+4,x
        sta tp_peer_recv_idx,x
        dex
        bpl @copy_idx

        rts

; =============================================================================
; counter_inc64 - Increment a 64-bit little-endian counter
;
; Input: zp_ptr1 points to 8-byte counter
; Output: counter incremented by 1
; Clobbers: A, Y
; =============================================================================
counter_inc64:
        clc
        ldy #0
        lda (zp_ptr1),y
        adc #1
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
        bcc @done
        iny
        lda (zp_ptr1),y
        adc #0
        sta (zp_ptr1),y
@done:
        rts

; =============================================================================
; transport_build_nonce - Build 12-byte AEAD nonce from counter
;
; AEAD nonce = 4 zero bytes + 8-byte counter
;
; Input: zp_ptr1 points to 8-byte counter
; Output: aead_nonce filled (12 bytes)
; Clobbers: A, X, Y
; =============================================================================
transport_build_nonce:
        ; first 4 bytes = 0
        lda #0
        sta aead_nonce
        sta aead_nonce+1
        sta aead_nonce+2
        sta aead_nonce+3

        ; next 8 bytes = counter
        ldy #0
@copy:
        lda (zp_ptr1),y
        sta aead_nonce+4,y
        iny
        cpy #8
        bne @copy

        rts

; =============================================================================
; transport_encrypt - Encrypt payload into Type 4 packet
;
; Input:
;   tp_payload_ptr  — pointer to plaintext data
;   tp_payload_len  — payload length (max ~220)
;   hs_transport_send — 32-byte send key
;   tp_peer_recv_idx — 4-byte receiver index
;   tp_send_counter — 8-byte send counter
;
; Output:
;   tp_packet — complete Type 4 packet
;   tp_packet_len — total packet length (16 + payload + 16)
;   tp_send_counter — incremented
;
; Clobbers: A, X, Y
; =============================================================================
transport_encrypt:
        ; --- 1. Write header ---
        ; type = 4 (LE u32)
        lda #$04
        sta tp_packet
        lda #$00
        sta tp_packet+1
        sta tp_packet+2
        sta tp_packet+3

        ; receiver_index (4 bytes at offset 4)
        ldx #3
@copy_idx:
        lda tp_peer_recv_idx,x
        sta tp_packet+4,x
        dex
        bpl @copy_idx

        ; counter (8 bytes at offset 8)
        ldx #7
@copy_ctr:
        lda tp_send_counter,x
        sta tp_packet+8,x
        dex
        bpl @copy_ctr

        ; --- 2. Copy plaintext to tp_packet+16 for in-place AEAD ---
        lda tp_payload_ptr
        sta zp_ptr1
        lda tp_payload_ptr+1
        sta zp_ptr1+1
        ldy #0
        ldx tp_payload_len
        beq @skip_copy
@copy_pt:
        lda (zp_ptr1),y
        sta tp_packet+16,y
        iny
        dex
        bne @copy_pt
@skip_copy:

        ; --- 3. Set up AEAD ---
        ; Copy hs_transport_send → aead_key
        ldx #31
@copy_key:
        lda hs_transport_send,x
        sta aead_key,x
        dex
        bpl @copy_key

        ; Build nonce from send counter
        lda #<tp_send_counter
        sta zp_ptr1
        lda #>tp_send_counter
        sta zp_ptr1+1
        jsr transport_build_nonce

        ; AAD = empty
        lda #0
        sta aead_aad_len

        ; Data pointer = tp_packet+16 (in-place)
        lda #<(tp_packet+16)
        sta aead_data_ptr
        lda #>(tp_packet+16)
        sta aead_data_ptr+1
        lda tp_payload_len
        sta aead_data_len

        ; --- 4. Encrypt ---
        jsr aead_encrypt

        ; --- 5. Append Poly1305 tag after ciphertext ---
        ; tag goes at tp_packet + 16 + payload_len
        lda #<(tp_packet+16)
        clc
        adc tp_payload_len
        sta zp_ptr1
        lda #>(tp_packet+16)
        adc #0
        sta zp_ptr1+1

        ldy #0
@copy_tag:
        lda poly1305_tag,y
        sta (zp_ptr1),y
        iny
        cpy #16
        bne @copy_tag

        ; --- 6. Set tp_packet_len = 16 + payload_len + 16 = 32 + payload_len ---
        lda tp_payload_len
        clc
        adc #32
        sta tp_packet_len
        lda #0
        adc #0
        sta tp_packet_len+1

        ; --- 7. Increment send counter ---
        lda #<tp_send_counter
        sta zp_ptr1
        lda #>tp_send_counter
        sta zp_ptr1+1
        jsr counter_inc64

        rts

; =============================================================================
; transport_decrypt - Decrypt incoming Type 4 packet
;
; Input:
;   udp_recv_buf — received packet data
;   udp_recv_len — received packet length
;   hs_transport_recv — 32-byte recv key
;   tp_recv_counter — 8-byte next minimum accepted counter
;
; Output:
;   tp_packet+16 — decrypted plaintext
;   tp_payload_len — plaintext length
;   A = 0 on success, A = $FF on failure
;   tp_recv_counter — updated on success
;
; Clobbers: A, X, Y
; =============================================================================
transport_decrypt:
        ; --- 1. Verify type byte ---
        lda udp_recv_buf
        cmp #$04
        beq @type_ok
        lda #$ff
        rts
@type_ok:

        ; --- 2. Extract counter from packet[8..15] ---
        ldx #7
@copy_ctr:
        lda udp_recv_buf+8,x
        sta tp_recv_counter_tmp,x
        dex
        bpl @copy_ctr

        ; --- 3. Sliding window replay check ---
        ; Compare received (tp_recv_counter_tmp) vs rw_counter_max
        ; MSB-first comparison (byte 7 down to 0)
        lda #0
        sta rw_new_counter       ; assume not new high counter
        ldx #7
@replay_cmp:
        lda tp_recv_counter_tmp,x
        cmp rw_counter_max,x
        bcc @recv_less           ; received < max
        bne @recv_greater        ; received > max
        dex
        bpl @replay_cmp
        ; All bytes equal: received == max
        ; Check if bit already set in bitmap
        jmp @check_bitmap

@recv_greater:
        ; received > rw_counter_max -> accept (will advance window after decrypt)
        lda #1
        sta rw_new_counter
        jmp @replay_ok

@recv_less:
        ; received < rw_counter_max
        ; Compute delta = rw_counter_max - received (64-bit)
        ; Only need low 16 bits; if any of bytes 2-7 are nonzero, delta >= 65536 > 2048
        sec
        lda rw_counter_max
        sbc tp_recv_counter_tmp
        sta rw_shift_lo
        lda rw_counter_max+1
        sbc tp_recv_counter_tmp+1
        sta rw_shift_hi

        ; Check bytes 2-7 of delta for nonzero (means delta >= 65536)
        ldx #2
@check_high:
        lda rw_counter_max,x
        cmp tp_recv_counter_tmp,x
        bne @replay_fail          ; any difference in high bytes with borrow means too old
        inx
        cpx #8
        bne @check_high

        ; Now delta is in rw_shift_hi:rw_shift_lo (16-bit)
        ; Check if delta >= 2048 ($0800): high byte >= 8
        lda rw_shift_hi
        cmp #8
        bcs @replay_fail          ; delta >= 2048, outside window

        ; delta < 2048, within window. Check bitmap for duplicate.
@check_bitmap:
        ; Compute byte_offset and bit_index from received counter low 11 bits
        ; bit_index = tp_recv_counter_tmp[0] & 7
        ; byte_offset = ((tp_recv_counter_tmp[1] & $07) << 5) | (tp_recv_counter_tmp[0] >> 3)
        lda tp_recv_counter_tmp
        and #$07
        tax                       ; X = bit index (0-7)
        lda tp_recv_counter_tmp+1
        and #$07
        asl
        asl
        asl
        asl
        asl                       ; *32
        sta zp_tmp1               ; high part of byte offset
        lda tp_recv_counter_tmp
        lsr
        lsr
        lsr                       ; /8
        ora zp_tmp1               ; combine
        tay                       ; Y = byte offset in bitmap (0-255)
        lda rw_bitmap,y
        and rw_bit_mask,x
        bne @replay_fail          ; bit already set -> duplicate, reject
        ; Bit clear -> not yet seen, accept
        jmp @replay_ok

@replay_fail:
        lda #$ff
        rts

@replay_ok:
        ; --- 4. Compute payload_len = udp_recv_len - 32 ---
        ; Total = 16 header + payload + 16 tag, so payload = total - 32
        lda udp_recv_len
        sec
        sbc #32
        sta tp_payload_len
        ; If carry was clear, packet too small
        bcs @pkt_ok
        jmp @decrypt_fail
@pkt_ok:

        ; --- 5. Copy ciphertext to tp_packet+16 ---
        ldy #0
        ldx tp_payload_len
        beq @skip_ct_copy
@copy_ct:
        lda udp_recv_buf+16,y
        sta tp_packet+16,y
        iny
        dex
        bne @copy_ct
@skip_ct_copy:

        ; Copy tag (16 bytes after ciphertext in recv buf)
        ; Tag is at udp_recv_buf + 16 + payload_len
        ; Y already = payload_len from the copy loop (or 0 if skip)
        ldy tp_payload_len
        ldx #0
@copy_in_tag:
        lda udp_recv_buf+16,y
        sta aead_tag,x
        iny
        inx
        cpx #16
        bne @copy_in_tag

        ; --- 6. Set up AEAD for decryption ---
        ; Copy hs_transport_recv → aead_key
        ldx #31
@copy_key:
        lda hs_transport_recv,x
        sta aead_key,x
        dex
        bpl @copy_key

        ; Build nonce from received counter
        lda #<tp_recv_counter_tmp
        sta zp_ptr1
        lda #>tp_recv_counter_tmp
        sta zp_ptr1+1
        jsr transport_build_nonce

        ; AAD = empty
        lda #0
        sta aead_aad_len

        ; Data = tp_packet+16 (in-place decrypt)
        lda #<(tp_packet+16)
        sta aead_data_ptr
        lda #>(tp_packet+16)
        sta aead_data_ptr+1
        lda tp_payload_len
        sta aead_data_len

        ; --- 7. Decrypt and verify ---
        jsr aead_decrypt
        cmp #0
        beq @decrypt_ok
        jmp @decrypt_fail
@decrypt_ok:

        ; --- 8. On success: update sliding window ---
        lda rw_new_counter
        beq @just_set_bit       ; received <= max, just set the bit

        ; --- received > rw_counter_max: advance window ---
        ; Compute shift = received - rw_counter_max (16-bit)
        sec
        lda tp_recv_counter_tmp
        sbc rw_counter_max
        sta rw_shift_lo
        lda tp_recv_counter_tmp+1
        sbc rw_counter_max+1
        sta rw_shift_hi

        ; Check if any bytes 2-7 differ (shift >= 65536)
        ldx #2
@chk_big:
        lda tp_recv_counter_tmp,x
        cmp rw_counter_max,x
        bne @clear_all           ; high bytes differ -> huge shift, clear all
        inx
        cpx #8
        bne @chk_big

        ; shift is 16-bit in rw_shift_hi:rw_shift_lo
        ; If shift >= 256 (high byte != 0), clear all bitmap
        lda rw_shift_hi
        bne @clear_all

        ; shift < 256: clear newly exposed bytes in bitmap
        ; We need to clear bytes for positions (old_max+1) to (new_max)
        ; byte_start = ((old_max + 1) & $7FF) >> 3
        ; num_bytes_to_clear = (shift + 7) >> 3

        ; Compute start byte offset from (rw_counter_max + 1) low 11 bits
        ; Increment rw_counter_max[0..1] temporarily to get old_max+1
        lda rw_counter_max
        clc
        adc #1
        sta zp_tmp1              ; low byte of (old_max+1)
        lda rw_counter_max+1
        adc #0
        sta zp_tmp2              ; byte 1 of (old_max+1)

        ; start_byte = ((zp_tmp2 & $07) << 5) | (zp_tmp1 >> 3)
        lda zp_tmp2
        and #$07
        asl
        asl
        asl
        asl
        asl
        sta zp_ptr2              ; use zp_ptr2 as temp
        lda zp_tmp1
        lsr
        lsr
        lsr
        ora zp_ptr2
        tay                      ; Y = start byte offset

        ; num_bytes = (shift + 7) >> 3
        lda rw_shift_lo
        clc
        adc #7
        lsr
        lsr
        lsr                      ; A = number of bytes to clear
        tax                      ; X = count
        beq @advance_done        ; shift was 0? shouldn't happen but guard

        lda #0
@clear_loop:
        sta rw_bitmap,y
        iny                      ; wraps at 256 naturally (8-bit Y)
        dex
        bne @clear_loop
        jmp @advance_done

@clear_all:
        ; Zero entire bitmap (256 bytes)
        lda #0
        ldx #0
@clear_all_loop:
        sta rw_bitmap,x
        inx
        bne @clear_all_loop

@advance_done:
        ; Update rw_counter_max = received
        ldx #7
@upd_max:
        lda tp_recv_counter_tmp,x
        sta rw_counter_max,x
        dex
        bpl @upd_max

@just_set_bit:
        ; Set bit for received counter in bitmap
        ; byte_offset = ((tp_recv_counter_tmp[1] & $07) << 5) | (tp_recv_counter_tmp[0] >> 3)
        ; bit_index = tp_recv_counter_tmp[0] & 7
        lda tp_recv_counter_tmp+1
        and #$07
        asl
        asl
        asl
        asl
        asl
        sta zp_tmp1
        lda tp_recv_counter_tmp
        lsr
        lsr
        lsr
        ora zp_tmp1
        tay                      ; Y = byte offset
        lda tp_recv_counter_tmp
        and #$07
        tax                      ; X = bit index
        lda rw_bitmap,y
        ora rw_bit_mask,x
        sta rw_bitmap,y

        ; Update tp_recv_counter = rw_counter_max + 1 (for backward compat)
        ldx #7
@upd_ctr:
        lda rw_counter_max,x
        sta tp_recv_counter,x
        dex
        bpl @upd_ctr
        lda #<tp_recv_counter
        sta zp_ptr1
        lda #>tp_recv_counter
        sta zp_ptr1+1
        jsr counter_inc64

        lda #0                  ; success
        rts

@decrypt_fail:
        lda #$ff                ; failure
        rts

; =============================================================================
; transport_send - Encrypt and send Type 4 packet via UDP
;
; Input:
;   tp_payload_ptr  — pointer to plaintext data
;   tp_payload_len  — payload length
;   Network must be initialized, peer IP/port set
;
; Output: C=0 success, C=1 failure
; Clobbers: A, X, Y
; =============================================================================
transport_send:
        jsr transport_encrypt

        ; Set up UDP send
        lda tp_packet_len
        sta udp_send_len_local
        lda tp_packet_len+1
        sta udp_send_len_local+1

        lda #<tp_packet
        ldx #>tp_packet
        jsr net_udp_send

        rts
