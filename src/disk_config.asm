; =============================================================================
; disk_config.asm - SEQ file configuration reader
;
; Reads WireGuard configuration from "WG.CFG" on disk using KERNAL I/O.
; BASIC ROM is banked out; KERNAL ROM is available.
;
; Config file format (fixed-order, CR-terminated lines):
;   Line 1: static private key (64 hex chars)
;   Line 2: static public key (64 hex chars)
;   Line 3: peer public key (64 hex chars)
;   Line 4: endpoint IP (dotted decimal, e.g. "10.0.0.1")
;   Line 5: endpoint port (decimal, e.g. "51820")
;   Line 6: tunnel IP (dotted decimal)
;   Line 7: ping target IP (dotted decimal)
;   Line 8: preshared key (64 hex chars) — optional, zeros if omitted
;   Line 9: Unix timestamp (decimal, up to 10 digits) — optional, zeros if omitted
;
; Interface:
;   config_read_file  - read and parse entire config file
; =============================================================================

; =============================================================================
; config_read_file - Open and parse WireGuard config from disk
;
; Opens "WG.CFG" as SEQ file on device 8, reads all 7 lines,
; parses hex keys and decimal addresses into config buffers.
;
; Output: C=0 success, C=1 failure
; Clobbers: A, X, Y
; =============================================================================
config_read_file:
        ; SETLFS: logical file 2, device 8, secondary address 2 (SEQ read)
        lda #2                  ; logical file number
        ldx #8                  ; device 8
        ldy #2                  ; sa=2 for SEQ read (NOT sa=0 = LOAD mode)
        jsr setlfs

        ; SETNAM: filename
        lda #config_filename_len
        ldx #<config_filename
        ldy #>config_filename
        jsr setnam

        ; OPEN
        jsr open
        bcc @open_ok
        jmp @fail
@open_ok:

        ; CHKIN: set input channel to logical file 2
        ldx #2
        jsr chkin
        bcc @chkin_ok
        jmp @close_fail
@chkin_ok:

        ; --- Line 1: static private key (32 bytes from 64 hex chars) ---
        lda #<cfg_static_priv
        sta zp_ptr2
        lda #>cfg_static_priv
        sta zp_ptr2+1
        lda #32
        sta zp_tmp1
        jsr hex_to_bytes
        jsr chrin               ; consume CR terminator

        ; --- Line 2: static public key ---
        lda #<cfg_static_pub
        sta zp_ptr2
        lda #>cfg_static_pub
        sta zp_ptr2+1
        lda #32
        sta zp_tmp1
        jsr hex_to_bytes
        jsr chrin               ; consume CR

        ; --- Line 3: peer public key ---
        lda #<cfg_peer_pub
        sta zp_ptr2
        lda #>cfg_peer_pub
        sta zp_ptr2+1
        lda #32
        sta zp_tmp1
        jsr hex_to_bytes
        jsr chrin               ; consume CR

        ; --- Line 4: endpoint IP ---
        lda #<cfg_peer_endpoint_ip
        sta zp_ptr1
        lda #>cfg_peer_endpoint_ip
        sta zp_ptr1+1
        jsr parse_decimal_ip

        ; --- Line 5: endpoint port ---
        lda #<cfg_peer_endpoint_port
        sta zp_ptr2
        lda #>cfg_peer_endpoint_port
        sta zp_ptr2+1
        jsr parse_decimal_u16

        ; --- Line 6: tunnel IP ---
        lda #<tunnel_ip
        sta zp_ptr1
        lda #>tunnel_ip
        sta zp_ptr1+1
        jsr parse_decimal_ip

        ; --- Line 7: ping target IP ---
        lda #<ping_target_ip
        sta zp_ptr1
        lda #>ping_target_ip
        sta zp_ptr1+1
        jsr parse_decimal_ip

        ; --- Line 8 (optional): preshared key (64 hex chars) ---
        jsr readst
        and #$40                ; bit 6 = EOF
        bne @skip_psk

        lda #<cfg_preshared_key
        sta zp_ptr2
        lda #>cfg_preshared_key
        sta zp_ptr2+1
        lda #32
        sta zp_tmp1
        jsr hex_to_bytes
        jsr chrin               ; consume CR
        jmp @psk_done
@skip_psk:
        ldx #31
        lda #0
@zero_psk:
        sta cfg_preshared_key,x
        dex
        bpl @zero_psk
@psk_done:

        ; --- Line 9 (optional): Unix timestamp (decimal, up to 10 digits) ---
        jsr readst
        and #$40                ; bit 6 = EOF
        bne @skip_timestamp

        jsr parse_decimal_u64
        jmp @timestamp_done
@skip_timestamp:
        ldx #7
        lda #0
@zero_timestamp:
        sta tai64n_base_time,x
        dex
        bpl @zero_timestamp
@timestamp_done:

        ; Close and restore channels
        jsr clrchn
        lda #2
        jsr close
        clc                     ; C=0 success
        rts

@close_fail:
        jsr clrchn
@fail:
        lda #2
        jsr close
        sec                     ; C=1 failure
        rts

; =============================================================================
; hex_to_bytes - Read hex characters from CHRIN and convert to bytes
;
; Input: zp_ptr2 = output buffer pointer
;        zp_tmp1 = number of bytes to read (each byte = 2 hex chars)
; Output: buffer filled with decoded bytes
; Clobbers: A, X, Y
; =============================================================================
hex_to_bytes:
        ldy #0                  ; output index
@loop:
        ; Read high nibble
        jsr chrin
        jsr @hex_digit          ; A = high nibble value
        asl
        asl
        asl
        asl
        sta zp_tmp2             ; save high nibble shifted

        ; Read low nibble
        jsr chrin
        jsr @hex_digit          ; A = low nibble value
        ora zp_tmp2             ; combine high | low

        sta (zp_ptr2),y
        iny
        dec zp_tmp1
        bne @loop
        rts

; Convert ASCII/PETSCII hex digit in A to 0-15
@hex_digit:
        sec
        sbc #$30                ; subtract '0'
        cmp #10
        bcc @done               ; 0-9 already correct
        sbc #$07                ; A-F: $41-$30=$11, -$07=$0A
@done:
        rts

; =============================================================================
; parse_decimal_ip - Read dotted decimal IP from CHRIN
;
; Input: zp_ptr1 = output buffer (4 bytes)
; Output: 4 octets stored at (zp_ptr1)
; Clobbers: A, X, Y
; =============================================================================
parse_decimal_ip:
        ldy #0                  ; octet index
@octet:
        lda #0                  ; accumulator for current octet
        sta zp_tmp2
@digit:
        jsr chrin
        cmp #'.'
        beq @store
        cmp #$0d                ; CR = end of line
        beq @store

        ; Accumulate: result = result * 10 + digit
        pha                     ; save digit char
        lda zp_tmp2
        asl                     ; *2
        sta zp_tmp2
        asl                     ; *4
        asl                     ; *8
        clc
        adc zp_tmp2             ; *8 + *2 = *10
        sta zp_tmp2
        pla                     ; restore digit char
        sec
        sbc #$30                ; ASCII to value
        clc
        adc zp_tmp2
        sta zp_tmp2
        jmp @digit

@store:
        lda zp_tmp2
        sta (zp_ptr1),y
        iny
        cpy #4
        bcc @octet              ; more octets expected
        rts

; =============================================================================
; parse_decimal_u16 - Read decimal number from CHRIN, store as big-endian u16
;
; Input: zp_ptr2 = output buffer (2 bytes, big-endian)
; Output: 16-bit value stored at (zp_ptr2)
; Clobbers: A, X, Y
; =============================================================================
parse_decimal_u16:
        lda #0
        sta zp_tmp1             ; result high byte
        sta zp_tmp2             ; result low byte
@loop:
        jsr chrin
        cmp #$0d                ; CR = end
        beq @store

        ; Save digit value
        sec
        sbc #$30
        tax                     ; X = digit value

        ; result = result * 10: multiply by shifting
        ; Save original result
        lda zp_tmp2
        sta @orig_lo+1          ; self-mod: save low
        lda zp_tmp1
        sta @orig_hi+1          ; self-mod: save high

        ; result * 2
        asl zp_tmp2
        rol zp_tmp1
        ; result * 4
        asl zp_tmp2
        rol zp_tmp1
        ; result * 4 + original = result * 5
@orig_lo:
        lda #0                  ; (self-modified)
        clc
        adc zp_tmp2
        sta zp_tmp2
@orig_hi:
        lda #0                  ; (self-modified)
        adc zp_tmp1
        sta zp_tmp1
        ; result * 10
        asl zp_tmp2
        rol zp_tmp1

        ; Add digit
        txa
        clc
        adc zp_tmp2
        sta zp_tmp2
        lda #0
        adc zp_tmp1
        sta zp_tmp1

        jmp @loop

@store:
        ; Store big-endian: high byte first
        ldy #0
        lda zp_tmp1
        sta (zp_ptr2),y
        iny
        lda zp_tmp2
        sta (zp_ptr2),y
        rts

; =============================================================================
; parse_decimal_u64 - Read decimal number from CHRIN, store as big-endian u64
;
; Reads up to 10 ASCII digits (CR-terminated) from CHRIN and converts to an
; 8-byte big-endian integer stored in tai64n_base_time.
;
; Algorithm: digit by digit, accumulator = accumulator * 10 + digit
; Multiply by 10 = (shift left 3) + (shift left 1) = *8 + *2
; Uses u64_acc (8 bytes) as accumulator, u64_tmp (8 bytes) as temp.
;
; Output: tai64n_base_time filled with 8-byte big-endian value
; Clobbers: A, X, Y
; =============================================================================
parse_decimal_u64:
        ; Zero the accumulator
        ldx #7
        lda #0
@zero_acc:
        sta u64_acc,x
        dex
        bpl @zero_acc

@loop:
        jsr chrin
        cmp #$0d                ; CR = end
        beq @store

        ; Convert ASCII digit to value 0-9
        sec
        sbc #$30
        pha                     ; save digit on stack

        ; --- Multiply u64_acc by 10 ---
        ; Copy accumulator to temp
        ldx #7
@copy:
        lda u64_acc,x
        sta u64_tmp,x
        dex
        bpl @copy

        ; Shift u64_acc left by 1 (accumulator now = original * 2)
        clc
        ldx #7
@shl1:
        rol u64_acc,x
        dex
        bpl @shl1

        ; Shift u64_tmp left by 3 (temp now = original * 8)
        ldy #3                  ; shift count
@shl3_outer:
        clc
        ldx #7
@shl3_inner:
        rol u64_tmp,x
        dex
        bpl @shl3_inner
        dey
        bne @shl3_outer

        ; Add u64_tmp (*8) to u64_acc (*2) => accumulator = original * 10
        clc
        ldx #7
@add_mul:
        lda u64_acc,x
        adc u64_tmp,x
        sta u64_acc,x
        dex
        bpl @add_mul

        ; Add digit value to accumulator (big-endian: add to byte 7 = LSB)
        pla                     ; restore digit
        clc
        adc u64_acc+7
        sta u64_acc+7
        ; Propagate carry through upper bytes
        ldx #6
@carry:
        bcc @loop               ; no carry, done
        lda u64_acc,x
        adc #0
        sta u64_acc,x
        dex
        bpl @carry

        jmp @loop

@store:
        ; Copy accumulator to tai64n_base_time
        ldx #7
@copy_out:
        lda u64_acc,x
        sta tai64n_base_time,x
        dex
        bpl @copy_out
        rts

; 8-byte working buffers for u64 decimal parsing
u64_acc:
        !fill 8, 0
u64_tmp:
        !fill 8, 0
