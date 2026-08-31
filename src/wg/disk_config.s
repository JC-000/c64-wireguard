; =============================================================================
; wg/disk_config.s - SEQ file configuration reader (ca65)
;
; ca65 port of src/disk_config.asm. Was a syntax-only translation until #88,
; which made hex_digit case-insensitive and made a non-hex character a
; reported error rather than a silent conversion.
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
;   Line 8: preshared key (64 hex chars) - optional, zeros if omitted
;   Line 9: Unix timestamp (decimal, up to 10 digits) - optional, zeros if omitted
;
; Hex fields accept '0'-'9', 'A'-'F' and 'a'-'f' interchangeably; any other
; character aborts the read with C=1, which boot.s reports as CONFIG ERROR.
; (The decimal fields on lines 4-7 and 9 still convert whatever they are
; given -- they are not part of #88.)
;
; Interface:
;   config_read_file  - read and parse entire config file
; =============================================================================

.include "constants.inc"

; ---- Public entry points -----------------------------------------------------
.export config_read_file

; ---- External symbols (defined in other modules) ----------------------------
; Config buffers (defined in data.s)
.import cfg_static_priv
.import cfg_static_pub
.import cfg_peer_pub
.import cfg_peer_endpoint_ip
.import cfg_peer_endpoint_port
.import cfg_preshared_key
.import tunnel_ip
.import ping_target_ip
.import tai64n_base_time
.import config_filename
.import config_filename_len

; =============================================================================
; Code
; =============================================================================
.segment "APP_CODE"

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
        lda #<config_filename_len
        ldx #<config_filename
        ldy #>config_filename
        jsr setnam

        ; OPEN
        jsr open
        bcs @fail

        ; CHKIN: set input channel to logical file 2
        ldx #2
        jsr chkin
        bcs @close_fail

        ; --- Line 1: static private key (32 bytes from 64 hex chars) ---
        lda #<cfg_static_priv
        ldy #>cfg_static_priv
        jsr read_key_line
        bcs @close_fail

        ; --- Line 2: static public key ---
        lda #<cfg_static_pub
        ldy #>cfg_static_pub
        jsr read_key_line
        bcs @close_fail

        ; --- Line 3: peer public key ---
        lda #<cfg_peer_pub
        ldy #>cfg_peer_pub
        jsr read_key_line
        bcs @close_fail

        jmp @lines_4_to_7

        ; --- Failure epilogue, parked mid-routine ---------------------------
        ; It sits here, not after the success path, so that every key line
        ; reaches it with a 2-byte `bcs` -- including the optional PSK below,
        ; which is the only BACKWARD branch to it and the reason for the
        ; placement. Four `bcc @next / jmp @close_fail` pairs instead would
        ; cost 12 bytes more.
        ;
        ; That matters because APP_DATA ends a handful of bytes short of the
        ; align=$100 boundary at $4B00 that LIB_CHACHA20_POLY1305_CODE sits
        ; on: crossing it moves every later segment up a page, and
        ; MAIN_AREA_LO has no page to give. Folding the four copies of the
        ; key-line preamble into read_key_line is what paid for the
        ; validation added here.
        ;
        ; Do NOT copy a byte count out of this comment -- the slack differs
        ; per backend (BACKEND=uci also puts UCI_BSS in MAIN_AREA_LO) and
        ; goes stale on every link. The authority is the link itself:
        ; src/contract_asserts.s:240 asserts __MAIN_AREA_LO_LAST__ <=
        ; WG_SQTAB_BASE with lderror, so an over-budget image fails to link
        ; rather than silently overrunning. That assert, not a number in a
        ; comment, is why this is not a repeat of the "176 free bytes" trap.
        ; Read build/wireguard.map for the current figure.
@close_fail:
        jsr clrchn
@fail:
        lda #2
        jsr close
        sec                     ; C=1 failure
        rts

@lines_4_to_7:
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
        ldy #>cfg_preshared_key
        jsr read_key_line
        bcs @close_fail
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

; =============================================================================
; read_key_line - Read one 64-hex-char key line plus its CR terminator
;
; Input:  A = low byte of destination buffer
;         Y = high byte of destination buffer
; Output: 32 bytes written; C=0 success, C=1 if any character was not a
;         hex digit (in which case the buffer holds a partial decode and the
;         file is left mid-line -- the caller must abandon the read)
; Clobbers: A, X, Y
; =============================================================================
read_key_line:
        sta zp_ptr2
        sty zp_ptr2+1
        lda #32                 ; 32 bytes = 64 hex characters
        sta zp_tmp1
        jsr hex_to_bytes
        bcs @bad
        jsr chrin               ; consume CR terminator
        clc                     ; C=0 success
@bad:
        rts                     ; C=1 already set by hex_to_bytes

; =============================================================================
; hex_to_bytes - Read hex characters from CHRIN and convert to bytes
;
; Input: zp_ptr2 = output buffer pointer
;        zp_tmp1 = number of bytes to read (each byte = 2 hex chars)
; Output: buffer filled with decoded bytes
;         C=0 success, C=1 if any character was not a hex digit (the buffer
;         then holds a partial decode; the caller must abandon the read)
; Clobbers: A, X, Y
; =============================================================================
hex_to_bytes:
        ldy #0                  ; output index
@loop:
        ; Read high nibble
        jsr chrin
        jsr hex_digit           ; A = high nibble value
        bcs @not_hex
        asl
        asl
        asl
        asl
        sta zp_tmp2             ; save high nibble shifted

        ; Read low nibble
        jsr chrin
        jsr hex_digit           ; A = low nibble value
        bcs @not_hex
        ora zp_tmp2             ; combine high | low

        sta (zp_ptr2),y
        iny
        dec zp_tmp1
        bne @loop
        clc                     ; C=0 success
@not_hex:
        rts                     ; on the error path C=1 is already set

; =============================================================================
; hex_digit - Convert one ASCII hex digit in A to its value 0-15
;
; Accepts '0'-'9', 'A'-'F' and 'a'-'f'. Everything else is REPORTED, not
; converted: C=1 on return and A is undefined.
;
; Output: C=0 and A = 0..15, or C=1 for a non-hex character
; Clobbers: A
; Preserves: X, Y  (relied on by hex_to_bytes' output index in Y)
;
; Issue #88. This used to be `sbc #$30 / cmp #10 / bcc done / sbc #$07`, which
; decodes uppercase only -- the $07 adjustment is calibrated for 'A'-'F'
; ($41-$30-$07 = $0A). Lowercase 'a' is $61, so $61-$30 = $31 and $31-$07 =
; $2A: bit 5 survives, and every byte whose LOW nibble is a-f came out wrong.
; "ca" decoded to $EA rather than $CA. Nothing validated the result, so the
; only symptom was a handshake that never completed -- indistinguishable from
; a genuine protocol defect. Lowercase is what `bytes.hex()`, `xxd -p`,
; `openssl` and `wg pubkey | base64 -d | xxd -p` all emit, and README asked
; only for "64 hex chars", so lowercase is the likely file, not the odd one.
;
; The fold is `and #$df` applied AFTER the '0' subtraction, which is exact
; rather than approximate: for X = c - $30, X & $DF lands in $11..$16 if and
; only if X is $11..$16 or $31..$36, i.e. c is 'A'-'F' or 'a'-'f'. No other
; character folds into range, so accepting lowercase costs nothing in
; strictness. `and` leaves C alone, so the carry `cmp #10` set is still live
; for the `sbc` below.
;
; Deliberately NOT accepted: shifted-PETSCII letters ($C1-$C6, what a file
; typed on the C64 in lower/uppercase display mode contains). They now raise
; CONFIG ERROR instead of decoding to garbage, which is the point of the
; carry: a config error the user can see beats key material that is silently
; wrong. Same for a stray CR/LF from a CRLF-terminated file -- which used to
; shift the whole remaining parse.
; =============================================================================
hex_digit:
        sec
        sbc #$30                ; subtract '0'
        bcc @not_hex            ; below '0'
        cmp #10
        bcc @done               ; '0'-'9' already correct, C=0
        and #$df                ; fold 'a'-'f' onto 'A'-'F' (clears bit 5)
        sbc #$11                ; C=1 here; 'A'-'F' -> 0-5
        cmp #6
        bcs @not_hex            ; anything else in the >= 10 range
        adc #10                 ; C=0 here; 0-5 -> 10-15, and leaves C=0
@done:
        rts
@not_hex:
        sec                     ; C=1: not a hex digit
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

; =============================================================================
; BSS: 8-byte working buffers for u64 decimal parsing
; =============================================================================
.segment "APP_BSS"

u64_acc:
        .res 8, 0
u64_tmp:
        .res 8, 0
