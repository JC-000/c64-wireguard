; =============================================================================
; net/ip65/net.s - ip65 network wrapper with zero page time-sharing
;                  (ca65 port of src/net.asm)
;
; All ip65 calls go through this wrapper. Before each call:
;   1. Save crypto ZP ($02-$1B) to zp_save_buf
;   2. Call ip65 function
;   3. Restore crypto ZP from zp_save_buf
;
; The UDP receive callback fires DURING ip65_process, while ip65's ZP is
; active. The callback must NOT touch crypto state — it only copies received
; data into udp_recv_buf for later processing by the main loop.
;
; This module ships in LOADER (CODE segment) — it is called during boot
; before crypto goes live, and by the main loop from then on.
; =============================================================================

.include "constants.inc"
.include "net/ip65/ip65_symbols.inc"

; ---- Public entry points -----------------------------------------------------
.export net_init
.export net_dhcp
.export net_poll
.export net_udp_listen
.export net_udp_send
.export net_udp_recv_cb
.export net_print_ip
.export net_save_zp
.export net_restore_zp

; ---- Public data labels (defined in this module) -----------------------------
.export net_send_ptr
.export udp_send_len_local

; ---- External data symbols (defined in wg/data.s) ----------------------------
.import udp_recv_buf
.import udp_recv_len
.import udp_recv_ready
.import udp_recv_src_ip
.import udp_recv_src_port
.import wg_local_port
.import wg_peer_ip
.import wg_peer_port
.import zp_save_buf

; =============================================================================
.segment "CODE"

; =============================================================================
; net_init - initialize ip65 + ethernet (RR-Net CS8900a)
; Output: C=0 success, C=1 failure
; =============================================================================
net_init:
        jsr net_save_zp
        lda #0                  ; eth_init_default
        jsr ip65_init
        php                     ; save carry result
        jsr net_restore_zp
        plp                     ; restore carry
        rts

; =============================================================================
; net_dhcp - obtain IP address via DHCP
; Output: C=0 success, C=1 failure
; =============================================================================
net_dhcp:
        jsr net_save_zp
        jsr ip65_dhcp_init
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_poll - call ip65_process (non-blocking)
; Must be called frequently from main loop.
; =============================================================================
net_poll:
        jsr net_save_zp
        jsr ip65_process
        jsr net_restore_zp
        rts

; =============================================================================
; net_udp_listen - register UDP listener on specified port
; Input: wg_local_port set to port number (little-endian)
; Output: C=0 success, C=1 failure
; =============================================================================
net_udp_listen:
        jsr net_save_zp
        ; set callback vector
        lda #<net_udp_recv_cb
        ldx #>net_udp_recv_cb
        jsr ip65_set_udp_cb
        ; add listener on our port
        lda wg_local_port
        ldx wg_local_port+1
        jsr ip65_udp_add
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_udp_send - send UDP packet
; Input: A/X = pointer to data buffer
;        udp_send_len_local = 16-bit length
;        wg_peer_ip, wg_peer_port, wg_local_port must be set
; Output: C=0 success, C=1 failure
; =============================================================================
net_udp_send:
        sta net_send_ptr
        stx net_send_ptr+1
        jsr net_save_zp
        ; set destination IP
        lda #<wg_peer_ip
        ldx #>wg_peer_ip
        jsr ip65_set_udp_dest
        ; set dest port (big-endian in ip65)
        lda wg_peer_port
        sta ip65_udp_snd_dport
        lda wg_peer_port+1
        sta ip65_udp_snd_dport+1
        ; set source port
        lda wg_local_port
        sta ip65_udp_snd_sport
        lda wg_local_port+1
        sta ip65_udp_snd_sport+1
        ; set length
        lda udp_send_len_local
        sta ip65_udp_snd_len
        lda udp_send_len_local+1
        sta ip65_udp_snd_len+1
        ; send — AX = data pointer
        lda net_send_ptr
        ldx net_send_ptr+1
        jsr ip65_udp_send
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_udp_recv_cb - UDP receive callback
; Called by ip65 DURING ip65_process while ip65's ZP is active.
; DO NOT touch crypto ZP. Only copy data to udp_recv_buf.
;
; ip65 provides incoming data at udp_inp + 8 (udp_data offset).
; Length from UDP header at udp_inp + 4 (network byte order, minus 8 for hdr).
; Source IP from ip_inp + 12 (source IP in IP header).
; =============================================================================
net_udp_recv_cb:
        ; read UDP payload length from header (network byte order)
        ; udp_inp + udp_len = total UDP length including 8-byte header
        lda ip65_udp_inp + 4    ; length high byte (network order)
        sta udp_recv_len+1
        lda ip65_udp_inp + 5    ; length low byte
        sec
        sbc #8                  ; subtract UDP header
        sta udp_recv_len
        bcs :+
        dec udp_recv_len+1
:
        ; cap at 1500 bytes (our buffer size)
        lda udp_recv_len+1
        cmp #>(1500)            ; = $05
        bcc @copy               ; high byte < 5, fits
        bne @too_large          ; high byte > 5, too large
        lda udp_recv_len
        cmp #<(1500)            ; = $DC
        bcc @copy               ; fits
        beq @copy               ; exactly 1500

@too_large:
        lda #<(1500)
        sta udp_recv_len
        lda #>(1500)
        sta udp_recv_len+1

@copy:
        ; Check for zero length
        lda udp_recv_len
        ora udp_recv_len+1
        beq @done

        ; 16-bit copy using self-modifying code (ip65 owns ZP pointers)
        ; Set up source/dest high bytes for self-mod
        lda #>(ip65_udp_inp + 8)
        sta @pg_ld+2
        lda #>udp_recv_buf
        sta @pg_st+2

        ; Copy full pages
        ldx udp_recv_len+1
        ldy #0
        cpx #0
        beq @setup_rem

@pg_ld: lda ip65_udp_inp + 8,y
@pg_st: sta udp_recv_buf,y
        iny
        bne @pg_ld
        inc @pg_ld+2
        inc @pg_st+2
        dex
        bne @pg_ld

@setup_rem:
        ; Copy final high bytes to remainder instructions
        lda @pg_ld+2
        sta @rm_ld+2
        lda @pg_st+2
        sta @rm_st+2

        ldx udp_recv_len        ; low byte = remaining count
        beq @copy_done
        ldy #0
@rm_ld: lda ip65_udp_inp + 8,y
@rm_st: sta udp_recv_buf,y
        iny
        dex
        bne @rm_ld
@copy_done:
        ; copy source IP (ip_inp + 12 = source IP in IP header)
        ; ip65_udp_inp is ip_inp + ip_data(20), so ip_inp = udp_inp - 20
        ; source IP at ip_inp + 12 = udp_inp - 8
        lda ip65_udp_inp - 8
        sta udp_recv_src_ip
        lda ip65_udp_inp - 7
        sta udp_recv_src_ip+1
        lda ip65_udp_inp - 6
        sta udp_recv_src_ip+2
        lda ip65_udp_inp - 5
        sta udp_recv_src_ip+3

        ; copy source port from UDP header (network byte order)
        lda ip65_udp_inp + 0    ; source port high byte
        sta udp_recv_src_port
        lda ip65_udp_inp + 1    ; source port low byte
        sta udp_recv_src_port+1

        ; set ready flag
        lda #1
        sta udp_recv_ready

@done:
        rts

; =============================================================================
; net_print_ip - display current IP address in dotted decimal
; =============================================================================
net_print_ip:
        lda ip65_cfg_ip
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+1
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+2
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+3
        jsr @print_byte
        lda #$0d
        jsr chrout
        rts

; print decimal byte value (0-255)
@print_byte:
        sta @pb_val
        ; hundreds
        ldx #0
        sec
@pb_100:
        sbc #100
        bcc @pb_100d
        inx
        jmp @pb_100
@pb_100d:
        adc #100
        cpx #0
        beq @pb_tens            ; skip leading zero
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_tens:
        ldx #0
        sec
@pb_10:
        sbc #10
        bcc @pb_10d
        inx
        jmp @pb_10
@pb_10d:
        adc #10
        cpx #0
        bne @pb_t_out
        ldy @pb_val
        cpy #10
        bcc @pb_ones            ; value < 10, skip tens
@pb_t_out:
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_ones:
        ora #$30
        jsr chrout
        rts
@pb_val: .byte 0

; =============================================================================
; ZP save/restore — 26 bytes ($02-$1B)
; =============================================================================
net_save_zp:
        ldx #ip65_zp_size - 1
:       lda ip65_zp_start,x
        sta zp_save_buf,x
        dex
        bpl :-
        rts

net_restore_zp:
        ldx #ip65_zp_size - 1
:       lda zp_save_buf,x
        sta ip65_zp_start,x
        dex
        bpl :-
        rts

; =============================================================================
; net module data
; =============================================================================
.segment "BSS"

net_send_ptr:       .res 2      ; pointer for udp_send wrapper
udp_send_len_local: .res 2      ; length for udp_send wrapper
