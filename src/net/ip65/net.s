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
.export net_dhcp_acquire
.export net_poll
.export net_udp_listen
.export net_udp_send
.export net_udp_close
.export net_udp_recv_cb
.export net_print_ip

; ---- Public data labels (defined in this module) -----------------------------
.export net_udp_send_ptr
.export net_udp_send_len

; ---- Adapter-internal state, exported for observability (issue #84) ---------
.export ip65_listening
.export ip65_listen_port

; ---- External data symbols (defined in wg/data.s) ----------------------------
.import udp_recv_buf
.import udp_recv_len
.import udp_recv_ready
.import udp_recv_src_ip
.import udp_recv_src_port
.import wg_local_port
.import net_udp_dest_ip
.import net_udp_dest_port
.import zp_save_buf

; =============================================================================
; BOOT_CODE (not bare CODE): CODE is ceded to the chacha sibling archive
; (contract §4 gap, upstream issue #48); this wrapper stays in LOADER.
.segment "BOOT_CODE"

; =============================================================================
; net_init - initialize ip65 + ethernet (RR-Net CS8900a)
; Output: C=0 success, C=1 failure
; =============================================================================
net_init:
        ; ip65_init -> ip_init -> udp_init zeroes udp_cbcount, so any listener
        ; we held is gone from the blob's table by the time this returns.
        ; Forget it here, or a later net_udp_close would ask the blob to
        ; remove a port it no longer knows about and report a bogus C=1
        ; (issue #84). Cleared BEFORE the call so a failed init cannot leave
        ; a stale claim behind either.
        lda #$00
        sta ip65_listening

        jsr net_save_zp
        lda #0                  ; eth_init_default
        jsr ip65_init
        php                     ; save carry result
        jsr net_restore_zp
        plp                     ; restore carry
        rts

; =============================================================================
; net_dhcp_acquire - obtain IP address via DHCP
; Output: C=0 success, C=1 failure
; =============================================================================
net_dhcp_acquire:
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
        ; §13.2: C=1 means a BACKEND ERROR, and this path has none to report —
        ; ip65_process's own carry is a "did work" flag, and net_restore_zp does
        ; not preserve it anyway, so the carry reaching the caller was previously
        ; undefined. Inbound data is signalled by udp_recv_ready, set from the
        ; receive callback. Say so explicitly rather than leaking a stale flag.
        clc
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
        bcs @nl_fail

        ; Record the port we actually claimed rather than promising to
        ; re-read wg_local_port at close time. wg_local_port is consumer
        ; state — boot.s stages it before every listen — so a close that
        ; re-read it could ask the blob to remove a port it never registered
        ; and silently leak the one it did (issue #84).
        lda wg_local_port
        sta ip65_listen_port
        lda wg_local_port+1
        sta ip65_listen_port+1
        lda #$01
        sta ip65_listening
        clc
        rts

@nl_fail:
        ; Table full, or this port is already handled. We took nothing here,
        ; so leave ip65_listening alone: an earlier successful listen still
        ; owns its slot and must still be released.
        sec
        rts

; =============================================================================
; net_udp_close - release the UDP listener slot we claimed
;
; What this used to say: "ip65's UDP is connectionless: udp_add_listener /
; udp_remove_listener manage a local port, and there is no firmware-side
; socket handle to abandon" — and then `clc / rts`.
;
; The first clause is true and the conclusion does not follow: the same
; sentence names the thing that leaks. udp_add_listener claims one entry in a
; FOUR-entry table (`udp_cbmax = 4`, ip65/ip65/udp.s), keyed by port, and
; udp_remove_listener is the call that gives it back. It is reachable — the
; blob exports it through the jump table at ip65_base + 15
; (ip65-build/ip65_stub.s) — and nothing in this tree had ever called it. So
; every listen consumed a slot permanently and this routine reported success
; having done nothing (issue #84).
;
; Two consequences, both real on the shipped wireguard-rrnet-*.prg:
;   * Four listens on distinct ports exhaust the table; the fifth fails.
;   * A re-listen on the SAME port does not even get that far.
;     udp_add_listener refuses a port already in the table (its @busy leg),
;     so a single listen/close/listen cycle on our one port failed at the
;     second listen. Closing had to actually close for that to work.
;
; There is no firmware-side reaper here as there is under UCI: the table is
; in the blob's own BSS, and only ip65_init clears it (ip65_init -> ip_init
; -> udp_init zeroes udp_cbcount). That is why net_init above drops our
; bookkeeping: after a re-init the blob has forgotten our slot, so we must.
;
; Output: C=0 on success or when we hold no listener; C=1 if the blob had no
; such listener to remove. Unlike the UCI backend there is no net_last_error
; to set — the §13.2 codes are UCI-allocated and the contract is silent on
; close (c64-lib-contract#163) — so the carry is the whole report.
;
; Clobbers: A, X
; =============================================================================
net_udp_close:
        lda ip65_listening
        beq @nc_none                ; we hold no slot — nothing to release

        jsr net_save_zp
        lda ip65_listen_port
        ldx ip65_listen_port+1
        jsr ip65_udp_remove
        php                         ; the blob's verdict, kept across the
                                    ; restore and the bookkeeping below
        jsr net_restore_zp

        ; Drop our claim either way. C=1 means the blob has no listener on
        ; that port, in which case we do not own one either; going on
        ; believing we do would make the NEXT close remove a slot some later
        ; listen had legitimately claimed.
        lda #$00
        sta ip65_listening
        plp
        bcs @nc_fail
        clc
        rts

@nc_fail:
        sec
        rts

@nc_none:
        clc
        rts

; =============================================================================
; net_udp_send - send UDP packet
; Input: A/X = pointer to data buffer
;        net_udp_send_len = 16-bit length
;        net_udp_dest_ip, net_udp_dest_port, wg_local_port must be set
; Output: C=0 success, C=1 failure
; =============================================================================
net_udp_send:
        sta net_udp_send_ptr
        stx net_udp_send_ptr+1

        ; Reclaim the listener slot if a teardown released it.
        ;
        ; This is what makes net_udp_close safe to call from the consumer's
        ; abandonment paths, which is the whole of issue #84. It mirrors the
        ; UCI backend exactly: there net_udp_close clears uci_socket_open and
        ; the next net_udp_send re-issues UDP_CONNECT, so a consumer that
        ; tears a session down carries on without re-running net_init. Before
        ; this, an ip65 close that actually released would have left the app
        ; permanently deaf — sends would keep succeeding and nothing would
        ; ever be received again, because only do_net_init ('I') listens.
        ;
        ; A send whose reply can never arrive is not a successful send, so a
        ; failed re-listen fails the send rather than going silently deaf.
        ;
        ; Guarded on ip65_listen_port being non-zero, i.e. on net_udp_listen
        ; having ALREADY succeeded once this run. Without that guard this
        ; becomes the first call site that can reach udp_add_listener before
        ; ip65_init has run — boot.s dispatches 'H' whether or not 'I' was
        ; pressed — and udp_add_listener indexes its table with udp_cbcount,
        ; which lives in the blob's BSS at $A000 and is uninitialised until
        ; ip65_init zeroes it. A garbage count writes four bytes at a garbage
        ; offset into the blob's own state. This is BSS in MAIN_AREA_LO
        ; (file = %O, fill = yes, fillval = $00), so LOAD really does stamp
        ; it zero and the guard really does hold on a cold boot.
        lda ip65_listening
        bne @snd_go
        lda ip65_listen_port
        ora ip65_listen_port+1
        beq @snd_go                 ; never listened — nothing of ours to reclaim
        jsr net_udp_listen
        bcs @snd_no_listener
@snd_go:
        jsr net_save_zp
        ; set destination IP
        lda #<net_udp_dest_ip
        ldx #>net_udp_dest_ip
        jsr ip65_set_udp_dest
        ; set dest port (big-endian in ip65)
        lda net_udp_dest_port
        sta ip65_udp_snd_dport
        lda net_udp_dest_port+1
        sta ip65_udp_snd_dport+1
        ; set source port
        lda wg_local_port
        sta ip65_udp_snd_sport
        lda wg_local_port+1
        sta ip65_udp_snd_sport+1
        ; set length
        lda net_udp_send_len
        sta ip65_udp_snd_len
        lda net_udp_send_len+1
        sta ip65_udp_snd_len+1
        ; send — AX = data pointer
        lda net_udp_send_ptr
        ldx net_udp_send_ptr+1
        jsr ip65_udp_send
        php
        jsr net_restore_zp
        plp
        rts

@snd_no_listener:
        sec
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

        ; 16-bit copy using self-modifying code (ip65 owns ZP pointers).
        ;
        ; §13.3 (c64-lib-contract): the count is a two-byte quantity and is
        ; handled as one. The previous form split it into a page loop driven
        ; by `ldx udp_recv_len+1` and a remainder loop driven by
        ; `ldx udp_recv_len` — arithmetically sound, but it is the exact
        ; "one-byte register holding a piece of a two-byte length" habit
        ; that produced the c64-https 255-byte rx clamp (their PR #27), and
        ; the two loops had to be kept consistent by hand. Now: one loop,
        ; one 16-bit countdown in udp_copy_rem, Y is only the page offset
        ; and the SMC bases advance when it wraps. Same shape as the UCI
        ; adapter's receive loop.
        lda udp_recv_len
        sta udp_copy_rem
        lda udp_recv_len+1
        sta udp_copy_rem+1

        lda #<(ip65_udp_inp + 8)
        sta @cp_ld+1
        lda #>(ip65_udp_inp + 8)
        sta @cp_ld+2
        lda #<udp_recv_buf
        sta @cp_st+1
        lda #>udp_recv_buf
        sta @cp_st+2

        ldy #0
@cp_loop:
        lda udp_copy_rem
        ora udp_copy_rem+1
        beq @copy_done
@cp_ld: lda ip65_udp_inp + 8,y     ; SMC: base patched above
@cp_st: sta udp_recv_buf,y         ; SMC: base patched above
        iny
        bne @cp_nohi
        inc @cp_ld+2
        inc @cp_st+2
@cp_nohi:
        lda udp_copy_rem
        bne @cp_noborrow
        dec udp_copy_rem+1
@cp_noborrow:
        dec udp_copy_rem
        jmp @cp_loop
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

net_udp_send_ptr:       .res 2      ; pointer for udp_send wrapper
net_udp_send_len: .res 2      ; length for udp_send wrapper
udp_copy_rem:       .res 2      ; 16-bit countdown for the rx copy (§13.3)

; --- listener ownership (issue #84) ------------------------------------------
; The one slot we hold in ip65's 4-entry udp_cb* table, so net_udp_close can
; hand back exactly what net_udp_listen took. Adapter-internal — not part of
; the §13.1 surface — exported only so a test can observe the claim.
ip65_listening:     .res 1      ; 1 = we hold a listener slot
ip65_listen_port:   .res 2      ; the port it was registered on (LE, as passed)
