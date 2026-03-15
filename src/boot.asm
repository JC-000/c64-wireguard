; =============================================================================
; boot.asm - BASIC stub and program entry point
; =============================================================================

; BASIC stub: 10 SYS 2064
basic_stub:
        !word basic_end         ; pointer to next BASIC line
        !word 10                ; line number 10
        !byte $9e               ; SYS token
        !text "2064"            ; decimal address (must match start label)
        !byte 0                 ; end of line
basic_end:
        !word 0                 ; end of BASIC program

; =============================================================================
; main program entry point
; =============================================================================
start:
        ; bank out BASIC ROM to use $A000-$BFFF as RAM
        lda proc_port
        and #$fe                ; clear bit 0 (LORAM) — bank out BASIC ROM
        sta proc_port

        ; clear screen
        jsr clrscr

        ; display title
        lda #<title_msg
        ldy #>title_msg
        jsr print_string

        ; fall through to main loop
main_loop:
        lda net_initialized
        beq @no_poll
        jsr net_poll            ; poll ip65 for packets
@no_poll:
        jsr getin
        beq main_loop           ; wait for keypress

        cmp #$51                ; 'Q' = quit
        beq quit
        cmp #$49                ; 'I' = init network
        beq @init_net
        cmp #$53                ; 'S' = send test packet
        beq @send_test

        jmp main_loop

@init_net:
        jsr do_net_init
        jmp main_loop

@send_test:
        jsr do_send_test
        jmp main_loop

quit:
        ; restore BASIC ROM before returning
        lda proc_port
        ora #$01
        sta proc_port
        rts

; =============================================================================
; do_net_init - initialize network, DHCP, start UDP listener
; =============================================================================
do_net_init:
        ; print init message
        lda #<net_init_msg
        ldy #>net_init_msg
        jsr print_string

        ; init ip65
        jsr net_init
        bcc @init_ok

        ; init failed
        lda #<net_err_msg
        ldy #>net_err_msg
        jsr print_string
        rts

@init_ok:
        ; print DHCP message
        lda #<net_dhcp_msg
        ldy #>net_dhcp_msg
        jsr print_string

        ; request DHCP
        jsr net_dhcp
        bcc @dhcp_ok

        ; DHCP failed
        lda #<dhcp_err_msg
        ldy #>dhcp_err_msg
        jsr print_string
        rts

@dhcp_ok:
        ; print IP address
        lda #<net_ok_msg
        ldy #>net_ok_msg
        jsr print_string
        jsr net_print_ip

        ; set default WireGuard port
        lda #<wg_default_port
        sta wg_local_port
        lda #>wg_default_port
        sta wg_local_port+1

        ; start UDP listener
        jsr net_udp_listen
        bcc @listen_ok

        lda #<net_listen_err_msg
        ldy #>net_listen_err_msg
        jsr print_string
        rts

@listen_ok:
        lda #<net_listen_msg
        ldy #>net_listen_msg
        jsr print_string

        ; mark network as initialized
        lda #1
        sta net_initialized
        rts

; =============================================================================
; do_send_test - send a test transport packet
; =============================================================================
do_send_test:
        ; set up test payload pointer
        lda #<test_payload
        sta tp_payload_ptr
        lda #>test_payload
        sta tp_payload_ptr+1
        lda #test_payload_len
        sta tp_payload_len

        ; encrypt and send
        jsr transport_send
        bcs @send_err

        lda #<send_ok_msg
        ldy #>send_ok_msg
        jsr print_string
        rts

@send_err:
        lda #<send_err_msg
        ldy #>send_err_msg
        jsr print_string
        rts

; =============================================================================
; clrscr - clear screen
; =============================================================================
clrscr:
        lda #$93                ; PETSCII clear screen
        jsr chrout
        rts

; =============================================================================
; print_string - print null-terminated string
; input: A = low byte of address, Y = high byte of address
; =============================================================================
print_string:
        sta zp_ptr1
        sty zp_ptr1+1
        ldy #0
@loop:
        lda (zp_ptr1),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts
