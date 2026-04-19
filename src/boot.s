; =============================================================================
; src/boot.s — BASIC stub, program entry point, and main event loop.
;
; ca65 port of src/boot.asm (Phase 6 of the ACME -> ca65 migration, the
; final module). Replaces the Phase 1 scaffolding in src/main.s.
;
; Segment layout (see cfg/c64-wireguard-ip65.cfg):
;   EXEHDR  -> LOADER region at $0801, holds the 12-byte BASIC stub so
;              `start:` lands at $080D (= SYS 2061).
;   CODE    -> LOADER region, holds `start` and every boot subroutine.
;   APP_BSS -> SHADOW_BSS region at $A000, not currently used by boot.
;
; No logic changes from boot.asm — this is a mechanical syntax port.
; =============================================================================

        .include "constants.inc"
        .include "net_abi.inc"
        .include "crypto_abi.inc"

; --- Exports --------------------------------------------------------------
        .export start                   ; SYS 2061 entry point
        .export print_string            ; used by session.s, timer.s

; --- Imports: external data from src/wg/data.s ---------------------------
        .import net_initialized
        .import wg_state
        .import udp_recv_ready
        .import wg_local_port
        .import tp_payload_ptr
        .import tp_payload_len
        .import ip_packet_buf
        .import ip_pkt_len
        .import msg_input_buf
        .import msg_input_len

; --- Imports: strings from src/wg/strings.s ------------------------------
        .import title_msg
        .import net_init_msg
        .import net_err_msg
        .import net_dhcp_msg
        .import dhcp_err_msg
        .import net_ok_msg
        .import net_listen_msg
        .import net_listen_err_msg
        .import send_ok_msg
        .import send_err_msg
        .import test_payload
        .import test_payload_len
        .import hs_start_msg
        .import ping_sent_msg
        .import not_active_msg
        .import msg_prompt
        .import cfg_loading_msg
        .import cfg_ok_msg
        .import cfg_err_msg

; --- Imports: subroutines from other modules -----------------------------
        .import session_handle_packet   ; src/wg/session.s
        .import session_initiate        ; src/wg/session.s
        .importzp SESSION_ACTIVE        ; src/wg/session.s (zp-sized equate)
        .import timer_check             ; src/wg/timer.s
        .import timer_mark_send         ; src/wg/timer.s
        .import transport_send          ; src/wg/transport.s
        .import icmp_build_echo         ; src/wg/ip_build.s
        .import udp_tunnel_build        ; src/wg/ip_build.s
        .import config_read_file        ; src/wg/disk_config.s
        .import entropy_init            ; src/crypto/entropy.s

; (net_init, net_dhcp, net_poll, net_udp_listen, net_print_ip come via
;  net_abi.inc; sqtab_init, reu_mul_init come via crypto_abi.inc.)

; =============================================================================
; BASIC stub: 10 SYS 2061
; Loaded at $0801. Byte-identical to the Phase 1 pattern in src/main.s so
; `start:` lands exactly at $080D (= 2061 decimal).
; =============================================================================
        .segment "EXEHDR"
        .word   bas_end                 ; pointer to next BASIC line
        .word   10                      ; line number 10
        .byte   $9e                     ; SYS token
        .byte   "2061"                  ; decimal address of `start` ($080D)
        .byte   0                       ; end of BASIC line
bas_end:
        .word   0                       ; end of BASIC program

; =============================================================================
; Main program entry point
; =============================================================================
        .segment "CODE"

start:
        ; bank out BASIC ROM to use $A000-$BFFF as RAM
        lda     proc_port
        and     #$fe                    ; clear bit 0 (LORAM) -- bank out BASIC ROM
        sta     proc_port

        ; BSS is now below $8000 and emitted as zero bytes in the PRG
        ; file, so LOAD stamps zeros into RAM for us. Additionally zero
        ; $A000-$BFFF (where ip65's own BSS lives) as a defensive
        ; measure — some WG tests rely on these pages being clean even
        ; though WG doesn't own them directly.
        ldy     #$00
        ldx     #$20                    ; 32 pages = $2000 bytes
        lda     #$A0
        sta     @zbss_store+2
        lda     #$00
@zbss_page:
@zbss_store:
        sta     $A000,y                 ; self-modified high byte walks $A0..$BF
        iny
        bne     @zbss_store
        inc     @zbss_store+2
        dex
        bne     @zbss_page

        ; clear screen
        jsr     clrscr

        ; display title
        lda     #<title_msg
        ldy     #>title_msg
        jsr     print_string

        ; Initialize quarter-square table (needed by mul_8x8 and fe_sqr)
        jsr     sqtab_init

        ; Initialize REU multiplication tables (precompute all 256x256 products)
        jsr     reu_mul_init

        ; fall through to main loop
main_loop:
        lda     net_initialized
        beq     no_poll
        jsr     net_poll                ; poll ip65 for packets
        lda     udp_recv_ready
        beq     no_poll
        jsr     session_handle_packet
no_poll:
        ; check timers when active
        lda     wg_state
        cmp     #<SESSION_ACTIVE
        bne     no_timer
        jsr     timer_check
no_timer:
        jsr     getin
        beq     main_loop               ; wait for keypress

        cmp     #$51                    ; 'Q' = quit
        beq     quit
        cmp     #$49                    ; 'I' = init network
        beq     do_init_net
        cmp     #$48                    ; 'H' = handshake
        beq     do_hs
        cmp     #$53                    ; 'S' = send test packet
        beq     do_st
        cmp     #$50                    ; 'P' = ping
        beq     do_pg
        cmp     #$4d                    ; 'M' = message
        beq     do_msg
        cmp     #$4c                    ; 'L' = load config
        beq     do_cfg

        jmp     main_loop

do_init_net:
        jsr     do_net_init
        jmp     main_loop

do_st:
        jsr     do_send_test
        jmp     main_loop

do_hs:
        jsr     do_handshake
        jmp     main_loop

do_pg:
        jsr     do_ping
        jmp     main_loop

do_msg:
        jsr     do_message_input
        jmp     main_loop

do_cfg:
        jsr     do_load_config
        jmp     main_loop

quit:
        ; restore BASIC ROM before returning
        lda     proc_port
        ora     #$01
        sta     proc_port
        rts

; =============================================================================
; do_net_init - initialize network, DHCP, start UDP listener
; =============================================================================
do_net_init:
        ; print init message
        lda     #<net_init_msg
        ldy     #>net_init_msg
        jsr     print_string

        ; init ip65
        jsr     net_init
        bcc     @init_ok

        ; init failed
        lda     #<net_err_msg
        ldy     #>net_err_msg
        jsr     print_string
        rts

@init_ok:
        ; print DHCP message
        lda     #<net_dhcp_msg
        ldy     #>net_dhcp_msg
        jsr     print_string

        ; request DHCP
        jsr     net_dhcp
        bcc     @dhcp_ok

        ; DHCP failed
        lda     #<dhcp_err_msg
        ldy     #>dhcp_err_msg
        jsr     print_string
        rts

@dhcp_ok:
        ; print IP address
        lda     #<net_ok_msg
        ldy     #>net_ok_msg
        jsr     print_string
        jsr     net_print_ip

        ; set default WireGuard port
        lda     #<wg_default_port
        sta     wg_local_port
        lda     #>wg_default_port
        sta     wg_local_port+1

        ; start UDP listener
        jsr     net_udp_listen
        bcc     @listen_ok

        lda     #<net_listen_err_msg
        ldy     #>net_listen_err_msg
        jsr     print_string
        rts

@listen_ok:
        lda     #<net_listen_msg
        ldy     #>net_listen_msg
        jsr     print_string

        ; mark network as initialized
        lda     #1
        sta     net_initialized
        rts

; =============================================================================
; do_send_test - send a test transport packet
; =============================================================================
do_send_test:
        ; set up test payload pointer
        lda     #<test_payload
        sta     tp_payload_ptr
        lda     #>test_payload
        sta     tp_payload_ptr+1
        lda     #<test_payload_len
        sta     tp_payload_len
        lda     #0
        sta     tp_payload_len+1

        ; encrypt and send
        jsr     transport_send
        bcs     @send_err

        lda     #<send_ok_msg
        ldy     #>send_ok_msg
        jsr     print_string
        rts

@send_err:
        lda     #<send_err_msg
        ldy     #>send_err_msg
        jsr     print_string
        rts

; =============================================================================
; do_handshake - initiate WireGuard handshake
; =============================================================================
do_handshake:
        lda     #<hs_start_msg
        ldy     #>hs_start_msg
        jsr     print_string

        ; init entropy sources
        jsr     entropy_init

        ; small delay for SID to settle (256 iterations)
        ldx     #0
@delay:
        nop
        nop
        nop
        nop
        dex
        bne     @delay

        ; initiate session
        jsr     session_initiate

        rts

; =============================================================================
; do_ping - send ICMP echo request through tunnel
; =============================================================================
do_ping:
        lda     wg_state
        cmp     #<SESSION_ACTIVE
        beq     @ping_ok
        lda     #<not_active_msg
        ldy     #>not_active_msg
        jsr     print_string
        rts
@ping_ok:
        jsr     icmp_build_echo
        ; set transport payload to ip_packet_buf
        lda     #<ip_packet_buf
        sta     tp_payload_ptr
        lda     #>ip_packet_buf
        sta     tp_payload_ptr+1
        lda     ip_pkt_len
        sta     tp_payload_len
        lda     #0
        sta     tp_payload_len+1
        jsr     transport_send
        jsr     timer_mark_send
        lda     #<ping_sent_msg
        ldy     #>ping_sent_msg
        jsr     print_string
        rts

; =============================================================================
; do_message_input - read text from keyboard and send via tunnel
; =============================================================================
do_message_input:
        lda     wg_state
        cmp     #<SESSION_ACTIVE
        beq     @msg_ok
        lda     #<not_active_msg
        ldy     #>not_active_msg
        jsr     print_string
        rts
@msg_ok:
        lda     #<msg_prompt
        ldy     #>msg_prompt
        jsr     print_string
        jsr     read_input_line
        ; build UDP tunnel packet
        lda     #<msg_input_buf
        sta     zp_ptr1
        lda     #>msg_input_buf
        sta     zp_ptr1+1
        lda     msg_input_len
        sta     zp_tmp1
        jsr     udp_tunnel_build
        ; send through transport
        lda     #<ip_packet_buf
        sta     tp_payload_ptr
        lda     #>ip_packet_buf
        sta     tp_payload_ptr+1
        lda     ip_pkt_len
        sta     tp_payload_len
        lda     #0
        sta     tp_payload_len+1
        jsr     transport_send
        jsr     timer_mark_send
        lda     #<send_ok_msg
        ldy     #>send_ok_msg
        jsr     print_string
        rts

; =============================================================================
; do_load_config - load configuration from disk
; =============================================================================
do_load_config:
        lda     #<cfg_loading_msg
        ldy     #>cfg_loading_msg
        jsr     print_string
        jsr     config_read_file
        bcs     @cfg_err
        lda     #<cfg_ok_msg
        ldy     #>cfg_ok_msg
        jsr     print_string
        rts
@cfg_err:
        lda     #<cfg_err_msg
        ldy     #>cfg_err_msg
        jsr     print_string
        rts

; =============================================================================
; read_input_line - read a line of text from keyboard
; Output: msg_input_buf filled, msg_input_len set
; =============================================================================
read_input_line:
        ldy     #0                      ; buffer position
@ril_loop:
        jsr     getin
        beq     @ril_loop               ; no key pressed
        cmp     #$0d                    ; RETURN
        beq     @ril_done
        cmp     #$14                    ; DELETE (PETSCII)
        beq     @ril_del
        cpy     #40                     ; max length
        beq     @ril_loop               ; buffer full, ignore
        sta     msg_input_buf,y
        jsr     chrout                  ; echo
        iny
        jmp     @ril_loop
@ril_del:
        cpy     #0
        beq     @ril_loop               ; nothing to delete
        dey
        lda     #$14                    ; PETSCII delete
        jsr     chrout
        jmp     @ril_loop
@ril_done:
        sty     msg_input_len
        lda     #$0d
        jsr     chrout                  ; newline
        rts

; =============================================================================
; clrscr - clear screen
; =============================================================================
clrscr:
        lda     #$93                    ; PETSCII clear screen
        jsr     chrout
        rts

; =============================================================================
; print_string - print null-terminated string
; input: A = low byte of address, Y = high byte of address
; =============================================================================
print_string:
        sta     zp_ptr1
        sty     zp_ptr1+1
        ldy     #0
@loop:
        lda     (zp_ptr1),y
        beq     @done
        jsr     chrout
        iny
        bne     @loop
@done:
        rts
