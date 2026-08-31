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
;   APP_BSS -> MAIN_AREA_HI, not currently used by boot. (This line used
;              to name a SHADOW_BSS region at $A000; no such region has
;              existed since the ca65 port — see issue #80.)
;
; No logic changes from boot.asm — this is a mechanical syntax port.
; =============================================================================

        .include "constants.inc"
        .include "net_abi.inc"

        ; Not part of the §13.1 contract surface — imported explicitly so the
        ; dependency on an adapter extra is visible here, not implied by
        ; net_abi.inc. See that header's closing note.
        .import net_print_ip
        .include "crypto_abi.inc"

; --- Exports --------------------------------------------------------------
        .export start                   ; SYS 2061 entry point
        .export print_string            ; used by session.s, timer.s

; --- Imports: external data from src/wg/data.s ---------------------------
        .import vic_boost_begin, vic_boost_end
        .import net_initialized
        .import boot_ready
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
        .import ready_msg
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

; --- Imports: linker-defined bounds of the reclaimed cold segment ---------
; Published by `define = yes` on LIB_X25519_INIT_CODE in both cfgs. The
; zero-fill after the table build below is what turns that span from code
; into APP_BSS; see the comment there and issue #103.
; Only defined when the x25519 archive is in the link — under
; USE_X25519_SIBLING=0 the segment is empty, ld65 defines nothing for it,
; and there is no cold code to reclaim in the first place.
.ifdef USE_X25519_SIBLING
        .import __LIB_X25519_INIT_CODE_LOAD__
        .import __LIB_X25519_INIT_CODE_SIZE__
.endif

; (net_init, net_dhcp_acquire, net_poll, net_udp_listen, net_print_ip come via
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
; BOOT_CODE (not bare CODE): the bare CODE segment name is ceded to the
; c64-ChaCha20-Poly1305 sibling archive, which has not adopted the
; contract §4 prefixed segment names yet (upstream issue #48). The cfg
; places BOOT_CODE in LOADER directly after EXEHDR so `start:` stays at
; $080D — the BASIC stub's hardcoded SYS 2061 depends on it.
        .segment "BOOT_CODE"

start:
        ; bank out BASIC ROM to use $A000-$BFFF as RAM
        lda     proc_port
        and     #$fe                    ; clear bit 0 (LORAM) -- bank out BASIC ROM
        sta     proc_port

        ; BSS is now below $8000 and emitted as zero bytes in the PRG
        ; file, so LOAD stamps zeros into RAM for us. Additionally zero
        ; $A000-$BFFF, which under BACKEND=ip65 is the blob's private BSS
        ; (IP65_BSS in the cfg; $A000-$AF3F occupied). It is file = "" —
        ; no PRG bytes are emitted for it — so LOAD leaves whatever was
        ; there, and this loop is what actually clears it. Runs under
        ; BACKEND=uci too, where the span is simply unused; the cost is a
        ; few ms once at boot and it keeps the two builds' RAM identical.
        ;
        ; The bank-out above is a PRECONDITION for the loop being visible:
        ; with LORAM set, the writes would still land in RAM (writes always
        ; go under ROM) but every read-back would return BASIC ROM, so
        ; nothing that later reads this span — ip65's frame buffers most of
        ; all — would work. Do not move either half.
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

        ; Build the multiply tables with the display blanked. This is the
        ; longest uninterrupted stretch of compute in the program — the REU
        ; precompute walks all 256x256 products, ~10 s of emulated time —
        ; and nothing is printed while it runs, so there is no progress to
        ; hide. ~6.3% off the boot wait; see src/wg/vic_boost.s.
        jsr     vic_boost_begin

        ; Initialize quarter-square table (needed by mul_8x8 and fe_sqr).
        ; Under the sibling build go through poly1305_lib_init, which
        ; runs the same table builder AND sets chacha's sqtab_ready —
        ; see crypto_abi.inc for why that flag is worth setting here.
.ifdef USE_CHACHA_SIBLING
        jsr     poly1305_lib_init
.else
        jsr     sqtab_init
.endif

.ifndef WG_NO_REU
        ; Initialize REU multiplication tables (precompute all 256x256 products)
        jsr     reu_mul_init
.endif

.ifdef USE_X25519_SIBLING
        ; --- Reclaim LIB_X25519_INIT_CODE as APP_BSS (issue #103) ------------
        ;
        ; THIS IS THE LAST INSTANT THE COLD INIT CODE EXISTS. The two calls
        ; above are the only callers of anything in LIB_X25519_INIT_CODE
        ; (sqtab_init / mul_tables_init, reu_mul_init; reu_probe is never
        ; called from this repo at all), and both have returned. From here
        ; on, cfg/c64-wireguard-*.cfg lays APP_BSS over that span through
        ; the APP_BSS_OVERLAY region, so those 826 bytes (160 under
        ; WG_NO_REU) are ordinary zero-initialised BSS like every other
        ; byte of APP_BSS — and this loop is what makes them zero, because
        ; it is the one part of the span LOAD could not stamp with the
        ; region's fill.
        ;
        ; ORDER IS LOAD-BEARING, in both directions:
        ;   - it must run AFTER the table build, or it erases the code
        ;     mid-flight;
        ;   - it must run BEFORE anything writes an APP_BSS variable that
        ;     falls in the span, or it erases live state. Nothing above it
        ;     touches APP_BSS: `start:` banks out BASIC, zeroes $A000-$BFFF,
        ;     calls clrscr / print_string / vic_boost_begin (screen RAM,
        ;     $D0xx and their own locals), then the two table builders.
        ;     boot_ready, the first APP_BSS write in the program, is set
        ;     below.
        ;
        ; Overwriting with $00 is also what makes the deadness claim
        ; testable rather than asserted: $00 is BRK, so any surviving entry
        ; into this span after boot derails into the KERNAL BRK handler
        ; instead of silently doing something plausible. See
        ; tools/test_cold_segment_reclaim.py.
        ;
        ; The bounds come from the linker (define = yes on the segment), not
        ; from a constant here — the span is 826 bytes under REU and 160
        ; under the onchip profile, and hardcoding either would be a number
        ; that goes stale exactly like the ones issue #103 is about.
        lda     #<__LIB_X25519_INIT_CODE_LOAD__
        sta     zp_ptr1
        lda     #>__LIB_X25519_INIT_CODE_LOAD__
        sta     zp_ptr1+1
        ldx     #>__LIB_X25519_INIT_CODE_SIZE__ ; whole pages to clear
        lda     #$00
        ldy     #$00
@cold_page:
        cpx     #$00
        beq     @cold_tail
@cold_page_byte:
        sta     (zp_ptr1),y
        iny
        bne     @cold_page_byte
        inc     zp_ptr1+1
        dex
        jmp     @cold_page
@cold_tail:
        ldy     #<__LIB_X25519_INIT_CODE_SIZE__ ; 0..255 trailing bytes
        beq     @cold_done
@cold_tail_byte:
        dey
        sta     (zp_ptr1),y
        bne     @cold_tail_byte
@cold_done:
.endif

        jsr     vic_boost_end

        ; Boot-complete marker (issue #55): title_msg's "Q=QUIT" prints
        ; before the table build above and only means "boot started" —
        ; tests gating on it proceed against a half-booted machine. Set
        ; the flag and print the human-visible line only now that the
        ; table build has returned and the display is unblanked, so both
        ; signals are true boot-complete indicators.
        lda     #1
        sta     boot_ready

        lda     #<ready_msg
        ldy     #>ready_msg
        jsr     print_string

        ; fall through to main loop
main_loop:
        lda     net_initialized
        beq     no_poll
        jsr     net_poll                ; poll ip65 for packets
        lda     udp_recv_ready
        beq     no_poll
        jsr     session_handle_packet
no_poll:
        ; Timers, in every state. This used to be gated on
        ; wg_state == SESSION_ACTIVE — a second copy of the gate timer_check
        ; already applies internally, and the outer copy was the binding one:
        ; it meant nothing could ever time an unanswered handshake, because
        ; timer_check was not called at all in HS_SENT (issue #84). One gate,
        ; inside the routine that owns it. In IDLE this costs a compare and
        ; an rts per loop iteration.
        jsr     timer_check
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
        ; Hand the firmware socket back before we go. Abandoning a live one
        ; poisons the U64E's UCI lease path until a wall power cycle — see
        ; net_udp_close and issue #58. Safe when nothing is open.
        jsr     net_udp_close

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
        jsr     net_dhcp_acquire
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
        lda     ip_pkt_len+1
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
        sta     zp_tmp1                 ; text length, 16-bit
        lda     msg_input_len+1
        sta     zp_tmp2
        jsr     udp_tunnel_build
        ; send through transport
        lda     #<ip_packet_buf
        sta     tp_payload_ptr
        lda     #>ip_packet_buf
        sta     tp_payload_ptr+1
        lda     ip_pkt_len
        sta     tp_payload_len
        lda     ip_pkt_len+1
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
;
; THE INDEX MUST NOT LIVE IN Y ACROSS getin. KERNAL GETIN ($FFE4) does not
; preserve Y: its keyboard-buffer fetch loads the character with LDY $0277,
; shifts the queue using X, and returns it via TYA — so on return Y holds the
; CHARACTER and X the shift count. This routine used to keep the buffer
; position in Y across that call, which meant:
;
;   sta msg_input_buf,y   stored at msg_input_buf + char. 'A' ($41) landed at
;                         $97A1, ~66 bytes past a 40-byte buffer, scattering
;                         every keystroke over whatever followed it.
;   cpy #40               could never match, Y being a character code >= $20,
;                         so the length guard never fired either.
;   sty msg_input_len     on RETURN stored Y = $0D, so the length was always
;                         13 no matter what was typed.
;
; Net effect: the buffer was never written, and do_message_input tunnelled 13
; bytes of stale buffer content. Every outbound chat message from the C64 was
; empty — for a person at the keyboard exactly as much as for a host driving
; the queue over DMA. Measured in isolation: after typing 8 characters, Y read
; $49, i.e. the last character 'H' ($48) plus one iny.
;
; So the position lives in msg_input_len, which is where the count has to end
; up anyway. Registers are then free to be clobbered by any KERNAL call.
;
; The position is 16-bit (contract §13.3): the buffer is MSG_TEXT_MAX bytes,
; one full tunnel packet's worth of text, which is past what an 8-bit index
; reaches. Each character is stored through a pointer rebuilt from the
; position, so no register carries state across getin/chrout.
; Output: msg_input_buf filled, msg_input_len set (16-bit)
; =============================================================================
read_input_line:
        lda     #0
        sta     msg_input_len           ; buffer position AND final count
        sta     msg_input_len+1
@ril_loop:
        jsr     getin                   ; clobbers X and Y; A = character
        beq     @ril_loop               ; no key pressed
        cmp     #$0d                    ; RETURN
        beq     @ril_done
        cmp     #$14                    ; DELETE (PETSCII)
        beq     @ril_del
        sta     zp_tmp1                 ; park the character
        ; buffer full? (msg_input_len >= MSG_TEXT_MAX, 16-bit compare)
        lda     msg_input_len+1
        cmp     #>MSG_TEXT_MAX
        bcc     @ril_store
        bne     @ril_loop               ; high byte above: full, ignore
        lda     msg_input_len
        cmp     #<MSG_TEXT_MAX
        bcs     @ril_loop               ; low byte at/above: full, ignore
@ril_store:
        lda     #<msg_input_buf         ; zp_ptr1 = msg_input_buf + position
        clc
        adc     msg_input_len
        sta     zp_ptr1
        lda     #>msg_input_buf
        adc     msg_input_len+1
        sta     zp_ptr1+1
        ldy     #0
        lda     zp_tmp1
        sta     (zp_ptr1),y
        jsr     chrout                  ; echo (preserves A)
        inc     msg_input_len
        bne     @ril_loop
        inc     msg_input_len+1
        jmp     @ril_loop
@ril_del:
        lda     msg_input_len
        ora     msg_input_len+1
        beq     @ril_loop               ; nothing to delete
        lda     msg_input_len
        bne     @ril_dec_lo
        dec     msg_input_len+1         ; borrow into the high byte
@ril_dec_lo:
        dec     msg_input_len
        lda     #$14                    ; PETSCII delete
        jsr     chrout
        jmp     @ril_loop
@ril_done:
        lda     #$0d
        jsr     chrout                  ; newline
        rts                             ; msg_input_len already holds the count

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
