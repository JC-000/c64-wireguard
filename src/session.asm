; =============================================================================
; session.asm - WireGuard session state machine
;
; States:
;   0 (IDLE)    - no handshake in progress
;   1 (HS_SENT) - initiation sent, waiting for response
;   2 (ACTIVE)  - transport keys established, can send/recv data
;
; Interface:
;   session_initiate      - start handshake (IDLE -> HS_SENT)
;   session_handle_packet - process received UDP packet
;   session_reset         - return to IDLE
;   display_payload       - print decrypted payload to screen
; =============================================================================

SESSION_IDLE    = 0
SESSION_HS_SENT = 1
SESSION_ACTIVE  = 2

; =============================================================================
; session_initiate - Start WireGuard handshake
;
; Loads config, generates ephemeral key, creates Type 1 initiation,
; sends via UDP.
;
; Input: cfg_* buffers populated, network initialized
; Output: hs_packet sent, state = HS_SENT
; Clobbers: everything
; =============================================================================
session_initiate:
        ; Load configuration
        jsr config_load

        ; Generate ephemeral private key (32 random bytes)
        lda #<hs_ephem_priv
        sta zp_ptr1
        lda #>hs_ephem_priv
        sta zp_ptr1+1
        ldy #32
        jsr entropy_fill

        ; Increment timestamp for replay protection
        jsr tai64n_increment

        ; Create Type 1 initiation packet
        jsr hs_create_initiation

        ; Send packet (148 bytes)
        lda #148
        sta udp_send_len_local
        lda #0
        sta udp_send_len_local+1
        lda #<hs_packet
        ldx #>hs_packet
        jsr net_udp_send

        ; Update state
        lda #SESSION_HS_SENT
        sta wg_state

        rts

; =============================================================================
; session_handle_packet - Process received UDP packet
;
; Reads packet type from udp_recv_buf[0] and dispatches:
;   Type 2 (in STATE_HS_SENT): process handshake response
;   Type 4 (in STATE_ACTIVE): decrypt transport data
;
; Input: udp_recv_buf contains packet, udp_recv_ready = 1
; Output: state may transition, udp_recv_ready cleared
; Clobbers: everything
; =============================================================================
session_handle_packet:
        ; Clear ready flag
        lda #0
        sta udp_recv_ready

        ; Check packet type (first byte, LE u32)
        lda udp_recv_buf
        cmp #2
        beq @type2
        cmp #3
        beq @type3
        cmp #4
        beq @type4
        rts                     ; unknown type, ignore

@type3:
        jsr cookie_handle_type3
        cmp #0
        bne @cookie_fail
        lda #<cookie_recv_msg
        ldy #>cookie_recv_msg
        jsr print_string
        ; re-initiate handshake with cookie
        jsr session_initiate
        rts
@cookie_fail:
        rts

@type2:
        ; Only accept in HS_SENT state
        lda wg_state
        cmp #SESSION_HS_SENT
        bne @wrong_state

        ; Copy udp_recv_buf to hs_resp_packet (92 bytes)
        ldx #91
@copy_resp:
        lda udp_recv_buf,x
        sta hs_resp_packet,x
        dex
        bpl @copy_resp

        ; Process response - derives transport keys
        jsr hs_process_response
        cmp #0
        bne @hs_fail

        ; Initialize transport state
        jsr transport_init

        ; Transition to ACTIVE
        lda #SESSION_ACTIVE
        sta wg_state

        jsr timer_session_start

        ; Print success
        lda #<hs_ok_msg
        ldy #>hs_ok_msg
        jsr print_string
        rts

@hs_fail:
        lda #<hs_fail_msg
        ldy #>hs_fail_msg
        jsr print_string
        rts

@wrong_state:
        rts                     ; silently ignore

@type4:
        ; Only accept in ACTIVE state
        lda wg_state
        cmp #SESSION_ACTIVE
        bne @wrong_state

        ; Copy received packet to tp_packet for decrypt
        ; Need to know length - use udp_recv_len
        ldx #0
@copy_t4:
        lda udp_recv_buf,x
        sta tp_packet,x
        inx
        cpx udp_recv_len        ; low byte (max 255)
        bne @copy_t4

        ; Set packet length
        lda udp_recv_len
        sta tp_packet_len
        lda udp_recv_len+1
        sta tp_packet_len+1

        ; Decrypt
        jsr transport_decrypt
        cmp #0
        bne @decrypt_fail

        ; Route by IP protocol
        lda tp_packet+16+9      ; IP protocol byte
        cmp #IP_PROTO_ICMP
        beq @t4_icmp
        cmp #IP_PROTO_UDP
        beq @t4_udp
        ; fallback: display raw
        jsr display_payload
        rts
@t4_icmp:
        jsr icmp_parse_reply
        cmp #0
        bne @t4_icmp_other
        lda #<ping_reply_msg
        ldy #>ping_reply_msg
        jsr print_string
        rts
@t4_icmp_other:
        jsr display_payload
        rts
@t4_udp:
        jsr udp_tunnel_parse
        cmp #0
        bne @t4_udp_bad
        ; display received message
        lda #<msg_recv_hdr
        ldy #>msg_recv_hdr
        jsr print_string
        ; print msg_recv_len bytes from msg_recv_ptr
        lda msg_recv_ptr
        sta zp_ptr1
        lda msg_recv_ptr+1
        sta zp_ptr1+1
        ldy #0
        ldx msg_recv_len
        beq @t4_udp_done
@t4_udp_print:
        lda (zp_ptr1),y
        jsr chrout
        iny
        dex
        bne @t4_udp_print
@t4_udp_done:
        lda #$0d
        jsr chrout
        rts
@t4_udp_bad:
        jsr display_payload
        rts

@decrypt_fail:
        lda #<decrypt_fail_msg
        ldy #>decrypt_fail_msg
        jsr print_string
        rts

; =============================================================================
; session_reset - Reset session to IDLE state
;
; Clobbers: A
; =============================================================================
session_reset:
        lda #SESSION_IDLE
        sta wg_state
        rts

; =============================================================================
; display_payload - Print decrypted transport payload as ASCII
;
; Prints tp_payload_len bytes from tp_packet+16 (payload starts after header).
; Non-printable characters (< $20 or > $7E) replaced with '.'.
; Prints newline at end.
;
; Clobbers: A, X, Y
; =============================================================================
display_payload:
        lda #<recv_data_msg
        ldy #>recv_data_msg
        jsr print_string

        ldy #0
        ldx tp_payload_len
        beq @done               ; no payload
@loop:
        lda tp_packet+16,y
        cmp #$20
        bcc @dot                ; < space
        cmp #$7f
        bcs @dot                ; >= $7F
        jmp @print
@dot:
        lda #'.'
@print:
        jsr chrout
        iny
        dex
        bne @loop
@done:
        lda #$0d                ; newline
        jsr chrout
        rts
