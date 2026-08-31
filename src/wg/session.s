; =============================================================================
; wg/session.s - WireGuard session state machine
;
; ca65 port of src/session.asm. No logic changes; syntax translation only.
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

.include "constants.inc"

; ---- Session-state constants (exported for other modules) -------------------
SESSION_IDLE    = 0
SESSION_HS_SENT = 1
SESSION_ACTIVE  = 2

; ---- Public entry points ----------------------------------------------------
.export session_stage_dest
.export session_initiate
.export session_handle_packet
.export session_reset
.export display_payload
.export endpoint_update

; ---- Exported session-state constants (referenced by timer.s, etc.) --------
; Using .exportzp because ca65 treats small numeric equates as zeropage-sized
; by default, and importers use them with #<immediate addressing.
.exportzp SESSION_IDLE
.exportzp SESSION_HS_SENT
.exportzp SESSION_ACTIVE

; ---- External subroutines ---------------------------------------------------
; Config / entropy / timestamp
.import config_load
.import entropy_fill
.import tai64n_increment
; Handshake
.import hs_create_initiation
.import hs_process_response
; Transport
.import transport_init
.import transport_decrypt
; Cookie (wg/cookie.s)
.import cookie_handle_type3
; Session timer (wg/timer.s)
.import timer_session_start
.import timer_handshake_start
; Networking
.import net_udp_send
.import net_udp_close
.import net_udp_dest_port
.import net_udp_dest_ip
; IP-layer parsers
.import icmp_parse_reply
.import udp_tunnel_parse
; Console output
.import print_string

; ---- External data buffers / state ------------------------------------------
; Handshake buffers
.import hs_ephem_priv
.import hs_sender_idx
.import hs_packet
.import hs_resp_packet
; UDP I/O buffers / flags
.import net_udp_send_len
.import udp_recv_buf
.import udp_recv_len
.import udp_recv_ready
.import udp_recv_src_ip
.import udp_recv_src_port
; Peer endpoint
.import wg_peer_ip
.import wg_peer_port
; Session state variable
.import wg_state
.import hs_timer_armed
; Transport packet buffers
.import tp_packet
.import tp_packet_len
.import tp_payload_len
; Tunnel UDP message receive state
.import msg_recv_ptr
.import msg_recv_len

; ---- Imported strings (wg/strings.s) ---------------------------------------
.import cookie_recv_msg
.import hs_ok_msg
.import hs_fail_msg
.import hs_send_err_msg
.import decrypt_fail_msg
.import recv_data_msg
.import ping_reply_msg
.import msg_recv_hdr

.segment "APP_CODE"

; =============================================================================
; session_stage_dest — copy the peer endpoint into the §13.1 ABI cells
;
; The backend reads net_udp_dest_ip / net_udp_dest_port, never wg_peer_*.
; Call immediately before net_udp_send. Kept as one routine so a roaming
; update to wg_peer_* cannot leave a send pointed at a stale endpoint.
;
; Clobbers: A, X
; =============================================================================
; Placed in APP_EXTRA (MAIN_AREA_HI), not APP_CODE. It was moved here when
; MAIN_AREA_LO could not hold it; the §6.7 image-overrun assert in
; contract_asserts.s is what caught that, and is what would catch it again.
; Nothing about this routine needs to be low — it copies six bytes between
; two absolute addresses. No headroom figures: see the note in
; src/crypto/entropy.s for why this repo stopped writing them down.
.segment "APP_EXTRA"

session_stage_dest:
        ; wg_peer_ip(4) and wg_peer_port(2) are contiguous, as are
        ; net_udp_dest_ip(4) and net_udp_dest_port(2), so one 6-byte copy
        ; does both. data.s keeps them adjacent for exactly this reason.
        ldx #$05
@sd_copy:
        lda wg_peer_ip,x
        sta net_udp_dest_ip,x
        dex
        bpl @sd_copy
        rts

; The single 6-byte copy above is only correct while each pair is contiguous
; and in this order. Inserting a variable between them would silently copy
; the wrong bytes into the send destination — a wrong-peer bug with no crash
; and no test that would obviously catch it. Fail the link instead.
.assert net_udp_dest_port = net_udp_dest_ip + 4, lderror, "net_udp_dest_port must directly follow net_udp_dest_ip — session_stage_dest copies both in one 6-byte loop"
.assert wg_peer_port = wg_peer_ip + 4, lderror, "wg_peer_port must directly follow wg_peer_ip — session_stage_dest copies both in one 6-byte loop"

.segment "APP_CODE"

; =============================================================================
; session_initiate - Start WireGuard handshake
;
; Loads config, generates ephemeral key, creates Type 1 initiation,
; sends via UDP.
;
; Input: cfg_* buffers populated, network initialized
; Output: C=0, hs_packet sent, state = HS_SENT
;         C=1, nothing sent, state = IDLE and the backend resource returned
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

        ; Generate sender index (4 fresh random bytes, WireGuard Type 1 offset 4)
        lda #<hs_sender_idx
        sta zp_ptr1
        lda #>hs_sender_idx
        sta zp_ptr1+1
        ldy #4
        jsr entropy_fill

        ; Increment timestamp for replay protection
        jsr tai64n_increment

        ; Create Type 1 initiation packet
        jsr hs_create_initiation

        ; Send packet (148 bytes)
        lda #148
        sta net_udp_send_len
        lda #0
        sta net_udp_send_len+1
        jsr session_stage_dest  ; §13.1: backend reads net_udp_dest_*
        lda #<hs_packet
        ldx #>hs_packet
        jsr net_udp_send
        bcc @si_sent
        jmp session_send_failed ; nothing went out — see APP_EXTRA below

@si_sent:
        ; Update state
        lda #SESSION_HS_SENT
        sta wg_state

        ; Start the clock on this initiation. Without it HS_SENT is an
        ; absorbing state: nothing ever leaves it except a Type 2 that may
        ; never come, and the backend's socket stays pinned to a peer we
        ; have already stopped hearing from (issue #84).
        jsr timer_handshake_start

        clc
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
        ; This initiation is dead: hs_process_response rejected the Type 2,
        ; so no transport keys exist and the peer will not send another
        ; response for a sender index we are about to stop using. Abandon it
        ; properly instead of returning to HS_SENT holding the socket —
        ; session_reset drops to IDLE, disarms the deadline and hands the
        ; socket back (issue #84).
        jsr session_reset
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

        ; Copy received packet to tp_packet for decrypt (16-bit)
        lda #<udp_recv_buf
        sta zp_ptr1
        lda #>udp_recv_buf
        sta zp_ptr1+1
        lda #<tp_packet
        sta zp_ptr2
        lda #>tp_packet
        sta zp_ptr2+1
        ; Copy full pages
        ldx udp_recv_len+1
        ldy #0
        cpx #0
        beq @t4_copy_rem
@t4_copy_pg:
        lda (zp_ptr1),y
        sta (zp_ptr2),y
        iny
        bne @t4_copy_pg
        inc zp_ptr1+1
        inc zp_ptr2+1
        dex
        bne @t4_copy_pg
@t4_copy_rem:
        ldx udp_recv_len
        beq @t4_copy_done
        ldy #0
@t4_copy_lo:
        lda (zp_ptr1),y
        sta (zp_ptr2),y
        iny
        dex
        bne @t4_copy_lo
@t4_copy_done:

        ; Set packet length
        lda udp_recv_len
        sta tp_packet_len
        lda udp_recv_len+1
        sta tp_packet_len+1

        ; Decrypt
        jsr transport_decrypt
        cmp #0
        bne @decrypt_fail

        ; Update peer endpoint if changed (roaming support)
        jsr endpoint_update

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
        ; print msg_recv_len (16-bit) bytes from msg_recv_ptr, raw
        lda msg_recv_ptr
        sta zp_ptr1
        lda msg_recv_ptr+1
        sta zp_ptr1+1
        lda #0
        sta zp_tmp1             ; no printable filter
        ldx msg_recv_len
        lda msg_recv_len+1
        jsr print_buf16
        lda #$0d
        jsr chrout
        rts
@t4_udp_bad:
        jsr display_payload
        rts

@decrypt_fail:
        ; Deliberately NOT a teardown, unlike @hs_fail above. This is one
        ; datagram that failed AEAD, not an abandoned session: the keys are
        ; still good and the peer is still there. Tearing down here would be
        ; a remotely triggerable session kill — under ip65 anything on the
        ; LAN can put a type-4 byte into udp_recv_buf, and WireGuard's own
        ; answer to an undecryptable packet is to discard it.
        ;
        ; It is not a leak either: the state is ACTIVE, so the 180 s expiry
        ; in timer_check already bounds a session whose keys have genuinely
        ; gone bad and which therefore decrypts nothing from here on.
        lda #<decrypt_fail_msg
        ldy #>decrypt_fail_msg
        jsr print_string
        rts

; =============================================================================
; session_reset - Reset session to IDLE state
;
; This is the canonical teardown primitive: the session is being dropped, so
; hand the backend's UDP socket back as well. Until #84 it had exactly one
; caller — the 180 s expiry in timer.s — which is how every other abandonment
; path came to hold its socket for the rest of the run. It is now reached from
; the handshake deadline and from @hs_fail as well.
;
; The UCI firmware never reclaims an abandoned connected UDP socket (issue
; #71; GideonZ/1541ultimate#808) — a dropped session that keeps its socket
; open leaks it until a wall power cycle. net_udp_close is safe when nothing
; is open (returns having done nothing).
;
; It is NOT a no-op on ip65 any more, which is the other half of #84: that
; backend now releases the listener slot it claimed in ip65's 4-entry table.
; Correct for both, because reopening is automatic in both: net_udp_close
; clears uci_socket_open and the next net_udp_send re-issues UDP_CONNECT;
; ip65's net_udp_send re-registers the listener the same way. The rekey path
; does NOT go through here (it re-handshakes via session_initiate, which keeps
; wg_state and the live socket), so closing on every session_reset never
; churns a socket that a rekey wants to reuse.
;
; Clobbers: A, X, Y (net_udp_close uses all three)
; =============================================================================
; Placed in APP_EXTRA (MAIN_AREA_HI), not APP_CODE, for the same reason
; session_stage_dest above is. The constraint in MAIN_AREA_LO is
; LIB_CHACHA20_POLY1305_CODE's align = $100 pin: APP_CODE growth that
; crosses it moves every later segment up a whole page, which the area's
; tail may not be able to absorb. Whether it can is a per-build fact the
; linker reports; it is not written down here.
.segment "APP_EXTRA"

; =============================================================================
; session_send_failed - net_udp_send refused the Type 1 initiation
;
; session_initiate used to ignore net_udp_send's carry and advance to HS_SENT
; regardless. Every backend failure — $8C SEND_TOO_LONG, $89 WAIT_TIMEOUT,
; $85 SEND_FAIL, $87 SHORT_WRITE, $8D OPEN_REFUSED — therefore left wg_state
; at HS_SENT with NOTHING ON THE WIRE, holding the socket, and do_handshake
; printed no status either way. That is a sharper case than the one #84
; describes: not "the peer never answered" but "we never asked, we knew we
; never asked, and we sat in HS_SENT holding the socket anyway". The 90 s
; deadline would eventually paper over it, but a failure that was observable
; at once should not take 90 s and a silent screen to surface.
;
; Reached by jmp, so its rts is session_initiate's rts.
;
; session_reset is the right teardown even when the state was ACTIVE (a rekey
; re-handshakes through session_initiate): a send the backend refused means
; the peer is not reachable at all, so a session still marked live is a
; fiction, and holding its socket is exactly what #84 is about. The previous
; behaviour destroyed that ACTIVE session too — HS_SENT makes
; session_handle_packet reject every Type 4 via @wrong_state — but kept the
; socket. This is strictly better, never worse.
;
; The numeric code is deliberately NOT printed. net_last_error is exported by
; the UCI backend and by neither ip65 nor this file's imports: src/net_abi.inc
; records that as a known §13.1 non-conformance, because ip65's driver has no
; error channel and referencing the symbol here would break the ip65 link. A
; host reading net_last_error over the monitor still gets the code on UCI.
;
; Output: C=1, always.
; Clobbers: A, X, Y
; =============================================================================
session_send_failed:
        jsr session_reset       ; IDLE, disarm, hand the resource back
        lda #<hs_send_err_msg
        ldy #>hs_send_err_msg
        jsr print_string
        sec
        rts

session_reset:
        lda #SESSION_IDLE
        sta wg_state
        sta hs_timer_armed      ; SESSION_IDLE = 0: also disarms the #84
                                ; handshake deadline, so a reset session
                                ; cannot be torn down twice
        jsr net_udp_close       ; hand the firmware UDP socket back (#71)
        rts

.segment "APP_CODE"

; =============================================================================
; endpoint_update - Update peer endpoint after successful decrypt
;
; Compares current source IP/port against stored peer IP/port.
; If different, updates the stored values (roaming support).
; Only called after successful AEAD decrypt (spoof protection).
;
; A roam moves the endpoint under a live socket, which under UCI is pinned to
; the OLD address by UDP_CONNECT — so the socket is handed back on the update
; path for the same reason config_load does it (issue #65). Reconnection is
; automatic on the next net_udp_send. Nothing is lost by closing: a socket
; pinned to the address the peer just left cannot receive from the new one
; either, so keeping it open only guarantees we talk to nobody.
;
; Note this update path is currently unreachable under the UCI backend: its
; net_poll synthesises udp_recv_src_ip from net_udp_dest_ip ("connected UDP:
; source IP == net_udp_dest_ip"), which session_stage_dest staged from
; wg_peer_ip, so the comparison below can never differ. Detecting a roam at
; all under UCI needs the backend to report a real source address. The close
; is here so the invariant — the endpoint never moves under a socket pinned to
; where it was — holds at every site that writes wg_peer_ip, rather than
; holding by accident at this one.
;
; Clobbers: A, X, Y (net_udp_close uses all three)
; =============================================================================
endpoint_update:
        ; Compare source IP (4 bytes)
        ldx #3
@cmp_ip:
        lda udp_recv_src_ip,x
        cmp wg_peer_ip,x
        bne @update
        dex
        bpl @cmp_ip

        ; IP matches, check port (2 bytes)
        lda udp_recv_src_port
        cmp wg_peer_port
        bne @update
        lda udp_recv_src_port+1
        cmp wg_peer_port+1
        bne @update

        ; All same, nothing to do
        rts

@update:
        ; Copy new IP
        ldx #3
@copy_ip:
        lda udp_recv_src_ip,x
        sta wg_peer_ip,x
        dex
        bpl @copy_ip

        ; Copy new port
        lda udp_recv_src_port
        sta wg_peer_port
        lda udp_recv_src_port+1
        sta wg_peer_port+1

        ; The endpoint moved — drop the socket pinned to where it was (#65).
        jsr net_udp_close
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

        lda #<(tp_packet+16)
        sta zp_ptr1
        lda #>(tp_packet+16)
        sta zp_ptr1+1
        lda #1
        sta zp_tmp1             ; replace non-printables with '.'
        ldx tp_payload_len
        lda tp_payload_len+1
        jsr print_buf16
        lda #$0d                ; newline
        jsr chrout
        rts

; The two routines that widened the message path — this one and
; udp_tunnel_parse in ip_build.s — live in APP_EXTRA (MAIN_AREA_HI) beside
; session_stage_dest, because MAIN_AREA_LO could not hold them when they
; were written. Same precedent, same reason.
.segment "APP_EXTRA"

; =============================================================================
; print_buf16 - Print a 16-bit-length byte run through chrout
;
; Input:  zp_ptr1 = source pointer
;         X       = length low byte
;         A       = length high byte
;         zp_tmp1 = 0 print raw, nonzero replace bytes outside $20-$7E by '.'
; Clobbers: A, X, Y, zp_ptr1 (advanced past the full pages), zp_tmp2
;
; Full pages first (Y wraps once per page, zp_ptr1+1 advances), then the
; low-byte remainder held in X. @emit touches only A: it relies on KERNAL
; CHROUT preserving X and Y (it does; the old 8-bit loop leaned on that too).
; =============================================================================
print_buf16:
        sta zp_tmp2             ; full pages remaining
        beq @rem
        ldy #0
@page:
        jsr @emit
        iny
        bne @page
        inc zp_ptr1+1
        dec zp_tmp2
        bne @page
@rem:
        cpx #0
        beq @done
        ldy #0
@lo:
        jsr @emit
        iny
        dex
        bne @lo
@done:
        rts
@emit:
        lda zp_tmp1
        beq @raw_load
        lda (zp_ptr1),y
        cmp #$20
        bcc @dot                ; < space
        cmp #$7f
        bcc @out                ; printable
@dot:
        lda #'.'
        bne @out                ; always ('.' is nonzero)
@raw_load:
        lda (zp_ptr1),y
@out:
        jsr chrout
        rts
