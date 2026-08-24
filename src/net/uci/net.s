; src/net/uci/net.s — UCI (Ultimate Command Interface) UDP networking backend
;
; Implements the net_abi.inc contract for WireGuard on top of the U64E
; host-visible command interface. Unlike the TCP-oriented UCI backend in
; c64-https, WireGuard uses exactly one peer at a time, so this backend
; uses UCI's connected-UDP socket model: UDP_CONNECT pins the socket to
; (wg_peer_ip, wg_peer_port), and all reads/writes flow through that
; single socket id.
;
; Lifecycle:
;   net_init       -> uci_abort + probe UCI_ID
;   net_dhcp       -> read firmware IP via GET_IPADDR
;   net_udp_listen -> latches wg_local_port only; the actual UDP_CONNECT
;                     is deferred until the first net_udp_send, at which
;                     point wg_peer_ip/wg_peer_port are known.
;   net_udp_send   -> on first call, issues UDP_CONNECT(peer_ip, peer_port)
;                     and stores uci_socket_id. Subsequent calls go straight
;                     to SOCKET_WRITE on the connected socket.
;   net_poll       -> issues SOCKET_READ; if a packet arrives, copies it
;                     into udp_recv_buf / udp_recv_len / udp_recv_src_ip
;                     and sets udp_recv_ready.
;   net_udp_recv_cb-> dead under UCI (callbacks are an ip65 concept); kept
;                     as an RTS stub so the ABI import resolves.
;   net_save_zp / net_restore_zp -> no-op RTS stubs (UCI primitives never
;                     touch the crypto ZP, so there is nothing to save).

.include "uci_regs.inc"
.include "uci_errors.inc"
.include "constants.inc"

; The tunnel MTU must fit inside one SOCKET_READ. The firmware truncates
; rather than splits, so exceeding this is silent data loss, not an error.
; Both symbols are equates, so this is checked at assembly time.
.assert (WG_MTU + WG_DATA_OVERHEAD) <= UCI_READ_CHUNK_MAX, error, "WG_MTU + overhead exceeds UCI_READ_CHUNK_MAX: inbound datagrams would be truncated silently"

; --- net_abi.inc contract ---
.export net_init
.export net_dhcp
.export net_poll
.export net_udp_listen
.export net_udp_send
.export net_udp_close
.export net_udp_recv_cb
.export net_print_ip
.export net_save_zp
.export net_restore_zp

; --- public data labels (defined in this module) ---
.export net_send_ptr
.export udp_send_len_local

; --- UCI-owned state exported for debug / future phases ---
.export net_local_ip
.export net_last_error
.export uci_socket_id
.export uci_socket_open

; --- primitives from uci_cmd.s ---
.import uci_abort
.import uci_wait_idle
.import uci_wait_not_busy
.import uci_begin_cmd
.import uci_put_byte
.import uci_push_wait
.import uci_check_err
.import uci_read_resp_bytes
.import uci_drain_resp
.import uci_drain_status
.import uci_ack
.import uci_resp_dst
.import uci_resp_max
.import uci_resp_count

; --- external data from src/wg/data.s ---
.import udp_recv_buf
.import udp_recv_len
.import udp_recv_ready
.import udp_recv_src_ip
.import udp_recv_src_port
.import wg_peer_ip
.import wg_peer_port
.import wg_local_port

.segment "UCI_CODE"

; =============================================================================
; net_init — initialize UCI networking
;
; 1. uci_abort to flush any in-flight state from a warm reset.
; 2. Probe UCI_ID; if not $C9, U64E command interface is not present
;    (stock C64, VICE, or firmware without UCI enabled) — fail with
;    UCI_ERR_NOT_PRESENT.
; 3. Zero adapter state (net_local_ip, uci_socket_id, uci_socket_open,
;    net_last_error) and return C=0.
; Clobbers: A, X
; =============================================================================
net_init:
        ; Probe UCI_ID FIRST. When UCI firmware is absent or disabled,
        ; every $DF1x register reads $FF, so uci_abort followed by any
        ; STATUS-polling helper would hang (DATA_AV / STATE bits always
        ; appear asserted). The probe must precede any state-machine
        ; touch so UCI_ERR_NOT_PRESENT stays reachable.
        lda UCI_ID
        uci_fence                   ; settle before comparing ID
        cmp #UCI_ID_VALUE
        beq @present

        lda #UCI_ERR_NOT_PRESENT
        sta net_last_error
        sec
        rts

@present:
        ; UCI present. uci_abort's intrinsic settle delay is sufficient
        ; preparation for the first command — we deliberately do NOT
        ; jsr uci_wait_idle here. Calling wait_idle after abort makes
        ; net_init wedge whenever STATE bit 5 is sticky from a prior
        ; run, which is exactly the firmware quirk that previously
        ; required cold power cycles between iterations. c64-https's
        ; UCI backend does the same: abort, then go.
        jsr uci_abort

        ; Close any socket still open from a previous run BEFORE we throw
        ; the handle away. Zeroing uci_socket_id/uci_socket_open without
        ; telling the firmware is what orphaned a live socket on every
        ; re-init, and resetting the C64 with a live firmware socket
        ; poisons the U64E's UCI lease path until a wall power cycle
        ; (GET_IPADDR then returns nothing while REST/menu stay healthy).
        ; That is issue #58: reproduced 2026-08-24 in 3 echo runs on a
        ; freshly power-cycled U64E, with no idle window anywhere.
        ;
        ; Guarded on the flag holding exactly $01: this is BSS, so on a
        ; cold boot it is whatever the RAM happened to contain, and we
        ; must not push a garbage socket id at the firmware. A close
        ; failure is deliberately non-fatal — net_init must still
        ; complete, and having tried to close beats never trying.
        lda uci_socket_open
        cmp #$01
        bne @ni_no_socket
        jsr net_udp_close
@ni_no_socket:

        lda #$00
        sta net_local_ip+0
        sta net_local_ip+1
        sta net_local_ip+2
        sta net_local_ip+3
        sta uci_socket_id
        sta uci_socket_open
        sta net_last_error
        clc
        rts

; =============================================================================
; net_dhcp — read the firmware-assigned IP via UCI GET_IPADDR
;
; The U64E firmware runs DHCP autonomously before the PRG is launched, so
; this routine READS the result via GET_IPADDR rather than performing
; DHCP itself. The 12-byte response is IP(4) + Netmask(4) + Gateway(4);
; we keep the first 4 bytes in net_local_ip.
;
; Clobbers: A, X, Y
; =============================================================================
net_dhcp:
        jsr uci_wait_idle
        bcc @dhcp_go            ; FPGA wedged — cannot issue the command
        rts                     ; (net_last_error = UCI_ERR_WAIT_TIMEOUT, C=1)
@dhcp_go:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_GET_IPADDR
        jsr uci_put_byte

        ; Interface index 0.
        lda #$00
        jsr uci_put_byte

        jsr uci_push_wait

        jsr uci_check_err
        bcc @no_err

        lda #UCI_ERR_CMD_FAILED
        sta net_last_error
        sec
        rts

@no_err:
        ; Read the 12-byte response into uci_ipaddr_resp.
        lda #<uci_ipaddr_resp
        sta uci_resp_dst
        lda #>uci_ipaddr_resp
        sta uci_resp_dst+1
        lda #12
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Copy the first 4 bytes (IP) into net_local_ip.
        ldx #3
@copy_ip:
        lda uci_ipaddr_resp,x
        sta net_local_ip,x
        dex
        bpl @copy_ip

        ; If all four bytes are zero the firmware has no lease yet.
        lda net_local_ip+0
        ora net_local_ip+1
        ora net_local_ip+2
        ora net_local_ip+3
        bne @have_ip

        lda #UCI_ERR_NO_IP
        sta net_last_error
        sec
        rts

@have_ip:
        clc
        rts

; =============================================================================
; net_udp_listen — latch wg_local_port into state.
;
; Entry: A = port_lo, X = port_hi
;
; UDP in UCI is connection-oriented: UDP_CONNECT pins the socket to a
; single peer (IP + port). Since wg_peer_ip / wg_peer_port aren't known
; until the first outbound send, we defer the actual UDP_CONNECT to
; net_udp_send. This routine only stores the local port for posterity
; (wg_local_port is also written by the caller, so this is belt-and-
; braces — see boot.s).
;
; Clobbers: A, X
; =============================================================================
net_udp_listen:
        sta wg_local_port+0
        stx wg_local_port+1
        clc
        rts

; =============================================================================
; net_udp_send — send a UDP packet to wg_peer_ip:wg_peer_port.
;
; Entry: A = buffer_lo, X = buffer_hi; udp_send_len_local = 16-bit length.
;        wg_peer_ip / wg_peer_port must already be populated.
;
; UDP adaptation vs. c64-https TCP backend:
;   - If the UCI socket isn't open yet (uci_socket_open == 0), issue
;     UDP_CONNECT(peer_ip, peer_port) and store the returned socket id.
;     The UDP_CONNECT parameter layout mirrors TCP_CONNECT but with the
;     UDP_CONNECT command ID and an IP-bytes payload instead of a host
;     string (the firmware accepts a dotted quad directly).
;   - Then SOCKET_WRITE the buffer on the connected socket. Because UDP
;     is datagram-oriented, we push the entire buffer in one command —
;     WireGuard packets are at most ~1420 bytes, well under UCI's
;     DATA_QUEUE_MAX of 800 per push... wait, under it we go in chunks
;     exactly as the TCP path does. WireGuard payloads up to MTU are
;     fine with a chunked inner loop.
;
; Output: C=0 on success, C=1 on failure (net_last_error populated).
; Clobbers: A, X, Y
; =============================================================================
net_udp_send:
        sta net_send_ptr+0
        stx net_send_ptr+1

        ; Open the UCI UDP socket on first send.
        lda uci_socket_open
        bne @socket_ready
        jsr uci_udp_connect
        bcc @connected
        ; Connect failed — net_last_error already set by uci_udp_connect.
        rts
@connected:
        lda #$01
        sta uci_socket_open

@socket_ready:
        ; Copy length into a decrementing 16-bit counter for the chunk loop.
        lda udp_send_len_local+0
        sta uci_send_rem+0
        lda udp_send_len_local+1
        sta uci_send_rem+1

        ; Zero-length: nothing to do.
        ora uci_send_rem+0
        bne @chunk_loop
        clc
        rts

@chunk_loop:
        ; this_chunk = min(uci_send_rem, UCI_DATA_QUEUE_MAX). WireGuard
        ; MTU packets are typically ~1420 bytes so the outer chunking
        ; will generally fire twice per datagram. That's benign: each
        ; SOCKET_WRITE on a connected UDP socket queues bytes into the
        ; same outgoing datagram boundary (firmware coalesces them).
        lda uci_send_rem+1
        cmp #>UCI_DATA_QUEUE_MAX
        bcc @use_rem
        bne @use_cap
        lda uci_send_rem+0
        cmp #<UCI_DATA_QUEUE_MAX
        bcc @use_rem
@use_cap:
        lda #<UCI_DATA_QUEUE_MAX
        sta uci_chunk_len+0
        sta uci_write_resp+0    ; pre-stash: SOCKET_WRITE returns no count,
        lda #>UCI_DATA_QUEUE_MAX ; so we treat the chunk we're about to push
        sta uci_chunk_len+1     ; as authoritatively "written" (UDP is atomic).
        sta uci_write_resp+1
        jmp @begin_chunk
@use_rem:
        lda uci_send_rem+0
        sta uci_chunk_len+0
        sta uci_write_resp+0    ; pre-stash (see @use_cap)
        lda uci_send_rem+1
        sta uci_chunk_len+1
        sta uci_write_resp+1

@begin_chunk:
        jsr uci_wait_idle
        bcc @bc_go              ; wedged before the chunk went out — bail with
        rts                     ; C=1 so the caller does not count it as sent
@bc_go:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_WRITE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; Patch the source base into the LDA abs,Y instruction.
        lda net_send_ptr+0
        sta @sb_load+1
        lda net_send_ptr+1
        sta @sb_load+2

        ldy #$00
@sb_loop:
        lda uci_chunk_len+0
        ora uci_chunk_len+1
        bne :+
        jmp @sb_push
:
@sb_load:
        lda $ffff,y             ; SMC: source base patched above
        sta UCI_CMD_DATA
        uci_fence         ; heavy fence: FIFO overruns at 48 MHz with standard fence
        iny
        bne @sb_nohi
        inc @sb_load+2
@sb_nohi:
        lda uci_chunk_len+0
        sec
        sbc #$01
        sta uci_chunk_len+0
        lda uci_chunk_len+1
        sbc #$00
        sta uci_chunk_len+1
        jmp @sb_loop

@sb_push:
        jsr uci_push_wait

        jsr uci_check_err
        bcc @sb_no_err

        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@sb_no_err:
        ; SOCKET_WRITE on U64E fw 3.14d does NOT put a written-count into
        ; RESP_DATA ($DF1E); only a status string into STATUS_DATA ($DF1F).
        ; The previous design spin-waited on RESP_DATA's DATA_AV bit, which
        ; never asserts for SOCKET_WRITE — by the time the spin-wait timed
        ; out, the firmware's TX window for the queued datagram had closed
        ; and the packet was silently discarded (C64 saw no error but no
        ; bytes reached the wire). Canonical pattern per c64-test-harness
        ; build_socket_write: drain STATUS then wait_idle. UDP is atomic —
        ; if uci_check_err didn't flag, the whole chunk went out.
        ;
        ; uci_write_resp was pre-stashed = uci_chunk_len at @use_cap/@use_rem,
        ; so the bookkeeping below still advances net_send_ptr / decrements
        ; uci_send_rem by the count we actually pushed.
        jsr uci_drain_status
        bcs @sb_wedged
        jsr uci_wait_idle
        bcs @sb_wedged
@sb_had_write:

        ; Advance source pointer by actual written count.
        lda net_send_ptr+0
        clc
        adc uci_write_resp+0
        sta net_send_ptr+0
        lda net_send_ptr+1
        adc uci_write_resp+1
        sta net_send_ptr+1

        ; Subtract written count from remaining.
        lda uci_send_rem+0
        sec
        sbc uci_write_resp+0
        sta uci_send_rem+0
        lda uci_send_rem+1
        sbc uci_write_resp+1
        sta uci_send_rem+1

        ; Bail on zero-written to avoid infinite loop.
        lda uci_write_resp+0
        ora uci_write_resp+1
        beq @sb_done

        lda uci_send_rem+0
        ora uci_send_rem+1
        beq @sb_done
        jmp @chunk_loop

@sb_done:
        clc
        rts

@sb_wedged:
        ; The FPGA stopped responding mid-send. net_last_error is already
        ; UCI_ERR_WAIT_TIMEOUT. Report failure rather than letting the
        ; caller believe the datagram went out — silent send success is
        ; exactly the failure mode issue #58 cost days to diagnose.
        sec
        rts

; =============================================================================
; uci_udp_connect — issue UDP_CONNECT(wg_peer_ip, wg_peer_port) to pin the
; socket to the WireGuard peer. Stores the returned socket id in
; uci_socket_id. On error, sets net_last_error = UCI_ERR_CONNECT_FAIL
; and returns C=1.
;
; Parameter layout (firmware expects the same hostname-string shape as
; TCP_CONNECT — raw IP bytes hang the firmware waiting for a null):
;   target=NETWORK, cmd=UDP_CONNECT,
;   port_lo, port_hi,
;   <ASCII dotted-decimal host bytes>, 0x00
; Response: 1 byte = socket_id.
;
; NOTE: wg_peer_port is stored big-endian (high byte at +0, low byte at +1)
; because disk_config.s::parse_decimal_u16 stores network byte order and
; config.s copies it verbatim. The firmware's UDP_CONNECT expects port_lo
; then port_hi (little-endian), so we swap here: send +1 first, then +0.
;
; Clobbers: A, X, Y
; =============================================================================
; net_udp_close — close the firmware UDP socket, if we hold one.
;
; The firmware hands back the same UDP handle every time (measured
; 2026-08-24: 24 consecutive UDP_CONNECTs all returned socket_id 10), so
; this is not about exhausting a pool. It is about not abandoning a LIVE
; socket: the U64E poisons its own lease path when the C64 is reset while
; one is still open, and only a wall power cycle clears that.
;
; Safe to call when nothing is open — returns C=0 having done nothing.
; A firmware-side failure is reported via C=1 but the local bookkeeping is
; cleared regardless: if we cannot close it we must at least not go on
; believing we still own it.
;
; Output: C=0 on success or nothing-to-do, C=1 if the command failed.
; Clobbers: A, X, Y
; =============================================================================
net_udp_close:
        lda uci_socket_open
        beq @uc_none                ; nothing open — nothing to do

        jsr uci_wait_idle
        bcc @uc_go
        ; Wedged before we could issue the close. Drop our bookkeeping so a
        ; later net_udp_send re-connects rather than writing to a handle we
        ; can no longer manage, and report the timeout.
        lda #$00
        sta uci_socket_id
        sta uci_socket_open
        sec
        rts
@uc_go:
        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_CLOSE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        jsr uci_push_wait

        jsr uci_check_err
        php                         ; keep the command's verdict across the
                                    ; drains, which have a carry of their own
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Clear local state whatever the firmware said.
        lda #$00
        sta uci_socket_id
        sta uci_socket_open

        plp
        bcc @uc_ok
        lda #UCI_ERR_CMD_FAILED
        sta net_last_error
        sec
        rts
@uc_ok:
        clc
        rts

@uc_none:
        clc
        rts

; =============================================================================
uci_udp_connect:
        jsr uci_wait_idle
        bcc @uc_go              ; wedged — no socket was opened, so leave
        rts                     ; uci_socket_open clear and report C=1
@uc_go:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_UDP_CONNECT
        jsr uci_put_byte

        ; Port (LE to firmware): wg_peer_port is BE so swap bytes on push.
        lda wg_peer_port+1      ; low byte of port (BE byte 1)
        jsr uci_put_byte
        lda wg_peer_port+0      ; high byte of port (BE byte 0)
        jsr uci_put_byte

        ; Peer IP as ASCII dotted-decimal. UCI firmware's CONNECT
        ; commands take a null-terminated hostname string; dotted-quad
        ; form is parsed directly (no DNS). Pushing raw IP bytes leaves
        ; the firmware waiting for a null byte forever.
        lda wg_peer_ip+0
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda wg_peer_ip+1
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda wg_peer_ip+2
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda wg_peer_ip+3
        jsr push_byte_as_ascii
        lda #$00
        jsr uci_put_byte              ; explicit null terminator

        jsr uci_push_wait

        jsr uci_check_err
        bcc @uc_no_err

        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@uc_no_err:
        ; 1-byte socket_id response.
        ;
        ; Pre-zero uci_socket_id so a short read leaves a known sentinel:
        ; uci_read_resp_bytes only writes the bytes it actually receives,
        ; so without this the "socket id" is whatever was there before.
        lda #$00
        sta uci_socket_id

        lda #<uci_socket_id
        sta uci_resp_dst
        lda #>uci_socket_id
        sta uci_resp_dst+1
        lda #$01
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; PHANTOM-SOCKET GUARD (c64-https issue #36; our issue #58).
        ; At least one U64E firmware path returns NO payload while clearing
        ; the error bit. Unvalidated, that left uci_socket_id = 0, the
        ; caller latched uci_socket_open = 1, and every subsequent
        ; SOCKET_WRITE went to socket 0 — which the firmware discards.
        ; The result is the #58 signature exactly: net_last_error = $00,
        ; carry clear, wg_state advancing, and nothing on the wire.
        ; Both halves are load-bearing: resp_count catches the short read,
        ; socket_id catches a returned-but-bogus id.
        lda uci_resp_count
        beq @uc_no_socket
        lda uci_socket_id
        beq @uc_no_socket

        clc
        rts

@uc_no_socket:
        lda #UCI_ERR_NO_SOCKET
        sta net_last_error
        sec
        rts

; =============================================================================
; net_poll — drive UDP receive via SOCKET_READ on the connected socket.
;
; If no socket is open yet, nothing to do (we haven't sent the first
; handshake packet yet). If udp_recv_ready is already set, the main loop
; hasn't consumed the previous packet — skip so we don't overwrite it.
;
; Otherwise: SOCKET_READ(sock, 1500). Response = actual_len (2 B) +
; payload. Copy payload into udp_recv_buf, store length into udp_recv_len,
; copy wg_peer_ip into udp_recv_src_ip (connected-UDP: the source is
; always the peer we're pinned to), set udp_recv_ready = 1.
;
; Output: C=0 when a packet was delivered, C=1 when nothing.
; Clobbers: A, X, Y
; =============================================================================
net_poll:
        lda uci_socket_open
        bne @sock_ok
        sec
        rts
@sock_ok:
        ; Don't clobber an un-consumed inbound packet.
        lda udp_recv_ready
        beq @do_poll
        sec
        rts

@do_poll:
        jsr uci_wait_not_busy
        bcc @dp_go              ; wedged — surface as a poll error (§13.2:
        rts                     ; C=1 is reserved for real backend errors)
@dp_go:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_READ
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; Same symbol the reply is validated against below — a literal here
        ; would let the request and the clamp drift apart silently.
        lda #<UCI_READ_CHUNK_MAX
        jsr uci_put_byte
        lda #>UCI_READ_CHUNK_MAX
        jsr uci_put_byte

        jsr uci_push_wait

        jsr uci_check_err
        bcc @no_err

        lda #UCI_ERR_READ_FAIL
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@no_err:
        ; First 2 bytes of response = actual_len (LE).
        uci_fence               ; give firmware time to stage response
        ldy #$00
@hdr_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @hdr_got
        jmp @hdr_none               ; long branch: fence too wide for BEQ
@hdr_got:
        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing header byte
        sta uci_read_hdr,y
        iny
        cpy #2
        bcs @hdr_got2
        jmp @hdr_loop               ; long branch: fence too wide for BCC
@hdr_got2:
        jmp @hdr_done

@hdr_none:
        ; <2 bytes returned: nothing to deliver.
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@hdr_done:
        ; VALIDATE THE LENGTH BEFORE IT BECOMES A COPY COUNT.
        ;
        ; The byte loop below stores through an SMC address that bumps its
        ; own high byte every time Y wraps, so this count is the ONLY thing
        ; bounding where it writes. udp_recv_buf holds 1500 bytes and
        ; udp_recv_len / udp_recv_src_ip / wg_peer_ip / wg_state sit
        ; immediately after it in data.s, so an over-long count does not
        ; merely overflow a buffer — it eats the network state that the
        ; receive path itself depends on, then keeps going into $D000 I/O.
        ;
        ; Not hypothetical. Observed mid-chat on a U64E (fw 3.14d): the VIC
        ; register block came back holding WireGuard packet bytes — $D018 =
        ; $A3 repointed the screen at $2800 and the charset at $0800 (a
        ; screenful of garbage over intact screen RAM), $D020 = $F2 turned
        ; the border red, and wg_state was zeroed, so the session died and
        ; keepalives stopped after exactly one inbound message.
        ;
        ; We asked for UCI_READ_CHUNK_MAX; a reply claiming more than that
        ; is a framing violation, and #46 records this firmware returning
        ; lengths that are not the byte count (0xFFFF for a 1500 request).
        ; DROP rather than trim: a length we do not believe means the
        ; response framing is not what we think it is, so the payload bytes
        ; behind it cannot be trusted either.
        lda uci_read_hdr+1
        cmp #>UCI_READ_CHUNK_MAX
        bcc @len_ok                 ; hi < 2 → certainly under the cap
        bne @len_bad                ; hi > 2 → certainly over it
        lda uci_read_hdr+0          ; hi == 2 → only exactly 512 is legal
        beq @len_ok

@len_bad:
        lda #UCI_ERR_LONG_READ
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@len_ok:
        ; actual_len → uci_poll_rem. If zero, no datagram this tick.
        lda uci_read_hdr+0
        sta uci_poll_rem+0
        sta udp_recv_len+0
        lda uci_read_hdr+1
        sta uci_poll_rem+1
        sta udp_recv_len+1
        ora uci_poll_rem+0
        bne @have_data
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@have_data:
        ; Copy uci_poll_rem bytes from UCI_RESP_DATA into udp_recv_buf.
        ; We use an SMC store so the copy can cross a page boundary
        ; without Y-register gymnastics: patch the target base to
        ; udp_recv_buf, bump the high byte each time Y wraps.
        lda #<udp_recv_buf
        sta @rb_store+1
        lda #>udp_recv_buf
        sta @rb_store+2
        ldy #$00

@byte_loop:
        lda uci_poll_rem+0
        ora uci_poll_rem+1
        bne :+
        jmp @done_data
:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @have_byte
        jmp @done_data

@have_byte:
        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing data byte
@rb_store:
        sta $ffff,y             ; SMC: base patched above
        iny
        bne @br_nohi
        inc @rb_store+2
@br_nohi:
        lda uci_poll_rem+0
        sec
        sbc #$01
        sta uci_poll_rem+0
        lda uci_poll_rem+1
        sbc #$00
        sta uci_poll_rem+1
        jmp @byte_loop

@done_data:
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Connected UDP: source IP == wg_peer_ip. Copy it directly.
        lda wg_peer_ip+0
        sta udp_recv_src_ip+0
        lda wg_peer_ip+1
        sta udp_recv_src_ip+1
        lda wg_peer_ip+2
        sta udp_recv_src_ip+2
        lda wg_peer_ip+3
        sta udp_recv_src_ip+3

        ; Source port == wg_peer_port (big-endian in the ip65 adapter's
        ; contract, but the WG upper layers only check for equality with
        ; the peer's stored port, so we mirror wg_peer_port's LE form
        ; straight across — udp_recv_src_port is not load-bearing under
        ; the connected-UDP model).
        lda wg_peer_port+0
        sta udp_recv_src_port+0
        lda wg_peer_port+1
        sta udp_recv_src_port+1

        lda #$01
        sta udp_recv_ready
        clc
        rts

; =============================================================================
; net_udp_recv_cb — ABI placeholder.
; Under ip65 this is a callback invoked during ip65_process. Under UCI we
; drive receive by polling SOCKET_READ, so this entry point is never
; called. Kept as an RTS stub so the .import in net_abi.inc resolves.
; =============================================================================
net_udp_recv_cb:
        rts

; =============================================================================
; net_print_ip — print net_local_ip as dotted decimal (PETSCII + CR).
;
; Matches the ip65 adapter's signature: takes no arguments, prints the
; local IP stored in this module's BSS. boot.s calls this directly.
; =============================================================================
net_print_ip:
        lda net_local_ip+0
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+1
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+2
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+3
        jsr @print_byte
        lda #$0d
        jsr chrout
        rts

@print_byte:
        sta @pb_val
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
        beq @pb_tens
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
        bcc @pb_ones
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
; push_byte_as_ascii — A = byte (0..255). Emits 1..3 ASCII decimal
; digit bytes to UCI_CMD_DATA (via uci_put_byte). Leading zeros
; suppressed unless the value is < 10 (single digit) or < 100 (two
; digits). Clobbers A, X, Y. Preserves nothing useful to the caller.
; =============================================================================
push_byte_as_ascii:
        sta @pa_val
        ldx #0
        sec
@pa_100:
        sbc #100
        bcc @pa_100d
        inx
        jmp @pa_100
@pa_100d:
        adc #100
        cpx #0
        beq @pa_tens
        pha
        txa
        ora #$30
        jsr uci_put_byte
        pla
@pa_tens:
        ldx #0
        sec
@pa_10:
        sbc #10
        bcc @pa_10d
        inx
        jmp @pa_10
@pa_10d:
        adc #10
        cpx #0
        bne @pa_t_out
        ldy @pa_val
        cpy #10
        bcc @pa_ones
@pa_t_out:
        pha
        txa
        ora #$30
        jsr uci_put_byte
        pla
@pa_ones:
        ora #$30
        jmp uci_put_byte            ; tail call
@pa_val: .byte 0

; =============================================================================
; net_save_zp / net_restore_zp — no-ops under UCI.
; UCI primitives use only absolute / abs,Y addressing — they never touch
; the crypto zero-page — so the save/restore dance from the ip65 backend
; is unnecessary here. Kept as RTS-only stubs so the ABI resolves.
; =============================================================================
net_save_zp:
        rts

net_restore_zp:
        rts

; =============================================================================
; BSS — UCI adapter state
; =============================================================================
.segment "UCI_BSS"

net_send_ptr:       .res 2          ; caller-visible: buffer pointer
udp_send_len_local: .res 2          ; caller-visible: 16-bit length

net_local_ip:       .res 4          ; local IPv4 (filled by net_dhcp)
net_last_error:     .res 1          ; 0 = OK, nonzero = UCI_ERR_*

uci_ipaddr_resp:    .res 12         ; scratch for GET_IPADDR response

; --- UDP socket state ---
uci_socket_id:      .res 1          ; socket_id returned by UDP_CONNECT
uci_socket_open:    .res 1          ; 0 = not yet opened, 1 = connected

; --- send state ---
uci_send_rem:       .res 2          ; 16-bit bytes remaining to send
uci_chunk_len:      .res 2          ; 16-bit bytes remaining in current chunk
uci_write_resp:     .res 2          ; written_lo/hi from SOCKET_WRITE

; --- receive state ---
uci_read_hdr:       .res 2          ; actual_len_lo/hi from SOCKET_READ
uci_poll_rem:       .res 2          ; bytes left to copy from response
