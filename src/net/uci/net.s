; src/net/uci/net.s — UCI (Ultimate Command Interface) UDP networking backend
;
; Implements the net_abi.inc contract for WireGuard on top of the U64E
; host-visible command interface. Unlike the TCP-oriented UCI backend in
; c64-https, WireGuard uses exactly one peer at a time, so this backend
; uses UCI's connected-UDP socket model: UDP_CONNECT pins the socket to
; (net_udp_dest_ip, net_udp_dest_port), and all reads/writes flow through that
; single socket id.
;
; Lifecycle:
;   net_init       -> uci_abort + probe UCI_ID
;   net_dhcp_acquire       -> read firmware IP via GET_IPADDR
;   net_udp_listen -> latches wg_local_port only; the actual UDP_CONNECT
;                     is deferred until the first net_udp_send, at which
;                     point net_udp_dest_ip/net_udp_dest_port are known.
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
; Compared against the §13 capability this backend publishes in
; net_caps.inc (NET_UDP_RECV_MAX). That guarantee can never exceed what the
; adapter actually requests per read (UCI_READ_CHUNK_MAX); both are
; equates, so this is checked at assembly time.
.assert NET_UDP_RECV_MAX <= UCI_READ_CHUNK_MAX, error, "net_caps.inc NET_UDP_RECV_MAX exceeds UCI_READ_CHUNK_MAX: the adapter never reads that much"
.assert (WG_MTU + WG_DATA_OVERHEAD) <= NET_UDP_RECV_MAX, error, "WG_MTU + overhead exceeds NET_UDP_RECV_MAX: inbound datagrams would be truncated silently"

; SEND side — the mirror of the assert above, and it was missing. On a
; connected UDP socket each SOCKET_WRITE emits its OWN datagram, so a frame
; larger than one write does not chunk, it FRAGMENTS: measured on hardware
; 2026-08-27, a 1452-byte send left the C64 as 800 + 652 bytes, two torn
; datagrams, with carry=0 and net_last_error=$00. The peer drops both and
; nothing reports it: the written count the firmware returns after the write
; is the full chunk length — the queue really did accept every byte; it is
; the datagram framing that was torn — so the bookkeeping reads as full
; success.
.assert NET_UDP_SEND_MAX <= UCI_DATA_QUEUE_MAX, error, "net_caps.inc NET_UDP_SEND_MAX exceeds UCI_DATA_QUEUE_MAX: the adapter would fragment a datagram it promised to send whole"
.assert (WG_MTU + WG_DATA_OVERHEAD) <= NET_UDP_SEND_MAX, error, "WG_MTU + overhead exceeds NET_UDP_SEND_MAX: outbound datagrams would be silently fragmented into multiple UDP packets"

.ifdef UCI_CHUNKED_WRITE
; Chunked send (issue #70): a $16 part carries at most 895 - 7 bytes. Offering
; 889+ would be truncated at the command-buffer fencepost with a clean status,
; the 893-style silent loss all over again — so the cap is pinned here too.
.assert UCI_CHUNK_PART_MAX <= 888, error, "UCI_CHUNK_PART_MAX above 888: a $16 part would be truncated at the 895-byte command buffer"
.assert NET_UDP_SEND_MAX <= 1472, error, "NET_UDP_SEND_MAX above 1472: the firmware refuses a larger announced total (82,PARAMETER(S) OUT OF RANGE)"
.export uci_send_part
.endif

; --- net_abi.inc contract ---
.export net_init
.export net_dhcp_acquire
.export net_poll
.export net_udp_listen
.export net_udp_send
.export net_udp_close
.export net_udp_recv_cb
.export net_print_ip

; --- public data labels (defined in this module) ---
.export net_udp_send_ptr
.export net_udp_send_len

; --- UCI-owned state exported for debug / future phases ---
.export net_local_ip
.export net_last_error
.export uci_socket_id
.export uci_socket_open
; Exported for diagnostics: the raw SOCKET_READ response header, before the
; §13.3 length validation consumes it. c64-lib-contract#139 records the UDP
; header on an oversized datagram as UNMEASURED — this makes it observable
; from the host so the $8A row's mechanism note can be written from data.
.export uci_read_hdr

; --- primitives from uci_cmd.s ---
.import uci_abort
.import uci_wait_idle
.import uci_wait_reply_staged
.import uci_tod_start
.import uci_wait_not_busy
.import uci_begin_cmd
.import uci_put_byte
.import uci_push_wait
.import uci_check_err
.import uci_read_resp_bytes
.import uci_drain_resp
.import uci_drain_status
.import uci_status_seen
.import uci_status_leading_code
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
.import net_udp_dest_ip
.import net_udp_dest_port
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
        jsr uci_tod_start           ; bounded waits need a RUNNING TOD (uci_cmd.s, #58)
        bcc @tod_ok
        rts                         ; C=1, net_last_error = NET_ERR_TIMEBASE_STOPPED
@tod_ok:
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
        ; Guarded on the flag holding exactly $01 so we never push a
        ; garbage socket id at the firmware.
        ;
        ; The guard's old rationale — "this is BSS, so on a cold boot it is
        ; whatever the RAM happened to contain" — is not true on the load
        ; path, and was the #80 family of stale comment: UCI_BSS lands in
        ; MAIN_AREA_LO, which the cfg declares `file = %O, fill = yes,
        ; fillval = $00`, so the area is padded into the PRG and LOAD stamps
        ; zeros over it. src/boot.s says so outright. After a LOAD this flag
        ; is always $00 and this branch cannot be taken.
        ;
        ; The guard still earns its place, for the case it is actually
        ; reachable in: an in-run re-init ('I' pressed a second time) with a
        ; socket genuinely open from the first. A close failure is
        ; deliberately non-fatal — net_init must still complete, and having
        ; tried to close beats never trying.
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
; net_dhcp_acquire — read the firmware-assigned IP via UCI GET_IPADDR
;
; The U64E firmware runs DHCP autonomously before the PRG is launched, so
; this routine READS the result via GET_IPADDR rather than performing
; DHCP itself. The 12-byte response is IP(4) + Netmask(4) + Gateway(4);
; we keep the first 4 bytes in net_local_ip.
;
; Clobbers: A, X, Y
; =============================================================================
net_dhcp_acquire:
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
; single peer (IP + port). Since net_udp_dest_ip / net_udp_dest_port aren't known
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
; net_udp_send — send a UDP packet to net_udp_dest_ip:net_udp_dest_port.
;
; Entry: A = buffer_lo, X = buffer_hi; net_udp_send_len = 16-bit length.
;        net_udp_dest_ip / net_udp_dest_port must already be populated.
;
; UDP adaptation vs. c64-https TCP backend:
;   - If the UCI socket isn't open yet (uci_socket_open == 0), issue
;     UDP_CONNECT(peer_ip, peer_port) and store the returned socket id.
;     The UDP_CONNECT parameter layout mirrors TCP_CONNECT but with the
;     UDP_CONNECT command ID and an IP-bytes payload instead of a host
;     string (the firmware accepts a dotted quad directly).
;   - Then SOCKET_WRITE the whole buffer in ONE command. Each write on a
;     connected UDP socket is one datagram on the wire, so there is no
;     chunking: a length above NET_UDP_SEND_MAX (892, the ceiling this
;     adapter guarantees in net_caps.inc, §13.3) is refused up front with
;     UCI_ERR_SEND_TOO_LONG before any register is touched.
;   - After the push, read the 2-byte written count the firmware returns
;     on RESP_DATA and compare it to the requested length; a mismatch is
;     UCI_ERR_SHORT_WRITE, a $FFFF (lwip -1) is UCI_ERR_SEND_FAIL.
;
; UCI_CHUNKED_WRITE=1 (issue #70, GideonZ/1541ultimate#807 spike firmware):
;   - NET_UDP_SEND_MAX is 1472 and EVERY datagram — the 148-byte Type-1
;     included — goes out as NET_CMD_WRITE_SOCKET_CHUNK ($16) parts of at
;     most UCI_CHUNK_PART_MAX (888) bytes, one uci_send_part call each.
;     One code path; and on a firmware without $16 (stock 3.15) the first
;     send fails loudly with UCI_ERR_CMD_UNKNOWN ($8E) instead of the
;     tunnel half-working up to 892 bytes.
;   - The completing part is judged exactly like a SOCKET_WRITE (2-byte
;     count == total). A non-completing part is judged on the STATUS line
;     only (absent or "00" = queued); see uci_send_part for how its reply,
;     which the bench did not characterise, is captured for the host.
;
; Output: C=0 on success, C=1 on failure (net_last_error populated).
;   $8C SEND_TOO_LONG  — refused pre-push (nothing on the wire)
;   $89 WAIT_TIMEOUT   — a bounded wait expired (state unknown)
;   $85 SEND_FAIL      — error bit set, written count $FFFF, or (chunked)
;                        a part refused on the STATUS line (81/82)
;   $87 SHORT_WRITE    — no count / count != length (datagram not whole)
;   $8E CMD_UNKNOWN    — (chunked only) STATUS said `21,UNKNOWN COMMAND`:
;                        this firmware has no $16, rebuild without the flag
; Clobbers: A, X, Y
; =============================================================================
net_udp_send:
        sta net_udp_send_ptr+0
        stx net_udp_send_ptr+1

        ; Latch the 16-bit length. It is both the push count for the loop
        ; below and the value the firmware's returned count is checked
        ; against afterwards, so keep two copies: uci_chunk_len is consumed
        ; by the loop, uci_send_rem survives it.
        lda net_udp_send_len+0
        sta uci_send_rem+0
        sta uci_chunk_len+0
        lda net_udp_send_len+1
        sta uci_send_rem+1
        sta uci_chunk_len+1

        ; Zero-length: nothing to do.
        ora uci_send_rem+0
        bne @check_fits
        clc
        rts

@check_fits:
        ; PRE-CHECK (c64-lib-contract#142): REFUSE anything that will not fit
        ; in ONE SOCKET_WRITE, BEFORE any UCI register is touched. (Under
        ; UCI_CHUNKED_WRITE the same compare is against 1472, the largest
        ; total the firmware's $16 accepts — issue #70.)
        ;
        ; This loop used to chunk, on the belief recorded here that "each
        ; SOCKET_WRITE on a connected UDP socket queues bytes into the same
        ; outgoing datagram boundary (firmware coalesces them)". THAT IS
        ; FALSE. NetworkTarget::write_socket does one lwip_send per command
        ; on a SOCK_DGRAM socket, so every chunk is its own DATAGRAM.
        ; Measured 2026-08-27: a 1452-byte send left the C64 as 800 + 652 —
        ; two torn datagrams the peer drops — with carry=0 and
        ; net_last_error=$00, because the old code pre-stashed the chunk
        ; length as the "written" count so the bookkeeping read as success.
        ; The handshake (148 B) hid it for months; only payloads over ~768 B
        ; fragmented.
        ;
        ; For a datagram socket, splitting is never correct. Refuse loudly
        ; instead: the §13.2 contract says C=1 with net_last_error set, and a
        ; caller that respects WG_MTU can never reach this (the link-time
        ; assert in this file guarantees WG_MTU + overhead <= the cap).
        ; Ordering matters: nothing has been pushed yet, so the state machine
        ; is untouched and no drain/ack is owed on this exit.
        lda uci_send_rem+1
        cmp #>NET_UDP_SEND_MAX
        bcc @fits                   ; hi < cap_hi -> fits
        bne @too_big                ; hi > cap_hi -> cannot fit
        lda uci_send_rem+0
        cmp #<NET_UDP_SEND_MAX
        beq @fits                   ; exactly the cap -> fits
        bcc @fits                   ; below the cap -> fits
@too_big:
        lda #UCI_ERR_SEND_TOO_LONG
        sta net_last_error
        sec
        rts

@fits:
        ; Open the UCI UDP socket on first send. Deliberately AFTER the length
        ; pre-check above: UDP_CONNECT is itself a UCI transaction, and #142
        ; requires an over-long send to fail before any register is touched.
        lda uci_socket_open
        bne @fits_len
        jsr uci_udp_connect
        bcc @connected
        ; Connect failed — net_last_error already set by uci_udp_connect.
        rts
@connected:
        lda #$01
        sta uci_socket_open

@fits_len:
.ifdef UCI_CHUNKED_WRITE
        ; -------------------------------------------------------------------
        ; CHUNKED SEND (issue #70). Walk the datagram in parts; uci_send_part
        ; advances uci_chunk_off by the part it pushed and returns C=1 with
        ; net_last_error set (queues drained and acked) on any failure. The
        ; loop ends when the offset reaches the total, i.e. after the
        ; completing part, whose count check is inside uci_send_part.
        ; -------------------------------------------------------------------
        lda #$00
        sta uci_chunk_off+0
        sta uci_chunk_off+1
@part_loop:
        jsr uci_send_part
        bcs @part_fail
        lda uci_chunk_off+0
        cmp uci_send_rem+0
        bne @part_loop
        lda uci_chunk_off+1
        cmp uci_send_rem+1
        bne @part_loop
        clc
        rts
@part_fail:
        rts                     ; C=1, net_last_error already named the cause

; =============================================================================
; uci_send_part — push ONE NET_CMD_WRITE_SOCKET_CHUNK ($16) part of the
; datagram at net_udp_send_ptr / uci_send_rem, starting at uci_chunk_off.
;
; Exported (it lands in labels.txt) so a build can be PROVEN chunked by the
; label's presence, and so hardware tests can call it directly.
;
; Part length = min(total - offset, UCI_CHUNK_PART_MAX). Command layout:
;   $03 $16 socket_id off_lo off_hi total_lo total_hi <part bytes>
; The offset is advanced BEFORE the push so the completing-part test after
; the push is "offset == total".
;
; Reply semantics. COMPLETING part: the firmware emits the datagram and
; answers with the 2-byte total on RESP_DATA — judged exactly as the plain
; SOCKET_WRITE path judges its count. NON-COMPLETING part: the spec says no
; RESP_DATA reply, and that is the one thing the #807 bench did not verify,
; so this routine MEASURES instead of assuming: once CMD_BUSY has cleared,
; if DATA_AV is already up the first two bytes are captured into
; uci_write_resp exactly as for a completing part, else uci_resp_count is
; set to 0 — WITHOUT paying uci_read_resp_bytes' 1 s per-part wait budget.
; Either way, after any part the host can read uci_resp_count,
; uci_write_resp and uci_status_buf/uci_status_seen and see what the
; firmware actually said. The verdict for a non-completing part comes from
; the STATUS line alone: no line, or a leading "00", means queued; any
; other code (81 overrun, 82 total out of range, 21 unknown command) is a
; refusal and the datagram will never leave whole.
;
; Output: C=0 part accepted, uci_chunk_off advanced.
;         C=1 failure, net_last_error set ($85 / $87 / $89 / $8E as
;         documented at net_udp_send); the transaction has been acked.
; Clobbers: A, X, Y
; =============================================================================
uci_send_part:
        jsr uci_wait_idle
        bcc @sp_go              ; wedged before the part went out — bail
        rts                     ; with C=1 so the caller does not count it as sent
@sp_go:
        ; uci_chunk_len = total - offset, clamped to UCI_CHUNK_PART_MAX.
        lda uci_send_rem+0
        sec
        sbc uci_chunk_off+0
        sta uci_chunk_len+0
        lda uci_send_rem+1
        sbc uci_chunk_off+1
        sta uci_chunk_len+1
        cmp #>UCI_CHUNK_PART_MAX
        bcc @sp_len_ok          ; hi < cap_hi -> fits in one part
        bne @sp_clamp           ; hi > cap_hi -> clamp
        lda uci_chunk_len+0
        cmp #<UCI_CHUNK_PART_MAX
        bcc @sp_len_ok
        beq @sp_len_ok          ; exactly the cap -> fits
@sp_clamp:
        lda #<UCI_CHUNK_PART_MAX
        sta uci_chunk_len+0
        lda #>UCI_CHUNK_PART_MAX
        sta uci_chunk_len+1
@sp_len_ok:
        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd
        lda #UCI_CMD_SOCKET_WRITE_CHUNK
        jsr uci_put_byte
        lda uci_socket_id
        jsr uci_put_byte
        lda uci_chunk_off+0     ; offset of this part
        jsr uci_put_byte
        lda uci_chunk_off+1
        jsr uci_put_byte
        lda uci_send_rem+0      ; announced datagram total
        jsr uci_put_byte
        lda uci_send_rem+1
        jsr uci_put_byte

        ; Patch source = buffer + offset into the LDA abs,Y below.
        lda net_udp_send_ptr+0
        clc
        adc uci_chunk_off+0
        sta @sp_load+1
        lda net_udp_send_ptr+1
        adc uci_chunk_off+1
        sta @sp_load+2

        ; Advance the offset past this part now (the loop below consumes
        ; uci_chunk_len, and the completing test after the push needs it).
        lda uci_chunk_off+0
        clc
        adc uci_chunk_len+0
        sta uci_chunk_off+0
        lda uci_chunk_off+1
        adc uci_chunk_len+1
        sta uci_chunk_off+1

        ; Push uci_chunk_len bytes — same 16-bit SMC loop as the plain path.
        ldy #$00
@sp_loop:
        lda uci_chunk_len+0
        ora uci_chunk_len+1
        bne :+
        jmp @sp_push
:
@sp_load:
        lda $ffff,y             ; SMC: source base patched above
        sta UCI_CMD_DATA
        uci_fence               ; heavy fence: FIFO overruns at 48 MHz otherwise
        iny
        bne @sp_nohi
        inc @sp_load+2
@sp_nohi:
        lda uci_chunk_len+0
        sec
        sbc #$01
        sta uci_chunk_len+0
        lda uci_chunk_len+1
        sbc #$00
        sta uci_chunk_len+1
        jmp @sp_loop

@sp_push:
        jsr uci_push_wait
        bcc :+
        rts                     ; PUSH never went CMD_BUSY=0 — $89 already set
:
        jsr uci_check_err
        bcc @sp_no_err
        ; Hardware ERROR bit. Drain and ack first (the accept is mandatory,
        ; see the plain path), then name the cause from the STATUS line.
        jsr uci_drain_resp
        bcc :+
        rts
:
        jsr uci_drain_status
        bcc :+
        rts
:
        jsr uci_ack
        lda #UCI_ERR_SEND_FAIL
        jmp @sp_status_err

@sp_no_err:
        ; Completing part iff the advanced offset equals the total.
        lda uci_chunk_off+0
        cmp uci_send_rem+0
        bne @sp_more
        lda uci_chunk_off+1
        cmp uci_send_rem+1
        bne @sp_more

        ; COMPLETING PART: read the 2-byte total count (bounded), drain,
        ; ack, then judge — the same sequence and verdicts as the plain path.
        lda #$00
        sta uci_write_resp+0
        sta uci_write_resp+1
        lda #<uci_write_resp
        sta uci_resp_dst
        lda #>uci_write_resp
        sta uci_resp_dst+1
        lda #$02
        sta uci_resp_max
        jsr uci_read_resp_bytes
        jsr uci_drain_resp
        bcc :+
        rts
:
        jsr uci_drain_status
        bcc :+
        rts
:
        jsr uci_ack
        lda uci_resp_count
        cmp #$02
        bcc @sp_short           ; no count arrived within the budget
        lda uci_write_resp+0
        and uci_write_resp+1
        cmp #$FF
        beq @sp_send_fail       ; $FFFF = lwip_send returned -1
        lda uci_write_resp+0
        cmp uci_send_rem+0
        bne @sp_short
        lda uci_write_resp+1
        cmp uci_send_rem+1
        bne @sp_short
        clc
        rts
@sp_short:
        lda #UCI_ERR_SHORT_WRITE
        jmp @sp_status_err
@sp_send_fail:
        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        sec
        rts

@sp_more:
        ; NON-COMPLETING PART — capture whatever reply is already staged
        ; (see the header), never wait for one.
        lda #$00
        sta uci_resp_count
        sta uci_write_resp+0
        sta uci_write_resp+1
        lda UCI_STATUS
        uci_fence
        and #UCI_STAT_DATA_AV
        beq @sp_no_resp
        lda #<uci_write_resp
        sta uci_resp_dst
        lda #>uci_write_resp
        sta uci_resp_dst+1
        lda #$02
        sta uci_resp_max
        jsr uci_read_resp_bytes
@sp_no_resp:
        jsr uci_drain_resp
        bcc :+
        rts
:
        jsr uci_drain_status
        bcc :+
        rts
:
        jsr uci_ack
        lda uci_status_seen
        cmp #$02
        bcc @sp_queued          ; no status line: the documented "no reply"
        jsr uci_status_leading_code
        beq @sp_queued          ; "00,..." — part queued
        lda #UCI_ERR_SEND_FAIL  ; 81/82 refusal (21 is renamed below)
        jmp @sp_status_err
@sp_queued:
        clc
        rts

@sp_status_err:
        ; A = the generic code for this failure. If the captured STATUS line
        ; says `21,UNKNOWN COMMAND` the real cause is a firmware without $16,
        ; which deserves its own name ($8E) so a wrong-firmware build is
        ; diagnosed from the screen, not from a protocol trace.
        sta net_last_error
        lda uci_status_seen
        cmp #$02
        bcc @sp_se_done
        jsr uci_status_leading_code
        cmp #21
        bne @sp_se_done
        lda #UCI_ERR_CMD_UNKNOWN
        sta net_last_error
@sp_se_done:
        sec
        rts
.else
        jsr uci_wait_idle
        bcc @bc_go              ; wedged before the datagram went out — bail
        rts                     ; with C=1 so the caller does not count it as sent
@bc_go:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_WRITE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; Patch the source base into the LDA abs,Y instruction.
        lda net_udp_send_ptr+0
        sta @sb_load+1
        lda net_udp_send_ptr+1
        sta @sb_load+2

        ; Push uci_chunk_len bytes. 16-bit countdown (§13.3) — Y is only the
        ; page offset, and the SMC base advances when it wraps.
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
        bcs @sb_wedged          ; PUSH never went CMD_BUSY=0 — timeout is set

        jsr uci_check_err
        bcc @sb_no_err

        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        jsr uci_drain_resp
        bcs @sb_wedged
        jsr uci_drain_status
        bcs @sb_wedged
        jsr uci_ack
        sec
        rts

@sb_no_err:
        ; READ THE WRITTEN COUNT. An earlier revision of this comment claimed
        ; that SOCKET_WRITE "does NOT put a written-count into RESP_DATA;
        ; only a status string into STATUS_DATA". That is FALSE. The
        ; firmware's NetworkTarget::write_socket (GideonZ/1541ultimate,
        ; software/io/network/network_target.cc) ends with
        ;
        ;     data_message.message[0] = (ret & 0xFF);
        ;     data_message.message[1] = (ret & 0xFF00) >> 8;
        ;     data_message.length = 2;
        ;
        ; where ret is the lwip_send return: the byte count actually handed
        ; to the stack, or -1 ($FFFF) on a socket error. It is on the
        ; RESP_DATA channel ($DF1E), exactly like the 2-byte SOCKET_READ
        ; header, and c64-https's net_tcp_send has read it there all along.
        ; What the earlier revision observed was an UNBOUNDED spin on
        ; DATA_AV at the wrong moment; the bounded read below is the
        ; correct shape.
        ;
        ; Register sequence (each access fenced, §13.6; wait TOD-bounded,
        ; §13.4 — uci_read_resp_bytes gives up after
        ; UCI_RESP_WAIT_BUDGET_TENTHS and reports what it got in
        ; uci_resp_count rather than wedging):
        ;   [STATUS $DF1C] poll DATA_AV -> [RESP_DATA $DF1E] read lo
        ;   [STATUS $DF1C] poll DATA_AV -> [RESP_DATA $DF1E] read hi
        ;   uci_drain_resp   : any further RESP_DATA bytes, NEXT_DATA each
        ;   uci_drain_status : STATUS_DATA $DF1F line, NEXT_DATA each
        ;   uci_ack          : final NEXT_DATA — the accept that returns
        ;                      the state machine to idle
        ;
        ; The accept is mandatory on every transaction, sends included:
        ; without it the next PUSH_CMD is silently dropped (`else
        ; error_busy <= '1'`), and because command-byte writes are not
        ; state-gated a dropped command still advances the command pointer,
        ; so every later command lands in a mis-positioned buffer — one
        ; missing accept corrupts the interface from then on. Hence the
        ; drains complete BEFORE the count is judged, whatever it says.
        lda #$00                ; pre-clear so a short read is detectable
        sta uci_write_resp+0
        sta uci_write_resp+1
        lda #<uci_write_resp
        sta uci_resp_dst
        lda #>uci_write_resp
        sta uci_resp_dst+1
        lda #$02
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        bcs @sb_wedged
        jsr uci_drain_status
        bcs @sb_wedged
        jsr uci_ack

        ; No 2-byte count arrived within the budget: the reply framing is not
        ; what we think it is, so we cannot claim the datagram went out whole.
        lda uci_resp_count
        cmp #$02
        bcc @sb_short

        ; $FFFF = ret of -1: lwip_send failed on the firmware side (the
        ; status line carries the errno; we drained it). Not a short write —
        ; nothing was sent.
        lda uci_write_resp+0
        and uci_write_resp+1
        cmp #$FF
        beq @sb_send_fail

        ; written == requested? Full 16-bit compare (§13.3). Anything else —
        ; fewer (the firmware's 893-byte truncation lands here: it drops the
        ; last byte with a clean status and reports 892) or an impossible
        ; more — means the datagram on the wire is not the one the caller
        ; built, and for UDP that datagram is already gone; no retry
        ; bookkeeping applies.
        lda uci_write_resp+0
        cmp uci_send_rem+0
        bne @sb_short
        lda uci_write_resp+1
        cmp uci_send_rem+1
        bne @sb_short

        clc
        rts

@sb_short:
        lda #UCI_ERR_SHORT_WRITE
        sta net_last_error
        sec
        rts

@sb_send_fail:
        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        sec
        rts

@sb_wedged:
        ; The FPGA stopped responding mid-send. net_last_error is already
        ; UCI_ERR_WAIT_TIMEOUT. Report failure rather than letting the
        ; caller believe the datagram went out — silent send success is
        ; exactly the failure mode issue #58 cost days to diagnose.
        sec
        rts
.endif ; UCI_CHUNKED_WRITE

; =============================================================================
; uci_udp_connect — issue UDP_CONNECT(net_udp_dest_ip, net_udp_dest_port) to pin the
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
; NOTE: net_udp_dest_port is stored big-endian (high byte at +0, low byte at +1)
; because disk_config.s::parse_decimal_u16 stores network byte order and
; config.s copies it verbatim. The firmware's UDP_CONNECT expects port_lo
; then port_hi (little-endian), so we swap here: send +1 first, then +0.
;
; Clobbers: A, X, Y
; =============================================================================
; net_udp_close — close the firmware UDP socket, if we hold one.
;
; There IS a pool, and it is finite: lwIP's MEMP_NUM_UDP_PCB = 8
; (GideonZ/1541ultimate#808). The 2026-08-24 observation that 24 consecutive
; UDP_CONNECTs all returned socket_id 10 did NOT prove "the firmware hands back
; the same handle regardless" — that run CLOSED between every open, so slot 10
; was simply freed and immediately re-leased each time. It says nothing about
; how many sockets can be open AT ONCE. Leaking opens (never reaching this
; close) walks through the 8 slots and then the 9th UDP_CONNECT is refused with
; `85,ERROR OPENING SOCKET` on the STATUS channel — the refusal that
; uci_udp_connect now surfaces as UCI_ERR_OPEN_REFUSED (issue #72).
;
; So closing matters for two reasons: to return the slot to that 8-deep pool,
; and to not abandon a LIVE socket — the U64E poisons its own lease path when
; the C64 is reset while one is still open, and only a wall power cycle clears
; that.
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

        ; Port (LE to firmware): net_udp_dest_port is BE so swap bytes on push.
        lda net_udp_dest_port+1      ; low byte of port (BE byte 1)
        jsr uci_put_byte
        lda net_udp_dest_port+0      ; high byte of port (BE byte 0)
        jsr uci_put_byte

        ; Peer IP as ASCII dotted-decimal. UCI firmware's CONNECT
        ; commands take a null-terminated hostname string; dotted-quad
        ; form is parsed directly (no DNS). Pushing raw IP bytes leaves
        ; the firmware waiting for a null byte forever.
        lda net_udp_dest_ip+0
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda net_udp_dest_ip+1
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda net_udp_dest_ip+2
        jsr push_byte_as_ascii
        lda #'.'
        jsr uci_put_byte
        lda net_udp_dest_ip+3
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
        ; REFUSAL FAST-PATH (issue #72; GideonZ/1541ultimate#808).
        ; A refused open — the firmware's UDP-PCB pool (MEMP_NUM_UDP_PCB=8) is
        ; exhausted — does NOT set the hardware ERROR bit (so uci_check_err
        ; passed above) and returns NO socket_id on RESP_DATA. It reports the
        ; refusal ONLY on the $DF1F STATUS channel as `85,ERROR OPENING SOCKET`.
        ;
        ; uci_push_wait has already waited for CMD_BUSY=0, so if a status line
        ; exists it is posted by now. Drain it FIRST: if a non-"00" refusal code
        ; is present we can name it (UCI_ERR_OPEN_REFUSED) and bail immediately,
        ; instead of sitting out uci_read_resp_bytes' full wall-clock budget
        ; waiting for a socket_id byte that will never arrive and then surfacing
        ; a generic $88. Draining status here does not disturb the socket_id on
        ; the separate RESP_DATA queue (no NEXT_DATA flush happens until the
        ; final uci_ack), so the success path below reads it unchanged.
        jsr uci_drain_status
        lda uci_status_seen
        cmp #$02                    ; need at least the two "NN" digits
        bcc @uc_read_id             ; no status posted -> not a refusal (wedge):
                                    ; fall through to the socket_id read, whose
                                    ; short-read guard yields $88 as before.
        jsr uci_status_leading_code ; A = decimal NN; Z=1 iff "00" (OK)
        beq @uc_read_id             ; "00,..." = success status -> read the id
        ; Non-zero code: the firmware refused the open. The captured line in
        ; uci_status_buf carries the decimal code (e.g. 85).
        lda #UCI_ERR_OPEN_REFUSED
        sta net_last_error
        jsr uci_drain_resp          ; nothing expected on RESP, but keep the
        jsr uci_ack                 ; queues clean for the next command
        sec
        rts

@uc_read_id:
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
; Otherwise: SOCKET_READ(sock, UCI_READ_CHUNK_MAX). Response = actual_len (2 B) +
; payload. Copy payload into udp_recv_buf, store length into udp_recv_len,
; copy net_udp_dest_ip into udp_recv_src_ip (connected-UDP: the source is
; always the peer we're pinned to), set udp_recv_ready = 1.
;
; Output: C=1 ONLY on a backend error, with net_last_error set. C=0 carries
; NO "data arrived" meaning — per c64-lib-contract SPEC §13.2, "no data" is
; never an error, and availability is observed via udp_recv_ready. The main
; loop already reads udp_recv_ready and ignores the carry, so this is a
; producing-side change only.
; Clobbers: A, X, Y
; =============================================================================
net_poll:
        lda uci_socket_open
        bne @sock_ok
        clc                     ; no socket yet — nothing to do, not an error
        rts
@sock_ok:
        ; Don't clobber an un-consumed inbound packet.
        lda udp_recv_ready
        beq @do_poll
        clc                     ; caller has not drained the last one yet
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
@poll_fail:
        ; Shared error exit: net_last_error already holds the code. Also the
        ; landing for a $89 from uci_wait_reply_staged below.
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@no_err:
        ; uci_push_wait returned on CMD_BUSY clearing, i.e. the firmware's
        ; HANDSHAKE_ACCEPT_COMMAND. The reply is NOT staged yet: STATE is
        ; still 01 until copy_result() has memcpy'd up to 895 bytes and
        ; written VALIDATE_LAST/MORE (command_intf.cc). Sampling DATA_AV in
        ; that window reads "no data" and abandons a block the firmware then
        ; presents to nobody. Wait for STATE to leave 01 (bounded, $89).
        ; Same window as the continuation race fixed at @block_end; this one
        ; is straight-line firmware code (no task switch) and has not been
        ; observed, so this is the defensive half of the same fix.
        jsr uci_wait_reply_staged
        bcs @poll_fail
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
        ; <2 bytes returned: nothing to deliver. §13.2 — no datagram is not
        ; an error, so C=0 with udp_recv_ready left clear.
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        clc
        rts

@hdr_done:
        ; VALIDATE THE LENGTH BEFORE IT BECOMES A COPY COUNT.
        ;
        ; The byte loop below stores through an SMC address that bumps its
        ; own high byte every time Y wraps, so this count is the ONLY thing
        ; bounding where it writes. udp_recv_buf holds 1500 bytes and
        ; udp_recv_len / udp_recv_src_ip / net_udp_dest_ip / wg_state sit
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
        ; $FFFF FIRST: it is the firmware's NO-DATA sentinel, not a length.
        ; Measured 2026-08-24 — with nothing pending, every SOCKET_READ on a
        ; UDP socket returns header $FFFF. Without this test that sentinel
        ; falls through the over-claim check below (since $FFFF > 512) and
        ; every idle poll reports UCI_ERR_LONG_READ, which is exactly why
        ; docs/hardware-validation-runbook.md recorded $8A as "firing
        ; routinely during healthy sessions". It was never an over-claim;
        ; it was an empty read misfiled as a framing violation. c64-https
        ; sees the same $FFFF sentinel on TCP (their #140).
        ;
        ; §13.2: no data is NEVER an error, so this exits C=0 with
        ; udp_recv_ready left clear and net_last_error untouched.
        lda uci_read_hdr+0
        and uci_read_hdr+1
        cmp #$FF
        beq @hdr_none               ; $FFFF — nothing pending, not an error

        ; Full 16-bit "header > cap" comparison. The previous form ended
        ; `lda uci_read_hdr+0 / beq @len_ok`, i.e. it accepted the equal-high-
        ; byte case ONLY when the low byte was zero. That is correct for a cap
        ; of 512 ($0200) and silently wrong for any other shape: measured
        ; 2026-08-26 with the cap at 893 ($037D), datagrams of 800/861/893 —
        ; all legal, all delivered by the firmware — were DROPPED by this
        ; check and reported as $8A, because their high byte was $03 and their
        ; low byte was not zero. A guard whose correctness depends on the
        ; low byte of an unrelated constant is a trap for the next person to
        ; retune the cap, which is exactly what happened.
        lda uci_read_hdr+1
        cmp #>UCI_READ_CHUNK_MAX
        bcc @len_ok                 ; hi < cap_hi → certainly under
        bne @len_bad                ; hi > cap_hi → certainly over
        lda uci_read_hdr+0          ; hi == cap_hi → decide on the low byte
        cmp #<UCI_READ_CHUNK_MAX
        beq @len_ok                 ; exactly the cap → legal
        bcc @len_ok                 ; below the cap → legal

@len_bad:
        ; A genuine over-claim: a length above what we requested that is NOT
        ; the $FFFF sentinel. On a datagram socket the excess is discarded by
        ; the firmware (GideonZ/1541ultimate#802), so the datagram is
        ; unrecoverable and dropping it is the only correct action —
        ; contrast c64-https, which caps on a stream because the remainder
        ; stays queued.

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
        ; Zero-length read: no datagram. §13.2 — not an error.
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        clc
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
        jmp @block_end          ; block exhausted — may be Data More

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

@block_end:
        ; DATA_AV cleared. Under fw 3.15 a reply larger than one response
        ; block is handed over in pieces via the command interface's Data
        ; More mechanism (GideonZ/1541ultimate#806), so this is the end of a
        ; BLOCK, not necessarily the end of the reply. The 2-byte header is
        ; the TOTAL payload length, so uci_poll_rem still holds what is
        ; outstanding; concatenating the blocks yields exactly the datagram a
        ; single large queue would have delivered.
        ;
        ; STATE (bits 5..4) says which, and it has FOUR values, not two
        ; (command_protocol.vhd "Protocol"; UCI_STATE_* in uci_regs.inc):
        ;
        ;   $30 Data More    block drained, next one announced -> DATA_ACC,
        ;                    then back to @byte_loop to drain it
        ;   $10 Command Busy the firmware is still producing the next block
        ;                    -> WAIT (bounded) for STATE to change, then back
        ;                    to @byte_loop; $89 on expiry
        ;   $20 Data Last    reply ended with bytes outstanding: short reply,
        ;   $00 Idle         take what we got rather than hang
        ;
        ; WHY $10 IS REACHABLE HERE: our DATA_ACC on a Data More block makes
        ; the FPGA drop STATE to 01 at once (vhdl: `state(1) <= '0'` with
        ; state(0) still 1) and post CMD_DATA_ACCEPTED to the firmware; the
        ; next block is then staged by an ISR, a queue post, a FreeRTOS task
        ; switch and a memcpy (command_intf.cc run_task -> get_more_data ->
        ; copy_result -> HANDSHAKE_VALIDATE_*). DATA_AV is 0 throughout, so
        ; @byte_loop lands here with bytes outstanding and STATE == 01. The
        ; previous code had only a two-way test — "$30, else Data Last" —
        ; and a wait on CMD_BUSY (bit 0), which is already clear once a
        ; command has been accepted and never rises for a continuation. At
        ; 1 MHz ~17 ms of fences hid the window; at 48 MHz it was ~340 us
        ; and every 1452/1472-byte datagram was truncated to block 1 (893
        ; bytes) with the header's full length — measured 2026-09-01 on the
        ; U64E (fw 3.15 + #807 spike, REU=0). Issue #70 / PR #112.
        lda uci_poll_rem+0
        ora uci_poll_rem+1
        beq @done_data          ; nothing outstanding — reply complete

        lda UCI_STATUS
        uci_fence               ; settle before testing STATE
        and #UCI_STAT_STATE
        cmp #UCI_STATE_DATA_MORE
        beq @block_more
        cmp #UCI_STATE_BUSY
        bne @done_data          ; Data Last / Idle with bytes outstanding:
                                ; short reply, take what we got

        ; Command Busy: the continuation is being staged. Bounded wait for
        ; STATE to leave 01, then resume draining into the SAME buffer
        ; (Y/SMC intact). The wait clobbers only A.
        jsr uci_wait_reply_staged
        bcs @block_wedged
        jmp @byte_loop

@block_more:
        ; Accept the drained block. state(0)=1 tells the Ultimate to produce
        ; the next one; @byte_loop will see DATA_AV clear and come back here
        ; in Command Busy to wait for it.
        jsr uci_ack
        jmp @byte_loop

@block_wedged:
        ; $89 already in net_last_error. The datagram is unrecoverable (a
        ; datagram socket has no "rest of it" to fetch later), so this is an
        ; error exit, NOT a delivery of the partial buffer.
        jmp @poll_fail

@done_data:
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Connected UDP: source IP == net_udp_dest_ip. Copy it directly.
        lda net_udp_dest_ip+0
        sta udp_recv_src_ip+0
        lda net_udp_dest_ip+1
        sta udp_recv_src_ip+1
        lda net_udp_dest_ip+2
        sta udp_recv_src_ip+2
        lda net_udp_dest_ip+3
        sta udp_recv_src_ip+3

        ; Source port == net_udp_dest_port (big-endian in the ip65 adapter's
        ; contract, but the WG upper layers only check for equality with
        ; the peer's stored port, so we mirror net_udp_dest_port's LE form
        ; straight across — udp_recv_src_port is not load-bearing under
        ; the connected-UDP model).
        lda net_udp_dest_port+0
        sta udp_recv_src_port+0
        lda net_udp_dest_port+1
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

net_udp_send_ptr:       .res 2          ; caller-visible: buffer pointer
net_udp_send_len: .res 2          ; caller-visible: 16-bit length

net_local_ip:       .res 4          ; local IPv4 (filled by net_dhcp_acquire)
net_last_error:     .res 1          ; 0 = OK, nonzero = UCI_ERR_*

uci_ipaddr_resp:    .res 12         ; scratch for GET_IPADDR response

; --- UDP socket state ---
uci_socket_id:      .res 1          ; socket_id returned by UDP_CONNECT
uci_socket_open:    .res 1          ; 0 = not yet opened, 1 = connected

; --- send state ---
uci_send_rem:       .res 2          ; 16-bit requested length (kept for the count check)
uci_chunk_len:      .res 2          ; 16-bit push countdown (consumed by the loop)
uci_write_resp:     .res 2          ; written_lo/hi from SOCKET_WRITE (RESP_DATA)
.ifdef UCI_CHUNKED_WRITE
uci_chunk_off:      .res 2          ; offset of the NEXT $16 part (issue #70)
.endif

; --- receive state ---
uci_read_hdr:       .res 2          ; actual_len_lo/hi from SOCKET_READ
uci_poll_rem:       .res 2          ; bytes left to copy from response
