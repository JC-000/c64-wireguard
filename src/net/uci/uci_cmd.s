; src/net/uci/uci_cmd.s — shared UCI command primitives
;
; Plain JSR-callable helpers for driving the Ultimate 64 Elite's host-visible
; Command Interface at $DF1B-$DF1F. None of these touch zero page — everything
; is absolute or abs,Y — so the crypto / ip65 ZP save/restore dance is not
; required around calls. Matches the hand-emitted pattern in
; c64-test-harness/scripts/test_uci_tcp_echo.py.
;
; Exported primitives (see the per-routine headers for calling conventions):
;
;   uci_abort          — flush the state machine (write ABORT + short delay)
;   uci_wait_idle      — spin until (STATE==0 AND CMD_BUSY==0); TOD-bounded
;   uci_wait_not_busy  — spin until CMD_BUSY==0; TOD-bounded
;   uci_begin_cmd      — A = target id; writes target to UCI_CMD_DATA
;   uci_put_byte       — A = parameter byte; writes to UCI_CMD_DATA
;   uci_push_wait      — writes PUSH_CMD, then uci_wait_not_busy
;   uci_check_err      — returns C=1 if error bit set, clears it; C=0 otherwise
;   uci_read_resp_bytes— drain DATA_AV bytes to caller-provided buffer
;                        (caller fills uci_resp_dst/uci_resp_max beforehand;
;                         uci_resp_count returned; Y = count)
;   uci_drain_resp     — drain remaining DATA_AV bytes to nowhere, ACKing each;
;                        TOD-bounded (5 s wall-clock), C=1 on expiry
;   uci_drain_status   — drain remaining STAT_AV bytes to nowhere, ACKing each;
;                        TOD-bounded (5 s wall-clock), C=1 on expiry
;   uci_ack            — single NEXT_DATA pulse
;
; Phase 2 only needs enough machinery for GET_IPADDR (12-byte response,
; one interface-index parameter). Later phases will extend as needed.

.include "uci_regs.inc"
.include "uci_errors.inc"

; net_last_error lives in net.s's BSS — we set it on wait timeout.
.import net_last_error

.export uci_abort
.export uci_wait_idle
.export uci_tod_start
.export uci_wait_not_busy
.export uci_begin_cmd
.export uci_put_byte
.export uci_push_wait
.export uci_check_err
.export uci_read_resp_bytes
.export uci_drain_resp
.export uci_drain_status
.export uci_status_buf
.export uci_status_len
.export uci_status_seen
.export uci_status_leading_code
.export uci_ack

.export uci_resp_dst
.export uci_resp_max
.export uci_resp_count

.segment "UCI_CODE"

; =============================================================================
; uci_abort — force the UCI FIFO back to idle
; Writes ABORT to UCI_CONTROL, then burns ~$20 iterations as a settle delay.
; Clobbers: A, X
; =============================================================================
uci_abort:
        lda #UCI_CTRL_ABORT
        sta UCI_CONTROL
        uci_fence
        ldx #$20
@spin:
        dex
        bne @spin
        rts

; =============================================================================
; uci_wait_idle — spin until STATE==0 AND CMD_BUSY==0, with a wall-clock cap
; UCI_STAT_STATE ($30) covers the state field; CMD_BUSY ($01) is bit 0.
; ORing them (MASK $31) and looping while nonzero gives "fully idle".
;
; Issue #45 — the historical unbounded spin turned an FPGA wedge into a hung
; machine: Bug #3 leaves the UCI STATE bit set for ~161 s after SOCKET_WRITE,
; and client.reboot() does not clear it (only a physical power-cycle does), so
; the C64 sat in this loop forever.
;
; The budget uses CIA1 TOD (CIA_TOD_TENTHS, 10 Hz) — the only clock that runs
; at the same wall-clock rate regardless of CPU turbo. Cycle-counted budgets
; do NOT work here: each fence is ~38 us of FPGA wall time but only a few CPU
; cycles at 48 MHz, so a budget tuned at 1 MHz collapses at turbo. c64-https
; shipped cycle-counted budgets on feat/net-drain-abi and broke turbo DHCP for
; exactly this reason — see its "bounded timeouts must use wall-clock time"
; design note. The jiffy clock is useless here (interrupts are masked).
;
; CIA TOD read protocol: reading HOUR latches all four registers atomically;
; reading TENTHS unlatches them. We only need TENTHS, but we latch+unlatch
; properly so we don't strand TOD for other readers.
;
; Ported from c64-https src/net/uci/uci_cmd.s (its issue #37).
;
; Output: C=0 on idle, C=1 on timeout (net_last_error = UCI_ERR_WAIT_TIMEOUT).
; Clobbers: A
; =============================================================================
CIA_TOD_TENTHS = $DC08
CIA_TOD_HOUR   = $DC0B
UCI_WAIT_IDLE_BUDGET_TENTHS = 50      ; 5 seconds at 10 Hz
; Per-byte response wait. Shorter than the command budget above because it
; sits inside a loop that runs once per response byte: the old counted
; version intended ~150 ms, and 1 s of real time is generous for a LAN
; round-trip while keeping a full short-read bail well inside any sane
; caller timeout.
UCI_RESP_WAIT_BUDGET_TENTHS = 10      ; 1 second at 10 Hz

; =============================================================================
; uci_tod_start — start the CIA1 TOD clock the bounded waits depend on, and
; VERIFY that it ticks.
;
; MEASURED 2026-08-27 (U64E fw 3.15, IRQ-hooked sampling on a hung machine):
; the TOD is STOPPED after reset — 207 samples over 3 s all read 00:00:00.0
; (hour byte $91, the untouched reset value). A CIA TOD does not run until
; its TENTHS register is written; writing HOURS halts it. Nothing in this
; adapter (or the c64-https original it was ported from) ever wrote it, so
; every "TOD-bounded" wait below was unbounded on real hardware: a firmware
; command that never completed hung the C64 forever, and no live run ever
; produced UCI_ERR_WAIT_TIMEOUT. Starting the clock from an IRQ hook made a
; hung net_udp_send expire within 2 s and return C=1 (issue #58).
;
; Contract (c64-lib-contract#145, SPEC v0.13.0 §13.4): start, then spin until
; the tenths digit changes; the spin is paced by uci_fence so its bound is
; wall-clock-ish regardless of CPU clock (4096 fences ~ 0.35 s at 64 MHz,
; >= 2 tenths; ~22 s at 1 MHz but only on the failure path). If it never
; changes: C=1, net_last_error = NET_ERR_TIMEBASE_STOPPED ($01).
;
; CRB bit 7 must be 0 so the writes address the clock, not the alarm. Write
; order: HOURS/MIN/SEC first, TENTHS last. Every reset stops the TOD again,
; so this belongs in net_init, not a one-off. Clobbers: A
; =============================================================================
CIA_TOD_MIN    = $DC09
CIA_TOD_SEC    = $DC0A
CIA_CRB        = $DC0F
uci_tod_start:
        lda CIA_CRB
        and #$7F                    ; bit 7 = 0: TOD writes set the clock
        sta CIA_CRB
        lda #$00
        sta CIA_TOD_HOUR            ; halts the clock (already halted)
        sta CIA_TOD_MIN
        sta CIA_TOD_SEC
        sta CIA_TOD_TENTHS          ; starts the clock
        ; Verify: latch (HOUR), read TENTHS, then spin until it changes.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @ts_first
        lda #$00
        sta @ts_lo
        lda #$10
        sta @ts_hi                  ; 16 * 256 = 4096 fenced polls
@ts_loop:
        uci_fence
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @ts_first
        bne @ts_ok
        dec @ts_lo
        bne @ts_loop
        dec @ts_hi
        bne @ts_loop
        lda #NET_ERR_TIMEBASE_STOPPED
        sta net_last_error
        sec
        rts
@ts_ok:
        clc
        rts
@ts_first: .byte 0
@ts_lo:    .byte 0
@ts_hi:    .byte 0

uci_wait_idle:
        ; Sample initial TENTHS for delta-tracking. Latch via HOUR,
        ; release via TENTHS. The HOUR value itself is not used.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @wi_last_tenths
        lda #$00
        sta @wi_elapsed
@wi_loop:
        lda UCI_STATUS
        uci_fence                   ; settle read before testing bits
        and #(UCI_STAT_STATE | UCI_STAT_CMD_BUSY)   ; $31
        beq @idle_done

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @wi_last_tenths
        beq @wi_loop                ; no change — keep spinning
        sta @wi_last_tenths
        inc @wi_elapsed
        lda @wi_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @wi_loop                ; under budget — continue
        ; Budget exhausted.
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@idle_done:
        clc
        rts
@wi_last_tenths: .byte 0
@wi_elapsed:     .byte 0

; =============================================================================
; uci_wait_not_busy — spin until CMD_BUSY==0 (ignore STATE), wall-clock bounded
; Called after writing PUSH_CMD while response data / status is still being
; prepared — STATE is allowed to be nonzero here.
;
; Same rationale, clock and budget as uci_wait_idle above; see that header for
; why the bound must be wall-clock rather than cycle-counted.
;
; Output: C=0 on not-busy, C=1 on timeout (net_last_error = UCI_ERR_WAIT_TIMEOUT).
; Clobbers: A
; =============================================================================
uci_wait_not_busy:
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @wnb_last_tenths
        lda #$00
        sta @wnb_elapsed
@wnb_loop:
        lda UCI_STATUS
        uci_fence                   ; settle read before testing bits
        and #UCI_STAT_CMD_BUSY
        beq @wnb_done

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @wnb_last_tenths
        beq @wnb_loop_long          ; no change — keep spinning
        sta @wnb_last_tenths
        inc @wnb_elapsed
        lda @wnb_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @wnb_loop_long          ; under budget — continue
        ; Budget exhausted.
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@wnb_loop_long:
        jmp @wnb_loop               ; long branch: fence too wide for BCC/BEQ
@wnb_done:
        clc
        rts
@wnb_last_tenths: .byte 0
@wnb_elapsed:     .byte 0

; =============================================================================
; uci_begin_cmd — entry: A = target id (e.g. UCI_TARGET_NETWORK = $03)
; Writes A to UCI_CMD_DATA. Caller continues pushing the command byte and
; any parameters (via uci_put_byte or direct STA UCI_CMD_DATA).
; Clobbers: none beyond A
; =============================================================================
uci_begin_cmd:
        sta UCI_CMD_DATA
        uci_fence
        rts

; =============================================================================
; uci_put_byte — entry: A = parameter byte
; Thin wrapper around STA UCI_CMD_DATA for readability at call sites.
; Clobbers: none beyond A
; =============================================================================
uci_put_byte:
        sta UCI_CMD_DATA
        uci_fence
        rts

; =============================================================================
; uci_push_wait — commit pushed bytes as a command, then wait for CMD_BUSY=0
;
; At turbo speeds the FPGA may not have latched PUSH_CMD by the time the
; CPU starts polling CMD_BUSY. A plain uci_fence after the write gives only
; ≈ 2 µs at 48 MHz — insufficient for the FPGA to assert CMD_BUSY. We add
; a short delay loop ($40 iterations ≈ 6 µs at 48 MHz, ≈ 300 µs at 1 MHz)
; before polling, ensuring CMD_BUSY has been asserted by the time we check.
;
; Clobbers: A, X
; =============================================================================
uci_push_wait:
        lda #UCI_CTRL_PUSH_CMD
        sta UCI_CONTROL
        uci_fence
        ; Fixed settle delay — at turbo speeds the FPGA may not have
        ; latched PUSH_CMD and asserted CMD_BUSY by the time the CPU
        ; starts polling. $FF iterations × 5 cycles ≈ 27 µs at 48 MHz,
        ; ≈ 1.3 ms at 1 MHz — sufficient for the FPGA to latch the
        ; command without using inline NOP fences that bloat code size.
        ldx #$FF
@pw_settle:
        dex
        bne @pw_settle
        jmp uci_wait_not_busy

; =============================================================================
; uci_check_err — test UCI_STAT_ERROR
; Output: C=1 if error bit was set (error has been cleared); C=0 otherwise.
; Clobbers: A
; =============================================================================
uci_check_err:
        lda UCI_STATUS
        uci_fence                   ; settle before testing error bit
        and #UCI_STAT_ERROR
        bne @has_err
        clc
        rts
@has_err:
        ; clear the latched error
        lda #UCI_CTRL_CLR_ERR
        sta UCI_CONTROL
        uci_fence
        sec
        rts

; =============================================================================
; uci_ack — single NEXT_DATA pulse (advance response/status FIFO by one byte)
; Clobbers: A
; =============================================================================
uci_ack:
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        uci_fence
        rts

; =============================================================================
; uci_read_resp_bytes — drain DATA_AV bytes into caller-provided buffer.
;
; Caller must set:
;   uci_resp_dst (2 bytes) — destination pointer
;   uci_resp_max (1 byte)  — max bytes to store
;
; On return:
;   uci_resp_count         — actual bytes stored
;   Y                      — same value (convenience for callers)
;
; Reads while DATA_AV is set AND count < max, storing each byte via a
; self-modified `STA uci_resp_dst,Y`, ACKing each byte with NEXT_DATA.
; If DATA_AV clears before max is reached, returns early. If max is reached
; while DATA_AV is still set, the excess is left for uci_drain_resp.
;
; Clobbers: A, Y. X preserved.
; =============================================================================
uci_read_resp_bytes:
        ; Patch the dst pointer into the STA abs,Y instruction below.
        ; At turbo speeds the firmware may not have staged response data
        ; by the time the CPU reaches this point (e.g. TCP_CONNECT takes
        ; a full network round-trip), so we wait for DATA_AV per byte.
        ;
        ; This wait WAS a 16-bit iteration counter documented as "~150 ms
        ; at 48 MHz, ~110 cycles per iteration". That figure was implicitly
        ; calibrated against UCI_FENCE_INNER = 100; raising the fence to
        ; 217 for the C64 Ultimate floor (§13.6) more than doubled every
        ; iteration, stretching the full spin to ~7.5 s at 48 MHz — and at
        ; 1 MHz it is minutes. Measured consequence on 2026-08-24: once the
        ; firmware stopped answering UDP_CONNECT, net_udp_send stopped
        ; failing in ~3.5 s and started blowing past a 10 s caller timeout
        ; instead, with net_last_error still $00 because nothing here was
        ; bounded in wall-clock terms.
        ;
        ; That is exactly the failure §13.4 forbids counted budgets to
        ; prevent: the budget is a function of clock speed and fence width,
        ; not of time. Same CIA1-TOD treatment as the other waits, with its
        ; own shorter budget since this one sits in a per-byte loop.
        lda uci_resp_dst
        sta @rd_store+1
        lda uci_resp_dst+1
        sta @rd_store+2
        ldy #$00
@rd_loop:
        cpy uci_resp_max
        bcc @rd_not_max
        jmp @rd_done
@rd_not_max:
        ; Wall-clock wait for DATA_AV, UCI_RESP_WAIT_BUDGET_TENTHS.
        ; X is preserved across the wait.
        stx @rd_save_x
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @rd_last_tenths
        lda #$00
        sta @rd_elapsed
@rd_wait:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @rd_have

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @rd_last_tenths
        beq @rd_wait_long           ; no change — keep waiting
        sta @rd_last_tenths
        inc @rd_elapsed
        lda @rd_elapsed
        cmp #UCI_RESP_WAIT_BUDGET_TENTHS
        bcc @rd_wait_long           ; under budget — continue
@rd_timeout:
        ; Budget exhausted: DATA_AV never appeared — bail with a partial
        ; read. uci_resp_count reports how many bytes actually landed, and
        ; callers that care (uci_udp_connect's phantom-socket guard) check
        ; it. Deliberately NOT an error here: a short response is a normal
        ; outcome for some commands.
        ldx @rd_save_x
        jmp @rd_done
@rd_wait_long:
        jmp @rd_wait                ; long branch: fence too wide for BEQ/BCC
@rd_have:
        ldx @rd_save_x
        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing/looping
@rd_store:
        sta $FFFF,y             ; SMC: dst low/high patched above
        iny
        jmp @rd_loop
@rd_done:
        sty uci_resp_count
        rts
@rd_save_x:      .byte 0
@rd_last_tenths: .byte 0
@rd_elapsed:     .byte 0

; =============================================================================
; uci_drain_resp — ACK remaining response bytes until DATA_AV is clear.
; Used after uci_read_resp_bytes when the caller only wanted the first N bytes
; of a potentially longer response. Reads UCI_RESP_DATA (forcing the FIFO to
; advance on firmwares that require a read), then pulses NEXT_DATA.
; Clobbers: A
; =============================================================================
uci_drain_resp:
        ; The historical `ldx #$FF` iteration cap is gone: c64-lib-contract
        ; §13.4 forbids counted budgets for device waits, because the cost
        ; per iteration scales with turbo (a cap tuned at 1 MHz is a
        ; different wall-clock budget at 48 MHz). It also consumed X, where
        ; this version clobbers A only. Same 5 s TOD budget as uci_wait_idle.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @drn_last_tenths
        lda #$00
        sta @drn_elapsed
@drn_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @drn_have
        clc
        rts
@drn_have:
        lda UCI_RESP_DATA
        uci_fence                   ; settle before NEXT_DATA write
        ; NO PER-BYTE ACK. Reading UCI_RESP_DATA / UCI_STATUS_DATA advances the
        ; queue pointer by itself (command_protocol.vhd: io_read on the
        ; response/status slots does `pointer <= pointer + 1`). Control bit 1
        ; is DATA_ACC, and the Register API v1.1 §2.4.1 is explicit about what
        ; it costs:
        ;
        ;   "Writing to this bit also causes the transfer of the data/status
        ;    queues to be aborted and reset. Thus, the data response and status
        ;    response queues will be empty after writing this bit."
        ;
        ; So a per-byte pulse FLUSHES both queues — it read one byte and threw
        ; the rest away, which is why our status capture only ever saw the
        ; first character of the status line.
        ;
        ; The canonical order (Gideon's own uci_wedge.s, and every wrapper in
        ; the reference C lib) is: push command -> read response -> read status
        ; -> ONE DATA_ACC. Nothing is written to $DF1C between the two reads.
        ; That single accept is load-bearing, not optional: it releases the
        ; state machine back to idle, and without it the next PUSH_CMD lands on
        ; `else error_busy <= '1'` and is silently dropped. net_poll and the
        ; other command paths issue it once per exit via uci_ack.

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @drn_last_tenths
        beq @drn_loop_long          ; no change — keep draining
        sta @drn_last_tenths
        inc @drn_elapsed
        lda @drn_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @drn_loop_long          ; under budget — continue
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@drn_loop_long:
        jmp @drn_loop               ; long branch: fence too wide for BEQ/BCC
@drn_last_tenths: .byte 0
@drn_elapsed:     .byte 0

; =============================================================================
; uci_drain_status — ACK remaining status string bytes until STAT_AV is clear.
; Phase 2 discards the status string; later phases may want to capture it.
; Clobbers: A
; =============================================================================
uci_drain_status:
        ; TOD-bounded; see uci_drain_resp for why the counted cap is gone.
        ;
        ; Now CAPTURES as well as drains. The status line at $DF1F is where
        ; every UCI target reports its result — the transport ERROR bit in
        ; $DF1C means only "a command was sent while not idle" and is not a
        ; target result channel. Draining this without reading it is why a
        ; SOCKET_READ rejected with `82,PARAMETER(S) OUT OF RANGE` looked
        ; like an empty read for months, and it is what fw 3.15's new
        ; `04,DATAGRAM TRUNCATED: <real length>` would otherwise be invisible
        ; through. The first UCI_STATUS_MAX bytes land in uci_status_buf and
        ; the total seen goes in uci_status_len; the rest still drains.
        ;
        ; The length is committed only if this drain actually saw bytes, so a
        ; later EMPTY drain cannot erase an earlier meaningful status. net_poll
        ; drains status several times per cycle and the last one runs after the
        ; data has been copied — resetting unconditionally captured that final
        ; empty drain and threw away the "04,DATAGRAM TRUNCATED: <len>" line
        ; belonging to the read. uci_status_len therefore holds the most recent
        ; NON-EMPTY status; the consumer clears it when it has acted on one.
        lda #$00
        sta @dst_idx
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @dst_last_tenths
        lda #$00
        sta @dst_elapsed
@dst_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing STAT_AV
        and #UCI_STAT_STAT_AV
        bne @dst_have
        jsr @dst_commit
        clc
        rts
@dst_have:
        lda UCI_STATUS_DATA
        uci_fence                   ; settle before NEXT_DATA write
        ; Stash it if there is room. X is free here (the TOD version clobbers
        ; A only), so use it as the index and restore nothing.
        ldx @dst_idx
        cpx #UCI_STATUS_MAX
        bcs @dst_no_room
        sta uci_status_buf,x
        inx
        stx @dst_idx
@dst_no_room:
        ; NO PER-BYTE ACK — see uci_drain_resp.

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @dst_last_tenths
        beq @dst_loop_long          ; no change — keep draining
        sta @dst_last_tenths
        inc @dst_elapsed
        lda @dst_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @dst_loop_long          ; under budget — continue
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        jsr @dst_commit
        sec
        rts
@dst_commit:
        ; STICKY-FIRST, and the direction matters. net_poll drains status
        ; several times per cycle: the FIRST drain after a command consumes the
        ; whole line, and later drains catch at most a stray byte. Publishing
        ; the LAST non-empty capture therefore let a 1-byte remnant overwrite
        ; the real "04,DATAGRAM TRUNCATED: <len>" — measured, and it looked
        ; exactly like the firmware not emitting the status at all. So the
        ; first capture wins and stays until the consumer zeroes
        ; uci_status_len to arm the next one.
        lda @dst_idx
        sta uci_status_seen         ; NON-STICKY: bytes this drain actually saw.
                                    ; uci_status_len is sticky-first (above) and
                                    ; has no consumer that clears it, so it can
                                    ; hold a line from an EARLIER drain; callers
                                    ; that must know "did THIS drain see a status"
                                    ; (uci_udp_connect's refusal fast-path) read
                                    ; uci_status_seen, which is rewritten — 0
                                    ; included — on every drain.
        beq @dst_commit_done        ; nothing captured this time
        ldx uci_status_len
        bne @dst_commit_done        ; one already held, do not clobber it
        sta uci_status_len
@dst_commit_done:
        rts
@dst_loop_long:
        jmp @dst_loop               ; long branch: fence too wide for BEQ/BCC
@dst_last_tenths: .byte 0
@dst_elapsed:     .byte 0
; MUST stay above uci_status_buf/uci_status_len: those are non-local
; labels and they close this routine's ca65 cheap-local (@) scope, so an
; @dst_idx declared after them is a DIFFERENT symbol from the one the
; routine references. That mistake captured exactly one status byte and
; looked for all the world like the firmware emitting nothing.
@dst_idx:         .byte 0

; Captured status line (ASCII, e.g. "04,DATAGRAM TRUNCATED: 1420").
; Not NUL-terminated; uci_status_len says how many bytes are valid.
uci_status_buf:  .res UCI_STATUS_MAX, 0
uci_status_len:  .byte 0
; Bytes captured by the MOST RECENT uci_drain_status call (non-sticky; see the
; note in @dst_commit). 0 means that drain saw no status line at all.
uci_status_seen: .byte 0

; =============================================================================
; uci_status_leading_code — parse the leading "NN" decimal code of the captured
; status line (uci_status_buf) into a byte.
;
; The $DF1F status channel is `NN,TEXT` where NN is a two-ASCII-digit decimal
; code: "00" = OK, and every non-zero code is a failure the firmware names in
; TEXT (e.g. "85,ERROR OPENING SOCKET", "82,PARAMETER(S) OUT OF RANGE").
;
; Caller MUST have just run uci_drain_status and confirmed uci_status_seen >= 2
; so that uci_status_buf+0/+1 hold this line's digits (not stale bytes).
;
; Output: A = (buf+0 - '0')*10 + (buf+1 - '0'); Z set iff A == 0 (i.e. "00").
;         Non-digit bytes yield a non-zero value, which is the safe verdict —
;         a malformed status is not "00,OK", so treating it as a failure code
;         cannot mask a refusal.
; Clobbers: A
; =============================================================================
uci_status_leading_code:
        lda uci_status_buf+0
        sec
        sbc #'0'                    ; tens digit value
        sta @slc_tmp
        asl a                       ; 2*tens
        asl a                       ; 4*tens
        clc
        adc @slc_tmp                ; 5*tens
        asl a                       ; 10*tens
        sta @slc_tmp
        lda uci_status_buf+1
        sec
        sbc #'0'                    ; ones digit value
        clc
        adc @slc_tmp                ; 10*tens + ones
        rts                         ; Z reflects the final A
@slc_tmp:        .byte 0

; =============================================================================
; Control block for uci_read_resp_bytes — lives in UCI_BSS so no ZP is needed
; and the block persists across backend calls.
; =============================================================================
.segment "UCI_BSS"

uci_resp_dst:    .res 2         ; destination pointer (lo, hi)
uci_resp_max:    .res 1         ; max bytes to store
uci_resp_count:  .res 1         ; actual bytes stored (filled on return)
