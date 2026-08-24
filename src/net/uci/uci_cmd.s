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
.export uci_wait_not_busy
.export uci_begin_cmd
.export uci_put_byte
.export uci_push_wait
.export uci_check_err
.export uci_read_resp_bytes
.export uci_drain_resp
.export uci_drain_status
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
        ; a full network round-trip). Use a 16-bit spin-wait on DATA_AV
        ; so we tolerate up to ~150 ms at 48 MHz without bailing early.
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
        ; 16-bit spin-wait for DATA_AV. ~65536 iterations; at 48 MHz
        ; each iteration is ~110 cycles → total ≈ 150 ms, enough for
        ; TCP handshakes over a LAN. X is preserved across the wait.
        stx @rd_save_x
        lda #$00
        sta @rd_ctr_hi
        ldx #$00
@rd_wait:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @rd_have
        dex
        beq @rd_xzero
        jmp @rd_wait                ; long branch: fence too wide for BNE
@rd_xzero:
        dec @rd_ctr_hi
        beq @rd_timeout
        jmp @rd_wait                ; long branch: fence too wide for BNE
@rd_timeout:
        ; Timeout: DATA_AV never appeared — bail with partial read.
        ldx @rd_save_x
        jmp @rd_done
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
@rd_save_x: .byte 0
@rd_ctr_hi: .byte 0

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
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        uci_fence

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
        clc
        rts
@dst_have:
        lda UCI_STATUS_DATA
        uci_fence                   ; settle before NEXT_DATA write
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        uci_fence

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
        sec
        rts
@dst_loop_long:
        jmp @dst_loop               ; long branch: fence too wide for BEQ/BCC
@dst_last_tenths: .byte 0
@dst_elapsed:     .byte 0

; =============================================================================
; Control block for uci_read_resp_bytes — lives in UCI_BSS so no ZP is needed
; and the block persists across backend calls.
; =============================================================================
.segment "UCI_BSS"

uci_resp_dst:    .res 2         ; destination pointer (lo, hi)
uci_resp_max:    .res 1         ; max bytes to store
uci_resp_count:  .res 1         ; actual bytes stored (filled on return)
