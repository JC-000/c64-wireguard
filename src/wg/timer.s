; =============================================================================
; wg/timer.s - Session timers using jiffy clock ($A0-$A2, 60Hz)
;
; ca65 port of src/timer.asm. No logic changes; syntax translation only.
;
; The C64 jiffy clock is a 24-bit counter at $A0(hi)/$A1(mid)/$A2(lo),
; incremented at 60Hz by the KERNAL IRQ handler.
;
; Thresholds (in jiffies at 60Hz):
;   Keepalive:      600  ($0258) = 10 seconds
;   Rekey:         7200  ($1C20) = 120 seconds
;   Session expire: 10800 ($2A30) = 180 seconds
;
; Interface:
;   timer_session_start   - snapshot jiffy clock at session start
;   timer_handshake_start - snapshot it at initiation and arm the handshake
;                           deadline (issue #84)
;   timer_check           - check handshake timeout / expiry / rekey /
;                           keepalive (main loop)
;   timer_mark_send       - update last-send time after transport_send
;   timer_elapsed_cmp     - compare elapsed time against threshold
; =============================================================================

.include "constants.inc"

; --- Public entry points ---
.export timer_session_start
.export timer_handshake_start
.export timer_check_handshake
.export timer_check
.export timer_mark_send
.export timer_elapsed_cmp

; --- External symbols ---
; SESSION_ACTIVE, SESSION_IDLE : session state constants (src/session.asm)
.importzp SESSION_ACTIVE
.importzp SESSION_HS_SENT
.importzp SESSION_IDLE
; wg_state, rekey_pending, session_start_jiffy, last_send_jiffy,
; tp_payload_len : mutable globals (src/data.asm)
.import session_reset
.import wg_state
.import rekey_pending
.import hs_timer_armed
.import session_start_jiffy
.import last_send_jiffy
.import tp_payload_len
; transport_send : send routine (src/transport.asm)
.import transport_send
; print_string : string printer (src/boot.asm)
.import print_string
; session_expired_msg, rekey_msg, keepalive_msg : strings (src/strings.asm)
.import session_expired_msg
.import hs_timeout_msg
.import rekey_msg
.import keepalive_msg

KEEPALIVE_JIFFIES_LO = $58     ; 600 = $0258
KEEPALIVE_JIFFIES_HI = $02
REKEY_JIFFIES_LO     = $20     ; 7200 = $1C20
REKEY_JIFFIES_HI     = $1c
EXPIRE_JIFFIES_LO    = $30     ; 10800 = $2A30
EXPIRE_JIFFIES_HI    = $2a
; Handshake deadline: 5400 jiffies = 90 s. That is WireGuard's own
; REKEY_ATTEMPT_TIME — the point at which a peer gives up on an initiation
; rather than a number invented here. It bounds the WAIT for a Type 2, not
; the cost of producing the Type 1: the jiffy clock does not advance while
; the crypto runs with interrupts masked, and the state only becomes HS_SENT
; after the initiation is on the wire.
HS_TIMEOUT_JIFFIES_LO = $18    ; 5400 = $1518
HS_TIMEOUT_JIFFIES_HI = $15

.segment "APP_CODE"

; =============================================================================
; timer_session_start - Record session start time
;
; Snapshots jiffy clock into session_start_jiffy and last_send_jiffy.
; Call when transitioning to SESSION_ACTIVE.
;
; Also disarms the handshake deadline: the handshake it was timing has just
; completed, and leaving it armed would let a later stale comparison tear
; down a session that is now live.
;
; Clobbers: A
; =============================================================================
timer_session_start:
        lda $a0
        sta session_start_jiffy
        sta last_send_jiffy
        lda $a1
        sta session_start_jiffy+1
        sta last_send_jiffy+1
        lda $a2
        sta session_start_jiffy+2
        sta last_send_jiffy+2
        lda #$00
        sta hs_timer_armed
        rts

; =============================================================================
; timer_check - Periodic timer checks
;
; Called every main loop iteration, in EVERY state. It used to be called only
; when wg_state == ACTIVE — by boot.s' main loop, and again by its own first
; three instructions — which is precisely why an unanswered handshake was
; unreclaimable: the one mechanism that reclaims a session could not see the
; state most likely to need reclaiming (issue #84). boot.s no longer
; pre-filters; this routine is the single place the state gate lives.
;
; HS_SENT:
;   0. Handshake deadline (90s) -> session_reset (returns the socket)
; ACTIVE, in priority order:
;   1. Session expired (180s) -> reset to IDLE
;   2. Rekey needed (120s) -> set rekey_pending flag
;   3. Keepalive needed (10s) -> send empty Type 4
;
; Clobbers: A, X, Y
; =============================================================================
timer_check:
        lda wg_state
        cmp #<SESSION_ACTIVE
        beq @active
        cmp #<SESSION_HS_SENT
        beq @handshaking
        rts

@handshaking:
        ; Check 0 lives in APP_EXTRA (MAIN_AREA_HI), not here — the same
        ; escape session_stage_dest took, taken for the same reason, when
        ; APP_CODE could not grow far enough to hold it. The binding
        ; constraint in MAIN_AREA_LO is LIB_CHACHA20_POLY1305_CODE's
        ; align = $100 pin; the §6.7 image-overrun assert in
        ; contract_asserts.s is what reports crossing it.
        ; It has to be a jmp, not a branch: the two
        ; segments are ~$4000 apart.
        jmp timer_check_handshake

@active:
        ; --- Check 1: session expired? (elapsed > 10800 jiffies) ---
        lda #<session_start_jiffy
        sta zp_ptr1
        lda #>session_start_jiffy
        sta zp_ptr1+1
        lda #EXPIRE_JIFFIES_LO
        ldx #EXPIRE_JIFFIES_HI
        jsr timer_elapsed_cmp
        bcc @check_rekey        ; C=0: not expired yet

        ; Expired — tear the session down. Route through session_reset so the
        ; UDP socket is handed back (issue #71 / GideonZ/1541ultimate#808), not
        ; just wg_state cleared inline — session_reset now closes the socket.
        jsr session_reset
        lda #<session_expired_msg
        ldy #>session_expired_msg
        jsr print_string
        rts

@check_rekey:
        ; --- Check 2: rekey needed? (elapsed > 7200 jiffies) ---
        lda rekey_pending
        bne @check_keepalive    ; already flagged, skip

        lda #<session_start_jiffy
        sta zp_ptr1
        lda #>session_start_jiffy
        sta zp_ptr1+1
        lda #REKEY_JIFFIES_LO
        ldx #REKEY_JIFFIES_HI
        jsr timer_elapsed_cmp
        bcc @check_keepalive    ; C=0: not yet

        ; Flag rekey
        lda #1
        sta rekey_pending
        lda #<rekey_msg
        ldy #>rekey_msg
        jsr print_string

@check_keepalive:
        ; --- Check 3: keepalive needed? (elapsed > 600 jiffies) ---
        lda #<last_send_jiffy
        sta zp_ptr1
        lda #>last_send_jiffy
        sta zp_ptr1+1
        lda #KEEPALIVE_JIFFIES_LO
        ldx #KEEPALIVE_JIFFIES_HI
        jsr timer_elapsed_cmp
        bcc @done               ; C=0: not yet

        ; Send keepalive (empty Type 4 packet)
        lda #0
        sta tp_payload_len
        sta tp_payload_len+1
        jsr transport_send
        jsr timer_mark_send

        lda #<keepalive_msg
        ldy #>keepalive_msg
        jsr print_string
@done:
        rts

; =============================================================================
; timer_mark_send - Update last-send timestamp
;
; Call after every transport_send to reset the keepalive timer.
;
; Clobbers: A
; =============================================================================
timer_mark_send:
        lda $a0
        sta last_send_jiffy
        lda $a1
        sta last_send_jiffy+1
        lda $a2
        sta last_send_jiffy+2
        rts

; =============================================================================
; timer_elapsed_cmp - Compare elapsed jiffies against threshold
;
; Input: zp_ptr1 = pointer to saved 3-byte jiffy time (hi/mid/lo)
;        A = threshold low byte, X = threshold high byte (16-bit)
; Output: C=1 if elapsed >= threshold, C=0 if less
; Clobbers: A, X, Y
; =============================================================================
timer_elapsed_cmp:
        ; Save threshold
        sta @thr_lo+1           ; self-mod
        stx @thr_hi+1           ; self-mod

        ; Compute elapsed = current - saved (3 bytes)
        ; Jiffy clock: $A0=hi, $A1=mid, $A2=lo
        ; Saved buffer layout: [0]=hi, [1]=mid, [2]=lo (same order as $A0-$A2)
        ; Subtract saved from current, low byte first
        ldy #2
        sec
        lda $a2                 ; current low
        sbc (zp_ptr1),y         ; saved[2] = lo
        pha                     ; save elapsed low
        dey
        lda $a1                 ; current mid
        sbc (zp_ptr1),y         ; saved[1] = mid
        tax                     ; X = elapsed mid

        pla                     ; A = elapsed low

        ; Compare 16-bit elapsed (X:A) against threshold
        ; Actually we need: elapsed_hi:elapsed_lo vs thr_hi:thr_lo
        ; X = elapsed high byte, A = elapsed low byte
@thr_hi:
        cpx #0                  ; (self-modified: threshold high)
        bcc @less               ; elapsed_hi < thr_hi
        bne @ge                 ; elapsed_hi > thr_hi
        ; High bytes equal, compare low
@thr_lo:
        cmp #0                  ; (self-modified: threshold low)
        bcc @less               ; elapsed_lo < thr_lo
@ge:
        sec                     ; C=1: elapsed >= threshold
        rts
@less:
        clc                     ; C=0: elapsed < threshold
        rts

; =============================================================================
; APP_EXTRA (MAIN_AREA_HI) — the #84 handshake deadline
;
; Placed here for space, not for structure: see the comment at @handshaking.
; =============================================================================
.segment "APP_EXTRA"

; =============================================================================
; timer_handshake_start - Record initiation time and arm the handshake deadline
;
; Call from session_initiate once the Type 1 is on the wire. Until #84 the
; only thing that could reclaim a session was the 180 s expiry, and that is
; gated on SESSION_ACTIVE — so an initiation that never got an answer sat in
; HS_SENT holding the backend's socket for the rest of the run. This starts
; the clock on that state instead.
;
; Clobbers: A
; =============================================================================
timer_handshake_start:
        jsr timer_session_start ; snapshot the clock (and disarm)...
        lda #$01
        sta hs_timer_armed      ; ...then arm on top of it
        rts

; =============================================================================
; timer_check_handshake - Check 0: initiation unanswered too long?
;
; Tail of timer_check for wg_state == HS_SENT; entered by jmp, so its rts is
; timer_check's rts.
;
; Armed only by timer_handshake_start, i.e. only for an initiation this build
; actually sent. A caller that sets wg_state = HS_SENT by hand has taken no
; jiffy snapshot, and measuring a deadline from whatever session_start_jiffy
; last held would fire immediately.
;
; Clobbers: A, X, Y
; =============================================================================
timer_check_handshake:
        lda hs_timer_armed
        beq @hs_done

        lda #<session_start_jiffy
        sta zp_ptr1
        lda #>session_start_jiffy
        sta zp_ptr1+1
        lda #HS_TIMEOUT_JIFFIES_LO
        ldx #HS_TIMEOUT_JIFFIES_HI
        jsr timer_elapsed_cmp
        bcc @hs_done            ; C=0: still within the deadline

        ; Give up on this handshake. session_reset is the canonical teardown:
        ; it drops to IDLE, disarms this deadline, and hands the backend's
        ; socket back — which is the whole point. Deliberately NOT a retry:
        ; re-initiating from a timer would loop against an unreachable peer
        ; forever. The user re-arms with 'H'.
        jsr session_reset
        lda #<hs_timeout_msg
        ldy #>hs_timeout_msg
        jsr print_string
@hs_done:
        rts
