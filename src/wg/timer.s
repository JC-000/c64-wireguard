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
;   timer_session_start - snapshot jiffy clock at session start
;   timer_check         - check expiry/rekey/keepalive (main loop)
;   timer_mark_send     - update last-send time after transport_send
;   timer_elapsed_cmp   - compare elapsed time against threshold
; =============================================================================

.include "constants.inc"

; --- Public entry points ---
.export timer_session_start
.export timer_check
.export timer_mark_send
.export timer_elapsed_cmp

; --- External symbols ---
; SESSION_ACTIVE, SESSION_IDLE : session state constants (src/session.asm)
.importzp SESSION_ACTIVE
.importzp SESSION_IDLE
; wg_state, rekey_pending, session_start_jiffy, last_send_jiffy,
; tp_payload_len : mutable globals (src/data.asm)
.import wg_state
.import rekey_pending
.import session_start_jiffy
.import last_send_jiffy
.import tp_payload_len
; transport_send : send routine (src/transport.asm)
.import transport_send
; print_string : string printer (src/boot.asm)
.import print_string
; session_expired_msg, rekey_msg, keepalive_msg : strings (src/strings.asm)
.import session_expired_msg
.import rekey_msg
.import keepalive_msg

KEEPALIVE_JIFFIES_LO = $58     ; 600 = $0258
KEEPALIVE_JIFFIES_HI = $02
REKEY_JIFFIES_LO     = $20     ; 7200 = $1C20
REKEY_JIFFIES_HI     = $1c
EXPIRE_JIFFIES_LO    = $30     ; 10800 = $2A30
EXPIRE_JIFFIES_HI    = $2a

.segment "APP_CODE"

; =============================================================================
; timer_session_start - Record session start time
;
; Snapshots jiffy clock into session_start_jiffy and last_send_jiffy.
; Call when transitioning to SESSION_ACTIVE.
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
        rts

; =============================================================================
; timer_check - Periodic timer checks for active session
;
; Called every main loop iteration. Only operates when wg_state == ACTIVE.
; Checks (in priority order):
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
        rts
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

        ; Expired — reset to IDLE
        lda #<SESSION_IDLE
        sta wg_state
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
