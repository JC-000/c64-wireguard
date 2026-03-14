; =============================================================================
; tai64n.asm - TAI64N timestamp helpers
;
; Minimal: test harness injects timestamps via memory writes.
; Provides tai64n_increment for monotonicity.
; =============================================================================

; =============================================================================
; tai64n_increment - Increment TAI64N timestamp for replay protection
;
; TAI64N: 8-byte big-endian seconds + 4-byte big-endian nanoseconds
; Increments nanoseconds by 1. On overflow (>= 999999999), resets to 0
; and increments seconds.
;
; Input: hs_timestamp (12 bytes)
; Output: hs_timestamp incremented
; Clobbers: A, X
; =============================================================================
tai64n_increment:
        ; Increment nanoseconds (big-endian bytes 8..11)
        ldx #11
        sec                    ; set carry for +1
@inc_nano:
        lda hs_timestamp,x
        adc #0
        sta hs_timestamp,x
        bcc @done              ; no carry → done
        dex
        cpx #7
        bne @inc_nano

        ; Carry out of nanoseconds → increment seconds (bytes 0..7)
        ; Also zero out nanoseconds
        lda #0
        sta hs_timestamp+8
        sta hs_timestamp+9
        sta hs_timestamp+10
        sta hs_timestamp+11

        ldx #7
        sec
@inc_sec:
        lda hs_timestamp,x
        adc #0
        sta hs_timestamp,x
        bcc @done
        dex
        bpl @inc_sec

@done:
        rts
