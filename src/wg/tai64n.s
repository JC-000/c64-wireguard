; =============================================================================
; tai64n.s - TAI64N timestamp helpers (ca65 port of src/tai64n.asm)
;
; Provides tai64n_init (set epoch anchor), tai64n_now (current time),
; and tai64n_increment (legacy monotonic increment).
; =============================================================================

        .include "constants.inc"

        .export tai64n_init
        .export tai64n_now
        .export tai64n_increment

        .import tai64n_base_time
        .import tai64n_init_jiffy
        .import tai64n_seq
        .import hs_timestamp

        .segment "APP_CODE"

; =============================================================================
; tai64n_init - Initialize timestamp from base Unix epoch
;
; Snapshots the jiffy clock into tai64n_init_jiffy, copies
; tai64n_base_time into hs_timestamp[0..7], zeros nanoseconds,
; and zeros the sub-second sequence counter.
;
; Clobbers: A, X
; =============================================================================
tai64n_init:
        ; Snapshot jiffy clock ($A0=hi, $A1=mid, $A2=lo)
        lda $a0
        sta tai64n_init_jiffy
        lda $a1
        sta tai64n_init_jiffy+1
        lda $a2
        sta tai64n_init_jiffy+2

        ; Copy tai64n_base_time -> hs_timestamp[0..7]
        ldx #7
@copy_base:
        lda tai64n_base_time,x
        sta hs_timestamp,x
        dex
        bpl @copy_base

        ; Zero nanoseconds (hs_timestamp[8..11])
        lda #0
        sta hs_timestamp+8
        sta hs_timestamp+9
        sta hs_timestamp+10
        sta hs_timestamp+11

        ; Zero sequence counter
        sta tai64n_seq
        sta tai64n_seq+1
        sta tai64n_seq+2
        sta tai64n_seq+3
        rts

; =============================================================================
; tai64n_now - Set hs_timestamp to current time
;
; Computes elapsed jiffies since tai64n_init, converts to seconds,
; adds to tai64n_base_time, stores in hs_timestamp[0..7].
; Stores monotonic sequence counter in hs_timestamp[8..11].
;
; Clobbers: A, X, Y
; =============================================================================
tai64n_now:
        ; --- Read current jiffy clock ---
        lda $a2                 ; lo
        sec
        sbc tai64n_init_jiffy+2
        sta @elapsed+2
        lda $a1                 ; mid
        sbc tai64n_init_jiffy+1
        sta @elapsed+1
        lda $a0                 ; hi
        sbc tai64n_init_jiffy
        sta @elapsed

        ; --- Divide elapsed jiffies by 60 to get seconds ---
        ; 24-bit / 8-bit = repeated subtraction
        ; Quotient in @seconds (3 bytes), remainder discarded
        lda #0
        sta @seconds
        sta @seconds+1
        sta @seconds+2

@div_loop:
        ; Check if elapsed >= 60
        lda @elapsed            ; hi byte
        bne @can_sub            ; hi > 0 means >= 256 > 60
        lda @elapsed+1          ; mid byte
        bne @can_sub            ; mid > 0 means >= 256 > 60
        lda @elapsed+2          ; lo byte
        cmp #60
        bcc @div_done           ; < 60, done

@can_sub:
        ; Subtract 60 from elapsed (3-byte)
        lda @elapsed+2
        sec
        sbc #60
        sta @elapsed+2
        lda @elapsed+1
        sbc #0
        sta @elapsed+1
        lda @elapsed
        sbc #0
        sta @elapsed

        ; Increment seconds (3-byte)
        inc @seconds+2
        bne @div_loop
        inc @seconds+1
        bne @div_loop
        inc @seconds
        jmp @div_loop

@div_done:
        ; --- Add seconds to tai64n_base_time -> hs_timestamp[0..7] ---
        ; tai64n_base_time is 8-byte big-endian (MSB at byte 0)
        ; @seconds is 3 bytes; add to bytes 5,6,7 of timestamp
        ; First copy base_time to hs_timestamp
        ldx #7
@copy_base2:
        lda tai64n_base_time,x
        sta hs_timestamp,x
        dex
        bpl @copy_base2

        ; Add @seconds (3 bytes) to hs_timestamp[5..7], carry into [0..4]
        clc
        lda hs_timestamp+7
        adc @seconds+2
        sta hs_timestamp+7
        lda hs_timestamp+6
        adc @seconds+1
        sta hs_timestamp+6
        lda hs_timestamp+5
        adc @seconds
        sta hs_timestamp+5
        ; Propagate carry through bytes 4..0
        ldx #4
@carry_prop:
        bcc @carry_done
        lda hs_timestamp,x
        adc #0
        sta hs_timestamp,x
        dex
        bpl @carry_prop
@carry_done:

        ; --- Increment and store sequence counter ---
        ; tai64n_seq is 4-byte big-endian monotonic counter
        ldx #3
        sec                     ; +1
@inc_seq:
        lda tai64n_seq,x
        adc #0
        sta tai64n_seq,x
        bcc @seq_done
        dex
        bpl @inc_seq
@seq_done:
        ; Copy to hs_timestamp[8..11]
        lda tai64n_seq
        sta hs_timestamp+8
        lda tai64n_seq+1
        sta hs_timestamp+9
        lda tai64n_seq+2
        sta hs_timestamp+10
        lda tai64n_seq+3
        sta hs_timestamp+11
        rts

; Temporaries for tai64n_now (in code segment to avoid data.asm clutter)
@elapsed:
        .res 3, 0
@seconds:
        .res 3, 0

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
        bcc @done              ; no carry -> done
        dex
        cpx #7
        bne @inc_nano

        ; Carry out of nanoseconds -> increment seconds (bytes 0..7)
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
