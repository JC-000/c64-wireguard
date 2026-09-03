; =============================================================================
; tai64n.s - TAI64N timestamp helpers (ca65 port of src/tai64n.asm)
;
; Provides tai64n_init (set the epoch anchor), tai64n_sync (re-anchor only
; when the staged base time changed), tai64n_now (the current, strictly
; increasing timestamp - the routine on the initiation path) and
; tai64n_increment (+1 ns; also the guard's bump primitive).
;
; WireGuard's responder discards a Type 1 whose 12-byte TAI64N compares
; <= the greatest it has already seen from that peer (a memcmp over the 12
; bytes: 8-byte TAI64 seconds, then 4-byte nanoseconds, both big-endian).
; Issue #87: every initiation used to carry tai64n_base_time || 00000001,
; because config_load - which runs at the top of EVERY session_initiate on
; purpose (#65) - called tai64n_init unconditionally, and session_initiate
; then did one tai64n_increment on the freshly zeroed nanoseconds. Nothing
; carried forward, so a conformant peer accepted exactly one handshake per
; base time and silently dropped every rekey. tai64n_now existed to derive
; an advancing value from the jiffy snapshot and had no caller. Now:
;
;   * config_load calls tai64n_sync, which re-anchors (tai64n_init) ONLY
;     when tai64n_base_time differs from the copy taken at the last init
;     (tai64n_init_base): the first load, or a genuinely new base time.
;     A re-anchor resets the anchor and seq but NOT tai64n_last: the
;     peer only knows greatest-seen per static key, so a re-anchor to a
;     LOWER base must still emit above what already went out, and the
;     guard does exactly that. tai64n_last is zero only at cold start.
;   * session_initiate calls tai64n_now. The candidate is
;     base + (jiffies since the anchor) / 60 seconds, with the sub-second
;     sequence counter tai64n_seq (+1 per call) in the nanosecond field.
;     It is then held strictly above tai64n_last, the last value emitted,
;     so the output advances even when the jiffy clock does not (VICE
;     jsr() tests run with interrupts masked and the clock never ticks).
;
; Persistence across reboots is OUT of scope here (#87 follow-up):
; tai64n_last and tai64n_seq live in BSS and the jiffy clock restarts at
; power-on, so two runs with the same WG.CFG base time collide again. The
; live tools stage tai64n_base_time from host time on every load, which
; sidesteps it; a stored high-water mark would close it.
; =============================================================================

        .include "constants.inc"

        .export tai64n_init
        .export tai64n_sync
        .export tai64n_now
        .export tai64n_increment

        .import tai64n_base_time
        .import tai64n_init_jiffy
        .import tai64n_init_base
        .import tai64n_seq
        .import tai64n_last
        .import hs_timestamp

        .segment "APP_CODE"

; =============================================================================
; tai64n_sync - Re-anchor the timeline only if the base time changed
;
; Compares the 8 staged bytes of tai64n_base_time against tai64n_init_base,
; the copy tai64n_init took. Different (which includes the first load, when
; tai64n_init_base is still the BSS zeros) -> tai64n_init. Same -> nothing,
; so the running timeline survives the config_load at the top of every
; session_initiate (rekey, manual 'H', re-initiation after expiry).
;
; An all-zero base time is never re-anchored by this route; the anchor is
; then jiffy 0 with tai64n_last = 0, which still produces an increasing
; sequence - it is just not a real configuration.
;
; Clobbers: A, X
; =============================================================================
tai64n_sync:
        ldx #7
@cmp:
        lda tai64n_base_time,x
        cmp tai64n_init_base,x
        bne tai64n_init         ; base moved: re-anchor (tail call)
        dex
        bpl @cmp
        rts                     ; unchanged: keep the running timeline

; =============================================================================
; tai64n_init - Initialize timestamp from base Unix epoch
;
; Snapshots the jiffy clock into tai64n_init_jiffy, copies
; tai64n_base_time into hs_timestamp[0..7] and tai64n_init_base,
; zeros nanoseconds and the sub-second sequence counter. It does NOT
; touch tai64n_last: what has already been emitted stays the floor for
; everything that follows, whatever the new base is.
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

        ; Copy tai64n_base_time -> hs_timestamp[0..7] and record it as
        ; the anchored base for tai64n_sync
        ldx #7
@copy_base:
        lda tai64n_base_time,x
        sta hs_timestamp,x
        sta tai64n_init_base,x
        dex
        bpl @copy_base

        ; Zero nanoseconds (hs_timestamp[8..11])
        lda #0
        sta hs_timestamp+8
        sta hs_timestamp+9
        sta hs_timestamp+10
        sta hs_timestamp+11

        ; Zero the sequence counter (tai64n_last deliberately kept)
        ldx #3
@zero:
        sta tai64n_seq,x
        dex
        bpl @zero
        rts

; =============================================================================
; tai64n_now - Set hs_timestamp to the next strictly increasing timestamp
;
; Candidate: elapsed jiffies since tai64n_init (the KERNAL clock at
; $A0-$A2 ticks at 60 Hz on PAL and NTSC alike - the KERNAL programs CIA1
; timer A for 1/60 s on both - and UDTIM rolls it over to 0 at $4F1A00,
; i.e. 24 h, NOT at $FFFFFF), divided by 60, added to tai64n_base_time
; -> hs_timestamp[0..7]; tai64n_seq + 1 -> hs_timestamp[8..11].
;
; Guard: if the candidate is not > tai64n_last (96-bit big-endian compare),
; emit tai64n_last + 1 instead (tai64n_increment: +1 ns, carry into the
; seconds). Either way the emitted value is > tai64n_last, and becomes it.
;
; Why it is strictly increasing:
;   - stalled jiffy clock (VICE jsr, interrupts masked): seconds are
;     constant, seq is +1 per call -> the candidate alone increases;
;   - running clock: seconds are non-decreasing for 24 h after the anchor
;     (the $4F1A00 correction covers the KERNAL's rollover), seq +1 -> the
;     candidate alone increases;
;   - anything else (a re-anchor to a LOWER base time, more than 24 h
;     since the anchor, a DMA write to the clock, tai64n_init_jiffy poked
;     by a test): the guard emits last + 1.
;   So by induction every call emits a value > the previous one for the
;   whole run: tai64n_init never clears tai64n_last.
;
; Nanoseconds stay < 1e9: seq advances once per initiation, and a
; handshake takes tens of seconds even at 48 MHz.
;
; Clobbers: A, X, Y
; =============================================================================
tai64n_now:
        ; --- elapsed = jiffy clock - tai64n_init_jiffy (24-bit) ---
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
        bcs @no_wrap
        ; Borrow: the clock is behind the anchor, which (short of someone
        ; writing $A0-$A2) means UDTIM rolled it over at 24 h. Add $4F1A00
        ; so the difference is the true elapsed count; exact while fewer
        ; than 24 h have passed since the anchor, and past that the guard
        ; below still keeps monotonicity. The low byte of $4F1A00 is $00:
        ; nothing to add there and no carry out of it.
        lda @elapsed+1
        clc
        adc #$1a
        sta @elapsed+1
        lda @elapsed
        adc #$4f
        sta @elapsed
@no_wrap:

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
        ldx #3
@copy_seq:
        lda tai64n_seq,x
        sta hs_timestamp+8,x
        dex
        bpl @copy_seq

        ; --- Guard: hold the result strictly above tai64n_last ---
        ; Big-endian 96-bit compare, most significant byte first
        ldx #0
@cmp_last:
        lda hs_timestamp,x
        cmp tai64n_last,x
        bcc @bump               ; candidate < last
        bne @keep               ; candidate > last
        inx
        cpx #12
        bne @cmp_last
        ; equal: fall through and bump
@bump:
        ; candidate <= last: emit last + 1 ns instead
        ldx #11
@copy_last:
        lda tai64n_last,x
        sta hs_timestamp,x
        dex
        bpl @copy_last
        jsr tai64n_increment
@keep:
        ; Remember what went out
        ldx #11
@save_last:
        lda hs_timestamp,x
        sta tai64n_last,x
        dex
        bpl @save_last
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
; Increments nanoseconds by 1. On a carry out of the 32-bit nanosecond
; field, resets it to 0 and increments seconds. (No 1e9 rollover: the
; callers keep nanoseconds far below it - see tai64n_now.)
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
