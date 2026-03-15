; =============================================================================
; entropy.asm - Hardware random number generation
;
; Uses SID voice 3 noise waveform + CIA1 timer A for entropy.
; =============================================================================

; =============================================================================
; entropy_init - Initialize entropy sources
;
; Sets SID voice 3 to noise waveform with maximum frequency.
; Starts CIA1 timer A in free-running mode.
;
; Clobbers: A
; =============================================================================
entropy_init:
        ; SID voice 3: max frequency
        lda #$ff
        sta sid_v3_freq_lo
        sta sid_v3_freq_hi
        ; noise waveform (bit 7 = 1)
        lda #$80
        sta sid_v3_ctrl
        ; CIA1 timer A: free-running, continuous
        ; Start timer (bit 0 = 1), continuous mode (bit 3 = 0)
        lda cia1_cra
        ora #$01                ; set start bit
        and #$f7                ; clear one-shot bit
        sta cia1_cra
        rts

; =============================================================================
; entropy_byte - Get one random byte
;
; Returns: A = random byte (XOR of SID osc3 + CIA1 timer low)
; Preserves: X, Y
; =============================================================================
entropy_byte:
        lda sid_osc3
        eor cia1_ta_lo
        rts

; =============================================================================
; entropy_fill - Fill memory with random bytes
;
; Input: zp_ptr1 = destination pointer, Y = count (1-255)
; Output: Y bytes written to (zp_ptr1)
; Clobbers: A, Y
; =============================================================================
entropy_fill:
        dey
@loop:
        lda sid_osc3
        eor cia1_ta_lo
        sta (zp_ptr1),y
        dey
        bpl @loop               ; unsigned: 0 still processes, $FF exits
        rts
