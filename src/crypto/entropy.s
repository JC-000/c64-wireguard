; =============================================================================
; entropy.s - Hardware random number generation
;
; Uses SID voice 3 noise waveform + CIA1 timer A for entropy.
; =============================================================================

.include "constants.inc"

.export entropy_init
.export entropy_byte
.export entropy_fill

; APP_EXTRA (MAIN_AREA_HI), not CRYPTO_CODE. Nothing about this module needs
; to be low: it touches only $D41B/$DC0x and its callers reach it by JSR.
;
; No free-space figure here, deliberately. The line that used to sit at this
; spot said MAIN_AREA_HI had "~1.9 KB free"; when issue #103 measured it, it
; had 28 bytes, and a PR had already been sized against the comment in good
; faith. Both areas fail the link when they are overrun — MAIN_AREA_LO on the
; §6.7 image-overrun assert in contract_asserts.s, MAIN_AREA_HI on a plain
; ld65 area overflow — so the budget is something to be told by a build, never
; something to be remembered.
.segment "APP_EXTRA"

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
; Returns: A = random byte
; Preserves: X, Y
;
; WHY THE PERSISTENT STATE. The two hardware reads alone are NOT independent:
; $D41B (SID OSC3) and $DC04 (CIA1 timer A low) are both affine in the CPU
; clock with OPPOSITE slopes — OSC3 counts up, TA counts down — so their sum
; S = (osc + cia) & $FF is invariant in elapsed time; the clock cancels, and S
; only steps when TA underflows. For a value derived as x EOR (S - x), there
; are exactly two S at which the result is the same for every x:
;
;     S = $7F  ->  every byte is $7F
;     S = $FF  ->  every byte is $FF
;
; i.e. 2 of 256 phases produce a CONSTANT stream. Measured 1.00% of sampled
; phases under VICE, reproducing both signatures exactly, and it is what made
; test_session/test_handshake fail intermittently on "all 17 bytes identical
; (0x7f)" and "sender_idx ffffffff == ffffffff".
;
; Under VICE this is total degeneracy because OSC3 is a clock-derived ramp
; rather than noise (VICE does not clock reSID with sound disabled). On real
; hardware OSC3 IS noise, so the failure is not total — but two operands that
; are affine in the same clock still carry far less entropy than they appear
; to, which matters because this feeds WireGuard ephemeral keys.
;
; Stirring a persistent byte in breaks the cancellation: consecutive outputs
; can no longer be a function of S alone. XOR-ing the hardware reads on top is
; entropy-preserving, so this is strictly no worse anywhere; the rotate only
; whitens. Costs ~8 cycles and one byte of RAM.
;
; NOTE the failure signature is deliberately still reachable by a genuinely
; dead RNG (state stuck, both reads flat), so the assertions in
; tools/test_session.py and tools/test_handshake.py keep their teeth.
; =============================================================================
entropy_byte:
        lda entropy_state
        rol                     ; whiten: carry-in from the previous step
        eor sid_osc3
        eor cia1_ta_lo
        sta entropy_state
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
        lda entropy_state
        rol
        eor sid_osc3
        eor cia1_ta_lo
        sta entropy_state
        sta (zp_ptr1),y
        dey
        bpl @loop               ; unsigned: 0 still processes, $FF exits
        rts

; APP_EXTRA_BSS, which the cfg routes into APP_BSS_OVERLAY (MAIN_AREA_HI's
; RAM from $8800 up), rather than CRYPTO_BSS. CRYPTO_BSS is page-aligned for
; a constant-time reason that has nothing to do with this byte, and one
; stray .res there moves the whole segment.
.segment "APP_EXTRA_BSS"

; Persistent whitening state. Power-on value is whatever RAM held, which is
; itself a weak entropy source and is never worse than starting from a
; constant.
entropy_state:  .res 1
