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
; entropy_init - Initialize entropy sources and seed the whitening state
;
; Sets SID voice 3 to noise waveform with maximum frequency.
; Starts CIA1 timer A in free-running mode.
; Mixes the current machine state into entropy_state (issue #89).
;
; Clobbers: A
; Preserves: X, Y
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

        ; --- Seed entropy_state from live machine state (issue #89) -------
        ; entropy_state is zero on entry to the FIRST call after LOAD (see
        ; its declaration below for why), and entropy_fill turns it into
        ; hs_ephem_priv, so without this the ephemeral key's whole feedback
        ; chain starts from a compile-time constant on every machine.
        ;
        ; XOR-in, never assign: this routine is called before every
        ; handshake, and later calls have a state that already absorbed
        ; hundreds of hardware reads. XOR cannot reduce the entropy already
        ; there, an assignment would throw it away.
        ;
        ; Ordered AFTER the SID/CIA setup above so sid_osc3 is reading an
        ; oscillator that has been told to run: before the sta sid_v3_ctrl
        ; it reads whatever waveform the KERNAL left, which is silence.
        ;
        ; The four sources and what each is worth is deliberately modest:
        ;   jiffy_lo/mid  time from RESET to this call, in 1/60 s. Moves
        ;                 with drive timing, host scheduling and how long
        ;                 the operator took to press H. Coarse but genuinely
        ;                 unpredictable across power cycles.
        ;   cia1_ta_lo/hi timer A's phase, one CPU cycle of resolution over
        ;                 a ~$4295 period. The finest-grained source here.
        ;   vic_raster    beam position, 0..261; correlated with timer A
        ;                 (both clock-derived) but not identical to it,
        ;                 since the two have different periods.
        ;   sid_osc3      real noise on hardware, a clock ramp under VICE.
        ;
        ; This is a SEED, not a CSPRNG. It buys "not the same constant on
        ; every run"; it does not buy a secure key on its own. See the
        ; entropy_byte note below for the cancellation that still limits
        ; what the generator itself can contribute.
        lda entropy_state
        eor jiffy_lo
        eor jiffy_mid
        eor cia1_ta_lo
        eor cia1_ta_hi
        eor vic_raster
        eor sid_osc3
        sta entropy_state
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

; Persistent whitening state.
;
; ITS LOAD-TIME VALUE IS $00, ON EVERY RUN AND EVERY MACHINE. This comment
; used to claim the opposite -- "power-on value is whatever RAM held" -- and
; that was wrong for a mechanical reason worth stating, because it is easy
; to make again: BSS placed in a file-backed, fill=yes area is emitted into
; the PRG as fill bytes, so LOAD stamps them. APP_EXTRA_BSS loads into
; MAIN_AREA_HI, which cfg/c64-wireguard-*.cfg declares
; `file = %O, ..., fill = yes, fillval = $00`, and the image runs to $9FFF.
; src/boot.s says the same thing about the low BSS. Verified rather than
; argued: build/wireguard.map placed entropy_state at $9FE3, the PRG loads
; at $0801 and is 38913 bytes, and file offset 2 + $9FE3 - $0801 reads $00.
; A `type = bss` marking hides none of that -- it only means ld65 emits no
; CONTENT of its own; the area's fill still covers the address.
;
; Because entropy_byte/entropy_fill feed this byte back into every output,
; and entropy_fill writes hs_ephem_priv in session_initiate, a fixed start
; means the whole ephemeral-key chain is deterministic in the hardware reads
; alone. In the cancelled phases described above that is not a weakening but
; a total loss: measured under VICE, 2.00% of 200 paired trials had
; entropy_fill produce output identical to the previous call from the same
; state, always the same machine-independent 9-byte cycle
; ($ff $01 $fc $07 $f0 $1f $c0 $7f $00, which is exactly what the recurrence
; predicts for s0 = $00 with osc EOR ta pinned at $ff).
;
; entropy_init therefore mixes live machine state in here before every
; handshake (issue #89). That removes the universal constant. It does NOT
; remove the cancellation itself, which is a separate defect in
; entropy_byte's two-source design.
entropy_state:  .res 1
