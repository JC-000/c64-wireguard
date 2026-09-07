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
; The voice-3 control value, named so it can be asserted. Zero bytes of
; code: these are link-time checks on a constant, not runtime guards.
SID_V3_CTRL_NOISE = $80

; Assert BOTH directions, not just the one whose failure was imagined.
; "noise is on" alone passes for $88, which is the value the comment
; wrongly claimed and which would freeze the oscillator; "TEST is off"
; alone passes for $00, which is silence.
;
; WHAT THESE TWO LINES DO NOT COVER, stated because the first version of
; this guard was shipped believing they did. They pin the CONSTANT. The
; instruction below is free to stop using it: edit `lda #SID_V3_CTRL_NOISE`
; to `lda #$88` and the symbol is merely unused, both asserts stay green,
; ca65 exits 0, and a TEST-set SID ships. Abandoning the symbol is exactly
; the edit shape this module's own history documents, so a guard that only
; watches the symbol is guarding the wrong thing.
;
; The byte that actually reaches $D412 is asserted where it can be:
; tools/test_entropy_seed.py LINEAR-DECODES the built PRG across
; entropy_init..entropy_fill's rts and checks every store that targets the
; register, whatever its form — plus that at least one exists, so a build
; that dropped the SID setup cannot satisfy an all-quantifier vacuously.
;
; IT DECODES, it does not search for bytes, and that distinction was
; learned the hard way: the first version searched for the literal encoding
; `8D 12 D4`, and two clean images shipping $88 to $D412 scored 4/4 PASS
; against it — `ldx #$00 / lda #$88 / sta sid_v3_ctrl,x` ($9D) and
; `ldx #$88 / stx sid_v3_ctrl` ($8E). $99, $8C and $91 were equally
; invisible. The .assert pair pins a SYMBOL the instruction can abandon;
; a byte search pins an ENCODING the instruction can abandon. What holds up
; is not enumerating every way to write this register — that list is
; open-ended — but FAILING on any form whose target or value cannot be read
; statically: an unknown opcode, an indexed store that could land here, a
; value loaded from memory. All failures, none silent passes.
;
; Keep both layers: this pair catches the edit at assembly time with a
; message at the point of the mistake, the image check catches the edits
; this pair cannot see.
;
; BIT 1 (SYNC) IS DELIBERATELY UNPINNED, and $82 would pass both asserts.
; SYNC hard-syncs voice 3 to voice 2, so with a non-zero voice-2 frequency
; it does perturb how the noise LFSR is clocked. It is left open because
; nothing in this program ever writes a voice-2 frequency, so the effect is
; unreachable here, and because a third assert would pin a bit whose
; correct value is "whatever the rest of the SID is doing" rather than a
; property of this routine. If this program ever drives voice 2, revisit.
; $81 (GATE) also passes and SHOULD: GATE drives the envelope generator,
; not the oscillator, and $D41B is an oscillator readout.
.assert (SID_V3_CTRL_NOISE & $80) <> 0, error, "SID voice 3 must select the NOISE waveform: $D41B is only a noise-LFSR tap with bit 7 set, and entropy_byte's non-affinity argument (and the 0/6144 hardware result) rests on that. See src/crypto/entropy.s."
.assert (SID_V3_CTRL_NOISE & $08) = 0, error, "SID voice 3 TEST bit (bit 3) must be CLEAR: TEST holds the oscillator in reset and freezes $D41B to a constant, which is exactly the degeneracy entropy_byte documents. VICE will not catch this -- it does not clock reSID. See src/crypto/entropy.s."

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
        ; Noise waveform, TEST CLEAR. Both halves are load-bearing and both
        ; are asserted below rather than left to this comment, because the
        ; comment DID go wrong here: it claimed for a while that the value
        ; was $88 (noise + TEST), and the hardware result that closed the
        ; #101 exposure was attributed to that non-existent TEST bit.
        ;
        ; bit 7 (noise) makes $D41B a tap off the 23-bit noise LFSR, which
        ; is what stops it being affine in the CPU clock. bit 3 (TEST) would
        ; hold the oscillator in reset, freezing $D41B to a constant — the
        ; exact degeneracy entropy_byte's note is about. A one-bit edit here
        ; silently guts the generator on hardware while every VICE test
        ; keeps passing, because VICE does not clock reSID at all.
        lda #SID_V3_CTRL_NOISE
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
        ; NOT every session_initiate reaches this. There are two call sites:
        ; boot.s's do_handshake, which calls entropy_init first, and
        ; session.s's Type-3 cookie-reply branch, which re-initiates without
        ; it. That path is benign today only because a Type 3 can arrive
        ; only after a Type 1 already went out, so the state has been seeded
        ; and has since absorbed a full initiation's worth of reads -- but
        ; "every handshake is seeded" would be false, and that path is
        ; already under review as issue #94.
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
        ;   vic_raster    beam position, 0..261. WORTH ALMOST NOTHING and
        ;                 kept only because it is already paid for: an NTSC
        ;                 frame is 65 * 263 = 17095 cycles and timer A's
        ;                 period is 17046, so the two are within 50 cycles
        ;                 of each other and the raster is in the same
        ;                 clock-affine family as the timer, not an
        ;                 independent axis. Do NOT reach for it as the
        ;                 non-affine source issue #101 needs -- CIA1 TOD is
        ;                 the one that is genuinely off this clock
        ;                 (uci_tod_start already runs in net_init under
        ;                 BACKEND=uci, but not under ip65).
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
; READ THE SCOPE LINE BEFORE THE ARGUMENT. The next three paragraphs
; describe VICE and ONLY VICE. They used to open by asserting, flatly and
; unconditionally, that "$D41B and $DC04 are both affine in the CPU clock" —
; and then retracted it four paragraphs later. A reader who stopped early
; got the wrong picture of the shipped generator, which is the failure mode
; a comment exists to prevent. The hardware picture is further down and it
; is the one that describes what runs on a C64.
;
; UNDER VICE the two hardware reads are not independent: $D41B (SID OSC3)
; and $DC04 (CIA1 timer A low) are there both affine in the CPU clock with
; OPPOSITE slopes — OSC3 counts up, TA counts down — so their sum
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
; EVERYTHING ABOVE IS THE VICE PICTURE. It is total degeneracy there because
; OSC3 is a clock-derived ramp rather than noise: VICE does not clock reSID
; with sound disabled.
;
; This paragraph used to go on to say that on real hardware "OSC3 IS noise, so
; the failure is not total -- but two operands that are affine in the same
; clock still carry far less entropy than they appear to". That was a guess,
; and it has since been measured and is wrong in both halves. On a real 6581/
; 8580 the two operands are NOT both affine in the CPU clock, and the sum
; does not cancel at any phase. The measurements are with entropy_state
; below; read them before acting on anything in this block.
;
; WHAT THE MECHANISM IS NOT. This block used to attribute that to "voice-3
; ctrl $88 (noise + TEST)". entropy_init forty lines above writes #$80 --
; noise with TEST CLEAR -- so $88 is not a value this program ever writes,
; and the sentence was self-refuting besides: freezing the oscillator to a
; single value and being an LFSR are opposite claims about the same
; register.
;
; The account that fits both the code and the measurement: with TEST clear
; and freq $FFFF, the noise waveform's 23-bit LFSR is clocked by the
; oscillator, and $D41B presents eight bits tapped off it. An LFSR's output
; is a pseudo-random function of how many times it has shifted, not an
; affine function of elapsed time, so osc + ta does not stay invariant --
; which is what "105 of 128 distinct S" below is measuring. VICE with sound
; disabled does not clock reSID at all, so nothing there advances that LFSR,
; and that is the only reason $D41B ever looked like a ramp.
;
; MARK THE STATUS OF THAT PARAGRAPH HONESTLY, because the sentence it
; replaces was confidently wrong: the NUMBERS below are measured, the
; mechanism above is the best available account of them and is not itself
; measured. Do not let it become the next thing quoted as established.
;
; Stirring a persistent byte in makes consecutive outputs stop being a
; function of S alone. DO NOT READ THAT AS "THE STIRRING FIXED THE
; DEGENERACY" -- it is true and it is not the property that matters. When S
; sits at a cancelling phase, K = osc EOR ta is constant and the recurrence
; is s <- (ROL s) EOR K, which is still a PURE FUNCTION OF THE SEED. All the
; rotate did was stop the output being one repeated byte, which is worse than
; nothing on its own: it took a visible failure signature and made it look
; like a stream. What actually protects the key is that the precondition does
; not hold on real hardware (see entropy_state below), not this instruction.
;
; XOR-ing the hardware reads on top is entropy-preserving, so this is
; strictly no worse anywhere. Costs ~8 cycles and one byte of RAM.
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
;
; That routing is the cfg's to state and has already moved once. Nothing
; about the $00 below depends on knowing it: what matters is only that the
; PRG image reaches this address, and the note on entropy_state gives the
; check that settles that for any layout.
.segment "APP_EXTRA_BSS"

; Persistent whitening state.
;
; ITS LOAD-TIME VALUE IS $00, ON EVERY RUN AND EVERY MACHINE. This comment
; used to claim the opposite -- "power-on value is whatever RAM held".
;
; THE CHECK, which is the durable form and the one to trust:
;
;   take entropy_state's address from build/wireguard.map, read the PRG's
;   2-byte load address, and the byte at file offset 2 + addr - load is what
;   LOAD writes to it.
;
; It reads $00 in every backend/REU combination. tools/test_entropy_seed.py
; performs exactly that computation on every run and asserts the value in RAM
; after boot matches it, so the claim cannot quietly stop being true.
;
; The mechanism, stated so it does not have to be re-stated: a PRG is a
; contiguous byte stream from its load address, so ANY address the image
; reaches gets written by LOAD. An address is reached when some enclosing
; memory area is file-backed and fill = yes -- and `type = bss` does not
; exempt it, because that marking only means ld65 emits no CONTENT of its
; own; the enclosing area's fill still covers the address. src/boot.s makes
; the same point about the low BSS.
;
; DELIBERATELY NOT NAMED HERE: which area that is. It has already changed
; once in this file's lifetime and again when #107 landed the overlay, so a
; comment naming the segment-to-area mapping would go false without anything
; in this module being edited -- as three comments in this file's history
; already have. If you are deciding whether some OTHER symbol is safe, do
; not reason from this paragraph --
; run the check above on that symbol. It is three lines of Python and it is
; the only form of this claim that cannot go stale.
;
; Because entropy_byte/entropy_fill feed this byte back into every output,
; and entropy_fill writes hs_ephem_priv in session_initiate, a fixed start
; means the whole ephemeral-key chain is deterministic in the hardware reads
; alone. In the cancelled phases described above that is not a weakening but
; a total loss: measured under VICE, 2.00% of 200 paired trials had
; entropy_fill produce output identical to the previous call from the same
; state. There are TWO such constants, not one -- K = osc EOR ta is fixed at
; both of the phases entropy_byte's note names, S = $ff and S = $7f -- and
; each yields its own machine-independent cycle, exactly as the recurrence
; predicts for s0 = $00:
;
;     K = $ff  (period 9)   ff 01 fc 07 f0 1f c0 7f 00
;     K = $7f  (period 18)  7f 81 7d 84 77 90 5f c0 ff
;                           80 7e 82 7b 88 6f a0 3f 00
;
; Those are GENERATION order. entropy_fill writes DESCENDING -- Y counts
; down -- so a buffer dump is the reverse, which is why the $ff case is
; measured as f0 07 fc 01 ff 00 7f c0 1f repeating and not as it reads
; above. Reproduce either with the recurrence
; s <- (ROL s) EOR K, carry-in = bit 7 of the pre-ROL s.
;
; entropy_init therefore mixes live machine state in here (issue #89). READ
; WHAT THAT DOES AND DOES NOT BUY. It removes the two UNIVERSAL constants:
; a cancelled output stops being one of 2 precomputable keys and becomes one
; of 2 * 256 = 512, since s0 is now a byte instead of $00. It does not change
; how OFTEN a cancellation happens -- under VICE, still 25/1500 = 1.67% of
; fills after the fix. 9 bits of ephemeral private key would be as fatal to
; WireGuard as 1 bit.
;
; BUT THE CANCELLATION IS A VICE ARTEFACT, NOT A HARDWARE DEFECT, and this
; comment would overstate in the other direction if it stopped above.
; Measured on a U64E (fw 3.15, BACKEND=uci REU=0, everything executed on the
; 6510), against the same code that shows it under VICE:
;
;                       VICE     HW 1 MHz    HW 48 MHz
;   distinct S /128        2         105          100
;   duplicate fills    4/200     0/3072       0/3072
;   universal keys   present    0/6144       0/6144
;
; S is statistically indistinguishable from uniform on metal; the 95% upper
; bound on the degenerate rate is 0.049%, which excludes VICE's 1-2% at about
; 1e-27. The cause is that voice-3 ctrl $80 -- noise, TEST CLEAR, which is
; what entropy_init writes -- makes $D41B a tap off the noise LFSR rather
; than a clock ramp, so it is NOT affine in the CPU clock. An earlier
; version of this sentence said $88 (noise + TEST); that value is never
; written here and freezing the oscillator would be the opposite of what
; makes this work. VICE with sound disabled does not clock reSID, which is
; the only reason it ever looked affine. The null result is trustworthy because the same run forced
; the condition -- a byte-identical entropy_fill with its two reads replaced
; by immediates XORing to a constant K -- and got 8/8 exact predicted
; universal keys, so the detector was proven to fire before the 0/6144 was
; believed.
;
; So: #89 was a real defect and this is a real fix -- the seed reaching
; hs_ephem_priv was $00 on every run, confirmed on hardware. What #89 does
; NOT do is fix the generator, and what the hardware says is that the
; generator's known weakness is not exploitable on a real C64. Issue #101
; stays open on design grounds (two sources that CAN cancel in principle,
; and only one of them is real entropy), not as a live exposure. Anyone
; reaching for it should read the hardware numbers above first.
;
; THE THIRD SOURCE, COSTED. #101 asks for a source that is not affine in the
; CPU clock at all, so that no phase can cancel even in principle. CIA1 TOD
; is the candidate. The obstacle is NOT the space budget, which is the thing
; everyone assumes and it was measured rather than assumed: adding
; `eor $dc08` to entropy_byte and to entropy_fill is +6 bytes in APP_EXTRA
; and ALL SIX release variants still link (2026-09-07, APP_EXTRA $166 ->
; $16C; APP_CODE is the area with one byte left, and this module is not in
; it).
;
; The obstacle is that under BACKEND=ip65 THE TOD IS NEVER STARTED.
; uci_tod_start lives in src/net/uci/ and is not linked into the ip65
; builds, and src/net/ip65/net.s spells out that giving that backend a TOD
; means duplicating a ~90-byte start-and-verify routine for a clock nothing
; else in the build uses. A stopped TOD reads a fixed value, so in the two
; shipped rrnet variants `eor $dc08` would XOR in a CONSTANT while looking
; from the source like a third independent source. That is worse than
; leaving it out: it is the same shape as every other trap in this repo,
; where the wrong answer looks like a right one, and a reader auditing the
; generator would count three sources and find two.
;
; So the honest form of the change is: start the TOD under ip65 too, then
; mix it in both backends, then verify on hardware that the mixed byte
; actually moves. The first and third of those are the work; the +6 bytes
; are not. Nobody should land the cheap two thirds on the grounds that they
; fit.
entropy_state:  .res 1
