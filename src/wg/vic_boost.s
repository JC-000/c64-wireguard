; =============================================================================
; src/wg/vic_boost.s — reclaim VIC-II badline cycles around long crypto.
;
; WHAT IT BUYS: 6.3%, measured. Not the "~20-25%" the c64-x25519 header
; quotes for its own vic_blank — that figure does not hold for a plain text
; screen with no sprites, which is what WG runs.
;
; Measured with tools/bench_vic_blank.py (CIA1 TOD, emulated time, NTSC):
;   blake2s_compress  1.068x     fe25519_mul   1.068x
;   chacha20_block    1.068x     fe25519_sqr   1.067x
;   poly1305_block    1.068x     x25519_scalarmult 1.066x
; Uniform across every routine, which is the signature of a pure
; cycle-availability effect rather than a cache or layout artefact.
;
; It matches first-principles arithmetic exactly, which is why we trust it:
; NTSC is 65 cycles x 262 lines = 17030 cycles/frame, and 25 text rows mean
; 25 badlines/frame at ~43 stolen cycles each = 1075/17030 = 6.31%.
; Sprites would add more (WG uses none), and a bitmap mode more again —
; that is the likely origin of the 20-25% figure.
;
; WHY WG OWNS THESE 8 BYTES rather than importing the sibling's vic_blank:
; the in-tree build (USE_X25519_SIBLING=0) links no sibling archive, so an
; import would need an .ifdef at every call site and would silently do
; nothing in that configuration. Costing eight bytes to keep all four build
; configurations behaving identically is the right trade.
;
; DISPLAY POLICY: blanking is scoped to individual crypto operations, never
; held across the whole handshake. The handshake is ~20 minutes and prints
; progress as it goes; a user staring at a black screen for that long has
; no way to tell a working session from a hung one. Each wrapper restores
; the display before returning, so the UI between operations is unaffected
; and only the compute windows are dark.
;
; NOT WIRED INTO BOOT, deliberately. The obvious second site is the
; sqtab_init + reu_mul_init pair in src/boot.s — the longest single stretch
; of compute in the program, with no output to hide. It is left alone
; because that path currently does not complete under VICE with an REU
; attached (`-reu -reusize 512`): the PC pins inside the x25519 init code
; and `sqtab_ready` stays 0 after 240 s of undisturbed emulation. That
; predates this file — it reproduces identically with these wrappers
; removed — and is invisible today because title_msg (which contains
; "Q=QUIT") prints BEFORE the hang, so every suite's wait_for_text
; succeeds and then drives the crypto by direct jsr, never depending on
; boot finishing.
;
; Blanking there would convert a title screen that merely looks idle into
; a permanently black one. Wire it up once that hang is understood, not
; before.
;
; The screen CONTENTS survive blanking untouched — DEN=0 stops the VIC
; fetching, it does not clear video RAM — so the display returns exactly as
; it was, with no repaint needed.
; =============================================================================

.include "constants.inc"

.export vic_boost_begin, vic_boost_end

.segment "APP_CODE"

; -----------------------------------------------------------------------------
; vic_boost_begin — clear DEN ($D011 bit 4), blanking the display.
; Clobbers: A. Preserves X, Y and every other bit of $D011 (the raster
; high bit and the Y-scroll live in the same register).
; -----------------------------------------------------------------------------
.proc vic_boost_begin
        lda vic_ctrl1
        and #$ef                ; DEN = 0
        sta vic_ctrl1
        rts
.endproc

; -----------------------------------------------------------------------------
; vic_boost_end — set DEN, restoring the display.
; Clobbers: A. Preserves X, Y.
;
; Sets the bit rather than restoring a saved copy deliberately: WG never
; blanks for any other reason, so there is no prior blanked state to
; preserve, and a saved-value approach would leave the screen dark forever
; if begin/end ever got unbalanced by an early return.
; -----------------------------------------------------------------------------
.proc vic_boost_end
        lda vic_ctrl1
        ora #$10                ; DEN = 1
        sta vic_ctrl1
        rts
.endproc
