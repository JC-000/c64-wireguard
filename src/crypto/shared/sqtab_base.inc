; =============================================================================
; src/crypto/shared/sqtab_base.inc — the §8.1 shared quarter-square table
; window. SINGLE SOURCE OF TRUTH for its base address.
;
; c64-lib-contract SPEC §8.1 forbids a library exporting
; LIB_SHARED_SQTAB_BASE, because the table is placed by an *equate*, not
; by a segment: no bytes are emitted into it, so ld65 does not know the
; region exists and cannot resolve an import against it. That leaves
; every consumer holding its own copy of the address — and v0.10.2 makes
; holding it in ONE shared include a MUST for exactly that reason: two
; copies can silently disagree, and then any guard checks a different
; window than the table actually occupies.
;
; Before this file, WG held SIX copies of $8000 across five files:
;   cfg/c64-wireguard-ip65.cfg  SQTAB_HOLE start
;   cfg/c64-wireguard-uci.cfg   SQTAB_HOLE start
;   src/exports.s               sqtab_lo / sqtab_hi (sibling build)
;   src/crypto/poly1305.s       sqtab_lo / sqtab_hi (in-tree build)
;   tools/integration/build_x25519.sh  -D LIB_SHARED_SQTAB_BASE=32768
; Nothing tied them together. Editing one and missing another would have
; pointed sqtab_init at a window the cfg does not reserve, so the table
; would be built straight over live code or data — silently, at boot,
; with no assemble error, link error or warning at any stage.
;
; Now: the two .s sites derive from here, the two cfgs are checked
; against here by the §6.7 asserts in src/contract_asserts.s, and the
; integration script PARSES this file for the value it passes to ca65
; rather than repeating it. Change the window here and nowhere else.
;
; Constraints on the value:
;   - PAGE-ALIGNED. sqtab_lo and sqtab_hi are each 256-entry tables read
;     with `lda tab,x` on secret indexes; a non-page-aligned base makes
;     that cross a page boundary and become data-dependent in timing.
;     The sibling asserts this on its side too.
;   - 1024 bytes must be RESERVED, not merely free. The cfgs carve
;     SQTAB_HOLE out as a real file-backed area so no segment can be
;     placed across it (and, per [[prg-file-gap-shift-hazard]], so the
;     PRG has no unpadded file gap that would shift every later byte).
; =============================================================================

.ifndef WG_SQTAB_BASE_INC
WG_SQTAB_BASE_INC = 1

; $8000-$83FF. Chosen to sit above MAIN_AREA_LO and below MAIN_AREA_HI,
; splitting WG's main region around the window.
WG_SQTAB_BASE   = $8000

; The two halves the tables occupy: low bytes of floor(n^2/4) at +$000,
; high bytes at +$200. Both are 512 bytes / 256 entries.
WG_SQTAB_LO     = WG_SQTAB_BASE
WG_SQTAB_HI     = WG_SQTAB_BASE + $0200
WG_SQTAB_SIZE   = $0400

.endif ; WG_SQTAB_BASE_INC
