; =============================================================================
; src/contract_asserts.s — link-time c64-lib-contract composition checks.
;
; Active only in the two-sibling build (USE_X25519_SIBLING=1 +
; USE_CHACHA_SIBLING=1; the Makefile enforces that the toggles match).
;
; Contract obligations covered (SPEC v0.4.1):
;   §3  REU bank budget — LIB_X25519_REU_BANKS_USED vs WG's own claims.
;   §8.0 shared-primitive ownership — x25519 owns §8.1 sqtab + §8.3
;       ct_mul_8x8 (+ §8.2 reu_mul under the REU profile); chacha defers
;       both its bits via SHARED_SQTAB_INIT / SHARED_CT_MUL_8X8.
;
; ONE-SIDED BY NECESSITY: both archives' manifest members export
; unprefixed common symbols (LIB_VERSION_*, LIB_ABI_VERSION, and — the
; one that actually fires — LIB_PRECALC_sqtab_{SIZE,REGION,SHARED}, both
; libraries describing the same shared table). Pulling both members into
; one link dies with "Duplicate external identifier", so only the x25519
; manifest is imported here; the chacha-side masks (REU_BANKS_USED=$00,
; SHARED_PRIMITIVES=$0000 after deferral) are verified numerically at
; archive-build time by tools/integration/build_chacha20poly1305.sh via
; od65. Contract §1/§5 gap; measured and reported upstream.
;
; NOTE: masks are combined with `&` (bitwise), NOT the SPEC snippets'
; `.and` — `.and` is boolean in ca65, which inverts the check's meaning
; for any two nonzero masks. Filed as c64-lib-contract issue #41.
; =============================================================================

.ifdef USE_X25519_SIBLING

.import LIB_X25519_REU_BANKS_USED
.import LIB_X25519_SHARED_PRIMITIVES
.import LIB_ABI_VERSION

; WG's own REU claims. The overlay store (bank 2, see
; crypto/shared/reu_layout.inc) is reserved-not-allocated: no code
; touches it yet, so it contributes no bits. Becomes nonzero the day the
; overlay dispatcher lands — at which point these asserts start guarding
; it against sibling bank moves for free.
WG_REU_BANKS_USED = $00

; Chacha's masks are $00/$0000 (zero REU DMA since v0.6.0; both shared-
; primitive bits deferred) — verified at build time, folded in here as
; constants so the WG-side budget still composes all three parties.
CHACHA_REU_BANKS_USED_BUILDTIME = $00

.assert (LIB_X25519_REU_BANKS_USED & WG_REU_BANKS_USED) = 0, lderror, "REU bank collision: x25519 vs WG"
.assert (LIB_X25519_REU_BANKS_USED & CHACHA_REU_BANKS_USED_BUILDTIME) = 0, lderror, "REU bank collision: x25519 vs chacha20poly1305"

; x25519 must own at least §8.1 sqtab ($0001) + §8.3 ct_mul_8x8 ($0004)
; in every profile WG builds (the §8.2 bit $0002 is profile-dependent:
; present under REU, absent under onchip).
.assert (LIB_X25519_SHARED_PRIMITIVES & $0005) = $0005, lderror, "x25519 no longer owns sqtab+ct_mul_8x8 — recheck the §8.0 composition"

.assert LIB_ABI_VERSION = 1, lderror, "x25519 LIB_ABI_VERSION != 1 — re-audit the integration against the new ABI"

.endif
