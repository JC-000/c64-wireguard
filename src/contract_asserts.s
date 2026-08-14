; =============================================================================
; src/contract_asserts.s — link-time c64-lib-contract composition checks.
;
; Active only in the two-sibling build (USE_X25519_SIBLING=1 +
; USE_CHACHA_SIBLING=1; the Makefile enforces that the toggles match).
;
; Pins: c64-x25519 v0.10.0, c64-ChaCha20-Poly1305 v0.7.0.
;
; Contract obligations covered (SPEC v0.7.x):
;   §1   per-library ABI generation pins.
;   §3   REU bank budget — x25519 vs chacha vs WG's own claims.
;   §8.0 shared-primitive ownership (disjointness), the v0.5.0 coverage
;        assert, and the per-library subset invariant.
;   §8.4 cross-library agreement on the shared sqtab's shape.
;
; TWO-SIDED AS OF THE v0.10.0 / v0.7.0 BUMP. Until then this file could
; only import the x25519 manifest: both archives exported unprefixed
; symbols (LIB_VERSION_*, LIB_ABI_VERSION, and — the one that actually
; fired — LIB_PRECALC_sqtab_{SIZE,REGION,SHARED}, both libraries
; describing the same shared table), so pulling both manifest members
; into one link died with "Duplicate external identifier". The chacha
; masks were hardcoded here as build-time constants and checked
; out-of-band by od65 in tools/integration/build_chacha20poly1305.sh.
; Contract v0.7.0 added library-prefixed manifest exports gated on
; LIB_NO_BARE_EXPORTS (we build both siblings with it), and v0.7.3
; stopped adopters exporting the §8.x bit constants. Both halves shipped,
; so the gap is CLOSED: every check below is now a real link-time
; assertion over both libraries' own numbers, with nothing hardcoded and
; nothing verified out-of-band.
;
; PROFILE-AGNOSTIC BY CONSTRUCTION. WG builds two x25519 profiles — the
; default REU profile (SHARED_PRIMITIVES = $0007) and the ONCHIP_MUL
; no-REU profile ($0005, no §8.2 reu_mul). Every assert below is
; *relational* — it compares the libraries' masks against each other
; rather than against a literal — so both profiles are covered by the
; same lines. The previous `& $0005 = $0005` ownership floor needed a
; comment explaining which bits were profile-dependent; the coverage
; assert subsumes it and needs no such carve-out.
;
; NOTE: masks are combined with `&` / `~` (bitwise), NOT the SPEC
; snippets' `.and` — `.and` is BOOLEAN in ca65, so `A .and B` is 1
; whenever both operands are nonzero, which inverts a disjointness
; check's meaning for any two nonzero masks. Filed and fixed upstream as
; c64-lib-contract issue #41 (SPEC v0.4.2), kept here as a standing
; warning for anyone copying a snippet out of the current SPEC.
; =============================================================================

.ifdef USE_X25519_SIBLING

; The Makefile refuses to build a mixed configuration, but this file is
; also assemblable by hand; fail loudly rather than silently checking
; half a composition.
.ifndef USE_CHACHA_SIBLING
    .error "contract_asserts.s: USE_X25519_SIBLING without USE_CHACHA_SIBLING — these checks describe the two-sibling composition and cannot verify half of it"
.endif

; --- §5 manifest surface, both libraries ------------------------------------
.import LIB_X25519_REU_BANKS_USED
.import LIB_X25519_SHARED_PRIMITIVES
.import LIB_X25519_SHARED_CONSUMES
.import LIB_X25519_ABI_VERSION

.import LIB_CHACHA20_POLY1305_REU_BANKS_USED
.import LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES
.import LIB_CHACHA20_POLY1305_SHARED_CONSUMES
.import LIB_CHACHA20_POLY1305_ABI_VERSION

; §8.4 shared-table shape. Only _SIZE is imported: contract v0.7.4 pins
; _REGION/_SHARED ": abs", which x25519 v0.10.0 carries but chacha v0.7.0
; (built against SPEC v0.7.2) does not — importing chacha's as absolute
; would emit an ld65 address-size mismatch warning. _SIZE is absolute on
; both sides. Note this import form is only valid for tables <= $FFFF
; (contract #18): sqtab is 1024, but reu_mul at 131072 must never be
; imported this way — it exports 'far' and raises a range error here.
.import LIB_X25519_PRECALC_sqtab_SIZE
.import LIB_CHACHA20_POLY1305_PRECALC_sqtab_SIZE

; --- §3 REU bank budget ------------------------------------------------------
;
; WG's own REU claims. The overlay store (bank 2, see
; crypto/shared/reu_layout.inc) is reserved-not-allocated: no code
; touches it yet, so it contributes no bits. Becomes nonzero the day the
; overlay dispatcher lands — at which point these asserts start guarding
; it against sibling bank moves for free.
WG_REU_BANKS_USED = $00

.assert (LIB_X25519_REU_BANKS_USED & WG_REU_BANKS_USED) = 0, lderror, "REU bank collision: x25519 vs WG's own claims — relocate via -D X25519_REU_BANK or move WG's overlay bank"
.assert (LIB_CHACHA20_POLY1305_REU_BANKS_USED & WG_REU_BANKS_USED) = 0, lderror, "REU bank collision: chacha20poly1305 vs WG's own claims"
.assert (LIB_X25519_REU_BANKS_USED & LIB_CHACHA20_POLY1305_REU_BANKS_USED) = 0, lderror, "REU bank collision: x25519 vs chacha20poly1305 — one of them must be rebased via its -D bank override"

; --- §8.0 shared-primitive ownership ----------------------------------------
;
; Disjointness: no primitive may be owned by both libraries. A deferring
; build drops the bit, so a correctly-composed pair is always disjoint.
.assert (LIB_X25519_SHARED_PRIMITIVES & LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES) = 0, lderror, "shared-primitive double-ownership: x25519 and chacha20poly1305 both claim the same §8 primitive — exactly one provider must be built without that primitive's SHARED_* switch"

; Coverage (SPEC v0.5.0): every primitive either library CONSUMES must be
; OWNED by someone in the link. This is the load-bearing one for our
; composition: chacha defers BOTH §8.1 sqtab and §8.3 ct_mul_8x8 to
; x25519, so if an x25519 profile change ever drops an ownership bit that
; chacha still consumes, the table would be read with no init having run —
; a silent wrong result. This turns that into a named link error.
.assert ((LIB_X25519_SHARED_CONSUMES | LIB_CHACHA20_POLY1305_SHARED_CONSUMES) & ~(LIB_X25519_SHARED_PRIMITIVES | LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES)) = 0, lderror, "consumed shared primitive with no owner in the link — chacha defers sqtab+ct_mul_8x8 to x25519; check that the x25519 profile still owns them (a build with that primitive's SHARED_* switch defined provides nothing)"

; Subset invariant (SPEC v0.5.0): a build cannot own a primitive it does
; not consume. Adopters assert this internally; re-checking it here costs
; nothing and catches a malformed manifest at integration time.
.assert (LIB_X25519_SHARED_PRIMITIVES & ~LIB_X25519_SHARED_CONSUMES) = 0, lderror, "x25519 manifest is malformed: owns a §8 primitive it does not declare as consumed"
.assert (LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES & ~LIB_CHACHA20_POLY1305_SHARED_CONSUMES) = 0, lderror, "chacha20poly1305 manifest is malformed: owns a §8 primitive it does not declare as consumed"

; --- §8.4 shared-table shape agreement ---------------------------------------
;
; Both libraries describe the same §8.1 sqtab. If they ever disagree on
; its size, one of them reads a table built to the other's shape — the
; failure the §8.4 prefixed exports were introduced to make checkable
; (this repo filed it as c64-lib-contract #43; before the prefixes both
; libraries emitted one symbol name, so there was nothing to compare).
.assert LIB_X25519_PRECALC_sqtab_SIZE = LIB_CHACHA20_POLY1305_PRECALC_sqtab_SIZE, lderror, "linked libraries disagree on the shared §8.1 sqtab size — the deferring library would read a table built to a different shape"

; --- §1 ABI generation pins --------------------------------------------------
;
; Per-library now. The previous bare `LIB_ABI_VERSION` import read as an
; x25519 check but silently bound to whichever archive the linker reached
; first, since both libraries exported that same name.
;
; x25519 is at generation 2: contract v0.7.5 reclassified LIB_<X>_ABI_VERSION
; as a monotonic counter incremented on any breaking export change,
; independent of MAJOR, and v0.9.0's removal of the LIB_SHARED_PRIMITIVES_*
; exports qualified. v0.10.0 is the erratum that advanced the counter — no
; code change, PRG byte-identical to v0.8.0/v0.9.0.
.assert LIB_X25519_ABI_VERSION = 2, lderror, "x25519 ABI generation != 2 — its exported surface changed; re-audit the integration before bumping this pin"
.assert LIB_CHACHA20_POLY1305_ABI_VERSION = 1, lderror, "chacha20poly1305 ABI generation != 1 — its exported surface changed; re-audit the integration before bumping this pin"

.endif
