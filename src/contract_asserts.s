; =============================================================================
; src/contract_asserts.s — link-time c64-lib-contract composition checks.
;
; Active only in the two-sibling build (USE_X25519_SIBLING=1 +
; USE_CHACHA_SIBLING=1; the Makefile enforces that the toggles match).
;
; Pins: c64-x25519 v0.11.2, c64-ChaCha20-Poly1305 v0.9.0.
;
; Contract obligations covered (SPEC v0.10.3, the latest tagged contract
; release; the siblings' own ledgers run through SPEC v0.10.6, which adds
; no obligation on this side — see the v0.11.2 notes):
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

; The §8.1 window base, single-sourced. §8.1 forbids the libraries
; exporting LIB_SHARED_SQTAB_BASE, so the consumer holds it — in exactly
; one place, per contract v0.10.2.
.include "crypto/shared/sqtab_base.inc"

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

; §6.6 footprint pairs, od65-measured on each library's side.
.import LIB_X25519_RESIDENT_BYTES, LIB_X25519_COLD_BYTES
.import LIB_CHACHA20_POLY1305_RESIDENT_BYTES, LIB_CHACHA20_POLY1305_COLD_BYTES

; §8.4 shared-table shape. All three fields are imported as of the
; v0.11.0 / v0.8.0 pins: contract v0.7.4 pins _REGION/_SHARED ": abs",
; which x25519 has carried since v0.10.0 and chacha picked up in v0.8.0
; (it shipped v0.7.0 against SPEC v0.7.2, where importing its _REGION /
; _SHARED as absolute drew an ld65 address-size mismatch warning — hence
; the earlier _SIZE-only import). Measured absolute on both sides at
; these tags before widening.
;
; Note this import form is only valid for tables <= $FFFF (contract #18):
; sqtab is 1024, but reu_mul at 131072 must never be imported this way —
; it exports 'far' and raises a range error here.
.import LIB_X25519_PRECALC_sqtab_SIZE
.import LIB_X25519_PRECALC_sqtab_REGION
.import LIB_X25519_PRECALC_sqtab_SHARED
.import LIB_CHACHA20_POLY1305_PRECALC_sqtab_SIZE
.import LIB_CHACHA20_POLY1305_PRECALC_sqtab_REGION
.import LIB_CHACHA20_POLY1305_PRECALC_sqtab_SHARED

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

; Region agreement. Both must place the table in the same §8.4 region
; class (1 = main RAM) — a table one library builds in the REU and the
; other reads from main RAM is the same silent-wrong-result failure as a
; size mismatch, and size alone would not catch it.
.assert LIB_X25519_PRECALC_sqtab_REGION = LIB_CHACHA20_POLY1305_PRECALC_sqtab_REGION, lderror, "linked libraries disagree on the shared §8.1 sqtab region — one builds the table where the other does not read it"

; Both sides must actually declare the table SHARED. If either ever
; reverts to a private table, the §8.0 masks would still look consistent
; while the two libraries silently maintained separate copies.
.assert LIB_X25519_PRECALC_sqtab_SHARED = 1, lderror, "x25519 no longer declares the §8.1 sqtab shared — the deferral in build_chacha20poly1305.sh has nothing to defer to"
.assert LIB_CHACHA20_POLY1305_PRECALC_sqtab_SHARED = 1, lderror, "chacha20poly1305 no longer declares the §8.1 sqtab shared — it would build a private table over x25519's"

; --- §1 ABI generation pins --------------------------------------------------
;
; Per-library now. The previous bare `LIB_ABI_VERSION` import read as an
; x25519 check but silently bound to whichever archive the linker reached
; first, since both libraries exported that same name.
;
; Contract v0.7.5 reclassified LIB_<X>_ABI_VERSION as a monotonic counter
; incremented on any breaking export change, independent of MAJOR. Both
; libraries are at generation 3 as of the phase-3 fleet wave, and both got
; there for reasons this repo had to act on rather than merely re-pin:
;
;   x25519  1 -> 2  v0.9.0 removed the LIB_SHARED_PRIMITIVES_* exports
;                   (v0.10.0 was the erratum that advanced the counter).
;           2 -> 3  v0.11.0: bare LIB_SHARED_REU_MUL_* un-exported in
;                   favour of the LIB_X25519_*-prefixed outputs (#92),
;                   the zp_ptr1/zp_tmp1/zp_tmp2 trio dropped from the
;                   export surface (#93), and poly_carry -> mul_carry —
;                   poly_ is chacha-registered under SPEC §2 (#95). The
;                   last two are what let src/exports.s stop describing
;                   an imaginary ZP fence and start relying on a real
;                   one; see its x25519 comment block.
;
;   chacha  1 -> 2  library issue #67, under the same v0.7.5 rule.
;           2 -> 3  v0.8.0: the four general-purpose ZP slots took the
;                   §2 registry prefix, so its TUs now .importzp
;                   chacha20poly1305_zp_* — names a consumer supplying
;                   the slots from its own zp_config (exactly WG) must
;                   export or fail to link. Under LIB_NO_BARE_EXPORTS
;                   the bare aliases are gone entirely.
;
; Both bumps are codegen-neutral upstream — each library re-verified its
; test PRG byte-identical across the rename — so no perf, CT or hardware
; result carried in this repo's docs needs re-measuring.
.assert LIB_X25519_ABI_VERSION = 3, lderror, "x25519 ABI generation != 3 — its exported surface changed; re-audit the integration before bumping this pin"
.assert LIB_CHACHA20_POLY1305_ABI_VERSION = 3, lderror, "chacha20poly1305 ABI generation != 3 — its exported surface changed; re-audit the integration before bumping this pin"

; --- §6.6 footprint fit ------------------------------------------------------
;
; Both libraries publish RESIDENT + COLD byte counts, od65-measured on
; their side. Assert the pair fits the regions WG gives them. The SPEC
; form is single-line, `lderror`, RESIDENT and COLD together, `<=`.
;
; WG splits each library across two areas — CODE/DATA into MAIN_AREA_LO,
; x25519's reclaimable INIT_CODE into MAIN_AREA_HI — so the honest
; consumer-side bound is the pair against the sum of the two areas. That
; is looser than a per-region check would be, and deliberately so: a
; tighter literal would have to encode WG's own code size, which changes
; on every commit and would turn this into a maintenance tax that gets
; disabled. What it does catch is the case it exists for — a sibling
; bump growing the libraries past the space WG has to give them.
;
; Measured at the v0.11.2 / v0.9.0 pins: 8383 + 826 (x25519) + 16640 + 0
; (chacha) = 25849 against $4D10 + $1C00 = 26896. 1047 bytes of headroom,
; which looks tighter than it is: RESIDENT_BYTES describes the whole
; archive, while ld65 pulls only the members actually referenced (chacha
; contributes 8448 B of _CODE + 295 B of _DATA to this link, not 16640).
; The assert is therefore conservative — it fails before the map does,
; which is the safe direction for a fit check, but do not read the
; headroom figure as WG's real remaining space.
.import __MAIN_AREA_LO_SIZE__, __MAIN_AREA_HI_SIZE__
.assert (LIB_X25519_RESIDENT_BYTES + LIB_X25519_COLD_BYTES + LIB_CHACHA20_POLY1305_RESIDENT_BYTES + LIB_CHACHA20_POLY1305_COLD_BYTES) <= (__MAIN_AREA_LO_SIZE__ + __MAIN_AREA_HI_SIZE__), lderror, "sibling libraries no longer fit MAIN_AREA_LO + MAIN_AREA_HI — a sibling bump grew past WG's budget; re-plan the memory map before re-pinning"

; --- §6.7 sqtab window guard (consumer mirror) -------------------------------
;
; The §8.1 sqtab is placed by an EQUATE, not a segment. Nothing is
; emitted into it, so ld65 does not know the region exists: absent these
; asserts, a memory map that disagrees with the equate links clean,
; passes every test that does not exercise Poly1305 after boot, and
; corrupts 1 KB of whatever it does overlap when sqtab_init runs. No
; assemble error, no link error, no warning at any stage. Both siblings
; added this guard for their own images (x25519 v0.11.1, chacha v0.9.0)
; and both name the consumer mirror as the consumer's own obligation —
; their guard TUs ship in no archive precisely because an .import of a
; consumer's area symbol would force every consumer to declare it.
;
; WG's exposure is narrower than the general case but not zero. Growth
; INTO the window is already a hard ld65 area-overflow, because
; MAIN_AREA_LO is bounded at $7FFF and SQTAB_HOLE is a real reserved
; area rather than a gap. What was unguarded is AGREEMENT: the cfg's
; window and WG_SQTAB_BASE were independent copies of $8000, and moving
; one without the other pointed sqtab_init outside the reservation.
.import __SQTAB_HOLE_START__, __SQTAB_HOLE_SIZE__
.assert __SQTAB_HOLE_START__ = WG_SQTAB_BASE, lderror, "cfg SQTAB_HOLE base disagrees with WG_SQTAB_BASE — sqtab_init would build the table outside the reserved window; reconcile cfg/c64-wireguard-*.cfg against src/crypto/shared/sqtab_base.inc"
.assert __SQTAB_HOLE_SIZE__ >= WG_SQTAB_SIZE, lderror, "cfg SQTAB_HOLE reserves less than the 1024 bytes sqtab_init writes"

; Image-overrun leg, for symmetry with the siblings' guard and to stay
; correct if MAIN_AREA_LO is ever resized: its last byte must stay below
; the window.
.import __MAIN_AREA_LO_LAST__
.assert __MAIN_AREA_LO_LAST__ <= WG_SQTAB_BASE, lderror, "image overruns the sqtab window — MAIN_AREA_LO now extends past WG_SQTAB_BASE"

.endif

; --- §13.8 network-backend capability fit (SPEC v0.12.0 §13.3 / §13.8) -------
;
; The selected backend publishes what it guarantees to move in one datagram
; (src/net/$(BACKEND)/net_caps.inc, via the Makefile -I path; §13.3). The
; consumer must size its receive buffer to the receive guarantee and keep
; its tunnel MTU inside the send guarantee; both are equates, so a backend
; swap or a capability bump that no longer fits fails here at assembly
; time. These are the §13.8 UDP-consumer asserts verbatim in shape, against
; WG's own size equates (a .res in another TU has no size ca65 can see).
; The send leg is also asserted inside the UCI adapter (src/net/uci/net.s)
; against its private queue constant — this is the backend-agnostic mirror.
.include "constants.inc"
.include "net_caps.inc"
.assert NET_UDP_SEND_MAX >= 1, error, "backend must publish NET_UDP_SEND_MAX (SPEC 13.3) — header defines but never sets it"
.assert NET_UDP_RECV_MAX >= 1, error, "backend must publish NET_UDP_RECV_MAX (SPEC 13.3) — header defines but never sets it"
.assert UDP_RECV_BUF_SIZE >= NET_UDP_RECV_MAX, error, "udp_recv_buf is smaller than the backend's NET_UDP_RECV_MAX — a full-size inbound datagram would overrun it"
.assert WG_MTU + WG_DATA_OVERHEAD <= NET_UDP_SEND_MAX, error, "WG_MTU + WG_DATA_OVERHEAD exceeds the backend's NET_UDP_SEND_MAX — outbound datagrams would be torn"
.assert WG_MTU + WG_DATA_OVERHEAD <= NET_UDP_RECV_MAX, error, "WG_MTU + WG_DATA_OVERHEAD exceeds the backend's NET_UDP_RECV_MAX — inbound datagrams would be truncated"
