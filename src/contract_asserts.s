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

;  §6.6 footprint pairs, od65-measured on each library's side. Used by the
; §6.6b declared-vs-linked checks below — but note the .import is itself
; load-bearing even before any assert reads the value: an .import is a
; link-time REQUIREMENT that the symbol exist, so a manifest TU that is
; restructured, renamed or dropped upstream becomes an unresolved external
; here rather than a silently absent guard. That is the same mechanism the
; §8.1 presence check below relies on. Do not remove these imports on the
; grounds that "nothing reads them" without removing the requirement too.
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

; Deferral DIRECTION is NOT asserted here, deliberately. Today every
; deferral runs chacha -> x25519 (chacha's SHARED_PRIMITIVES is $00,
; MEASURED at the v0.11.0 pin), and that one-directional shape is what lets
; a single §8.1 import close the archive-order problem below. A `.assert
; LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = 0` was written for this spot and
; then REMOVED: tools/integration/build_chacha20poly1305.sh already refuses
; to produce the archive when that mask is non-zero, and MEASURED it fires
; strictly earlier — at archive-build time, before ld65 runs at all, so the
; link-time assert could never be reached. The link-order consequence is
; recorded on that check's message instead.

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
.assert LIB_X25519_ABI_VERSION = 4, lderror, "x25519 ABI generation != 4 — its exported surface changed; re-audit the integration before bumping this pin"
.assert LIB_CHACHA20_POLY1305_ABI_VERSION = 4, lderror, "chacha20poly1305 ABI generation != 4 — its exported surface changed; re-audit the integration before bumping this pin"

; --- §6.6 linked-footprint ratchet ------------------------------------------
;
; WHAT THIS IS NOT. It is not a fit check. Fit is already owned, twice and
; more precisely: ld65 errors on a segment overflowing its memory area, and
; §6.7's `__MAIN_AREA_LO_LAST__ <= WG_SQTAB_BASE` below fires 944 B (uci
; REU=0) into growth. Any "sum of these segments <= |MAIN_AREA_LO| +
; |MAIN_AREA_HI|" check is a TAUTOLOGY — every segment counted is placed by
; the cfg inside one of those two areas, so a successful placement implies
; it. MEASURED: +1000 B into LIB_X25519_CODE leaves such a sum passing while
; §6.7 fires; it only trips at about +14600 B, long after ld65 has warned.
; The previous form of this block was that tautology, applied to the
; libraries' archive-wide RESIDENT/COLD equates rather than to linked bytes.
; It was removed rather than repaired.
;
; WHAT IT IS. A ratchet on the bytes ld65 ACTUALLY PULLED from each sibling
; archive, read off the `define = yes` segment sizes. The property guarded
; is "each library segment was really linked, at the size we measured when
; we pinned this version" — the property the v0.16.0 bump broke. There, the
; §8.1 group moved into a new archive member `sqtab_init.o` that nothing
; extracted on ld65's single scan of x25519.a; the consumer-visible symptom
; was an unresolved external, but the same class of upstream reorganisation
; can just as easily drop a member SILENTLY and shrink the image.
;
; WHY EXACT, NOT A BAND. These four numbers are a function of exactly two
; things: the pinned library versions and the REU profile. MEASURED across
; the clean four-profile matrix, all four are byte-identical between
; BACKEND=uci and BACKEND=ip65 — the libraries are built by their own
; Makefiles and WG's CA65FLAGS (WG_MTU1440, UCI_CHUNKED_WRITE, the backend
; source set) do not reach them. So there is no routine churn for a band to
; absorb: any movement at all is either a pin bump or a change in which
; members WG's code causes to be extracted, and BOTH are things a human
; should look at. A band would only buy room to miss a small regression.
;
; RE-MEASURING. When a pin bump legitimately moves a number, do not widen
; a tolerance — rebuild all four profiles and read the new values from the
; `Segment list` of build/wireguard.map:
;   for B in uci ip65; do for R in 0 1; do make clean; make BACKEND=$B REU=$R
;     && grep -E '^LIB_(X25519|CHACHA20_POLY1305)_' build/wireguard.map; done; done
; The two backends must agree; if they do not, that is itself the finding.
;
; BEFORE CONCLUDING A PIN BUMP MOVED A NUMBER, rule out the two things that
; move all five at once and have nothing to do with the pins: a DIFFERENT
; CC65 VERSION (measured with ca65/ld65 V2.18; README.md pins none), and a
; DIRTY libs/ submodule tree, which force-rebuilds the archives from edited
; sources. Both present as several of these asserts firing together with
; messages that point at the pins — the wrong diagnosis. Check `cl65
; --version` and `git -C libs/x25519 status` first.
;
; Values below MEASURED 2026-09-06 at the x25519 v0.16.0 / chacha v0.11.0
; pins, all four profiles, one clean matrix run.
.import __LIB_CHACHA20_POLY1305_CODE_SIZE__, __LIB_CHACHA20_POLY1305_DATA_SIZE__
.import __LIB_X25519_CODE_SIZE__, __LIB_X25519_DATA_SIZE__, __LIB_X25519_INIT_CODE_SIZE__

; chacha is REU-free on every path (its LIB_CHACHA20_POLY1305_REU_BANKS_USED
; is $00), so its two segments do not vary with the profile.
.assert __LIB_CHACHA20_POLY1305_CODE_SIZE__ = 8448, lderror, "LIB_CHACHA20_POLY1305_CODE is not the 8448 bytes measured at the v0.11.0 pin — the bytes ld65 pulled from chacha20poly1305.a changed; if a pin bump moved it, re-measure all four profiles off build/wireguard.map and update src/contract_asserts.s §6.6"
.assert __LIB_CHACHA20_POLY1305_DATA_SIZE__ = 295, lderror, "LIB_CHACHA20_POLY1305_DATA is not the 295 bytes measured at the v0.11.0 pin — see §6.6 re-measuring note"

; x25519's DATA segment is the mul tables; it loads into LOADER, not
; MAIN_AREA_*, and is the same 3584 B in both profiles (the REU profile
; moves table USE into REU banks, not the resident copy).
.assert __LIB_X25519_DATA_SIZE__ = 3584, lderror, "LIB_X25519_DATA is not the 3584 bytes measured at the v0.16.0 pin — see §6.6 re-measuring note"

.ifdef WG_NO_REU
; X25519_ONCHIP_MUL profile.
.assert __LIB_X25519_CODE_SIZE__ = 3474, lderror, "LIB_X25519_CODE is not the 3474 bytes measured for the onchip profile at the v0.16.0 pin — see §6.6 re-measuring note"
.assert __LIB_X25519_INIT_CODE_SIZE__ = 160, lderror, "LIB_X25519_INIT_CODE is not the 160 bytes measured for the onchip profile at the v0.16.0 pin — at this profile sqtab_init.o is its ONLY contributor, so a value of 0 means that member was never extracted from x25519.a: check the ld65 archive order in the Makefile before anything else"
.else
; REU profile.
.assert __LIB_X25519_CODE_SIZE__ = 3746, lderror, "LIB_X25519_CODE is not the 3746 bytes measured for the REU profile at the v0.16.0 pin — see §6.6 re-measuring note"
.assert __LIB_X25519_INIT_CODE_SIZE__ = 947, lderror, "LIB_X25519_INIT_CODE is not the 947 bytes measured for the REU profile at the v0.16.0 pin — 787 specifically means sqtab_init.o (160 B) was not extracted from x25519.a while x25519_init.o was: check the ld65 archive order in the Makefile"
.endif

; --- §6.6b declared footprint vs linked footprint ----------------------------
;
; The §5 RESIDENT/COLD equates are the libraries' own od65-measured
; declaration of their archive-wide footprint. Nothing in a link forces them
; to be truthful, and upstream has shipped them wrong before — x25519's
; v0.16.0 notes record RESIDENT_BYTES literals sitting 39-295 B BELOW the
; real segment totals in earlier releases. A declaration that under-states
; the archive is what makes a consumer's own planning arithmetic unsafe.
;
; So the equates get a real use rather than a dangling .import: whatever
; ld65 pulled must fit inside what the library declared. This is a genuine
; one-directional bound, not a tautology — the link does not compute these
; equates, it reads them from the manifest TU.
;
; MEASURED at these pins (declared vs linked): x25519 8234 vs 7058 onchip,
; 8506 vs 7330 REU; chacha 17664 vs 8743 both. x25519's COLD equate tracks
; INIT_CODE exactly (160 / 947), so that leg is asserted `=`, not `>=`.
.assert LIB_X25519_RESIDENT_BYTES >= (__LIB_X25519_CODE_SIZE__ + __LIB_X25519_DATA_SIZE__), lderror, "x25519 declares fewer RESIDENT_BYTES than its segments contribute to this link — the library's manifest under-states its own archive; do not plan memory against it"
; EQUALITY HERE IS DELIBERATE, AND IT ASSERTS A WG PROPERTY, NOT A LIBRARY
; ONE. COLD_BYTES is an archive-wide declaration; __LIB_X25519_INIT_CODE_SIZE__
; is what THIS link pulled. `>=` is the relation that follows from linked
; being a subset of archive — which is why chacha's leg above uses it. They
; are equal here only because WG references every one of x25519's cold
; members, and that invariant is itself worth knowing about: if upstream
; adds a cold routine WG never calls, this fires, and the correct reading is
; "WG no longer extracts all of x25519's cold init" — NOT "the manifest is
; wrong". Relax to `>=` if that stops being interesting. (The one-byte
; manifest mutation used to prove this leg fires would fire under `>=` too,
; so it is evidence the leg is live, not evidence for equality.)
.assert LIB_X25519_COLD_BYTES = __LIB_X25519_INIT_CODE_SIZE__, lderror, "x25519 declares more COLD_BYTES than LIB_X25519_INIT_CODE contributes to this link — most likely WG no longer references every one of x25519 cold members (upstream added cold code we do not call), not a malformed manifest; see the note above before editing the library"
; INERT AT CURRENT PINS — READ THIS BEFORE COUNTING IT AS PROTECTION.
; chacha declares 17664 RESIDENT_BYTES and contributes 8743 B to this link,
; so this assert carries 8921 B of slack (MEASURED, all four profiles) and
; cannot fire on any realistic movement. It is the mild form of the
; tautology deleted above and is kept for ONE reason only: it gives
; LIB_CHACHA20_POLY1305_RESIDENT_BYTES a reader, so the .import stays and
; the equate is still REQUIRED to exist at link time. The guard that
; actually protects chacha's linked size is the pair of exact asserts on
; __LIB_CHACHA20_POLY1305_CODE_SIZE__ / _DATA_SIZE__ above. Do not treat
; this line as a second layer; it is a hook for the import, nothing more.
; (x25519's equivalent below is NOT inert in the same way — its COLD leg is
; asserted `=` and MEASURED firing on a one-byte manifest error.)
.assert LIB_CHACHA20_POLY1305_RESIDENT_BYTES >= (__LIB_CHACHA20_POLY1305_CODE_SIZE__ + __LIB_CHACHA20_POLY1305_DATA_SIZE__), lderror, "chacha20poly1305 declares fewer RESIDENT_BYTES than its segments contribute to this link — the library's manifest under-states its own archive"
.assert LIB_CHACHA20_POLY1305_COLD_BYTES = 0, lderror, "chacha20poly1305 now declares a non-zero COLD_BYTES — it has gained a reclaimable cold region WG does not place; re-audit the memory map"

; --- §6.6c §8.1 group presence, directly ------------------------------------
;
; UNREACHABLE WHILE THE RATCHET STANDS — do not count these two asserts as
; protection. Any relocation of the 160 B §8.1 group moves two of the exactly
; ratcheted sizes ~40 lines above, and ld65 reports only its first error, so
; the ratchet fires first. MEASURED both ways: moving the group between
; segments trips the ratchet at both REU settings, and trips §6.6b's COLD
; leg even with the ratchet constants relaxed. They are kept because the
; `.import` below IS load-bearing and these are what stop it being deleted
; as unused.
;
; Both legs compare mul_tables_init, a RUN address, against
; __LIB_X25519_INIT_CODE_LOAD__. That is only correct because the segment
; has no `run =` in either cfg, so LOAD and RUN coincide. If one is ever
; added, switch to __LIB_X25519_INIT_CODE_RUN__ or this fails bafflingly.
;
; `mul_tables_init` is the c64-lib-contract §8.1 canonical entry. It must
; exist, and it must live inside LIB_X25519_INIT_CODE — if it ever resolved
; to some other segment, boot.s's cold-init reclaim would be zeroing over a
; live routine, or leaving a cold one resident.
;
; THE IMPORT IS THE POINT. contract_asserts.o is passed to ld65 BEFORE any
; archive, so this .import is a pending undefined symbol when x25519.a is
; first scanned — which FORCES sqtab_init.o to be extracted on that pass.
; That is what makes the link order-independent. At the v0.16.0 pin the §8.1
; group moved out of mul_8x8.o into its own archive member that nothing in
; x25519's own pulled-in members references; ld65 scans an archive once, in
; command-line order, so chacha's poly1305_lib.o then imported a symbol from
; an archive already behind the read head. MEASURED: with this .import
; present the link is clean both with and without the Makefile's defensive
; re-listing of x25519.a.
.import mul_tables_init
.import __LIB_X25519_INIT_CODE_LOAD__
.assert mul_tables_init >= __LIB_X25519_INIT_CODE_LOAD__, lderror, "mul_tables_init resolved below LIB_X25519_INIT_CODE — the §8.1 entry is not in x25519's cold-init segment; boot.s's reclaim would zero the wrong span"
.assert mul_tables_init < (__LIB_X25519_INIT_CODE_LOAD__ + __LIB_X25519_INIT_CODE_SIZE__), lderror, "mul_tables_init resolved above LIB_X25519_INIT_CODE — the §8.1 entry is not in x25519's cold-init segment; boot.s's reclaim would leave it resident or zero a live routine"

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

; --- APP_CODE alignment cliff (an ERROR since the margin went single-digit) ---
; LIB_CHACHA20_POLY1305_CODE follows APP_CODE in MAIN_AREA_LO with
; align = $100 (a constant-time requirement, see the cfg). So APP_CODE
; growing past the next page boundary does not cost the bytes it grew by:
; it costs a whole page, because every later MAIN_AREA_LO segment moves up
; $100 at once. That has happened silently before (#103: 3 bytes of growth
; overran $7FFF by 42). The boundary is measured, not remembered: it is
; wherever the chacha archive currently lands, $4900 as of #87.
;
; NO HEADROOM FIGURE IS QUOTED HERE ANY MORE, deliberately. The margin is a
; function of every commit that touches APP_CODE, so a number written into
; this comment is stale almost immediately — it said "20 B in every build"
; while the branch tip was at 3. Read it off a build instead:
;   make BACKEND=uci REU=0 && python3 -c "import re;d=dict(re.findall(r'al C:([0-9A-F]+) \.(__APP_CODE_(?:RUN|SIZE)__)',open('build/labels.txt').read())[::-1]);print(0x4900-sum(int(k,16) for k in d))"
; Two data points, both MEASURED 2026-09-06 on ca65/ld65 V2.18, identical
; across uci/ip65 and REU 0/1: 20 B at the library-bump commit, 3 B at the
; branch tip once the acceptance tests landed.
;
; WHY lderror NOW, WHERE IT WAS ldwarning. MEASURED at uci REU=0, injecting
; into APP_CODE: +21 B trips this assert and nothing else, and costs a whole
; page — §6.7 headroom drops 944 -> 688 in one step. It stays warning-only
; through +300 (432 left) and +700 (176 left); the first HARD failure is
; around +1000 B, where §6.7's `__MAIN_AREA_LO_LAST__ <= WG_SQTAB_BASE`
; errors and ld65 also reports CRYPTO_BSS overflowing MAIN_AREA_LO by 42.
; So across roughly 750 bytes of growth this warning is the ONLY signal, and
; it is not dominated by anything. A warning is fine when the margin is 20 B
; and a page is cheap; at 3 B, with 688 B of §6.7 headroom at REU=1, one
; unnoticed page is 37 % of the remaining slack and the warning would be
; scrolled past exactly when it matters.
;
; A DELIBERATE shift is still perfectly allowed — it now costs one edit: move
; the $4900 constant to wherever the chacha archive lands and say why in the
; commit. That is the "measured, not remembered" rule doing its job, not an
; obstacle. If you would rather have the old behaviour back, changing the one
; word `lderror` to `ldwarning` restores it exactly.
.import __APP_CODE_RUN__, __APP_CODE_SIZE__
.assert __APP_CODE_RUN__ + __APP_CODE_SIZE__ <= $4900, lderror, "APP_CODE crossed the chacha align: every later MAIN_AREA_LO segment just moved up a whole page, costing 256 B of MAIN_AREA_LO for however many bytes you added. Either shrink APP_CODE back under $4900, or move this constant deliberately to wherever LIB_CHACHA20_POLY1305_CODE now lands (read it off build/wireguard.map) and record the page in the commit message"

.endif

; --- APP_BSS_OVERLAY guard (issue #103) --------------------------------------
;
; APP_BSS_OVERLAY ($8800-$9FFF) is the same RAM as the top of MAIN_AREA_HI,
; described a second time so APP_BSS can be laid over LIB_X25519_INIT_CODE —
; 826 bytes of cold init that is dead the moment src/boot.s's table build
; returns, and which boot.s then zeroes so the span is ordinary BSS.
;
; ld65 catches the two size failures on its own (either side going over is a
; plain area overflow). What it CANNOT catch is the overlap being wrong,
; because it does not know the two regions describe the same bytes: it will
; happily link an image where live file content extends past $8800 and is
; then erased at boot, or where the regions have drifted apart and there is a
; hole between them. Both fail silently on the C64 — data quietly turning to
; zeros a few hundred thousand cycles into the boot is about the least
; debuggable failure this program could have. Hence lderror, here, rather
; than a comment stating the boundary — the defect class issue #103 exists to
; stop (cf. the "~1.9 KB free" comment this change deletes).
;
; APP_DATA is the last LIVE file-emitting segment in MAIN_AREA_HI in every
; configuration — including USE_X25519_SIBLING=0, where the archive is not
; linked at all and LIB_X25519_INIT_CODE does not exist. So the boundary
; check is anchored on APP_DATA's end, not on the cold segment's load
; address: keying it to the cold segment would make the one safety property
; here evaporate in exactly the build that has no cold segment to reclaim.
.import __MAIN_AREA_HI_START__, __MAIN_AREA_HI_SIZE__
.import __APP_BSS_OVERLAY_START__, __APP_BSS_OVERLAY_SIZE__
.import __APP_DATA_LOAD__, __APP_DATA_SIZE__

; The live constraint is APP_DATA's end against __APP_BSS_OVERLAY_START__
; ($8800), NOT MAIN_AREA_HI free: APP_DATA growth spends overlay slack, so
; the MAIN_AREA_HI figure stays put while this shrinks. Re-read the current
; margin rather than trusting a number written here — build, then
; $8800 minus (__APP_DATA_LOAD__ + __APP_DATA_SIZE__) from build/labels.txt.
; A dated data point, not a live claim: 47 B at 2380165 (2026-09-07) —
; identical in uci and ip65, REU=0 and REU=1. The margin is small enough
; that a single ordinary string addition can eat most of it, so re-read it
; rather than assuming this number still holds.
.assert __APP_DATA_LOAD__ + __APP_DATA_SIZE__ <= __APP_BSS_OVERLAY_START__, lderror, "live MAIN_AREA_HI file content (APP_EXTRA/APP_DATA) has grown past the APP_BSS_OVERLAY boundary — APP_BSS is laid over that RAM and boot.s's cold-segment zero-fill would erase part of it at boot; raise APP_BSS_OVERLAY's start in cfg/c64-wireguard-*.cfg (which costs APP_BSS the same number of bytes) or move data back to MAIN_AREA_LO"

; The overlay must be a SUBSET of MAIN_AREA_HI and must end with it. A gap at
; the top would strand RAM no region owns; an overlay extending past $9FFF
; would put APP_BSS in the ip65 blob's BSS ($A000-$AF3F, measured from
; ip65-build/ip65-c64.map) — issue #80 in the other direction.
.assert __APP_BSS_OVERLAY_START__ >= __MAIN_AREA_HI_START__, lderror, "APP_BSS_OVERLAY starts below MAIN_AREA_HI — it is meant to overlay the top of that region, not extend it downward into the sqtab window"
.assert __APP_BSS_OVERLAY_START__ + __APP_BSS_OVERLAY_SIZE__ = __MAIN_AREA_HI_START__ + __MAIN_AREA_HI_SIZE__, lderror, "APP_BSS_OVERLAY and MAIN_AREA_HI no longer end together — either APP_BSS runs past $9FFF into the ip65 blob's BSS, or the top of MAIN_AREA_HI is stranded with no segment able to use it"

; The rest only exists when the x25519 archive is in the link. Under
; USE_X25519_SIBLING=0 the segment is `optional = yes` and empty, so
; ld65 defines none of its symbols and importing them is an unresolved
; external, not a satisfied assert.
.ifdef USE_X25519_SIBLING
.import __LIB_X25519_INIT_CODE_LOAD__, __LIB_X25519_INIT_CODE_SIZE__

; ADJACENCY, not ordering. The cold segment must start at exactly the byte
; after APP_DATA ends.
;
; `>=` was not enough, and the hole is worth spelling out because it is
; invisible: a NEW file-emitting segment declared BETWEEN APP_DATA and
; LIB_X25519_INIT_CODE satisfies every other assert in this block while
; putting live data on top of APP_BSS. Demonstrated with a 200-byte probe
; segment in a scratch cfg:
;
;   APP_DATA              008536  0087A0
;   PROBE_HI              0087A1  008868   <- 105 live bytes above $8800
;   APP_BSS               008800  009F72   <- hs_c / hs_h underneath them
;   LIB_X25519_INIT_CODE  008869  008BA2
;   ld65 exit = 0, no assert, no warning
;
; The boundary check above is anchored on APP_DATA's end, so it only sees
; APP_DATA; the check below only sees the cold segment's own extent. With
; `>=`, everything in between is unexamined. Requiring the two to abut
; means any segment inserted there displaces the cold segment and fails
; here, which is the whole point of this block: the invariant must not
; depend on someone remembering the ordering rule in the cfg comment.
.assert __LIB_X25519_INIT_CODE_LOAD__ = __APP_DATA_LOAD__ + __APP_DATA_SIZE__, lderror, "LIB_X25519_INIT_CODE no longer starts immediately after APP_DATA — a file-emitting segment has been inserted between them (or after the cold segment), so live data now sits inside the span boot.s zeroes at the end of the table build. The cold segment must be the LAST file-emitting segment in MAIN_AREA_HI and must abut APP_DATA; route the new segment to MAIN_AREA_LO, or place it before APP_DATA and re-check the APP_BSS_OVERLAY boundary above"
.assert __LIB_X25519_INIT_CODE_LOAD__ + __LIB_X25519_INIT_CODE_SIZE__ <= __APP_BSS_OVERLAY_START__ + __APP_BSS_OVERLAY_SIZE__, lderror, "LIB_X25519_INIT_CODE runs past the end of APP_BSS_OVERLAY — boot.s would zero bytes outside the region the overlay reclaims"
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

; --- handshake AEAD write extent (issue: ignored aead_encrypt status) --------
;
; transport_encrypt checks aead_encrypt's status byte; handshake.s:507 and
; :609 deliberately do not, and this records WHY that split is correct
; rather than lucky. At handshake.s:493-501 and :595-602 all four AEAD
; domain-guard operands are LINK-TIME CONSTANTS — aead_data_ptr is
; hs_packet+40 / hs_packet+88, aead_data_len is an immediate #32 / #12, and
; aead_aad_ptr / aead_aad_len are hs_h / #32. Nothing runtime-derived
; reaches them, so the library's domain guard is statically decidable at
; those two sites and cannot reject. transport.s was the only call site with
; runtime-derived operands, which is why it is the only one that needed the
; status check. (MEASURED: hs_packet resolves to $8930 in all four profiles.)
;
; WHAT THIS ASSERT DOES AND DOES NOT DO. It bounds the highest byte those two
; sites write — the second tag lands at hs_packet+100..115 — against the 148
; bytes data.s reserves, so growing an offset or shrinking the buffer becomes
; a link error instead of a silent overwrite of hs_resp_packet. It does NOT
; detect the change the paragraph above is really about: if someone replaces
; `lda #12` with a runtime value, this assert is untouched and still passes.
; No link-time expression can see that. The reasoning is welded here by the
; COMMENT; the assert only guards the write extent. A `hs_packet + 100 <=
; $10000` form was considered and rejected for exactly that reason — it can
; never fire and would have implied protection it does not give.
;
; This one CAN fire: 32 bytes of slack, and MEASURED firing when data.s's
; .res is shortened.
.import hs_packet, hs_resp_packet
.assert hs_packet + 116 <= hs_resp_packet, lderror, "the handshake initiation AEAD writes past the end of hs_packet — its second tag lands at hs_packet+100..115 and data.s reserves 148 bytes; an offset grew or the .res shrank, and the overflow would land in hs_resp_packet"
