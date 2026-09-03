#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_chacha20poly1305.sh — build the c64-ChaCha20-
# Poly1305 sibling archive via the library's own `make lib` target and copy
# it to build/lib/chacha20poly1305.a for the WG link.
#
# Composition (contract §8.0, two-sibling link with c64-x25519 >= v0.8.0):
# c64-x25519 owns the §8.1 sqtab builder and the §8.3 ct_mul_8x8 body;
# this library defers both:
#   -D SHARED_SQTAB_INIT=1    drops the lib's sqtab_init export, imports
#                             mul_tables_init (satisfied by x25519)
#   -D SHARED_CT_MUL_8X8=1    clears the §8.3 manifest bit AND gates the
#                             mul_8x8 / poly_prod_* exports (v0.7.0, #47)
#   -D POLY1305_MULTIPLY_ROLLED_OUTER=1
#                             size elbow: -8 KB linked, +4.08% cycles on
#                             aead_encrypt n=1024 (right trade for WG)
#   -D LIB_NO_BARE_EXPORTS=1  contract SPEC §1/§8.4 — suppress the
#                             deprecated unprefixed LIB_VERSION_* /
#                             LIB_PRECALC_<name>_* exports so this archive
#                             and x25519's can co-link. build_x25519.sh
#                             passes the same define; the two MUST agree.
# LIB_SHARED_SQTAB_BASE stays at the lib default $8000 == WG's window.
#
# Segments (contract §4, adopted upstream in v0.7.0 — issue #48 CLOSED):
# the library now emits LIB_CHACHA20_POLY1305_CODE / _DATA and puts ZERO
# bytes in bare CODE / DATA (measured at v0.7.0: 8094 B of _CODE across
# five members, 295 B of _DATA; the bare names appear in the segment table
# at size 0, as ca65 always lists them).
#
#   *** CT HAZARD — the align=$100 requirement MOVED WITH THE BYTES. ***
#   The two page-aligned nibswap LUTs read on secret indexes now live in
#   LIB_CHACHA20_POLY1305_CODE (data_lib.o contributes 512 B of it, and the
#   object declares Alignment: 256). It is THAT segment the cfg must place
#   with align = $100 — an align on the now-empty bare CODE protects
#   nothing. ld65 only WARNS on an under-aligned segment, so getting this
#   wrong loses constant-time silently. WG's cfgs still describe the old
#   arrangement; see cfg/c64-wireguard-*.cfg.
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_ROOT="$PROJECT_ROOT/libs/chacha20poly1305"
# Archive output dir. The Makefile passes OUT_DIR=$(LIB_DIR) so a BUILD_DIR
# override (e.g. BUILD_DIR=build_msgport53) links against an archive in ITS
# OWN tree instead of build/lib — before this, every such build failed at
# ld65 with "build_msgport53/lib/chacha20poly1305.a not found". Standalone runs keep
# the historical default.
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/build/lib}"
ARCHIVE="$OUT_DIR/chacha20poly1305.a"

DEFS='-D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1 -D POLY1305_MULTIPLY_ROLLED_OUTER=1 -D LIB_NO_BARE_EXPORTS=1'

# Force a full sibling rebuild: their Makefile tracks source timestamps,
# not the define set, so a define change would silently reuse stale
# objects.
rm -rf "$LIB_ROOT/build/lib"

# CONTRACT_DEFINES is the §6.2 seam, added in v0.8.0. It replaces the old
# `CA65="ca65 $DEFS"` override, which worked only by accident: overriding
# CA65 prepends the defines ahead of the library's own CA65FLAGS, so it
# happened to keep `-t c64 -g -I ...`, but the library documents CA65 as
# unsupported for exactly that reason. There is deliberately no
# CONTRACT_ZP_DEFINES here — this archive ships no ZP-defining member
# (src/zp_config.s is excluded so consumers assemble their own), which is
# why WG's src/exports.s has to supply the §2 registry slot names.
make -C "$LIB_ROOT" lib CONTRACT_DEFINES="$DEFS"

mkdir -p "$OUT_DIR"
# §6.1 canonical basename (v0.8.0). `c64-chacha20-poly1305.a` is the
# deprecated dialect, still written through the §6.5 rename window and
# dropped at the library's next MAJOR — don't depend on it.
cp "$LIB_ROOT/build/lib/chacha20poly1305.a" "$ARCHIVE"

# The interim poly1305_lib.o member swap that lived here is GONE. It gated
# the legacy mul_8x8 / poly_prod_lo / poly_prod_hi exports behind
# `.ifndef SHARED_CT_MUL_8X8` to stop them colliding with x25519's; upstream
# shipped exactly that gate in v0.7.0 (issue #47), so the swap had already
# become a no-op via its own probe before being deleted here.

# --- Build-time manifest verification (od65) ---
# Historically this was the ONLY place the chacha-side §3/§8.0 obligations
# could be checked: both archives exported the same unprefixed symbols
# (LIB_PRECALC_sqtab_*, LIB_VERSION_*), so src/contract_asserts.s could pull
# only ONE manifest member into the link. v0.7.0 + x25519 v0.9.0 fixed that
# (SPEC §1/§8.4), and with LIB_NO_BARE_EXPORTS both manifests now co-link,
# so these are ALSO expressible as link-time asserts. Kept here as a cheap
# fail-fast that runs before the 30-min build/test cycle:
#   REU_BANKS_USED must be $00 (zero REU DMA since v0.6.0)
#   SHARED_PRIMITIVES must be $0000 (both bits deferred to x25519)
# NOTE: LIB_CHACHA20_POLY1305_SHARED_CONSUMES (new in v0.7.0) is $0005 here,
# NOT zero — it must never be added to the zero-checking loop below. It is
# the mask that lets the consumer assert every deferred primitive still has
# an owner in the link; that check belongs in src/contract_asserts.s.
manifest_dump=$(od65 --dump-exports "$LIB_ROOT/build/lib/objs/lib_manifest.o")
for sym in LIB_CHACHA20_POLY1305_REU_BANKS_USED LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES; do
    hex=$(grep -A1 "\"$sym\"" <<<"$manifest_dump" | sed -n 's/.*Value:[[:space:]]*0x\([0-9A-Fa-f]*\).*/\1/p')
    if [[ -z "$hex" ]]; then
        echo "ERROR: $sym not found in lib_manifest.o export dump" >&2
        exit 1
    fi
    if (( 16#$hex != 0 )); then
        echo "ERROR: $sym = 0x$hex, expected 0 — deferral defines not in effect?" >&2
        exit 1
    fi
done

# Version sanity. Checks the PREFIXED symbol: under LIB_NO_BARE_EXPORTS the
# unprefixed LIB_VERSION_MAJOR no longer exists, so grepping for it would
# warn on every successful build.
ver_dump=$(od65 --dump-exports "$LIB_ROOT/build/lib/objs/lib_version.o" 2>/dev/null || true)
if ! grep -q '"LIB_CHACHA20_POLY1305_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "warning: could not verify chacha lib version via od65" >&2
fi
# The bare forms MUST be absent — their presence means LIB_NO_BARE_EXPORTS
# did not reach ca65, and the two-sibling link will fail at ld65 with
# "Duplicate external identifier" once both manifests enter it.
if grep -q '"LIB_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "ERROR: chacha archive still exports the bare LIB_VERSION_MAJOR —" >&2
    echo "       LIB_NO_BARE_EXPORTS=1 did not take effect (SPEC §1)." >&2
    exit 1
fi

echo "built $ARCHIVE (Profile B, rolled-outer, sqtab+ct_mul deferred to x25519)"
