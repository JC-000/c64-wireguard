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
#   -D SHARED_CT_MUL_8X8=1    clears the §8.3 manifest bit
#   -D POLY1305_MULTIPLY_ROLLED_OUTER=1
#                             size elbow: -8 KB linked, +4.08% cycles on
#                             aead_encrypt n=1024 (right trade for WG)
# LIB_SHARED_SQTAB_BASE stays at the lib default $8000 == WG's window.
#
# Segments: the lib has not adopted contract §4 yet (upstream issue #48) —
# it emits bare CODE / DATA, which WG's cfg maps directly (WG's own boot
# code moved to BOOT_CODE to free the names). CODE carries the two
# page-aligned nibswap LUTs read on secret indexes: the cfg MUST keep
# align=$100 on CODE or constant-time is silently lost. DATA cells must
# PRG-load as zero, so DATA stays type=rw in a file-emitting region.
#
# INTERIM member swap (upstream issue #47): SHARED_CT_MUL_8X8=1 gates the
# manifest bit but not the legacy mul_8x8 / poly_prod_lo / poly_prod_hi
# exports, which collide with x25519's — ld65: "Duplicate external
# identifier". Until #47 lands we re-assemble poly1305_lib.s with those
# two .export lines wrapped in .ifndef SHARED_CT_MUL_8X8 and swap the
# member in OUR COPY of the archive (the submodule tree and the library's
# own build output are never touched). The swap auto-disables itself once
# upstream ships the gate.
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_ROOT="$PROJECT_ROOT/libs/chacha20poly1305"
OUT_DIR="$PROJECT_ROOT/build/lib"
STAGING="$OUT_DIR/chacha_staging"
ARCHIVE="$OUT_DIR/chacha20poly1305.a"

DEFS='-D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1 -D POLY1305_MULTIPLY_ROLLED_OUTER=1'

# Force a full sibling rebuild: their Makefile tracks source timestamps,
# not the CA65 override's define set, so a define change would silently
# reuse stale objects.
rm -rf "$LIB_ROOT/build/lib"

make -C "$LIB_ROOT" lib CA65="ca65 $DEFS"

mkdir -p "$OUT_DIR"
cp "$LIB_ROOT/build/lib/c64-chacha20-poly1305.a" "$ARCHIVE"

# --- Interim export-gating member swap (issue #47) ---
SRC="$LIB_ROOT/src/lib/poly1305_lib.s"
if grep -q '^\.ifndef SHARED_CT_MUL_8X8$' "$SRC"; then
    echo "upstream #47 gate detected in poly1305_lib.s — skipping member swap"
else
    rm -rf "$STAGING"
    mkdir -p "$STAGING"
    # Gate exactly the two unconditional export lines; anything else is a
    # layout change upstream and must fail loudly rather than mis-patch.
    for pat in '^\.export poly_prod_lo, poly_prod_hi$' '^\.export mul_8x8$'; do
        if [[ $(grep -c "$pat" "$SRC") -ne 1 ]]; then
            echo "ERROR: expected exactly one line matching $pat in $SRC" >&2
            echo "       (upstream layout changed — revisit issue #47 status)" >&2
            exit 1
        fi
    done
    sed -e 's/^\.export poly_prod_lo, poly_prod_hi$/.ifndef SHARED_CT_MUL_8X8\n.export poly_prod_lo, poly_prod_hi\n.endif/' \
        -e 's/^\.export mul_8x8$/.ifndef SHARED_CT_MUL_8X8\n.export mul_8x8\n.endif/' \
        "$SRC" > "$STAGING/poly1305_lib_gated.s"
    ca65 -t c64 -g \
        -I "$LIB_ROOT/src/include" -I "$LIB_ROOT/src/lib" -I "$LIB_ROOT/src" \
        $DEFS \
        "$STAGING/poly1305_lib_gated.s" -o "$STAGING/poly1305_lib.o"
    ar65 d "$ARCHIVE" poly1305_lib.o
    ar65 a "$ARCHIVE" "$STAGING/poly1305_lib.o"
fi

# --- Build-time manifest verification (od65) ---
# The link-time contract asserts (src/contract_asserts.s) can only pull
# ONE archive's manifest member — both export unprefixed common symbols
# (LIB_PRECALC_sqtab_*, LIB_VERSION_*) that collide. So the chacha-side
# §3/§8.0 obligations are checked here instead, numerically:
#   REU_BANKS_USED must be $00 (zero REU DMA since v0.6.0)
#   SHARED_PRIMITIVES must be $0000 (both bits deferred to x25519)
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

ver_dump=$(od65 --dump-exports "$LIB_ROOT/build/lib/objs/lib_version.o" 2>/dev/null || true)
if ! grep -q '"LIB_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "warning: could not verify chacha lib version via od65" >&2
fi

echo "built $ARCHIVE (Profile B, rolled-outer, sqtab+ct_mul deferred to x25519)"
