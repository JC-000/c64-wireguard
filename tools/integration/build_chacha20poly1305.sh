#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_chacha20poly1305.sh - Build c64-ChaCha20-Poly1305
# sibling AEAD primitives as a resident .a archive linked into the main PRG.
#
# Activated only when `make USE_CHACHA_SIBLING=1`. Default is OFF; the
# in-tree src/crypto/chacha20.s + poly1305.s + aead.s remain the default
# implementation until the sibling integration is signed off.
#
# Pinned to the c64-ChaCha20-Poly1305 master SHA recorded in the
# libs/chacha20poly1305 submodule.
#
# Profile: defaults to Profile B (no POLY1305_PROFILE_LONG, no
# POLY1305_REU). Profile A would consume REU bank 0 for sqtab stash —
# which collides with WG's REU bank 0-1 allocation for x25519 mul tables
# (see src/crypto/shared/reu_layout.inc).
#
# Integration path — Option A (staged-source + sed, NOT `make lib-aead-only`)
# ---------------------------------------------------------------------------
# Two integration paths were considered against the sibling's new SPEC §6
# library archive targets (`make lib` / `make lib-aead-only`, landed in
# JC-000/c64-ChaCha20-Poly1305 PRs #35/#36/#38/#39/#41 — see CHANGELOG).
#
#   Option A (chosen): keep WG's existing staging+sed pipeline and add
#     ca65 `-D` overrides for the new size knobs. Required because
#     (a) the sibling Makefile emits `.segment "CODE"` / `.segment "DATA"`
#         which WG must rewrite to CHACHA_CODE / CHACHA_BSS / CHACHA_RODATA
#         (no `--segment-rename` flag in the sibling Make rules), and
#     (b) WG cannot enable Alt 1 (`-DLIB_VARIANT_AEAD_ONLY=1`) because WG
#         imports both `chacha20_quarter_round` (src/wg/cookie.s, for the
#         HChaCha20 cookie derivation) and `mul_8x8` (src/crypto/fe25519.s,
#         the in-tree x25519 implementation when USE_X25519_SIBLING=0).
#         The aead-only variant strips both symbol bodies, not just the
#         `.export` lines. Re-evaluate when WG drops the in-tree fe25519
#         (covered by PR #37) and either drops the HChaCha20 cookie path
#         or restores `chacha20_quarter_round` as a full-archive export.
#
#   Option B (deferred): invoke the sibling's `make lib-aead-only` and
#     copy the resulting `.a`. Blocked on (a) and (b) above. Would
#     require either upstreaming a segment-rename knob to the sibling
#     Makefile or accepting Alt 1's symbol stripping.
#
# Size-reduction switches opted into here (per PR #36 / supervisor's
# "combined D" measurement target):
#   -D POLY1305_MULTIPLY_ROLLED_OUTER=1
#       PR #36 alt 2-partial: rolls the outer 16-iteration j loop of
#       poly1305_multiply; the 17 inner partial products stay inlined.
#       Cost: +4.08% cycles on aead_encrypt n=1024. Saves ~8 KB linked.
#       This is the right elbow for WG (we're size-bound, not cy-bound).
#
#   -D LIB_SHARED_SQTAB_BASE=$8000
#       PR #39 / SPEC §8.1 canonical sqtab equate. The sibling's default
#       is already $8000, but pass it explicitly for symmetry with the
#       x25519 sibling integration script and to defend against a future
#       upstream default change.
#
# Size-reduction switches DELIBERATELY NOT opted into:
#   -D POLY1305_MULTIPLY_ROLLED=1
#       PR #36 alt 2-full: rolls both outer and inner loops. Saves an
#       additional ~576 B but costs +17.4% cycles on aead_encrypt n=1024.
#       Wrong elbow for WG: the AEAD path dominates handshake cost on the
#       transport encrypt/decrypt critical path; +17% would be visible.
#
#   -D LIB_VARIANT_AEAD_ONLY=1
#       PR #35 alt 1: see Option-A rationale above. WG imports symbols
#       this gate strips bodies of (chacha20_quarter_round, mul_8x8).
#
#   -D POLY1305_PROFILE_LONG=1
#       Profile A. WG runs Profile B exclusively (REU bank 0 collision
#       with x25519 mul tables — see reu_layout.inc plan).
#
# Included in the archive:
#   - libs/chacha20poly1305/src/lib/word32_lib.s        (32-bit add/xor/rotate)
#   - libs/chacha20poly1305/src/lib/chacha20_lib.s      (ChaCha20 core)
#   - libs/chacha20poly1305/src/lib/poly1305_lib.s      (Poly1305 + sqtab_init,
#                                                        mul_8x8, poly_prod_*)
#   - libs/chacha20poly1305/src/lib/chacha20poly1305_lib.s (AEAD wrapper)
#   - libs/chacha20poly1305/src/lib/data_lib.s          (cc20_*, poly_*, aead_*
#                                                        buffers + chacha
#                                                        nibswap tables)
#
# Excluded:
#   - libs/chacha20poly1305/src/main.s                  : BASIC stub / test
#                                                        harness entry.
#   - libs/chacha20poly1305/src/lib_version.s           : LIB_VERSION_*
#                                                        manifest equates;
#                                                        leave out until WG
#                                                        consumes them.
#   - libs/chacha20poly1305/src/lib/lib_manifest.s      : LIB_CHACHA20_POLY1305_*
#                                                        aggregate equates;
#                                                        same rationale.
#   - libs/chacha20poly1305/src/zp_config.s             : would duplicate
#                                                        exportzp's WG already
#                                                        emits from src/exports.s
#                                                        (zp_tmp1/2, w32_*,
#                                                        cc20_*, poly_*,
#                                                        zp_ptr1/2). WG's
#                                                        exports.s satisfies
#                                                        the sibling's
#                                                        .importzp's.
#
# ZP slot analysis (sibling defaults vs WG's src/zp_config.inc):
#   - zp_tmp1=$02, zp_tmp2=$03                          : match.
#   - w32_src1=$04, w32_src2=$06, w32_dst=$08           : match.
#   - cc20_round=$14, cc20_qr_idx=$15, cc20_data_ptr=$16: match.
#   - cc20_remain=$18, cc20_buf_pos=$19                 : match.
#   - poly_i=$1a, poly_j=$1b, poly_carry=$1c, poly_tmp=$1d : match.
#   - cc20_work=$40 (64-byte block in ZP, aliases cc20_keystream)
#                                                        : WG places
#                                                        cc20_work in BSS at
#                                                        an absolute address.
#                                                        Sibling pins it to
#                                                        ZP. Requires WG to
#                                                        drop the BSS def
#                                                        (handled in wg/data.s
#                                                        via .ifdef
#                                                        USE_CHACHA_SIBLING)
#                                                        and to define
#                                                        cc20_work/cc20_keystream
#                                                        as ZP equates
#                                                        ($40) — done in
#                                                        zp_config.inc /
#                                                        exports.s.
#   - ct_diff_raw=$1e, ct_sign_mask=$1f                 : sibling Profile B
#                                                        ct_mul_8x8 scratch.
#                                                        WG aliases these to
#                                                        fe_src1/fe_src2 ($1e,
#                                                        $20)? No, $1e/$1f.
#                                                        fe_src1=$1e is a
#                                                        2-byte pointer ($1e
#                                                        + $1f). Time-share:
#                                                        ChaCha20-Poly1305 AEAD
#                                                        and fe25519 don't
#                                                        co-run in WG's
#                                                        handshake (DH is
#                                                        complete before
#                                                        AEAD encryption /
#                                                        decryption). Safe.
#                                                        Equates added to
#                                                        src/zp_config.inc +
#                                                        exports.s.
#   - zp_ptr1=$fb, zp_ptr2=$fd                          : match.
#
# Usage (from top-level Makefile, gated by USE_CHACHA_SIBLING=1):
#   bash tools/integration/build_chacha20poly1305.sh
# Produces:
#   build/lib/chacha20poly1305.a
#   build/lib/chacha20poly1305.sizes.txt (per-source byte counts)
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/chacha20poly1305/src"
STAGING="$PROJECT_ROOT/build/lib/chacha20poly1305_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/chacha20poly1305.a"
SIZES="$OUT_DIR/chacha20poly1305.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

# Copy the include dir contents (constants_lib.s + smc.inc) for -I resolution.
cp "$LIB_SRC"/lib/word32_lib.s            "$STAGING/word32_lib_raw.s"
cp "$LIB_SRC"/lib/chacha20_lib.s          "$STAGING/chacha20_lib_raw.s"
cp "$LIB_SRC"/lib/poly1305_lib.s          "$STAGING/poly1305_lib_raw.s"
cp "$LIB_SRC"/lib/chacha20poly1305_lib.s  "$STAGING/chacha20poly1305_lib_raw.s"
cp "$LIB_SRC"/lib/data_lib.s              "$STAGING/data_lib_raw.s"

# constants_lib.s is .include'd from each lib source by relative name.
# Stage it alongside so the staged sources resolve via -I $STAGING.
cp "$LIB_SRC"/lib/constants_lib.s         "$STAGING/constants_lib.s"

# smc.inc is referenced by some lib sources via "src/include/smc.inc".
# Provide it via the include path: ca65 -I "$LIB_SRC/include"
# (the sibling's own ca65hl/* sources are not used; smc.inc is the
# only header we need from include/).

# --- Route segments to WG's CRYPTO_CODE / CRYPTO_BSS / CRYPTO_RODATA ---
# Sibling uses `.segment "CODE"` and `.segment "DATA"`. WG cfg has CODE
# pointing at LOADER (BASIC stub region) — we want the crypto sibling
# in MAIN_AREA_LO. WG cfg has no `DATA` segment, so we retarget to
# CRYPTO_BSS (mutable cells with zero defaults — data_lib.s explicitly
# documents that the cells come up zero at PRG load time, which is what
# CRYPTO_BSS gives us in WG's cfg since both MAIN_AREA_LO regions are
# fill=yes / fillval=$00).
for f in word32_lib_raw chacha20_lib_raw poly1305_lib_raw \
         chacha20poly1305_lib_raw data_lib_raw; do
    sed -i '' \
        -e 's/^\.segment "CODE"$/.segment "CHACHA_CODE"/' \
        -e 's/^\.segment "DATA"$/.segment "CHACHA_BSS"/' \
        "$STAGING/$f.s"
done

# data_lib_raw.s ends with a `.segment "CODE"` block for the
# chacha_nibswap_*_tab page-aligned lookup tables. Those need to land
# in CRYPTO_RODATA (rodata, page-aligned via WG's CRYPTO_RODATA load =
# LOADER which allows tight packing) rather than CRYPTO_CODE so they
# don't intermix code and data. The earlier blanket sed already
# rewrote the second `.segment "CODE"` too; we need to leave the
# code-region rewrite for the first occurrence only and route the
# nibswap-table block separately.
#
# Approach: replace the SECOND `.segment "CHACHA_CODE"` in data_lib_raw
# (originally the second `.segment "CODE"`) with `.segment "CHACHA_RODATA"`.
# The first `.segment "CHACHA_CODE"` is the original `.segment "DATA"`
# converted; wait — let me re-check. data_lib.s has:
#   .segment "DATA"     -> CHACHA_BSS
#   .segment "CODE"     -> CHACHA_CODE
# So there's exactly ONE `.segment "CHACHA_CODE"` (the nibswap tables
# block). It needs to be CHACHA_RODATA.
python3 - "$STAGING/data_lib_raw.s" <<'PY_EOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
# Replace the SOLE `.segment "CHACHA_CODE"` in data_lib_raw with
# CHACHA_RODATA (it was originally `.segment "CODE"` and held only
# the chacha_nibswap_*_tab page-aligned LUTs).
text = text.replace('.segment "CHACHA_CODE"', '.segment "CHACHA_RODATA"')
with open(path, 'w') as f:
    f.write(text)
PY_EOF

# poly1305_lib_raw.s also has internal `.segment "DATA"` / `.segment "CODE"`
# transitions (for poly1305_reu_sqtab_bank/offset, both gated by
# POLY1305_PROFILE_LONG which we don't define — so the block is dead
# under Profile B). The blanket sed already retargeted them; no further
# patching needed since the .ifdef gate keeps the code inert.

# --- Sanity: no leftover CODE / DATA segments in patched sources ---
for f in word32_lib_raw chacha20_lib_raw poly1305_lib_raw \
         chacha20poly1305_lib_raw data_lib_raw; do
    if grep -qE '^\.segment "CODE"$' "$STAGING/$f.s"; then
        echo "ERROR: leftover .segment \"CODE\" in $f.s" >&2
        exit 1
    fi
    if grep -qE '^\.segment "DATA"$' "$STAGING/$f.s"; then
        echo "ERROR: leftover .segment \"DATA\" in $f.s" >&2
        exit 1
    fi
done

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

STAGED=(word32_lib_raw chacha20_lib_raw poly1305_lib_raw
        chacha20poly1305_lib_raw data_lib_raw)

for src in "${STAGED[@]}"; do
    # -I $STAGING resolves the staged constants_lib.s.
    # -I $LIB_SRC/include resolves smc.inc.
    # -D POLY1305_MULTIPLY_ROLLED_OUTER=1 : PR #36 alt 2-partial size
    #     reduction (see header). Only poly1305_lib.s reads it, but
    #     passing it uniformly keeps every staged .o under the same
    #     define set, which simplifies reasoning about cross-module
    #     equate consistency.
    # -D LIB_SHARED_SQTAB_BASE=$8000     : PR #39 canonical sqtab equate
    #     pinned explicitly (header rationale).
    "$CA65" \
        -g \
        -I "$STAGING" \
        -I "$LIB_SRC/include" \
        -D POLY1305_MULTIPLY_ROLLED_OUTER=1 \
        -D 'LIB_SHARED_SQTAB_BASE=$8000' \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive ---
rm -f "$ARCHIVE"
OBJS=()
for src in "${STAGED[@]}"; do
    OBJS+=("$OBJ_DIR/$src.o")
done
"$AR65" a "$ARCHIVE" "${OBJS[@]}"

# --- Per-source byte counts ---
{
    echo "# chacha20poly1305.a per-source byte counts (ca65 .o file sizes)"
    for src in "${STAGED[@]}"; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
