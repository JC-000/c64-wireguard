#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_x25519.sh - Build c64-x25519 sibling X25519
# primitives as a resident .a archive linked into the main PRG.
#
# Activated only when `make USE_X25519_SIBLING=1`. Default is OFF; the
# in-tree src/crypto/fe25519.s + src/crypto/x25519.s remain the
# default implementation until the sibling integration is signed off.
#
# Adapted from c64-https/tools/integration/build_x25519.sh — same
# staged-source pattern, retargeted at WG's segment names
# (CRYPTO_CODE / CRYPTO_RODATA / CRYPTO_BSS) and pinned to the c64-x25519
# v0.6.0 tag recorded in the libs/x25519 submodule.
#
# v0.6.0 deltas (vs the v0.5.0 / 4d1c752 pin this script originally
# targeted) that this script accounts for:
#   - PR #54 (bank-2 drop): sibling's LIB_X25519_REU_BANKS_USED manifest
#     mask flipped from $3F to $3B (banks 0,1,3,4,5; bank 2 released).
#     Resolves WG's latent overlay-store collision documented in
#     src/crypto/shared/reu_layout.inc — no script change needed; the
#     fix is purely on the sibling side.
#   - PR #56 (§8.1 shared sqtab adoption): sibling now sources sqtab_lo
#     / sqtab_hi from `LIB_SHARED_SQTAB_BASE` (default $7800 in the
#     sibling). WG places sqtab at $8000 (see src/exports.s and the
#     linker cfg sqtab hole), so we MUST pass
#     `-D LIB_SHARED_SQTAB_BASE=$8000` to every staged TU so
#     the sibling's SMC patch sites resolve to the same page WG's
#     runtime sqtab_init writes. Page-alignment + page-delta are hard-
#     asserted in the sibling's constants.s; a missed override fails
#     at assemble time, not as a silent runtime table corruption.
#   - PR #55 (`make lib-x25519-1764` build variant): size-reduced 1764B
#     archive variant for tightly-budgeted consumers. WG isn't size-
#     constrained on the x25519 surface (we exclude bench/util/main and
#     re-export ZP slots in-tree) so we keep the standard build.
#
# Excluded from the archive:
#   - libs/x25519/src/mul_8x8.s : c64-wireguard's in-tree src/crypto/poly1305.s
#     already exports mul_8x8 / sqtab_init / poly_prod_lo / poly_prod_hi.
#     Including the sibling's would duplicate those symbols.
#   - libs/x25519/src/main.s    : the sibling's BASIC stub / standalone test
#     harness entry — WG has its own boot.s entry point.
#   - libs/x25519/src/util.s    : bench helpers (vic_blank/unblank, bench_*)
#     not used by WG.
#   - libs/x25519/src/zp_config.s : would duplicate exportzp's WG already
#     emits from src/exports.s (fe25519_src1/2/dst, mul_pending, fe_carry,
#     fe_loop, fe_mul_i/j, x25_prev_bit, x25_byte_idx, x25_bit_mask,
#     poly_carry, etc.). The equates are still available to the sibling
#     code via constants.s's `.include "zp_config.s"` (which it does
#     under ZP_CONFIG_NO_EXPORTS=1).
#   - libs/x25519/src/reu_config.s : same export-suppression rationale;
#     X25519_REU_BANK / X25519_REU_OFFSET are equates pulled in via
#     constants.s. WG owns REU banks 0-1 for the in-tree fe25519 mul
#     tables — sibling default X25519_REU_BANK=0 matches that allocation,
#     so no override needed. (v0.6.0 narrows the claim from banks 0-5 to
#     banks 0,1,3,4,5 via LIB_X25519_REU_BANKS_USED=$3B; bank 2 is now
#     free for WG's overlay store. See PR #54 and the updated comment
#     block in src/crypto/shared/reu_layout.inc.)
#   - libs/x25519/src/lib_version.s : exports LIB_VERSION_*, LIB_X25519_*
#     manifest equates. Not currently used by WG; leaving them out
#     avoids a "linked but unreferenced" warning and keeps the archive
#     minimal. Re-enable when WG begins asserting against the manifest.
#
# ZP slot analysis (sibling defaults vs WG layout, see src/zp_config.inc):
#   - fe25519_src1/src2/dst = $1e/$20/$22 — match WG's fe_src1/2/dst.
#   - mul_pending=$24       — WG has fe_misc=$24, only used by fe25519.
#                             Aliases when sibling owns fe25519.
#   - mul_bound=$25         — unused in WG layout.
#   - fe_carry=$26          — match.
#   - fe_loop=$27, fe_mul_i=$28, fe_mul_j=$29 — match.
#   - x25_prev_bit=$2a, x25_byte_idx=$2c, x25_bit_mask=$2d — match.
#   - mul_ripple_start=$2f, fe_sqr_pairs=$2e — unused in WG layout.
#   - fe_cmp_mask=$14, fe_subp_rhs=$15, fe_add_carry_mask=$16 — alias WG's
#     cc20_round/cc20_qr_idx/cc20_data_ptr (ChaCha20 working ZP).
#     Time-share: ChaCha20 and fe25519 never co-run in the WG handshake
#     (DH happens before AEAD) so the alias is safe.
#   - poly_carry=$1c        — match.
#
# No --asm-define ZP overrides needed — sibling defaults work as-is.
#
# Usage (from top-level Makefile, gated by USE_X25519_SIBLING=1):
#   bash tools/integration/build_x25519.sh
# Produces:
#   build/lib/x25519.a
#   build/lib/x25519.sizes.txt  (per-source byte counts)
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/x25519/src"
STAGING="$PROJECT_ROOT/build/lib/x25519_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/x25519.a"
SIZES="$OUT_DIR/x25519.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

cp "$LIB_SRC"/constants.s    "$STAGING/"
cp "$LIB_SRC"/zp_config.s    "$STAGING/"   # equate definitions (no .exportzp at use)
cp "$LIB_SRC"/reu_config.s   "$STAGING/"   # equate definitions (no .export at use)
cp "$LIB_SRC"/fe25519.s      "$STAGING/fe25519_raw.s"
cp "$LIB_SRC"/x25519.s       "$STAGING/x25519_raw.s"
cp "$LIB_SRC"/x25519_init.s  "$STAGING/x25519_init_raw.s"

# Emit fresh data extraction (rather than sed-patch libs/x25519/src/data.s).
# Buffer ordering / size / alignment match the sibling source.
cat > "$STAGING/data_x25519_bss_raw.s" <<'BSS_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_bss_raw.s — zero-init buffers extracted from
; libs/x25519/src/data.s for the c64-wireguard Phase D integration.
;
; Routed to a dedicated X25519_BSS segment (added to both
; cfg/c64-wireguard-{ip65,uci}.cfg) so the sibling's ~1.3 KB of buffers
; can be placed in MAIN_AREA_HI ($8400-$9FFF) without pushing MAIN_AREA_LO
; ($32F0-$7FFF) over its budget. All buffers must live below $A000 (BASIC
; ROM shadow) and must NOT collide with the $8000-$83FF sqtab runtime
; window.
; =============================================================================

.export fe25519_tmp1, fe25519_tmp2, fe25519_tmp3, fe25519_tmp4
.export x25_x2, x25_z2, x25_x3, x25_z3
.export x25_a, x25_b, x25_da, x25_cb, x25_e
.export x25_scalar, x25_u, x25_result
.export mul_cached_a, mul_src2_buf
.export mul_dma_lo, mul_dma_hi, mul_dma_carry

.segment "X25519_BSS"

; --- Page-aligned 32-byte field buffers (block 1) ---
        .align 256
fe25519_tmp1:   .res 32, 0
fe25519_tmp2:   .res 32, 0
fe25519_tmp3:   .res 32, 0
fe25519_tmp4:   .res 32, 0
x25_x2:         .res 32, 0
x25_z2:         .res 32, 0
x25_x3:         .res 32, 0
x25_z3:         .res 32, 0

; --- Page-aligned 32-byte field buffers (block 2) ---
        .align 256
x25_a:          .res 32, 0
x25_b:          .res 32, 0
x25_da:         .res 32, 0
x25_cb:         .res 32, 0
x25_e:          .res 32, 0
x25_scalar:     .res 32, 0
x25_u:          .res 32, 0
x25_result:     .res 32, 0

; --- fe25519_mul optimization scratch (unaligned) ---
; 35 bytes: 32 + 1 phantom (sibling fe25519_sqr body B reads up to
; byte 32) + 2 over-read pad (kept consistent with nistcurves pattern
; even though WG doesn't link nistcurves — costs 2 B in BSS).
mul_cached_a:   .res 1, 0
mul_src2_buf:   .res 35, 0

; --- REU DMA target buffers (page-aligned for abs,Y without penalty) ---
        .align 256
mul_dma_lo:     .res 256, 0
mul_dma_hi:     .res 256, 0
mul_dma_carry:  .res 256, 0

; --- Alignment asserts (mirrored from sibling data.s) ---
.assert (fe25519_tmp1 & $1F) = 0, lderror, "fe25519_tmp1 must be 32-byte aligned"
.assert (fe25519_tmp2 & $1F) = 0, lderror, "fe25519_tmp2 must be 32-byte aligned"
.assert (fe25519_tmp3 & $1F) = 0, lderror, "fe25519_tmp3 must be 32-byte aligned"
.assert (fe25519_tmp4 & $1F) = 0, lderror, "fe25519_tmp4 must be 32-byte aligned"
.assert (x25_x2 & $1F) = 0, lderror, "x25_x2 must be 32-byte aligned"
.assert (x25_z2 & $1F) = 0, lderror, "x25_z2 must be 32-byte aligned"
.assert (x25_x3 & $1F) = 0, lderror, "x25_x3 must be 32-byte aligned"
.assert (x25_z3 & $1F) = 0, lderror, "x25_z3 must be 32-byte aligned"
.assert (x25_a & $1F) = 0, lderror, "x25_a must be 32-byte aligned"
.assert (x25_b & $1F) = 0, lderror, "x25_b must be 32-byte aligned"
.assert (x25_da & $1F) = 0, lderror, "x25_da must be 32-byte aligned"
.assert (x25_cb & $1F) = 0, lderror, "x25_cb must be 32-byte aligned"
.assert (x25_e & $1F) = 0, lderror, "x25_e must be 32-byte aligned"
.assert (x25_scalar & $1F) = 0, lderror, "x25_scalar must be 32-byte aligned"
.assert (x25_u & $1F) = 0, lderror, "x25_u must be 32-byte aligned"
.assert (x25_result & $1F) = 0, lderror, "x25_result must be 32-byte aligned"
BSS_EOF

cat > "$STAGING/data_x25519_rodata_raw.s" <<'RODATA_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_rodata_raw.s — initialized lookup tables extracted from
; libs/x25519/src/data.s for the c64-wireguard Phase D integration.
;
; Routed to a dedicated X25519_RODATA segment (added to both
; cfg/c64-wireguard-{ip65,uci}.cfg, align=$20 so fe_p / x25_basepoint
; can land on a 32-byte boundary as the sibling's .align 32 + .assert
; require). Loaded into LOADER ($0801-$1FFF) which has plenty of slack
; after the BASIC stub + boot code.
; =============================================================================

.export mul38_lo_tab, mul38_hi_tab
.export sqr_lo, sqr_hi
.export a24_b0, a24_b1, a24_b2, a24_b3

.export x25_basepoint, fe_p

.segment "X25519_RODATA"

        .align 32
x25_basepoint:
        .byte 9
        .res 31, 0
fe_p:
        .byte $ed
        .res 30, $ff
        .byte $7f

.assert (x25_basepoint & $1F) = 0, lderror, "x25_basepoint must be 32-byte aligned"
.assert (fe_p & $1F) = 0, lderror, "fe_p must be 32-byte aligned"

; mul_by_38 lookup tables (256 B each)
        .align 256
mul38_lo_tab:
        .byte 0
        .repeat 255, i
                .byte <((i+1) * 38)
        .endrepeat
mul38_hi_tab:
        .byte 0
        .repeat 255, i
                .byte >((i+1) * 38)
        .endrepeat

; fe25519_sqr diagonal squaring tables (page-aligned)
        .align 256
sqr_lo:
        .repeat 256, i
                .byte <(i * i)
        .endrepeat
sqr_hi:
        .repeat 256, i
                .byte >(i * i)
        .endrepeat

; fe25519_mul_a24 split tables (page-aligned)
        .align 256
a24_b0:
        .repeat 256, i
                .byte <(121665 * i)
        .endrepeat
a24_b1:
        .repeat 256, i
                .byte <((121665 * i) >> 8)
        .endrepeat
a24_b2:
        .repeat 256, i
                .byte <((121665 * i) >> 16)
        .endrepeat
a24_b3:
        .repeat 256, i
                .byte <((121665 * i) >> 24)
        .endrepeat

RODATA_EOF

# mul_8x8.s is intentionally NOT staged. The in-tree src/crypto/poly1305.s
# provides mul_8x8 / sqtab_init / poly_prod_lo / poly_prod_hi /
# sqtab_lo / sqtab_hi. The sibling's fe25519 + x25519_init imports those
# symbols; the in-tree link satisfies them.

# --- Route CODE segments to CRYPTO_CODE ---
# Sibling uses `.segment "CODE"` (= LOADER in WG cfg) — retarget to
# CRYPTO_CODE so the sibling lands in MAIN_AREA_LO alongside the rest
# of the crypto code, not in the BASIC-stub LOADER region.
for src in fe25519_raw x25519_raw x25519_init_raw; do
    sed -i '' 's/^\.segment "CODE"$/.segment "CRYPTO_CODE"/' "$STAGING/$src.s"
done

# --- Sanity: no leftover CODE segments in patched sources ---
for src in fe25519_raw x25519_raw x25519_init_raw; do
    if grep -qE '^\.segment "CODE"$' "$STAGING/$src.s"; then
        echo "ERROR: leftover .segment \"CODE\" in $src.s" >&2
        exit 1
    fi
done

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

STAGED=(fe25519_raw x25519_raw x25519_init_raw data_x25519_bss_raw data_x25519_rodata_raw)

# -D LIB_SHARED_SQTAB_BASE=$8000 pins the sibling's §8.1
# shared-sqtab equate to WG's existing sqtab runtime window ($8000-$83FF;
# see src/exports.s and the cfg/ sqtab hole). Sibling default is $7800;
# every staged TU must see the same value or the sibling's SMC patch
# sites would resolve to a different page than WG's sqtab_init writes.
# Page-alignment + page-delta are hard-asserted in the sibling's
# constants.s, so a missed override here is a hard assemble-time error,
# not a silent runtime corruption.
# Note: the c64-lib-contract docs and sibling comments reference the
# cl65-driver-style `--asm-define` spelling; ca65 itself takes `-D`.
for src in "${STAGED[@]}"; do
    "$CA65" \
        -g \
        -D LIB_SHARED_SQTAB_BASE='$8000' \
        -I "$STAGING" \
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
    echo "# x25519.a per-source byte counts (ca65 .o file sizes)"
    for src in "${STAGED[@]}"; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-28s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
