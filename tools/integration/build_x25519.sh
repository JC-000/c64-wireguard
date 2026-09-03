#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_x25519.sh — build the c64-x25519 sibling archive
# via the library's own contract-§6 `make lib` target and copy it to
# build/lib/x25519.a for the WG link.
#
# Replaces the pre-v0.8.0 staged-source pipeline: since c64-x25519 v0.8.0
# the archive is fully self-contained (own data buffers, own zp/reu config,
# §4-prefixed segments LIB_X25519_CODE / LIB_X25519_DATA /
# LIB_X25519_INIT_CODE) and imports nothing from the consumer, so WG links
# it directly with zero source patches. WG-side obligations live in
# cfg/c64-wireguard-*.cfg (segment placement) and src/boot.s (init calls).
#
# Profile selection (WG Makefile REU knob):
#   X25519_PROFILE=default  REU profile (banks 0,1,3,4,5; fastest at 1 MHz)
#   X25519_PROFILE=onchip   X25519_ONCHIP_MUL=1 — zero REU, runs on a
#                           stock C64; ~1.7x slower scalarmult at 1 MHz
#
# Defines passed to every library TU:
#   -D LIB_SHARED_SQTAB_BASE=<derived>  WG's sqtab window (the cfg's
#       reserved SQTAB_HOLE). The library default is $7800 — without this
#       override sqtab_init would clobber the top of MAIN_AREA_LO. The
#       value is PARSED from src/crypto/shared/sqtab_base.inc, never
#       written here; see the SQTAB_INC block below.
#       Passed as DECIMAL — see that block for why the hex form silently
#       builds the table over zero page, the stack and the IRQ vector.
#       Separate ca65 gotcha: X25519_ONCHIP_MUL must be spelled `=1`; a
#       bare -D defines it 0 and silently builds the REU profile.
#   -D LIB_NO_BARE_EXPORTS=1        contract SPEC §1/§8.4. Suppresses the
#       DEPRECATED unprefixed exports (LIB_VERSION_*, LIB_ABI_VERSION,
#       LIB_PRECALC_<name>_*) that every contract library emits identically,
#       leaving only the LIB_X25519_*-prefixed forms. Mandatory for a
#       consumer linking two or more contract libraries: without it, ld65
#       rejects the link with "Duplicate external identifier" as soon as
#       both manifests enter it. The chacha ingestion script passes the
#       same define — the two MUST agree or the collision returns.
#
# Defines go through the contract §6.2 variables (CONTRACT_DEFINES /
# CONTRACT_ZP_DEFINES, both added in v0.11.0), NOT CA65FLAGS. CA65FLAGS
# survives as a deprecated alias through the §6.5 window, but it is a
# hard-assign: passing it clobbers the library's own `-t c64 -g`, so
# every object was being assembled without the C64 target or debug info.
# The two variables differ in routing — CONTRACT_ZP_DEFINES reaches
# every slot-defining TU but never a consumer TU that .importzp's a
# slot, where a -D would be a hard "already defined" error.
#
# Separate BUILD_DIRs per profile so switching REU=1 <-> REU=0 can never
# reuse stale objects assembled under the other profile's defines.
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_ROOT="$PROJECT_ROOT/libs/x25519"
# Archive output dir. The Makefile passes OUT_DIR=$(LIB_DIR) so a BUILD_DIR
# override (e.g. BUILD_DIR=build_msgport53) links against an archive in ITS
# OWN tree instead of build/lib — before this, every such build failed at
# ld65 with "build_msgport53/lib/x25519.a not found". Standalone runs keep
# the historical default.
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/build/lib}"
ARCHIVE="$OUT_DIR/x25519.a"

PROFILE="${X25519_PROFILE:-default}"

# The sqtab window base: DERIVED, and passed as DECIMAL.
#
# Derived, not repeated — src/crypto/shared/sqtab_base.inc is the single
# source of truth (contract v0.10.2 MUST). Parse the hex out of it and
# hand ca65 the decimal. A literal here would be one more copy of $8000,
# and the only copy no WG-side assert can reach, since it lives outside
# the assembly where the §6.7 checks run.
#
# Decimal because the value crosses TWO expansion layers inside the
# sibling build — make expands the recipe line ($(CA65) $(ALL_DEFINES)),
# then /bin/sh expands the resulting command. `$8000` loses `$8` to make
# ($(8) = empty); `$$8000` survives make but then the SHELL eats `$8` as
# a positional parameter. Either way ca65 silently receives BASE=000 and
# sqtab_init builds the table over ZERO PAGE, THE STACK, AND THE IRQ
# VECTOR at runtime (measured: boot dies with ($0314) = $4A4A =
# sqtab_hi[276..277], then a KIL jam). Decimal has no metacharacters and
# survives both layers. $((16#...)) below does that conversion, so the
# hex form never reaches a command line at all.
SQTAB_INC="$PROJECT_ROOT/src/crypto/shared/sqtab_base.inc"
SQTAB_HEX=$(sed -n 's/^WG_SQTAB_BASE[[:space:]]*=[[:space:]]*\$\([0-9A-Fa-f]\{1,4\}\).*/\1/p' "$SQTAB_INC")
if [[ -z "$SQTAB_HEX" ]]; then
    echo "error: could not parse WG_SQTAB_BASE out of $SQTAB_INC" >&2
    exit 1
fi
SQTAB_BASE=$((16#$SQTAB_HEX))
if (( SQTAB_BASE % 256 != 0 )); then
    echo "error: WG_SQTAB_BASE=\$$SQTAB_HEX is not page-aligned — the sqtab" >&2
    echo "       LUTs are read with lda tab,x on SECRET indexes, so a" >&2
    echo "       page-crossing base makes that timing data-dependent." >&2
    exit 1
fi

case "$PROFILE" in
    default)
        BUILD_DIR="build"
        FLAGS="-D LIB_SHARED_SQTAB_BASE=$SQTAB_BASE -D LIB_NO_BARE_EXPORTS=1"
        ;;
    onchip)
        BUILD_DIR="build-onchip"
        FLAGS="-D X25519_ONCHIP_MUL=1 -D LIB_SHARED_SQTAB_BASE=$SQTAB_BASE -D LIB_NO_BARE_EXPORTS=1"
        ;;
    *)
        echo "error: X25519_PROFILE must be 'default' or 'onchip' (got '$PROFILE')" >&2
        exit 1
        ;;
esac

# ZP export suppression, live as of v0.11.1.
#
# src/exports.s supplies every ZP slot the library declares, so
# zp_config.o's .exportzp block is redundant here — and ten of its names
# overlap WG's own (fe_carry, fe_loop, fe_mul_i, fe_mul_j,
# fe25519_src1/2/dst, x25_prev_bit, x25_byte_idx, x25_bit_mask; it was
# fourteen before v0.11.0 dropped the zp_ptr1/zp_tmp1/zp_tmp2 trio and
# renamed poly_carry -> mul_carry). The overlap was dormant only because
# no WG TU .importzp's an x25519 slot, so zp_config.o is never pulled;
# one future import would have collided on all of them at once. That is
# WG issue #51.
#
# exports.s claimed for several releases that this define was passed
# here. It was not, and until v0.11.1 it COULD not be: constants.s
# assigned the symbol unguarded, so any -D was
#   src/constants.s(128): Error: Symbol 'ZP_CONFIG_NO_EXPORTS' is already defined
# in every TU. Filed as c64-x25519#99, fixed upstream with the .ifndef
# guard in v0.11.1 (which also caught the identical bug on
# REU_CONFIG_NO_EXPORTS next door). Verified consumer-side before
# enabling: zp_config.o goes from 18 exports to 0, the two-sibling link
# succeeds, all ten names remain in labels.txt from WG's own exports.s,
# and the PRG is byte-identical.
#
# The precondition is standing, not incidental: WG must keep supplying
# EVERY slot in the library's zp_config.s, not just the overlapping
# ones, or suppression turns a duplicate-export into an unresolved
# external.
CONTRACT_ZP_FLAGS='-D ZP_CONFIG_NO_EXPORTS=1'

# Force a full sibling rebuild: their Makefile tracks source timestamps,
# not define values, so a flag change would silently reuse stale
# objects. The library builds in seconds; determinism wins.
rm -rf "$LIB_ROOT/$BUILD_DIR"

make -C "$LIB_ROOT" lib \
    BUILD_DIR="$BUILD_DIR" \
    LIB_DIR="$BUILD_DIR/lib" \
    CONTRACT_DEFINES="$FLAGS" \
    CONTRACT_ZP_DEFINES="$CONTRACT_ZP_FLAGS"

mkdir -p "$OUT_DIR"
# §6.1 canonical basename (v0.11.0). The old `libx25519.a` spelling is a
# deprecated dialect, still written through the §6.5 rename window and
# dropped at the library's next MAJOR — don't depend on it.
cp "$LIB_ROOT/$BUILD_DIR/lib/x25519.a" "$ARCHIVE"

# Version sanity. Checks the PREFIXED symbol: under LIB_NO_BARE_EXPORTS the
# unprefixed LIB_VERSION_MAJOR no longer exists, so grepping for it would
# warn on every successful build.
#
# The collision that forced this out-of-band (both siblings exporting the
# same unprefixed LIB_VERSION_* / LIB_PRECALC_* names, so only one manifest
# could enter the link) was fixed upstream in x25519 v0.9.0 + chacha v0.7.0
# per c64-lib-contract SPEC §1/§8.4. A link-time `.import
# LIB_X25519_VERSION_MAJOR` + `.assert` in src/contract_asserts.s is now
# possible and strictly better; this check is kept as a cheap build-time
# canary that the archive was assembled with the expected define set at all.
ver_dump=$(od65 --dump-exports "$LIB_ROOT/$BUILD_DIR/lib/lib_version.o" 2>/dev/null || true)
if ! grep -q '"LIB_X25519_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "warning: could not verify x25519 lib version via od65" >&2
fi
# The bare forms MUST be absent — their presence means LIB_NO_BARE_EXPORTS
# did not reach ca65, and the two-sibling link will fail at ld65 with
# "Duplicate external identifier" once the chacha manifest joins it.
if grep -q '"LIB_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "ERROR: x25519 archive still exports the bare LIB_VERSION_MAJOR —" >&2
    echo "       LIB_NO_BARE_EXPORTS=1 did not take effect (SPEC §1)." >&2
    exit 1
fi

echo "built $ARCHIVE (profile: $PROFILE)"
