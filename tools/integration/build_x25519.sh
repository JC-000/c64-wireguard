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
#   -D LIB_SHARED_SQTAB_BASE=32768  WG's sqtab window is $8000-$83FF (the
#       cfg hole). The library default is $7800 — without this override
#       sqtab_init would clobber the top of MAIN_AREA_LO.
#       DECIMAL, NOT $8000 — see the FLAGS block below. Writing the hex
#       form here would be copied into a command line and silently build
#       the table over zero page, the stack and the IRQ vector.
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
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/x25519.a"

PROFILE="${X25519_PROFILE:-default}"

# DECIMAL 32768, never $8000: the flags value crosses TWO expansion
# layers inside the sibling build — make expands the recipe line
# ($(CA65) $(ALL_DEFINES)), then /bin/sh expands the resulting command.
# `$8000` loses `$8` to make ($(8) = empty); `$$8000` survives make but
# then the SHELL eats `$8` as a positional parameter. Either way ca65
# silently receives BASE=000 and sqtab_init builds the table over ZERO
# PAGE, THE STACK, AND THE IRQ VECTOR at runtime (measured: boot dies
# with ($0314) = $4A4A = sqtab_hi[276..277], then a KIL jam). Decimal
# has no metacharacters and survives both layers; the sibling's
# page-alignment assert still applies (32768 = $8000).
case "$PROFILE" in
    default)
        BUILD_DIR="build"
        FLAGS='-D LIB_SHARED_SQTAB_BASE=32768 -D LIB_NO_BARE_EXPORTS=1'
        ;;
    onchip)
        BUILD_DIR="build-onchip"
        FLAGS='-D X25519_ONCHIP_MUL=1 -D LIB_SHARED_SQTAB_BASE=32768 -D LIB_NO_BARE_EXPORTS=1'
        ;;
    *)
        echo "error: X25519_PROFILE must be 'default' or 'onchip' (got '$PROFILE')" >&2
        exit 1
        ;;
esac

# CONTRACT_ZP_DEFINES is threaded through but deliberately EMPTY.
#
# The obvious use for it would be -D ZP_CONFIG_NO_EXPORTS=1, to suppress
# zp_config.o's .exportzp block: src/exports.s supplies every ZP slot the
# library declares, so those exports are redundant, and ten of them
# overlap WG's own names (fe_carry, fe_loop, fe_mul_i, fe_mul_j,
# fe25519_src1/2/dst, x25_prev_bit, x25_byte_idx, x25_bit_mask — down
# from fourteen at v0.10.1). WG issue #51 proposed exactly that.
#
# MEASURED AT v0.11.0: it does not work, and cannot. src/constants.s:128
# assigns `ZP_CONFIG_NO_EXPORTS = 1` unguarded before including
# zp_config.s, so a command-line -D is a hard redefinition for every TU
# that includes constants.s — which is all of them:
#   src/constants.s(128): Error: Symbol 'ZP_CONFIG_NO_EXPORTS' is already defined
# The define is only usable by zp_config.s compiled standalone, and
# `make lib` builds it with the same pattern rule as everything else, so
# the §6.2 seam cannot scope it there. Filed as c64-x25519#99; the fix
# is a one-line .ifndef guard on that assignment.
#
# The dangerous half of the collision is closed at the source anyway:
# upstream #93 dropped the zp_ptr1/zp_tmp1/zp_tmp2 trio and #95 renamed
# poly_carry -> mul_carry. The remaining fe_*/x25_* overlap stays
# dormant for the same reason it always has — no WG TU .importzp's an
# x25519 slot, so zp_config.o is never pulled from the archive.
CONTRACT_ZP_FLAGS=''

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
