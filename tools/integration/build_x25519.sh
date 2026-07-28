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
#   -D LIB_SHARED_SQTAB_BASE=$8000  WG's sqtab window is $8000-$83FF (the
#       cfg hole). The library default is $7800 — without this override
#       sqtab_init would clobber the top of MAIN_AREA_LO. ca65 gotcha:
#       X25519_ONCHIP_MUL must be spelled `=1`; a bare -D defines it 0 and
#       silently builds the REU profile.
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
# ($(CA65) $(CA65FLAGS)), then /bin/sh expands the resulting command.
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
        FLAGS='-D LIB_SHARED_SQTAB_BASE=32768'
        ;;
    onchip)
        BUILD_DIR="build-onchip"
        FLAGS='-D X25519_ONCHIP_MUL=1 -D LIB_SHARED_SQTAB_BASE=32768'
        ;;
    *)
        echo "error: X25519_PROFILE must be 'default' or 'onchip' (got '$PROFILE')" >&2
        exit 1
        ;;
esac

# Force a full sibling rebuild: their Makefile tracks source timestamps,
# not CA65FLAGS values, so a flag change would silently reuse stale
# objects. The library builds in seconds; determinism wins.
rm -rf "$LIB_ROOT/$BUILD_DIR"

make -C "$LIB_ROOT" lib \
    BUILD_DIR="$BUILD_DIR" \
    LIB_DIR="$BUILD_DIR/lib" \
    CA65FLAGS="$FLAGS"

mkdir -p "$OUT_DIR"
cp "$LIB_ROOT/$BUILD_DIR/lib/libx25519.a" "$ARCHIVE"

# Version sanity (od65 instead of link-time .import: the unprefixed
# LIB_VERSION_* equates collide between siblings if both lib_version.o
# members enter the link — contract gap, see c64-lib-contract SPEC §1).
ver_dump=$(od65 --dump-exports "$LIB_ROOT/$BUILD_DIR/lib/lib_version.o" 2>/dev/null || true)
if ! grep -q '"LIB_VERSION_MAJOR"' <<<"$ver_dump"; then
    echo "warning: could not verify x25519 lib version via od65" >&2
fi

echo "built $ARCHIVE (profile: $PROFILE)"
