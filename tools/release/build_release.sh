#!/usr/bin/env bash
# =============================================================================
# tools/release/build_release.sh — build the full release artifact set.
#
# Produces in build/release/:
#   wireguard-rrnet-reu.prg          BACKEND=ip65 REU=1  (RR-Net + REU)
#   wireguard-rrnet-noreu.prg        BACKEND=ip65 REU=0  (RR-Net, stock C64)
#   wireguard-uci-reu.prg            BACKEND=uci  REU=1  (Ultimate 64 / C64U)
#   wireguard-uci-noreu.prg          BACKEND=uci  REU=0  (Ultimate, REU disabled)
#   wireguard-uci-noreu-mtu1440.prg  BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
#                                    (standard MTU 1440 — needs GideonZ/
#                                     1541ultimate#807 firmware, unmerged)
#   wireguard-uci-reu-mtu1440.prg    BACKEND=uci REU=1 UCI_CHUNKED_WRITE=1
#                                    (same, REU DMA tables)
#   wireguard-reu.d64                wg-rrnet + wg-uci PRGs (REU builds)
#                                    + wg.cfg + fw-warning
#   wireguard-noreu.d64              same pair, no-REU builds
#                                    + wg.cfg + fw-warning
#   wireguard-mtu1440.d64            both mtu1440 PRGs + wg.cfg + fw-warning
#   FIRMWARE-WARNING.txt             copy of tools/release/FIRMWARE-WARNING.txt
#   VERSION                          `git describe --tags --always --dirty`
#   SHA256SUMS                       header line names the version
#
# The wg.cfg on each disk is the placeholder template from
# tools/release/wg.cfg.template (all-zero keys, RFC 5737 endpoint) — the
# 9-line fixed-order SEQ format documented in src/wg/disk_config.s. Users
# replace it with their real keys before use.
#
# Every build/labels.txt is checked structurally after each variant is
# built (not by grepping PRG bytes): the default variants must come out
# with WG_MTU == $035C and no uci_send_part symbol; the mtu1440 variants
# must come out with WG_MTU == $05A0 and uci_send_part present. A mismatch
# fails the script — see the CA65FLAGS staleness trap in the Makefile,
# which is why `make clean` runs between every variant below.
#
# Usage: bash tools/release/build_release.sh
# (invoked by `make release`; every variant is a clean build)
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
REL="$PROJECT_ROOT/build/release"
TEMPLATE="$PROJECT_ROOT/tools/release/wg.cfg.template"
WARNING="$PROJECT_ROOT/tools/release/FIRMWARE-WARNING.txt"
LABELS="$PROJECT_ROOT/build/labels.txt"

command -v c1541 >/dev/null || { echo "ERROR: c1541 (VICE) not on PATH" >&2; exit 1; }
[ -f "$WARNING" ] || { echo "ERROR: $WARNING not found" >&2; exit 1; }

rm -rf "$REL"
mkdir -p "$REL"

# --- Structural label assertions -------------------------------------------
# $1 = artifact name (for error messages), $2 = "default" | "mtu1440"
assert_labels() {
    local out="$1" kind="$2"
    [ -f "$LABELS" ] || { echo "ERROR: $LABELS missing after building $out" >&2; exit 1; }

    local mtu_line mtu_hex send_part_present=0
    mtu_line=$(grep -E '^al C:[0-9A-Fa-f]{4} \.WG_MTU$' "$LABELS" || true)
    [ -n "$mtu_line" ] || { echo "ERROR: $out: WG_MTU label missing from labels.txt" >&2; exit 1; }
    mtu_hex=$(sed -E 's/^al C:([0-9A-Fa-f]{4}) \.WG_MTU$/\1/' <<<"$mtu_line" | tr '[:lower:]' '[:upper:]')
    grep -qE '\.uci_send_part$' "$LABELS" && send_part_present=1

    case "$kind" in
        default)
            [ "$mtu_hex" = "035C" ] || {
                echo "ERROR: $out: expected WG_MTU=\$035C (860), got \$$mtu_hex" >&2; exit 1; }
            [ "$send_part_present" -eq 0 ] || {
                echo "ERROR: $out: uci_send_part unexpectedly present for a default build" >&2; exit 1; }
            ;;
        mtu1440)
            [ "$mtu_hex" = "05A0" ] || {
                echo "ERROR: $out: expected WG_MTU=\$05A0 (1440), got \$$mtu_hex" >&2; exit 1; }
            [ "$send_part_present" -eq 1 ] || {
                echo "ERROR: $out: uci_send_part missing for an mtu1440 build" >&2; exit 1; }
            ;;
        *)
            echo "ERROR: assert_labels: unknown kind '$kind'" >&2; exit 1 ;;
    esac
    echo "    labels OK: WG_MTU=\$$mtu_hex uci_send_part=$([ "$send_part_present" -eq 1 ] && echo present || echo absent)"
}

# $1 = backend, $2 = REU, $3 = chunked (0|1), $4 = output filename
build_variant() {
    local backend="$1" reu="$2" chunked="$3" out="$4"
    local kind="default"
    local -a extra=()
    if [ "$chunked" = "1" ]; then
        extra=(UCI_CHUNKED_WRITE=1)
        kind="mtu1440"
    fi
    echo "=== $out (BACKEND=$backend REU=$reu${chunked:+ UCI_CHUNKED_WRITE=$chunked}) ==="
    make clean >/dev/null
    make BACKEND="$backend" REU="$reu" "${extra[@]}" >/dev/null
    assert_labels "$out" "$kind"
    cp build/wireguard.prg "$REL/$out"
}

build_variant ip65 1 0 wireguard-rrnet-reu.prg
build_variant ip65 0 0 wireguard-rrnet-noreu.prg
build_variant uci  1 0 wireguard-uci-reu.prg
build_variant uci  0 0 wireguard-uci-noreu.prg
build_variant uci  0 1 wireguard-uci-noreu-mtu1440.prg
build_variant uci  1 1 wireguard-uci-reu-mtu1440.prg

cp "$WARNING" "$REL/FIRMWARE-WARNING.txt"

# --- D64 images --------------------------------------------------------
# Two per REU class (both backends, default MTU), one carrying the two
# mtu1440 UCI variants. Every disk also carries wg.cfg and the firmware
# warning as PETSCII-safe SEQ files.
make_d64_2() {
    local d64="$1" prg1="$2" prg1_name="$3" prg2="$4" prg2_name="$5" diskname="$6"
    rm -f "$REL/$d64"
    # Two invocations: c1541 detaches the image after -format, so
    # chaining -write onto the same command writes into the void.
    c1541 -format "$diskname,wg" d64 "$REL/$d64" >/dev/null
    c1541 "$REL/$d64" \
          -write "$REL/$prg1" "$prg1_name" \
          -write "$REL/$prg2" "$prg2_name" \
          -write "$TEMPLATE" "wg.cfg,s" \
          -write "$WARNING" "fw-warning,s" >/dev/null
    local listing
    listing=$(c1541 "$REL/$d64" -list 2>/dev/null)
    for f in "$prg1_name" "$prg2_name" "wg.cfg" "fw-warning"; do
        grep -q "$f" <<<"$listing" || {
            echo "ERROR: $d64 missing '$f' in directory" >&2; exit 1; }
    done
}

make_d64_2 wireguard-reu.d64   wireguard-rrnet-reu.prg   "wg-rrnet" \
                                wireguard-uci-reu.prg    "wg-uci"   "wireguard reu"
make_d64_2 wireguard-noreu.d64 wireguard-rrnet-noreu.prg "wg-rrnet" \
                                wireguard-uci-noreu.prg  "wg-uci"   "wireguard noreu"
make_d64_2 wireguard-mtu1440.d64 wireguard-uci-noreu-mtu1440.prg "wg-uci-noreu" \
                                  wireguard-uci-reu-mtu1440.prg   "wg-uci-reu"   "wireguard mtu1440"

# --- Version stamp -----------------------------------------------------
VERSION="$(git describe --tags --always --dirty)"
echo "$VERSION" > "$REL/VERSION"

# --- Checksums -----------------------------------------------------------
(
    cd "$REL"
    {
        echo "# c64-wireguard $VERSION — SHA256 checksums"
        shasum -a 256 *.prg *.d64 FIRMWARE-WARNING.txt VERSION
    } > SHA256SUMS
)

echo
echo "Version: $VERSION"
echo "Release artifacts:"
ls -la "$REL"
