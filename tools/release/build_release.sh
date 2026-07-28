#!/usr/bin/env bash
# =============================================================================
# tools/release/build_release.sh — build the full release artifact set.
#
# Produces in build/release/:
#   wireguard-rrnet-reu.prg     BACKEND=ip65 REU=1  (RR-Net + REU)
#   wireguard-rrnet-noreu.prg   BACKEND=ip65 REU=0  (RR-Net, stock C64)
#   wireguard-uci-reu.prg       BACKEND=uci  REU=1  (Ultimate 64 / C64U)
#   wireguard-uci-noreu.prg     BACKEND=uci  REU=0  (Ultimate, REU disabled)
#   wireguard-reu.d64           wg-rrnet + wg-uci PRGs (REU builds) + wg.cfg
#   wireguard-noreu.d64         same pair, no-REU builds        + wg.cfg
#   SHA256SUMS
#
# The wg.cfg on each disk is the placeholder template from
# tools/release/wg.cfg.template (all-zero keys, RFC 5737 endpoint) — the
# 9-line fixed-order SEQ format documented in src/wg/disk_config.s. Users
# replace it with their real keys before use.
#
# Usage: bash tools/release/build_release.sh
# (invoked by `make release`; every variant is a clean build)
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"
REL="$PROJECT_ROOT/build/release"
TEMPLATE="$PROJECT_ROOT/tools/release/wg.cfg.template"

command -v c1541 >/dev/null || { echo "ERROR: c1541 (VICE) not on PATH" >&2; exit 1; }

rm -rf "$REL"
mkdir -p "$REL"

build_variant() {
    local backend="$1" reu="$2" out="$3"
    echo "=== $out (BACKEND=$backend REU=$reu) ==="
    make clean >/dev/null
    make BACKEND="$backend" REU="$reu" >/dev/null
    cp build/wireguard.prg "$REL/$out"
}

build_variant ip65 1 wireguard-rrnet-reu.prg
build_variant ip65 0 wireguard-rrnet-noreu.prg
build_variant uci  1 wireguard-uci-reu.prg
build_variant uci  0 wireguard-uci-noreu.prg

# --- D64 images: one per REU class, both backends on each disk ---
make_d64() {
    local d64="$1" rrnet_prg="$2" uci_prg="$3" diskname="$4"
    rm -f "$REL/$d64"
    # Two invocations: c1541 detaches the image after -format, so
    # chaining -write onto the same command writes into the void.
    c1541 -format "$diskname,wg" d64 "$REL/$d64" >/dev/null
    c1541 "$REL/$d64" \
          -write "$REL/$rrnet_prg" "wg-rrnet" \
          -write "$REL/$uci_prg" "wg-uci" \
          -write "$TEMPLATE" "wg.cfg,s" >/dev/null
    # Verify directory contents made it
    local listing
    listing=$(c1541 "$REL/$d64" -list 2>/dev/null)
    for f in "wg-rrnet" "wg-uci" "wg.cfg"; do
        grep -q "$f" <<<"$listing" || {
            echo "ERROR: $d64 missing '$f' in directory" >&2; exit 1; }
    done
}

make_d64 wireguard-reu.d64   wireguard-rrnet-reu.prg   wireguard-uci-reu.prg   "wireguard reu"
make_d64 wireguard-noreu.d64 wireguard-rrnet-noreu.prg wireguard-uci-noreu.prg "wireguard noreu"

# --- Checksums ---
( cd "$REL" && shasum -a 256 *.prg *.d64 > SHA256SUMS )

echo
echo "Release artifacts:"
ls -la "$REL"
