#!/usr/bin/env bash
# diff_vendored.sh — divergence report for c64-wireguard's vendored crypto sources.
#
# c64-wireguard currently keeps hard copies of crypto modules under
# src/crypto/*.s. Each one has (or used to have) a counterpart in a sibling
# repository (c64-x25519 or c64-ChaCha20-Poly1305). This script diffs every
# vendored file against its sibling origin and prints a short summary so we
# can see at a glance which files are still in sync and which have drifted.
#
# Always exits 0 -- this is a report, not a gate. See tools/check_abi_drift.py
# for the matching gate over the .import/.export ABI surface.
#
# Flags:
#   --full   Print the full unified diff (no 40-line truncation).
#   -h|--help  Show this header.

set -u

WG_ROOT="/Users/someone/Documents/c64-wireguard"
X25519_SRC="/Users/someone/Documents/c64-x25519/src"
CHACHA_LIB="/Users/someone/Documents/c64-ChaCha20-Poly1305/src/lib"
CRYPTO_DIR="${WG_ROOT}/src/crypto"
TRUNC_LINES=40
FULL=0

usage() {
  sed -n '2,18p' "$0"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --full) FULL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

# Path-mapping table. Empty sibling means NO_SIBLING (no upstream to compare to).
# Format: "<wg-file>|<sibling-path-or-empty>"
PAIRS=(
  "fe25519.s|${X25519_SRC}/fe25519.s"
  "x25519.s|${X25519_SRC}/x25519.s"
  "word32.s|${CHACHA_LIB}/word32_lib.s"
  "chacha20.s|${CHACHA_LIB}/chacha20_lib.s"
  "poly1305.s|${CHACHA_LIB}/poly1305_lib.s"
  "aead.s|${CHACHA_LIB}/chacha20poly1305_lib.s"
  "blake2s.s|"
  "blake2s_kdf.s|"
  "entropy.s|"
)

line_count() {
  # Robust line count even if the last line lacks a newline.
  if [ -f "$1" ]; then
    wc -l < "$1" | tr -d ' '
  else
    echo "0"
  fi
}

echo "============================================================================"
echo " diff_vendored.sh -- WG vendored crypto vs sibling origin"
echo "============================================================================"
echo " WG crypto dir : ${CRYPTO_DIR}"
echo " x25519 src    : ${X25519_SRC}"
echo " chacha lib    : ${CHACHA_LIB}"
echo " truncation    : $( [ "$FULL" -eq 1 ] && echo 'OFF (--full)' || echo "${TRUNC_LINES} lines" )"
echo "----------------------------------------------------------------------------"
echo

n_modified=0
n_identical=0
n_no_sibling=0
n_missing_wg=0

for pair in "${PAIRS[@]}"; do
  wg_name="${pair%%|*}"
  sib_path="${pair#*|}"
  wg_path="${CRYPTO_DIR}/${wg_name}"

  if [ ! -f "$wg_path" ]; then
    printf '== %-22s\n' "$wg_name"
    echo "  [warn] WG file missing: ${wg_path}"
    n_missing_wg=$((n_missing_wg + 1))
    echo
    continue
  fi

  if [ -z "$sib_path" ]; then
    printf '== %-22s (WG-only, no upstream library)\n' "$wg_name"
    echo "  [skip] NO SIBLING"
    n_no_sibling=$((n_no_sibling + 1))
    echo
    continue
  fi

  if [ ! -f "$sib_path" ]; then
    printf '== %-22s\n' "$wg_name"
    echo "  [skip] NO SIBLING (expected at: ${sib_path})"
    n_no_sibling=$((n_no_sibling + 1))
    echo
    continue
  fi

  if cmp -s "$wg_path" "$sib_path"; then
    printf '== %-22s\n' "$wg_name"
    echo "  [ok]   IDENTICAL  (sibling: ${sib_path})"
    n_identical=$((n_identical + 1))
    echo
    continue
  fi

  # Count adds / removes from a full diff -u; cheap enough on these files.
  diff_out=$(diff -u "$sib_path" "$wg_path" 2>/dev/null || true)
  added=$(  printf '%s\n' "$diff_out" | grep -cE '^\+[^+]' || true)
  removed=$(printf '%s\n' "$diff_out" | grep -cE '^-[^-]' || true)
  wg_lines=$(line_count "$wg_path")
  sib_lines=$(line_count "$sib_path")

  printf '==== %s (WG=%s / sib=%s / +%s/-%s) ====\n' \
         "$wg_name" "$wg_lines" "$sib_lines" "$added" "$removed"

  if [ "$FULL" -eq 1 ]; then
    printf '%s\n' "$diff_out"
  else
    printf '%s\n' "$diff_out" | sed -n "1,${TRUNC_LINES}p"
    total=$(printf '%s\n' "$diff_out" | wc -l | tr -d ' ')
    if [ "$total" -gt "$TRUNC_LINES" ]; then
      echo "  (... truncated; run \`diff -u ${sib_path} ${wg_path}\` for full)"
    fi
  fi
  n_modified=$((n_modified + 1))
  echo
done

echo "----------------------------------------------------------------------------"
printf ' Summary: %d modified, %d identical, %d no-sibling' \
       "$n_modified" "$n_identical" "$n_no_sibling"
if [ "$n_missing_wg" -gt 0 ]; then
  printf ', %d WG-file-missing' "$n_missing_wg"
fi
echo
echo "============================================================================"

exit 0
