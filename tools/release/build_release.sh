#!/usr/bin/env bash
# =============================================================================
# tools/release/build_release.sh — build the full release artifact set.
#
# Produces in build/release/:
#   wireguard-rrnet-noreu-mtu1440.prg  BACKEND=ip65 REU=0 WG_MTU1440=1
#                                    (RR-Net, stock C64, MTU 1440)
#                                    *** THE ONLY HARDWARE-VALIDATED ARTIFACT
#                                     IN THIS SET *** — physical RR-Net in the
#                                     U64E cartridge port, 3 runs 2026-09-05.
#                                     No firmware dependency: ip65's 1472-byte
#                                     caps are native. On-disk as wg-rrnet.
#   wireguard-rrnet-reu-mtu1440.prg  BACKEND=ip65 REU=1 WG_MTU1440=1
#                                    (same with REU DMA tables; NOT the build
#                                     that ran — see #69, REU at 48 MHz.)
#   (there is no ip65 MTU-860 artifact: 860 comes from the UCI 892-byte
#    SOCKET_WRITE cap, which ip65 does not have — see the call sites below)
#   wireguard-uci-reu.prg            BACKEND=uci  REU=1  (Ultimate 64 / C64U)
#   wireguard-uci-noreu.prg          BACKEND=uci  REU=0  (Ultimate, REU disabled)
#   wireguard-uci-noreu-mtu1440.prg  BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
#                                    (standard MTU 1440 — needs Ultimate fw
#                                     3.15+ (not a public release) plus
#                                     GideonZ/1541ultimate#807, an open,
#                                     unmerged issue; on-disk as
#                                     wg-mtu1440-noreu)
#   wireguard-uci-reu-mtu1440.prg    BACKEND=uci REU=1 UCI_CHUNKED_WRITE=1
#                                    (same, REU DMA tables; on-disk as
#                                     wg-mtu1440-reu; no hardware run — REU
#                                     fails the handshake at 48 MHz, #69)
#   wireguard-reu.d64                wg-rrnet + wg-uci PRGs (REU builds)
#                                    + wg.cfg + fw-warning
#   wireguard-noreu.d64              same pair, no-REU builds
#                                    + wg.cfg + fw-warning
#   wireguard-mtu1440.d64            both UCI mtu1440 PRGs (wg-mtu1440-noreu,
#                                    wg-mtu1440-reu) + wg.cfg + fw-warning
#                                    (fw-warning is CR-terminated on disk;
#                                    the flat .txt copy below keeps LF)
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
# must come out with WG_MTU == $05A0 and uci_send_part present; and every
# variant must carry its own backend's private label (net_arp_pump for
# ip65, uci_tod_start for uci) and not the other's, so a BACKEND that
# silently fell back cannot ship green. A mismatch fails the script — see
# the CA65FLAGS staleness trap in the Makefile, which is why `make clean`
# runs between every variant below.
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
# has_label <symbol> — true if labels.txt exports that symbol.
has_label() { grep -qE "\\.$1\$" "$LABELS"; }

# $1 = artifact name (for error messages), $2 = "default" | "mtu1440",
# $3 = expected backend ("ip65" | "uci")
#
# The backend check is not cosmetic. `uci_send_part` alone cannot tell an ip65
# build from a uci one: under BACKEND=ip65 no UCI translation unit links at
# all, so "uci_send_part absent" is satisfied for a reason that has nothing to
# do with UCI_CHUNKED_WRITE, and `build_variant ip65 1 0` and
# `build_variant uci 1 0` produced identical verdicts — a BACKEND that
# silently fell back to the other adapter would have shipped green. So each
# variant also asserts one label that only its own backend defines, and the
# absence of the other backend's:
#   ip65 only  net_arp_pump      (src/net/ip65/net.s — the #120 ARP pump)
#   uci  only  uci_tod_start     (src/net/uci/uci_cmd.s — the CIA1 TOD start)
# `net_last_error` is deliberately NOT used: since #122 both backends export
# it, so it discriminates nothing.
assert_labels() {
    local out="$1" kind="$2" backend="$3"
    [ -f "$LABELS" ] || { echo "ERROR: $LABELS missing after building $out" >&2; exit 1; }

    local mtu_line mtu_hex send_part_present=0 arp_pump=0 tod_start=0
    mtu_line=$(grep -E '^al C:[0-9A-Fa-f]{4} \.WG_MTU$' "$LABELS" || true)
    [ -n "$mtu_line" ] || { echo "ERROR: $out: WG_MTU label missing from labels.txt" >&2; exit 1; }
    mtu_hex=$(sed -E 's/^al C:([0-9A-Fa-f]{4}) \.WG_MTU$/\1/' <<<"$mtu_line" | tr '[:lower:]' '[:upper:]')
    if has_label uci_send_part; then send_part_present=1; fi
    if has_label net_arp_pump;  then arp_pump=1;          fi
    if has_label uci_tod_start; then tod_start=1;         fi

    case "$backend" in
        ip65)
            [ "$arp_pump" -eq 1 ] || {
                echo "ERROR: $out: net_arp_pump missing — this is not an ip65 build" >&2; exit 1; }
            [ "$tod_start" -eq 0 ] || {
                echo "ERROR: $out: uci_tod_start present — a uci unit linked into an ip65 build" >&2; exit 1; }
            ;;
        uci)
            [ "$tod_start" -eq 1 ] || {
                echo "ERROR: $out: uci_tod_start missing — this is not a uci build" >&2; exit 1; }
            [ "$arp_pump" -eq 0 ] || {
                echo "ERROR: $out: net_arp_pump present — an ip65 unit linked into a uci build" >&2; exit 1; }
            ;;
        *)
            echo "ERROR: assert_labels: unknown backend '$backend'" >&2; exit 1 ;;
    esac

    # WG_MTU is decided by the kind; uci_send_part is decided by the kind AND
    # the backend, because the two 1440 routes are not the same mechanism.
    # Under BACKEND=uci the only way to 1440 is the chunked SOCKET_WRITE path,
    # so uci_send_part MUST be there. Under BACKEND=ip65 the 1472-byte caps
    # are native (Makefile: "or use BACKEND=ip65 where the 1472-byte caps are
    # native"), WG_MTU1440=1 alone suffices, and NO UCI translation unit links
    # at all -- so uci_send_part must be ABSENT. Asserting it present for
    # every mtu1440 build would make an ip65 1440 variant unbuildable, and
    # asserting it absent for every one would let a uci 1440 build ship with
    # its send path silently missing.
    case "$kind" in
        default)
            [ "$mtu_hex" = "035C" ] || {
                echo "ERROR: $out: expected WG_MTU=\$035C (860), got \$$mtu_hex" >&2; exit 1; }
            want_send_part=0
            ;;
        mtu1440)
            [ "$mtu_hex" = "05A0" ] || {
                echo "ERROR: $out: expected WG_MTU=\$05A0 (1440), got \$$mtu_hex" >&2; exit 1; }
            [ "$backend" = "uci" ] && want_send_part=1 || want_send_part=0
            ;;
        *)
            echo "ERROR: assert_labels: unknown kind '$kind'" >&2; exit 1 ;;
    esac
    [ "$send_part_present" -eq "$want_send_part" ] || {
        echo "ERROR: $out: uci_send_part is $([ "$send_part_present" -eq 1 ] && echo present || echo absent)," \
             "expected $([ "$want_send_part" -eq 1 ] && echo present || echo absent)" \
             "for a $kind/$backend build" >&2; exit 1; }
    echo "    labels OK: WG_MTU=\$$mtu_hex uci_send_part=$([ "$send_part_present" -eq 1 ] && echo present || echo absent)" \
         "backend=$backend (net_arp_pump=$arp_pump uci_tod_start=$tod_start)"
}

# $1 = backend, $2 = REU, $3 = kind (default|mtu1440), $4 = output filename
#
# The MTU-1440 FLAG DIFFERS BY BACKEND and this is the whole reason the kind
# is passed explicitly rather than inferred from a "chunked" boolean:
#   uci  + mtu1440 -> UCI_CHUNKED_WRITE=1  (the chunked SOCKET_WRITE path;
#                     needs Ultimate fw 3.15+ plus GideonZ/1541ultimate#807)
#   ip65 + mtu1440 -> WG_MTU1440=1         (native 1472 caps, NO firmware
#                     dependency of any kind -- it talks to a CS8900a, not to
#                     the Ultimate firmware)
# Passing UCI_CHUNKED_WRITE=1 to an ip65 build would be meaningless, and
# passing WG_MTU1440=1 to a uci build without the chunked path is refused by
# the Makefile at parse time because WG_MTU would silently clamp back to 860.
build_variant() {
    local backend="$1" reu="$2" kind="$3" out="$4"
    local -a extra=()
    if [ "$kind" = "mtu1440" ]; then
        case "$backend" in
            uci)  extra=(UCI_CHUNKED_WRITE=1) ;;
            ip65) extra=(WG_MTU1440=1) ;;
            *) echo "ERROR: build_variant: unknown backend '$backend'" >&2; exit 1 ;;
        esac
    elif [ "$kind" != "default" ]; then
        echo "ERROR: build_variant: unknown kind '$kind'" >&2; exit 1
    fi
    echo "=== $out (BACKEND=$backend REU=$reu ${extra[*]:-default-MTU}) ==="
    make clean >/dev/null
    make BACKEND="$backend" REU="$reu" "${extra[@]}" >/dev/null
    assert_labels "$out" "$kind" "$backend"
    cp build/wireguard.prg "$REL/$out"
}

# ip65 ships at MTU 1440 ONLY, and no longer at 860.
#
# WHY 860 EXISTED AT ALL, since the reason was never an ip65 one: WG_MTU 860
# derives from WG_DATAGRAM_CAP 892, which is the UCI SOCKET_WRITE payload cap
# ($11, one block). ip65 advertises NET_UDP_SEND_MAX/RECV_MAX 1472/1472
# natively and has no such cap -- so an ip65 build at 860 was carrying a UCI
# limitation into a backend that does not have it. It shipped that way only
# because WG_MTU1440 used to be a generic opt-in defaulting off for both
# backends. Since v1.2.0 the Makefile defaults it to 1 under BACKEND=ip65, so
# a bare `make` and the shipped RR-Net artifact are the same build. The
# WG_MTU1440=1 below is therefore now REDUNDANT and is kept deliberately:
# every variant in this script names its own shape rather than inheriting
# one, so a future change to the default cannot silently re-point a release
# artifact. assert_labels checks the built WG_MTU either way.
#
# NOTE ON THE KIND NAMES. `default` and `mtu1440` name the MTU (860 / 1440),
# not "the default build" -- for ip65 the default build IS the mtu1440 kind,
# and no ip65 `default` variant is built at all.
#
# wireguard-rrnet-noreu-mtu1440.prg is also the ONLY artifact in this set
# validated on real hardware: a physical CS8900a in the U64E cartridge port,
# handshake to ACTIVE and content-verified transport both ways, three runs,
# 2026-09-05. Its sha256 is pinned in docs/RELEASE_NOTES_v1.2.0.md against the
# run logs, so a rebuild that no longer reproduces it is a signal, not a
# curiosity. Dropping 860 means the ip65 slot on every disk is now the build
# that actually ran, rather than a sibling of it.
#
# The -mtu1440 suffix is KEPT rather than renaming these to the plain
# wireguard-rrnet-*.prg names: those names shipped in v1.1.0 meaning MTU 860,
# and reusing them at 1440 would change what a filename means between releases
# without saying so. A name with no successor is a louder signal.
build_variant ip65 0 mtu1440 wireguard-rrnet-noreu-mtu1440.prg
build_variant ip65 1 mtu1440 wireguard-rrnet-reu-mtu1440.prg
build_variant uci  1 default wireguard-uci-reu.prg
build_variant uci  0 default wireguard-uci-noreu.prg
build_variant uci  0 mtu1440 wireguard-uci-noreu-mtu1440.prg
build_variant uci  1 mtu1440 wireguard-uci-reu-mtu1440.prg

cp "$WARNING" "$REL/FIRMWARE-WARNING.txt"

# --- D64 images --------------------------------------------------------
# Two per REU class (both backends, default MTU), one carrying the two
# mtu1440 UCI variants. Every disk also carries wg.cfg and the firmware
# warning as PETSCII-safe SEQ files.
make_d64_2() {
    local d64="$1" prg1="$2" prg1_name="$3" prg2="$4" prg2_name="$5" diskname="$6"
    rm -f "$REL/$d64"
    # The on-disk SEQ warning uses CR (0x0D) line endings, matching real
    # PETSCII text files (a CBM screen editor never sees LF) — the flat
    # FIRMWARE-WARNING.txt copy in $REL stays LF for normal text tools.
    local cr_warning="$REL/.fw-warning.cr"
    tr '\n' '\r' < "$WARNING" > "$cr_warning"
    # Two invocations: c1541 detaches the image after -format, so
    # chaining -write onto the same command writes into the void.
    c1541 -format "$diskname,wg" d64 "$REL/$d64" >/dev/null
    c1541 "$REL/$d64" \
          -write "$REL/$prg1" "$prg1_name" \
          -write "$REL/$prg2" "$prg2_name" \
          -write "$TEMPLATE" "wg.cfg,s" \
          -write "$cr_warning" "fw-warning,s" >/dev/null
    rm -f "$cr_warning"
    local listing
    listing=$(c1541 "$REL/$d64" -list 2>/dev/null)
    for f in "$prg1_name" "$prg2_name" "wg.cfg" "fw-warning"; do
        grep -q "$f" <<<"$listing" || {
            echo "ERROR: $d64 missing '$f' in directory" >&2; exit 1; }
    done
}

# One disk per REU class, carrying one build of each backend. The ip65 slot is
# the MTU-1440 build now that 860 is gone; the uci slot stays at 860, which is
# a real constraint for that backend rather than an inherited one.
make_d64_2 wireguard-reu.d64   wireguard-rrnet-reu-mtu1440.prg   "wg-rrnet" \
                                wireguard-uci-reu.prg            "wg-uci"   "wireguard reu"
make_d64_2 wireguard-noreu.d64 wireguard-rrnet-noreu-mtu1440.prg "wg-rrnet" \
                                wireguard-uci-noreu.prg          "wg-uci"   "wireguard noreu"
make_d64_2 wireguard-mtu1440.d64 wireguard-uci-noreu-mtu1440.prg "wg-mtu1440-noreu" \
                                  wireguard-uci-reu-mtu1440.prg   "wg-mtu1440-reu"   "wg mtu1440"
# No separate RR-Net disk: with 860 dropped, both RR-Net builds are already the
# ip65 slot on wireguard-reu.d64 and wireguard-noreu.d64. A third disk would
# just be a second copy of the same two PRGs. (It existed in the first draft of
# this release, when ip65 shipped at both MTUs and the 1440 pair had nowhere to
# live that was not the #807 firmware disk.)

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
