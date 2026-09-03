#!/usr/bin/env bash
# vice_eth_nat.sh — NAT the VICE Ethernet rig (10.0.65.0/24 on feth1) out to
# the internet, so the emulated C64 running the ip65/RR-Net build can reach a
# real WireGuard peer (e.g. Cloudflare WARP at 162.159.192.1:2408).
#
# WHAT THIS CHANGES (host-wide, for as long as it is `up`)
# ========================================================
#   1. net.inet.ip.forwarding = 1 — the Mac routes IPv4 between ALL of its
#      interfaces, not just the rig's.  `down` restores the previous value.
#   2. pf is enabled by reference (`pfctl -E`) and a NAT + pass ruleset is
#      loaded into the anchor "com.apple/c64wg".  Your own pf rules are NOT
#      touched: `down` flushes only that anchor and releases the pf enable
#      reference with the token `up` recorded (`pfctl -X <token>`), so pf goes
#      back down only if nothing else still holds it up.
#
#   The anchor is nested under com.apple/ ON PURPOSE.  Stock /etc/pf.conf
#   references only `nat-anchor "com.apple/*"` / `anchor "com.apple/*"`; a
#   top-level anchor named `c64wg` would load without error and then be
#   completely inert, because nothing in the main ruleset evaluates it.
#   Nesting under the wildcard is what makes the rules actually run without
#   editing /etc/pf.conf.  Override with --anchor if you have added your own
#   anchor point.
#
# THE MTU CAVEAT (measured on this host, 2026-09-03)
# ==================================================
#   A full-size WireGuard datagram for WG_MTU1440 is 1472 bytes of UDP
#   payload = 1500 bytes on the wire.  It only survives if the egress path
#   is a 1500-byte path.  Measured here:
#
#     * en0 (10.43.23.99) -> LAN gw 10.43.23.1, DF, 1472 B ....... OK
#     * default route is utun1 (Cloudflare WARP, MTU 1300):
#       DF 1472 to 1.1.1.1 ....................... "sendto: Message too long"
#     * bound to en0 (`ping -b en0`), ANY size, to 1.1.1.1 / 8.8.8.8 /
#       162.159.192.1 ..................... 100% loss; TCP/443 also refused.
#
#   i.e. while the Cloudflare WARP client is connected, it both takes
#   0.0.0.0/0 AND enforces "Firewall Scope: All interfaces", so pinning NAT
#   to en0 does NOT get around it — direct en0 egress is dropped outright.
#   Only 10/8, 172.16/12, 192.168/16 &c. (WARP's exclude list) reach the LAN.
#
#   So, before a full-MTU run, the user must do ONE of (neither needs sudo):
#     a) warp-cli disconnect                      # whole host off WARP
#     b) warp-cli tunnel ip add 162.159.192.0/24  # split-tunnel just the peer
#   and then confirm the path really moved:
#     route -n get 162.159.192.1 | grep -E 'interface|mtu'   # want en0 / 1500
#
#   If you leave WARP up, this script still works, but the egress is utun1 at
#   MTU 1300: the largest WireGuard datagram that can leave is 1300 - 20 - 8
#   = 1272 bytes, i.e. an inner MTU of about 1240.  A 1472-byte datagram is
#   dropped and the kernel answers the rig with ICMP frag-needed, which ip65
#   does not act on — so it black-holes.  `status` reports this verdict.
#
# USAGE
#   sudo bash tools/vice_eth_nat.sh up     [--iface en0] [--net 10.0.65.0/24]
#   sudo bash tools/vice_eth_nat.sh status [--iface en0]
#   sudo bash tools/vice_eth_nat.sh down
#
# Idempotent: `up` twice is a no-op-with-reload, `down` twice is harmless.

set -euo pipefail

ANCHOR="com.apple/c64wg"
RIG_NET="10.0.65.0/24"
RIG_IFACE="feth1"
EGRESS=""
STATE_FILE="/var/run/c64wg-nat.state"
WARP_PEER="162.159.192.1"

die()  { echo "[fail] $*" >&2; exit 1; }
info() { echo "[ok] $*"; }
warn() { echo "[warn] $*" >&2; }

usage() {
    sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        cat >&2 <<EOF
[refused] $(basename "$0") $ACTION needs root: it sets a sysctl and talks to
          /dev/pf, both of which are root-only on macOS.

          Re-run it as:

              sudo bash tools/vice_eth_nat.sh $ACTION${EGRESS:+ --iface $EGRESS}

EOF
        exit 2
    fi
}

# Interface carrying the default route, unless --iface says otherwise.
default_egress() {
    route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}'
}

iface_mtu() {
    ifconfig "$1" 2>/dev/null \
        | awk '/mtu /{for (i = 1; i <= NF; i++) if ($i == "mtu") { print $(i + 1); exit } }'
}

iface_exists() { ifconfig "$1" >/dev/null 2>&1; }

resolve_egress() {
    [[ -n "$EGRESS" ]] || EGRESS="$(default_egress)"
    [[ -n "$EGRESS" ]] || die "no default route and no --iface given"
    iface_exists "$EGRESS" || die "egress interface '$EGRESS' does not exist"
}

# Everything the MTU verdict needs, in one place.
mtu_verdict() {
    local mtu peer_if peer_mtu
    mtu="$(iface_mtu "$EGRESS")"
    peer_if="$(route -n get "$WARP_PEER" 2>/dev/null | awk '/interface:/ {print $2; exit}')"
    peer_mtu="$(route -n get "$WARP_PEER" 2>/dev/null | awk '/^ *[0-9]/ {print $7; exit}')"

    echo "egress             : $EGRESS (mtu ${mtu:-?})"
    echo "route to $WARP_PEER: ${peer_if:-none} (route mtu ${peer_mtu:-?})"

    if [[ "${mtu:-0}" -ge 1500 && "$peer_if" == "$EGRESS" ]]; then
        echo "VERDICT            : OK — 1472-byte WireGuard datagrams (WG_MTU1440) fit."
    elif [[ "$peer_if" != "$EGRESS" ]]; then
        echo "VERDICT            : DEGRADED — traffic to $WARP_PEER leaves via" \
             "'${peer_if:-none}', not the NAT egress '$EGRESS'."
        echo "                     Likely a VPN holding 0.0.0.0/0. A full-MTU run will fail."
        echo "                     Fix: warp-cli disconnect   (or)"
        echo "                          warp-cli tunnel ip add 162.159.192.0/24"
    else
        echo "VERDICT            : DEGRADED — egress mtu ${mtu:-?} < 1500; the largest"
        echo "                     WireGuard datagram that survives is $(( ${mtu:-0} - 28 ))" \
             "bytes, so 1472 will black-hole."
    fi
}

pf_rules() {
    cat <<EOF
nat on $EGRESS inet from $RIG_NET to any -> ($EGRESS)
pass in  on $RIG_IFACE inet from $RIG_NET to any keep state
pass out on $EGRESS inet from any to any keep state
EOF
}

do_up() {
    require_root
    resolve_egress
    iface_exists "$RIG_IFACE" \
        || warn "rig interface '$RIG_IFACE' is not up — run rig-up-macos.sh first"

    # Save prior state exactly once, so a repeated `up` cannot overwrite the
    # real pre-NAT values with the ones this script itself installed.
    if [[ ! -f "$STATE_FILE" ]]; then
        local prev_fwd token
        prev_fwd="$(sysctl -n net.inet.ip.forwarding)"
        # -E enables pf by reference and prints "Token : <n>".
        token="$(pfctl -E 2>&1 | awk '/Token/ {print $NF}')"
        [[ -n "$token" ]] || die "pfctl -E did not return a token"
        printf 'PREV_FORWARDING=%s\nPF_TOKEN=%s\nEGRESS=%s\n' \
               "$prev_fwd" "$token" "$EGRESS" > "$STATE_FILE"
        info "saved prior state to $STATE_FILE (forwarding=$prev_fwd, pf token=$token)"
    else
        info "state file already present — reloading rules only"
    fi

    sysctl -w net.inet.ip.forwarding=1 >/dev/null
    info "net.inet.ip.forwarding = 1"

    pf_rules | pfctl -a "$ANCHOR" -f - \
        || die "pfctl refused the ruleset (see the syntax error above)"
    info "anchor '$ANCHOR' loaded: NAT $RIG_NET -> ($EGRESS)"

    echo
    mtu_verdict
}

do_down() {
    require_root

    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        . "$STATE_FILE"
    fi
    EGRESS="${EGRESS:-$(default_egress)}"

    pfctl -a "$ANCHOR" -F nat   >/dev/null 2>&1 || true
    pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1 || true
    info "anchor '$ANCHOR' flushed (your own pf rules untouched)"

    if [[ -n "${PREV_FORWARDING:-}" ]]; then
        sysctl -w net.inet.ip.forwarding="$PREV_FORWARDING" >/dev/null
        info "net.inet.ip.forwarding restored to $PREV_FORWARDING"
    else
        warn "no saved forwarding value — leaving net.inet.ip.forwarding as-is"
    fi

    if [[ -n "${PF_TOKEN:-}" ]]; then
        # Releases OUR reference only; pf stays up if anything else holds one.
        if pfctl -X "$PF_TOKEN" >/dev/null 2>&1; then
            info "pf enable reference $PF_TOKEN released"
        else
            warn "pfctl -X $PF_TOKEN failed (already released?)"
        fi
    else
        warn "no saved pf token — leaving pf enabled"
    fi

    rm -f "$STATE_FILE"
    info "down"
}

do_status() {
    require_root
    resolve_egress

    echo "=== anchor $ANCHOR ==="
    echo "--- nat ---"
    pfctl -a "$ANCHOR" -s nat 2>/dev/null || echo "(none)"
    echo "--- rules ---"
    pfctl -a "$ANCHOR" -s rules 2>/dev/null || echo "(none)"
    echo
    echo "=== forwarding ==="
    sysctl net.inet.ip.forwarding
    echo
    echo "=== pf ==="
    pfctl -s info 2>/dev/null | head -2 || echo "(pf status unavailable)"
    if [[ -f "$STATE_FILE" ]]; then
        echo "state: $STATE_FILE"
        sed 's/^/  /' "$STATE_FILE"
    else
        echo "state: none (NAT is down, or was never brought up by this script)"
    fi
    echo
    echo "=== mtu ==="
    mtu_verdict
}

ACTION="${1:-}"
if [[ $# -gt 0 ]]; then shift; fi
case "$ACTION" in
    up|down|status) ;;
    -h|--help|help|"") usage 0 ;;
    *) echo "unknown action: $ACTION" >&2; usage 1 ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)     EGRESS="${2:-}";    shift 2 ;;
        --net)       RIG_NET="${2:-}";   shift 2 ;;
        --rig-iface) RIG_IFACE="${2:-}"; shift 2 ;;
        --anchor)    ANCHOR="${2:-}";    shift 2 ;;
        -h|--help)   usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 1 ;;
    esac
done

case "$ACTION" in
    up)     do_up ;;
    down)   do_down ;;
    status) do_status ;;
esac
