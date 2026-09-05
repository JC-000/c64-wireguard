#!/usr/bin/env bash
# =============================================================================
# tools/rig-up-rrnet-macos.sh — bring up the PHYSICAL RR-Net segment on macOS.
#
# Topology: a real RR-Net cartridge in the U64E's cartridge port, cabled
# DIRECTLY (no switch) to a USB-Ethernet NIC on this Mac. The NIC is the only
# other station on that segment, so it plays gateway, DHCP server and
# WireGuard peer all at once.
#
#   [ C64 + RR-Net (CS8900a, 10baseT) ] <--cable--> [ Mac USB-Eth NIC ]
#
# WHY THIS IS NEEDED. src/boot.s's do_net_init calls net_dhcp_acquire and
# RETURNS on failure -- there is no static-IP path, and WG.CFG carries no
# local-address line (only peer/endpoint/tunnel/ping). So without a DHCP
# server on this segment the ip65 build stops at "DHCP FAILED" and never
# reaches net_udp_listen. Self-assigned 169.254 addressing is not enough:
# the C64 does not do IPv4LL, it does DHCP or nothing.
#
# This replaces the self-assigned 169.254 address on the NIC with a real
# /24 and serves leases on it. The C64 then gets a routable-looking address
# and the Mac is reachable at HOST_IP as the WireGuard endpoint.
#
# SUBNET CHOICE: 10.0.66.0/24, deliberately NOT 10.0.65.0/24. The VICE-side
# feth rig (tools/rig-up-macos.sh in c64-https) already owns 10.0.65.1 on
# feth1. Sharing the subnet would put 10.0.65.1 on two interfaces, make the
# route for 10.0.65.0/24 ambiguous, and have a second dnsmasq fight for a
# listen-address the first already holds -- and we want BOTH rigs up at once,
# since comparing real silicon against the feth pair is the whole point.
#
# NOTE: a lease is NOT a route. This link has no path off itself. The
# WireGuard peer must therefore run ON this Mac, listening at HOST_IP, with
# WG.CFG's endpoint pointed at it. Reaching anything beyond the cable would
# need ip forwarding plus a pfctl NAT rule, which is deliberately out of scope
# for a first hardware validation -- it would add two failure modes to a run
# whose job is to test the C64 side.
#
# Requires sudo: binding UDP/67 and setting an interface address both do.
#
#   Up:    sudo bash tools/rig-up-rrnet-macos.sh en4
#   Down:  sudo bash tools/rig-up-rrnet-macos.sh en4 down
#
# Idempotent. `down` restores DHCP (self-assigned) addressing on the NIC.
# =============================================================================
set -euo pipefail

IFACE="${1:?usage: $0 <interface> [down]   e.g. $0 en4}"
ACTION="${2:-up}"

HOST_IP=10.0.66.1
NETMASK=255.255.255.0
LEASE_LO=10.0.66.10
LEASE_HI=10.0.66.60
LEASE_TIME=1h

# ip65's default MAC on this cartridge, measured by the c64-test-harness lane.
# Pinned so the C64 always takes the SAME address, which makes captures and
# checkers comparable across runs -- and .200 matches the address the
# static-IP pingstatic control build uses, so the bench-health control and the
# WireGuard run see the C64 at one address either way.
C64_MAC=00:0e:3a:64:64:64
C64_IP=10.0.66.200

PIDFILE=/tmp/c64-rrnet-dnsmasq.pid
LOGFILE=/tmp/c64-rrnet-dnsmasq.log
LEASEFILE=/tmp/c64-rrnet-dnsmasq.leases
OFFSETFILE=/tmp/c64-rrnet-dnsmasq.offset
DNSMASQ="$(command -v dnsmasq || echo /opt/homebrew/sbin/dnsmasq)"

if [[ "$ACTION" == "down" ]]; then
    if [[ -f "$PIDFILE" ]]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
        echo "dnsmasq stopped"
    fi
    # Hand the NIC back to DHCP/self-assigned.
    ipconfig set "$IFACE" DHCP 2>/dev/null || true
    echo "$IFACE returned to DHCP addressing"
    exit 0
fi

# --- sanity: the NIC must exist and the cable must be up ---------------------
if ! ifconfig "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: no such interface: $IFACE" >&2; exit 1
fi
if ! ifconfig "$IFACE" | grep -q "status: active"; then
    echo "ERROR: $IFACE is not 'status: active' -- is the cable connected and" >&2
    echo "       the C64 powered on? A CS8900a only lights the link when the" >&2
    echo "       cartridge has power." >&2
    ifconfig "$IFACE" | sed 's/^/       /' >&2
    exit 1
fi
# A 10baseT link is the expected media for an RR-Net; anything faster means
# we are almost certainly pointed at the wrong NIC.
if ! ifconfig "$IFACE" | grep -q "10baseT"; then
    echo "WARNING: $IFACE is not negotiated at 10baseT. An RR-Net (CS8900a) is" >&2
    echo "         10 Mbps only, so this may be the wrong interface." >&2
    ifconfig "$IFACE" | grep media | sed 's/^/         /' >&2
fi

# --- refuse to collide with the feth rig --------------------------------------
if pgrep -f "dnsmasq.*listen-address=$HOST_IP" >/dev/null 2>&1; then
    echo "ERROR: a dnsmasq is already serving $HOST_IP. Two rigs cannot share" >&2
    echo "       an address. Check: pgrep -fl dnsmasq" >&2
    exit 1
fi

# --- address ------------------------------------------------------------------
ifconfig "$IFACE" inet "$HOST_IP" netmask "$NETMASK" up
echo "$IFACE -> $HOST_IP/${NETMASK}"

# --- dnsmasq ------------------------------------------------------------------
# TRUNCATE BOTH UNCONDITIONALLY, and record the byte offset a checker must
# start reading the log from. --log-facility APPENDS, and the lease file
# survives a rig-up that finds dnsmasq already running -- so without this a
# checker grepping for "DHCPACK ... 10.0.66.200" matches YESTERDAY's line and
# reports "the C64 took a lease" with the C64 POWERED OFF. That is a false
# pass on the one step everything downstream depends on, since our build
# stops at DHCP failure and never reaches net_udp_listen.
: > "$LEASEFILE"
: > "$LOGFILE"
echo 0 > "$OFFSETFILE"
echo "leases and log truncated; checkers read $LOGFILE from offset 0"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "dnsmasq already running (pid $(cat "$PIDFILE"))"
else
    "$DNSMASQ" \
        --interface="$IFACE" \
        --bind-interfaces \
        --except-interface=lo0 \
        --listen-address="$HOST_IP" \
        --dhcp-range="$LEASE_LO,$LEASE_HI,$LEASE_TIME" \
        --dhcp-host="$C64_MAC,$C64_IP" \
        --dhcp-option=option:router,"$HOST_IP" \
        --dhcp-option=option:dns-server,"$HOST_IP" \
        --dhcp-authoritative \
        --log-dhcp \
        --log-facility="$LOGFILE" \
        --pid-file="$PIDFILE" \
        --dhcp-leasefile="$LEASEFILE" \
        --port=0
    echo "dnsmasq started (pid $(cat "$PIDFILE" 2>/dev/null || echo '?'))"
fi

echo
echo "Rig up on $IFACE:"
echo "  host / WG endpoint : $HOST_IP"
echo "  DHCP pool          : $LEASE_LO - $LEASE_HI"
echo "  leases             : $LEASEFILE"
echo "  dnsmasq log        : $LOGFILE (truncated; read from offset $(cat "$OFFSETFILE"))"
echo
echo "Watch the C64 take a lease with:  tail -f $LOGFILE"
echo "Capture the wire with:            sudo tcpdump -i $IFACE -n -s0 -w /tmp/rrnet.pcap"
