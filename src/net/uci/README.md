# UCI (Ultimate Command Interface) networking backend

UDP backend for c64-wireguard targeting the **Ultimate 64 Elite** /
1541-Ultimate host-visible Command Interface at `$DF1B-$DF1F`. It
replaces the ip65 + RR-Net stack with firmware-provided sockets, freeing
the C64's zero page and CPU cycles for the WireGuard crypto work.

## Selecting the backend

```
make BACKEND=uci
```

The Makefile and `cfg/c64-wireguard-uci.cfg` (segments `UCI_CODE` /
`UCI_BSS`) are wired up by the build agent — this directory contains
only the assembly sources.

## Hardware requirement

**Not usable on a stock C64 or in VICE.** The backend probes `UCI_ID`
(`$DF1D`) for the firmware signature `$C9` and bails with
`UCI_ERR_NOT_PRESENT` if it isn't there. You need:

- An Ultimate 64 Elite (or a 1541 Ultimate cartridge on a C64), AND
- The Command Interface enabled in firmware, AND
- The firmware's DHCP step to have already completed before the PRG
  loads (we read the lease via `GET_IPADDR`, we don't run DHCP ourselves).

## Relationship to c64-https

The sibling project `c64-https` has a TCP-oriented UCI backend that
ships HTTP and TLS over the same `$DF1x` interface. This directory is
the UDP adaptation for WireGuard. The files `uci_regs.inc`,
`uci_errors.inc`, and `uci_cmd.s` are ported verbatim from c64-https —
the FPGA fence timing (`UCI_FENCE_OUTER=5`, `UCI_FENCE_INNER=100`) is
correctness-critical at 48 MHz turbo and must not be "simplified".

Only `net.s` diverges: instead of `TCP_CONNECT` + stream semantics, it
uses `UDP_CONNECT` to pin the socket to `wg_peer_ip` + `wg_peer_port`
on first send, matching WireGuard's single-peer model. Receive is
polled (not callback-driven), and the peer source IP is copied directly
from `wg_peer_ip` rather than parsed out of an IP header.

## No banner export

The parent c64-https has a `net_banner_str` label consumed by its
`boot.s`. c64-wireguard's `boot.s` doesn't import a per-backend banner
(it prints fixed `net_init_msg` / `net_dhcp_msg` strings from
`src/wg/strings.s`), so there's no `exports.s` in this directory.
