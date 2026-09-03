# UCI (Ultimate Command Interface) networking backend

UDP backend for c64-wireguard targeting the host-visible Command Interface
at `$DF1B-$DF1F` on the **Ultimate 64 Elite** and the **C64 Ultimate**
("Starlight"), and on a 1541-Ultimate cartridge in a stock C64. It replaces
the ip65 + RR-Net stack with firmware-provided sockets, freeing the C64's
zero page and CPU cycles for the WireGuard crypto work — `cfg/c64-wireguard-uci.cfg`
drops the `ZP_IP65` (`$02-$1B`) window entirely, so nothing here needs the
ip65 adapter's save/restore dance around every driver call.

## Selecting the backend

```
make BACKEND=uci
```

`cfg/c64-wireguard-uci.cfg` places this directory's code in `UCI_CODE`
(loaded into the `NET_CODE` region at `$2000`, the slot the ip65 blob
occupies under `BACKEND=ip65`) and its state in `UCI_BSS`. The Makefile
also puts `src/net/$(BACKEND)` on ca65's include path, which is how the
consumer's `.include "net_caps.inc"` resolves to *this* backend's
capabilities header rather than another backend's (SPEC §13.8).

Flags are not tracked across backend switches, so `make clean` between
`BACKEND=ip65` and `BACKEND=uci` is mandatory (issue #76).

## Hardware requirement

**Not usable on a stock C64 or in VICE.** The backend probes `UCI_ID`
(`$DF1D`) for the firmware signature `$C9` and bails with
`UCI_ERR_NOT_PRESENT` if it isn't there. You need:

- An Ultimate 64 Elite / C64 Ultimate (or a 1541 Ultimate cartridge on a
  C64), AND
- The Command Interface enabled in firmware, AND
- Firmware 3.15 or later — 3.14d is no longer supported. See the read-cap
  history in `uci_errors.inc`: 3.14d has no multi-block SOCKET_READ reply,
  and a request of exactly 894 bytes wedges the interface
  (GideonZ/1541ultimate#802), AND
- The firmware's DHCP step to have already completed before the PRG
  loads (`net_dhcp_acquire` reads the lease via `GET_IPADDR`; we don't run
  DHCP ourselves).

## Files

| File | Contents |
|---|---|
| `net.s` | the `src/net_abi.inc` surface: `net_init`, `net_dhcp_acquire`, `net_udp_listen`, `net_udp_send`, `net_udp_close`, `net_poll` |
| `uci_cmd.s` | command-interface primitives: FIFO push, bounded waits, response/status drains |
| `uci_regs.inc` | register map, command IDs, and the `uci_fence` delay macro |
| `uci_errors.inc` | `net_last_error` codes and the adapter's private send/read ceilings |
| `net_caps.inc` | the §13.3 capability header consumers read (`NET_UDP_SEND_MAX`, `NET_UDP_RECV_MAX`) |

## Relationship to c64-https

The sibling project `c64-https` has a TCP-oriented UCI backend that ships
HTTP and TLS over the same `$DF1x` interface. This directory is the UDP
adaptation for WireGuard. `uci_regs.inc`, `uci_errors.inc` and `uci_cmd.s`
were originally ported from c64-https and are **no longer verbatim copies** —
diff them before assuming a fix travels unchanged in either direction. The
UDP side has since grown its own error codes (`$8A` `LONG_READ`, `$8C`
`SEND_TOO_LONG`, `$8D` `OPEN_REFUSED`), its own send/read ceilings
(`UCI_DATA_QUEUE_MAX`, `UCI_READ_CHUNK_MAX`), the multi-block SOCKET_READ
reassembly, and `uci_status_leading_code` for reading the firmware's decimal
refusal codes off the `$DF1F` status channel. What the two adapters *do*
share is the wire-level discipline below, and that half is meant to stay in
lockstep.

### FPGA fence timing (SPEC §13.6)

`UCI_FENCE_OUTER = 5`, `UCI_FENCE_INNER = 217` — one nested delay loop
inserted after every `$DF1C-$DF1F` access, giving the FPGA time to latch
writes and settle reads. This is correctness-critical and must not be
"simplified": below the floor, commands are silently never latched — no
error bit, no status line, just a connect that never happened.

The floor is a property of the *slowest* supported device, not of the one
you own. Bracketed at 64 MHz on a C64 Ultimate (fw 1.1.0 / core 1.49):
51.6 µs FAILs, 62.9 µs PASSes. 217 sits at 85.2 µs, ~35% margin. The
U64E-era `INNER=100` never visibly failed on a U64E but is *below* the C64
Ultimate's floor, which is a §13.6 conformance failure regardless of which
device happens to be on the desk. It only bites under sustained `CMD_DATA`
bursts — the dotted-quad host push in `uci_udp_connect` is exactly that
shape, while short commands like `GET_IPADDR` survive spacings that lose the
connect. The full FAIL/PASS matrix, and the warning about the deliberately
missing `SEC` before the inner `sbc`, are in `uci_regs.inc`.

### Bounded waits (SPEC §13.4)

Every wait is a **wall-clock** budget read from CIA1's TOD, never a cycle
count: a cycle-counted budget collapses at turbo. `uci_wait_idle` and
`uci_wait_not_busy` get 5 s (`UCI_WAIT_IDLE_BUDGET_TENTHS = 50`), response
reads get 1 s, and expiry is `UCI_ERR_WAIT_TIMEOUT` (`$89`) rather than a
hang. The TOD is *stopped* after reset on a U64E, so `net_init` calls
`uci_tod_start` and fails with `NET_ERR_TIMEBASE_STOPPED` (`$01`) if the
clock never ticks — without that every "bounded" wait was unbounded on
hardware while looking fine in VICE, whose TOD runs.

Two different "busy" conditions, two different waits. `uci_wait_not_busy`
watches `CMD_BUSY` (bit 0): "a `PUSH_CMD` has not been accepted yet". It is
already clear the moment the firmware accepts the command, and it never
rises for a Data More continuation. `uci_wait_reply_staged` watches the
STATE field (bits 5..4) and spins while it reads `01` Command Busy — the
firmware is producing a reply block — returning once a block is VALIDATEd
(`$30` Data More / `$20` Data Last) or the interface is Idle; 1 s budget,
`$89` on expiry. `net_poll` uses it before reading the reply header and,
crucially, after acking a Data More block: on that ack the FPGA drops STATE
to `01` at once and the next block is staged by an interrupt, a FreeRTOS
queue post, a task switch and a memcpy on the firmware side. Sampling STATE
once in that window reads "not Data More", which the pre-#112 code took as
Data Last and delivered the first 893-byte block as the whole datagram —
invisible at 1 MHz (the fences alone are ~17 ms), every time at 48 MHz.
The four STATE values are `UCI_STATE_*` in `uci_regs.inc`.

## UDP adaptation

Instead of `TCP_CONNECT` + stream semantics, the adapter uses `UDP_CONNECT`
to pin one socket to a single peer, matching WireGuard's single-peer model.

- **Destination comes from the ABI cells, not from WG state.** The socket is
  pinned to `net_udp_dest_ip` / `net_udp_dest_port` (SPEC §13.1). The adapter
  must never reach into `wg_peer_ip` / `wg_peer_port` — that is the layering
  inversion the ABI cells exist to prevent. `session_stage_dest` in
  `src/wg/session.s` is the consumer-side copy peer → dest, and any host-side
  tool calling `net_udp_send` directly is responsible for staging those cells
  itself; staging only `wg_peer_*` sends to `0.0.0.0` with carry clear and no
  error, i.e. it looks exactly like a working send.
- **The connect is deferred.** `net_udp_listen` only latches the local port;
  the destination isn't known until the first outbound packet, so
  `UDP_CONNECT` fires inside the first `net_udp_send`.
- **One write, one datagram.** A connected UDP socket emits one packet per
  `SOCKET_WRITE`, so an oversized frame does not chunk, it *fragments*:
  measured on hardware, a 1452-byte send left as 800 + 652 with carry clear
  and no error. Hence the `$8C` `SEND_TOO_LONG` pre-check against
  `NET_UDP_SEND_MAX` (892) before any register is touched. Receive is not
  symmetric — fw 3.15 splits large replies across Data More blocks, so
  `NET_UDP_RECV_MAX` is 1472 and the tunnel MTU is send-bound.
- **Receive is polled**, not callback-driven; callbacks are an ip65 concept
  and `net_udp_recv_cb` is only an RTS stub here. `net_poll` returns C=1 only
  on a backend error — carry carries no "data arrived" meaning (SPEC §13.2);
  availability is `udp_recv_ready`.
- **The peer source IP is copied from `net_udp_dest_ip`** rather than parsed
  out of an IP header — on a connected socket the source is always the peer
  we're pinned to.
- **The socket is closed on teardown.** lwIP's `MEMP_NUM_UDP_PCB` is 8
  (GideonZ/1541ultimate#808), so leaked opens walk the pool and the 9th
  `UDP_CONNECT` is refused with `85,ERROR OPENING SOCKET` on the status
  channel — surfaced as `$8D` `OPEN_REFUSED`. Abandoning a *live* socket also
  poisons the U64E's lease path until a wall power cycle (issue #58), so
  `net_udp_close` is part of the ABI, not an optimisation.

## No banner export

The parent c64-https has a `net_banner_str` label consumed by its
`boot.s`. c64-wireguard's `boot.s` doesn't import a per-backend banner
(it prints fixed `net_init_msg` / `net_dhcp_msg` strings from
`src/wg/strings.s`), so there's no `exports.s` in this directory.

## Not yet shipped

`net_manifest.s` (SPEC §13.0 `NET_BACKEND_FAMILIES`) and the consumer's
`net_abi_asserts.s` (§13.8) are deliberately absent, for both backends. The
ip65 backend exports no `net_last_error`, so a `NET_FAMILY_CORE` claim would
link green over an error channel that does not exist. The reasoning is
recorded at `src/net_abi.inc`; tracked in issue #48, blocked on
c64-lib-contract#148.
