# Phase 9 milestone — first WireGuard handshake on the wire

**2026-05-16**

A C64 running c64-wireguard on a U64E Elite (UCI backend) built a
148-byte WireGuard IKpsk2 Type-1 initiation packet, emitted it as a
UDP datagram, and a Python responder (`tools/wg_responder/`) on the
host LAN accepted it, MAC1-verified it, decoded the noise payload,
and replied with a 92-byte Type-2 response. `wg_state` transitioned
to `SESSION_HS_SENT`. Wall-clock from `do_handshake` entry to return:
**740.8 seconds (12 min 20 s)** at 1 MHz.

This is the first end-to-end live WireGuard handshake exchange this
project has ever produced. The unit-test suite (642 cases across 13
suites) has been green for months; what was missing was the actual
wire path on real hardware with a real peer.

## What had to land

The path from "all unit tests pass" to "Type-1 reaches a peer"
required four C64-side fixes and one host-side responder:

### 1. Custom Python responder (`tools/wg_responder/`)

Real `wg` implementations enforce `REKEY_TIMEOUT = 5 s` and
`REJECT_AFTER_TIME = 180 s` — they reject any Type-1 they took longer
than 180 s to answer. The C64 takes ~12 minutes to compute Type-1
(three X25519 scalar multiplications plus BLAKE2s / ChaCha20-Poly1305
work), so a real peer would never wait. The responder is built on
`noiseprotocol`'s pure-Python `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
implementation with all timing constraints removed — the C64 sets the
pace.

### 2. Port-endianness convention (`src/net/uci/net.s`)

`disk_config.s::parse_decimal_u16` stores port numbers big-endian (to
match `ip65`'s native network-byte-order layout). The UCI firmware's
`UDP_CONNECT` command expects port_lo / port_hi (little-endian) on
the wire. The UCI backend now swaps bytes on push rather than
imposing a storage convention on the rest of the codebase. Without
this, the C64 told the firmware to send to a byte-swapped peer port
and nothing reached the host.

### 3. Type-1 `sender_idx` randomness (`src/wg/session.s`)

`hs_create_initiation` correctly copies `hs_sender_idx[0..3]` into
the Type-1 packet at offset 4, but `session_initiate` (its only
caller) never seeded `hs_sender_idx` with entropy — only the
ephemeral private key got `entropy_fill`'d. The 4-byte field lived in
BSS (zero at boot, never written), so every Type-1 emitted
`0x00000000` as its sender index. The responder echoes that back as
`receiver_idx` in Type-2 and the C64 uses it as `receiver_idx` for
subsequent Type-4 transport packets, so using zero is correctness-
broken across sessions and cryptographically suspect in the
handshake-transcript hashing. Fixed by adding a second
`entropy_fill` call in `session_initiate`, immediately after the
ephemeral-key fill.

### 4. `net_udp_send` SOCKET_WRITE response handling (`src/net/uci/net.s`)

This was the headliner — the bug that made `net_udp_send` silently
report success while no datagram reached the wire. The U64E firmware's
`SOCKET_WRITE` command does **not** put a written-count into
`$DF1E` (RESP_DATA); the only response is a status string in `$DF1F`
(STATUS_DATA). The original c64-wireguard code spin-waited on
`$DF1E`'s `DATA_AV` bit waiting for bytes that never arrived. The
16-bit timeout inside `uci_read_resp_bytes` eventually fired (~3 min
at 1 MHz), but by then the firmware's transmit window for the queued
datagram had closed and the packet was silently discarded. No error
bit, no `net_last_error`, no warning — `wg_state` flipped to
`SESSION_HS_SENT` and nothing was on the wire.

The canonical pattern (from `c64-test-harness/build_socket_write`,
empirically verified by `tests/test_uci_udp_send_live.py`) is:
`drain_status → wait_idle` with no RESP_DATA read at all. UDP is
atomic — if `uci_check_err` didn't flag an error, the whole chunk
went out.

## Empirical metrics

| Metric | Value |
|---|---|
| `do_handshake` wall-clock @ 1 MHz | 740.8 s (12 min 20 s) |
| Type-1 packet size on the wire | 148 bytes |
| C64 source IP (UCI firmware-allocated) | DHCP-assigned, peer-port stable |
| `sender_idx` chosen by C64 (sample run) | `0x7CD1987A` (≠ 0) |
| `wg_state` final | `SESSION_HS_SENT` (1) |
| Responder MAC1 verification | OK |
| Responder noise `read_message(Type-1)` | OK |
| Responder Type-2 emission | 92 bytes back to C64 |

## What's still ahead

- **Stage 2 — `SESSION_ACTIVE`**: the C64 receives the responder's
  92-byte Type-2 via `net_poll`, dispatches to `session_handle_packet`,
  runs `hs_process_response` (two more X25519 operations — another
  ~8 minutes wall-clock), and transitions `wg_state` to `SESSION_ACTIVE`.
- **Stage 3 — Type-4 transport round-trip**: send one ICMP-over-Type-4
  packet through the tunnel and verify the responder decrypts it.
- **Real-`wg` interop**: a future milestone — the custom responder
  exists specifically because real `wg` won't wait the 12 minutes.
  Interop requires either a smaller-budget handshake (turbo-mode
  benchmarking) or a real-`wg` fork with relaxed timing.
- **Robustness follow-ups** documented in session memory:
  port `c64-https`'s TOD-bounded `uci_wait_idle` (the unbounded
  version wedges on stuck STATE bits); investigate U64E firmware
  states like "POST `/v1/machine:writemem` >128 B returns 404" that a
  power-cycle clears.

## Stable hardware quirks documented during this session

Four U64E firmware 3.14d quirks surfaced empirically and are now
captured in persistent memory:

| Quirk | Behaviour | Recovery |
|---|---|---|
| `SOCKET_READ` size cap | Truncates 600–1280 → 512; returns `0xFFFF` for ≥1500 | Always request 512 |
| `SOCKET_WRITE` response | No written-count to RESP_DATA, status-only to STATUS_DATA | Use the harness pattern |
| `uci_wait_idle` wedge | C64-side spin on stuck STATE bit | `client.reboot()` direct (not `recover()`) |
| `writemem` POST degradation | Transient: >128 B body returns 404 "Could not read data from attachment" | Physical power-cycle |
