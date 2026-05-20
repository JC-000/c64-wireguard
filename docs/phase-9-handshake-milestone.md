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

## Stage 2 investigation (2026-05-17 update)

Stage 2 (`SESSION_ACTIVE`) is **still failing** but the failure mode is now
characterised. Two bugs and one blocker found during the investigation:

### Bug #1: `b2s_out_len` truncation leak — FIXED

`hs_compute_mac1` (`src/wg/handshake.s`) sets `b2s_out_len = 16` for MAC1's
128-bit truncated BLAKE2s output, then RTSes without restoring the default
of 32. Every subsequent BLAKE2s call in `hs_process_response` — which
includes `hs_mix_hash`, `hmac_blake2s`, and every KDF round — silently
truncates to 16 bytes, leaving stale `b2s_h[16..31]` in positions 16–31
of every `kdf_out1/2/3`. The chaining-key transcript becomes garbage
within the first `mix_hash` call.

The same leak exists symmetrically in `hs_set_mac2` (`src/wg/cookie.s`),
which only fires on the Type-3 cookie path so it wasn't on the stage-2
critical path; fixed for parity.

Diagnostic evidence — pre-fix C64 dump (every output shares a 16-byte tail):

```
C64 kdf_out1 = 4361d76729964ac962cc061782ca990e c1075bd70719be356b92cb15b6e1280b
C64 kdf_out2 = 1e6effe1c8492b027ab38be1c2db50f3 c1075bd70719be356b92cb15b6e1280b
C64 kdf_out3 = a43b48db3619a2956b3a51a840a24c2c c1075bd70719be356b92cb15b6e1280b
```

The shared suffix is the stale `b2s_h` state from a previous BLAKE2s
finalisation; only the first 16 bytes of each "32-byte" value are valid
output. Fix: restore `b2s_out_len = 32` before `rts`.

### Bug #2: AEAD-verify state still diverges after Bug #1 — UNRESOLVED

With the b2s_out_len fix in place, all C64 outputs become full 32 bytes
(no shared tail), but the values still don't match the responder's view
at AEAD-verify time:

```
C64 hs_h       = 4de2dc4463471356a7c744c22555a6496df40cee1979abadd92450e779083de6
resp h_at_aead = f9fda1c1b96c47d3dce26cf7b8882e4a737700b2dd55cd1b8041f0e1f568b4ed

C64 aead_key   = 7567193cfd0161ae81d26bacfcff96a76dac7250ec762a6215de952c6380eb73
resp k_at_aead = 85ebb7147f1a8e024c4c421ec0a8ecac8714341a9d94bf5d5a63bc4cc5babde7
```

Type-2 packet bytes match between C64 (`hs_resp_packet`) and the
responder's transmitted bytes, so the divergence is in the transcript
computation, not the wire. The next step is to read C64's `hs_h` and
`hs_c` immediately after `do_handshake` (post-Type-1 emit, pre-Type-2
receive) and compare against the responder's `h_after_T1` / `ck_after_T1`
captured via SymmetricState monkey-patch. The instrumentation is in
`tools/test_uci_handshake_live.py --dump-aead` but Bug #3 (below)
prevents reliable iteration.

### Bug #3: `uci_wait_idle` STATE-bit wedge — filed as test-harness#112

`uci_wait_idle` in `src/net/uci/uci_cmd.s` is an unbounded spin loop.
After ~3 successful `run_prg` cycles per physical power-cycle, the U64E
FPGA's UCI STATE bit stays set for ~178 s after the next `SOCKET_WRITE`;
`uci_wait_idle` wedges, the queued datagram is silently dropped
(`net_last_error = $00`, `carry = 0`), and any responder times out.
`client.reboot()` does not clear the state — only a physical
power-cycle. Filed as
[c64-test-harness#112](https://github.com/JC-000/c64-test-harness/issues/112).

**Deterministic reproduction** is now available via
[`tools/test_uci_wedge_repro.py`](../tools/test_uci_wedge_repro.py),
which isolates the trigger. Controlled arms showed:

* 80 × `SOCKET_WRITE` in a single PRG-load session: **0 wedges**
  (max latency 0.82 s).
* 80 × `SOCKET_WRITE` + 651 concurrent `writemem` POSTs: **0 wedges**
  (max latency 0.71 s).
* 5 × back-to-back `run_prg` sessions (10 sends each): clean through
  session 3, **wedge at session 4 iter-0 for 178.12 s**, session 5
  wedges identically — state persists across fresh `run_prg`.

So the trigger is **cumulative `run_prg` count**, not UCI command volume
and not arbitrary REST POST volume. Each `run_prg` issues a chunked
writemem burst plus a `runners` start control POST; repetition of that
specific REST sequence is what walks the FPGA UCI STATE machine into
the silent-wedge condition.

Practical budget: **≤3 `run_prg` cycles per physical power-cycle.**
Plan instrumented test runs accordingly until #112 yields a software
UCI-state-reset primitive.

Proper C64-side fix (still required): port the TOD-bounded
`uci_wait_idle` and `uci_wait_not_busy` from
`c64-https/src/net/uci/uci_cmd.s` (5 s CIA1 TOD budget; returns
`C=1` on timeout with `net_last_error = UCI_ERR_WAIT_TIMEOUT`).
Callers in `src/net/uci/net.s` need to propagate the carry-flag error.
This turns the 178 s silent wedge into a fast-fail error code but
does not recover the underlying FPGA state — that still needs #112.

## What's still ahead

- **Bug #2: locate AEAD transcript divergence point** — re-run
  `--dump-aead` with post-Type-1 hs_h/hs_c snapshot and the `uci_wait_idle`
  fix from #112 in place. If post-T1 state matches responder's, the bug
  is inside `hs_process_response`; otherwise it's in `hs_create_initiation`
  (despite the responder accepting Type-1).
- **Stage 2 — `SESSION_ACTIVE`**: dependent on Bug #2.
- **Stage 3 — Type-4 transport round-trip**: send one ICMP-over-Type-4
  packet through the tunnel and verify the responder decrypts it.
- **Real-`wg` interop**: a future milestone — the custom responder
  exists specifically because real `wg` won't wait the 12 minutes.
  Interop requires either a smaller-budget handshake (turbo-mode
  benchmarking) or a real-`wg` fork with relaxed timing.

## Stable hardware quirks documented during this session

Four U64E firmware 3.14d quirks surfaced empirically and are now
captured in persistent memory:

| Quirk | Behaviour | Recovery |
|---|---|---|
| `SOCKET_READ` size cap | Truncates 600–1280 → 512; returns `0xFFFF` for ≥1500 | Always request 512 |
| `SOCKET_WRITE` response | No written-count to RESP_DATA, status-only to STATUS_DATA | Use the harness pattern |
| `uci_wait_idle` wedge | Deterministic after ~3 `run_prg` cycles; ~178 s silent drop | Physical power-cycle; ≤3 cycles/budget |
| `writemem` POST degradation | Transient: >128 B body returns 404 "Could not read data from attachment" | Physical power-cycle |
