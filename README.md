# c64-wireguard

WireGuard Noise protocol implementation for the Commodore 64, written in 6502 assembly.

## Status

**Milestone reached (2026-07-21): a Commodore 64 completed a full WireGuard IKpsk2 handshake to `SESSION_ACTIVE` and exchanged encrypted Type-4 transport data in both directions on real hardware** (C64 Ultimate, fw 1.1.0, UCI backend, against a Python responder). See `docs/phase-9-handshake-milestone.md` for the campaign log, including the two BLAKE2s key-length state bugs it flushed out.

**[v1.0.0](https://github.com/JC-000/c64-wireguard/releases/tag/v1.0.0) is the first tagged release** (2026-07-28): ready-to-run `.prg` and `.d64` artifacts for both network backends in REU and stock-C64 (no-REU) variants. The released UCI/REU build repeated the full handshake + bidirectional transport on hardware post-tag (`docs/RELEASE_NOTES_v1.0.0.md` §Verification).

The shipped build links the sibling crypto libraries [c64-x25519](https://github.com/JC-000/c64-x25519) (v0.11.2) and [c64-ChaCha20-Poly1305](https://github.com/JC-000/c64-ChaCha20-Poly1305) (v0.9.0) as archives per the [c64-lib-contract](https://github.com/JC-000/c64-lib-contract) conventions — every reachable multiply on the X25519 and Poly1305 paths is the contract's constant-time `ct_mul_8x8` body. The in-tree crypto remains available behind `USE_*_SIBLING=0` as a legacy/dev configuration.

**Phase 8 complete**: Pre-Shared Key (PSK) support — IKpsk2 protocol compliance, optional PSK in disk config, backward-compatible with zero PSK.

Development-phase history (per-suite test counts have drifted since; `tools/run_regression.py` reports current totals):

| Phase | Components |
|-------|-----------|
| 1 | BLAKE2s-256, HMAC-BLAKE2s, WireGuard KDF |
| 2 | ChaCha20, Poly1305 MAC, ChaCha20-Poly1305 AEAD |
| 3 | Field arithmetic mod 2^255-19, X25519, Noise handshake |
| 4 | UDP networking (ip65, RR-Net, DHCP, ZP time-sharing) |
| 5 | Transport data packets (Type 4 encrypt/decrypt, replay protection) |
| 6 | Session state machine (entropy, config, handshake, packet dispatch) |
| 7 | Application layer (IP packets, disk config, cookies, timers) |
| 8 | Pre-Shared Key support (IKpsk2 compliance, config, disk parsing) |
| MTU / TAI64N / MAC2 / Replay | large payloads, timestamps, cookies→MAC2, 2048-bit sliding window |

## Building

Requires:
- [cc65](https://cc65.github.io/) toolchain (ca65 + ld65 + ar65 + od65) — assembles WG and the sibling archives
- git submodules initialized (`git submodule update --init`) — the sibling crypto libraries in `libs/`
- [ip65](https://github.com/cc65/ip65) source tree symlinked at `ip65/` — only for `BACKEND=ip65`
- VICE's `c1541` — only for `make release` (D64 packaging)

```bash
make                 # ip65/RR-Net backend, REU profile, sibling crypto (default)
make BACKEND=uci     # Ultimate 64 / C64U UCI backend instead of ip65
make REU=0           # no-REU build (x25519 onchip profile) — FASTEST on turbo hardware
make release         # all 4 PRG variants + 2 D64 images + SHA256SUMS in build/release/
make run             # build and launch in VICE (x64sc)
make clean
```

Build knobs (combine freely):

| Knob | Values | Meaning |
|---|---|---|
| `BACKEND` | `ip65` (default) / `uci` | RR-Net via ip65 blob, or Ultimate Command Interface ($DF1B-$DF1F) |
| `REU` | `1` (default) / `0` | `1`: REU-DMA multiply tables (banks 0,1,3,4,5; ~4.3 min/scalarmult at 1 MHz). `0`: constant-time on-chip multiply, zero REU use anywhere (~7.3 min/scalarmult at 1 MHz). **Which is faster inverts with clock speed — `REU=0` wins on turbo hardware. See [Performance](#performance), and note the 1 MHz limitation ([#58](https://github.com/JC-000/c64-wireguard/issues/58)).** |
| `USE_X25519_SIBLING` / `USE_CHACHA_SIBLING` | `1`/`1` (default) or `0`/`0` | Sibling archives vs legacy in-tree crypto. Must match — mixed configs are refused |

The sibling archives are built by the libraries' own `make lib` targets (contract §6) via `tools/integration/build_*.sh` and linked unmodified — no source staging. Both are built with `-D LIB_NO_BARE_EXPORTS=1` so each exports only its `LIB_<X>_`-prefixed manifest, which is what lets `src/contract_asserts.s` import both and check the composition at link time. The networking layer sits behind `src/net_abi.inc`; both backends share the WG core.

## Memory Layout

```
$0801-$1FFF  LOADER:       BASIC stub + BOOT_CODE (boot + net wrapper) +
                            RODATA tables + LIB_X25519_DATA (~3.5 KB of
                            x25519 archive buffers/tables)
$2000-$32EF  NET_CODE:     ip65 binary blob (~4.8 KB) or UCI adapter (~2 KB)
$32F0-$7FFF  MAIN_AREA_LO: crypto + app code + BSS, plus the chacha archive
                            (LIB_CHACHA20_POLY1305_CODE/_DATA since v0.7.0
                            adopted contract §4 prefixes; _CODE is
                            page-aligned — a constant-time requirement, as
                            its nibswap LUTs are read on secret indexes)
                            and LIB_X25519_CODE
$8000-$83FF  SQTAB_HOLE:   quarter-square table window, runtime-built by
                            sqtab_init. Emitted into the PRG as ZERO FILL —
                            a PRG is one contiguous stream, so a file gap
                            here would load everything above it $400 low
$8400-$9FFF  MAIN_AREA_HI: LIB_X25519_INIT_CODE (cold init, reclaimable
                            after boot) + APP_BSS overflow
$A000-$BFFF  ip65 BSS:     private to ip65 (BASIC ROM banked out); unused
                            under BACKEND=uci
```

ip65 uses zero page $02-$1B (cc65 standard). These overlap our crypto ZP variables. The `src/net/ip65/net.s` wrapper saves and restores $02-$1B around every ip65 call (~60 cycles overhead, negligible vs network latency).

The full memory layout is defined in `cfg/c64-wireguard-ip65.cfg` and `cfg/c64-wireguard-uci.cfg` (identical MEMORY maps, so PRG offsets match across backends). Code and data sections declare their target segment with ca65's `.segment` directive; ld65 resolves absolute addresses at link time.

## Source Files

| File | Description |
|---|---|
| `src/loadaddr.s` | 2-byte PRG load address header ($0801) |
| `src/boot.s` | BASIC stub, startup, main loop, network init UI |
| `src/exports.s` | Promotes ZP equates to linker-visible labels for the test harness |
| `src/constants.inc` | Zero page variables, hardware equates (header, not assembled directly) |
| `src/crypto_abi.inc` | Public crypto ABI contract (fe25519_*, x25519_*, chacha20_*, poly1305_*, aead_*, blake2s_*) matching the sibling libraries |
| `src/net_abi.inc` | Public UDP networking ABI contract (net_init, net_dhcp, net_poll, net_udp_*) |
| `src/contract_asserts.s` | Link-time c64-lib-contract checks: REU bank masks disjoint, §8.0 shared-primitive ownership, sibling ABI version |
| `libs/x25519/` | c64-x25519 submodule (v0.11.2) — X25519 + fe25519, the shipped implementation; built via its own `make lib` |
| `libs/chacha20poly1305/` | c64-ChaCha20-Poly1305 submodule (v0.9.0) — ChaCha20/Poly1305/AEAD/word32, the shipped implementation |
| `src/crypto/blake2s.s` | BLAKE2s-256: init, update, final, compress, G function, keyed hashing (in-tree by design — no sibling library) |
| `src/crypto/blake2s_kdf.s` | HMAC-BLAKE2s and WireGuard KDF (kdf_1, kdf_2, kdf_3) |
| `src/crypto/entropy.s` | Hardware RNG: SID voice 3 noise XOR CIA1 timer |
| `src/crypto/word32.s`, `chacha20.s`, `poly1305.s`, `aead.s`, `fe25519.s`, `x25519.s` | **Legacy in-tree crypto** — links only under `USE_*_SIBLING=0` (dev/bisection builds; not shipped — the in-tree `mul_8x8` is non-constant-time, issue #16) |
| `src/wg/handshake.s` | WireGuard IKpsk2 Noise handshake (Type 1/Type 2 packets) |
| `src/wg/transport.s` | Transport data packets: Type 4 encrypt/decrypt, replay protection |
| `src/wg/session.s` | Session state machine: initiate, handle packet, reset, display |
| `src/wg/config.s` | Peer configuration: copy config buffers to handshake state |
| `src/wg/disk_config.s` | KERNAL SEQ file reader for WG.CFG (hex, IP, port parsing) |
| `src/wg/cookie.s` | Type 3 cookie handling (HChaCha20, XChaCha20-Poly1305) |
| `src/wg/ip_build.s` | IP/ICMP/UDP packet construction for tunnel payloads |
| `src/wg/timer.s` | Session timers: keepalive (10s), rekey (120s), expire (180s) |
| `src/wg/tai64n.s` | TAI64N timestamp increment |
| `src/wg/data.s` | Mutable buffers (crypto state, transport state, session config, network buffers) |
| `src/wg/strings.s` | Display strings |
| `src/net/ip65/net.s` | ip65 wrapper: ZP save/restore, init, DHCP, UDP listen/send/recv |
| `src/net/ip65/ip65_blob.s` | `.incbin` wrapper around the pre-built ip65 binary blob |
| `src/net/ip65/ip65_symbols.inc` | ip65 jump-table + variable-pointer equates |
| `src/net/uci/net.s` | UCI backend: net ABI over the Ultimate Command Interface sockets (the hardware-proven backend) |
| `src/net/uci/uci_cmd.s` | UCI register-level command primitives ($DF1B-$DF1F) |
| `src/crypto/shared/reu_layout.inc` | Authoritative REU bank-allocation ledger |
| `tools/integration/build_*.sh` | Sibling archive builds via the libraries' own `make lib` (contract §6) |
| `tools/release/build_release.sh` | `make release` — PRG/D64 artifact matrix + checksums |

### ip65 Build

| File | Description |
|---|---|
| `ip65-build/ip65_stub.s` | Jump table with 10 UDP-focused entry points |
| `ip65-build/ip65.cfg` | ld65 linker config (raw binary at $2000) |

## Zero Page Layout

| Address | Name | Purpose |
|---|---|---|
| $02-$03 | zp_tmp1/2 | Temporary bytes |
| $04-$09 | w32_src1/src2/dst | Word32 operand pointers |
| $0A-$13 | b2s_* | BLAKE2s working variables |
| $14-$1D | cc20_*/lmul*/poly_* | ChaCha20, mult66 pointers (aliased), Poly1305 |
| $1E-$29 | fe_* | Field element arithmetic ($1E-$1F also alias the chacha archive's ct_diff_raw/ct_sign_mask — time-shared, DH and AEAD never co-run) |
| $2A-$2D | x25_* | X25519 ladder state |
| $40-$7F | fe_wide / cc20_work | 64-byte ZP work block: x25519 archive's fe_wide (SMC-pinned, not relocatable) aliasing the chacha archive's cc20_work/keystream — time-shared per call, no state persists |
| $FB-$FE | zp_ptr1/2 | General-purpose pointers |

Note: $02-$1B overlaps with ip65's cc65 ZP usage. The `src/net/ip65/net.s` wrapper handles time-sharing via save/restore. Sibling ZP slots are satisfied by `src/exports.s` (`src/zp_config.inc` is the relocatable slot manifest).

## Testing

Tests use the [c64-test-harness](https://github.com/JC-000/c64-test-harness) package with VICE emulator.

```bash
pip install c64-test-harness

# All 22 suites — the canonical run, and the gate for any change.
# Most run in a staggered parallel pool against a single build; the four that
# rebuild the tree themselves (x25519, write_bytes, uci_stub, both_backends)
# run serially afterwards, then the default build is restored.
python3 tools/run_regression.py

# Individual suites (per-suite counts drift; the runner reports totals):
python3 tools/test_blake2s.py                    # BLAKE2s, HMAC, KDF
python3 tools/test_chacha20_poly1305.py          # ChaCha20, Poly1305, AEAD
python3 tools/test_fe25519.py                    # field arithmetic (accepts the sibling's lazy-reduction [0,2p) contract)
python3 tools/test_x25519.py                     # --slow for full scalarmult
python3 tools/test_handshake.py                  # IKpsk2 Type 1/2
python3 tools/test_networking.py                 # UDP / DHCP / ZP time-sharing
python3 tools/test_transport.py                  # Type 4 + replay
python3 tools/test_session.py                    # state machine
python3 tools/test_phase7.py                     # application layer
python3 tools/test_disk_config.py                # WG.CFG parser
python3 tools/test_phase8_psk.py                 # IKpsk2 PSK
python3 tools/test_mtu.py                        # large payloads (16-bit lengths)
python3 tools/test_tai64n.py                     # timestamps
python3 tools/test_mac2_integration.py           # cookie → MAC2 end-to-end
python3 tools/test_write_bytes_limit.py          # VICE write chunking

# Live hardware (C64U/U64, DeviceLock-aware; needs U64_ALLOW_MUTATE=1):
U64_ALLOW_MUTATE=1 python3 tools/test_uci_handshake_live.py --stage 3 --host <device-ip>
```

All tests use the direct-memory `jsr()` pattern. Use `--seed N` to reproduce specific runs. The MTU suite uses a flag-based `jsr_flag()` that polls a completion flag instead of relying on VICE breakpoints, which become unreliable during long warp-mode computations (>~1000 byte payloads).

### Performance

At 1 MHz. The handshake and turbo figures below were measured on hardware on 2026-08-15 at the current v0.11.2 / v0.9.0 pins; the per-primitive numbers remain hardware-anchored to the c64-x25519 v0.8.0 release and the v1.0.0 runs, and stay current because that library's PRG is byte-identical from v0.8.0 through v0.11.2 — every release since changed manifest metadata, naming, guards and docs only.

(The freshly measured 21.7 min handshake is modestly under the ~23 min this section previously quoted. The direction is consistent with the VIC blanking and `poly1305_lib_init` changes added since v1.0.0, but the old figure was rounded to the nearest minute, so it is too coarse to treat as confirmation of either.)

- X25519 scalar multiply: **~4.3 min** (REU build, 262M cycles) / **~7.3 min** (no-REU build, constant-time on-chip multiply)
- Full handshake wall-clock to `SESSION_ACTIVE`: **21.7 min** measured on hardware (initiation 777.6 s + Type-2 processing 523.1 s; REU build, includes responder round-trips)
- Type-4 transport encrypt/decrypt: ~1-2 s per small packet

#### Turbo scaling on an Ultimate 64 Elite

Measured 2026-08-15 on a U64E (fw 3.14d) at the v0.11.2 / v0.9.0 pins, both legs the same PRG in the same session via [`tools/test_uci_handshake_live.py --stage 3 --turbo N`](tools/test_uci_handshake_live.py) — full stage-3 PASS at both speeds, tunnel carrying data in both directions:

| phase | 1 MHz | 48 MHz | speedup |
|---|---:|---:|---:|
| boot incl. `reu_mul_init` | 11.9 s | 3.2 s | 3.75x |
| Type-1 initiation | 777.6 s | 53.0 s | 14.67x |
| Type-2 → `SESSION_ACTIVE` | 523.1 s | 36.2 s | 14.45x |
| **handshake total** | **1302.0 s** | **89.9 s** | **14.48x** |
| Type-4 round-trip | 3.2 s | 0.6 s | 5.53x |

**A 48x clock buys 14.5x — about 30% scaling efficiency.** This is the REU DMA wall-clock floor: REU transfers do not accelerate with CPU turbo, so the DMA-bound multiply path caps the gain. The internal spread is the evidence rather than an assumption — boot is dominated by `reu_mul_init`'s 128 KB precompute and gains only **3.75x**, while the crypto-bound phases gain ~14.5x. The more DMA-bound the phase, the less turbo helps.

#### Which build to run: the answer inverts with clock speed

The `REU=0` build has no DMA floor, so it scales with the clock. Measured on the same device and session, Type-1 initiation:

| build | 1 MHz | 48 MHz | scaling |
|---|---:|---:|---:|
| REU (`REU=1`, default) | 777.6 s | 53.0 s | 14.7x |
| no-REU (`REU=0`, onchip multiply) | 1505.4 s | **29.1 s** | **51.7x** |

**At 48 MHz the no-REU build is 1.8x FASTER than the REU build** — 49.0 s of handshake crypto against 89.2 s, and it boots in 0.3 s rather than 3.2 s because it has no table precompute. At 1 MHz the ranking is the other way round, with the REU build ~1.9x ahead. So the correct build depends on the machine:

- **1 MHz up to and including 16 MHz** → `REU=1` (default), if an REU is present. Note the limitation below.
- **20 MHz and above** → **`REU=0`**, which is faster *and* removes the REU requirement entirely.

The crossover was measured in the sibling project `c64-https` to fall **between 16 and 20 MHz**, and the Ultimate's selectable speeds are discrete — `1 2 3 4 5 6 8 10 12 14 16 20 24 32 40 48 64` — with nothing between those two settings. So the bracket is as tight as the hardware permits and the rule above has no grey zone in practice.

That is consistent with this repo's own two-point model, which puts it at ~20.4 MHz (treating the REU build as a fixed DMA wall time plus CPU work, `37.6 s + 740/f`, against the no-REU build's pure `1505/f`). The model sits one setting above the measured bracket, which is about the accuracy a two-point fit deserves — quoted here only as corroboration, not as the source.

The 51.7x from a 48x clock is not a measurement error. Badline DMA costs a *fixed* amount at the VIC's own 1 MHz rate, so it takes ~6% of the CPU at 1 MHz and ~0.13% at 48 MHz: predicted `48 x 1.063 = 51.0x` against 51.7x measured. That is the same ~6% figure the VIC blanking section derives, arrived at independently.

Practical consequence: a handshake on turbo hardware is **49-90 seconds** depending on build, not the ~27 s a linear scale would predict of the REU build, and not the 21.7 min of a stock machine.

#### Known limitation: no-REU at 1 MHz does not deliver its Type-1

On a stock 1 MHz machine the `REU=0` build spends **25.1 minutes** computing the initiation and then fails to deliver it — [#58](https://github.com/JC-000/c64-wireguard/issues/58). The C64 reports success (`carry=0`, `net_last_error=$00`), stages a correct 148-byte packet and generates a healthy ephemeral, but the responder never receives anything.

The suspicion is that the UDP socket does not survive 25 minutes of idle computation and the write succeeds against a dead handle, which this firmware's UCI write status cannot distinguish. It is **not** confirmed: the REU build delivers after 777 s at the same clock, so all that is established is a bracket somewhere between ~13 and ~25 minutes.

No turbo configuration is affected, and the REU build at 1 MHz is unaffected. It does hit the stock-C64 case that `REU=0` exists to serve, so treat 1 MHz + `REU=0` as unsupported until #58 is closed.

All timings are host-side wall clock. On-device CIA-timer measurement is invalid above 1 MHz — the CIA keeps counting at its fixed rate while the CPU runs N× faster, so cycle counts read as `cycles/N` with no error raised.
- Symmetric primitives (order of magnitude, in-tree-era measurements): BLAKE2s compress ~22 ms, ChaCha20 block ~65 ms, Poly1305 block ~110 ms

**VIC-II blanking** buys **6.3%** (1.068x), measured by [`tools/bench_vic_blank.py`](tools/bench_vic_blank.py) across six routines — BLAKE2s, ChaCha20, Poly1305, `fe25519_mul`/`_sqr` and a full `x25519_scalarmult` — all landing in a 1.067-1.069x band. `src/wg/vic_boost.s` applies it around the five scalar multiplies in the handshake and around boot's `sqtab_init`/`reu_mul_init` table build, restoring the display between operations so progress output stays visible.

Measured end-to-end rather than projected: Type-2 handshake processing (`session_handle_packet`, 3x X25519 — README's "~9 min" leg) runs **462.8 s unblanked vs 434.4 s blanked, saving 28.4 s (6.1%)**, reproducible to the tenth of a second across three trials with different key material. See [`tools/bench_vic_blank_handshake.py`](tools/bench_vic_blank_handshake.py), which disables blanking by patching `vic_boost_begin` to an `RTS` at runtime so both legs run the identical binary. 6.1% rather than the per-primitive 6.3% because the KDF/AEAD stretches between the scalar multiplies run unblanked by design, so progress output stays visible.

Note that 6.3% is well short of the "~20-25%" quoted in the c64-x25519 `vic_blank` header, and the smaller figure is the one that survives checking: NTSC is 65 cycles x 262 lines = 17030 cycles per frame, and 25 text rows give 25 badlines per frame at ~43 stolen cycles each — 1075/17030 = 6.31%, which is what the emulator measures to two decimal places. The larger number would need sprites (WG uses none) or a bitmap mode. Filed upstream as [c64-x25519#103](https://github.com/JC-000/c64-x25519/issues/103) and corrected across the fleet (also [c64-nist-curves#116](https://github.com/JC-000/c64-nist-curves/issues/116)).

**All the figures above are NTSC.** Every measurement here runs under `ViceConfig(ntsc=True)`, and the saving is smaller on PAL: 63 cycles x 312 lines = 19656 cycles/frame against the same 25 badlines x ~43 = 1075, giving **~5.5%**. So a PAL machine — including the hardware-validation C64U, if it is running PAL — sees roughly 5.5% rather than 6.3%, and the Type-2 saving would be ~25 s rather than 28.4 s. The blanking figure is a property of the display standard and of the caller's own screen contents, not of the crypto.

The heavy lifting lives in the sibling libraries since v1.0.0 — REU DMA multiply tables (128 KB precompute, banks per [`src/crypto/shared/reu_layout.inc`](src/crypto/shared/reu_layout.inc)), dedicated squaring, SMC cswap, mul38 tables, and the constant-time `ct_mul_8x8` all come from [c64-x25519](https://github.com/JC-000/c64-x25519); the AEAD side from [c64-ChaCha20-Poly1305](https://github.com/JC-000/c64-ChaCha20-Poly1305) (rolled-outer multiply — the size/speed elbow WG opts into). On turbo hosts (Ultimate at 16-48 MHz) the no-REU build scales nearly linearly with clock; the REU build hits a DMA wall-clock floor.

## Architecture

The WireGuard handshake follows the IKpsk2 Noise pattern:

1. **Initiator** generates a 148-byte Type 1 packet containing:
   - Ephemeral public key (X25519)
   - Encrypted static public key (ChaCha20-Poly1305 AEAD)
   - Encrypted timestamp (ChaCha20-Poly1305 AEAD)
   - MAC1 (BLAKE2s-128 keyed hash)

2. **Responder** replies with a 92-byte Type 2 packet. The initiator processes it to derive symmetric transport keys for data encryption.

Key derivation uses HMAC-BLAKE2s based HKDF. All field arithmetic operates mod 2^255-19 in little-endian representation, matching the 6502's native carry propagation direction.

### Transport

After the handshake, data is exchanged using Type 4 transport packets:

```
[0-3]   type = 4 (LE u32)
[4-7]   receiver_index (from handshake)
[8-15]  counter (64-bit LE, per-packet nonce)
[16+]   encrypted payload + 16-byte Poly1305 tag
```

Each packet is encrypted with ChaCha20-Poly1305 AEAD using the transport key derived from the handshake. The 12-byte AEAD nonce is 4 zero bytes followed by the 8-byte counter. Replay protection rejects packets with counters below the highest successfully decrypted counter.

### Networking

Two interchangeable backends sit behind the `src/net_abi.inc` façade (`net_init`, `net_dhcp`, `net_poll`, `net_udp_listen`, `net_udp_send`, `net_udp_recv_cb`); higher-level modules (handshake, transport, session) only use these ABI names. Select with `make BACKEND=ip65|uci`.

**ip65 / RR-Net** (`BACKEND=ip65`, the default — VICE-testable): UDP via [ip65](https://github.com/cc65/ip65), driving the RR-Net CS8900a ethernet adapter. The ip65 library is built as a standalone binary blob (ca65/ld65) and linked into the final PRG at $2000 via ca65's `.incbin` directive in `src/net/ip65/ip65_blob.s`. A 10-entry jump table provides: init, process, DHCP, DNS, UDP add/remove listener, UDP send, and helper wrappers. The UDP receive callback fires during `ip65_process` while ip65 owns the zero page; it copies incoming data to `udp_recv_buf` and sets a flag for the main loop — no crypto ZP is touched.

**UCI** (`BACKEND=uci` — the hardware-proven backend for the milestone and v1.0.0 runs): the same ABI implemented over the Ultimate 64 / C64 Ultimate Command Interface sockets ($DF1B-$DF1F, `src/net/uci/`), no ip65 dependency. Firmware caveats: inbound `SOCKET_READ` is capped at 512 bytes (larger datagrams are truncated — #46 tracks pinning the WG MTU accordingly), and the busy-wait loops are currently unbounded (#45). See `docs/hardware-validation-runbook.md`.

### Session State Machine

The session module connects all components into a working WireGuard client:

```
STATE_IDLE (0) → session_initiate → STATE_HS_SENT (1)
STATE_HS_SENT (1) → Type 2 received → STATE_ACTIVE (2)
STATE_ACTIVE (2) → session_reset → STATE_IDLE (0)
```

- **session_initiate**: Loads peer config, generates ephemeral key (SID+CIA hardware entropy), creates Type 1 handshake packet, sends via UDP
- **session_handle_packet**: Dispatches by type — Type 2 (handshake response) derives transport keys, Type 3 (cookie) decrypts and stores cookie for next handshake, Type 4 (data) decrypts and routes by IP protocol
- **Payload routing**: Decrypted Type 4 payloads are routed by IP protocol — ICMP echo replies are validated, UDP packets matching the message port are displayed as text, other payloads are shown as hex

State guards ensure Type 2 packets are only accepted during STATE_HS_SENT and Type 4 packets only during STATE_ACTIVE.

### Application Layer

The tunnel carries standard IPv4 packets. The C64 constructs outgoing IP packets from templates:

- **ICMP ping**: 20-byte IPv4 header + 8-byte ICMP echo request, with RFC 1071 checksum
- **UDP messaging**: 20-byte IPv4 header + 8-byte UDP header + text payload

User commands: `L` loads config from disk, `H` initiates handshake, `P` sends ping, `M` opens message prompt, `S` sends test payload, `Q` quits.

### Configuration

Peer configuration is loaded from a `WG.CFG` sequential file on disk (device 8). The file contains 7 to 9 CR-terminated lines:

1. Static private key (64 hex chars)
2. Static public key (64 hex chars)
3. Peer public key (64 hex chars)
4. Endpoint IP (dotted decimal)
5. Endpoint port (decimal)
6. Tunnel IP (dotted decimal)
7. Ping target IP (dotted decimal)
8. Pre-shared key (64 hex chars) — *optional, defaults to zeros if omitted*
9. Unix timestamp (decimal, up to 10 digits) — *optional, defaults to zeros if omitted*

The Unix timestamp (line 9) initializes the TAI64N epoch anchor for handshake replay protection. If omitted, timestamps start from zero and increment monotonically.

### Cookies and Timers

**Type 3 cookies**: When the server is under load, it replies with a cookie instead of completing the handshake. The cookie is decrypted using XChaCha20-Poly1305 (HChaCha20 subkey derivation) and included as MAC2 in the next handshake initiation.

**Session timers** use the C64's jiffy clock ($A0-$A2, 60 Hz):
- **Keepalive**: Empty Type 4 packet after 10 seconds of silence
- **Rekey**: Re-initiate handshake after 120 seconds
- **Expire**: Reset session after 180 seconds
