# c64-wireguard

WireGuard Noise protocol implementation for the Commodore 64, written in 6502 assembly.

## Status

**Milestone reached (2026-07-21): a Commodore 64 completed a full WireGuard IKpsk2 handshake to `SESSION_ACTIVE` and exchanged encrypted Type-4 transport data in both directions on real hardware** (C64 Ultimate, fw 1.1.0, UCI backend, against a Python responder). See `docs/phase-9-handshake-milestone.md` for the campaign log, including the two BLAKE2s key-length state bugs it flushed out.

**Interactive chat, verified bidirectional and self-sustaining (2026-08-17).** A person at the keyboard can hold a two-way conversation over the tunnel: [`tools/wg_chat.py`](tools/wg_chat.py) types from the host, `M` on the C64 types back, and the session rekeys itself so it outlives WireGuard's 180 s `REJECT_AFTER_TIME`. [`tools/wg_demo.py`](tools/wg_demo.py) runs the same path unattended with both ends speaking. See [Interactive chat and demo](#interactive-chat-and-demo).

**The wire is verified encrypted, by assertion rather than inference (2026-08-17).** [`tools/test_wire_encryption_live.py`](tools/test_wire_encryption_live.py) passes 9/9 on hardware: the plaintext is absent from real datagrams in both directions, identical plaintext yields different ciphertext with an advancing counter, and the C64 rejects a packet with one flipped ciphertext bit while the session survives the rejection. See [Verifying encryption on the wire](#verifying-encryption-on-the-wire) — including what is cleartext by design, and the control-plane caveat.

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
| `REU` | `1` (default) / `0` | `1`: REU-DMA multiply tables (banks 0,1,3,4,5; ~4.3 min/scalarmult at 1 MHz). `0`: constant-time on-chip multiply, zero REU use anywhere (~7.3 min/scalarmult at 1 MHz). **Which is faster inverts with clock speed — `REU=0` wins on turbo hardware. See [Performance](#performance).** |
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
$A000-$BFFF  IP65_BSS:     the ip65 blob's private BSS, occupied to $AF3F
                            (BACKEND=ip65 only; reserved but empty at link
                            time — the driver claims it at runtime). Free
                            under BACKEND=uci, which has no blob
```

`$A000-$BFFF` is the RAM under BASIC ROM. `src/boot.s` banks BASIC out
(`lda proc_port` / `and #$fe`) as its first instruction and only restores it
on quit, so the span reads back as RAM for the whole time ip65 can run;
KERNAL lives at `$E000+` and is unaffected. `IP65_BSS` is declared
`file = ""` — a file-backed region there would append 8 KB of zeros to every
ip65 PRG, and it is safe as a non-file region only because it sits above
every file-backed area (see the load-shift note under `SQTAB_HOLE`).

This is issue **#80**, fixed by relinking the blob. Until then
`ip65-build/ip65.cfg` linked the BSS at `$4000` — inside `MAIN_AREA_LO`,
directly on top of `APP_CODE`, `APP_DATA` and the chacha archive — while
this table claimed `$A000-$BFFF` and nothing checked either number. One DHCP
exchange on the ethernet VICE rig overwrote 733 bytes of `APP_CODE`
(`transport_encrypt`, `transport_decrypt`, the replay window) and 284 bytes
of `LIB_CHACHA20_POLY1305_CODE`. The §13.7 equates in
`src/net/ip65/ip65_blob.s` now declare the footprint and assert it at link
time against `IP65_BSS` and against every other region in the cfg, so the
two sides can no longer drift apart silently.

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
| `src/net_abi.inc` | Public UDP networking ABI contract (net_init, net_dhcp_acquire, net_poll, net_udp_*) |
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
U64_ALLOW_MUTATE=1 python3 tools/test_wire_encryption_live.py --host <device-ip>
U64_ALLOW_MUTATE=1 python3 tools/test_config_reload_live.py --host <device-ip>
```

`--host` has no default on the newer tools deliberately: the device's address
moves, and a stale default fails as "unreachable" rather than as "you forgot
the flag". Identify the machine by `GET /v1/info` (`unique_id`), not by IP.

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

- **1 MHz up to and including 16 MHz** → `REU=1` (default), if an REU is present.
- **20 MHz and above** → **`REU=0`**, which is faster *and* removes the REU requirement entirely.

The crossover was measured in the sibling project `c64-https` to fall **between 16 and 20 MHz**, and the Ultimate's selectable speeds are discrete — `1 2 3 4 5 6 8 10 12 14 16 20 24 32 40 48 64` — with nothing between those two settings. So the bracket is as tight as the hardware permits and the rule above has no grey zone in practice.

That is consistent with this repo's own two-point model, which puts it at ~20.4 MHz (treating the REU build as a fixed DMA wall time plus CPU work, `37.6 s + 740/f`, against the no-REU build's pure `1505/f`). The model sits one setting above the measured bracket, which is about the accuracy a two-point fit deserves — quoted here only as corroboration, not as the source.

The 51.7x from a 48x clock is not a measurement error. Badline DMA costs a *fixed* amount at the VIC's own 1 MHz rate, so it takes ~6% of the CPU at 1 MHz and ~0.13% at 48 MHz: predicted `48 x 1.063 = 51.0x` against 51.7x measured. That is the same ~6% figure the VIC blanking section derives, arrived at independently.

Practical consequence: a handshake on turbo hardware is **49-90 seconds** depending on build, not the ~27 s a linear scale would predict of the REU build, and not the 21.7 min of a stock machine.

#### Known limitation: repeated sessions degrade the Ultimate until sends fail silently

After enough back-to-back sessions on one power cycle, the U64E stops delivering packets: `do_handshake` returns `carry=0` with `net_last_error=$00` and a correct 148-byte packet staged, and nothing arrives — [#58](https://github.com/JC-000/c64-wireguard/issues/58). **A power cycle clears it completely.**

This affects **both builds and both clock speeds**. It is device/firmware state, not a property of any configuration: an identical REU binary failed six consecutive runs and then passed immediately after a power cycle, with the hash verified on both sides of it.

The consumer-visible defect is that `net_udp_send` reports success when the write did not happen. This firmware's UCI write status cannot distinguish the two, so a silent send is indistinguishable from a real one from the C64's side. If a session that previously worked stops delivering, power-cycle the Ultimate before suspecting the build.

An earlier revision of this section attributed the same symptom to `REU=0` at 1 MHz and to a socket that could not survive a 25-minute computation. That diagnosis was wrong — it was device state — and is retracted. What remains genuinely untested is `REU=0` at 1 MHz on a *healthy* device: the only run of that combination happened on a degraded one, so its 25.1-minute Type-1 computation is a sound measurement while its delivery failure proves nothing.

All timings are host-side wall clock. On-device CIA-timer measurement is invalid above 1 MHz — the CIA keeps counting at its fixed rate while the CPU runs N× faster, so cycle counts read as `cycles/N` with no error raised.
- Symmetric primitives (order of magnitude, in-tree-era measurements): BLAKE2s compress ~22 ms, ChaCha20 block ~65 ms, Poly1305 block ~110 ms

**VIC-II blanking** buys **6.3%** (1.068x), measured by [`tools/bench_vic_blank.py`](tools/bench_vic_blank.py) across six routines — BLAKE2s, ChaCha20, Poly1305, `fe25519_mul`/`_sqr` and a full `x25519_scalarmult` — all landing in a 1.067-1.069x band. `src/wg/vic_boost.s` applies it around the five scalar multiplies in the handshake and around boot's `sqtab_init`/`reu_mul_init` table build, restoring the display between operations so progress output stays visible.

Measured end-to-end rather than projected: Type-2 handshake processing (`session_handle_packet`, 3x X25519 — README's "~9 min" leg) runs **462.8 s unblanked vs 434.4 s blanked, saving 28.4 s (6.1%)**, reproducible to the tenth of a second across three trials with different key material. See [`tools/bench_vic_blank_handshake.py`](tools/bench_vic_blank_handshake.py), which disables blanking by patching `vic_boost_begin` to an `RTS` at runtime so both legs run the identical binary. 6.1% rather than the per-primitive 6.3% because the KDF/AEAD stretches between the scalar multiplies run unblanked by design, so progress output stays visible.

Note that 6.3% is well short of the "~20-25%" quoted in the c64-x25519 `vic_blank` header, and the smaller figure is the one that survives checking: NTSC is 65 cycles x 262 lines = 17030 cycles per frame, and 25 text rows give 25 badlines per frame at ~43 stolen cycles each — 1075/17030 = 6.31%, which is what the emulator measures to two decimal places. The larger number would need sprites (WG uses none) or a bitmap mode. Filed upstream as [c64-x25519#103](https://github.com/JC-000/c64-x25519/issues/103) and corrected across the fleet (also [c64-nist-curves#116](https://github.com/JC-000/c64-nist-curves/issues/116)).

**All the figures above are NTSC.** Every measurement here runs under `ViceConfig(ntsc=True)`, and the saving is smaller on PAL: 63 cycles x 312 lines = 19656 cycles/frame against the same 25 badlines x ~43 = 1075, giving **~5.5%**. So a PAL machine — including the hardware-validation C64U, if it is running PAL — sees roughly 5.5% rather than 6.3%, and the Type-2 saving would be ~25 s rather than 28.4 s. The blanking figure is a property of the display standard and of the caller's own screen contents, not of the crypto.

The heavy lifting lives in the sibling libraries since v1.0.0 — REU DMA multiply tables (128 KB precompute, banks per [`src/crypto/shared/reu_layout.inc`](src/crypto/shared/reu_layout.inc)), dedicated squaring, SMC cswap, mul38 tables, and the constant-time `ct_mul_8x8` all come from [c64-x25519](https://github.com/JC-000/c64-x25519); the AEAD side from [c64-ChaCha20-Poly1305](https://github.com/JC-000/c64-ChaCha20-Poly1305) (rolled-outer multiply — the size/speed elbow WG opts into). On turbo hosts (Ultimate at 16-48 MHz) the no-REU build scales nearly linearly with clock; the REU build hits a DMA wall-clock floor.

## Interactive chat and demo

```bash
# Interactive: type here, press M on the C64 to type back. /quit to exit.
python3 tools/wg_chat.py --host <device-ip>

# Unattended: a scripted dialogue with both ends speaking.
python3 tools/wg_demo.py --host <device-ip>
```

Both bring the tunnel up from scratch — build, upload, stage config, drive
`do_handshake` to `SESSION_ACTIVE`, hand the machine back to its own main loop
— then relay. Both default to **48 MHz** and restore the shared device to
1 MHz on exit, Ctrl-C included.

**Rekey, so a chat can run indefinitely.** `rekey_pending` has no consumer in
the firmware: `src/wg/timer.s` raises it and prints `REKEY NEEDED`,
`src/wg/transport.s` raises it too, and nothing acts on either — so a session
dies at WireGuard's 180 s `REJECT_AFTER_TIME`. Instead of new in-session
assembly, [`tools/wg_c64_input.py`](tools/wg_c64_input.py) drives the existing
`H` menu entry, re-running the proven `do_handshake` path. Measured: 88 s to a
fresh session, conversation resuming across cycles.

It can do that because `main_loop` and `read_input_line` both read KERNAL
`getin`, which takes from the keyboard *buffer* — ordinary RAM at `$0277` with
its count at `$C6` — and `read/write_memory` still work after the handoff
because they are DMA, not CPU. So the host can type even though trampoline
control is gone by design.

**Rekey only closes at turbo.** A handshake is ~90 s of Type-1 plus ~36 s to
process the Type-2 at 48 MHz, which fits inside the 180 s lifetime. At 1 MHz
the same handshake is ~21.7 min — roughly 7x the lifetime of the session it is
meant to replace — so a self-sustaining chat is arithmetically impossible at
stock speed, not merely slow. The session timers are jiffy-based off the 60 Hz
KERNAL clock (`src/wg/timer.s`: 600 / 7200 / 10800 jiffies = keepalive 10 s,
rekey 120 s, expire 180 s), so they are wall time and turbo does not shorten
them.

## Verifying encryption on the wire

[`tools/test_wire_encryption_live.py`](tools/test_wire_encryption_live.py) —
9/9 on hardware (U64E fw 3.14d, 48 MHz). It asserts on real datagrams:

- the plaintext marker is **absent** from the wire in **both** directions,
  while the same datagram decrypts to it;
- the length accounts for the 16-byte Poly1305 tag (`16 hdr + n + 16`);
- identical plaintext yields **different** ciphertext with an advancing
  counter, so the stream is not a fixed keystream;
- the C64 **rejects** a packet with one flipped ciphertext bit — it is
  authenticating, not merely deciphering — and the session still works
  afterwards, so the rejection is not a denial of service.

The responder socket is a legitimate wire tap for this: we are the peer, so
the bytes handed to `decrypt_transport` are exactly what the C64 transmitted.
No pcap or elevated privileges required.

At unit level, [`tools/test_transport.py`](tools/test_transport.py) runs the
C64's own `transport_send` in VICE and compares ciphertext **and tag**
byte-for-byte against Python's ChaCha20-Poly1305, and additionally asserts the
plaintext does not appear anywhere in the packet the C64 built (guarded to
>= 8-byte plaintexts, since a shorter random string can occur inside
ciphertext by chance and a probabilistic gate failure would be worse than no
check).

**Cleartext by design:** the 16-byte Type-4 header — message type, receiver
index, counter. Everything after it is ciphertext plus tag. That is
WireGuard's own framing, not a shortcut here.

**Control-plane caveat — read this before quoting a green run.** These tools
stage private keys and inject keystrokes over the Ultimate's REST/DMA
interface, which is **plain HTTP on port 80**. So in a `wg_demo.py` run the
C64-side dialogue and the staged keys *do* cross the LAN in the clear, from
the harness's control plane rather than from the tunnel. A packet capture will
find them; filter `not port 80` to isolate the tunnel. A human typing at the
C64's own keyboard has no such exposure.

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

Two interchangeable backends sit behind the `src/net_abi.inc` façade (`net_init`, `net_dhcp_acquire`, `net_poll`, `net_udp_listen`, `net_udp_send`, `net_udp_recv_cb`); higher-level modules (handshake, transport, session) only use these ABI names. Select with `make BACKEND=ip65|uci`.

**ip65 / RR-Net** (`BACKEND=ip65`, the default — VICE-testable): UDP via [ip65](https://github.com/cc65/ip65), driving the RR-Net CS8900a ethernet adapter. The ip65 library is built as a standalone binary blob (ca65/ld65) and linked into the final PRG at $2000 via ca65's `.incbin` directive in `src/net/ip65/ip65_blob.s`. A 10-entry jump table provides: init, process, DHCP, DNS, UDP add/remove listener, UDP send, and helper wrappers. The UDP receive callback fires during `ip65_process` while ip65 owns the zero page; it copies incoming data to `udp_recv_buf` and sets a flag for the main loop — no crypto ZP is touched.

**UCI** (`BACKEND=uci` — the hardware-proven backend for the milestone and v1.0.0 runs): the same ABI implemented over the Ultimate 64 / C64 Ultimate Command Interface sockets ($DF1B-$DF1F, `src/net/uci/`), no ip65 dependency. **Requires Ultimate firmware 3.15 or later** (multi-block `SOCKET_READ`, [GideonZ/1541ultimate#806](https://github.com/GideonZ/1541ultimate/issues/806)). 3.14d is no longer supported: its 893-byte single-read cap and the hang on a 894-byte request cannot be worked around from the C64 side. With 3.15 the C64 can **send** at most 892 bytes per datagram (`SOCKET_WRITE` has no continuation, so anything larger fragments) and **receive** up to 1472; the smaller of the two pins the tunnel MTU — see [Tunnel MTU](#tunnel-mtu) below ([#46](https://github.com/JC-000/c64-wireguard/issues/46)). The device busy-waits are now wall-clock bounded ([#45](https://github.com/JC-000/c64-wireguard/issues/45)). See `docs/hardware-validation-runbook.md`.

> **⚠️ REU build known-failing on fw 3.15 at turbo.** On firmware 3.15 the REU-DMA multiply (`REU=1`, the default) produces wrong products at 48 MHz turbo, so the handshake fails (the responder rejects the C64's Type-1 with `InvalidTag`) — [#69](https://github.com/JC-000/c64-wireguard/issues/69). The cause is a DMA post-execute settle the shared `reu_mul` primitive doesn't yet perform (tracked in c64-x25519; c64-lib-contract §8.2). **Until the x25519 submodule bump lands, build with `REU=0` for hardware** (it also scales better at turbo). The gate's "22/22" and the hardware rows below cover the `REU=0` path and the non-REU logic; they do **not** certify the REU build on 3.15.

### Tunnel MTU

**Peers must be configured with `MTU = 860`, and the Ultimate must run firmware 3.15 or later.** WireGuard's default is 1420; leaving it there will appear to work and then fail on anything large. Firmware 3.14d is not supported (see the UCI paragraph above): its single-read cap of 893 bytes and the 894-request hang are firmware behaviour, fixed upstream in 3.15's multi-block `SOCKET_READ` ([#806](https://github.com/GideonZ/1541ultimate/issues/806)).

A WireGuard Type-4 datagram is `payload + 32` (16-byte header + 16-byte Poly1305 tag). On firmware 3.15 the C64 has two different ceilings, both hardware-verified and both declared in `src/net/uci/net_caps.inc`:

| Direction | Cap | Why |
|---|---|---|
| **Send** (`NET_UDP_SEND_MAX`) | **892** B | `SOCKET_WRITE` carries at most 892 bytes of payload in one command and the firmware has no continuation (`WRITE_SOCKET_MORE`), so a larger datagram is split into several — which a WireGuard peer rejects. |
| **Receive** (`NET_UDP_RECV_MAX`) | **1472** B | Multi-block `SOCKET_READ` (firmware 3.15, [GideonZ/1541ultimate#806](https://github.com/GideonZ/1541ultimate/issues/806)) reassembles up to the largest datagram that reaches the device at all — lwIP is built with `IP_REASSEMBLY = 0`. |

The tunnel MTU is the smaller of the two minus the overhead: `WG_MTU = min(892, 1472) − 32 = 860`, derived in `src/constants.inc` from `net_caps.inc` — it is **send-bound**. The host-side tools read the same two files (`tools/c64_caps.py`) so no Python constant can drift from the assembly.

```ini
[Interface]
MTU = 860
```

**If upstream ships `WRITE_SOCKET_MORE`** ([GideonZ/1541ultimate#802](https://github.com/GideonZ/1541ultimate/issues/802)), the send side stops being the bottleneck: `NET_UDP_SEND_MAX` becomes 1472 too and the tunnel MTU rises to `1472 − 32 = 1440`. That is a one-line change in `net_caps.inc`; the responder already accepts 1440-byte payloads today.

**Why 893 and not 894:** the firmware's own limit is 894 (`CMD_MAX_REPLY_LEN` 896 minus the 2-byte length header), but a read of *exactly* 894 builds a 896-byte reply — precisely the response-queue size — and the FPGA then stops the response pointer while still asserting `DATA_AV`, so the queue repeats its last byte forever. 893 is the largest value that both fits and drains. Requests above 894 are rejected with `82,PARAMETER(S) OUT OF RANGE` on the status channel.

**Correction (2026-08-26).** This section previously stated `MTU = 480` and called `512 − 32` a *measured hardware ceiling*. That was wrong, and the mistake is worth recording: 512 was **this project's own** `UCI_READ_CHUNK_MAX`, chosen as a Phase 3 MVP value. Having only ever asked for 512, we measured that we only ever received 512 and concluded the firmware could do no more. The one larger request we tried (1024) returned nothing, which looked like confirmation — but 1024 is above the real 894 cap and was being *rejected* on the status channel, which this adapter drains without reading. Every individual measurement was sound; the inference joining them was not. Root-caused upstream by chrisgleissner ([GideonZ/1541ultimate#802](https://github.com/GideonZ/1541ultimate/issues/802)) and re-measured here on our own U64E: datagrams of 512, 600, 700, 800, 861 and 893 bytes all arrive whole in a single `net_poll`, the header reporting the true length.

**Follow-up (2026-08-27): 861 → 860.** The previous revision of this section said `MTU = 861`, derived from the *read* side (893 − 32); that was itself one byte too generous, because the ceiling that actually binds is the *send* side: `SOCKET_WRITE` takes at most 892 payload bytes per command and, with no `WRITE_SOCKET_MORE`, the adapter was silently fragmenting anything larger into two datagrams. Receive is no longer the constraint at all — with multi-block reads (fw 3.15, [#806](https://github.com/GideonZ/1541ultimate/issues/806)) the C64 accepts up to 1472 — so the MTU is `892 − 32 = 860`, and it now lives in `net_caps.inc` as `NET_UDP_SEND_MAX` rather than being re-derived by hand.

**A standard 1420-byte MTU is still unreachable**, for two independent reasons:

- One `SOCKET_WRITE` carries at most **892** bytes and the firmware has no continuation command, so a larger outbound datagram is emitted as several — a WireGuard peer rejects each fragment. This is the binding limit today; [GideonZ/1541ultimate#802](https://github.com/GideonZ/1541ultimate/issues/802) tracks `WRITE_SOCKET_MORE`, which would raise it to 1440.
- **1472 bytes** is the largest datagram that reaches the device at all: lwIP is built with `IP_REASSEMBLY = 0`, so anything that fragments is dropped before a socket sees it. That applies to every network service on the device, not just UCI, and is why 1440 rather than 1420-plus would be the ceiling even after #802.

**Cost at stock speed.** Every byte read carries a `uci_fence`, and the C64-Ultimate-conformant fence (`UCI_FENCE_INNER = 217`) is ~5.45 ms at 1 MHz — so an 893-byte read takes several seconds of wall clock at stock speed, against roughly a tenth of that at 48 MHz. Raising the MTU raises that cost proportionally. It is a genuine tension between §13.6 conformance and the no-REU/1 MHz configuration.

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
