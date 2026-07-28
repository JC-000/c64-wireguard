# c64-wireguard v1.0.0 — first release: hardware-proven tunnel, contract-aligned crypto, REU and stock-C64 builds

The first tagged release of the WireGuard implementation for the
Commodore 64, and the release that marks the project's original goal
reached: **on 2026-07-21 a C64 Ultimate (fw 1.1.0) completed a full
WireGuard IKpsk2 handshake to `SESSION_ACTIVE` and exchanged encrypted
Type-4 transport data in both directions on real hardware** against a
Python responder (`docs/phase-9-handshake-milestone.md` is the
campaign log).

## Artifacts

| File | Backend | Field multiply | Runs on |
|---|---|---|---|
| `wireguard-rrnet-reu.prg` | ip65 / RR-Net | REU DMA tables | C64 + RR-Net + REU (512 KB+) |
| `wireguard-rrnet-noreu.prg` | ip65 / RR-Net | CT on-chip | stock C64 + RR-Net |
| `wireguard-uci-reu.prg` | UCI | REU DMA tables | Ultimate 64 / C64 Ultimate |
| `wireguard-uci-noreu.prg` | UCI | CT on-chip | Ultimate with REU disabled |
| `wireguard-reu.d64` | both REU PRGs (`wg-rrnet`, `wg-uci`) + `wg.cfg` template | | |
| `wireguard-noreu.d64` | both no-REU PRGs + `wg.cfg` template | | |

`wg.cfg` on each disk is a placeholder (all-zero keys, RFC 5737
endpoint) in the 9-line fixed-order SEQ format documented in
`src/wg/disk_config.s` — replace it with real keys before use. At
1 MHz, expect ~4.3 min per X25519 scalarmult on the REU builds and
~7.3 min on the no-REU builds (a full handshake is 3 scalarmults plus
AEAD/hashing).

## Contract-aligned sibling crypto (now the shipped default)

The crypto core is no longer the in-tree implementation: the release
links [c64-x25519 v0.8.0](https://github.com/JC-000/c64-x25519) and
[c64-ChaCha20-Poly1305 v0.6.0](https://github.com/JC-000/c64-ChaCha20-Poly1305)
as archives built by the libraries' own contract-§6 `make lib`
targets, composed per
[c64-lib-contract](https://github.com/JC-000/c64-lib-contract) v0.4.1
§8.0: x25519 owns the shared sqtab (§8.1), the REU multiply tables
(§8.2, REU profile only), and the constant-time `ct_mul_8x8` body
(§8.3); chacha defers both its bits (`SHARED_SQTAB_INIT` +
`SHARED_CT_MUL_8X8`). Composition is enforced three ways: link-time
`.assert`s (`src/contract_asserts.s`), od65 manifest checks at
archive-build time, and the existing ABI drift gate. Architecture:
`docs/library-ingestion-architecture.md`.

**Constant-time consequence**: every multiply reachable on the X25519
and Poly1305 paths is now the contract's CT body — the long-standing
non-CT `mul_8x8` finding (#16) is fixed in all shipped
configurations. (The in-tree copy, and its known non-CT branches,
survives only in the non-shipped `USE_*_SIBLING=0` dev build.)

- BLAKE2s remains in-tree by design (no sibling library exists).
- x25519 v0.8.0 also brings the v0.7.0 RFC 7748 decode fix and the
  §4 segment prefixes (`LIB_X25519_*`), adopted in both backend cfgs.
- chacha v0.6.0 removed its REU path upstream: **the no-REU builds
  issue zero REU DMA anywhere**, verified by manifest masks
  (`LIB_X25519_REU_BANKS_USED=$00` onchip, chacha `$00` always).

## Build-system changes

- `USE_X25519_SIBLING` / `USE_CHACHA_SIBLING` default **ON** (must
  match; mixed configs are refused with an explanation).
- New `REU=1|0` knob selects the x25519 profile (REU DMA vs
  `X25519_ONCHIP_MUL`) and gates `reu_mul_init` out of boot.
- New `make release` target: 4 PRG variants + 2 D64 images (c1541) +
  `SHA256SUMS` into `build/release/`.
- WG's own boot/net-wrapper code moved from `CODE` to `BOOT_CODE`,
  ceding the bare `CODE`/`DATA` names to the chacha archive (which
  has not adopted contract §4 yet — upstream #48). `start:` stays at
  $080D; the memory map is unchanged, including the $8000-$83FF
  sqtab hole.

## Issue housekeeping shipped with this release

- #28 (UCI backend port) closed — landed long since; live remnants
  re-filed as #45 (TOD-bounded UCI waits) and #46 (512-byte inbound
  SOCKET_READ cap → WG MTU pinning).
- #16 (non-CT mul_8x8) — fixed in shipped configurations, see above.
- Upstream reports filed from this integration: chacha #47
  (deferral-export gating; a 2-line interim member swap in
  `tools/integration/build_chacha20poly1305.sh` carries us until it
  lands) and #48 (§4 adoption); contract #41 (`.and` vs `&` in the
  SPEC's assert snippets, measured) and #43 (unprefixed manifest
  symbols collide in a two-library link, measured).

## Known limitations

- Inbound datagrams are capped at 512 bytes on the UCI backend
  (firmware truncation, #46) — keep tunnel MTU conservative.
- A full handshake takes ~25 min wall-clock at 1 MHz including
  responder round-trips; standard `wg` peers time out long before
  that, so interop currently needs a patient responder (the Python
  one in `tools/`). Turbo hosts (Ultimate at 48 MHz) scale nearly
  linearly on the no-REU build.
- `uci_wait_idle` is still unbounded (#45); the fw wedge documented
  in the hardware runbook applies.

## Verification

- Full VICE regression suite (642 tests across 19 suites) green on
  the shipped default (ip65 + REU + siblings) at the release commit.
- All four artifact variants + the legacy `0/0` build link clean with
  the contract asserts active.
- Hardware validation: the 2026-07-21 milestone runs (handshake +
  bidirectional transport) on C64 Ultimate fw 1.1.0 predate this
  branch's crypto swap; the sibling implementations passed their own
  hardware suites upstream (x25519 v0.8.0 oracle-gated RFC 7748 runs
  on U64E + C64U; chacha v0.6.0 hardware bench/tests). A post-release
  on-hardware smoke of the v1.0.0 UCI PRG is the first item in the
  next hardware session.
