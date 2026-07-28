# Library-ingestion architecture

How c64-wireguard consumes the sibling crypto libraries `c64-x25519`
(v0.8.0) and `c64-ChaCha20-Poly1305` (v0.6.0) **as the shipped
default**, linking the libraries' own contract-§6 archive products with
zero source staging (one documented interim exception).

The companion piece is the [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
repo (SPEC v0.4.1), which pins the cross-project ZP / REU / segment /
shared-primitive conventions. The pre-release staged-source pipeline
(PRs #35-#38, submodule pins x25519 v0.6.0 / chacha `8cc3ab3`) is
retired; see git history of this file and of
`tools/integration/*.sh` for that design.

## Scope

Consumer side only: how WG's Makefile, integration scripts, linker
configs, and ABI gates wire the sibling `.a` files into the PRG.
Audience: someone bumping a submodule pin, adding a third sibling, or
debugging a duplicate-symbol / unresolved-import link error.

## The toggles

| Toggle | Default | Sibling repo | Pinned in |
| --- | --- | --- | --- |
| `USE_X25519_SIBLING` | **1** | `c64-x25519` (`libs/x25519`) | `.gitmodules` |
| `USE_CHACHA_SIBLING` | **1** | `c64-ChaCha20-Poly1305` (`libs/chacha20poly1305`) | `.gitmodules` |

The toggles must match (both 1 or both 0); the Makefile refuses mixed
configs. That is new versus the staged-source era, where each toggle
composed independently: the archives now cross-resolve — x25519
provides `sqtab_init`/`mul_tables_init` and the §8.3 `ct_mul_8x8`
body, chacha defers to it — so a half-on link hits duplicate-export
(x25519 + in-tree poly1305 both export `mul_8x8`/`sqtab_init`) or
unresolved-import (chacha's deferred `mul_tables_init` with no x25519)
errors. `0/0` remains the legacy all-in-tree dev build.

## §8.0 composition: who owns what

| Shared primitive | Provider | Mechanism |
| --- | --- | --- |
| §8.1 sqtab (1 KB quarter-square table at `$8000`) | c64-x25519 | `sqtab_init`/`mul_tables_init` exported in both profiles; both libs assemble with `LIB_SHARED_SQTAB_BASE=$8000` (x25519's default is `$7800` — the override is load-bearing) |
| §8.2 reu_mul (REU DMA row tables) | c64-x25519 (REU profile only) | absent entirely under `REU=0` (onchip profile) |
| §8.3 `ct_mul_8x8` (constant-time multiply) | c64-x25519 | chacha built with `-D SHARED_CT_MUL_8X8=1`; x25519's body is the canonical CT implementation, byte-identical to chacha's internal one |

chacha is built with `-D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1`,
dropping its manifest bits to `$0000`. Masks are therefore disjoint in
every WG profile: x25519 `$0007` (REU) / `$0005` (onchip) vs chacha
`$0000`.

**CT consequence**: with both in-tree crypto sets dropped, every
multiply reachable on the X25519 *and* Poly1305 paths is the CT body —
this is what closed the long-standing non-CT `mul_8x8` finding
(issue #16). chacha's legacy non-CT `mul_8x8` body is still assembled
into its archive but is unreferenced in the link.

## Verification layers

1. **Link-time** — `src/contract_asserts.s`: REU bank masks disjoint
   (x25519 vs WG's own claims), x25519 owns `$0005` minimum,
   `LIB_ABI_VERSION = 1`. Uses `&`, never `.and` (boolean in ca65 —
   contract issue #41).
2. **Archive-build-time** — `tools/integration/build_chacha20poly1305.sh`
   verifies chacha's `REU_BANKS_USED=$00` and `SHARED_PRIMITIVES=$0000`
   numerically via `od65 --dump-exports`. Done there, not at link,
   because both archives' manifest members export unprefixed common
   symbols (`LIB_PRECALC_sqtab_*`, `LIB_VERSION_*`) that collide if
   both are pulled — contract issue #43.
3. **ABI drift** — `tools/check_abi_drift.py` (unchanged): imports in
   `src/crypto_abi.inc` vs sibling exports.

## Integration scripts

Both scripts invoke the sibling's own Makefile and copy the archive to
`build/lib/`; they are `FORCE`-driven from WG's Makefile (the sibling
make is the incrementality layer).

**`build_x25519.sh`** — `make -C libs/x25519 lib` with
`CA65FLAGS='-D LIB_SHARED_SQTAB_BASE=$8000'`, plus
`-D X25519_ONCHIP_MUL=1` under `X25519_PROFILE=onchip` (WG `REU=0`).
Separate sibling `BUILD_DIR`s per profile (`build` / `build-onchip`)
so profile switches can never reuse stale objects. ca65 gotcha: a bare
`-D X25519_ONCHIP_MUL` defines the symbol **0** and silently builds
the REU profile — always `=1`.

**`build_chacha20poly1305.sh`** — `make -C libs/chacha20poly1305 lib`
with the deferral + `POLY1305_MULTIPLY_ROLLED_OUTER=1` defines passed
via `CA65=` override (their `CA65FLAGS` is `=`-assigned, not `?=`).
Carries the one interim staging step: upstream
[#47](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/47)
(`SHARED_CT_MUL_8X8=1` doesn't gate the legacy `mul_8x8` /
`poly_prod_lo/hi` exports, which collide with x25519's) is worked
around by re-assembling `poly1305_lib.s` with the two export lines
gated and swapping the member in WG's copy of the archive. The swap
detects an upstreamed fix and disables itself; the guard fails loudly
if the source layout drifts.

## Linker-config mapping

Both `cfg/c64-wireguard-{ip65,uci}.cfg` carry the same segment set:

- **x25519 (§4-prefixed since v0.8.0)**: `LIB_X25519_CODE` (rw —
  contains SMC patch sites; MAIN_AREA_LO), `LIB_X25519_DATA` (rw,
  `align=$100`, 3584 B — placed in LOADER's slack), and
  `LIB_X25519_INIT_CODE` (rw, `define=yes`, MAIN_AREA_HI; reclaimable
  after boot via `__LIB_X25519_INIT_CODE_LOAD__`/`__..._SIZE__` —
  826 B REU / 160 B onchip). Ordering rule: `LIB_X25519_INIT_CODE`
  must stay the last file-emitting segment in its area, before any
  bss segment.
- **chacha (no §4 upstream yet — issue
  [#48](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/48))**:
  the lib emits bare `CODE`/`DATA`, so WG **cedes those names**: WG's
  own boot + net-wrapper code moved to `BOOT_CODE` (which must stay
  first after `EXEHDR` — the BASIC stub hardcodes SYS 2061 = `start:`
  at $080D). `CODE` maps to MAIN_AREA_LO with **`align=$100` — a
  constant-time requirement**, not cosmetic: the nibswap LUTs inside
  it are read with `lda tab,x` on secret indexes and ld65 only warns
  if alignment is dropped. `DATA` (295 B) must PRG-load as zero
  (`sqtab_ready` gate), hence rw in a zero-filled file region.
- The `$8000-$83FF` sqtab hole remains reserved in both cfgs; nothing
  may be placed there.

## ZP and REU contract

### Zero-page

`src/zp_config.inc` is the relocatable slot manifest; `.exportzp`
declarations live in `src/exports.s` (single `.o` to avoid
duplicate-export at link). The x25519 archive is fully self-contained
(imports nothing, ZP included); the chacha archive imports 19 ZP
names, all satisfied by `src/exports.s`. Highlights:

- `fe25519_src1/src2/dst` ($1e/$20/$22) alias WG's `fe_src1/src2/dst`;
  exported unconditionally for the test harness.
- `cc20_work`/`cc20_keystream`: ZP `$40-$7F` under the chacha sibling
  (`.ifdef` in `exports.s`/`data.s`); aliases x25519's non-overridable
  `fe_wide` ($40-$7F). Safe: DH and AEAD calls never overlap in time,
  and neither buffer carries state across calls.
- `ct_diff_raw`/`ct_sign_mask` ($1e/$1f): exported unconditionally;
  consumed by chacha's internal CT body. (x25519 v0.8.0 keeps its own
  copies as static bytes inside `LIB_X25519_CODE` — zero ZP cost.)

### REU banks

Authoritative ledger: `src/crypto/shared/reu_layout.inc`.

- `REU=1`: x25519 claims banks 0,1,3,4,5 (`$3B`). Bank 2 (WG overlay
  store) stays free.
- `REU=0`: x25519 onchip claims **nothing** (`$00`); chacha claims
  nothing in any profile since v0.6.0 (the `POLY1305_REU` path was
  removed upstream). The PRG issues no REU DMA at all.
- WG's own claims are `$00` today (overlay store is
  reserved-not-allocated); `src/contract_asserts.s` composes all
  three masks.

## Bumping a sibling submodule

1. `cd libs/<name> && git fetch --tags && git checkout <tag>`
2. Re-read the sibling `CHANGELOG.md`/release notes. Deltas that
   matter: segment names, exported symbols, ZP slots, REU masks,
   `LIB_SHARED_SQTAB_BASE` default, `-D` knobs, archive target names.
   Update the integration script header — it is the load-bearing
   record of *why* each define is passed.
3. `make clean && make` (and `make REU=0`) — must build clean; the
   od65 manifest checks and link-time asserts are the tripwires.
4. `python3 tools/check_abi_drift.py` — must exit 0.
5. `python3 tools/run_regression.py` — must pass.
6. Commit bump + script changes together; call out size/knob deltas.

## Adding a third sibling

Same shape as before: submodule + integration script (prefer the
library's `make lib` product; document every define), Makefile toggle
+ archive rule, cfg segments in **both** backend cfgs (`optional=yes`),
suppression `.ifdef`s in `exports.s`/`data.s` if it displaces in-tree
code, drift-gate coverage, and a row in the §8.0 composition table
above deciding shared-primitive ownership *before* the first link.

## Why the in-tree copies are still here

They are the `USE_*_SIBLING=0` legacy/dev build — useful for
bisecting whether a regression is WG-side or library-side, and as the
reference implementation for the test suites' direct-`jsr()` entry
points. They are no longer shipped, and the in-tree `poly1305.s`
`mul_8x8` retains the known non-CT branches (issue #16) — do not ship
`0/0` builds.

## References

- c64-x25519 v0.8.0 release notes (`libs/x25519/docs/RELEASE_NOTES_v0.8.0.md`)
  — §4 rename, cold split, onchip profile, consumer-cfg migration.
- c64-ChaCha20-Poly1305 v0.6.0 `CHANGELOG.md` + `docs/INTEGRATION.md`
  — POLY1305_REU removal, zp_config header, archive targets.
- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
  SPEC v0.4.1 §§1-8; WG-filed issues
  [#41](https://github.com/JC-000/c64-lib-contract/issues/41) (`.and`
  defect), [#43](https://github.com/JC-000/c64-lib-contract/issues/43)
  (unprefixed manifest collisions).
- `src/contract_asserts.s`, `tools/integration/*.sh`,
  `tools/check_abi_drift.py` — the verification layers.
- PRs #35-#38 — the retired staged-source pipeline (git history).
