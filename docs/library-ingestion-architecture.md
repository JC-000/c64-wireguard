# Library-ingestion architecture

How c64-wireguard consumes the sibling crypto libraries `c64-x25519`
and `c64-ChaCha20-Poly1305` while keeping the in-tree implementations
as the shipped default. Captures the contract established by
PRs #35-#38 (2026-05-20 / 2026-05-21).

The companion piece is the [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
repo, which pins the cross-project ZP / REU / sqtab conventions that
make this ingestion pattern repeatable across consumers (`c64-https`
is set to follow).

## Scope

This document covers the *consumer* side: how WG's Makefile, build
scripts, linker config, and ABI gates wire a sibling `.a` into the
PRG. It does not document the sibling internals — those live in the
upstream repos and in `libs/<name>/CHANGELOG.md` / SPEC docs.

Audience: someone bumping a submodule pin, adding a third sibling, or
debugging a duplicate-symbol / unresolved-import link error.

## The contract

Each sibling integration is governed by a single Make-level toggle:

| Toggle | Default | Sibling repo | Pinned in |
| --- | --- | --- | --- |
| `USE_X25519_SIBLING=1` | OFF | `c64-x25519` (`libs/x25519`) | `.gitmodules` |
| `USE_CHACHA_SIBLING=1` | OFF | `c64-ChaCha20-Poly1305` (`libs/chacha20poly1305`) | `.gitmodules` |

Default `make` produces byte-for-byte the same PRG it did pre-Phase-D.
`make USE_X25519_SIBLING=1`, `make USE_CHACHA_SIBLING=1`, and the
combination each build a different PRG; the toggles compose
independently. None of these are the hardware-signed-off path yet —
real-Ultimate-64 A/B validation is workstream D in the post-Phase-D
resume.

Flipping a toggle on causes three things to happen:

1. The corresponding in-tree `src/crypto/*.s` sources are filtered
   out of the link line. See `COMMON_SRCS_ALL` / `X25519_REPLACED_SRCS`
   / `CHACHA_REPLACED_SRCS` in `Makefile`.
2. `build/lib/<name>.a` is built from `libs/<name>/` via
   `tools/integration/build_<name>.sh` and appended to the link line.
3. `-D USE_<NAME>_SIBLING=1` is passed to *every* ca65 invocation in
   the tree, so `.ifdef`-gated decls in `src/exports.s` and
   `src/wg/data.s` suppress the in-tree exports / BSS reservations
   that would otherwise duplicate-link against the sibling archive.

## Per-sibling build script

`tools/integration/build_<name>.sh` is the staging pipeline. Each
script is self-contained and reads the sibling sources straight out
of the submodule — there is no patching of `libs/<name>/` in place.

Shape (see the scripts' file headers for full rationale):

```
libs/<name>/src/*.s        ──cp──>  build/lib/<name>_staging/*.s
                                          │
                                          │  sed: '.segment "CODE"' → CRYPTO_CODE or CHACHA_CODE or …
                                          │  sed: '.segment "DATA"' → CHACHA_BSS         (chacha only)
                                          │  python: second CHACHA_CODE → CHACHA_RODATA  (chacha data_lib.s)
                                          ▼
                                    ca65 -g -D LIB_SHARED_SQTAB_BASE=$8000 \
                                             [-D POLY1305_MULTIPLY_ROLLED_OUTER=1] …
                                          │
                                          ▼
                                    ar65 a build/lib/<name>.a *.o
                                    build/lib/<name>.sizes.txt
```

### Inputs and exclusions

The integration script `cp`s a curated subset of `libs/<name>/src/`:

**Always excluded:**

- `main.s` — the sibling's BASIC stub / standalone test harness entry.
  WG has its own `src/boot.s`.
- `lib_version.s` / `lib_manifest.s` — `LIB_VERSION_*` /
  `LIB_<NAME>_*` aggregate equates. Leaving them out avoids
  "linked but unreferenced" warnings until WG starts asserting against
  the manifest.

**Sibling-specific exclusions:**

- `libs/x25519/src/mul_8x8.s` — would duplicate `mul_8x8`,
  `sqtab_init`, `poly_prod_lo/hi` (always provided in-tree by
  `src/crypto/poly1305.s` or the chacha sibling).
- `libs/x25519/src/util.s` — bench helpers (`vic_blank`,
  `bench_*`) not used by WG.
- `libs/<name>/src/zp_config.s` / `reu_config.s` — would
  duplicate `.exportzp`s that `src/exports.s` already emits. The
  equates themselves are still pulled in via `constants.s` under
  `ZP_CONFIG_NO_EXPORTS=1` so the sibling code resolves its own
  imports.

### Segment retargeting

The siblings emit `.segment "CODE"` / `.segment "DATA"`. The WG
linker config has `CODE` pointing at `LOADER` (the `$0801` BASIC-stub
region) and no `DATA` segment at all. Every staged source is
`sed`-rewritten before assembly:

| Sibling segment | Retargets to | Loaded into |
| --- | --- | --- |
| `CODE` (x25519) | `CRYPTO_CODE` | `MAIN_AREA_LO` |
| `CODE` (chacha lib) | `CHACHA_CODE` | `MAIN_AREA_LO` |
| `CODE` (chacha `data_lib.s` second block — nibswap LUTs) | `CHACHA_RODATA` | `LOADER` |
| `DATA` (chacha) | `CHACHA_BSS` | `MAIN_AREA_HI` |
| *(synthesised in-script)* x25519 BSS | `X25519_BSS` | `MAIN_AREA_HI` |
| *(synthesised in-script)* x25519 rodata (`fe_p`, `mul38_*_tab`, `sqr_*`, `a24_b*`) | `X25519_RODATA` | `LOADER` |

The two x25519 data segments are *not* `cp`'d from
`libs/x25519/src/data.s` — they are re-emitted in
`build_x25519.sh` via heredocs so the segment routing and buffer
layout stay under WG's control. See the `BSS_EOF` / `RODATA_EOF`
blocks in the script.

`CHACHA_RODATA` carries one quirk: `data_lib.s` has two `.segment
"CODE"` blocks, and only the second (the page-aligned nibswap LUTs)
should be rodata. The blanket `sed` would rewrite both to
`CHACHA_CODE`, so the script post-processes the file with a Python
one-liner that flips the sole resulting `CHACHA_CODE` in
`data_lib_raw.s` to `CHACHA_RODATA`. The earlier `.segment "DATA"`
in the same file is the actual `CHACHA_BSS` block.

A sanity pass at the end of each script greps for leftover
`.segment "CODE"` / `.segment "DATA"` lines and fails the build if
any survived — protects against an upstream commit that adds a new
segment we did not anticipate.

### ca65 `-D` overrides

`LIB_SHARED_SQTAB_BASE=$8000` is mandatory for both sibling scripts.
The c64-x25519 sibling defaults to `$7800` per
[c64-lib-contract §8.1](https://github.com/JC-000/c64-lib-contract);
WG places the runtime quarter-square table at `$8000` (see the
`sqtab` hole carved in `cfg/c64-wireguard-{ip65,uci}.cfg` and
`src/exports.s`). Page-alignment + page-delta are hard-asserted in
the sibling's `constants.s`, so a missed override fails at assemble
time, not as silent runtime table corruption.

The chacha sibling defaults to `$8000` already; the script passes it
explicitly for symmetry and to defend against a future upstream
default change.

`POLY1305_MULTIPLY_ROLLED_OUTER=1` is opt-in for the chacha sibling
only. It rolls the outer 16-iteration `j` loop of
`poly1305_multiply`, saving ~8 KB of linked code at +4.08 % cycles on
`aead_encrypt n=1024`. WG is size-bound, not cycle-bound, so this is
the right elbow. The full rolling variant
(`POLY1305_MULTIPLY_ROLLED`) saves a further ~576 B at +17.4 % cycles
and is *not* opted into — the AEAD path is on the handshake critical
path.

`POLY1305_PROFILE_LONG=1` (Profile A) is not opted into: it consumes
REU bank 0, which collides with WG's REU bank 0-1 allocation for the
x25519 multiplication tables. See
`src/crypto/shared/reu_layout.inc`.

`LIB_VARIANT_AEAD_ONLY=1` is not opted into: WG imports
`chacha20_quarter_round` (via `src/wg/cookie.s`'s HChaCha20 cookie
derivation) and `mul_8x8` (via the in-tree `src/crypto/fe25519.s`
when `USE_X25519_SIBLING=0`). The aead-only variant strips both
symbol bodies, not just the `.export` lines.

## Linker-config additions

`cfg/c64-wireguard-{ip65,uci}.cfg` define the sibling-owned segments
as `optional = yes`, so a default-OFF build (where no sibling object
references them) still links cleanly:

```
X25519_RODATA: load = LOADER,       type = ro,  align = $20,  optional = yes;
X25519_BSS:    load = MAIN_AREA_HI, type = bss, align = $100, optional = yes;
CHACHA_CODE:   load = MAIN_AREA_LO, type = ro,                optional = yes;
CHACHA_BSS:    load = MAIN_AREA_HI, type = bss,               optional = yes;
CHACHA_RODATA: load = LOADER,       type = ro,  align = $100, optional = yes;
```

Placement constraints:

- Everything in `MAIN_AREA_LO` must end before the `sqtab` hole at
  `$8000-$83FF`. WG migrated the ~1.3 KB of x25519 BSS to
  `MAIN_AREA_HI` precisely because keeping it in LO would have
  pushed the budget over.
- `MAIN_AREA_HI` lives at `$8400-$9FFF` (just past the runtime sqtab
  table, below the BASIC ROM shadow at `$A000`).
- `align = $20` on `X25519_RODATA` satisfies the sibling's
  `.assert (x25_basepoint & $1F) = 0` / `.assert (fe_p & $1F) = 0`.
- `align = $100` on `CHACHA_RODATA` satisfies the page-aligned
  `chacha_nibswap_*_tab` LUTs.

The cfg has running annotations on each segment explaining its size
(~8 KB for `CHACHA_CODE` at sibling pin `8cc3ab3`) and migration
history. When budgets get tight, those annotations spell out the
escape routes (more BSS to HI, or trim `CHACHA_CODE` via additional
size knobs).

## ZP and REU contract

### Zero-page

`src/zp_config.inc` is the relocatable slot manifest — every slot is
`.ifndef`-guarded so `--asm-define <slot>=<addr>` can pin it
elsewhere. The `.exportzp` declarations live in `src/exports.s`
(single `.o` to avoid duplicate-export at link).

Sibling defaults align with WG's allocation. The build-script
headers (`tools/integration/build_x25519.sh` and
`build_chacha20poly1305.sh`) carry the full per-slot equivalence
analysis — re-read those if a sibling commit changes its
`zp_config.s`. Highlights:

- `fe25519_src1/src2/dst` ($1e/$20/$22) alias WG's
  `fe_src1/src2/dst`. The aliases are exported unconditionally from
  `src/exports.s` so the test harness's `Labels.from_file()` sees both
  names regardless of which implementation is linked.
- `cc20_work` / `cc20_keystream` live in non-ZP BSS in the in-tree
  build but the chacha sibling pins them to ZP `$40`. `src/exports.s`
  emits the ZP equates only under `.ifdef USE_CHACHA_SIBLING`, and
  `src/wg/data.s` suppresses the non-ZP BSS definitions in the same
  case.
- `ct_diff_raw` / `ct_sign_mask` ($1e/$1f) are exported
  unconditionally as ZP from `src/exports.s` so the chacha sibling's
  `.importzp` resolves even with `USE_CHACHA_SIBLING=0`. They time-share
  with `fe_src1` — safe because fe25519 (DH) and AEAD never co-run in
  the WG handshake.

### REU banks

REU bank ownership is authoritative in `src/crypto/shared/reu_layout.inc`
(see `README.md`'s "REU DMA" section).

- c64-x25519 v0.6.0 claims banks 0, 1, 3, 4, 5
  (`LIB_X25519_REU_BANKS_USED=$3B`). PR #54 narrowed this from the
  previous `$3F` (banks 0-5) by dropping bank 2, which is now free for
  WG's overlay store.
- c64-ChaCha20-Poly1305 in Profile B does *not* touch the REU. Profile
  A (`POLY1305_PROFILE_LONG=1`) would claim bank 0 and we do not opt in.

`tools/check_abi_drift.py` validates the symbol surface but does *not*
validate REU bank claims. If you bump a sibling and its
`LIB_<NAME>_REU_BANKS_USED` mask changes, update
`reu_layout.inc` by hand.

## ABI drift gate

`tools/check_abi_drift.py` parses `src/crypto_abi.inc` for `.import`
lines and the sibling repos' `.s`/`.inc` files for `.export` lines.
It prints three tables (satisfied / missing / extra) and exits non-zero
if any non-allowlisted import has no sibling export.

The allowlist (in the script's `WG_ONLY_PREFIXES` / `WG_ONLY_EXACT`)
covers symbols that legitimately have no sibling counterpart:

- `blake2s_*`, `hmac_blake2s`, `kdf_*` — WG provides BLAKE2s
  in-tree (`src/crypto/blake2s.s`, `blake2s_kdf.s`). There is no
  sibling library for BLAKE2s by design.
- `kdf_1`, `kdf_2`, `kdf_3` — same family.
- `fe25519_cmp_p`, `fe25519_reduce_wide` — WG-only fe25519 helpers
  called out as such in `crypto_abi.inc`.

Run with `--verbose` to get per-symbol provenance (which sibling file
each export came from). Defaults assume the sibling repos are checked
out as siblings of `c64-wireguard/`; override with `--x25519-inc` and
`--chacha-dir` for CI / different layouts.

## Vendored-diff report

`tools/diff_vendored.sh` is informational only — it diffs each
in-tree `src/crypto/*.s` against the corresponding sibling source and
prints adds/removes per file. Useful during the period when both
implementations coexist; will become noise once the in-tree copies are
deleted in a later phase.

It is *not* a gate — always exits 0. Use the ABI drift gate for that.

## Bumping a sibling submodule

The PR #37 and PR #38 commits are the established pattern. Typical
flow:

1. `cd libs/<name> && git fetch && git checkout <new-rev>`
2. `cd ../.. && git add libs/<name>`
3. Re-read the sibling `CHANGELOG.md` / release notes. If the new
   revision changes any of:
   - segment names emitted (CODE/DATA/RODATA)
   - exported symbols
   - ZP slot defaults or REU bank claims
   - `LIB_SHARED_SQTAB_BASE` default
   - public configuration `-D` knobs
   …update `tools/integration/build_<name>.sh` and add a
   `vN.M.K deltas vs <previous pin>` block in the script header
   documenting the change. The header is the load-bearing record;
   git log alone is not enough because the rationale chain spans
   multiple repos.
4. `make clean && make USE_<NAME>_SIBLING=1` — must build clean.
5. `python3 tools/check_abi_drift.py` — must exit 0.
6. `python3 tools/run_regression.py` (or the relevant subset) —
   must pass.
7. Commit the submodule bump + any build-script changes together.
   Commit message body should call out the size delta
   (`build/lib/<name>.sizes.txt`) and any new `-D` knobs opted into.

## Adding a third sibling

The pattern is mechanical:

1. `git submodule add <url> libs/<name>` and pin a SHA / tag.
2. Write `tools/integration/build_<name>.sh` modelled on the existing
   two. The header is part of the deliverable — document every
   `-D` knob, every exclusion, and every ZP/REU/segment override.
3. Wire the Makefile:
   - `USE_<NAME>_SIBLING ?= 0`
   - Add `<NAME>_REPLACED_SRCS` and extend the `filter-out`.
   - Add `<NAME>_ARCHIVE = $(LIB_DIR)/<name>.a` and a rule that calls
     the build script.
   - `ifeq` block to extend `CA65FLAGS += -D USE_<NAME>_SIBLING=1`.
4. Add sibling-owned segments to *both* `cfg/c64-wireguard-ip65.cfg`
   and `cfg/c64-wireguard-uci.cfg`. Mark them `optional = yes`.
5. Add `.ifdef USE_<NAME>_SIBLING` suppression blocks to
   `src/exports.s` and (if the sibling owns any buffers) `src/wg/data.s`.
6. Extend `tools/check_abi_drift.py`'s sibling export discovery to
   include the new repo's `src/` (and update `WG_ONLY_EXACT` /
   `WG_ONLY_PREFIXES` if needed).
7. Optionally add a row to `tools/diff_vendored.sh`'s `PAIRS` if there
   is an in-tree counterpart worth tracking divergence against.

## Why the in-tree copies are still here

Until each sibling integration is signed off on real Ultimate 64
hardware (workstream D), the in-tree `src/crypto/*.s` files are the
shipped default. Once a sibling is signed off, its in-tree
counterpart becomes deletable — at that point the corresponding
toggle should flip default to `1` and the suppression `.ifdef`s in
`src/exports.s` / `src/wg/data.s` get inverted (or the `.ifndef`
blocks become unconditional).

The signed-off cutover is intentionally not yet performed for either
sibling: it would conflate the library-ingestion refactor with a
behaviour change in the shipped PRG.

## References

- PRs [#35](https://github.com/JC-000/c64-wireguard/pull/35),
  [#36](https://github.com/JC-000/c64-wireguard/pull/36),
  [#37](https://github.com/JC-000/c64-wireguard/pull/37),
  [#38](https://github.com/JC-000/c64-wireguard/pull/38) — Phase A-D
  rollout.
- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract) —
  the cross-project ZP / REU / sqtab contract. §8.1 (`LIB_SHARED_SQTAB_BASE`)
  is the equate this consumer pins to `$8000`.
- `src/crypto/shared/reu_layout.inc` — REU bank-allocation ledger.
- `docs/phase-9-handshake-milestone.md` — first-on-the-wire context;
  the AEAD-divergence investigation may be revisited under
  `USE_X25519_SIBLING=1` now that v0.6.0 fe25519 is available.
- `tools/integration/build_x25519.sh`, `build_chacha20poly1305.sh`,
  `tools/check_abi_drift.py`, `tools/diff_vendored.sh` — load-bearing
  scripts; their headers are the authoritative per-flag rationale.
