# Library-ingestion architecture

How c64-wireguard consumes the sibling crypto libraries `c64-x25519`
(v0.11.2) and `c64-ChaCha20-Poly1305` (v0.9.0) **as the shipped
default**, linking the libraries' own contract-§6 archive products with
zero source staging: each sibling builds itself via its own `make lib`
target, and WG links the resulting `.a` unmodified.

The companion piece is the [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
repo, which pins the cross-project ZP / REU / segment / shared-primitive
conventions.

**No SPEC version is named here on purpose.** This line used to say "SPEC
v0.7.5", and the tree disagreed with it in three different places at once —
`src/net/{uci,ip65}/net_caps.inc` cite v0.12.0 §13.3, `src/net/uci/uci_cmd.s:125`
cites v0.13.0 §13.4, and `src/contract_asserts.s:8` calls v0.10.3 "the latest
tagged contract release". A single version asserted in prose here would just
become a fourth answer. **Take the governing version from the file you are
actually working in**, which cites its own clause next to the code it
constrains. Note also that contract §13 (the net ABI and its error registry)
was RETIRED at contract v1.0.0 — the published values remain valid but this
project owns its registry now (`src/net_abi.inc`), so check `SPEC.md` before
citing any §13 clause.

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
configs. The two archives cross-resolve — x25519 provides
`sqtab_init`/`mul_tables_init` and the §8.3 `ct_mul_8x8` body, and
chacha is built to defer to it — so a half-on link fails either way:
duplicate-export (x25519 and the in-tree poly1305 both exporting
`mul_8x8`/`sqtab_init`) or unresolved-import (chacha's deferred
`mul_tables_init` with no x25519 to supply it). `0/0` is the legacy
all-in-tree dev build.

## §8.0 composition: who owns what

| Shared primitive | Provider | Mechanism |
| --- | --- | --- |
| §8.1 sqtab (1 KB quarter-square table at `$8000`) | c64-x25519 | `sqtab_init`/`mul_tables_init` exported in both profiles; both libs assemble with `LIB_SHARED_SQTAB_BASE=32768` (= `$8000`; x25519's default is `$7800`, so the override is load-bearing — and it must be written in **decimal**, see below) |
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

1. **Link-time** — `src/contract_asserts.s` imports **both** libraries'
   manifests and checks the whole composition:
   - §3 REU bank masks pairwise disjoint across x25519, chacha and WG's
     own claims.
   - §8.0 no double ownership of a shared primitive.
   - §8.0 (SPEC v0.5.0) **coverage**: every primitive any library
     declares it *consumes* has exactly one owner in the link —
     `((A_CONSUMES | B_CONSUMES) & ~(A_OWNED | B_OWNED)) = 0`. This is
     the assert that matters most for WG's composition: chacha defers
     both its primitives to x25519, so the failure it guards is an
     x25519 profile change silently dropping an ownership bit, which
     would otherwise surface as a table read with no init.
   - §8.0 subset invariant per library (`OWNED & ~CONSUMES = 0`).
   - §1 per-library ABI pins: `LIB_X25519_ABI_VERSION = 3` and
     `LIB_CHACHA20_POLY1305_ABI_VERSION = 3`.

   Both libraries are built with `-D LIB_NO_BARE_EXPORTS=1` so each
   exports only its `LIB_<X>_`-prefixed manifest. That is what lets one
   translation unit import both. Masks are combined with `&`, never
   `.and` — `.and` is *boolean* in ca65, so it evaluates true whenever
   both operands are nonzero and inverts the meaning of every
   disjointness check.
2. **ABI drift** — `tools/check_abi_drift.py`: imports declared in
   `src/crypto_abi.inc` versus what the sibling archives actually
   export.

## Integration scripts

Both scripts invoke the sibling's own Makefile and copy the archive to
`build/lib/`; they are `FORCE`-driven from WG's Makefile (the sibling
make is the incrementality layer).

**`build_x25519.sh`** — `make -C libs/x25519 lib` with
`CONTRACT_DEFINES='-D LIB_SHARED_SQTAB_BASE=32768 -D LIB_NO_BARE_EXPORTS=1'`,
plus `-D X25519_ONCHIP_MUL=1` under `X25519_PROFILE=onchip` (WG
`REU=0`). Separate sibling `BUILD_DIR`s per profile
(`build` / `build-onchip`) so profile switches can never reuse stale
objects.

`CONTRACT_DEFINES` is the contract §6.2 seam, available since v0.11.0,
and replaced a `CA65FLAGS=` override. `CA65FLAGS` survives upstream as a
deprecated alias, but it is a hard assign that clobbers the library's own
`-t c64 -g` — every sibling object through the v0.10.1 pin was assembled
without the C64 target or debug info.

The companion `CONTRACT_ZP_DEFINES` is threaded through but left empty.
It would be the natural home for `-D ZP_CONFIG_NO_EXPORTS=1` (WG #51),
which suppresses `zp_config.o`'s redundant `.exportzp` block — but
`libs/x25519/src/constants.s` assigns that symbol *unguarded* before
including `zp_config.s`, so a command-line `-D` is a hard
"already defined" error in every TU. Not currently reachable through any
supported seam; filed as [c64-x25519#99](https://github.com/JC-000/c64-x25519/issues/99),
where the fix is a one-line `.ifndef`.

Two ca65/make traps this flag list exists to avoid, both of which fail
**silently**:

- **Write the sqtab base in decimal.** `32768`, never `$8000`. The
  value crosses WG's make, the sibling's make, *and* `/bin/sh` before
  ca65 sees it: `$8000` loses `$8` to make (`$(8)` is empty) and
  `$$8000` is then eaten by the shell as a positional parameter.
  Either way ca65 receives `BASE=000` and `sqtab_init` builds its
  table over zero page, the stack and the IRQ vector at boot — the
  observed signature is `($0314) = $4A4A` followed by a KIL jam.
  Decimal has no metacharacters and survives both layers.
- **Always write `=1` on the profile switch.** A bare
  `-D X25519_ONCHIP_MUL` defines the symbol as **0**, which builds the
  REU profile while the build log looks like it asked for onchip.

**`build_chacha20poly1305.sh`** — `make -C libs/chacha20poly1305 lib`
with the deferral defines, `POLY1305_MULTIPLY_ROLLED_OUTER=1` and
`LIB_NO_BARE_EXPORTS=1`, passed via `CONTRACT_DEFINES` (v0.8.0). This
replaced a `CA65=` override, which was needed because their `CA65FLAGS`
is `=`-assigned, not `?=`, so a `CA65FLAGS=` on the command line was
discarded. There is deliberately no `CONTRACT_ZP_DEFINES` upstream: the
archive ships no ZP-defining member, which is why WG's `src/exports.s`
must supply the §2 registry slot names itself. The archive is copied to
`build/lib/` unmodified — no member rewriting, no source staging.

Both scripts copy the §6.1 **canonical** archive basenames
(`x25519.a`, `chacha20poly1305.a`). The old `libx25519.a` /
`c64-chacha20-poly1305.a` spellings are deprecated dialects, still
written through the §6.5 rename window and dropped at each library's
next MAJOR.

## Linker-config mapping

Both `cfg/c64-wireguard-{ip65,uci}.cfg` carry the same segment set:

- **x25519 (§4-prefixed since v0.8.0)**: `LIB_X25519_CODE` (rw —
  contains SMC patch sites; MAIN_AREA_LO), `LIB_X25519_DATA` (rw,
  `align=$100`, 3584 B — placed in LOADER's slack), and
  `LIB_X25519_INIT_CODE` (rw, `define=yes`, MAIN_AREA_HI — 826 B REU /
  160 B onchip). As of issue #103 this segment is **actually
  reclaimed**, not merely documented as reclaimable: `APP_BSS_OVERLAY`
  in both cfgs describes the top of MAIN_AREA_HI a second time as a
  non-file region so `APP_BSS` lies over it, and `src/boot.s` zeroes the
  span through `__LIB_X25519_INIT_CODE_LOAD__`/`__..._SIZE__` the
  instant the table build returns. Ordering rule, now load-bearing for
  more than R5: `LIB_X25519_INIT_CODE` must stay the **last**
  file-emitting segment in MAIN_AREA_HI, because its load address is
  what `src/contract_asserts.s` uses as "end of live file content" when
  it checks the overlay boundary. A file-emitting segment declared after
  it would be live data inside the span boot zeroes, and the assert
  would not see it.

  What makes the reclaim safe is that the segment holds only
  `sqtab_init`/`mul_tables_init`, `reu_mul_init` and `reu_probe`; the
  first two are called once from `src/boot.s` before `boot_ready` is
  set, and `reu_probe` is not called from this repo at all. The one
  guarded hot-path re-entry — `poly1305_init`'s `jsr sqtab_init` — is
  gated on chacha's `sqtab_ready`, which lives in the file-backed
  `LIB_CHACHA20_POLY1305_DATA`, is set at boot, and is never cleared.
- **chacha (§4-prefixed since v0.7.0)**:
  `LIB_CHACHA20_POLY1305_CODE` (rw, MAIN_AREA_LO, 8094 B) with
  **`align=$100` — a constant-time requirement**, not cosmetic: the
  two nibswap LUTs inside it are read with `lda tab,x` on *secret*
  indexes, and ld65 only *warns* if the alignment is dropped, so the
  link still succeeds and the CT property is lost silently. And
  `LIB_CHACHA20_POLY1305_DATA` (rw, 295 B), which **must never be
  declared `type=bss`**: its zero bytes gate `poly1305_init`'s
  `sqtab_ready` check, and a bss declaration emits no file bytes, so
  the gate reads power-on garbage, `sqtab_init` is skipped, and every
  Poly1305 multiply is poisoned — again with no link error.
- WG's own boot + net-wrapper code lives in `BOOT_CODE`, which must
  stay the first code segment after `EXEHDR`: the BASIC stub hardcodes
  SYS 2061 = `start:` at `$080D`. (The bare `CODE`/`DATA` names are
  free as of chacha v0.7.0 and are declared `optional` and empty, but
  moving `BOOT_CODE` back onto `CODE` buys nothing and risks the entry
  point — leave it.)
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
  consumed by chacha's internal CT body. (x25519 keeps its own copies
  as static bytes inside `LIB_X25519_CODE` — zero ZP cost.)

### REU banks

Authoritative ledger: `src/crypto/shared/reu_layout.inc`.

- `REU=1`: x25519 claims banks 0,1,3,4,5 (`$3B`). Bank 2 (WG overlay
  store) stays free.
- `REU=0`: x25519 onchip claims **nothing** (`$00`); chacha claims
  nothing in any profile. The PRG issues no REU DMA at all, and
  `reu_mul_init` / `reu_fetch_mul_row` are absent from the link
  entirely — the onchip profile builds no REU table to initialise.
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
   link-time composition asserts are the tripwires.
4. `python3 tools/check_abi_drift.py` — must exit 0.
5. `python3 tools/run_regression.py` — must pass (22 suites as of
   2026-08-14; the list previously covered only 13 of the 27
   `tools/test_*.py` scripts, so a suite passing locally was not
   necessarily a suite the gate ran).
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

- c64-x25519 release notes (`libs/x25519/docs/`) — the v0.8.0 notes
  cover the §4 rename, cold split and onchip profile; v0.9.0 the
  contract v0.7.0/v0.5.0 manifest migration; v0.10.0 the
  `LIB_X25519_ABI_VERSION` 1→2 erratum (generation counter catching up
  with v0.9.0's export removal — no code change); v0.10.1 a docs/snippet
  sweep, also no code change (its PRG is byte-identical all the way back
  to v0.8.0); v0.11.0 the phase-3 fleet wave — SPEC v0.9.x §6 adoption,
  the `LIB_SHARED_REU_MUL_*` and ZP-trio export removals and the
  `poly_carry` → `mul_carry` rename, ABI 2→3, still byte-identical;
  v0.11.1 the §6.6/§6.7 placement guards and the consumer-reachable
  `ZP_CONFIG_NO_EXPORTS` fix (filed from here as their #99); v0.11.2 a
  docs-accuracy release correcting `vic_blank` from "~20-25%" to ~6%
  (filed from here as their #103, and our measurement is one of the
  three independent sources it cites) plus the §6.3 `X25519_PROFILE`
  knob guard. ABI has stayed 3 and the PRG byte-identical throughout.
- c64-ChaCha20-Poly1305 `CHANGELOG.md` + `docs/INTEGRATION.md` — v0.7.0
  brought §4 segment prefixes, the prefixed manifest exports and the
  `SHARED_CT_MUL_8X8` deferral gate; v0.8.0 the §2 ZP registry rename
  (ABI 1→3), §6.1 canonical archive basenames and §6.2 defines
  forwarding, all codegen-neutral; v0.9.0 the §6.7 image guard and the
  R2 ZP-usage drift ratchet, ABI unchanged at 3. Its INTEGRATION.md is
  also the source of the "always call `poly1305_lib_init` once at boot"
  rule that src/boot.s now follows.
- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
  SPEC v0.10.3 §§1-8 (latest tagged release; the siblings' ledgers run
  through v0.10.6, which adds no obligation on the consumer side) — §1 prefixed version exports and the
  `LIB_NO_BARE_EXPORTS` gate, §2 the ZP slot-name registry, §5 aggregate
  manifests, §6 the packaging chapter (§6.1 canonical basenames, §6.2
  defines forwarding, §6.3 app-owned targets, §6.5 the rename window),
  §8.0 three-state ownership semantics and the coverage assert, §8.4 the
  precalc-table macro.
- `src/contract_asserts.s`, `tools/integration/*.sh`,
  `tools/check_abi_drift.py` — the verification layers.
