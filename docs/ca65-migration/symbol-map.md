# ACME → ca65 Symbol Rename Map

This document is the authoritative source of truth for Phase 3 crypto
migration. Every public symbol the wireguard ca65 build exports must
appear here; anything missing must be added before that module's
migration PR is merged.

**Goal:** align WG's in-tree crypto symbol names with the sibling
libraries (`c64-x25519`, `c64-ChaCha20-Poly1305`) so a future swap to
those libraries is a link-line-only change. Symbols outside the sibling
ABI (BLAKE2s, WG-specific buffers) are standardized but kept in-tree.

## Sources of truth

- `c64-x25519` public ABI: `/home/someone/c64-x25519/src/x25519.inc`
- `c64-ChaCha20-Poly1305` public ABI: `/home/someone/c64-ChaCha20-Poly1305/src/lib/*_lib.s` (search for `.export`)
- `c64-https` migration template: `/home/someone/c64-https/src/crypto_abi.inc`

## ZP layout — decision

WG's current ZP layout **already aligns** with c64-x25519's contract:

| Slot | WG today (`src/constants.asm`) | c64-x25519 (`x25519.inc`) | Status |
|------|-------------------------------|---------------------------|--------|
| $14-$17 | `cc20_round`/`cc20_qr_idx`/`cc20_data_ptr` aliased as `lmul0`/`lmul1` | `lmul0`/`lmul1` (mul_8x8 sqtab pointers) | ✅ Aliased — not used concurrently (ChaCha20 vs. mul_8x8) |
| $1A-$1D | `poly_i/j/carry/tmp` | `poly_i/j/carry/tmp` (mul_8x8 scratch) | ✅ Same |
| $1E-$23 | `fe_src1/src2/dst` | `fe25519_src1/src2/dst` | ⚠️ **Rename** (value identical, name differs) |
| $24-$29 | `fe_misc/carry/loop/mul_i/mul_j` | `fe_misc/carry/loop/mul_i/mul_j` | ✅ Same |
| $2A-$2D | `x25_prev_bit/bit_ctr/byte_idx/bit_mask` | Same names | ✅ Same |
| $40-$7F | `fe_wide` (64-byte product accumulator) | `fe_wide` | ✅ Same |
| $FB-$FE | `zp_ptr1/zp_ptr2` | Same | ✅ Same |

**Decision: no ZP relocation required.** The c64-x25519 audit's
"collision" finding was based on only reading the library's own doc; WG's
constants.asm already documents the identical overlap (`lmul0 = $14 ;
aliases cc20_round/$14`). Phase 3 ZP rename for `fe_src1 → fe25519_src1`
is cosmetic — the address is the same.

## Module: word32 (crypto/word32.s)

No sibling library for word32 alone, but c64-ChaCha20-Poly1305 re-exports
identical primitives. Names already match — no renames needed.

| ACME | ca65 | Notes |
|------|------|-------|
| `add32` | `add32` | unchanged |
| `add32_to_dst` | `add32_to_dst` | unchanged |
| `xor32` | `xor32` | unchanged |
| `xor32_in_place` | `xor32_in_place` | unchanged |
| `rotr32_1/7/8/12/16` | same | unchanged |
| `rotl32_1/4/7/8/12` | same | unchanged |
| `copy32` | `copy32` | unchanged |
| `zero32` | `zero32` | unchanged |

ZP: `w32_src1`/`w32_src2`/`w32_dst` — keep names (not exported by any sibling-lib `.inc` observed).

## Module: blake2s (crypto/blake2s.s, crypto/blake2s_kdf.s)

**No sibling library exists.** Standardize prefixes for consistency but
don't align with a non-existent ABI.

| ACME | ca65 | Notes |
|------|------|-------|
| `blake2s_init` | `blake2s_init` | unchanged |
| `blake2s_update` | `blake2s_update` | unchanged |
| `blake2s_final` | `blake2s_final` | unchanged |
| `blake2s_hash_oneshot` | `blake2s_hash_oneshot` | unchanged |
| `hmac_blake2s` | `hmac_blake2s` | unchanged |
| `kdf_1` / `kdf_2` / `kdf_3` | `blake2s_kdf_1` / `_2` / `_3` | **Rename** — prefix for discoverability |

Data buffers (`blake2s_iv`, `blake2s_sigma`, `b2s_h`, `b2s_buf`,
`b2s_hash`) — keep names; they have no sibling counterpart.

## Module: chacha20 (crypto/chacha20.s)

Sibling: `c64-ChaCha20-Poly1305/src/lib/chacha20_lib.s`. **All names already match.**

| ACME | ca65 | Notes |
|------|------|-------|
| `chacha20_init` | `chacha20_init` | unchanged |
| `chacha20_block` | `chacha20_block` | unchanged |
| `chacha20_encrypt` | `chacha20_encrypt` | unchanged |

Data: `cc20_state`, `cc20_key`, `cc20_nonce`, `cc20_counter`,
`cc20_work`, `cc20_keystream`, `cc20_constants`, `cc20_qr_table` — all
match sibling names.

ACME macros: `+cc20_set_dst` / `+cc20_set_src1` → ca65 `.macro`/`.endmacro`.

## Module: poly1305 (crypto/poly1305.s)

Sibling: `c64-ChaCha20-Poly1305/src/lib/poly1305_lib.s`. All names match.

| ACME | ca65 | Notes |
|------|------|-------|
| `poly1305_init` | `poly1305_init` | unchanged |
| `poly1305_clamp` | `poly1305_clamp` | unchanged |
| `poly1305_block` | `poly1305_block` | unchanged |
| `poly1305_update` | `poly1305_update` | unchanged |
| `poly1305_final` | `poly1305_final` | unchanged |
| `poly1305_multiply` | `poly1305_multiply` | unchanged (internal-ish) |
| `poly1305_reduce` | `poly1305_reduce` | unchanged (internal-ish) |
| `mul_8x8` | `mul_8x8` | unchanged |
| `sqtab_init` | `sqtab_init` | unchanged |

**Open question for Phase 3:** c64-ChaCha20-Poly1305 requires
`poly1305_lib_init` (idempotent via `sqtab_ready` flag). WG currently
calls `sqtab_init` directly at boot. Align by renaming WG's boot call
site to `poly1305_lib_init` — cheaper than diverging.

## Module: aead (crypto/aead.s)

Sibling: `c64-ChaCha20-Poly1305/src/lib/chacha20poly1305_lib.s`.

| ACME | ca65 | Notes |
|------|------|-------|
| `aead_encrypt` | `aead_encrypt` | unchanged |
| `aead_decrypt` | `aead_decrypt` | unchanged |

Data: `aead_key`, `aead_nonce`, `aead_aad_ptr`, `aead_aad_len`,
`aead_data_ptr`, `aead_data_len`, `aead_tag`, `aead_scratch` — all
match sibling.

## Module: fe25519 (crypto/fe25519.s)

Sibling: `c64-x25519/src/x25519.inc` + `src/fe25519.s`. **Most symbols
must be renamed** — the WG names use `fe_` prefix, the library uses
`fe25519_` prefix.

### Public entry points

| ACME (current) | ca65 (target) | Exists in lib? |
|----------------|---------------|----------------|
| `fe_copy` | `fe25519_copy` | ✅ |
| `fe_zero` | `fe25519_zero` | ✅ |
| `fe_one` | `fe25519_one` | ✅ |
| `fe_add` | `fe25519_add` | ✅ |
| `fe_sub` | `fe25519_sub` | ✅ |
| `fe_mul` | `fe25519_mul` | ✅ |
| `fe_sqr` | `fe25519_sqr` | ✅ |
| `fe_mul_a24` | `fe25519_mul_a24` | ✅ |
| `fe_inv` | `fe25519_inv` | ✅ |
| `fe_cswap` | `fe25519_cswap` | ✅ |
| `fe_reduce_final` | `fe25519_reduce_final` | ✅ |
| `fe_cmp_p` | `fe25519_cmp_p` | ❌ WG-only (kept for WG internal use) |
| `fe_reduce_wide` | `fe25519_reduce_wide` | ❌ WG-only (internal helper; sibling has its own) |
| `reu_mul_init` | `reu_mul_init` | ✅ unchanged |
| `reu_fetch_mul_row` | `reu_fetch_mul_row` | ✅ unchanged |

### ZP pointers (constants.s)

| ACME | ca65 | Notes |
|------|------|-------|
| `fe_src1` ($1E) | `fe25519_src1` | rename |
| `fe_src2` ($20) | `fe25519_src2` | rename |
| `fe_dst` ($22) | `fe25519_dst` | rename |
| `fe_misc` ($24) | `fe_misc` | unchanged (same in lib) |
| `fe_carry` ($26) | `fe_carry` | unchanged |
| `fe_loop` ($27) | `fe_loop` | unchanged |
| `fe_mul_i` ($28) | `fe_mul_i` | unchanged |
| `fe_mul_j` ($29) | `fe_mul_j` | unchanged |

### Scratch buffers

The library uses `fe25519_tmp1..4`, `fe_wide`. WG uses `fe_tmp1..3`,
`fe_wide`. Rename `fe_tmp*` → `fe25519_tmp*` and **add `fe25519_tmp4`**
if any lib code path needs it (deferred; check during Phase 3 migration
of x25519.s).

### Migration friction

- **Self-modifying code** in `fe_cswap`, `fe_mul`, `fe_sqr` — patches
  absolute addresses into LDA/STA. c64-x25519's versions use the same
  pattern (v0.3 "self-mod fe_cswap" from recent commits). Port
  mechanically.
- **Buffer alignment** — c64-x25519 requires destination buffers at
  page-aligned 32-byte-stride offsets ($00, $20, $40, ..., $E0 within a
  page). WG already places `fe_tmp*`, `x25_*` this way per
  `src/data.asm`. Verify during Phase 4 data.asm migration.

## Module: x25519 (crypto/x25519.s)

Sibling: `c64-x25519/src/x25519.s` + `x25519.inc`. **All public names
already match.** Callers of `fe_*` inside this module must be updated to
`fe25519_*` in the same PR as fe25519 migration.

| ACME | ca65 | Notes |
|------|------|-------|
| `x25519_clamp` | `x25519_clamp` | unchanged |
| `x25519_scalarmult` | `x25519_scalarmult` | unchanged |
| `x25519_base` | `x25519_base` | unchanged |
| `x25519_ladder_step` | `x25519_ladder_step` | internal, unchanged |

Data buffers: `x25_scalar`, `x25_u`, `x25_result`, `x25_basepoint`,
`x25_x2`, `x25_z2`, `x25_x3`, `x25_z3`, `x25_a`, `x25_b`, `x25_da`,
`x25_cb`, `x25_e` — all match library names.

## WG-only modules (no sibling; no rename)

- `handshake.asm`, `transport.asm`, `session.asm`, `cookie.asm`,
  `tai64n.asm`, `timer.asm`, `entropy.asm`, `config.asm`,
  `disk_config.asm`, `ip_build.asm`, `net.asm` — keep symbol names. Move
  to `src/wg/*.s` and `src/net/ip65/*.s` per plan.

## Net ABI symbols (introduced in Phase 5)

Mirroring `c64-https/src/net_abi.inc`, adapted for UDP:

```
.import net_init
.import net_dhcp_acquire
.import net_poll
.import net_udp_bind
.import net_udp_send
.import net_udp_recv
.import net_udp_close
.import net_udp_set_recv_cb
.import net_dns_resolve
.import net_local_ip
.import net_resolved_ip
.import net_last_error
```

Phase 5 replaces direct `ip65_udp_*` / `ip65_dns_*` calls in
`handshake.s`, `transport.s`, `session.s` with these `net_udp_*` calls,
and moves the ZP save/restore from `net.asm` into
`src/net/ip65/net.s`.

## Verification scripts (built in Phase 3)

`tools/check_abi_drift.py` — diff our `src/crypto_abi.inc` against the
sibling libs' public exports and fail CI if names diverge. Runs in CI
after `make`.

## Summary

- **~20 symbols renamed** (all `fe_*` → `fe25519_*`, plus 3 `kdf_*` →
  `blake2s_kdf_*`).
- **~15 call sites per renamed symbol** (x25519.asm, handshake.asm,
  transport.asm are heaviest consumers).
- **0 ZP slots relocated.**
- **No logic changes.**

Total Phase 3 churn: ~300 line edits, localized to crypto modules + their
direct callers.
