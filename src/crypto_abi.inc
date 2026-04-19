; =============================================================================
; src/crypto_abi.inc — public crypto API consumed by WireGuard protocol layers.
;
; Drop-in contract: any implementation (in-tree today, sibling library
; tomorrow) must export these exact symbols with these exact calling
; conventions. Swapping implementation = changing the link line, no
; call-site changes.
;
; Sibling library correspondence:
;   fe25519_* / x25519_*  → c64-x25519           (src/x25519.inc)
;   chacha20_* / poly1305_* / aead_* → c64-ChaCha20-Poly1305
;   blake2s_*             → (no sibling library; stays in-tree)
;
; Consumers (.include "crypto_abi.inc") then reference the symbols as
; `.import`ed names. Phase 4 higher-level modules (handshake, transport,
; session) should use THIS file to stay future-swap-ready.
;
; Source of truth for symbol names: docs/ca65-migration/symbol-map.md
; =============================================================================

; --- X25519 / fe25519 (c64-x25519 library ABI) ---
.import fe25519_copy
.import fe25519_zero
.import fe25519_one
.import fe25519_add
.import fe25519_sub
.import fe25519_mul
.import fe25519_sqr
.import fe25519_mul_a24
.import fe25519_inv
.import fe25519_cswap
.import fe25519_reduce_final

.import x25519_clamp
.import x25519_scalarmult
.import x25519_base

; --- ChaCha20 / Poly1305 / AEAD (c64-ChaCha20-Poly1305 library ABI) ---
.import chacha20_init
.import chacha20_block
.import chacha20_encrypt

.import poly1305_init
.import poly1305_clamp
.import poly1305_block
.import poly1305_update
.import poly1305_final

.import aead_encrypt
.import aead_decrypt

; --- BLAKE2s family (WG-specific, no sibling library) ---
.import blake2s_init
.import blake2s_update
.import blake2s_final
.import blake2s_hash_oneshot
.import hmac_blake2s
.import blake2s_kdf_1
.import blake2s_kdf_2
.import blake2s_kdf_3

; --- One-off helpers that are NOT part of any sibling-lib ABI but are
;     currently WG-internal. Group separately so future ABI-drift
;     verification (tools/check_abi_drift.py in Phase 3.5) ignores them.

; fe25519 WG-only helpers (no sibling equivalent)
.import fe25519_cmp_p
.import fe25519_reduce_wide

; REU setup — called once at boot
.import sqtab_init
.import reu_mul_init
