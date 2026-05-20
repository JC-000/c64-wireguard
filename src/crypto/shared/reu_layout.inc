; =============================================================================
; src/crypto/shared/reu_layout.inc - Authoritative REU bank-allocation map
;
; The REU (Ram Expansion Unit) is shared between the X25519 multiplication
; tables (~128 KB), future swappable code overlays, and any future sibling
; library that needs REU-backed precompute. This header is the single
; source of truth for which bank/offset each consumer owns.
;
; Adapted from c64-https/src/crypto/shared/reu_layout.inc (same project
; family). The bank map below matches WG's existing in-tree REU usage
; verbatim — `src/crypto/fe25519.s:reu_mul_init` already writes to banks
; 0-1 with `bank = a >> 7`, `offset = (a & $7F) * 512`. Codifying the map
; here lets future consumers (chacha sibling Profile A, code overlays,
; P-256 / P-384 precompute, etc.) coexist without bank-allocation fights.
;
; Bank map (REU 24-bit address):
;   $00000-$1FFFF  (banks 0-1, 128 KB)  x25519 mul tables   (in-tree default)
;   $00000-$5FFFF  (banks 0-5, 384 KB)  x25519 sibling      (USE_X25519_SIBLING=1)
;   $20000-$2FFFF  (bank 2,    64 KB)   overlay store (3x 8 KB slots + slack)
;   $30000-$3FFFF  (bank 3,    64 KB)   P-256 precompute    (RESERVED)
;   $40000-$7FFFF  (banks 4-7, 256 KB)  P-384 precompute + headroom (RESERVED)
;
; ** Latent collision under USE_X25519_SIBLING=1 **
; The c64-x25519 sibling (post-c64-lib-contract §3) reserves SIX
; contiguous banks at `X25519_REU_BANK` (default $00), giving
; `LIB_X25519_REU_BANKS_USED = $3F << X25519_REU_BANK`. With the default
; pin, banks 0-5 are claimed, which overlaps:
;   - bank 2: overlay store (unused at runtime today; latent)
;   - bank 3: P-256 (reserved-not-allocated; latent)
;   - banks 4-5: P-384 (reserved-not-allocated; latent)
; All four overlapping reservations are aspirational — the overlay
; dispatcher hasn't been vendored, and P-256/P-384 are RESERVED-not-
; ALLOCATED. The collision becomes a real bug the first time WG
; activates any of those reservations. Plan when that day comes:
; pin `--asm-define X25519_REU_BANK=$08` (requires 1750-class REU,
; 16 banks) OR contract the x25519 sibling at a non-zero base after
; rewriting reu_layout.inc to compress the reservation map.
;
; Each declared overlay image is 8 KB. The live overlay slot in main RAM
; (CRYPTO_OVERLAY region in the linker cfg) is paged in by a future
; `crypto_swap_to_*` dispatcher (not yet vendored — c64-https has the
; reference implementation in src/crypto/shared/crypto_swap.s, ~80 lines).
;
; Usage:
;   .include "crypto/shared/reu_layout.inc"
;   ; ... then refer to REU_X25519_MUL_TABLES_BASE / REU_OVERLAY_X25519 / etc.
;
; Override at assemble time:
;   ca65 --asm-define REU_OVERLAY_STORE_BASE=$30000 ...
;
; Compatibility note (chacha sibling Profile A):
;   c64-ChaCha20-Poly1305 v0.3.2+ (issue #19 fix) accepts overrides via
;   POLY1305_REU_BANK / POLY1305_REU_OFFSET. WG should not use Profile A
;   today (sqtab at $8000-$83FF is never clobbered post-boot, so the
;   fast-restore has no value for WG); when chacha sibling lands, set
;   POLY1305_REU=undef to take Profile B and avoid the bank-0 collision.
; =============================================================================

; --- x25519 mul tables (banks 0-1, 128 KB) ---
; Layout: row a (a = 0..255) at bank=(a>>7), offset=(a & $7F) * $200.
; Each row is 512 bytes: 256 bytes of low product, then 256 bytes of high.
; Owned by src/crypto/fe25519.s:reu_mul_init / reu_fetch_mul_row.
.ifndef REU_X25519_MUL_TABLES_BASE
REU_X25519_MUL_TABLES_BASE = $00000
.endif

; --- overlay storage (single bank; three 8 KB slots) ---
; NOTE: offset $0000-$003F in bank 2 is reserved by the c64-x25519 sibling
; as a 64-byte zero buffer for `reu_clear_wide` (DMA-zeros fe_wide on the
; C64 side). Overlay images start at offset $0100 so they do not collide.
; (WG's in-tree fe25519 does not currently use reu_clear_wide; the slot
; is reserved for future sibling-import compatibility.)
.ifndef REU_OVERLAY_STORE_BASE
REU_OVERLAY_STORE_BASE     = $20100
.endif
.ifndef REU_OVERLAY_X25519
REU_OVERLAY_X25519         = $20100
.endif
.ifndef REU_OVERLAY_P256
REU_OVERLAY_P256           = $22100
.endif
.ifndef REU_OVERLAY_P384
REU_OVERLAY_P384           = $24100
.endif

; --- P-256 precompute (1 bank, RESERVED for future c64-nist-curves import) ---
.ifndef REU_P256_PRECOMPUTE_BASE
REU_P256_PRECOMPUTE_BASE   = $30000
.endif

; --- P-384 precompute (4 banks, RESERVED for future c64-nist-curves import) ---
.ifndef REU_P384_PRECOMPUTE_BASE
REU_P384_PRECOMPUTE_BASE   = $40000
.endif

; --- overlay slot size (bytes) ---
; Each overlay image occupies exactly this many bytes in the REU store and
; is DMA'd into the live CRYPTO_OVERLAY region at runtime (when that
; region exists — currently deferred; see docs/ for status).
.ifndef OVERLAY_SIZE
OVERLAY_SIZE               = $2000   ; 8 KB
.endif

; --- chacha sibling Profile A reservation (currently unused by WG) ---
; If a future build flips POLY1305_REU on, the chacha sibling stashes its
; 1 KB sqtab backup at this address. Default ($0000 in bank 0) collides
; with REU_X25519_MUL_TABLES_BASE — overriding is mandatory if Profile A
; is ever enabled. Recommended override: bank 2 offset $1F00 (just below
; the overlay store), or carve a dedicated bank.
;
; .define POLY1305_REU_BANK=...  / POLY1305_REU_OFFSET=...
