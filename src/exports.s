; =============================================================================
; src/exports.s - Promote equates from constants.inc to linker-visible labels.
;
; ca65 does NOT emit labels.txt entries for equates declared via `name = value`
; unless they're explicitly exported. But since each .s file .includes
; constants.inc, declaring `.exportzp` there would cause duplicate-export
; errors at link. So the exports live here in a single .o file.
;
; Every symbol the c64-test-harness Labels reader may reference (via
; `labels[\"b2s_data_ptr\"]` etc.) must be listed here. Missing a symbol
; causes `FATAL: 'X' label not found in labels.txt` from the test harness.
;
; The ACME build emits all equates automatically via `--vicelabels`, so
; this file has no ACME counterpart.
; =============================================================================

.include "constants.inc"

; REU bank-allocation map. Authoritative single source of truth for which
; REU bank/offset each subsystem owns; included here so it is syntax-
; checked on every build even though no .s file currently references the
; equates by symbol (fe25519.s still hard-codes its bank/offset compute).
.include "crypto/shared/reu_layout.inc"

; --- General-purpose / word32 ZP ---
.exportzp zp_ptr1, zp_ptr2, zp_tmp1, zp_tmp2
.exportzp w32_src1, w32_src2, w32_dst

; --- BLAKE2s ZP ---
.exportzp b2s_round, b2s_i, b2s_ptr, b2s_data_ptr, b2s_remain
.exportzp b2s_key_len, b2s_offset

; --- ChaCha20 ZP ---
.exportzp cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain, cc20_buf_pos

; --- Poly1305 ZP ---
.exportzp poly_i, poly_j, poly_carry, poly_tmp

; --- mult66 pointers (aliased with cc20_*) ---
.exportzp lmul0, lmul1

; --- ChaCha20-Poly1305 sibling Profile B ct_mul_8x8 scratch ($1e/$1f) ---
; Always exported so the chacha sibling's .importzp ct_diff_raw /
; ct_sign_mask resolves even when USE_CHACHA_SIBLING=0 (harmless: the
; in-tree poly1305.s doesn't reference these). Same byte range as
; fe_src1 ($1e-$1f); time-share applies — see zp_config.inc.
.exportzp ct_diff_raw, ct_sign_mask

; --- ChaCha20 ZP-pinned working buffer ($40-$7F, sibling-only) ---
; cc20_work / cc20_keystream are non-ZP BSS labels in the in-tree
; build (defined in wg/data.s); the sibling pins them to ZP $40.
; Exported as ZP only when USE_CHACHA_SIBLING=1 so the in-tree linker
; still sees the BSS definitions otherwise.
.ifdef USE_CHACHA_SIBLING
.exportzp cc20_work, cc20_keystream
.endif

; --- fe25519 ZP ---
.exportzp fe_src1, fe_src2, fe_dst, fe_misc, fe_carry, fe_loop
.exportzp fe_mul_i, fe_mul_j

; --- fe25519 ZP ABI-aligned aliases (match c64-x25519 library naming) ---
; Mandatory under USE_X25519_SIBLING=1 (sibling's .importzp targets);
; left unconditional so test-harness Labels.from_file() always sees them.
fe25519_src1 = fe_src1
fe25519_src2 = fe_src2
fe25519_dst  = fe_dst
.exportzp fe25519_src1, fe25519_src2, fe25519_dst

; --- X25519 ZP ---
.exportzp x25_prev_bit, x25_bit_ctr, x25_byte_idx, x25_bit_mask

; --- Sibling fe25519 / x25519 imports satisfied via host-side equates ---
; The c64-x25519 sibling's .importzp set (mul_pending, mul_bound,
; mul_ripple_start, fe_sqr_pairs, fe_cmp_mask, fe_subp_rhs,
; fe_add_carry_mask) is resolved by reusing WG's existing ZP slots
; via the sibling's own zp_config.s defaults — those defaults are not
; redefined here, so the .ifndef-guarded equates in the staged
; libs/x25519/src/zp_config.s take effect at sibling assemble time.
; (Staged with ZP_CONFIG_NO_EXPORTS=1 in the integration script so the
; sibling's .o does not duplicate-export them.)

; --- Quarter-square table at $8000-$83FF (runtime-built by sqtab_init) ---
; Address-only equates; the table itself is built at runtime by
; either the in-tree src/crypto/poly1305.s:sqtab_init or the sibling
; libs/chacha20poly1305/src/lib/poly1305_lib.s:sqtab_init. The sibling
; x25519's x25519_init.s .imports sqtab_lo / sqtab_hi to clear /
; verify the table region. Without this fallback, USE_X25519_SIBLING=1
; combined with USE_CHACHA_SIBLING=1 would leave sqtab_lo/hi
; unresolved (in-tree poly1305.s is dropped under USE_CHACHA_SIBLING,
; and the chacha sibling treats sqtab_lo/hi as private equates). The
; equate values match both in-tree and sibling private definitions.
;
; Only emitted under USE_CHACHA_SIBLING=1 — otherwise the in-tree
; src/crypto/poly1305.s already exports them and ld65 would flag a
; duplicate-export error.
.ifdef USE_CHACHA_SIBLING
sqtab_lo = $8000
sqtab_hi = $8200
.export sqtab_lo, sqtab_hi
.endif

; --- Non-ZP constants the test harness or tools may reference ---
.export blake2s_block_size, blake2s_hash_size, blake2s_rounds
.export max_input_len
.export wg_default_port, WG_ICMP_ID, IP_PROTO_ICMP, IP_PROTO_UDP
.export REJECT_COUNTER_B7, REKEY_COUNTER_B7

; --- Kernal routines (exported for completeness; tests rarely need these
;     by name, but symmetry with ACME's vicelabels output helps) ---
.export chrout, getin, chrin, setlfs, setnam, open, close, clrchn
.export load, readst, chkin

; --- Hardware registers ---
.export vic_border, vic_bg
.export cia1_ta_lo, cia1_ta_hi, cia1_cra
.export sid_v3_freq_lo, sid_v3_freq_hi, sid_v3_ctrl, sid_osc3
.export reu_status, reu_command, reu_c64_lo, reu_c64_hi
.export reu_reu_lo, reu_reu_hi, reu_bank, reu_len_lo, reu_len_hi
.export reu_addr_ctrl, proc_port

; --- System addresses ---
.export screen_ram, color_ram, kbd_buffer, kbd_buf_count, cassette_buf
