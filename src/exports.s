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

; --- fe25519 ZP ---
.exportzp fe_src1, fe_src2, fe_dst, fe_misc, fe_carry, fe_loop
.exportzp fe_mul_i, fe_mul_j

; --- X25519 ZP ---
.exportzp x25_prev_bit, x25_bit_ctr, x25_byte_idx, x25_bit_mask

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
