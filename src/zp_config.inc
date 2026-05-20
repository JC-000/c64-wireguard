; =============================================================================
; src/zp_config.inc — zero-page slot allocation (relocatable via --asm-define)
;
; Every slot below is `.ifndef`-guarded so a consumer or future sibling-
; library import can pin a different address at assemble time:
;
;   ca65 --asm-define fe_src1=$22 --asm-define fe_src2=$24 ...
;
; Defaults match the historical c64-wireguard allocation (Phase 0–8). The
; `.exportzp` declarations live in src/exports.s (a single .o file) per
; the existing convention — putting them here would cause duplicate-export
; errors since this header is .include'd transitively by every crypto
; module via src/constants.inc.
;
; Reference pattern: c64-nist-curves/src/zp_config.s. The relocatability
; story is part of the Phase B/C library-ingestion refactor — see the
; sibling issues filed at JC-000/c64-x25519#44 and
; JC-000/c64-ChaCha20-Poly1305#26 for the matching upstream work.
;
; Aliases (lmul0/lmul1) are defined in terms of the slots they alias so
; that overriding cc20_round/cc20_data_ptr automatically propagates.
;
; ip65 owns ZP $02–$1B (cc65 standard). The wrapper at
; src/net/ip65/net.s saves/restores those bytes around every ip65 call.
; Anything an override puts in $02–$1B must accept that round-trip.
; =============================================================================

; --- General-purpose pointers ---
.ifndef zp_ptr1
zp_ptr1         = $fb           ; 2-byte pointer
.endif
.ifndef zp_ptr2
zp_ptr2         = $fd           ; 2-byte pointer
.endif
.ifndef zp_tmp1
zp_tmp1         = $02           ; temp byte
.endif
.ifndef zp_tmp2
zp_tmp2         = $03           ; temp byte
.endif

; --- word32 operand pointers ---
.ifndef w32_src1
w32_src1        = $04
.endif
.ifndef w32_src2
w32_src2        = $06
.endif
.ifndef w32_dst
w32_dst         = $08
.endif

; --- BLAKE2s working variables ---
.ifndef b2s_round
b2s_round       = $0a
.endif
.ifndef b2s_i
b2s_i           = $0b
.endif
.ifndef b2s_ptr
b2s_ptr         = $0c
.endif
.ifndef b2s_data_ptr
b2s_data_ptr    = $0f
.endif
.ifndef b2s_remain
b2s_remain      = $11
.endif
.ifndef b2s_key_len
b2s_key_len     = $12
.endif
.ifndef b2s_offset
b2s_offset      = $13
.endif

; --- ChaCha20 working variables ---
.ifndef cc20_round
cc20_round      = $14
.endif
.ifndef cc20_qr_idx
cc20_qr_idx     = $15
.endif
.ifndef cc20_data_ptr
cc20_data_ptr   = $16
.endif
.ifndef cc20_remain
cc20_remain     = $18
.endif
.ifndef cc20_buf_pos
cc20_buf_pos    = $19
.endif

; --- Poly1305 working variables ---
.ifndef poly_i
poly_i          = $1a
.endif
.ifndef poly_j
poly_j          = $1b
.endif
.ifndef poly_carry
poly_carry      = $1c
.endif
.ifndef poly_tmp
poly_tmp        = $1d
.endif

; --- mult66 pointers (aliased with cc20_round / cc20_data_ptr) ---
; Defined in terms of the aliased slot so overrides propagate.
.ifndef lmul0
lmul0           = cc20_round
.endif
.ifndef lmul1
lmul1           = cc20_data_ptr
.endif

; --- fe25519 field arithmetic ---
.ifndef fe_src1
fe_src1         = $1e
.endif
.ifndef fe_src2
fe_src2         = $20
.endif
.ifndef fe_dst
fe_dst          = $22
.endif
.ifndef fe_misc
fe_misc         = $24
.endif
.ifndef fe_carry
fe_carry        = $26
.endif
.ifndef fe_loop
fe_loop         = $27
.endif
.ifndef fe_mul_i
fe_mul_i        = $28
.endif
.ifndef fe_mul_j
fe_mul_j        = $29
.endif

; --- X25519 ladder state ---
.ifndef x25_prev_bit
x25_prev_bit    = $2a
.endif
.ifndef x25_bit_ctr
x25_bit_ctr     = $2b
.endif
.ifndef x25_byte_idx
x25_byte_idx    = $2c
.endif
.ifndef x25_bit_mask
x25_bit_mask    = $2d
.endif
