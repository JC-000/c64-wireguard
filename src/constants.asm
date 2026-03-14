; =============================================================================
; constants.asm - System equates, zero page, hardware addresses
; No code emitted - pure equates only
; =============================================================================

; --- Kernal routines ---
chrout          = $ffd2         ; output character
getin           = $ffe4         ; get character from keyboard
chrin           = $ffcf         ; input character
setlfs          = $ffba         ; set file parameters
setnam          = $ffbd         ; set filename
open            = $ffc0         ; open file
close           = $ffc3         ; close file
clrchn          = $ffcc         ; clear channels
load            = $ffd5         ; load from device

; --- Hardware registers ---
vic_border      = $d020         ; border color
vic_bg          = $d021         ; background color
cia1_ta_lo      = $dc04         ; CIA #1 timer A low byte
cia1_ta_hi      = $dc05         ; CIA #1 timer A high byte
cia1_cra        = $dc0e         ; CIA #1 control register A
sid_v3_freq_lo  = $d40e         ; SID voice 3 frequency low
sid_v3_freq_hi  = $d40f         ; SID voice 3 frequency high
sid_v3_ctrl     = $d412         ; SID voice 3 control
sid_osc3        = $d41b         ; SID oscillator 3 readout
reu_status      = $df00         ; REU status register
reu_command     = $df01         ; REU command register
reu_c64_lo      = $df02         ; REU C64 address low
reu_c64_hi      = $df03         ; REU C64 address high
reu_reu_lo      = $df04         ; REU address low
reu_reu_hi      = $df05         ; REU address high
reu_bank        = $df06         ; REU bank
reu_len_lo      = $df07         ; REU transfer length low
reu_len_hi      = $df08         ; REU transfer length high
proc_port       = $01           ; processor port (ROM banking)

; --- System addresses ---
screen_ram      = $0400         ; screen memory (40x25)
color_ram       = $d800         ; color memory
kbd_buffer      = $0277         ; keyboard buffer
kbd_buf_count   = $00c6         ; keyboard buffer count
cassette_buf    = $0334         ; cassette buffer (safe scratch area)

; --- Zero page variables ---
; General purpose pointers
zp_ptr1         = $fb           ; 2-byte pointer
zp_ptr2         = $fd           ; 2-byte pointer
zp_tmp1         = $02           ; temp byte
zp_tmp2         = $03           ; temp byte

; word32 operand pointers (used by add32, xor32, etc.)
w32_src1        = $04           ; 2-byte pointer to first 32-bit operand
w32_src2        = $06           ; 2-byte pointer to second 32-bit operand
w32_dst         = $08           ; 2-byte pointer to destination 32-bit word

; BLAKE2s working variables
b2s_round       = $0a           ; current round counter
b2s_i           = $0b           ; loop counter
b2s_ptr         = $0c           ; 2-byte general pointer for BLAKE2s
; $0e reserved
b2s_data_ptr    = $0f           ; 2-byte pointer to input data
b2s_remain      = $11           ; bytes remaining in current update
b2s_key_len     = $12           ; key length (0 = unkeyed)
b2s_offset      = $13           ; offset into current block buffer

; ChaCha20 working variables
cc20_round      = $14           ; round counter (0-9)
cc20_qr_idx     = $15           ; quarter-round parameter index
cc20_data_ptr   = $16           ; 2-byte pointer to input data ($16-$17)
cc20_remain     = $18           ; bytes remaining
cc20_buf_pos    = $19           ; position within 64-byte keystream buffer

; Poly1305 working variables
poly_i          = $1a           ; inner loop counter
poly_j          = $1b           ; outer loop counter
poly_carry      = $1c           ; carry byte for multi-precision arithmetic
poly_tmp        = $1d           ; temp for multiply

; --- BLAKE2s constants ---
blake2s_block_size = 64         ; bytes per block
blake2s_hash_size  = 32         ; output size (256 bits)
blake2s_rounds     = 10         ; number of rounds

; --- General constants ---
max_input_len   = 255           ; maximum single-call input length
