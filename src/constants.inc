; =============================================================================
; src/constants.inc - ca65 equates (mirrors src/constants.asm for ACME build)
;
; This file is the ca65 source of truth for WG's system equates. It is
; functionally identical to src/constants.asm (which ACME keeps using
; until Phase 6 retires the ACME build). The two files must stay in
; sync until constants.asm is deleted.
;
; Pure equates, no code emitted. Safe to .include at the top of any
; ca65 source file.
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
readst          = $ffb7         ; read I/O status
chkin           = $ffc6         ; set input channel

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
reu_addr_ctrl   = $df0a         ; REU address control
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

; word32 operand pointers
w32_src1        = $04
w32_src2        = $06
w32_dst         = $08

; BLAKE2s working variables
b2s_round       = $0a
b2s_i           = $0b
b2s_ptr         = $0c
b2s_data_ptr    = $0f
b2s_remain      = $11
b2s_key_len     = $12
b2s_offset      = $13

; ChaCha20 working variables
cc20_round      = $14
cc20_qr_idx     = $15
cc20_data_ptr   = $16
cc20_remain     = $18
cc20_buf_pos    = $19

; Poly1305 working variables
poly_i          = $1a
poly_j          = $1b
poly_carry      = $1c
poly_tmp        = $1d

; mult66 pointers (aliased with cc20_*)
lmul0           = $14
lmul1           = $16

; fe25519 field arithmetic
fe_src1         = $1e
fe_src2         = $20
fe_dst          = $22
fe_misc         = $24
fe_carry        = $26
fe_loop         = $27
fe_mul_i        = $28
fe_mul_j        = $29

; X25519
x25_prev_bit    = $2a
x25_bit_ctr     = $2b
x25_byte_idx    = $2c
x25_bit_mask    = $2d

; --- BLAKE2s constants ---
blake2s_block_size = 64
blake2s_hash_size  = 32
blake2s_rounds     = 10

; --- General constants ---
max_input_len   = 255

; --- ip65 ZP overlap zone ---
ip65_zp_start   = $02
ip65_zp_end     = $1b
ip65_zp_size    = ip65_zp_end - ip65_zp_start + 1

; --- ip65 jump table and variable pointers are defined in
;     src/net/ip65/ip65_symbols.inc ---

; --- WireGuard protocol constants ---
wg_default_port     = 51820
WG_ICMP_ID          = $c640
IP_PROTO_ICMP       = 1
IP_PROTO_UDP        = 17

; Key rotation counter thresholds
REJECT_COUNTER_B7   = $10
REKEY_COUNTER_B7    = $0F
