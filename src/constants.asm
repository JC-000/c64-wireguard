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

; fe25519 field arithmetic working variables
fe_src1         = $1e           ; 2-byte pointer to operand 1
fe_src2         = $20           ; 2-byte pointer to operand 2
fe_dst          = $22           ; 2-byte pointer to destination
fe_misc         = $24           ; 2-byte misc pointer
fe_carry        = $26           ; carry/borrow byte
fe_loop         = $27           ; loop counter
fe_mul_i        = $28           ; multiply outer index
fe_mul_j        = $29           ; multiply inner index

; X25519 working variables
x25_prev_bit    = $2a           ; previous k_t for swap
x25_bit_ctr     = $2b           ; bit counter
x25_byte_idx    = $2c           ; byte index in scalar
x25_bit_mask    = $2d           ; current bit mask

; --- BLAKE2s constants ---
blake2s_block_size = 64         ; bytes per block
blake2s_hash_size  = 32         ; output size (256 bits)
blake2s_rounds     = 10         ; number of rounds

; --- General constants ---
max_input_len   = 255           ; maximum single-call input length

; =============================================================================
; ip65 ZP overlap zone
; ip65 uses $02-$1B during execution (cc65 standard ZP). Overlaps our crypto
; ZP. net.asm save/restore handles time-sharing.
; =============================================================================
ip65_zp_start   = $02
ip65_zp_end     = $1b           ; inclusive
ip65_zp_size    = ip65_zp_end - ip65_zp_start + 1  ; 26 bytes

; =============================================================================
; ip65 jump table at $2000 (fixed offsets from ip65-build/ip65_stub.s)
; =============================================================================
ip65_base           = $2000
ip65_init           = ip65_base + 0     ; A=0 default; C=0 ok
ip65_process        = ip65_base + 3     ; poll; C=0 packet, C=1 idle
ip65_dhcp_init      = ip65_base + 6     ; DHCP; C=0 ok
ip65_dns_resolve    = ip65_base + 9     ; resolve; C=0 ok
ip65_udp_add        = ip65_base + 12    ; udp_callback set, AX=port; C=0 ok
ip65_udp_remove     = ip65_base + 15    ; AX=port; C=0 ok
ip65_udp_send       = ip65_base + 18    ; AX=data ptr; C=0 ok
ip65_dns_set_host   = ip65_base + 21    ; AX=hostname ptr
ip65_set_udp_cb     = ip65_base + 24    ; AX=callback addr
ip65_set_udp_dest   = ip65_base + 27    ; AX=4-byte IP ptr

; ip65 variable table at ip65_base+30 (2-byte address pointers)
ip65_vt             = ip65_base + 30
ip65_vt_cfg_mac     = ip65_vt + 0       ; -> 6 bytes MAC
ip65_vt_cfg_ip      = ip65_vt + 2       ; -> 4 bytes our IP
ip65_vt_cfg_netmask = ip65_vt + 4       ; -> 4 bytes netmask
ip65_vt_cfg_gateway = ip65_vt + 6       ; -> 4 bytes gateway
ip65_vt_cfg_dns     = ip65_vt + 8       ; -> 4 bytes DNS server
ip65_vt_dns_ip      = ip65_vt + 10      ; -> 4 bytes resolved IP
ip65_vt_ip65_error  = ip65_vt + 12      ; -> 1 byte error code
ip65_vt_udp_dest    = ip65_vt + 14      ; -> 4 bytes UDP dest IP
ip65_vt_udp_dport   = ip65_vt + 16      ; -> 2 bytes UDP dest port
ip65_vt_udp_sport   = ip65_vt + 18      ; -> 2 bytes UDP src port
ip65_vt_udp_snd_len = ip65_vt + 20      ; -> 2 bytes UDP send length

; Direct addresses (from ip65-c64.map)
ip65_cfg_ip         = $3252             ; 4 bytes: our IP address
ip65_cfg_mac        = $324c             ; 6 bytes: our MAC address
ip65_udp_snd_dest   = $4ef5            ; 4 bytes: udp_send_dest
ip65_udp_snd_dport  = $4efb            ; 2 bytes: udp_send_dest_port
ip65_udp_snd_sport  = $4ef9            ; 2 bytes: udp_send_src_port
ip65_udp_snd_len    = $4efd            ; 2 bytes: udp_send_len
ip65_error_addr     = $4ce8            ; 1 byte: last error code
ip65_udp_inp        = $412b            ; udp_inp (inbound UDP packet base)
ip65_udp_data_off   = 8                ; offset of data within UDP packet

; WireGuard default port
wg_default_port     = 51820

WG_ICMP_ID      = $c640         ; ICMP echo identifier
IP_PROTO_ICMP   = 1             ; IP protocol: ICMP
IP_PROTO_UDP    = 17            ; IP protocol: UDP
