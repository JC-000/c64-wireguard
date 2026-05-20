; =============================================================================
; src/hw_constants.inc — Commodore 64 hardware register + KERNAL equates.
;
; Pure equates, no code emitted. Safe to .include from any ca65 source.
; Hardware addresses are fixed by the C64 architecture and do not need
; `.ifndef` guards (a future relocatable build would not move these).
;
; Linker-symbol exports for these addresses live in src/exports.s, so
; the test harness can resolve them via labels.txt by name.
; =============================================================================

; --- KERNAL routines ---
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

; --- VIC-II ---
vic_border      = $d020         ; border color
vic_bg          = $d021         ; background color

; --- CIA #1 ---
cia1_ta_lo      = $dc04         ; CIA #1 timer A low byte
cia1_ta_hi      = $dc05         ; CIA #1 timer A high byte
cia1_cra        = $dc0e         ; CIA #1 control register A

; --- SID ---
sid_v3_freq_lo  = $d40e         ; SID voice 3 frequency low
sid_v3_freq_hi  = $d40f         ; SID voice 3 frequency high
sid_v3_ctrl     = $d412         ; SID voice 3 control
sid_osc3        = $d41b         ; SID oscillator 3 readout

; --- REU (1764/1750 RAM Expansion Unit) ---
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

; --- CPU I/O port ---
proc_port       = $01           ; processor port (ROM banking)

; --- System addresses ---
screen_ram      = $0400         ; screen memory (40x25)
color_ram       = $d800         ; color memory
kbd_buffer      = $0277         ; keyboard buffer
kbd_buf_count   = $00c6         ; keyboard buffer count
cassette_buf    = $0334         ; cassette buffer (safe scratch area)
