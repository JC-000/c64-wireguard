; =============================================================================
; main.asm - WireGuard Noise Protocol for Commodore 64
; Top-level file: includes all modules in correct order
;
; Memory layout:
;   $0801-$1FFF: boot, net wrapper (~6KB available)
;   $2000-$32EF: ip65 binary blob (UDP-only, ~4.8KB)
;   $32F0+:      crypto code + data + strings
;   $7800-$7BFF: sqtab (quarter-square multiply tables)
; =============================================================================

!cpu 6502
; --- Constants and equates (no code emitted) ---
!source "constants.asm"

; --- Program origin ---
* = $0801

; --- Code that must fit before $2000 ---
!source "boot.asm"
!source "net.asm"

; =============================================================================
; ip65 binary blob — built with ca65/ld65, placed at $2000
; Jump table at $2000, code+data $2000-$32EF, BSS at $4000+
; =============================================================================
* = $2000
!binary "../ip65-build/ip65-c64.bin"

; =============================================================================
; Crypto modules (relocated after ip65 blob)
; =============================================================================
!source "word32.asm"
!source "blake2s.asm"
!source "blake2s_kdf.asm"
!source "chacha20.asm"
!source "poly1305.asm"
!source "aead.asm"
!source "fe25519.asm"
!source "x25519.asm"
!source "tai64n.asm"
!source "handshake.asm"
!source "transport.asm"
!source "entropy.asm"
!source "config.asm"
!source "session.asm"

; --- Data and strings (placed after code) ---
!source "data.asm"
!source "strings.asm"
