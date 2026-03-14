; =============================================================================
; main.asm - WireGuard Noise Protocol for Commodore 64
; Top-level file: includes all modules in correct order
; =============================================================================

!cpu 6502
; --- Constants and equates (no code emitted) ---
!source "constants.asm"

; --- Program origin ---
* = $0801

; --- Code modules ---
!source "boot.asm"
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

; --- Data and strings (placed after code) ---
!source "data.asm"
!source "strings.asm"
