; src/net/ip65/ip65_blob.s — ca65 wrapper around the pre-built ip65 binary.
;
; The ip65 library is built by the ACME→cc65 Makefile pipeline into
;   ip65-build/ip65-c64.bin
; which is a WG-specific UDP-only blob pre-linked at $2000 (jump table
; at $2000, code+data through ~$32EF, BSS at $A000+). This wrapper
; .incbin's that blob into the NET_CODE segment so ld65 places it at
; $2000 inside the final PRG.
;
; Do NOT modify ip65-build/ or the ip65 submodule — they remain the
; source of truth for the ip65 binary. This file just glues the pre-
; built blob into the ca65 link.
;
; Segment NET_CODE is defined by cfg/c64-wireguard-ip65.cfg as
;   start = $2000, size = $2000, file = %O, type = ro
; which causes ld65 to place the blob at $2000.

.segment "NET_CODE"

; ca65 resolves .incbin paths relative to the including source file,
; so from src/net/ip65/ip65_blob.s the blob is three levels up from
; repo root.
.incbin "../../../ip65-build/ip65-c64.bin"
