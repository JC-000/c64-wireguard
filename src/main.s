; src/main.s — Phase 1 scaffolding entry point.
;
; Minimal ca65 stub that produces a loadable PRG. Later phases will
; replace this with the real boot sequence (BASIC ROM swap-out,
; SHADOW_BSS zero, banner, ip65 init, WireGuard state machine).
;
; For Phase 1 the only goal is: a .prg that loads into memory without
; crashing and proves the cfg + ip65 blob embedding work end-to-end.
; We set the border color red so a successful load is visible, then
; halt in an infinite loop. RESTORE + STOP returns to BASIC.

; =============================================================================
; BASIC stub: 10 SYS 2061
; Loaded at $0801. Matches c64-https's layout so `start` lands at $080D.
; =============================================================================
        .segment "EXEHDR"
        .word   bas_end                 ; pointer to next BASIC line
        .word   10                      ; line number
        .byte   $9e                     ; SYS token
        .byte   "2061"                  ; decimal address of `start` ($080D)
        .byte   0                       ; end of BASIC line
bas_end:
        .word   0                       ; end of BASIC program

; =============================================================================
; Code
; =============================================================================
        .segment "CODE"

start:
        sei                             ; mask IRQs
        lda #$02                        ; red
        sta $d020                       ; border
        sta $d021                       ; background
@halt:
        jmp @halt                       ; RUN/STOP+RESTORE to return to BASIC
