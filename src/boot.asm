; =============================================================================
; boot.asm - BASIC stub and program entry point
; =============================================================================

; BASIC stub: 10 SYS 2064
basic_stub:
        !word basic_end         ; pointer to next BASIC line
        !word 10                ; line number 10
        !byte $9e               ; SYS token
        !text "2064"            ; decimal address (must match start label)
        !byte 0                 ; end of line
basic_end:
        !word 0                 ; end of BASIC program

; =============================================================================
; main program entry point
; =============================================================================
start:
        ; bank out BASIC ROM to use $A000-$BFFF as RAM
        lda proc_port
        and #$fe                ; clear bit 0 (LORAM) — bank out BASIC ROM
        sta proc_port

        ; clear screen
        jsr clrscr

        ; display title
        lda #<title_msg
        ldy #>title_msg
        jsr print_string

        ; fall through to main loop
main_loop:
        jsr getin
        beq main_loop           ; wait for keypress

        cmp #$51                ; 'Q' = quit
        beq quit

        jmp main_loop

quit:
        ; restore BASIC ROM before returning
        lda proc_port
        ora #$01
        sta proc_port
        rts

; =============================================================================
; clrscr - clear screen
; =============================================================================
clrscr:
        lda #$93                ; PETSCII clear screen
        jsr chrout
        rts

; =============================================================================
; print_string - print null-terminated string
; input: A = low byte of address, Y = high byte of address
; =============================================================================
print_string:
        sta zp_ptr1
        sty zp_ptr1+1
        ldy #0
@loop:
        lda (zp_ptr1),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts
