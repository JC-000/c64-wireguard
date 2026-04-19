; src/loadaddr.s — 2-byte PRG load address header (CBM convention).
; ld65 places this at the start of the output file.
.segment "LOADADDR"
.word $0801
