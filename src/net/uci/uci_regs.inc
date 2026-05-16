; src/net/uci/uci_regs.inc — UCI (Ultimate Command Interface) register map
;
; The Ultimate 64 / 1541 Ultimate exposes a host-visible command interface
; in the $DFxx IO region. Commands are pushed into a FIFO via writes to
; UCI_CMD_DATA, the host issues control bits via UCI_CONTROL, and reads
; response bytes from UCI_RESP_DATA. Status bits drive a non-blocking
; state machine in the UCI adapter.
;
; Phase 1b: equates only — no code references these yet. Including this
; file into net.s validates that the headers compile cleanly and exposes
; the constants for Phase 2+.

; =============================================================================
; Register addresses
; =============================================================================
UCI_DEVICE        = $DF1B       ; r/w  device number (select target device)
UCI_STATUS        = $DF1C       ; r    status bits (see below)
UCI_CONTROL       = $DF1C       ; w    control bits (see below)
UCI_CMD_DATA      = $DF1D       ; w    command / parameter byte FIFO
UCI_ID            = $DF1D       ; r    identification byte ($C9 when present)
UCI_RESP_DATA     = $DF1E       ; r    response data FIFO
UCI_STATUS_DATA   = $DF1F       ; r    status string FIFO

; Expected value of UCI_ID when the command interface is available
UCI_ID_VALUE      = $C9

; =============================================================================
; Status register bits (read from UCI_STATUS)
; =============================================================================
UCI_STAT_DATA_AV  = $80         ; response data available
UCI_STAT_STAT_AV  = $40         ; status string available
UCI_STAT_STATE    = $30         ; state field mask
UCI_STAT_ERROR    = $08         ; command returned an error
UCI_STAT_CMD_BUSY = $01         ; command FIFO busy / command in flight

; =============================================================================
; Control register bits (write to UCI_CONTROL)
; =============================================================================
UCI_CTRL_PUSH_CMD = $01         ; commit pushed bytes as a command
UCI_CTRL_NEXT_DATA= $02         ; advance response data FIFO
UCI_CTRL_ABORT    = $04         ; abort in-flight command
UCI_CTRL_CLR_ERR  = $08         ; clear error state

; =============================================================================
; Device numbers (select target of a pushed command)
; =============================================================================
UCI_TARGET_NETWORK = $03        ; network stack

; =============================================================================
; Delay-loop fence macro — insert after every STA or LDA that accesses a UCI
; register ($DF1C-$DF1F), giving the FPGA time to latch writes AND settle
; reads before the CPU acts on the value.
;
; A simple NOP sled can't provide enough wall-clock time at high CPU
; speeds without overflowing the code segment (256 NOPs is the max that
; fits, giving only ~10.7 µs at 48 MHz — insufficient for the ~38 µs
; the FPGA needs). Instead we use a nested delay loop:
;   total cycles ≈ OUTER * (INNER * 5 + 5)
;
; Tuned empirically via binary search at 48 MHz:
;   OUTER=3 INNER=121 (~1830 cycles, ~38 µs at 48 MHz) = FAIL
;   OUTER=3 INNER=122 (~1845 cycles, ~38.4 µs at 48 MHz) = PASS (minimum)
;   OUTER=5 INNER=100 (~2525 cycles, ~52 µs at 48 MHz) = chosen (35% margin)
;
; At 1 MHz the overhead is ~2.5 ms per access — acceptable for networking.
; The macro preserves A and X via the stack, costing ~14 bytes per call
; site (vs 256 for the NOP sled that still wasn't enough).
; =============================================================================
UCI_FENCE_OUTER = 5     ; outer loop iterations
UCI_FENCE_INNER = 100   ; inner loop iterations

.macro uci_fence
    pha                         ; save A
    txa
    pha                         ; save X
    ldx #UCI_FENCE_OUTER
:   lda #UCI_FENCE_INNER
:   sbc #1
    bne :-
    dex
    bne :--
    pla
    tax                         ; restore X
    pla                         ; restore A
.endmacro

; =============================================================================
; Command IDs (issued as the first command byte after selecting the target)
; Phase 2+ will use these; Phase 1b keeps them here purely as equates.
; =============================================================================
UCI_CMD_IDENTIFY        = $01
UCI_CMD_GET_IFACE_COUNT = $02
UCI_CMD_GET_NETADDR     = $04
UCI_CMD_GET_IPADDR      = $05
UCI_CMD_SET_IPADDR      = $06
UCI_CMD_TCP_CONNECT     = $07
UCI_CMD_UDP_CONNECT     = $08
UCI_CMD_SOCKET_CLOSE    = $09
UCI_CMD_SOCKET_READ     = $10
UCI_CMD_SOCKET_WRITE    = $11
UCI_CMD_LISTEN_START    = $12
UCI_CMD_LISTEN_ACCEPT   = $13
UCI_CMD_LISTEN_STOP     = $14
UCI_CMD_LISTEN_STATUS   = $15
