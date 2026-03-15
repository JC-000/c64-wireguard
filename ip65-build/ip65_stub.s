; =============================================================================
; ip65_stub.s - ip65 UDP + RR-Net wrapper with fixed jump table at $2000
;
; Assembled with ca65, linked with ld65 against ip65.lib + ip65_c64.lib.
; Produces a raw binary at $2000 for inclusion in ACME via !binary.
;
; Jump table at $2000 with 3-byte JMP entries at fixed offsets.
; Variable table follows with addresses of ip65 state we expose.
; =============================================================================

.include "../ip65/inc/common.inc"

; --- Imports from ip65 ---
.import ip65_init
.import ip65_process
.import ip65_error

.import dhcp_init

.import dns_set_hostname
.import dns_resolve
.import dns_ip

.import udp_add_listener
.import udp_remove_listener
.import udp_send
.import udp_callback
.import udp_send_dest
.import udp_send_dest_port
.import udp_send_src_port
.import udp_send_len

.import cfg_mac
.import cfg_ip
.import cfg_netmask
.import cfg_gateway
.import cfg_dns

.importzp eth_init_default
.importzp ptr1

; keep ld65 happy — cc65 runtime segments
.segment "INIT"
.segment "ONCE"

; =============================================================================
; Jump table at $2000 — 3-byte JMP entries, called from ACME code
; =============================================================================
.segment "JUMPTAB"

; Function jump table (each 3 bytes = JMP xxxx)
jmp ip65_init               ; $2000 +0   A=0 for default; C=0 ok, C=1 err
jmp ip65_process            ; $2003 +3   poll packets; C=0 packet, C=1 idle
jmp dhcp_init               ; $2006 +6   DHCP; C=0 ok, C=1 err
jmp dns_resolve             ; $2009 +9   resolve; C=0 ok, C=1 err
jmp udp_add_listener        ; $200C +12  udp_callback set, AX=port; C=0 ok
jmp udp_remove_listener     ; $200F +15  AX=port; C=0 ok
jmp udp_send                ; $2012 +18  AX=data ptr; C=0 ok, C=1 err
jmp wrap_dns_set_hostname   ; $2015 +21  AX=hostname ptr
jmp wrap_set_udp_callback   ; $2018 +24  AX=callback addr
jmp wrap_set_udp_dest       ; $201B +27  set dest IP from AX ptr

; Variable address table follows immediately
; Each entry is a 2-byte address (lo/hi) — ACME reads from known offsets
.word cfg_mac               ; +30  -> 6 bytes MAC
.word cfg_ip                ; +32  -> 4 bytes IP
.word cfg_netmask           ; +34  -> 4 bytes netmask
.word cfg_gateway           ; +36  -> 4 bytes gateway
.word cfg_dns               ; +38  -> 4 bytes DNS server
.word dns_ip                ; +40  -> 4 bytes resolved IP
.word ip65_error            ; +42  -> 1 byte error code
.word udp_send_dest         ; +44  -> 4 bytes UDP dest IP
.word udp_send_dest_port    ; +46  -> 2 bytes UDP dest port
.word udp_send_src_port     ; +48  -> 2 bytes UDP src port
.word udp_send_len          ; +50  -> 2 bytes UDP send length

; =============================================================================
; Wrapper routines
; =============================================================================

.segment "STARTUP"
  rts     ; no standalone entry point

.code

; wrap_dns_set_hostname - set hostname for DNS resolution
; Input: AX = pointer to null-terminated hostname string
wrap_dns_set_hostname:
  jsr dns_set_hostname
  rts

; wrap_set_udp_callback - set UDP receive callback vector
; Input: AX = callback function address
wrap_set_udp_callback:
  stax udp_callback
  rts

; wrap_set_udp_dest - set UDP destination IP from 4-byte buffer
; Input: AX = pointer to 4-byte IP address
wrap_set_udp_dest:
  sta ptr1
  stx ptr1+1
  ldy #0
  lda (ptr1),y
  sta udp_send_dest
  iny
  lda (ptr1),y
  sta udp_send_dest+1
  iny
  lda (ptr1),y
  sta udp_send_dest+2
  iny
  lda (ptr1),y
  sta udp_send_dest+3
  rts
