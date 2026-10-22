; IP65 ping over RR-Net, static IP configuration.
;
; test/ping.s brings the stack up with DHCP and pings the default
; gateway.  On a point-to-point link to a host NIC there is neither a
; DHCP server nor a gateway, so this variant does the same job with a
; static config and pings the host directly.
;
; Everything below the config is stock IP65: ip65_init brings up the
; cs8900a driver, and icmp_ping does ARP + echo request + reply match.
;
; The RR-Net bench-health control for tools/test_ip65_rrnet_hw.py: the
; 10.0.66 re-target the rig helper serves (C64 .200, host .1). Built by
; `make pingstatic` against this tree's ip65 (inc/ for common.inc,
; commonprint.inc, net.inc; ip65_tcp.lib + drivers/c64rrnet.lib). Tracked
; here since 2026-10-21 from the c64-test-harness lane's scratch copy, whose
; build of ip65 25a9c5a it reproduces byte for byte (sha256 daec793d...).

.include "common.inc"
.include "commonprint.inc"
.include "net.inc"

.export start

.import exit_to_basic
.import icmp_echo_ip
.import icmp_ping

; keep LD65 happy
.segment "INIT"
.segment "ONCE"

.segment "STARTUP"

  ; switch to lower case charset
  lda #14
  jsr print_a

start:
  jsr print_cr

  ; --- bring up the ethernet driver (no DHCP) ---
  ldax #initialising
  jsr print
  lda #eth_init_default
  jsr ip65_init
  bcc :+
  ldax #drv_failed
  jsr print
  jmp exit_to_basic
:
  ldax #drv_ok
  jsr print

  ; --- static IP configuration ---
  ldx #$03
: lda my_ip,x
  sta cfg_ip,x
  lda my_netmask,x
  sta cfg_netmask,x
  lda my_gateway,x
  sta cfg_gateway,x
  lda peer_ip,x
  sta icmp_echo_ip,x
  dex
  bpl :-

  jsr print_ip_config
  jsr print_cr

  ldax #pinging
  jsr print
  ldax #icmp_echo_ip
  jsr print_dotted_quad
  jsr print_cr

  jsr icmp_ping
  bcs @error
  jsr print_integer
  ldax #ms
  jsr print
  jmp exit_to_basic

@error:
  ldax #failed
  jsr print
  jsr print_errorcode
  jmp exit_to_basic


.rodata

initialising: .byte "INIT DRIVER: ",0
drv_ok:       .byte "OK",13,0
drv_failed:   .byte "FAILED",13,0
pinging:      .byte "PINGING ",0
ms:           .byte " MS",13,0
failed:       .byte "PING FAILED: ",0

; the C64, which the rig's dnsmasq also pins by MAC
my_ip:        .byte 10,0,66,200
; /24, so the host is on-link and gets ARPed for directly
my_netmask:   .byte 255,255,255,0
my_gateway:   .byte 10,0,66,1
; the host NIC (the helper's HOST_IP)
peer_ip:      .byte 10,0,66,1
