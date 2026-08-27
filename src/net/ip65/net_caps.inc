.ifndef NET_CAPS_INC
NET_CAPS_INC = 1
; =============================================================================
; net/ip65/net_caps.inc - ip65 backend datagram capabilities (assemble-time)
;
; Selected by the Makefile's `-I src/net/$(BACKEND)`; consumers just
; `.include "net_caps.inc"`. Header only — equates, no code, no data.
;
; ip65 + RR-Net moves whole Ethernet frames, so both directions are bound by
; the 1500-byte IP MTU: 1472 = 1500 - 20 (IPv4) - 8 (UDP). No fragmentation
; support either way. c64-lib-contract SPEC v0.12.0 §13.3 (published
; ceilings, normative); intake c64-lib-contract#142.
; =============================================================================
NET_UDP_SEND_MAX = 1472
NET_UDP_RECV_MAX = 1472
; Source-side backing for 1472: ip65 stages every inbound frame in
; `eth_inp: .res 1518` (ip65/eth_buffer.s:10, prelinked blob, ip65 25a9c5a);
; 1518 - 14 (Ethernet) - 20 (IPv4) - 8 (UDP) = 1476 >= 1472, so the driver
; can hold a full 1472-byte UDP payload before net_udp_recv_cb copies it.
.endif ; NET_CAPS_INC
