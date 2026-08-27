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
.endif ; NET_CAPS_INC
