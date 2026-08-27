; net_families.inc — canonical per c64-lib-contract SPEC §13.0.
;
; CANONICAL SOURCE. The fenced block in SPEC.md §13.0 is shown for
; readability; this file is the byte-for-byte source backends and
; consumers copy into their own src/net/net_families.inc. Plain
; assemble-time equates, never .export'ed: both sides of the link carry
; the header, and only exported symbols can collide. Bits are append-only
; and never reused (§8.0 discipline). Updates land via coordinated
; cross-repo PR; do not edit your local copy.

.ifndef NET_FAMILIES_INC_INCLUDED
NET_FAMILIES_INC_INCLUDED = 1

NET_FAMILY_CORE = $0001         ; net_init, net_dhcp_acquire, net_poll,
                                ; net_local_ip, net_last_error
NET_FAMILY_TCP  = $0002         ; net_tcp_connect/send/close, net_tcp_state,
                                ; consumer-owned rx ring (§13.3)
NET_FAMILY_UDP  = $0004         ; net_udp_listen/send, UDP rx buffer
NET_FAMILY_DNS  = $0008         ; net_dns_resolve, net_resolved_ip

.endif
