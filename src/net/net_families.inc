; net_families.inc — from c64-lib-contract SPEC §13.0, which was retired at
; contract v1.0.0 (text at `git show v0.17.1:SPEC.md`). This copy is ours
; now, and nothing in this repo includes it. c64-https keeps the same bits in
; its src/net/net_families.inc and nothing checks that they agree: a new bit
; is a cross-repo agreement with that lane.
;
; Plain assemble-time equates, never .export'ed (only exported symbols can
; collide). Bits are append-only and never reused (§8.0 discipline).

.ifndef NET_FAMILIES_INC_INCLUDED
NET_FAMILIES_INC_INCLUDED = 1

NET_FAMILY_CORE = $0001         ; net_init, net_dhcp_acquire, net_poll,
                                ; net_local_ip, net_last_error
NET_FAMILY_TCP  = $0002         ; net_tcp_connect/send/close, net_tcp_state,
                                ; consumer-owned rx ring (§13.3)
NET_FAMILY_UDP  = $0004         ; net_udp_listen/send, UDP rx buffer
NET_FAMILY_DNS  = $0008         ; net_dns_resolve, net_resolved_ip

.endif
