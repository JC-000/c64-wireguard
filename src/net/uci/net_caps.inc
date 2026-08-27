.ifndef NET_CAPS_INC
NET_CAPS_INC = 1
; =============================================================================
; net/uci/net_caps.inc - UCI backend datagram capabilities (assemble-time)
;
; Selected by the Makefile's `-I src/net/$(BACKEND)`; consumers just
; `.include "net_caps.inc"`. Header only — equates, no code, no data.
;
; These are ADAPTER GUARANTEES, not facts about one firmware (c64-lib-contract
; SPEC v0.12.0 §13.3, normative; intake c64-lib-contract#142): each value is
; the smallest ceiling across
; every firmware this build supports. Raise one only when the build drops
; support for every firmware below the new floor — never because a newer
; firmware happens to do better.
;
; Firmware baseline: U64E fw 3.15 and later (decided 2026-08-27).
;
; NET_UDP_SEND_MAX  Largest payload net_udp_send guarantees to emit as ONE
;                   datagram. 892: a connected UDP socket turns every
;                   SOCKET_WRITE into its own packet and the firmware queue
;                   takes 892 bytes per write, so anything larger leaves as
;                   two torn datagrams (measured 2026-08-27: 1452 -> 800 +
;                   652). Unchanged by 3.15. A firmware WRITE_SOCKET_MORE
;                   (chunked push, GideonZ/1541ultimate#802) would lift this to ~1440, and WG_MTU
;                   follows it — this is the binding side of the tunnel MTU.
; NET_UDP_RECV_MAX  Largest datagram net_poll guarantees to deliver whole.
;                   1472 assumes fw >= 3.15 (GideonZ/1541ultimate#806
;                   multi-block SOCKET_READ); on 3.14d the read cap is 893
;                   and a larger request hangs the device — 3.14d is no
;                   longer supported. 1472 = 1500 - 20 - 8 is the ceiling on
;                   what reaches the device at all (lwIP IP_REASSEMBLY = 0).
;                   Read-cap history: GideonZ/1541ultimate#802.
;
; WG_MTU = min(892, 1472) - 32 = 860, send-bound.
;
; The adapter's private constants (UCI_DATA_QUEUE_MAX, UCI_READ_CHUNK_MAX in
; uci_errors.inc) are what the adapter actually pushes/requests; net.s
; asserts these guarantees never exceed them. These are the public §13.3
; names a consumer is allowed to depend on; deriving from the adapter's
; own equates is the layering inversion §13.1 retired.
; =============================================================================
NET_UDP_SEND_MAX = 892
NET_UDP_RECV_MAX = 1472
.endif ; NET_CAPS_INC
