; =============================================================================
; src/net_abi.inc — public UDP networking ABI for WireGuard.
;
; Drop-in contract: any backend (ip65/RR-Net today, U64E UCI next) must
; export these exact symbols. Swapping backend = link-time choice via
; different ld65 cfg + different src/net/<backend>/*.o files. No changes
; to handshake/transport/session sources.
;
; This mirrors the pattern of c64-https/src/net_abi.inc but is UDP-only
; (WireGuard does not use TCP). When we later import the c64-https
; networking stack, UCI-backed UDP sockets will plug in through these
; same symbols — proven on Ultimate 64 at 48 MHz and 1 MHz and on VICE
; at normal speed.
;
; Consumers (.include "net_abi.inc") then reference the symbols as
; `.import`ed names. Phase 5 added this contract; higher-level modules
; already use `net_udp_send` after Phase 4's migration, so the surface
; is already live.
; =============================================================================

; --- Lifecycle (§13.1 CORE) ---
.import net_init            ; initialise the backend. C=0 ok, C=1 sets
                            ; net_last_error.
.import net_dhcp_acquire    ; acquire an address via DHCP; populates
                            ; net_local_ip. C=0 ok.
.import net_poll            ; pump ONE unit of work. C=1 ONLY on a backend
                            ; error (§13.2) — C=0 carries NO "data arrived"
                            ; meaning. Inbound availability is observed via
                            ; udp_recv_ready, never via the carry.

; --- UDP socket surface (§13.1 NET_FAMILY_UDP) ---
.import net_udp_listen      ; bind local port (A=lo, X=hi)
.import net_udp_send        ; send one datagram. Caller stages all four
                            ; operands below first.
.import net_udp_close       ; release the backend's UDP socket, if any.
                            ; Under UCI it hands the firmware handle back —
                            ; abandoning a live one poisons the U64E lease
                            ; path until a wall power cycle (issue #58).
                            ; Under ip65 it releases the entry claimed in
                            ; the blob's 4-entry listener table; it was a
                            ; bare `clc / rts` until issue #84, so that
                            ; backend leaked a slot per listen and reported
                            ; success. Safe when idle. Both backends
                            ; re-acquire lazily on the next net_udp_send, so
                            ; a consumer may close on any abandonment path
                            ; without re-running net_init.

; --- Caller-set send operands (§13.1) ---
.import net_udp_send_ptr    ; 2 B — buffer address
.import net_udp_send_len    ; 2 B — length
.import net_udp_dest_ip     ; 4 B — destination address
.import net_udp_dest_port   ; 2 B — destination port, big-endian
                            ; The backend reads THESE. It must never reach
                            ; into wg_peer_* — that is the §13.1 layering
                            ; inversion this surface exists to prevent.
                            ; session_stage_dest copies peer -> dest.

; DELIBERATELY NOT IN THIS CONTRACT (c64-lib-contract SPEC §13.1):
;   net_udp_recv_cb    — adapter-internal; ip65 takes its address for
;                        ip65_set_udp_cb, the UCI backend has no callback.
;   net_print_ip       — a consumer convenience, not a backend operation.
;   net_save_zp /      — §13.5: ZP save/restore around driver calls is
;   net_restore_zp       adapter-internal and a backend MUST NOT export it.
; A consumer that genuinely needs one of the first two imports it directly
; (see src/boot.s) rather than through the shared ABI surface, so the
; dependency is visible at the call site instead of implied by this header.

; NOT DECLARED HERE — net_local_ip and net_last_error.
; Both belong to the lifecycle surface above and neither is declared.
;
; net_last_error: BOTH backends now export it. The ip65 side got its own
; error channel in issue #120 (src/net/ip65/net.s) — the same gap c64-https
; closed as its P1 (their #70/#142). It is still not declared here only
; because net_local_ip is not, and a half-declared surface is worse than an
; honest omission.
;
; net_local_ip: the UCI backend exports it, ip65 does not — ip65's address
; lives in the blob at ip65_cfg_ip and is read through ip65_symbols.inc, not
; through a WG-owned label. Declaring it here would break the ip65 link the
; moment a consumer referenced it. That is the one remaining blocker.

; =============================================================================
; RULE — a transient send failure is not a send failure.
;
; A backend's net_udp_send either puts the datagram on the wire or reports a
; REAL failure. A next hop that is merely UNRESOLVED is not a real failure:
; a backend whose driver reports one MUST resolve and retry within a bounded
; wall-clock budget before giving up, and only then report.
;
; This is written here because there is nowhere upstream to write it. The
; retired c64-lib-contract §13 had no category for it — its error model
; offered terminal (C=1) and advisory (C=0) and nothing in between, and
; net_udp_send's whole normative definition was a single table row; a search
; of that repository for `arp`, `link-layer`, `non-block`, `retry` or
; `transient` returns no normative hit. The silence let both of our backends
; be conformant while disagreeing about something that decides whether the
; product works: the UCI adapter blocks until the firmware has taken the
; datagram, while ip65 returned failure the instant ARP was cold. Because
; the off-subnet case resolves on the second attempt, the ip65 backend could
; never complete a first handshake with a real peer, and that went unnoticed
; for the life of the backend — every Ethernet test used an on-subnet peer
; with a pre-warmed cache. Incident: c64-wireguard#120; fix in
; src/net/ip65/net.s:net_arp_pump.
;
; =============================================================================
; net_last_error REGISTRY — canonical for this repository.
;
; Both backends write one byte, and this is the only place the whole set is
; written down. $00 is always "no error". A code is added HERE first, then in
; the emitting adapter (src/net/uci/uci_errors.inc, src/net/ip65/net.s), each
; of which points back at this table.
;
; ONE RULE, and it is the only one that ever mattered: A PUBLISHED VALUE IS
; NEVER REASSIGNED. Not renumbered to close a gap, not reused because a code
; turned out unreachable, not "tidied" when a range looks sparse. The reason
; is on the record: c64-wireguard once allocated $88 for UCI_ERR_LONG_READ
; while c64-https had long emitted $88 as UCI_ERR_NO_SOCKET, and one byte
; meant two things for four days with neither side doing anything wrong.
; Gaps below ($43-$45, $47) are deliberate and stay.
;
; That rule is not folklore here: THIS BRANCH broke it and was caught. The
; first commit of #120 minted $40-$44 for the ip65 channel by picking
; free-looking bytes out of the family range, and $41-$45 were already
; c64-https's — a live collision, in review, three weeks after the $88
; incident that motivated the table. It was remapped to the values below
; before merge. Any later reading that says "the codes were not remapped,
; nothing collided" is describing the post-remap history only.
;
; PROVENANCE. Most values were allocated against c64-lib-contract SPEC §13.2,
; a cross-repo registry RETIRED wholesale at contract v1.0.0 — a network
; backend is source in its consumer's own tree, compiled into that consumer's
; binary, never an artifact one party builds and another links, so the shared
; registry had no mechanism behind it. No value CHANGED at that release; the
; retired text is permanent at `git show v0.17.1:SPEC.md`. So the numbers
; below are exactly the published ones and still read correctly to anyone who
; remembers the table. Only ownership moved: this file is now the registry.
;
;   Code  Name                        Origin
;   ----  --------------------------  --------------------------------------
;   $01   NET_ERR_TIMEBASE_STOPPED    retired table, contract-generic
;   $41   NET_ERR_IP65_INIT           retired table, c64-https; we emit too
;   $42   NET_ERR_IP65_DHCP           retired table, c64-https; we emit too
;   $43   NET_ERR_IP65_DNS            retired table, c64-https — WE DO NOT EMIT
;   $44   NET_ERR_IP65_CONNECT        retired table, c64-https — WE DO NOT EMIT
;   $45   NET_ERR_IP65_SEND           retired table, c64-https — WE DO NOT EMIT
;   $46   NET_ERR_IP65_UDP_LISTEN     retired table, ours
;   $47   NET_ERR_IP65_UDP_SEND       retired table, ours — RESERVED, never
;                                     emitted; net.s defines and exports the
;                                     equate plus asserts so the value cannot
;                                     be quietly reused (see #120)
;   $48   NET_ERR_IP65_WAIT_TIMEOUT   OURS, minted here (issue #120)
;   $49   NET_ERR_IP65_UDP_UNBIND     OURS, minted here (issue #120)
;   $81   UCI_ERR_NOT_PRESENT         retired table, c64-https (grandfathered)
;   $82   UCI_ERR_CMD_FAILED          retired table, c64-https (grandfathered)
;   $83   UCI_ERR_NO_IP               retired table, c64-https (grandfathered)
;   $84   UCI_ERR_CONNECT_FAIL        retired table, c64-https (grandfathered)
;   $85   UCI_ERR_SEND_FAIL           retired table, c64-https (grandfathered)
;   $86   UCI_ERR_READ_FAIL           retired table, c64-https (grandfathered)
;   $87   UCI_ERR_SHORT_WRITE         retired table, c64-https (grandfathered)
;   $88   UCI_ERR_NO_SOCKET           retired table, c64-https (grandfathered)
;   $89   UCI_ERR_WAIT_TIMEOUT        retired table, c64-https (grandfathered)
;   $8A   UCI_ERR_LONG_READ           retired table, ours (moved off $88)
;   $8B   UCI_ERR_BAD_READ_HDR        retired table, c64-https — WE DO NOT EMIT
;   $8C   UCI_ERR_SEND_TOO_LONG       retired table, ours
;   $8D   UCI_ERR_OPEN_REFUSED        retired table, ours
;   $8E   UCI_ERR_CMD_UNKNOWN         OURS, minted here (PR #112)
;   $8F   UCI_ERR_SHORT_READ          OURS, minted here (issue #130)
;
; This table is names, values and ownership only. The per-code reasoning —
; what triggers each one, what a consumer should do about it — stays in
; uci_errors.inc and src/net/ip65/net.s, which point back here.
; =============================================================================
;
; It is also why src/net/<backend>/net_manifest.s and net_abi_asserts.s are
; NOT in this branch yet: a NET_FAMILY_CORE claim asserted over an absent
; error channel would link green and mean nothing. Manifests come after the
; channel exists, not before. Tracked in #48.
