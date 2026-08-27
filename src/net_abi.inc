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
                            ; No-op under ip65; under UCI it hands the
                            ; firmware handle back. Abandoning a live one
                            ; poisons the U64E lease path until a wall
                            ; power cycle — issue #58. Safe when idle.

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

; KNOWN §13.1 NON-CONFORMANCE — net_local_ip / net_last_error.
; §13.1 puts both in NET_FAMILY_CORE and this header should declare them.
; It does not, because the UCI backend exports both and the ip65 backend
; exports NEITHER: ip65's driver reports only a carry, so there is no error
; channel to expose. Declaring them here would break the ip65 link the
; moment a consumer referenced them.
;
; This is the same gap c64-https closed as its P1 (their #70/#142) by giving
; ip65 a real error channel with codes from the §13.2 ip65 family range
; ($40-$7F). Ours wants the same treatment, and per the allocate-in-the-
; table-first rule added in c64-lib-contract#139 the codes get filed against
; §13.2 before they are used here.
;
; It is also why src/net/<backend>/net_manifest.s and net_abi_asserts.s are
; NOT in this branch yet: a NET_FAMILY_CORE claim asserted over an absent
; error channel would link green and mean nothing. Manifests come after the
; channel exists, not before. Tracked in #48.
