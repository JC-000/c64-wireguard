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

; --- Lifecycle ---
.import net_init            ; initialise ethernet + ip65; C=0 ok
.import net_dhcp            ; acquire IP via DHCP; C=0 ok
.import net_poll            ; process one packet from driver; C=0 packet

; --- UDP socket surface ---
.import net_udp_listen      ; bind local_port (A=lo,X=hi); register
                            ; net_udp_recv_cb as the inbound callback
.import net_udp_send        ; send UDP packet (net_send_ptr = buffer,
                            ; udp_send_len_local = 2-byte length);
                            ; uses wg_peer_ip/wg_peer_port as destination
.import net_udp_recv_cb     ; invoked BY ip65 when a packet arrives;
                            ; copies data into udp_recv_buf and sets
                            ; udp_recv_ready

; --- Helpers ---
.import net_print_ip        ; print 4-byte IP to screen (for banner)
.import net_save_zp         ; save crypto ZP $02-$1B into zp_save_buf
.import net_restore_zp      ; restore crypto ZP $02-$1B from zp_save_buf

; --- Caller-visible data ---
.import net_send_ptr        ; 2 bytes — set by caller before net_udp_send
.import udp_send_len_local  ; 2 bytes — set by caller before net_udp_send
