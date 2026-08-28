; =============================================================================
; config.s - Peer configuration loader (ca65)
;
; Copies configuration data from cfg_* buffers into handshake state.
; Test harness or user writes actual values to cfg_* before calling.
; =============================================================================

.include "constants.inc"

.export config_load

.import cfg_static_priv
.import cfg_static_pub
.import cfg_peer_pub
.import cfg_peer_endpoint_ip
.import cfg_peer_endpoint_port
.import cfg_preshared_key
.import hs_static_priv
.import hs_static_pub
.import hs_resp_pub
.import hs_preshared_key
.import wg_peer_ip
.import wg_peer_port
.import tai64n_init
.import net_udp_close

; config_load copies the peer endpoint as ONE 6-byte run over IP(4)+port(2),
; on both the cfg side and the live side. That is only correct while each
; pair stays contiguous and in this order — inserting a variable between them
; would silently write the wrong bytes into the peer address, a wrong-peer bug
; with no crash and no test that would obviously catch it. Fail the link
; instead. (session.s carries the same guard for session_stage_dest.)
.assert wg_peer_port = wg_peer_ip + 4, lderror, "wg_peer_port must directly follow wg_peer_ip — config_load copies both in one 6-byte loop"
.assert cfg_peer_endpoint_port = cfg_peer_endpoint_ip + 4, lderror, "cfg_peer_endpoint_port must directly follow cfg_peer_endpoint_ip — config_load copies both in one 6-byte loop"

.segment "APP_CODE"

; =============================================================================
; config_load - Load peer configuration into handshake state
;
; Input: cfg_static_priv, cfg_static_pub, cfg_peer_pub,
;        cfg_peer_endpoint_ip, cfg_peer_endpoint_port
; Output: hs_static_priv, hs_static_pub, hs_resp_pub,
;         wg_peer_ip, wg_peer_port set. If the peer endpoint changed, the
;         backend's UDP socket is closed so the next send reconnects to it
;         (issue #65); an unchanged endpoint leaves the socket alone.
; Clobbers: A, X, Y (net_udp_close uses all three)
; =============================================================================
config_load:
        ; Copy static private key (32 bytes)
        ldx #31
@priv:
        lda cfg_static_priv,x
        sta hs_static_priv,x
        dex
        bpl @priv

        ; Copy static public key (32 bytes)
        ldx #31
@pub:
        lda cfg_static_pub,x
        sta hs_static_pub,x
        dex
        bpl @pub

        ; Copy peer public key (32 bytes)
        ldx #31
@peer:
        lda cfg_peer_pub,x
        sta hs_resp_pub,x
        dex
        bpl @peer

        ; --- Peer endpoint: IP(4) + port(2), copied as one 6-byte run ---
        ;
        ; Each byte is compared against the live value before it overwrites
        ; it, so the loop also answers "did the endpoint MOVE?" — Y carries
        ; that out (X is the index, A holds the byte across the cmp/sta pair).
        ; The single run is what keeps this cheap: MAIN_AREA_LO has 176 bytes
        ; of slack and an align=$100 segment behind it, so a separate compare
        ; pass would cross a page boundary and cost a full 256.
        ldy #0                          ; 0 = endpoint unchanged so far
        ldx #5
@endpoint:
        lda cfg_peer_endpoint_ip,x
        cmp wg_peer_ip,x
        beq @endpoint_byte_same
        ldy #1
@endpoint_byte_same:
        sta wg_peer_ip,x
        dex
        bpl @endpoint

        ; The endpoint just moved under a possibly-live socket. Under UCI the
        ; socket is CONNECTION-ORIENTED: UDP_CONNECT pins it to one peer
        ; address, read from wg_peer_ip/wg_peer_port at connect time, and
        ; net_udp_send short-circuits on uci_socket_open without ever
        ; revisiting that. So a socket opened for the previous peer keeps
        ; sending to the previous peer, and nothing reports it — loading a new
        ; config looks like it took effect (issue #65).
        ;
        ; Handing the socket back here is the whole fix: net_udp_close clears
        ; uci_socket_open, so the next net_udp_send re-issues UDP_CONNECT
        ; against the address we just stored. It is safe when nothing is open
        ; (returns having done nothing) and the ip65 backend's is a no-op —
        ; ip65's UDP is connectionless and reads the destination per send, so
        ; that backend never had the bug.
        ;
        ; ONLY when it moved. config_load runs at the top of every
        ; session_initiate, rekey included, and rekey re-handshakes with the
        ; same config: closing unconditionally would churn a firmware socket
        ; slot that the rekey is about to reuse, from an 8-deep pool the
        ; firmware does not reclaim (GideonZ/1541ultimate#808).
        cpy #0
        beq @endpoint_kept
        jsr net_udp_close
@endpoint_kept:

        ; Copy preshared key (32 bytes)
        ldx #31
@psk:
        lda cfg_preshared_key,x
        sta hs_preshared_key,x
        dex
        bpl @psk

        ; Initialize TAI64N epoch anchor from base time
        jsr tai64n_init

        rts
