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

.segment "APP_CODE"

; =============================================================================
; config_load - Load peer configuration into handshake state
;
; Input: cfg_static_priv, cfg_static_pub, cfg_peer_pub,
;        cfg_peer_endpoint_ip, cfg_peer_endpoint_port
; Output: hs_static_priv, hs_static_pub, hs_resp_pub,
;         wg_peer_ip, wg_peer_port set
; Clobbers: A, X
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

        ; Copy peer endpoint IP (4 bytes)
        ldx #3
@ip:
        lda cfg_peer_endpoint_ip,x
        sta wg_peer_ip,x
        dex
        bpl @ip

        ; Copy peer endpoint port (2 bytes)
        lda cfg_peer_endpoint_port
        sta wg_peer_port
        lda cfg_peer_endpoint_port+1
        sta wg_peer_port+1

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
