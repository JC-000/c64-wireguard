; =============================================================================
; wg/strings.s - UI strings
;
; ca65 port of src/strings.asm. No logic changes; syntax translation only.
; =============================================================================

; --- Exported string labels ---
.export title_msg
.export net_init_msg
.export net_dhcp_msg
.export net_ok_msg
.export net_err_msg
.export dhcp_err_msg
.export net_listen_msg
.export net_listen_err_msg
.export send_ok_msg
.export send_err_msg
.export test_payload
.export test_payload_len
.export hs_start_msg
.export hs_ok_msg
.export hs_fail_msg
.export decrypt_fail_msg
.export recv_data_msg
.export ping_sent_msg
.export ping_reply_msg
.export not_active_msg
.export msg_prompt
.export msg_recv_hdr
.export cfg_loading_msg
.export cfg_ok_msg
.export cfg_err_msg
.export cookie_recv_msg
.export rekey_msg
.export session_expired_msg
.export keepalive_msg

.segment "APP_DATA"

title_msg:
        .byte "WIREGUARD NOISE PROTOCOL", 13
        .byte "FOR COMMODORE 64", 13, 13
        .byte "L=LOAD H=HS P=PING", 13
        .byte "M=MSG S=SEND Q=QUIT", 13, 0

net_init_msg:
        .byte "INITIALIZING NETWORK...", 13, 0
net_dhcp_msg:
        .byte "REQUESTING DHCP...", 13, 0
net_ok_msg:
        .byte "NETWORK READY. IP: ", 0
net_err_msg:
        .byte "NETWORK INIT FAILED", 13, 0
dhcp_err_msg:
        .byte "DHCP FAILED", 13, 0
net_listen_msg:
        .byte "LISTENING ON PORT 51820", 13, 0
net_listen_err_msg:
        .byte "UDP LISTEN FAILED", 13, 0

send_ok_msg:
        .byte "PACKET SENT OK", 13, 0
send_err_msg:
        .byte "SEND FAILED", 13, 0

; --- Test payload ---
test_payload:
        .byte "HELLO WIREGUARD"
test_payload_len = * - test_payload

; --- Session status messages ---
hs_start_msg:
        .byte "STARTING HANDSHAKE...", 13, 0
hs_ok_msg:
        .byte "HANDSHAKE OK", 13, 0
hs_fail_msg:
        .byte "HANDSHAKE FAILED", 13, 0
decrypt_fail_msg:
        .byte "DECRYPT FAILED", 13, 0
recv_data_msg:
        .byte "RECV: ", 0

; --- Phase 7 messages ---
ping_sent_msg:
        .byte "PING SENT", 13, 0
ping_reply_msg:
        .byte "PING REPLY OK", 13, 0
not_active_msg:
        .byte "NOT ACTIVE", 13, 0
msg_prompt:
        .byte "MSG> ", 0
msg_recv_hdr:
        .byte "MSG: ", 0
cfg_loading_msg:
        .byte "LOADING CONFIG...", 13, 0
cfg_ok_msg:
        .byte "CONFIG OK", 13, 0
cfg_err_msg:
        .byte "CONFIG ERROR", 13, 0
cookie_recv_msg:
        .byte "COOKIE RECEIVED", 13, 0
rekey_msg:
        .byte "REKEY NEEDED", 13, 0
session_expired_msg:
        .byte "SESSION EXPIRED", 13, 0
keepalive_msg:
        .byte "KEEPALIVE", 13, 0
