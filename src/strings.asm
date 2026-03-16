; =============================================================================
; strings.asm - UI strings
; =============================================================================

title_msg:
        !text "WIREGUARD NOISE PROTOCOL", 13
        !text "FOR COMMODORE 64", 13, 13
        !text "L=LOAD H=HS P=PING", 13
        !text "M=MSG S=SEND Q=QUIT", 13, 0

net_init_msg:
        !text "INITIALIZING NETWORK...", 13, 0
net_dhcp_msg:
        !text "REQUESTING DHCP...", 13, 0
net_ok_msg:
        !text "NETWORK READY. IP: ", 0
net_err_msg:
        !text "NETWORK INIT FAILED", 13, 0
dhcp_err_msg:
        !text "DHCP FAILED", 13, 0
net_listen_msg:
        !text "LISTENING ON PORT 51820", 13, 0
net_listen_err_msg:
        !text "UDP LISTEN FAILED", 13, 0

send_ok_msg:
        !text "PACKET SENT OK", 13, 0
send_err_msg:
        !text "SEND FAILED", 13, 0

; --- Test payload ---
test_payload:
        !text "HELLO WIREGUARD"
test_payload_len = * - test_payload

; --- Session status messages ---
hs_start_msg:
        !text "STARTING HANDSHAKE...", 13, 0
hs_ok_msg:
        !text "HANDSHAKE OK", 13, 0
hs_fail_msg:
        !text "HANDSHAKE FAILED", 13, 0
decrypt_fail_msg:
        !text "DECRYPT FAILED", 13, 0
recv_data_msg:
        !text "RECV: ", 0

; --- Phase 7 messages ---
ping_sent_msg:
        !text "PING SENT", 13, 0
ping_reply_msg:
        !text "PING REPLY OK", 13, 0
not_active_msg:
        !text "NOT ACTIVE", 13, 0
msg_prompt:
        !text "MSG> ", 0
msg_recv_hdr:
        !text "MSG: ", 0
cfg_loading_msg:
        !text "LOADING CONFIG...", 13, 0
cfg_ok_msg:
        !text "CONFIG OK", 13, 0
cfg_err_msg:
        !text "CONFIG ERROR", 13, 0
cookie_recv_msg:
        !text "COOKIE RECEIVED", 13, 0
rekey_msg:
        !text "REKEY NEEDED", 13, 0
session_expired_msg:
        !text "SESSION EXPIRED", 13, 0
keepalive_msg:
        !text "KEEPALIVE", 13, 0
