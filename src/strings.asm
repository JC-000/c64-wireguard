; =============================================================================
; strings.asm - UI strings
; =============================================================================

title_msg:
        !text "WIREGUARD NOISE PROTOCOL", 13
        !text "FOR COMMODORE 64", 13, 13
        !text "I=INIT NETWORK  Q=QUIT", 13, 0

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
