; src/net/ip65/ip65_symbols.inc — ca65 equates for ip65 symbols used by WG.
;
; The ip65 blob (ip65-build/ip65-c64.bin) is pre-linked at $2000 and
; exposes a fixed jump table + variable-pointer table. Symbols here are
; derived from the WG-specific ip65 stub (ip65-build/ip65_stub.s), which
; is UDP-oriented (WireGuard does not use TCP).
;
; Only symbols actually referenced by src/net/ip65/net.s should be
; defined here. Matching ABI in c64-https/src/net/ip65/ip65_symbols.inc,
; but with UDP entry points instead of TCP.
;
; Source of truth: /home/someone/c64-wireguard/src/constants.asm
; (migrated during Phase 1; constants.asm will keep these until Phase 4
; when the ACME build is retired).

; --- ip65 ZP overlap zone (26 bytes: $02-$1B) ---
ip65_zp_start   = $02
ip65_zp_end     = $1b
ip65_zp_size    = ip65_zp_end - ip65_zp_start + 1

; --- ip65 jump table at $2000 (fixed offsets from ip65_stub.s) ---
ip65_base           = $2000
ip65_init           = ip65_base + 0     ; A=0 default; C=0 ok
ip65_process        = ip65_base + 3     ; poll; C=0 packet, C=1 idle
ip65_dhcp_init      = ip65_base + 6     ; DHCP; C=0 ok
ip65_dns_resolve    = ip65_base + 9     ; resolve; C=0 ok
ip65_udp_add        = ip65_base + 12    ; udp_callback set, AX=port; C=0 ok
ip65_udp_remove     = ip65_base + 15    ; AX=port; C=0 ok
ip65_udp_send       = ip65_base + 18    ; AX=data ptr; C=0 ok
ip65_dns_set_host   = ip65_base + 21    ; AX=hostname ptr
ip65_set_udp_cb     = ip65_base + 24    ; AX=callback addr
ip65_set_udp_dest   = ip65_base + 27    ; AX=4-byte IP ptr

; --- ip65 variable-pointer table at ip65_base+30 ---
; Each entry holds a 2-byte address pointing at the real ip65 variable.
ip65_vt             = ip65_base + 30
ip65_vt_cfg_mac     = ip65_vt + 0       ; -> 6 bytes MAC
ip65_vt_cfg_ip      = ip65_vt + 2       ; -> 4 bytes our IP
ip65_vt_cfg_netmask = ip65_vt + 4       ; -> 4 bytes netmask
ip65_vt_cfg_gateway = ip65_vt + 6       ; -> 4 bytes gateway
ip65_vt_cfg_dns     = ip65_vt + 8       ; -> 4 bytes DNS server
ip65_vt_dns_ip      = ip65_vt + 10      ; -> 4 bytes resolved IP
ip65_vt_ip65_error  = ip65_vt + 12      ; -> 1 byte error code
ip65_vt_udp_dest    = ip65_vt + 14      ; -> 4 bytes UDP dest IP
ip65_vt_udp_dport   = ip65_vt + 16      ; -> 2 bytes UDP dest port
ip65_vt_udp_sport   = ip65_vt + 18      ; -> 2 bytes UDP src port
ip65_vt_udp_snd_len = ip65_vt + 20      ; -> 2 bytes UDP send length

; --- Direct variable addresses (from ip65-build/ip65-c64.map) ---
ip65_cfg_ip         = $3252             ; 4 bytes: our IP address
ip65_cfg_mac        = $324c             ; 6 bytes: our MAC address
ip65_udp_snd_dest   = $aef5             ; 4 bytes: udp_send_dest
ip65_udp_snd_dport  = $aefb             ; 2 bytes: udp_send_dest_port
ip65_udp_snd_sport  = $aef9             ; 2 bytes: udp_send_src_port
ip65_udp_snd_len    = $aefd             ; 2 bytes: udp_send_len
ip65_error_addr     = $ace8             ; 1 byte: last error code
ip65_udp_inp        = $a12b             ; udp_inp (inbound UDP packet base)
ip65_udp_data_off   = 8                 ; offset of data within UDP packet
