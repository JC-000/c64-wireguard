; =============================================================================
; ip_build.asm - IP/ICMP/UDP packet construction for WireGuard tunnel payloads
;
; Builds inner IP packets for encapsulation inside WireGuard Type 4 transport
; packets. Provides ICMP echo (ping) and UDP text messaging.
;
; All multi-byte fields in IP/ICMP/UDP headers are big-endian (network order).
; =============================================================================

; =============================================================================
; ip_checksum - RFC 1071 Internet checksum (16-bit one's complement sum)
;
; Input:  zp_ptr1 ($FB/$FC) = pointer to buffer
;         zp_tmp1 ($02)     = byte count (MUST be even)
; Output: ip_cksum_result (2 bytes, big-endian / network byte order)
; Clobbers: A, Y, zp_tmp2
; =============================================================================
ip_checksum:
        ; initialize 16-bit sum to 0
        lda #0
        sta zp_tmp2             ; sum high byte
        sta ip_cksum_result     ; sum low byte (reuse as accumulator)
        tay                     ; Y = 0 (buffer index)

@loop:
        cpy zp_tmp1
        beq @fold

        ; add big-endian 16-bit word: high byte first, low byte second
        ; sum_hi += data[y], sum_lo += data[y+1], propagate carry
        clc
        lda ip_cksum_result     ; sum low
        adc (zp_ptr1),y         ; + high byte of word (cross-stored for NBO)
        sta ip_cksum_result
        iny
        lda zp_tmp2             ; sum high
        adc (zp_ptr1),y         ; + low byte of word
        sta zp_tmp2
        iny

        bcc @loop               ; no carry overflow
        ; carry out: fold back into low byte
        inc ip_cksum_result
        bne @loop
        inc zp_tmp2             ; propagate if low wrapped
        bne @loop               ; (always branches; sum never reaches $ffff+carry twice)

@fold:
        ; one's complement: NOT the result
        lda ip_cksum_result
        eor #$ff
        sta ip_cksum_result     ; result high byte (network order)
        lda zp_tmp2
        eor #$ff
        sta ip_cksum_result+1   ; result low byte (network order)
        rts

; =============================================================================
; icmp_build_echo - Build a 28-byte IP/ICMP echo request packet
;
; Uses: tunnel_ip (src), ping_target_ip (dst), ping_seq (incremented)
; Output: ip_packet_buf filled (20B IPv4 + 8B ICMP), ip_pkt_len = 28
; Clobbers: A, X, Y, zp_ptr1, zp_tmp1
; =============================================================================
icmp_build_echo:
        ; --- copy IP header template (20 bytes) ---
        ldx #19
@copy_hdr:
        lda ip_hdr_template,x
        sta ip_packet_buf,x
        dex
        bpl @copy_hdr

        ; --- fill IP header fields ---
        ; total length = 28 (big-endian)
        lda #0
        sta ip_packet_buf+2
        lda #28
        sta ip_packet_buf+3

        ; protocol = ICMP (1)
        lda #IP_PROTO_ICMP
        sta ip_packet_buf+9

        ; clear header checksum for computation
        lda #0
        sta ip_packet_buf+10
        sta ip_packet_buf+11

        ; src IP = tunnel_ip
        ldx #3
@copy_src:
        lda tunnel_ip,x
        sta ip_packet_buf+12,x
        dex
        bpl @copy_src

        ; dst IP = ping_target_ip
        ldx #3
@copy_dst:
        lda ping_target_ip,x
        sta ip_packet_buf+16,x
        dex
        bpl @copy_dst

        ; --- build ICMP echo request (8 bytes at offset 20) ---
        lda #8                  ; type = echo request
        sta ip_packet_buf+20
        lda #0                  ; code = 0
        sta ip_packet_buf+21
        sta ip_packet_buf+22    ; checksum = 0 (for computation)
        sta ip_packet_buf+23

        ; ID = WG_ICMP_ID (big-endian: $C6, $40)
        lda #>WG_ICMP_ID
        sta ip_packet_buf+24
        lda #<WG_ICMP_ID
        sta ip_packet_buf+25

        ; sequence = ping_seq (big-endian)
        lda ping_seq
        sta ip_packet_buf+26
        lda ping_seq+1
        sta ip_packet_buf+27

        ; --- compute ICMP checksum over 8 bytes (offset 20-27) ---
        lda #<(ip_packet_buf+20)
        sta zp_ptr1
        lda #>(ip_packet_buf+20)
        sta zp_ptr1+1
        lda #8
        sta zp_tmp1
        jsr ip_checksum
        lda ip_cksum_result
        sta ip_packet_buf+22
        lda ip_cksum_result+1
        sta ip_packet_buf+23

        ; --- compute IP header checksum over 20 bytes ---
        lda #<ip_packet_buf
        sta zp_ptr1
        lda #>ip_packet_buf
        sta zp_ptr1+1
        lda #20
        sta zp_tmp1
        jsr ip_checksum
        lda ip_cksum_result
        sta ip_packet_buf+10
        lda ip_cksum_result+1
        sta ip_packet_buf+11

        ; --- set packet length ---
        lda #28
        sta ip_pkt_len

        ; --- increment ping_seq (big-endian) ---
        inc ping_seq+1
        bne @seq_done
        inc ping_seq
@seq_done:
        rts

; =============================================================================
; icmp_parse_reply - Check if decrypted IP payload is a valid ICMP echo reply
;
; Input:  tp_packet+16 = decrypted IP packet
; Output: A = 0 if valid echo reply, A = $FF if invalid
; Clobbers: A
; =============================================================================
icmp_parse_reply:
        ; check protocol (byte 9) == ICMP (1)
        lda tp_packet+16+9
        cmp #IP_PROTO_ICMP
        bne @invalid

        ; check ICMP type (byte 20) == 0 (echo reply)
        lda tp_packet+16+20
        bne @invalid

        ; check ICMP ID (bytes 24-25) == WG_ICMP_ID
        lda tp_packet+16+24
        cmp #>WG_ICMP_ID
        bne @invalid
        lda tp_packet+16+25
        cmp #<WG_ICMP_ID
        bne @invalid

        ; valid echo reply
        lda #0
        rts

@invalid:
        lda #$ff
        rts

; =============================================================================
; udp_tunnel_build - Build an IP/UDP packet for text messaging in the tunnel
;
; Input:  zp_ptr1 ($FB/$FC) = pointer to text data
;         zp_tmp1 ($02)     = text length
;         tunnel_ip (src), ping_target_ip (dst), msg_port (port)
; Output: ip_packet_buf filled (20B IPv4 + 8B UDP + payload), ip_pkt_len set
; Clobbers: A, X, Y, zp_ptr1, zp_ptr2, zp_tmp1, zp_tmp2
; =============================================================================
udp_tunnel_build:
        ; save text pointer and length before we clobber zp_ptr1/zp_tmp1
        lda zp_ptr1
        sta zp_ptr2
        lda zp_ptr1+1
        sta zp_ptr2+1
        lda zp_tmp1
        sta zp_tmp2             ; text length saved in zp_tmp2

        ; --- copy IP header template (20 bytes) ---
        ldx #19
@copy_hdr:
        lda ip_hdr_template,x
        sta ip_packet_buf,x
        dex
        bpl @copy_hdr

        ; --- fill IP header fields ---
        ; total length = 28 + text_len (big-endian)
        lda #0
        sta ip_packet_buf+2
        lda #28
        clc
        adc zp_tmp2
        sta ip_packet_buf+3     ; assumes total < 256

        ; protocol = UDP (17)
        lda #IP_PROTO_UDP
        sta ip_packet_buf+9

        ; clear header checksum
        lda #0
        sta ip_packet_buf+10
        sta ip_packet_buf+11

        ; src IP = tunnel_ip
        ldx #3
@copy_src:
        lda tunnel_ip,x
        sta ip_packet_buf+12,x
        dex
        bpl @copy_src

        ; dst IP = ping_target_ip
        ldx #3
@copy_dst:
        lda ping_target_ip,x
        sta ip_packet_buf+16,x
        dex
        bpl @copy_dst

        ; --- build UDP header (8 bytes at offset 20) ---
        ; src port = msg_port (big-endian)
        lda msg_port
        sta ip_packet_buf+20
        lda msg_port+1
        sta ip_packet_buf+21

        ; dst port = msg_port (big-endian)
        lda msg_port
        sta ip_packet_buf+22
        lda msg_port+1
        sta ip_packet_buf+23

        ; UDP length = 8 + text_len (big-endian)
        lda #0
        sta ip_packet_buf+24
        lda #8
        clc
        adc zp_tmp2
        sta ip_packet_buf+25

        ; UDP checksum = 0 (optional per RFC 768)
        lda #0
        sta ip_packet_buf+26
        sta ip_packet_buf+27

        ; --- copy text payload (from zp_ptr2, length in zp_tmp2) ---
        ldy #0
@copy_text:
        cpy zp_tmp2
        beq @text_done
        lda (zp_ptr2),y
        sta ip_packet_buf+28,y
        iny
        bne @copy_text          ; max 255 bytes
@text_done:

        ; --- compute IP header checksum over 20 bytes ---
        lda #<ip_packet_buf
        sta zp_ptr1
        lda #>ip_packet_buf
        sta zp_ptr1+1
        lda #20
        sta zp_tmp1
        jsr ip_checksum
        lda ip_cksum_result
        sta ip_packet_buf+10
        lda ip_cksum_result+1
        sta ip_packet_buf+11

        ; --- set packet length = 28 + text_len ---
        lda #28
        clc
        adc zp_tmp2
        sta ip_pkt_len

        rts

; =============================================================================
; udp_tunnel_parse - Parse a decrypted IP/UDP packet from the tunnel
;
; Input:  tp_packet+16 = decrypted IP packet
; Output: A = 0 success (msg_recv_ptr/msg_recv_len set), A = $FF fail
; Clobbers: A
; =============================================================================
udp_tunnel_parse:
        ; check protocol (byte 9) == UDP (17)
        lda tp_packet+16+9
        cmp #IP_PROTO_UDP
        bne @fail

        ; check dst port (bytes 22-23) == msg_port (big-endian)
        lda tp_packet+16+22
        cmp msg_port
        bne @fail
        lda tp_packet+16+23
        cmp msg_port+1
        bne @fail

        ; msg_recv_ptr = tp_packet + 16 + 28 (IP hdr + UDP hdr)
        lda #<(tp_packet+16+28)
        sta msg_recv_ptr
        lda #>(tp_packet+16+28)
        sta msg_recv_ptr+1

        ; msg_recv_len = UDP length (byte 25) - 8
        ; UDP length field is big-endian at offset 24-25; high byte assumed 0
        lda tp_packet+16+25
        sec
        sbc #8
        sta msg_recv_len

        lda #0
        rts

@fail:
        lda #$ff
        rts
