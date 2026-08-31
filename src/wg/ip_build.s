; =============================================================================
; ip_build.s - IP/ICMP/UDP packet construction (ca65 port of src/ip_build.asm)
;
; Builds inner IP packets for encapsulation inside WireGuard Type 4 transport
; packets. Provides ICMP echo (ping) and UDP text messaging.
;
; All multi-byte fields in IP/ICMP/UDP headers are big-endian (network order).
; =============================================================================

        .include "constants.inc"

        .export ip_checksum
        .export icmp_build_echo
        .export icmp_parse_reply
        .export udp_tunnel_build
        .export udp_tunnel_parse

        .import ip_packet_buf
        .import ip_hdr_template
        .import ip_cksum_result
        .import ip_pkt_len
        .import tunnel_ip
        .import ping_target_ip
        .import ping_seq
        .import msg_port
        .import msg_recv_ptr
        .import msg_recv_len
        .import tp_packet
        .import tp_payload_len

        .segment "APP_CODE"

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
;         zp_tmp1 ($02)     = text length, low byte
;         zp_tmp2 ($03)     = text length, high byte
;         tunnel_ip (src), ping_target_ip (dst), msg_port (port)
; Output: ip_packet_buf filled (20B IPv4 + 8B UDP + payload), ip_pkt_len set
;         (16-bit). A length above MSG_TEXT_MAX is clamped to it: the packet
;         must fit one Type-4 payload and ip_packet_buf is exactly WG_MTU.
; Clobbers: A, X, Y, zp_ptr1, zp_ptr2, zp_tmp1, zp_tmp2
;
; Every length here is 16-bit (contract §13.3): the IP total-length and UDP
; length header fields, the payload copy, and ip_pkt_len.
; =============================================================================
udp_tunnel_build:
        ; --- clamp text length to MSG_TEXT_MAX (16-bit compare) ---
        lda zp_tmp2
        cmp #>MSG_TEXT_MAX
        bcc @len_ok
        bne @clamp
        lda zp_tmp1
        cmp #<MSG_TEXT_MAX
        bcc @len_ok
        beq @len_ok
@clamp:
        lda #<MSG_TEXT_MAX
        sta zp_tmp1
        lda #>MSG_TEXT_MAX
        sta zp_tmp2
@len_ok:

        ; --- copy IP header template (20 bytes) ---
        ldx #IP_HDR_LEN-1
@copy_hdr:
        lda ip_hdr_template,x
        sta ip_packet_buf,x
        dex
        bpl @copy_hdr

        ; --- fill IP header fields ---
        ; total length = 28 + text_len (big-endian, 16-bit)
        lda zp_tmp1
        clc
        adc #IP_UDP_HDR_LEN
        sta ip_packet_buf+3
        lda zp_tmp2
        adc #0
        sta ip_packet_buf+2

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

        ; UDP length = 8 + text_len (big-endian, 16-bit)
        lda zp_tmp1
        clc
        adc #UDP_HDR_LEN
        sta ip_packet_buf+25
        lda zp_tmp2
        adc #0
        sta ip_packet_buf+24

        ; UDP checksum = 0 (optional per RFC 768)
        lda #0
        sta ip_packet_buf+26
        sta ip_packet_buf+27

        ; --- copy text payload (16-bit: full pages, then remainder) ---
        lda #<(ip_packet_buf+IP_UDP_HDR_LEN)
        sta zp_ptr2
        lda #>(ip_packet_buf+IP_UDP_HDR_LEN)
        sta zp_ptr2+1
        ldy #0
        ldx zp_tmp2             ; full pages
        beq @copy_rem
@copy_pg:
        lda (zp_ptr1),y
        sta (zp_ptr2),y
        iny
        bne @copy_pg
        inc zp_ptr1+1
        inc zp_ptr2+1
        dex
        bne @copy_pg
@copy_rem:
        ldx zp_tmp1             ; remaining bytes
        beq @text_done
        ldy #0
@copy_lo:
        lda (zp_ptr1),y
        sta (zp_ptr2),y
        iny
        dex
        bne @copy_lo
@text_done:

        ; --- set packet length = 28 + text_len (16-bit) ---
        ;
        ; BEFORE the checksum, not after: ip_checksum documents "Clobbers:
        ; A, Y, zp_tmp2" and uses zp_tmp2 as its own sum-high accumulator,
        ; while the text length lives there. Computing this afterwards read
        ; checksum residue instead of a length.
        ;
        ; It hid because the IP header's own total-length field is written
        ; earlier (from the same zp_tmp2, while still live), so the packet
        ; was internally consistent and parsed fine — only the count of
        ; bytes handed to transport_send was wrong. Measured on hardware: a
        ; 13-character message set ip_pkt_len = 103 instead of 41, so 62
        ; bytes of whatever the previous packet left in ip_packet_buf were
        ; encrypted and transmitted after the text. That is stale memory
        ; going out over the wire, not merely a display artefact.
        lda zp_tmp1
        clc
        adc #IP_UDP_HDR_LEN
        sta ip_pkt_len
        lda zp_tmp2
        adc #0
        sta ip_pkt_len+1

        ; --- compute IP header checksum over 20 bytes ---
        lda #<ip_packet_buf
        sta zp_ptr1
        lda #>ip_packet_buf
        sta zp_ptr1+1
        lda #IP_HDR_LEN
        sta zp_tmp1
        jsr ip_checksum
        lda ip_cksum_result
        sta ip_packet_buf+10
        lda ip_cksum_result+1
        sta ip_packet_buf+11

        rts

; In APP_EXTRA (MAIN_AREA_HI): MAIN_AREA_LO has no headroom left for the
; 16-bit length checks added here. See the note above print_buf16 in
; session.s.
        .segment "APP_EXTRA"

; =============================================================================
; udp_tunnel_parse - Parse a decrypted IP/UDP packet from the tunnel
;
; Input:  tp_packet+16     = decrypted IP packet
;         tp_payload_len   = how many bytes were actually decrypted into it
; Output: A = 0 success (msg_recv_ptr/msg_recv_len set, 16-bit), A = $FF fail
; Clobbers: A, X
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

        ; msg_recv_len = UDP length (bytes 24-25, big-endian) - 8, 16-bit.
        ; A UDP length below 8 is malformed (borrow out of the high byte).
        lda tp_packet+16+25
        sec
        sbc #UDP_HDR_LEN
        sta msg_recv_len
        lda tp_packet+16+24
        sbc #0
        sta msg_recv_len+1
        bcc @fail

        ; Two bounds, and they prove different things. Both are needed.
        ;
        ; (1) MSG_TEXT_MAX keeps the display inside tp_packet: the highest
        ;     byte reachable is 44 + MSG_TEXT_MAX - 1 = 875, and
        ;     MSG_TEXT_MAX < sizeof tp_packet - 44 holds by the same
        ;     derivation that caps WG_MTU. This says nothing about whether
        ;     the bytes were ever received.
        lda msg_recv_len+1
        cmp #>MSG_TEXT_MAX
        bcc @len_ok
        bne @fail
        lda msg_recv_len
        cmp #<MSG_TEXT_MAX
        bcc @len_ok
        bne @fail
@len_ok:

        ; (2) tp_payload_len bounds it to what this packet actually
        ;     decrypted, which is the property that matters (issue #97).
        ;     The length field is peer-supplied and nothing clears tp_packet
        ;     between datagrams: session.s copies only udp_recv_len bytes in.
        ;     Without this bound the display runs from tp_packet+44 through
        ;     the PREVIOUS INBOUND packet's decrypted plaintext -- the whole
        ;     832-byte window in the worst case, and that case needs no
        ;     forged length at all. An empty keepalive (payload 0) overwrites
        ;     only tp_packet[0..31], leaving the destination port at +38..39
        ;     and the length at +40..41 holding the last message's inner UDP
        ;     header: dst port is msg_port by construction and the length is
        ;     that message's own, so the whole of it is reprinted. A forged
        ;     length in a 26-byte payload -- the shortest that still carries
        ;     the field it forges -- reaches 818.
        ;
        ;     Inbound only. transport_encrypt's AEAD is also in place at
        ;     tp_packet+16 (transport.s:338-345), so residue left by a SEND
        ;     is ciphertext, not plaintext.
        ;
        ;     msg_recv_len + IP_UDP_HDR_LEN must be within tp_payload_len.
        ;     Bound (1) already caps msg_recv_len at 832, so the add cannot
        ;     carry out of 16 bits. A peer that pads its plaintext up to the
        ;     WireGuard 16-byte boundary sends MORE than it declares, which
        ;     passes; only claiming more than arrived is rejected.
        lda msg_recv_len
        clc
        adc #IP_UDP_HDR_LEN
        tax                     ; X = claimed total, low
        lda msg_recv_len+1
        adc #0                  ; A = claimed total, high
        cmp tp_payload_len+1
        bcc @len_fits
        bne @fail
        cpx tp_payload_len
        bcc @len_fits
        bne @fail
@len_fits:

        lda #0
        rts

@fail:
        ; msg_recv_ptr and msg_recv_len were stored above, BEFORE either bound
        ; ran, so on this path msg_recv_len still holds the peer's unchecked
        ; value (measured: A=$ff, msg_recv_len=832). session.s tests A before
        ; reading it, and that is the whole of what makes it safe -- a caller
        ; that read msg_recv_len without checking A would reinstate #97 in
        ; full. Zeroing the pair here is 8 bytes; MAIN_AREA_HI has 2 free at
        ; REU=1 (map: APP_EXTRA_BSS ends $9FFD, area ends $9FFF), so the
        ; invariant is stated rather than enforced. Spend the bytes here first
        ; if any ever come free.
        lda #$ff
        rts
