; src/net/uci/uci_errors.inc — UCI backend error codes
;
; CANONICAL REGISTRY: src/net_abi.inc. That table covers BOTH backends and
; records which values came from the retired c64-lib-contract §13.2 table and
; which are ours; this file is the UCI half, with the per-code reasoning.
; Add a code there first. A published value is never reassigned.
;
; Values stored in net_last_error by the UCI adapter. 0 = OK.
; Kept deliberately small and distinct from any ip65 error values so
; that future multi-backend debugging can tell them apart at a glance.
;
; $80-$BF is the grandfathered UCI range (c64-lib-contract SPEC §13.2).
; $81-$89 are the shared c64-https spellings and MUST NOT be reassigned
; here — they are the cross-consumer half of the table.
;
; NOTE ($8A, 2026-08-24): UCI_ERR_LONG_READ was ours alone and used to sit
; at $88, which c64-https had already assigned to UCI_ERR_NO_SOCKET. Two
; adapters emitting one byte with two meanings is what c64-lib-contract
; SPEC 13.2's allocation table now exists to prevent; LONG_READ moved to
; $8A and $88/$89 match c64-https exactly.
;
; CORRECTION (2026-08-24, later): an earlier version of this note said the
; move mattered because this adapter emits LONG_READ "on every healthy
; session". It did emit it constantly, but not because reads were long --
; $FFFF is the firmware's NO-DATA sentinel (measured: every idle UDP
; SOCKET_READ returns header $FFFF with rx_len 0, 11/11 sizes), and it
; fell through the over-claim test because $FFFF > the read cap (512 then). net_poll now
; excludes the sentinel first, so this code no longer fires on idle polls.
;
; The same sentinel, taken as a copy count, is the whole of the incident
; that created this code: 65535 from udp_recv_buf ($89D4) through a store
; loop that bumps its own high byte on every Y wrap reaches $D000 and the
; VIC registers, which is the ~18 KB overrun in PR #62. No firmware
; over-claim is needed to explain it. A non-sentinel over-claim has never
; been measured on either transport, so $8A is reserved defensively rather
; than for an observed condition -- the durable rule is the one that
; travels: exclude the sentinel before any length arithmetic, and never
; let a device-supplied count be the only bound on a store loop.

UCI_ERR_OK             = $00    ; no error
UCI_ERR_NOT_PRESENT    = $81    ; $DF1D did not read back UCI_ID_VALUE ($C9)
UCI_ERR_CMD_FAILED     = $82    ; UCI reported an error bit after PUSH_CMD
UCI_ERR_NO_IP          = $83    ; GET_IPADDR returned all-zero IP
UCI_ERR_CONNECT_FAIL   = $84    ; TCP_CONNECT returned an error bit
UCI_ERR_SEND_FAIL      = $85    ; SOCKET_WRITE returned an error bit, or a
                                ; written count of $FFFF (lwip_send ret -1)
UCI_ERR_READ_FAIL      = $86    ; SOCKET_READ returned an error bit
UCI_ERR_SHORT_WRITE    = $87    ; SOCKET_WRITE's returned count != requested
                                ; length (or no 2-byte count arrived). On UDP
                                ; the torn datagram is already gone — no retry.
; Contract-generic (§13.2 range $01-$3F, c64-lib-contract#145): the wall-clock
; timebase the bounded waits depend on did not start ticking. Any family may
; emit it. Measured 2026-08-27: the U64E's CIA1 TOD is stopped after reset.
NET_ERR_TIMEBASE_STOPPED = $01
UCI_ERR_NO_SOCKET      = $88    ; socket-open response yielded no socket_id
UCI_ERR_WAIT_TIMEOUT   = $89    ; a bounded wait exceeded its wall-clock budget
UCI_ERR_SEND_TOO_LONG  = $8C    ; datagram exceeds NET_UDP_SEND_MAX (the
                                ; adapter's published net_caps.inc guarantee:
                                ; 892, or 1472 under UCI_CHUNKED_WRITE);
                                ; refused BEFORE any register is touched
                                ; (c64-lib-contract#141/#142) because a split
                                ; would emit multiple UDP packets.
                                ; $8B is c64-https's UCI_ERR_BAD_READ_HDR —
                                ; allocated in SPEC §13.2 before use, per the
                                ; rule added after the $88 collision.
UCI_ERR_LONG_READ      = $8A    ; SOCKET_READ claimed more bytes than we asked for
UCI_ERR_OPEN_REFUSED   = $8D    ; the firmware REFUSED a socket open: it cleared
                                ; the hardware ERROR bit and returned no socket
                                ; id, but posted a named refusal on the $DF1F
                                ; STATUS channel (e.g. `85,ERROR OPENING SOCKET`,
                                ; the UDP-PCB pool MEMP_NUM_UDP_PCB=8 exhausted,
                                ; GideonZ/1541ultimate#808). DISTINCT from $88
                                ; NO_SOCKET (no id AND no status = short read /
                                ; phantom socket) and $89 WAIT_TIMEOUT (a bounded
                                ; wait elapsed with no device response = wedge):
                                ; $8D means a refusal STATUS was actually seen.
                                ; The captured line (uci_status_buf) carries the
                                ; firmware's decimal STATUS code (85).
                                ; c64-lib-contract#147 allocates it in §13.2.
UCI_ERR_CMD_UNKNOWN    = $8E    ; the firmware does not know the command: the
                                ; $DF1F STATUS line read `21,UNKNOWN COMMAND`.
                                ; Raised by the UCI_CHUNKED_WRITE send path when
                                ; NET_CMD_WRITE_SOCKET_CHUNK ($16, issue #70,
                                ; GideonZ/1541ultimate#807) is pushed at a
                                ; firmware without it — stock 3.15 included —
                                ; so a chunked build on the wrong firmware fails
                                ; on its very first send (the 148-byte Type-1)
                                ; with a named code instead of a generic $85/$87.
                                ; OURS, minted in this repo's own registry
                                ; (src/net_abi.inc): $8E was the next free UCI
                                ; code after #147's $8D. The contract filing
                                ; this once said was pending never happened
                                ; and never will — §13 was retired wholesale
                                ; at contract v1.0.0 and the numbering came
                                ; home with it.

; TCP state values stored in net_tcp_state
UCI_TCP_CLOSED         = $00    ; no active socket
UCI_TCP_CONNECTED      = $01    ; connected, reads/writes valid
UCI_TCP_ERROR          = $02    ; saw an error on a read — stop polling
UCI_TCP_CONNECT_FAIL   = $03    ; connect did not yield a usable socket

; Per-SOCKET_WRITE payload ceiling (c64-test-harness uci_network.py's
; SOCKET_WRITE_MAX_BYTES agrees: 892, hardware-verified).
; Largest payload in ONE SOCKET_WRITE — and therefore the largest datagram
; this adapter can SEND, because a connected UDP socket emits one datagram
; per write. This is NOT a chunk size: raising the tunnel MTU above it does
; not split a frame across writes, it fragments one WireGuard packet into
; several UDP datagrams that the peer drops. Measured 2026-08-27 at the old
; value of 800: a 1452-byte send arrived as 800 + 652, carry=0, no error.
;
; 892, and the off-by-one is real. The command buffer is 896, but
; command_protocol.vhd freezes command_pointer at c_cmd_if_command_buffer_end
; (895) and derives command_length from it, so the length SATURATES at 895 and
; the 896th slot is written but never read. Payload = 895 - 3 (target, command,
; socket id) = 892. Push 893 and the last byte is dropped with a clean status —
; c64-test-harness measured exactly that ("893 arrives as 892", uci_network.py
; SOCKET_WRITE_MAX_BYTES) and attributed it to "likely a fencepost"; the VHDL
; guard IS that fencepost. Same shape as the read side's 894 = 896 - 2.
;
; NOTE THE ASYMMETRY: reads can exceed this. fw 3.15 returns datagrams up to
; 1472 B by splitting the REPLY across Data More blocks
; (GideonZ/1541ultimate#806), and net_poll reassembles them. In stock 3.15 no
; equivalent exists for the command direction, so the tunnel MTU is bounded
; by SEND.
;
; UCI_CHUNKED_WRITE (issue #70): the #807 spike firmware adds
; NET_CMD_WRITE_SOCKET_CHUNK ($16), which accumulates PARTS into one datagram
; and emits it on the part that completes the announced total. The datagram
; ceiling becomes the firmware's own 1472 (IP_REASSEMBLY = 0), and the
; per-part ceiling is the same 895-byte command buffer minus the 7-byte
; header ($03 $16 id off_lo off_hi tot_lo tot_hi) = 888. The adapter never
; offers more than UCI_CHUNK_PART_MAX in one part (net.s asserts it), so the
; 893-style silent truncation cannot recur at the part boundary.
.ifdef UCI_CHUNKED_WRITE
UCI_DATA_QUEUE_MAX     = 1472
.else
UCI_DATA_QUEUE_MAX     = 892
.endif
UCI_CHUNK_PART_MAX     = 895 - 7
.assert UCI_CHUNK_PART_MAX = 888, error, "UCI_CHUNK_PART_MAX must be 888: 895-byte command buffer minus the 7-byte $16 header (GideonZ/1541ultimate#807)"

; SOCKET_READ max-length cap we ask for per net_poll cycle.
;
; Firmware baseline: 3.15 or later (3.14d is no longer supported — see the
; history line below). Current behaviour, fw 3.15:
;   - 1472 = the largest UDP payload in a 1500-byte Ethernet frame (20 IP +
;     8 UDP). A reply larger than one 896-byte response block is delivered
;     across "Data More" blocks (GideonZ/1541ultimate#806); net_poll
;     reassembles them into udp_recv_buf, and the 2-byte header — the TOTAL
;     length — is what this value is validated against.
;   - A datagram larger than the request is cut by the firmware and reported
;     on the STATUS channel as `04,DATAGRAM TRUNCATED: <n>` (UCI_STATUS_MAX
;     below is sized for that line).
;   - $FFFF in the header is the firmware's NO-DATA sentinel, not a length
;     (see the $8A note above); net_poll excludes it before any comparison.
;   - Receive is therefore NOT bounded by the command-interface RAM the way
;     send is (892 per SOCKET_WRITE, above): the tunnel MTU is set by the
;     send side.
;
; HISTORY (why 3.14d is unsupported): 3.14d has no multi-block reply, so a
; single SOCKET_READ tops out at 894 and a request of EXACTLY 894 hangs the
; interface — the 2+894 = 896-byte reply fills the response queue and
; DATA_AV never clears (GideonZ/1541ultimate#802). The cap sat at 893 from
; 2026-08-26 until the 3.15 reassembly landed, and before that at 512 —
; this project's own Phase 3 MVP choice, misread for months as a firmware
; ceiling because we only ever ASKED for 512.
UCI_READ_CHUNK_MAX     = 1472

; Bytes of the $DF1F status line kept by uci_drain_status. Long enough for
; fw 3.15's "04,DATAGRAM TRUNCATED: 1420" (27 chars) with room to spare.
UCI_STATUS_MAX         = 48
