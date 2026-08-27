; src/net/uci/uci_errors.inc — UCI backend error codes
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
; fell through the over-claim test because $FFFF > 512. net_poll now
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
UCI_ERR_SEND_FAIL      = $85    ; SOCKET_WRITE returned an error bit
UCI_ERR_READ_FAIL      = $86    ; SOCKET_READ returned an error bit
UCI_ERR_SHORT_WRITE    = $87    ; SOCKET_WRITE wrote fewer bytes than requested
UCI_ERR_NO_SOCKET      = $88    ; socket-open response yielded no socket_id
UCI_ERR_WAIT_TIMEOUT   = $89    ; a bounded wait exceeded its wall-clock budget
UCI_ERR_SEND_TOO_LONG  = $8C    ; datagram exceeds UCI_DATA_QUEUE_MAX; a
                                ; split would emit multiple UDP packets.
                                ; $8B is c64-https's UCI_ERR_BAD_READ_HDR —
                                ; allocated in SPEC §13.2 before use, per the
                                ; rule added after the $88 collision.
UCI_ERR_LONG_READ      = $8A    ; SOCKET_READ claimed more bytes than we asked for

; TCP state values stored in net_tcp_state
UCI_TCP_CLOSED         = $00    ; no active socket
UCI_TCP_CONNECTED      = $01    ; connected, reads/writes valid
UCI_TCP_ERROR          = $02    ; saw an error on a read — stop polling
UCI_TCP_CONNECT_FAIL   = $03    ; connect did not yield a usable socket

; UCI firmware data queue max per SOCKET_WRITE push (see uci_network.py)
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
; (GideonZ/1541ultimate#806), and net_poll reassembles them. No equivalent
; exists for the command direction, so the tunnel MTU is bounded by SEND.
UCI_DATA_QUEUE_MAX     = 892

; SOCKET_READ max-length cap we ask for per net_poll cycle.
;
; 893, and the exact value matters — 894 is a HANG on this firmware.
;
; The firmware's real limit is 894 (CMD_MAX_REPLY_LEN 896 minus the 2-byte
; length header), fixed by the FPGA's command-interface RAM partition; a
; larger request is REJECTED with `82,PARAMETER(S) OUT OF RANGE` on the
; STATUS channel. But a read of exactly 894 builds a 2+894 = 896-byte reply,
; exactly the response-queue size: the FPGA stops the response pointer at
; the last byte while still asserting DATA_AV, so the flag never clears and
; the queue repeats its final byte forever (GideonZ/1541ultimate#802, found
; by chrisgleissner; their fix moves the refusal to 894 but ships in 3.15,
; which is not downloadable — we are on 3.14d, where 894 is ACCEPTED and
; will do this). 893 is the largest value that both fits and drains.
;
; This was 512 until 2026-08-26, described here as "the conservative Phase 3
; MVP choice" — which it was. It was never a firmware limit, though this
; project reasoned about it as one for months. Measured on our own U64E
; (fw 3.14d): datagrams of 512/600/700/800/861/893 all arrive WHOLE in a
; single poll with the header reporting their true length.
UCI_READ_CHUNK_MAX     = 1472

; Bytes of the $DF1F status line kept by uci_drain_status. Long enough for
; fw 3.15's "04,DATAGRAM TRUNCATED: 1420" (27 chars) with room to spare.
UCI_STATUS_MAX         = 48
