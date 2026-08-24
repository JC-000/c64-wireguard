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
UCI_ERR_LONG_READ      = $8A    ; SOCKET_READ claimed more bytes than we asked for

; TCP state values stored in net_tcp_state
UCI_TCP_CLOSED         = $00    ; no active socket
UCI_TCP_CONNECTED      = $01    ; connected, reads/writes valid
UCI_TCP_ERROR          = $02    ; saw an error on a read — stop polling
UCI_TCP_CONNECT_FAIL   = $03    ; connect did not yield a usable socket

; UCI firmware data queue max per SOCKET_WRITE push (see uci_network.py)
UCI_DATA_QUEUE_MAX     = 800

; SOCKET_READ max-length cap we ask for per net_poll cycle.
; 512 bytes is well under the 4 KB ring and the firmware data queue,
; and matches the conservative Phase 3 MVP choice.
UCI_READ_CHUNK_MAX     = 512
