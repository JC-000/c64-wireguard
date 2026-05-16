; src/net/uci/uci_errors.inc — UCI backend error codes
;
; Values stored in net_last_error by the UCI adapter. 0 = OK.
; Kept deliberately small and distinct from any ip65 error values so
; that future multi-backend debugging can tell them apart at a glance.

UCI_ERR_OK             = $00    ; no error
UCI_ERR_NOT_PRESENT    = $81    ; $DF1D did not read back UCI_ID_VALUE ($C9)
UCI_ERR_CMD_FAILED     = $82    ; UCI reported an error bit after PUSH_CMD
UCI_ERR_NO_IP          = $83    ; GET_IPADDR returned all-zero IP
UCI_ERR_CONNECT_FAIL   = $84    ; TCP_CONNECT returned an error bit
UCI_ERR_SEND_FAIL      = $85    ; SOCKET_WRITE returned an error bit
UCI_ERR_READ_FAIL      = $86    ; SOCKET_READ returned an error bit
UCI_ERR_SHORT_WRITE    = $87    ; SOCKET_WRITE wrote fewer bytes than requested

; TCP state values stored in net_tcp_state
UCI_TCP_CLOSED         = $00    ; no active socket
UCI_TCP_CONNECTED      = $01    ; connected, reads/writes valid
UCI_TCP_ERROR          = $02    ; saw an error on a read — stop polling

; UCI firmware data queue max per SOCKET_WRITE push (see uci_network.py)
UCI_DATA_QUEUE_MAX     = 800

; SOCKET_READ max-length cap we ask for per net_poll cycle.
; 512 bytes is well under the 4 KB ring and the firmware data queue,
; and matches the conservative Phase 3 MVP choice.
UCI_READ_CHUNK_MAX     = 512
