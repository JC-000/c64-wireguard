; =============================================================================
; net/ip65/net.s - ip65 network wrapper with zero page time-sharing
;                  (ca65 port of src/net.asm)
;
; All ip65 calls go through this wrapper. Before each call:
;   1. Save crypto ZP ($02-$1B) to zp_save_buf
;   2. Call ip65 function
;   3. Restore crypto ZP from zp_save_buf
;
; The UDP receive callback fires DURING ip65_process, while ip65's ZP is
; active. The callback must NOT touch crypto state — it only copies received
; data into udp_recv_buf for later processing by the main loop.
;
; This module ships in LOADER (CODE segment) — it is called during boot
; before crypto goes live, and by the main loop from then on.
;
; -----------------------------------------------------------------------------
; net_last_error — this backend's error channel (issue #120, #116 class)
; -----------------------------------------------------------------------------
; Until now the ip65 backend reported failures ONLY through the carry, so a
; failed send was invisible to any structural probe: src/net_abi.inc's
; "NOT DECLARED HERE" note and the manifest gap in ip65_blob.s both exist
; because of this missing byte. One byte closes it. src/net_abi.inc also
; carries the canonical registry of every code both backends emit.
;
; CANONICAL REGISTRY: src/net_abi.inc. Both backends' codes are tabulated
; there; this header is the ip65 half restated where it is emitted. Add a
; code THERE first, then here.
;
; Provenance. These values were allocated against c64-lib-contract SPEC
; §13.2, which was RETIRED wholesale at contract v1.0.0 — a network backend
; is source in its consumer's own tree, never an artifact one party builds
; and another links, so the cross-repo registry had no mechanism behind it.
; The retired text is permanent at `git show v0.17.1:SPEC.md`. Nothing
; renumbered: no value changed at v1.0.0, and these still read correctly to
; anyone who remembers the table. What changed is ownership — the registry
; is ours now.
;
; Two rules survive the retirement on their own merits, and both are why
; this list looks the way it does. First: a published value is never
; reassigned. $41-$45 are c64-https's and $40 was never allocated at all, so
; "pick the next free-looking byte in our range" is precisely the mistake
; that made $88 mean two things in two UCI adapters. Second: translate the
; driver's errors, never forward them — ip65's own ip65_error namespace is
; $80-$A1, which lands squarely inside our UCI codes.
;
;   $00  IP65_ERR_OK              no error
;   $01  NET_ERR_TIMEBASE_STOPPED contract-generic. Here: the jiffy clock the
;                                 send budget is bound to never advanced.
;   $41  NET_ERR_IP65_INIT        ip65_init failed (no RR-Net / cs8900a).
;                                 c64-https's code; we are the SECOND EMITTER
;                                 (contract #148, v0.14.0).
;   $42  NET_ERR_IP65_DHCP        ip65_dhcp_init failed, no lease. Same
;                                 second-emitter status (contract #148).
;   $46  NET_ERR_IP65_UDP_LISTEN  udp_add_listener refused the bind: the
;                                 blob's table is full (udp_cbmax = 4) or the
;                                 port is already handled. Ours, filed before
;                                 use (contract #148). The table deliberately
;                                 collapses those two causes into one code.
;   $48  NET_ERR_IP65_WAIT_TIMEOUT  a bounded wait exceeded its wall-clock
;                                 budget — the ip65 counterpart of $89
;                                 UCI_ERR_WAIT_TIMEOUT. Emitted by
;                                 net_arp_pump on budget expiry. OURS: minted
;                                 in this repo's registry, never in the
;                                 contract (the filing that would have
;                                 allocated it was withdrawn when §13 went).
;   $49  NET_ERR_IP65_UDP_UNBIND  udp_remove_listener found no listener on
;                                 the port we believed we held. Ours, same
;                                 provenance as $48. Reachable: see
;                                 net_udp_close.
;
; ALLOCATED TO US BUT NOT EMITTED HERE:
;   $47  NET_ERR_IP65_UDP_SEND    "udp_send failed — transmit rejected below
;                                 IP". We cannot reach it. The cold-ARP C=1
;                                 and a genuine rejection are indistinguish-
;                                 able at this ABI (see net_arp_pump), so
;                                 every send failure leaves through the
;                                 budget as $48. Reserved, not reassigned.
;
; LIFETIME: cleared by net_init, and cleared by net_udp_send on entry — so
; the byte read immediately after a net_udp_send is exactly that send's
; verdict. The other entry points only WRITE it on failure, so a code left
; by an earlier failure survives a later successful listen/close. Probes
; should read it right after the call they are judging.
; =============================================================================

.include "constants.inc"
.include "net/ip65/ip65_symbols.inc"

; ---- Public entry points -----------------------------------------------------
.export net_init
.export net_dhcp_acquire
.export net_poll
.export net_udp_listen
.export net_udp_send
.export net_udp_close
.export net_udp_recv_cb
.export net_print_ip

; ---- Public data labels (defined in this module) -----------------------------
.export net_udp_send_ptr
.export net_udp_send_len

; ---- Adapter-internal state, exported for observability (issue #84) ---------
.export ip65_listening
.export ip65_listen_port

; ---- Error channel + send observability (issue #120) ------------------------
; All three live in BSS below, i.e. in MAIN_AREA_LO, which the cfg emits as
; file-backed zero fill — so LOAD stamps them $00 and a DMA read of the
; freshly loaded PRG sees a defined value before any code runs.
.export net_last_error
.export ip65_send_pump
.export ip65_send_attempts
.export ip65_recv_dropped

; =============================================================================
; Error codes. Canonical registry: src/net_abi.inc — see the file header
; above for provenance and for $47 (ours, reserved, unreachable here).
; =============================================================================
IP65_ERR_OK                = $00
NET_ERR_TIMEBASE_STOPPED   = $01
NET_ERR_IP65_INIT          = $41
NET_ERR_IP65_DHCP          = $42
NET_ERR_IP65_UDP_LISTEN    = $46
NET_ERR_IP65_UDP_SEND      = $47    ; RESERVED — defined, never emitted
NET_ERR_IP65_WAIT_TIMEOUT  = $48
NET_ERR_IP65_UDP_UNBIND    = $49

; $47 reuse guard. A comment cannot stop an edit, and $47 is the value the
; registry most needs to protect because nothing emits it. ca65 has no
; "reserve this value" primitive, so this is what is actually enforceable,
; stated exactly: defining the NAME means a second definition of it is a hard
; ca65 error ("Symbol already defined"); EXPORTING it puts it in labels.txt so
; a probe can assert the reservation still stands; and the asserts below fail
; the assembly if a code in THIS block — the block the header tells you to add
; to — silently takes the value. What none of that catches is a new symbol in
; a DIFFERENT file choosing $47. That residue is unavoidable here; the
; registry in src/net_abi.inc is the backstop for it.
.export NET_ERR_IP65_UDP_SEND
.assert NET_ERR_IP65_UDP_LISTEN   <> NET_ERR_IP65_UDP_SEND, error, "$47 is reserved (src/net_abi.inc registry)"
.assert NET_ERR_IP65_WAIT_TIMEOUT <> NET_ERR_IP65_UDP_SEND, error, "$47 is reserved (src/net_abi.inc registry)"
.assert NET_ERR_IP65_UDP_UNBIND   <> NET_ERR_IP65_UDP_SEND, error, "$47 is reserved (src/net_abi.inc registry)"
.assert NET_ERR_IP65_INIT         <> NET_ERR_IP65_UDP_SEND, error, "$47 is reserved (src/net_abi.inc registry)"
.assert NET_ERR_IP65_DHCP         <> NET_ERR_IP65_UDP_SEND, error, "$47 is reserved (src/net_abi.inc registry)"

; =============================================================================
; Send retry budget (issue #120).
;
; The C64 jiffy clock, $A0(hi)/$A1(mid)/$A2(lo), ticks at 60 Hz from the
; KERNAL IRQ, so 30 ticks is ~0.5 s.
;
; WHY 30 AND NOT MORE. Do not raise this without redoing this arithmetic.
; A LAN ARP round trip is sub-millisecond, and ip65's arp_lookup re-broadcasts
; the request every ARP_TIMEOUT_MS = 100 ms while it stays unresolved, so
; 0.5 s covers FIVE retransmits — five independent chances for a reply, on a
; medium where one normally suffices in under a millisecond. Everything past
; that is not extra reliability, it is extra cost, and the cost is specific:
; the receive callback is disarmed for the whole window (see net_arp_pump),
; so every jiffy of budget is a jiffy of deafness to inbound tunnel traffic.
; The first version of this used 120 (2.0 s) for no better reason than "a
; budget of ~2 s is generous"; 30 buys the same five retransmits and cuts the
; deafness fourfold.
; =============================================================================
IP65_ARP_BUDGET_JIFFIES  = 30

; Iterations before the stopped-clock detector tests the jiffy (see
; net_arp_pump). One byte: the counter is decremented from $00 and wraps to
; $00 again after exactly 256 decrements.
IP65_ARP_STALL_ITERS     = 256

; ---- External data symbols (defined in wg/data.s) ----------------------------
.import udp_recv_buf
.import udp_recv_len
.import udp_recv_ready
.import udp_recv_src_ip
.import udp_recv_src_port
.import wg_local_port
.import net_udp_dest_ip
.import net_udp_dest_port
.import zp_save_buf

; =============================================================================
; BOOT_CODE (not bare CODE): CODE is ceded to the chacha sibling archive
; (contract §4 gap, upstream issue #48); this wrapper stays in LOADER.
.segment "BOOT_CODE"

; =============================================================================
; net_init - initialize ip65 + ethernet (RR-Net CS8900a)
; Output: C=0 success, C=1 failure
; =============================================================================
net_init:
        ; ip65_init -> ip_init -> udp_init zeroes udp_cbcount, so any listener
        ; we held is gone from the blob's table by the time this returns.
        ; Forget it here, or a later net_udp_close would ask the blob to
        ; remove a port it no longer knows about and report a bogus C=1
        ; (issue #84). Cleared BEFORE the call so a failed init cannot leave
        ; a stale claim behind either.
        lda #$00
        sta ip65_listening
        sta net_last_error      ; #120: fresh channel for a fresh stack
        sta ip65_send_pump
        sta ip65_send_attempts  ; every observable byte, not just some
        sta ip65_recv_dropped

        jsr net_save_zp
        lda #0                  ; eth_init_default
        jsr ip65_init
        php                     ; save carry result
        jsr net_restore_zp
        plp                     ; restore carry
        bcs @ni_fail
        rts
@ni_fail:
        lda #NET_ERR_IP65_INIT
        sta net_last_error      ; does not touch C
        sec
        rts

; =============================================================================
; net_dhcp_acquire - obtain IP address via DHCP
; Output: C=0 success, C=1 failure
; =============================================================================
net_dhcp_acquire:
        jsr net_save_zp
        jsr ip65_dhcp_init
        php
        jsr net_restore_zp
        plp
        bcs @nd_fail
        rts
@nd_fail:
        lda #NET_ERR_IP65_DHCP
        sta net_last_error
        sec
        rts

; =============================================================================
; net_poll - call ip65_process (non-blocking)
; Must be called frequently from main loop.
; =============================================================================
net_poll:
        jsr net_save_zp
        jsr ip65_process
        jsr net_restore_zp
        ; §13.2: C=1 means a BACKEND ERROR, and this path has none to report —
        ; ip65_process's own carry is a "did work" flag, and net_restore_zp does
        ; not preserve it anyway, so the carry reaching the caller was previously
        ; undefined. Inbound data is signalled by udp_recv_ready, set from the
        ; receive callback. Say so explicitly rather than leaking a stale flag.
        clc
        rts

; =============================================================================
; net_udp_listen - register UDP listener on specified port
; Input: wg_local_port set to port number (little-endian)
; Output: C=0 success, C=1 failure
; =============================================================================
net_udp_listen:
        jsr net_save_zp
        ; set callback vector
        lda #<net_udp_recv_cb
        ldx #>net_udp_recv_cb
        jsr ip65_set_udp_cb
        ; add listener on our port
        lda wg_local_port
        ldx wg_local_port+1
        jsr ip65_udp_add
        php
        jsr net_restore_zp
        plp
        bcs @nl_fail

        ; Record the port we actually claimed rather than promising to
        ; re-read wg_local_port at close time. wg_local_port is consumer
        ; state — boot.s stages it before every listen — so a close that
        ; re-read it could ask the blob to remove a port it never registered
        ; and silently leak the one it did (issue #84).
        lda wg_local_port
        sta ip65_listen_port
        lda wg_local_port+1
        sta ip65_listen_port+1
        lda #$01
        sta ip65_listening
        clc
        rts

@nl_fail:
        ; Table full, or this port is already handled. We took nothing here,
        ; so leave ip65_listening alone: an earlier successful listen still
        ; owns its slot and must still be released.
        lda #NET_ERR_IP65_UDP_LISTEN
        sta net_last_error
        sec
        rts

; =============================================================================
; net_udp_close - release the UDP listener slot we claimed
;
; What this used to say: "ip65's UDP is connectionless: udp_add_listener /
; udp_remove_listener manage a local port, and there is no firmware-side
; socket handle to abandon" — and then `clc / rts`.
;
; The first clause is true and the conclusion does not follow: the same
; sentence names the thing that leaks. udp_add_listener claims one entry in a
; FOUR-entry table (`udp_cbmax = 4`, ip65/ip65/udp.s), keyed by port, and
; udp_remove_listener is the call that gives it back. It is reachable — the
; blob exports it through the jump table at ip65_base + 15
; (ip65-build/ip65_stub.s) — and nothing in this tree had ever called it. So
; every listen consumed a slot permanently and this routine reported success
; having done nothing (issue #84).
;
; Two consequences, both real on the shipped wireguard-rrnet-*.prg:
;   * Four listens on distinct ports exhaust the table; the fifth fails.
;   * A re-listen on the SAME port does not even get that far.
;     udp_add_listener refuses a port already in the table (its @busy leg),
;     so a single listen/close/listen cycle on our one port failed at the
;     second listen. Closing had to actually close for that to work.
;
; There is no firmware-side reaper here as there is under UCI: the table is
; in the blob's own BSS, and only ip65_init clears it (ip65_init -> ip_init
; -> udp_init zeroes udp_cbcount). That is why net_init above drops our
; bookkeeping: after a re-init the blob has forgotten our slot, so we must.
;
; Output: C=0 on success or when we hold no listener; C=1 if the blob had no
; such listener to remove, with net_last_error = NET_ERR_IP65_UDP_UNBIND
; ($49). That code did not exist while the cross-repo table owned the
; numbering and there was nothing to set here but the carry; issue #120 gave
; this backend an error channel and this repo its own registry, so the
; condition finally gets a name (see src/net_abi.inc).
;
; Clobbers: A, X
; =============================================================================
net_udp_close:
        lda ip65_listening
        beq @nc_none                ; we hold no slot — nothing to release

        jsr net_save_zp
        lda ip65_listen_port
        ldx ip65_listen_port+1
        jsr ip65_udp_remove
        php                         ; the blob's verdict, kept across the
                                    ; restore and the bookkeeping below
        jsr net_restore_zp

        ; Drop our claim either way. C=1 means the blob has no listener on
        ; that port, in which case we do not own one either; going on
        ; believing we do would make the NEXT close remove a slot some later
        ; listen had legitimately claimed.
        lda #$00
        sta ip65_listening
        plp
        bcs @nc_fail
        clc
        rts

@nc_fail:
        ; The blob has no listener on the port we thought we owned. Reachable
        ; (udp_remove_listener's @notfound leg), so it gets a code now that
        ; the registry is ours to extend rather than a filing to wait on.
        lda #NET_ERR_IP65_UDP_UNBIND
        sta net_last_error
        sec
        rts

@nc_none:
        clc
        rts

; =============================================================================
; net_udp_send - send UDP packet
; Input: A/X = pointer to data buffer
;        net_udp_send_len = 16-bit length
;        net_udp_dest_ip, net_udp_dest_port, wg_local_port must be set
; Output: C=0 success, C=1 failure, net_last_error set
; =============================================================================
net_udp_send:
        sta net_udp_send_ptr
        stx net_udp_send_ptr+1
        lda #IP65_ERR_OK
        sta net_last_error          ; #120: this call's verdict, not a stale one
        lda #$01
        sta ip65_send_attempts      ; the attempt we are about to make

        ; Reclaim the listener slot if a teardown released it.
        ;
        ; This is what makes net_udp_close safe to call from the consumer's
        ; abandonment paths, which is the whole of issue #84. It mirrors the
        ; UCI backend exactly: there net_udp_close clears uci_socket_open and
        ; the next net_udp_send re-issues UDP_CONNECT, so a consumer that
        ; tears a session down carries on without re-running net_init. Before
        ; this, an ip65 close that actually released would have left the app
        ; permanently deaf — sends would keep succeeding and nothing would
        ; ever be received again, because only do_net_init ('I') listens.
        ;
        ; A send whose reply can never arrive is not a successful send, so a
        ; failed re-listen fails the send rather than going silently deaf.
        ;
        ; Guarded on ip65_listen_port being non-zero, i.e. on net_udp_listen
        ; having ALREADY succeeded once this run. Without that guard this
        ; becomes the first call site that can reach udp_add_listener before
        ; ip65_init has run — boot.s dispatches 'H' whether or not 'I' was
        ; pressed — and udp_add_listener indexes its table with udp_cbcount,
        ; which lives in the blob's BSS at $A000 and is uninitialised until
        ; ip65_init zeroes it. A garbage count writes four bytes at a garbage
        ; offset into the blob's own state. This is BSS in MAIN_AREA_LO
        ; (file = %O, fill = yes, fillval = $00), so LOAD really does stamp
        ; it zero and the guard really does hold on a cold boot.
        lda ip65_listening
        bne @snd_go
        lda ip65_listen_port
        ora ip65_listen_port+1
        beq @snd_go                 ; never listened — nothing of ours to reclaim
        jsr net_udp_listen
        bcs @snd_no_listener
@snd_go:
        jsr net_save_zp
        ; set destination IP
        lda #<net_udp_dest_ip
        ldx #>net_udp_dest_ip
        jsr ip65_set_udp_dest
        ; set dest port. net_udp_dest_port is BIG-endian (net_abi.inc §13.1,
        ; the UCI backend swaps it on push too); ip65 keeps udp_send_dest_port
        ; LITTLE-endian in memory and builds the wire header from +1 then +0
        ; (ip65/udp.s udp_send). A raw copy therefore byte-swapped every
        ; destination port on the wire: a peer configured on 51820 ($CA6C)
        ; was sent the Type-1 on 27850 ($6CCA), so no responder ever saw an
        ; ip65 handshake (measured on the VICE-eth rig 2026-09-03, tcpdump
        ; showed dst port 0x99B7 for a staged $B7 $99). Swap on copy.
        lda net_udp_dest_port+1     ; BE low byte -> ip65 LE byte 0
        sta ip65_udp_snd_dport
        lda net_udp_dest_port       ; BE high byte -> ip65 LE byte 1
        sta ip65_udp_snd_dport+1
        ; set source port
        lda wg_local_port
        sta ip65_udp_snd_sport
        lda wg_local_port+1
        sta ip65_udp_snd_sport+1
        ; set length
        lda net_udp_send_len
        sta ip65_udp_snd_len
        lda net_udp_send_len+1
        sta ip65_udp_snd_len+1
        ; send — AX = data pointer
        lda net_udp_send_ptr
        ldx net_udp_send_ptr+1
        jsr ip65_udp_send
        bcc @snd_done               ; warm ARP cache: byte-for-byte the old path
        jsr net_arp_pump            ; issue #120 — see below
@snd_done:
        php
        jsr net_restore_zp
        plp
        rts

@snd_no_listener:
        ; net_udp_listen already set net_last_error = NET_ERR_IP65_UDP_LISTEN.
        sec
        rts

; =============================================================================
; net_arp_pump - bounded ARP-resolution retry for a send ip65 just refused
;                (issue #120)
;
; THE BUG THIS EXISTS FOR. ip65 does not queue a datagram whose next-hop MAC
; it does not know. udp_send -> udp_send_internal -> ip_send -> arp_lookup:
; on a cache miss arp_lookup broadcasts an ARP request, sets arp_state =
; arp_wait and returns C=1, and ip_send bails at ip65/ip65/ip.s:320-322 —
; `jsr arp_lookup / bcc :+ / rts  ; packet buffer nuked, fail` — the staged
; frame in eth_outp having been overwritten by the ARP request itself. That
; line is the authoritative statement of why the retry below must RE-CALL
; ip65_udp_send rather than resume anything: the driver says outright that
; the buffer is gone, so re-presenting the caller's pointer and letting
; udp_send re-copy is the only correct move, not merely the convenient one.
; Confirmed downstream, and this is the part that makes the re-call SOUND
; rather than merely safe: ip65's udp_send re-runs copymem from the caller's
; buffer and then FALLS THROUGH into udp_send_internal, which rebuilds the
; virtual header, both ports, the length and the checksum from scratch on
; every call. So each attempt emits a wholly rebuilt frame, and a resume
; anywhere downstream of the frame build would put a right-sized datagram of
; wrong bytes on the wire — right length, right ports, wrong contents, which
; every count-and-length check would pass. The carry came back through net_udp_send unchanged and
; session_initiate treated it as a fatal handshake failure. Cloudflare is
; off-subnet, so the next hop is the gateway and the FIRST send after
; net_init always took that path: measured on bridged-Ethernet VICE,
; attempt 1 C=1 with 0 ARP rows, attempt 2 C=0 with 2 rows and the 148-byte
; Type 1 on the wire. The ip65 backend had therefore never completed a
; handshake with a real peer.
;
; The backend's contract is "send it or report a real failure" (the UCI
; adapter blocks until the firmware has taken the datagram), so the retry
; belongs HERE and not in session_initiate — the keepalive path, the
; receive-side reply path and every future caller get it for free. They need
; it: ip65's ARP cache is an 8-entry MRU list (arp.s ac_add_source shifts
; every entry down and drops the last), and every inbound ARP request for
; our IP inserts its sender at the top, so on a busy LAN the gateway entry
; CAN be evicted and a mid-session keepalive goes cold exactly like the
; first handshake did.
;
; WHY WE RETRY EVERY C=1, NOT JUST THE COLD-ARP CASE. ip65 gives us nothing
; to discriminate with: neither arp_lookup's @notimeout leg nor ip_send's
; bail writes ip65_error, so the blob's error byte (ip65_error_addr) still
; holds whatever the last DHCP or DNS call left there, and arp_state is not
; reachable through the stub's jump table. So this retries ANY C=1 for the
; budget. The other thing that can set it is eth_tx refusing the frame,
; which retrying is also the right answer to. The price is stated plainly:
; a genuinely dead link now costs IP65_ARP_BUDGET_JIFFIES (~0.5 s) per send
; instead of failing instantly — once per send, not once per retry.
;
; WHY THE JIFFY CLOCK AND NOT A CIA TOD BUDGET — DO NOT "FIX" THIS TO TOD.
; The rule this satisfies came from c64-lib-contract §13.4, retired at
; contract v1.0.0 (permanent at `git show v0.17.1:SPEC.md`), so take the
; reasoning rather than the section number, because the reasoning is what
; was ever load-bearing: a wait must be bounded by something that advances
; with REAL TIME and not with cycles, so that the bound means the same thing
; at 1 MHz and at 48 MHz. The clause named "CIA TOD or timer" — two
; instances, not one requirement. The jiffy at $A0-$A2 is timer-driven (the
; 60 Hz KERNAL IRQ) and CPU-clock-independent, so it is the same kind of
; thing as the TOD and satisfies the same property. The UCI adapter uses
; CIA1 TOD (uci_cmd.s) because the U64E's TOD is stopped after reset and a
; counted spin is not a wall-clock bound at all. That reasoning does not
; transfer to this backend, and the TOD is the wrong clock here:
;   * uci_tod_start lives in src/net/uci/, which is NOT linked under
;     BACKEND=ip65. Using TOD would mean a second, duplicated ~90-byte
;     start-and-verify routine for a clock nothing else in this build uses.
;   * The KERNAL IRQ is not masked while this loop runs, so the jiffy
;     advances. Note carefully what that claim rests on, because an earlier
;     version of this comment said "nothing in src/ or libs/ executes sei or
;     cli — checked, zero hits" and that is FALSE: there are six, and the one
;     that matters is libs/x25519/src/x25519.s, where x25519_scalarmult masks
;     interrupts across the ENTIRE scalarmult to protect its 83 ZP bytes and
;     its REU DMA. src/wg/timer.s already records the consequence — the jiffy
;     does not advance while that crypto runs. The grep that produced "zero
;     hits" silently excluded libs/, and the conclusion happened to survive
;     the bad evidence, which is the worst way to be right.
;     The real reason this loop is safe is structural, not statistical:
;     x25519_scalarmult brackets its mask with php/sei ... plp, so the I flag
;     is RESTORED before it returns, and every caller stages its datagram and
;     calls net_udp_send only after the crypto has returned. A send is never
;     issued from inside the masked region, so the pump never runs there. If
;     that ever changes, this loop degrades into the stopped-clock case below
;     rather than hanging — which is exactly why that detector exists.
;   * Decisively: the jiffy clock is ALREADY ip65's own timebase in this
;     blob. ip65-c64.map links drivers/clk_timer.o, whose timer_read is
;     cc65's clock(), i.e. the jiffy at $A0-$A2; arp_lookup's 100 ms
;     retransmit is built on it. Budgeting the retry on a DIFFERENT clock
;     would let our bound and ip65's ARP state machine disagree about how
;     much time has passed.
;   * It is also the project's own session timebase (src/wg/timer.s), so a
;     stopped jiffy is a pre-existing, already-visible failure rather than
;     one this routine would newly hide.
; The one property TOD has that the jiffy lacks — it cannot be silently
; stopped by someone else's sei — is the exact case that reasoning worries
; about, and it is covered by testing the clock itself.
;
; STOPPED-CLOCK DETECTOR. After IP65_ARP_STALL_ITERS (256) iterations, the
; elapsed value the budget check already computes is compared against zero:
; exactly zero means the jiffy has not moved AT ALL since entry, i.e. it is
; stopped, and the loop exits with NET_ERR_TIMEBASE_STOPPED ($01) — the same
; verdict uci_tod_start reaches when its verification spin sees no tick.
; This replaced a 65535-attempt counter, which was a proxy for the wrong
; thing and was not even safe in the right direction: iteration cost is not
; fixed, so a fast host can fit more than 65535 iterations inside the budget
; and the counter would have reported a stopped clock while the clock was
; healthy. Testing the clock cannot make that mistake.
;
; THE 256 IS ARITHMETIC, NOT TASTE. The detector is correct as long as 256
; iterations span MORE than one jiffy, so that a live clock has certainly
; ticked: at 1 MHz that needs a mean iteration cost above 16667/256 = 65
; cycles. Every iteration runs jsr ip65_process plus a full ip65_udp_send —
; copymem over the payload, a UDP checksum over payload plus the 12-byte
; pseudo-header, header construction, arp_lookup's 8-entry findip scan, and
; ip65's own cc65 clock() call with its 32-bit divide for the ARP retransmit
; timer. findip's scan alone clears 65 cycles. The margin at 1 MHz is two
; orders of magnitude, so the detector cannot misfire on the host this
; backend actually targets (a 1 MHz C64 with RR-Net, or VICE).
; NOT MEASURED BY ME: I have no rig access, so that is a static cycle
; argument, not a stopwatch. The one live number that bears on it is the
; red/green lane's Phase 3 run against the old 120-jiffy budget, which
; returned in 2.01 s against a 2.00 s nominal — a 10 ms overshoot, i.e. a
; final iteration well under one jiffy, which is consistent with the above
; but does not pin the iteration count.
; The residual corner, stated: on a MUCH faster host (a 48 MHz U64 running
; an ip65 build) 256 iterations need >3125 cycles each to still span a
; jiffy, and a small payload might not reach that. The consequence is a
; TRUNCATED BUDGET, which is worse than a mislabelled one and is the honest
; way to say it. The detector does not merely rename the failure: reaching
; the check with elapsed still zero ENDS the pump, so the effective budget
; collapses from 30 jiffies to however long 256 iterations happen to take —
; roughly 11 ms for a 32-byte keepalive at 48 MHz. That is short of ip65's
; OWN first ARP retransmit at 100 ms, so the pump would give up before the
; driver had even re-asked. Unreachable today: there is no 48 MHz ip65 path,
; and on such a host a healthy link resolves ARP within a handful of
; iterations and never reaches the check. If one ever appears, raise
; IP65_ARP_STALL_ITERS rather than the budget — the constant is the thing
; that is calibrated to host speed.
; Detection latency on a genuinely dead clock is 256 iterations, i.e. a few
; hundred milliseconds to ~2.5 s at 1 MHz depending on payload size. Bounded,
; and only on the path where the wall clock has already failed.
;
; 24-HOUR JIFFY ROLLOVER, worked through rather than hand-waved. The KERNAL
; resets $A0-$A2 from 5,183,999 to 0 once a day. This routine subtracts only
; the low 16 bits, and 5,184,000 mod 65,536 = 6,656, so a pump straddling
; that instant computes elapsed = (real_elapsed - 6,656) mod 65,536, which
; for any real_elapsed below the budget is 58,880 or more — high byte $E6.
; The high-byte test below therefore fires and the pump ends immediately with
; $48. The failure is deterministic and one-directional: a rollover can only
; CUT a budget short, never extend one, because any wrap forces a non-zero
; high byte. Worst case is one send per day that gives up early instead of
; retrying for half a second, on the already-failing path, returning a proper
; code rather than hanging. Left as is: guarding it costs bytes and branches
; to convert a safe-direction, once-a-day early exit into a slightly later
; early exit.
;
; RE-ENTRANCY. ip65_process is the only pump the stub exposes (jump table
; +3); there is no narrower arp-only or receive-free primitive, and adding
; one would mean relinking the blob and moving every fixed address in
; ip65_symbols.inc. ip65_process therefore dispatches inbound IP through
; ip_process -> udp_process -> net_udp_recv_cb, i.e. it re-enters OUR
; receive path from inside a send. That is not safe: session_handle_packet
; clears udp_recv_ready and then works out of udp_recv_buf, and the type-3
; and type-4 legs can reach net_udp_send while that buffer is still live —
; a datagram taken in here would overwrite it under the caller. So the
; callback is disarmed for the duration: ip65_send_pump is set across the
; loop and net_udp_recv_cb returns immediately while it is set. Inbound UDP
; is DROPPED during the pump; ARP replies and ARP requests are still handled
; (they never reach the UDP callback), which is the whole point of pumping.
;
; WHAT THAT DROP ACTUALLY COSTS, stated without euphemism. An earlier version
; of this comment said "every message type is retransmitted by the peer".
; That is false. WireGuard retransmits HANDSHAKE INITIATIONS (REKEY_TIMEOUT,
; every 5 s up to REKEY_ATTEMPT_TIME); it does NOT retransmit Type 4
; transport data. So the cold-handshake case this routine was written for
; loses nothing — a dropped Type 2 response is re-driven by the next
; initiation. But the eviction case does: a keepalive sent to a gateway whose
; ARP row has been pushed out of ip65's 8-entry cache pumps for up to
; IP65_ARP_BUDGET_JIFFIES, and every tunnel datagram that arrives in that
; window is discarded and is GONE. Nothing at this layer will ask for it
; again; only an inner protocol that retransmits on its own (TCP inside the
; tunnel) recovers, and inner UDP or ICMP simply loses those packets.
; That cost is why the budget is 30 jiffies rather than 120, and why the loss
; is COUNTED rather than silent: ip65_recv_dropped is exported and bumped
; once per discarded datagram, so the price of this design is measurable in
; any post-mortem instead of being an argument in a comment. The pump only
; runs on a send that has already failed, so a healthy warm-cache send never
; enters it and the receive path is untouched in the normal case.
;
; Entered ONLY with ip65's ZP live (we are inside net_udp_send's
; net_save_zp / net_restore_zp window) and with the send operands still
; staged in the blob's own BSS — ip65_process touches eth_inp/eth_outp, not
; udp_send_dest/_port/_len, so each retry only has to re-present the data
; pointer. It must re-call ip65_udp_send rather than some resume entry
; precisely because ip_send nuked the copy in eth_outp.
;
; Input:  C=1 from the failed ip65_udp_send; net_udp_send_ptr staged
; Output: C=0 if a retry got the datagram out, net_last_error = $00
;         C=1 otherwise, net_last_error = $48 (budget) or $01 (no timebase)
; Clobbers: A, X, Y
; =============================================================================
net_arp_pump:
        lda #$01
        sta ip65_send_pump          ; disarm net_udp_recv_cb for the duration
        jsr net_jiffy16
        sta @ap_t0
        stx @ap_t0+1
        lda #$00                    ; 256 decrements back to $00, see header
        sta @ap_stall

@ap_loop:
        jsr ip65_process            ; take the ARP reply in (arp_process)

        lda ip65_send_attempts      ; observability, saturating
        cmp #$ff
        beq :+
        inc ip65_send_attempts
:
        lda net_udp_send_ptr
        ldx net_udp_send_ptr+1
        jsr ip65_udp_send
        bcc @ap_ok

        ; --- wall-clock bound: elapsed jiffies since entry ---
        jsr net_jiffy16
        sec
        sbc @ap_t0
        tay                         ; Y = elapsed low
        txa
        sbc @ap_t0+1
        bne @ap_expired             ; >= 256 jiffies: long past the budget
        cpy #IP65_ARP_BUDGET_JIFFIES
        bcs @ap_expired

        ; --- stopped-clock detector: test the clock, not a proxy ---
        ; Y still holds elapsed-low and the high byte is known 0 here, so
        ; elapsed == 0 means the jiffy has not moved since entry.
        dec @ap_stall
        bne @ap_loop                ; not at the check point yet
        tya
        bne @ap_loop                ; the clock HAS moved — trust it

        lda #NET_ERR_TIMEBASE_STOPPED
        sta net_last_error
        jmp @ap_fail

@ap_expired:
        lda #NET_ERR_IP65_WAIT_TIMEOUT
        sta net_last_error
@ap_fail:
        lda #$00
        sta ip65_send_pump
        sec
        rts

@ap_ok:
        lda #$00
        sta ip65_send_pump
        clc
        rts

@ap_t0:    .word 0                  ; jiffy snapshot at entry
@ap_stall: .byte 0                  ; iterations left before the clock test

; =============================================================================
; net_jiffy16 - read the low 16 bits of the KERNAL jiffy clock coherently
;
; The jiffy is stored big-endian at $A0(hi)/$A1(mid)/$A2(lo) and is bumped
; by the 60 Hz IRQ, so a naive two-byte read can straddle the $A2 wrap and
; come back 256 jiffies short — which would silently stretch a 2.0 s budget
; to 6.3 s once every 256 ticks. Re-read the mid byte and retry if it moved.
;
; Output: A = $A2 (low), X = $A1 (mid). Clobbers: A, X
; =============================================================================
net_jiffy16:
        lda $a1
        sta @j_mid
        lda $a2
        ldx $a1
        cpx @j_mid
        bne net_jiffy16
        rts
@j_mid:  .byte 0

; =============================================================================
; net_udp_recv_cb - UDP receive callback
; Called by ip65 DURING ip65_process while ip65's ZP is active.
; DO NOT touch crypto ZP. Only copy data to udp_recv_buf.
;
; ip65 provides incoming data at udp_inp + 8 (udp_data offset).
; Length from UDP header at udp_inp + 4 (network byte order, minus 8 for hdr).
; Source IP from ip_inp + 12 (source IP in IP header).
; =============================================================================
net_udp_recv_cb:
        ; #120: net_arp_pump calls ip65_process from INSIDE net_udp_send to
        ; take in an ARP reply, and ip65_process dispatches inbound UDP
        ; straight back here. The caller of net_udp_send may still be working
        ; out of udp_recv_buf (session_handle_packet clears udp_recv_ready
        ; before it reads the packet), so taking a datagram in here would
        ; overwrite live data under it. Drop it — the peer retransmits, and
        ; ARP is handled by arp_process, which never reaches this callback.
        lda ip65_send_pump
        beq @cb_live
        lda ip65_recv_dropped   ; count the cost of the disarm, saturating
        cmp #$ff
        beq @cb_drop
        inc ip65_recv_dropped
@cb_drop:
        rts
@cb_live:

        ; read UDP payload length from header (network byte order)
        ; udp_inp + udp_len = total UDP length including 8-byte header
        lda ip65_udp_inp + 4    ; length high byte (network order)
        sta udp_recv_len+1
        lda ip65_udp_inp + 5    ; length low byte
        sec
        sbc #8                  ; subtract UDP header
        sta udp_recv_len
        bcs :+
        dec udp_recv_len+1
:
        ; cap at 1500 bytes (our buffer size)
        lda udp_recv_len+1
        cmp #>(1500)            ; = $05
        bcc @copy               ; high byte < 5, fits
        bne @too_large          ; high byte > 5, too large
        lda udp_recv_len
        cmp #<(1500)            ; = $DC
        bcc @copy               ; fits
        beq @copy               ; exactly 1500

@too_large:
        lda #<(1500)
        sta udp_recv_len
        lda #>(1500)
        sta udp_recv_len+1

@copy:
        ; Check for zero length
        lda udp_recv_len
        ora udp_recv_len+1
        beq @done

        ; 16-bit copy using self-modifying code (ip65 owns ZP pointers).
        ;
        ; §13.3 (c64-lib-contract): the count is a two-byte quantity and is
        ; handled as one. The previous form split it into a page loop driven
        ; by `ldx udp_recv_len+1` and a remainder loop driven by
        ; `ldx udp_recv_len` — arithmetically sound, but it is the exact
        ; "one-byte register holding a piece of a two-byte length" habit
        ; that produced the c64-https 255-byte rx clamp (their PR #27), and
        ; the two loops had to be kept consistent by hand. Now: one loop,
        ; one 16-bit countdown in udp_copy_rem, Y is only the page offset
        ; and the SMC bases advance when it wraps. Same shape as the UCI
        ; adapter's receive loop.
        lda udp_recv_len
        sta udp_copy_rem
        lda udp_recv_len+1
        sta udp_copy_rem+1

        lda #<(ip65_udp_inp + 8)
        sta @cp_ld+1
        lda #>(ip65_udp_inp + 8)
        sta @cp_ld+2
        lda #<udp_recv_buf
        sta @cp_st+1
        lda #>udp_recv_buf
        sta @cp_st+2

        ldy #0
@cp_loop:
        lda udp_copy_rem
        ora udp_copy_rem+1
        beq @copy_done
@cp_ld: lda ip65_udp_inp + 8,y     ; SMC: base patched above
@cp_st: sta udp_recv_buf,y         ; SMC: base patched above
        iny
        bne @cp_nohi
        inc @cp_ld+2
        inc @cp_st+2
@cp_nohi:
        lda udp_copy_rem
        bne @cp_noborrow
        dec udp_copy_rem+1
@cp_noborrow:
        dec udp_copy_rem
        jmp @cp_loop
@copy_done:
        ; copy source IP (ip_inp + 12 = source IP in IP header)
        ; ip65_udp_inp is ip_inp + ip_data(20), so ip_inp = udp_inp - 20
        ; source IP at ip_inp + 12 = udp_inp - 8
        lda ip65_udp_inp - 8
        sta udp_recv_src_ip
        lda ip65_udp_inp - 7
        sta udp_recv_src_ip+1
        lda ip65_udp_inp - 6
        sta udp_recv_src_ip+2
        lda ip65_udp_inp - 5
        sta udp_recv_src_ip+3

        ; copy source port from UDP header (network byte order)
        lda ip65_udp_inp + 0    ; source port high byte
        sta udp_recv_src_port
        lda ip65_udp_inp + 1    ; source port low byte
        sta udp_recv_src_port+1

        ; set ready flag
        lda #1
        sta udp_recv_ready

@done:
        rts

; =============================================================================
; net_print_ip - display current IP address in dotted decimal
; =============================================================================
net_print_ip:
        lda ip65_cfg_ip
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+1
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+2
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+3
        jsr @print_byte
        lda #$0d
        jsr chrout
        rts

; print decimal byte value (0-255)
@print_byte:
        sta @pb_val
        ; hundreds
        ldx #0
        sec
@pb_100:
        sbc #100
        bcc @pb_100d
        inx
        jmp @pb_100
@pb_100d:
        adc #100
        cpx #0
        beq @pb_tens            ; skip leading zero
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_tens:
        ldx #0
        sec
@pb_10:
        sbc #10
        bcc @pb_10d
        inx
        jmp @pb_10
@pb_10d:
        adc #10
        cpx #0
        bne @pb_t_out
        ldy @pb_val
        cpy #10
        bcc @pb_ones            ; value < 10, skip tens
@pb_t_out:
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_ones:
        ora #$30
        jsr chrout
        rts
@pb_val: .byte 0

; =============================================================================
; ZP save/restore — 26 bytes ($02-$1B)
; =============================================================================
net_save_zp:
        ldx #ip65_zp_size - 1
:       lda ip65_zp_start,x
        sta zp_save_buf,x
        dex
        bpl :-
        rts

net_restore_zp:
        ldx #ip65_zp_size - 1
:       lda zp_save_buf,x
        sta ip65_zp_start,x
        dex
        bpl :-
        rts

; =============================================================================
; net module data
; =============================================================================
.segment "BSS"

net_udp_send_ptr:       .res 2      ; pointer for udp_send wrapper
net_udp_send_len: .res 2      ; length for udp_send wrapper
udp_copy_rem:       .res 2      ; 16-bit countdown for the rx copy (§13.3)

; --- listener ownership (issue #84) ------------------------------------------
; The one slot we hold in ip65's 4-entry udp_cb* table, so net_udp_close can
; hand back exactly what net_udp_listen took. Adapter-internal — not part of
; the §13.1 surface — exported only so a test can observe the claim.
ip65_listening:     .res 1      ; 1 = we hold a listener slot
ip65_listen_port:   .res 2      ; the port it was registered on (LE, as passed)

; --- error channel + send observability (issue #120) -------------------------
; See the code table in the file header. All three are DMA-readable: BSS here
; is MAIN_AREA_LO, which the cfg emits as file-backed $00 fill.
net_last_error:      .res 1     ; last failure code, $00 = OK
ip65_send_pump:      .res 1     ; 1 = net_arp_pump is pumping ip65_process;
                                ; net_udp_recv_cb is disarmed while set
ip65_send_attempts:  .res 1     ; ip65_udp_send calls made by the LAST
                                ; net_udp_send, saturating at $FF. 1 = the
                                ; ARP cache was warm and nothing was retried;
                                ; >1 is the #120 path having fired.
ip65_recv_dropped:   .res 1     ; datagrams discarded by net_udp_recv_cb
                                ; because a pump was in progress, saturating
                                ; at $FF. CUMULATIVE since net_init, unlike
                                ; ip65_send_attempts which is per-send: the
                                ; point is a running total of what the
                                ; callback disarm has actually cost this
                                ; session. Non-zero means real inbound
                                ; traffic was thrown away (see net_arp_pump).
