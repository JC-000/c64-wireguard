#!/usr/bin/env python3
"""Prove on real hardware that a config reload actually moves the peer (#65).

    U64_ALLOW_MUTATE=1 python3.13 tools/test_config_reload_live.py --host <ip>
    U64_ALLOW_MUTATE=1 python3.13 tools/test_config_reload_live.py --host <ip> --soak 8

WHAT #65 WAS. Under UCI the socket is CONNECTION-ORIENTED: UDP_CONNECT pins it
to one peer address and net_udp_send short-circuits on uci_socket_open without
ever revisiting that. Loading a config that named a new peer therefore left
every subsequent datagram going to the OLD peer, silently — the reload looked
like it had taken effect. PR #75 made config_load compare the 6-byte endpoint
run as it copies it and call net_udp_close when, and only when, it moved.

WHY THE EXISTING COVERAGE IS NOT ENOUGH. tools/test_uci_backend_stub.py tests
4 and 5 run in VICE, where there is no UCI at all: every $DF1x reads $FF, so
net_udp_close's uci_wait_idle times out and the TIMEOUT LEG clears the
bookkeeping. uci_socket_open does go 1 -> 0, so the decision logic is proven —
but via a path that never issues SOCKET_CLOSE, never talks to firmware, and
would report exactly the same result if the real close were broken. And
nothing anywhere asserted the property that actually matters: that the next
datagram goes to the NEW peer.

WHAT THIS ASSERTS, on live firmware, in this order:

  1. Baseline round trip to peer A over an ACTIVE session (so "it moved"
     later means something).
  2. NO-CHANGE MUST NOT CLOSE. config_load with the endpoint untouched leaves
     uci_socket_open and uci_socket_id exactly as they were. This matters
     more on hardware than in VICE: a spurious close/reopen churns a real
     firmware socket slot out of an 8-deep pool the firmware does not
     reclaim (GideonZ/1541ultimate#808).
  3. THE CLOSE IS REAL, NOT A TIMEOUT. Move cfg_peer_endpoint_port, JSR
     config_load, and require all three of: uci_socket_open 1 -> 0,
     net_last_error untouched (a sentinel we plant survives — so it is
     neither $89 UCI_ERR_WAIT_TIMEOUT nor $82 UCI_ERR_CMD_FAILED), and
     wall-clock well under the ~1.5 s TOD budget that uci_wait_idle would
     burn before giving up. The VICE path fails two of those three.
  4. THE DATAGRAM FOLLOWS THE ENDPOINT. Drive do_handshake — the same entry
     the 'H' key uses — and require the Type-1 to land on socket B while
     socket A, still bound and still listening, receives NOTHING. That is
     the only assertion here that would have caught #65 in the field.
  5. The reconnected socket really works: complete the handshake through B to
     SESSION_ACTIVE and run a full Type-4 round trip over it.

WHY IT HIJACKS _hand_back_to_c64. test_uci_handshake_live's post_session_hook
fires only under --chat, and --chat hands the machine back to its own main
loop first — which is the one thing that permanently ends host-side
trampoline control. This test needs that control AFTER the session is up, to
JSR config_load and do_handshake at chosen moments. So it replaces
_hand_back_to_c64 with a no-op for the duration: the C64 stays parked in the
trampoline and we keep driving it. Everything else — build, fingerprint,
upload, staged config, handshake, device lock, teardown — is reused as-is.

SOAK MODE (--soak N) is a separate question about the same box: issue #58,
"the device degrades after ~5 program loads and needs a wall power cycle".
It runs N consecutive PRG loads, each driven to net_init + net_udp_listen +
a real UDP_CONNECT (asserted by a datagram arriving at a host sink), and
reports a per-iteration table. No handshake, no crypto — the point is the
socket path, which is where #58 stalled.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_uci_handshake_live as live                       # noqa: E402
from test_uci_handshake_live import (                        # noqa: E402
    SESSION_ACTIVE, SESSION_HS_SENT,
)
from test_uci_udp_echo_live import (                         # noqa: E402
    SEND_BUF, STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_TIMEOUT,
    _install_trampoline, _local_ip_for, _run_step,
)

from c64_test_harness import (                               # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, enable_uci, get_uci_enabled,
    probe_u64, write_bytes,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (    # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (   # noqa: E402
    recover, runner_health_check, set_reu, set_turbo_mhz, get_turbo_mhz,
)

log = live.log

# src/net/uci/uci_errors.inc
UCI_ERR_CMD_FAILED = 0x82
UCI_ERR_WAIT_TIMEOUT = 0x89

# Planted in net_last_error before each config_load. Not a real error code:
# if it survives, nothing on the close path wrote an error, which is the
# cleanest possible statement of "the SOCKET_CLOSE succeeded".
ERR_SENTINEL = 0xEE

# uci_wait_idle's wall-clock budget is ~1.5 s of CIA1 TOD (see #145 /
# uci_cmd.s). A close that returns in a small fraction of that cannot have
# gone through the timeout leg. Generous enough to absorb the host's HTTP
# round trips, which dominate the measurement at 48 MHz.
TOD_BUDGET_S = 1.5
FAST_CLOSE_S = 0.6

# Step ids, distinct from every id test_uci_handshake_live already uses
# (0x11/0x22/0x33/0x44/0x55/0x66/0x77/0x88/0x99/0xC0).
STEP_CFG_SAME = 0xA1
STEP_CFG_MOVED = 0xA2
STEP_REHANDSHAKE = 0xA3
STEP_CLOSE = 0xA4
STEP_SEND = 0xA5

SOAK_PAYLOAD = bytes(0x40 + (i % 32) for i in range(32))

# Type-2 arrives within a second; hs_process_response is ~35 s at 48 MHz.
# STAGE2_ACTIVE_WAIT's 1800 s is sized for 1 MHz and would hide a hang here.
REKEY_ACTIVE_WAIT = 600.0

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          + (f"\n          {detail}" if detail else ""), flush=True)
    return bool(ok)


def _report() -> int:
    failed = [label for ok, label in results if not ok]
    print("\n" + "=" * 66, flush=True)
    print(f"{len(results) - len(failed)}/{len(results)} checks passed",
          flush=True)
    for label in failed:
        print(f"  FAILED: {label}", flush=True)
    print("=" * 66, flush=True)
    return 1 if failed else 0


def _tap(rt) -> list[tuple[str, int, object]]:
    """Record every WireGuard packet the responder thread dispatches.

    Type-1 and Type-4 are the only types the C64 ever emits, and run()
    dispatches both through these two instance methods, so shadowing them
    counts everything that arrives without touching the thread's logic.
    """
    seen: list[tuple[str, int, object]] = []
    orig1, orig4 = rt._handle_type1, rt._handle_type4

    def t1(data, src):
        seen.append(("T1", len(data), src))
        return orig1(data, src)

    def t4(data):
        seen.append(("T4", len(data), None))
        return orig4(data)

    rt._handle_type1, rt._handle_type4 = t1, t4
    return seen


def _sock_state(tr, L) -> tuple[int, int, int]:
    """(uci_socket_open, uci_socket_id, net_last_error)."""
    return (tr.read_memory(L["uci_socket_open"], 1)[0],
            tr.read_memory(L["uci_socket_id"], 1)[0],
            tr.read_memory(L["net_last_error"], 1)[0])


def _timed_step(tr, *, step_id: int, target: int, timeout: float) -> tuple[int, float]:
    t0 = time.monotonic()
    carry = _run_step(tr, step_id=step_id, target=target, timeout=timeout)
    return carry, time.monotonic() - t0


# ── The #65 probe ─────────────────────────────────────────────────────────

def build_probe(args):
    def probe(tr, L, rt, responder) -> int:
        a_seen = _tap(rt)
        port_a = rt.port
        local_ip = _local_ip_for(args.host)

        print(f"\n=== 0. baseline: ACTIVE session pinned to peer "
              f"{local_ip}:{port_a} ===", flush=True)
        open0, id0, err0 = _sock_state(tr, L)
        log.info("uci_socket_open=%d uci_socket_id=$%02X net_last_error=$%02X",
                 open0, id0, err0)
        if not check(open0 == 1,
                     "a real UCI socket is open after the handshake",
                     f"uci_socket_open={open0} uci_socket_id=${id0:02X}"):
            return _report()

        # Round trip on A, so "the traffic moved" later is a change from a
        # known-working state rather than from an unknown one.
        before = len(a_seen)
        carry, dt = _timed_step(tr, step_id=STEP_SEND, target=L["do_send_test"],
                                timeout=120.0)
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and len(a_seen) == before:
            time.sleep(0.2)
        check(len(a_seen) > before and carry == 0,
              "peer A receives the C64's Type-4 before the endpoint moves",
              f"do_send_test carry={carry} in {dt:.2f}s; "
              f"A saw {[s[0] for s in a_seen[before:]]}")

        # ── 1. no-change config_load must NOT close ──
        print("\n=== 1. config_load with the endpoint UNCHANGED ===",
              flush=True)
        live_ep = bytes(tr.read_memory(L["wg_peer_ip"], 6))
        cfg_ep = bytes(tr.read_memory(L["cfg_peer_endpoint_ip"], 6))
        log.info("wg_peer_ip..port=%s cfg_peer_endpoint=%s",
                 live_ep.hex(" "), cfg_ep.hex(" "))
        check(live_ep == cfg_ep,
              "precondition: live endpoint already equals the config",
              f"live={live_ep.hex(' ')} cfg={cfg_ep.hex(' ')}")

        write_bytes(tr, L["net_last_error"], bytes([ERR_SENTINEL]))
        carry, dt_same = _timed_step(tr, step_id=STEP_CFG_SAME,
                                     target=L["config_load"], timeout=30.0)
        open1, id1, err1 = _sock_state(tr, L)
        log.info("after no-change config_load: open=%d id=$%02X err=$%02X "
                 "(%.2fs)", open1, id1, err1, dt_same)
        check(open1 == 1 and id1 == id0,
              "unchanged endpoint leaves the socket ALONE (no slot churn)",
              f"uci_socket_open {open0}->{open1}, "
              f"uci_socket_id ${id0:02X}->${id1:02X}")
        check(err1 == ERR_SENTINEL,
              "no-change config_load touched no error state",
              f"net_last_error=${err1:02X} (sentinel ${ERR_SENTINEL:02X})")

        # ── 2. the move: a REAL close ──
        rt_b = live._ResponderThread(responder, bind_addr="", port=0)
        rt_b.start()
        b_seen = _tap(rt_b)
        port_b = rt_b.port
        print(f"\n=== 2. move cfg_peer_endpoint_port {port_a} -> {port_b}, "
              f"then config_load ===", flush=True)
        write_bytes(tr, L["cfg_peer_endpoint_port"],
                    bytes([port_b >> 8, port_b & 0xFF]))
        write_bytes(tr, L["net_last_error"], bytes([ERR_SENTINEL]))
        carry, dt_moved = _timed_step(tr, step_id=STEP_CFG_MOVED,
                                      target=L["config_load"], timeout=30.0)
        open2, id2, err2 = _sock_state(tr, L)
        new_ep = bytes(tr.read_memory(L["wg_peer_ip"], 6))
        log.info("after moved config_load: open=%d id=$%02X err=$%02X "
                 "wg_peer=%s (%.2fs)", open2, id2, err2, new_ep.hex(" "),
                 dt_moved)

        check(open2 == 0,
              "moved endpoint HANDS THE SOCKET BACK (uci_socket_open 1 -> 0)",
              f"uci_socket_open {open1}->{open2}, "
              f"uci_socket_id ${id1:02X}->${id2:02X}")
        check(new_ep == bytes(tr.read_memory(L["cfg_peer_endpoint_ip"], 6)),
              "the new endpoint was stored in wg_peer_ip/wg_peer_port",
              f"wg_peer={new_ep.hex(' ')} "
              f"(port {int.from_bytes(new_ep[4:], 'big')} == {port_b})")
        # The two discriminators between a real SOCKET_CLOSE and the VICE
        # timeout leg, which reaches the same uci_socket_open=0 by giving up.
        check(err2 not in (UCI_ERR_WAIT_TIMEOUT, UCI_ERR_CMD_FAILED)
              and err2 == ERR_SENTINEL,
              "the close reported NO error — not $89 WAIT_TIMEOUT, not $82",
              f"net_last_error=${err2:02X}; sentinel ${ERR_SENTINEL:02X} "
              f"survived, so nothing on the close path wrote an error")
        check(dt_moved < FAST_CLOSE_S,
              f"the close completed in << the {TOD_BUDGET_S}s TOD budget",
              f"{dt_moved:.2f}s with the close vs {dt_same:.2f}s without; "
              f"uci_wait_idle would have burned >={TOD_BUDGET_S}s before "
              f"clearing the bookkeeping on a timeout")

        # ── 3. the datagram follows the endpoint ──
        print("\n=== 3. does the next datagram go to B, and NOT to A? ===",
              flush=True)
        a_before = len(a_seen)
        b_before = len(b_seen)
        # do_handshake is literally the 'H' menu entry: entropy_init, a SID
        # settle delay, session_initiate. Its carry is net_udp_send's carry
        # (session_initiate's trailing lda/sta do not touch it), so carry=0
        # already means the UDP_CONNECT to the new address succeeded.
        log.info("driving do_handshake (the 'H' path) — Type-1 must land on "
                 "port %d, not %d", port_b, port_a)
        t0 = time.monotonic()
        carry = live._run_step_slow(
            tr, step_id=STEP_REHANDSHAKE, target=L["do_handshake"],
            timeout=live.HS_INIT_TIMEOUT,
            probes={"wg_state": L["wg_state"],
                    "net_err": L["net_last_error"],
                    "sock_open": L["uci_socket_open"]})
        dt = time.monotonic() - t0
        log.info("do_handshake returned in %.1fs (carry=%d)", dt, carry)

        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and len(b_seen) == b_before:
            time.sleep(0.25)
        got_b = b_seen[b_before:]
        got_a = a_seen[a_before:]
        err3 = tr.read_memory(L["net_last_error"], 1)[0]
        check(carry == 0,
              "do_handshake succeeded against the new endpoint",
              f"carry={carry} in {dt:.1f}s, net_last_error=${err3:02X}")
        check(any(k == "T1" for k, _, _ in got_b),
              f"the Type-1 ARRIVED on the NEW peer (port {port_b})",
              f"B saw {[(k, n) for k, n, _ in got_b]}, "
              f"src={got_b[0][2] if got_b else None}")
        check(not got_a,
              f"the OLD peer (port {port_a}) received NOTHING after the move",
              f"A saw {[(k, n) for k, n, _ in got_a]} in the same window "
              f"(socket still bound and listening throughout)")
        open3 = tr.read_memory(L["uci_socket_open"], 1)[0]
        check(open3 == 1,
              "net_udp_send re-issued UDP_CONNECT against the new address",
              f"uci_socket_open {open2}->{open3}, "
              f"uci_socket_id ${tr.read_memory(L['uci_socket_id'], 1)[0]:02X}")

        # ── 4. the reconnected socket actually works ──
        print("\n=== 4. full round trip over the reconnected socket ===",
              flush=True)
        state = tr.read_memory(L["wg_state"], 1)[0]
        if state != SESSION_HS_SENT:
            check(False, "wg_state = HS_SENT after the re-initiation",
                  f"wg_state={state}")
            return _report()
        deadline = time.monotonic() + REKEY_ACTIVE_WAIT
        polls = 0
        while time.monotonic() < deadline:
            _run_step(tr, step_id=live.STEP_POLL, target=L["net_poll"],
                      timeout=live.POLL_TIMEOUT + 1.0)
            polls += 1
            if tr.read_memory(L["udp_recv_ready"], 1)[0] != 0:
                live._run_step_slow(tr, step_id=live.STEP_HANDLE,
                                    target=L["session_handle_packet"],
                                    timeout=live.HANDLE_TIMEOUT)
                state = tr.read_memory(L["wg_state"], 1)[0]
                log.info("session_handle_packet -> wg_state=%d", state)
                if state != SESSION_HS_SENT:
                    break
            time.sleep(0.4)
        if not check(state == SESSION_ACTIVE,
                     "SESSION_ACTIVE re-established through peer B",
                     f"wg_state={state} after {polls} polls"):
            return _report()
        rc3 = live._run_stage3(tr, L, rt_b, responder)
        check(rc3 == 0,
              "Type-4 transport round trip works over the new endpoint",
              "forward (C64 -> B) is the gate; reverse (B -> C64) is logged")
        check(not a_seen[a_before:],
              f"peer A STILL received nothing, end to end",
              f"A total across the whole run: {len(a_seen)} packets, "
              f"all before the move")

        rt_b.stop()
        return _report()

    return probe


# ── #58 soak ──────────────────────────────────────────────────────────────

SOAK_LABELS = ("main_loop", "net_init", "net_dhcp_acquire", "net_udp_listen",
               "net_udp_send", "net_udp_close", "net_udp_send_len",
               "net_udp_dest_ip", "net_udp_dest_port", "wg_local_port",
               "net_last_error", "uci_socket_open", "uci_socket_id",
               "boot_ready")


def run_soak(args) -> int:
    """N consecutive PRG loads, each driven to a real UDP_CONNECT.

    #58's signature was a stall: the first UDP_CONNECT after roughly five
    loads never returned, and only wall power cleared it. With the CIA1 TOD
    fix a wedged firmware surfaces as $89 in ~1.5 s instead of hanging, so
    BOTH shapes are caught here — a carry, a $89, or a datagram that never
    reaches the sink.

    The socket is ABANDONED between loads by default (see --soak-close): the
    root cause recorded for #58 is a firmware leak from connected UDP sockets
    nobody closed, so a soak that tidily closed each one would prove the
    opposite of what is being asked. What is supposed to make abandonment
    survivable now is GideonZ/1541ultimate#814's close-all-on-C64-reset,
    which run_prg triggers on every iteration.
    """
    pr = probe_u64(args.host)
    if not pr.reachable:
        live._skip(f"U64E {args.host} not reachable: {pr.error}")
    live._build_uci()

    root = live.PROJECT_ROOT
    labels = Labels.from_file(str(root / "build" / "labels.txt"))
    L = dict(labels)
    missing = [n for n in SOAK_LABELS if n not in L]
    if missing:
        print(f"FATAL: missing labels: {missing}", file=sys.stderr)
        return 1
    prg_bytes = (root / "build" / "wireguard.prg").read_bytes()
    import hashlib
    log.info("PRG fingerprint: sha256=%s reu_mul_init=%s -> %s build",
             hashlib.sha256(prg_bytes).hexdigest()[:32],
             "reu_mul_init" in L,
             "REU" if "reu_mul_init" in L else "onchip/REU=0")

    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("", 0))
    sink.settimeout(6.0)
    sink_port = sink.getsockname()[1]
    local_ip = _local_ip_for(args.host)
    log.info("soak sink bound on %s:%d", local_ip, sink_port)

    lock = DeviceLock(args.host)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        live._skip(str(e))

    rows: list[tuple[int, str, float, str]] = []
    try:
        client = Ultimate64Client(host=args.host, password=args.password,
                                  timeout=30.0)
        tr = Ultimate64Transport(host=args.host, password=args.password,
                                 timeout=30.0, client=client)
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner wedged: %s — recovering", exc)
            recover(client)
            runner_health_check(client)
        if not get_uci_enabled(client):
            enable_uci(client)
            time.sleep(0.5)
        try:
            set_reu(client, False)
        except Exception as exc:                              # noqa: BLE001
            log.warning("set_reu failed (continuing): %s", exc)
        time.sleep(0.5)
        set_turbo_mhz(client, args.turbo)
        if get_turbo_mhz(client) != args.turbo:
            live._skip(f"turbo did not stick at {args.turbo} MHz")

        for i in range(1, args.soak + 1):
            print(f"\n--- soak load {i}/{args.soak} ---", flush=True)
            t0 = time.monotonic()
            verdict, note = "OK", ""
            try:
                client.run_prg(prg_bytes)
                live._wait_boot_ready(tr, L)
                _install_trampoline(tr, L["main_loop"])

                c = _run_step(tr, step_id=STEP_INIT, target=L["net_init"])
                if c != 0:
                    raise RuntimeError(
                        "net_init C=1 net_last_error=$%02X"
                        % tr.read_memory(L["net_last_error"], 1)[0])
                c = _run_step(tr, step_id=STEP_DHCP,
                              target=L["net_dhcp_acquire"])
                if c != 0:
                    note = ("dhcp C=1 ($%02X, display-only)"
                            % tr.read_memory(L["net_last_error"], 1)[0])
                lp = 51820
                if _run_step(tr, step_id=STEP_LISTEN,
                             target=L["net_udp_listen"],
                             reg_a=lp & 0xFF, reg_x=lp >> 8) != 0:
                    raise RuntimeError("net_udp_listen C=1")

                # Force a real UDP_CONNECT + SOCKET_WRITE. This is the exact
                # operation #58 stalled on.
                write_bytes(tr, L["net_udp_dest_ip"],
                            bytes(int(o) for o in local_ip.split(".")))
                write_bytes(tr, L["net_udp_dest_port"],
                            bytes([sink_port >> 8, sink_port & 0xFF]))
                write_bytes(tr, L["wg_local_port"],
                            bytes([lp & 0xFF, lp >> 8]))
                write_bytes(tr, SEND_BUF, SOAK_PAYLOAD)
                write_bytes(tr, L["net_udp_send_len"],
                            struct.pack("<H", len(SOAK_PAYLOAD)))
                write_bytes(tr, L["net_last_error"], bytes([ERR_SENTINEL]))
                t_send = time.monotonic()
                c = _run_step(tr, step_id=STEP_SEND, target=L["net_udp_send"],
                              reg_a=SEND_BUF & 0xFF, reg_x=SEND_BUF >> 8,
                              timeout=STEP_TIMEOUT + 5.0)
                dt_send = time.monotonic() - t_send
                err = tr.read_memory(L["net_last_error"], 1)[0]
                opened = tr.read_memory(L["uci_socket_open"], 1)[0]
                if c != 0 or err == UCI_ERR_WAIT_TIMEOUT:
                    raise RuntimeError(
                        f"net_udp_send C={c} net_last_error=${err:02X} "
                        f"({dt_send:.2f}s) — #58 shape")
                if opened != 1:
                    raise RuntimeError(f"uci_socket_open={opened} after send")
                try:
                    data, src = sink.recvfrom(2048)
                except socket.timeout:
                    raise RuntimeError("sink never received the datagram")
                if data != SOAK_PAYLOAD:
                    raise RuntimeError(
                        f"sink got {len(data)}B, wanted {len(SOAK_PAYLOAD)}B")
                note = (note + " " if note else "") + \
                    f"connect+send {dt_send:.2f}s from {src[0]}:{src[1]}"

                # DEFAULT: ABANDON the socket, which is what #58 was about.
                # The app never closes on reset either, so each load leaves a
                # connected UDP socket behind in the firmware's table — the
                # exact accumulation that used to wedge the box after ~3.
                # --soak-close hands the slot back instead, which is good
                # hygiene but would MASK a leak, so it is not the default.
                if args.soak_close:
                    if _run_step(tr, step_id=STEP_CLOSE,
                                 target=L["net_udp_close"]) != 0:
                        note += (" close C=1 ($%02X)"
                                 % tr.read_memory(L["net_last_error"], 1)[0])
                    else:
                        note += " closed"
                else:
                    note += " abandoned"
            except Exception as exc:                          # noqa: BLE001
                verdict, note = "STALL", f"{type(exc).__name__}: {exc}"
                log.error("soak load %d FAILED: %s", i, note)
            dt = time.monotonic() - t0
            rows.append((i, verdict, dt, note))
            print(f"  load {i}: {verdict} ({dt:.1f}s) {note}", flush=True)
    finally:
        lock.release()
        sink.close()

    print("\n" + "=" * 66, flush=True)
    print(f"{'load':>4}  {'verdict':<8} {'wall':>7}  note", flush=True)
    for i, verdict, dt, note in rows:
        print(f"{i:>4}  {verdict:<8} {dt:>6.1f}s  {note}", flush=True)
    bad = [r for r in rows if r[1] != "OK"]
    print(f"\n{len(rows) - len(bad)}/{len(rows)} loads reached net_init + a "
          f"live UDP_CONNECT", flush=True)
    if bad:
        print("STALLED LOADS: " + ", ".join(str(r[0]) for r in bad),
              flush=True)
    print("=" * 66, flush=True)
    return 1 if bad else 0


# ── entry point ───────────────────────────────────────────────────────────

def _no_handback(tr, L, main_loop_orig) -> None:
    """Replaces _hand_back_to_c64 so trampoline control SURVIVES the session.

    --chat's contract is that host-side control ends when the C64 gets its
    main loop back. This test needs the opposite: it calls config_load and
    do_handshake by hand after SESSION_ACTIVE. Leaving the machine parked in
    the trampoline is exactly right for that, and nothing here needs the
    C64's own loop — every poll, send and handle below is driven explicitly.
    """
    log.info("handback SUPPRESSED — keeping trampoline control for the "
             "config-reload probe")


def _turbo_down(host: str) -> None:
    """Leave the bench at 1 MHz for whoever has it next."""
    try:
        set_turbo_mhz(Ultimate64Client(host), 1)
    except Exception:                                         # noqa: BLE001
        pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("U64_HOST",
                                                    live.DEFAULT_HOST))
    p.add_argument("--turbo", type=int, default=48)
    p.add_argument("--password", default=os.environ.get("U64_PASSWORD"))
    p.add_argument("--soak", type=int, default=0, metavar="N",
                   help="Instead of the #65 test, run N consecutive PRG "
                        "loads to net_init + UDP_CONNECT (issue #58).")
    p.add_argument("--soak-close", action="store_true",
                   help="Close the socket at the end of each soak iteration. "
                        "Off by default: #58 is a leak of ABANDONED sockets, "
                        "and closing them would hide it.")
    args = p.parse_args()
    if not args.host:
        print("ERROR: pass --host <ip> or set U64_HOST", file=sys.stderr)
        return 2
    if os.environ.get("U64_ALLOW_MUTATE") != "1":
        live._skip("U64_ALLOW_MUTATE != 1 — this test mutates the device")

    # The REU build is broken at 48 MHz on fw 3.15 (#69), and _build_uci()
    # runs unconditionally at tool start unless C64_SKIP_BUILD is set — so
    # without this it would happily replace a correct REU=0 binary with the
    # REU one. C64_SKIP_BUILD=1 still wins if the caller wants the tree as-is.
    os.environ.setdefault("C64_REU", "0")

    if args.soak:
        try:
            return run_soak(args)
        finally:
            _turbo_down(args.host)

    live.post_session_hook = build_probe(args)
    live._hand_back_to_c64 = _no_handback
    sys.argv = ["test_uci_handshake_live.py", "--chat",
                "--host", args.host, "--turbo", str(args.turbo),
                "--reu", "off"]
    if args.password:
        sys.argv += ["--password", args.password]
    try:
        return live.main()
    finally:
        _turbo_down(args.host)


if __name__ == "__main__":
    sys.exit(main())
