#!/usr/bin/env python3
"""Live Ultimate 64 Elite test: end-to-end WireGuard handshake on UCI.

Drives the C64 against a patient Python responder (tools.wg_responder) —
no REKEY/REJECT timeouts on the Python side, so the C64 has all the time
it needs (full handshake ~9 min on hardware).

Stages, gated by ``--stage``:

  1   "Type-1 emitted and accepted by responder" (Type-1 reaches the
      responder, MAC1 validates, noise read_message succeeds). Fast
      finish (~3-4 min C64 wall-clock).
  2   (default) "SESSION_ACTIVE" — full handshake completes: responder
      sends Type-2, C64 decodes it, wg_state transitions to 2. ~7-10 min.

Gates: ``U64_HOST`` (default 10.43.23.81) and ``U64_ALLOW_MUTATE=1``.
Skip exit is 77.

Run::

    U64_HOST=10.43.23.81 U64_ALLOW_MUTATE=1 \\
        /opt/homebrew/bin/python3.13 tools/test_uci_handshake_live.py --stage 1
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, enable_uci, get_uci_enabled,
    probe_u64, write_bytes,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    recover, runner_health_check, set_reu, set_turbo_mhz,
)

# Reuse the trampoline helpers from the echo test (battle-tested).
from test_uci_udp_echo_live import (  # noqa: E402
    BOOT_TIMEOUT, CARRY, GO_FLAG, SENTINEL, STEP_ID, TRAMP,
    SMC_REG_A, SMC_REG_X, SMC_TARG_LO, SMC_TARG_HI,
    STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_POLL, STEP_TIMEOUT,
    _build_trampoline, _build_uci, _install_trampoline, _local_ip_for,
    _run_step, _wait_boot,
)

from wg_responder.keys import generate_keypair  # noqa: E402
from wg_responder.responder import (  # noqa: E402
    MSG_TYPE_INITIATION, MSG_TYPE_RESPONSE, MSG_TYPE_TRANSPORT,
    T1_TOTAL, WireGuardResponder,
)

DEFAULT_HOST = "10.43.23.81"

# Custom step IDs for handshake-specific JSR targets.
STEP_HS_INIT = 0x66        # session_initiate (Type-1 build & send)
STEP_HANDLE = 0x77         # session_handle_packet (Type-2 process)

# Timeouts (wall-clock seconds). Empirically do_handshake at 1 MHz takes
# ~18-20 min (the README's "~9 min" figure was either at turbo or a
# different code path). uci_read_resp_bytes' 16-bit spin-wait alone is
# ~2.7 min at 1 MHz and the SOCKET_WRITE path can hit it multiple times
# when the firmware doesn't return a proper write-count. Long timeouts
# cost only wall-clock.
HS_INIT_TIMEOUT = 1800.0   # do_handshake (entropy_init + session_initiate)
POLL_TIMEOUT = 1.0         # individual net_poll JSR — short, called in a loop
HANDLE_TIMEOUT = 1800.0    # session_handle_packet: hs_process_response is similar
STAGE1_RESPONDER_WAIT = 60.0   # responder side is fast — should be immediate
STAGE2_ACTIVE_WAIT = 1800.0    # max wall-clock to wait for SESSION_ACTIVE

# Session state constants (must match src/wg/session.s).
SESSION_IDLE = 0
SESSION_HS_SENT = 1
SESSION_ACTIVE = 2

REQUIRED_LABELS = (
    "main_loop", "net_init", "net_dhcp", "net_udp_listen",
    "net_poll", "do_handshake", "session_handle_packet",
    "mul_dma_hi", "wg_state", "wg_peer_ip", "wg_peer_port", "wg_local_port",
    "udp_recv_ready", "net_last_error", "net_local_ip",
    "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
    "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
    "cfg_preshared_key", "tunnel_ip", "ping_target_ip", "tai64n_base_time",
)


def _log_err(tr: Ultimate64Transport, L: dict[str, int], step: str) -> None:
    err = tr.read_memory(L["net_last_error"], 1)[0]
    log.info("%s: net_last_error=$%02X", step, err)


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("uci_handshake")


def _skip(reason: str) -> None:
    print(f"SKIP: {reason}")
    sys.exit(77)


def _run_step_slow(
    tr: Ultimate64Transport, *, step_id: int, target: int,
    reg_a: int = 0, reg_x: int = 0, timeout: float = 600.0,
    poll_interval: float = 1.0,
    probes: Optional[dict[str, int]] = None,
) -> int:
    """Like _run_step but polls less aggressively for multi-minute JSRs.

    `probes` is an optional ``{label: address}`` mapping read at each
    heartbeat to expose C64-side progress (e.g. {'wg_state': $7912}).
    """
    t = bytearray(_build_trampoline())
    t[SMC_REG_A], t[SMC_REG_X] = reg_a & 0xFF, reg_x & 0xFF
    t[SMC_TARG_LO], t[SMC_TARG_HI] = target & 0xFF, (target >> 8) & 0xFF
    write_bytes(tr, TRAMP, bytes(t))
    write_bytes(tr, SENTINEL, bytes([0, 0, step_id]))   # SENT, CARRY, STEP_ID
    write_bytes(tr, GO_FLAG, bytes([1]))
    deadline = time.monotonic() + timeout
    last_log = time.monotonic()
    while time.monotonic() < deadline:
        if tr.read_memory(SENTINEL, 1)[0] == step_id:
            carry = tr.read_memory(CARRY, 1)[0]
            log.info("step $%02X done; carry=%d (%.1fs)", step_id, carry,
                     timeout - (deadline - time.monotonic()))
            return carry
        # Heartbeat log every 30s so we can see the test isn't wedged.
        now = time.monotonic()
        if now - last_log >= 30.0:
            elapsed = timeout - (deadline - now)
            extras = ""
            if probes:
                vals = []
                for name, addr in probes.items():
                    b = tr.read_memory(addr, 1)[0]
                    vals.append(f"{name}=${b:02X}")
                extras = " [" + " ".join(vals) + "]"
            log.info("step $%02X still running (%.0fs elapsed)%s",
                     step_id, elapsed, extras)
            last_log = now
        time.sleep(poll_interval)
    got = tr.read_memory(SENTINEL, 1)[0]
    raise TimeoutError(
        f"step ${step_id:02X} timed out after {timeout}s (SENTINEL=${got:02X})"
    )


# ── Patient responder (UDP loop in a daemon thread) ──────────────────────

class _ResponderThread(threading.Thread):
    """Bind a UDP socket; drive WireGuardResponder on incoming Type-1.

    Exposes state flags that the main test thread reads to advance stages.
    """

    def __init__(self, responder: WireGuardResponder, bind_addr: str = "",
                 port: int = 0) -> None:
        super().__init__(daemon=True, name="wg-responder")
        self._responder = responder
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((bind_addr, port))
        self._sock.settimeout(0.25)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        # State (lock-guarded; updated inside .run())
        self._lock = threading.Lock()
        self.type1_received_at: Optional[float] = None
        self.type2_sent_at: Optional[float] = None
        self.type4_received_at: Optional[float] = None
        self.c64_addr: Optional[tuple[str, int]] = None
        self.last_error: Optional[str] = None

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        log.info("responder bound on 0.0.0.0:%d", self.port)
        while not self._stop.is_set():
            try:
                data, src = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue
            mt = data[0]
            log.info("responder: rx %dB from %s:%d type=0x%02x first16=%s",
                     len(data), src[0], src[1], mt, data[:16].hex())
            with self._lock:
                self.c64_addr = src
            if mt == MSG_TYPE_INITIATION and len(data) == T1_TOTAL:
                self._handle_type1(data, src)
            elif mt == MSG_TYPE_TRANSPORT:
                self._handle_type4(data)
            else:
                log.warning("responder: ignoring packet type=0x%02x len=%d",
                            mt, len(data))
        try:
            self._sock.close()
        except OSError:
            pass

    def _handle_type1(self, data: bytes, src: tuple[str, int]) -> None:
        try:
            type2 = self._responder.handle_initiation(data)
        except Exception as exc:
            log.error("responder: Type-1 rejected: %s", exc)
            with self._lock:
                self.last_error = f"type1: {exc}"
            return
        with self._lock:
            self.type1_received_at = time.monotonic()
        log.info("responder: Type-1 OK (c64_sender_idx=%d); sending Type-2 (%dB)",
                 self._responder._c64_sender_idx, len(type2))
        try:
            self._sock.sendto(type2, src)
        except OSError as exc:
            log.error("responder: Type-2 send failed: %s", exc)
            with self._lock:
                self.last_error = f"type2-send: {exc}"
            return
        with self._lock:
            self.type2_sent_at = time.monotonic()

    def _handle_type4(self, data: bytes) -> None:
        try:
            pt = self._responder.decrypt_transport(data)
        except Exception as exc:
            log.error("responder: Type-4 decrypt failed: %s", exc)
            with self._lock:
                self.last_error = f"type4: {exc}"
            return
        with self._lock:
            self.type4_received_at = time.monotonic()
        log.info("responder: Type-4 OK (%dB plaintext, first16=%s)",
                 len(pt), pt[:16].hex())


# ── C64-side staging ──────────────────────────────────────────────────────

def _stage_config(tr: Ultimate64Transport, L: dict[str, int],
                  c64_priv: bytes, c64_pub: bytes,
                  resp_pub: bytes, psk: bytes,
                  resp_ip: str, resp_port: int,
                  tunnel_ip: str = "10.7.0.2",
                  ping_target_ip: str = "10.7.0.1") -> None:
    """Write cfg_* state into C64 RAM, bypassing the disk_config path."""
    assert len(c64_priv) == 32 and len(c64_pub) == 32
    assert len(resp_pub) == 32 and len(psk) == 32
    write_bytes(tr, L["cfg_static_priv"], c64_priv)
    write_bytes(tr, L["cfg_static_pub"], c64_pub)
    write_bytes(tr, L["cfg_peer_pub"], resp_pub)
    write_bytes(tr, L["cfg_preshared_key"], psk)
    write_bytes(tr, L["cfg_peer_endpoint_ip"],
                bytes(int(o) for o in resp_ip.split(".")))
    # cfg_peer_endpoint_port is BIG-endian (parse_decimal_u16 storage convention).
    write_bytes(tr, L["cfg_peer_endpoint_port"],
                bytes([resp_port >> 8, resp_port & 0xFF]))
    write_bytes(tr, L["tunnel_ip"],
                bytes(int(o) for o in tunnel_ip.split(".")))
    write_bytes(tr, L["ping_target_ip"],
                bytes(int(o) for o in ping_target_ip.split(".")))
    # tai64n_base_time: 8 bytes BE. Seconds since 1970-01-01 12:00 TAI =
    # Unix epoch seconds + 10 (TAI minus UTC). Approximate is fine for a
    # one-shot handshake.
    tai = int(time.time()) + 10
    write_bytes(tr, L["tai64n_base_time"], tai.to_bytes(8, "big"))
    # Reset wg_state to IDLE.
    write_bytes(tr, L["wg_state"], bytes([SESSION_IDLE]))
    log.info("cfg staged: c64_pub=%s... resp_pub=%s... peer=%s:%d tai64=%d",
             c64_pub.hex()[:8], resp_pub.hex()[:8], resp_ip, resp_port, tai)


def _stage_net_ports(tr: Ultimate64Transport, L: dict[str, int],
                     resp_port: int, local_port: int) -> None:
    """Mirror echo test: wg_peer_port BE, wg_local_port LE."""
    write_bytes(tr, L["wg_peer_port"],
                bytes([resp_port >> 8, resp_port & 0xFF]))
    write_bytes(tr, L["wg_local_port"],
                bytes([local_port & 0xFF, local_port >> 8]))


# ── Main flow ─────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--stage", type=int, choices=[1, 2], default=2,
                   help="1=Type-1 accepted; 2=SESSION_ACTIVE (default)")
    p.add_argument("--host", default=os.environ.get("U64_HOST", DEFAULT_HOST))
    p.add_argument("--password", default=os.environ.get("U64_PASSWORD"))
    args = p.parse_args()

    if os.environ.get("U64_ALLOW_MUTATE") != "1":
        _skip("U64_ALLOW_MUTATE != 1 — this test mutates the device")

    pr = probe_u64(args.host)
    if not pr.reachable:
        _skip(f"U64E {args.host} not reachable: {pr.error}")
    log.info("U64E %s ok (%.1f ms)", args.host, pr.latency_ms or -1)

    _build_uci()
    labels_path = PROJECT_ROOT / "build" / "labels.txt"
    prg_path = PROJECT_ROOT / "build" / "wireguard.prg"
    if not labels_path.exists() or not prg_path.exists():
        log.error("build artifacts missing")
        return 1
    L = dict(Labels.from_file(str(labels_path)))
    missing = [n for n in REQUIRED_LABELS if n not in L]
    if missing:
        log.error("missing labels: %s", missing)
        return 1
    for n in REQUIRED_LABELS:
        log.info("label %-26s = $%04X", n, L[n])

    # ── Generate keys
    c64_priv_hex, c64_pub_hex = generate_keypair()
    resp_priv_hex, resp_pub_hex = generate_keypair()
    c64_priv, c64_pub = bytes.fromhex(c64_priv_hex), bytes.fromhex(c64_pub_hex)
    resp_priv, resp_pub = bytes.fromhex(resp_priv_hex), bytes.fromhex(resp_pub_hex)
    psk = bytes(32)
    log.info("keys: c64_pub=%s resp_pub=%s psk=zero", c64_pub.hex(), resp_pub.hex())

    # ── Start patient responder thread
    responder = WireGuardResponder(static_priv=resp_priv,
                                   peer_static_pub=c64_pub, psk=psk)
    rt = _ResponderThread(responder, bind_addr="", port=0)
    rt.start()

    local_ip = _local_ip_for(args.host)
    log.info("host=%s local_ip=%s responder_port=%d", args.host, local_ip, rt.port)

    rc = 1
    lock = DeviceLock(args.host)
    try:
        # 120s is the new "ad-hoc work" ceiling per c64-test skill (the
        # heartbeat extends the deadline for live, progressing holders).
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        rt.stop()
        log.error("DeviceLock acquire failed: host=%s holder_pid=%s "
                  "pid_alive=%s lockfile_age=%.1fs reachable_rest=%s",
                  e.device_host, e.holder_pid, e.pid_alive,
                  e.lockfile_age_seconds, e.device_reachable_rest)
        _skip(str(e))

    try:
        client = Ultimate64Client(host=args.host, password=args.password, timeout=10.0)
        tr = Ultimate64Transport(host=args.host, password=args.password, timeout=10.0,
                                 client=client)
        # Check the firmware's runner subsystem isn't wedged before we
        # commit to a 15+ minute test. If wedged, recover() escalates.
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner is wedged: %s — running recover()", exc)
            step = recover(client)
            log.info("recover() returned %r — re-checking runner", step)
            runner_health_check(client)
        if not get_uci_enabled(client):
            log.info("enabling UCI via REST")
            enable_uci(client)
            time.sleep(0.5)
            if not get_uci_enabled(client):
                _skip(f"enable_uci did not stick on {args.host}")
        # Match echo test prep order: REU first (needs cold-ish state),
        # THEN turbo. set_reu may reset the machine; do it before run_prg
        # but BEFORE turbo so the reset doesn't drop our turbo setting.
        try:
            set_reu(client, True, "512 KB")
        except Exception as exc:
            log.warning("set_reu failed (continuing): %s", exc)
        time.sleep(0.5)
        set_turbo_mhz(client, 1)
        time.sleep(0.2)
        # Load PRG and run.
        prg_bytes = prg_path.read_bytes()
        client.run_prg(prg_bytes)
        log.info("PRG sent (%d B); waiting for boot...", len(prg_bytes))
        _wait_boot(tr, L["mul_dma_hi"])

        # Hijack main_loop, install trampoline.
        _install_trampoline(tr, L["main_loop"])

        # ── Drive net init/dhcp/listen
        if _run_step(tr, step_id=STEP_INIT, target=L["net_init"]) != 0:
            _log_err(tr, L, "net_init")
            # Also probe UCI_ID via a tiny trampoline read so we know what
            # the C64 actually sees at $DF1D. Write a 3-byte program at
            # SEND_BUF: LDA $DF1D ; STA $0400 ; RTS; trampoline-call it.
            log.info("UCI was enabled at run start: %s",
                     get_uci_enabled(client))
            log.error("net_init failed")
            return 1
        if _run_step(tr, step_id=STEP_DHCP, target=L["net_dhcp"]) != 0:
            log.error("net_dhcp failed")
            return 1
        # net_udp_listen takes A=lo, X=hi. Use a fixed C64-side local port
        # (arbitrary; firmware picks the actual ephemeral source port).
        local_port = 51820
        local_port_lo, local_port_hi = local_port & 0xFF, local_port >> 8
        if _run_step(tr, step_id=STEP_LISTEN, target=L["net_udp_listen"],
                     reg_a=local_port_lo, reg_x=local_port_hi) != 0:
            log.error("net_udp_listen failed")
            return 1

        # ── Stage config
        _stage_config(tr, L, c64_priv, c64_pub, resp_pub, psk,
                      resp_ip=local_ip, resp_port=rt.port)
        _stage_net_ports(tr, L, resp_port=rt.port, local_port=local_port)

        # ── Trigger do_handshake (entropy_init + delay + session_initiate)
        # do_handshake is what the 'H' key normally invokes — it ensures
        # entropy_init runs before session_initiate's entropy_fill.
        log.info("driving do_handshake (timeout %.0fs)...", HS_INIT_TIMEOUT)
        # Progress probes: x25_bit_ctr ticks during scalar mult (0→255 per op);
        # wg_state goes 0→1 when session_initiate completes; net_last_error
        # surfaces firmware errors; udp_send_len_local becomes 148 right
        # before net_udp_send.
        probes = {
            "wg_state": L["wg_state"],
            "x25_bit": 0x2B,                    # x25_bit_ctr (ZP)
            "fe_loop": 0x27,                    # fe_loop (ZP)
            "send_len_lo": L["udp_send_len_local"],
            "net_err": L["net_last_error"],
        }
        t0 = time.monotonic()
        carry = _run_step_slow(tr, step_id=STEP_HS_INIT,
                               target=L["do_handshake"],
                               timeout=HS_INIT_TIMEOUT, probes=probes)
        dt = time.monotonic() - t0
        log.info("do_handshake returned in %.1fs (carry=%d)", dt, carry)
        if carry != 0:
            log.error("do_handshake failed (carry=1)")
            return 1
        # Verify state is now HS_SENT.
        state = tr.read_memory(L["wg_state"], 1)[0]
        if state != SESSION_HS_SENT:
            log.error("after session_initiate, wg_state=%d (expected HS_SENT=1)",
                      state)
            return 1
        log.info("wg_state = SESSION_HS_SENT ✓")

        # ── Wait for responder to see Type-1 (should be immediate by now)
        deadline = time.monotonic() + STAGE1_RESPONDER_WAIT
        while time.monotonic() < deadline:
            with rt._lock:
                if rt.type1_received_at is not None:
                    break
                if rt.last_error:
                    log.error("responder reported error: %s", rt.last_error)
                    return 1
            time.sleep(0.5)
        else:
            log.error("responder never saw Type-1 (timeout)")
            return 1
        log.info("STAGE 1 ✓ — Type-1 accepted by responder")

        if args.stage == 1:
            log.info("STAGE 1 only — done")
            rc = 0
            return 0

        # ── Stage 2: drive net_poll + session_handle_packet until ACTIVE
        log.info("stage 2: waiting for Type-2 + session_handle_packet → ACTIVE "
                 "(timeout %.0fs)", STAGE2_ACTIVE_WAIT)
        deadline = time.monotonic() + STAGE2_ACTIVE_WAIT
        polls = 0
        type2_seen_at: Optional[float] = None
        while time.monotonic() < deadline:
            # Drive one net_poll.
            _run_step(tr, step_id=STEP_POLL, target=L["net_poll"],
                      timeout=POLL_TIMEOUT)
            polls += 1
            ready = tr.read_memory(L["udp_recv_ready"], 1)[0]
            if ready != 0:
                if type2_seen_at is None:
                    type2_seen_at = time.monotonic()
                    log.info("udp_recv_ready set after %d polls — driving "
                             "session_handle_packet", polls)
                t0 = time.monotonic()
                carry = _run_step_slow(tr, step_id=STEP_HANDLE,
                                       target=L["session_handle_packet"],
                                       timeout=HANDLE_TIMEOUT)
                dt = time.monotonic() - t0
                log.info("session_handle_packet returned in %.1fs (carry=%d)",
                         dt, carry)
                state = tr.read_memory(L["wg_state"], 1)[0]
                log.info("wg_state = %d", state)
                if state == SESSION_ACTIVE:
                    log.info("STAGE 2 ✓ — SESSION_ACTIVE reached")
                    rc = 0
                    return 0
                if state == SESSION_IDLE:
                    log.error("wg_state reverted to IDLE after handle_packet")
                    return 1
                # Else HS_SENT (still waiting for next packet) — continue
            time.sleep(0.5)
        log.error("timeout waiting for SESSION_ACTIVE (%d polls, "
                  "type2_seen=%s, final_state=%d)",
                  polls,
                  "yes" if type2_seen_at else "no",
                  tr.read_memory(L["wg_state"], 1)[0])
        return 1

    finally:
        try:
            rt.stop()
            rt.join(timeout=2.0)
        except Exception:
            pass
        lock.release()
        if rc == 0:
            print("PASS — UCI WireGuard handshake stage", args.stage)
        else:
            print("FAIL — see log")
    return rc


if __name__ == "__main__":
    sys.exit(main())
