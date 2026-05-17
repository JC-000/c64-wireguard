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
from c64_test_harness.backends.u64_debug_capture import DebugCapture  # noqa: E402
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    DEBUG_MODE_6510, check_measurement_environment, get_debug_stream_mode,
    recover, runner_health_check, set_debug_stream_mode,
    set_reu, set_turbo_mhz, Ultimate64MeasurementEnvironmentError,
)

# Reuse the trampoline helpers from the echo test (battle-tested).
from test_uci_udp_echo_live import (  # noqa: E402
    BOOT_TIMEOUT, CARRY, DEBUG_PORT, GO_FLAG, SENTINEL, STEP_ID, TRAMP,
    SMC_REG_A, SMC_REG_X, SMC_TARG_LO, SMC_TARG_HI,
    STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_POLL, STEP_TIMEOUT,
    _build_trampoline, _build_uci, _install_trampoline, _local_ip_for,
    _persist_trace, _run_step, _safe, _wait_boot,
)

from wg_responder.keys import generate_keypair  # noqa: E402
from wg_responder.responder import (  # noqa: E402
    MSG_TYPE_INITIATION, MSG_TYPE_RESPONSE, MSG_TYPE_TRANSPORT,
    T1_TOTAL, WireGuardResponder,
)

# Stage-2 AEAD-failure diagnostic: capture the responder's pre-AEAD state
# (h, K) via monkey-patch so we can compare against the C64's view after
# hs_process_response fails.
_DIAG_CAPTURE: dict[str, Optional[bytes]] = {
    "h_after_T1": None, "ck_after_T1": None,
    "h_at_aead": None, "k_at_aead": None,
    "type2_packet": None, "e_priv_resp": None, "e_pub_resp": None,
}


def _install_aead_capture_patch() -> None:
    """Monkey-patch SymmetricState to record handshake-transcript state at
    key boundaries:

    * After each decrypt_and_hash (Type-1 ingestion): the last call's
      post-state gives h/ck immediately after consuming Type-1 — i.e.
      what the C64's hs_h/hs_c must be at hs_process_response entry.
    * Before encrypt_and_hash (Type-2 emission's empty-payload encrypt):
      h and the AEAD key K that the C64 must reproduce at AEAD verify
      time."""
    import noise.state as _ns  # noqa: PLC0415
    _orig_eah = _ns.SymmetricState.encrypt_and_hash
    _orig_dah = _ns.SymmetricState.decrypt_and_hash

    def _capture_eah(self, plaintext):  # type: ignore[no-untyped-def]
        if _DIAG_CAPTURE["h_at_aead"] is None:
            _DIAG_CAPTURE["h_at_aead"] = bytes(self.h)
            k = getattr(self.cipher_state, "k", None)
            _DIAG_CAPTURE["k_at_aead"] = bytes(k) if k is not None else None
        return _orig_eah(self, plaintext)

    def _capture_dah(self, ciphertext):  # type: ignore[no-untyped-def]
        out = _orig_dah(self, ciphertext)
        # Last call wins — that's h/ck right after Type-1's timestamp
        # is consumed (which is the final mutation in read_message).
        _DIAG_CAPTURE["h_after_T1"] = bytes(self.h)
        _DIAG_CAPTURE["ck_after_T1"] = bytes(self.ck)
        return out

    _ns.SymmetricState.encrypt_and_hash = _capture_eah
    _ns.SymmetricState.decrypt_and_hash = _capture_dah

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
    # AEAD-failure diagnostic state (read by _dump_aead_state).
    "hs_h", "hs_c", "aead_key", "kdf_out1", "kdf_out2", "kdf_out3",
    "hs_resp_packet", "hs_ephem_pub",
)


def _log_err(tr: Ultimate64Transport, L: dict[str, int], step: str) -> None:
    err = tr.read_memory(L["net_last_error"], 1)[0]
    log.info("%s: net_last_error=$%02X", step, err)


def _dump_aead_state(tr: Ultimate64Transport, L: dict[str, int],
                     dh1_ok: bool = False) -> None:
    """Read the C64-side AEAD-verify inputs out of the failed hs_process_response
    and compare against the responder's captured pre-AEAD state."""
    # NB: aead_key was loaded from kdf_out3 just before aead_decrypt
    # (handshake.s:829-834); both should still hold the same 32-byte K.
    addrs = [
        ("hs_h",          L["hs_h"],          32),
        ("hs_c",          L["hs_c"],          32),
        ("aead_key",      L["aead_key"],      32),
        ("kdf_out1",      L["kdf_out1"],      32),
        ("kdf_out2",      L["kdf_out2"],      32),
        ("kdf_out3",      L["kdf_out3"],      32),
        ("hs_resp_packet", L["hs_resp_packet"], 92),
        ("hs_ephem_pub",  L["hs_ephem_pub"],  32),
    ]
    c64 = {name: bytes(tr.read_memory(addr, n)) for name, addr, n in addrs}
    log.info("--- AEAD diagnostic ---")
    for name, _, n in addrs:
        log.info("C64 %-16s = %s", name, c64[name].hex())
    log.info("--- responder captured ---")
    for k in ("h_after_T1", "ck_after_T1", "h_at_aead", "k_at_aead",
              "e_pub_resp", "e_priv_resp", "type2_packet"):
        v = _DIAG_CAPTURE.get(k)
        log.info("resp %-16s = %s",
                 k, v.hex() if isinstance(v, (bytes, bytearray)) else "(none)")

    log.info("--- comparisons ---")

    def _cmp(label: str, c64_val: bytes, resp_val: Optional[bytes]) -> None:
        if resp_val is None:
            log.info("%-32s  RESP=NONE", label)
            return
        match = c64_val == resp_val
        marker = "OK " if match else "MISMATCH"
        log.info("%-32s  %s", label, marker)
        if not match:
            log.info("  C64 : %s", c64_val.hex())
            log.info("  RESP: %s", resp_val.hex())

    _cmp("Type-2 packet (92B)",
         c64["hs_resp_packet"],
         _DIAG_CAPTURE.get("type2_packet"))
    if _DIAG_CAPTURE.get("e_pub_resp"):
        _cmp("resp_e_pub vs packet[12..43]",
             c64["hs_resp_packet"][12:44],
             _DIAG_CAPTURE["e_pub_resp"])
    _cmp("hs_h at AEAD",     c64["hs_h"],     _DIAG_CAPTURE.get("h_at_aead"))
    _cmp("aead_key (=kdf_out3) vs K",
         c64["aead_key"], _DIAG_CAPTURE.get("k_at_aead"))
    _cmp("kdf_out3 vs K",
         c64["kdf_out3"], _DIAG_CAPTURE.get("k_at_aead"))


def _safe_read(tr: Ultimate64Transport, addr: int, n: int = 1,
               attempts: int = 6, backoff: float = 1.0) -> bytes:
    # The U64E REST stack occasionally drops TCP connections during long
    # CPU-bound work on the 6502 (X25519 grind). Retry transient resets
    # rather than letting a one-off RST kill a 25-minute test.
    last_exc: Optional[BaseException] = None
    for i in range(attempts):
        try:
            return tr.read_memory(addr, n)
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            last_exc = exc
            if i + 1 == attempts:
                break
            time.sleep(backoff * (i + 1))
            log.warning("read_memory($%04X, %d) transient %s — retry %d/%d",
                        addr, n, type(exc).__name__, i + 1, attempts)
    assert last_exc is not None
    raise last_exc


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("uci_handshake")


def _skip(reason: str) -> None:
    print(f"SKIP: {reason}")
    sys.exit(77)


def _kick_step(
    tr: Ultimate64Transport, *, step_id: int, target: int,
    reg_a: int = 0, reg_x: int = 0,
) -> None:
    """Fire the trampoline for `target` without waiting.

    Pairs with `_wait_step`. The C64-side JSR runs synchronously inside
    the trampoline; from the host we observe completion via SENTINEL.
    """
    t = bytearray(_build_trampoline())
    t[SMC_REG_A], t[SMC_REG_X] = reg_a & 0xFF, reg_x & 0xFF
    t[SMC_TARG_LO], t[SMC_TARG_HI] = target & 0xFF, (target >> 8) & 0xFF
    write_bytes(tr, TRAMP, bytes(t))
    write_bytes(tr, SENTINEL, bytes([0, 0, step_id]))   # SENT, CARRY, STEP_ID
    write_bytes(tr, GO_FLAG, bytes([1]))


def _wait_step(
    tr: Ultimate64Transport, *, step_id: int, timeout: float = 600.0,
    poll_interval: float = 1.0,
    probes: Optional[dict[str, int]] = None,
    start_time: Optional[float] = None,
) -> int:
    """Poll SENTINEL until it equals `step_id`; return CARRY."""
    started = start_time if start_time is not None else time.monotonic()
    deadline = started + timeout
    last_log = time.monotonic()
    while time.monotonic() < deadline:
        if _safe_read(tr, SENTINEL, 1)[0] == step_id:
            carry = _safe_read(tr, CARRY, 1)[0]
            log.info("step $%02X done; carry=%d (%.1fs)", step_id, carry,
                     time.monotonic() - started)
            return carry
        # Heartbeat log every 30s so we can see the test isn't wedged.
        now = time.monotonic()
        if now - last_log >= 30.0:
            elapsed = now - started
            extras = ""
            if probes:
                vals = []
                for name, addr in probes.items():
                    b = _safe_read(tr, addr, 1)[0]
                    vals.append(f"{name}=${b:02X}")
                extras = " [" + " ".join(vals) + "]"
            log.info("step $%02X still running (%.0fs elapsed)%s",
                     step_id, elapsed, extras)
            last_log = now
        time.sleep(poll_interval)
    got = _safe_read(tr, SENTINEL, 1)[0]
    raise TimeoutError(
        f"step ${step_id:02X} timed out after {timeout}s (SENTINEL=${got:02X})"
    )


def _run_step_slow(
    tr: Ultimate64Transport, *, step_id: int, target: int,
    reg_a: int = 0, reg_x: int = 0, timeout: float = 600.0,
    poll_interval: float = 1.0,
    probes: Optional[dict[str, int]] = None,
) -> int:
    """Kick + wait; thin wrapper for the common case where capture
    isn't needed and the trampoline can be polled to completion."""
    started = time.monotonic()
    _kick_step(tr, step_id=step_id, target=target, reg_a=reg_a, reg_x=reg_x)
    return _wait_step(tr, step_id=step_id, timeout=timeout,
                      poll_interval=poll_interval, probes=probes,
                      start_time=started)


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
        # AEAD-failure diagnosis: type2_packet bytes are enough; h_at_aead/
        # k_at_aead/h_after_T1/ck_after_T1 are already in _DIAG_CAPTURE from
        # the monkey-patch on SymmetricState. handshake_state is gone by
        # now (python-noise calls handshake_done() after split() in
        # write_message), so don't reach into it.
        _DIAG_CAPTURE["type2_packet"] = type2
        # The responder's e_pub_resp is the unencrypted ephemeral at
        # type2[12..44] per WireGuard's Type-2 layout.
        _DIAG_CAPTURE["e_pub_resp"] = type2[12:44]
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
    p.add_argument("--debug-capture", action="store_true",
                   help="In stage 2, wrap the first session_handle_packet "
                        "call in a 30s DebugCapture window to record the "
                        "C64 bus trace through the start of hs_process_response "
                        "(MAC1 check + early KDF). Saves trace to artifacts/. "
                        "Useful for diagnosing why wg_state doesn't advance to "
                        "SESSION_ACTIVE.")
    p.add_argument("--dump-aead", action="store_true",
                   help="In stage 2, after the first session_handle_packet "
                        "returns, dump the C64-side AEAD verify inputs "
                        "(hs_h, hs_c, aead_key, kdf_out1/2/3, hs_resp_packet) "
                        "and compare against the responder's expected values "
                        "captured via SymmetricState monkey-patch. Exits "
                        "after one iteration regardless of outcome.")
    args = p.parse_args()
    if args.dump_aead:
        _install_aead_capture_patch()

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
    labels = Labels.from_file(str(labels_path))
    L = dict(labels)
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
        # Verify turbo actually stuck (harness PR #106 footgun: a prior
        # session may have left turbo at 48 MHz and reset() doesn't clear it).
        try:
            check_measurement_environment(client)
        except Ultimate64MeasurementEnvironmentError as exc:
            _skip(f"unexpected turbo state: {exc}")
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

        if args.dump_aead:
            # Snapshot hs_h / hs_c immediately after Type-1 was emitted and
            # accepted by the responder. These must match the responder's
            # h_after_T1 / ck_after_T1 — if they don't, the Type-1 emission
            # transcript itself has diverged (even though the responder
            # accepted the message). If they do match but the post-AEAD
            # values still mismatch, the bug is in hs_process_response.
            post_t1_h = bytes(tr.read_memory(L["hs_h"], 32))
            post_t1_c = bytes(tr.read_memory(L["hs_c"], 32))
            log.info("post-Type-1: hs_h=%s", post_t1_h.hex())
            log.info("post-Type-1: hs_c=%s", post_t1_c.hex())
            log.info("resp        h_after_T1=%s",
                     (_DIAG_CAPTURE.get("h_after_T1") or b"").hex())
            log.info("resp        ck_after_T1=%s",
                     (_DIAG_CAPTURE.get("ck_after_T1") or b"").hex())
            h_ok = post_t1_h == _DIAG_CAPTURE.get("h_after_T1")
            c_ok = post_t1_c == _DIAG_CAPTURE.get("ck_after_T1")
            log.info("post-Type-1 hs_h match: %s | hs_c match: %s",
                     "OK" if h_ok else "MISMATCH",
                     "OK" if c_ok else "MISMATCH")

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
                first_handle = type2_seen_at is None
                if first_handle:
                    type2_seen_at = time.monotonic()
                    log.info("udp_recv_ready set after %d polls — driving "
                             "session_handle_packet", polls)
                t0 = time.monotonic()
                if first_handle and args.debug_capture:
                    # Wrap the first 30s of session_handle_packet in a
                    # cycle-accurate debug capture. hs_process_response
                    # starts here; if it silently fails (no carry, no
                    # state transition), the trace will show exactly
                    # which path the C64 took. The first 30s covers
                    # MAC1 verification + the first part of
                    # hs_process_response's KDF chain.
                    log.info("debug-capture: starting 30s window over "
                             "session_handle_packet entry")
                    cap = DebugCapture(port=DEBUG_PORT)
                    cap.start()
                    _safe(set_debug_stream_mode, client, DEBUG_MODE_6510)
                    client.stream_debug_start(f"{local_ip}:{DEBUG_PORT}")
                    _kick_step(tr, step_id=STEP_HANDLE,
                               target=L["session_handle_packet"])
                    time.sleep(30.0)
                    _safe(client.stream_debug_stop)
                    time.sleep(0.3)
                    cap_result = cap.stop()
                    trace_path = _persist_trace(cap_result, labels,
                                                mhz=1, mode=DEBUG_MODE_6510)
                    log.info("debug-capture: trace saved to %s "
                             "(packets=%d dropped=%d cycles=%d)",
                             trace_path, cap_result.packets_received,
                             cap_result.packets_dropped,
                             cap_result.total_cycles)
                    # Continue waiting for session_handle_packet to finish.
                    carry = _wait_step(tr, step_id=STEP_HANDLE,
                                       timeout=HANDLE_TIMEOUT - 30,
                                       start_time=t0)
                else:
                    carry = _run_step_slow(tr, step_id=STEP_HANDLE,
                                           target=L["session_handle_packet"],
                                           timeout=HANDLE_TIMEOUT)
                dt = time.monotonic() - t0
                log.info("session_handle_packet returned in %.1fs (carry=%d)",
                         dt, carry)
                state = tr.read_memory(L["wg_state"], 1)[0]
                log.info("wg_state = %d", state)
                if args.dump_aead and first_handle:
                    _dump_aead_state(tr, L, dh1_ok=False)
                    rc = 0 if state == SESSION_ACTIVE else 1
                    return rc
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
