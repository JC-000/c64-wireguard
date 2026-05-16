#!/usr/bin/env python3
"""Live Ultimate 64 Elite test: UCI backend UDP echo end-to-end.

Drives net_init -> net_dhcp -> net_udp_listen -> net_udp_send -> net_poll
on real hardware against a host-side UDP echo server, under a full
debug-bus-cycle capture so any failure can be root-caused from the
trace artifact.

Gates: ``U64_HOST`` (default 10.43.23.81) and ``U64_ALLOW_MUTATE=1``.
Skip exit is 77.  Run::

    U64_HOST=10.43.23.81 U64_ALLOW_MUTATE=1 \\
        python3 tools/test_uci_udp_echo_live.py
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.udp_echo_listener import UDPEchoListener  # noqa: E402

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, enable_uci, get_uci_enabled,
    probe_u64, write_bytes,
)
from c64_test_harness.backends.u64_debug_capture import DebugCapture  # noqa: E402
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    DEBUG_MODE_6510, check_measurement_environment, get_debug_stream_mode,
    get_reu_config, get_turbo_mhz, recover, runner_health_check,
    set_debug_stream_mode, set_reu, set_turbo_mhz,
    Ultimate64MeasurementEnvironmentError,
)

DEFAULT_HOST = "10.43.23.81"
DEBUG_PORT = 11002

# Trampoline + signal bytes (cassette buffer + scratch, free post-boot).
TRAMP, GO_FLAG, SENTINEL, CARRY, STEP_ID = 0x0334, 0x03E0, 0x03E1, 0x03E2, 0x03E3
# SMC offsets inside the trampoline image (see _build_trampoline).
SMC_REG_A, SMC_REG_X, SMC_TARG_LO, SMC_TARG_HI = 14, 16, 18, 19
STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_SEND, STEP_POLL = 0x11, 0x22, 0x33, 0x44, 0x55
TEST_PAYLOAD = bytes(range(0x40, 0x60))  # 32 bytes, no $00 for trace eyeballing
SEND_BUF = 0x02A7                        # free space before cassette buffer
BOOT_TIMEOUT, STEP_TIMEOUT, ECHO_TIMEOUT = 60.0, 10.0, 5.0
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("uci_udp_echo")


def _skip(reason: str) -> None:
    print(f"SKIP: {reason}")
    sys.exit(77)


def _local_ip_for(host: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 80))
        return s.getsockname()[0]


def _build_uci() -> None:
    if os.environ.get("C64_SKIP_BUILD"):
        return log.info("C64_SKIP_BUILD set — skipping make")
    log.info("make clean && make BACKEND=uci")
    for cmd in (["make", "clean"], ["make", "BACKEND=uci"]):
        r = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr.decode(errors="replace"))
            sys.exit(1)


def _build_trampoline() -> bytes:
    """36-byte trampoline: loop on GO_FLAG, JSR SMC target, store carry + step."""
    return bytes([
        0xAD, GO_FLAG & 0xFF, GO_FLAG >> 8,           # LDA GO_FLAG
        0xF0, 0xFB,                                   # BEQ -3
        0xA9, 0x00,                                   # LDA #0
        0x8D, GO_FLAG & 0xFF, GO_FLAG >> 8,           # STA GO_FLAG
        0x8D, SENTINEL & 0xFF, SENTINEL >> 8,         # STA SENTINEL
        0xA9, 0x00,                                   # LDA #$00  (SMC A @14)
        0xA2, 0x00,                                   # LDX #$00  (SMC X @16)
        0x20, 0xFF, 0xFF,                             # JSR $FFFF (SMC @18/19)
        0x08, 0x68, 0x29, 0x01,                       # PHP PLA AND #$01
        0x8D, CARRY & 0xFF, CARRY >> 8,               # STA CARRY
        0xAD, STEP_ID & 0xFF, STEP_ID >> 8,           # LDA STEP_ID
        0x8D, SENTINEL & 0xFF, SENTINEL >> 8,         # STA SENTINEL
        0x4C, TRAMP & 0xFF, TRAMP >> 8,               # JMP TRAMP
    ])


def _wait_boot(tr: Ultimate64Transport, mul_dma_hi: int) -> None:
    """Wait for reu_mul_init to finish: ``mul_dma_hi[255]`` becomes
    ``(255*255) >> 8 = $FE`` only after the last outer iteration."""
    deadline = time.monotonic() + BOOT_TIMEOUT
    last = 0
    while time.monotonic() < deadline:
        last = tr.read_memory(mul_dma_hi + 255, 1)[0]
        if last == 0xFE:
            log.info("boot complete — mul_dma_hi[255]=$FE (reu_mul_init done)")
            return
        time.sleep(0.5)
    raise TimeoutError(
        f"reu_mul_init not finished within {BOOT_TIMEOUT}s; "
        f"mul_dma_hi[255]=${last:02X}"
    )


def _install_trampoline(tr: Ultimate64Transport, main_loop: int) -> None:
    write_bytes(tr, TRAMP, _build_trampoline())
    write_bytes(tr, GO_FLAG, bytes([0, 0, 0, 0]))
    hijack = bytes([0x4C, TRAMP & 0xFF, TRAMP >> 8])
    write_bytes(tr, main_loop, hijack)
    # Verify: read-back must match, else the CPU may be running RAM-from-ROM
    # or the DMA is being clobbered.
    got = bytes(tr.read_memory(main_loop, 3))
    if got != hijack:
        raise RuntimeError(
            f"hijack at ${main_loop:04X} failed; "
            f"wrote {hijack.hex()} but read back {got.hex()}"
        )
    log.info("hijack installed @ $%04X = %s", main_loop, got.hex())


def _run_step(
    tr: Ultimate64Transport, *, step_id: int, target: int,
    reg_a: int = 0, reg_x: int = 0, timeout: float = STEP_TIMEOUT,
) -> int:
    """Drive one trampoline iteration; return captured carry (0/1)."""
    t = bytearray(_build_trampoline())
    t[SMC_REG_A], t[SMC_REG_X] = reg_a & 0xFF, reg_x & 0xFF
    t[SMC_TARG_LO], t[SMC_TARG_HI] = target & 0xFF, (target >> 8) & 0xFF
    write_bytes(tr, TRAMP, bytes(t))
    write_bytes(tr, SENTINEL, bytes([0, 0, step_id]))   # SENT, CARRY, STEP_ID
    write_bytes(tr, GO_FLAG, bytes([1]))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(SENTINEL, 1)[0] == step_id:
            carry = tr.read_memory(CARRY, 1)[0]
            log.info("step $%02X done; carry=%d", step_id, carry)
            return carry
        time.sleep(0.05)
    got = tr.read_memory(SENTINEL, 1)[0]
    raise TimeoutError(
        f"step ${step_id:02X} timed out after {timeout}s (SENTINEL=${got:02X})"
    )


def _poll_until_recv_ready(tr, ready_addr, net_poll_addr, timeout) -> bool:
    deadline = time.monotonic() + timeout
    iters = 0
    while time.monotonic() < deadline:
        _run_step(tr, step_id=STEP_POLL, target=net_poll_addr)
        iters += 1
        if tr.read_memory(ready_addr, 1)[0] != 0:
            log.info("udp_recv_ready set after %d polls", iters)
            return True
        time.sleep(0.02)
    return False


def _persist_trace(result, labels: Labels, *, mhz: int, mode: str) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = ARTIFACTS_DIR / f"uci_trace_{stamp}.txt"
    by_addr = {a: n for n, a in dict(labels).items() if 0 <= a < 0x10000}
    with open(path, "w") as f:
        f.write(f"# mhz={mhz} mode={mode} packets={result.packets_received} "
                f"dropped={result.packets_dropped} "
                f"duration={result.duration_seconds:.3f} "
                f"cycles={result.total_cycles}\n")
        for i, cyc in enumerate(result.trace):
            if not cyc.is_cpu:
                continue
            sym = by_addr.get(cyc.address, "")
            f.write(f"{i:08d} {cyc.address:04X} "
                    f"rw={'R' if cyc.is_read else 'W'} "
                    f"data={cyc.data:02X}{' ' + sym if sym else ''}\n")
    latest = ARTIFACTS_DIR / "uci_trace_latest.txt"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(path.name)
    except OSError:
        latest.write_bytes(path.read_bytes())
    log.info("trace persisted to %s (cycles=%d)", path, result.total_cycles)
    return path


def _ensure_gitignore_artifacts() -> None:
    gi = PROJECT_ROOT / ".gitignore"
    if not gi.exists():
        return
    content = gi.read_text()
    if any(ln.strip() in {"artifacts/", "/artifacts/"}
           for ln in content.splitlines()):
        return
    with open(gi, "a") as f:
        f.write(("" if content.endswith("\n") else "\n") + "artifacts/\n")
    log.info("added artifacts/ to .gitignore")


REQUIRED_LABELS = (
    "main_loop", "net_init", "net_dhcp", "net_udp_listen", "net_udp_send",
    "net_poll", "net_local_ip", "net_last_error", "mul_dma_hi",
    "wg_peer_ip", "wg_peer_port", "wg_local_port",
    "udp_recv_ready", "udp_recv_len", "udp_recv_buf", "udp_send_len_local",
)


def _run_sequence(
    tr: Ultimate64Transport, L: dict[str, int],
    listener: UDPEchoListener, local_ip: str,
) -> list[str]:
    """Drive the five UCI steps; return a list of failure descriptions."""
    fail: list[str] = []
    # Stage peer config. wg_peer_ip = 4 bytes in natural octet order (see
    # net.s :427-434). wg_peer_port = BIG-endian (matches ip65 native + the
    # disk_config.s parse_decimal_u16 storage convention; uci/net.s swaps
    # on push to firmware). wg_local_port = LITTLE-endian (net_udp_listen
    # stores A=lo,X=hi in net.s :213-215).
    ip_bytes = bytes(int(o) for o in local_ip.split("."))
    port_be = bytes([listener.port >> 8, listener.port & 0xFF])
    port_le = bytes([listener.port & 0xFF, listener.port >> 8])
    log.info("peer=%s:%d wg_peer_ip(hex)=%s peer_port_be(hex)=%s local_port_le(hex)=%s",
             local_ip, listener.port, ip_bytes.hex(), port_be.hex(), port_le.hex())
    write_bytes(tr, L["wg_peer_ip"], ip_bytes)
    write_bytes(tr, L["wg_peer_port"], port_be)
    write_bytes(tr, L["wg_local_port"], port_le)
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    write_bytes(tr, SEND_BUF, TEST_PAYLOAD)
    write_bytes(tr, L["udp_send_len_local"], bytes([len(TEST_PAYLOAD), 0]))
    _install_trampoline(tr, L["main_loop"])
    time.sleep(0.05)

    def call(name: str, step: int, **kw):
        c = _run_step(tr, step_id=step, target=L[name], **kw)
        nle = tr.read_memory(L["net_last_error"], 1)[0]
        log.info("%s carry=%d net_last_error=$%02X", name, c, nle)
        return c, nle

    # net_init
    c, nle = call("net_init", STEP_INIT)
    if c != 0:
        fail.append(f"net_init C=1 (net_last_error=$%02X; "
                    "$81=NOT_PRESENT, $82=CMD_FAILED)" % nle)
    if nle != 0:
        fail.append(f"net_last_error=${nle:02X} after net_init")
    # If net_init failed, STOP. net_dhcp and later calls read $DF1x
    # registers without their own UCI_ID probe — on a non-UCI device
    # they hang. Respect the init contract: no further backend calls
    # unless init succeeded.
    if c != 0:
        log.warning("skipping net_dhcp + later steps — net_init did not succeed")
        return fail
    # net_dhcp
    c, nle = call("net_dhcp", STEP_DHCP)
    ip = tr.read_memory(L["net_local_ip"], 4)
    log.info("net_local_ip=%s", ".".join(str(b) for b in ip))
    if c != 0:
        fail.append(f"net_dhcp C=1 (net_last_error=${nle:02X})")
    if ip == bytes(4):
        fail.append("net_local_ip == 0.0.0.0 after net_dhcp")
    # net_udp_listen
    c, _ = call("net_udp_listen", STEP_LISTEN,
                reg_a=listener.port & 0xFF, reg_x=listener.port >> 8)
    if c != 0:
        fail.append("net_udp_listen C=1")
    # net_udp_send
    c, nle = call("net_udp_send", STEP_SEND,
                  reg_a=SEND_BUF & 0xFF, reg_x=SEND_BUF >> 8)
    if c != 0:
        fail.append(f"net_udp_send C=1 (net_last_error=${nle:02X}; "
                    "$84=CONNECT_FAIL, $85=SEND_FAIL, $87=SHORT_WRITE)")

    # Host echo
    echo_dl = time.monotonic() + 2.0
    while time.monotonic() < echo_dl and not listener.received:
        time.sleep(0.05)
    rx_list = listener.received
    log.info("listener received %d packet(s)", len(rx_list))
    if not rx_list:
        fail.append("echo listener got NO packet from C64")
    elif rx_list[0][1] != TEST_PAYLOAD:
        fail.append(f"sent payload mismatch: {rx_list[0][1]!r} vs {TEST_PAYLOAD!r}")

    # net_poll loop
    got = _poll_until_recv_ready(tr, L["udp_recv_ready"], L["net_poll"],
                                 ECHO_TIMEOUT)
    if not got:
        fail.append(f"udp_recv_ready stayed 0 for {ECHO_TIMEOUT}s after echo")
    else:
        lo, hi = tr.read_memory(L["udp_recv_len"], 2)
        rx_len = lo | (hi << 8)
        log.info("udp_recv_len=%d", rx_len)
        if rx_len != len(TEST_PAYLOAD):
            fail.append(f"udp_recv_len={rx_len}, expected {len(TEST_PAYLOAD)}")
        rx = bytes(tr.read_memory(L["udp_recv_buf"],
                                  min(rx_len, len(TEST_PAYLOAD))))
        if rx != TEST_PAYLOAD:
            fail.append(f"udp_recv_buf mismatch: {rx!r} vs {TEST_PAYLOAD!r}")
    return fail


def _safe(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except Exception as exc:
        log.warning("%s(%r, %r) failed: %s", getattr(fn, "__name__", fn), args, kw, exc)
        return None


def main() -> int:
    host = os.environ.get("U64_HOST", DEFAULT_HOST)
    if not host:
        _skip("U64_HOST not set")
    if os.environ.get("U64_ALLOW_MUTATE") != "1":
        _skip("U64_ALLOW_MUTATE=1 required (test mutates Turbo + Debug Stream Mode)")
    password = os.environ.get("U64_PASSWORD")
    probe = probe_u64(host, password=password)
    if not probe.reachable:
        _skip(f"U64 at {host} not reachable: {probe.error}")

    _ensure_gitignore_artifacts()
    _build_uci()

    labels_path = PROJECT_ROOT / "build" / "labels.txt"
    prg_path = PROJECT_ROOT / "build" / "wireguard.prg"
    if not labels_path.exists() or not prg_path.exists():
        print(f"FATAL: missing {labels_path} or {prg_path}", file=sys.stderr)
        return 1

    labels = Labels.from_file(labels_path)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: missing labels: {missing}", file=sys.stderr)
        return 1
    L = {n: labels[n] for n in REQUIRED_LABELS}
    for n, a in L.items():
        log.info("label %-22s = $%04X", n, a)

    lock = DeviceLock(host)
    try:
        # 120s ceiling per c64-test skill — heartbeat extends deadline
        # for live progressing holders; this only fires on wedged/dead.
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        log.error("DeviceLock acquire failed: host=%s holder_pid=%s "
                  "pid_alive=%s lockfile_age=%.1fs reachable_rest=%s",
                  e.device_host, e.holder_pid, e.pid_alive,
                  e.lockfile_age_seconds, e.device_reachable_rest)
        _skip(str(e))

    client = Ultimate64Client(host=host, password=password, timeout=10.0)
    tr = Ultimate64Transport(host=host, password=password, timeout=10.0,
                             client=client)

    # Detect wedged-runner state before doing destructive work.
    try:
        runner_health_check(client)
    except Ultimate64RunnerStuckError as exc:
        log.warning("runner is wedged: %s — running recover()", exc)
        step = recover(client)
        log.info("recover() returned %r — re-checking runner", step)
        runner_health_check(client)

    # Minimal setup: assume UCI is already enabled (via menu or prior
    # enable_uci). No reboot, no reset — just run the PRG on the
    # existing state. If UCI misbehaves, the operator can power cycle.
    if not get_uci_enabled(client):
        log.info("enabling UCI via REST")
        enable_uci(client)
        time.sleep(0.5)
        if not get_uci_enabled(client):
            _skip(f"enable_uci did not stick on {host}")

    orig_mhz = _safe(get_turbo_mhz, client)
    orig_mode = _safe(get_debug_stream_mode, client) or ""
    local_ip = _local_ip_for(host)
    log.info("host=%s local_ip=%s", host, local_ip)

    cap, listener = DebugCapture(port=DEBUG_PORT), UDPEchoListener(port=0)
    result, trace_path, streamed, failures = None, None, False, []
    try:
        listener.start()
        log.info("echo listener bound on %s:%d", local_ip, listener.port)
        cap.start()
        set_debug_stream_mode(client, DEBUG_MODE_6510)
        set_turbo_mhz(client, 1)
        # Verify turbo stuck at 1 MHz (harness PR #106 footgun: prior 48 MHz
        # session can survive reset() and silently warp our measurements).
        try:
            check_measurement_environment(client)
        except Ultimate64MeasurementEnvironmentError as exc:
            _skip(f"unexpected turbo state: {exc}")
        _safe(set_reu, client, True, "512 KB")  # reu_mul_init needs REU
        time.sleep(0.5)
        client.stream_debug_start(f"{local_ip}:{DEBUG_PORT}")
        streamed = True
        with open(prg_path, "rb") as f:
            client.run_prg(f.read())
        log.info("PRG sent; waiting for boot...")
        _wait_boot(tr, L["mul_dma_hi"])
        failures = _run_sequence(tr, L, listener, local_ip)
        _safe(client.stream_debug_stop)
        streamed = False
        time.sleep(0.3)
        result = cap.stop()
        trace_path = _persist_trace(result, labels, mhz=1, mode=DEBUG_MODE_6510)
        if failures:
            print("FAIL — assertions did not hold:")
            for f in failures:
                print(f"  - {f}")
            print(f"Debug trace: {trace_path}")
            return 1
        print("PASS — UCI UDP echo round-trip verified.")
        print(f"Debug capture: packets={result.packets_received} "
              f"dropped={result.packets_dropped} "
              f"cycles={result.total_cycles} "
              f"duration={result.duration_seconds:.2f}s")
        print(f"Trace: {trace_path}")
        return 0
    finally:
        if streamed:
            _safe(client.stream_debug_stop)
        if result is None:
            try:
                time.sleep(0.2)
                trace_path = _persist_trace(
                    cap.stop(), labels, mhz=1, mode=DEBUG_MODE_6510,
                )
                print(f"Debug trace (partial): {trace_path}")
            except Exception as exc:
                log.warning("failed to persist trace: %s", exc)
        _safe(set_turbo_mhz, client, orig_mhz)
        if orig_mode:
            _safe(set_debug_stream_mode, client, orig_mode)
        _safe(listener.stop)
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
