#!/usr/bin/env python3
"""UCI UDP read-size probe.

Discovers UCI firmware (3.14d) UDP read semantics empirically by sending
the C64 datagrams of varying sizes and observing what `net_poll` recovers.

For each size in SIZES:
  1. Set the host-side responder's response_size.
  2. Reset C64 udp_recv_ready / udp_recv_len / udp_recv_buf bytes.
  3. Trigger a kick from the C64 via net_udp_send (always 32 bytes).
  4. Loop net_poll until udp_recv_ready or timeout.
  5. Read udp_recv_len + first 16 bytes + last byte; confirm against the
     expected pattern (byte i == i & 0xFF).

Reveals: whether the firmware truncates oversized datagrams (POSIX), splits
them across multiple SOCKET_READ calls (stream-style), refuses outright
(error status), or has size-dependent quirks.

Runs at 1 MHz with debug-stream capture for failure post-mortem.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = "/Users/someone/Documents/c64-test-harness/src"
if SRC not in sys.path:
    sys.path.insert(0, SRC)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from c64_test_harness import (
    Labels, enable_uci, get_uci_enabled, probe_u64, write_bytes,
)
from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.u64_debug_capture import DebugCapture
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    DEBUG_MODE_6510, get_debug_stream_mode, get_turbo_mhz,
    set_debug_stream_mode, set_reu, set_turbo_mhz,
)

# Reuse helpers from the echo test.
from test_uci_udp_echo_live import (  # type: ignore[import-not-found]
    BOOT_TIMEOUT, CARRY, DEBUG_PORT, GO_FLAG, SENTINEL, SEND_BUF,
    STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_SEND, STEP_POLL,
    STEP_TIMEOUT, TEST_PAYLOAD, TRAMP,
    _install_trampoline, _local_ip_for, _run_step, _safe, _wait_boot,
    log,
)

from uci.udp_size_responder import UDPSizeResponder, make_pattern  # type: ignore[import-not-found]

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
SIZES = [32, 100, 256, 400, 480, 512, 600, 768, 1024, 1280, 1500]
PER_SIZE_TIMEOUT = 3.0


def _required_labels() -> list[str]:
    return [
        "main_loop", "net_init", "net_dhcp", "net_udp_listen", "net_udp_send",
        "net_poll", "net_local_ip", "net_last_error", "mul_dma_hi",
        "wg_peer_ip", "wg_peer_port", "wg_local_port",
        "udp_recv_ready", "udp_recv_len", "udp_recv_buf", "udp_send_len_local",
    ]


def _setup_peer(tr: Ultimate64Transport, L: dict, host_ip: str, port: int) -> None:
    octets = bytes(int(x) for x in host_ip.split("."))
    write_bytes(tr, L["wg_peer_ip"], octets)
    write_bytes(tr, L["wg_peer_port"], bytes([port & 0xFF, port >> 8]))
    write_bytes(tr, L["wg_local_port"], bytes([port & 0xFF, port >> 8]))
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    write_bytes(tr, L["udp_send_len_local"], bytes([len(TEST_PAYLOAD), 0]))
    log.info("peer set to %s:%d", host_ip, port)


def _reset_recv_state(tr: Ultimate64Transport, L: dict) -> None:
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    # Wipe a guard region of udp_recv_buf so partial fills are visible.
    write_bytes(tr, L["udp_recv_buf"], b"\xCC" * 64)


def _verify_pattern(buf: bytes, expected_len: int) -> tuple[bool, str]:
    """Check that `buf[:expected_len]` matches the size-responder pattern."""
    expected = make_pattern(expected_len)
    if len(buf) < expected_len:
        return False, f"short read: got {len(buf)} need {expected_len}"
    actual = buf[:expected_len]
    if actual != expected[:expected_len]:
        for i, (a, e) in enumerate(zip(actual, expected)):
            if a != e:
                return False, f"mismatch at byte {i}: got ${a:02X} want ${e:02X}"
    return True, "OK"


def _probe_one_size(
    tr: Ultimate64Transport, L: dict, responder: UDPSizeResponder,
    size: int, listener_kick_ok: bool,
) -> dict:
    responder.response_size = size
    _reset_recv_state(tr, L)
    write_bytes(tr, SEND_BUF, TEST_PAYLOAD)
    write_bytes(tr, L["udp_send_len_local"], bytes([len(TEST_PAYLOAD), 0]))

    # Kick the responder.
    requests_before = responder.responses_sent
    send_carry = _run_step(
        tr, step_id=STEP_SEND, target=L["net_udp_send"],
        reg_a=SEND_BUF & 0xFF, reg_x=SEND_BUF >> 8,
    )
    nle_after_send = tr.read_memory(L["net_last_error"], 1)[0]

    # Wait for the responder to actually send (so the firmware has data).
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if responder.responses_sent > requests_before:
            break
        time.sleep(0.02)
    sent_back = responder.responses_sent > requests_before

    # Poll up to PER_SIZE_TIMEOUT for udp_recv_ready.
    polls = 0
    deadline = time.monotonic() + PER_SIZE_TIMEOUT
    ready = 0
    while time.monotonic() < deadline:
        _run_step(tr, step_id=STEP_POLL, target=L["net_poll"])
        polls += 1
        ready = tr.read_memory(L["udp_recv_ready"], 1)[0]
        if ready:
            break
        time.sleep(0.02)

    rx_len = 0
    rx_first = b""
    rx_tail = b""
    if ready:
        lo, hi = tr.read_memory(L["udp_recv_len"], 2)
        rx_len = lo | (hi << 8)
        # Cap reads at the buffer's known size (1500 bytes per src/wg/data.s)
        # AND keep within the 16-bit address space.
        max_buf = 1500
        n = min(rx_len, 64, max_buf)
        if n > 0:
            rx_first = bytes(tr.read_memory(L["udp_recv_buf"], n))
        if rx_len > 64:
            effective = min(rx_len, max_buf)
            tail_off = max(0, effective - 16)
            tail_addr = L["udp_recv_buf"] + tail_off
            if 0 <= tail_addr <= 0xFFFF - 16:
                rx_tail = bytes(tr.read_memory(tail_addr, 16))

    # Try a second poll to see if firmware has more (stream-style).
    second_ready = 0
    second_len = 0
    if ready:
        write_bytes(tr, L["udp_recv_ready"], bytes([0]))
        write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
        _run_step(tr, step_id=STEP_POLL, target=L["net_poll"])
        second_ready = tr.read_memory(L["udp_recv_ready"], 1)[0]
        if second_ready:
            lo, hi = tr.read_memory(L["udp_recv_len"], 2)
            second_len = lo | (hi << 8)

    nle_final = tr.read_memory(L["net_last_error"], 1)[0]
    return {
        "size": size,
        "send_carry": send_carry,
        "nle_after_send": nle_after_send,
        "sent_back": sent_back,
        "polls": polls,
        "ready": int(ready),
        "rx_len": rx_len,
        "rx_first16": rx_first[:16].hex(),
        "rx_tail16": rx_tail.hex() if rx_tail else "",
        "second_ready": int(second_ready),
        "second_len": second_len,
        "nle_final": f"${nle_final:02X}",
    }


def _print_summary(results: list[dict]) -> None:
    print()
    print("=" * 90)
    print(f"{'requested':>9} {'rx_len':>7} {'polls':>6} {'sent_back':>9} "
          f"{'ready':>5} {'2nd?':>5} {'2nd_len':>8} "
          f"{'nle':>4}  first16 / tail16")
    print("-" * 90)
    for r in results:
        first = r["rx_first16"]
        tail = r["rx_tail16"]
        print(
            f"{r['size']:>9} {r['rx_len']:>7} {r['polls']:>6} {str(r['sent_back']):>9} "
            f"{r['ready']:>5} {r['second_ready']:>5} {r['second_len']:>8} "
            f"{r['nle_final']:>4}  {first}{(' / ' + tail) if tail else ''}"
        )
    print("=" * 90)


def main() -> int:
    host = os.environ.get("U64_HOST")
    if not host:
        print("SKIP: U64_HOST not set", file=sys.stderr); return 77
    if not os.environ.get("U64_ALLOW_MUTATE"):
        print("SKIP: U64_ALLOW_MUTATE not set", file=sys.stderr); return 77

    if not probe_u64(host).reachable:
        print(f"SKIP: {host} unreachable"); return 77

    if not os.environ.get("C64_SKIP_BUILD"):
        import subprocess
        for cmd in (["make", "clean"], ["make", "BACKEND=uci"]):
            r = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True)
            if r.returncode != 0:
                sys.stderr.write(r.stderr.decode(errors="replace")); return 1

    labels = Labels.from_file(PROJECT_ROOT / "build" / "labels.txt")
    L = {n: labels[n] for n in _required_labels()}

    lock = DeviceLock(host)
    if not lock.acquire(timeout=120.0):
        print(f"SKIP: could not acquire device lock for {host}"); return 77

    client = Ultimate64Client(host=host, timeout=10.0)
    tr = Ultimate64Transport(host=host, timeout=10.0, client=client)

    log.info("rebooting U64 to clear UCI state...")
    client.reboot()
    time.sleep(10.0)
    if not get_uci_enabled(client):
        log.info("re-enabling UCI via REST")
        enable_uci(client); time.sleep(0.5)

    orig_mhz = _safe(get_turbo_mhz, client)
    orig_mode = _safe(get_debug_stream_mode, client) or ""
    local_ip = _local_ip_for(host)

    cap = DebugCapture(port=DEBUG_PORT)
    responder = UDPSizeResponder(port=0)
    results: list[dict] = []
    try:
        responder.start()
        log.info("size responder bound on %s:%d", local_ip, responder.port)
        cap.start()
        set_debug_stream_mode(client, DEBUG_MODE_6510)
        set_turbo_mhz(client, 1)
        _safe(set_reu, client, True, "512 KB")
        time.sleep(0.5)
        client.stream_debug_start(f"{local_ip}:{DEBUG_PORT}")

        prg = (PROJECT_ROOT / "build" / "wireguard.prg").read_bytes()
        client.run_prg(prg)
        log.info("PRG sent; waiting for boot...")
        _wait_boot(tr, L["mul_dma_hi"])
        _setup_peer(tr, L, local_ip, responder.port)
        _install_trampoline(tr, L["main_loop"])

        # Bring the WG net stack up and open the UCI socket via the first send.
        c = _run_step(tr, step_id=STEP_INIT, target=L["net_init"])
        if c != 0:
            log.error("net_init failed; aborting probe"); return 1
        _run_step(tr, step_id=STEP_DHCP, target=L["net_dhcp"])
        _run_step(tr, step_id=STEP_LISTEN, target=L["net_udp_listen"],
                  reg_a=responder.port & 0xFF, reg_x=responder.port >> 8)

        # Iterate sizes — each call kicks the responder, polls, records.
        for size in SIZES:
            log.info("--- probing size=%d ---", size)
            results.append(_probe_one_size(tr, L, responder, size, True))

    finally:
        try: client.stream_debug_stop()
        except Exception: pass
        time.sleep(0.3)
        result = cap.stop()
        ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = ARTIFACTS_DIR / f"uci_size_probe_{stamp}.txt"
        log.info("trace persisted to %s (cycles=%d)", path, result.total_cycles)
        with open(path, "w") as f:
            f.write(f"# packets={result.packets_received} dropped={result.packets_dropped} "
                    f"duration={result.duration_seconds:.3f} cycles={result.total_cycles}\n")
            for i, cyc in enumerate(result.trace):
                if not cyc.is_cpu: continue
                f.write(f"{i:08d} {cyc.address:04X} "
                        f"rw={'R' if cyc.is_read else 'W'} data={cyc.data:02X}\n")
        if orig_mhz is not None: _safe(set_turbo_mhz, client, orig_mhz)
        if orig_mode: _safe(set_debug_stream_mode, client, orig_mode)
        responder.stop(); responder.join(timeout=1.0)
        lock.release()

    _print_summary(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
