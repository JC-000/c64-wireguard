#!/usr/bin/env python3
"""Deterministic repro for the UCI STATE-bit wedge (harness #112).

Hypothesis under test (per user, 2026-05-19): the ~161 s ``uci_wait_idle``
wedge after ``SOCKET_WRITE`` is induced by REST-POST resource exhaustion
on the U64E REST stack — i.e. cumulative ``/v1/machine:writemem`` traffic
that builds up across PRG-load cycles in the live handshake test — rather
than by C64-side UCI usage patterns.

This tool isolates the two by loading the PRG **once** and then driving
``net_udp_send`` in a tight loop.  The only REST traffic in the control
arm is the GET-based SENTINEL polling that the trampoline pattern uses;
no further POSTs are issued after the single PRG load.  The treatment
arm spawns a background thread that floods writemem POSTs in parallel.

Arms (``--mode``):
  uci-only     : control — only the SENTINEL-poll reads; no POST traffic
                 after PRG load.
  rest-stress  : treatment — background thread floods writemem at the
                 configured rate/size, targeting a scratch RAM page.

Outcomes:
  * Wedge appears in *both* arms       → UCI-side state degradation
  * Wedge appears *only* in rest-stress → POST exhaustion confirmed
  * Wedge in neither (within budget)    → repro failed, try ``--iterations``

Gates: ``U64_HOST`` (default 10.43.23.81) and ``U64_ALLOW_MUTATE=1``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import logging
import os
import statistics
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from uci.udp_echo_listener import UDPEchoListener  # noqa: E402

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, enable_uci, get_uci_enabled,
    probe_u64, write_bytes,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    check_measurement_environment, get_turbo_mhz, recover, runner_health_check,
    set_reu, set_turbo_mhz,
    Ultimate64MeasurementEnvironmentError,
)

DEFAULT_HOST = "10.43.23.81"

# Trampoline + signal bytes — same layout as test_uci_udp_echo_live.py.
TRAMP, GO_FLAG, SENTINEL, CARRY, STEP_ID = 0x0334, 0x03E0, 0x03E1, 0x03E2, 0x03E3
SMC_REG_A, SMC_REG_X, SMC_TARG_LO, SMC_TARG_HI = 14, 16, 18, 19
STEP_INIT, STEP_DHCP, STEP_LISTEN, STEP_SEND = 0x11, 0x22, 0x33, 0x44
SEND_BUF = 0x02A7
PAYLOAD = bytes(range(0x40, 0x60))           # 32 B, avoids $00 for trace eyeballing
SCRATCH_ADDR = 0xCF00                        # high RAM, well above typical PRG load
SCRATCH_PAYLOAD_DEFAULT = bytes(64)          # ≤64 B per project-writemem-64b-threshold
BOOT_TIMEOUT = 60.0
WEDGE_THRESHOLD = 5.0                        # call > 5 s = wedge candidate
SEND_TIMEOUT = 200.0                         # let the 161-s wedge surface fully
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("uci_wedge_repro")


def _skip(reason: str) -> None:
    print(f"SKIP: {reason}", file=sys.stderr)
    sys.exit(77)


def _local_ip_for(host: str) -> str:
    import socket as _sk
    s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
    try:
        s.connect((host, 11000))
        return s.getsockname()[0]
    finally:
        s.close()


def _build_uci() -> None:
    import subprocess
    cmd = ["make", "clean"]
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True, capture_output=True)
    cmd = ["make", "BACKEND=uci"]
    r = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout.decode("utf-8", "replace"))
        sys.stderr.write(r.stderr.decode("utf-8", "replace"))
        raise RuntimeError(f"make BACKEND=uci failed (rc={r.returncode})")


def _build_trampoline() -> bytes:
    return bytes([
        0xAD, GO_FLAG & 0xFF, GO_FLAG >> 8,
        0xF0, 0xFB,
        0xA9, 0x00,
        0x8D, GO_FLAG & 0xFF, GO_FLAG >> 8,
        0x8D, SENTINEL & 0xFF, SENTINEL >> 8,
        0xA9, 0x00,
        0xA2, 0x00,
        0x20, 0xFF, 0xFF,
        0x08, 0x68, 0x29, 0x01,
        0x8D, CARRY & 0xFF, CARRY >> 8,
        0xAD, STEP_ID & 0xFF, STEP_ID >> 8,
        0x8D, SENTINEL & 0xFF, SENTINEL >> 8,
        0x4C, TRAMP & 0xFF, TRAMP >> 8,
    ])


def _wait_boot(tr: Ultimate64Transport, mul_dma_hi: int) -> None:
    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        last = tr.read_memory(mul_dma_hi + 255, 1)[0]
        if last == 0xFE:
            log.info("boot complete")
            return
        time.sleep(0.5)
    raise TimeoutError("reu_mul_init did not finish")


def _install_trampoline(tr: Ultimate64Transport, main_loop: int) -> None:
    write_bytes(tr, TRAMP, _build_trampoline())
    write_bytes(tr, GO_FLAG, bytes([0, 0, 0, 0]))
    hijack = bytes([0x4C, TRAMP & 0xFF, TRAMP >> 8])
    write_bytes(tr, main_loop, hijack)
    got = bytes(tr.read_memory(main_loop, 3))
    if got != hijack:
        raise RuntimeError(f"hijack failed: wrote {hijack.hex()}, read {got.hex()}")


def _run_step(tr: Ultimate64Transport, *, step_id: int, target: int,
              reg_a: int = 0, reg_x: int = 0,
              timeout: float = SEND_TIMEOUT) -> tuple[int, float]:
    """Drive one trampoline iteration. Returns (carry, wall_seconds)."""
    t = bytearray(_build_trampoline())
    t[SMC_REG_A], t[SMC_REG_X] = reg_a & 0xFF, reg_x & 0xFF
    t[SMC_TARG_LO], t[SMC_TARG_HI] = target & 0xFF, (target >> 8) & 0xFF
    write_bytes(tr, TRAMP, bytes(t))
    write_bytes(tr, SENTINEL, bytes([0, 0, step_id]))
    write_bytes(tr, GO_FLAG, bytes([1]))
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(SENTINEL, 1)[0] == step_id:
            carry = tr.read_memory(CARRY, 1)[0]
            return carry, time.monotonic() - started
        time.sleep(0.05)
    raise TimeoutError(
        f"step ${step_id:02X} timed out after {timeout}s "
        f"(SENTINEL=${tr.read_memory(SENTINEL, 1)[0]:02X})"
    )


def _setup_peer(tr: Ultimate64Transport, L: dict, local_ip: str,
                local_port: int) -> None:
    ip_bytes = bytes(int(o) for o in local_ip.split("."))
    port_be = bytes([local_port >> 8, local_port & 0xFF])
    port_le = bytes([local_port & 0xFF, local_port >> 8])
    write_bytes(tr, L["wg_peer_ip"], ip_bytes)
    write_bytes(tr, L["wg_peer_port"], port_be)
    write_bytes(tr, L["wg_local_port"], port_le)
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    write_bytes(tr, SEND_BUF, PAYLOAD)
    write_bytes(tr, L["udp_send_len_local"], bytes([len(PAYLOAD), 0]))


def _rest_stress_thread(tr: Ultimate64Transport, stop_event: threading.Event,
                        rate_hz: float, payload_size: int,
                        counter: dict) -> None:
    """Background writemem flooder. Counts requests + errors for the summary."""
    period = 1.0 / max(rate_hz, 0.01)
    payload = bytes((i & 0xFF) for i in range(payload_size))
    counter["posts"] = 0
    counter["errors"] = 0
    while not stop_event.is_set():
        cycle_start = time.monotonic()
        try:
            tr.write_memory(SCRATCH_ADDR, payload)
            counter["posts"] += 1
        except Exception as exc:
            counter["errors"] += 1
            log.warning("rest-stress writemem failed: %s", exc)
        sleep_for = period - (time.monotonic() - cycle_start)
        if sleep_for > 0:
            stop_event.wait(timeout=sleep_for)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=("uci-only", "rest-stress"),
                   default="uci-only",
                   help="Test arm. uci-only = control; rest-stress = POST flood.")
    p.add_argument("--iterations", type=int, default=80,
                   help="Number of net_udp_send calls (default: 80; "
                        "issue says wedge after equiv. of 2-3 handshake runs).")
    p.add_argument("--inter-call-delay", type=float, default=0.10,
                   help="Sleep between net_udp_send calls (s).")
    p.add_argument("--post-rate", type=float, default=10.0,
                   help="(rest-stress only) writemem POSTs per second.")
    p.add_argument("--post-size", type=int, default=64,
                   help="(rest-stress only) bytes per writemem POST "
                        "(<=64 per project-writemem-64b-threshold).")
    p.add_argument("--no-rebuild", action="store_true",
                   help="Skip make clean + make BACKEND=uci.")
    p.add_argument("--max-wedges", type=int, default=2,
                   help="Bail after this many wedged iters (caps wall-clock; "
                        "first wedge alone disambiguates the hypothesis).")
    args = p.parse_args()

    if args.post_size > 64:
        _skip("--post-size > 64 hits the writemem 64-B threshold (see memory)")

    host = os.environ.get("U64_HOST", DEFAULT_HOST)
    if not host:
        _skip("U64_HOST not set")
    if os.environ.get("U64_ALLOW_MUTATE") != "1":
        _skip("U64_ALLOW_MUTATE=1 required")
    password = os.environ.get("U64_PASSWORD")
    probe = probe_u64(host, password=password)
    if not probe.reachable:
        _skip(f"U64 at {host} not reachable: {probe.error}")

    if not args.no_rebuild:
        _build_uci()

    labels_path = PROJECT_ROOT / "build" / "labels.txt"
    prg_path = PROJECT_ROOT / "build" / "wireguard.prg"
    if not labels_path.exists() or not prg_path.exists():
        print(f"FATAL: missing {labels_path} or {prg_path}", file=sys.stderr)
        return 1

    required = ("main_loop", "net_init", "net_dhcp", "net_udp_listen",
                "net_udp_send", "net_local_ip", "net_last_error", "mul_dma_hi",
                "wg_peer_ip", "wg_peer_port", "wg_local_port",
                "udp_recv_ready", "udp_recv_len", "udp_send_len_local")
    labels = Labels.from_file(labels_path)
    L = {}
    for n in required:
        a = labels.address(n)
        if a is None:
            print(f"FATAL: missing label: {n}", file=sys.stderr)
            return 1
        L[n] = a

    lock = DeviceLock(host)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        log.error("DeviceLock acquire failed: %s", e)
        _skip(str(e))

    client = Ultimate64Client(host=host, password=password, timeout=10.0)
    tr = Ultimate64Transport(host=host, password=password, timeout=10.0,
                             client=client)

    try:
        runner_health_check(client)
    except Ultimate64RunnerStuckError as exc:
        log.warning("runner wedged: %s — recover()ing", exc)
        recover(client)
        runner_health_check(client)

    if not get_uci_enabled(client):
        enable_uci(client)
        time.sleep(0.5)
        if not get_uci_enabled(client):
            _skip("enable_uci did not stick")

    orig_mhz = get_turbo_mhz(client)
    local_ip = _local_ip_for(host)

    listener = UDPEchoListener(port=0)
    listener.start()
    log.info("listener bound on %s:%d", local_ip, listener.port)

    set_turbo_mhz(client, 1)
    try:
        check_measurement_environment(client)
    except Ultimate64MeasurementEnvironmentError as exc:
        _skip(f"unexpected turbo state: {exc}")
    set_reu(client, True, "512 KB")
    time.sleep(0.5)

    with open(prg_path, "rb") as f:
        client.run_prg(f.read())
    log.info("PRG sent — waiting for boot")
    _wait_boot(tr, L["mul_dma_hi"])

    _setup_peer(tr, L, local_ip, listener.port)
    _install_trampoline(tr, L["main_loop"])
    time.sleep(0.05)

    # One-shot setup steps.
    for name, sid in (("net_init", STEP_INIT),
                      ("net_dhcp", STEP_DHCP)):
        c, dt = _run_step(tr, step_id=sid, target=L[name], timeout=15.0)
        nle = tr.read_memory(L["net_last_error"], 1)[0]
        log.info("%s: carry=%d nle=$%02X dt=%.2fs", name, c, nle, dt)
        if c != 0:
            _skip(f"{name} failed (nle=${nle:02X})")
    c, dt = _run_step(tr, step_id=STEP_LISTEN, target=L["net_udp_listen"],
                      reg_a=listener.port & 0xFF, reg_x=listener.port >> 8,
                      timeout=10.0)
    log.info("net_udp_listen: carry=%d dt=%.2fs", c, dt)
    if c != 0:
        _skip("net_udp_listen failed")

    # Optional POST stressor.
    stop_event = threading.Event()
    counter: dict = {}
    stress_thread = None
    if args.mode == "rest-stress":
        stress_thread = threading.Thread(
            target=_rest_stress_thread,
            args=(tr, stop_event, args.post_rate, args.post_size, counter),
            daemon=True,
        )
        stress_thread.start()
        log.info("rest-stress thread started: %.1f Hz x %d B writemem to $%04X",
                 args.post_rate, args.post_size, SCRATCH_ADDR)

    log.info("=== STRESS LOOP: %d net_udp_send calls (mode=%s) ===",
             args.iterations, args.mode)
    iter_records: list[dict] = []
    wedge_first_iter = None
    try:
        for i in range(args.iterations):
            # Refresh send buffer so each datagram has a unique tag we can
            # observe in the listener.  Single small writemem per iter.
            tag = bytes([(i >> 8) & 0xFF, i & 0xFF]) + PAYLOAD[2:]
            write_bytes(tr, SEND_BUF, tag)
            recv_before = len(listener.received)
            c, dt = _run_step(tr, step_id=STEP_SEND, target=L["net_udp_send"],
                              reg_a=SEND_BUF & 0xFF, reg_x=SEND_BUF >> 8,
                              timeout=SEND_TIMEOUT)
            nle = tr.read_memory(L["net_last_error"], 1)[0]
            # udp_send_len_local low byte = what we just told the firmware to send;
            # echoing this in the log makes the trace comparable to the issue's
            # "send_len_lo=$94" wedge sentinel.
            send_lo = tr.read_memory(L["udp_send_len_local"], 1)[0]
            # Wait briefly for the host listener to confirm arrival.
            arrive_dl = time.monotonic() + 1.0
            arrived = False
            while time.monotonic() < arrive_dl:
                if len(listener.received) > recv_before:
                    arrived = True
                    break
                time.sleep(0.02)
            rec = dict(i=i, dt=dt, carry=c, nle=nle,
                       send_lo=send_lo, arrived=arrived)
            iter_records.append(rec)
            level = (log.warning if dt > WEDGE_THRESHOLD or not arrived
                     else log.info)
            level("iter %3d  dt=%6.2fs  carry=%d  nle=$%02X  send_lo=$%02X  "
                  "arrived=%s", i, dt, c, nle, send_lo, arrived)
            if dt > WEDGE_THRESHOLD:
                if wedge_first_iter is None:
                    wedge_first_iter = i
                wedge_count = sum(1 for r in iter_records if r["dt"] > WEDGE_THRESHOLD)
                if wedge_count >= args.max_wedges:
                    log.warning("--max-wedges=%d reached; bailing", args.max_wedges)
                    break
            if args.inter_call_delay > 0:
                time.sleep(args.inter_call_delay)
    finally:
        stop_event.set()
        if stress_thread is not None:
            stress_thread.join(timeout=2.0)
        try:
            set_turbo_mhz(client, orig_mhz)
        except Exception:
            pass
        listener.stop()
        lock.release()

    # ---------- summary ----------
    dts = [r["dt"] for r in iter_records]
    arrived = sum(1 for r in iter_records if r["arrived"])
    wedges = [r for r in iter_records if r["dt"] > WEDGE_THRESHOLD]
    print()
    print("=" * 70)
    print(f"UCI WEDGE REPRO — mode={args.mode}  iters={len(iter_records)}")
    print("=" * 70)
    print(f"net_udp_send dt:  min={min(dts):.2f}  p50={statistics.median(dts):.2f}  "
          f"p95={statistics.quantiles(dts, n=20)[-1]:.2f}  max={max(dts):.2f}  (seconds)")
    print(f"listener-arrived: {arrived}/{len(iter_records)}")
    print(f"wedges (dt>{WEDGE_THRESHOLD}s): {len(wedges)}")
    if wedges:
        print(f"first wedge at iter {wedge_first_iter}; "
              f"dts of wedged iters: " +
              ", ".join(f"i{w['i']}={w['dt']:.1f}s" for w in wedges[:10]) +
              (" ..." if len(wedges) > 10 else ""))
    if args.mode == "rest-stress":
        print(f"writemem POSTs:   ok={counter.get('posts', 0)}  "
              f"errors={counter.get('errors', 0)}")

    # Persist artifact.
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ARTIFACTS_DIR / f"uci_wedge_{args.mode}_{stamp}.txt"
    with open(out, "w") as f:
        f.write(f"# mode={args.mode} iters={len(iter_records)} "
                f"first_wedge={wedge_first_iter}\n")
        f.write("# iter dt_seconds carry nle send_lo arrived\n")
        for r in iter_records:
            f.write(f"{r['i']:4d} {r['dt']:7.3f} {r['carry']} "
                    f"${r['nle']:02X} ${r['send_lo']:02X} "
                    f"{'1' if r['arrived'] else '0'}\n")
    print(f"\nDetailed log: {out}")
    return 0 if wedges else 0  # always exit 0; wedge presence is the data


if __name__ == "__main__":
    sys.exit(main())
