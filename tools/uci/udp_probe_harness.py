#!/usr/bin/env python3
"""Direct UCI UDP round-trip probe using harness's validated builders.

Bypasses c64-wireguard's UCI backend entirely. If this works, our adapter
has a bug; if it doesn't, UCI firmware doesn't receive on connected UDP
sockets — a finding that reshapes the design.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

from c64_test_harness import (
    enable_uci, get_uci_enabled,
    uci_probe, uci_udp_connect, uci_socket_write, uci_socket_read,
    uci_socket_close, uci_get_ip,
)
from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client


HOST = os.environ.get("U64_HOST", "10.43.23.81")


def _local_ip_for(remote_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((remote_ip, 53))
    ip = s.getsockname()[0]
    s.close()
    return ip


class EchoThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.received: list[tuple] = []
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data, src = self.sock.recvfrom(2048)
                self.received.append((src, data))
                print(f"[echo] got {len(data)} bytes from {src}: {data.hex()}")
                self.sock.sendto(data, src)
                print(f"[echo] echoed back to {src}")
            except socket.timeout:
                pass

    def stop(self):
        self._stop.set()
        self.sock.close()


def main():
    if not get_uci_enabled_quick(HOST):
        print(f"enabling UCI on {HOST}...")
    client = Ultimate64Client(host=HOST, timeout=10.0)
    if not get_uci_enabled(client):
        enable_uci(client)
        time.sleep(0.5)
        assert get_uci_enabled(client)

    lock = DeviceLock(HOST)
    if not lock.acquire(timeout=60.0):
        print("could not acquire device lock")
        return 2
    try:
        tr = Ultimate64Transport(host=HOST, timeout=10.0, client=client)

        # Soft reset only — reboot() resets the FPGA and loses UCI config.
        # The live-test pattern (tests/test_uci_turbo_live.py) uses
        # client.reset() + 3s settle after enable_uci.
        print("soft-reset U64...")
        client.reset()
        time.sleep(3.0)
        # UCI may need re-enable after reset on some firmwares.
        if not get_uci_enabled(client):
            enable_uci(client)
            time.sleep(0.5)

        assert uci_probe(tr) == 0xC9
        my_ip = uci_get_ip(tr)
        print(f"U64 IP: {my_ip}")

        local_ip = _local_ip_for(HOST)
        echo = EchoThread()
        echo.start()
        print(f"echo listener on {local_ip}:{echo.port}")

        print(f"uci_udp_connect -> {local_ip}:{echo.port}")
        sock_id = uci_udp_connect(tr, local_ip, echo.port)
        print(f"  socket_id = {sock_id}")

        payload = b"HELLO-UCI-UDP\n"
        print(f"uci_socket_write {len(payload)} bytes")
        written = uci_socket_write(tr, sock_id, payload)
        print(f"  written = {written}")

        # Wait briefly for echo to arrive at the firmware.
        time.sleep(0.5)

        print("uci_socket_read loop (up to 5 attempts)...")
        got = None
        for i in range(5):
            data = uci_socket_read(tr, sock_id, max_len=255)
            print(f"  attempt {i}: len={len(data) if data else 0}"
                  + (f" data={data.hex()}" if data else ""))
            if data:
                got = data
                break
            time.sleep(0.3)

        try:
            uci_socket_close(tr, sock_id)
        except Exception as e:
            print(f"close error (non-fatal): {e}")

        echo.stop()
        echo.join(timeout=1.0)

        if got == payload:
            print("=== PASS: UDP round-trip via UCI firmware works ===")
            return 0
        elif got:
            print(f"=== PARTIAL: got {got.hex()}, expected {payload.hex()} ===")
            return 3
        else:
            print("=== FAIL: firmware never delivered the echo via SOCKET_READ ===")
            print(f"listener received {len(echo.received)} packet(s) — "
                  "write path works; receive path does not")
            return 1
    finally:
        lock.release()


def get_uci_enabled_quick(host: str) -> bool:
    try:
        c = Ultimate64Client(host=host, timeout=3.0)
        return get_uci_enabled(c)
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
