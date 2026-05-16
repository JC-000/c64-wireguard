"""UDP responder that replies with a configurable-size payload.

Receives any packet from a peer, then replies with a payload sized to
``response_size`` bytes containing a recognisable pattern: byte i = i & 0xFF.
Used by tools/test_uci_udp_size_probe.py to learn UCI firmware's UDP read
semantics for datagrams larger than the SOCKET_READ maxlen.
"""
from __future__ import annotations

import logging
import socket
import threading

log = logging.getLogger(__name__)


def make_pattern(n: int) -> bytes:
    """Pattern: byte i = i & 0xFF. So bytes 0,1,2,...255,0,1,2,..."""
    return bytes((i & 0xFF) for i in range(n))


class UDPSizeResponder(threading.Thread):
    def __init__(self, port: int = 0):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.response_size = 32
        self.last_request: tuple | None = None
        self.responses_sent = 0
        self._stop = threading.Event()

    def run(self) -> None:
        log.info("UDPSizeResponder bound on 0.0.0.0:%d", self.port)
        while not self._stop.is_set():
            try:
                data, src = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            self.last_request = (src, data)
            payload = make_pattern(self.response_size)
            self.sock.sendto(payload, src)
            self.responses_sent += 1
            log.info(
                "responder: kick from %s (len=%d), replied with %d bytes",
                src, len(data), self.response_size,
            )

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass

    def __enter__(self) -> "UDPSizeResponder":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()
        self.join(timeout=1.0)
