"""UDP responder that replies with a configurable-size payload.

Receives any packet from a peer, then replies with a payload sized to
``response_size`` bytes containing a recognisable pattern: byte i = i & 0xFF.
Used by tools/test_uci_udp_size_probe.py to learn UCI firmware's UDP read
semantics for datagrams larger than the SOCKET_READ maxlen.

``response_payload`` overrides the default pattern with caller-supplied
bytes. The probe needs that because ``make_pattern``'s byte i = i & 0xFF
COLLIDES with a poison fill: any poison scheme has some offset where the
pattern happens to carry the poison byte, and a coincidental match shortens
a backward poison scan. The probe therefore sends bytes chosen to differ
from the poison at every offset (see ``_payload_for`` there) and needs the
responder to put exactly those bytes on the wire.
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
        #: Exact bytes to reply with. When set, it wins over
        #: ``response_size`` and is sent verbatim — the caller is
        #: responsible for its length.
        self.response_payload: bytes | None = None
        self.last_request: tuple | None = None
        #: Bytes of the most recent reply, so a caller can compare what the
        #: C64 holds against what actually crossed the wire rather than
        #: against what it MEANT to send.
        self.last_response: bytes | None = None
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
            payload = (self.response_payload if self.response_payload
                       is not None else make_pattern(self.response_size))
            self.sock.sendto(payload, src)
            self.last_response = payload
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
