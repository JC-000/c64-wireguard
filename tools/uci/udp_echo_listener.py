"""UDP echo server for live UCI round-trip tests. Binds on
``0.0.0.0:<port>``, echoes every incoming datagram back to its sender
verbatim, and records ``(src_addr, payload)`` for post-hoc inspection.
A daemon thread drives the recv/echo loop; ``received`` is RLock-guarded.

    with UDPEchoListener(port=0) as listener:
        ...  # drive the C64
        for src, payload in listener.received: ...
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import List, Tuple

__all__ = ["UDPEchoListener"]

_log = logging.getLogger(__name__)


class UDPEchoListener:
    """UDP echo server that records every packet it handles."""

    def __init__(
        self, port: int = 0, bind_addr: str = "", max_payload: int = 2048,
    ) -> None:
        self._port = port
        self._bind_addr = bind_addr
        self._max_payload = max_payload
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._received: List[Tuple[Tuple[str, int], bytes]] = []

    def start(self) -> None:
        """Bind and start the background recv/echo thread."""
        if self._sock is not None:
            raise RuntimeError("UDPEchoListener already started")
        self._stop_event.clear()
        with self._lock:
            self._received.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._bind_addr, self._port))
        self._port = sock.getsockname()[1]
        sock.settimeout(0.25)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._recv_loop, name="udp-echo-listener", daemon=True,
        )
        self._thread.start()
        _log.info("UDPEchoListener bound on %s:%d",
                  self._bind_addr or "0.0.0.0", self._port)

    def stop(self) -> None:
        """Signal the recv thread to exit and close the socket."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "UDPEchoListener":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def port(self) -> int:
        """UDP port currently bound; valid after :meth:`start`."""
        return self._port

    @property
    def received(self) -> List[Tuple[Tuple[str, int], bytes]]:
        """Snapshot copy of ``(src_addr, payload)`` tuples received so far."""
        with self._lock:
            return list(self._received)

    def clear(self) -> None:
        """Drop all recorded packets."""
        with self._lock:
            self._received.clear()

    def _recv_loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while not self._stop_event.is_set():
            try:
                payload, src = sock.recvfrom(self._max_payload)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise
            with self._lock:
                self._received.append((src, payload))
            _log.info(
                "echo from %s:%d len=%d first16=%s",
                src[0], src[1], len(payload), payload[:16].hex(),
            )
            try:
                sock.sendto(payload, src)
            except OSError as exc:
                _log.warning("echo sendto %r failed: %s", src, exc)
