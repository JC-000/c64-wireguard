"""Single source of truth for the C64's datagram ceilings, on the host side.

The numbers live in the assembly sources; the host tools read them from there
at import time so that a change to the .inc files cannot leave a Python
constant silently stale (a hardcoded 240/512 once hid a real bug for months —
see the "Correction (2026-08-26)" paragraph in the README's Tunnel MTU
section).

    NET_UDP_SEND_MAX   src/net/uci/net_caps.inc   largest datagram the C64 can SEND
    NET_UDP_RECV_MAX   src/net/uci/net_caps.inc   largest datagram the C64 can RECEIVE
    WG_DATA_OVERHEAD   src/constants.inc          Type-4 header (16) + Poly1305 tag (16)

Exports
    C64_SEND_MAX     = NET_UDP_SEND_MAX                    (892 today)
    C64_RECV_MAX     = NET_UDP_RECV_MAX                    (1472 today)
    C64_TUNNEL_MTU   = min(SEND, RECV) - WG_DATA_OVERHEAD  (860 today, send-bound)
    C64_RECV_MTU     = RECV - WG_DATA_OVERHEAD             (1440: what the C64
                       can accept inbound; becomes the tunnel MTU if the
                       firmware ships WRITE_SOCKET_MORE, GideonZ/1541ultimate#802)

If a source file (or a symbol in it) cannot be found — e.g. a worktree that
predates net_caps.inc — the hardware-verified defaults below are used and a
warning is emitted naming which value fell back. The host has no RAM
constraint of its own and must never be the thing that caps the tunnel.
"""
from __future__ import annotations

import re
import warnings
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NET_CAPS_INC = PROJECT_ROOT / "src" / "net" / "uci" / "net_caps.inc"
CONSTANTS_INC = PROJECT_ROOT / "src" / "constants.inc"

# Hardware-verified on U64E, 2026-08-27 (send on 3.14d; receive 1472 needs
# the fw 3.15 multi-block SOCKET_READ, the UCI backend's minimum). Do not
# re-derive.
_DEFAULTS = {
    "NET_UDP_SEND_MAX": 892,
    "NET_UDP_RECV_MAX": 1472,
    "WG_DATA_OVERHEAD": 32,
}

_ASSIGN_RE = r"^\s*{name}\s*=\s*(\$[0-9A-Fa-f]+|[0-9]+)\b"


def _read_symbol(path: Path, name: str) -> int | None:
    """Return the integer bound to a ca65 `NAME = value` line, or None."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.search(_ASSIGN_RE.format(name=re.escape(name)), text, re.MULTILINE)
    if not m:
        return None
    tok = m.group(1)
    return int(tok[1:], 16) if tok.startswith("$") else int(tok, 10)


def _load(path: Path, name: str) -> tuple[int, bool]:
    value = _read_symbol(path, name)
    if value is None:
        try:
            rel = path.relative_to(PROJECT_ROOT)
        except ValueError:
            rel = path
        warnings.warn(
            f"c64_caps: {name} not found in {rel}; using hardware-verified "
            f"default {_DEFAULTS[name]} (2026-08-27)",
            RuntimeWarning, stacklevel=3)
        return _DEFAULTS[name], False
    return value, True


C64_SEND_MAX, SEND_FROM_SOURCE = _load(NET_CAPS_INC, "NET_UDP_SEND_MAX")
C64_RECV_MAX, RECV_FROM_SOURCE = _load(NET_CAPS_INC, "NET_UDP_RECV_MAX")
WG_DATA_OVERHEAD, OVERHEAD_FROM_SOURCE = _load(CONSTANTS_INC, "WG_DATA_OVERHEAD")

C64_TUNNEL_MTU = min(C64_SEND_MAX, C64_RECV_MAX) - WG_DATA_OVERHEAD
C64_RECV_MTU = C64_RECV_MAX - WG_DATA_OVERHEAD
FROM_SOURCE = SEND_FROM_SOURCE and RECV_FROM_SOURCE and OVERHEAD_FROM_SOURCE

__all__ = [
    "C64_SEND_MAX", "C64_RECV_MAX", "C64_TUNNEL_MTU", "C64_RECV_MTU",
    "WG_DATA_OVERHEAD", "FROM_SOURCE", "NET_CAPS_INC", "CONSTANTS_INC",
]


def describe() -> str:
    src = "src/" if FROM_SOURCE else "DEFAULTS (source .inc missing)"
    return (f"C64 caps [{src}]: send {C64_SEND_MAX} B, recv {C64_RECV_MAX} B, "
            f"overhead {WG_DATA_OVERHEAD} B -> tunnel MTU {C64_TUNNEL_MTU} "
            f"(recv-side {C64_RECV_MTU})")


if __name__ == "__main__":
    print(describe())
