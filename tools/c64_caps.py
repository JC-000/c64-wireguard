"""Single source of truth for the C64's datagram ceilings, on the host side.

The numbers live in the assembly sources and, since issue #70, DEPEND ON HOW
THE PRG WAS BUILT: `make BACKEND=uci UCI_CHUNKED_WRITE=1` sends with the
firmware's chunked $16 command and advertises NET_UDP_SEND_MAX = 1472 /
WG_MTU = 1440, the default build 892 / 860. So the host tools read the values
FROM THE BUILD — build/labels.txt, where src/exports.s promotes the equates
to linker labels — and only fall back to parsing the .inc files when no
build is present. A hardcoded 240/512 once hid a real bug for months (see
the "Correction (2026-08-26)" paragraph in the README's Tunnel MTU section);
a regex that happened to take the first `.ifdef` branch would hide this one.

    NET_UDP_SEND_MAX   largest datagram the C64 can SEND    (labels.txt; src/net/uci/net_caps.inc)
    NET_UDP_RECV_MAX   largest datagram the C64 can RECEIVE (labels.txt; src/net/uci/net_caps.inc)
    WG_DATA_OVERHEAD   Type-4 header (16) + Poly1305 tag (16) (labels.txt; src/constants.inc)
    WG_MTU             the built tunnel MTU (labels.txt only; cross-checks the derivation)

Exports
    C64_SEND_MAX     = NET_UDP_SEND_MAX                    (892; 1472 chunked)
    C64_RECV_MAX     = NET_UDP_RECV_MAX                    (1472)
    C64_TUNNEL_MTU   = min(SEND, RECV) - WG_DATA_OVERHEAD  (860; 1440 chunked)
    C64_RECV_MTU     = RECV - WG_DATA_OVERHEAD             (1440: what the C64
                       can accept inbound regardless of the send side)
    C64_CHUNKED      = True iff the build carries the chunked send path
                       (the `uci_send_part` label is present in labels.txt)
    FROM_LABELS      = True iff every value came from build/labels.txt
    FROM_SOURCE      = True iff every value came from a real file (labels or .inc)

Selecting the build: the module-level constants come from
`$C64_WG_LABELS` if set, else <repo>/build/labels.txt. `load_caps(path)`
returns the same numbers for any labels.txt (or any directory holding one),
for tools that hold several builds at once.

If neither a labels.txt nor the source .inc files can be found, the
hardware-verified defaults below are used and a warning is emitted naming
which value fell back. The host has no RAM constraint of its own and must
never be the thing that caps the tunnel.
"""
from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NET_CAPS_INC = PROJECT_ROOT / "src" / "net" / "uci" / "net_caps.inc"
CONSTANTS_INC = PROJECT_ROOT / "src" / "constants.inc"
DEFAULT_LABELS = PROJECT_ROOT / "build" / "labels.txt"
LABELS_ENV = "C64_WG_LABELS"

# Hardware-verified on U64E, 2026-08-27 (send on 3.14d; receive 1472 needs
# the fw 3.15 multi-block SOCKET_READ, the UCI backend's minimum). Do not
# re-derive. These are the DEFAULT (non-chunked) build's numbers.
_DEFAULTS = {
    "NET_UDP_SEND_MAX": 892,
    "NET_UDP_RECV_MAX": 1472,
    "WG_DATA_OVERHEAD": 32,
}

# Which .inc each symbol's source fallback lives in.
_SOURCE_OF = {
    "NET_UDP_SEND_MAX": NET_CAPS_INC,
    "NET_UDP_RECV_MAX": NET_CAPS_INC,
    "WG_DATA_OVERHEAD": CONSTANTS_INC,
}

# The label whose presence proves a chunked build (src/net/uci/net.s exports
# it only under UCI_CHUNKED_WRITE). Structural, not textual: a PRG either
# has the routine or it does not.
CHUNK_LABEL = "uci_send_part"

_ASSIGN_RE = r"^\s*{name}\s*=\s*(\$[0-9A-Fa-f]+|[0-9]+)\b"
# ld65 -Ln line: `al C:982D .msg_input_buf`
_LABEL_RE = re.compile(r"^al\s+C:([0-9A-Fa-f]+)\s+\.(\S+)\s*$")


def _read_labels(path: Path) -> dict[str, int] | None:
    """Parse an ld65 labels.txt into {name: value}, or None if unreadable."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = _LABEL_RE.match(line)
        if m:
            out[m.group(2)] = int(m.group(1), 16)
    return out or None


def _read_symbol(path: Path, name: str) -> int | None:
    """Return the integer bound to a ca65 `NAME = value` line, or None.

    The LAST assignment wins: net_caps.inc / constants.inc spell the
    flag-dependent values as `.ifdef UCI_CHUNKED_WRITE / <flag> / .else /
    <default> / .endif`, so the last match is the default (non-chunked)
    build. Source parsing can only ever describe that build; a chunked PRG
    is recognised from its labels.txt.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    ms = re.findall(_ASSIGN_RE.format(name=re.escape(name)), text, re.MULTILINE)
    if not ms:
        return None
    tok = ms[-1]
    return int(tok[1:], 16) if tok.startswith("$") else int(tok, 10)


def _rel(path: Path) -> Path:
    try:
        return path.relative_to(PROJECT_ROOT)
    except ValueError:
        return path


@dataclass(frozen=True)
class Caps:
    send_max: int
    recv_max: int
    overhead: int
    chunked: bool
    from_labels: bool
    from_source: bool
    labels_path: Path | None
    mtu_label: int | None = None    # WG_MTU as exported by the build, if any

    @property
    def tunnel_mtu(self) -> int:
        return min(self.send_max, self.recv_max) - self.overhead

    @property
    def recv_mtu(self) -> int:
        return self.recv_max - self.overhead

    def describe(self) -> str:
        if self.from_labels:
            src = f"labels {_rel(self.labels_path)}"
        elif self.from_source:
            src = "src/ (.inc files; describes the DEFAULT build)"
        else:
            src = "DEFAULTS (no build, source .inc missing)"
        kind = "chunked $16 send" if self.chunked else "plain SOCKET_WRITE"
        return (f"C64 caps [{src}; {kind}]: send {self.send_max} B, recv "
                f"{self.recv_max} B, overhead {self.overhead} B -> tunnel MTU "
                f"{self.tunnel_mtu} (recv-side {self.recv_mtu})")


def load_caps(labels: Path | str | None = None, *, warn: bool = True) -> Caps:
    """Resolve the caps for one build.

    `labels` is a labels.txt path or a directory containing build/labels.txt
    or labels.txt; None means $C64_WG_LABELS, else <repo>/build/labels.txt.
    Labels win; each symbol missing from them falls back to its .inc, then
    to the hardware-verified default (with a warning when `warn`).
    """
    if labels is None:
        env = os.environ.get(LABELS_ENV)
        labels_path = Path(env) if env else DEFAULT_LABELS
    else:
        labels_path = Path(labels)
    if labels_path.is_dir():
        for cand in (labels_path / "build" / "labels.txt",
                     labels_path / "labels.txt"):
            if cand.exists():
                labels_path = cand
                break

    table = _read_labels(labels_path)
    values: dict[str, int] = {}
    from_labels = table is not None
    from_source = True
    for name in _DEFAULTS:
        if table is not None and name in table:
            values[name] = table[name]
            continue
        from_labels = False
        v = _read_symbol(_SOURCE_OF[name], name)
        if v is None:
            from_source = False
            v = _DEFAULTS[name]
            if warn:
                where = (f"{_rel(labels_path)} or " if table is not None else "")
                warnings.warn(
                    f"c64_caps: {name} not found in {where}"
                    f"{_rel(_SOURCE_OF[name])}; using hardware-verified "
                    f"default {v} (2026-08-27)", RuntimeWarning, stacklevel=2)
        values[name] = v

    chunked = bool(table) and CHUNK_LABEL in table
    mtu_label = table.get("WG_MTU") if table else None
    caps = Caps(values["NET_UDP_SEND_MAX"], values["NET_UDP_RECV_MAX"],
                values["WG_DATA_OVERHEAD"], chunked, from_labels,
                from_source, labels_path if table is not None else None,
                mtu_label)
    if mtu_label is not None and mtu_label != caps.tunnel_mtu and warn:
        # The consumer may clamp below the backend caps (WG_DATAGRAM_CAP,
        # e.g. ip65: caps 1472/1472 but WG_MTU 860). Trust the build.
        warnings.warn(
            f"c64_caps: built WG_MTU {mtu_label} != min(send, recv) - "
            f"overhead {caps.tunnel_mtu}; the build's WG_DATAGRAM_CAP clamps "
            f"below the backend caps — using the built value",
            RuntimeWarning, stacklevel=2)
        caps = Caps(min(caps.send_max, mtu_label + caps.overhead),
                    caps.recv_max, caps.overhead, chunked, from_labels,
                    from_source, caps.labels_path, mtu_label)
    return caps


_CAPS = load_caps()

C64_SEND_MAX = _CAPS.send_max
C64_RECV_MAX = _CAPS.recv_max
WG_DATA_OVERHEAD = _CAPS.overhead
C64_TUNNEL_MTU = _CAPS.tunnel_mtu
C64_RECV_MTU = _CAPS.recv_mtu
C64_CHUNKED = _CAPS.chunked
FROM_LABELS = _CAPS.from_labels
FROM_SOURCE = _CAPS.from_source or _CAPS.from_labels
LABELS_PATH = _CAPS.labels_path

__all__ = [
    "C64_SEND_MAX", "C64_RECV_MAX", "C64_TUNNEL_MTU", "C64_RECV_MTU",
    "C64_CHUNKED", "WG_DATA_OVERHEAD", "FROM_LABELS", "FROM_SOURCE",
    "LABELS_PATH", "NET_CAPS_INC", "CONSTANTS_INC", "DEFAULT_LABELS",
    "LABELS_ENV", "CHUNK_LABEL", "Caps", "load_caps", "describe",
]


def describe() -> str:
    return _CAPS.describe()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(load_caps(sys.argv[1]).describe())
    else:
        print(describe())
