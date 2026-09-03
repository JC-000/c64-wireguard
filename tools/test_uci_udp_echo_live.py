#!/usr/bin/env python3
"""Live Ultimate 64 Elite test: UCI backend UDP echo end-to-end.

Drives net_init -> net_dhcp_acquire -> net_udp_listen -> net_udp_send -> net_poll
on real hardware against a host-side UDP echo server, under a full
debug-bus-cycle capture so any failure can be root-caused from the
trace artifact.

Gates: ``U64_HOST`` (default 10.43.23.81) and ``U64_ALLOW_MUTATE=1``.
Skip exit is 77.  Run::

    U64_HOST=10.43.23.81 U64_ALLOW_MUTATE=1 \\
        python3 tools/test_uci_udp_echo_live.py

Issue #70 chunked-write sweep (build once, then never let the tool rebuild)::

    make clean && make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
    C64_SKIP_BUILD=1 ECHO_PAYLOAD_SWEEP=1 U64_ALLOW_MUTATE=1 \\
        python3 tools/test_uci_udp_echo_live.py

or ``ECHO_PAYLOAD_LEN=888,889,1472`` for a hand-picked list. Every size is
sent once, on one boot; per size the tool asserts the listener saw exactly
ONE datagram of exactly that length (a torn 888+584 write is two), and that
sizes above the build's exported NET_UDP_SEND_MAX are refused with $8C and
never reach the wire. Run once against stock 3.15 to see $8E.

Inbound multi-block SOCKET_READ at turbo (issue #70 / PR #112: at 48 MHz a
1452/1472-byte datagram arrived as its first 893-byte reply block with the
header's full length, because net_poll took STATE "Command Busy" for "Data
Last" while the firmware was still staging block 2)::

    make clean && make BACKEND=uci REU=0
    C64_SKIP_BUILD=1 ECHO_TURBO_MHZ=48 ECHO_REPLY_LEN=893,894,1452,1472 \\
        U64_ALLOW_MUTATE=1 python3 tools/test_uci_udp_echo_live.py

``ECHO_TURBO_MHZ`` runs the whole sequence at that CPU speed (default 1 —
which is exactly the speed at which that bug cannot be seen; the tool used
to pin 1 MHz unconditionally). ``ECHO_REPLY_LEN`` makes the listener answer
each datagram with a fresh payload of THAT length instead of an echo, so the
RECEIVE path is driven past NET_UDP_SEND_MAX on the default (892-byte send)
build too — the build whose PRG the fix changes. Every inbound datagram is
asserted on udp_recv_len AND on content byte-for-byte; a mismatch reports
how many leading bytes matched (893 = one reply block = the #70 signature).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import logging
import os
import random
import struct
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
    Ultimate64Client, Ultimate64Error, Ultimate64RunnerStuckError,
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
# ECHO_PAYLOAD_LEN sizes the round trip: one integer (default 32) or a
# comma-separated list, each size sent ONCE in order on the same boot.
# ECHO_PAYLOAD_SWEEP=1 selects the issue #70 chunked-write sweep around the
# two firmware boundaries — 888 (max payload of one WRITE_SOCKET_CHUNK part:
# 895-byte command buffer minus the 7-byte header), 892 (the plain
# WRITE_SOCKET cap), and 1472 (the datagram cap):
#
#     888  one part, exactly full          893  two parts, first > plain cap
#     889  two parts (888 + 1)            1452  two parts (888 + 564)
#     891  two parts, one below plain cap 1472  two parts (888 + 584), max
#     892  two parts, == plain cap        1473  one above the datagram cap
#
# Anything above the build's NET_UDP_SEND_MAX must be refused with $8C and
# put NOTHING on the wire: on the default build that is 893 and up, on the
# chunked build only 1473 exercises it (udp_recv_buf is 1500, so it stages).
#
# Whether a size is expected to go through is decided per BUILD, from the
# NET_UDP_SEND_MAX the PRG exports: 892 on the default build, 1472 under
# UCI_CHUNKED_WRITE=1. Content is random bytes per run (see _payload/_reply
# below), seeded and reproducible via --seed/TEST_SEED (standing directive,
# 2026-09-03): a fixed byte pattern could in principle be "gamed" by a stale
# buffer that happens to match, and randomising per run rules that out. $00
# is excluded from both alphabets for trace eyeballing.
SWEEP_SIZES = (888, 889, 891, 892, 893, 1452, 1472, 1473)

# Disjoint per-direction byte alphabets: an echo of what the C64 sent (or a
# stale buffer left over from the previous size) can never satisfy the other
# direction's assertion, because the two ranges never overlap.
REQUEST_BYTE_ALPHABET = bytes(range(0x40, 0x60))    # C64 -> host (_payload)
REPLY_BYTE_ALPHABET = bytes(range(0x61, 0x7A))      # host -> C64 (_reply)
assert not (set(REQUEST_BYTE_ALPHABET) & set(REPLY_BYTE_ALPHABET))


def _payload_sizes() -> list[int]:
    if os.environ.get("ECHO_PAYLOAD_SWEEP") == "1":
        return list(SWEEP_SIZES)
    return [int(s) for s in os.environ.get("ECHO_PAYLOAD_LEN", "32").split(",")
            if s.strip()]


def _payload(n: int, seed: int) -> bytes:
    """n random bytes from REQUEST_BYTE_ALPHABET, deterministic per
    (seed, n) via plain-int seeding (never a str/tuple hash, which
    PYTHONHASHSEED randomises per process) so --seed/TEST_SEED actually
    reproduces a run."""
    rng = random.Random((seed + n * 97 + 1) & 0xFFFFFFFF)
    return bytes(rng.choice(REQUEST_BYTE_ALPHABET) for _ in range(n))


def _reply_sizes() -> list[int]:
    """ECHO_REPLY_LEN: listener answers with a payload of each of these
    lengths (per sent size) instead of echoing. Empty = plain echo."""
    return [int(s) for s in os.environ.get("ECHO_REPLY_LEN", "").split(",")
            if s.strip()]


def _reply(n: int, seed: int) -> bytes:
    """n random bytes from REPLY_BYTE_ALPHABET — a DISJOINT alphabet from
    _payload's — deterministic per (seed, n), so an echo of what the C64
    sent, or a stale buffer from the previous size, cannot satisfy the
    assertion."""
    rng = random.Random((seed + n * 97 + 2) & 0xFFFFFFFF)
    return bytes(rng.choice(REPLY_BYTE_ALPHABET) for _ in range(n))


def resolve_seed(cli_seed: int | None = None) -> int:
    """--seed wins; else TEST_SEED env; else a fresh random seed."""
    if cli_seed is not None:
        return cli_seed
    env = os.environ.get("TEST_SEED")
    if env:
        return int(env)
    return random.SystemRandom().randint(0, 2**32 - 1)


def _resolve_seed_from_argv() -> int:
    """Parses only --seed out of sys.argv (this tool's other knobs are all
    env vars — ECHO_TURBO_MHZ, ECHO_PAYLOAD_LEN, etc. — so this stays
    additive to the existing CLI/env contract rather than replacing it)."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--seed", type=int, default=None)
    args, _ = parser.parse_known_args()
    return resolve_seed(args.seed)


PAYLOAD_SIZES = _payload_sizes()
REPLY_SIZES = _reply_sizes()
# CPU speed for the whole sequence. 1 MHz hides timing races between the
# 6510 and the firmware's cmdif task (the uci_fence alone is ~5.5 ms there);
# 48 MHz is where issue #70's multi-block read truncation reproduced.
TURBO_MHZ = int(os.environ.get("ECHO_TURBO_MHZ", "1"))
SEND_BUF = 0x02A7                        # free space before cassette buffer (<= 64 B);
                                         # larger payloads are staged in udp_recv_buf
BOOT_TIMEOUT, STEP_TIMEOUT, ECHO_TIMEOUT = 60.0, 10.0, 5.0
UCI_ERR_SEND_TOO_LONG = 0x8C             # pre-check refusal, nothing on the wire
UCI_ERR_CMD_UNKNOWN = 0x8E               # firmware "21,UNKNOWN COMMAND" (stock 3.15)
CHUNK_PATH_LABEL = "uci_send_part"       # linked only under UCI_CHUNKED_WRITE=1
# UCI state the adapter leaves behind after a send, read for the log when the
# build exports it. These are POST-COMPLETION values: the whole send is one
# trampoline step, so the host cannot observe a non-completing part's reply
# in between — that needs a single-step build or the debug-bus trace.
# NOT in this tuple: `uci_status_leading_code`. It is a ROUTINE in uci_cmd.s,
# not a cell — reading one byte at its label yields $AD (the LDA opcode),
# which an earlier version of this tool printed as if it were the firmware's
# status code. The code is decoded from uci_status_buf's text below, the
# same two-digit decimal the routine itself parses.
UCI_TELEMETRY = ("uci_resp_count", "uci_status_seen", "uci_status_buf")


class _NoCapture:
    """Stand-in capture result when U64_NO_CAPTURE=1 (no debug stream)."""
    packets_received = packets_dropped = total_cycles = 0
    duration_seconds = 0.0
    trace = ()
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
    """Build the UCI PRG, honouring C64_REU.

    WHY C64_REU EXISTS: this used to hard-code `make BACKEND=uci`, i.e.
    always REU=1, and it runs unconditionally at tool start. So a caller
    who had carefully built `make BACKEND=uci REU=0` and then launched a
    hardware run had that binary silently replaced by the REU build
    before it ever reached the device.

    That cost a full afternoon on 2026-08-15: the REU build was shipped to
    a machine with the REU detached (`--reu off`), where reu_mul_init
    builds its tables from hardware that is not there, so every handshake
    was rejected. It read exactly like a broken REU=0 build — two speeds,
    reproducible, and completely wrong. The no-REU build was in fact fine
    and is faster than the REU build at turbo.

    Set C64_REU=0 for the onchip build, or C64_SKIP_BUILD=1 to use
    whatever is already on disk. test_uci_handshake_live also fingerprints
    the PRG it sends and refuses a REU build with --reu off.
    """
    if os.environ.get("C64_SKIP_BUILD"):
        return log.info("C64_SKIP_BUILD set — skipping make")
    reu = os.environ.get("C64_REU", "1")
    target = ["make", "BACKEND=uci"] + ([] if reu == "1" else ["REU=0"])
    # Same trap, one knob later: without this a chunked-write build on disk
    # is silently replaced by the plain 892-byte one (issue #70).
    if os.environ.get("C64_UCI_CHUNKED_WRITE") == "1":
        target.append("UCI_CHUNKED_WRITE=1")
    log.info("make clean && %s", " ".join(target))
    for cmd in (["make", "clean"], target):
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
    """Wait for reu_mul_init to finish.

    Terminal RAM-table signatures, checked as the ([128], [255]) byte
    pair — a single byte is ambiguous because plain row 253 transiently
    shows $FC at [255] mid-init (the PR #40 takeover-during-init race):

    - in-tree init ends with plain row 255 in RAM:
        [128] = (255*128)>>8 = $7F, [255] = (255*255)>>8 = $FE
    - c64-x25519 sibling init ends with the pre-doubled row 255:
        [128] = (510*128)>>8 = $FF, [255] = (2*255*255 & $FFFF)>>8 = $FC
      No plain row can put $FF at [128] (a*128 < 32768 for a <= 255),
      so the pair is unambiguous.
    """
    deadline = time.monotonic() + BOOT_TIMEOUT
    pair = (0, 0)
    while time.monotonic() < deadline:
        b128 = tr.read_memory(mul_dma_hi + 128, 1)[0]
        b255 = tr.read_memory(mul_dma_hi + 255, 1)[0]
        pair = (b128, b255)
        if pair in ((0x7F, 0xFE), (0xFF, 0xFC)):
            variant = "in-tree" if pair[1] == 0xFE else "x25519-sibling"
            log.info("boot complete — mul_dma_hi[128,255]=($%02X,$%02X) "
                     "(%s reu_mul_init done)", b128, b255, variant)
            return
        time.sleep(0.5)
    raise TimeoutError(
        f"reu_mul_init not finished within {BOOT_TIMEOUT}s; "
        f"mul_dma_hi[128,255]=(${pair[0]:02X},${pair[1]:02X})"
    )


def _wait_boot_ready(tr: Ultimate64Transport, labels: Labels,
                     L: dict[str, int]) -> None:
    """Wait for boot to complete, in any build configuration.

    Prefers `boot_ready` (src/wg/data.s), which src/boot.s sets to 1 as its
    last act (issue #55); falls back to `_wait_boot`'s REU multiply-table
    signature only when the label is absent (a pre-#55 PRG).

    The fallback CANNOT work on a REU=0 build: it polls `mul_dma_hi` for the
    signature `reu_mul_init` writes, and under WG_NO_REU that routine is
    compiled out (0 label entries) while `mul_dma_hi` still resolves as a
    plain BSS label — so it times out on a machine that booted fine. That
    is how this tool hung on every REU=0 build until 2026-09-01. Ported
    from test_uci_handshake_live.py's `_wait_boot_ready`.
    """
    addr = labels.address("boot_ready")
    if addr is None:
        log.warning("no boot_ready label (pre-#55 PRG); "
                    "falling back to the REU table signature")
        _wait_boot(tr, L["mul_dma_hi"])
        return
    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1)[0] == 1:
            log.info("boot complete — boot_ready=1 (%.1fs)",
                     BOOT_TIMEOUT - (deadline - time.monotonic()))
            return
        time.sleep(0.25)
    raise TimeoutError(
        f"boot_ready never set within {BOOT_TIMEOUT}s — boot did not complete")


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


def _poll_until_recv_ready(tr, ready_addr, net_poll_addr, timeout,
                           payload_len) -> bool:
    deadline = time.monotonic() + timeout
    iters = 0
    while time.monotonic() < deadline:
        # Every received byte costs two uci_fences (~11 ms at 1 MHz), so the
        # poll budget scales with the payload: 892 B is ~10 s at stock speed.
        _run_step(tr, step_id=STEP_POLL, target=net_poll_addr,
                  timeout=STEP_TIMEOUT + 0.02 * payload_len)
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
    "main_loop", "net_init", "net_dhcp_acquire", "net_udp_listen", "net_udp_send",
    "net_poll", "net_local_ip", "net_last_error", "mul_dma_hi",
    "wg_peer_ip", "wg_peer_port", "net_udp_dest_ip", "net_udp_dest_port", "wg_local_port",
    "udp_recv_ready", "udp_recv_len", "udp_recv_buf", "net_udp_send_len",
)


def _send_max(labels: Labels) -> tuple[int, str]:
    """The datagram cap THIS build guarantees, and where the number came from.

    NET_UDP_SEND_MAX is exported to labels.txt since issue #70 (892 plain,
    1472 under UCI_CHUNKED_WRITE=1). A build without the export predates the
    flag and is a plain 892 build by construction.
    """
    v = labels.address("NET_UDP_SEND_MAX")
    if v is not None:
        return v, "NET_UDP_SEND_MAX label"
    return 892, "default (NET_UDP_SEND_MAX not exported: pre-#70 plain build)"


def _uci_telemetry(tr: Ultimate64Transport, labels: Labels) -> str:
    """Post-send UCI adapter state, for the log. See UCI_TELEMETRY."""
    out = []
    for name in UCI_TELEMETRY:
        addr = labels.address(name)
        if addr is None:
            continue
        if name == "uci_status_buf":
            raw = bytes(tr.read_memory(addr, 24))
            text = raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            out.append(f"{name}={text!r}")
            code = int(text[:2]) if text[:2].isdigit() else None
            out.append(f"status_code={code}")
        elif name == "uci_resp_count":
            lo, hi = tr.read_memory(addr, 2)
            out.append(f"{name}={lo | (hi << 8)}")
        else:
            out.append(f"{name}=${tr.read_memory(addr, 1)[0]:02X}")
    return " ".join(out) if out else "(no UCI telemetry labels exported)"


def _echo_once(
    tr: Ultimate64Transport, L: dict[str, int], labels: Labels,
    listener: UDPEchoListener, payload: bytes, send_max: int,
    reply: bytes | None = None,
) -> list[str]:
    """Send one datagram of len(payload) and expect exactly one back.

    COUNTS datagrams. Content equality alone is satisfied by a torn
    888+584 send whose first fragment happens to be what the listener
    reports first; `len(listener.received) == 1` is the assertion that
    says the chunked write left the firmware as ONE datagram.

    `reply`, when given, is what the listener answers with instead of the
    echo (ECHO_REPLY_LEN), and what the inbound side is asserted against.
    """
    n = len(payload)
    expected = payload if reply is None else reply
    n_exp = len(expected)
    tag = f"[{n} B]" if reply is None else f"[{n} B -> reply {n_exp} B]"
    fail: list[str] = []
    expect_ok = n <= send_max
    listener.clear()
    listener.reply_fn = None if reply is None else (lambda _p, r=reply: r)
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
    send_buf = SEND_BUF if n <= 64 else L["udp_recv_buf"]
    log.info("%s staged at $%04X; expect %s (send_max=%d)", tag, send_buf,
             "accept" if expect_ok else f"refuse ${UCI_ERR_SEND_TOO_LONG:02X}",
             send_max)
    write_bytes(tr, send_buf, payload)
    write_bytes(tr, L["net_udp_send_len"], struct.pack("<H", n))
    c = _run_step(tr, step_id=STEP_SEND, target=L["net_udp_send"],
                  reg_a=send_buf & 0xFF, reg_x=send_buf >> 8,
                  timeout=STEP_TIMEOUT + 0.01 * n)     # 1 fence/byte
    nle = tr.read_memory(L["net_last_error"], 1)[0]
    log.info("%s net_udp_send carry=%d net_last_error=$%02X %s", tag, c, nle,
             _uci_telemetry(tr, labels))

    if nle == UCI_ERR_CMD_UNKNOWN:
        fail.append(f"{tag} net_last_error=$8E: the firmware answered "
                    f"'21,UNKNOWN COMMAND' to WRITE_SOCKET_CHUNK ($16) — "
                    f"stock 3.15, not the GideonZ#807 spike")
        return fail

    # Give a torn or late second fragment time to show up before counting.
    echo_dl = time.monotonic() + 2.0
    while time.monotonic() < echo_dl and not listener.received:
        time.sleep(0.05)
    time.sleep(0.3)
    rx_list = list(listener.received)
    log.info("%s listener received %d datagram(s): %s", tag, len(rx_list),
             [len(p) for _, p in rx_list])

    if not expect_ok:
        if c != 1 or nle != UCI_ERR_SEND_TOO_LONG:
            fail.append(f"{tag} above send_max {send_max}: expected C=1 with "
                        f"$8C SEND_TOO_LONG, got C={c} net_last_error=${nle:02X}")
        if rx_list:
            fail.append(f"{tag} refused size still reached the wire: "
                        f"{len(rx_list)} datagram(s) {[len(p) for _, p in rx_list]}")
        return fail

    if c != 0:
        fail.append(f"{tag} net_udp_send C=1 (net_last_error=${nle:02X}; "
                    "$84=CONNECT_FAIL, $85=SEND_FAIL, $87=SHORT_WRITE, "
                    "$8C=SEND_TOO_LONG, $8E=CMD_UNKNOWN)")
    if len(rx_list) != 1:
        fail.append(f"{tag} expected exactly ONE datagram at the listener, "
                    f"got {len(rx_list)} with lengths "
                    f"{[len(p) for _, p in rx_list]}")
    if rx_list:
        got = rx_list[0][1]
        if len(got) != n:
            fail.append(f"{tag} datagram length {len(got)}, expected {n}")
        if got != payload:
            first = next((i for i in range(min(len(got), n))
                          if got[i] != payload[i]), min(len(got), n))
            fail.append(f"{tag} payload mismatch, first difference at "
                        f"offset {first}")
    if fail:
        return fail

    # net_poll loop
    got = _poll_until_recv_ready(tr, L["udp_recv_ready"], L["net_poll"],
                                 ECHO_TIMEOUT, n_exp)
    nle = tr.read_memory(L["net_last_error"], 1)[0]
    if not got:
        fail.append(f"{tag} udp_recv_ready stayed 0 for {ECHO_TIMEOUT}s after "
                    f"the reply (net_last_error=${nle:02X}; $89=WAIT_TIMEOUT "
                    f"is the multi-block continuation never being staged)")
    else:
        lo, hi = tr.read_memory(L["udp_recv_len"], 2)
        rx_len = lo | (hi << 8)
        log.info("%s udp_recv_len=%d net_last_error=$%02X", tag, rx_len, nle)
        if rx_len != n_exp:
            fail.append(f"{tag} udp_recv_len={rx_len}, expected {n_exp}")
        # Read the FULL expected length regardless of rx_len: the #70
        # truncation left udp_recv_len at the header's total while only the
        # first block had been stored, so a read bounded by rx_len would
        # have covered the bytes that were never written.
        rx = bytes(tr.read_memory(L["udp_recv_buf"], n_exp))
        if rx != expected:
            match = next((i for i in range(n_exp) if rx[i] != expected[i]),
                         n_exp)
            tail_zero = all(b == 0 for b in rx[match:])
            note = ""
            if match == 893:
                note = (" — exactly one UCI reply block (896-byte response "
                        "queue minus the 2-byte header): the issue #70 "
                        "multi-block truncation")
            fail.append(f"{tag} udp_recv_buf content mismatch: first {match} "
                        f"of {n_exp} bytes match"
                        f"{', remainder all zero' if tail_zero else ''}{note}")
    return fail


def _run_sequence(
    tr: Ultimate64Transport, L: dict[str, int], labels: Labels,
    listener: UDPEchoListener, local_ip: str, seed: int,
) -> list[str]:
    """Drive init/dhcp/listen once, then one echo per payload size;
    return a list of failure descriptions."""
    fail: list[str] = []
    send_max, send_src = _send_max(labels)
    log.info("build send cap: %d via %s; sizes: %s", send_max, send_src,
             PAYLOAD_SIZES)
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
    # §13.1: the backend reads net_udp_dest_*, NOT wg_peer_*. In the app
    # session_stage_dest copies peer -> dest before each send; a host-side
    # driver that calls net_udp_send directly IS the caller and must stage
    # them itself. Omitting this sends to 0.0.0.0 with carry clear.
    write_bytes(tr, L["net_udp_dest_ip"], ip_bytes)
    write_bytes(tr, L["net_udp_dest_port"], port_be)
    write_bytes(tr, L["wg_local_port"], port_le)
    write_bytes(tr, L["udp_recv_ready"], bytes([0]))
    write_bytes(tr, L["udp_recv_len"], bytes([0, 0]))
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
    # If net_init failed, STOP. net_dhcp_acquire and later calls read $DF1x
    # registers without their own UCI_ID probe — on a non-UCI device
    # they hang. Respect the init contract: no further backend calls
    # unless init succeeded.
    if c != 0:
        log.warning("skipping net_dhcp_acquire + later steps — net_init did not succeed")
        return fail
    # net_dhcp_acquire
    c, nle = call("net_dhcp_acquire", STEP_DHCP)
    ip = tr.read_memory(L["net_local_ip"], 4)
    log.info("net_local_ip=%s", ".".join(str(b) for b in ip))
    if c != 0:
        fail.append(f"net_dhcp_acquire C=1 (net_last_error=${nle:02X})")
    if ip == bytes(4):
        fail.append("net_local_ip == 0.0.0.0 after net_dhcp_acquire")
    # net_udp_listen
    c, _ = call("net_udp_listen", STEP_LISTEN,
                reg_a=listener.port & 0xFF, reg_x=listener.port >> 8)
    if c != 0:
        fail.append("net_udp_listen C=1")
    if fail:
        return fail

    # One echo per size, each size ONCE, all on this boot and socket. A
    # size that fails stops nothing: the next size still runs, so a sweep
    # reports the whole boundary picture rather than its first casualty.
    # With ECHO_REPLY_LEN, each sent size is answered with each reply size
    # in turn; the inbound datagram may then exceed what this build can
    # send, which is the whole point (receive is 1472 on every build).
    plan = [(n, None) for n in PAYLOAD_SIZES] if not REPLY_SIZES else \
           [(n, r) for n in PAYLOAD_SIZES for r in REPLY_SIZES]
    for n, r in plan:
        try:
            fail.extend(_echo_once(tr, L, labels, listener, _payload(n, seed),
                                   send_max,
                                   reply=None if r is None else _reply(r, seed)))
        except TimeoutError as exc:
            fail.append(f"[{n} B] {exc}")
            log.error("[%d B] step timed out — the adapter may be wedged; "
                      "skipping the remaining sizes", n)
            break
    return fail


def _safe(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except Exception as exc:
        log.warning("%s(%r, %r) failed: %s", getattr(fn, "__name__", fn), args, kw, exc)
        return None


def main() -> int:
    seed = _resolve_seed_from_argv()
    print(f"Random seed: {seed} (reproduce with --seed {seed} or "
          f"TEST_SEED={seed})", flush=True)

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
        # U64_NO_CAPTURE=1 skips the 6510 debug-bus stream entirely (no
        # set_debug_stream_mode, no stream_debug_start) — the firmware then
        # sends nothing but the echo itself. Used to A/B the #58 send stall.
        capture = os.environ.get("U64_NO_CAPTURE") != "1"
        if capture:
            cap.start()
            set_debug_stream_mode(client, DEBUG_MODE_6510)
        else:
            log.info("U64_NO_CAPTURE set — debug stream disabled for this run")
        # REU first, THEN turbo: set_reu may reset the machine, and a reset
        # would drop the turbo setting (same order as the handshake tool).
        _safe(set_reu, client, True, "512 KB")  # reu_mul_init needs REU
        time.sleep(0.5)
        set_turbo_mhz(client, TURBO_MHZ)
        # A CPU-speed write can lose the next UCI command on a C64 Ultimate
        # (memory: settle ~3 s, then ASSERT the speed stuck — harness PR #106
        # footgun: a prior 48 MHz session survives reset()).
        time.sleep(3.0)
        if TURBO_MHZ == 1:
            try:
                check_measurement_environment(client)
            except Ultimate64MeasurementEnvironmentError as exc:
                _skip(f"unexpected turbo state: {exc}")
        else:
            actual = get_turbo_mhz(client)
            if actual != TURBO_MHZ:
                _skip(f"requested ECHO_TURBO_MHZ={TURBO_MHZ} but the device "
                      f"reports {actual} MHz")
            log.warning("RUNNING AT %d MHz — every timing this tool logs is "
                        "host-side wall clock", TURBO_MHZ)
        try:
            if capture:
                client.stream_debug_start(f"{local_ip}:{DEBUG_PORT}")
                streamed = True
        except Ultimate64Error as exc:
            # C64 Ultimate fw 1.1.0 has no 6510 debug stream (HTTP 500 on
            # /v1/streams/debug:start) — the echo test is still valid, just
            # without a cycle trace.
            log.warning("debug stream unavailable — continuing without "
                        "cycle capture: %s", exc)
        prg_bytes = prg_path.read_bytes()
        # Fingerprint the binary before sending it (same rationale as
        # test_uci_handshake_live): this tool must be able to say which
        # build it ran — REU profile AND, since issue #70, whether the
        # chunked-write path is linked at all.
        import hashlib
        has_chunk = labels.address(CHUNK_PATH_LABEL) is not None
        log.info("PRG fingerprint: sha256=%s reu_mul_init=%s %s=%s -> %s, %s",
                 hashlib.sha256(prg_bytes).hexdigest()[:32],
                 labels.address("reu_mul_init") is not None,
                 CHUNK_PATH_LABEL, has_chunk,
                 "REU" if labels.address("reu_mul_init") is not None
                 else "onchip/REU=0",
                 "chunked 1472" if has_chunk else "plain 892")
        client.run_prg(prg_bytes)
        log.info("PRG sent; waiting for boot...")
        _wait_boot_ready(tr, labels, L)
        failures = _run_sequence(tr, L, labels, listener, local_ip, seed)
        _safe(client.stream_debug_stop)
        streamed = False
        time.sleep(0.3)
        if capture:
            result = cap.stop()
            trace_path = _persist_trace(result, labels, mhz=TURBO_MHZ,
                                        mode=DEBUG_MODE_6510)
        else:
            result, trace_path = _NoCapture(), "(capture disabled)"
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
        if result is None and capture:
            try:
                time.sleep(0.2)
                trace_path = _persist_trace(
                    cap.stop(), labels, mhz=TURBO_MHZ, mode=DEBUG_MODE_6510,
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
