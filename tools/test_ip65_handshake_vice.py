#!/usr/bin/env python3
"""test_ip65_handshake_vice.py — ip65 handshake + rekey x2 under VICE warp.

OPT-IN, VICE-ethernet only. Exit 77 (skipped) when the feth/pcap rig is
not up; deliberately NOT in tools/run_regression.py.

WHAT IT PROVES
==============

The ip65/RR-Net backend can complete a real WireGuard handshake against
the bench responder (tools/wg_responder/server.py on 10.0.65.1:51820) and
then REKEY twice through the menu ('H', tools/wg_c64_input.rekey) with a
strictly increasing TAI64N on every initiation — the responder enforces
WireGuard's greatest-seen timestamp rule (issue #87) and silently drops a
repeat, so a stuck timestamp shows up here as a rekey that never returns
to ACTIVE.

Wall time per handshake is measured and reported. Speed is an axis:
DHCP runs at honest speed (warp compresses ip65's retry budget below
dnsmasq's OFFER latency — tools/vice_eth_rig.py), and warp is turned on
only once net_initialized is set, for the crypto. Under VICE's binary
monitor "warp" is the Speed resource lifted to an effectively unlimited
percentage (see BinaryViceTransport.set_warp).

ip65 fails a send whose destination is not in its ARP cache (it emits
the request and returns C=1, ip65/ip.s) and session_initiate treats that
as a failed handshake, so before 'H' the host pings the C64: ip65's
arp_process caches the SENDER of an ARP request (ip65/arp.s), which is
the host — no takeover of the C64's main loop needed.

Randomised per run: both static keypairs and the TAI64N base time —
seeded, the seed logged once and reproducible via --seed / $TEST_SEED.

Usage::

    python3 tools/test_ip65_handshake_vice.py [--mtu1440] [--rekeys N]
                                              [--seed S] [--verbose]

    C64_SKIP_BUILD=1   reuse build/wireguard.prg as found

Exit codes: 0 PASS / 1 FAIL / 77 SKIP (rig absent).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from c64_test_harness import Labels  # noqa: E402
import wg_c64_input as ki  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    DEFAULT_VICE_BIN, HOST_IP, LABELS_PATH, PRG_PATH, PROJECT_ROOT, EthVice,
    ResumingTransport, Tap, assert_ip65_build, boot_and_net_init, build_ip65,
    c64_ip, log, screen_text, skip_if_rig_down, wait_boot_ready,
)

WG_PORT = 51820
TUNNEL_IP = "10.0.65.2"          # inner address; anything the responder ignores
SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2

HS_TIMEOUT = float(os.environ.get("IP65_HS_TIMEOUT_S", "1800"))   # per handshake, warp
VERBOSE = False
results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    log(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if detail and (not ok or VERBOSE):
        for line in detail.splitlines():
            log(f"        {line}")
    return bool(ok)


def keypair(rng: random.Random) -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.from_private_bytes(bytes(rng.randrange(256) for _ in range(32)))
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv.private_bytes_raw(), pub


def hs_timestamp_gt(new: bytes, old: bytes) -> bool:
    return int.from_bytes(new, "big") > int.from_bytes(old, "big")


def stage_config(tr, L, c64_priv: bytes, c64_pub: bytes, resp_pub: bytes,
                 tai: int) -> None:
    tr.write_memory(L["cfg_static_priv"], c64_priv)
    tr.write_memory(L["cfg_static_pub"], c64_pub)
    tr.write_memory(L["cfg_peer_pub"], resp_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in HOST_IP.split(".")))
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    bytes([WG_PORT >> 8, WG_PORT & 0xFF]))       # big-endian
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in TUNNEL_IP.split(".")))
    tr.write_memory(L["ping_target_ip"], bytes(int(o) for o in HOST_IP.split(".")))
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))


class Responder:
    """tools/wg_responder/server.py on HOST_IP:51820, stderr to a log."""

    def __init__(self, priv: bytes, peer_pub: bytes, logpath: str):
        self.logpath = logpath
        self._fh = open(logpath, "w")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "tools.wg_responder.server",
             "--listen", f"{HOST_IP}:{WG_PORT}",
             "--priv", priv.hex(), "--peer-pub", peer_pub.hex()],
            cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=self._fh)
        # Wait for the listen line so a bind failure is caught up front.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if "listening on" in open(logpath).read():
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.2)
        raise RuntimeError(f"responder did not start:\n{open(logpath).read()}")

    def text(self) -> str:
        self._fh.flush()
        return open(self.logpath).read()

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._fh.close()


def host_ping(ip: str) -> bool:
    r = subprocess.run(["ping", "-c", "2", "-W", "1000", ip],
                       capture_output=True, text=True)
    return r.returncode == 0


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--mtu1440", action="store_true",
                    help="build with WG_MTU1440=1 (ignored under C64_SKIP_BUILD)")
    ap.add_argument("--rekeys", type=int, default=2)
    ap.add_argument("--seed", type=int,
                    default=int(os.environ.get("TEST_SEED", "0")) or None)
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--responder-log", default=os.path.join(
        PROJECT_ROOT, "build", "ip65_handshake_responder.log"))
    args = ap.parse_args()
    VERBOSE = args.verbose

    seed = args.seed if args.seed is not None else random.randint(1, 2**31 - 1)
    rng = random.Random(seed)
    log("test_ip65_handshake_vice.py — ip65 handshake + rekey under warp")
    log(f"Random seed: {seed} (reproduce with --seed {seed})")

    skip_if_rig_down(args.vice_bin)

    build_ip65(["WG_MTU1440=1"] if args.mtu1440 else [])
    for path in (PRG_PATH, LABELS_PATH):
        if not os.path.exists(path):
            log(f"FATAL: missing {path}")
            return 1
    assert_ip65_build()
    L = Labels.from_file(LABELS_PATH)
    required = ["boot_ready", "net_initialized", "ip65_blob_start", "wg_state",
                "hs_timestamp", "cfg_static_priv", "cfg_static_pub",
                "cfg_peer_pub", "cfg_preshared_key", "cfg_peer_endpoint_ip",
                "cfg_peer_endpoint_port", "tunnel_ip", "ping_target_ip",
                "tai64n_base_time", "WG_MTU"]
    missing = [n for n in required if L.address(n) is None]
    if missing:
        log(f"FATAL: labels missing: {missing}")
        return 1
    log(f"  PRG sha256 {hashlib.sha256(open(PRG_PATH, 'rb').read()).hexdigest()}"
        f"  WG_MTU={L['WG_MTU']}")

    c64_priv, c64_pub = keypair(rng)
    resp_priv, resp_pub = keypair(rng)
    tai = int(time.time()) + 10 + rng.randint(0, 3600)
    log(f"  c64 pub {c64_pub.hex()[:16]}…  responder pub {resp_pub.hex()[:16]}…  "
        f"tai64n base {tai}")

    os.makedirs(os.path.dirname(args.responder_log), exist_ok=True)
    responder = Responder(resp_priv, c64_pub, args.responder_log)
    timings: list[tuple[str, float]] = []
    t_start = time.monotonic()
    try:
        with EthVice(args.vice_bin, port=args.port) as vice:
            tr = vice.tr
            # boot_ready first, then the config, then 'I': staging before
            # boot would race the LOAD's zero-fill of APP_BSS.
            from vice_eth_rig import wait_boot_ready
            if not wait_boot_ready(tr, L):
                log("FATAL: boot_ready never set")
                log(screen_text(tr))
                return 1
            stage_config(tr, L, c64_priv, c64_pub, resp_pub, tai)
            tr.resume()
            net_secs = boot_and_net_init(tr, L)
            timings.append(("boot+DHCP+listen (honest speed)", net_secs))

            ip = c64_ip(tr, L)
            log(f"  C64 at {ip}")
            tr.resume()
            pinged = host_ping(ip)
            log(f"  host ping {ip}: {'replied' if pinged else 'no ICMP reply'} "
                "(the ARP exchange is what matters)")

            # Warp ON for the crypto; the hardware helpers need a transport
            # that resumes after every monitor command.
            tr.set_warp(True)
            check(tr.get_warp(), "warp enabled after network init")
            rt = ResumingTransport(tr)

            log("\n=== Handshake ('H') under warp ===")
            tap = Tap(f"udp and host {ip}")
            tap.__enter__()
            t0 = time.monotonic()
            if not check(ki.press_key(rt, "H", timeout=20.0), "H consumed"):
                return 1
            left = ki.wait_while_state(rt, L["wg_state"], SESSION_IDLE, HS_TIMEOUT, poll=1.0)
            check(left, "wg_state left IDLE (Type-1 built and sent)",
                  screen_text(tr))
            # The Type-1 is 148 bytes. Where it went on the wire is the one
            # fact the responder's silence cannot tell you: net_udp_dest_port
            # is big-endian in the ABI (net_abi.inc) and the ip65 backend
            # copied it raw into ip65's little-endian port (measured
            # 2026-09-03: 51820 left for 27850). Assert the wire, not the log.
            time.sleep(2.0)
            t1 = [(dp, ln) for dp, ln in tap.udp(ip, HOST_IP) if ln == 148]
            check(bool(t1) and t1[0][0] == WG_PORT,
                  f"Type-1 (148 B) left for {HOST_IP}:{WG_PORT} on the wire",
                  f"148-byte datagrams C64->host (dport, len): {t1}; "
                  f"all C64->host: {tap.udp(ip, HOST_IP)}")
            active = ki.wait_for_state(rt, L["wg_state"], SESSION_ACTIVE, HS_TIMEOUT, poll=1.0)
            hs_secs = time.monotonic() - t0
            timings.append(("handshake 1 (warp)", hs_secs))
            check(active, f"session ACTIVE after the first handshake "
                  f"({hs_secs:.0f}s under warp)", screen_text(tr))
            if not active:
                log(responder.text()[-2000:])
                for line in tap.raw[-10:]:
                    log(f"      tap: {line}")
                tap.__exit__(None, None, None)
                return 1
            tap.__exit__(None, None, None)
            ts_prev = bytes(rt.read_memory(L["hs_timestamp"], 12))
            log(f"  hs_timestamp {ts_prev.hex()}")

            for i in range(1, args.rekeys + 1):
                log(f"\n=== Rekey {i} ('H' via wg_c64_input.rekey) ===")
                t0 = time.monotonic()
                ok = ki.rekey(rt, L["wg_state"], SESSION_ACTIVE, timeout=HS_TIMEOUT)
                secs = time.monotonic() - t0
                timings.append((f"rekey {i} (warp)", secs))
                check(ok, f"rekey {i}: left ACTIVE and returned to ACTIVE "
                      f"({secs:.0f}s)", screen_text(tr))
                ts_new = bytes(rt.read_memory(L["hs_timestamp"], 12))
                check(hs_timestamp_gt(ts_new, ts_prev),
                      f"rekey {i}: hs_timestamp strictly increased",
                      f"prev {ts_prev.hex()}\nnew  {ts_new.hex()}")
                log(f"  hs_timestamp {ts_new.hex()}")
                ts_prev = ts_new
                if not ok:
                    break

            rlog = responder.text()
            accepted = rlog.count("TAI64N accepted")
            rejected = rlog.count("REJECT Type1")
            check(accepted == 1 + args.rekeys and rejected == 0,
                  f"responder accepted {1 + args.rekeys} initiations and "
                  f"rejected none (log: accepted={accepted} rejected={rejected})",
                  rlog[-1500:])
            tr.set_warp(False)
    finally:
        responder.close()

    log("\n=== Wall time ===")
    for name, secs in timings:
        log(f"  {name:<36s} {secs:8.1f} s")
    passed = sum(1 for ok, _ in results if ok)
    failed = len(results) - passed
    log(f"\nResults: {passed}/{len(results)} passed, {failed} failed "
        f"({time.monotonic() - t_start:.0f}s, seed {seed})")
    if failed:
        for ok, label in results:
            if not ok:
                log(f"  - {label}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
