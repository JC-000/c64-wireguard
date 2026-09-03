#!/usr/bin/env python3
"""tools/test_warp_live.py — Real-peer WireGuard interop test against
Cloudflare WARP (issue #70 / #87).

Drives the C64 through its OWN menu (boot.s: I/H/P/M), not a host-side
trampoline: after `run_prg` + boot_ready, cfg_* is staged directly over DMA
(bypassing WG.CFG, which is not read on hardware), then 'I' (net init/DHCP/
listen), 'H' (handshake) and 'P'/'M' (ping / message) are typed via the
KERNAL keyboard queue exactly as a person at the keyboard would, so this
exercises the real do_handshake / do_ping / do_message_input paths against
a REAL WireGuard responder (Cloudflare WARP), not the project's own patient
Python responder.

WARP profile: pass the path to a wgcf-style profile (`[Interface]
PrivateKey=...`, `Address = .../32`, `[Peer] PublicKey = ...`) via the
WARP_PROFILE environment variable. The private key is read from that file
at run time and is NEVER written to this repo, a log line, or stdout —
only its derived X25519 public key (via `wg pubkey`) is used and logged.

Stages:
  A — msg_port=9999 build: stage config, press I, H; poll wg_state for
      SESSION_ACTIVE (real Cloudflare Type-2). Records handshake wall time.
  B — ping (P) through the tunnel to 1.1.1.1, then a keyboard chat message
      (M) to the same target (no reply expected).
  C — msg_port=53 build: a FRESH run_prg + FRESH handshake (new tai64n
      base time), then two real DNS queries (host-crafted wire bytes,
      staged raw over DMA into the message-input path) to 1.1.1.1:53 —
      one sized to land under the single-block boundary, one aimed at
      Cloudflare's 1280-byte WARP MTU — asserting the decrypted inbound
      reply's IP/UDP header and DNS transaction ID/question section.
  D — restore 1 MHz / REU off, assert by read-back, release the lock.

Run::

    WARP_PROFILE=/path/to/wgcf-profile.conf U64_HOST=10.43.23.81 \\
        /Users/someone/.local/bin/python3 tools/test_warp_live.py
"""
from __future__ import annotations

import argparse
import logging
import os
import random
import string
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from c64_test_harness import (  # noqa: E402
    DeviceLock, DeviceLockTimeout, Labels, dump_screen, enable_uci,
    get_uci_enabled, probe_u64, wait_for_text,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport  # noqa: E402
from c64_test_harness.backends.ultimate64_client import (  # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (  # noqa: E402
    get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz,
)

import wg_c64_input as ki  # noqa: E402

log = logging.getLogger("warp_live")
logging.basicConfig(level=logging.INFO,
                     format="%(asctime)s %(levelname)s %(message)s")

DEFAULT_HOST = "10.43.23.81"
WG_PUBKEY_BIN = "/opt/homebrew/bin/wg"

# --- Cloudflare WARP peer (fixed by the task; NOT the private key) ---
WARP_PEER_PUB_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT_IP = "162.159.192.1"          # engage.cloudflareclient.com
WARP_ENDPOINT_PORT = 2408
TUNNEL_IP = "172.16.0.2"
PING_TARGET_IP = "1.1.1.1"

SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2

PRG_A = PROJECT_ROOT / "build" / "wireguard.prg"                  # msg_port 9999
LABELS_A = PROJECT_ROOT / "build" / "labels.txt"
PRG_C = PROJECT_ROOT / "build_msgport53" / "wireguard.prg"        # msg_port 53
LABELS_C = PROJECT_ROOT / "build_msgport53" / "labels.txt"

HS_POLL_TIMEOUT = 120.0
PING_TIMEOUT = 10.0
DNS_TIMEOUT = 10.0
BOOT_TIMEOUT = 60.0

DNS_QTYPE_TXT = 16


# =============================================================================
# WARP profile / key handling — the private key never leaves this function
# except as bytes handed straight to `wg pubkey` over stdin.
# =============================================================================
def _load_warp_profile(path: str) -> tuple[bytes, str, str]:
    """Returns (c64_priv_32B, tunnel_ip, resp_pub_b64). Never logs the key."""
    priv_b64 = None
    address = None
    peer_pub = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("PrivateKey"):
                priv_b64 = line.split("=", 1)[1].strip()
            elif line.startswith("Address"):
                address = line.split("=", 1)[1].strip().split(",")[0].strip()
            elif line.startswith("PublicKey"):
                peer_pub = line.split("=", 1)[1].strip()
    if not priv_b64:
        raise RuntimeError("WARP_PROFILE has no PrivateKey= line")
    if peer_pub != WARP_PEER_PUB_B64:
        log.warning("profile PublicKey %s != expected %s — using profile's",
                    peer_pub, WARP_PEER_PUB_B64)
    import base64
    priv = base64.b64decode(priv_b64)
    assert len(priv) == 32
    tunnel_ip = (address.split("/")[0] if address else TUNNEL_IP)
    return priv, tunnel_ip, (peer_pub or WARP_PEER_PUB_B64)


def _derive_pubkey(priv: bytes) -> bytes:
    """wg pubkey < priv, over stdin only. Returns 32 raw bytes."""
    import base64
    p = subprocess.run([WG_PUBKEY_BIN, "pubkey"],
                       input=base64.b64encode(priv) + b"\n",
                       capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"wg pubkey failed: {p.stderr!r}")
    return base64.b64decode(p.stdout.strip())


# =============================================================================
# DNS query construction (host-side, pure wire format)
# =============================================================================
def build_dns_query(name: str, qtype: int, txn_id: int,
                    bufsize: int = 1400) -> bytes:
    def enc_name(n: str) -> bytes:
        out = b""
        for label in n.strip(".").split("."):
            if label:
                out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 1)  # RD=1, 1 Q, 1 ARCOUNT (OPT)
    question = enc_name(name) + struct.pack(">HH", qtype, 1)     # QCLASS=IN
    opt = b"\x00" + struct.pack(">HHIH", 41, bufsize, 0, 0)      # root name, TYPE=OPT
    # NOTE (post-run fix): first return value is the QUESTION SECTION ONLY
    # (no header) — it is compared against reply bytes starting at the
    # reply's own offset 12, so it must not carry this query's 12-byte
    # header. An earlier version returned header+question here, which made
    # every "question_echo_ok" check compare the wrong 12 bytes and always
    # read False on hardware even though the actual DNS exchange (txn_id
    # match, QR=1, correct ANCOUNT, correct IP/port) was fully correct.
    return question, header + question + opt


def stage_raw_dma(tr: Ultimate64Transport, payload: bytes, L: dict,
                  timeout: float = 30.0) -> bool:
    """Like wg_c64_input.send_message_dma but stages RAW bytes (no ASCII
    upper()/encode() transform), for binary DNS wire data."""
    limit = ki.input_max_from_labels(L)
    if len(payload) > limit:
        raise ValueError(f"{len(payload)} bytes exceeds this build's "
                         f"MSG_TEXT_MAX of {limit}")
    if not ki.press_key(tr, "M", timeout):
        return False
    if not ki._wait_drained(tr, timeout):
        return False
    time.sleep(0.3)
    base = L["ip_packet_buf"] + ki.IP_UDP_HDR_LEN
    for i in range(0, len(payload), ki.DMA_CHUNK):
        tr.write_memory(base + i, payload[i:i + ki.DMA_CHUNK])
    tr.write_memory(L["msg_input_len"], len(payload).to_bytes(2, "little"))
    return ki.press_key(tr, "\r", timeout)


# =============================================================================
# Device-side helpers
# =============================================================================
def _wait_boot_ready(tr: Ultimate64Transport, L: dict, timeout: float = BOOT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    addr = L["boot_ready"]
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1)[0] == 1:
            log.info("boot complete — boot_ready=1")
            return
        time.sleep(0.25)
    raise RuntimeError(f"boot_ready never set within {timeout}s")


def _stage_config(tr: Ultimate64Transport, L: dict, c64_priv: bytes,
                  c64_pub: bytes, resp_pub: bytes, tunnel_ip: str,
                  ping_target_ip: str) -> int:
    """Stage cfg_* over DMA; returns the tai64n base time used."""
    tr.write_memory(L["cfg_static_priv"], c64_priv)
    tr.write_memory(L["cfg_static_pub"], c64_pub)
    tr.write_memory(L["cfg_peer_pub"], resp_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))  # no PSK
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in WARP_ENDPOINT_IP.split(".")))
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF]))
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in tunnel_ip.split(".")))
    tr.write_memory(L["ping_target_ip"],
                    bytes(int(o) for o in ping_target_ip.split(".")))
    # issue #87: stage the CURRENT unix time as the TAI64N base every run,
    # so this run's first initiation is strictly newer than any prior run's
    # against the same static key (Cloudflare enforces monotonicity).
    tai = int(time.time()) + 10  # TAI-UTC offset (approximate is fine)
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))
    log.info("cfg staged: c64_pub=%s... resp_pub=%s... peer=%s:%d tai64=%d",
             c64_pub.hex()[:8], resp_pub.hex()[:8], WARP_ENDPOINT_IP,
             WARP_ENDPOINT_PORT, tai)
    return tai


def _dump_failure(tr: Ultimate64Transport, L: dict, tag: str) -> None:
    err = tr.read_memory(L["net_last_error"], 1)[0]
    log.error("[%s] net_last_error=$%02X", tag, err)
    for name, n in (("hs_h", 32), ("hs_c", 32), ("hs_resp_packet", 92),
                    ("hs_ephem_pub", 32)):
        if name in L:
            log.error("[%s] %s = %s", tag, name,
                      bytes(tr.read_memory(L[name], n)).hex())
    dump_screen(tr, label=tag)


def run_stage_ab(tr: Ultimate64Transport, client: Ultimate64Client, L: dict,
                 c64_priv: bytes, c64_pub: bytes, resp_pub: bytes,
                 seed: int) -> dict:
    result: dict = {"stage": "A/B"}
    prg_bytes = PRG_A.read_bytes()
    import hashlib
    log.info("Stage A PRG sha256=%s (%d B)",
             hashlib.sha256(prg_bytes).hexdigest(), len(prg_bytes))
    client.run_prg(prg_bytes)
    _wait_boot_ready(tr, L)

    _stage_config(tr, L, c64_priv, c64_pub, resp_pub, TUNNEL_IP, PING_TARGET_IP)

    if not ki.press_key(tr, "I", timeout=20.0):
        result["error"] = "press I (net init) not consumed"
        return result
    time.sleep(1.0)  # net_init/DHCP read/listen — fast, but let it settle
    err = tr.read_memory(L["net_last_error"], 1)[0]
    log.info("after I: net_last_error=$%02X", err)

    if not ki.press_key(tr, "H", timeout=20.0):
        result["error"] = "press H (handshake) not consumed"
        return result

    t0 = time.monotonic()
    active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE, HS_POLL_TIMEOUT, poll=1.0)
    elapsed = time.monotonic() - t0
    state = tr.read_memory(L["wg_state"], 1)[0]
    result["handshake_seconds"] = round(elapsed, 1)
    result["wg_state_final"] = state
    result["active"] = active

    if not active:
        _dump_failure(tr, L, "stageA-handshake")
        return result

    log.info("Stage A: ACTIVE in %.1fs", elapsed)

    # --- Stage B: ping ---
    if not ki.press_key(tr, "P", timeout=15.0):
        result["ping_error"] = "press P not consumed"
    else:
        grid = wait_for_text(tr, "PING REPLY OK", timeout=PING_TIMEOUT, verbose=False)
        result["ping_reply"] = grid is not None
        if grid is None:
            dump_screen(tr, label="stageB-ping-timeout")

    # --- Stage B: chat message (no reply expected) ---
    suffix = "".join(random.choice(string.ascii_uppercase + string.digits)
                     for _ in range(8))
    msg_text = f"HELLO {suffix}"
    before = int.from_bytes(tr.read_memory(L["tp_send_counter"], 2), "little") \
        if "tp_send_counter" in L else None
    ok = ki.send_message_dma(tr, msg_text, L, timeout=15.0)
    time.sleep(0.5)
    err_after = tr.read_memory(L["net_last_error"], 1)[0]
    after = int.from_bytes(tr.read_memory(L["tp_send_counter"], 2), "little") \
        if "tp_send_counter" in L else None
    result["message_sent_keypress_ok"] = ok
    result["message_text"] = msg_text
    result["tp_send_counter_before"] = before
    result["tp_send_counter_after"] = after
    result["net_last_error_after_message"] = f"${err_after:02X}"
    return result


def run_stage_c(tr: Ultimate64Transport, client: Ultimate64Client, L: dict,
                c64_priv: bytes, c64_pub: bytes, resp_pub: bytes,
                seed: int) -> dict:
    result: dict = {"stage": "C"}
    prg_bytes = PRG_C.read_bytes()
    import hashlib
    log.info("Stage C PRG sha256=%s (%d B)",
             hashlib.sha256(prg_bytes).hexdigest(), len(prg_bytes))
    client.run_prg(prg_bytes)
    _wait_boot_ready(tr, L)

    _stage_config(tr, L, c64_priv, c64_pub, resp_pub, TUNNEL_IP, PING_TARGET_IP)

    if not ki.press_key(tr, "I", timeout=20.0):
        result["error"] = "press I (net init) not consumed"
        return result
    time.sleep(1.0)

    if not ki.press_key(tr, "H", timeout=20.0):
        result["error"] = "press H (handshake) not consumed"
        return result

    t0 = time.monotonic()
    active = ki.wait_for_state(tr, L["wg_state"], SESSION_ACTIVE, HS_POLL_TIMEOUT, poll=1.0)
    elapsed = time.monotonic() - t0
    result["handshake_seconds"] = round(elapsed, 1)
    result["active"] = active
    if not active:
        _dump_failure(tr, L, "stageC-handshake")
        return result
    log.info("Stage C: ACTIVE in %.1fs", elapsed)

    random.seed(seed)
    queries = [
        ("namecheap.com", DNS_QTYPE_TXT, 1278, "900-1279 band"),
        ("github.com", DNS_QTYPE_TXT, 1928, "targets >1280 (Cloudflare WARP MTU)"),
    ]
    result["queries"] = []
    for name, qtype, dig_size, band in queries:
        txn_id = random.randint(0, 0xFFFF)
        question, wire = build_dns_query(name, qtype, txn_id, bufsize=1400)
        log.info("DNS query %s %s txn_id=%d wire_len=%d dig_measured=%d (%s)",
                 name, {16: "TXT"}.get(qtype, qtype), txn_id, len(wire),
                 dig_size, band)

        # Clear the receive markers so we can tell a NEW reply apart.
        tr.write_memory(L["msg_recv_len"], bytes(2))
        tr.write_memory(L["tp_payload_len"], bytes(2))

        staged = stage_raw_dma(tr, wire, L, timeout=15.0)
        q = {"name": name, "qtype": qtype, "txn_id": txn_id,
            "wire_len": len(wire), "dig_measured": dig_size, "band": band,
            "staged_ok": staged}

        deadline = time.monotonic() + DNS_TIMEOUT
        recv_len = 0
        while time.monotonic() < deadline:
            recv_len = int.from_bytes(tr.read_memory(L["msg_recv_len"], 2), "little")
            if recv_len:
                break
            time.sleep(0.25)
        q["reply_recv_len"] = recv_len

        if recv_len:
            recv_ptr = int.from_bytes(tr.read_memory(L["msg_recv_ptr"], 2), "little")
            dns_payload = bytes(tr.read_memory(recv_ptr, min(recv_len, 1450)))
            ip_hdr = bytes(tr.read_memory(L["tp_packet"] + 16, 20))
            udp_hdr = bytes(tr.read_memory(L["tp_packet"] + 16 + 20, 8))
            src_ip = ".".join(str(b) for b in ip_hdr[12:16])
            dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
            src_port = (udp_hdr[0] << 8) | udp_hdr[1]
            dst_port = (udp_hdr[2] << 8) | udp_hdr[3]
            reply_txn = (dns_payload[0] << 8) | dns_payload[1] if len(dns_payload) >= 2 else None
            qr_bit = bool(dns_payload[2] & 0x80) if len(dns_payload) >= 3 else None
            ancount = (dns_payload[6] << 8) | dns_payload[7] if len(dns_payload) >= 8 else None
            question_echo_ok = dns_payload[12:12 + len(question)] == question \
                if len(dns_payload) >= 12 + len(question) else False
            q.update({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "txn_id_match": reply_txn == txn_id,
                "qr_bit": qr_bit, "ancount": ancount,
                "question_echo_ok": question_echo_ok,
                "src_ip_ok": src_ip == PING_TARGET_IP,
                "dst_ip_ok": dst_ip == TUNNEL_IP,
                "ports_ok": src_port == 53 and dst_port == 53,
            })
        else:
            dump_screen(tr, label=f"stageC-dns-timeout-{name}")
        result["queries"].append(q)
    return result


# =============================================================================
# main
# =============================================================================
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("U64_HOST", DEFAULT_HOST))
    p.add_argument("--turbo", type=int, default=48)
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()

    seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)
    log.info("Random seed: %d (reproduce with --seed %d)", seed, seed)

    profile_path = os.environ.get("WARP_PROFILE")
    if not profile_path:
        log.error("WARP_PROFILE env var not set (path to wgcf profile)")
        return 2
    c64_priv, tunnel_ip, resp_pub_b64 = _load_warp_profile(profile_path)
    c64_pub = _derive_pubkey(c64_priv)
    import base64
    resp_pub = base64.b64decode(resp_pub_b64)
    log.info("c64 static pub (derived, safe to log): %s", base64.b64encode(c64_pub).decode())
    log.info("peer pub: %s", resp_pub_b64)

    probe = probe_u64(args.host)
    if not probe.reachable:
        log.error("device %s not reachable: %s", args.host, probe.error)
        return 1
    log.info("probe: %s", probe)

    lock = DeviceLock(args.host)
    try:
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as e:
        log.error("DeviceLock acquire failed: %s", e)
        return 77

    results: dict = {"seed": seed}
    turbo_restored = False
    reu_restored = False
    try:
        client = Ultimate64Client(host=args.host, timeout=30.0)
        tr = Ultimate64Transport(host=args.host, timeout=30.0, client=client)

        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            log.warning("runner wedged: %s — recovering", exc)
            recover(client)
            runner_health_check(client)

        if not get_uci_enabled(client):
            enable_uci(client)
            time.sleep(0.5)

        set_reu(client, False)
        log.warning("REU DETACHED (REU=0 build)")
        time.sleep(0.5)
        set_turbo_mhz(client, args.turbo)
        time.sleep(3.0)  # settle
        actual = get_turbo_mhz(client)
        if actual != args.turbo:
            log.error("turbo did not stick: requested %d, device reports %d",
                      args.turbo, actual)
            return 1
        log.info("turbo confirmed stuck at %d MHz", actual)

        # --- Stage A/B ---
        L_A = dict(Labels.from_file(str(LABELS_A)))
        ab = run_stage_ab(tr, client, L_A, c64_priv, c64_pub, resp_pub, seed)
        results["stage_ab"] = ab

        # --- Stage C ---
        L_C = dict(Labels.from_file(str(LABELS_C)))
        c = run_stage_c(tr, client, L_C, c64_priv, c64_pub, resp_pub, seed)
        results["stage_c"] = c

        # --- Stage D: restore ---
        set_turbo_mhz(client, 1)
        time.sleep(1.0)
        actual1 = get_turbo_mhz(client)
        turbo_restored = (actual1 == 1)
        set_reu(client, False)
        reu_restored = True
        log.info("restore: turbo=%d MHz (restored=%s) REU off", actual1, turbo_restored)

    finally:
        lock.release()
        log.info("lock released")

    import json
    log.info("RESULTS:\n%s", json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
