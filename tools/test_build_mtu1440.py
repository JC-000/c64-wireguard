#!/usr/bin/env python3
"""test_build_mtu1440.py — the WG_MTU1440=1 build knob (issue #70, ip65 half).

Build-level, no emulator. Everything is read STRUCTURALLY from the build
through tools/c64_caps.py's labels path — the same path every host tool
uses to learn the built MTU — never from a byte pattern in the PRG and
never from the .inc files (which can only describe the default build).

WHAT THE KNOB MUST DO
    make BACKEND=ip65 WG_MTU1440=1
        exports WG_MTU = 1440, NET_UDP_SEND_MAX = NET_UDP_RECV_MAX = 1472
        (ip65's caps are natively 1472/1472; the knob lifts this consumer's
        own WG_DATAGRAM_CAP from 892 to 1472).
    make BACKEND=uci WG_MTU1440=1
        MUST FAIL: without UCI_CHUNKED_WRITE=1 the UCI adapter's send
        ceiling is still 892, so a 1440 MTU would be a lie. The diagnostic
        must name both flags.
    make BACKEND=uci WG_MTU1440=1 UCI_CHUNKED_WRITE=1
        links, WG_MTU = 1440 (the two knobs agree).
    make BACKEND=ip65 / make BACKEND=uci (no knob)
        BYTE-IDENTICAL to a tree without the knob: WG_MTU = 860 and the
        PRG sha256 equals (a) the same build with WG_MTU1440=0 spelled out
        and (b) the master baseline when one is supplied via
        --baseline DIR / $WG_MTU1440_BASELINE (a directory holding
        wireguard-ip65.prg and wireguard-uci.prg from a master build).

RED ON MASTER (measured 2026-09-03, master fa5b11a): the knob is unknown
to the Makefile, so `make BACKEND=ip65 WG_MTU1440=1` builds the DEFAULT
PRG (WG_MTU 860) and `make BACKEND=uci WG_MTU1440=1` succeeds instead of
refusing. Both cases fail here with messages that say so.

Build-tree mutator: listed under SERIAL_TESTS in tools/run_regression.py
next to both_backends; restores the default tree on exit.

Usage:
    python3 tools/test_build_mtu1440.py [--baseline DIR] [--keep-tree]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import warnings
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_caps import load_caps  # noqa: E402
from c64_test_harness import Labels  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRG = PROJECT_ROOT / "build" / "wireguard.prg"
LABELS = PROJECT_ROOT / "build" / "labels.txt"

CHUNK_LABEL = "uci_send_part"

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if detail and not ok:
        for line in detail.splitlines():
            print(f"        {line}")
    return bool(ok)


def make(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["make", *args], cwd=PROJECT_ROOT,
                          capture_output=True, text=True, check=False)


def clean_build(*args: str) -> subprocess.CompletedProcess:
    r = make("clean")
    if r.returncode != 0:
        raise SystemExit(f"make clean failed:\n{r.stderr}")
    return make(*args)


def sha256_prg() -> str:
    return hashlib.sha256(PRG.read_bytes()).hexdigest()


def caps_from_build():
    """tools/c64_caps.py's reading of build/labels.txt, warnings captured."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        caps = load_caps(LABELS)
    return caps, [str(x.message) for x in w]


def label_present(name: str) -> bool:
    return Labels.from_file(str(LABELS)).address(name) is not None


def combined(r: subprocess.CompletedProcess) -> str:
    return (r.stdout or "") + (r.stderr or "")


# ---------------------------------------------------------------------------

def case_default(backend: str, expect_send: int) -> str | None:
    print(f"\n--- make BACKEND={backend} (default) ---")
    r = clean_build(f"BACKEND={backend}")
    if not check(r.returncode == 0, f"[{backend} default] builds",
                 combined(r)[-1500:]):
        return None
    caps, warns = caps_from_build()
    check(caps.from_labels, f"[{backend} default] caps come from labels.txt",
          caps.describe())
    check(caps.mtu_label == 860 and caps.tunnel_mtu == 860,
          f"[{backend} default] WG_MTU == 860 (labels path)",
          f"WG_MTU label = {caps.mtu_label}, tunnel_mtu = {caps.tunnel_mtu}")
    check(caps.recv_max == 1472, f"[{backend} default] NET_UDP_RECV_MAX == 1472",
          f"got {caps.recv_max}")
    raw = Labels.from_file(str(LABELS)).address("NET_UDP_SEND_MAX")
    check(raw == expect_send,
          f"[{backend} default] NET_UDP_SEND_MAX == {expect_send} (exported)",
          f"got {raw}")
    sha = sha256_prg()
    print(f"        sha256 {sha}")
    return sha


def case_knob_off_identity(backend: str, default_sha: str | None) -> None:
    print(f"\n--- make BACKEND={backend} WG_MTU1440=0 (explicit off) ---")
    r = clean_build(f"BACKEND={backend}", "WG_MTU1440=0")
    if not check(r.returncode == 0, f"[{backend} knob=0] builds",
                 combined(r)[-1500:]):
        return
    sha = sha256_prg()
    check(default_sha is not None and sha == default_sha,
          f"[{backend} knob=0] PRG byte-identical to the default build",
          f"default {default_sha}\nknob=0  {sha}")


def case_baseline(backend: str, default_sha: str | None, baseline: Path | None
                  ) -> None:
    if baseline is None:
        print(f"        (no --baseline: {backend} default sha not compared "
              "to a master build; see the header)")
        return
    ref = baseline / f"wireguard-{backend}.prg"
    if not ref.exists():
        check(False, f"[{backend} default] baseline {ref} exists")
        return
    ref_sha = hashlib.sha256(ref.read_bytes()).hexdigest()
    check(default_sha == ref_sha,
          f"[{backend} default] PRG byte-identical to the master baseline",
          f"baseline {ref_sha}\nthis     {default_sha}")


def case_ip65_knob() -> None:
    print("\n--- make BACKEND=ip65 WG_MTU1440=1 ---")
    r = clean_build("BACKEND=ip65", "WG_MTU1440=1")
    if not check(r.returncode == 0, "[ip65 knob] builds", combined(r)[-1500:]):
        return
    caps, warns = caps_from_build()
    check(caps.from_labels, "[ip65 knob] caps come from labels.txt",
          caps.describe())
    check(caps.mtu_label == 1440,
          "[ip65 knob] WG_MTU == 1440 exported (labels path)",
          f"WG_MTU label = {caps.mtu_label} — the Makefile has no "
          "WG_MTU1440 knob, or it did not raise WG_DATAGRAM_CAP for ip65")
    check(caps.send_max == 1472 and caps.recv_max == 1472,
          "[ip65 knob] NET_UDP_SEND_MAX == NET_UDP_RECV_MAX == 1472",
          f"send {caps.send_max} recv {caps.recv_max}")
    check(caps.tunnel_mtu == 1440,
          "[ip65 knob] c64_caps derives tunnel MTU 1440 from the build",
          f"tunnel_mtu = {caps.tunnel_mtu}; warnings: {warns}")
    check(not warns, "[ip65 knob] c64_caps raised no clamp warning "
          "(built WG_MTU agrees with min(send, recv) - overhead)",
          "\n".join(warns))
    check(not label_present(CHUNK_LABEL),
          f"[ip65 knob] {CHUNK_LABEL} NOT linked (no UCI chunk path on ip65)")
    # ip_packet_buf is `.res WG_MTU` with ip_pkt_len right after it: the
    # buffer the built MTU claims must physically exist.
    L = Labels.from_file(str(LABELS))
    span = L["ip_pkt_len"] - L["ip_packet_buf"]
    check(span == 1440, "[ip65 knob] ip_packet_buf is 1440 bytes "
          "(ip_pkt_len - ip_packet_buf)", f"got {span}")


def case_uci_knob_alone() -> None:
    print("\n--- make BACKEND=uci WG_MTU1440=1 (no UCI_CHUNKED_WRITE) ---")
    r = clean_build("BACKEND=uci", "WG_MTU1440=1")
    out = combined(r)
    if not check(r.returncode != 0,
                 "[uci knob alone] make REFUSES to build",
                 "make succeeded: the knob is silently ignored on uci (the "
                 "PRG is the default 860 build, or a 1440 build over an 892 "
                 "send ceiling)"):
        caps, _ = caps_from_build()
        print(f"        built anyway: {caps.describe()}")
        return
    check("WG_MTU1440" in out and "UCI_CHUNKED_WRITE" in out,
          "[uci knob alone] diagnostic names WG_MTU1440 and "
          "UCI_CHUNKED_WRITE", out[-800:])
    check("Traceback" not in out and "Segmentation fault" not in out,
          "[uci knob alone] refused cleanly (no crash)", out[-800:])
    check(not PRG.exists(),
          "[uci knob alone] no build/wireguard.prg left behind",
          "a PRG exists after a refused build — a C64_SKIP_BUILD consumer "
          "would pick it up")


def case_uci_knob_with_chunked() -> None:
    print("\n--- make BACKEND=uci WG_MTU1440=1 UCI_CHUNKED_WRITE=1 ---")
    r = clean_build("BACKEND=uci", "WG_MTU1440=1", "UCI_CHUNKED_WRITE=1")
    if not check(r.returncode == 0, "[uci knob+chunked] builds",
                 combined(r)[-1500:]):
        return
    caps, warns = caps_from_build()
    check(caps.mtu_label == 1440 and caps.send_max == 1472,
          "[uci knob+chunked] WG_MTU == 1440, NET_UDP_SEND_MAX == 1472",
          caps.describe())
    check(label_present(CHUNK_LABEL),
          f"[uci knob+chunked] {CHUNK_LABEL} linked")


def restore_default_tree() -> None:
    print("\nRestoring the default build tree: make clean && make")
    make("clean")
    r = make()
    if r.returncode != 0:
        print(f"WARNING: default rebuild failed:\n{r.stderr[-1500:]}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--baseline", default=os.environ.get("WG_MTU1440_BASELINE"),
                    help="directory with wireguard-ip65.prg / wireguard-uci.prg "
                         "from a master build (default: $WG_MTU1440_BASELINE)")
    ap.add_argument("--keep-tree", action="store_true",
                    help="do not restore the default build on exit")
    args = ap.parse_args()
    baseline = Path(args.baseline).resolve() if args.baseline else None

    print("test_build_mtu1440.py — issue #70 (ip65 WG_MTU1440 knob)")
    try:
        ip65_sha = case_default("ip65", expect_send=1472)
        case_knob_off_identity("ip65", ip65_sha)
        case_baseline("ip65", ip65_sha, baseline)
        uci_sha = case_default("uci", expect_send=892)
        case_knob_off_identity("uci", uci_sha)
        case_baseline("uci", uci_sha, baseline)
        case_ip65_knob()
        case_uci_knob_alone()
        case_uci_knob_with_chunked()
    finally:
        if not args.keep_tree:
            restore_default_tree()

    passed = sum(1 for ok, _ in results if ok)
    failed = len(results) - passed
    print(f"\nResults: {passed}/{len(results)} passed, {failed} failed")
    if failed:
        print("Failed checks:")
        for ok, label in results:
            if not ok:
                print(f"  - {label}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
