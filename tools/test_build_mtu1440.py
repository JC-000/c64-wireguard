#!/usr/bin/env python3
"""test_build_mtu1440.py — the WG_MTU1440=1 build knob (issue #70, ip65 half).

Build-level, no emulator. Everything is read STRUCTURALLY from the build
through tools/c64_caps.py's labels path — the same path every host tool
uses to learn the built MTU — never from a byte pattern in the PRG and
never from the .inc files (which can only describe the default build).

THE KNOB IS BACKEND-DEPENDENT BY DEFAULT. Since v1.2.0 ships RR-Net at
MTU 1440 only (physical-hardware validated 2026-09-05), `WG_MTU1440`
defaults to 1 under BACKEND=ip65 and to 0 under BACKEND=uci. The default
BUILD and the shipped ARTEFACT must not disagree, which is what this
suite now pins.

WHAT THE KNOB MUST DO
    make BACKEND=ip65   (no knob spelled out)
        exports WG_MTU = 1440, NET_UDP_SEND_MAX = NET_UDP_RECV_MAX = 1472
        (ip65's caps are natively 1472/1472; the knob lifts this consumer's
        own WG_DATAGRAM_CAP from 892 to 1472).
    make BACKEND=ip65 WG_MTU1440=1
        BYTE-IDENTICAL to the bare ip65 build above: `?=` means the
        default already is 1, so spelling it out changes nothing.
    make BACKEND=ip65 WG_MTU1440=0
        DIFFERENT bytes, WG_MTU = 860 — the opt-OUT still works, i.e. a
        command-line assignment beats the backend-dependent default.
    make BACKEND=uci    (no knob spelled out)
        WG_MTU = 860, NET_UDP_SEND_MAX = 892 — uci is unchanged.
    make BACKEND=uci WG_MTU1440=0
        BYTE-IDENTICAL to the bare uci build.
    make BACKEND=uci WG_MTU1440=1
        MUST FAIL: without UCI_CHUNKED_WRITE=1 the UCI adapter's send
        ceiling is still 892, so a 1440 MTU would be a lie. The diagnostic
        must name both flags.
    make BACKEND=uci WG_MTU1440=1 UCI_CHUNKED_WRITE=1
        links, WG_MTU = 1440 (the two knobs agree).

WHAT THE GATE ACTUALLY PROVES. run_regression.py runs this with no
--baseline, so the identity claim it enforces is the IN-COPY one: within
one tree, spelling out the knob's DEFAULT value for that backend produces
the same bytes as not spelling it out. That is the property a default
build can lose by accident (a knob leaking into CA65FLAGS unconditionally,
or the default drifting away from what `make release` ships), and it needs
no reference artefact. Both directions are required for ip65, because
"identical" alone is satisfied by a Makefile that ignores the knob
entirely: `=1` identical to bare AND `=0` different from bare AND at 860.

Comparing against a real pre-change build is strictly extra, opt-in, and
only meaningful with provenance: pass --baseline DIR (or
$WG_MTU1440_BASELINE) where DIR holds wireguard-ip65.prg,
wireguard-uci.prg AND a COMMIT file naming the sha they were built from.
That commit must be an ancestor of HEAD and lie at or below the
merge-base with master, or the whole mode is refused — a baseline built
from this branch would otherwise pass trivially and prove nothing
(#118).

RED ON MASTER (measured 2026-09-05, master 214bfcd / tag v1.2.0):
`WG_MTU1440 ?= 0` is backend-independent, so a bare `make BACKEND=ip65`
builds WG_MTU 860 while the shipped RR-Net artefact is 1440. Three checks
here fail on that tree — the ip65 default's WG_MTU, the ip65 `=1` identity,
and the ip65 `=0` difference — and their messages say so. (The knob's own
existence was the 2026-09-03 RED against master fa5b11a; that is now
history, and the ip65 `=1` build case below no longer distinguishes
anything on its own, since it is the default.)

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

def case_default(backend: str, expect_send: int, expect_mtu: int) -> str | None:
    """The BARE build for a backend: no WG_MTU1440 on the command line.

    expect_mtu is the backend's DEFAULT MTU, which since v1.2.0 differs
    per backend: ip65 1440 (what `make release` ships and what ran on
    physical RR-Net hardware), uci 860 (plain SOCKET_WRITE caps at 892).
    """
    print(f"\n--- make BACKEND={backend} (default) ---")
    r = clean_build(f"BACKEND={backend}")
    if not check(r.returncode == 0, f"[{backend} default] builds",
                 combined(r)[-1500:]):
        return None
    caps, warns = caps_from_build()
    check(caps.from_labels, f"[{backend} default] caps come from labels.txt",
          caps.describe())
    check(caps.mtu_label == expect_mtu and caps.tunnel_mtu == expect_mtu,
          f"[{backend} default] WG_MTU == {expect_mtu} (labels path)",
          f"WG_MTU label = {caps.mtu_label}, tunnel_mtu = {caps.tunnel_mtu} "
          f"— the bare `make BACKEND={backend}` MTU must be the one the "
          f"released {backend} artefact carries")
    check(caps.recv_max == 1472, f"[{backend} default] NET_UDP_RECV_MAX == 1472",
          f"got {caps.recv_max}")
    raw = Labels.from_file(str(LABELS)).address("NET_UDP_SEND_MAX")
    check(raw == expect_send,
          f"[{backend} default] NET_UDP_SEND_MAX == {expect_send} (exported)",
          f"got {raw}")
    sha = sha256_prg()
    print(f"        sha256 {sha}")
    return sha


def case_knob_default_identity(backend: str, knob: int,
                               default_sha: str | None) -> None:
    """Spelling out the knob's DEFAULT value must change nothing.

    This is the no-leak property: `WG_MTU1440` must reach CA65FLAGS only
    when it is set to 1, never unconditionally. `knob` is the value that
    IS this backend's default (ip65 1, uci 0).
    """
    print(f"\n--- make BACKEND={backend} WG_MTU1440={knob} "
          f"(the default, spelled out) ---")
    r = clean_build(f"BACKEND={backend}", f"WG_MTU1440={knob}")
    if not check(r.returncode == 0, f"[{backend} knob={knob}] builds",
                 combined(r)[-1500:]):
        return
    sha = sha256_prg()
    check(default_sha is not None and sha == default_sha,
          f"[{backend} knob={knob}] PRG byte-identical to the default build",
          f"default        {default_sha}\nknob={knob}         {sha}\n"
          f"WG_MTU1440={knob} is this backend's default, so writing it out "
          f"must not change a byte")


def case_knob_flip_differs(backend: str, knob: int, default_sha: str | None,
                           expect_mtu: int) -> str | None:
    """The NON-default value must actually build something else.

    Without this, `case_knob_default_identity` is satisfied by a Makefile
    that ignores WG_MTU1440 altogether. It also proves the opt-out: a
    command-line `WG_MTU1440=` assignment beats the `?=` default, so an
    ip65 user can still get 860.
    """
    print(f"\n--- make BACKEND={backend} WG_MTU1440={knob} "
          f"(the NON-default value) ---")
    r = clean_build(f"BACKEND={backend}", f"WG_MTU1440={knob}")
    if not check(r.returncode == 0, f"[{backend} knob={knob}] builds",
                 combined(r)[-1500:]):
        return None
    sha = sha256_prg()
    check(default_sha is not None and sha != default_sha,
          f"[{backend} knob={knob}] PRG DIFFERS from the default build",
          f"default {default_sha}\nknob={knob}  {sha}\n"
          f"identical bytes mean the command line did not override the "
          f"backend-dependent default — the knob is inert on {backend}")
    caps, _ = caps_from_build()
    check(caps.mtu_label == expect_mtu,
          f"[{backend} knob={knob}] WG_MTU == {expect_mtu} (labels path)",
          f"WG_MTU label = {caps.mtu_label}")
    return sha


def baseline_provenance(baseline: Path) -> tuple[str | None, str]:
    """The commit a baseline directory was built from, and how we know.

    A baseline is only evidence if it predates the change under test. The
    directory must therefore carry COMMIT — one line, the full sha the
    PRGs were built from — written by whoever produced it. Without that
    the comparison is unfalsifiable: point --baseline at a build of the
    branch itself and it passes trivially, which is what the #118 review
    found.
    """
    f = baseline / "COMMIT"
    if not f.exists():
        return None, (f"{f} is missing — a baseline with no recorded commit "
                      "cannot be shown to predate this branch")
    sha = f.read_text().split()[0] if f.read_text().split() else ""
    if len(sha) < 7:
        return None, f"{f} does not contain a commit sha"
    return sha, f"baseline built from {sha[:12]}"


def check_baseline_provenance(baseline: Path | None) -> bool:
    """Gate the whole --baseline mode on the baseline being older than us.

    Older means: the recorded commit is an ANCESTOR of this working tree's
    HEAD and is reachable from master (i.e. it is at or below the
    merge-base), so the PRGs really are the pre-change artefacts.
    """
    if baseline is None:
        return False
    sha, why = baseline_provenance(baseline)
    if sha is None:
        check(False, "[baseline] provenance recorded", why)
        return False

    def git(*args: str) -> tuple[int, str]:
        r = subprocess.run(["git", *args], cwd=PROJECT_ROOT,
                           capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    rc, _ = git("cat-file", "-e", sha + "^{commit}")
    if rc != 0:
        check(False, "[baseline] recorded commit exists in this repo", why)
        return False
    rc, _ = git("merge-base", "--is-ancestor", sha, "HEAD")
    if not check(rc == 0, f"[baseline] {sha[:12]} is an ancestor of HEAD",
                 f"{why}, which is NOT in this tree's history — it cannot be "
                 "the 'before' artefact for this branch"):
        return False
    rc, mb = git("merge-base", sha, "master")
    ok = rc == 0 and mb == sha
    check(ok, f"[baseline] {sha[:12]} is on master (at or below the "
          "merge-base)",
          f"merge-base({sha[:12]}, master) = {mb or 'unknown'}: the baseline "
          "was built from a commit off master, so 'byte-identical to master' "
          "would not be what it proves")
    return ok


def case_baseline(backend: str, sha: str | None, baseline: Path | None,
                  usable: bool, what: str) -> None:
    """Compare against a PRE-CHANGE master build, if one was supplied.

    `what` names which of this copy's builds is the right comparand. For
    uci that is still the default build. For ip65 it is the WG_MTU1440=0
    build: a pre-change master's ip65 DEFAULT was MTU 860, and making the
    default 1440 is the whole point of this change, so comparing the new
    default to the old one would have to fail. What must still hold is
    that the 860 build itself is unchanged.
    """
    if baseline is None:
        print(f"        (no --baseline: the {backend} shas are compared only "
              "within this copy; see the header)")
        return
    if not usable:
        print(f"        (--baseline rejected on provenance; the {backend} "
              "comparison is NOT run)")
        return
    ref = baseline / f"wireguard-{backend}.prg"
    if not ref.exists():
        check(False, f"[{backend} {what}] baseline {ref} exists")
        return
    ref_sha = hashlib.sha256(ref.read_bytes()).hexdigest()
    check(sha == ref_sha,
          f"[{backend} {what}] PRG byte-identical to the master baseline",
          f"baseline {ref_sha}\nthis     {sha}")


def case_ip65_knob() -> None:
    """The 1440 ip65 build in detail — now also the DEFAULT ip65 build.

    Since WG_MTU1440 defaults to 1 under BACKEND=ip65 these bytes are the
    same ones case_default() produced (case_knob_default_identity pins
    that). The checks are kept and still earn their place: they are the
    only ones that look at NET_UDP_*_MAX together, at c64_caps' clamp
    warning, at uci_send_part's absence, and at ip_packet_buf physically
    being 1440 bytes wide.
    """
    print("\n--- make BACKEND=ip65 WG_MTU1440=1 (== the ip65 default) ---")
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
    baseline_ok = check_baseline_provenance(baseline)
    try:
        # ip65: the knob defaults to 1, so BOTH directions are required.
        ip65_sha = case_default("ip65", expect_send=1472, expect_mtu=1440)
        case_knob_default_identity("ip65", 1, ip65_sha)
        ip65_860_sha = case_knob_flip_differs("ip65", 0, ip65_sha,
                                              expect_mtu=860)
        case_baseline("ip65", ip65_860_sha, baseline, baseline_ok, "knob=0")
        # uci: the knob defaults to 0; its flip (=1 alone) is not a build
        # at all but a refusal, covered by case_uci_knob_alone below.
        uci_sha = case_default("uci", expect_send=892, expect_mtu=860)
        case_knob_default_identity("uci", 0, uci_sha)
        case_baseline("uci", uci_sha, baseline, baseline_ok,
                      "default")
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
