#!/usr/bin/env python3
"""test_build_both_backends.py -- CI-friendly build smoke test.

Verifies that both BACKEND=ip65 and BACKEND=uci produce a valid
build/wireguard.prg plus a VICE-format build/labels.txt. No emulator
or hardware needed -- pure subprocess + file inspection.

Usage:
    python3 tools/test_build_both_backends.py      # quick loop mode
    pytest tools/test_build_both_backends.py       # under pytest
"""

import os
import re
import subprocess
import sys

from c64_test_harness import Labels


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
PRG_PATH = os.path.join(BUILD_DIR, "wireguard.prg")
LABELS_PATH = os.path.join(BUILD_DIR, "labels.txt")
IP65_BIN = os.path.join(PROJECT_ROOT, "ip65-build", "ip65-c64.bin")

BACKENDS = ("ip65", "uci")

# Labels every backend must export (names without the leading `.`).
# NOTE: the task spec listed `net_last_error` under COMMON, but the ip65
# backend does not export it -- only the UCI backend does. Moved here to
# UCI_LABELS to reflect the actual source of truth (src/net/*/net.s).
COMMON_LABELS = (
    "net_init", "net_dhcp_acquire", "net_poll",
    "net_udp_send", "net_udp_listen",
)

# UCI-only labels (ip65 has no equivalents worth enumerating here).
UCI_LABELS = (
    "net_last_error",
    "uci_abort", "uci_wait_idle", "uci_wait_not_busy",
    "uci_push_wait", "uci_read_resp_bytes", "uci_ack",
    "uci_socket_id", "uci_socket_open",
)

LABEL_LINE_RE = re.compile(r"^al C:[0-9a-fA-F]{4} \.[A-Za-z_0-9@]+$")


def _run_make(*args, env_extra=None):
    """Run make with args; return CompletedProcess."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["make", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _assert_valid_prg():
    assert os.path.exists(PRG_PATH), f"PRG not produced at {PRG_PATH}"
    size = os.path.getsize(PRG_PATH)
    assert size >= 16 * 1024, f"PRG suspiciously small: {size} bytes (< 16 KiB)"
    with open(PRG_PATH, "rb") as f:
        header = f.read(2)
    assert header == b"\x01\x08", (
        f"PRG load address wrong: got {header!r}, expected b'\\x01\\x08'"
    )
    return size


def _assert_valid_labels():
    assert os.path.exists(LABELS_PATH), f"labels file not produced at {LABELS_PATH}"
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if line.startswith("al 00"):
            raise AssertionError(
                f"labels.txt line {lineno} not rewritten by sed step: {line!r}"
            )
        if not LABEL_LINE_RE.match(line):
            raise AssertionError(
                f"labels.txt line {lineno} does not match VICE format: {line!r}"
            )


def _check_labels_present(backend):
    labels = Labels.from_file(LABELS_PATH)
    required = list(COMMON_LABELS)
    if backend == "uci":
        required += list(UCI_LABELS)
    missing = [n for n in required if labels.address(n) is None]
    assert not missing, f"[{backend}] missing required labels: {missing}"


def _build_backend(backend):
    clean = _run_make("clean")
    assert clean.returncode == 0, (
        f"[{backend}] make clean failed ({clean.returncode}):\n{clean.stderr}"
    )
    build = _run_make(f"BACKEND={backend}")
    assert build.returncode == 0, (
        f"[{backend}] make BACKEND={backend} failed ({build.returncode}):\n"
        f"STDOUT:\n{build.stdout}\nSTDERR:\n{build.stderr}"
    )


def _check_backend(backend):
    _build_backend(backend)
    size = _assert_valid_prg()
    _assert_valid_labels()
    _check_labels_present(backend)
    print(f"[{backend}] build OK ({size} bytes, labels valid)")


def test_backend_ip65():
    _check_backend("ip65")


def test_backend_uci():
    _check_backend("uci")


def test_unknown_backend_fails_cleanly():
    _run_make("clean")
    result = _run_make("BACKEND=bogus")
    assert result.returncode != 0, (
        "make BACKEND=bogus unexpectedly succeeded"
    )
    combined = (result.stderr or "") + (result.stdout or "")
    assert "Unknown BACKEND" in combined, (
        "expected 'Unknown BACKEND' diagnostic; got:\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    # Guard against tracebacks / crashes leaking into make output.
    for bad in ("Traceback", "Segmentation fault"):
        assert bad not in combined, (
            f"make BACKEND=bogus produced {bad!r}:\n{combined}"
        )
    print("[bogus] rejected cleanly with 'Unknown BACKEND' diagnostic")


def test_uci_build_does_not_require_ip65_blob():
    _run_make("clean")
    backup = IP65_BIN + ".bak"
    renamed = False
    try:
        if os.path.exists(IP65_BIN):
            os.rename(IP65_BIN, backup)
            renamed = True
        result = _run_make("BACKEND=uci")
        assert result.returncode == 0, (
            "make BACKEND=uci failed with ip65 blob absent:\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        _assert_valid_prg()
        _assert_valid_labels()
        _check_labels_present("uci")
        print("[uci-no-blob] build OK without ip65-c64.bin present")
    finally:
        if renamed and os.path.exists(backup):
            # Restore even if the PRG step happened to recreate the blob.
            if os.path.exists(IP65_BIN):
                os.remove(IP65_BIN)
            os.rename(backup, IP65_BIN)


# ---------------------------------------------------------------------------
# Issue #70: UCI_CHUNKED_WRITE build flag (1472-byte datagrams via the
# firmware's chunked SOCKET_WRITE, WG_MTU 1440).
#
# Everything below is STRUCTURAL — read from labels.txt — never a byte-grep
# of the PRG. A textual check on the binary can match ciphertext, a string
# constant or the previous build's stale file; a label either links or it
# does not. The equates are visible because src/exports.s promotes them
# (`.export WG_MTU, NET_UDP_SEND_MAX`); the chunk-path routine is visible
# because it is a linked label, and only exists inside `.ifdef
# UCI_CHUNKED_WRITE`. So the same three reads distinguish the two states
# of the flag, and a build that ignores the flag (a Makefile that never
# gained the knob) fails on the flag-build check with a message naming the
# missing label rather than an exception.
#
# `make clean` between flag states is not optional: the #76 flag stamp
# covers CA65FLAGS, but these checks must hold even if the stamp is ever
# broken, since a stale object from the other flag state is exactly the
# false green they exist to catch.
# ---------------------------------------------------------------------------

CHUNK_PATH_LABEL = "uci_send_part"     # only linked under UCI_CHUNKED_WRITE=1

# (WG_MTU, NET_UDP_SEND_MAX) per flag state, from net_caps.inc/constants.inc:
# default 892 - 32 = 860; chunked 1472 - 32 = 1440.
EXPECT_DEFAULT = {"WG_MTU": 860, "NET_UDP_SEND_MAX": 892}
EXPECT_CHUNKED = {"WG_MTU": 1440, "NET_UDP_SEND_MAX": 1472}


def _label_values(names):
    """Return {name: address-or-None} from the current labels.txt."""
    labels = Labels.from_file(LABELS_PATH)
    return {n: labels.address(n) for n in names}


def _assert_exported_equates(tag, expect):
    got = _label_values(expect)
    missing = [n for n, v in got.items() if v is None]
    assert not missing, (
        f"[{tag}] equate(s) {missing} not present in labels.txt — "
        f"src/exports.s must `.export` them (issue #70) so the build's "
        f"MTU can be checked structurally")
    wrong = {n: (got[n], expect[n]) for n in expect if got[n] != expect[n]}
    assert not wrong, (
        f"[{tag}] exported equates disagree with the flag state: "
        + ", ".join(f"{n} = {g} (expected {e})" for n, (g, e) in wrong.items()))


def test_uci_default_build_has_no_chunk_path():
    """Default `make BACKEND=uci`: plain 892-byte SOCKET_WRITE, MTU 860,
    and the chunk-path routine is NOT linked."""
    _build_backend("uci")
    _assert_valid_labels()
    _assert_exported_equates("uci default", EXPECT_DEFAULT)
    present = _label_values([CHUNK_PATH_LABEL])[CHUNK_PATH_LABEL]
    assert present is None, (
        f"[uci default] {CHUNK_PATH_LABEL} is linked at ${present:04X} in a "
        f"build WITHOUT UCI_CHUNKED_WRITE=1 — the chunk path must live "
        f"inside `.ifdef UCI_CHUNKED_WRITE`")
    print(f"[uci default] WG_MTU=860 NET_UDP_SEND_MAX=892, "
          f"{CHUNK_PATH_LABEL} absent")


def test_uci_chunked_write_flag_build():
    """`make BACKEND=uci UCI_CHUNKED_WRITE=1`: links; WG_MTU 1440,
    NET_UDP_SEND_MAX 1472; the chunk-path routine IS linked."""
    clean = _run_make("clean")
    assert clean.returncode == 0, f"make clean failed:\n{clean.stderr}"
    try:
        build = _run_make("BACKEND=uci", "UCI_CHUNKED_WRITE=1")
        assert build.returncode == 0, (
            "[uci chunked] make BACKEND=uci UCI_CHUNKED_WRITE=1 failed "
            f"({build.returncode}) — the flag build does not link:\n"
            f"STDOUT:\n{build.stdout}\nSTDERR:\n{build.stderr}")
        _assert_valid_prg()
        _assert_valid_labels()
        _check_labels_present("uci")
        present = _label_values([CHUNK_PATH_LABEL])[CHUNK_PATH_LABEL]
        assert present is not None, (
            f"[uci chunked] {CHUNK_PATH_LABEL} not in labels.txt after "
            f"`make BACKEND=uci UCI_CHUNKED_WRITE=1` — either the Makefile "
            f"has no UCI_CHUNKED_WRITE knob (flag silently ignored) or the "
            f"chunk path is not exported under that name")
        _assert_exported_equates("uci chunked", EXPECT_CHUNKED)
        print(f"[uci chunked] build OK, WG_MTU=1440 NET_UDP_SEND_MAX=1472, "
              f"{CHUNK_PATH_LABEL} at ${present:04X}")
    finally:
        # Never leave a flag-state tree behind for the next check.
        _run_make("clean")


def test_ip65_rejects_chunked_write_flag():
    """`make BACKEND=ip65 UCI_CHUNKED_WRITE=1` must refuse: the flag names
    a UCI firmware command, and ip65 keeps its 892 cap."""
    _run_make("clean")
    try:
        result = _run_make("BACKEND=ip65", "UCI_CHUNKED_WRITE=1")
        assert result.returncode != 0, (
            "make BACKEND=ip65 UCI_CHUNKED_WRITE=1 unexpectedly SUCCEEDED — "
            "the Makefile must $(error ...) on that combination (issue #70)")
        combined = (result.stderr or "") + (result.stdout or "")
        assert "UCI_CHUNKED_WRITE" in combined, (
            "ip65 + UCI_CHUNKED_WRITE=1 failed, but not with a diagnostic "
            f"naming the flag:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        for bad in ("Traceback", "Segmentation fault"):
            assert bad not in combined, (
                f"make BACKEND=ip65 UCI_CHUNKED_WRITE=1 produced {bad!r}:\n"
                f"{combined}")
        print("[ip65+chunked] rejected cleanly with a UCI_CHUNKED_WRITE "
              "diagnostic")
    finally:
        _run_make("clean")


def _main():
    checks = [
        ("ip65 build + labels", lambda: _check_backend("ip65")),
        ("uci build + labels", lambda: _check_backend("uci")),
        ("unknown BACKEND rejected cleanly", test_unknown_backend_fails_cleanly),
        ("uci build without ip65 blob", test_uci_build_does_not_require_ip65_blob),
        # Issue #70 — serial by construction (each rebuilds the tree), and
        # each `make clean`s on its way out.
        ("uci default: no chunk path, MTU 860",
         test_uci_default_build_has_no_chunk_path),
        ("uci UCI_CHUNKED_WRITE=1: links, MTU 1440, chunk path present",
         test_uci_chunked_write_flag_build),
        ("ip65 UCI_CHUNKED_WRITE=1 refused",
         test_ip65_rejects_chunked_write_flag),
    ]
    failures = []
    for name, fn in checks:
        try:
            fn()
            print(f"PASS: {name}")
        except AssertionError as exc:
            failures.append((name, str(exc)))
            print(f"FAIL: {name}\n{exc}")
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for name, msg in failures:
            print(f"  - {name}: {msg.splitlines()[0]}")
        sys.exit(1)
    print(f"All {len(checks)} checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    _main()
