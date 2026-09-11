#!/usr/bin/env python3
"""Unit tests for tools/u64_firmware.py — the /v1/info build-identity check.

Host-side only: no device, no lock, and no traffic beyond a throwaway HTTP
server on 127.0.0.1. What is worth testing is the JUDGEMENT and the
BLAST RADIUS, not the happy path:

  * an unrecognised git_commit_hash must NOT be an error — the next
    legitimate rebase produces one, and a host-side allowlist that refused
    it would block a good build;
  * firmware with no git_commit_hash must say so rather than silently
    reading as "not the spike";
  * the recorded `kind` must actually route. Hardcoding the verdict made
    every KNOWN_BUILDS entry read as a spike image no matter what it said;
  * `describe_build` must never raise and `fetch_info` must never
    propagate, because both run in a PREFLIGHT, inside the device lock (main() acquires it; log_build's callers already hold it), in
    tools whose runs must not die for a build check.

Assertions here avoid substrings that also appear in KNOWN_BUILDS' prose:
an earlier version asserted `"$03 $16" in text`, which stayed green under
the worst false-green in the module because a KNOWN_BUILDS entry happens
to contain that literal too. Checks assert the VERDICT (structural) and,
where text matters, a marker unique to that branch.

Run::

    python3 tools/test_u64_firmware.py [--verbose]
"""
from __future__ import annotations

import http.server
import re
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import u64_firmware as fw  # noqa: E402
from u64_firmware import KNOWN_BUILDS, VERDICTS, describe_build  # noqa: E402

# Captured ONCE at import, so a test that sabotages fw.MAX_INFO_BYTES does
# not also inflate the body the server sends: the oversize body must stay a
# fixed size, or the check passes because the request got slower rather than
# because the guard fired.
HUGE_BODY_BYTES = fw.MAX_INFO_BYTES + 1024

INFO_A474 = {
    "product": "Ultimate 64 Elite", "firmware_version": "3.15",
    "git_commit_hash": "a474a7ed", "fpga_version": "125",
    "core_version": "1.4F", "unique_id": "601A96", "errors": [],
}
# The same device BEFORE upstream added the field (the fpga 124 image).
INFO_NO_HASH = {
    "product": "Ultimate 64 Elite", "firmware_version": "3.15",
    "fpga_version": "124", "core_version": "1.4F",
    "unique_id": "601A96", "errors": [],
}


class _Log:
    """Minimal logger double: records (level, formatted message)."""

    def __init__(self):
        self.calls = []

    def info(self, fmt, *a):
        self.calls.append(("info", fmt % a))

    def warning(self, fmt, *a):
        self.calls.append(("warning", fmt % a))


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves whatever the test asked for, including malformed replies."""

    mode = "good"

    def do_GET(self):                                    # noqa: N802
        if self.mode == "short":
            # 200 promising 500 bytes and delivering 7: urllib raises
            # http.client.IncompleteRead, which is NOT an OSError.
            self.send_response(200)
            self.send_header("Content-Length", "500")
            self.end_headers()
            self.wfile.write(b"{\"a\":1}")
        elif self.mode == "huge":
            # VALID JSON, deliberately: a huge body of junk is refused by the
            # JSON parse whether or not the size guard exists, so the
            # "oversized body is refused" check would have passed for the
            # wrong reason. Only a parseable oversize body tests the guard.
            pad = "x" * HUGE_BODY_BYTES
            body = ('{"firmware_version": "3.15", "pad": "'
                    + pad + '"}').encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.mode in ("403", "404"):
            code = int(self.mode)
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.mode == "drip":
            # Promises 27 bytes, sends one per second. urllib's timeout=
            # resets on every successful recv, so this is UNBOUNDED without
            # a deadline: measured at 108 s against a 10 s timeout.
            self.send_response(200)
            self.send_header("Content-Length", "27")
            self.end_headers()
            for _ in range(27):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(1.0)
                except (BrokenPipeError, ConnectionResetError):
                    return
        elif self.mode == "notjson":
            self._body(b"<html>not json</html>")
        elif self.mode == "notobject":
            self._body(b"[1, 2, 3]")
        else:
            self._body(b'{"firmware_version": "3.15"}')

    def _body(self, b):
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):                           # silence
        pass


def _check(name, cond, detail, fails, verbose, _n=[0]):
    _n[0] += 1
    if cond:
        if verbose:
            print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}: {detail}")
        fails.append(name)
    return _n[0]


def main(argv) -> int:
    verbose = "--verbose" in argv
    fails: list = []
    # Reset the counter: _n lives on the function object, so three calls in
    # ONE process printed 10/10, then 20/20, then 30/30. Safe only while the
    # gate spawns a subprocess — and test_suite_imports.py already imports
    # this module in a foreign process. Same bug this suite was written to
    # fix, one level up.
    _check.__defaults__[0][0] = 0

    def chk(name, cond, detail=""):
        _check(name, cond, detail, fails, verbose)

    # --- verdict routing -------------------------------------------------
    v, text = describe_build(INFO_A474)
    chk("measured image -> chunked", v == "chunked", f"got {v!r}")
    chk("measured image names the hash", "a474a7ed" in text, repr(text))

    v, text = describe_build(dict(INFO_A474, git_commit_hash="deadbeef"))
    chk("unknown hash -> unknown", v == "unknown", f"got {v!r}")
    chk("unknown hash text is the unknown branch, not a KNOWN_BUILDS entry",
        "not measured by this repo" in text
        and all(d not in text for _, d in KNOWN_BUILDS.values()), repr(text))

    v, text = describe_build(INFO_NO_HASH)
    chk("missing field -> no-hash", v == "no-hash", f"got {v!r}")
    chk("no-hash text is the no-hash branch",
        "predates the field" in text, repr(text))

    chk("empty hash -> no-hash",
        describe_build(dict(INFO_A474, git_commit_hash=""))[0] == "no-hash")
    chk("no info -> unreachable", describe_build(None)[0] == "unreachable")

    # --- the recorded kind must ROUTE, not decorate ----------------------
    # Regression: describe_build hardcoded "chunked", so an entry recording a
    # stock image would have false-greened the preflight.
    saved = dict(KNOWN_BUILDS)
    try:
        KNOWN_BUILDS["beef1234"] = ("no-hash", "a stock image, recorded " * 3)
        v, _ = describe_build(dict(INFO_A474, git_commit_hash="beef1234"))
        chk("recorded kind routes the verdict", v == "no-hash", f"got {v!r}")
    finally:
        KNOWN_BUILDS.clear()
        KNOWN_BUILDS.update(saved)

    # --- markers must DISCRIMINATE, not merely appear ---------------------
    # The original bug was not "a substring assertion", it was a substring
    # that is not unique to the branch: `"$03 $16" in text` matched a
    # KNOWN_BUILDS entry's prose instead of the branch under test. So each
    # marker is asserted present in its OWN branch and ABSENT from every
    # other — which also holds if someone later edits KNOWN_BUILDS' wording.
    branches = {
        "chunked": describe_build(INFO_A474)[1],
        "unknown": describe_build(dict(INFO_A474, git_commit_hash="deadbeef"))[1],
        "absent": describe_build(INFO_NO_HASH)[1],
        "empty": describe_build(dict(INFO_A474, git_commit_hash=""))[1],
        "http": describe_build({"__http_status__": 404})[1],
    }
    markers = {"chunked": "1653b0ac", "unknown": "not measured by this repo",
               "absent": "ABSENT", "empty": "EMPTY", "http": "REPLIED"}
    for name, marker in markers.items():
        chk(f"{name} marker is in its own branch", marker in branches[name],
            repr(branches[name][:60]))
        strays = [o for o, txt in branches.items() if o != name and marker in txt]
        chk(f"{name} marker appears in NO other branch", not strays, f"also in {strays}")

    # ABSENT and EMPTY are different device states with different remedies:
    # absent = firmware predates the field; empty = current firmware built
    # outside a git repo (rules.mk backticks, no failure handling, routes.cc
    # emits the key regardless). Same verdict, but they must not read alike.
    chk("absent and empty do not produce identical text",
        branches["absent"] != branches["empty"])

    # --- abbreviation length must not decide the verdict ------------------
    # The firmware embeds `git rev-parse --short HEAD`, whose width follows
    # the BUILDER's core.abbrev, so the same commit can present as 7 chars
    # here and 8 there. An exact dict lookup would report a recorded image
    # as [unknown] purely because someone's git config differs.
    chk("7-char prefix of a recorded hash still matches",
        describe_build(dict(INFO_A474, git_commit_hash="a474a7e"))[0] == "chunked")
    chk("a longer form of a recorded hash still matches",
        describe_build(dict(INFO_A474, git_commit_hash="a474a7ed99"))[0] == "chunked")
    chk("a prefix below the 7-char floor does NOT match",
        describe_build(dict(INFO_A474, git_commit_hash="a474"))[0] == "unknown")
    chk("an uppercase hash still matches",
        describe_build(dict(INFO_A474, git_commit_hash="A474A7ED"))[0] == "chunked")
    chk("a whitespace-padded hash still matches",
        describe_build(dict(INFO_A474, git_commit_hash=" a474a7ed "))[0] == "chunked")
    chk("a non-hex value is not prefix-matched",
        describe_build(dict(INFO_A474, git_commit_hash="not-a-hash"))[0] == "unknown")

    saved2 = dict(KNOWN_BUILDS)
    try:
        KNOWN_BUILDS["a474a7ee"] = ("chunked", "a different image, recorded " * 2)
        v, txt = describe_build(dict(INFO_A474, git_commit_hash="a474a7e"))
        chk("an ambiguous prefix refuses to guess",
            v == "unknown" and "more than one" in txt, f"{v!r} {txt!r}")
    finally:
        KNOWN_BUILDS.clear()
        KNOWN_BUILDS.update(saved2)

    # --- the recorded entry must stay checkable after gc -------------------
    # a474a7ed is a dangling object (0 refs, gc-eligible). The entry has to
    # name its published equivalent or the evidence evaporates with it.
    chk("the unpublished hash names its published equivalent",
        "1653b0ac" in KNOWN_BUILDS["a474a7ed"][1],
        "entry does not name the published commit")

    # --- describe_build must never raise ---------------------------------
    hostile = [[], "3.15", 42, 3.5, True, {"git_commit_hash": ["a"]},
               {"git_commit_hash": {"a": 1}}, {"git_commit_hash": 7},
               {"firmware_version": None}, {}, {"git_commit_hash": "x" * 5000}]
    raised = []
    for h in hostile:
        try:
            vv, tt = describe_build(h)
            if vv not in VERDICTS or not isinstance(tt, str):
                raised.append((h, f"bad return {vv!r}"))
        except Exception as e:                            # noqa: BLE001
            raised.append((h, repr(e)))
    chk("describe_build never raises on hostile payloads", not raised,
        f"{raised[:2]}")

    # --- fetch_info must never propagate ---------------------------------
    # A 200 with a short body raises http.client.IncompleteRead, which is not
    # an OSError and once killed a run at preflight.
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    host = f"127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # The property that matters is NOT a particular return value, it is
        # that nothing propagates and whatever comes back is judged safely.
        # ("short" is a 200 promising 500 bytes and sending 7. Reading with
        # an explicit size means urllib does not enforce Content-Length, so
        # a truncated-but-parseable body arrives as data. That is a WRONG
        # verdict at worst — warning level, never a gate — where the old
        # unsized read raised IncompleteRead and killed the run.)
        for mode in ("short", "huge", "notjson", "notobject", "good"):
            _Handler.mode = mode
            try:
                got = fw.fetch_info(host, timeout=5.0)
                v, txt = describe_build(got)
                chk(f"fetch_info + describe_build survive a {mode} reply",
                    v in VERDICTS and isinstance(txt, str), f"verdict {v!r}")
            except Exception as e:                        # noqa: BLE001
                chk(f"fetch_info + describe_build survive a {mode} reply",
                    False, repr(e))
        _Handler.mode = "huge"
        chk("an oversized body is refused, not parsed",
            fw.fetch_info(host, timeout=5.0) is None)
        _Handler.mode = "notjson"
        chk("a non-JSON body is refused", fw.fetch_info(host, timeout=5.0) is None)

        # An HTTP status is an ANSWER: a device that replies 403 (network
        # password) or 404 (firmware with no /v1/info) is reachable, and
        # calling it "unreachable" diagnoses a state we did not establish.
        for code in ("403", "404"):
            _Handler.mode = code
            v, txt = describe_build(fw.fetch_info(host, timeout=5.0))
            chk(f"HTTP {code} is not reported as unreachable",
                v == "no-hash" and "REPLIED" in txt, f"{v!r} {txt!r}")
            chk(f"HTTP {code} names the status", code in txt, repr(txt))

        # The wait must be bounded in TOTAL, not per-recv.
        _Handler.mode = "drip"
        t0 = time.monotonic()
        fw.fetch_info(host, timeout=3.0)
        drip = time.monotonic() - t0
        chk("a slow drip is bounded by the total deadline", drip < 8.0,
            f"took {drip:.1f}s for a 3s budget")

        # A non-object 200 must reach describe_build and be judged, not crash.
        _Handler.mode = "notobject"
        v, _ = describe_build(fw.fetch_info(host, timeout=5.0))
        chk("non-object /v1/info -> unreachable", v == "unreachable", f"got {v!r}")

        # log_build routes level by verdict and returns it.
        _Handler.mode = "good"
        lg = _Log()
        v = fw.log_build(host, lg, timeout=5.0)
        chk("log_build returns the verdict", v == "no-hash", f"got {v!r}")
        chk("log_build WARNS on a non-chunked verdict",
            lg.calls and lg.calls[-1][0] == "warning", f"{lg.calls}")

        lg2 = _Log()
        saved_fetch = fw.fetch_info
        try:
            fw.fetch_info = lambda *a, **k: INFO_A474
            v = fw.log_build(host, lg2)
            chk("log_build INFOs a measured image",
                v == "chunked" and lg2.calls[-1][0] == "info", f"{lg2.calls}")
            # Stub the DeviceLock. main() acquires one for real (that is
            # the contract this suite pins below), and a hardware-free gate
            # suite must not open a machine-global lockfile or construct a
            # client that probes /v1/info to get here.
            import contextlib
            import device_session as _ds
            saved_lc = _ds.locked_client
            acquired = []

            @contextlib.contextmanager
            def _fake_locked_client(h, timeout=None, purpose=None, logger=None):
                acquired.append((h, timeout, purpose))
                yield object()          # a granted lock yields a client

            @contextlib.contextmanager
            def _busy_locked_client(h, timeout=None, purpose=None, logger=None):
                acquired.append((h, timeout, purpose))
                yield None              # busy: locked_client yields None

            try:
                _ds.locked_client = _fake_locked_client
                chk("main() exits 0 on a measured image",
                    fw.main(["x", host]) == 0)
                # The point of the lock is that it is TAKEN. Assert it, or
                # this suite would pass just as happily with main() reading
                # the device unserialised, which is what it used to do.
                chk("main() queued for the device through locked_client",
                    len(acquired) == 1 and acquired[0][0] == host,
                    f"{acquired}")
                # `acquired and ...`: if the lock is gone entirely this
                # must REPORT a failed check, not raise IndexError out of
                # the suite and skip every check below it.
                chk("main() waits like a live tool, not like a restore (120s)",
                    bool(acquired) and acquired[0][1] == 120.0,
                    f"acquired={acquired}")
                _ds.locked_client = _busy_locked_client
                chk("main() exits 3 (NOT 0) when the lock is busy — a busy "
                    "lock means no check was taken",
                    fw.main(["x", host]) == 3)
            finally:
                _ds.locked_client = saved_lc
        finally:
            fw.fetch_info = saved_fetch
        chk("main() exits 2 on wrong argument count", fw.main(["x"]) == 2)
    finally:
        srv.shutdown()

    # --- every recorded build carries its evidence -----------------------
    for h, (kind, detail) in KNOWN_BUILDS.items():
        chk(f"{h} records evidence", len(detail) > 40 and kind in VERDICTS,
            f"thin entry {detail!r}")
        # A reassembly claim must carry a STRUCTURED evidence token, not
        # prose. Required form, anywhere in the detail:
        #
        #     REASSEMBLY-EVIDENCE: <bytes>B as <n> datagram(s) on <YYYY-MM-DD>
        #
        # and it is only evidence if <bytes> exceeds the $16 part cap (888,
        # so the send MUST have been split) and <n> is 1 (so the firmware
        # put it back together). At or under the cap, one datagram evidences
        # dispatch, not reassembly.
        #
        # Two earlier versions of this check were wrong, both instructively:
        #   - "reassembl" not in detail -- i.e. NO entry may claim it. True
        #     while none had measured it; a false positive the moment one
        #     did. A guard encoding the state of the world expires silently.
        #   - a free-text scan for any number > 888. Satisfied by incidental
        #     figures elsewhere in the prose (ECHO_PAYLOAD_LEN=888,1472),
        #     so deleting the actual evidence left it green. Proven by
        #     mutation, which is why the token is structured now.
        d = detail.lower()
        claims_reassembly = ("reassembl" in d
                             and "does NOT evidence" not in detail
                             and "rests on" not in detail)
        if claims_reassembly:
            m = re.search(r"REASSEMBLY-EVIDENCE:\s*(\d+)B as (\d+) datagram"
                          r"[s]? on (\d{4}-\d{2}-\d{2})", detail)
            chk(f"{h} reassembly claim carries a structured evidence token",
                m is not None,
                f"no REASSEMBLY-EVIDENCE token in {detail!r}")
            if m:
                nbytes, ndg = int(m.group(1)), int(m.group(2))
                chk(f"{h} reassembly evidence exceeds the $16 part cap",
                    nbytes > 888, f"{nbytes}B does not require splitting")
                chk(f"{h} reassembly evidence is a single datagram",
                    ndg == 1, f"observed {ndg} datagrams, not 1")
        else:
            chk(f"{h} does not claim reassembly it did not measure", True)

    # Counted, not hardcoded: a check that stops running must not keep
    # inflating the total it is reported against.
    n = _check.__defaults__[0][0]
    if fails:
        print(f"FAIL: {len(fails)} of {n} checks failed: {', '.join(fails)}")
        return 1
    print(f"PASS: {n}/{n} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
