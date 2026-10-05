#!/usr/bin/env python3
"""tools/test_live_tools_wifi.py — host-side red/green for the live-tool
defects the 2026-10-04 WiFi run exposed (U64E fw 3a1ff9ff).

No device, no VICE, no build. Every case drives the REAL tool code with the
device side faked, and every case carries a network guard: any attempt to
open a socket to a non-loopback address, take a DeviceLock or spawn a
process naming a device is RECORDED and REFUSED, so a test can never touch
the shared U64E and "made no contact" is measured, not assumed.

  2  test_uci_udp_size_probe.py: `cap = _recv_buf_capacity(L)` shadowed the
     DebugCapture; the finally's `cap.stop()` raised AttributeError and
     skipped the summary, teardown_device() and lock.release().
  3  same tool: stream_debug_start raising (HTTP 500 "No Operational Network
     Interface" — the debug stream needs the wired port) was fatal. The
     trace is post-mortem only, so the fixed tool notes `debug_trace
     unavailable` and its verdict comes from the payload checks: clean ->
     PASS. The vacuous-pass detector targets the GATING checks instead: no
     size probed, a size skipped, a responder that never answered must not
     PASS (self-checked both ways on fabricated outcomes). A mutation that
     SHOULD survive (_print_summary emptied) is run and must stay green.
  4  test_uci_handshake_live.py / test_config_reload_live.py: every
     net_poll call site's budget is MEASURED by executing the call
     expression exactly as written against a fake C64 on a fake clock:
     a 1.97 s first poll (observed after Type-2 at 1 MHz on WiFi) must
     complete, a hang must still time out, within 30 s, and the guard must
     fire just past its measured budget and not just before it.
  5  seeded-random tunnel payloads in _run_stage3 (was "HELLO WIREGUARD"
     forward / "PONG-FROM-PY-C64" reverse): different seeds -> different
     LEADING bytes, same seed -> identical bytes, forward and reverse
     alphabets disjoint, and the forward check compares content (a C64
     that sends the wrong bytes must fail stage 3).
  6  u64_firmware.KNOWN_BUILDS: 3a1ff9ff dispatches $16 -> "chunked"; the
     set of chunked hashes is pinned by EQUALITY.
  7  live tools must refuse to run without U64_HOST/--host: non-zero exit,
     a message naming U64_HOST, and zero contact (measured by the guard in
     a child process, whose loading is itself asserted).

HARDWARE-ONLY: whether 3a1ff9ff's debug stream really 500s on WiFi, and the
real first-poll latency, are the live run's observations; the commands that
re-measure them are in the PR description.

Usage: python3 tools/test_live_tools_wifi.py [--seed N] [--only 2|3|4|5|6|7]
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.util
import inspect
import io
import json
import logging
import os
import random
import socket
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS = PROJECT_ROOT / "tools"
sys.path.insert(0, str(TOOLS))

OBSERVED_FIRST_POLL_S = 1.97     # live run 2026-10-04, 1 MHz, WiFi, after Type-2
POLL_BUDGET_CEILING_S = 30.0     # "not unbounded": a hung poll is seen within this
FORWARD_LEN = 15                 # test_payload_len in build/labels.txt (= 15)


class Result:
    def __init__(self):
        self.passed = self.failed = 0
        self.names: list[str] = []
        self.failures: list[str] = []

    def check(self, ok, name, detail=""):
        self.names.append(name)
        if ok:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            self.failures.append(name)
            print(f"  FAIL  {name}\n        {detail}")
        return bool(ok)


# =============================================================================
# The network guard
# =============================================================================
def _is_local(host) -> bool:
    h = str(host)
    return h.startswith("127.") or h in ("localhost", "::1", "", "0.0.0.0")


class ContactRefused(PermissionError):
    pass


@contextlib.contextmanager
def contact_guard():
    """Record and refuse device contact for the duration (in-process)."""
    log: list[str] = []
    orig = {
        "connect": socket.socket.connect,
        "connect_ex": socket.socket.connect_ex,
        "sendto": socket.socket.sendto,
        "create_connection": socket.create_connection,
        "Popen": subprocess.Popen,
    }

    def _addr(a):
        return a[0] if isinstance(a, tuple) and a else a

    def connect(self, address):
        if not _is_local(_addr(address)):
            log.append(f"socket.connect {address!r}")
            raise ContactRefused(f"guard: connect to {address!r} refused")
        return orig["connect"](self, address)

    def connect_ex(self, address):
        if not _is_local(_addr(address)):
            log.append(f"socket.connect_ex {address!r}")
            raise ContactRefused(f"guard: connect_ex to {address!r} refused")
        return orig["connect_ex"](self, address)

    def sendto(self, data, *a):
        address = a[-1]
        if not _is_local(_addr(address)):
            log.append(f"socket.sendto {address!r}")
            raise ContactRefused(f"guard: sendto {address!r} refused")
        return orig["sendto"](self, data, *a)

    def create_connection(address, *a, **kw):
        if not _is_local(_addr(address)):
            log.append(f"socket.create_connection {address!r}")
            raise ContactRefused(f"guard: create_connection {address!r} refused")
        return orig["create_connection"](address, *a, **kw)

    class Popen(orig["Popen"]):           # type: ignore[misc, valid-type]
        def __init__(self, args, *a, **kw):
            log.append(f"subprocess {args!r}")
            raise ContactRefused(f"guard: subprocess {args!r} refused")

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.create_connection = create_connection
    subprocess.Popen = Popen
    try:
        yield log
    finally:
        socket.socket.connect = orig["connect"]
        socket.socket.connect_ex = orig["connect_ex"]
        socket.socket.sendto = orig["sendto"]
        socket.create_connection = orig["create_connection"]
        subprocess.Popen = orig["Popen"]


# The same guard for a CHILD process, installed through sitecustomize. It
# also refuses DeviceLock acquisition: taking the lock for a device you were
# never told to use is contact, and it would queue behind the lane that
# really holds the U64E.
SITECUSTOMIZE = r'''
import json, os, socket, subprocess, sys
# Chain to the interpreter's own sitecustomize (Homebrew's puts site paths,
# and with them c64_test_harness, on sys.path) before installing the guard.
_here = os.path.dirname(os.path.abspath(__file__))
for _p in list(sys.path):
    _f = os.path.join(_p, "sitecustomize.py")
    if _p and os.path.abspath(_p) != _here and os.path.isfile(_f):
        exec(compile(open(_f).read(), _f, "exec"), {"__name__": "sitecustomize_chained", "__file__": _f})
        break
_LOG = os.environ["LIVE_GUARD_LOG"]
def _rec(kind, what):
    with open(_LOG, "a") as f:
        f.write(json.dumps({"kind": kind, "what": repr(what)}) + "\n")
_rec("guard-loaded", sys.argv)
def _local(a):
    h = a[0] if isinstance(a, tuple) and a else a
    h = str(h)
    return h.startswith("127.") or h in ("localhost", "::1", "", "0.0.0.0")
_oc, _ocx, _os, _occ = (socket.socket.connect, socket.socket.connect_ex,
                        socket.socket.sendto, socket.create_connection)
def _c(self, a):
    if not _local(a):
        _rec("connect", a); raise PermissionError(f"guard refused connect {a!r}")
    return _oc(self, a)
def _cx(self, a):
    if not _local(a):
        _rec("connect", a); raise PermissionError(f"guard refused connect {a!r}")
    return _ocx(self, a)
def _s(self, d, *a):
    if not _local(a[-1]):
        _rec("sendto", a[-1]); raise PermissionError(f"guard refused sendto {a[-1]!r}")
    return _os(self, d, *a)
def _cc(a, *x, **k):
    if not _local(a):
        _rec("connect", a); raise PermissionError(f"guard refused connect {a!r}")
    return _occ(a, *x, **k)
socket.socket.connect, socket.socket.connect_ex = _c, _cx
socket.socket.sendto, socket.create_connection = _s, _cc
_OP = subprocess.Popen
_ALLOW = {"git", "wg", "ifconfig", "uname", "sw_vers"}
class _P(_OP):
    def __init__(self, args, *a, **k):
        argv = [args] if isinstance(args, str) else list(args)
        prog = os.path.basename(str(argv[0])) if argv else ""
        if prog not in _ALLOW:
            _rec("subprocess", argv); raise PermissionError(f"guard refused {argv!r}")
        super().__init__(args, *a, **k)
subprocess.Popen = _P
try:
    from c64_test_harness.backends import device_lock as _dl
    def _no(self, *a, **k):
        _rec("devicelock", {k: v for k, v in vars(self).items() if "host" in k} or vars(self))
        raise PermissionError("guard refused DeviceLock acquisition")
    for _m in ("acquire", "acquire_or_raise"):
        if hasattr(_dl.DeviceLock, _m):
            setattr(_dl.DeviceLock, _m, _no)
except Exception as _e:                      # noqa: BLE001
    _rec("guard-note", f"DeviceLock not patched: {_e!r}")
'''


# =============================================================================
# Fakes
# =============================================================================
class FakeTime:
    """A clock that only moves when slept on. Replaces a module's `time`."""

    def __init__(self):
        self.t = 1000.0
        self.slept = 0

    def monotonic(self):
        return self.t

    def time(self):
        return self.t

    def perf_counter(self):
        return self.t

    def sleep(self, dt):
        self.slept += 1
        if self.slept > 2_000_000:
            raise RuntimeError("fake clock: runaway sleep loop")
        self.t += max(float(dt), 1e-4)

    def strftime(self, *a):
        import time as _t
        return _t.strftime(*a)


class AutoLabels(dict):
    """L[...] for any name: distinct fake addresses, with the equates real."""

    EQUATES = {"test_payload_len": FORWARD_LEN}

    def __init__(self, fixed=None):
        super().__init__()
        self._next = 0x5000
        for k, v in (fixed or {}).items():
            self[k] = v

    def __missing__(self, name):
        if name in self.EQUATES:
            self[name] = self.EQUATES[name]
        else:
            self[name] = self._next
            self._next += 0x200
        return self[name]

    def address(self, name):
        return self[name]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Capture:
    """stdout + stderr + logging, as one string."""

    def __enter__(self):
        self.buf = io.StringIO()
        self._o = contextlib.redirect_stdout(self.buf)
        self._e = contextlib.redirect_stderr(self.buf)
        self._o.__enter__(); self._e.__enter__()
        self.h = logging.StreamHandler(self.buf)
        self.h.setLevel(logging.DEBUG)
        root = logging.getLogger()
        self._lvl = root.level
        root.addHandler(self.h)
        root.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        root = logging.getLogger()
        root.removeHandler(self.h)
        root.setLevel(self._lvl)
        self._e.__exit__(*exc); self._o.__exit__(*exc)
        self.text = self.buf.getvalue()
        return False


# =============================================================================
# 2 + 3: test_uci_udp_size_probe.py teardown and capture-down
# =============================================================================
def run_size_probe(*, capture_down: bool, mutate_summary: bool = False,
                   seed: int = 1, sizes=None, responder_silent: bool = False):
    """Run the probe's REAL main() with the device faked. Returns a record."""
    rec = SimpleNamespace(exc=None, rc=None, text="", lock_acq=0, lock_rel=0,
                          teardowns=0, cap_started=0, cap_stopped=0,
                          served=[], contact=[], probed_sizes=[])
    old_env = {k: os.environ.get(k) for k in
               ("U64_HOST", "U64_ALLOW_MUTATE", "C64_SKIP_BUILD", "TEST_SEED")}
    os.environ.update(U64_HOST="192.0.2.10", U64_ALLOW_MUTATE="1",
                      C64_SKIP_BUILD="1", TEST_SEED=str(seed))
    old_argv = sys.argv
    sys.argv = ["test_uci_udp_size_probe.py"]
    tmp = tempfile.TemporaryDirectory(prefix="sizeprobe_")
    import device_session
    old_teardown = device_session.teardown_device
    try:
        sp = _load(TOOLS / "test_uci_udp_size_probe.py",
                   f"size_probe_under_test_{random.randrange(1 << 30)}")
        L = AutoLabels({"udp_recv_buf": 0x3000, "udp_recv_len": 0x3000 + 1500})
        mem = bytearray(0x10000)

        class FakeLabelsFile:
            @staticmethod
            def from_file(_p):
                return L

        class FakeLock:
            def __init__(self, host, *a, **k):
                self.host = host

            def acquire_or_raise(self, *a, **k):
                rec.lock_acq += 1
                return True

            acquire = acquire_or_raise

            def release(self):
                rec.lock_rel += 1

        class FakeClient:
            def __init__(self, *a, **k):
                pass

            def reboot(self):
                pass

            def stream_debug_start(self, *_a, **_k):
                if capture_down:
                    raise RuntimeError(
                        "HTTP 500 from PUT /v1/streams/debug:start: "
                        "No Operational Network Interface")

            def stream_debug_stop(self, *_a, **_k):
                pass

            def run_prg(self, *_a, **_k):
                pass

        class FakeTr:
            def __init__(self, *a, **k):
                pass

            def read_memory(self, addr, n):
                return bytes(mem[addr:addr + n])

            def write_memory(self, addr, data):
                mem[addr:addr + len(data)] = bytes(data)

            def close(self):
                pass

        class FakeCapResult:
            packets_received = 10
            packets_dropped = 0
            duration_seconds = 1.0
            total_cycles = 12345
            trace = []

        class FakeCapture:
            def __init__(self, *a, **k):
                pass

            def start(self):
                rec.cap_started += 1

            def stop(self):
                rec.cap_stopped += 1
                return FakeCapResult()

        class FakeResponder:
            def __init__(self, port=0, **k):
                self.port = 40000
                self.response_size = 0
                self.response_payload = b""
                self.last_response = None
                self.responses_sent = 0
                self.pending = None

            def start(self):
                pass

            def stop(self):
                pass

            def join(self, timeout=None):
                pass

        responders = []

        def make_responder(*a, **k):
            r = FakeResponder(*a, **k)
            responders.append(r)
            return r

        def fake_run_step(tr, *, step_id, target, reg_a=0, reg_x=0, timeout=None):
            r = responders[-1] if responders else None
            if target == L["net_udp_send"] and r is not None and not responder_silent:
                r.responses_sent += 1
                r.last_response = r.response_payload
                r.pending = r.response_payload
                rec.served.append(len(r.response_payload))
            elif target == L["net_poll"] and r is not None and r.pending is not None:
                data, r.pending = r.pending, None
                a = L["udp_recv_buf"]
                mem[a:a + len(data)] = data
                ln = L["udp_recv_len"]
                mem[ln] = len(data) & 0xFF
                mem[ln + 1] = len(data) >> 8
                mem[L["udp_recv_ready"]] = 1
            return 0

        def fake_teardown(*a, **k):
            rec.teardowns += 1
            return {}

        ft = FakeTime()
        patches = {
            "Labels": FakeLabelsFile, "DeviceLock": FakeLock,
            "probe_u64": lambda *a, **k: SimpleNamespace(reachable=True, error=None,
                                                         latency_ms=1.0),
            "Ultimate64Client": FakeClient, "Ultimate64Transport": FakeTr,
            "runner_health_check": lambda *a, **k: None,
            "recover": lambda *a, **k: "reset",
            "get_uci_enabled": lambda *a, **k: True,
            "enable_uci": lambda *a, **k: None,
            "get_turbo_mhz": lambda *a, **k: 1,
            "set_turbo_mhz": lambda *a, **k: None,
            "get_debug_stream_mode": lambda *a, **k: "6510 Only",
            "set_debug_stream_mode": lambda *a, **k: None,
            "check_measurement_environment": lambda *a, **k: None,
            "set_reu": lambda *a, **k: None,
            "DebugCapture": FakeCapture, "UDPSizeResponder": make_responder,
            "_wait_boot": lambda *a, **k: None,
            "_install_trampoline": lambda *a, **k: None,
            "_local_ip_for": lambda *a, **k: "127.0.0.1",
            "_run_step": fake_run_step,
            "time": ft,
            "ARTIFACTS_DIR": Path(tmp.name),
            "PROJECT_ROOT": Path(tmp.name),
        }
        for k, v in patches.items():
            setattr(sp, k, v)
        if mutate_summary:
            sp._print_summary = lambda *a, **k: None
        if sizes is not None:
            sp.SIZES = list(sizes)
        (Path(tmp.name) / "build").mkdir()
        (Path(tmp.name) / "build" / "wireguard.prg").write_bytes(b"\x01\x08")
        (Path(tmp.name) / "build" / "labels.txt").write_text("")
        device_session.teardown_device = fake_teardown
        cap = 0
        rec.cap_of = lambda: cap
        rec.sizes = [s for s in sp.SIZES if s <= 1500]
        with contact_guard() as contact, Capture() as out:
            try:
                rec.rc = sp.main()
            except BaseException as exc:          # noqa: BLE001
                rec.exc = exc
        rec.contact = list(contact)
        rec.text = out.text
    finally:
        device_session.teardown_device = old_teardown
        sys.argv = old_argv
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        tmp.cleanup()
    return rec


TRACE_NOTE = "debug_trace unavailable"


def judge_gating(exc, rc):
    """The vacuous-pass detector for the GATING checks. A run in which a
    gating check could not be made (no size probed, a size skipped, no reply
    on the wire) must end in a clean non-zero verdict: not a PASS, and not a
    crash that skips the teardown either. Returns reasons it is NOT ok."""
    if exc is not None:
        return [f"the tool raised {type(exc).__name__}: {exc}"]
    if rc == 0:
        return ["exit status 0 — PASS over a gating check that was never made"]
    if rc is None:
        return ["main() returned None, not a verdict"]
    return []


def case_size_probe(res, seed):
    print("\n[2] size probe: teardown survives (DebugCapture not shadowed)")
    r = run_size_probe(capture_down=False, seed=seed)
    res.check(r.exc is None, "2/main-returns-without-raising",
              f"main() raised {type(r.exc).__name__}: {r.exc}")
    res.check(r.lock_acq == 1 and r.lock_rel == 1, "2/lock-released-exactly-once",
              f"DeviceLock acquire={r.lock_acq} release={r.lock_rel}")
    res.check(r.teardowns == 1, "2/teardown_device-ran",
              f"teardown_device called {r.teardowns} times")
    res.check(r.cap_started == 1 and r.cap_stopped == 1,
              "2/debug-capture-started-and-stopped",
              f"DebugCapture.start x{r.cap_started}, .stop x{r.cap_stopped}")
    res.check(r.served == r.sizes, "2/every-size-probed",
              f"responder served {r.served}, want one reply per size {r.sizes}")
    res.check(r.exc is None and r.rc == 0, "2/healthy-capture-is-a-clean-PASS",
              f"rc={r.rc} exc={r.exc!r}")
    res.check(not r.contact, "2/no-device-contact", f"{r.contact}")

    res.check(TRACE_NOTE not in r.text, "2/healthy-capture-prints-no-trace-note",
              f"'{TRACE_NOTE}' printed although the capture worked — a note that "
              f"fires on a healthy run cannot tell the two apart")

    print("\n[3] size probe: stream_debug_start -> HTTP 500 (WiFi)")
    d = run_size_probe(capture_down=True, seed=seed)
    res.check(d.exc is None, "3/capture-refused-does-not-crash",
              f"main() raised {type(d.exc).__name__}: {d.exc}")
    res.check(d.served == d.sizes, "3/sizes-still-probed-with-capture-refused",
              f"responder served {d.served}, want {d.sizes}: the trace is "
              f"post-mortem only, so losing it must not cost the measurement")
    res.check(d.exc is None and d.rc == 0, "3/clean-payloads-PASS-without-trace",
              f"rc={d.rc} exc={d.exc!r}: no gating assertion reads the trace")
    res.check(TRACE_NOTE in d.text, "3/refused-trace-is-reported",
              f"no '{TRACE_NOTE}' note: a refused capture must be said, not silent")
    res.check(d.lock_acq == 1 and d.lock_rel == 1 and d.teardowns == 1,
              "3/teardown-and-lock-release-with-capture-refused",
              f"acquire={d.lock_acq} release={d.lock_rel} teardown={d.teardowns}")
    res.check(not d.contact, "3/no-device-contact", f"{d.contact}")

    # Vacuous-pass detector: gating checks that could not be made.
    gating = [
        ("no-size-probed", dict(sizes=[])),
        ("a-size-skipped", dict(sizes=[32, 4000])),
        ("responder-never-answered", dict(responder_silent=True)),
    ]
    for name, kw in gating:
        g = run_size_probe(capture_down=True, seed=seed, **kw)
        why = judge_gating(g.exc, g.rc)
        res.check(not why and g.lock_rel == 1, f"3/gating-{name}-is-not-PASS",
                  "; ".join(why) + f" (release={g.lock_rel})")
    fab = [("crash", RuntimeError("x"), None, False),
           ("plain PASS", None, 0, False),
           ("no verdict", None, None, False),
           ("honest FAIL", None, 1, True)]
    bad = [n for n, e, rc, want_ok in fab if (not judge_gating(e, rc)) != want_ok]
    res.check(not bad, "3/vacuous-pass-detector-fires-both-ways",
              f"detector misjudged: {bad}")

    # A mutation that SHOULD survive: the summary TABLE is presentation; no
    # check above may depend on it.
    m = run_size_probe(capture_down=True, mutate_summary=True, seed=seed)
    ok = (m.exc is None and m.rc == 0 and m.lock_rel == 1 and m.teardowns == 1
          and m.served == m.sizes)
    res.check(ok, "3/should-survive-mutation-empty-summary-table-stays-green",
              f"exc={m.exc!r} rc={m.rc} release={m.lock_rel} "
              f"teardown={m.teardowns} served={m.served}")


# =============================================================================
# 4: net_poll budgets, measured
# =============================================================================
class FakeC64:
    """The host-side trampoline protocol of test_uci_udp_echo_live, on a fake
    clock: GO_FLAG=1 starts the step, SENTINEL reads the step id once the
    step has run for `delay` seconds (never, if delay is None)."""

    def __init__(self, echo, clock, delay, on_target=None, labels=None):
        self.echo = echo
        self.clock = clock
        self.delay = delay
        self.mem = bytearray(0x10000)
        self.done_at = None
        self.on_target = on_target
        self.labels = labels

    def _complete_if_due(self):
        if self.done_at is not None and self.clock.t >= self.done_at:
            e = self.echo
            self.mem[e.SENTINEL] = self.mem[e.SENTINEL + 2]
            self.mem[e.CARRY] = 0
            self.done_at = None

    def read_memory(self, addr, n):
        self._complete_if_due()
        return bytes(self.mem[addr:addr + n])

    def write_memory(self, addr, data):
        self.mem[addr:addr + len(data)] = bytes(data)
        e = self.echo
        if addr == e.GO_FLAG and data and data[0] == 1:
            tgt = (self.mem[e.TRAMP + e.SMC_TARG_LO]
                   | (self.mem[e.TRAMP + e.SMC_TARG_HI] << 8))
            if self.on_target is not None:
                self.on_target(self, tgt)
            if self.delay is not None:
                self.done_at = self.clock.t + self.delay
            self._complete_if_due()


def net_poll_call_sites(path: Path):
    """Every call in the file whose `target=` names L["net_poll"]."""
    tree = ast.parse(path.read_text())
    sites = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and any(
                    kw.arg == "target" and "net_poll" in ast.unparse(kw.value)
                    for kw in node.keywords):
                sites.append((fn.name, node.lineno, node))
    # Calls nested in nested functions are seen twice; keep one per line.
    seen, out = set(), []
    for s in sites:
        if s[1] not in seen:
            seen.add(s[1])
            out.append(s)
    return out


def run_poll_site(mod, echo, call, delay, labels):
    """Execute the call expression exactly as written. Returns (completed,
    elapsed_fake_s, exc)."""
    clock = FakeTime()
    tr = FakeC64(echo, clock, delay)
    ns = dict(mod.__dict__)
    ns.update(tr=tr, L=labels, args=SimpleNamespace(turbo=1, reu="on", stage=2,
                                                    chat=False, host="192.0.2.10"))
    fn_expr = ast.unparse(call.func)
    fn = eval(fn_expr, ns)
    patched = []
    for g in {id(mod.__dict__): mod.__dict__,
              id(getattr(fn, "__globals__", {})): getattr(fn, "__globals__", {})}.values():
        for name in ("time",):
            if name in g:
                patched.append((g, name, g[name]))
                g[name] = clock
        for name in ("monotonic", "sleep"):
            if name in g and callable(g[name]):
                patched.append((g, name, g[name]))
                g[name] = getattr(clock, name)
    ns["time"] = clock
    t0 = clock.t
    exc = None
    try:
        # Locals of the enclosing function are not in scope here. Bind each
        # one the expression needs: a clock knob to 1 (MHz), anything else to
        # the datagram the observation was made on — a 92-byte Type-2.
        for _ in range(8):
            try:
                eval(ast.unparse(call), ns)
                break
            except NameError as ne:
                missing = getattr(ne, "name", None) or str(ne).split("'")[1]
                if missing in ns:
                    raise
                ns[missing] = 1 if ("mhz" in missing or "turbo" in missing) \
                    else bytes(92)
    except Exception as e:                     # noqa: BLE001
        exc = e
    finally:
        for g, name, v in patched:
            g[name] = v
    completed = tr.mem[echo.SENTINEL] == tr.mem[echo.SENTINEL + 2] and \
        tr.mem[echo.SENTINEL + 2] != 0
    return completed and exc is None, clock.t - t0, exc


def case_poll_budget(res):
    print("\n[4] net_poll budgets (fake clock, the REAL call expressions)")
    echo = _load(TOOLS / "test_uci_udp_echo_live.py", "echo_for_poll_budget")
    sys.modules.setdefault("test_uci_udp_echo_live", echo)
    files = [("handshake", TOOLS / "test_uci_handshake_live.py"),
             ("config_reload", TOOLS / "test_config_reload_live.py")]
    for short, path in files:
        mod = _load(path, f"{short}_for_poll_budget")
        sites = net_poll_call_sites(path)
        res.check(bool(sites), f"4/{short}/has-net_poll-call-sites",
                  f"no call with target=...net_poll... found in {path.name}")
        for fname, line, call in sites:
            tag = f"4/{short}/{fname}"
            labels = AutoLabels()
            try:
                ok_obs, t_obs, e_obs = run_poll_site(mod, echo, call,
                                                     OBSERVED_FIRST_POLL_S, labels)
                ok_hang, t_hang, e_hang = run_poll_site(mod, echo, call, None, labels)
            except Exception as e:             # noqa: BLE001
                res.check(False, f"{tag}/observed-1.97s-poll-completes",
                          f"could not execute `{ast.unparse(call)}`: {e!r}")
                res.check(False, f"{tag}/hang-times-out-bounded", "not executed")
                res.check(False, f"{tag}/guard-fires-at-its-boundary", "not executed")
                continue
            res.check(ok_obs, f"{tag}/observed-1.97s-poll-completes",
                      f"line {line}: a poll that takes {OBSERVED_FIRST_POLL_S} s "
                      f"(measured after Type-2, 1 MHz, WiFi) was abandoned after "
                      f"{t_obs:.2f} s: {type(e_obs).__name__ if e_obs else ''} {e_obs}")
            res.check(not ok_hang and t_hang <= POLL_BUDGET_CEILING_S,
                      f"{tag}/hang-times-out-bounded",
                      f"line {line}: a poll that never completes "
                      + ("RETURNED AS COMPLETE" if ok_hang else
                         f"was abandoned after {t_hang:.2f} s (ceiling "
                         f"{POLL_BUDGET_CEILING_S:.0f} s)"))
            ok_in, _, _ = run_poll_site(mod, echo, call, max(t_hang - 0.15, 0.0), labels)
            ok_out, _, _ = run_poll_site(mod, echo, call, t_hang + 0.3, labels)
            res.check(ok_in and not ok_out, f"{tag}/guard-fires-at-its-boundary",
                      f"measured budget {t_hang:.2f} s: completes at -0.15 s: "
                      f"{ok_in}, abandoned at +0.30 s: {not ok_out}")


# =============================================================================
# 5: seeded-random tunnel payloads
# =============================================================================
def run_stage3(seed: int, *, wrong_forward=False):
    """Drive _run_stage3 with a fake C64/responder. Returns (forward, reverse,
    rc, text): forward = the bytes in test_payload when do_send_test ran,
    reverse = what the host asked the responder to encrypt for the C64."""
    old = os.environ.get("TEST_SEED")
    os.environ["TEST_SEED"] = str(seed)
    try:
        live = _load(TOOLS / "test_uci_handshake_live.py",
                     f"hs_live_seed_{seed}_{random.randrange(1 << 30)}")
    finally:
        if old is None:
            os.environ.pop("TEST_SEED", None)
        else:
            os.environ["TEST_SEED"] = old
    echo = sys.modules["test_uci_udp_echo_live"]
    L = AutoLabels()
    clock = FakeTime()
    got = SimpleNamespace(forward=None, reverse=None)

    class RT:
        type4_received_at = None
        c64_addr = ("127.0.0.2", 51820)
        last_error = None
        type4_count = 0

        def __init__(self):
            self.q = []
            self.to_c64 = []

        def drain_type4(self):
            q, self.q = self.q, []
            return q

        def send_raw(self, data):
            self.to_c64.append(data)

    rt = RT()

    class Responder:
        def encrypt_transport(self, pt):
            got.reverse = bytes(pt)
            return b"\x04\x00\x00\x00" + bytes(pt)

        def decrypt_transport(self, data):
            return bytes(data[4:])

    def on_target(tr, tgt):
        # Whatever the C64 is asked to encrypt is what crosses the wire:
        # do_send_test sends test_payload; transport_send sends
        # tp_payload_len bytes at tp_payload_ptr.
        fwd = None
        if tgt == L["do_send_test"]:
            n = L["test_payload_len"]
            fwd = bytes(tr.mem[L["test_payload"]:L["test_payload"] + n])
        elif tgt == L["transport_send"]:
            ptr = tr.mem[L["tp_payload_ptr"]] | (tr.mem[L["tp_payload_ptr"] + 1] << 8)
            n = tr.mem[L["tp_payload_len"]] | (tr.mem[L["tp_payload_len"] + 1] << 8)
            fwd = bytes(tr.mem[ptr:ptr + n])
        if fwd is not None:
            got.forward = fwd
            pt = bytearray(got.forward)
            if wrong_forward and pt:
                pt[0] ^= 0x01
            rt.q.append(bytes(pt))
            rt.type4_count += 1
            rt.type4_received_at = clock.t
        elif tgt == L["net_poll"] and rt.to_c64:
            tr.mem[L["udp_recv_ready"]] = 1
        elif tgt == L["session_handle_packet"] and rt.to_c64:
            pt = rt.to_c64.pop(0)[4:]
            a = L["tp_packet"] + 16
            tr.mem[a:a + len(pt)] = pt
            pl = L["tp_payload_len"]
            tr.mem[pl], tr.mem[pl + 1] = len(pt) & 0xFF, len(pt) >> 8

    tr = FakeC64(echo, clock, 0.0, on_target=on_target)
    tr.mem[L["test_payload"]:L["test_payload"] + FORWARD_LEN] = b"HELLO WIREGUARD"
    patched = []
    for g in (live.__dict__, echo.__dict__):
        patched.append((g, "time", g.get("time")))
        g["time"] = clock
    # Seed the way main() does: --seed/TEST_SEED -> the module's seeding
    # hook when it has one (the fix: seed_payloads), else whatever it read
    # from TEST_SEED at import. main()'s own use of --seed is checked
    # separately, in a child process (5/handshake-main-logs-the-seed).
    if callable(getattr(live, "seed_payloads", None)):
        live.seed_payloads(seed)
    fn = live._run_stage3
    kw = {}
    params = inspect.signature(fn).parameters
    if "seed" in params:
        kw["seed"] = seed
    if "rng" in params:
        kw["rng"] = random.Random(seed)
    rc, exc = None, None
    with contact_guard() as contact, Capture() as out:
        try:
            rc = fn(tr, L, rt, Responder(), **kw)
        except Exception as e:                 # noqa: BLE001
            exc = e
    for g, name, v in patched:
        g[name] = v
    return SimpleNamespace(forward=got.forward, reverse=got.reverse, rc=rc,
                           exc=exc, text=out.text, contact=list(contact))


def case_payloads(res, seed):
    print("\n[5] seeded-random tunnel payloads")
    rng = random.Random(seed)
    s1 = rng.randrange(1, 2 ** 31)
    s2 = s1 + 1 + rng.randrange(1, 2 ** 20)
    a, a2, b = run_stage3(s1), run_stage3(s1), run_stage3(s2)
    for name, r in (("s1", a), ("s1-again", a2), ("s2", b)):
        if r.exc is not None or r.forward is None or r.reverse is None:
            res.check(False, f"5/stage3-runs-{name}",
                      f"exc={r.exc!r} forward={r.forward!r} reverse={r.reverse!r}")
            return
    print(f"      seed {s1}: forward={a.forward.hex()} reverse={a.reverse.hex()}")
    print(f"      seed {s2}: forward={b.forward.hex()} reverse={b.reverse.hex()}")
    res.check(a.forward[:4] != b.forward[:4],
              "5/forward-leading-bytes-differ-by-seed",
              f"seeds {s1} and {s2} both put {a.forward!r} on the wire C64->peer")
    res.check(a.reverse[:4] != b.reverse[:4],
              "5/reverse-leading-bytes-differ-by-seed",
              f"seeds {s1} and {s2} both put {a.reverse!r} on the wire peer->C64")
    res.check(a.forward == a2.forward and a.reverse == a2.reverse,
              "5/same-seed-reproduces-both-payloads",
              f"seed {s1} twice: {a.forward!r}/{a2.forward!r}, "
              f"{a.reverse!r}/{a2.reverse!r}")
    fwd_alpha = set(a.forward) | set(b.forward)
    rev_alpha = set(a.reverse) | set(b.reverse)
    res.check(not (fwd_alpha & rev_alpha), "5/forward-and-reverse-alphabets-disjoint",
              f"shared bytes {sorted(fwd_alpha & rev_alpha)}: an echo of the "
              f"C64's own datagram could satisfy the reverse check")
    res.check(len(a.reverse) > 9 and a.reverse[9] not in (1, 17),
              "5/reverse-plaintext-not-routed-as-ICMP-or-UDP",
              f"reverse[9]={a.reverse[9] if len(a.reverse) > 9 else None}: "
              f"1/17 would send it to the C64's IP parser, not display_payload")
    res.check(a.rc == 0, "5/stage3-passes-on-a-faithful-C64",
              f"rc={a.rc}")
    w = run_stage3(s1, wrong_forward=True)
    res.check(w.exc is None and w.rc not in (0, None),
              "5/stage3-fails-when-the-peer-decrypts-different-bytes",
              f"the responder decrypted {(w.forward or b'')[:1]!r}^1... instead "
              f"of what was written to test_payload, and stage 3 returned "
              f"rc={w.rc} exc={w.exc!r} — randomising a payload nobody "
              f"compares proves nothing")
    res.check(not (a.contact or b.contact or w.contact), "5/no-device-contact",
              f"{a.contact + b.contact + w.contact}")
    for tool in ("test_uci_handshake_live.py", "test_config_reload_live.py"):
        h = subprocess.run([sys.executable, str(TOOLS / tool), "--help"],
                           capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, U64_HOST="", PYTHONPATH=str(TOOLS)))
        res.check("--seed" in h.stdout, f"5/{tool}-accepts---seed",
                  f"--help does not list --seed (rc={h.returncode})")
    tag = random.Random(seed).randrange(10_000_000, 99_999_999)
    with tempfile.TemporaryDirectory(prefix="seedlog_") as td:
        # A TEST-NET-1 host (RFC 5737), never a device; the child's guard
        # refuses whatever the tool then tries against it.
        rc, out, events = run_without_host("tools/test_uci_handshake_live.py",
                                           Path(td), extra=["--seed", str(tag),
                                                            "--host", "192.0.2.10"])
    # Not `str(tag) in out`: argparse's "unrecognized arguments: --seed N"
    # carries the number too, and passed that version on the unfixed tree.
    import re as _re
    logged = any(_re.search(rf"seed\D{{0,40}}\b{tag}\b", ln, _re.I)
                 and "unrecognized" not in ln for ln in out.splitlines())
    res.check(logged and any(e["kind"] == "guard-loaded" for e in events),
              "5/handshake-main-logs-the-seed",
              f"--seed {tag} not echoed by main() (rc={rc}): "
              f"{' | '.join(out.strip().splitlines()[-2:])[:200]}")


# =============================================================================
# 6: firmware table
# =============================================================================
CHUNKED_HASHES = {"a474a7ed", "4011c97c", "3a1ff9ff"}


def case_firmware(res):
    print("\n[6] u64_firmware: 3a1ff9ff dispatches $16")
    fw = _load(TOOLS / "u64_firmware.py", "u64_firmware_under_test")
    info = {"product": "Ultimate 64 Elite", "firmware_version": "3.15",
            "fpga_version": "125", "git_commit_hash": "3a1ff9ff"}
    v, text = fw.describe_build(info)
    res.check(v == "chunked", "6/3a1ff9ff-is-chunked", f"verdict {v!r}: {text}")
    v7, _ = fw.describe_build(dict(info, git_commit_hash="3a1ff9f"))
    res.check(v7 == "chunked", "6/3a1ff9ff-7-char-abbrev-is-chunked", f"{v7!r}")
    got = {k for k, (kind, _) in fw.KNOWN_BUILDS.items() if kind == "chunked"}
    res.check(got == CHUNKED_HASHES, "6/chunked-set-equality",
              f"table has {sorted(got)}; pinned {sorted(CHUNKED_HASHES)} — "
              f"missing {sorted(CHUNKED_HASHES - got)}, unexpected "
              f"{sorted(got - CHUNKED_HASHES)}")
    each = {h: fw.describe_build(dict(info, git_commit_hash=h))[0]
            for h in fw.KNOWN_BUILDS}
    res.check(all(each[h] == fw.KNOWN_BUILDS[h][0] for h in each),
              "6/every-recorded-hash-routes-to-its-own-kind",
              f"{each} (an ambiguous prefix would read as 'unknown')")


# =============================================================================
# 7: no hardcoded device address
# =============================================================================
LIVE_TOOLS = [
    "tools/test_uci_handshake_live.py",
    "tools/test_warp_live.py",
    "tools/test_uci_udp_echo_live.py",
    "tools/test_ip65_rrnet_hw.py",
    "tools/test_config_reload_live.py",
    "tools/test_uci_udp_size_probe.py",
    "tools/uci/udp_probe_harness.py",
    "tools/test_wire_encryption_live.py",
    "tools/wg_chat.py",
    "tools/wg_demo.py",
]


def run_without_host(tool: str, tmpdir: Path, extra=()):
    guard_dir = tmpdir / "guard"
    guard_dir.mkdir(exist_ok=True)
    (guard_dir / "sitecustomize.py").write_text(SITECUSTOMIZE)
    log_path = tmpdir / (Path(tool).stem + ".jsonl")
    log_path.write_text("")
    profile = tmpdir / "wgcf-profile.conf"
    if not profile.exists():
        import base64
        profile.write_text("[Interface]\nPrivateKey = "
                           + base64.b64encode(os.urandom(32)).decode()
                           + "\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = "
                           + base64.b64encode(os.urandom(32)).decode() + "\n")
    env = {k: v for k, v in os.environ.items() if k != "U64_HOST"}
    env.update(PYTHONPATH=os.pathsep.join(
        [str(guard_dir), str(TOOLS)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])),
        LIVE_GUARD_LOG=str(log_path), U64_ALLOW_MUTATE="1", C64_SKIP_BUILD="1",
        WARP_PROFILE=str(profile), TEST_SEED="1")
    try:
        p = subprocess.run([sys.executable, str(PROJECT_ROOT / tool), *extra],
                           capture_output=True, text=True, timeout=180,
                           cwd=str(tmpdir), env=env)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out = "TIMEOUT", (e.stdout or "") + (e.stderr or "")
        out = out if isinstance(out, str) else out.decode(errors="replace")
    events = [json.loads(x) for x in log_path.read_text().splitlines() if x.strip()]
    return rc, out, events


def case_no_default_host(res):
    print("\n[7] live tools refuse to run without U64_HOST / --host")
    with tempfile.TemporaryDirectory(prefix="nohost_") as td:
        for tool in LIVE_TOOLS:
            rc, out, events = run_without_host(tool, Path(td))
            loaded = any(e["kind"] == "guard-loaded" for e in events)
            contact = [e for e in events if e["kind"] not in ("guard-loaded", "guard-note")]
            name = Path(tool).name
            if not loaded:
                res.check(False, f"7/{name}", "the network guard did not load in "
                          "the child — 'no contact' would be unmeasured")
                continue
            tail = " | ".join(out.strip().splitlines()[-3:])
            ok = rc not in (0, "TIMEOUT") and "U64_HOST" in out and not contact
            res.check(ok, f"7/{name}",
                      f"rc={rc}, names U64_HOST: {'U64_HOST' in out}, contact "
                      f"attempts: {[(e['kind'], e['what']) for e in contact][:3]} "
                      f"— last output: {tail[:300]}")


# =============================================================================
# 8: test_ip65_rrnet_hw.py probes the device only UNDER the lock
# =============================================================================
class _StopRun(Exception):
    pass


def case_rrnet_probe_under_lock(res):
    print("\n[8] rrnet_hw: probe_u64 runs inside the DeviceLock")
    mod = _load(TOOLS / "test_ip65_rrnet_hw.py", "rrnet_hw_for_lock_order")
    order: list[str] = []
    held = {"n": 0}

    class FakeLock:
        def __init__(self, host, *a, **k):
            order.append(f"lock-construct {host}")

        def acquire_or_raise(self, *a, **k):
            held["n"] += 1
            order.append("acquire")
            return True

        def acquire(self, *a, **k):
            return self.acquire_or_raise()

        def release(self):
            held["n"] -= 1
            order.append("release")

    def fake_probe(host, *a, **k):
        order.append("probe-held" if held["n"] > 0 else "probe-UNLOCKED")
        return SimpleNamespace(reachable=True, error=None, latency_ms=1.0,
                               write_ok=True)

    def fake_client(*a, **k):
        order.append("client" if held["n"] > 0 else "client-UNLOCKED")
        raise _StopRun("fake device: stop here")

    class FakeCap:
        mode, note = "off", "fake"

        def __init__(self, *a, **k):
            pass

        def start(self):
            return True

        def stop(self):
            return None

    class HwProxy:
        def __init__(self, real):
            self._real = real

        def provenance(self, *a, **k):
            return {}

        def format_provenance(self, *a, **k):
            return []

        def __getattr__(self, n):
            return getattr(self._real, n)

    patches = dict(
        selftest_library=lambda *a, **k: [], selftest_wire_gate=lambda *a, **k: [],
        selftest_rig_probe=lambda *a, **k: [], rig_problems=lambda *a, **k: [],
        iface_state=lambda *a, **k: {}, assert_ip65_build=lambda *a, **k: None,
        fingerprint=lambda *a, **k: {"sha256": "0" * 64},
        load_labels=lambda *a, **k: AutoLabels(), Capture=FakeCap,
        probe_u64=fake_probe, DeviceLock=FakeLock,
        Ultimate64Client=fake_client, hw=HwProxy(mod.hw), time=FakeTime())
    missing = [k for k in patches if not hasattr(mod, k)]
    for k, v in patches.items():
        setattr(mod, k, v)
    exc = rc = None
    with contact_guard() as contact, Capture():
        try:
            rc = mod.main(["--host", "192.0.2.10", "--skip-build",
                           "--capture", "off", "--seed", "1"])
        except _StopRun:
            pass
        except BaseException as e:            # noqa: BLE001
            exc = e
    probes = [o for o in order if o.startswith("probe")]
    res.check(not missing and exc is None and bool(probes),
              "8/rrnet-main-reached-the-device-stage",
              f"missing patch points {missing}; exc={exc!r}; rc={rc}; order={order}")
    res.check(bool(probes) and all(o == "probe-held" for o in probes),
              "8/probe_u64-only-while-the-lock-is-held",
              f"call order {order}: a REST/ping probe of the shared device "
              f"before acquire races the lane that holds it")
    res.check("release" in order and held["n"] == 0, "8/lock-released",
              f"order={order}")
    res.check(not contact, "8/no-device-contact", f"{contact}")


# =============================================================================
def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--only", default=None)
    a = p.parse_args(argv)
    seed = a.seed if a.seed is not None else int(
        os.environ.get("TEST_SEED") or random.randrange(2 ** 31))
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    res = Result()
    cases = [("2", lambda: case_size_probe(res, seed)),
             ("4", lambda: case_poll_budget(res)),
             ("5", lambda: case_payloads(res, seed)),
             ("6", lambda: case_firmware(res)),
             ("7", lambda: case_no_default_host(res)),
             ("8", lambda: case_rrnet_probe_under_lock(res))]
    for key, fn in cases:
        if a.only and a.only not in (key, "3" if key == "2" else key):
            continue
        fn()
    if len(set(res.names)) != len(res.names):
        print("FATAL: duplicate check names")
        return 2
    print(f"\nResults: {res.passed} passed, {res.failed} failed — "
          f"{res.passed + res.failed} checks")
    if res.failures:
        print("FAILED: " + ", ".join(res.failures))
    return 0 if res.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
