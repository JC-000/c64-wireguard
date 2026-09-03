#!/usr/bin/env python3
"""test_live_tool_seams.py — the live tools' shared seam still exists.

The hardware tools (test_config_reload_live, test_wire_encryption_live,
wg_chat, wg_demo) are NOT in the regression gate: they need a real U64 and a
patient responder, so nothing runs them automatically. That is fine for what
they assert, but it leaves a gap — they all reach into
test_uci_handshake_live through a shared seam, and if that seam is renamed or
its contract changes, every one of them breaks and the gate stays green. The
break would surface the next time someone picks up the device, which may be
months later and will not look like a refactor.

This suite closes that gap WITHOUT hardware. It only imports and inspects,
so it runs in milliseconds anywhere:

    post_session_hook          the takeover point itself
    wants_trampoline           the opt-out from the handback
    main(argv)                 callable without mutating the sys.argv global
    _hand_back_to_c64          still referenced by the conditional

It deliberately does NOT test what the hooks do — that needs the device.
It tests that the wiring they hang from is still there.
"""

from __future__ import annotations

import ast
import inspect
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

passed = failed = 0

def _handback_is_guarded(live) -> bool:
    """True iff every _hand_back_to_c64 call in main() is under a
    wants_trampoline `if`.

    Structural, not textual: a substring check passes vacuously on a log
    message that merely mentions the name.
    """
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(live.main)))
    except (OSError, SyntaxError):
        return False

    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "id", getattr(n.func, "attr", None))
             == "_hand_back_to_c64"]
    if not calls:
        return False                      # it vanished — also a seam break

    for call in calls:
        node, guarded = call, False
        while node in parents:
            parent = parents[node]
            if isinstance(parent, ast.If) and "wants_trampoline" in ast.dump(
                    parent.test):
                guarded = True
                break
            node = parent
        if not guarded:
            return False
    return True




def _restore_in_finally_ast(tree: ast.AST,
                            restore_call: str = "set_turbo_mhz") -> bool:
    """True iff some ast.Try node's `finalbody` (NOT its `body` or
    `handlers`) contains a call to *restore_call*.

    Structural, not textual: walking only `finalbody` means a restore call
    left in the try body — with an unrelated `finally:` elsewhere in the
    same function, e.g. one that only releases a lock — is correctly NOT
    flagged as restored-in-finally. A keyword/substring search for
    "finally" and the call name anywhere in the source would pass
    vacuously on that exact shape (which is what this file looked like
    before the fix this check exists to guard).
    """
    for t in ast.walk(tree):
        if not isinstance(t, ast.Try) or not t.finalbody:
            continue
        for stmt in t.finalbody:
            for sub in ast.walk(stmt):
                if (isinstance(sub, ast.Call)
                        and getattr(sub.func, "id",
                                   getattr(sub.func, "attr", None))
                        == restore_call):
                    return True
    return False


def _restore_in_finally(mod, fn_name: str = "main",
                        restore_call: str = "set_turbo_mhz") -> bool:
    """`_restore_in_finally_ast`, sourced from a real module's function."""
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(mod, fn_name))))
    except (OSError, SyntaxError, AttributeError, TypeError):
        return False
    return _restore_in_finally_ast(tree, restore_call)


def check(label: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")


def main() -> int:
    print("=== the seam in test_uci_handshake_live ===")
    try:
        import test_uci_handshake_live as live
    except Exception as exc:                                  # noqa: BLE001
        print(f"  FAIL  test_uci_handshake_live does not import: {exc!r}")
        return 1

    check("post_session_hook exists and defaults to None",
          getattr(live, "post_session_hook", "missing") is None,
          f"got {getattr(live, 'post_session_hook', 'missing')!r}")

    check("wants_trampoline exists and is callable",
          callable(getattr(live, "wants_trampoline", None)))

    if callable(getattr(live, "wants_trampoline", None)):
        def _sample():
            return 0
        marked = live.wants_trampoline(_sample)
        check("wants_trampoline marks the function it decorates",
              getattr(marked, "wants_trampoline", False) is True)
        check("wants_trampoline returns the same function (not a wrapper)",
              marked is _sample,
              "a wrapper would break hooks compared by identity")

    check("_hand_back_to_c64 still exists",
          callable(getattr(live, "_hand_back_to_c64", None)),
          "the conditional handback in main() calls it by this name")

    # main(argv) — the contract that lets consumers stop writing sys.argv.
    try:
        sig = inspect.signature(live.main)
        has_argv = "argv" in sig.parameters
        defaulted = has_argv and sig.parameters["argv"].default is None
    except (TypeError, ValueError):
        has_argv = defaulted = False
    check("main() accepts an argv parameter", has_argv,
          "without it, consumers must mutate the sys.argv global")
    check("main()'s argv defaults to None (argparse reads sys.argv)",
          defaulted)

    # Guard the conditional itself, structurally.
    #
    # The failure being guarded against is someone restoring the
    # unconditional handback during a refactor, which would silently strand
    # every @wants_trampoline hook. A substring search for "wants_trampoline"
    # in main()'s source does NOT catch that — it matches the word in a
    # neighbouring log message and passes vacuously. (Measured: that version
    # of this check stayed green against exactly the mutant it existed to
    # catch.) So walk the AST instead and require every call to
    # _hand_back_to_c64 to sit inside an `if` that tests wants_trampoline.
    check("every _hand_back_to_c64 call in main() is guarded by "
          "wants_trampoline", _handback_is_guarded(live),
          "an unconditional _hand_back_to_c64 strands trampoline hooks")

    print("\n=== consumers still match the seam ===")

    # config-reload probe: assert the MARK, since losing it is exactly the
    # regression that would make PR #85's tool hang instead of fail loudly.
    try:
        import test_config_reload_live as cfg
        probe = cfg.build_probe(SimpleNamespace(host="0.0.0.0", turbo=48,
                                                password=None, soak=0,
                                                soak_close=False))
        check("test_config_reload_live's probe declares wants_trampoline",
              getattr(probe, "wants_trampoline", False) is True,
              "without the mark the handshake tool hands the machine back "
              "and every JSR the probe makes afterwards is lost")
    except Exception as exc:                                  # noqa: BLE001
        check("test_config_reload_live imports and builds its probe", False,
              repr(exc))

    # The presentation hooks must NOT be marked: they run after the handback
    # and rely on the C64 driving itself.
    for mod_name, builder, args in (
        ("test_wire_encryption_live", "build_probe", ()),
        ("wg_chat", "build_chat_loop", ()),
        ("wg_demo", "build_demo_loop", ()),
    ):
        try:
            mod = __import__(mod_name)
            fn = getattr(mod, builder, None)
            if fn is None:
                check(f"{mod_name}.{builder} exists", False,
                      "the hook builder was renamed")
                continue
            hook = fn(*args)
            check(f"{mod_name}'s hook does NOT ask for the trampoline",
                  getattr(hook, "wants_trampoline", False) is False,
                  "a presentation loop needs the C64 running its own loop")
        except Exception as exc:                              # noqa: BLE001
            check(f"{mod_name} imports and builds its hook", False, repr(exc))

    print("\n=== size tables (#70) ===")
    # A size above the build's MSG_TEXT_MAX must be SKIPPED, never failed:
    # the default build (832) is not making the 1472-byte claim, and its
    # 9/9 must not become 9/12 because the flag build's sizes are listed.
    try:
        import test_wire_encryption_live as wire
        run, skipped = wire.partition_outbound_sizes(832)
        check("default build (MSG_TEXT_MAX=832) skips the sizes above it",
              skipped == (833, 1392, 1412) and 833 not in run,
              f"run={run} skipped={skipped}")
        check("default build still runs the sizes at and below 832",
              run == (828, 829, 831, 832), f"run={run}")
        run, skipped = wire.partition_outbound_sizes(1412)
        check("chunked build (MSG_TEXT_MAX=1412) skips nothing",
              skipped == () and run == wire.OUTBOUND_TEXT_SIZES,
              f"run={run} skipped={skipped}")
    except Exception as exc:                                  # noqa: BLE001
        check("test_wire_encryption_live exposes partition_outbound_sizes",
              False, repr(exc))

    print("\n=== payload/message randomisation (standing directive, 2026-09-03) ===")
    # Red/green tests that send data across the wire must randomise their
    # initial words/payload per run, seeded and reproducible via
    # --seed/TEST_SEED, with disjoint alphabets per direction so an echo
    # cannot satisfy a reply check. This is a static check of the
    # generators themselves — same seed -> identical, two seeds -> almost
    # certainly different, and the two alphabets never overlap — with no
    # hardware involved.
    try:
        import test_wire_encryption_live as wire
        w1 = wire.random_words(12345, wire.REQUEST_ALPHABET)
        w2 = wire.random_words(12345, wire.REQUEST_ALPHABET)
        w3 = wire.random_words(67890, wire.REQUEST_ALPHABET)
        check("wire tool: same seed -> identical leading words",
              w1 == w2, f"{w1!r} != {w2!r}")
        check("wire tool: two different seeds -> different leading words",
              w1 != w3, f"both produced {w1!r}")
        check("wire tool: request/reply alphabets are disjoint",
              not (set(wire.REQUEST_ALPHABET) & set(wire.REPLY_ALPHABET)),
              f"REQUEST={wire.REQUEST_ALPHABET!r} REPLY={wire.REPLY_ALPHABET!r}")
        t1 = wire._sized_text("OUT", 888, 12345, wire.REQUEST_ALPHABET)
        t2 = wire._sized_text("OUT", 888, 12345, wire.REQUEST_ALPHABET)
        t3 = wire._sized_text("OUT", 888, 67890, wire.REQUEST_ALPHABET)
        check("wire tool: same seed -> identical sized-probe text",
              t1 == t2, f"{t1!r} != {t2!r}")
        check("wire tool: two different seeds -> different sized-probe text",
              t1 != t3, f"both produced {t1!r}")
    except Exception as exc:                                  # noqa: BLE001
        check("test_wire_encryption_live exposes the randomisation API",
              False, repr(exc))

    try:
        import test_uci_udp_echo_live as echo
        p1 = echo._payload(64, 12345)
        p2 = echo._payload(64, 12345)
        p3 = echo._payload(64, 67890)
        check("echo tool: same seed -> identical payload bytes",
              p1 == p2, f"{p1.hex()} != {p2.hex()}")
        check("echo tool: two different seeds -> different payload bytes",
              p1 != p3, f"both produced {p1.hex()}")
        r1 = echo._reply(64, 12345)
        check("echo tool: request/reply byte alphabets are disjoint",
              not (set(echo.REQUEST_BYTE_ALPHABET)
                   & set(echo.REPLY_BYTE_ALPHABET)),
              f"REQUEST={echo.REQUEST_BYTE_ALPHABET!r} "
              f"REPLY={echo.REPLY_BYTE_ALPHABET!r}")
        check("echo tool: a reply never satisfies the request alphabet "
              "(no byte overlap in these samples)",
              not (set(p1) & set(r1)) if p1 and r1 else True,
              f"payload={p1.hex()} reply={r1.hex()}")
    except Exception as exc:                                  # noqa: BLE001
        check("test_uci_udp_echo_live exposes the randomisation API",
              False, repr(exc))

    print("\n=== warp rekey helper + restore-in-finally (#87) ===")
    # hs_timestamp_gt: a 96-bit big-endian compare (8-byte seconds, then
    # 4-byte nanoseconds). These three cases each rule out a specific
    # plausible bug: a non-strict >= (equal case), comparing nanoseconds
    # instead of/before seconds (lower-seconds/higher-nanos case), or only
    # comparing seconds and ignoring the tie-break (covered implicitly by
    # requiring exact 96-bit semantics, not just a seconds-only compare).
    try:
        import test_warp_live as warp
        zero12 = bytes(12)
        eq_a = (5).to_bytes(8, "big") + (100).to_bytes(4, "big")
        eq_b = (5).to_bytes(8, "big") + (100).to_bytes(4, "big")
        check("hs_timestamp_gt: identical stamps -> False (strict, not >=)",
              warp.hs_timestamp_gt(eq_a, eq_b) is False)

        higher_sec_lower_nanos_new = (6).to_bytes(8, "big") + (0).to_bytes(4, "big")
        higher_sec_lower_nanos_old = (5).to_bytes(8, "big") + (999).to_bytes(4, "big")
        check("hs_timestamp_gt: higher seconds / lower nanos -> True "
              "(seconds dominate)",
              warp.hs_timestamp_gt(higher_sec_lower_nanos_new,
                                   higher_sec_lower_nanos_old) is True)

        lower_sec_higher_nanos_new = (5).to_bytes(8, "big") + (999).to_bytes(4, "big")
        lower_sec_higher_nanos_old = (6).to_bytes(8, "big") + (0).to_bytes(4, "big")
        check("hs_timestamp_gt: lower seconds / higher nanos -> False "
              "(nanos never outrank seconds)",
              warp.hs_timestamp_gt(lower_sec_higher_nanos_new,
                                   lower_sec_higher_nanos_old) is False)

        check("hs_timestamp_gt: sanity zero-vs-zero -> False",
              warp.hs_timestamp_gt(zero12, zero12) is False)
    except Exception as exc:                                      # noqa: BLE001
        check("test_warp_live exposes hs_timestamp_gt", False, repr(exc))

    # Stage D restore (turbo 1MHz / REU off) must sit inside main()'s
    # `finally`, so a raise anywhere above it — notably the rekey stage's
    # asserts, expected to raise on unfixed firmware — still restores the
    # device (today's failure mode before this fix: only lock.release()
    # was in finally, so the device was left at 48 MHz / turbo stuck).
    try:
        import test_warp_live as warp
        check("test_warp_live.main(): Stage D restore call is inside "
              "the outer try/finally's `finally:` block",
              _restore_in_finally(warp),
              "set_turbo_mhz(client, 1) must be reachable even when an "
              "earlier stage (e.g. rekey) raises")

        # Alarm-proof: parse two synthetic ASTs directly (bypassing
        # inspect.getsource, which needs a real backing file) with
        # _restore_in_finally_ast — the same function the real check
        # above calls. The "bad" shape is exactly the REGRESSION this
        # check exists to catch: set_turbo_mhz called in the try body,
        # with an unrelated finally (just lock.release(), as it was in
        # this file before this change) alongside it. If the detector
        # can't tell that apart from the real fix, it is vacuous.
        bad_src = (
            "def main():\n"
            "    try:\n"
            "        set_turbo_mhz(client, 1)\n"
            "    finally:\n"
            "        lock.release()\n"
        )
        check("alarm-proof: restore-in-try-body (not finally) is "
              "correctly flagged as NOT restored-in-finally",
              _restore_in_finally_ast(ast.parse(bad_src)) is False,
              "the detector must distinguish this from the real fix, or "
              "it would pass vacuously on the pre-fix code")

        good_src = (
            "def main():\n"
            "    try:\n"
            "        pass\n"
            "    finally:\n"
            "        set_turbo_mhz(client, 1)\n"
            "        lock.release()\n"
        )
        check("alarm-proof: restore-in-finally IS detected",
              _restore_in_finally_ast(ast.parse(good_src)) is True)
    except Exception as exc:                                      # noqa: BLE001
        check("test_warp_live.main() restore-in-finally check runs", False,
              repr(exc))

    print("\n=== test_warp_live backend seams (#70, ip65 warp) ===")
    # Structural checks of the pieces the ip65 run hangs from, with labels
    # shaped like the three REAL builds (addresses from the 2026-09-03
    # isolated builds on feat/ip65-mtu1440-warp): default uci, chunked
    # uci, and ip65 + WG_MTU1440. ip_pkt_len - ip_packet_buf is how the
    # tool reads WG_MTU, so the MTU numbers here are the real ones.
    try:
        import test_warp_live as warp
        uci_default = _warp_labels("uci", ip_pkt_len=0x9B8F)
        uci_chunked = _warp_labels("uci", ip_pkt_len=0x9DD3, chunked=True)
        ip65_1440 = _warp_labels("ip65", ip_pkt_len=0x9DD3)
        check("detect_backend: default uci build -> 'uci'",
              warp.detect_backend(uci_default) == "uci")
        check("detect_backend: chunked uci build -> 'uci'",
              warp.detect_backend(uci_chunked) == "uci")
        check("detect_backend: ip65 build -> 'ip65'",
              warp.detect_backend(ip65_1440) == "ip65")
        # Coincidence guard: a classifier that keys on ip65_blob_start
        # ALONE still passes the three checks above; a mixed map (blob plus
        # the uci error byte) and an empty map must both be refused.
        mixed = dict(ip65_1440, net_last_error=0x7C32)
        for name, lab in (("blob + net_last_error", mixed),
                          ("no markers at all", {})):
            try:
                got = warp.detect_backend(lab)
                raised = False
            except ValueError:
                raised, got = True, None
            check(f"detect_backend: {name} raises ValueError",
                  raised, f"returned {got!r}")
        for kind, lab, want in (("default uci", uci_default, 860),
                                ("chunked uci", uci_chunked, 1440),
                                ("ip65 WG_MTU1440", ip65_1440, 1440)):
            fp = warp._fingerprint("seam", b"\x00", lab,
                                   warp.detect_backend(lab))
            check(f"_fingerprint: {kind} reports WG_MTU {want}",
                  fp["wg_mtu"] == want, f"got {fp['wg_mtu']}")
        check("_fingerprint: uci_send_part flag follows the label",
              (warp._fingerprint("s", b"", uci_chunked, "uci")["uci_send_part"]
               is True)
              and (warp._fingerprint("s", b"", uci_default, "uci")
                   ["uci_send_part"] is False))

        # load_labels_for_backend on a real-format labels file: a uci
        # labels.txt requested as ip65 raises BackendMismatch naming both.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            lf = Path(td) / "labels.txt"
            lf.write_text("".join(f"al C:{v:04X} .{k}\n"
                                  for k, v in uci_default.items()))
            try:
                warp.load_labels_for_backend(lf, "ip65")
                mism = None
            except warp.BackendMismatch as exc:
                mism = str(exc)
            check("load_labels_for_backend: uci labels.txt as --backend "
                  "ip65 raises BackendMismatch naming both",
                  mism is not None and "ip65" in mism and "uci" in mism,
                  repr(mism))
            check("load_labels_for_backend: matching backend returns labels",
                  warp.load_labels_for_backend(lf, "uci")["ip_packet_buf"]
                  == 0x9833)

        # _dump_failure gating: on ip65 labels the UCI-only net_last_error
        # must never be read (it is not even in the map).
        class _Tr:
            def __init__(self):
                self.reads = []

            def read_memory(self, addr, n):
                self.reads.append(addr)
                return bytes(n)
        saved_dump = warp.dump_screen
        warp.dump_screen = lambda *a, **k: None
        try:
            tr = _Tr()
            warp._dump_failure(tr, ip65_1440, "seam")
            check("_dump_failure: no reads at all on ip65 labels without "
                  "hs_* labels (net_last_error never touched)",
                  tr.reads == [], f"reads={tr.reads}")
            tr = _Tr()
            warp._dump_failure(tr, uci_default, "seam")
            check("_dump_failure: uci labels DO read net_last_error",
                  tr.reads == [uci_default["net_last_error"]],
                  f"reads={tr.reads}")
        finally:
            warp.dump_screen = saved_dump

        # _net_init_ip65 ordering: 1 MHz before 'I', turbo only after
        # net_initialized reads 1; a timeout returns False and never
        # raises the clock.
        calls = []
        mem = {ip65_1440["net_initialized"]: 0}

        class _TrNet(_Tr):
            def read_memory(self, addr, n):
                calls.append(("read", addr))
                if addr == ip65_1440["net_initialized"]:
                    mem[addr] = 1 if len(calls) > 3 else mem[addr]
                    return bytes([mem[addr]])
                return bytes(n)
        saved = (warp.set_turbo_mhz, warp.get_turbo_mhz, warp.ki.press_key,
                 warp.time.sleep, warp.dump_screen, warp.NET_INIT_BUDGET_S)
        try:
            warp.set_turbo_mhz = lambda c, m: calls.append(("turbo", m))
            warp.get_turbo_mhz = lambda c: calls[-1][1] if calls else 0
            warp.ki.press_key = lambda tr, ch, timeout=0: (
                calls.append(("key", ch)) or True)
            warp.time.sleep = lambda s: None
            warp.dump_screen = lambda *a, **k: None
            res = {}
            ok = warp._net_init_ip65(_TrNet(), None, ip65_1440, 48, res)
            seq = [c for c in calls if c[0] != "read"]
            reads_before_turbo48 = any(
                c == ("read", ip65_1440["net_initialized"])
                for c in calls[:calls.index(("turbo", 48))]) \
                if ("turbo", 48) in calls else False
            check("_net_init_ip65: 1 MHz -> I -> net_initialized -> turbo",
                  ok is True and seq == [("turbo", 1), ("key", "I"),
                                         ("turbo", 48)]
                  and reads_before_turbo48 and res.get("net_initialized"),
                  f"ok={ok} seq={seq} res={res}")
            # timeout path
            calls.clear()
            mem[ip65_1440["net_initialized"]] = 0
            warp.NET_INIT_BUDGET_S = 0.0
            res = {}
            ok = warp._net_init_ip65(_Tr(), None, ip65_1440, 48, res)
            check("_net_init_ip65: net_initialized never 1 -> False, error "
                  "set, turbo NOT raised",
                  ok is False and "net_initialized" in res.get("error", "")
                  and ("turbo", 48) not in calls
                  and calls[:2] == [("turbo", 1), ("key", "I")],
                  f"ok={ok} calls={calls} res={res}")
        finally:
            (warp.set_turbo_mhz, warp.get_turbo_mhz, warp.ki.press_key,
             warp.time.sleep, warp.dump_screen, warp.NET_INIT_BUDGET_S) = saved

        # Exit code: a stage that recorded an error must fail the process.
        check("stage_errors: Stage A error is reported",
              warp.stage_errors({"seed": 1, "stage_ab": {"error": "boom"},
                                 "stage_c": {"active": True}})
              == ["stage_ab: boom"])
        check("stage_errors: clean results report nothing",
              warp.stage_errors({"seed": 1, "stage_ab": {"active": True}})
              == [])
    except Exception as exc:                                      # noqa: BLE001
        check("test_warp_live backend seams run", False, repr(exc))
    print("\n=== backend detection in test_warp_live (#70, ip65 warp) ===")
    # The tool now runs against either backend, and the two builds differ
    # in what they export: only ip65 links `ip65_blob_start`, only uci links
    # `net_last_error` (and `uci_send_part` under UCI_CHUNKED_WRITE). A tool
    # that assumed uci and read net_last_error on an ip65 PRG would raise a
    # KeyError AFTER run_prg — with the device already loaded and the lock
    # held. So the preflight must classify the labels.txt it was given and
    # refuse a mismatch with exit 2 BEFORE any device call. Two layers:
    #   (a) detect_backend(): a pure classifier on any labels mapping;
    #   (b) the CLI, as a subprocess, fed a labels.txt of the OTHER backend.
    # (b) discriminates carefully: argparse's own "unrecognized arguments"
    # ALSO exits 2, and so does the tool when WARP_PROFILE is unset, so exit
    # code alone is a false green on master. Refusal must name both the
    # requested and the detected backend, must not be an argparse usage
    # error, and must beat probe_u64 — with --host 127.0.0.1 a tool that
    # reaches the probe exits 1 instead.
    try:
        import test_warp_live as warp
        det = getattr(warp, "detect_backend", None)
        check("test_warp_live.detect_backend exists", callable(det),
              "the backend classifier the preflight hangs from is missing")
        if callable(det):
            check("detect_backend: ip65 labels -> 'ip65'",
                  det(_fake_labels("ip65")) == "ip65")
            check("detect_backend: uci labels -> 'uci'",
                  det(_fake_labels("uci")) == "uci")
            check("detect_backend: chunked uci labels (uci_send_part) -> 'uci'",
                  det(_fake_labels("uci", chunked=True)) == "uci")
            try:
                det(_fake_labels("neither"))
                ambiguous_raises = False
            except ValueError:
                ambiguous_raises = True
            check("detect_backend: labels with neither marker raise ValueError",
                  ambiguous_raises)
            try:
                det(_fake_labels("both"))
                both_raises = False
            except ValueError:
                both_raises = True
            check("detect_backend: labels carrying BOTH markers raise "
                  "ValueError (a mixed build is not a backend)", both_raises)
    except Exception as exc:                                      # noqa: BLE001
        check("test_warp_live imports", False, repr(exc))

    for requested, given in (("ip65", "uci"), ("uci", "ip65")):
        rc, out = _run_warp_tool_preflight(requested, given)
        argparse_err = ("unrecognized arguments" in out
                        or "error: the following arguments" in out
                        or "usage:" in out.lower())
        names_both = requested in out.lower() and given in out.lower()
        refused = rc == 2 and names_both and not argparse_err
        tail = "\n".join(out.strip().splitlines()[-4:])
        check(f"CLI: --backend {requested} on a {given} labels.txt refuses "
              f"with exit 2 before any device call",
              refused,
              f"exit {rc}; argparse_error={argparse_err}; "
              f"names_both={names_both}\n{tail}")

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1



# ---------------------------------------------------------------------------
# Labels shaped like the real builds, for the test_warp_live backend seams.
# Addresses are the measured ones (ip_packet_buf $9833 in every build;
# ip_pkt_len $9B8F at MTU 860, $9DD3 at MTU 1440).
# ---------------------------------------------------------------------------
def _warp_labels(kind: str, ip_pkt_len: int, chunked: bool = False) -> dict:
    L = {"boot_ready": 0x8E60, "wg_state": 0x8E61, "net_initialized": 0x908E,
         "ip_packet_buf": 0x9833, "ip_pkt_len": ip_pkt_len,
         "WG_MTU": ip_pkt_len - 0x9833}
    if kind == "ip65":
        L["ip65_blob_start"] = 0x2000
    else:
        L["net_last_error"] = 0x7C32
        if chunked:
            L["uci_send_part"] = 0x211C
    return L
# ---------------------------------------------------------------------------
# Synthetic inputs for the backend-detection checks. Fake labels are the
# right tool here: the classifier keys on three labels' PRESENCE, so a real
# build adds nothing but a make dependency (and the pool has only one
# backend's tree anyway).
# ---------------------------------------------------------------------------

_COMMON_FAKE_LABELS = (
    "boot_ready", "wg_state", "net_initialized", "hs_timestamp",
    "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub", "cfg_preshared_key",
    "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port", "tunnel_ip",
    "ping_target_ip", "tai64n_base_time", "ip_packet_buf", "ip_pkt_len",
    "msg_input_len", "tp_send_counter", "WG_MTU", "NET_UDP_SEND_MAX",
    "NET_UDP_RECV_MAX", "WG_DATA_OVERHEAD",
)


def _fake_labels(kind: str, chunked: bool = False) -> dict[str, int]:
    names = list(_COMMON_FAKE_LABELS)
    if kind in ("ip65", "both"):
        names += ["ip65_blob_start", "ip65_blob_end", "ip65_listening"]
    if kind in ("uci", "both"):
        names += ["net_last_error", "uci_socket_open", "uci_wait_idle"]
        if chunked:
            names.append("uci_send_part")
    return {n: 0x1000 + 16 * i for i, n in enumerate(names)}


def _write_fake_labels_file(path: Path, kind: str) -> None:
    path.write_text("".join(f"al C:{addr:04X} .{name}\n"
                            for name, addr in _fake_labels(kind).items()))


def _run_warp_tool_preflight(requested: str, given: str) -> tuple[int, str]:
    """Run tools/test_warp_live.py as a subprocess against a foreign labels
    file. Returns (exit code, combined output).

    WARP_PROFILE is a throwaway wgcf-style profile with a FRESH random
    X25519 key — the tool derives the public key via `wg pubkey` before it
    classifies the build, and an unset profile is its own exit-2 path.
    """
    import base64
    import os
    import subprocess
    import tempfile
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )
        priv = X25519PrivateKey.generate().private_bytes_raw()
    except Exception:                                             # noqa: BLE001
        priv = os.urandom(32)
    with tempfile.TemporaryDirectory(prefix="warp_seam_") as td:
        labels = Path(td) / f"labels-{given}.txt"
        _write_fake_labels_file(labels, given)
        profile = Path(td) / "profile.conf"
        profile.write_text(
            "[Interface]\n"
            f"PrivateKey = {base64.b64encode(priv).decode()}\n"
            "Address = 172.16.0.2/32\n"
            "[Peer]\n"
            "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n")
        env = dict(os.environ, WARP_PROFILE=str(profile))
        env.pop("U64_HOST", None)
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent /
                                 "test_warp_live.py"),
             "--backend", requested, "--labels", str(labels),
             "--host", "127.0.0.1"],
            capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


if __name__ == "__main__":
    sys.exit(main())
