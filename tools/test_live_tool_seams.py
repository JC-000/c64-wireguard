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
import math
import os
import random
import re
import struct
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent

passed = failed = 0
SEED = 0

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


# ---------------------------------------------------------------------------
# The --multipart padded-query builder (#70). Decoded from the WIRE, with a
# parser that shares no code with the builder — a builder checked against
# itself proves only that it is self-consistent.
# ---------------------------------------------------------------------------
EDNS_OPT_PADDING = 12       # RFC 7830
DNS_TYPE_OPT = 41           # RFC 6891
UCI_CHUNK_PART_MAX = 888    # 895-byte $16 command buffer - 7-byte header
WG_DATA_OVERHEAD = 32
IP_UDP_HDR = 28


def _decode_dns(wire: bytes) -> dict:
    """Decode a one-question, one-OPT-RR DNS query. Raises on anything it
    cannot account for, so trailing junk or a lying RDLEN is an error rather
    than a silent pass."""
    txn, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", wire[:12])
    i = 12
    labels = []
    while wire[i]:
        n = wire[i]
        labels.append(wire[i + 1:i + 1 + n].decode("ascii"))
        i += 1 + n
    i += 1
    qtype, qclass = struct.unpack(">HH", wire[i:i + 4])
    i += 4
    question = wire[12:i]
    if wire[i] != 0:
        raise ValueError(f"OPT RR name is not root: {wire[i]:#04x}")
    i += 1
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", wire[i:i + 10])
    i += 10
    rdata = wire[i:i + rdlen]
    if len(rdata) != rdlen:
        raise ValueError(f"RDLEN {rdlen} but only {len(rdata)} bytes left")
    i += rdlen
    if i != len(wire):
        raise ValueError(f"{len(wire) - i} unaccounted trailing byte(s)")
    opt_code = opt_len = None
    pad = b""
    if rdlen >= 4:
        opt_code, opt_len = struct.unpack(">HH", rdata[:4])
        pad = rdata[4:]
    return {"txn": txn, "flags": flags, "qd": qd, "an": an, "ns": ns,
            "ar": ar, "name": ".".join(labels), "qtype": qtype,
            "qclass": qclass, "question": question, "rtype": rtype,
            "rclass": rclass, "ttl": ttl, "rdlen": rdlen, "rdata": rdata,
            "opt_code": opt_code, "opt_len": opt_len, "pad": pad}


def _multipart_name_is_random(warp) -> bool:
    """True iff run_stage_c builds the --multipart query name with a random
    choice rather than a constant (standing directive: what crosses the wire
    is randomised per run). Structural: an AST walk of the `if multipart:`
    body, not a substring search that a comment could satisfy."""
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(warp.run_stage_c)))
    except (OSError, SyntaxError, AttributeError, TypeError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if getattr(node.test, "id", None) != "multipart":
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and getattr(sub.func, "attr", None)
                    in ("choice", "choices", "randint", "randrange")):
                return True
    return False


def check_multipart_builder(seed: int) -> None:
    """Section body: everything --multipart's padded query must satisfy."""
    print("\n=== --multipart padded-query builder (#70) ===")
    try:
        import test_warp_live as warp
    except Exception as exc:                                  # noqa: BLE001
        check("test_warp_live imports (for the --multipart builder)",
              False, repr(exc))
        return

    build_padded = getattr(warp, "build_padded_dns_query", None)
    parts_of = getattr(warp, "datagram_parts", None)
    ok_b, ok_p = callable(build_padded), callable(parts_of)
    check("test_warp_live.build_padded_dns_query exists", ok_b,
          f"got {build_padded!r} — --multipart cannot stage a query above "
          f"the {UCI_CHUNK_PART_MAX}-byte part cap without it")
    check("test_warp_live.datagram_parts exists", ok_p,
          f"got {parts_of!r} — nothing derives the datagram size or the "
          f"part count from the inner length")
    if not (ok_b and ok_p):
        return

    rng = random.Random(seed)

    # --- (a) exact length, well-formed OPT RR, question round-trips --------
    # Pinned boundaries plus random lengths: the pins are where the arithmetic
    # is most likely wrong, the random ones stop the pins being special-cased.
    lengths = [70, 100, 828, 829, 888, 889, 1412]
    lengths += sorted(rng.randrange(70, 1413) for _ in range(6))
    for want in lengths:
        tok = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz")
                      for _ in range(rng.randrange(3, 12)))
        name = f"{tok}.cloudflare.com"
        txn = rng.randrange(0x10000)
        bufsize = rng.choice((512, 1232, 1400))
        question, wire = build_padded(name, warp.DNS_QTYPE_TXT, txn, want,
                                      bufsize=bufsize)
        exact = len(wire) == want
        check(f"padded query of {want} B is EXACTLY {want} B", exact,
              f"got {len(wire)} (name={name!r} bufsize={bufsize})")
        if not exact:
            continue
        try:
            d = _decode_dns(wire)
        except Exception as exc:                              # noqa: BLE001
            check(f"{want} B: the padded query decodes as DNS", False,
                  repr(exc))
            continue
        check(f"{want} B: header is 1 question, 0 answers, 1 additional, "
              f"txn {txn}",
              (d["qd"], d["an"], d["ns"], d["ar"], d["txn"])
              == (1, 0, 0, 1, txn),
              f"qd/an/ns/ar/txn = {d['qd']}/{d['an']}/{d['ns']}/{d['ar']}/"
              f"{d['txn']}")
        check(f"{want} B: the question section round-trips "
              f"({name} TXT IN)",
              d["name"] == name and d["qtype"] == warp.DNS_QTYPE_TXT
              and d["qclass"] == 1 and d["question"] == question,
              f"decoded {d['name']!r} type {d['qtype']} class {d['qclass']}; "
              f"returned question {'matches' if d['question'] == question else 'DIFFERS'}")
        check(f"{want} B: the additional RR is an OPT RR (type 41, class = "
              f"bufsize {bufsize}, ttl 0)",
              (d["rtype"], d["rclass"], d["ttl"]) == (DNS_TYPE_OPT, bufsize, 0),
              f"type={d['rtype']} class={d['rclass']} ttl={d['ttl']}")
        check(f"{want} B: RDATA is one EDNS0 option, code "
              f"{EDNS_OPT_PADDING} (RFC 7830), length self-consistent",
              d["opt_code"] == EDNS_OPT_PADDING
              and d["opt_len"] == len(d["pad"])
              and d["rdlen"] == 4 + len(d["pad"]),
              f"code={d['opt_code']} optlen={d['opt_len']} "
              f"rdlen={d['rdlen']} padbytes={len(d['pad'])}")
        check(f"{want} B: every padding octet is zero, as RFC 7830 requires "
              f"(so the per-run randomness must live in the QNAME and txn id)",
              d["pad"] == bytes(len(d["pad"])),
              f"{sum(1 for b in d['pad'] if b)} non-zero padding octet(s)")
        # The padding is additive: header + question are untouched by it.
        _, plain = warp.build_dns_query(name, warp.DNS_QTYPE_TXT, txn,
                                        bufsize=bufsize)
        check(f"{want} B: header and question are byte-identical to the "
              f"unpadded query",
              wire[:12 + len(question)] == plain[:12 + len(question)])

    # --- refusal, not a quietly-shorter packet ----------------------------
    short = 30
    try:
        _, w = build_padded("a.cloudflare.com", warp.DNS_QTYPE_TXT, 1, short)
        raised = f"returned {len(w)} bytes"
    except ValueError:
        raised = None
    except Exception as exc:                                  # noqa: BLE001
        raised = repr(exc)
    check(f"a total_len of {short} B (below the unpadded query) raises "
          f"ValueError instead of emitting a shorter packet",
          raised is None, raised or "")

    # --- determinism / randomisation --------------------------------------
    a = build_padded("x.cloudflare.com", warp.DNS_QTYPE_TXT, 0x1234, 900)[1]
    b = build_padded("x.cloudflare.com", warp.DNS_QTYPE_TXT, 0x1234, 900)[1]
    c = build_padded("x.cloudflare.com", warp.DNS_QTYPE_TXT, 0x4321, 900)[1]
    e = build_padded("y.cloudflare.com", warp.DNS_QTYPE_TXT, 0x1234, 900)[1]
    check("same name+txn -> identical wire bytes (reproducible from a seed)",
          a == b)
    check("a different transaction id changes the wire", a != c)
    check("a different QNAME label changes the wire", a != e)
    check("run_stage_c randomises the --multipart QNAME rather than using a "
          "constant name",
          _multipart_name_is_random(warp),
          "no random.choice/randint call inside run_stage_c's `if multipart:` "
          "branch — a fixed name is cacheable and gameable")

    # --- (c) datagram_parts: the arithmetic the run logs -------------------
    for inner, outer, want_parts in ((0, 60, 1), (828, 888, 1), (829, 889, 2),
                                     (1412, 1472, 2)):
        got = parts_of(inner)
        check(f"datagram_parts({inner}) == ({outer}, {want_parts})",
              got == (outer, want_parts), f"got {got}")
    bad = [n for n in range(0, 1500)
           if parts_of(n) != (n + IP_UDP_HDR + WG_DATA_OVERHEAD,
                              math.ceil((n + IP_UDP_HDR + WG_DATA_OVERHEAD)
                                        / UCI_CHUNK_PART_MAX))]
    check(f"datagram_parts(n) == (n+{IP_UDP_HDR + WG_DATA_OVERHEAD}, "
          f"ceil(outer/{UCI_CHUNK_PART_MAX})) for every n in 0..1499",
          not bad, f"{len(bad)} disagreement(s), first at n={bad[0] if bad else None}")
    thresh = next(n for n in range(0, 1500) if parts_of(n)[1] >= 2)
    check(f"the split threshold is inner n={829}: the cap bites on the OUTER "
          f"datagram, so it is NOT n=888/889",
          thresh == 829, f"first multi-part inner length is {thresh}")
    check("parts never decrease as the inner length grows",
          all(parts_of(n)[1] <= parts_of(n + 1)[1] for n in range(0, 1499)))


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
        for _name, _lab, _want in (("default uci build", uci_default, "uci"),
                                   ("chunked uci build", uci_chunked, "uci"),
                                   ("ip65 build", ip65_1440, "ip65")):
            _got, _why = _classify(warp, _lab)
            check(f"detect_backend: {_name} -> {_want!r}", _got == _want,
                  _why or f"returned {_got!r}")
        # ISSUE #131 LIVED HERE. This block used to read:
        #
        #     mixed = dict(ip65_1440, net_last_error=0x7C32)
        #     check("detect_backend: blob + net_last_error raises ValueError")
        #
        # `dict(ip65_build, net_last_error=...)` IS a real post-#120 ip65
        # build. So this suite did not merely fail to catch #131, it
        # asserted the defect: it required detect_backend to refuse the
        # exact shape every shipping ip65 build has. Fixing the classifier
        # made this check go red, which is the only reason it was ever
        # looked at.
        #
        # The coincidence guard is still needed — a classifier keying on
        # ip65_blob_start ALONE passes the three checks above — so it is
        # kept, with an input that is genuinely ambiguous: the ip65 blob
        # plus a UCI-ONLY marker. No build can produce that.
        mixed = dict(ip65_1440, uci_socket_open=0x7C30)
        for name, lab in (("blob + a uci-only marker", mixed),
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
                                   _classify(warp, lab)[0] or "?")
            check(f"_fingerprint: {kind} reports WG_MTU {want}",
                  fp["wg_mtu"] == want, f"got {fp['wg_mtu']}")
        _assert_fixtures_match_a_real_build(check, warp)
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
            # _dump_failure classifies the labels internally, so a broken
            # classifier makes it RAISE rather than misbehave — and #131
            # meant it raised on every ip65 build, at the exact moment a
            # run had already failed and wanted a post-mortem. Reported as
            # its own named check so that shows up as itself instead of
            # collapsing the section.
            for _n, _lab, _want in (
                    ("no reads at all on ip65 labels without hs_* labels "
                     "(net_last_error never touched)", ip65_1440, []),
                    ("uci labels DO read net_last_error", uci_default,
                     [uci_default["net_last_error"]])):
                tr = _Tr()
                try:
                    warp._dump_failure(tr, _lab, "seam")
                    detail = f"reads={tr.reads}"
                    ok_dump = tr.reads == _want
                except Exception as exc:              # noqa: BLE001
                    ok_dump, detail = False, (
                        f"_dump_failure RAISED {exc!r} — the post-mortem "
                        f"path is unusable on this build")
                check(f"_dump_failure: {_n}", ok_dump, detail)
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
            # Wrapped: a raise here used to escape to the section-level
            # `except` and collapse every remaining check into one generic
            # "test_warp_live imports FAIL", moving the denominator.
            for _n, _lab, _want in (
                    ("ip65 labels", _fake_labels("ip65"), "ip65"),
                    ("uci labels", _fake_labels("uci"), "uci"),
                    ("chunked uci labels (uci_send_part)",
                     _fake_labels("uci", chunked=True), "uci")):
                _got, _why = _classify(warp, _lab)
                check(f"detect_backend: {_n} -> {_want!r}", _got == _want,
                      _why or f"returned {_got!r}")
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

    print("\n=== uncalled verdict functions (the #128 instrument shape) ===")
    check_no_uncalled_verdicts(check)

    check_multipart_builder(SEED)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1



# Names that promise a VERDICT. A function called `_verify_*` /
# `check_*` / `score_*` exists to say whether something is true; if
# nothing ever calls it, the thing it describes is unchecked while the
# file still reads as though it were checked.
_VERDICT_NAME = re.compile(
    r'^_?(verify|check|assert|validate|score|expect)_|_(ok|matches|verified)$')


def _uncalled_verdict_functions(tools_dir: Path) -> list[tuple[str, int, str]]:
    """Module-level verdict functions referenced NOWHERE in tools/.

    ISSUE #128's INSTRUMENT, GENERALISED. tools/test_uci_udp_size_probe.py
    defined `_verify_pattern` at line 133, documented byte-exact checking
    in its module docstring, and never called it — the only module-level
    function in that file with zero call sites. `main()` ended
    `_print_summary(results); return 0`, so the tool exited 0 whatever the
    firmware did, and its output was then cited as the control that ruled
    the UCI read out of #128. It was not a control; it was a table.

    That shape is invisible to every other guard we have. It imports
    cleanly, so tools/test_suite_imports.py passes it. It has no assertion
    to observe failing, so "has this ever been red?" returns nothing to
    look at. Only the call graph shows it.

    CROSS-FILE on purpose. `assert_ip65_build` lives in
    tools/vice_eth_rig.py and is called by six sibling suites; a
    same-file-only rule would flag it and five others, and a guard that
    cries wolf gets disbelieved, which is worse than no guard. Measured on
    this tree: same-file-only flags 2 helpers, both false; cross-file
    flags 0. On the pre-fix tree, cross-file flags `_verify_pattern` and
    nothing else.
    """
    srcs: dict[str, str] = {}
    for f in sorted(os.listdir(tools_dir)):
        if f.endswith(".py"):
            try:
                srcs[f] = (tools_dir / f).read_text()
            except OSError:
                pass
    trees: dict[str, ast.AST] = {}
    for f, src in srcs.items():
        try:
            trees[f] = ast.parse(src)
        except SyntaxError:
            pass

    referenced: dict[str, int] = {}
    for tree in trees.values():
        for n in ast.walk(tree):
            if isinstance(n, ast.Name):
                referenced[n.id] = referenced.get(n.id, 0) + 1
            elif isinstance(n, ast.alias):
                referenced[n.name] = referenced.get(n.name, 0) + 1
            elif isinstance(n, ast.Attribute):
                referenced[n.attr] = referenced.get(n.attr, 0) + 1

    out: list[tuple[str, int, str]] = []
    for f, tree in sorted(trees.items()):
        for n in getattr(tree, "body", []):
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _VERDICT_NAME.search(n.name):
                continue
            if referenced.get(n.name, 0) == 0:
                out.append((f, n.lineno, n.name))
    return out


def check_no_uncalled_verdicts(check) -> None:
    """Gate check + its own alarm proof."""
    tools_dir = PROJECT_ROOT / "tools"
    dead = _uncalled_verdict_functions(tools_dir)
    check("no verdict function in tools/ is defined-but-never-called",
          not dead,
          "; ".join(f"{f}:{ln} {nm}() is never called anywhere in tools/ — "
                    f"whatever it claims to check is unchecked"
                    for f, ln, nm in dead))

    # ALARM PROOF. Write a file containing exactly the pre-fix shape and
    # require the scan to report it, then delete it. Without this, "0
    # flagged" is equally consistent with a scanner that flags nothing.
    probe = tools_dir / "zz_uncalled_verdict_alarm_probe.py"
    if probe.exists():
        check("alarm-proof: uncalled-verdict probe file is writable", False,
              f"{probe} already exists; refusing to overwrite")
        return
    try:
        probe.write_text(
            "def _verify_nothing(buf, expected):\n"
            "    return buf == expected\n\n\n"
            "def main():\n"
            "    return 0\n")
        found = _uncalled_verdict_functions(tools_dir)
        hit = any(f == probe.name and nm == "_verify_nothing"
                  for f, _ln, nm in found)
    finally:
        probe.unlink(missing_ok=True)
    check("alarm-proof: a defined-but-uncalled _verify_* IS reported", hit,
          "the scan did not flag a file written to contain exactly the "
          "shape it exists to catch, so its clean verdict means nothing")


def _classify(warp, lab):
    """detect_backend(lab) as (verdict, detail); a raise is a verdict, not a
    crash.

    Calling `warp.detect_backend(x) == "ip65"` directly INSIDE a check()
    argument means a ValueError escapes to the section-level `except`, and
    the whole block reports as one generic "backend seams run FAIL" while
    the remaining checks never run. Two things go wrong then: the failure
    does not name which case broke, and the denominator moves (143 vs 165
    checks), so two runs stop being comparable. Both are failure shapes
    this suite exists to catch elsewhere; it should not have them itself.
    """
    try:
        return warp.detect_backend(lab), ""
    except ValueError as exc:
        return None, f"raised ValueError: {exc}"


def _assert_fixtures_match_a_real_build(check, warp) -> None:
    """Pin the synthetic fixtures to a BUILT labels.txt — issue #131.

    This is the check that did not exist, and its absence is the whole of
    why #131 shipped. Every witness for `detect_backend` was a synthetic
    dict written by hand from what the backends exported AT THE TIME. #120
    gave ip65 its own `net_last_error`; the dicts kept the pre-#120 split;
    the classifier kept keying on it; and every ip65 build was refused
    while this suite stayed green. The fixture comment even argued the
    point out loud — "a real build adds nothing but a make dependency" —
    which is false in exactly the way that matters, because a real build is
    the only thing that can tell you WHICH labels exist.

    So: classify whichever `build/labels.txt` is on disk, and require the
    synthetic fixture for that same backend to carry the identical set of
    DISCRIMINATING markers. A future export change then breaks this check
    rather than silently rotting the fixtures.

    Skipped, loudly, when there is no build to read — this suite runs in
    the gate's parallel pool, which always has one, but it must also be
    runnable on a bare tree without inventing a pass.
    """
    labels_path = PROJECT_ROOT / "build" / "labels.txt"
    if not labels_path.exists():
        check("fixtures pinned to a real build", True,
              "SKIPPED: no build/labels.txt on disk")
        print(f"  NOTE  no {labels_path} — the fixture/real-build "
              f"cross-check did not run. This is the check that would have "
              f"caught #131; a run without it proves less than it looks.")
        return
    from c64_test_harness import Labels
    real = dict(Labels.from_file(str(labels_path)))

    # 1. The real build must classify at all. This alone is red on master:
    #    detect_backend raised ValueError on every ip65 build since #120.
    try:
        found = warp.detect_backend(real)
        err = None
    except ValueError as exc:
        found, err = None, str(exc)
    check("detect_backend classifies the REAL build/labels.txt",
          found in ("uci", "ip65"),
          f"raised instead: {err}" if err else f"returned {found!r}")
    if found is None:
        # Do NOT return: the three checks below would vanish and the
        # denominator would move (162 vs 165), making a red run and a green
        # run incomparable. They cannot be evaluated, so they are reported
        # as failures of the thing that actually broke.
        for nm in ("_fake_labels", "_warp_labels"):
            check(f"{nm}(<real backend>) carries the same discriminating "
                  f"markers as the built labels.txt", False,
                  "not evaluated: detect_backend could not classify the "
                  "real build, so there is no backend to compare against")
        check("net_last_error is not used as a backend discriminator (#120 "
              "gave it to BOTH backends)",
              "net_last_error" not in tuple(warp.IP65_MARKERS)
              + tuple(warp.UCI_MARKERS),
              "it is back in IP65_MARKERS/UCI_MARKERS; every ip65 build "
              "will be refused again, which is issue #131 verbatim")
        return
    print(f"  NOTE  build/labels.txt is a {found} build "
          f"({len(real)} labels)")

    # 2. The synthetic fixture for that backend must carry the SAME
    #    discriminating markers as the real one. This is the pin.
    markers = tuple(warp.IP65_MARKERS) + tuple(warp.UCI_MARKERS)
    real_markers = {m for m in markers if m in real}
    for fixture_name, fixture in (
            ("_fake_labels", _fake_labels(found)),
            ("_warp_labels", _warp_labels(found, ip_pkt_len=0x9DD3))):
        fake_markers = {m for m in markers if m in fixture}
        # uci_send_part is build-flag dependent (UCI_CHUNKED_WRITE=1), so
        # it is excluded from the equality — it is legitimately absent from
        # a default uci build and present in a chunked one.
        flag_dependent = {"uci_send_part"}
        missing = (real_markers - fake_markers) - flag_dependent
        extra = (fake_markers - real_markers) - flag_dependent
        check(f"{fixture_name}(<real backend>) carries the same "
              f"discriminating markers as the built labels.txt",
              not missing and not extra,
              f"fixture is missing {sorted(missing)} and invents "
              f"{sorted(extra)}; the real build exports "
              f"{sorted(real_markers)}. A fixture that has drifted from "
              f"the build is a witness to nothing — this is exactly the "
              f"state that let #131 ship.")

    # 3. net_last_error must NOT be a discriminator. Stated as its own
    #    check because it is the specific fact #131 turned on, and a
    #    regression here would otherwise only show up as (1) going red on
    #    a backend nobody happened to build that day.
    check("net_last_error is not used as a backend discriminator (#120 "
          "gave it to BOTH backends)",
          "net_last_error" not in markers,
          "it is back in IP65_MARKERS/UCI_MARKERS; every ip65 build will "
          "be refused again, which is issue #131 verbatim")


# ---------------------------------------------------------------------------
# Labels shaped like the real builds, for the test_warp_live backend seams.
# Addresses are the measured ones (ip_packet_buf $9833 in every build;
# ip_pkt_len $9B8F at MTU 860, $9DD3 at MTU 1440).
# ---------------------------------------------------------------------------
def _warp_labels(kind: str, ip_pkt_len: int, chunked: bool = False) -> dict:
    # `net_last_error` is in BOTH arms, because since #120 both backends
    # export it (src/net/ip65/net.s:112, src/net/uci/net.s). The previous
    # version of this fixture put it in the uci arm ONLY, which is what let
    # issue #131 through: detect_backend keyed on it, every real ip65 build
    # carried it, and no witness here ever looked like a real ip65 build.
    # _assert_fixtures_match_a_real_build() below now pins these sets to a
    # BUILT labels.txt so the next such divergence cannot hide.
    L = {"boot_ready": 0x8E60, "wg_state": 0x8E61, "net_initialized": 0x908E,
         "ip_packet_buf": 0x9833, "ip_pkt_len": ip_pkt_len,
         "WG_MTU": ip_pkt_len - 0x9833, "net_last_error": 0x7C32}
    if kind == "ip65":
        L["ip65_blob_start"] = 0x2000
        L["ip65_blob_end"] = 0x32EF
        L["ip65_listening"] = 0x7954
    else:
        L["uci_socket_open"] = 0x7C30
        L["uci_wait_idle"] = 0x6A00
        L["uci_status_buf"] = 0x7C40
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
    # BOTH backends export net_last_error since #120 — see the note in
    # _warp_labels. Keeping it in the common set is what makes "ip65" here
    # the shape of a real ip65 build rather than a pre-#120 fossil.
    names.append("net_last_error")
    if kind in ("ip65", "both"):
        names += ["ip65_blob_start", "ip65_blob_end", "ip65_listening"]
    if kind in ("uci", "both"):
        names += ["uci_socket_open", "uci_wait_idle", "uci_status_buf"]
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
    # Seeded so the --multipart builder section is reproducible; the seed is
    # on the first line of the output and overridable with --seed/TEST_SEED.
    if "--seed" in sys.argv:
        SEED = int(sys.argv[sys.argv.index("--seed") + 1])
    else:
        SEED = int(os.environ.get("TEST_SEED", random.randrange(2 ** 32)))
    print(f"Random seed: {SEED} (reproduce with --seed {SEED})")
    sys.exit(main())
