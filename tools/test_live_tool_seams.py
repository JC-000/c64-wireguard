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

It also audits every device tool's TEARDOWN (check_live_tool_teardown,
#134/#166): what each tool owes is derived from what it changes, the tools
are discovered rather than listed, and each must pay in a `finally:`
inside its own lock.
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

    # Stage D teardown (turbo 1 MHz / REU off / verified reset) must sit
    # inside main()'s `finally`, so a raise anywhere above it — notably the
    # rekey stage's asserts, expected to raise on unfixed firmware — still
    # restores the device (the failure mode before that fix: only
    # lock.release() was in finally, so the device was left at 48 MHz).
    #
    # THE CALL NAME CHANGED, AND THAT IS WORTH A NOTE. This check used to
    # look for `set_turbo_mhz`, which was the whole restore when it was
    # written. #134 replaced the hand-written Stage D block with
    # device_session.teardown_device, which does clock AND REU AND a
    # read-back-verified reset — and this check went red on the refactor,
    # correctly: it could no longer see the restore it was guarding. Keying
    # on the helper is the stronger form, because the helper is the whole
    # contract rather than one third of it.
    try:
        import test_warp_live as warp
        check("test_warp_live.main(): Stage D teardown call is inside "
              "the outer try/finally's `finally:` block",
              _restore_in_finally(warp, restore_call="teardown_device"),
              "teardown_device(...) must be reachable even when an "
              "earlier stage (e.g. rekey) raises")
        # The restore must not have quietly gone back to being partial. A
        # bare set_turbo_mhz in the finally would satisfy the check above's
        # OLD form while abandoning the UDP sockets again, so assert the
        # helper specifically and assert the hand-written block is GONE.
        warp_src = inspect.getsource(warp.main)
        check("test_warp_live.main(): Stage D goes through the shared "
              "teardown helper, not a hand-written copy of it",
              "teardown_device" in warp_src
              and "client.reset()" not in warp_src,
              "the point of #134 is one teardown contract; a local "
              "reimplementation is how the seven tools drifted apart")

        # test_uci_handshake_live.main() now OWNS the teardown for every
        # tool that delegates to it (test_wire_encryption_live, wg_demo,
        # test_config_reload_live), which is why those no longer call it
        # themselves. That made it the load-bearing copy, and nothing
        # asserted it: deleting the whole finally block left this gate at
        # 49/49. Pin the helper, the default, and the single opt-out.
        import test_uci_handshake_live as uci_live
        check("test_uci_handshake_live.main(): teardown call is inside the "
              "`finally:` block",
              _restore_in_finally(uci_live, restore_call="teardown_device"),
              "the tools that delegate to this main() stopped tearing down "
              "themselves; if it does not happen here it happens nowhere")
        # #166: the flag became a MODE — kwargs splatted into
        # teardown_device inside the held lock. The default is the FULL
        # teardown, i.e. no overrides at all.
        check("test_uci_handshake_live: teardown mode defaults to the full "
              f"teardown {{}} (got {uci_live.post_session_teardown!r})",
              isinstance(uci_live.post_session_teardown, dict)
              and uci_live.post_session_teardown == {},
              "any override in the default silently weakens the restore for "
              "every delegating tool at once")

        # The departure from the full teardown is asserted by SET
        # EQUALITY, not membership: exactly one tool may run a gentler
        # mode. A second one appearing here is the regression — an
        # operator-tool exemption quietly spreading to a batch tool that
        # ought to restore the box it borrowed.
        _GENTLE_EXPECTED = {"wg_chat.py"}
        # ...and the gentle mode is pinned EXACTLY: no reset, no REU detach
        # (set_reu may itself reset the machine), but the clock IS restored
        # inside the held lock. Before #166 wg_chat opted out entirely and
        # restored the clock afterwards under a second lock.
        _GENTLE_MODE = {"reset": False, "reu_off": False}
        _delegators = ("wg_chat.py", "wg_demo.py",
                       "test_wire_encryption_live.py",
                       "test_config_reload_live.py")
        # The set above is hand-maintained, so a FIFTH tool that delegates
        # and opts out would pass unnoticed. Pin the DENOMINATOR too: every
        # file importing test_uci_handshake_live is either a delegator or
        # named here as a non-delegator, with the reason. A naive
        # "imports it" rule would over-include all three of these.
        _NOT_DELEGATORS = {
            "test_live_tool_seams.py",          # this file; inspects, never runs main()
            "test_wire_encryption_defaults.py",  # stubs main(), never calls it
            "test_wire_encryption_control.py",   # imports only to stub it out
        }
        _tools_dir = Path(__file__).resolve().parent
        # AST, not substring. A text search matches the four files that
        # merely MENTION test_uci_handshake_live in a comment or docstring
        # (test_suite_imports, test_uci_udp_echo_live, test_warp_live,
        # wg_c64_input) — none of them import it. Only a real import counts.
        def _imports_live(path: Path) -> bool:
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:
                return False
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    if any(a.name == "test_uci_handshake_live"
                           for a in node.names):
                        return True
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "test_uci_handshake_live":
                        return True
            return False

        _importers = {
            f.name for f in _tools_dir.glob("*.py")
            if f.name != "test_uci_handshake_live.py" and _imports_live(f)
        }
        check("every importer of test_uci_handshake_live is classified as a "
              "delegator or an explicit non-delegator "
              f"(unclassified: {sorted(_importers - set(_delegators) - _NOT_DELEGATORS)})",
              not (_importers - set(_delegators) - _NOT_DELEGATORS),
              "a new tool delegating to live.main() must be added to "
              "_delegators, or the opt-out equality below cannot see it")
        # STRUCTURAL, not textual. A substring search for an assignment
        # also matches the sentence in test_wire_encryption_live.py's
        # comment explaining what opting out WOULD mean — it reported that
        # file as an opt-out on the first run of this check. Only a real
        # assignment counts, evaluated by _eval_mode (the teardown audit's
        # evaluator, so the two cannot disagree about what a mode means).
        # A computed value — `{"reset": bool(args.keep)}` — is UNKNOWN and
        # FAILS: it may opt out for real while reading as opted in, which
        # is the false-green direction.
        def _teardown_assignments(path: Path):
            return _mode_assignments(ast.parse(path.read_text()),
                                     module_level=False)

        _modes = {n: _teardown_assignments(_tools_dir / n)
                  for n in _delegators}
        _unknown = {n for n, ms in _modes.items()
                    if _UNKNOWN in ms or len(ms) > 1}
        check("no delegator sets post_session_teardown to a value this "
              f"check cannot evaluate (found {sorted(_unknown)})",
              not _unknown,
              "a computed value (or two assignments) may opt out for real "
              "while reading as opted-in; pin ONE literal dict")
        _skippers = {n for n, ms in _modes.items() if None in ms}
        check("no delegator skips the shared teardown outright "
              f"(found {sorted(_skippers)})",
              not _skippers,
              "the boolean opt-out is gone (#166): a tool that must not "
              "reset passes a gentler mode, it does not skip the restore")
        _gentle_found = {n for n, ms in _modes.items()
                         if ms and ms[0] not in ({}, _UNKNOWN)}
        check("exactly wg_chat departs from the full teardown "
              f"(found {sorted(_gentle_found)})",
              _gentle_found == _GENTLE_EXPECTED,
              "wg_chat is the deliberate exception because a human is at "
              "the machine (issue #134); every other delegator must restore")
        _chat_modes = _modes.get("wg_chat.py", [])
        check(f"wg_chat's mode is exactly {_GENTLE_MODE} (got {_chat_modes})",
              _chat_modes == [_GENTLE_MODE],
              "the clock must still be restored INSIDE the lock (#166); "
              "dropping more than reset/REU leaves the box at 48 MHz")

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
            "        teardown_device(host, client=client)\n"
            "    finally:\n"
            "        lock.release()\n"
        )
        check("alarm-proof: restore-in-try-body (not finally) is "
              "correctly flagged as NOT restored-in-finally",
              _restore_in_finally_ast(ast.parse(bad_src),
                                      restore_call="teardown_device") is False,
              "the detector must distinguish this from the real fix, or "
              "it would pass vacuously on the pre-fix code")

        good_src = (
            "def main():\n"
            "    try:\n"
            "        pass\n"
            "    finally:\n"
            "        teardown_device(host, client=client)\n"
            "        lock.release()\n"
        )
        check("alarm-proof: restore-in-finally IS detected",
              _restore_in_finally_ast(ast.parse(good_src),
                                      restore_call="teardown_device") is True)
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
        # A pre-#120 ip65 map: no net_last_error label at all.
        ip65_pre120 = {k: v for k, v in ip65_1440.items()
                       if k != "net_last_error"}
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

        # _dump_failure post-mortem: net_last_error is read wherever the
        # map has it — BOTH backends since #120 (src/net/ip65/net.s:112) —
        # exactly once, at the label's own address. A map without it (a
        # pre-#120 ip65 build) must neither raise nor read. Issue #170.
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
            check("_dump_failure fixtures: ip65 and uci net_last_error sit "
                  "at different addresses (else 'at the label's address' "
                  "cannot tell the two maps apart)",
                  ip65_1440["net_last_error"]
                  != uci_default["net_last_error"],
                  f"both ${ip65_1440['net_last_error']:04X}")
            for _n, _lab, _want in (
                    ("ip65 labels read net_last_error exactly once, at its "
                     "own address (#170)", ip65_1440,
                     [ip65_1440["net_last_error"]]),
                    ("uci labels read net_last_error exactly once, at its "
                     "own address", uci_default,
                     [uci_default["net_last_error"]]),
                    ("labels WITHOUT net_last_error (pre-#120 ip65 map): "
                     "no raise, no read", ip65_pre120, [])):
                tr = _Tr()
                try:
                    warp._dump_failure(tr, _lab, "seam")
                    detail = (f"reads={[hex(a) for a in tr.reads]} "
                              f"want={[hex(a) for a in _want]}")
                    ok_dump = tr.reads == _want
                except Exception as exc:              # noqa: BLE001
                    ok_dump, detail = False, (
                        f"_dump_failure RAISED {exc!r} — the post-mortem "
                        f"path is unusable on this build")
                check(f"_dump_failure: {_n}", ok_dump, detail)
        finally:
            warp.dump_screen = saved_dump

        # run_stage_ab, Stage-B message step: net_last_error is read after
        # send_message_dma wherever the map has it, at the label's own
        # address. Driven through the real run_stage_ab with every
        # device-facing collaborator stubbed. The fake memory holds $00
        # until the send_message_dma stub has run, then a nonzero
        # per-address byte, so a read before the message, a None/$00
        # default or a read at the wrong address cannot pass. The 0.5 s
        # settle after the message is not pinned. Issue #170.
        import tempfile as _tf
        _NLE_BYTE = {ip65_1440["net_last_error"]: 0x48,
                     uci_default["net_last_error"]: 0x5A}
        _ab_sent = [False]

        class _TrAB:
            def __init__(self, L):
                self.L = L

            def read_memory(self, addr, n):
                if addr == self.L.get("wg_state"):
                    return bytes([warp.SESSION_ACTIVE]) + bytes(n - 1)
                b = _NLE_BYTE.get(addr, 0) if _ab_sent[0] else 0
                return bytes([b]) + bytes(n - 1)

        class _ClientAB:
            def run_prg(self, data):
                pass
        saved_ab = (warp._wait_boot_ready, warp._stage_config,
                    warp._net_init_ip65, warp.ki.press_key,
                    warp.ki.wait_for_state, warp.ki.send_message_dma,
                    warp.wait_for_text, warp.dump_screen, warp.time.sleep)
        try:
            warp._wait_boot_ready = lambda *a, **k: None
            warp._stage_config = lambda *a, **k: None
            warp._net_init_ip65 = lambda *a, **k: True
            warp.ki.press_key = lambda *a, **k: True
            warp.ki.wait_for_state = lambda *a, **k: True
            warp.ki.send_message_dma = lambda *a, **k: (
                _ab_sent.__setitem__(0, True) or True)
            warp.wait_for_text = lambda *a, **k: [["PING REPLY OK"]]
            warp.dump_screen = lambda *a, **k: None
            warp.time.sleep = lambda s: None
            with _tf.TemporaryDirectory() as td:
                prg = Path(td) / "a.prg"
                prg.write_bytes(b"\x01\x08\x00")
                for _n, _lab, _bk, _want in (
                        ("ip65 labels: the byte at ip65's own address (#170)",
                         ip65_1440, "ip65", "$48"),
                        ("uci labels: the byte at uci's own address",
                         uci_default, "uci", "$5A"),
                        ("labels WITHOUT net_last_error (pre-#120 ip65 "
                         "map): None, no raise", ip65_pre120, "ip65",
                         None)):
                    _ab_sent[0] = False
                    try:
                        res = warp.run_stage_ab(
                            _TrAB(_lab), _ClientAB(), _lab, b"", b"", b"",
                            seed=1, backend=_bk, prg_path=prg)
                        got = res.get("net_last_error_after_message", "<unset>")
                        ok_ab = (res.get("active") is True
                                 and "error" not in res and got == _want)
                        detail = (f"net_last_error_after_message={got!r} "
                                  f"want={_want!r} active={res.get('active')}")
                    except Exception as exc:              # noqa: BLE001
                        ok_ab, detail = False, f"run_stage_ab RAISED {exc!r}"
                    check(f"run_stage_ab Stage-B net_last_error: {_n}",
                          ok_ab, detail)
        finally:
            (warp._wait_boot_ready, warp._stage_config,
             warp._net_init_ip65, warp.ki.press_key,
             warp.ki.wait_for_state, warp.ki.send_message_dma,
             warp.wait_for_text, warp.dump_screen, warp.time.sleep) = saved_ab

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
            # The failure verdict ip65 net_init/DHCP/listen left behind
            # ($41/$42/$46) is read from net_last_error on the timeout path,
            # at the label's own address; a map without the label neither
            # raises nor records a value. $42 is nonzero so a $00/None
            # default cannot pass.

            class _TrInitFail:
                def read_memory(self, addr, n):
                    b = 0x42 if addr == ip65_1440["net_last_error"] else 0
                    return bytes([b]) + bytes(n - 1)
            for _n, _lab, _want in (
                    ("ip65 labels record net_last_error=$42 (#170)",
                     ip65_1440, "$42"),
                    ("labels WITHOUT net_last_error (pre-#120 ip65 map): "
                     "None, no raise", ip65_pre120, None)):
                calls.clear()
                res = {}
                try:
                    ok = warp._net_init_ip65(_TrInitFail(), None, _lab, 48,
                                             res)
                    got = res.get("net_last_error", "<unset>")
                    ok_nle = ok is False and got == _want
                    detail = f"ok={ok} net_last_error={got!r} want={_want!r}"
                except Exception as exc:              # noqa: BLE001
                    ok_nle, detail = False, f"_net_init_ip65 RAISED {exc!r}"
                check(f"_net_init_ip65 timeout: {_n}", ok_nle, detail)
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
    # `uci_socket_open` (and `uci_send_part` under UCI_CHUNKED_WRITE); both
    # link `net_last_error`. A tool that assumed uci and read a uci-only
    # label on an ip65 PRG would raise a KeyError AFTER run_prg — with the
    # device already loaded and the lock held. So the preflight must
    # classify the labels.txt it was given and refuse a mismatch with exit
    # 2 BEFORE any device call. Two layers:
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

    print("\n=== live-tool teardown, by obligation (#134, #166) ===")
    check_live_tool_teardown(check)
    check_live_tool_teardown_alarms(check)

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
    # The probe goes in a TEMPDIR, not in tools/.
    #
    # It used to be written as tools/zz_uncalled_verdict_alarm_probe.py and
    # unlinked in the finally. That is invisible standalone and wrong under
    # the parallel gate: tools/ is scanned by other suites, and
    # test_cold_init_seam globs tools/*.py. It caught the probe in its
    # listing, the unlink landed before its read, and it reported
    # "unreadable" as a call-site VIOLATION -- a red gate, passing
    # standalone, diagnosing a file that no longer existed. Measured
    # 2026-09-05: one red run, two green, identical tree.
    #
    # A tempdir keeps the proof intact. What is being proven is "a file
    # containing exactly the shape IS reported", and the scanner takes the
    # directory as an argument, so a directory holding only the probe proves
    # it without touching a tree anyone else is reading.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="seams-alarm-") as td:
        probe = Path(td) / "zz_uncalled_verdict_alarm_probe.py"
        probe.write_text(
            "def _verify_nothing(buf, expected):\n"
            "    return buf == expected\n\n\n"
            "def main():\n"
            "    return 0\n")
        found = _uncalled_verdict_functions(Path(td))
        hit = any(f == probe.name and nm == "_verify_nothing"
                  for f, _ln, nm in found)
    check("alarm-proof: a defined-but-uncalled _verify_* IS reported", hit,
          "the scan did not flag a file written to contain exactly the "
          "shape it exists to catch, so its clean verdict means nothing")


# ---------------------------------------------------------------------------
# Live-tool teardown, by OBLIGATION (#134, #166).
#
# The pins further up this file guard ONE copy of the teardown — the one in
# test_uci_handshake_live.main() — and the opt-out flag. Nothing guarded the
# other tools' copies: deleting the teardown_device call from
# test_uci_udp_echo_live.py left this suite 177/177 and
# test_live_tools_wifi.py 59/59 (adversarial review, 2026-10). The same was
# true of test_config_reload_live.py. So this audit does not look for a
# particular call in a particular file; it asks every device tool what it
# OWES and whether a `finally:` pays it.
#
# OBLIGATIONS ARE DERIVED, never listed (ported from be36f9a, which was
# never merged; master solved #134 with teardown_device instead):
#
#   set_turbo_mhz  the tool sets a clock that is not literally 1 MHz
#   set_reu        the tool calls set_reu with anything but literal False
#   reset          the tool runs a PRG (run_prg / run_prg_via_sys) — the
#                  reset is the only thing that closes its UDP sockets
#
# and a tool that delegates to test_uci_handshake_live.main() inherits that
# file's obligations, discharged by the teardown main() runs INSIDE its lock
# with the delegator's `post_session_teardown` kwargs. A hardcoded list
# would let a new tool arrive owing nothing; a hardcoded file list would let
# a new tool arrive unaudited — so the files are DISCOVERED too, and the
# discovered set must EQUAL the classified set in both directions.
#
# Two ledgers, not one. A delegator that ALSO drives the device itself
# (test_config_reload_live's --soak path) owes its own obligations from its
# own finally; crediting it with main()'s teardown would let a deleted soak
# teardown pass because a different code path restores.
# ---------------------------------------------------------------------------

_HS_MODULE = "test_uci_handshake_live"
_HS_FILE = "test_uci_handshake_live.py"
_MODE_NAME = "post_session_teardown"
_TEARDOWN_KWARGS = ("idle_mhz", "reu_off", "reset")
_OBLIGATIONS = frozenset({"reset", "set_reu", "set_turbo_mhz"})
_UNKNOWN = "UNKNOWN"

# A file is a device tool if it CALLS one of these (or delegates to
# live.main()). Calls, not mentions: a docstring naming run_prg is not a
# device access.
_DEVICE_CALLS = frozenset({
    "set_turbo_mhz", "set_reu", "run_prg", "run_prg_via_sys", "DeviceLock",
    "locked_client", "teardown_device", "restore_idle", "reset_and_verify",
    "Ultimate64Client",
})

# Every device tool this audit checks. Adding a tool means adding it here
# (or to _NOT_LIVE_TOOLS with a reason) — the equality check below fails
# until you do, which is the point.
LIVE_TOOLS = frozenset({
    "test_uci_handshake_live.py",
    "test_uci_udp_echo_live.py",
    "test_uci_udp_size_probe.py",
    "test_config_reload_live.py",
    "test_warp_live.py",
    "test_wire_encryption_live.py",
    "test_ip65_rrnet_hw.py",
    "wg_chat.py",
    "wg_demo.py",
    "u64_firmware.py",
    "uci/udp_probe_harness.py",
})

# Files that call a device API but are not tools that borrow the device.
# (Suites that only STUB these names — `"set_reu": lambda ...`,
# `ds.teardown_device = fake` — make no call and are not discovered.)
_NOT_LIVE_TOOLS = {
    "device_session.py": "the shared lock/teardown helpers themselves",
    "test_device_teardown.py": "unit suite for teardown_device, fake clients",
}

# The ONLY permitted shortfalls, by SET EQUALITY: a tool listed here must
# be missing exactly these and no more (a regression) and no fewer (a
# stale exemption that would quietly cover a future regression).
#
# wg_chat is an operator tool attached to a machine a human is using: a
# reset — and set_reu, which may reset (test_uci_handshake_live.py's
# REU-before-turbo comment) — would destroy the session that is its whole
# purpose (#134). It still restores the CLOCK, inside the lock (#166).
EXPECTED_SHORTFALL = {"wg_chat.py": frozenset({"reset", "set_reu"})}

_TREE_CACHE: dict[str, ast.AST] = {}


def _parse_cached(text: str) -> ast.AST:
    t = _TREE_CACHE.get(text)
    if t is None:
        t = _TREE_CACHE[text] = ast.parse(text)
    return t


def _callee(c: ast.Call):
    f = c.func
    return (f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute) else None)


def _calls_in(node) -> list:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _effective(c: ast.Call):
    """(callee, positional args), with `_safe(fn, *args)` unwrapped — the
    echo/probe tools route set_reu through it."""
    if _callee(c) == "_safe" and c.args and isinstance(
            c.args[0], (ast.Name, ast.Attribute)):
        inner = c.args[0]
        return (inner.id if isinstance(inner, ast.Name) else inner.attr,
                list(c.args[1:]))
    return _callee(c), list(c.args)


def _is_one(node) -> bool:
    return (isinstance(node, ast.Constant) and type(node.value) is int
            and node.value == 1)


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _direct_need(tree) -> set:
    """What this file's OWN calls leave on the device. A missing or
    non-literal argument counts as the unsafe value: it might be."""
    need = set()
    for c in _calls_in(tree):
        nm, args = _effective(c)
        if nm == "set_turbo_mhz":
            if not (len(args) >= 2 and _is_one(args[1])):
                need.add("set_turbo_mhz")
        elif nm == "set_reu":
            if not (len(args) >= 2 and _is_false(args[1])):
                need.add("set_reu")
        elif nm in ("run_prg", "run_prg_via_sys"):
            need.add("reset")
    return need


def _hs_aliases(tree) -> set:
    return {a.asname or a.name for n in ast.walk(tree)
            if isinstance(n, ast.Import) for a in n.names
            if a.name == _HS_MODULE}


def _delegates(tree) -> bool:
    """live.main() via `import test_uci_handshake_live as live`, OR a bare
    call to `main` imported `from test_uci_handshake_live import main [as x]`
    (adversarial review: the from-import form was invisible)."""
    al = _hs_aliases(tree)
    fn_names = {a.asname or a.name for n in ast.walk(tree)
                if isinstance(n, ast.ImportFrom) and n.module == _HS_MODULE
                for a in n.names if a.name == "main"}
    for c in _calls_in(tree):
        f = c.func
        if (isinstance(f, ast.Attribute) and f.attr == "main"
                and isinstance(f.value, ast.Name) and f.value.id in al):
            return True
        if isinstance(f, ast.Name) and f.id in fn_names:
            return True
    return False


def _structure_problems(tree, is_hs: bool) -> list:
    """Shapes the audit cannot follow, so it refuses them instead of
    passing them (adversarial review, M2/M2b/M7/M8):

    * a device API imported under ANOTHER NAME — `teardown_device as td`
      is neither credited nor flagged, so it must not exist;
    * the mode changed without an assignment — `.update(...)`, `setattr`
      — which the assignment evaluator cannot see, and which mutates the
      shared module-level default in place.
    """
    out = []
    watched = set(_DEVICE_CALLS) | {"get_turbo_mhz"}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                base = a.name.rsplit(".", 1)[-1]
                if a.asname and a.asname != base and (
                        base in watched or (
                            isinstance(n, ast.ImportFrom)
                            and n.module == _HS_MODULE and base == "main")):
                    out.append(f"line {n.lineno}: `{a.name} as {a.asname}` — "
                               f"the teardown audit keys on the real name; "
                               f"import it unaliased")
        if (not is_hs and isinstance(n, ast.Attribute)
                and n.attr == _MODE_NAME and isinstance(n.ctx, ast.Load)):
            out.append(f"line {n.lineno}: {_MODE_NAME} READ/mutated in place "
                       f"(e.g. .update()) — that also changes the shared "
                       f"default for every later caller; assign one literal")
        if (isinstance(n, ast.Call) and _callee(n) in ("setattr", "delattr")
                and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
                and n.args[1].value == _MODE_NAME):
            out.append(f"line {n.lineno}: {_callee(n)}(..., '{_MODE_NAME}') "
                       f"— assign one literal dict instead")
    return out


def _eval_mode(node):
    """A post_session_teardown value -> teardown kwargs, None (no teardown
    at all), or _UNKNOWN. A computed value is UNKNOWN and FAILS — it might
    opt out while reading as opted in.

    The old BOOLEANS are not modes any more and must not read as one. `True`
    was the old default, so an old branch or a copied snippet will write it:
    at runtime `teardown_device(**True)` raises TypeError, main()'s
    BaseException guard swallows it with a warning, and NOTHING is restored
    (adversarial review, finding 1). So True is UNKNOWN, and False — which
    fails the same way — is None: no teardown."""
    if isinstance(node, ast.Constant) and node.value is True:
        return _UNKNOWN
    if isinstance(node, ast.Constant) and node.value is False:
        return None
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value in _TEARDOWN_KWARGS
                    and isinstance(v, ast.Constant)):
                return _UNKNOWN
            out[k.value] = v.value
        return out
    return _UNKNOWN


def _mode_assignments(tree, module_level: bool) -> list:
    nodes = tree.body if module_level else list(ast.walk(tree))
    out = []
    for n in nodes:
        if not isinstance(n, (ast.Assign, ast.AnnAssign)):
            continue
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        for t in targets:
            name = (t.id if isinstance(t, ast.Name) and module_level
                    else t.attr if isinstance(t, ast.Attribute)
                    and not module_level else None)
            if name == _MODE_NAME:
                out.append(_eval_mode(n.value) if n.value is not None
                           else _UNKNOWN)
    return out


def _helper_facts(ds_tree):
    """What device_session.teardown_device ACTUALLY does, and its defaults.

    The credit given to a bare `teardown_device(host, client=c)` rests on
    both. Read from the AST, not imported, so a mutated copy is audited as
    written."""
    fns = {n.name: n for n in getattr(ds_tree, "body", [])
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    td = fns.get("teardown_device")
    defaults = {k: _UNKNOWN for k in _TEARDOWN_KWARGS}
    does: set = set()
    if td is None:
        return defaults, does
    a = td.args
    pos = a.posonlyargs + a.args
    pairs = list(zip(pos[len(pos) - len(a.defaults):], a.defaults))
    pairs += [(p, d) for p, d in zip(a.kwonlyargs, a.kw_defaults) if d]
    for p, d in pairs:
        if p.arg in defaults and isinstance(d, ast.Constant):
            defaults[p.arg] = d.value
    called = {}
    for c in _calls_in(td):
        called.setdefault(_callee(c), []).append(c)
    parents = {ch: p for p in ast.walk(td) for ch in ast.iter_child_nodes(p)}

    def _gated_by(node, names) -> bool:
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.If) and any(
                    isinstance(x, ast.Name) and x.id in names
                    for x in ast.walk(node.test)):
                return True
        return False
    # The clock is the ONE stage the gentle mode keeps, so crediting it
    # requires the set to be unconditional on reu_off/reset: gated behind
    # either, wg_chat's {"reset": False, "reu_off": False} would skip it.
    if ("get_turbo_mhz" in called and any(
            not _gated_by(c, {"reu_off", "reset"})
            for c in called.get("set_turbo_mhz", []))):
        does.add("set_turbo_mhz")          # set AND read back
    if any(len(c.args) >= 2 and _is_false(c.args[1])
           for c in called.get("set_reu", [])):
        does.add("set_reu")
    rv = fns.get("reset_and_verify")
    if ("reset_and_verify" in called and rv is not None
            and any(_callee(c) == "reset" for c in _calls_in(rv))):
        does.add("reset")
    return defaults, does


def _finally_calls(tree) -> list:
    """Calls reachable from any `finally:`, following module-level helpers
    up to three levels (config-reload's `_turbo_down` shape). A helper
    that does nothing is followed and credits nothing."""
    helpers = {n.name: n for n in getattr(tree, "body", [])
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    frontier = []
    for t in ast.walk(tree):
        if isinstance(t, ast.Try) and t.finalbody:
            for s in t.finalbody:
                frontier += _calls_in(s)
    out, seen = [], set()
    for depth in range(4):
        nxt = []
        for c in frontier:
            out.append(c)
            nm = _callee(c)
            if (depth < 3 and isinstance(c.func, ast.Name)
                    and nm in helpers and nm not in seen):
                seen.add(nm)
                nxt += _calls_in(helpers[nm])
        frontier = nxt
    return out


def _discharge(calls, defaults, does, mode):
    """(obligations paid, problems) by *calls*. *mode* is the value a
    `**post_session_teardown` splat expands to here."""
    done, problems = set(), []
    for c in calls:
        nm, args = _effective(c)
        ln = getattr(c, "lineno", "?")
        if nm == "teardown_device":
            client_arg = (c.args[1] if len(c.args) >= 2 else next(
                (k.value for k in c.keywords if k.arg == "client"), None))
            if client_arg is None or (isinstance(client_arg, ast.Constant)
                                      and client_arg.value is None):
                problems.append(
                    f"line {ln}: teardown_device() without client= takes a "
                    f"SECOND lock after this tool released its own — an "
                    f"unserialised window another lane can acquire into "
                    f"(#166). Pass client= from inside the locked region.")
                continue
            params = dict(defaults)
            skip = False
            for k in c.keywords:
                if k.arg is None:
                    if (isinstance(k.value, ast.Name)
                            and k.value.id == _MODE_NAME):
                        if mode is None:
                            skip = True
                        elif mode == _UNKNOWN:
                            problems.append(
                                f"line {ln}: {_MODE_NAME} cannot be "
                                f"evaluated — pin it to a literal dict of "
                                f"{list(_TEARDOWN_KWARGS)}")
                            skip = True
                        else:
                            params.update(mode)
                    else:
                        problems.append(f"line {ln}: teardown_device(**...) "
                                        f"splat this audit cannot evaluate")
                        skip = True
                elif k.arg in _TEARDOWN_KWARGS:
                    params[k.arg] = (k.value.value
                                     if isinstance(k.value, ast.Constant)
                                     else _UNKNOWN)
            if skip:
                continue
            idle = params["idle_mhz"]
            if type(idle) is int and idle == 1:
                if "set_turbo_mhz" in does:
                    done.add("set_turbo_mhz")
            else:
                problems.append(
                    f"line {ln}: teardown_device restores to idle_mhz="
                    f"{idle!r}, not 1 MHz. Idle is 1 MHz + REU off "
                    f"(runbook §4/§5a, red-green.md); 'whatever it was when "
                    f"we arrived' hands on another lane's leftover clock.")
            if params["reu_off"] is True and "set_reu" in does:
                done.add("set_reu")
            if params["reset"] is True and "reset" in does:
                done.add("reset")
        elif nm == "restore_idle":
            problems.append(
                f"line {ln}: restore_idle() from a finally takes its own "
                f"lock, after this tool's was released — the #166 window.")
        elif nm == "set_turbo_mhz" and len(args) >= 2 and _is_one(args[1]):
            done.add("set_turbo_mhz")
        elif nm == "set_reu" and len(args) >= 2 and _is_false(args[1]):
            done.add("set_reu")
        elif nm == "reset_and_verify" or (
                nm == "reset" and isinstance(c.func, ast.Attribute)
                and not c.args and isinstance(c.func.value, ast.Name)
                and (c.func.value.id == "c"
                     or "client" in c.func.value.id)):
            # A device client's reset — not listener.reset() or any other
            # object's (adversarial review, M6).
            done.add("reset")
    return done, problems


_RESTORE_CALLEES = {"teardown_device", "set_turbo_mhz", "set_reu",
                    "reset", "reset_and_verify"}


def _released_before_restore(tree) -> list:
    """A restore that runs AFTER a `.release()` in the same `finally:` is
    outside the lock however it is spelled (adversarial review, M3). Source
    order within one finalbody is execution order for straight-line code,
    which is what every teardown here is."""
    out = []
    for t in ast.walk(tree):
        if not (isinstance(t, ast.Try) and t.finalbody):
            continue
        calls = [c for s in t.finalbody for c in _calls_in(s)]
        rel = [c.lineno for c in calls if _callee(c) == "release"
               and isinstance(c.func, ast.Attribute)]
        for c in calls:
            if _effective(c)[0] in _RESTORE_CALLEES and rel and min(rel) < c.lineno:
                out.append(f"line {c.lineno}: {_effective(c)[0]}() runs "
                           f"after a .release() at line {min(rel)} in the "
                           f"same finally — outside the lock")
    return out


def _teardown_audit(tools_dir: Path, overrides: dict | None = None) -> dict:
    """The whole audit as data, so the alarm proofs can run it on a mutated
    tree (*overrides*: relpath -> source text, or None to delete)."""
    texts: dict[str, str] = {}
    for p in sorted(tools_dir.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            texts[p.relative_to(tools_dir).as_posix()] = p.read_text()
        except OSError:
            pass
    for rel, text in (overrides or {}).items():
        if text is None:
            texts.pop(rel, None)
        else:
            texts[rel] = text

    res = {"discovered": set(), "parse_errors": [], "tools": {},
           "helper": {}, "mode_refs_ok": False}
    trees: dict[str, ast.AST] = {}
    needles = tuple(_DEVICE_CALLS) + (_HS_MODULE,)
    for rel, text in texts.items():
        if not any(s in text for s in needles):
            continue
        try:
            tree = _parse_cached(text)
        except SyntaxError as exc:
            res["parse_errors"].append(f"{rel}: {exc}")
            continue
        trees[rel] = tree
        if (any(_effective(c)[0] in _DEVICE_CALLS for c in _calls_in(tree))
                or _delegates(tree)):
            res["discovered"].add(rel)

    ds_tree = trees.get("device_session.py", ast.Module(body=[],
                                                        type_ignores=[]))
    defaults, does = _helper_facts(ds_tree)
    res["helper"] = {"defaults": defaults, "does": does}

    hs_tree = trees.get(_HS_FILE, ast.Module(body=[], type_ignores=[]))
    hs_modes = _mode_assignments(hs_tree, module_level=True)
    hs_default = hs_modes[0] if len(hs_modes) == 1 else _UNKNOWN
    res["hs_default"] = hs_default
    hs_need = _direct_need(hs_tree)
    hs_fin = _finally_calls(hs_tree)
    # The mode may be READ in exactly one place: the splat into the
    # teardown call. A second read — `if post_session_teardown:` — would
    # turn the default `{}` (falsy) into a silent skip for every delegator.
    loads = [n for n in ast.walk(hs_tree) if isinstance(n, ast.Name)
             and n.id == _MODE_NAME and isinstance(n.ctx, ast.Load)]
    splats = [k.value for c in _calls_in(hs_tree)
              if _callee(c) == "teardown_device" for k in c.keywords
              if k.arg is None and isinstance(k.value, ast.Name)
              and k.value.id == _MODE_NAME]
    res["mode_refs_ok"] = bool(splats) and len(loads) == len(splats)
    res["mode_loads"] = len(loads)
    res["mode_splats"] = len(splats)

    for rel in sorted(res["discovered"] & LIVE_TOOLS):
        tree = trees[rel]
        need = _direct_need(tree)
        own_mode = hs_default if rel == _HS_FILE else _UNKNOWN
        done, problems = _discharge(_finally_calls(tree), defaults, does,
                                    own_mode)
        missing = need - done
        problems += _structure_problems(tree, rel == _HS_FILE)
        problems += _released_before_restore(tree)
        info = {"need": set(need), "missing": missing,
                "problems": problems, "delegates": False}
        if rel != _HS_FILE and _delegates(tree):
            info["delegates"] = True
            modes = _mode_assignments(tree, module_level=False)
            if not modes:
                mode = hs_default
            elif len(modes) == 1:
                mode = modes[0]
            else:
                mode = _UNKNOWN
                problems.append(f"{len(modes)} assignments to {_MODE_NAME}; "
                                f"pin exactly one literal")
            info["mode"] = mode
            d_done, d_prob = _discharge(hs_fin, defaults, does, mode)
            # Problems main()'s finally has under its OWN default are
            # reported against test_uci_handshake_live; only those this
            # delegator's mode introduces (an idle_mhz override, an
            # unevaluable value) are this delegator's.
            base = set(_discharge(hs_fin, defaults, does, hs_default)[1])
            problems += [p for p in d_prob if p not in base]
            info["need"] |= hs_need
            missing |= hs_need - d_done
        res["tools"][rel] = info
    return res


def check_live_tool_teardown(check, tools_dir: Path | None = None) -> None:
    """Gate check: every device tool restores what it changed, in a
    `finally`, inside its lock — derived, discovered, set-equal."""
    tools_dir = tools_dir or (PROJECT_ROOT / "tools")
    r = _teardown_audit(tools_dir)
    disc = r["discovered"]
    classified = LIVE_TOOLS | set(_NOT_LIVE_TOOLS)
    check("teardown audit: every tools/ file parses",
          not r["parse_errors"], "; ".join(r["parse_errors"]))
    check(f"teardown audit: discovery found the live tools "
          f"({len(disc & LIVE_TOOLS)}/{len(LIVE_TOOLS)})",
          LIVE_TOOLS <= disc and len(disc) >= len(LIVE_TOOLS),
          "a discovery that finds fewer files than are classified is "
          "vacuous for the ones it missed")
    check("teardown audit: LIVE_TOOLS and _NOT_LIVE_TOOLS are disjoint",
          not (LIVE_TOOLS & set(_NOT_LIVE_TOOLS)),
          f"both: {sorted(LIVE_TOOLS & set(_NOT_LIVE_TOOLS))}")
    check(f"teardown audit: discovered device tools == classified "
          f"(unclassified {sorted(disc - classified)}, "
          f"stale {sorted(classified - disc)})",
          disc == classified,
          "a NEW file calling a device API must be added to LIVE_TOOLS "
          "(audited) or _NOT_LIVE_TOOLS (with a reason); a STALE entry "
          "means a tool stopped matching discovery — find out why before "
          "deleting it")
    check("teardown audit: every EXPECTED_SHORTFALL key is a live tool",
          set(EXPECTED_SHORTFALL) <= LIVE_TOOLS,
          f"{sorted(set(EXPECTED_SHORTFALL) - LIVE_TOOLS)}")

    h = r["helper"]
    check("teardown_device itself sets+reads back the clock, detaches the "
          f"REU and does a verified reset (does {sorted(h['does'])})",
          h["does"] == _OBLIGATIONS,
          f"missing {sorted(_OBLIGATIONS - h['does'])} — every tool "
          f"crediting this helper is relying on work it does not do")
    check(f"teardown_device defaults are idle_mhz=1, reu_off=True, "
          f"reset=True (got {h['defaults']})",
          h["defaults"] == {"idle_mhz": 1, "reu_off": True, "reset": True},
          "a bare teardown_device(host, client=c) is credited as the FULL "
          "restore on the strength of these defaults")
    # The default being {} is pinned once, on the imported module, by the
    # "teardown mode defaults to the full teardown" check further up; the
    # audit uses r["hs_default"] but does not report it a second time.
    check(f"test_uci_handshake_live: {_MODE_NAME} is read ONLY as the "
          f"**splat into teardown_device ({r['mode_loads']} reads, "
          f"{r['mode_splats']} splats)",
          r["mode_refs_ok"],
          "an `if post_session_teardown:` guard turns the default {} into "
          "a silent skip; a missing splat ignores every delegator's mode")

    for rel in sorted(LIVE_TOOLS & disc):
        info = r["tools"][rel]
        allowed = set(EXPECTED_SHORTFALL.get(rel, set()))
        ok = info["missing"] == allowed and not info["problems"]
        detail = (f"missing {sorted(info['missing'])} (allowed "
                  f"{sorted(allowed)})")
        if info["problems"]:
            detail += "; " + " | ".join(info["problems"])
        check(f"teardown/{rel}: owes {sorted(info['need'])}"
              + (" via live.main()" if info["delegates"] else "")
              + (f", exempt {sorted(allowed)}" if allowed else "")
              + " — paid in a finally, inside the lock",
              ok, detail)


def _mutated(rel: str, old: str, new: str) -> dict | None:
    """{rel: text with *old* -> *new*}, or None when *old* does not occur
    exactly once — a mutation that did not apply proves nothing."""
    try:
        text = (PROJECT_ROOT / "tools" / rel).read_text()
    except OSError:
        return None
    if text.count(old) != 1:
        return None
    return {rel: text.replace(old, new)}


def check_live_tool_teardown_alarms(check) -> None:
    """Each mutation is the regression the audit exists for, near its
    boundary; each must turn exactly the expected tool red, with the
    expected shortfall. Run on overrides, never on files in tools/."""
    tools_dir = PROJECT_ROOT / "tools"
    echo, cfg, chat = ("test_uci_udp_echo_live.py",
                       "test_config_reload_live.py", "wg_chat.py")
    echo_call = ("teardown_device(host, client=client, logger=log)")
    cfg_call = ("teardown_device(args.host, client=client, logger=log)")
    chat_mode = '{"reset": False, "reu_off": False}'
    full = set(_OBLIGATIONS)
    cases = [
        # (label, rel, override, tool, expected missing, expect a problem)
        ("echo_live: teardown call deleted", echo,
         _mutated(echo, echo_call, "pass"), echo, full, False),
        ("echo_live: clock restore dropped only (idle_mhz=48)", echo,
         _mutated(echo, echo_call,
                  "teardown_device(host, client=client, idle_mhz=48, "
                  "logger=log)"), echo, {"set_turbo_mhz"}, True),
        ("echo_live: reset dropped only (reset=False)", echo,
         _mutated(echo, echo_call,
                  "teardown_device(host, client=client, reset=False, "
                  "logger=log)"), echo, {"reset"}, False),
        ("echo_live: restore taken AFTER release (no client=)", echo,
         _mutated(echo, echo_call, "teardown_device(host, logger=log)"),
         echo, full, True),
        ("config_reload --soak: teardown call deleted", cfg,
         _mutated(cfg, cfg_call, "pass"), cfg,
         {"reset", "set_turbo_mhz"}, False),
        ("config_reload --soak: clock restore dropped only", cfg,
         _mutated(cfg, cfg_call,
                  "teardown_device(args.host, client=client, idle_mhz=48, "
                  "logger=log)"), cfg, {"set_turbo_mhz"}, True),
        ("wg_chat: gentle mode stops restoring the clock", chat,
         _mutated(chat, chat_mode,
                  '{"reset": False, "reu_off": False, "idle_mhz": 48}'),
         chat, full, True),
        ("wg_chat: back to the boolean opt-out", chat,
         _mutated(chat, chat_mode, "False"), chat, full, False),
        ("wg_chat: exemption no longer needed (full mode) is STALE", chat,
         _mutated(chat, chat_mode, "{}"), chat, set(), False),
        ("wg_demo: quietly adopts the gentle mode", "wg_demo.py",
         _mutated("wg_demo.py", "live.post_session_hook = build_demo_loop()",
                  "live.post_session_hook = build_demo_loop()\n"
                  "    live.post_session_teardown = {\"reset\": False}"),
         "wg_demo.py", {"reset"}, False),
        ("wire_encryption_live: computed mode is UNKNOWN, not opted-in",
         "test_wire_encryption_live.py",
         _mutated("test_wire_encryption_live.py",
                  "live.post_session_hook = build_probe()",
                  "live.post_session_hook = build_probe()\n"
                  "    live.post_session_teardown = dict(reset=args.turbo)"),
         "test_wire_encryption_live.py", full, True),
    ]
    for label, rel, ov, tool, want_missing, want_problem in cases:
        if ov is None:
            check(f"alarm-proof: {label}", False,
                  f"the mutation did not apply to {rel} (anchor text not "
                  f"found exactly once) — update the anchor, do not drop "
                  f"the case")
            continue
        info = _teardown_audit(tools_dir, ov)["tools"].get(tool)
        got = (info["missing"], bool(info["problems"])) if info else None
        check(f"alarm-proof: {label} -> missing {sorted(want_missing)}"
              + (" + a problem" if want_problem else ""),
              got == (set(want_missing), want_problem)
              and (set(want_missing)
                   != set(EXPECTED_SHORTFALL.get(tool, set()))
                   or want_problem),
              f"audit returned {got}")

    # The adversarial review's false greens (M-numbers from that report).
    # Each must now turn its tool red — missing an obligation OR reporting
    # a problem. Anchors are the post-fix shapes; a non-applying anchor
    # fails rather than skips.
    demo_hook = "live.post_session_hook = build_demo_loop()"
    echo_fin = ("        teardown_device(host, client=client, logger=log)\n"
                "        lock.release()\n")
    review = [
        ("M1 wg_demo writes the old default `= True` (**True raises at "
         "runtime; nothing restored)", "wg_demo.py",
         _mutated("wg_demo.py", demo_hook,
                  demo_hook + "\n    live.post_session_teardown = True")),
        ("M2 wg_demo mutates the mode in place with .update()", "wg_demo.py",
         _mutated("wg_demo.py", demo_hook, demo_hook +
                  "\n    live.post_session_teardown.update(reset=False)")),
        ("M2b wg_demo sets the mode with setattr()", "wg_demo.py",
         _mutated("wg_demo.py", demo_hook, demo_hook +
                  "\n    setattr(live, 'post_session_teardown', {})")),
        ("M3 echo_live releases the lock BEFORE the teardown", echo,
         _mutated(echo, echo_fin,
                  "        lock.release()\n"
                  "        teardown_device(host, client=client, logger=log)\n")),
        ("M4 echo_live passes client=None", echo,
         _mutated(echo, echo_call,
                  "teardown_device(host, client=None, logger=log)")),
        ("M6 echo_live 'resets' a listener, not the device", echo,
         _mutated(echo, echo_call,
                  "teardown_device(host, client=client, reset=False, "
                  "logger=log); listener.reset()")),
        ("M8 echo_live imports teardown_device under an alias", echo,
         _mutated(echo, "        from device_session import teardown_device\n"
                  "        teardown_device(host, client=client, logger=log)\n",
                  "        from device_session import teardown_device as td\n"
                  "        td(host, client=client, idle_mhz=48, logger=log)\n")),
        ("M10 a from-import delegator is discovered (and unclassified)",
         "zz_from_import_delegator.py",
         {"zz_from_import_delegator.py":
          "from test_uci_handshake_live import main as hs\nhs()\n"}),
    ]
    for label, tool, ov in review:
        if ov is None:
            check(f"alarm-proof (review): {label}", False,
                  "the mutation did not apply (anchor not found exactly "
                  "once) — update the anchor, do not drop the case")
            continue
        r = _teardown_audit(tools_dir, ov)
        if tool not in LIVE_TOOLS:
            check(f"alarm-proof (review): {label}",
                  tool in r["discovered"], f"discovered={sorted(r['discovered'])}")
            continue
        info = r["tools"].get(tool)
        allowed = set(EXPECTED_SHORTFALL.get(tool, set()))
        red = info is not None and (info["missing"] != allowed
                                    or bool(info["problems"]))
        check(f"alarm-proof (review): {label} -> red", red,
              f"audit returned {info}")

    # The helper's clock credit requires an UNCONDITIONAL set: gated behind
    # reu_off, the gentle mode would silently skip it (review finding 6).
    ov = _mutated("device_session.py",
                  "                set_turbo_mhz(c, idle_mhz)\n",
                  "                if reu_off: set_turbo_mhz(c, idle_mhz)\n")
    r = _teardown_audit(tools_dir, ov) if ov else None
    check("alarm-proof (review): a clock set gated on reu_off withdraws the "
          "clock credit (wg_chat goes red)",
          r is not None and "set_turbo_mhz" not in r["helper"]["does"]
          and "set_turbo_mhz" in r["tools"]["wg_chat.py"]["missing"],
          "mutation did not apply" if r is None else
          f"does={sorted(r['helper']['does'])}")

    # Mutations that SHOULD SURVIVE: equivalent spellings of a correct
    # restore. A guard that also fires on these keys on spelling, not on
    # the property, and gets "fixed" by whoever trips it next.
    survivors = [
        ("echo_live: idle_mhz=1 spelled out", echo,
         _mutated(echo, echo_call,
                  "teardown_device(host, client=client, idle_mhz=1, "
                  "reu_off=True, reset=True, logger=log)"), echo),
        ("wg_chat: the same gentle mode, keys reordered", chat,
         _mutated(chat, chat_mode, '{"reu_off": False, "reset": False}'),
         chat),
        ("echo_live: a COMMENT naming restore_idle() in the finally", echo,
         _mutated(echo, echo_call,
                  echo_call + "  # not restore_idle(host): #166"), echo),
    ]
    for label, rel, ov, tool in survivors:
        if ov is None:
            check(f"should-survive: {label}", False,
                  f"the mutation did not apply to {rel}")
            continue
        info = _teardown_audit(tools_dir, ov)["tools"].get(tool)
        allowed = set(EXPECTED_SHORTFALL.get(tool, set()))
        check(f"should-survive: {label} stays green",
              info is not None and info["missing"] == allowed
              and not info["problems"],
              f"audit returned {info}")

    # Discovery, both directions.
    ov = {"zz_new_live_tool.py": "def main(c):\n    c.run_prg(b'')\n"}
    r = _teardown_audit(tools_dir, ov)
    check("alarm-proof: a NEW file calling run_prg is discovered and "
          "unclassified",
          "zz_new_live_tool.py" in r["discovered"]
          and "zz_new_live_tool.py" not in LIVE_TOOLS | set(_NOT_LIVE_TOOLS))
    r = _teardown_audit(tools_dir, {"test_uci_udp_size_probe.py": None})
    check("alarm-proof: a classified tool that vanishes is STALE",
          "test_uci_udp_size_probe.py" not in r["discovered"])

    # The helper's credit is verified, not assumed.
    ov = _mutated("device_session.py",
                  "st[\"reset\"] = reset_and_verify(c, logger=out)",
                  "st[\"reset\"] = None")
    r = _teardown_audit(tools_dir, ov) if ov else None
    check("alarm-proof: gutting teardown_device's reset withdraws the "
          "reset credit from EVERY tool that relies on it",
          r is not None and "reset" not in r["helper"]["does"]
          and "reset" in r["tools"][echo]["missing"]
          and "reset" in r["tools"]["test_warp_live.py"]["missing"],
          "mutation did not apply" if r is None else
          f"does={sorted(r['helper']['does'])}")

    # A second read of the mode in main() (the falsy-{} trap).
    ov = _mutated(_HS_FILE, "        if client is not None:\n"
                  "            # The import is INSIDE",
                  "        if client is not None and post_session_teardown:\n"
                  "            # The import is INSIDE")
    r = _teardown_audit(tools_dir, ov) if ov else None
    check("alarm-proof: `if ... post_session_teardown:` in main() is "
          "flagged (it would skip the default {} teardown)",
          r is not None and not r["mode_refs_ok"],
          "mutation did not apply" if r is None else "")

    # A local helper that does nothing credits nothing.
    src = ("def _restore(c):\n    pass\n\n"
           "def main(c):\n    try:\n        c.run_prg(b'')\n"
           "    finally:\n        _restore(c)\n")
    tree = ast.parse(src)
    done, _ = _discharge(_finally_calls(tree), {"idle_mhz": 1,
                         "reu_off": True, "reset": True}, set(_OBLIGATIONS),
                         {})
    check("alarm-proof: a do-nothing helper called from a finally pays "
          "nothing", _direct_need(tree) - done == {"reset"},
          f"done={sorted(done)}")


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
         "WG_MTU": ip_pkt_len - 0x9833, "net_last_error": 0x7D32}
    # net_last_error is the REU=1 address on both arms: uci $7D32, ip65
    # $79D2 (at REU=0: $7C32 and $78C2), measured at d5dd49f.
    if kind == "ip65":
        L["net_last_error"] = 0x79D2
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
