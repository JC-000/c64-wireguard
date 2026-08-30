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

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
