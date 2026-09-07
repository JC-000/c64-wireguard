#!/usr/bin/env python3
"""Assert the arm test_wire_encryption_live's DEFAULT invocation selects.

Issue #98: the tool passed neither `C64_REU` nor `--reu`, so it inherited
`C64_REU=1` and `--reu on` from the two tools it composes, and its plain
`--host <ip>` invocation was the REU build, REU attached, at 48 MHz. Every
green it ever recorded came from an operator overriding that — its passing
history described what its operators typed, not what the tool does.

That is precisely the class of defect that no amount of running the tool
finds, because the people who run it are the people who already know to
override. The only thing that catches it is an assertion on the DEFAULT,
which is what this file is.

Touches no device: `live.main` is stubbed to capture the argv it is handed
and the environment it is handed it in. Running the tool for real would
prove the opposite of what is wanted here — it would prove the arm the
runner configured.
"""
import contextlib
import io
import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

results = []


def check(ok, label, detail=""):
    results.append((ok, label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail else ""))
    return ok


def run_tool(env_overrides, extra_argv=()):
    """Run test_wire_encryption_live.main() with live.main stubbed out.

    Returns (argv_seen, env_seen). The environment is restored afterwards.
    """
    import test_wire_encryption_live as wire
    import test_uci_handshake_live as live
    import device_session as ds

    saved_env = {k: os.environ.get(k) for k in
                 ("C64_REU", "C64_SKIP_BUILD", "U64_ALLOW_MUTATE")}
    saved_main, saved_td = live.main, ds.teardown_device
    saved_argv = sys.argv
    seen = {}

    def fake_main(argv):
        seen["argv"] = list(argv)
        seen["C64_REU"] = os.environ.get("C64_REU")
        return 0

    try:
        for k, v in env_overrides.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for k in ("C64_REU", "C64_SKIP_BUILD"):
            if k not in env_overrides:
                os.environ.pop(k, None)
        live.main = fake_main
        ds.teardown_device = lambda *a, **k: {"turbo": 1, "reu": True,
                                              "reset": "verified"}
        sys.argv = ["test_wire_encryption_live.py", "--host", "10.0.0.1",
                    "--seed", "1", *extra_argv]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = wire.main()
        assert rc == 0, rc
        seen["stdout"] = buf.getvalue()
        return seen
    finally:
        live.main, ds.teardown_device, sys.argv = saved_main, saved_td, saved_argv
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def flag(argv, name):
    """The value of `name` in argv, or None if it is absent.

    Not argv.index: a missing flag is the defect this file exists to catch,
    and it must be REPORTED as a failed check, not raised as a ValueError
    from whichever check happens to look for it second.
    """
    return argv[argv.index(name) + 1] if name in argv else None


def main():
    # --- the default arm: no environment, no flags ------------------------
    seen = run_tool({})
    argv = seen["argv"]
    check(seen["C64_REU"] == "0",
          "default pins C64_REU=0 (the build)", str(seen["C64_REU"]))
    check(flag(argv, "--reu") == "off",
          "default passes --reu off (the attached device)", " ".join(argv))
    check(flag(argv, "--turbo") == "48",
          "default is still 48 MHz", " ".join(argv))
    # The build and the device must AGREE. A REU=0 build with --reu on only
    # warns, and a REU build with --reu off is refused — but neither guard
    # can help if the tool selects a mismatched pair itself.
    check(seen["C64_REU"] == "0" and flag(argv, "--reu") == "off",
          "the build knob and the REU flag select the SAME arm")

    # --- an operator asking for the REU arm still gets a coherent pair ----
    seen = run_tool({"C64_REU": "1"})
    argv = seen["argv"]
    check(flag(argv, "--reu") == "on",
          "C64_REU=1 carries through to --reu on, not a mismatched pair",
          " ".join(argv))

    # --- the #69 warning must fire EXACTLY on the arm it is about --------
    #
    # Both directions, because a warning that always fires is noise and a
    # warning that never fires is absent, and neither is distinguishable
    # from the other by looking only at the case you had in mind. #98 asked
    # for a refusal here; the tool warns instead and the reasoning is in
    # test_wire_encryption_live. Either way the operator has to be TOLD,
    # and "told" is a testable property.
    seen = run_tool({"C64_REU": "1"})
    check("#69" in seen["stdout"],
          "REU=1 at 48 MHz warns, naming #69")
    check("4011c97c" in seen["stdout"],
          "and names the firmware the null was measured on, so the warning "
          "is checkable rather than folklore")

    seen = run_tool({})
    check("#69" not in seen["stdout"],
          "the default arm does NOT warn — a warning on every run is a "
          "warning nobody reads")

    seen = run_tool({"C64_REU": "1"}, extra_argv=("--turbo", "1"))
    check("#69" not in seen["stdout"],
          "REU=1 at 1 MHz does NOT warn: #69 is a turbo fault, and warning "
          "here would make the warning mean 'REU' rather than '#69'")

    bad = [l for ok, l in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    for l in bad:
        print(f"  FAILED: {l}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
