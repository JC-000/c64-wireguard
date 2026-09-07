#!/usr/bin/env python3
"""Prove the shared teardown helper (issue #134) — and prove it can FAIL.

No device: the helper's contract is exercised against fake clients that
model the three outcomes a real one produces. That is deliberate. The claim
under test is not "the U64 resets" (the firmware's job) but "this helper
distinguishes a reset that took from one that did not", and a fake is the
only way to produce the second case on demand — a real device that resets
correctly cannot demonstrate the alarm.

The cases, and why each is here:

  reset_takes        RAMTAS zeroes $03FF -> "verified".
  reset_ignored      the device 204s the request and the 6510 keeps
                     running, so the sentinel survives -> "failed". THIS
                     IS THE MUTATION: the exact silent failure that
                     `client.reset()` with no read-back reports as success.
  write_mem_dead     the sentinel never lands, so $03FF reads $00 both
                     before and after -> "unverified", NOT "verified".
                     Without the arming check this case reads as a pass
                     for the same reason the $DE00 host probe did: the
                     instrument assumes the property it measures.
  turbo_throws       set_turbo_mhz raises (an aborting run against a flaky
                     device) and the reset MUST still be reached.
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import device_session as ds

ADDR = ds.RESET_SENTINEL_ADDR
results = []


def check(ok, label, detail=""):
    results.append((ok, label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail else ""))
    return ok


class FakeClient:
    """A C64 whose reset behaviour is configurable."""

    def __init__(self, reset_takes=True, writable=True, reset_raises=False):
        self.mem = {}
        self.reset_takes = reset_takes
        self.writable = writable
        self.reset_raises = reset_raises
        self.resets = 0
        self.host = "fake"

    def write_mem(self, addr, data):
        if not self.writable:
            return                      # 204 accepted, nothing written
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def read_mem(self, addr, length):
        return bytes(self.mem.get(addr + i, 0x00) for i in range(length))

    def reset(self):
        self.resets += 1
        if self.reset_raises:
            raise RuntimeError("PUT /v1/machine:reset -> 500")
        if self.reset_takes:
            # RAMTAS: zero $0002-$0101 and $0200-$03FF.
            for a in list(self.mem):
                if 0x0002 <= a <= 0x0101 or 0x0200 <= a <= 0x03FF:
                    self.mem[a] = 0x00


def main():
    ds.log.setLevel(50)                 # quiet: the helper's own logging is
                                        # exercised, not asserted, here
    # --- GREEN: a reset that takes is reported as verified ---------------
    c = FakeClient(reset_takes=True)
    st = ds.reset_and_verify(c, settle_s=0.0)
    check(st == "verified", "a reset that takes -> 'verified'", st)
    check(c.resets == 1, "reset() was actually issued", f"{c.resets}")
    check(c.mem.get(ADDR) == 0x00, f"sentinel at ${ADDR:04X} was cleared")

    # --- RED (the mutation): the 6510 never restarts ----------------------
    c = FakeClient(reset_takes=False)
    st = ds.reset_and_verify(c, settle_s=0.0)
    check(st == "failed", "a reset that does NOT take -> 'failed'", st)
    check(c.mem.get(ADDR) == ds.RESET_SENTINEL_VALUE,
          "the sentinel survived, which is what proves it")

    # --- RED: the check cannot arm, so it must not claim success ---------
    c = FakeClient(reset_takes=True, writable=False)
    st = ds.reset_and_verify(c, settle_s=0.0)
    check(st == "unverified",
          "sentinel that will not land -> 'unverified', not 'verified'", st)
    check(c.resets == 1, "the reset is still ISSUED when unverifiable")

    # --- RED: reset() itself raises ---------------------------------------
    c = FakeClient(reset_raises=True)
    st = ds.reset_and_verify(c, settle_s=0.0)
    check(st == "failed", "reset() raising -> 'failed'", st)

    # --- the #134 defect proper: a throwing clock must not skip the reset -
    import c64_test_harness.backends.ultimate64_helpers as H
    orig = H.set_turbo_mhz

    def boom(*a, **k):
        raise RuntimeError("device flaky mid-abort")

    H.set_turbo_mhz = boom
    try:
        c = FakeClient(reset_takes=True)
        st = ds.teardown_device("fake", client=c)
    finally:
        H.set_turbo_mhz = orig
    check(c.resets == 1,
          "a throwing set_turbo_mhz does NOT skip the reset", f"{c.resets}")
    check(st["reset"] == "verified",
          "and the reset is still verified", str(st))
    check(st["turbo"] is None, "the clock failure is still reported", str(st))

    # --- and the case that reaches the OUTER scope: the harness import
    # itself fails (a broken venv, a partial install — the shape that took
    # down every restore path at once). The reset lives in a `finally`
    # precisely so this cannot skip it. Without that, this is the mutation
    # that survives, because a throw INSIDE the clock's own try is caught
    # locally and never reaches the enclosing block.
    import types
    key = "c64_test_harness.backends.ultimate64_helpers"
    saved = sys.modules.get(key)
    sys.modules[key] = types.ModuleType(key)      # has none of the names
    try:
        c = FakeClient(reset_takes=True)
        st = ds.teardown_device("fake", client=c)
    finally:
        if saved is not None:
            sys.modules[key] = saved
        else:
            del sys.modules[key]
    check(c.resets == 1,
          "an ImportError in the restore path does NOT skip the reset",
          f"{c.resets}")
    check(st["reset"] == "verified",
          "and it is still verified after that", str(st))

    # --- THE NO-CLIENT PATH, which this suite did not exercise at all ----
    #
    # Every case above passes `client=`, so all of them run _body directly
    # and none of them go anywhere near locked_client. The first version of
    # this file was 13/13 green while teardown_device raised ImportError
    # and PermissionError out of the branch its own two lock-taking callers
    # use — test_wire_encryption_live and test_config_reload_live, both from
    # a `finally`, where a traceback REPLACES whatever ended the session.
    #
    # A suite that does not exercise a path cannot catch a defect on it,
    # and "13/13" reads exactly like coverage. That is the same shape as
    # the two assertions that claimed uci_send_part existed without ever
    # executing it.
    #
    # These cases take the no-client branch and require the contract to
    # hold on it: never raise, and never touch the device unserialised.
    import types
    key = "c64_test_harness"

    def with_broken_harness(fn):
        """Run fn() with the harness package stubbed to an empty module."""
        saved = {k: v for k, v in sys.modules.items() if k.startswith(key)}
        for k in list(sys.modules):
            if k.startswith(key):
                del sys.modules[k]
        sys.modules[key] = types.ModuleType(key)          # no DeviceLock
        try:
            return fn()
        finally:
            for k in list(sys.modules):
                if k.startswith(key):
                    del sys.modules[k]
            sys.modules.update(saved)

    raised = None
    st = None
    try:
        st = with_broken_harness(lambda: ds.teardown_device("10.0.0.1"))
    except BaseException as exc:                              # noqa: BLE001
        raised = exc
    check(raised is None,
          "no-client path: a broken harness import does NOT raise out of "
          "teardown_device", repr(raised))
    check(st == {"turbo": None, "reu": False, "reset": None},
          "no-client path: it reports having done nothing, rather than "
          "half-reporting success", str(st))

    # The lock MECHANISM failing (not a busy peer) must also be survivable,
    # and must NOT fall through to touching the device anyway.
    import device_session as _ds
    saved_lc = _ds.locked_client
    touched = []

    class _ExplodingLock:
        def __init__(self, host):
            self.host = host

        def acquire_or_raise(self, timeout=None):
            raise PermissionError("lockfile directory is not writable")

        def release(self):
            touched.append("release")

    import contextlib

    def probe_acquire_failure():
        """Drive the real locked_client with a lock that raises non-timeout."""
        import c64_test_harness as H
        saved_dl = H.DeviceLock
        H.DeviceLock = _ExplodingLock
        try:
            with _ds.locked_client("10.0.0.1", purpose="probe") as c:
                return c
        finally:
            H.DeviceLock = saved_dl

    raised = None
    got = "sentinel"
    try:
        got = probe_acquire_failure()
    except BaseException as exc:                              # noqa: BLE001
        raised = exc
    check(raised is None,
          "locked_client: a non-timeout error from acquire_or_raise does "
          "NOT escape", repr(raised))
    check(got is None,
          "locked_client: and it yields None, never an unlocked client",
          repr(got))

    # --- the client-construction guard: THE ONE THAT CAN STRAND THE LOCK -
    #
    # This branch holds the DeviceLock when it decides to give up, so it is
    # the only path in the helper that can leave a shared device locked by
    # a process that has moved on. Every other failure either has not
    # acquired yet or reaches the `finally`. That is the widest blast
    # radius in the file — a stranded lock stops every lane, and #58's
    # note is emphatic that hand-removing a lockfile is never the answer —
    # so it gets its own case rather than being assumed correct because it
    # reads correct.
    lock_events = []

    class _OkLock:
        def __init__(self, host):
            self.host = host

        def acquire_or_raise(self, timeout=None):
            lock_events.append("acquire")

        def release(self):
            lock_events.append("release")

    def probe_client_failure():
        import c64_test_harness as H
        from c64_test_harness.backends import ultimate64_client as UC
        saved_dl, saved_cl = H.DeviceLock, UC.Ultimate64Client

        def boom_client(*a, **k):
            raise OSError("no route to host")

        H.DeviceLock = _OkLock
        UC.Ultimate64Client = boom_client
        try:
            with _ds.locked_client("10.0.0.1", purpose="probe") as c:
                return c
        finally:
            H.DeviceLock, UC.Ultimate64Client = saved_dl, saved_cl

    raised = None
    got = "sentinel"
    try:
        got = probe_client_failure()
    except BaseException as exc:                              # noqa: BLE001
        raised = exc
    check(raised is None,
          "locked_client: a failing Ultimate64Client() does NOT escape",
          repr(raised))
    check(got is None,
          "locked_client: and it yields None rather than a broken client",
          repr(got))
    check(lock_events == ["acquire", "release"],
          "locked_client: THE LOCK IS RELEASED on that path — it is held "
          "when the decision to give up is made, and the `finally` below "
          "is not reached from there", str(lock_events))

    bad = [l for ok, l in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    if bad:
        for l in bad:
            print(f"  FAILED: {l}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
