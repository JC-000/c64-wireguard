#!/usr/bin/env python3
"""Run all regression test suites with bounded parallelism.

Builds once up front. Launches up to MAX_PARALLEL test processes at a
time, staggered so VICE boots don't stampede each other, and refills
the pool as each suite finishes. Sets C64_SKIP_BUILD=1 so individual
test scripts skip their own make clean && make.

Parallelism cap rationale: the c64-test-harness allocates VICE ports
from a 10-slot pool, so we cap at 5 to leave half the pool free for
other agents that may be running concurrently. Raising the cap past 10
causes port-allocation collisions; past ~8 the wall-clock win gets
eaten by sporadic "Main menu did not appear" timeouts as too many
VICE instances compete for CPU during boot.
"""

import os
import subprocess
import sys
import time

TESTS = [
    ("session",    ["tools/test_session.py", "--seed", "51820", "--verbose"]),
    ("transport",  ["tools/test_transport.py", "--seed", "7539"]),
    ("blake2s",    ["tools/test_blake2s.py", "--seed", "7539"]),
    ("chacha",     ["tools/test_chacha20_poly1305.py", "--seed", "7539"]),
    ("fe25519",    ["tools/test_fe25519.py", "--seed", "7539"]),
    ("networking", ["tools/test_networking.py", "--seed", "7539"]),
    ("handshake",  ["tools/test_handshake.py", "--seed", "7539"]),
    ("phase7",     ["tools/test_phase7.py", "--seed", "7"]),
    ("disk_config",["tools/test_disk_config.py", "--seed", "7"]),
    ("phase8_psk", ["tools/test_phase8_psk.py", "--seed", "7"]),
    ("mtu",        ["tools/test_mtu.py", "--seed", "1500"]),
    ("tai64n",     ["tools/test_tai64n.py", "--verbose"]),
    ("mac2",       ["tools/test_mac2_integration.py", "--verbose"]),
    # Added 2026-08-14. These are ordinary VICE suites that were simply never
    # listed here, so the gate documented in docs/library-ingestion-architecture.md
    # ("run_regression.py must pass") covered 13 of the 27 tools/test_*.py
    # scripts. Two of the omissions mattered: blake2s_keylen (the Bug #2
    # regression test — a regression test outside the gate stops protecting
    # anything) and build_both_backends (the only suite validating labels.txt
    # format; it had been failing since the v0.8.0 pin landed in v1.0.0 and
    # nothing reported it).
    ("blake2s_keylen", ["tools/test_blake2s_keylen_regression.py"]),
    ("replay_window",  ["tools/test_replay_window.py"]),
    ("key_rotation",   ["tools/test_key_rotation.py"]),
    ("endpoint_update",["tools/test_endpoint_update.py"]),
    ("type2_slow",     ["tools/test_type2_slow.py"]),
    # PR #91's two handshake-recovery behaviours (the 90 s deadline and
    # @hs_fail -> session_reset). Nothing asserted either, and the #95 severity
    # downgrade rests entirely on them: revert either and #95 returns to its
    # filed severity with the gate still green. Fast — ~8 s, zero X25519.
    ("hs_recovery",    ["tools/test_issue_95_handshake_recovery.py"]),
    # The live tools themselves cannot run here, but the seam they all hang
    # from can be checked without hardware — and if it breaks, every one of
    # them breaks while this gate stays green. Import-only, milliseconds.
    ("live_seams",     ["tools/test_live_tool_seams.py"]),
    # Issue #103. LIB_X25519_INIT_CODE is now reclaimed as APP_BSS rather
    # than merely documented as reclaimable, which is only safe while the
    # cold init is genuinely dead after boot. This suite is the red/green
    # for that: it checks the span is erased, that the tables the erased
    # code built are still correct, and — the red half — that deliberately
    # forcing the one guarded branch back into the span does NOT return.
    # Without the red half, a green gate would be consistent with the code
    # still being needed and simply never exercised.
    ("cold_reclaim",   ["tools/test_cold_segment_reclaim.py"]),
    # NOT listed, deliberately: tools/test_uci_*_live.py and
    # tools/test_wg_responder*.py need real hardware or a live responder.
]

# Suites that MUTATE the shared build tree. These CANNOT run in the parallel
# pool: while they rebuild, build/wireguard.prg and build/labels.txt are
# transiently absent or half-written, and whichever concurrent suite happens to
# read them fails with a FileNotFoundError that has nothing to do with the code
# under test. The failure is timing-dependent, so it passes often enough to look
# fine — it bit us only once these suites were added to the gate.
#
# Two distinct reasons a suite lands here:
#   * ignores C64_SKIP_BUILD and runs `make` regardless (x25519, write_bytes)
#   * needs a tree built differently from the pool's default: uci_stub requires
#     BACKEND=uci, and both_backends rebuilds every backend in turn
#
# uci_stub previously "passed" in the pool only by accident — both_backends
# happened to run first and leave a BACKEND=uci tree behind. It was never
# actually testing against a tree it had asked for.
#
# They run sequentially after the pool drains, and WITHOUT C64_SKIP_BUILD so
# each builds exactly what it needs. The tree is restored to the default
# afterwards.
SERIAL_TESTS = [
    ("x25519",         ["tools/test_x25519.py"]),
    ("write_bytes",    ["tools/test_write_bytes_limit.py"]),
    ("uci_stub",       ["tools/test_uci_backend_stub.py"]),
    ("both_backends",  ["tools/test_build_both_backends.py"]),
]

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# Max concurrent VICE instances from this runner. The harness port pool
# holds 10 slots; keep headroom for concurrent agents.
MAX_PARALLEL = 5

# Seconds between launches even when under the concurrency cap. Lets
# the first VICE instance get past its initial port bind + LOAD + RUN
# burst before the next one starts competing for CPU.
STAGGER_SECONDS = 2.0

# Poll interval while waiting for a slot to free up.
POLL_SECONDS = 1.0

# Per-suite subprocess timeout (seconds).
SUITE_TIMEOUT = 1800


def launch(name, cmd, env):
    p = subprocess.Popen(
        ["python3"] + cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    print(f"  → launch {name:15s} (PID {p.pid})")
    return p


def reap(running, results):
    """Move any finished processes out of `running` into `results`."""
    still_running = []
    for name, proc, started in running:
        rc = proc.poll()
        if rc is None:
            still_running.append((name, proc, started))
        else:
            out = proc.communicate(timeout=5)[0].decode(errors="replace")
            elapsed = time.monotonic() - started
            results[name] = (rc, out)
            status = "PASS" if rc == 0 else "FAIL"
            print(f"  ← {status:4s} {name:15s}  ({elapsed:.0f}s)")
    return still_running


def main():
    os.chdir(PROJECT_ROOT)

    # Build once
    print("Building...")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("Build OK\n")

    env = os.environ.copy()
    env["C64_SKIP_BUILD"] = "1"

    print(f"Running {len(TESTS)} parallel + {len(SERIAL_TESTS)} serial suites  "
          f"(max {MAX_PARALLEL} concurrent, {STAGGER_SECONDS:.0f}s stagger)\n")

    pending = list(TESTS)
    running = []
    results = {}

    while pending or running:
        running = reap(running, results)
        while pending and len(running) < MAX_PARALLEL:
            name, cmd = pending.pop(0)
            running.append((name, launch(name, cmd, env), time.monotonic()))
            time.sleep(STAGGER_SECONDS)
        if running:
            time.sleep(POLL_SECONDS)

    # Hard timeout safety-net for any straggler that somehow deadlocked
    # (shouldn't fire in practice — reap() completes processes as they
    # exit — but bounds total wall-clock if a test hangs).
    start = time.monotonic()
    while running and time.monotonic() - start < SUITE_TIMEOUT:
        running = reap(running, results)
        time.sleep(POLL_SECONDS)

    # Build-tree mutators, one at a time, only once the pool is empty. No
    # C64_SKIP_BUILD: each of these needs to build the tree it actually tests.
    serial_env = os.environ.copy()
    serial_env.pop("C64_SKIP_BUILD", None)
    for name, cmd in SERIAL_TESTS:
        proc = launch(name, cmd, serial_env)
        pending_one = [(name, proc, time.monotonic())]
        while pending_one:
            pending_one = reap(pending_one, results)
            if pending_one:
                time.sleep(POLL_SECONDS)

    if SERIAL_TESTS:
        # Those suites left the tree on whichever backend they built last.
        # Restore the default so a subsequent `make run` or manual test does
        # not silently use it.
        subprocess.run(["make", "clean"], capture_output=True)
        subprocess.run(["make"], capture_output=True)

    print("\n" + "=" * 70)
    all_ok = True
    for name, (rc, out) in results.items():
        lines = out.strip().split("\n")
        pid_line = [l for l in lines if "VICE PID=" in l]
        pid_info = pid_line[0].strip() if pid_line else "no PID info"
        result_line = [l for l in lines if "Results:" in l or "All tests passed" in l]
        summary = (result_line[-1].strip() if result_line
                   else (lines[-1].strip() if lines else "(no output)"))
        status = "PASS" if rc == 0 else "FAIL"
        if rc != 0:
            all_ok = False
        print(f"  {status} {name:15s} {pid_info:40s} {summary}")

    print("=" * 70)
    if all_ok:
        print(f"All {len(TESTS) + len(SERIAL_TESTS)} suites passed!")
    else:
        print("\nFailed suites:")
        for name, (rc, out) in results.items():
            if rc != 0:
                print(f"\n=== {name} (exit {rc}) ===")
                print(out[-2000:])

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
