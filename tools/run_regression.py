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

    print(f"Running {len(TESTS)} suites  "
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
        print(f"All {len(TESTS)} suites passed!")
    else:
        print("\nFailed suites:")
        for name, (rc, out) in results.items():
            if rc != 0:
                print(f"\n=== {name} (exit {rc}) ===")
                print(out[-2000:])

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
