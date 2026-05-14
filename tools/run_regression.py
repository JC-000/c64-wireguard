#!/usr/bin/env python3
"""Run all regression test suites in parallel with staggered launch.

Builds once before launching tests. Sets C64_SKIP_BUILD=1 so individual
test scripts skip their own make clean && make.
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
STAGGER_DELAY = 2.0  # seconds between launches for port binding


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

    # Set env var so test scripts skip their own build
    env = os.environ.copy()
    env["C64_SKIP_BUILD"] = "1"

    procs = []
    for name, cmd in TESTS:
        p = subprocess.Popen(
            ["python3"] + cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )
        procs.append((name, p))
        print(f"Launched {name} (PID {p.pid})")
        time.sleep(STAGGER_DELAY)

    results = {}
    for name, p in procs:
        out = p.communicate(timeout=600)[0].decode()
        results[name] = (p.returncode, out)

    print("\n" + "=" * 70)
    all_ok = True
    for name, (rc, out) in results.items():
        lines = out.strip().split("\n")
        pid_line = [l for l in lines if "VICE PID=" in l]
        pid_info = pid_line[0].strip() if pid_line else "no PID info"
        result_line = [l for l in lines if "Results:" in l or "All tests passed" in l]
        summary = result_line[-1].strip() if result_line else (lines[-1].strip() if lines else "(no output)")
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
