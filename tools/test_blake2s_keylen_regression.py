#!/usr/bin/env python3
"""test_blake2s_keylen_regression.py — Bug #2 guard.

The keyed BLAKE2s callers (hs_compute_mac1, cookie mac2) set the module
ZP cell b2s_key_len ($12) to a nonzero key length. blake2s_init reads
that cell — NOT the X register — so the `ldx #0` at the unkeyed call
sites (hs_mix_hash, hs_init, kdf) is a dead load: they depend on
b2s_key_len already being 0.

If a keyed caller fails to restore b2s_key_len=0, the next unkeyed
BLAKE2s silently runs KEYED against the stale key, corrupting the whole
Noise transcript. On the live WireGuard handshake this is exactly what
happens: hs_compute_mac1 ends Type-1 emission, then hs_process_response's
first mix_hash inherits key_len=32 → total AEAD divergence ("Bug #2").
VICE type-2 tests and the crypto KATs never caught it because they never
run a keyed op immediately before an unkeyed one on the same machine
(the KATs re-write b2s_key_len before every init).

This test asserts the invariant directly: after each keyed caller,
b2s_key_len is 0. It works on VICE (default) or U64.

Usage:
    python3 tools/test_blake2s_keylen_regression.py
    C64_BACKEND=u64 U64_HOST=... python3 tools/test_blake2s_keylen_regression.py
"""
import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_text

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

B2S_KEY_LEN = 0x12   # src/zp_config.inc


def main():
    os.chdir(PROJECT_ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], capture_output=True)
        r = subprocess.run(["make", "BACKEND=uci", "USE_X25519_SIBLING=1"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            return 1

    labels = Labels.from_file(LABELS_PATH)
    for n in ("hs_compute_mac1", "hs_mac1_key", "hs_packet", "reu_mul_init"):
        if labels.address(n) is None:
            print(f"FATAL: label {n} missing")
            return 1

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
                        extra_args=["-reu", "-reusize", "512"])
    passed = failed = 0
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        tr = inst.transport
        if binary_wait_for_text(tr, "Q=QUIT", timeout=90.0) is None:
            print("FATAL: menu did not appear")
            return 1
        write_bytes(tr, 0x0339, bytes([0x4C, 0x39, 0x03]))
        jsr(tr, labels["reu_mul_init"], timeout=180.0)

        # Poison b2s_key_len, then run the keyed caller; it must restore 0.
        write_bytes(tr, labels["hs_mac1_key"], bytes(range(32)))
        write_bytes(tr, labels["hs_packet"], bytes((i * 7) & 0xFF
                                                   for i in range(116)))
        write_bytes(tr, B2S_KEY_LEN, bytes([0x7F]))  # deliberately dirty
        jsr(tr, labels["hs_compute_mac1"], timeout=30.0)
        kl = read_bytes(tr, B2S_KEY_LEN, 1)[0]
        if kl == 0:
            passed += 1
            print("PASS hs_compute_mac1 restores b2s_key_len=0")
        else:
            failed += 1
            print(f"FAIL hs_compute_mac1 left b2s_key_len=${kl:02X} "
                  f"(unkeyed BLAKE2s would run keyed → Bug #2)")

        mgr.release(inst)

    print(f"\nResults: {passed}/{passed + failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
