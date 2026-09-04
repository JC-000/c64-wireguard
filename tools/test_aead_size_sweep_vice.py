#!/usr/bin/env python3
"""test_aead_size_sweep_vice.py — length sweep of the LINKED AEAD (issue #128).

Question: does our ChaCha20-Poly1305 produce a wrong result at specific
plaintext lengths? Inbound WireGuard replies of certain sizes fail AEAD on
hardware while both smaller and larger sizes succeed, and size does not
order the outcomes.

This drives `aead_encrypt` / `aead_decrypt` in the REAL linked firmware
(build/wireguard.prg — Profile B rolled-outer chacha archive plus x25519's
shared ct_mul_8x8, which is what the poly1305 multiply actually calls), not
the sibling library's standalone Profile A test PRG. It reproduces the call
shape src/wg/transport.s uses on the receive path: empty AAD, in-place data
at tp_packet+16, tag in aead_tag, length in aead_data_len.

Ground truth is pyca/cryptography, independent of both the assembly and the
Python reference implementation in tools/test_chacha20_poly1305.py.

Usage:
    python3 tools/test_aead_size_sweep_vice.py --prg build/wireguard.prg \
        --labels build/labels.txt [--reu] [--seed S] [--sizes a,b,c]
"""

import argparse
import os
import random
import struct
import sys
import time

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr,
)
from vice_util import binary_wait_for_boot_ready

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


# --- Lengths under suspicion -------------------------------------------
#
# Observed udp_recv_len values on hardware: 99, 536, 1008, 1109, 1191,
# 1247, 1338. transport.s computes tp_payload_len = udp_recv_len - 32
# (16-byte Type-4 header + 16-byte Poly1305 tag) and passes THAT to
# aead_decrypt, so the payload lengths actually fed to the AEAD are:
PAYLOAD_LENS = [67, 504, 976, 1077, 1159, 1215, 1306]

# The "padded to a 16-byte multiple" reading of the same observations.
# Note these are NOT what transport.s passes — only one of the observed
# udp_recv_len values (1008) is even congruent to 32 mod 16, so the peer
# is plainly not padding to 16 as assumed. Tested anyway, cheaply.
PADDED_LENS = [80, 512, 1088, 1168, 1216, 1312]

# Dense sweep across the whole suspect band, to find the true boundary of
# any defect rather than only the seven observed points.
SWEEP_LENS = list(range(960, 1329, 16))

# Non-multiples of 16, to exercise partial-block tail handling (both the
# ChaCha20 keystream tail and the Poly1305 zero-padded final block).
TAIL_LENS = [961, 975, 977, 1001, 1063, 1105, 1201, 1279, 1327, 1330]


def default_sizes():
    return sorted(set(PAYLOAD_LENS + PADDED_LENS + SWEEP_LENS + TAIL_LENS))


def pyca_encrypt(key, nonce, aad, pt):
    combined = ChaCha20Poly1305(key).encrypt(nonce, pt, aad if aad else None)
    return combined[:-16], combined[-16:]


def c64_aead_encrypt(transport, labels, buf, key, nonce, pt):
    """Encrypt in place at *buf* with empty AAD (the transport.s shape)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)
    write_bytes(transport, labels["aead_aad_len"], bytes([0]))
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, buf, pt)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], struct.pack('<H', len(pt)))

    regs = jsr(transport, labels["aead_encrypt"], timeout=900.0)

    ct = read_bytes(transport, buf, len(pt))
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    return ct, tag, regs.get("A")


def c64_aead_decrypt(transport, labels, buf, key, nonce, ct, tag):
    """Decrypt in place at *buf*; returns (plaintext, status_A)."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)
    write_bytes(transport, labels["aead_aad_len"], bytes([0]))
    write_bytes(transport, labels["aead_aad_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, buf, ct)
    write_bytes(transport, labels["aead_data_ptr"],
                bytes([buf & 0xFF, buf >> 8]))
    write_bytes(transport, labels["aead_data_len"], struct.pack('<H', len(ct)))
    write_bytes(transport, labels["aead_tag"], tag)

    regs = jsr(transport, labels["aead_decrypt"], timeout=900.0)

    pt = read_bytes(transport, buf, len(ct))
    return pt, regs.get("A")


def first_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    if len(a) != len(b):
        return min(len(a), len(b))
    return None


def run_sweep(transport, labels, sizes, rng, sabotage=False):
    buf = labels["tp_packet"] + 16      # exactly what transport.s decrypts
    tp_end = labels["tp_packet"] + 1500
    print(f"data buffer = tp_packet+16 = ${buf:04X} "
          f"(tp_packet ends ${tp_end:04X})")

    results = []
    passed = failed = 0

    for n in sizes:
        if buf + n > tp_end:
            print(f"SKIP {n}: would overrun tp_packet")
            continue

        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        pt = bytes(rng.randint(0, 255) for _ in range(n))

        want_ct, want_tag = pyca_encrypt(key, nonce, b"", pt)

        # --prove-detector: hand the C64 a plaintext that differs from the
        # one pyca encrypted, in the LAST byte. Every check below must go
        # red; if any stays green the check is coinciding, not testing.
        c64_pt = pt
        if sabotage and n:
            c64_pt = pt[:-1] + bytes([pt[-1] ^ 0x5A])

        t0 = time.time()
        got_ct, got_tag, _ = c64_aead_encrypt(transport, labels, buf,
                                              key, nonce, c64_pt)
        enc_ct_ok = got_ct == want_ct
        enc_tag_ok = got_tag == want_tag

        dec_ct = want_ct
        if sabotage and n:
            dec_ct = want_ct[:-1] + bytes([want_ct[-1] ^ 0x5A])
        got_pt, status = c64_aead_decrypt(transport, labels, buf,
                                          key, nonce, dec_ct, want_tag)
        dec_pt_ok = got_pt == pt
        dec_status_ok = (status == 0)
        dt = time.time() - t0

        ok = enc_ct_ok and enc_tag_ok and dec_pt_ok and dec_status_ok
        if ok:
            passed += 1
            print(f"PASS n={n:5d}  enc ct+tag match, dec pt match, A=$00"
                  f"   [{dt:5.1f}s]")
        else:
            failed += 1
            print(f"FAIL n={n:5d}  enc_ct={enc_ct_ok} enc_tag={enc_tag_ok} "
                  f"dec_pt={dec_pt_ok} dec_A={status!r}   [{dt:5.1f}s]")
            if not enc_ct_ok:
                d = first_diff(got_ct, want_ct)
                print(f"       ct first differs at byte {d} "
                      f"(block {d // 64}, offset {d % 64})")
                print(f"       want {want_ct[max(0,d-4):d+12].hex()}")
                print(f"       got  {got_ct[max(0,d-4):d+12].hex()}")
            if not enc_tag_ok:
                print(f"       want tag {want_tag.hex()}")
                print(f"       got  tag {got_tag.hex()}")
            if not dec_pt_ok:
                d = first_diff(got_pt, pt)
                print(f"       pt first differs at byte {d}")
            print(f"       key={key.hex()} nonce={nonce.hex()}")

        results.append((n, ok, enc_ct_ok, enc_tag_ok, dec_pt_ok, status))

    return passed, failed, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prg", default=os.path.join(PROJECT_ROOT, "build",
                                                  "wireguard.prg"))
    ap.add_argument("--labels", default=os.path.join(PROJECT_ROOT, "build",
                                                     "labels.txt"))
    ap.add_argument("--reu", action="store_true",
                    help="attach a 512K REU (required by a REU=1 build)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--prove-detector", action="store_true",
                    help="deliberately corrupt one byte so every check must fail")
    ap.add_argument("--sizes", default=None,
                    help="comma-separated lengths (default: full sweep)")
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    rng = random.Random(seed)
    print(f"seed={seed}  prg={args.prg}  reu={args.reu}")

    labels = Labels.from_file(args.labels)
    for name in ("aead_encrypt", "aead_decrypt", "aead_key", "aead_nonce",
                 "aead_aad_ptr", "aead_aad_len", "aead_data_ptr",
                 "aead_data_len", "aead_tag", "poly1305_tag", "tp_packet"):
        if labels.address(name) is None:
            print(f"FATAL: label {name} missing from {args.labels}")
            sys.exit(1)

    sizes = ([int(s) for s in args.sizes.split(",")]
             if args.sizes else default_sizes())
    print(f"{len(sizes)} lengths: {sizes}")

    extra = ["-reu", "-reusize", "512"] if args.reu else []
    config = ViceConfig(prg_path=args.prg, warp=True, ntsc=True, sound=False,
                        extra_args=extra)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport
        if binary_wait_for_boot_ready(transport, labels, timeout=240.0) is None:
            print("FATAL: main menu did not appear")
            sys.exit(1)
        write_bytes(transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
        print("VICE ready")

        passed, failed, results = run_sweep(transport, labels, sizes, rng,
                                            sabotage=args.prove_detector)
        mgr.release(inst)

    print("=" * 66)
    print(f"Results: {passed}/{passed + failed} lengths fully matched pyca, "
          f"{failed} failed")
    if failed:
        print("failing lengths: " +
              ", ".join(str(n) for n, ok, *_ in results if not ok))
    print("=" * 66)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
