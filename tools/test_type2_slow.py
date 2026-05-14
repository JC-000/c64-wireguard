#!/usr/bin/env python3
"""test_type2_slow.py — Parallel slow Type 2 handshake tests.

Runs 6 independent Type 2 trials (5 valid + 1 tampered) on separate VICE
instances in parallel.  Each trial calls session_handle_packet which does
3x X25519 (~100 min each in VICE warp), so the timeout is ~7 hours.

Usage:
    python3 tools/test_type2_slow.py [--seed S] [--verbose] [--workers N]
"""

import hashlib
import hmac as hmac_mod
import os
import random
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# WireGuard protocol constants
WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
WG_LABEL_MAC1 = b"mac1----"

# Timeout for session_handle_packet with 3x X25519 (~7 hours)
TYPE2_TIMEOUT = 25000.0


# ============================================================================
# Crypto helpers (same as test_session.py)
# ============================================================================

def blake2s_256(data):
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_hmac(key, data):
    """HMAC-BLAKE2s-256."""
    return hmac_mod.new(key, data, lambda: hashlib.blake2s(digest_size=32)).digest()


def kdf_n(c, input_data, n):
    """WireGuard KDF: HMAC-based extract-then-expand.
    Returns n outputs (1, 2, or 3).
    """
    t0 = blake2s_hmac(c, input_data)
    t1 = blake2s_hmac(t0, b'\x01')
    if n == 1:
        return (t1,)
    t2 = blake2s_hmac(t0, t1 + b'\x02')
    if n == 2:
        return (t1, t2)
    t3 = blake2s_hmac(t0, t2 + b'\x03')
    return (t1, t2, t3)


def mix_hash(h, data):
    return blake2s_256(h + data)


def py_noise_responder_from_state(c, h, init_ephem_pub, init_static_pub_bytes,
                                   resp_static_priv_bytes, resp_static_pub_bytes,
                                   init_sender_idx, psk=None):
    """Build Type 2 from mid-handshake state (after Type 1 processing).

    Returns: (type2_packet, initiator_send_key, initiator_recv_key)
    """
    if psk is None:
        psk = b'\x00' * 32
    resp_ephem_priv = X25519PrivateKey.generate()
    resp_ephem_pub = resp_ephem_priv.public_key().public_bytes_raw()
    resp_sender_idx = os.urandom(4)

    init_ephem_pub_key = X25519PublicKey.from_public_bytes(init_ephem_pub)
    init_static_pub_key = X25519PublicKey.from_public_bytes(init_static_pub_bytes)

    h = mix_hash(h, resp_ephem_pub)
    (c,) = kdf_n(c, resp_ephem_pub, 1)

    dh3 = resp_ephem_priv.exchange(init_ephem_pub_key)
    (c,) = kdf_n(c, dh3, 1)

    dh4 = resp_ephem_priv.exchange(init_static_pub_key)
    (c,) = kdf_n(c, dh4, 1)

    # IKpsk2 PSK mixing
    c, t, k = kdf_n(c, psk, 3)
    h = mix_hash(h, t)

    nonce = b'\x00' * 12
    aead = ChaCha20Poly1305(k)
    encrypted_nothing = aead.encrypt(nonce, b'', h)

    h = mix_hash(h, encrypted_nothing)

    i_send, i_recv = kdf_n(c, b'', 2)

    # Build Type 2 packet
    type2 = bytearray(92)
    type2[0] = 2
    type2[1:4] = b'\x00' * 3
    type2[4:8] = resp_sender_idx
    type2[8:12] = init_sender_idx
    type2[12:44] = resp_ephem_pub
    type2[44:60] = encrypted_nothing
    mac1_key = blake2s_256(WG_LABEL_MAC1 + resp_static_pub_bytes)
    mac1 = hashlib.blake2s(bytes(type2[:60]), key=mac1_key, digest_size=16).digest()
    type2[60:76] = mac1
    type2[76:92] = b'\x00' * 16

    return bytes(type2), i_send, i_recv


def robust_jsr(transport, addr, timeout=30.0, retries=5):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0 + attempt * 0.5)
                continue
            raise


# ============================================================================
# Trial preparation (pure Python, no VICE)
# ============================================================================

def prepare_valid_trial(rng, trial_idx):
    """Prepare inputs for a valid Type 2 trial. Returns a dict."""
    init_static_priv = X25519PrivateKey.generate()
    init_static_pub = init_static_priv.public_key().public_bytes_raw()
    init_static_priv_bytes = init_static_priv.private_bytes_raw()

    resp_static_priv = X25519PrivateKey.generate()
    resp_static_pub = resp_static_priv.public_key().public_bytes_raw()
    resp_static_priv_bytes = resp_static_priv.private_bytes_raw()

    init_ephem_priv = X25519PrivateKey.generate()
    init_ephem_pub = init_ephem_priv.public_key().public_bytes_raw()
    init_ephem_priv_bytes = init_ephem_priv.private_bytes_raw()

    init_sender_idx = bytes(rng.randint(0, 255) for _ in range(4))

    # Replay initiator handshake steps to get (c, h)
    c_init = blake2s_256(WG_CONSTRUCTION)
    h_init = blake2s_256(c_init + WG_IDENTIFIER)
    h = mix_hash(h_init, resp_static_pub)
    c = c_init

    h = mix_hash(h, init_ephem_pub)
    (c,) = kdf_n(c, init_ephem_pub, 1)

    dh1 = init_ephem_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k1 = kdf_n(c, dh1, 2)

    nonce = b'\x00' * 12
    encrypted_static = ChaCha20Poly1305(k1).encrypt(nonce, init_static_pub, h)
    h = mix_hash(h, encrypted_static)

    dh2 = init_static_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k2 = kdf_n(c, dh2, 2)

    timestamp = bytes(rng.randint(0, 255) for _ in range(12))
    encrypted_timestamp = ChaCha20Poly1305(k2).encrypt(nonce, timestamp, h)
    h = mix_hash(h, encrypted_timestamp)

    # Build Type 2 from this state
    type2, i_send_key, i_recv_key = py_noise_responder_from_state(
        c, h, init_ephem_pub, init_static_pub,
        resp_static_priv_bytes, resp_static_pub,
        init_sender_idx
    )

    return {
        "name": f"valid #{trial_idx}",
        "c": c,
        "h": h,
        "ephem_priv": init_ephem_priv_bytes,
        "static_priv": init_static_priv_bytes,
        "static_pub": init_static_pub,
        "resp_pub": resp_static_pub,
        "sender_idx": init_sender_idx,
        "type2_packet": type2,
        "expected_send_key": i_send_key,
        "expected_recv_key": i_recv_key,
        "expect_success": True,
    }


def prepare_tampered_trial(rng):
    """Prepare inputs for a tampered Type 2 trial. Returns a dict."""
    init_static_priv = X25519PrivateKey.generate()
    init_static_pub = init_static_priv.public_key().public_bytes_raw()
    init_static_priv_bytes = init_static_priv.private_bytes_raw()

    resp_static_priv = X25519PrivateKey.generate()
    resp_static_pub = resp_static_priv.public_key().public_bytes_raw()
    resp_static_priv_bytes = resp_static_priv.private_bytes_raw()

    init_ephem_priv = X25519PrivateKey.generate()
    init_ephem_pub = init_ephem_priv.public_key().public_bytes_raw()
    init_ephem_priv_bytes = init_ephem_priv.private_bytes_raw()

    init_sender_idx = bytes([0x01, 0x02, 0x03, 0x04])

    # Replay initiator
    c_init = blake2s_256(WG_CONSTRUCTION)
    h_init = blake2s_256(c_init + WG_IDENTIFIER)
    h = mix_hash(h_init, resp_static_pub)
    c = c_init
    h = mix_hash(h, init_ephem_pub)
    (c,) = kdf_n(c, init_ephem_pub, 1)
    dh1 = init_ephem_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k1 = kdf_n(c, dh1, 2)
    nonce = b'\x00' * 12
    encrypted_static = ChaCha20Poly1305(k1).encrypt(nonce, init_static_pub, h)
    h = mix_hash(h, encrypted_static)
    dh2 = init_static_priv.exchange(X25519PublicKey.from_public_bytes(resp_static_pub))
    c, k2 = kdf_n(c, dh2, 2)
    timestamp = bytes(12)
    encrypted_timestamp = ChaCha20Poly1305(k2).encrypt(nonce, timestamp, h)
    h = mix_hash(h, encrypted_timestamp)

    valid_type2, _, _ = py_noise_responder_from_state(
        c, h, init_ephem_pub, init_static_pub,
        resp_static_priv_bytes, resp_static_pub,
        init_sender_idx
    )

    # Tamper: flip byte in AEAD tag area
    tampered = bytearray(valid_type2)
    tampered[50] ^= 0xFF

    return {
        "name": "tampered",
        "c": c,
        "h": h,
        "ephem_priv": init_ephem_priv_bytes,
        "static_priv": init_static_priv_bytes,
        "static_pub": init_static_pub,
        "resp_pub": resp_static_pub,
        "sender_idx": init_sender_idx,
        "type2_packet": bytes(tampered),
        "expected_send_key": None,
        "expected_recv_key": None,
        "expect_success": False,
    }


# ============================================================================
# Run a single trial on a VICE instance
# ============================================================================

def run_trial(instance, labels, trial):
    """Execute one Type 2 trial on a VICE instance. Returns (name, pass, msg)."""
    transport = instance.transport
    name = trial["name"]

    try:
        # Write handshake state
        write_bytes(transport, labels["hs_c"], trial["c"])
        write_bytes(transport, labels["hs_h"], trial["h"])
        write_bytes(transport, labels["hs_ephem_priv"], trial["ephem_priv"])
        write_bytes(transport, labels["hs_static_priv"], trial["static_priv"])
        write_bytes(transport, labels["hs_static_pub"], trial["static_pub"])
        write_bytes(transport, labels["hs_resp_pub"], trial["resp_pub"])
        write_bytes(transport, labels["hs_sender_idx"], trial["sender_idx"])
        write_bytes(transport, labels["hs_preshared_key"], b'\x00' * 32)
        write_bytes(transport, labels["wg_state"], bytes([1]))  # HS_SENT

        # Write Type 2 packet to receive buffer
        write_bytes(transport, labels["udp_recv_buf"], trial["type2_packet"])
        write_bytes(transport, labels["udp_recv_len"], struct.pack('<H', 92))
        write_bytes(transport, labels["udp_recv_ready"], bytes([1]))

        # Run session_handle_packet (3x X25519)
        robust_jsr(transport, labels["session_handle_packet"], timeout=TYPE2_TIMEOUT)

        # Check result
        state = read_bytes(transport, labels["wg_state"], 1)[0]

        if trial["expect_success"]:
            if state != 2:
                return (name, False, f"state={state}, expected 2 (ACTIVE)")

            c64_send = bytes(read_bytes(transport, labels["hs_transport_send"], 32))
            c64_recv = bytes(read_bytes(transport, labels["hs_transport_recv"], 32))

            if c64_send != trial["expected_send_key"]:
                return (name, False,
                        f"send key mismatch: expected {trial['expected_send_key'].hex()}, "
                        f"got {c64_send.hex()}")
            if c64_recv != trial["expected_recv_key"]:
                return (name, False,
                        f"recv key mismatch: expected {trial['expected_recv_key'].hex()}, "
                        f"got {c64_recv.hex()}")

            return (name, True, "transport keys match")
        else:
            # Tampered: should NOT reach ACTIVE
            if state != 2:
                return (name, True, f"rejected (state={state})")
            else:
                return (name, False, "tampered Type 2 accepted (state=ACTIVE)")

    except Exception as e:
        return (name, False, f"exception: {e}")


# ============================================================================
# Main
# ============================================================================

def main():
    global VERBOSE

    args = sys.argv[1:]
    seed = 51820
    workers = 6
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        elif args[i] == "--workers" and i + 1 < len(args):
            workers = int(args[i + 1])
            i += 2
        else:
            i += 1

    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    print(f"Workers: {workers}")

    # Build
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    assert os.path.exists(PRG_PATH), f"{PRG_PATH} not found after build"
    print(f"Built: {PRG_PATH}")

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required = [
        "hs_c", "hs_h", "hs_ephem_priv", "hs_static_priv",
        "hs_static_pub", "hs_resp_pub", "hs_sender_idx", "hs_preshared_key",
        "wg_state", "udp_recv_buf", "udp_recv_len", "udp_recv_ready",
        "hs_transport_send", "hs_transport_recv",
        "session_handle_packet", "entropy_init",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    # Pre-compute all 6 trials (pure Python, fast)
    print("Preparing trial data...")
    trials = []
    for idx in range(5):
        trials.append(prepare_valid_trial(rng, idx))
    trials.append(prepare_tampered_trial(rng))
    print(f"Prepared {len(trials)} trials")

    # Boot VICE instances
    effective_workers = min(workers, len(trials))
    print(f"\nLaunching {effective_workers} VICE instances...")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    mgr = ViceInstanceManager(config=config, port_range_start=6510,
                              port_range_end=6530)

    with mgr:
        instances = []
        for idx in range(effective_workers):
            inst = mgr.acquire()
            print(f"  Instance {idx}: PID={inst.pid}, port={inst.port}")
            instances.append(inst)
            if idx < effective_workers - 1:
                time.sleep(0.1)  # stagger launches for 6+ instances

        for idx, inst in enumerate(instances):
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=90.0,
                                 verbose=False)
            if grid is None:
                print(f"FATAL: Main menu did not appear on instance {idx}")
                sys.exit(1)
            write_bytes(inst.transport, 0x0339, bytes([0x4C, 0x39, 0x03]))
            robust_jsr(inst.transport, labels["entropy_init"])

        print(f"All {effective_workers} instances ready\n")
        print(f"Running {len(trials)} trials (timeout {TYPE2_TIMEOUT}s each)...")
        start_time = time.time()

        # Run trials in parallel
        results = {}
        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            future_to_trial = {}
            for idx, trial in enumerate(trials):
                inst = instances[idx % effective_workers]
                future = pool.submit(run_trial, inst, labels, trial)
                future_to_trial[future] = trial["name"]

            for future in as_completed(future_to_trial):
                name, passed, msg = future.result()
                status = "PASS" if passed else "FAIL"
                results[name] = passed
                elapsed = time.time() - start_time
                print(f"  {status} {name}: {msg}  [{elapsed:.0f}s elapsed]")

        elapsed = time.time() - start_time

    # Summary
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed, {failed} failed "
          f"({elapsed:.0f}s / {elapsed/60:.1f} min)")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
