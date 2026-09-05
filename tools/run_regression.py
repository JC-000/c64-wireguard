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

import hashlib
import os
import subprocess
import sys
import tempfile
import time

TESTS = [
    # FIRST because it is the cheapest and the most diagnostic: it imports
    # every tools/test_*.py and fails on an ImportError, a missing symbol, or
    # anything else raised at import time. A suite that raises before its
    # first line looks exactly like a suite with nothing to say —
    # test_ip65_listener_leak.py was in that state from c3fe7aa, and
    # test_uci_udp_size_probe.py from f021458, with nothing reporting either.
    # Build-tree independent (verified against a tree with no build/ at all),
    # so it is safe in the parallel pool alongside the mutators.
    ("suite_imports", ["tools/test_suite_imports.py"]),
    # THIS RUNNER'S OWN THREE DEFECTS, found 2026-09-04. All were silent
    # and two could not be seen from any suite's result: stdout=PIPE with
    # no reader deadlocked on >64 KB of output; SUITE_TIMEOUT lived only in
    # a loop below the pool whose condition could never be true, and the
    # serial loop had no deadline at all; and the restore `make` ignored
    # both return codes, so a failed rebuild still printed "All N suites
    # passed!" over an unusable tree. The gate is the one thing no suite
    # can test from the inside, so it tests itself, with all three shapes
    # exercised against throwaway subprocesses. Seconds, no build.
    ("gate_self",  ["tools/run_regression.py", "--self-check"]),
    # Host-side only (no device, no network): judgement about /v1/info's
    # git_commit_hash, incl. that an UNKNOWN hash warns rather than
    # refuses — a host-side allowlist that blocked the next legitimate
    # firmware rebase would be worse than the thing it guards against.
    ("u64_firmware", ["tools/test_u64_firmware.py", "--verbose"]),
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
    # #89. Boots four INDEPENDENT VICE instances of its own, which is the
    # whole point — "the whitening state starts from a compile-time constant"
    # is invisible inside any single run, so nothing already in this list
    # could have seen it. Its instances count against MAX_PARALLEL like any
    # other suite's, but they are sequential within the suite.
    ("entropy_seed",   ["tools/test_entropy_seed.py"]),
    # The live tools themselves cannot run here, but the seam they all hang
    # from can be checked without hardware — and if it breaks, every one of
    # them breaks while this gate stays green. Import-only, milliseconds.
    ("live_seams",     ["tools/test_live_tool_seams.py"]),
    # Issue #109. Enforcement for the cold-init trap that #107 created and
    # that has now caught three suites (type2_slow, hs_recovery, issue_94),
    # every one by copy-paste from a sibling that predated the reclaim.
    # Source-level and emulator-free, so it fires at edit time rather than
    # the first time someone runs the suite on a REU build; the runtime
    # symptom it replaces is an unattributed 180 s TimeoutError. Reads the
    # span from labels.txt, so the gate must have built first — which it has.
    ("cold_init_seam", ["tools/test_cold_init_seam.py"]),
    # Issue #103. LIB_X25519_INIT_CODE is now reclaimed as APP_BSS rather
    # than merely documented as reclaimable, which is only safe while the
    # cold init is genuinely dead after boot. This suite is the red/green
    # for that: it checks the span is erased, that the tables the erased
    # code built are still correct, and — the red half — that deliberately
    # forcing the one guarded branch back into the span does NOT return.
    # Without the red half, a green gate would be consistent with the code
    # still being needed and simply never exercised.
    ("cold_reclaim",   ["tools/test_cold_segment_reclaim.py"]),
    # Issue #94: the three guards on the Type 3 (cookie reply) path. Fast
    # group only — the suite's --slow group runs hs_process_response /
    # hs_create_initiation and is hours per case under VICE warp, well past
    # SUITE_TIMEOUT. The fast group is seconds and covers all three guards
    # plus their acceptance controls; T7 carries its own 300 s bound so a
    # regression fails inside the budget instead of hanging the pool.
    #
    # Measured, not assumed: the fast group runs ZERO X25519 scalarmults, and
    # X25519 is the only consumer of the REU (LIB_X25519_REU_BANKS_USED = $3B,
    # LIB_CHACHA20_POLY1305_REU_BANKS_USED = 0). So the REU=1/REU=0 split this
    # gate builds under cannot move it. Timed on the unfixed tree, where the
    # crypto actually runs: T1-T6 = 0.6 s at REU=1, 1.5 s at REU=0; on the
    # fixed tree 0.2 s total, because guarded packets are rejected before any
    # crypto. The suite prints a per-group timing table on every run — if that
    # ever disagrees with these numbers, say so rather than demoting the suite
    # to SERIAL_TESTS or thinning its assertions.
    ("issue_94",       ["tools/test_issue_94_95_adversarial.py"]),
    # Issue #87. The Type-1 TAI64N timestamp must be strictly increasing
    # across initiations; before the fix every initiation carried
    # base_time||00000001 and a conformant peer dropped every handshake after
    # the first. Drives the REAL session_initiate with the three scalarmults
    # and net_udp_send stubbed over DMA (zero X25519, seconds per call), so
    # the REU split cannot move it. Deliberately UNSEEDED here: the base time
    # and the jiffy deltas are random per run and the seed is on the first
    # line of its output (reproduce with --seed).
    ("tai64n_monotonic", ["tools/test_tai64n_monotonic.py", "--verbose"]),
    # Issue #87, the other half: the bench responder enforces WireGuard's
    # greatest-seen timestamp rule, so the bench peer can catch that class
    # of defect at all. No emulator, no hardware — a loopback UDP socket for
    # the server.py case; milliseconds.
    ("responder_ts",   ["tools/test_wg_responder_timestamp.py"]),
    # Issue #129. @t4_udp printed a peer's chat payload through CHROUT with
    # the printable filter OFF, so PETSCII control codes arriving from the
    # wire were EXECUTED on the display ($93 clear, $13 home, $12 reverse,
    # $0E/$8E charset, $90-$9F colour). The oracle is an identity, not a log
    # line: the same message is delivered twice, once with the control bytes
    # already replaced by '.', and the whole observable display state (screen
    # RAM, colour RAM, cursor, $C7/$D4/$D8, the line-link table, $0286, and
    # VIC $D011/$D016/$D018/$D020-$D024) must match. Ordinary VICE suite,
    # honours C64_SKIP_BUILD, no build-tree mutation. Deliberately UNSEEDED
    # here — the payload, the codes and their positions are random per run
    # and the seed is on the first line of its output (reproduce with --seed).
    ("petscii_ctrl",   ["tools/test_issue_129_petscii_control.py"]),
    # Issue #128, the INSTRUMENT half. The "1049-1187 B band" was retracted
    # as an artifact of tools/test_warp_live.py, which had no assertion that
    # had ever been observed failing — so nothing in this gate could have
    # caught it. This suite drives the REAL run_stage_c() against a scripted
    # fake device (64 KiB of RAM and a 25x40 screen behind the ordinary
    # transport surface), so the ground truth of every trial is known and
    # the tool's verdict can be compared to it. Covers the stale receive
    # state, the peer-controlled screen scrape (both its content and its
    # MSG> boundary), the size reported from a host-side table rather than
    # measured, and the sweep ladder's size/position confound.
    #
    # Host-side only: no VICE, no device, no build — it reads whichever
    # labels.txt the gate's build left behind (either backend). Deliberately
    # UNSEEDED here; the payloads are random per run and the seed is on the
    # first line of its output (reproduce with --seed).
    ("warp_instrument", ["tools/test_warp_instrument_unit.py"]),
    # The ip65/RR-Net HARDWARE validation, made capable of failing. Every
    # verdict that run reaches lives in tools/ip65_hw_checks.py as a pure
    # function over bytes, and this suite feeds each one a known-bad input
    # off-device and requires it to fail: plaintext on the wire at a
    # non-zero offset, torn across two IP fragments, reversed, in PETSCII,
    # in the Ethernet pad, in an ARP frame; a handshake the responder calls
    # complete while the C64 sits at HS_SENT; a reply the C64 never
    # decrypted; ip65's BUILD-TIME cfg_ip 192.168.1.64 and cfg_mac
    # 00:80:10:00:51:00 read as a lease and a programmed NIC; and a capture
    # of the Mac talking to itself passing as proof the C64 did anything.
    # The absence verdicts are three-state: a capture with no C64-sourced
    # datagrams in it is INCONCLUSIVE, never a pass, because on this cable
    # the Mac is DHCP server, peer, capturer and sentinel sender all at
    # once, so "we looked and it was clean" and "there was nothing of ours
    # to look at" are satisfied by the same guards.
    # Also: net_last_error $41 (our loader dropped the cartridge) decoded
    # apart from $42 (dnsmasq is not answering), which look identical on the
    # screen and lead to opposite actions, with the code table cross-checked
    # against the tree's own equates so a renumbering cannot leave it
    # confidently wrong; a stale pcap from an earlier session rejected rather
    # than parsed as evidence; and ICMP echo replies PAIRED to this run's
    # requests by (id, seq), because macOS queues replies against a stale
    # neighbour entry and flushes the backlog in one millisecond when an ARP
    # resolves -- so a checker that counts replies scores its best result on
    # exactly the broken case.
    # Each red case also asserts that the NAIVE checker it indicts still
    # passes, so a case whose trap has gone stale says so instead of
    # quietly proving nothing.
    #
    # Host-side only: no VICE, no device, no build, no DeviceLock, ~0.05 s.
    # Deliberately UNSEEDED here; the payloads, MACs and lease address are
    # random per run and the seed is on the first line of its output
    # (reproduce with --seed).
    ("ip65_hw_checks", ["tools/test_ip65_hw_checks_unit.py"]),
    # The alarm proof for the alarms above, run every time rather than
    # trusted from a report: 55 deliberate defects are spliced into
    # ip65_hw_checks.py one at a time and the suite must go RED for every
    # one, naming which checks caught it. A mutant that survives is a
    # defect the suite cannot see and fails this entry. ~20 s (case 18
    # builds a throwaway git repo in each of the 55 children).
    ("ip65_hw_checks_mutation",
     ["tools/test_ip65_hw_checks_unit.py", "--self-check"]),
    # Issue #128, the firmware half of the same retraction. transport_decrypt
    # has ONE `lda #$ff` shared by five rejection causes, so "DECRYPT FAILED"
    # is not evidence of an AEAD failure — which is how "9/9 fail AEAD" was
    # manufactured. Drives all five causes plus a genuinely ChaCha20-Poly1305
    # -sealed packet through jsr.
    #
    # Its contract is CONDITIONAL on the build, so it is honest without
    # crying wolf. No `tp_reject_cause` (every build today): it PINS THE
    # CONFLATION — all five causes must share the one $ff exit — and prints
    # that conflation as a measured property. It goes red the day any of the
    # five stops sharing it, i.e. the day the contract changes and the tests
    # do not. With `tp_reject_cause` present it requires five DISTINCT and
    # CORRECT codes, so a correct fix stays green and an incorrect one fails.
    # Both branches verified: 5/5 today, 12/12 on a tree carrying the cause
    # byte, and red when either contract is violated.
    #
    # Ordinary VICE suite, honours C64_SKIP_BUILD, no build-tree mutation.
    ("warp_instrument_vice", ["tools/test_warp_instrument_vice.py"]),
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
    # Issue #70. Needs `make BACKEND=uci UCI_CHUNKED_WRITE=1` — a third tree
    # state neither the pool nor the two above build — and it is the only
    # suite that exercises transport_send's 1440/1441 boundary under the
    # flag, with net_udp_send stubbed (VICE has no UCI). Serial for the same
    # reason as both_backends: it rebuilds the shared tree.
    ("chunked_send",   ["tools/test_chunked_send_boundary.py"]),
    # Issue #70, the half chunked_send cannot reach: it stubs net_udp_send at
    # its label, so the $16 PART LOOP has never run in any suite. This one
    # stubs only the UCI primitives underneath uci_send_part, so the real
    # clamp, the real offset advance and the real push loop execute, and reads
    # the adapter's own command stream back out of RAM: part count, offsets,
    # announced totals, and (with the push sink redirected) the bytes
    # themselves. Same tree state as chunked_send —
    # `make BACKEND=uci UCI_CHUNKED_WRITE=1` — hence serial, and it restores
    # the default build on exit. Unseeded: the datagrams and the padded DNS
    # queries are random per run and the seed is on its first line.
    ("multipart_split", ["tools/test_multipart_chunk_split.py"]),
    # Issue #70, ip65 half: the WG_MTU1440=1 knob. Builds ip65 and uci with
    # and without it, reads WG_MTU / NET_UDP_*_MAX back through
    # tools/c64_caps.py's labels path, requires `BACKEND=uci WG_MTU1440=1`
    # (no chunked flag) to be REFUSED, and pins the defaults byte-identical
    # to a knob-less tree. Serial: it rebuilds the tree five times.
    ("build_mtu1440",  ["tools/test_build_mtu1440.py"]),
    # Issue #80, the structural guard. The link-time asserts in
    # src/net/ip65/ip65_blob.s compare the §13.7 equate to the consumer
    # cfg; neither is the blob, so a relink of ip65-build/ip65.cfg back to
    # $4000 links CLEAN (measured 2026-09-03). This reads the blob's own
    # map. Serial: needs a BACKEND=ip65 tree and builds one. Retires the
    # FATAL path of tools/test_ip65_bss_corruption.py (rig-only, opt-in).
    ("ip65_bss_guard", ["tools/test_ip65_bss_guard.py"]),
    # Issue #130. net_poll's @block_end block-drain decision: a reply that
    # ends with uci_poll_rem non-zero must be DROPPED with a distinct error,
    # and a continuation staged inside the fence must still be DRAINED.
    # VICE cannot reach any of it — $DF1D reads $FF there, so the multi-block
    # SOCKET_READ path does not exist — so this runs the real assembled
    # net_poll on a host-side 6502 (tools/uci/mos6502.py) against a model of
    # $DF1C-$DF1F. Serial: needs `make BACKEND=uci`, which it builds itself,
    # so it mutates the shared tree exactly like uci_stub. Unseeded here; the
    # announced lengths and payloads are random per run and the seed is on
    # the first line of its output (reproduce with --seed).
    ("uci_short_read", ["tools/test_uci_short_read_drop.py"]),
    # NOT listed, deliberately: tools/test_ip65_udp_echo_vice.py and
    # tools/test_ip65_handshake_vice.py need the ethernet VICE rig (feth
    # pair + dnsmasq + a pcap-capable x64sc); they exit 77 without it.
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
    """Start a suite with its output going to a TEMP FILE, not a pipe.

    NOT subprocess.PIPE. It used to be, with nothing reading the pipe until
    after `proc.poll()` returned non-None — so a suite writing more than the
    ~64 KB pipe buffer blocked forever on write, poll() never returned, and
    the whole gate deadlocked with no timeout to rescue it (the "safety net"
    below the pool was unreachable dead code; see main()). Reproduced: a
    suite emitting 2 MB hangs the pre-fix runner indefinitely, poll() = None.

    A file has no such limit and needs no reader thread. The handle is
    carried alongside the process and read once, at reap.
    """
    fh = tempfile.NamedTemporaryFile(
        prefix=f"gate_{name}_", suffix=".log", delete=False, mode="w+b")
    p = subprocess.Popen(
        ["python3"] + cmd,
        stdout=fh,
        stderr=subprocess.STDOUT,
        env=env,
    )
    print(f"  → launch {name:15s} (PID {p.pid})")
    return p, fh


def _drain(fh):
    """Read a finished suite's log file and remove it."""
    try:
        fh.flush()
        fh.seek(0)
        out = fh.read().decode(errors="replace")
    except Exception as exc:                                  # noqa: BLE001
        out = f"(could not read suite log: {exc!r})"
    finally:
        try:
            fh.close()
            os.unlink(fh.name)
        except OSError:
            pass
    return out


def reap(running, results, timeout=None):
    """Move finished processes out of `running` into `results`.

    *timeout* is now ENFORCED, on every path. It used to exist only in a
    loop below the pool that could never be entered, so a suite that hung
    hung the gate — the opposite of what SUITE_TIMEOUT's comment claimed.
    A suite past its deadline is killed and recorded as a FAILURE, because
    a suite that had to be killed has not passed.
    """
    still_running = []
    for name, proc, fh, started in running:
        rc = proc.poll()
        elapsed = time.monotonic() - started
        if rc is None and timeout is not None and elapsed > timeout:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            out = _drain(fh)
            results[name] = (
                -1,
                out + f"\n\n*** KILLED: exceeded SUITE_TIMEOUT "
                      f"({timeout:.0f}s). A suite that had to be killed has "
                      f"not passed. ***\n")
            print(f"  ← KILL {name:15s}  ({elapsed:.0f}s, over "
                  f"{timeout:.0f}s budget)")
            continue
        if rc is None:
            still_running.append((name, proc, fh, started))
        else:
            out = _drain(fh)
            results[name] = (rc, out)
            status = "PASS" if rc == 0 else "FAIL"
            print(f"  ← {status:4s} {name:15s}  ({elapsed:.0f}s)")
    return still_running


def restore_default_build():
    """`make clean && make`, checked. Returns None on success, else why not.

    The gate leaves the tree on the DEFAULT backend (Makefile: BACKEND ?=
    ip65). That is deliberate and documented, but it is only true if this
    actually succeeded — which nothing verified before.
    """
    for cmd in (["make", "clean"], ["make"]):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            tail = "\n".join((r.stderr or r.stdout or "").strip()
                              .splitlines()[-15:])
            return (f"  `{' '.join(cmd)}` exited {r.returncode}\n{tail}")
    # Relative to where `make` actually ran, not to PROJECT_ROOT. In the
    # gate those coincide (main() chdir'd first), so an absolute check
    # would pass for a reason unrelated to the build it just ran — and it
    # would validate a DIFFERENT tree than it built. Caught by the
    # succeeding-build control in self_check().
    prg = os.path.join(os.getcwd(), "build", "wireguard.prg")
    if not os.path.exists(prg):
        return (f"  `make` reported success but {prg} does not exist — the "
                f"next run with C64_SKIP_BUILD=1 would have nothing to load")
    return None


def describe_tree():
    """Say what the gate LEFT BEHIND, so the next lane need not guess.

    A gate run leaves build/ on the default (ip65) backend, and the
    handoff notes record people being caught by that. Printing the
    fingerprint costs nothing and turns an inherited state into a stated
    one.
    """
    prg = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
    labels = os.path.join(PROJECT_ROOT, "build", "labels.txt")
    try:
        data = open(prg, "rb").read()
        sha = hashlib.sha256(data).hexdigest()[:16]
        size = len(data)
    except OSError as exc:
        return f"build/: UNREADABLE ({exc})"
    backend = "unknown"
    try:
        names = open(labels).read()
        has_ip65 = ".ip65_blob_start" in names
        has_uci = ".uci_wait_idle" in names
        backend = ("ip65" if has_ip65 and not has_uci else
                   "uci" if has_uci and not has_ip65 else "ambiguous")
    except OSError:
        pass
    return (f"Tree left as: BACKEND={backend}  build/wireguard.prg "
            f"{size} B sha256={sha}...\n"
            f"(the gate restores the DEFAULT build; rebuild explicitly "
            f"before any hardware run that needs another backend)")


def self_check():
    """Prove the three gate defects fixed on 2026-09-04 stay fixed.

    Each was silent, and two of them could make a red run look green or
    make no run finish at all:

      1. stdout=subprocess.PIPE with no reader — a suite emitting more than
         the pipe buffer blocked on write forever and poll() never
         returned.
      2. SUITE_TIMEOUT was referenced only in a loop below the pool whose
         condition could never be true, and the serial loop had no deadline
         at all. Nothing bounded a hung suite.
      3. the restore `make` ignored both return codes, so a failed rebuild
         still printed "All N suites passed!".

    Runs three throwaway suites in a temp dir. No project build, seconds.
    """
    print("=== run_regression self-check ===")
    failed = 0
    td = tempfile.mkdtemp(prefix="gate_selfcheck_")
    chatty = os.path.join(td, "chatty.py")
    hang = os.path.join(td, "hang.py")
    with open(chatty, "w") as fh:
        fh.write("import sys\n"
                 "for _ in range(20000):\n"
                 "    sys.stdout.write('x' * 100 + '\\n')\n"
                 "sys.exit(0)\n")
    with open(hang, "w") as fh:
        fh.write("import time\ntime.sleep(3600)\n")

    env = os.environ.copy()

    # (1) 2 MB of output must COMPLETE, not deadlock.
    results = {}
    proc, out_fh = launch("chatty", [chatty], env)
    running = [("chatty", proc, out_fh, time.monotonic())]
    deadline = time.monotonic() + 60
    while running and time.monotonic() < deadline:
        running = reap(running, results, timeout=60)
        time.sleep(0.2)
    if running or results.get("chatty", (1,))[0] != 0:
        print("  FAIL  a suite writing 2 MB to stdout did not complete "
              "cleanly — the pipe deadlock is back")
        for _n, pr, _f, _s in running:
            pr.kill()
        failed += 1
    else:
        got = len(results["chatty"][1])
        print(f"  PASS  a suite writing 2 MB completes ({got} B captured, "
              f"far past the ~64 KB pipe buffer that used to deadlock)")

    # (2) a hung suite must be KILLED and recorded as a FAILURE.
    results = {}
    proc, out_fh = launch("hang", [hang], env)
    running = [("hang", proc, out_fh, time.monotonic())]
    start = time.monotonic()
    while running and time.monotonic() - start < 30:
        running = reap(running, results, timeout=3)
        time.sleep(0.2)
    took = time.monotonic() - start
    rc = results.get("hang", (None,))[0]
    if running or rc is None or rc == 0:
        print(f"  FAIL  a suite that sleeps for an hour was not killed "
              f"(rc={rc!r}, still running={bool(running)}) — SUITE_TIMEOUT "
              f"bounds nothing again")
        for _n, pr, _f, _s in running:
            pr.kill()
        failed += 1
    elif "KILLED" not in results["hang"][1]:
        print("  FAIL  the hung suite was reaped but its output does not "
              "say it was killed; a reader cannot tell a kill from a "
              "genuine failure")
        failed += 1
    else:
        print(f"  PASS  a hung suite is killed at its deadline "
              f"({took:.1f}s for a 3 s budget) and recorded as a FAILURE")

    # (3) a failed restore build must be reported, not swallowed.
    saved = os.getcwd()
    try:
        os.chdir(td)
        # The failing `make` MUST still produce build/wireguard.prg.
        # Without that, restore_default_build()'s separate "the PRG does
        # not exist" branch catches the case and the return-code check —
        # the thing this is meant to prove — is never exercised. Caught
        # exactly that way on the first draft: disabling the return-code
        # check left this case still passing.
        with open(os.path.join(td, "Makefile"), "w") as fh:
            fh.write("all:\n"
                     "\t@mkdir -p build && echo prg > build/wireguard.prg\n"
                     "\t@echo 'deliberate build failure' >&2; exit 1\n"
                     "clean:\n\t@true\n")
        why = restore_default_build()
        # Second control: the SAME Makefile succeeding must NOT be
        # reported, or this case would pass for a checker that fails
        # every build.
        with open(os.path.join(td, "Makefile"), "w") as fh:
            fh.write("all:\n"
                     "\t@mkdir -p build && echo prg > build/wireguard.prg\n"
                     "clean:\n\t@true\n")
        why_ok = restore_default_build()
    finally:
        os.chdir(saved)
    if not why:
        print("  FAIL  a `make` that exits 1 (having still written a PRG) "
              "was reported as a successful restore — the gate would print "
              "'All suites passed' over a broken tree")
        failed += 1
    elif why_ok:
        print(f"  FAIL  a `make` that SUCCEEDED was reported as a failed "
              f"restore ({why_ok!r}) — a checker that fails every build "
              f"discriminates nothing")
        failed += 1
    else:
        print("  PASS  a failing restore build is reported (by its return "
              "code, with the PRG present) and a succeeding one is not")

    if failed:
        print(f"\n{failed} gate self-check(s) failed.")
        return 1
    print("\nAll three gate defects stay fixed.")
    return 0


def main():
    if "--self-check" in sys.argv:
        return self_check()
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
        running = reap(running, results, timeout=SUITE_TIMEOUT)
        while pending and len(running) < MAX_PARALLEL:
            name, cmd = pending.pop(0)
            proc, fh = launch(name, cmd, env)
            running.append((name, proc, fh, time.monotonic()))
            time.sleep(STAGGER_SECONDS)
        if running:
            time.sleep(POLL_SECONDS)

    # The "hard timeout safety-net" that used to sit here was DEAD CODE:
    # the loop above exits only when `pending` and `running` are both
    # empty, so its `while running and ...` condition could never be true.
    # SUITE_TIMEOUT bounded nothing at all. It is now passed into reap()
    # on every poll instead, which is the only place that can act on it.

    # Build-tree mutators, one at a time, only once the pool is empty. No
    # C64_SKIP_BUILD: each of these needs to build the tree it actually tests.
    serial_env = os.environ.copy()
    serial_env.pop("C64_SKIP_BUILD", None)
    for name, cmd in SERIAL_TESTS:
        proc, fh = launch(name, cmd, serial_env)
        # Bounded, like the pool. This loop previously had NO deadline of
        # any kind — not even the unreachable one above — so a serial suite
        # that hung hung the gate forever with no diagnostic.
        pending_one = [(name, proc, fh, time.monotonic())]
        while pending_one:
            pending_one = reap(pending_one, results, timeout=SUITE_TIMEOUT)
            if pending_one:
                time.sleep(POLL_SECONDS)

    restore_failure = None
    if SERIAL_TESTS:
        # Those suites left the tree on whichever backend they built last.
        # Restore the default so a subsequent `make run` or manual test does
        # not silently use it.
        #
        # BOTH RETURN CODES ARE CHECKED. They were not, and that is the
        # defect that could mask a broken tree: if this rebuild failed, the
        # gate still printed "All N suites passed!" over an absent or
        # half-written build/, and the next thing to run — a hardware tool
        # with C64_SKIP_BUILD=1, which is the documented workflow — would
        # either die or silently load a stale PRG. A gate that leaves the
        # tree unusable has not passed.
        restore_failure = restore_default_build()

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
    if restore_failure:
        all_ok = False
        print("\nRESTORE BUILD FAILED — the tree this gate leaves behind is "
              "NOT usable:")
        print(restore_failure)
    if all_ok:
        print(f"All {len(TESTS) + len(SERIAL_TESTS)} suites passed!")
        print(describe_tree())
    else:
        print("\nFailed suites:")
        for name, (rc, out) in results.items():
            if rc != 0:
                print(f"\n=== {name} (exit {rc}) ===")
                print(out[-2000:])

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
