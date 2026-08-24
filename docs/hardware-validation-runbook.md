# Hardware Validation Runbook — Sibling Toggles (D) + Bug #2 AEAD Re-test (E)

One document for the Ultimate 64 hardware session. Covers workstream D
(A/B validation of the sibling-library toggles on real hardware) and
workstream E (re-running the Phase 9 Bug #2 AEAD-divergence diagnostic
under `USE_X25519_SIBLING=1`).

Everything here was prepared from master `65b0498` (post-PR-#39).
Builds verified 2026-07-16; VICE regression smoke of the
`USE_X25519_SIBLING=1` build passed 22/22 (`tools/test_handshake.py`).

---

## 1. Binaries under test

All four UCI-backend variants build clean from `65b0498`. Every PRG is
37,889 bytes (the linker layout pads to the same top address), so **file
size cannot distinguish variants — verify by SHA-256 before flashing**:

| Variant | Build command | SHA-256 (`wireguard.prg`) |
|---|---|---|
| baseline | `make BACKEND=uci` | `bdf6cb8814bc440806358645baf656093175b208f9a82c1f03ce9b3dc5edcadb` |
| x25519-sibling | `make BACKEND=uci USE_X25519_SIBLING=1` | `5cc257035f3aba23b3d01847804c0bc202ab1435c5f09feede2969c92532d6b3` |
| chacha-sibling | `make BACKEND=uci USE_CHACHA_SIBLING=1` | `44651e787c3ddf1ef9ad157737b1b2123f0f28de1afe85c9e81056d05b6caef7` |
| both siblings | `make BACKEND=uci USE_X25519_SIBLING=1 USE_CHACHA_SIBLING=1` | `669f20de37e6c43f542feafc59d5b19809c4b5f37b2b938da4a2d416df853b2b` |

Prebuilt copies (PRG + map) are in `artifacts/wireguard-uci-<variant>.{prg,map}`.
Always `make clean` between variants — the build system does not
track toggle flags in object files.

Map-file deltas vs baseline (measured, decimal bytes):

| Segment | baseline | x25519-sib | chacha-sib | both |
|---|---|---|---|---|
| CRYPTO_CODE | 6,420 | 7,673 | 4,175 | 5,428 |
| CRYPTO_RODATA | 1,371 | 795 | 1,323 | 747 |
| CRYPTO_BSS | 2,688 | 1,247 | 2,176 | 810 |
| X25519_RODATA (page-aligned) | — | 2,304 @ `$0D40` | — | 2,304 @ `$0D20` |
| X25519_BSS | — | 1,536 @ `$9600` | — | 1,536 @ `$9600` |
| CHACHA_CODE | — | — | 8,022 @ `$5FA5` | 8,022 @ `$5F4F` |
| CHACHA_RODATA | — | — | 512 @ `$1000` | 512 @ `$1700` |
| CHACHA_BSS | — | — | 295 @ `$9544` | 295 @ `$9C00` |

Highest used address is `$9D26` (both-siblings CHACHA_BSS end) — clear
of `$A000` BASIC ROM shadow with ~700 bytes headroom.

## 2. Preflight checklist (do this before the first run)

- [ ] **Physical power-cycle the U64E.** Not `client.reboot()` — it does
      not clear the UCI wedge state. The wedge budget below starts
      counting from power-on.
- [ ] **Confirm the host address by probing, not by recall.** The older
      tools default to `U64_HOST=10.43.23.81`; that is a home-LAN address
      and the device moves (it has since been seen at `192.168.2.80` and
      `.81`). Identify the machine by `GET /v1/info` — `unique_id`,
      `hostname`, `firmware_version` — and pass `U64_HOST` / `--host`
      explicitly. A stale address fails as "unreachable", which reads like
      a dead device rather than a wrong flag. The newer tools
      (`wg_chat.py`, `wg_demo.py`, `test_wire_encryption_live.py`) have no
      default for exactly this reason.
- [ ] **Check the CPU speed.** `GET /v1/configs/U64%20Specific%20Settings`
      → `CPU Speed`. The device is shared and has been found left at a
      stale 16/48 MHz. Restore 1 MHz when you are done; the newer tools do
      this themselves, including on Ctrl-C.
- [ ] Start the **patient Python responder** (`tools/wg_responder/`) —
      real `wg` enforces REKEY_TIMEOUT (5 s) / REJECT_AFTER_TIME (180 s)
      and will drop the session long before the C64's ~9 min handshake
      completes. The responder has those timeouts disabled; the C64 sets
      the pace.
- [ ] Check [c64-test-harness#112](https://github.com/JC-000/c64-test-harness/issues/112)
      — **still OPEN as of 2026-07-16.** If a UCI-state-reset primitive
      has landed since, use it before each run and the session budget
      relaxes considerably.
- [ ] Preserve `artifacts/aead_diag*.log` from 2026-05-17 (the one good
      post-fix-1 dump). Do not overwrite or delete.

### Device quirks that will bite you (all firmware 3.14d)

- **Session budget: NOT 3 runs — but the wedge is real.** The old "≤3
  `run_prg` per power-cycle" figure is wrong; 7 clean bring-ups in a row
  have been observed repeatedly (2026-08-15 and again 2026-08-17). What
  does hold is that after *enough* sessions on one power cycle the
  Ultimate stops delivering: `do_handshake` returns `carry=0` with a
  correct 148-byte packet staged and nothing arrives (#58). Twice on
  2026-08-17 that appeared around the seventh bring-up. Do not ration
  runs on a count; instead **confirm the wedge cheaply** with
  `tools/test_uci_udp_echo_live.py`, which needs no crypto and fails in
  seconds with `net_udp_send` timing out.
- **Only a physical power-cycle clears it.** `PUT /v1/machine:reset`
  does not — verified twice. The wedge is in the Ultimate's firmware
  network stack, not in the C64.
- **`runner_health_check()` lies** — returns None even when UCI is
  wedged. Detect the wedge from the test's own progress log
  (`step $66 still running [send_len_lo=...]`).
- **SOCKET_READ: always request 512 bytes, AND validate the length it
  returns.** >512 truncates silently; 1500 returns `0xFFFF`. Worse, the
  firmware can report a length larger than the request even for a 512
  request: `net_poll` used to trust it and fed it to an unbounded copy,
  which walked ~18 KB from `udp_recv_buf` through `$D000` I/O and left
  WireGuard packet bytes in the VIC registers (red screen, garbage
  charset, `wg_state` zeroed). Fixed by clamping against
  `UCI_READ_CHUNK_MAX` and dropping the read.

  **`$FFFF` is the no-data sentinel, not a length** (measured 2026-08-24):
  with nothing pending, every `SOCKET_READ` on a UDP socket returns header
  `$FFFF`. c64-https sees the same sentinel on TCP. It must be excluded
  *before* the over-claim test, or it fires on every idle poll — which is
  exactly what this adapter did until 2026-08-24, and why this note
  previously claimed `UCI_ERR_LONG_READ` "fires routinely during healthy
  sessions". That was never an over-claim; it was an empty read misfiled as
  a framing violation, and the symptom got written up as a firmware quirk
  instead of our own misclassification. Now `$FFFF` exits `C=0` with
  `udp_recv_ready` clear per §13.2, and `$8A` means a genuine over-claim.

  So on a current build, seeing `$8A` **is** worth investigating — the
  opposite of the previous advice. The code also moved from `$88` to `$8A`
  on 2026-08-24 so `$88`/`$89` can carry c64-https's `UCI_ERR_NO_SOCKET` /
  `UCI_ERR_WAIT_TIMEOUT` unchanged — logs before that date show this
  condition as `$88`, and logs before the sentinel fix show it constantly.
- **SOCKET_WRITE status arrives in the STATUS register, not
  RESP_DATA**, and the written-count is garbage for UDP —
  `src/net/uci/net.s` already handles both (`uci_chunk_len` override);
  don't "fix" it back.
- **`writemem` 404s for payloads >64 bytes** — use `run_prg` for
  anything bigger.
- **`udp_recv_ready` fires ~4× per Type-2** — known firmware buffer
  behaviour, not a bug; don't burn a run investigating it.

## 3. Session plan (wedge-budget-aware)

Each stage-2 live run is ~25 min wall-clock. With ≤3 runs per
power-cycle, the priority order is:

**Power-cycle #1**
1. **Run E first** — x25519-sibling `--dump-aead` (§5). Highest value:
   it advances Bug #2 regardless of outcome, and doubles as the
   x25519-sibling hardware bring-up for D.
2. Baseline stage-2 run, recording wall-clock (§4) — re-establishes the
   timing reference on current master.
3. chacha-sibling stage-2 run, recording wall-clock.

**Power-cycle #2**
4. both-siblings stage-2 run, recording wall-clock.
5. Spare slot: repeat whichever earlier run was inconclusive, or (if E
   went well) a baseline `--dump-aead` for side-by-side comparison.

## 4. Workstream D — A/B validation protocol

Per variant:

```bash
make clean && make BACKEND=uci <TOGGLES>
shasum -a 256 build/wireguard.prg        # must match §1 table
U64_HOST=10.43.23.81 U64_ALLOW_MUTATE=1 \
  /opt/homebrew/bin/python3.13 tools/test_uci_handshake_live.py --stage 2
```

(The test rebuilds via `make clean && make BACKEND=uci` itself unless
`C64_SKIP_BUILD=1` — set the toggle flags in the environment the test
inherits, or export `C64_SKIP_BUILD=1` after building manually and
verifying the hash.)

Record per run:

| Field | Where to get it |
|---|---|
| Variant + PRG SHA-256 | §1 table |
| Type-1 emit wall-clock | test log timestamps (boot → Type-1 sent) |
| Full handshake wall-clock | boot → stage-2 verdict |
| Stage-2 outcome | `STAGE 2 ✓` / AEAD failure / wedge |
| Wedge count this power-cycle | running tally against the ≤3 budget |

Success criteria for D: every variant completes Type-1 emit and gets a
Type-2 back on real hardware at 48 MHz/1 MHz; per-variant wall-clock
deltas vs baseline are explainable by the known implementation
differences (sibling x25519 is expected to shift DH timing; chacha
sibling shifts AEAD timing). Stage-2 *failure* with identical AEAD
symptoms as baseline is **not** a D failure — that's Bug #2 (§5).

## 5. Workstream E — Bug #2 AEAD divergence re-test

Background: after the Bug #1 fix (PR #32), stage 2 still fails — the
C64's `hs_h`/`aead_key` at AEAD-verify totally diverge from the
responder's (every byte differs; see the 2026-05-17 dump in
`artifacts/aead_diag2_*.log`). The v0.6.0 x25519 sibling has different
fe25519 mul/sqr implementations — if the in-tree arithmetic was subtly
wrong, the sibling build may simply *fix* stage 2.

The one command (run it against the **x25519-sibling** build, once,
after a fresh power-cycle):

```bash
U64_HOST=10.43.23.81 U64_ALLOW_MUTATE=1 \
  /opt/homebrew/bin/python3.13 tools/test_uci_handshake_live.py --stage 2 --dump-aead
```

Read these lines first:

```
post-Type-1 hs_h match: OK|MISMATCH | hs_c match: OK|MISMATCH
```

### Decision tree

- **`STAGE 2 ✓ — SESSION_ACTIVE reached`** → Bug #2 was in the in-tree
  fe25519 arithmetic; the sibling fixed it. Take the screenshot (first
  end-to-end WireGuard handshake from a C64 — it goes in `docs/`).
  Follow-ups: minimal in-tree repro to pin the bad routine; decide
  whether to default `USE_X25519_SIBLING=1`.
- **post-Type-1 `hs_h`/`hs_c` both match, AEAD still diverges** →
  Type-1 emit transcript is correct; bug lives in
  `hs_process_response`. Next: bisect by reading `hs_h`/`hs_c` after
  each step (4-byte progress markers in the .s + rebuild), or analyse a
  `--debug-capture` cycle trace of the first 30 s of
  `hs_process_response` (covers `mix_hash(resp_e_pub)` + first
  `kdf_1`).
- **post-Type-1 MISMATCH** → Type-1 emit transcript already diverged
  (despite the responder accepting Type-1 — the final
  `mix_hash(encrypted_timestamp)` isn't verified by anything on the
  responder side before `write_message`). Prime suspect:
  `hs_mix_hash` (`src/wg/handshake.s`) — if `b2s_remain` is clobbered
  between the two `blake2s_update` calls we hash `hs_h || junk`.
  Trace it.

### E pitfalls (from the Bug #2 letter — they cost runs)

- Each iteration is ~25 min: stage the post-T1 snapshot **and** any
  C64-side instrumentation into the *same* cycle. Never burn a run on a
  non-AEAD-related change.
- Don't extract `handshake_state.e` from python-noise after
  `handle_initiation` — it's deleted; the test already takes
  `e_pub_resp` from `type2_packet[12:44]`.
- Save the new `--dump-aead` log to `artifacts/` immediately.

## 5a. Chat, rekey and encryption verification (added 2026-08-17)

Three tools that need no staging beyond `--host`, and which restore the
shared device to 1 MHz themselves (including on Ctrl-C):

```bash
python3 tools/wg_chat.py --host <ip>                    # interactive, both ways
python3 tools/wg_demo.py --host <ip>                    # unattended dialogue
U64_ALLOW_MUTATE=1 \
  python3 tools/test_wire_encryption_live.py --host <ip>  # 9 wire assertions
```

- Both chat tools default to **48 MHz** and rekey at 140 s by driving the
  `H` menu entry over DMA (`tools/wg_c64_input.py`). `rekey_pending` has
  no consumer in the firmware, so without that a session dies at 180 s.
  Rekey costs ~126 s of compute at 48 MHz and is impossible at 1 MHz,
  where a handshake is ~7x the session lifetime.
- **`wg_state` reads `ACTIVE` for the whole ~90 s of a rekey's Type-1**,
  because `session_initiate` stores `SESSION_HS_SENT` only after the
  scalarmult (`src/wg/session.s:144-146`). Waiting for "state == ACTIVE"
  therefore succeeds instantly and proves nothing — wait for it to LEAVE
  active first.
- The encryption test uses the responder socket as its wire tap: we are
  the peer, so those bytes are exactly what the C64 transmitted. No pcap
  or sudo needed.
- **Control-plane caveat:** keystroke injection and key staging go over
  the Ultimate's REST interface, i.e. plain HTTP on port 80. That text
  crosses the LAN in the clear. Filter `not port 80` in any capture meant
  to judge the tunnel.

## 6. After the session

Record results (per-variant wall-clocks, stage-2 verdicts, the E
decision-tree branch taken) in an `artifacts/` log and update the
Bug #2 memory/letter with the branch that was eliminated. If stage 2
passed: screenshot into `docs/`, and workstreams D and E close
together.
