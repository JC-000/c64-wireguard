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
of `$A000` BASIC ROM shadow with ~700 bytes headroom. That headroom is
`BACKEND=uci` slack only: under `BACKEND=ip65` the same span from `$A000`
is `IP65_BSS`, the ip65 blob's private BSS (issue #80), so growth past
`$9FFF` is not free there.

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
- [ ] **Identify the IMAGE, not just the device.** `python3
      tools/u64_firmware.py <host>` reads `/v1/info`'s `git_commit_hash`
      (added upstream 2026-09-03, alongside `ethernet_mac` / `wifi_mac`).
      Read-only and lock-free, so it is safe before anything else and
      safe while another lane holds the device. It answers *which image
      is flashed* — `[chunked]` for an image this repo has measured,
      `[unknown]` for one it has not (a warning, never a refusal: the
      next legitimate rebase lands there), `[no-hash]` for firmware
      predating the field. It does **not** answer whether the `$16`
      handler dispatches; only sending it does, and the chunked send
      path's `$8E` (`UCI_ERR_CMD_UNKNOWN`) remains that proof. Do not
      treat a green hash as a substitute for the probe.
      **A reflash resets device config to defaults** — Command Interface
      back to Disabled (`$DF1C` reads `$FF` until it is re-enabled *and*
      the C64 is reset) and any other bench settings gone. The live
      tools re-enable it themselves; a hand-driven session must not
      assume it survived.
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

### Device quirks that will bite you (measured on firmware 3.14d)

**The UCI backend now requires firmware 3.15 or later** (multi-block
`SOCKET_READ`, GideonZ/1541ultimate#806); 3.14d is unsupported because its
893-byte read cap and the 894-request hang below cannot be worked around from
our side. The 3.14d notes are kept because the other quirks still apply.

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
- **SOCKET_READ: request up to 1472 bytes (`NET_UDP_RECV_MAX`) — and validate
  the length it returns.** On firmware 3.15+ a read larger than one reply
  block comes back as several `Data More` blocks that the adapter
  concatenates (GideonZ/1541ultimate#806); a datagram the request can't hold
  is reported as `04,DATAGRAM TRUNCATED` instead of being cut silently. 1420
  and 600-byte datagrams verified arriving whole in one `net_poll`.

  **Why 3.14d is unsupported (historical):** its limit was a single 894-byte
  reply (`CMD_MAX_REPLY_LEN` 896 minus the 2-byte header). Anything above
  was rejected with `82,PARAMETER(S) OUT OF RANGE` **on the status channel**,
  which this adapter drains without reading, so a rejected read looked like
  an empty one; a read of *exactly* 894 built a 896-byte reply — the
  response-queue size — and the FPGA held the pointer at the last byte while
  still asserting `DATA_AV`, so the queue repeated forever. The safe request
  there was 893, and the remainder of a larger datagram was discarded.

  **Before 2026-08-26 this was "always request 512", and that was our own
  number, not the firmware's.** Having only ever asked for 512 we only ever
  received 512, and read that back as a hardware ceiling; the one larger
  request tried (1024) was above the real cap and being rejected on a channel
  we ignore. Upstream: GideonZ/1541ultimate#802.

  On fw 3.14d a datagram larger than the request is truncated with the
  remainder **discarded** — which is why 3.14d is no longer supported.
  fw 3.15's multi-block reads (GideonZ/1541ultimate#806) lift the receive
  side to 1472 B, the largest that reaches the device at all
  (`IP_REASSEMBLY = 0`, device-wide).
  `NET_UDP_RECV_MAX = 1472` in `src/net/uci/net_caps.inc`.
- **SOCKET_WRITE: 892 bytes per datagram, and this is what pins the MTU
  (2026-08-27).** Stock 3.15 has no continuation command, so anything larger
  goes out as two datagrams and the peer drops both. Hence
  `NET_UDP_SEND_MAX = 892` and `WG_MTU = 892 − 32 = 860` (not 861, which was
  read-side arithmetic). The host tools take these from `build/labels.txt`
  via `tools/c64_caps.py` (the .inc files are only a fallback, and they
  describe the DEFAULT build); do not hardcode them.
- **Chunked send, `make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1` (issue #70,
  device = the GideonZ/1541ultimate#807 spike firmware ONLY).** Every
  datagram goes out as `$16` parts of ≤ 888 bytes (`uci_send_part`, present
  in labels.txt only for this build); the firmware emits one wire datagram of
  up to 1472, so `NET_UDP_SEND_MAX = 1472`, `WG_MTU = 1440`, peer `MTU =
  1440`. Build ONCE and run every live tool with `C64_SKIP_BUILD=1` — the
  live tools rebuild without the flag otherwise; check the PRG fingerprint
  line. On stock 3.15 the first send fails with `$8E` (`21,UNKNOWN
  COMMAND`) and the screen prints `SEND FAILED, NET ERR $8E`. After a
  non-completing part the adapter leaves `uci_resp_count` / `uci_write_resp`
  / `uci_status_buf` readable over DMA: `uci_resp_count` should read 0 if the
  spec's "no reply for a non-completing part" holds — that is the one reply
  semantic the bench did not verify, so read it.

- **Receive-side fix — multi-block `SOCKET_READ` race, ALL builds
  (`9fa1923`, PR #112, 2026-09-03).** `net_poll`'s continuation path acked a
  `Data More` reply block and then sampled interface STATE **once** to
  decide whether another block was coming. On the firmware side the next
  block is staged by an interrupt, a FreeRTOS queue post, a task switch and
  a memcpy — a window unrelated to the 6510's clock: ~17 ms of surrounding
  `uci_fence` hides it at 1 MHz, but at 48 MHz turbo (~340 µs) the sample
  routinely landed on stale `01` (Command Busy), read as "reply complete",
  and the adapter delivered only the first 893-byte block while
  `udp_recv_len` still reported the full (larger) total — a silent
  truncation, not an error. Fixed by `uci_wait_reply_staged` (TOD-bounded,
  1 s, `$89` on expiry), which spins on STATE between blocks instead of
  sampling once. See `UCI_STATE_*` in `src/net/uci/uci_regs.inc` and the
  `@block_end` comments in `net.s`. Applies to every build, chunked or not.

  Verify on the **default** build:

  ```bash
  make clean && make BACKEND=uci REU=0
  C64_SKIP_BUILD=1 ECHO_TURBO_MHZ=48 ECHO_REPLY_LEN=893,894,1452,1472 \
      U64_ALLOW_MUTATE=1 python3 tools/test_uci_udp_echo_live.py
  ```

  Expected: all four reply lengths (893, 894, 1452, 1472) received
  byte-exact at 48 MHz. Before the fix the same four sizes passed 58/60 at
  48 MHz (60/60 at 1 and 8 MHz) — the two failures were the silent
  truncation above, not flakiness.

- **Chunked build, bidirectional, at turbo (issue #70, PR #112,
  2026-09-03, GideonZ/1541ultimate#807 spike firmware ONLY).** With the
  receive-side fix in place:

  ```bash
  make clean && make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
  C64_SKIP_BUILD=1 python3 tools/test_wire_encryption_live.py --turbo 48
  ```

  Run twice against the Python responder **left at WireGuard's own default
  MTU of 1420** (no per-peer MTU configuration): **60/60 both times**.
  Outbound text of 828-1412 characters produced datagrams of 888, 889, 891,
  892, 893, 1452 and 1472 bytes, each exactly one wire datagram; inbound
  860/861/1420/1440-character messages arrived and displayed correctly. A
  companion echo sweep on the same build and speed round-tripped every size
  from 888 to 1472 bytes as one datagram each; 1473 was refused locally
  (`$8C`) with nothing sent. Net result: WireGuard runs bidirectionally at
  MTU 1440 with the peer untouched at 1420, because 1420 already fits under
  the C64's 1440 ceiling.

  Tool knobs used by these two procedures: `ECHO_TURBO_MHZ`,
  `ECHO_REPLY_LEN`, `ECHO_PAYLOAD_SWEEP` (`tools/test_uci_udp_echo_live.py`);
  `C64_UCI_CHUNKED_WRITE=1` selects the flag build for tools that build for
  you; `C64_SKIP_BUILD=1` **always** after a manual flag build — otherwise
  the live tools rebuild WITHOUT the flag and silently test the wrong PRG,
  so check the fingerprint line every run; `wg_c64_input.send_message_dma`
  stages a long outbound message over DMA instead of hand-typing it;
  `tools/c64_caps.py` reads `build/labels.txt` before falling back to the
  `.inc` files, so its numbers reflect whichever build actually shipped.

  **The red-screen incident (PR #62) was the sentinel, not an over-claim.**
  `net_poll` trusted the response header as a byte count and fed it to an
  unbounded copy. On an empty read that header is `$FFFF`, so the copy ran
  65535 bytes from `udp_recv_buf` — which reaches `$D000` after 17,964
  bytes, i.e. the "~18 KB" walk through the VIC registers that zeroed
  `wg_state`, repointed the screen via `$D018` and reddened the border via
  `$D020`. The arithmetic matches the observed damage exactly, and **no
  firmware over-claim is required to explain any of it**. Fixed by clamping
  against `UCI_READ_CHUNK_MAX` and dropping the read; the sentinel is now
  excluded first (below).

  The wider lesson, and the reason this is worth the space: never let a
  device-supplied count be the only bound on a store loop, and exclude the
  sentinel before doing any arithmetic on a length.

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
U64_ALLOW_MUTATE=1 \
  python3 tools/test_config_reload_live.py --host <ip>    # 16 endpoint-move
```

`test_config_reload_live.py` is the hardware check for #65: it brings up a
session pinned to peer A, moves `cfg_peer_endpoint_port` to peer B, and asks
where the next datagram goes — with **A still bound and listening**, so "not
A" is measured rather than assumed. It also distinguishes a real
`SOCKET_CLOSE` from `uci_wait_idle`'s timeout leg, which the VICE stub tests
cannot: both drive `uci_socket_open` to 0, so it additionally requires a
`$EE` sentinel in `net_last_error` to survive and the close to land well
inside the ~1.5 s TOD budget. Defaults to REU=0 (#69) and 48 MHz, and
restores 1 MHz on the way out.

`--soak N` is a different question on the same box: N consecutive PRG loads
driven to `net_init` + a real `UDP_CONNECT`, for #58. The socket is
**abandoned** by default and `--soak-close` is the comparison — #58 is a leak
of abandoned sockets, so closing each one would answer the wrong question.
Do not "fix" the default.

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

## 5b. Real-peer (Cloudflare WARP) interop (added 2026-09-03)

[#70](https://github.com/JC-000/c64-wireguard/issues/70) / [#87](https://github.com/JC-000/c64-wireguard/issues/87). Tests against a **real** WireGuard responder — Cloudflare WARP — instead of the project's own patient Python responder. The profile holds a private key: generate it *outside this repo* and never commit it.

```bash
brew install wgcf wireguard-tools
cd ~/somewhere-not-c64-wireguard && wgcf register --accept-tos && wgcf generate

make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1
make BACKEND=uci REU=0 UCI_CHUNKED_WRITE=1 MSG_PORT=53 BUILD_DIR=build_msgport53   # own tree + lib/; do NOT `make clean` in between (it wipes build/)

WARP_PROFILE=/path/to/wgcf-profile.conf U64_HOST=<device-ip> \
    python3 tools/test_warp_live.py

# ip65 / RR-Net (issue #70): generic WG_MTU1440 knob, --backend ip65 (DHCP runs at 1 MHz, turbo after net_initialized)
make BACKEND=ip65 REU=0 WG_MTU1440=1
make BACKEND=ip65 REU=0 WG_MTU1440=1 MSG_PORT=53 BUILD_DIR=build_msgport53
WARP_PROFILE=/path/to/wgcf-profile.conf U64_HOST=<device-ip> \
    python3 tools/test_warp_live.py --backend ip65
```

Expected stage output (2026-09-03, U64E, upstream test-merge `d33b7802` + the [#807](https://github.com/GideonZ/1541ultimate/issues/807) spike, reporting fw 3.15 / fpga 124 / core 1.4F):

- Stage A/B: `Stage A: ACTIVE in 48.5s` (log line), then `PING REPLY OK` on screen.
- Stage C: a fresh `ACTIVE in ~48s` on the `MSG_PORT=53` PRG, then `reply_recv_len=1278` for the `namecheap.com` TXT query (the second query, above ~1280 B, is truncated by `1.1.1.1` inside WARP itself — expected, not a failure of this tool).

**Re-measured 2026-09-03 on the rebased spike** (`git_commit_hash a474a7ed` =
upstream test-merge `883f608d` + the #807 commits, fpga **125** — upstream rebuilt
the bitstream to decode `FENCE` as a NOP), with `--rekey 2`, seed `775774406`:
Stage A ACTIVE in 47.9 s, rekey 1/2 at 48.3 s / 48.1 s with `hs_timestamp`
strictly increasing (`…fadd/01` → `…fadf/02` → `…fae1/03`), Stage C 47.8 s,
`reply_recv_len=1278` ancount 15. The >1280 B query returns `len=39` ancount 0 —
Cloudflare resolver policy inside WARP, not our MTU and not the firmware.

Read that result together with the firmware lane's own: `uci-net-target` scored
197 checks / 40-of-40 / 0 failures on this image, identical to its score on the
previous one. Neither half stands alone — our interop run cannot separate a
firmware fault from a WireGuard one, and their suite says nothing about a real
peer. Together they are a claim of **parity with the previous image**, not a
general clearance of `883f608d`, and not a statement about ip65. Their gate's
default QUICK profile does **not** select `uci-net-target` (it is registered in
DEEP), and their runner takes **no device lock at all** — so lockfile state says
nothing about whether that lane is on the device. Coordinate by message.

**Restore:** on a clean run, the tool's own Stage D sets 1 MHz / REU off and asserts both by read-back, so no manual restore step is needed. Only the `DeviceLock` release is in a `finally` — an exception during Stage A/B/C skips Stage D and leaves the device at 48 MHz. Check `GET /v1/configs/U64%20Specific%20Settings` after any run that errored and restore turbo by hand if it is still fast.

Only one handshake per staged TAI64N base time is accepted by a real peer (#87); this tool stages a fresh base time and a fresh `run_prg` before each of its two handshakes rather than rekeying in place.

## 6. After the session

Record results (per-variant wall-clocks, stage-2 verdicts, the E
decision-tree branch taken) in an `artifacts/` log and update the
Bug #2 memory/letter with the branch that was eliminated. If stage 2
passed: screenshot into `docs/`, and workstreams D and E close
together.
