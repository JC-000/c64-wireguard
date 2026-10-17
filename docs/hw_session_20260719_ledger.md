# Hardware session ledger — 2026-07-19 — C64U @ 10.53.21.158

Device: "C64 Ultimate" (new product line), firmware 1.1.0, FPGA 122, core 1.49,
hostname C64-Ultimate-XXXXXX. NOT the U64E fw 3.14d the runbook targets.
Operating assumption (user decision): fw 3.14d quirk lore holds until proven
otherwise (≤3 run_prg per power-cycle, SOCKET_READ 512 cap, etc.).

## Config actions
- 21:17 bring-up: Command Interface Disabled→Enabled, REU already Enabled 512 KB
  (set by parallel nist-curves session), saved to flash, machine rebooted.
  NOTE: reboot done WITHOUT DeviceLock — disturbed the nist-curves bench. All
  subsequent device access goes through lock-aware tools only.

## run_prg budget ledger (per power-cycle, assume ≤3)
Power-cycle epoch #0 (state at session start; polluted by nist-curves bench
run_prg cycles + my 21:17 reboot — count unknown):
- [pending] echo probe run2 (queued on DeviceLock behind nist-curves bench
  PID 31301, bench_ecdsa_u64 --speeds 16,48,64, started 21:09)

Plan: physical power-cycle (user) after echo probe passes, before the
x25519-sibling --dump-aead money run.

## Run log
| # | time | what | outcome |
|---|------|------|---------|
| 1 | 21:18 | echo probe run1 (killed 21:29 — blocked on DeviceLock, output swallowed by tail buffering; no device interaction) | n/a |
| 2 | 21:29 | echo probe run2, queued on lock; acquired 21:37, died at stream_debug_start (HTTP 500 "No Operational Network Interface") BEFORE run_prg — no budget burned | fail (tooling) |
| 3 | 22:04 | echo probe run3 (debug-stream fallback patch) — run_prg #1 this epoch | **UCI PATH PROVEN**: boot+REU OK (9 s), net_init OK, 32-byte UDP echo round trip OK. net_dhcp $83 (GET_IPADDR=0.0.0.0) = fw 1.1.0 reporting quirk, display-only |

## 2026-07-20 morning — money-run attempts 1+2 (epoch #1, after user power-cycle)
| # | time | what | outcome |
|---|------|------|---------|
| 1 | 08:12 | x25519sib --dump-aead attempt 1 — run_prg POST timed out at 10 s (PRG actually loaded; first run_prg after cold boot is slow on fw 1.1.0) | fail (tooling); run_prg #1 |
| 2 | 08:15 | attempt 2 with 30 s client timeout — run_prg OK (17 s), but _wait_boot timed out: expected $FE sentinel, sibling init legitimately ends at $FC | fail (tooling); run_prg #2 |

Root cause of both: host-side. (a) client timeout too short for first run_prg
after cold boot → bumped to 30 s in test_uci_handshake_live.py. (b) _wait_boot
sentinel $FE is baseline-only: the c64-x25519 sibling's init overwrites the RAM
mul tables with pre-doubled rows, terminating at [255]=$FC (2*255*255=$1FC02).
Fixed _wait_boot to accept the unambiguous ([128],[255]) pair signatures
($7F,$FE) in-tree / ($FF,$FC) sibling. Device verified healthy both times
(menu on screen, doubled-row pattern confirmed at $9A40/$9A80/$9AFF).
REU banks 0-5 all written successfully ⇒ REU >128 KB works on fw 1.1.0.

## 2026-07-20 13:37 — MONEY RUN (epoch #2, fresh power-cycle, run_prg #1)
x25519-sibling --dump-aead, stage 2. Result:
- boot 17 s (new pair-sentinel worked); Type-1 emitted ~13.8 min after
  do_handshake start (faster than in-tree, as predicted for sibling DH).
- **STAGE 1 ✓** — responder accepted Type-1 (MAC1 + Noise read_message).
- **post-Type-1 hs_h match: OK, hs_c match: OK** (first-ever post-T1
  comparison) — Type-1 emit transcript branch of Bug #2 ELIMINATED.
- Type-2 (92B) received + packet bytes OK; session_handle_packet ~9.3 min.
- **AEAD verify: hs_h MISMATCH, aead_key/kdf_out3 vs K MISMATCH** —
  Bug #2 REPRODUCES with the sibling fe25519 ⇒ in-tree field arithmetic
  largely exonerated; bug localized inside hs_process_response
  (transcript/KDF chain or DH *input staging*).
- Dump archived: docs/evidence/aead_diag_x25519sib_20260720_135120.log
- Budget: epoch #2 has 2 run_prg slots left.

## 2026-07-20 14:09-14:13 — Bug #2 pre-screen (epoch #2, run_prg #2)
- First attempt at ZERO-cost trampoline reuse failed: the handshake test's
  cleanup zeroes the trampoline bytes under the idling CPU → BRK → machine
  derailed (menu on screen is stale; main_loop read "67 20 e6" garbage).
  Lesson: after any trampoline-driven test exits, the machine needs a fresh
  run_prg before further driving.
- Clean reload (run_prg #2) + trampoline: hardware unit tests 11/11 PASS —
  kdf_1 ×2, kdf_2, kdf_3 ×3 (incl. zero-psk message-2 shape + determinism),
  hs_mix_hash ×3 all match Python references byte-for-byte.
- ⇒ kdf_3 and hs_mix_hash EXONERATED on hardware. Remaining Bug #2 suspects:
  DH-input staging for message-2 (@copy1/@copy2 of resp_e_pub etc.) and
  message-2-only plumbing. Next: analyst's 6-slot ladder instrumentation run
  (epoch #2 slot #3).
- In parallel: tools/test_type2_slow.py launched in VICE (6 trials, warp,
  REU + PR#40 re-init fix applied to the script) against the SAME x25519sib
  PRG — full session_handle_packet path was NOT covered by the 07-16 VICE
  smoke (only helpers were), so a VICE repro of Bug #2 is still possible.
  Log: scratchpad/c64wg_type2_vice_x25519sib.log (hours).

## 2026-07-20 afternoon — Bug #2 hypothesis elimination + ladder instrumentation
- VICE type2 trials (test_type2_slow.py + REU/PR#40 fixes applied to script):
  **6/6 PASS in 48 s** on the exact hardware PRG ⇒ Bug #2 does NOT exist in
  emulation; it's a hardware-environment interaction. (The old "~100 min per
  X25519 in warp" docstring is obsolete — sibling+REU is ~50× faster.)
- REU/UCI corruption probe (epoch #2 run_prg #3, scratchpad
  c64wg_reu_uci_corruption_probe.py): fe25519_mul+sqr 40 vectors pre-UCI,
  echo round trip, 120 vectors post-UCI ⇒ **0 mismatches**. SOCKET_READ
  traffic does NOT corrupt single REU fe ops. Hypothesis refuted.
- Ladder instrumentation implemented (analyst's spec; analyst went
  unresponsive so implemented in main session):
  - src/wg/data.s: hs_dbg_ladder .res 192 (APP_BSS) + export
  - src/wg/handshake.s: 6× DBG_SNAP copies (slots: h post-mix_hash(re),
    ck post-kdf1(re)/kdf1(ee)/kdf1(se)/kdf3(psk), h post-mix_hash(tau))
  - tools/test_uci_handshake_live.py: _DIAG_LADDER responder capture
    (mix_hash/mix_key/mix_key_and_hash wraps, cleared at end of T1 read),
    ladder read+comparison+FIRST DIVERGENCE print in _dump_aead_state
  - Instrumented x25519sib PRG: SHA-256 ef1d2bf36a256c76e13b9739cf3c4a9d…,
    still 37,889 B, hs_dbg_ladder @ $8680
  - Validated: responder-ladder op sequence Mac-side (exact match, and
    mix_hash(tau).h == h_at_aead); instrumented build 6/6 VICE type2.
- Epoch #2 exhausted (3 run_prg + UCI). Next: power-cycle → instrumented
  --dump-aead run (epoch #3 run_prg #1).

## 2026-07-20 evening — ladder run + trample probes (epoch #3)
- 17:51 ladder run (run_prg #1, SHA ef1d2bf3): STAGE 1 ✓, post-T1 OK, but
  **FIRST DIVERGENCE at slot0** — the very first msg-2 op (mix_hash(re)).
  BOTH h and ck lanes wrong from their first steps. Responder verified
  correct (blake2s(h||e) reproduces resp[0] exactly). Offline brute of
  ~60 wrong-input candidates (truncations, offsets, swapped operands,
  alt pre-states): NO match for the C64's slot0.
  Log archived: artifacts/ (ladder run log). udp_recv after 1 poll.
- KEY STRUCTURAL FACT: VICE type2 test writes udp_recv_buf directly and
  never runs net_poll ⇒ net_poll's UCI receive path was the only
  VICE-unexercised code before the divergence.
- 18:18 trample probe (run_prg #2): pattern in hs_c..hs_dbg_ladder ($8400-
  $8680) survives the full echo sequence UNTOUCHED; ZP unchanged except
  $A2 jiffy. net_poll does NOT trample hs state (32B datagram case).
- 18:20 full-RAM probe (run_prg #3): before/after diff of $0000-$CFFF +
  $E000-$FFFF around the echo sequence = ONLY legitimate changes (SMC
  operands, net state vars, udp_recv_*, harness scratch $02A7 = SEND_BUF).
  Post-UCI mix_hash/kdf KATs 7/7 OK.
- Net: state clean, inputs clean, routines clean pre+post UCI, RAM clean,
  VICE-clean ⇒ leading hypothesis is **host DMA readmem polling
  interfering with the running computation** (fw 1.1.0 DMA path; the only
  mechanism scaling with the real run's 9-min grind that probes don't
  replicate and VICE cannot exhibit).
- Next run (combined build SHA 9eb26495, epoch #4 after power-cycle):
  slot11/12 entry h/ck + KAT@entry + reu_mul_init overlay + KAT@post +
  ee-DH operand/result capture + **poll_interval=30 s during
  session_handle_packet** (30× less DMA during crypto). Outcomes:
  slot11/12 wrong ⇒ pre-entry clobber (session preamble on hw path);
  all-OK + STAGE 2 ✓ ⇒ DMA-interference (or REU-reinit) fixed it, KAT
  disambiguates which; slot0 wrong again with clean entry ⇒ in-flight
  computation glitch confirmed.

## 2026-07-21 morning — combined run + offline analysis + probes (epoch #4)
- 09:24 combined run (SHA 9eb26495, run #1): STAGE 1 ✓, post-T1 OK. Verdicts:
  **slot11/12 (entry h/ck) OK; KAT@entry OK; KAT@post-reinit OK; ee operands
  OK; ee DH result == python X25519 (!)** — yet slots 0-5 ALL MISMATCH and
  AEAD failed (wg_state=1; step-carry is meaningless, not a return value).
  udp_recv_len=92 (no concatenated duplicates).
- Offline full-chain recompute (device RAM reads + host math):
  **responder is mathematically perfect** (h_at_aead/k match the correct
  chain exactly). C64 ladder wrong from slot0 AND does not self-cohere
  (slot2 != kdf1(slot1, ee) even with the DH result proven correct).
  Not the own-ephemeral mixup (tested). Duplicate-session artifact ruled
  out (exactly one Type-1 processed per run in all logs).
- 09:53 queued-data KAT probe (run #2): mix_hash/kdf KATs 7/7 PASS with
  unread 92-byte datagrams queued in the UCI socket. hs pattern intact.
- session.s reviewed: no mid-processing socket work; linear copy → 
  hs_process_response → transport_init.
- Current cornered fact: blake2s-family ops are wrong ONLY when executed
  in the real hs_process_response flow; correct in every trampoline
  context (fresh/post-UCI/queued) and in VICE, while fe25519/x25519 are
  correct EVERYWHERE including inside the failing flow.
- 10:0x in-context discriminator run launched (SHA dd10cad0, run #3):
  hs_mix_hash KAT over known constants INSIDE hs_process_response entry
  (slot13), determinism re-run of mix_hash(re) (slot14 vs slot0), full ZP
  snapshot at entry (hs_dbg_zp), + all prior instrumentation. Note:
  ld65 X25519_RODATA alignment warning observed on this build — layout
  address unchanged vs runbook ($0D40) and sibling's own $20-align assert
  holds; VICE 6/6 on this exact build.

## 2026-07-21 ~10:15 — ROOT CAUSE FOUND + FIXED (Bug #2 solved)

**Bug: `b2s_key_len` not restored after keyed BLAKE2s.** blake2s_init reads
the output length AND key length from ZP cells ($12 = b2s_key_len), not
from A/X — the `ldx #0` at every unkeyed call site (hs_mix_hash, hs_init,
kdf inner/outer) is a DEAD load. The two keyed callers, hs_compute_mac1
(handshake.s) and cookie mac2 (cookie.s), set b2s_key_len=32/16 and each
already restores b2s_out_len=32 — but NEITHER restored b2s_key_len.
hs_compute_mac1 is the LAST op of Type-1 emission; hs_process_response's
first op (mix_hash on the Type-2 ephemeral) then runs KEYED against the
stale mac1 key → every message-2 hash diverges → AEAD fails.

**Proof (offline, from combined-run device RAM):** C64 slot0 ==
blake2s(hs_h ‖ resp_e_pub, key=mac1_key, out_len=32, key_len=32) EXACTLY.
Tested all four (out_len,key_len) ∈ {16,32}² combos — only (32,32)
matches ⇒ out_len was fine (the existing restore works), key_len=32 was
the sole corruption.

**Why nothing caught it:** VICE type-2 tests inject the packet + call
session_handle_packet WITHOUT running session_initiate/mac1 first → cell
stays 0. Every crypto KAT re-writes b2s_key_len before init. My trampoline
probes never ran a keyed op immediately before an unkeyed one. It only
manifests on the real initiate→respond-same-machine path = the live
handshake. Firmware-INDEPENDENT — not a C64U/fw-1.1.0 issue at all; it
would fail identically on the U64E.

**Fix (committed to src):** add `lda #0 / sta b2s_key_len` beside the
existing b2s_out_len restore in BOTH keyed callers (hs_compute_mac1
handshake.s, cookie mac2 cookie.s). No new imports (b2s_key_len is a ZP
equate in zp_config.inc). Regression test tools/test_blake2s_keylen_
regression.py added: asserts b2s_key_len==0 after hs_compute_mac1.
Negative control verified — test FAILS ($20) with fix reverted, PASSES
with fix. VICE type2 still 6/6. Fixed instrumented PRG: SHA 0a936f1d.

Next: power-cycle → run fixed build → expect STAGE 2 ✓ (first end-to-end
C64 WireGuard handshake). Then strip debug instrumentation for the PR.

## 2026-07-21 ~11:46 — PR prep + green-handshake run (epoch #5)
- Separated the shippable fix from the debug instrumentation. Branch
  `fix/bug2-blake2s-key-len`, commit c97122e. Shipped: blake2s.s invariant
  comment, handshake.s (hs_compute_mac1 key_len restore + hs_mix_hash
  cleanup), cookie.s (mac2 key_len restore), test_blake2s_keylen_
  regression.py (new), + fw-1.1.0 device-enablement tooling fixes
  (test_uci_udp_echo_live pair-sentinel + debug-stream fallback,
  test_uci_handshake_live 30s timeout + net_dhcp tolerance, test_type2_slow
  REU+reinit). All Bug#2 diagnostic instrumentation reverted (data.s +
  handshake.s snapshots + test_uci_handshake_live ladder/H1/in-context).
- Clean fixed build ccb7d4ef validated in VICE: keylen regression 1/1
  (+ negative control fails), blake2s 64/64, handshake 22/22, type2 6/6.
- NOTE: the hardware green run uses the instrumented+fixed build 0a936f1d
  (has full ladder visibility); the clean PR build ccb7d4ef is proven
  equivalent by VICE + the non-interfering nature of the RAM-snapshot
  instrumentation. (2026-10-17: this ledger and its logs are now committed; logs in docs/evidence/.)
- Green run launched on fixed build; STAGE 1 ✓ (Type-1 @ 828.8s), Type-2
  received, session_handle_packet running with the fix.
- **12:09:47 — wg_state = 2, PASS — UCI WireGuard handshake stage 2.**
  FIRST END-TO-END C64 WIREGUARD HANDSHAKE. Ladder slots 0-5 ALL OK (were
  all MISMATCH pre-fix), in-context blake2s KAT (slot13) OK, aead_key==K.
  (hs_h at AEAD "MISMATCH" is a benign post-hoc artifact — the dump reads
  hs_h after the final ratchet, past the responder's capture point; the
  tag verified, which reaching SESSION_ACTIVE proves.) Handle time 571.5s.
  Log: docs/evidence/handshake_SESSION_ACTIVE_20260721_120948.log.
- Pushed fix/bug2-blake2s-key-len, opened PR #43.
- Remaining: Type-4 transport round-trip (stage 3) — the "tunnel carries
  data" milestone.

## 2026-07-21 12:47 — STAGE 3 PASS (bidirectional tunnel) — epoch #6
Added `--stage 3` to test_uci_handshake_live.py (branch feat/stage3-transport,
PR #44, on top of the fix). Full handshake → SESSION_ACTIVE, then:
- **Forward ✓**: C64 encrypted "HELLO WIREGUARD" → 47-byte Type-4 (counter
  0→1, tp_packet_len=47) → responder decrypted it (48454c4c4f... = correct).
- **Reverse ✓**: responder encrypted "PONG-FROM-PY-C64" → C64 decrypted it
  (tp_payload_len=16, plaintext matched at tp_packet+16).
- `PASS — UCI WireGuard handshake stage 3`, exit 0.
- Log: docs/evidence/transport_roundtrip_STAGE3_20260721_124736.log.
The C64 transport send/decrypt paths (transport_send, transport_decrypt,
do_send_test) worked first try on hardware — no code changes needed, just
the test harness. Full end-to-end WireGuard tunnel demonstrated on a C64.

## SESSION COMPLETE
Goal ("successful end-to-end handshake with a wireguard listener") achieved
and exceeded (bidirectional transport too). Bug #2 root-caused, fixed,
regression-guarded. PRs #43 (fix) + #44 (stage-3 test) open. Two optional
sibling submodule bumps still available (pre-existing, unrelated).

## Test-tooling notes discovered mid-session
- The handshake test's progress probes hardcode in-tree ZP addresses
  (x25_bit=$2B, fe_loop=$27); under USE_X25519_SIBLING the sibling's own
  zp_config means x25_bit reads a stale/unrelated byte (stuck $01 while
  fe_loop cycles). Cosmetic; consider label-driven probe addresses later.

## fw 1.1.0 findings so far
- `/v1/streams/debug:start` → HTTP 500 "No Operational Network Interface":
  no 6510 debug stream on this device. `--debug-capture` unusable; Bug #2
  bisection must use RAM progress markers instead.
- UCI GET_IPADDR returns 0.0.0.0 (net_dhcp errors $83) though sockets work.
  Test-side patches (uncommitted): echo test tolerates missing debug stream;
  handshake test warns-and-continues on net_dhcp failure. Fold into wrap-up PR.
