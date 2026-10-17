# Issue #128 — static analysis findings (read-only, no hardware)

Consolidated from six partial messages. Authoritative version.

Sources: `src/`, `libs/chacha20poly1305/`, `build/labels.txt`, `build/wireguard.map`,
commit `9fa1923`, and the raw run logs
`.../12f6305e-.../scratchpad/{sweep2.log,sweep3.log}` (not preserved).

---

## 0. THE PUZZLE THAT REMAINS — stated honestly

With counter-index confounding removed, the whole dataset reduces to a failure
*rate* per datagram size, pooled over both runs:

| `udp_recv_len` | inner (ct) | UCI blocks | block-2 bytes | failures |
|---|---|---|---|---|
| 99 | 67 | 1 | — | 0/8 |
| 536 | 504 | 1 | — | 0/6 |
| 1008 | 976 | 2 | 115 | 4/6 |
| 1109 | 1077 | 2 | 216 | 6/6 |
| 1191 | 1159 | 2 | 298 | 6/6 |
| 1247 | 1215 | 2 | 354 | 6/6 |
| 1338 | 1306 | 2 | 445 | 2/8 |

**Multi-block is necessary but not sufficient, and size does not order the
outcomes.** Every failure is a two-block read; but 1338 B is also a two-block
read and mostly succeeds. The rate rises from 0 to 100 % and then falls again.

**I cannot explain the 1338 escape.** Writing that down rather than papering
over it, as requested. What I can say precisely:

- A **pure race** in the block-staging state machine predicts a roughly
  *constant* rate for all two-block reads. The sampling window between our
  `DATA_ACC` and the firmware's `copy_result` does not obviously scale with the
  outstanding byte count. Observed rates are neither constant nor monotone.
- A **deterministic size threshold** is dead: the same size both succeeds and
  fails within one run (slack 1008 B succeeds at ctr 8 and 9, fails at ctr 10,
  in sweep3; namecheap 1338 B succeeds at ctr 20/21 and fails at ctr 22 in
  sweep2).
- A **time/position** explanation is dead: sweep3 fails at t=0 and succeeds from
  t=11.2 s to t=21.8 s; sweep2 succeeds from t=0 to t=9.7 s and fails from
  t=10.8 s. Opposite directions in the two runs.
- Eighteen consecutive failures at 1109/1191/1247 with zero successes, bracketed
  by partial rates at both edges, is not one mechanism I can name.

**The one structural hypothesis that would explain it, and how to test it for
free.** The 893-byte first-block payload is *inferred from a commit message*
(`9fa1923`), never measured by us. If the real block geometry differs — e.g. if
1338 B is actually a **three**-block read while 1109-1247 are two — the profile
becomes "two-block reads fail, one- and three-block reads pass", which is at
least a single coherent statement. That requires a block-2 capacity in
[354, 444]. I have no evidence for it. **The poison test in §2 measures the
firmware's true block boundaries directly** — the `stop` values will cluster at
whatever the real boundaries are — so this stops being a guess and becomes a
number. Nobody has ever measured them.

---

## 1. WHAT IS PROVEN (from the run logs, not inferred)

Decoding `recv_head[8:16]` as the peer's 64-bit LE counter across all 20
captured queries in **both** runs:

**Counters are 0..22, gapless, strictly increasing, no duplicates, no
reordering, no reset — in both runs.**

Consequences, each independent:

1. **Every query — success and failure — received exactly one inbound datagram**,
   at exactly the expected `udp_recv_len` (= DNS reply + 60). WARP answered
   every query. Peer-side rate limiting or a dropped session would show gaps.
   **The failures are ours, after the bytes are on the C64.**
2. **No re-handshake completed.** A completed re-handshake resets transport keys
   and restarts the peer counter at 0. It never resets. `transport_init` never
   re-ran; `rw_counter_max`/`rw_bitmap` were never re-zeroed mid-run.
3. `transport_decrypt` **ran and returned `$ff`** on every failing query. The
   screen during the outage is a repeating four-line block, one per query:
   `PACKET SENT OK / DECRYPT FAILED / KEEPALIVE / MSG>`. A *fresh* `DECRYPT
   FAILED` each time. The `@type4` `wg_state` gate prints nothing, so `wg_state`
   was ACTIVE throughout.
   (This also explains `screen_decrypt_fail_total` saturating at 6: 4 × 6 = 24
   lines fills the 25-line screen. That field was measuring screen geometry.)

### The five reject causes — four positively excluded

`transport_decrypt` has one `lda #$ff` exit shared by five causes, and one
printed string for all of them. That is what made this unfalsifiable.

| # | cause | verdict | evidence |
|---|---|---|---|
| 1 | type byte != 4 (`transport.s:405-410`) | **dead** | `head[0:4] = 04 00 00 00` on all 40 captures. Also structurally unreachable: `session_handle_packet` dispatches on the same byte and `net_poll` has exactly one caller, `main_loop` (`boot.s:287`) — no IRQ path, so the buffer cannot change in between |
| 2 | counter byte 7 >= `$10` (`REJECT_COUNTER_B7`, `constants.inc:50`) | **dead** | `head[15] = $00` on all 40. Would need a counter >= 2^60 |
| 3 | replay window | **dead by construction** | see below |
| 4 | `udp_recv_len < 32` | **dead** | 536-1338 observed |
| 5 | **AEAD tag mismatch** | **the survivor** | by elimination |

**Cause 3, dead by construction.** `transport.s:433-441`:

```
@replay_cmp:
        lda tp_recv_counter_tmp,x
        cmp rw_counter_max,x
        bcc @recv_less           ; -> can reach @replay_fail
        bne @recv_greater        ; -> jmp @replay_ok, unconditionally
        dex
        bpl @replay_cmp
        jmp @check_bitmap        ; all-equal -> can reach @replay_fail
```

`@recv_greater` jumps straight to `@replay_ok` on the first differing byte and
**never consults the bitmap**. A strictly greater counter is unconditionally
accepted. And a rejected packet does **not** advance the window (`@decrypt_fail`
is `lda #$ff / rts`; the advance runs only after `aead_decrypt` returns 0), so
through sweep2's twelve failures `rw_counter_max` stayed at 7 — which is exactly
why ctr 20 was still "greater" and still accepted. The window was **inert** for
these runs.

Also checked and correct: the advance loop clears exactly `(old_max, new_max]`
bit by bit (`transport.s:660-720`, `asl / bne / inc / iny` handles the byte
boundary); `transport_init` (`transport.s:94-134`) zeroes all 256 bitmap bytes,
`rw_counter_max`, both counters and `rw_new_counter`; the byte offset
`((c[1]&7)<<5)|(c[0]>>3)` is an exact 11-bit -> 256-byte map and `rw_bitmap,y`
with 8-bit Y cannot escape `$968F-$978E`, so it cannot reach `rw_counter_max`
(`$978F`) or `wg_state` (`$979A`).

`rw_bitmap` is **256 bytes / 2048 bits**; the 8-byte object is `rw_counter_max`.

**Separate defect found, opposite direction — file on its own:** `@clear_all`
(taken when shift >= 256 or any high byte differs) zeroes all 2048 bits
*including* counters already received and still inside the window, making them
replayable. It over-**accepts**, so it cannot cause these rejects.

### RETRACTED: my `tp_payload_len == 0` argument

`src/wg/timer.s:191-195`:

```
        ; Send keepalive (empty Type 4 packet)
        lda #0
        sta tp_payload_len
        sta tp_payload_len+1
        jsr transport_send
```

A failing query waits the full ~11 s DNS timeout; the 10 s keepalive fires
inside that window and zeroes the field before the tool reads it. A success
returns in ~1.5 s, ahead of any keepalive. The tell is in the same table:
**`tp_send_counter` advances by 2 per failing query and by 1 per successful
one.** `tp_payload_len == 0` does **not** show the AEAD was never reached.
Withdrawn.

### RETRACTED: the `wg_state` / 180 s expiry / 120 s rekey outage (mine and the lead's)

Killed three ways: (i) the fresh per-query `DECRYPT FAILED`; (ii) the
never-resetting peer counter (no re-handshake completed); (iii) the timestamps.

| | sweep2 | sweep3 |
|---|---|---|
| ACTIVE at | 11:03:09.786 | 11:08:54.208 |
| first failure | t = 10.8 s | ctr 0 at t = 0, then OK to t=21.8, fail from t = 23.9 s |
| recovery | t = 144.6 s | t = 136.1 s |
| `REKEY NEEDED` on screen | ~t = 120 s | ~t = 120 s |

Onset precedes the 120 s rekey by ~110 s in sweep2; the two onsets differ;
`REKEY NEEDED` correlates with *recovery*, not onset; and the "~4 s/query,
~48 s outage" arithmetic is wrong — failing queries take 11.1-11.3 s (the DNS
timeout), successful ones 1.0-1.8 s, so twelve failures is ~134 s.
`handshake_seconds` is logged once (48.3-48.5 s) and no second handshake appears.

### The 19->20 "boundary" dissolves

Every query received exactly one datagram, so **counter N ≡ query index N**, and
the ladder is fixed and identical in both runs:

```
ctr  8- 9-10 slack     1008      ctr 14-15-16 paypal    1191
ctr 11-12-13 bitbucket 1109      ctr 17-18-19 google    1247
                                 ctr 20-22    namecheap 1338
```

"Both runs recover at 19->20" **is** "1247 fails 6/6 and 1338 fails 2/8",
restated in counter coordinates. Not independent evidence. And the edge *is*
ragged where the rates are intermediate: 1008 starts the window at ctr 8 in
sweep2 but ctr 10 in sweep3; 1338 fails at ctr 22 in sweep2 but not in sweep3.
Only the 1109-1247 plateau is crisp, because those rates are 100 %.

---

## 2. (c) THE AUTOMATIC DECISION RULE

**Transition offset is 893 for all five sizes.** 1008/1109/1191/1247/1338 are
each exactly two blocks (893 payload in block 1 after the 2-byte header;
<= 895 available in block 2), so there is one expected copy stop, not a per-size
value. *Caveat: 893 comes from `9fa1923`'s commit message, not from our own
measurement — see §0.*

### The capture as currently specified CANNOT decide this

A stale tail and a fresh tail are both just bytes. Nothing in a single snapshot
of "last 32 B + 64 B straddling 893" distinguishes them. **impl-instrument must
add one of the two options below.**

### Option 1 — poison the buffer (best: unambiguous, single-shot, and it also measures the real block geometry)

Before each query, in addition to the existing zeroing:

```python
P = bytes(((i * 0x9D + 0x5A) & 0xFF) for i in range(1472))
tr.write_memory(L["udp_recv_buf"], P)
tr.write_memory(L["udp_recv_len"], bytes(2))   # NOT currently zeroed - add it
```

After the rung:

```python
B    = read(L["udp_recv_buf"], 1472)
stop = min(i for i in range(1473) if B[i:] == P[i:])   # bytes actually written
```

`stop` **is** the copy count — measured, not inferred.

| `stop` | verdict |
|---|---|
| `== 893` | truncation at the block-1 boundary |
| `== udp_recv_len` | fully received; the tag mismatch is **genuine** |
| any other value < `udp_recv_len` | truncation at an unexpected boundary — **report the value**, it is the real block geometry |
| `== 0` | nothing arrived (does not occur in these logs) |

A position-dependent fill means a false match needs every remaining byte to
coincide: ~2^-8 per byte.

Zeroing `udp_recv_len` matters independently: it is currently the one marker the
tool trusts but never clears, so "`udp_recv_len` == reply + 60" is not presently
proof of a fresh arrival.

### Option 2 — retain the previous query's capture (works with the regions already being built)

| region | short read at 893 | genuine tag mismatch |
|---|---|---|
| 64 B straddling 893 (offsets 861-924) | first 32 B **differ** from prev, last 32 B **identical** to prev | all 64 B differ |
| last 32 B (`len-32 .. len-1`) | **identical** to prev capture at those offsets | differ |

### What is actually in the tail — and the gap question

`udp_recv_buf` is `.res UDP_RECV_BUF_SIZE, 0` in APP_BSS, which the PRG loads as
zeros. So **byte *i* beyond the copy stop holds whatever the most recent
datagram that reached offset *i* wrote** — not necessarily the immediately
previous packet — and zeros only if no datagram ever reached that far.

Worked through sweep2, ascending: ctr 0 (1338 B) succeeded and filled
`[0, 1338)`. ctr 1-4 (99 B) and ctr 5-7 (536 B) overwrote only `[0, 536)`. So at
ctr 8 (1008 B), a truncation at 893 leaves the tail `[893, 1008)` holding
**packet 0's bytes at offsets 893-1007** — a 1338-byte datagram's mid-ciphertext.

**So: not zeros, and not the previous packet.** Expect coherent-looking
ciphertext from an older, *longer* packet. In an ascending sweep that opens with
a long query there is no zero zone at all. This is precisely why a single
snapshot cannot decide it.

### Strongest single check, if you want one number

Read `hs_transport_recv` (`$8A40`, 32 B) once at session start. On each failure
read all `udp_recv_len` bytes of `udp_recv_buf` and verify Poly1305 host-side:
nonce = `00 00 00 00` ‖ `buf[8:16]`, AAD empty, ct = `buf[16:len-16]`,
tag = `buf[len-16:len]`.

- **Tag verifies** -> buffer intact -> the on-device AEAD is wrong.
- **Tag fails** -> the bytes are wrong -> Option 1 localises the stop.

---

## 3. (d) VICE-ONLY REPRODUCTION — no for the UCI path, yes for half the problem

**A delay before `net_poll` cannot be tested in VICE.** `9fa1923` states it
plainly: *"VICE has no UCI"*. The multi-block `SOCKET_READ` path does not exist
in the emulator — not untested, absent. Reproducing it would mean writing a stub
for the UCI register interface and the four-state FPGA protocol
(`UCI_STATE_IDLE/BUSY/DATA_LAST/DATA_MORE`), and a stub that reproduces the race
is a stub that already encodes the answer.

**The CS8900a / park-the-CPU trap makes it worse, and is worth stating for the
record even though it is not the binding obstacle.** The project's own note is
that the VICE monitor *halts emulation between commands* — `time.sleep()` on the
host does not advance the C64. So even on the ip65 backend you cannot create
"time passes on the C64 while the datagram waits" from the host side; the delay
would have to be a busy-wait compiled into the C64 program itself. And ip65's
`net_udp_recv_cb` (`src/net/ip65/net.s:751-874`) is entirely different code with
no multi-block read, so a delay test there proves nothing about UCI.

**What VICE *can* settle, and it is the cheaper experiment — run it before
spending the device.** The other surviving candidate is fully testable off
hardware. Extend the sibling library's AEAD cross-check against pyca to the
exact ciphertext lengths in play:

```
libs/chacha20poly1305/tools/test_chacha20_poly1305.py:756
AEAD_PT_SIZES = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512]
                                                     ^ current ceiling
-> [504, 976, 1077, 1159, 1215, 1306, 1440]
```

Built with the WG define set (`POLY1305_MULTIPLY_ROLLED_OUTER=1`,
`SHARED_CT_MUL_8X8=1`, `SHARED_SQTAB_INIT=1`, `LIB_NO_BARE_EXPORTS=1`; see
`tools/integration/build_chacha20poly1305.sh:38`).

- **Red** -> the bug is found with no hardware at all.
- **Green** -> the AEAD is exonerated at every failing length, only the receive
  path remains, and the hardware run becomes targeted rather than exploratory.

Coverage gap for context: the functional suite stops at **512-byte** plaintexts;
`audit_cross_check.py:93` caps the randomised audit at `MAX_PT_LEN = 1024` with
uniform-random lengths, so >= 976 is drawn ~5 % of the time. Every failing
length is above the functional ceiling; 504 — the largest never-failing size —
is the largest tested one. That coincidence is why this candidate is still live.

**Verdict: (c) and (d) together cannot settle it without hardware, but (d) can
halve it for free. Run the VICE AEAD sweep first; spend the device only on
Option 1 if it comes back green.**

---

## 4. INSTRUMENT — exact addresses

Read from `build/labels.txt` **of the PRG that actually ran**. Do not hardcode:
I found stale cached values for three symbols (`net_last_error` is `$7C32`, not
`$7957`; `rekey_pending`/`hs_timer_armed` are `$9E14`/`$9E15`).

| symbol | addr | bytes | why |
|---|---|---|---|
| `wg_state` | `$979A` | 1 | `$00` IDLE / `$01` HS_SENT / `$02` ACTIVE. `!= $02` -> dropped at the `@type4` gate |
| `session_start_jiffy` | `$9E0E` | 3 | handshake epoch |
| *(live jiffy)* | `$00A0` | 3 | `elapsed = jiffy - session_start_jiffy` |
| `rekey_pending` | `$9E14` | 1 | `!= 0` -> past 120 s |
| `hs_timer_armed` | `$9E15` | 1 | re-handshake in flight |
| `last_send_jiffy` | `$9E11` | 3 | keepalive liveness |
| `tp_payload_len` | `$90AE` | 2 | **pair with `tp_send_counter`; discard when it advanced by >1** |
| `tp_send_counter` | `$9090` | 8 | the keepalive tell |
| `udp_recv_len` | `$9077` | 2 | zero before each query |
| `udp_recv_buf` | `$8A9B` | 16+ | `head[0]` type, `head[8:16]` counter |
| `rw_counter_max` | `$978F` | 8 | resolves a pre-step-4 reject |
| `hs_transport_recv` | `$8A40` | 32 | host-side Poly1305 verification |
| `net_last_error` | `$7C32` | 1 | adapter error |

Thresholds (`src/wg/timer.s:58-63`, 60 Hz): keepalive 600 j = 10 s; rekey
7200 j = **120 s**; expire 10800 j = **180 s** -> `session_reset`.

No symbol records that expiry *fired* — it only prints. Detect via `wg_state`
leaving `$02`, and by grepping the screen dump for `"SESSION EXPIRED"`
(`strings.s:114`) / `"REKEY NEEDED"` (`strings.s:112`). `dump_screen` already
runs on every timeout (`test_warp_live.py:962`) and greps for one string only.

**Record both clocks.** `timer_elapsed_cmp` uses the KERNAL jiffy, which stalls
while interrupts are masked during crypto — so the device's 180 s fires later
than 180 s wall-clock, by an amount proportional to how much crypto ran, i.e.
proportional to packet size. Their divergence would otherwise read as more
evidence for a size bug.

**Decode `recv_head[8:16]` as a counter per query.** The gapless sequence is the
single most informative number in these logs and it sat undecoded in a hex
string:

```python
q["recv_counter"]  = int.from_bytes(head[8:16], "little")
q["counter_b7_ok"] = head[15] < 0x10        # type4_ok only checks bytes 0-3
```

### Classifier

```
if wg_state != 0x02              -> NOT_ACTIVE (expiry/rekey)
elif udp_recv_len == 0           -> NEVER_ARRIVED
elif head[0:4] != 04 00 00 00    -> CAUSE_1 type byte
elif head[15] >= 0x10            -> CAUSE_2 counter byte 7
elif LE64(head[8:16]) <= LE64(rw_counter_max) -> CAUSE_3 replay
elif stop == 893                 -> TRUNCATED_BLOCK_1
elif stop < udp_recv_len         -> TRUNCATED_AT_{stop}   (report it)
elif poly1305_ok(B)              -> BUFFER_INTACT (on-device AEAD wrong)
else                             -> GENUINE_TAG_MISMATCH
```

`tp_payload_len` appears nowhere in this rule, by design.

### Instrument defects to fix regardless

1. **`decrypt_failed` is a stale-screen read.** `test_warp_live.py:932-933`
   tests `"DECRYPT FAILED" in screen.split("MSG>")[-1] if recv_len == 0`.
   `"MSG> "` (`strings.s:101`) is the **input prompt**; the per-message header is
   `"MSG: "` (`strings.s:103`). The split window spans several rungs on a 25-line
   scrolling screen, so a failure at rung *k* is re-attributed to *k+1, k+2, …*
   The flag means "no reply arrived AND some `DECRYPT FAILED` is still visible".
2. **`transport_decrypt` has five reject causes behind one `lda #$ff` and one
   printed string.** Five distinct messages, or a five-entry cause counter,
   would have answered #128 in one run. This is the root instrumentation defect.

---

## 5. ISSUE #130 — the short-read fall-through

**Answer to "regression or incomplete fix": incomplete, and knowingly so. Not a
regression.** `9fa1923` narrowed the fall-through by carving one state out of it:

```diff
-        cmp #(UCI_STAT_STATE)   ; $30 = Data More
-        bne @done_data          ; Data Last with bytes outstanding: short
-                                ; reply, take what we got rather than hang
+        cmp #UCI_STATE_DATA_MORE
+        beq @block_more
+        cmp #UCI_STATE_BUSY
+        bne @done_data          ; Data Last / Idle with bytes outstanding:
+                                ; short reply, take what we got
```

The commit message states it as intent: *"$10 Command Busy -> bounded wait…
**$20/$00 with bytes outstanding -> short reply as before**"*.

**The framing that makes it a bug rather than a design choice:** the *same
commit* made the neighbouring truncation path fail loudly — *"Expiry is an error
exit ($89, `udp_recv_ready` stays 0) instead of delivering the partial buffer"*
(`@block_wedged`, `net.s:1383`, whose comment reads "The datagram is
unrecoverable … so this is an error exit, NOT a delivery of the partial
buffer"). **Two adjacent terminal conditions with identical consequences get
opposite treatment.** The fix is to apply the existing reasoning to `$20`/`$00`.

### Blast radius

Complete consumer list for `udp_recv_len` (`find_referencing_symbols`):

| consumer | uses it as | exposed | notices? |
|---|---|---|---|
| `session.s:347,361,373` @type4 | copy count -> `tp_packet`, `tp_packet_len` | yes | only via AEAD |
| `transport.s:513,517` @replay_ok | `tp_payload_len` | yes | only via AEAD |
| `session.s` @type2 (92 B) / @type3 (64 B) | fixed-size copies | no | single block |
| ip65 `net_udp_recv_cb` | separate adapter, own 1500 cap | n/a | different path |

Three amplifiers:

1. **`udp_recv_buf` is never cleared between datagrams**, so a short copy leaves
   an older packet's bytes in the tail, and `session.s` copies them onward into
   `tp_packet`. `ip_build.s:445-460` already documents this exact class one layer
   up (issue #97 — a keepalive could make a peer's previous message reprint).
2. **Raw consumers have no backstop.** `test_uci_udp_echo_live.py` and
   `test_uci_udp_size_probe.py` read `udp_recv_buf` against `udp_recv_len`
   directly. Their byte-exact checks would catch it — likely why they never
   have — but any tool trusting the length without verifying content accepts
   residue silently, and nothing in the adapter raises.
3. **Precedent.** Issue #62 was this same field trusted *upward* — `net_poll`
   believed a returned length and copied ~18 KB through `$D000`, leaving
   WireGuard bytes in the VIC registers. That fix bounded it above
   (`UCI_ERR_LONG_READ`). This is the same trust, downward.

**The invariant "`udp_recv_len` is a byte count" is not maintained by
construction.** Cleanest fix: write the **actual copied count**, not the
announced total.

### Correction needed in #130

The sentence citing my `tp_payload_len` argument is wrong. The correct wording
is **not** "it is the cause of #128" but: *"the short read is **not excluded** as
a cause of #128; the argument previously given for excluding it was invalid."*
It is one of two surviving candidates. Its fit:

| observation | short read explains it? |
|---|---|
| every failure `> 893`; 99 B and 536 B never fail (0/14) | yes — it can only fire on two-block reads |
| same size, different outcome | yes — a race is non-deterministic |
| `udp_recv_len` correct, header intact, only the tag fails | yes — bytes 0-892 untouched |
| the rate profile 67/100/100/100/25 % | **no** (see §0) |

---

## 6. NEGATIVE RESULTS (things ruled out, so nobody re-hunts them)

**Length branches verified 16-bit clean** — all test the high byte before the
low and handle `hi != 0` first; no page-crossing or 8-bit truncation:

- `transport_decrypt` ciphertext copy — `src/wg/transport.s:540`
- `transport_decrypt` tag-pointer add — `src/wg/transport.s:572`
  (full 16-bit `adc tp_payload_len` / `adc tp_payload_len+1`)
- `session_handle_packet` @type4 copy — `src/wg/session.s:352`
- `transport_encrypt` plaintext copy — `src/wg/transport.s:288-312`
- `aead_process_padded` — `libs/chacha20poly1305/src/lib/chacha20poly1305_lib.s:279`
- `chacha20_encrypt` — `cc20_remain_hi` tested first
- `net_poll` SMC receive cursor — `src/net/uci/net.s:1308`
- `net_poll` header-vs-cap compare — `src/net/uci/net.s:1240-1252`
  (correct for a high byte of 4; `UCI_READ_CHUNK_MAX` = 1472 = `$05C0`)

**No buffer overlap.** `udp_recv_buf $8A9B` + 1500 = `$9077` = `udp_recv_len`
exactly; `tp_packet $90B0` + 1500 = `$968C` = `tp_packet_len` exactly. Max write
is 1472 (session copy) / 1472 (encrypt) / 1456 (decrypt); neither sentinel is
reachable at any size in the table. SQTAB is a linker hole at `$8000-$83FF` with
`APP_EXTRA` at `$8400`.

**Poly1305 cannot overflow.** `poly1305_reduce` leaves h < 2^130 + 5·2^124;
`poly1305_block` adds < 2^128, so h < 2^131 and h·r < 2^255, inside
`poly_product`'s 33 bytes. `poly_ripple`'s `cpx #33` bound
(`poly1305_lib.s:663`) is never reached, and no carry out of `poly_h+16` is
possible. The block-add carry chain is intact (`lda abs` and `iny` do not touch
C). None of it is length-dependent in any case.

**No `$16`/chunked-write constant on the read side.** `UCI_CHUNK_PART_MAX` (888)
appears only in `uci_send_part`; the read path uses `UCI_READ_CHUNK_MAX` only.

**Block count does not discriminate.** Every size from 1008 to 1338 is exactly
two blocks. A 2-vs-3-block split cannot separate them (unless the block geometry
is not what the commit message says — §0).

**`MSG_TEXT_MAX` build caveat.** `MSG_TEXT_MAX = WG_MTU - 28`. The runs used
`WG_MTU = 1440` (confirmed in both logs' PRG fingerprint lines:
`WG_MTU=1440 uci_send_part=True`), so 1412 — above every rung. On a
non-chunked build it would be 832, and rungs above that hit bound (1) in
`udp_tunnel_parse` (`ip_build.s:438-446`), whose `@fail` path leaves
`msg_recv_len` **non-zero** — a false *pass*, not a false failure. Not in play
here, but worth knowing before comparing against any default-build run.

---

## 7. THE ORIGINAL PREMISE, CORRECTED

Issue #128's "1049-1187 B fail 9/9, 476 B and 1278 B succeed" reads that way
because the table bolds only the 3/3 cells. Read as failures-out-of-6, 948 B
fails 3/3 in run 1 and 1278 B fails 1/3. The band was never as sharp as stated;
the sweep is also strictly ascending, so size was confounded with elapsed time,
session age and send counter. That confound is now removed (§1) and the residual
size-shaped *rate* is real but unexplained (§0).
