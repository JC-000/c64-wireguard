# Can the short read be recovered? — analysis for #128

Read-only. No tree changes, no device access.

Sources actually read (not paraphrased from the issue):

- `src/net/uci/net.s` — `net_poll` (lines 1098–1423), `@block_end` at ~1366
- `src/net/uci/uci_cmd.s` — `uci_wait_reply_staged` (286–327), `uci_ack` (393–416),
  `uci_wait_not_busy` (222–285), `uci_push_wait` (354–373), `uci_drain_resp` (504–570),
  `uci_drain_status` (571–671), `uci_abort` (64–137)
- `src/net/uci/uci_regs.inc`, `src/net/uci/uci_errors.inc`
- `~/Documents/1541ultimate` @ `870b5afd`:
  - `fpga/io/command_interface/vhdl_source/command_protocol.vhd` (**the RTL — this is what settles it**)
  - `fpga/io/command_interface/vhdl_source/command_if_pkg.vhd`
  - `software/io/command_interface/command_intf.cc` / `.h`
  - `software/io/network/network_target.cc` / `.h`

---

## 0. Bottom line

**A recovery is NOT sound. Dropping is right. `$8F` is the whole answer at this layer.**

Once `@block_end` sees `$20` (Data Last) or `$00` (Idle), the RTL proves that
no further data can ever be produced for this transaction, by any means
available to the C64. Waiting hangs forever (or, TOD-bounded, wastes 1 s and
then drops anyway). Acking ends the transaction. Re-reading the socket gets the
*next* datagram, because `lwip_recvmsg` already consumed this one and the
firmware has already called `discard_read_reply()`.

**But the team lead's leading candidate is refuted, and that changes what
happens next.** We are not sampling STATE in a handover window; the FPGA makes
that impossible. The terminal state we observe is *real*: the firmware genuinely
had nothing left to give. That relocates the bug from our sampling to *why the
firmware's pending read reply stopped matching the header it announced* — and
there is exactly one code path in `network_target.cc` that does that, and it
leaves a fingerprint on a channel **we already capture**.

So: ship `$8F`, and add ~4 bytes of state capture to it. One hardware run then
names the cause.

---

## 1. What the hardware actually guarantees

### 1.1 STATE and DATA_AV come from the same register, in the same read

`command_protocol.vhd`:

```vhdl
alias  response_valid   : std_logic is slot_status(7);   -- DATA_AV, bit 7
alias  state            : std_logic_vector(1 downto 0) is slot_status(5 downto 4);
```

`slot_status` is one 8-bit register. Our `lda UCI_STATUS` reads bit 7 and bits
5..4 **atomically**. There is no skew between "what STATE said" and "what
DATA_AV said" — they are the same byte.

### 1.2 DATA_AV is a pure function of pointer, length and state(1)

```vhdl
if (response_pointer - c_cmd_if_response_buffer_addr) < response_length then
    response_valid <= state(1) and not handshake_in(2);
else
    response_valid <= '0';
end if;
```

So `DATA_AV = (bytes_remaining_in_block > 0) AND state(1) AND (abort flag clear)`.

### 1.3 The staging write is atomic with respect to us

Firmware `copy_result()` writes, in order:

```c
CMD_IF_RESPONSE_LEN_H = len>>8;   // sets response_length(10:8)
CMD_IF_RESPONSE_LEN_L = len;      // sets response_length(7:0) AND resets response_pointer
CMD_IF_STATUS_LENGTH  = ...;
CMD_IF_HANDSHAKE_OUT  = VALIDATE_LAST | VALIDATE_MORE;   // state(1) <= '1'
```

and the RTL for the last write is:

```vhdl
if io_req.data(4)='1' then          -- validate data
    state(1) <= '1';
    state(0) <= io_req.data(5);     -- "more" bit
    reset_response;                 -- pointer <= base, again
end if;
```

`state(1)` goes to 1 **only at the VALIDATE write**, by which time
`response_length` and `response_pointer` are both already final. And
`response_valid` is registered off those same signals in the same process.

**Consequence: `STATE != BUSY` implies `response_length`/`response_pointer` are
final for that block. If the staged block had bytes, DATA_AV is set in the very
same STATUS byte.**

### 1.4 Legal (STATE, DATA_AV) combinations, and what our code does

At `@block_end` we have just read `DATA_AV == 0`. Let `rem = uci_poll_rem`.

| STATE | rem | Meaning | Our code | Correct? |
|---|---|---|---|---|
| `$30` Data More | >0 | block drained, another announced | `@block_more` → `uci_ack` → `@byte_loop` | yes |
| `$10` Busy | >0 | continuation being staged by the firmware task | `uci_wait_reply_staged` (TOD-bounded, 1 s, `$89`) → `@byte_loop` | yes — **this is the only legitimate "keep waiting"** |
| `$20` Data Last | 0 | normal end of reply | `@done_data` → `uci_ack` → Idle | yes |
| `$20` Data Last | >0 | **the staged final block was EMPTY** (see §3) | `@done_data`, deliver short buffer w/ full header | **the bug** → `$8F` |
| `$00` Idle | >0 | `HANDSHAKE_RESET` was written; transaction destroyed | same | **the bug** → `$8F` |
| `$30` Data More | 0 | firmware has more blocks than the header announced | `@done_data` → `uci_ack` posts a spurious DATA_ACCEPTED | latent hazard, see §6 |

---

## 2. Why the "handover window" hypothesis is refuted

The hypothesis was: `uci_wait_reply_staged` returns C=0 the moment STATE leaves
BUSY — *including to Data Last* — so we jump to `@byte_loop`, find DATA_AV clear
because the block is not yet readable, and mistake that for the end.

Two independent refutations:

**(a) Structural (§1.1–1.3).** For `@byte_loop` to see DATA_AV clear right after
STATE went to `$20`, the staged block must have `response_length == 0`. There is
no window in which `state(1)='1'` while the length/pointer are stale: the
VALIDATE write that sets `state(1)` is the *last* of the four writes and itself
re-resets the pointer. And since STATE and DATA_AV arrive in one byte, there is
no read-skew either. `uci_wait_reply_staged` returning on Data Last is
**harmless** — `@byte_loop` re-reads STATUS and, if there were bytes, would find
DATA_AV set and drain them.

**(b) Quantitative.** `uci_fence` is `OUTER=5, INNER=217` ≈ 5450 cycles ≈
**113 µs at 48 MHz** (≈57 µs if the carry-dependent `sbc #1` decrements by 2 —
see the `DO NOT "fix" the missing SEC` note in `uci_regs.inc`). `@byte_loop`
spends two fences per byte, so:

- ~114–227 µs per byte
- block 1 (893 bytes) ≈ **102–203 ms**
- a full 1472-byte read ≈ 170–334 ms

The firmware's block-2 staging is an ISR, a queue post, a FreeRTOS task switch
and a `memcpy` of 156–385 bytes — sub-millisecond. The "window" the hypothesis
needs is a handful of 50 MHz clocks, i.e. **~10⁴ times narrower than a single
one of our fences**. A race with those odds cannot produce 9/9 failures. It
would produce roughly zero.

**So the terminal STATE we observe is not a misread. The firmware really did
end the transaction with bytes outstanding.**

---

## 3. What the firmware must have done — and the one path that does it

`network_target.cc` block accounting:

```c
// start_read_reply (first block)
read_total  = copied;                 // == the 2-byte header we validated
read_offset = chunk;                  // min(copied, 893)
data_message.last_part = (read_offset >= read_total);

// get_more_data (continuations)
if (read_offset >= read_total) {      // <-- the no-data guard
    *reply  = &c_message_empty;       // { length 0, last_part TRUE, "" }
    *status = &c_status_net_no_data;  // "03,MORE DATA NOT SUPPORTED"
    return;
}
int chunk = min(read_total - read_offset, 895);
...
data_message.last_part = (read_offset >= read_total);
```

Note the shape: **every block the normal path produces exactly finishes
`read_total`.** A non-empty final block therefore always leaves `rem == 0` on
our side. `rem > 0` with `STATE == $20` is only reachable if the *final* block
had length 0 — and `c_message_empty` (`command_intf.cc:241`) is
`{ 0, true, "" }`, i.e. **length 0, `last_part = true` → `VALIDATE_LAST` →
STATE `$20`, `response_length = 0` → DATA_AV clear.**

That is a byte-exact match for the observed signature: 893 bytes copied, poison
untouched past 893, header claiming the full length, terminal STATE.

The guard fires when `read_total == 0`, i.e. **`discard_read_reply()` ran between
block 1 and block 2**. Its callers:

1. `parse_command()` — a new network command arrived mid-reply.
   *Ruled out for us:* the RTL refuses `PUSH_CMD` while `state /= "00"`
   (`else error_busy <= '1'`), and only `net.s`/`uci_cmd.s` touch `$DF1C-$DF1F`
   (verified: no other file in `src/` references them, and there is no IRQ hook).
2. `abort()` ← `run_task`'s `CMD_ABORT_DATA` branch.
3. `c64_reset()` ← same branch, via `c64_reset_pending`.
4. `start_read_reply`/`get_more_data` on `last_part` — normal, not this.

**(2) and (3) are the same `run_task` branch, and it is reachable two ways:**

```c
if(status_byte & CMD_ABORT_DATA) {
    ... command_targets[target]->abort(...);   // -> discard_read_reply()
    CMD_IF_HANDSHAKE_OUT = HANDSHAKE_RESET;    // 0x87 -> state <= "00"
}
if(status_byte & CMD_DATA_ACCEPTED) {
    get_more_data(...); copy_result(...);      // <- now hits the no-data guard
}
```

- the C64 writing `UCI_CTRL_ABORT` ($04) → `handshake_in(2)`. **We only do this in
  `net_init` (`uci_abort`, one call site, confirmed via `find_referencing_symbols`).**
- `ResetInterruptHandlerCmdIf()` — the Ultimate's **C64-RESET interrupt** — which
  posts `CMD_ABORT_DATA` straight into the queue and sets `c64_reset_pending`,
  *without* any C64 register write.

Both branches order abort-then-data-accepted **within the same status byte**, so
a single spurious event lands us in exactly the empty-last-block state. And if
the abort arrives as its own queue entry, the *next* DATA_ACCEPTED hits the same
guard. Either way: `$20`, length 0, `"03,MORE DATA NOT SUPPORTED"` on the status
channel.

A third, less likely mechanism with the same fingerprint: a duplicated
`CMD_DATA_ACCEPTED` queue entry (the second call re-enters `get_more_data` after
the last block already ran `discard_read_reply()`). I traced the ISR's
mask-set-then-post sequence in `command_interface_irq()` and it looks
duplicate-proof, but a `xQueueSendFromISR` failure prints `'\\'` to the U64
debug UART, which is worth checking.

**Note the `$00` Idle case is the same story told from one instruction earlier:**
`state <= "00"` is written *only* by `HANDSHAKE_RESET` (0x87), which in
`run_task` appears *only* in the abort branch (and for `no_reply` commands, which
SOCKET_READ is not). So `$00` at `@block_end` is *direct* evidence of the abort
path, and `$20` is indirect evidence of the same thing one step later.

---

## 4. Recovery: unsound, and provably so

### After `$20` Data Last

- **Wait?** `state(1)` is 1 and only two things change it: our `NEXT_DATA` write
  (→ `$00`), or the Ultimate writing `VALIDATE_*`/`RESET`. The Ultimate only
  writes those from `run_task`, which only runs on a queue event
  (`CMD_NEW_COMMAND` / `CMD_DATA_ACCEPTED` / `CMD_ABORT_DATA`) — none of which can
  now occur, because `CMD_DATA_ACCEPTED` requires *us* to ack a **Data More**
  block and the RTL sets `handshake_in(1) <= state(0)`, which is `'0'` in state
  `"10"`. **A wait here hangs forever.** TOD-bounded it becomes a 1 s stall
  followed by a `$89` drop — strictly worse than dropping immediately.
- **Ack and hope?** `NEXT_DATA` in state `"10"` sets `state <= "00"` and posts
  **no** DATA_ACCEPTED. The transaction simply ends.
- **Re-issue SOCKET_READ?** `lwip_recvmsg` consumed the datagram when the
  original command ran; `read_total`/`read_offset` are already zeroed. The
  payload does not exist in firmware RAM any more, and a datagram socket has no
  "rest of it". The next read returns the *next* datagram or `$FFFF`.

### After `$00` Idle

Strictly worse: the FPGA is already back at "ready for a new command". Waiting
both hangs and blocks the next poll.

### The one recovery that IS sound is already implemented

`STATE == $10` (Command Busy) with bytes outstanding → `uci_wait_reply_staged`,
bounded by CIA1 TOD at `UCI_RESP_WAIT_BUDGET_TENTHS = 10` tenths = 1 s, exiting
`$89` on expiry. That is the correct and only legitimate "keep waiting", and
`net.s:1372` already does it. Nothing to add.

**Verdict: the `$8F` fix is the whole answer at the UCI layer. Do not build a
recovery loop; any wait you could write in the `$20`/`$00` branch is a wait that
cannot terminate on its own.**

(And note the project's own history here: `uci_tod_start` exists because every
"bounded" wait was unbounded until 2026-08-27. A new wait in a branch where the
awaited event is *provably* unreachable is precisely the shape that bit us
before.)

---

## 5. The size dependence — and a reframe I think matters

### 5.1 What the block arithmetic says

Response = 2-byte header + payload. First block carries `NET_FIRST_BLOCK_PAYLOAD`
= 893 payload bytes; continuations carry up to `NET_MAX_REPLY_BLOCK` = 895
(`CMD_MAX_REPLY_LEN` 896 − 1, because the FPGA's pointer saturates on the last
buffer byte while still asserting DATA_AV — the firmware's own comment).

- `N ≤ 893` → **one block**. `get_more_data` is never called. `@block_end` is
  never reached with bytes outstanding. **476 B cannot fail. Confirmed by the data.**
- `894 ≤ N ≤ 1788` → **two blocks**, continuation = `N − 893`.

So every reported failure (1049–1187, cont. 156–294 B) and every reported
intermittent (1278, cont. 385 B) is the *same* two-block case. The
never-fails case (476) is the *only* one-block case in the set.

### 5.2 The honest reading

**The discriminator the data actually supports is "≥ 2 blocks", not "1049–1187".**

The band is not established against 1278: 9/9 vs 2/4 is p ≈ 0.02 by Fisher's
exact test, which is suggestive but is one more 1278 failure away from being
nothing. Before treating the band as a real phenomenon, note that it is also
exactly what you would get from a single per-continuation failure probability
plus unequal sample sizes.

I would not spend effort explaining the band until it survives equal-n sampling.
Specifically: **run the same number of trials at 476 (1 block, control), ~950
(1 block, upper edge), ~900 (2 blocks, smallest possible continuation), a band
length, and 1278.** If ~900 fails as hard as 1049, the band is an artifact and
the mechanism is "any continuation block". If ~900 is clean and 1049 is not,
the band is real and I am wrong about the mechanism.

Note the existing raw-path control cuts the same way: per
`project_uci_socket_read_quirks`, every size to 1472 arrived complete in one
`net_poll` on the raw probe (measured twice, 2026-09-04) — those are two- and
three-block reads passing on **identical code with identical fences**. So the
difference between raw probe and tunnel is not inside `net_poll`; it is state
carried *across* polls or something in the C64's electrical/interrupt
environment during a tunnel run. That is consistent with the abort/reset
mechanism in §3 and inconsistent with any pure block-handling defect.

### 5.3 On "seconds of crypto between polls"

It does not change the sampling. Within one `net_poll` the block drain is
straight-line code with the same fences either way; the crypto happens between
calls, after `udp_recv_ready` is set. What the inter-poll gap *does* change is
what precedes the read (a `SOCKET_WRITE` or a multi-part `$16` write always
does, in the tunnel) and how long the C64 spends hammering `$DFxx` per session
— which is the axis to look at if the reset/abort mechanism holds.

---

## 6. Recommendations, in priority order

**(1) Ship `$8F` — but record the STATE byte with it. ~4 bytes.**

In the `bne @done_data` branch at `@block_end`, before taking the error exit:

```asm
        sta uci_last_block_state    ; 3 bytes; A still holds STATUS & $30
```

plus one BSS byte. `$8F` alone tells us "short read"; `$8F` + the state byte
distinguishes **`$20` (empty final block → the `get_more_data` no-data guard)**
from **`$00` (HANDSHAKE_RESET → the abort/C64-reset branch)**, which per §3 are
different root causes. This costs nothing and turns the next hardware run into a
root-cause run instead of another symptom run. `$8F` is free in
`uci_errors.inc` (used: `$81`–`$8A`, `$8C`–`$8E`).

**(2) Read the status line on the failing path — the capture already exists.**

`uci_drain_status` already stores the line into `uci_status_buf` /
`uci_status_len`. The prediction is sharp and free:

- healthy 2-block read → `"00,OK"` (the last block carries `read_status`;
  intermediate blocks deliberately carry an empty status)
- the `get_more_data` no-data guard → **`"03,MORE DATA NOT SUPPORTED"`**

Reading `uci_status_buf` over DMA on a failing exchange confirms or kills §3 in
one run. **Caveat:** `uci_status_len` is *sticky-first* and its own comment says
it "has no consumer that clears it" — the instrument must zero `uci_status_len`
before each exchange or it will report a stale line.

**(3) Ask the firmware lane to check the U64 debug UART during a failing run** for
`"CMDIF: Requested for more data, but target is not set!"`, a stray `'\'`
(the `xQueueSendFromISR` overflow marker, queue depth 16), or evidence of
`ITU_INTERRUPT_RESET` firing. A spurious C64-reset interrupt is the single
mechanism that explains everything in §3 without any C64-side defect.

**(4) Latent hazard, separate from #128, worth an issue not a fix-now.**
`@done_data` runs `uci_drain_resp / uci_drain_status / uci_ack` unconditionally.
If it is ever reached with `rem == 0` while STATE is `$30` (Data More), that
`uci_ack` posts a `CMD_DATA_ACCEPTED` for a block nobody will read; the firmware
stages it and the interface is left non-idle, so the *next* poll's `PUSH_CMD`
lands on `else error_busy <= '1'` and is silently dropped (surfacing as `$86`).
The normal firmware paths can't produce it, but the whole point of #128 is that
something abnormal is happening. Cheap guard: at `@done_data`, if STATE is `$30`,
ack and drain to Idle before returning.

**(5) Do not write a recovery loop.** §4 is a proof, not a judgement call.

---

## 7. Confidence

- **§1, §2, §4 (RTL semantics, refutation of the sampling race, unsoundness of
  recovery): high.** These are read directly off `command_protocol.vhd` and
  `command_intf.cc`, and the fence arithmetic is an independent check.
- **§3 (the `get_more_data` no-data guard as the mechanism): moderate-to-high as
  the *only* path that produces the signature; low on which of abort /
  C64-reset / duplicated event triggers it.** Recommendation (1)+(2) resolve it.
- **§5 (the band is not established): moderate.** It rests on the sample sizes
  quoted to me (9/9 vs 2/4), which I did not verify against raw logs — the
  instrument in `tools/test_warp_live.py` captures `poison_stop` but not
  `UCI_STATUS`, so the `$20`/`$00` attribution in the brief is inferred from the
  code comment, not measured.
