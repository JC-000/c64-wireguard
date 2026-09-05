# c64-wireguard v1.2.0 — a real receive-path bug, and the instrument that hid it

Released 2026-09-05. Supersedes [v1.1.0](RELEASE_NOTES_v1.1.0.md).

**Every UCI build should be updated.** v1.2.0 fixes a data-corruption bug in the
inbound path that silently delivered partially-filled buffers under a full
announced length. It affects any inbound datagram over 893 bytes on the UCI
backend, and it is timing-dependent rather than size-deterministic — so a build
that appears to work can be corrupting traffic.

The RR-Net (ip65) backend is unaffected by the corruption fix.

---

## The fix — #128

`net_poll` sampled `UCI_STATUS` **twice**, and threw away the bit that
disambiguated them.

`@byte_loop` exits when DATA_AV reads clear. `@block_end` then read
`UCI_STATUS` a **second** time — one `uci_fence` later — and applied
`and #UCI_STAT_STATE`, which masks **bit 7, DATA_AV, off**. If the firmware
staged the continuation block inside that window, the second read held
`DATA_AV = 1` *and* `STATE = $20` in the same byte, and the code discarded the
disambiguator it was already holding in the accumulator. The result: a
partially-filled buffer delivered under the full announced length, so the
Poly1305 tag was read out of the ciphertext and the AEAD compare failed.

```
staging lands before the first read   -> fine
staging lands between the two reads   -> BROKEN   (one uci_fence wide)
staging lands after the second read   -> fine, the $10 Busy arm catches it
```

**One fatal window, safe on both sides.** That is why the failure presented as a
size *band* and as non-monotonic: it is a window in *staging latency*, not in
length. It is also why it is **turbo-only** — the window is ~85 µs of real
silicon time, far below any task switch at 1 MHz but squarely reachable at
48 MHz.

**The fix:** latch `UCI_STATUS` once, test **DATA_AV first**, drain the block if
one was staged after all, and only then decide from STATE. +22 bytes of code,
+1 of BSS.

A genuine terminal state with bytes outstanding now takes a named error exit —
`$8F UCI_ERR_SHORT_READ`, `udp_recv_ready` left 0, datagram dropped — rather
than delivering a partial buffer. `uci_short_read_state` records which terminal
state caused it. Recovery at that point was investigated and is **impossible**
from the FPGA's own protocol, so the drop is correct rather than a compromise.

**An error-exit-only fix would have been worse than the bug.** Without the
DATA_AV re-test it drops *complete* datagrams whose continuation merely landed
inside the fence — silent corruption traded for silent packet loss. Both cases
leave byte-identical evidence in the receive buffer, which is why the fix had to
be tested rather than the bug.

### Verification

Hardware, U64E at 48 MHz, DeviceLock held, receive buffer poisoned so the true
copy stop is measurable. Two runs; the first deliberately reuses the pre-fix
seed so the executed ladder matches rung for rung and the fix is the only
variable:

| | pre-fix | run 1 | run 2 |
|---|---|---|---|
| copy stop == announced length | 12/27 | **27/27** | **27/27** |
| short read under a longer length | **11** | **0** | **0** |
| `$8F` | — | 0 | 0 |

Every announced length that defined the reported band — 1008, 1109, 1191, 1247,
1338 — is clean, against 1/2, 0/2, 0/3, 1/2 and 3/2 before.

Two corroborations neither run was designed to produce: the send counter
advances by exactly 1 per query (it was 2 on every pre-fix failure, a keepalive
landing inside the receive window), and the session no longer expires mid-ladder
— each rung answers in ~2.5 s instead of burning a ~12 s DNS timeout, so a
27-rung ladder that used to outrun the 180 s expiry now finishes inside it.

---

## Also fixed — #129, a peer could drive the C64's display

`session_handle_packet`'s `@t4_udp` printed peer-supplied bytes raw through
KERNAL `CHROUT`, so PETSCII control codes arriving from a remote peer were
**executed**: `$93` clear screen, `$13` home, `$12`/`$92` reverse, `$0E`/`$8E`
charset, `$90-$9F` colour. `display_payload`, twelve lines away in the same
file, already did it correctly.

**Zero byte delta** — one differing byte in the PRG, map byte-identical.

Note the limitation, unchanged from `display_payload`: the filter is
ASCII-printable, so PETSCII shifted-case letters render as `.`.

---

## Instrumentation

The reported #128 symptom — a deterministic failure band at 1049-1187 bytes —
was an **artifact of the tool that measured it**, and the tool had no assertion
that had ever been observed failing. That is fixed, and the fixes are the reason
the real bug was findable:

- The per-query verdict is derived from device memory, not scraped from the
  screen. The old scrape could be **authored by the peer**: a payload
  containing the marker moved the parse boundary as well as filling it.
- Receive state is cleared and read-back-verified per query, so a previous
  datagram cannot be reported as the current one.
- The arrived length is recorded on failures, not assumed from a host-side
  table.
- The test ladder is shuffled under a logged seed, so size is no longer
  confounded with session age, counter and elapsed time.
- The receive buffer is poisoned with a position-dependent pattern, which
  **measures** the block boundary instead of inheriting it from a comment.

New suites: `test_uci_short_read_drop.py` (87 checks, driving the real
assembled `net_poll` on a host-side 6502 against a model of the register
protocol), `test_issue_129_petscii_control.py`, `test_warp_instrument_unit.py`
and `test_warp_instrument_vice.py`. Regression gate: **36 suites → 41** (measured at tag time from the gate's own
output, which now also reports the backend and PRG hash it leaves the tree in).

### An audit of the tests themselves

Prompted by the above, the suite was audited for the same defect class. Three
findings, all fixed here:

- **`test_uci_udp_size_probe.py` asserted nothing.** Its verification function
  was defined and never called while its docstring promised byte-exact checking,
  and `main()` returned 0 unconditionally — unplug the responder and it still
  passed. **This is the tool whose "the raw path is clean" result was cited as
  ruling out the read path in #128**, which helped point the investigation away
  from `net_poll` for two days. It now poisons and verifies the whole buffer
  against what the responder actually put on the wire, and scores through a pure
  function that reaches the exit code.
- **The regression gate could not fail in three ways.** Its suite timeout was
  unreachable dead code and the serial loop had no deadline at all; a suite
  producing more than ~64 KB deadlocked on an unread pipe; and the final restore
  build ignored both return codes, so **a failed rebuild still printed "all
  suites passed"**. All three fixed and sabotage-proven.
- A recurrence guard now scans for verdict-shaped functions that are never
  called anywhere in `tools/` — the shape that produced the first item.

---

## Known limits, stated plainly

- **The `$8F` path has never executed on real hardware.** The proof runs had
  zero rejects, so the new error exit is covered only by host-side simulation.
- **The window's absolute cycle endpoints come from a simulator** whose cycle
  table is not independently validated. The window's *existence* and its width
  of one `uci_fence` are structural, and the fence is separately bracketed at
  85.2 µs on real silicon — so the finding stands; the exact numbers carry a
  caveat.
- **The UCI status channel is still not readable on a delivering read**
  ([#132](https://github.com/JC-000/c64-wireguard/issues/132)). The capture was
  fixed to read `uci_status_seen` (non-sticky) rather than `uci_status_len`
  (sticky-first) as the buffer's length — reading a sticky length against a
  buffer rewritten on every drain spliced them, and reported a truncated line as
  complete. That makes the capture self-consistent; it does **not** make it
  sample the delivering read. **Behaviour change:** the live tooling now requires
  `uci_status_seen` and reports `status_line_available: false` on a build that
  predates it, rather than silently falling back to the sticky field. Refusing to
  report beats reporting a splice.
- ~~`--backend ip65` is rejected by the live tooling~~ **FIXED in this release**
  ([#131](https://github.com/JC-000/c64-wireguard/issues/131)). `detect_backend`
  had keyed on `net_last_error` as a UCI-only marker; #120 gave ip65 an error
  channel of its own, so from that commit **every** ip65 build matched both
  sides and was refused — `--backend ip65` had been unusable ever since.
  Shipped ip65 PRGs were never affected; this was a test-tool defect. It went
  unnoticed because the only witnesses were synthetic label dictionaries that
  hard-coded the pre-#120 split, and one of them asserted that the real
  post-#120 shape **must** raise — the suite did not merely miss the bug, it
  pinned it. Those fixtures are now cross-checked against a **built**
  `labels.txt`, which is the only witness that tracks what the backends
  actually export.
- **`REU=1` still fails the handshake at 48 MHz**
  ([#69](https://github.com/JC-000/c64-wireguard/issues/69)). Use `REU=0` on
  hardware.
- Firmware requirements are unchanged from v1.1.0 — see the warning in the
  README and `FIRMWARE-WARNING.txt` on each disk image.

---

## Artifacts

Unchanged in shape from v1.1.0: six `.prg` variants across both backends in REU
and no-REU forms plus the two MTU-1440 builds, three `.d64` disk images, a
`VERSION` stamp and `SHA256SUMS`. Every variant's `labels.txt` is checked
structurally after build, so a `BACKEND` that silently fell back cannot ship.
