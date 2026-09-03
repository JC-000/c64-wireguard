# c64-wireguard v1.1.0 — a working RR-Net backend, security sweep, standard MTU on both backends, monotonic handshakes, real-peer WARP interop

Second tagged release. Since v1.0.0: the ip65/RR-Net backend was found
to have never worked against a real peer and was repaired, a security
sweep closed nine issues (including a HIGH-severity remote DoS), a
standard-MTU (1440-byte) send path landed for both backends — natively
for ip65, and for UCI behind a build flag that needs firmware not yet
released for any Ultimate device — a receive-side bug that truncated
large inbound datagrams on **every UCI build** was fixed, and the C64
completed its first handshakes and key rotations against a real
production WireGuard peer (Cloudflare WARP) rather than only the
project's own Python responder, on **both** backends.

## Highlights

- **The ip65/RR-Net backend never worked against a real peer, and now
  does (#118, #120).** Three defects, each of which alone made the
  RR-Net build unusable against anything off-subnet, all found in one
  day:
  - **[#118](https://github.com/JC-000/c64-wireguard/issues/118)** —
    `src/net_abi.inc` declares `net_udp_dest_port` big-endian and the
    UCI adapter swaps it on push, but the ip65 adapter copied it raw
    into `udp_send_dest_port`, which the vendored ip65 treats as
    little-endian. Every datagram from an ip65 build therefore left
    for the byte-swapped port — for the default peer port 51820, that
    is 27850. **The RR-Net build had never completed a handshake on
    the wire in its life.** It stayed invisible because no ip65 build
    has ever run on hardware and every existing Ethernet-VICE suite
    measured things that do not depend on the destination port. Found
    by a new VICE-Ethernet echo suite via `tcpdump`, then confirmed in
    source; fixed by swapping on copy
    ([#119](https://github.com/JC-000/c64-wireguard/pull/119)).
  - **[#120](https://github.com/JC-000/c64-wireguard/issues/120)** —
    ip65 does not queue a datagram whose next-hop MAC is unresolved:
    it emits an ARP request and returns carry set. The adapter
    propagated that faithfully and `session_initiate` treated it as a
    fatal handshake failure. Any real peer is off-subnet, so the next
    hop is the gateway and **the first send after `net_init` always
    failed**, after computing the entire Type-1 and throwing it away.
    Nor is it first-send-only: ip65's ARP cache is an 8-entry list
    that shifts without deduplicating, so a chatty LAN can evict the
    gateway mid-session. `net_udp_send` now pumps `ip65_process` and
    re-calls `ip65_udp_send` under a 30-jiffy (~0.5 s) budget, with
    stopped-clock detection
    ([#122](https://github.com/JC-000/c64-wireguard/pull/122)).
  - **The backend reported nothing structural on any failure** — only
    a carry and a screen string, which is why both of the above were
    invisible for the backend's whole life. It now sets
    `net_last_error`: `$41` init, `$42` DHCP, `$46` listen refused,
    `$48` bounded-wait expiry, `$49` unbind not found, plus the
    generic `$01`. `src/net_abi.inc` gains the registry these codes
    live in, with the rule the retired contract §13 never had: a
    backend either sends the datagram or reports a real failure, and
    an unresolved next hop is not a failure.
- **#70 for ip65 — standard MTU 1440 natively.** The new generic
  `WG_MTU1440=1` knob lifts `WG_DATAGRAM_CAP` to 1472 and the tunnel
  `WG_MTU` to 1440 for either backend. Under `BACKEND=ip65` the flag
  alone suffices: ip65's caps are natively 1472/1472, so no firmware
  is involved. Measured at both REU settings with 371 B free in
  `MAIN_AREA_HI`, highest application address `$9E8C`, clear of the
  ip65 blob's BSS at `$A000-$AF3F`. This is a build option, not a
  shipped artefact — the `wireguard-rrnet-*.prg` files in this
  release are the default 860-byte-MTU builds.
- **2026-08-31 security sweep** — nine issues closed, most severe is
  **#94** (HIGH): a forged Type-3 cookie reply could be replayed by
  any off-path attacker who had observed one of the C64's own Type-1
  packets (the cookie key derives from the peer's non-secret static
  public key), tearing down an already-**ACTIVE** session with a
  single UDP packet and forcing a full handshake replay. See "Issue
  housekeeping" below for the rest.
- **#70 for UCI — standard MTU 1440**, behind the new
  `UCI_CHUNKED_WRITE=1` build flag. Requires the chunked
  `SOCKET_WRITE` firmware command from
  [GideonZ/1541ultimate#807](https://github.com/GideonZ/1541ultimate/issues/807),
  **which is not merged upstream and not in any released U64E or
  C64U firmware.** See the boxed warning below and
  `tools/release/FIRMWARE-WARNING.txt`.
- **Receive-side Command-Busy fix, all UCI builds (#112).** Multi-block
  `SOCKET_READ` now waits while firmware STATE is Command-Busy
  instead of stopping at the first reply block; at 48 MHz this had
  been silently truncating every inbound datagram above 893 bytes
  (58/60 in the original probe). This is not behind a flag — every
  shipped UCI PRG gets it (ip65/RR-Net builds have no `SOCKET_READ`).
- **Cloudflare WARP real-peer interop and rekeys, on both backends
  (#112, #115, #124).** The C64 completes a WireGuard handshake
  against Cloudflare's production edge (`162.159.192.1:2408`) using a
  `wgcf`-registered key, carries ICMP and DNS traffic through the
  tunnel, and — after the #87 fix — survives repeated rekeys against
  that same peer without being silently dropped. See "Real-peer
  interop" below for the ip65 run, its numbers and its caveats.
- **#87 — monotonic Type-1 timestamps.** Every handshake initiation
  previously carried the same TAI64N timestamp with only the nanosecond
  field incrementing from a fixed base; a conformant peer (WireGuard's
  greatest-seen-timestamp rule) accepted only the first handshake per
  boot and silently dropped every rekey. Fixed; the bench responder now
  enforces the same rule so this class of regression shows up locally.
- Live hardware tools randomise wire payload content per run (seeded,
  logged, disjoint by direction) instead of reusing fixed strings, so a
  hardcoded match can no longer coincide with a broken send/receive path.
- A **gate-wide import guard** (`tools/test_suite_imports.py`) now
  imports every `tools/test_*.py` in a subprocess and fails on a
  missing name, so an opt-in or hardware-only suite can no longer sit
  dead at module load looking like a suite with nothing to say. It
  needs no hardware, and it ships with a proof that its own alarm
  fires. It has already found two such suites — see #121 below.
- Repo-standing agent definitions for adversarial review and red/green
  testing, checked in under version control rather than living only in
  session memory.

## Artifacts

| File | Backend | Field multiply | MTU | Firmware required | Runs on |
|---|---|---|---|---|---|
| `wireguard-rrnet-reu.prg` | ip65 / RR-Net | REU DMA tables | 860 | none — RR-Net/ip65 needs no Ultimate firmware | C64 + RR-Net + REU (512 KB+) |
| `wireguard-rrnet-noreu.prg` | ip65 / RR-Net | CT on-chip | 860 | none — RR-Net/ip65 needs no Ultimate firmware | stock C64 + RR-Net |
| `wireguard-uci-reu.prg` | UCI | REU DMA tables | 860 | Ultimate 3.15+ — **not a public release** as of 2026-09-03 (U64/U64E: preview/test-merge builds only; C64 Ultimate firmware line: untested) | Ultimate 64 / C64 Ultimate |
| `wireguard-uci-noreu.prg` | UCI | CT on-chip | 860 | Ultimate 3.15+ — **not a public release** (see above) | Ultimate, REU disabled |
| `wireguard-uci-noreu-mtu1440.prg` | UCI | CT on-chip | 1440 | Ultimate 3.15+ (not public) **+ #807** (open issue, unmerged) | Ultimate running the #807 spike firmware |
| `wireguard-uci-reu-mtu1440.prg` | UCI | REU DMA tables | 1440 | Ultimate 3.15+ (not public) **+ #807** (open issue, unmerged) | Ultimate running the #807 spike firmware + REU — **no hardware run: REU builds fail the handshake at 48 MHz on the preview firmware (#69); ships for completeness, use `-noreu` for turbo** |
| `wireguard-reu.d64` | both REU PRGs (`wg-rrnet`, `wg-uci`) + `wg.cfg` + warning | | 860 | mixed: rrnet none, uci 3.15+ (not public) | |
| `wireguard-noreu.d64` | both no-REU PRGs + `wg.cfg` + warning | | 860 | mixed: rrnet none, uci 3.15+ (not public) | |
| `wireguard-mtu1440.d64` | both mtu1440 PRGs (on disk as `wg-mtu1440-noreu`, `wg-mtu1440-reu`) + `wg.cfg` + warning | | 1440 | Ultimate 3.15+ (not public) + #807 (open issue, unmerged) | |
| `FIRMWARE-WARNING.txt` | plain-text copy of the on-disk warning | | | | |
| `VERSION` | `git describe --tags --always --dirty` at build time | | | | |

**The RR-Net rows changed meaning in this release.** An earlier draft
of these notes carried "VICE-verified only" in that firmware column,
which was wrong in both directions. The `wireguard-rrnet-*.prg` files
**as built before this release could not complete a handshake with any
real peer**: every datagram left for a byte-swapped destination port
([#118](https://github.com/JC-000/c64-wireguard/issues/118)), and the
first send to any off-subnet peer was reported to the session layer as
a fatal failure
([#120](https://github.com/JC-000/c64-wireguard/issues/120)). The
files in *this* release have a real WireGuard handshake with
Cloudflare's production edge behind them, over the internet, with a
ping reply carried through the tunnel — see "Real-peer interop" below.
Two caveats on that claim, both real. The WARP run was made on the
`WG_MTU1440=1` variant of this backend rather than the 860-byte build
shipped here — both fixes are in the shared send path and neither
depends on the MTU, but the shipped configuration has not itself been
put in front of Cloudflare. And what remains unverified is the medium,
not the protocol: every one of these runs had the C64 on
bridged Ethernet VICE with its own DHCP lease on a real LAN, and **no
ip65 build has ever run on physical RR-Net hardware** (nor on a
physical Ultimate).

`wg.cfg` on each disk is a placeholder (all-zero keys, RFC 5737
endpoint) in the 9-line fixed-order SEQ format documented in
`src/wg/disk_config.s` — replace it with real keys before use.

> ```
> C64-WIREGUARD - FIRMWARE WARNING
> =================================
>
> ALL WIREGUARD-UCI-*.PRG NEED ULTIMATE
> FIRMWARE 3.15 OR NEWER. AS OF
> 2026-09-03 THIS IS NOT A PUBLIC
> RELEASE: U64/U64E RUN PREVIEW OR
> TEST-MERGE BUILDS ONLY; THE C64
> ULTIMATE FIRMWARE LINE IS UNTESTED.
>
> MTU1440 PRGS ADDITIONALLY NEED
> GIDEONZ/1541ULTIMATE#807 (CHUNKED
> SOCKET WRITE), AN OPEN ISSUE, NOT
> MERGED UPSTREAM:
>   WIREGUARD-UCI-NOREU-MTU1440.PRG
>     (WG-MTU1440-NOREU ON DISK)
>   WIREGUARD-UCI-REU-MTU1440.PRG
>     (WG-MTU1440-REU ON DISK)
>
> ON ANY RELEASED FIRMWARE THE FIRST
> SEND (THE HANDSHAKE) IS EXPECTED TO
> FAIL: SCREEN SHOWS "HANDSHAKE SEND
> FAILED" WITH NO CODE, THOUGH
> NET_LAST_ERROR IS $8E. THE CODE
> SHOWS ONLY OVER DMA OR ON THE 'S'
> MESSAGE PATH (ISSUE #116). NEVER
> OBSERVED ON HARDWARE - OUR RIG
> RUNS THE #807 SPIKE.
>
> WIREGUARD-RRNET-*.PRG NEED NO
> ULTIMATE FIRMWARE (RR-NET/IP65).
> THEY WORK AT MTU 860.
>
> REU CAVEAT (#69): REU=1 BUILDS
> FAIL THE HANDSHAKE AT 48 MHZ ON
> THE PREVIEW FIRMWARE. USE THE
> NOREU PRGS FOR TURBO HOSTS.
> ```

## Hardware validation

- **Standard MTU (mtu1440 build), U64E `601A96`, fw 3.15 / fpga 124,
  test-merge `d33b7802` + #807 spike, REU=0, 48 MHz:**
  `test_wire_encryption_live.py --turbo 48` against the Python
  responder at the peer's **default MTU 1420** — **60/60, twice**.
  Outbound 888–1472-byte payloads each produced exactly one wire
  datagram, decrypted correctly at the peer; a 1473-byte send was
  rejected with `$8C` and nothing hit the wire.
- **Default build (860-byte MTU), same device/settings:** inbound
  replies of 893, 894, 1452 and 1472 bytes were **all received
  whole** by the Command-Busy read fix (#112) — this exercises the
  same firmware behaviour the mtu1440 build depends on, on hardware
  that needs no firmware change.
- **Cloudflare WARP, UCI backend, 48 MHz, mtu1440 build:** handshake to `ACTIVE`
  in ~48 s at 48 MHz; a subsequent rekey (`H`) reached `ACTIVE` again in ~48 s,
  and a second rekey in ~47 s — each with a strictly greater TAI64N
  timestamp than the last (#87). ICMP echo and a 1278-byte DNS
  response were carried through the tunnel intact.

## Real-peer interop: Cloudflare WARP on the ip65 backend

The ip65 repairs above were not proved on a bench responder. They were
proved against Cloudflare's production WireGuard edge, over the open
internet ([#124](https://github.com/JC-000/c64-wireguard/pull/124)).

**68/68, 21m39s**, seed `398445094`, on bridged Ethernet VICE with an
`ip65 REU=0 WG_MTU1440=1` build: the emulated C64 binds a real USB
Ethernet adapter, joins the LAN as an ordinary node with **its own
DHCP lease from the router**, and reaches Cloudflare directly. Its
frames never enter the host's IP stack, so the host's own WARP tunnel
is bypassed rather than worked around — no address translation, no
firewall rules, no VPN change.

| Stage | Result |
|---|---|
| Handshake | `ACTIVE` in 454.5 s; Type-1 on the wire `10.43.23.225:51820 → 162.159.192.1:2408` |
| Ping | reply from `1.1.1.1` **through the tunnel** |
| DNS | both queries answered and structurally validated on the C64 |
| Rekey ×2 | `ACTIVE` both times, at 184.9 s and 193.6 s |
| Fragments | **zero**, throughout |

The destination port on the wire reads 2408, not the byte-swapped
value the old code produced — #118's fix confirmed against a
production peer.

**The rekeys are the #87 proof.** The three initiations carried

```
000000006a99d3d300000001
000000006a99d3e900000002
000000006a99d3fe00000003
```

strictly increasing as 96-bit big-endian integers, and `ACTIVE`
returned each time. Cloudflare enforces the greatest-seen timestamp
and **silently drops repeats**, so a stuck timestamp would have
presented exactly as a rekey that never comes back. This is the #87
fix verified against a peer that actually implements the rule, rather
than against our own responder.

**The MTU question, answered — and the answer is a negative.** There
is **no inbound datagram above 1280 bytes to claim**, in either
direction of this release's MTU story:

| name | measured on the C64 | on the host | TC | answers |
|---|---|---|---|---|
| namecheap.com | **1278 B** | 1278 B | 0 | 15 |
| github.com | **39 B** | 39 B | 1 | 0 |

Both were validated structurally rather than by length alone — inner
header `1.1.1.1:53 → 172.16.0.2:53`, transaction id, QR bit, question
echoed, and the length agreeing with the inner UDP header's own field.
The ceiling is **Cloudflare's resolver policy, not an MTU or path
effect**: we advertised a 1412-byte EDNS buffer derived from the
build, so our own request was demonstrably not the binding limit, and
the C64's direct path behaved identically to the host's, which rules
out the host tunnel. 1278 B is the largest datagram this run could
observe, and it is resolver-limited. That closes the question rather
than answering it the way we hoped.

Honest notes on the run: a reporting bug counted DNS replies across
queries (fixed in `4e050ec`; no assertion depended on it); a test-side
workaround for the first-send defect — warming the address cache — is
still present in the tool from before #122, and with #122 in the build
every handshake in this run sent its Type-1 on the first attempt
anyway. And the standing caveat: the C64 here is VICE bridged onto a
real LAN. The peer, the router, the lease and the internet path are
real; the machine is not.

## Issue housekeeping shipped with this release

Security sweep, closed 2026-08-30/31:

- **#94** (HIGH) — a forged Type-3 cookie reply, replayable from any
  off-path attacker, could tear down an ACTIVE session.
- **#95** — a single forged Type-2 packet poisoned the handshake
  state permanently, with no retry or timeout.
- **#97** — `udp_tunnel_parse` bounded inner text against a constant
  instead of the bytes actually decrypted; up to 804 bytes of prior
  tunnel plaintext could be printed to screen.
- **#89** — the entropy whitening state started from a fixed
  constant every run, weakening ephemeral key generation.
- **#88** — lowercase hex in `WG.CFG` silently produced wrong keys.
- **#86** — the anti-replay window erased records of received
  counters on advance, allowing a recent Type-4 packet to be replayed.
- **#84** — an incomplete handshake held the firmware UDP socket for
  the rest of the run, with teardown dependent on an unshipped
  firmware reaper.
- **#103** — the cold-init reclaim left only 3 B free in
  `MAIN_AREA_LO` and 28 B free in `MAIN_AREA_HI`, blocking the #94
  fix until the reclaim was widened.
- **#109** — following #103's reclaim, a test calling into the
  reclaimed cold-init span hung for 180 s instead of failing fast; a
  gate check now catches keyword and aliased spellings of the same call.

ip65/RR-Net, closed 2026-09-03:

- **#118** — the ip65 backend sent every datagram to the byte-swapped
  destination port (51820 on the wire as 27850), so the RR-Net build
  could never have completed a handshake. Fixed in PR #119.
- **#120** — the first send to any off-subnet peer failed because the
  next hop was unresolved, and `session_initiate` treated that as
  fatal. Fixed in PR #122, which also gave the backend the
  `net_last_error` channel it had never had.

Also landed:

- **#70** — standard MTU 1440: via `UCI_CHUNKED_WRITE=1` on the UCI
  backend, and natively via `WG_MTU1440=1` on ip65 (see above).
- **#87** — monotonic Type-1 timestamps across initiations, now also
  proved against Cloudflare's production edge (see above).

## Known issues

- **#807 is unmerged, and no released firmware carries it.** On any
  released firmware, the mtu1440 PRGs' first send — the Type-1
  handshake — is expected to fail: the screen shows `HANDSHAKE SEND
  FAILED` with no error code, though `net_last_error` is `$8E`; the
  code is visible only over DMA or on the 'S' message path
  ([#116](https://github.com/JC-000/c64-wireguard/issues/116)). This
  has never been observed on hardware — our rig runs the #807 spike.
  All `wireguard-uci-*` PRGs, mtu1440 or not, additionally require
  Ultimate firmware 3.15+, itself not a public release as of
  2026-09-03 (preview/test-merge builds only on U64/U64E; untested on
  the C64 Ultimate firmware line).
- **#69** — `REU=1` variants fail the handshake at 48 MHz on the
  preview firmware. Use the `-noreu` PRGs on turbo hosts until this
  is resolved upstream.
- **#113** — the default `MSG_PORT` (9999) is stored little-endian
  and copied to the wire big-endian, so the actual on-wire port is
  3879. Interop tooling that expects 9999 on the wire should be
  aware of this; not fixed in this release.
- **Cross-load TAI64N persistence.** `tai64n_last` (the #87 fix's
  monotonic floor) lives in `APP_BSS` and is zeroed by every PRG
  load. A real peer may reject the first handshake after a re-load
  until host wall-clock time passes the previous run's last
  timestamp. The live tools stage a fresh base time per run to avoid
  this in testing; a cold-loaded C64 in the field can hit it.
- **#104** — the `CRYPTO_BSS` page-alignment constant-time invariant
  is unenforced; nothing catches a change that silently drops it.
- **#106** — a forged cookie reply during `HS_SENT` still buys an
  attacker three X25519 scalarmults per 64-byte packet (residual
  after #94's fix, not itself a session-killer).
- **#98** — `test_wire_encryption_live`'s default invocation is the
  exact REU + 48 MHz combination #69 says is broken; use `REU=0`
  explicitly when running it at turbo.
- Both #121 and the earlier `tools/test_ip65_listener_leak.py` were
  found by the new gate-wide import guard described under Highlights.
  Neither was findable before it, because a suite that cannot import is
  indistinguishable from a suite with nothing to say — that is the
  reason this class of defect stops hiding from here on.
- **#121** — `tools/test_uci_udp_size_probe.py` has been dead at
  module load since `f021458`, a commit *in this release*: that commit
  moved `tools/test_uci_udp_echo_live.py` to seeded random payloads and
  removed `TEST_PAYLOAD`, which the probe imports at module scope. A
  one-sided rename; nothing reported it because the suite is opt-in and
  hardware-only, so it never ran in the gate to fail. The import is
  repaired and the gate is green, but **a green import proves only that
  the file loads** — it has not been executed against a U64E since, and
  whether the seeded payload changes what the probe demonstrates has not
  been checked.
- **#123** — `ip65_recv_dropped` counts inbound datagrams discarded
  while `net_udp_send` pumps the driver for a next-hop MAC (#120). Its
  **increment path has never executed on any target**, and its zero case
  is asserted twice — which is worse than no coverage, because a reader
  sees a counter under assertion and concludes it is tested. Covering it
  needs a menu-driven suite where the application's own main loop runs,
  so the C64 can answer ARP mid-pump. Note that WireGuard retransmits
  handshake initiations but **not** transport data, so this counter is
  the only signal that tunnel traffic was lost to a pump.
- **rrnet (ip65/RR-Net) builds are verified under emulation, not on
  RR-Net hardware.** #80 (ip65 blob BSS overlapping app code) was fixed
  by PR #83; #118 and #120 are fixed here, and the result was proved
  against a real peer over the real internet — but the C64 in that run
  was VICE bridged onto a real LAN. **No ip65 build has ever run on
  physical RR-Net hardware, or on a physical Ultimate.**

## For maintainers

**The ip65 fix ate most of the LOADER headroom.** #120's repair cost
`BOOT_CODE` +186 B, and `LOADER` (`$0801-$1FFF`) ends with
`LIB_X25519_DATA`, which is `align = $100`. That growth pushed the
segment from `$1000` to `$1100`, so it now ends at `$1EFF` — **256
bytes short of the ceiling**, where before it ended at `$1DFF` with
512 bytes of tail. Room left for further `BOOT_CODE` growth, measured
by padding and forcing a relink:

| growth | outcome |
|---|---|
| 0–201 B | links silently (the align gap absorbs it) |
| 202 B | takes the page step and trips the new warning |
| 457 B | the last that links at all |
| 458 B | hard `ld65` area overflow |

So there is a **new `ldwarning` on the page step**
(`src/net/ip65/ip65_blob.s`), firing 256 bytes before the link
actually breaks — deliberate runway, not an alarm on the last byte. It
lives in the ip65 translation unit because the uci cfg lays `LOADER`
out differently and the threshold is not meaningful there.

**Measure this only after forcing a relink.** `make` alone will leave
`build/wireguard.prg` untouched and a sweep that does not delete
`net.o` and the PRG produces non-monotonic nonsense — this project's
standing staleness trap wearing a new hat. An earlier hand measurement
that skipped the relink reported 454 / ~199 / warn-at-210, all three
wrong.

## Pinned sibling versions

- [c64-x25519](https://github.com/JC-000/c64-x25519) **v0.11.2**
  (up from v0.8.0 at v1.0.0)
- [c64-ChaCha20-Poly1305](https://github.com/JC-000/c64-ChaCha20-Poly1305)
  **v0.9.0** (up from v0.6.0 at v1.0.0)

Both match `README.md`'s stated pins; verified against the checked-out
submodule commits at this release, not asserted from memory.

## Checksums

**Release procedure:** create the annotated tag first, on a clean tree, then build — `VERSION` and the `SHA256SUMS` header are stamped from `git describe --tags --dirty`, so without the tag (or with a modified tracked file such as the `ip65` symlink) they read `v1.0.0-N-g…` or `…-dirty`:

```
git tag -a v1.1.0 -m "c64-wireguard v1.1.0"
make release
gh release create v1.1.0 --draft --target master --title "c64-wireguard v1.1.0" \
  --notes-file docs/RELEASE_NOTES_v1.1.0.md build/release/*
```


`SHA256SUMS` is attached to this release and covers every other
attached file. Its first line is a comment naming the release version
(`git describe --tags --always --dirty`); verify with `shasum -c
SHA256SUMS` from inside the extracted asset directory.
