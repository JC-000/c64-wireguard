# c64-wireguard v1.1.0 — security sweep, standard MTU behind unmerged firmware, monotonic handshakes, real-peer WARP interop

Second tagged release. Since v1.0.0: a security sweep closed nine
issues (including a HIGH-severity remote DoS), a standard-MTU
(1440-byte) send path landed behind a build flag that needs firmware
not yet released for any Ultimate device, a receive-side bug that
truncated large inbound datagrams on **every** build was fixed, and
the C64 completed its first handshakes and key rotations against a
real production WireGuard peer (Cloudflare WARP) rather than only the
project's own Python responder.

## Highlights

- **2026-08-31 security sweep** — nine issues closed, most severe is
  **#94** (HIGH): a forged Type-3 cookie reply could be replayed by
  any off-path attacker who had observed one of the C64's own Type-1
  packets (the cookie key derives from the peer's non-secret static
  public key), tearing down an already-**ACTIVE** session with a
  single UDP packet and forcing a full handshake replay. See "Issue
  housekeeping" below for the rest.
- **#70 — standard MTU 1440**, behind the new `UCI_CHUNKED_WRITE=1`
  build flag. Requires the chunked `SOCKET_WRITE` firmware command
  from [GideonZ/1541ultimate#807](https://github.com/GideonZ/1541ultimate/pull/807),
  **which is not merged upstream and not in any released U64E or
  C64U firmware.** See the boxed warning below and
  `tools/release/FIRMWARE-WARNING.txt`.
- **Receive-side Command-Busy fix, all builds (#112).** Multi-block
  `SOCKET_READ` now waits while firmware STATE is Command-Busy
  instead of stopping at the first reply block; at 48 MHz this had
  been silently truncating every inbound datagram above 893 bytes
  (58/60 in the original probe). This is not behind a flag — every
  shipped PRG gets it.
- **Cloudflare WARP real-peer interop and rekeys (#112, #115).** The
  C64 now completes a WireGuard handshake against Cloudflare's
  production edge (`162.159.192.1:2408`) using a `wgcf`-registered
  key, carries ICMP and DNS traffic through the tunnel, and — after
  the #87 fix — survives repeated rekeys against that same peer
  without being silently dropped.
- **#87 — monotonic Type-1 timestamps.** Every handshake initiation
  previously carried the same TAI64N timestamp with only the nanosecond
  field incrementing from a fixed base; a conformant peer (WireGuard's
  greatest-seen-timestamp rule) accepted only the first handshake per
  boot and silently dropped every rekey. Fixed; the bench responder now
  enforces the same rule so this class of regression shows up locally.
- Live hardware tools randomise wire payload content per run (seeded,
  logged, disjoint by direction) instead of reusing fixed strings, so a
  hardcoded match can no longer coincide with a broken send/receive path.
- Repo-standing agent definitions for adversarial review and red/green
  testing, checked in under version control rather than living only in
  session memory.

## Artifacts

| File | Backend | Field multiply | MTU | Firmware required | Runs on |
|---|---|---|---|---|---|
| `wireguard-rrnet-reu.prg` | ip65 / RR-Net | REU DMA tables | 860 | none (stock) | C64 + RR-Net + REU (512 KB+) |
| `wireguard-rrnet-noreu.prg` | ip65 / RR-Net | CT on-chip | 860 | none (stock) | stock C64 + RR-Net |
| `wireguard-uci-reu.prg` | UCI | REU DMA tables | 860 | none (stock) | Ultimate 64 / C64 Ultimate |
| `wireguard-uci-noreu.prg` | UCI | CT on-chip | 860 | none (stock) | Ultimate, REU disabled |
| `wireguard-uci-noreu-mtu1440.prg` | UCI | CT on-chip | 1440 | **#807 (unmerged)** | Ultimate running #807 firmware |
| `wireguard-uci-reu-mtu1440.prg` | UCI | REU DMA tables | 1440 | **#807 (unmerged)** | Ultimate running #807 firmware + REU |
| `wireguard-reu.d64` | both REU PRGs (`wg-rrnet`, `wg-uci`) + `wg.cfg` + warning | | 860 | none | |
| `wireguard-noreu.d64` | both no-REU PRGs + `wg.cfg` + warning | | 860 | none | |
| `wireguard-mtu1440.d64` | both mtu1440 PRGs (`wg-uci-noreu`, `wg-uci-reu`) + `wg.cfg` + warning | | 1440 | **#807 (unmerged)** | |
| `FIRMWARE-WARNING.txt` | plain-text copy of the on-disk warning | | | | |
| `VERSION` | `git describe --tags --always --dirty` at build time | | | | |

`wg.cfg` on each disk is a placeholder (all-zero keys, RFC 5737
endpoint) in the 9-line fixed-order SEQ format documented in
`src/wg/disk_config.s` — replace it with real keys before use.

> ```
> C64-WIREGUARD - FIRMWARE WARNING
> =================================
>
> MTU1440 PRGS NEED UNMERGED FIRMWARE:
>   WIREGUARD-UCI-NOREU-MTU1440.PRG
>   WIREGUARD-UCI-REU-MTU1440.PRG
>
> THESE REQUIRE GIDEONZ/1541ULTIMATE
> #807 (CHUNKED SOCKET WRITE), NOT
> MERGED UPSTREAM, AND NOT IN ANY
> RELEASED U64E OR C64U FIRMWARE AS
> OF 2026-09-03.
>
> ON RELEASED FIRMWARE (3.15 AND
> EARLIER) THE FIRST SEND FAILS:
>   SEND FAILED, NET ERR $8E
>
> THE DEFAULT PRGS (RRNET AND UCI,
> REU AND NOREU) NEED NO FIRMWARE
> CHANGE. THEY WORK ON RELEASED
> 3.15 AT MTU 860.
>
> REU CAVEAT (#69): REU=1 BUILDS
> GIVE WRONG X25519 RESULTS AT 48
> MHZ ON FW 3.15. USE THE NOREU
> PRGS FOR TURBO HOSTS.
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
- **Cloudflare WARP, 48 MHz, mtu1440 build:** handshake to `ACTIVE`
  in ~48 s; a subsequent rekey (`H`) reached `ACTIVE` again in ~48 s,
  and a second rekey in ~47 s — each with a strictly greater TAI64N
  timestamp than the last (#87). ICMP echo and a 1278-byte DNS
  response were carried through the tunnel intact.

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
- **#103** — the cold-init reclaim left only single-digit bytes free
  in `MAIN_AREA_LO`/`HI`, blocking the #94 fix until the reclaim was
  widened.
- **#109** — following #103's reclaim, a test calling into the
  reclaimed cold-init span hung for 180 s instead of failing fast; a
  gate check now catches keyword and aliased spellings of the same call.

Also landed:

- **#70** — standard MTU 1440 via `UCI_CHUNKED_WRITE=1` (see above).
- **#87** — monotonic Type-1 timestamps across initiations (see above).

## Known issues

- **#807 is unmerged.** The mtu1440 PRGs fail their first send with
  `NET ERR $8E` on any released firmware; only the default-MTU PRGs
  are usable until a firmware release ships #807.
- **#69** — `REU=1` variants produce wrong X25519 products at 48 MHz
  on fw 3.15. Use the `-noreu` PRGs on turbo hosts until this is
  resolved upstream.
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
- **rrnet (ip65/RR-Net) builds** — #80 (ip65 blob BSS overlapping app
  code) was fixed by PR #83, but that fix is **VICE-verified only**;
  it has not been re-confirmed against RR-Net hardware since.

## Pinned sibling versions

- [c64-x25519](https://github.com/JC-000/c64-x25519) **v0.11.2**
  (up from v0.8.0 at v1.0.0)
- [c64-ChaCha20-Poly1305](https://github.com/JC-000/c64-ChaCha20-Poly1305)
  **v0.9.0** (up from v0.6.0 at v1.0.0)

Both match `README.md`'s stated pins; verified against the checked-out
submodule commits at this release, not asserted from memory.

## Checksums

`SHA256SUMS` is attached to this release and covers every other
attached file. Its first line is a comment naming the release version
(`git describe --tags --always --dirty`); verify with `shasum -c
SHA256SUMS` from inside the extracted asset directory.
