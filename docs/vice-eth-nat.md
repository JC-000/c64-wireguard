# Giving the VICE Ethernet rig a route to the internet

The VICE Ethernet rig puts an emulated C64 (ip65 / RR-Net, pcap on `feth0`) on
an isolated `10.0.65.0/24` with the host at `10.0.65.1` on `feth1`. That net has
no way off the Mac. `tools/vice_eth_nat.sh` adds the missing piece — IPv4
forwarding plus a pf NAT — so the C64 can hand-shake against a **real**
WireGuard peer such as Cloudflare WARP at `162.159.192.1:2408`.

Everything here needs `sudo` for exactly two steps (the rig, and the NAT).

## 0. The blocker you will hit first: a VPN on the host

Measured on this Mac, 2026-09-03:

| probe | result |
| --- | --- |
| `ping -D -s 1472 10.43.23.1` (LAN gw, via `en0`) | **OK** — the LAN is a clean 1500 path |
| `ping -D -s 1472 1.1.1.1` (default route) | `sendto: Message too long` |
| `ping -b en0 -D -s 56 1.1.1.1` / `8.8.8.8` / `162.159.192.1` | **100% loss** |
| `nc -z -s 10.43.23.99 1.1.1.1 443` | **refused** |
| `route -n get 162.159.192.1` | `interface: utun1`, `mtu 1300` |

The Cloudflare WARP client is connected (`warp-cli status` → `Connected`,
`utun1`, MTU 1300, protocol MASQUE). It does two things that matter:

1. It takes `0.0.0.0/0` — including `162.159.192.0/22`, the WARP endpoint
   itself — so NAT'd rig traffic would go *into* the tunnel and be capped at
   1300 bytes.
2. `warp-cli settings` reports **`Firewall Scope: All interfaces`**. That is
   why binding to `en0` does not sneak past it: a 56-byte ping and a TCP/443
   connect both fail. Only WARP's exclude list (`10/8`, `172.16/12`,
   `192.168/16`, …) reaches the LAN — which is exactly why the LAN gateway
   still answers.

**So pinning NAT to `en0` does not work while WARP is up.** Pick one, neither
needs `sudo`:

```sh
warp-cli disconnect                        # (a) whole host off WARP
warp-cli tunnel ip add 162.159.192.0/24    # (b) split-tunnel just the peer
```

Then *verify the path actually moved* before spending an hour on a handshake:

```sh
route -n get 162.159.192.1 | grep -E 'interface|mtu'   # want: en0, 1500
ping -c1 -D -s 1472 -b en0 1.1.1.1                      # want: a reply
```

`warp-cli settings` shows `Always On: true` but `Switch Locked: false`, so a
disconnect is permitted — but a managed profile may reconnect on its own.
Re-check the route immediately before the run.

If you leave WARP up the rig still gets *connectivity*, just not full MTU: the
largest datagram that survives `utun1` is `1300 - 20 - 8 = 1272` bytes, i.e. an
inner MTU around 1240. A 1472-byte `WG_MTU1440` datagram is dropped and the
kernel replies to the rig with ICMP frag-needed, which ip65 does not act on —
it black-holes. `vice_eth_nat.sh status` prints this verdict for you.

## 1. Rig up

```sh
sudo bash ../c64-https/tools/rig-up-macos.sh
```

Creates the `feth0`/`feth1` pair (+ `bridge10` only to satisfy the harness
precondition — the feth peers are deliberately *not* bridge members), puts
`10.0.65.1` on `feth1`, opens `/dev/bpf*`, and starts dnsmasq bound to `feth1`
with a `10.0.65.100-150` pool.

Two things to check on this host:

- **Router option.** dnsmasq advertises itself as the default gateway by
  default, which is what the C64 needs to reach anything off-link. The rig
  script sets `--dhcp-option=6,10.0.65.1` (DNS) but not option 3. If the C64
  comes up with no gateway, add `--dhcp-option=3,10.0.65.1` and restart
  dnsmasq. DNS itself does not matter for a WARP run — the endpoint is a
  literal IP, and the rig's dnsmasq runs `--no-resolv` so it resolves nothing
  upstream anyway.
- **Idempotence is not perfect.** The script's "already running" test is
  `[[ -f /tmp/c64-rig-dnsmasq.pid ]]`. On this Mac dnsmasq is running (pid
  11847) but that pidfile has been reaped from `/tmp`, so a re-run will try to
  start a *second* dnsmasq and fail on the bind. Check `pgrep -f dnsmasq`
  first. Separately, `bridge10` currently carries a duplicate `10.0.65.1`
  alias that the script is supposed to remove — re-running it clears that.

## 2. NAT up

```sh
sudo bash tools/vice_eth_nat.sh up --iface en0
```

- sets `net.inet.ip.forwarding=1` (recording the old value),
- enables pf by reference (`pfctl -E`, token saved),
- loads into the anchor **`com.apple/c64wg`**:
  ```
  nat on en0 inet from 10.0.65.0/24 to any -> (en0)
  pass in  on feth1 inet from 10.0.65.0/24 to any keep state
  pass out on en0 inet from any to any keep state
  ```

The anchor is nested under `com.apple/` on purpose: stock `/etc/pf.conf`
references only `nat-anchor "com.apple/*"` and `anchor "com.apple/*"`, so a
top-level `c64wg` anchor would load without error and then never be evaluated.
Your own pf rules are untouched, and `down` flushes only this anchor.

State lives in `/var/run/c64wg-nat.state`. Check any time with:

```sh
sudo bash tools/vice_eth_nat.sh status
```

## 3. Build

```sh
make clean
make BACKEND=ip65 REU=0 WG_MTU1440=1
```

`make clean` is required on any `BACKEND`/`REU` switch — `CA65FLAGS` goes
stale otherwise.

## 4. Run — which tool?

**`tools/test_warp_live.py` cannot drive VICE.** It is hard-typed to
`Ultimate64Transport` / `Ultimate64Client` end to end: every stage helper takes
those, and it also uses `DeviceLock(host)`, `enable_uci`/`get_uci_enabled`,
`set_reu`, and a CPU-speed target — all REST calls to an Ultimate64. Its
`--backend ip65` flag only changes *which built PRG it accepts and how it waits
for net init*; the target is still the hardware at `U64_HOST`. Retargeting it at
VICE would mean swapping the transport for `vice_eth_rig.EthVice` /
`ResumingTransport`, dropping the lock and every UCI/REU/turbo call, and
replacing `run_prg` with the rig's boot path — effectively a rewrite of its
device layer.

**`tools/test_ip65_handshake_vice.py` is the right base for a Cloudflare run.**
It already does the VICE-ethernet half correctly: rig detection (exit 77 when
down), honest-speed DHCP with warp enabled only *after* `net_initialized`,
keyboard-driven `I`/`H` through the real menu, randomised keys and TAI64N base,
and a rekey loop that asserts a strictly increasing timestamp. What it points at
is the bench responder on `10.0.65.1:51820`. For a WARP run you would change:

- peer endpoint → `162.159.192.1:2408`, peer public key → the `[Peer]
  PublicKey` from your wgcf profile, C64 private key → that profile's
  `[Interface] PrivateKey` (read at run time; never commit it — follow
  `test_warp_live.py`'s handling, which logs only the derived public key);
- the inner address → the profile's `Address` rather than `10.0.65.2`;
- the pre-`H` ARP priming — it currently pings the C64 so ip65 caches the
  *host*; with a real peer the C64's next hop is the gateway `10.0.65.1`, which
  is the same host, so that step still does the right job;
- timeouts: `IP65_HS_TIMEOUT_S` defaults to 1800 s under warp — keep it
  generous, a real handshake at honest ip65 speed is slow.

`tools/test_ip65_udp_echo_vice.py` is the cheaper smoke test — run it first to
confirm the rig plus NAT actually carries a datagram off-box before committing
to a handshake.

## 5. Tear down

```sh
sudo bash tools/vice_eth_nat.sh down          # anchor flushed, forwarding + pf restored
sudo pkill -F /tmp/c64-rig-dnsmasq.pid        # (or: sudo pkill -f 'dnsmasq.*feth1')
sudo bash ../c64-test-harness/scripts/teardown-bridge-feth-macos.sh
```

And, if you disconnected it, bring the VPN back:

```sh
warp-cli connect
```

## Caveats worth restating

- The NAT is **host-wide** while it is up: `net.inet.ip.forwarding=1` makes the
  Mac route between all of its interfaces, not just the rig's. Take it down when
  you are done.
- `/dev/bpf*` is left world-readable by the rig script (it reverts on reboot).
- The rig's `10.0.65.0/24` is shared with c64-test-harness, which reserves
  `.1`–`.3`; the DHCP pool starts at `.100` for that reason. Do not narrow it.
