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

## 0b. Why there is no "bridged mode" on this Mac

The obvious way to dodge §0 entirely is to stop NATing through the host stack
and put the emulated C64's frames straight onto the physical LAN, so it takes a
DHCP lease from the real router (`10.43.23.1`) and never meets WARP at all —
the path the U64E already uses. **That is not reachable on this machine.**
Measured 2026-09-03, all read-only:

### There is no wired interface to bridge onto

```
$ networksetup -listallhardwareports | grep -A1 Wi-Fi
Hardware Port: Wi-Fi
Device: en0

$ ipconfig getsummary en0 | grep -E 'InterfaceType|LinkStatusActive'
  InterfaceType : WiFi
  LinkStatusActive : TRUE

$ route -n get default | grep interface
  interface: en0
```

`en0` — the only interface carrying a LAN address (`10.43.23.99`) and the
default route — is Wi-Fi. Classic `ifconfig bridge` L2 bridging cannot use it:
802.11 station mode gives the host one MAC, and a bridge needs to source frames
from the guest's MAC too (here ip65's `00:80:10:00:51:00`, `ip65/config.s:17`).

Every other candidate is down:

| iface | what it is | status |
| --- | --- | --- |
| `en1`, `en2` | Thunderbolt 1 / 2, members of `bridge0` | `status: inactive` |
| `en3`, `en5` | Apple internal (`anpi`-class, `media: none`) | `status: inactive` |
| `bridge0` | Thunderbolt Bridge | `status: inactive` |
| `en4` | **Belkin USB-C LAN** — configured service, adapter unplugged | absent from `ifconfig -a` |
| `en6` | **USB 10/100/1000 LAN** — configured service, adapter unplugged | absent from `ifconfig -a` |

`en4`/`en6` are the interesting rows: `networksetup -listnetworkserviceorder`
lists both as services 1 and 2, so this Mac *has* USB Ethernet adapters that
simply are not attached. **Plug one in and bridging becomes possible** — see
"If a wired adapter is attached" below.

### vmnet does not rescue it either

Apple's `vmnet` framework does give VMs a pseudo-bridge over Wi-Fi, but VICE
cannot reach it:

```
$ otool -L ~/opt/vice-eth/bin/x64sc | grep -i pcap
	/usr/lib/libpcap.A.dylib
$ ~/opt/vice-eth/bin/x64sc -help | grep -A1 ethernetio
-ethernetiodriver <Name>
	Set the low-level driver for Ethernet emulation (tuntap, pcap).
-ethernetioif <Name>
	Set the system ethernet interface
```

VICE takes a **libpcap interface name** (resource `ETHERNET_INTERFACE`, flag
`-ethernetioif <Name>`; driver `-ethernetiodriver pcap`). It links `libpcap`
and nothing else — no `vmnet.framework`. vmnet exposes no pcap device of its
own, so there is no direct binding. The nominal `tuntap` driver is a dead end
too: no `/dev/tap*` exists on this Mac (no tuntap kext).

The indirect route — let a VM stack create a vmnet bridge and add the rig's
`feth` to it — does not stand up either. UTM, Lima, Colima and Docker are all
installed, but no vmnet bridge is currently up (`ifconfig bridge100` →
`interface bridge100 does not exist`, no `vmenet*`), `socket_vmnet` is not
installed, and adding a member to a vmnet-managed bridge needs `sudo` against a
daemon-owned interface. **And it would not help anyway:** vmnet *shared* mode
NATs in the kernel and still egresses via the host routing table, so internet
traffic lands back on `utun1` at MTU 1300 — the exact cap §0 describes. Only
vmnet *bridged* mode would escape WARP, and that is what Wi-Fi rules out.

### Verdict: use §0's split-tunnel

Nothing found beats the known-working path. Keep the NAT rig and exclude the
peer prefix from WARP — no `sudo`, VPN stays up:

```sh
warp-cli tunnel ip add 162.159.192.0/24
route -n get 162.159.192.1 | grep -E 'interface|mtu'   # want: en0, 1500
```

`warp-cli tunnel ip list` and `warp-cli settings` both run unprivileged (this
is a managed/Zero-Trust client, so a policy push may still override a local
add — re-check the route, do not assume).

### If a wired adapter is attached

Should the Belkin (`en4`) or the USB adapter (`en6`) be plugged in later,
bridging becomes a real option and needs **no new tooling for VICE itself** —
VICE binds pcap directly to a named interface, so pointing it at the wired
`enX` *is* the bridge; no `bridge0` membership is required. The steps would be:

1. Confirm link: `ifconfig en4 | grep -E 'media|status'` → `status: active`.
2. Stop the host-only rig's DHCP server, or it will answer the C64 before the
   real router does — `rig-up-macos.sh` starts it:
   `sudo pkill -F /tmp/c64-rig-dnsmasq.pid`
3. Point VICE at the wired interface instead of `feth0`:
   `x64sc -ethernetiodriver pcap -ethernetioif en4 ...`
4. `/dev/bpf*` must be readable/writable. Already granted on this Mac
   (`crw----rw-`), by `rig-up-macos.sh`'s `chmod o+rw /dev/bpf*`; it reverts on
   reboot. **This is the only privileged step bridging needs.**
5. The C64 then DHCPs from `10.43.23.1` and takes a third lease alongside the
   U64E (`.81`) and this Mac (`.99`). ip65's default MAC is a valid unicast
   locally-administered-free address and the router has no reason to refuse it,
   but this is untested — watch for a lease in the router's client list.

Caveat for that mode: host-side listeners on `10.0.65.1` (the Python WireGuard
responder) are **not** reachable from a bridged C64. Bridged mode is for
real-peer / internet tests; keep the host-only rig for the responder.

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

## 6. Two rig failures that look like something else

Both of these cost multiple runs and one false defect report during the #120 work. Neither is
diagnosable from the C64's own output, which is exactly why they are written down here.

### An exhausted capture device looks like a broken network adapter

This bench has **four world-rw `/dev/bpf` nodes**, shared by every lane, and each VICE instance
needs one — as does each `tcpdump` tap. Oversubscribe them and `ip65_init` fails, the C64 prints
`NET INIT FAILED`, and (since #120) it also sets `net_last_error = $41 NET_ERR_IP65_INIT`.

**An oversubscribed rig and a genuine adapter fault are indistinguishable at the C64 end.** Before
concluding anything about the firmware, the driver or the build, count the live capture consumers:

```sh
pgrep -fl 'x64sc|tcpdump' | wc -l      # every one of these may hold a node
```

The nodes are made world-readable by the rig script and the permission **reverts on reboot**, so a
first run after a restart can fail this way with nothing else changed.

### A killed test driver orphans two processes, and the next run dies identically

Killing a runner leaves both `x64sc` **and** its `tcpdump` behind, still holding the interface and a
capture node. The next run then fails at launch in exactly the same way, which invites the
conclusion that the change under test broke something.

Reap by worktree, never with a broad pattern kill — a blanket `pkill -f x64sc` destroyed another
lane's run during this work:

```sh
for p in $(pgrep x64sc); do
  printf '%s -> %s\n' "$p" "$(lsof -a -p "$p" -d cwd -Fn | sed -n 's/^n//p')"
done
```

Kill by PID once you have matched the working directory to your own worktree. `tools/vice_eth_rig.py`
refuses to launch when another instance is bound to the interface and names the owning worktree
rather than terminating it; leave it that way.

Two further notes for anyone driving the emulator directly. Every ip65 build uses the same default
MAC address, so two instances on one interface are a live duplicate-address node rather than two
independent machines. And the process can change between a preflight check and a launch — observed
here — so re-check immediately before starting, not only at preflight.
