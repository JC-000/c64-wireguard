"""vice_eth_rig.py — shared scaffolding for the ethernet-VICE (RR-Net) suites.

Extracted from tools/test_ip65_bss_corruption.py (PR #81) so the ip65
suites that need a real ethernet emulation — the #80 corruption probe, the
UDP echo / datagram-count suite and the handshake+rekey suite — share one
rig preflight, one boot sequence and one set of map parsers instead of
three drifting copies.

THE RIG (macOS): c64-https' tools/rig-up-macos.sh creates an feth pair,
puts the host on feth1 (10.0.65.1/24), runs dnsmasq there as the DHCP
server, and VICE's pcap driver attaches to feth0. One privileged setup per
boot, NOT done here; a missing prerequisite is reported by
``rig_problems()`` so a suite can exit 77 (skipped) with the reason rather
than fail confusingly against dead silence.

VICE: stock macOS VICE gates pcap on euid 0 and Homebrew's bottle has
networking compiled out (c64-test-harness#144). ``$VICE_ETHERNET_BIN`` (or
``--vice-bin``) must name a build that can do it; ~/opt/vice-eth/bin/x64sc
is the patched 3.10 on this bench.

WARP AND DHCP: warp compresses ip65's DHCP retry budget below dnsmasq's
OFFER latency and DHCP fails every time. ``boot_and_net_init`` therefore
runs at honest speed; a suite that wants warp for crypto turns it on
AFTER network init (``transport.set_warp(True)``).

THE MONITOR HALTS THE MACHINE: every binary-monitor command pauses the
CPU, so any poll loop must ``resume()`` between reads or the C64 freezes
and looks exactly like a hang (issue #54/#55). Every helper here does.
``ResumingTransport`` wraps a transport so host-side helpers written for
hardware (tools/wg_c64_input.py, which polls with plain read_memory +
time.sleep) keep working under VICE unchanged.

KNOWN HAZARD — jsr() LEAKS STACK WHEN IT PRE-EMPTS AN INTERRUPT. The
harness's ``jsr()`` forces the PC to its trampoline without saving or
restoring SP. If the machine happens to be halted inside the KERNAL's IRQ
handler when a call is made, the 3-byte frame that handler pushed (PC +
status) is abandoned, and the I flag it was running under stays set. The
stack pointer therefore descends a few bytes per unlucky call. The echo
suite issues on the order of 1400 ``net_poll`` calls in a sweep, so over
a long enough run the 6510 stack can wrap and the jiffy IRQ can stop
firing.

Nothing in these suites depends on interrupts: every measurement is taken
by DMA or at the wire tap, the C64 is driven by explicit ``jsr()`` calls
rather than by main_loop, and the KERNAL keyboard queue is only used
before the takeover (while the machine is still running its own loop).
The suites are also short — a sweep is ~60 s of wall clock. So this is
documented rather than worked around; a suite that grows to depend on the
jiffy clock, on ``timer_check``, or on running for minutes under takeover
must reset the machine between phases instead of assuming SP is intact.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import threading
import time
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, ScreenGrid  # noqa: E402
from c64_test_harness.backends.vice_binary import BinaryViceTransport  # noqa: E402
from c64_test_harness.backends.vice_lifecycle import (  # noqa: E402
    ViceConfig, ViceProcess,
)
from c64_test_harness.backends.vice_manager import PortAllocator  # noqa: E402
from c64_test_harness.backends.vice_elevation import (  # noqa: E402
    ALLOW_UNELEVATED_ENV, driver_requires_root, effective_driver_name,
    rawnet_capability, vice_binary_supports_ethernet,
)


def vice_rawnet_problems(vice_bin: str, driver: str = "pcap") -> list[str]:
    """Whether VICE will actually get a rawnet driver — VICE's gate, not libpcap's.

    THIS REPLACES a ``bpf_capture_available()`` that checked whether
    /dev/bpf0 and /dev/bpf1 were world read-write. That helper was a
    verbatim copy of one the harness DELETED on purpose in c3fe7aa,
    "fix(vice): ask whether VICE can get rawnet, not whether /dev/bpf* is
    open" — it modelled libpcap's requirements instead of VICE's, so the
    preflight could pass and VICE then die. Copying it re-introduced the
    bug they removed. Do not re-copy that shape.

    VICE's gate is two conditions, and the harness exposes both:

      * the binary was BUILT with raw-network support —
        ``vice_binary_supports_ethernet()``, which reads ``x64sc
        -features``. This is the one that separates Homebrew's bottle
        (networking compiled out, c64-test-harness#144) from the patched
        ~/opt/vice-eth build, and no amount of node permission ever said
        anything about it.
      * ``archdep_rawnet_capability()`` holds for the child —
        ``rawnet_capability(as_root=...)`` (euid 0, or CAP_NET_RAW on
        Linux). Without it ``rawnet_arch_driver`` stays NULL and x64sc
        SIGSEGVs on the first reset with no log output.

    The patched build on this bench lifts the euid half deliberately,
    which is the whole reason it exists, so we run unelevated with
    VICE_ETHERNET_ALLOW_UNELEVATED=1 (set at import below). That opt-out
    is the harness's own documented escape hatch for "this host grants
    the capability by a route we cannot observe".

    /dev/bpf* permissions are libpcap's requirement, not VICE's. For the
    patched build they do still have to be right, so they are reported as
    an ADVISORY note — never as the gate.
    """
    problems: list[str] = []
    if not os.path.exists(vice_bin):
        problems.append(
            f"{vice_bin} missing — an ethernet-capable x64sc is required. "
            "Set VICE_ETHERNET_BIN or pass --vice-bin.")
        return problems
    if not vice_binary_supports_ethernet(vice_bin):
        problems.append(
            f"{vice_bin} was built WITHOUT raw-network support (x64sc "
            "-features says no rawnet) — Homebrew's macOS bottle compiles "
            "networking out entirely (c64-test-harness#144). Point "
            "VICE_ETHERNET_BIN at a build that has it.")
    if driver_requires_root(driver) \
            and not rawnet_capability(as_root=False) \
            and os.environ.get(ALLOW_UNELEVATED_ENV, "").strip() != "1":
        problems.append(
            f"VICE gates the {effective_driver_name(driver)} driver behind "
            "archdep_rawnet_capability() and this process is neither root "
            "nor CAP_NET_RAW; x64sc would SIGSEGV on the first reset with "
            f"no log output. Set {ALLOW_UNELEVATED_ENV}=1 if this build "
            "lifts the gate (the patched ~/opt/vice-eth one does), or run "
            "the launch elevated.")
    return problems


def libpcap_node_note() -> str | None:
    """An ADVISORY line when /dev/bpf* would stop libpcap, or None.

    Not a gate: see vice_rawnet_problems. libpcap needs a bpf node it can
    open, so an unelevated pcap launch on this bench does depend on the
    world-rw perms rig-up sets (they reset on reboot) — but that is a
    property of running unelevated, not the condition VICE tests, and
    treating it as the gate is the c3fe7aa bug.
    """
    bad = []
    for node in ("/dev/bpf0", "/dev/bpf1"):
        try:
            m = os.stat(node).st_mode
        except FileNotFoundError:
            bad.append(f"{node} missing")
            continue
        if not (m & stat.S_IROTH and m & stat.S_IWOTH):
            bad.append(f"{node} not world-rw")
    if not bad:
        return None
    return ("advisory: " + ", ".join(bad) + " — VICE does not read these, "
            "but libpcap does, so an UNELEVATED pcap launch will fail to "
            "open a capture handle. `sudo chmod o+rw /dev/bpf*` (rig-up "
            "does this; it resets on reboot).")


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
WG_MAP_PATH = os.path.join(PROJECT_ROOT, "build", "wireguard.map")
IP65_MAP_PATH = os.path.join(PROJECT_ROOT, "ip65-build", "ip65-c64.map")
CFG_PATH = os.path.join(PROJECT_ROOT, "cfg", "c64-wireguard-ip65.cfg")

HOST_IP = "10.0.65.1"
HOST_IFACE = "feth1"          # the host side of the pair; tcpdump taps here
ETH_IFACE = "feth0"           # VICE's pcap side
DNSMASQ_PIDFILE = "/tmp/c64-rig-dnsmasq.pid"
DEFAULT_VICE_BIN = os.path.expanduser("~/opt/vice-eth/bin/x64sc")

# --- BRIDGED mode --------------------------------------------------------
# The "host" mode above is a private feth pair: the C64 can only reach this
# Mac, and anything beyond it would have to be NATed through the host's IP
# stack — which on this bench means through the host's own Cloudflare WARP
# tunnel (utun1, MTU 1300), capping every path the C64 could take.
#
# BRIDGED mode attaches VICE's pcap driver to a REAL LAN interface instead.
# VICE's CS8900A then reads and writes frames directly on that segment, so
# the emulated C64 is an ordinary node on the physical LAN: it DHCPs from
# the real router, and its IP datagrams are switched to the default gateway
# without ever entering this Mac's IP stack. That is the whole point — the
# host's WARP tunnel is a route in the host's stack, and frames that never
# reach the stack cannot be routed through it. `bridged_problems()` refuses
# to run unless the named interface really is an active LAN interface, and
# the suite proves the bypass empirically (a real router lease, and a full
# 1500-byte-capable path) rather than asserting it from this comment.
#
# This became possible on 2026-09-03, when a USB-C ethernet adapter was
# attached: the built-in en0 is Wi-Fi, and Apple's Wi-Fi drivers do not
# accept injected frames with a foreign source MAC, which is why
# docs/rig said there was no bridged mode on this Mac.
BRIDGED_IFACE = os.environ.get("VICE_BRIDGED_IFACE", "en4")

# KERNAL keyboard queue — see tools/wg_c64_input.py for the mechanics.
KBD_BUFFER = 0x0277
KBD_COUNT = 0x00C6

BOOT_TIMEOUT = 180.0
DHCP_TIMEOUT = 120.0

# do_net_init's own strings (src/wg/strings.s), matched on screen. The
# structural signal is net_initialized (src/wg/data.s), set as the LAST act
# of do_net_init; the strings only name which step failed.
NET_OK_NEEDLE = "LISTENING ON PORT"
NET_FAIL_NEEDLES = ("NET INIT FAILED", "DHCP FAILED", "LISTEN FAILED")

SKIP_EXIT = 77

# The harness refuses an unelevated pcap launch unless told the binary
# grants rawnet capability another way (c64_test_harness/backends/
# vice_elevation.py). Stock VICE selects pcap only at euid 0; the patched
# ~/opt/vice-eth build lifts that gate and runs on the world-rw BPF nodes
# as uid 501 — which is the whole reason it exists — and the only NOPASSWD
# sudoers entry names Homebrew's non-networking x64sc, so elevation is not
# an option here anyway. Opt out, but only if the caller has not decided.
os.environ.setdefault("VICE_ETHERNET_ALLOW_UNELEVATED", "1")


def log(msg: str) -> None:
    print(msg, flush=True)


# ============================================================================
# Rig preflight
# ============================================================================

def _dnsmasq_alive() -> bool:
    """True iff the rig's dnsmasq is serving feth1.

    Two signals, either suffices. The pidfile is what rig-up-macos.sh asks
    dnsmasq to write, but dnsmasq drops to `nobody` and on this bench the
    file is routinely absent while the daemon is alive (measured
    2026-09-03: pid 11847 running with --pid-file=/tmp/c64-rig-dnsmasq.pid
    and no such file). So also accept a live process whose command line
    binds the rig interface — pgrep on `--interface=feth1`, which no other
    dnsmasq on this machine would carry.
    """
    try:
        pid = int(open(DNSMASQ_PIDFILE).read().strip())
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True   # EPERM == the root/nobody-owned process exists
    except (OSError, ValueError):
        pass
    r = subprocess.run(["pgrep", "-f", f"dnsmasq.*--interface={HOST_IFACE}"],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() != ""


def vice_holders(iface: str) -> list[str]:
    """`pid cmdline` for each x64 EMULATOR attached to *iface*.

    Matches the emulator, not the string. ``pgrep -f "ethernetioif en4"``
    also matches any SHELL whose own command line mentions it — a pgrep in
    a wait loop matches itself — and the preflight then reports a busy rig
    against an idle one (measured while writing the #120 suite). Require
    an x64 binary in argv[0] and drop our own pid.
    """
    r = subprocess.run(["pgrep", "-fl", f"ethernetioif {iface}"],
                       capture_output=True, text=True)
    out: list[str] = []
    for line in r.stdout.splitlines():
        pid, _, cmd = line.partition(" ")
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        argv0 = cmd.split()[0] if cmd.split() else ""
        if os.path.basename(argv0).startswith("x64"):
            out.append(line)
    return out


def rig_problems(vice_bin: str) -> list[str]:
    """Return missing-prerequisite messages; empty means the rig is up."""
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["not macOS — this rig is the feth/pcap one from "
                "c64-https' tools/rig-up-macos.sh"]
    problems += vice_rawnet_problems(vice_bin)
    note = libpcap_node_note()
    if note:
        problems.append(note)
    r = subprocess.run(["ifconfig", ETH_IFACE], capture_output=True, text=True)
    if r.returncode != 0:
        problems.append(f"{ETH_IFACE} missing")
    r = subprocess.run(["ifconfig", HOST_IFACE], capture_output=True, text=True)
    if r.returncode != 0 or f"inet {HOST_IP} " not in r.stdout:
        problems.append(f"{HOST_IFACE} missing or not at {HOST_IP}")
    # Another VICE on feth0 is a hard conflict: every ip65 instance uses the
    # same default MAC, so a leftover instance is a live duplicate-MAC node
    # eating the DHCP traffic. x64sc processes NOT on feth0 share this
    # bench — never touch those.
    procs = vice_on_iface(ETH_IFACE)
    if procs:
        problems.append(describe_conflict(procs, ETH_IFACE))
    if not _dnsmasq_alive():
        problems.append(f"rig dnsmasq not running (no live `dnsmasq "
                        f"--interface={HOST_IFACE}` and {DNSMASQ_PIDFILE} "
                        "stale or absent) — no DHCP server on the wire")
    return problems


def skip_if_rig_down(vice_bin: str) -> None:
    """Print the SKIP report and exit 77 when the rig is not up."""
    problems = rig_problems(vice_bin)
    if not problems:
        return
    log("SKIP: ethernet rig not ready:")
    for p in problems:
        log(f"    - {p}")
    log("  The rig needs one privileged setup per boot and is not created "
        "here;")
    log("  see c64-https' tools/rig-up-macos.sh (feth pair + dnsmasq + "
        "bpf perms).")
    sys.exit(SKIP_EXIT)


# ---------------------------------------------------------------------------
# Bridged-mode preflight
# ---------------------------------------------------------------------------

def iface_status(iface: str) -> dict:
    """Parse `ifconfig <iface>` into {up, running, active, inet, netmask,
    ether, mtu, media}.  Missing keys mean the field was not printed."""
    r = subprocess.run(["ifconfig", iface], capture_output=True, text=True)
    if r.returncode != 0:
        return {}
    t = r.stdout
    out: dict = {"raw": t}
    fl = re.search(r"flags=\d+<([^>]*)>", t)
    flags = fl.group(1).split(",") if fl else []
    out["up"] = "UP" in flags
    out["running"] = "RUNNING" in flags
    m = re.search(r"\bmtu (\d+)", t)
    if m:
        out["mtu"] = int(m.group(1))
    m = re.search(r"\bether ([0-9a-f:]{17})", t)
    if m:
        out["ether"] = m.group(1)
    m = re.search(r"\n\tinet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", t)
    if m:
        out["inet"] = m.group(1)
        out["netmask"] = int(m.group(2), 16)
    m = re.search(r"\n\tstatus: (\w+)", t)
    if m:
        out["active"] = m.group(1) == "active"
    m = re.search(r"\n\tmedia: (.*)", t)
    if m:
        out["media"] = m.group(1).strip()
    return out


def default_gateway(iface: str) -> str | None:
    """The IPv4 default gateway reachable over *iface*, from the route table."""
    r = subprocess.run(["netstat", "-rn", "-f", "inet"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] == "default" and f[-1] == iface \
                and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", f[1]):
            return f[1]
    return None


def dnsmasq_interfaces() -> list[str]:
    """Every interface any live dnsmasq on this host is bound to.

    `--bind-interfaces` plus `--interface=X` is a hard bind: the rig's
    dnsmasq answers DHCP on feth1 and nowhere else. The bridged suite
    asserts the LAN interface is NOT in this list, so a lease taken there
    is provably the real router's and not the rig's own DHCP server
    accidentally serving the physical segment (which would make the whole
    "we are on the real LAN" claim vacuous).
    """
    # `-fl`, not `-af`: -a is Linux pgrep. On macOS `pgrep -af` exits 1 with
    # no output, so this function returned [] for every input and the
    # "dnsmasq is not on the bridged interface" check passed vacuously —
    # caught 2026-09-03 by printing the list instead of trusting the empty
    # result. selftest_dnsmasq_probe() is the standing alarm for it.
    r = subprocess.run(["pgrep", "-fl", "dnsmasq"],
                       capture_output=True, text=True)
    out: list[str] = []
    for line in r.stdout.splitlines():
        out += re.findall(r"--interface[= ](\S+)", line)
    return out


def selftest_dnsmasq_probe() -> list[str]:
    """Prove the dnsmasq probe can actually see a running dnsmasq.

    An empty list from dnsmasq_interfaces() is the answer bridged mode
    wants to hear, so it must not be reachable by the probe being broken.
    If any dnsmasq is running at all, the probe has to name at least one
    interface for it; if none is running the probe is unexercised and says
    so rather than claiming a pass.
    """
    r = subprocess.run(["pgrep", "-fl", "dnsmasq"],
                       capture_output=True, text=True)
    running = [ln for ln in r.stdout.splitlines() if "dnsmasq" in ln]
    if not running:
        return ["no dnsmasq is running, so the interface probe is "
                "UNEXERCISED — its empty result proves nothing this run"]
    if not dnsmasq_interfaces():
        return [f"dnsmasq is running but the probe found no --interface: "
                f"{running}"]
    return []


def process_cwd(pid: int):
    """The working directory of *pid*, via lsof. None when unknowable.

    This is how a conflicting process is ATTRIBUTED rather than removed.
    Several agents share this bench and each works in its own worktree, so
    the cwd names the lane that owns the process. A blanket
    ``pkill -f x64sc`` is forbidden here (c64-test skill: "other agents may
    have VICE instances running") and it has already cost another lane a
    run -- 2026-09-03, by me. Identify, name, refuse; never kill what you
    did not start.
    """
    r = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("n"):
            return line[1:]
    return None


def _worktree_of(path):
    """The ``.claude/worktrees/<name>`` component of *path*, if any."""
    if not path:
        return None
    m = re.search(r"\.claude/worktrees/([^/]+)", path)
    return m.group(1) if m else None


def vice_on_iface(iface: str) -> list:
    """Every x64sc bound to *iface*: pid, cwd, worktree, argv."""
    r = subprocess.run(["pgrep", "-fl", "ethernetioif " + iface],
                       capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        head, _, argv = line.strip().partition(" ")
        if not head.isdigit():
            continue
        pid = int(head)
        cwd = process_cwd(pid)
        # The worktree also appears in the -autostart PRG path, which
        # survives even when lsof cannot report the cwd.
        wt = _worktree_of(cwd) or _worktree_of(argv)
        out.append({"pid": pid, "cwd": cwd, "worktree": wt, "argv": argv})
    return out


def describe_conflict(procs: list, iface: str) -> str:
    """A polite, attributing refusal. Never a kill suggestion."""
    lines = ["another VICE is already bound to " + iface + " -- every ip65 "
             "build uses the same default MAC, so a second instance is a "
             "live duplicate-MAC node on the segment:"]
    for pr in procs:
        who = ("worktree " + pr["worktree"]) if pr["worktree"] \
            else ("cwd " + (pr["cwd"] or "unknown"))
        lines.append("      pid %d  (%s)" % (pr["pid"], who))
    lines.append("      That process belongs to another lane. Do NOT kill "
                 "it, and never `pkill x64sc`: wait for the rig, or "
                 "coordinate with whoever owns that worktree.")
    return "\n".join(lines)


def selftest_conflict_probe(iface: str = "en4") -> list:
    """Prove vice_on_iface() can actually SEE a conflicting process.

    An empty list is the answer the preflight wants to hear, so it must
    not also be what a broken probe returns. This is the same coincidence
    class as the pgrep -af bug below: on macOS that flag does not exist,
    the probe returned [] for every input, and the assertion built on it
    passed with no evidence behind it.

    A decoy is spawned whose argv matches the pgrep pattern and whose cwd
    looks like an agent worktree, then the probe must find it AND
    attribute the worktree. The decoy is this function's own child, so
    terminating it is legitimate -- that is the ONLY process any code here
    may kill.
    """
    import tempfile
    bad = []
    with tempfile.TemporaryDirectory() as td:
        fake = os.path.join(td, ".claude", "worktrees", "agent-SELFTESTFAKE")
        os.makedirs(fake)
        decoy = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)",
             "--ethernetioif", iface, "--decoy"],
            cwd=fake, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            found = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                hits = [h for h in vice_on_iface(iface)
                        if h["pid"] == decoy.pid]
                if hits:
                    found = hits[0]
                    break
                time.sleep(0.1)
            if found is None:
                bad.append(f"vice_on_iface({iface}) did not find the decoy "
                           f"pid {decoy.pid} -- the conflict probe is BLIND, "
                           "so an empty result proves nothing")
            else:
                if found["worktree"] != "agent-SELFTESTFAKE":
                    bad.append("the probe found the decoy but misattributed "
                               f"it: worktree={found['worktree']!r} "
                               f"cwd={found['cwd']!r}")
                msg = describe_conflict([found], iface)
                if "SELFTESTFAKE" not in msg:
                    bad.append("describe_conflict() does not name the owner: "
                               + msg)
                if "pkill" not in msg:
                    bad.append("describe_conflict() omits the do-not-kill "
                               "warning: " + msg)
        finally:
            decoy.terminate()
            try:
                decoy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                decoy.kill()
    return bad


def bridged_problems(iface: str, vice_bin: str) -> list[str]:
    """Missing-prerequisite messages for bridged mode; empty means ready."""
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["not macOS — bridged mode is the pcap-on-a-real-NIC rig"]
    if not os.path.exists(vice_bin):
        problems.append(
            f"{vice_bin} missing — an ethernet-capable x64sc is required. "
            "Set VICE_ETHERNET_BIN or pass --vice-bin.")
    if not bpf_capture_available():
        problems.append(
            "/dev/bpf0 and /dev/bpf1 are not world read-write — VICE's pcap "
            "driver cannot attach. Ask the user to run: "
            "sudo chmod o+rw /dev/bpf*  (resets on reboot)")
    st = iface_status(iface)
    if not st:
        problems.append(f"{iface} does not exist")
        return problems
    if not (st.get("up") and st.get("running")):
        problems.append(f"{iface} is not UP+RUNNING")
    if st.get("active") is False:
        problems.append(f"{iface} has no link (status: not active)")
    if "ether" not in st:
        problems.append(f"{iface} is not an ethernet interface (no MAC) — "
                        "bridged mode needs a real L2 segment")
    ip = st.get("inet")
    if not ip:
        problems.append(f"{iface} has no IPv4 address — it is not on a LAN")
    else:
        if st.get("netmask", 0) == 0xFFFFFFFF:
            problems.append(f"{iface} is a /32 (point-to-point), not a LAN "
                            "segment")
        if ip.startswith("169.254."):
            problems.append(f"{iface} only has a link-local address ({ip}) — "
                            "no DHCP server answered on this segment")
    gw = default_gateway(iface)
    if not gw:
        problems.append(f"no IPv4 default gateway routes over {iface} — the "
                        "C64 would have no path off the segment")
    if iface in dnsmasq_interfaces():
        problems.append(
            f"the rig's dnsmasq is bound to {iface} — a lease taken here "
            "would be the rig's, not the real router's; bridged mode "
            "requires dnsmasq to stay on " + HOST_IFACE + " only")
    procs = vice_on_iface(iface)
    if procs:
        problems.append(describe_conflict(procs, iface))
    return problems


def describe_bridged(iface: str) -> str:
    st = iface_status(iface)
    return (f"{iface}: {st.get('inet', '?')}/{st.get('netmask', 0):08x} "
            f"mac={st.get('ether', '?')} mtu={st.get('mtu', '?')} "
            f"media={st.get('media', '?')} gw={default_gateway(iface)}")


def skip_if_bridged_rig_down(iface: str, vice_bin: str) -> None:
    problems = bridged_problems(iface, vice_bin)
    if not problems:
        return
    log(f"SKIP: bridged ethernet rig not ready on {iface}:")
    for p in problems:
        log(f"    - {p}")
    sys.exit(SKIP_EXIT)


def assert_vice_bound_to(proc, iface: str) -> str:
    """Read the LAUNCHED process's argv and prove the pcap binding.

    Structural: the config object this module built is not evidence — what
    matters is the command line the OS is actually running. Returns the
    argv string; raises RuntimeError naming what was missing.
    """
    p = getattr(proc, "_proc", None)
    if p is None:
        raise RuntimeError("VICE process not started")
    r = subprocess.run(["ps", "-o", "command=", "-p", str(p.pid)],
                       capture_output=True, text=True)
    argv = r.stdout.strip()
    if not argv:
        raise RuntimeError(f"VICE pid {p.pid} is gone — cannot verify binding")
    missing = []
    if "-ethernetiodriver pcap" not in argv:
        missing.append("-ethernetiodriver pcap")
    if f"-ethernetioif {iface}" not in argv:
        missing.append(f"-ethernetioif {iface}")
    # The cartridge itself is not a CLI flag: ViceProcess writes the RR-Net
    # resources into a temporary .rc handed to VICE with -addconfig. Read
    # that file rather than trusting the ViceConfig object we built.
    m = re.search(r"-addconfig (\S+)", argv)
    if not m:
        missing.append("-addconfig <rc> (no RR-Net resource file)")
    else:
        try:
            rc = open(m.group(1)).read()
        except OSError as e:
            raise RuntimeError(f"cannot read VICE's rc file: {e}") from e
        for want, why in (
                (r"^ETHERNETCART_ACTIVE=1\s*$", "cartridge not active"),
                (r"^EthernetCartMode=1\s*$", "not RR-Net mode"),
                (rf'^ETHERNET_INTERFACE="{re.escape(iface)}"\s*$',
                 f"interface is not {iface}"),
                (r'^ETHERNET_DRIVER="pcap"\s*$', "driver is not pcap")):
            if not re.search(want, rc, re.M):
                missing.append(f"{why} (no /{want}/ in rc):\n{rc}")
    if missing:
        raise RuntimeError(
            f"VICE was not launched bridged onto {iface}; missing "
            f"{missing} in:\n  {argv}")
    return argv


# ============================================================================
# Map / cfg parsers (structural inputs, never constants)
# ============================================================================

_SEG_ROW = re.compile(
    r"^(\S+)\s+([0-9A-Fa-f]{6})\s+([0-9A-Fa-f]{6})\s+([0-9A-Fa-f]{6})\s")


def parse_map_segments(path: str) -> dict[str, tuple[int, int]]:
    """Parse an ld65 map's `Segment list:` into {name: (start, end)}.

    `end` is inclusive, as printed.  Zero-size segments are dropped: ld65
    prints them with end == start - 1 under the six-digit format, which
    would otherwise read as a one-byte span.
    """
    out: dict[str, tuple[int, int]] = {}
    with open(path) as fh:
        lines = fh.read().splitlines()
    try:
        i = lines.index("Segment list:")
    except ValueError:
        raise RuntimeError(f"{path}: no 'Segment list:' section")
    for line in lines[i + 1:]:
        if line.startswith("Name") or line.startswith("---") or not line.strip():
            if out and not line.strip():
                break
            continue
        m = _SEG_ROW.match(line)
        if not m:
            break
        name, start, end, size = m.group(1), int(m.group(2), 16), \
            int(m.group(3), 16), int(m.group(4), 16)
        if size:
            out[name] = (start, end)
    if not out:
        raise RuntimeError(f"{path}: parsed no segments")
    return out


def parse_map_exports(path: str) -> dict[str, int]:
    """{symbol: value} from an ld65 map's `Exports list by name:`.

    Rows carry two symbols per line: ``name  00A000 RLA   other  00B000 RLA``.

    The terminator is spelled ``[^\\n]*`` rather than ``.*``: under re.S a
    dot matches newlines too, so ``^\\S.*:`` used to match the underline
    row right beneath the header and run on to the next colon anywhere in
    the file, leaving the body a single "\\n". This function raised
    "parsed no exports" on EVERY ld65 map — measured on both
    build/wireguard.map and ip65-build/ip65-c64.map — and had no caller to
    notice until issue #120's suite wanted arp_ip.
    """
    with open(path) as fh:
        text = fh.read()
    m = re.search(r"^Exports list by name:[^\n]*\n(.*?)^\S[^\n]*:[^\n]*$",
                  text, re.S | re.M)
    if not m:
        raise RuntimeError(f"{path}: no 'Exports list by name:' section")
    out: dict[str, int] = {}
    for name, val in re.findall(r"(\S+)\s+([0-9A-Fa-f]{6})\s+[A-Z]{2,3}\b",
                                m.group(1)):
        out[name] = int(val, 16)
    if not out:
        raise RuntimeError(f"{path}: parsed no exports")
    return out


#: A real ld65 map, trimmed to the shapes the parsers must survive: the
#: header, its underline row (which has no colon), two-symbols-per-line
#: export rows, and a FOLLOWING section header that terminates the block.
#: Kept here so the bug below can never come back silently.
_MAP_SAMPLE = """\
Segment list:
-------------
Name                   Start     End    Size  Align
----------------------------------------------------
CODE                  000801  0032EE  002AEE  00001
BSS                   00A000  00AF3F  000F40  00001
NOTHING               000002  000001  000000  00001

Exports list by name:
---------------------
arp_ip                    00A007 RLA    arp_lookup                00208D RLA
cfg_gateway               00325A RLA    cfg_ip                    003252 RLA

Exports list by value:
----------------------
arp_lookup                00208D RLA    cfg_ip                    003252 RLA
"""


def selftest_map_parsers() -> list[str]:
    """Alarm proof for parse_map_exports / parse_map_segments.

    parse_map_exports raised "parsed no exports" on EVERY ld65 map for as
    long as it existed: its terminator was spelled ``^\\S.*:\\s*$`` under
    re.S, where a dot matches newlines, so it matched the underline row
    directly beneath the header and ran on to the next colon anywhere in
    the file — leaving the captured body a single "\\n". Nothing called it,
    so nothing noticed, until the #120 suite wanted arp_ip. That is the
    coincidence class: a helper that had never once worked, sitting in a
    module three suites import.

    This pins the shapes so a future edit fails here instead of in a
    130-second rig run.
    """
    import tempfile
    bad: list[str] = []
    with tempfile.NamedTemporaryFile("w", suffix=".map", delete=False) as fh:
        fh.write(_MAP_SAMPLE)
        path = fh.name
    try:
        try:
            exports = parse_map_exports(path)
        except Exception as exc:  # noqa: BLE001
            return [f"parse_map_exports raised on a real map shape: {exc!r}"]
        want = {"arp_ip": 0xA007, "arp_lookup": 0x208D,
                "cfg_gateway": 0x325A, "cfg_ip": 0x3252}
        for name, value in want.items():
            if exports.get(name) != value:
                bad.append(f"parse_map_exports: {name} = "
                           f"{exports.get(name)}, expected ${value:04X}")
        # Both symbols on a row must be picked up, not just the first.
        if len(exports) != len(want):
            bad.append(f"parse_map_exports returned {len(exports)} symbols, "
                       f"expected {len(want)} — a row carries TWO")
        try:
            segs = parse_map_segments(path)
        except Exception as exc:  # noqa: BLE001
            bad.append(f"parse_map_segments raised: {exc!r}")
        else:
            if segs.get("BSS") != (0xA000, 0xAF3F):
                bad.append(f"parse_map_segments: BSS = {segs.get('BSS')}, "
                           "expected (0xA000, 0xAF3F)")
            if "NOTHING" in segs:
                bad.append("parse_map_segments kept a zero-size segment "
                           "(NOTHING), which reads as a one-byte span")
    finally:
        os.unlink(path)
    return bad


def parse_cfg_segment_types(path: str) -> dict[str, str]:
    """{segment name: ld65 type} from the cfg's SEGMENTS block."""
    text = open(path).read()
    m = re.search(r"^SEGMENTS\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        raise RuntimeError(f"{path}: no SEGMENTS block")
    types: dict[str, str] = {}
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        hit = re.match(r"(\w+)\s*:\s*(.*);", line)
        if not hit:
            continue
        t = re.search(r"\btype\s*=\s*(\w+)", hit.group(2))
        if t:
            types[hit.group(1)] = t.group(1)
    if not types:
        raise RuntimeError(f"{path}: parsed no segment types")
    return types


def parse_cfg_memory(path: str) -> dict[str, tuple[int, int]]:
    """{region: (start, end inclusive)} from the cfg's MEMORY block."""
    text = open(path).read()
    m = re.search(r"^MEMORY\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        raise RuntimeError(f"{path}: no MEMORY block")
    out: dict[str, tuple[int, int]] = {}
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        hit = re.match(r"(\w+)\s*:\s*(.*);", line)
        if not hit:
            continue
        s = re.search(r"\bstart\s*=\s*\$([0-9A-Fa-f]+)", hit.group(2))
        z = re.search(r"\bsize\s*=\s*\$([0-9A-Fa-f]+)", hit.group(2))
        if s and z:
            start, size = int(s.group(1), 16), int(z.group(1), 16)
            out[hit.group(1)] = (start, start + size - 1)
    return out


# ============================================================================
# Build
# ============================================================================

def build_ip65(extra_make_args: list[str] | None = None) -> None:
    """`make clean && make BACKEND=ip65 [extra]` unless C64_SKIP_BUILD."""
    if os.environ.get("C64_SKIP_BUILD"):
        log("C64_SKIP_BUILD set — reusing build/wireguard.prg")
        return
    extra = list(extra_make_args or [])
    cmd = ["make", "BACKEND=ip65"] + extra
    # The knobs go to `clean` too: BUILD_DIR selects WHICH tree is cleaned
    # (a BUILD_DIR=build_x build otherwise cleans `build` and leaves its own
    # stale objects), and the ca65 flag knobs are what the Makefile's
    # CA65_FLAGSTAMP compares against — see the KNOB_GUARDS comment.
    clean = ["make", "clean", "BACKEND=ip65"] + extra
    log(f"=== {' '.join(clean)} && {' '.join(cmd)} ===")
    for c in (clean, cmd):
        r = subprocess.run(c, cwd=PROJECT_ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout[-2000:])
            sys.stderr.write(r.stderr[-2000:])
            raise SystemExit(f"build failed: {' '.join(c)}")


def assert_ip65_build() -> None:
    """Refuse to run against a UCI build — the blob would not be linked in."""
    with open(WG_MAP_PATH) as fh:
        text = fh.read()
    if "ip65_blob.o" not in text:
        raise SystemExit(
            "FATAL: build/wireguard.map has no ip65_blob.o — this is not a "
            "BACKEND=ip65 build. Run `make clean && make BACKEND=ip65` (or "
            "unset C64_SKIP_BUILD).")


# ============================================================================
# VICE plumbing
# ============================================================================

class EthVice:
    """One ethernet-capable VICE on feth0, warp OFF, REU attached.

    Use as a context manager; ``.tr`` is the BinaryViceTransport.
    """

    def __init__(self, vice_bin: str, port: int = 0, prg_path: str = PRG_PATH,
                 reu: bool = True, iface: str = ETH_IFACE):
        self.vice_bin = vice_bin
        self.prg_path = prg_path
        self.reu = reu
        # The feth rig's VICE side by default; a BRIDGED run passes a real
        # NIC name instead (e.g. "en4"), which puts the C64 on the real LAN
        # with its own DHCP lease. VICE binds a libpcap interface by name,
        # so the NIC IS the bridge — see docs/vice-eth-nat.md.
        self.iface = iface
        self._allocator = PortAllocator(port_range_start=6570,
                                        port_range_end=6590)
        self._own_port = port == 0
        self.port = port or self._allocator.allocate()
        if self._own_port:
            res = self._allocator.take_socket(self.port)
            if res is not None:
                res.close()
        self.proc: ViceProcess | None = None
        self.tr: BinaryViceTransport | None = None

    def __enter__(self) -> "EthVice":
        config = ViceConfig(
            prg_path=self.prg_path,
            port=self.port,
            warp=False,               # load-bearing for DHCP, see module doc
            ntsc=True,
            sound=False,
            minimize=True,
            ethernet=True,
            ethernet_mode="rrnet",
            ethernet_interface=self.iface,
            ethernet_driver="pcap",
            ethernet_executable=self.vice_bin,
            run_as_root=False,        # the BPF nodes are world-rw on this rig
            extra_args=(["-reu", "-reusize", "512"] if self.reu else []),
        )
        self.proc = ViceProcess(config)
        self.proc.start()
        log(f"=== VICE pid={self.proc._proc.pid if self.proc._proc else '?'} "
            f"port={self.port} iface={self.iface} (warp OFF) ===")
        self.tr = self._connect()
        return self

    def __exit__(self, *exc) -> None:
        if self.tr is not None:
            try:
                self.tr.close()
            except Exception:  # noqa: BLE001
                pass
        if self.proc is not None:
            self.proc.stop()
        if self._own_port:
            self._allocator.release(self.port)

    def _connect(self, timeout: float = 30.0) -> BinaryViceTransport:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return BinaryViceTransport(port=self.port)
            except Exception as e:  # noqa: BLE001
                last = e
                p = self.proc._proc if self.proc else None
                if p is not None and p.poll() is not None:
                    raise RuntimeError(
                        f"VICE on port {self.port} exited early — is "
                        f"{self.vice_bin} really ethernet-capable?") from e
                time.sleep(0.25)
        raise RuntimeError(
            f"could not reach VICE's binary monitor on {self.port}: {last}")


class ResumingTransport:
    """Transport adapter that resumes the CPU after every monitor command.

    tools/wg_c64_input.py polls with plain ``read_memory`` + ``time.sleep``
    because on the U64 DMA does not stop the CPU. Under VICE's binary
    monitor every command pauses it, so those loops would freeze the
    machine and wait forever. Wrapping the transport keeps the helpers
    byte-for-byte the same as the hardware tools use.
    """

    def __init__(self, tr: BinaryViceTransport):
        self._tr = tr

    def read_memory(self, addr: int, length: int) -> bytes:
        data = self._tr.read_memory(addr, length)
        self._tr.resume()
        return data

    def write_memory(self, addr: int, data: bytes, *a, **kw) -> None:
        self._tr.write_memory(addr, data, *a, **kw)
        self._tr.resume()

    def __getattr__(self, name):
        return getattr(self._tr, name)


def wait_boot_ready(tr, labels: Labels, timeout: float = BOOT_TIMEOUT) -> bool:
    """Poll boot_ready, resuming between reads (issue #55 marker)."""
    addr = labels["boot_ready"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1) == b"\x01":
            return True
        tr.resume()
        time.sleep(1.0)
    return False


def press_key(tr, char: str, timeout: float = 15.0) -> bool:
    """Type one key into the KERNAL queue, resuming between polls."""
    def drained() -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if tr.read_memory(KBD_COUNT, 1)[0] == 0:
                return True
            tr.resume()
            time.sleep(0.1)
        return False

    if not drained():
        return False
    tr.write_memory(KBD_BUFFER, char.encode("ascii"))
    tr.write_memory(KBD_COUNT, bytes([1]))
    tr.resume()
    return drained()


def read_span(tr, start: int, end: int) -> bytes:
    """Read [start, end] via DMA in monitor-friendly chunks."""
    out = bytearray()
    addr, remaining = start, end - start + 1
    while remaining:
        n = min(256, remaining)
        out += tr.read_memory(addr, n)
        addr += n
        remaining -= n
    return bytes(out)


def screen_text(tr) -> str:
    return ScreenGrid.from_transport(tr).continuous_text().upper()


def wait_net_initialized(tr, labels: Labels, timeout: float = DHCP_TIMEOUT
                         ) -> tuple[str, str]:
    """After 'I': wait for net_initialized == 1, resuming between polls.

    Returns (outcome, screen) where outcome is "ok", one of
    NET_FAIL_NEEDLES, or "timeout". The byte is the structural signal;
    the screen is read only to name the failed step.
    """
    addr = labels["net_initialized"]
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        if tr.read_memory(addr, 1) == b"\x01":
            return "ok", screen_text(tr)
        text = screen_text(tr)
        hit = [n for n in NET_FAIL_NEEDLES if n in text]
        if hit:
            return hit[0], text
        tr.resume()
        time.sleep(2.0)
    return "timeout", text


def boot_and_net_init(tr, labels: Labels, *, boot_timeout: float = BOOT_TIMEOUT,
                      dhcp_timeout: float = DHCP_TIMEOUT) -> float:
    """boot_ready -> 'I' -> net_initialized, at honest speed.

    Returns the wall seconds to a listening network; raises SystemExit(1)
    with the screen on any failure.
    """
    t0 = time.monotonic()
    if not wait_boot_ready(tr, labels, boot_timeout):
        log(f"FATAL: boot_ready never set within {boot_timeout:.0f}s")
        log(screen_text(tr))
        raise SystemExit(1)
    log(f"  boot complete (+{time.monotonic() - t0:.0f}s)")
    log("=== Driving network init ('I' -> do_net_init -> DHCP -> listen) ===")
    if not press_key(tr, "I"):
        log("FATAL: the C64 never consumed the keystroke")
        raise SystemExit(1)
    outcome, text = wait_net_initialized(tr, labels, dhcp_timeout)
    if outcome != "ok":
        log(f"FATAL: network init {outcome} within {dhcp_timeout:.0f}s")
        log(text)
        raise SystemExit(1)
    elapsed = time.monotonic() - t0
    i = text.find("NETWORK READY")
    log(f"  net_initialized=1 (+{elapsed:.0f}s): "
        f"{text[i:i + 60].strip() if i >= 0 else '(banner not on screen)'}")
    if NET_OK_NEEDLE not in text:
        log(f"  note: '{NET_OK_NEEDLE}' not on screen although "
            "net_initialized=1 (screen scrolled?)")
    return elapsed


class UdpRec(NamedTuple):
    """One whole UDP datagram seen at the tap."""
    src: str
    sport: int
    dst: str
    dport: int
    length: int


# A `-q -n` full datagram row:
#   12:03:01.548 IP 10.0.65.130.51820 > 10.0.65.1.39351: UDP, length 1472
_TCPDUMP_UDP = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): "
    r"UDP, length (\d+)")
# A `-q -n` NON-FIRST fragment: no ports, because there is no UDP header in
# it — two bare addresses and a protocol word. This is the shape the BPF
# fragment clause admits and the shape the old substring test missed.
_TCPDUMP_FRAG_Q = re.compile(
    r"IP (\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): "
    r"(?:udp|ip-proto-17|ip-proto-udp)\b")
# The `-v` header line, when a caller runs tcpdump verbosely: a datagram is
# fragmented iff More-Fragments is set or this piece sits at a non-zero
# offset.
_TCPDUMP_V_FLAGS = re.compile(r"flags \[([^\]]*)\]")
_TCPDUMP_V_OFFSET = re.compile(r"offset (\d+)")


def classify_tcpdump_line(line: str):
    """Classify one tcpdump line: ("udp", UdpRec) | ("frag", line) | (None, None).

    Pure, so it can be proven against captured line shapes without a
    network — see selftest_classifier(). A torn send is the thing these
    suites exist to catch, so the fragment arm must not be able to score
    zero for the wrong reason.
    """
    m = _TCPDUMP_UDP.search(line)
    if m:
        return "udp", UdpRec(m.group(1), int(m.group(2)), m.group(3),
                             int(m.group(4)), int(m.group(5)))
    fl = _TCPDUMP_V_FLAGS.search(line)
    off = _TCPDUMP_V_OFFSET.search(line)
    if (fl and "+" in fl.group(1)) or (off and int(off.group(1)) > 0):
        return "frag", line.rstrip()
    if _TCPDUMP_FRAG_Q.search(line):
        return "frag", line.rstrip()
    if "ip-proto-17" in line or "frag" in line:
        return "frag", line.rstrip()
    return None, None


#: (line, expected kind) — real shapes, kept next to the classifier so a
#: regex edit that stops recognising one of them fails loudly.
CLASSIFIER_CASES = [
    ("12:03:01.548844 IP 10.0.65.130.51820 > 10.0.65.1.39351: UDP, length 1472",
     "udp"),
    ("12:02:57.162390 IP 10.0.65.1.46341 > 10.0.65.130.51820: UDP, length 1452",
     "udp"),
    # -q -n non-first fragment: no ports at all.
    ("12:03:04.572762 IP 10.0.65.130 > 10.0.65.1: udp", "frag"),
    ("12:03:04.572762 IP 10.0.65.130 > 10.0.65.1: ip-proto-17", "frag"),
    # -v header lines: More-Fragments set, and a non-zero offset.
    ("12:03:04.5 IP (tos 0x0, ttl 64, id 4, offset 0, flags [+], "
     "proto UDP (17), length 1500)", "frag"),
    ("12:03:04.5 IP (tos 0x0, ttl 64, id 4, offset 1480, flags [none], "
     "proto UDP (17), length 20)", "frag"),
    # Unfragmented -v header must NOT be called a fragment.
    ("12:03:04.5 IP (tos 0x0, ttl 64, id 4, offset 0, flags [DF], "
     "proto UDP (17), length 1500)", None),
    ("12:03:04.5 IP (tos 0x0, ttl 64, id 4, offset 0, flags [none], "
     "proto UDP (17), length 90)", None),
    ("tcpdump: listening on feth1, link-type EN10MB (Ethernet)", None),
    ("12:03:04.5 ARP, Request who-has 10.0.65.130 tell 10.0.65.1", None),
]


def selftest_classifier() -> list[str]:
    """Return a list of failure messages; empty means the detector works.

    This is the fragment arm's alarm proof. Without it, `fragments() == 0`
    is a claim no evidence supports: the pre-#118 detector scored the
    `-q -n` fragment shape as nothing, so the assertion passed on a
    capture full of torn datagrams.
    """
    bad: list[str] = []
    for line, want in CLASSIFIER_CASES:
        got, value = classify_tcpdump_line(line)
        if got != want:
            bad.append(f"classifier said {got!r}, expected {want!r}, for: "
                       f"{line.strip()[:88]}")
        if got == "udp" and value.length <= 0:
            bad.append(f"parsed a non-positive length from: {line.strip()}")
    rec = classify_tcpdump_line(CLASSIFIER_CASES[0][0])[1]
    if (rec.src, rec.sport, rec.dst, rec.dport, rec.length) != (
            "10.0.65.130", 51820, "10.0.65.1", 39351, 1472):
        bad.append(f"parsed the wrong fields from a known row: {rec}")
    return bad


class Tap:
    """tcpdump on feth1, parsed into UDP records (src, sport, dst, dport, len).

    ``filter`` is a BPF expression; a fragment clause is appended so a
    datagram torn by IP fragmentation shows up as extra rows (len -1).
    ``-U`` + ``-l`` so lines arrive as the packets do; the pump thread
    keeps every raw line in ``raw`` for the report.
    """

    _LINE = re.compile(
        r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): "
        r"UDP, length (\d+)")

    def __init__(self, bpf_filter: str, iface: str = HOST_IFACE):
        # feth1 (the host end of the rig pair) by default; a BRIDGED run
        # taps the same NIC VICE injects on, where the host's own BPF sees
        # both the C64's frames and the LAN's answers.
        self.iface = iface
        self.filter = f"({bpf_filter}) or (ip[6:2] & 0x1fff != 0)"
        self.records: list[UdpRec] = []
        self.frags: list[str] = []
        self.raw: list[str] = []
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None

    def __enter__(self) -> "Tap":
        self._proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-l", "-n", "-q", "-U", self.filter],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        threading.Thread(target=self._pump, daemon=True).start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            line = self._proc.stderr.readline()
            if "listening on" in line:
                return self
            if not line and self._proc.poll() is not None:
                break
        raise RuntimeError("tcpdump did not start listening on " + self.iface)

    def __exit__(self, *exc) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _pump(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            kind, value = classify_tcpdump_line(line)
            with self._lock:
                self.raw.append(line.rstrip())
                if kind == "udp":
                    self.records.append(value)
                elif kind == "frag":
                    self.frags.append(line.rstrip())

    def udp(self, src: str | None = None, dst: str | None = None,
            dport: int | None = None) -> list[UdpRec]:
        """Whole-datagram UDP records matching the direction.

        Each is a UdpRec(src, sport, dst, dport, length) — the SOURCE port
        is carried because it is load-bearing and otherwise unasserted:
        wg_local_port is the single little-endian port cell among four
        big-endian ones (src/wg/data.s; net_abi.inc declares
        net_udp_dest_port big-endian), and flipping its byte order would
        flip the send and the listen together, leaving every
        content-and-size check green. The handshake suite asserts the
        Type-1's source port against the configured local port for
        exactly that reason.
        """
        with self._lock:
            return [r for r in self.records
                    if (src is None or r.src == src)
                    and (dst is None or r.dst == dst)
                    and (dport is None or r.dport == dport)]

    def fragments(self) -> int:
        """Rows the classifier identified as IP fragments.

        Proven, not assumed: classify_tcpdump_line is a pure function and
        selftest_classifier() feeds it real captured line shapes,
        including the `-q -n` non-first fragment (two bare addresses, no
        ports) that the previous ip-proto-17/"frag" substring test scored
        as nothing at all — which made a `fragments() == 0` assertion pass
        vacuously. The echo suite runs that self-test before it sweeps.
        """
        with self._lock:
            return len(self.frags)


def c64_ip(tr, labels: Labels) -> str:
    """The C64's DHCP-assigned address, read from ip65's own cfg_ip.

    The blob's jump table (ip65-build/ip65_stub.s) is followed by a table
    of variable addresses; +32 is the word pointing at cfg_ip. Reading it
    through the blob rather than the screen keeps this structural.
    """
    base = labels["ip65_blob_start"]
    ptr = tr.read_memory(base + 32, 2)
    addr = ptr[0] | (ptr[1] << 8)
    return ".".join(str(b) for b in tr.read_memory(addr, 4))
