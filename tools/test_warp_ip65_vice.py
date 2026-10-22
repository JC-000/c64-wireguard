#!/usr/bin/env python3
"""test_warp_ip65_vice.py — ip65/RR-Net against Cloudflare WARP, BRIDGED VICE.

OPT-IN, VICE-ethernet only. Exit 77 (skipped) when the bridged rig is not
up; deliberately NOT in tools/run_regression.py (it needs a real LAN, a
real router and the real internet).

WHY BRIDGED, AND WHY IT IS NOT THE SAME TEST AS THE feth RIG
============================================================

The existing ip65 suites run on the feth pair (tools/vice_eth_rig.py's
"host" mode): the C64 can reach this Mac and nothing else, and the peer is
our own Python responder on 10.0.65.1. Everything about WireGuard that
depends on a *real* peer — Cloudflare's TAI64N monotonicity rule, its
cookie/rate limiting, its MTU behaviour, an internet round-trip time — is
therefore untested there.

Routing the feth segment out to the internet would mean NATing it through
this Mac's IP stack, and on this bench that stack's default route is the
host's own Cloudflare WARP tunnel (utun1, MTU 1300). Every C64 datagram
would then be encapsulated a second time and capped at 1300 bytes, so the
one thing #70 exists to prove — a full-size datagram — could not be
observed even if it worked.

BRIDGED mode removes the host stack from the path entirely. VICE's pcap
driver attaches to a real ethernet NIC (the Belkin USB-C adapter, found by
MAC -- en4 on the old Mac, en5 on this one; the built-in
en0 is Wi-Fi and Apple's drivers will not transmit a frame with a foreign
source MAC). The emulated CS8900A then reads and writes frames on the
physical segment, so the C64 is an ordinary LAN node: it DHCPs from the
real router and its IP datagrams are switched straight to the default
gateway. Frames that never enter this Mac's IP stack cannot be routed
through a tunnel that lives in that stack.

That is the reasoning; the suite does not take it on trust. Stage A
asserts the lease came from the real router's subnet and NOT from the feth
rig's 10.0.65.0/24, the preflight asserts the rig's dnsmasq is not bound
to the bridged interface, and Stage C measures on the wire whether a reply
larger than the host tunnel's MTU can reach the C64 whole.

STAGES
======

A  build (BACKEND=ip65 REU=0 WG_MTU1440=1), boot, 'I', REAL DHCP lease
   (read from ip65's own cfg_ip over DMA), stage the WARP peer, 'H', wait
   for wg_state == ACTIVE, and assert at the wire tap that the 148-byte
   Type-1 left FROM the configured local port TO 162.159.192.1 on this
   run's endpoint port (seeded, one of WARP's advertised ports).
B  'P' (ping 1.1.1.1 through the tunnel) and a randomised chat message.
C  rebuild with MSG_PORT=53 BUILD_DIR=build_msgport53, fresh boot and
   handshake, then two real DNS queries to 1.1.1.1:53 staged over DMA:
   one whose reply is host-measured in the 900-1279 B band and one whose
   true answer exceeds ~1280 B. Asserts the inner IPv4/UDP header, the
   transaction id, QR, and reports the received length against the
   host-measured one.
D  --rekey N: press H, assert hs_timestamp strictly increases as a 96-bit
   big-endian integer and ACTIVE returns each time (issue #87, against a
   production peer this time, on ip65).

RED WITHOUT THE FIXES
=====================

* Without the #118 port fix, net_udp_dest_port (big-endian, net_abi.inc)
  is copied raw into ip65's little-endian port cell, so 2408 leaves as
  26633. ``type1_dport_ok`` is the assertion that catches it, and it is
  the ONLY one that can: the handshake simply never completes, and every
  other check reports "timed out" without saying why. ``--prove-red port``
  demonstrates the alarm through net_udp_send DIRECTLY (an 8-byte stub at
  $0340 driven by jsr()), staging the destination port correctly and then
  byte-swapped and reading the dport off the tap. It goes through the send
  path rather than the menu because the menu computes the entire Type-1
  first -- 349 s of X25519 measured on this rig -- which makes it a
  hopeless place to demonstrate a wire-format assertion. Be clear about
  what this is: a deliberate one-field corruption that reproduces the
  unfixed tree's OUTPUT, not a build of the unfixed tree.
* Without WG_MTU1440, ip65's caps clamp WG_MTU to 860 and MSG_TEXT_MAX to
  832 (src/constants.inc), which is smaller than every reply Stage C asks
  for. ``mtu_admits_replies`` is checked from the BUILT labels before any
  VICE is started, so that build is refused up front instead of failing
  as a mysterious short read. ``--prove-red mtu`` links a no-flag build
  and shows the check going red.

TWO VACUOUS CHECKS FOUND IN THIS SUITE'S OWN SCAFFOLDING (2026-09-03)
====================================================================

Both are the coincidence class this project keeps hitting -- an assertion
that passes while testing nothing -- so both now carry a standing alarm
rather than a comment:

1. ``dnsmasq_interfaces()`` used ``pgrep -af``. ``-a`` is Linux pgrep; on
   macOS the call exits 1 with no output, so the function returned [] for
   every input and "the rig's dnsmasq is not serving the bridged
   interface" passed with no evidence behind it. It was found by PRINTING
   the list instead of trusting the empty result. Now ``pgrep -fl``, with
   ``selftest_dnsmasq_probe()`` failing the run when a dnsmasq is running
   that the probe cannot see. ``selftest_conflict_probe()`` guards the
   identical shape for "no other VICE is on this NIC", using a decoy
   process, because that answer is an empty list too.

2. The send-retry poll loop called the rig's ``screen_text()``, which does
   NOT resume, and then slept. Every binary-monitor command pauses the
   6510 (issue #54/#55), so the machine was halted for essentially the
   whole window and running crypto was indistinguishable from a hang --
   it burned a 900 s budget looking exactly like a stuck handshake. The
   local ``screen()`` wrapper in press_h_until_sent resumes, and the
   1000-byte screen read is throttled to 10 s while the 1-byte wg_state
   read carries the fast cadence.

Randomised per run: both C64 static keypairs, the chat payload and the DNS
transaction ids — seeded, the seed logged once, reproducible via --seed.

Usage::

    python3 tools/test_warp_ip65_vice.py [--stages ABCD] [--rekey 2]
                                         [--iface enN] [--seed S]
    --warp-profile PATH / WARP_PROFILE=... use an existing wgcf profile
                                           (offline, rate-limited) instead
                                           of registering a fresh one
    C64_SKIP_BUILD=1                       reuse the builds as found
    --self-test                            the registration/exit-code unit
                                           cases only: stub wgcf, no network

Exit codes: 0 PASS / 1 FAIL / 78 INCONCLUSIVE (nothing failed, but a claim
could not be evaluated -- e.g. every DNS reply's buffer was reused by a
keepalive before it could be read) / 77 SKIP (a precondition is missing: the rig,
or a WARP identity -- wgcf absent, no network, Cloudflare refusing or rate
limiting the registration, an unparseable profile). Once an identity is in
hand, every handshake or tunnel failure is a FAIL, exactly as before.

A FRESH WARP IDENTITY EVERY RUN. By default the suite registers a new
Cloudflare WARP device (`wgcf register --accept-tos`, `wgcf generate`) in a
private 0700 temp dir, reads the profile into memory, and wipes the files
at once -- before any build or VICE launch, and on SIGTERM too. Nothing
secret is stored or needed, anyone can run it, and a key nobody has seen
before is harder for a test to game. The public key's fingerprint is
logged and compared with the previous run's (a repeat is a FAIL).

Each run creates a new WARP account and NOTHING deletes it. wgcf 2.3.1
exposes no deregistration command (register / generate / status / trace /
update only); its generated API client does contain a DeleteSourceDevice
call, but calling Cloudflare's undocumented API directly is not something
this suite does. Accounts accumulate, one per run.

THE PRIVATE KEY IS NEVER PRINTED. Only the derived public key is logged,
and only its first bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import re
import shutil
import signal
import string
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import Labels, jsr  # noqa: E402
import wg_c64_input as ki  # noqa: E402
from vice_eth_rig import (  # noqa: E402
    BRIDGED_IFACE, DEFAULT_VICE_BIN, PROJECT_ROOT, SKIP_EXIT, EthVice,
    ResumingTransport, park_outside_net, resolve_bridged_iface,
    Tap, assert_ip65_build, assert_vice_bound_to, boot_and_net_init,
    build_ip65, c64_ip, default_gateway, describe_bridged, describe_conflict,
    dnsmasq_interfaces, iface_status, log, press_key, screen_text,
    selftest_classifier, selftest_conflict_probe, selftest_dnsmasq_probe,
    skip_if_bridged_rig_down, vice_on_iface, wait_boot_ready,
    wait_net_initialized,
)

# --- Cloudflare WARP peer (public facts; the private key comes from the
#     profile file and is never logged) ---
WARP_PEER_PUB_B64 = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_ENDPOINT_IP = "162.159.192.1"          # engage.cloudflareclient.com
#: WARP's advertised endpoint ports. One is chosen PER RUN from the seed
#: (choose_endpoint_port), not fixed at 2408: on 2026-10-22 the single
#: 5-tuple LAN :51820 -> 162.159.192.1:2408 was blackholed for >=600 s
#: (0/17 host-side injections, plus both C64 runs) while every neighbouring
#: tuple -- the same source to :500/:4500/:1701, or other sources to :2408
#: -- drew Type-2s. Whether that state lived in the router (which preserves
#: ports) or at Cloudflare is unknown; a different seed is the remedy.
WARP_ENDPOINT_PORTS = (2408, 500, 1701, 4500)
#: The run's choice; main() sets it before anything reads it.
WARP_ENDPOINT_PORT = WARP_ENDPOINT_PORTS[0]
TUNNEL_IP = "172.16.0.2"
PING_TARGET_IP = "1.1.1.1"

#: An explicit profile to use instead of registering (None: register).
DEFAULT_WARP_PROFILE = os.environ.get("WARP_PROFILE") or None
WGCF_TIMEOUT_S = float(os.environ.get("WARP_WGCF_TIMEOUT_S", "60"))
#: Recent runs' public-key fingerprints -- public data, kept OUT of $TMPDIR
#: (cleaned by the OS, which would make the freshness check compare nothing).
RECENT_FP_PATH = os.path.join(os.path.expanduser("~"), ".cache",
                              "c64-wireguard", "warp-recent-pubkeys")
RECENT_FP_KEEP = 20

# The feth rig's subnet. A lease from here would mean VICE was NOT bridged
# onto the physical segment, and every "real internet" claim would be void.
RIG_SUBNET_PREFIX = "10.0.65."

SESSION_IDLE, SESSION_HS_SENT, SESSION_ACTIVE = 0, 1, 2
TYPE1_LEN = 148                     # WireGuard MessageInitiation on the wire

BUILD_A = os.path.join(PROJECT_ROOT, "build")
BUILD_C = os.path.join(PROJECT_ROOT, "build_msgport53")
BUILD_RED = os.path.join(PROJECT_ROOT, "build_red_nomtu1440")

DHCP_BUDGET_S = float(os.environ.get("WARP_IP65_DHCP_BUDGET_S", "120"))
HS_BUDGET_S = float(os.environ.get("WARP_IP65_HS_BUDGET_S", "900"))
PING_BUDGET_S = float(os.environ.get("WARP_IP65_PING_BUDGET_S", "60"))
DNS_BUDGET_S = float(os.environ.get("WARP_IP65_DNS_BUDGET_S", "60"))

DNS_QTYPE_TXT = 16
#: (qname, qtype, host-measured reply bytes, band). Measured host-side with
#: the same wire format this suite sends, immediately before the run — see
#: --measure-dns, which reprints them. github.com's TXT answer genuinely
#: exceeds 1280 B; 1.1.1.1 answers it with a 39-byte TC=1 stub on the host's
#: WARP path. Whether the C64's own (host-stack-free) path gets the same
#: stub or the whole record is the datum Stage C exists to collect.
#: Re-queries allowed when the reply's buffer was reused before it was read.
DNS_REUSE_RETRIES = 3

DNS_QUERIES = [
    ("namecheap.com", DNS_QTYPE_TXT, "900-1279 band"),
    ("github.com", DNS_QTYPE_TXT, "true answer >1280 B"),
]

VERBOSE = False
results: list[tuple[bool, str]] = []
#: Claims the run could not evaluate (neither PASS nor FAIL): exit 78.
inconclusive: list[str] = []
#: Every tcpdump tap started, so main()'s finally can stop one an abort left
#: running: a SIGTERM'd run on 2026-10-22 orphaned its Stage C tcpdump
#: (ppid 1, still capturing on en5) because only VICE was in the finally.
_OPEN_TAPS: list = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((bool(ok), label))
    log(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if detail and (not ok or VERBOSE):
        for line in str(detail).splitlines():
            log(f"        {line}")
    return bool(ok)


# ============================================================================
# WARP profile — private key in, public key out, nothing printed
# ============================================================================

def load_warp_profile(path: str) -> tuple[bytes, str, str]:
    """(private key bytes, tunnel ip, peer pubkey b64) from a wgcf profile.

    The private key is returned as bytes and never enters a log line, a
    filename or a subprocess argv (the public key is derived in-process).
    """
    priv_b64 = peer_pub = address = None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("PrivateKey"):
                priv_b64 = line.split("=", 1)[1].strip()
            elif line.startswith("Address"):
                address = line.split("=", 1)[1].strip()
            elif line.startswith("PublicKey"):
                peer_pub = line.split("=", 1)[1].strip()
    if not priv_b64:
        raise RuntimeError(f"{path} has no PrivateKey= line")
    priv = base64.b64decode(priv_b64)
    if len(priv) != 32:
        raise RuntimeError("PrivateKey is not 32 bytes")
    tunnel_ip = address.split("/")[0] if address else TUNNEL_IP
    return priv, tunnel_ip, (peer_pub or WARP_PEER_PUB_B64)


def _stop_all(vices: list) -> None:
    """Stop every VICE and every wire tap this run started (main's finally).

    Taps too: a SIGTERM'd run on 2026-10-22 orphaned its Stage C tcpdump
    (ppid 1, still capturing on en5) because only VICE was stopped here.
    Each __exit__ is idempotent, so the normal path's own stops are fine.
    """
    for v in list(vices):
        try:
            v.__exit__(None, None, None)
        except Exception as e:      # noqa: BLE001
            log(f"  cleanup: {e}")
    log("  cleanup: all VICE instances stopped")
    for t in list(_OPEN_TAPS):
        try:
            t.__exit__(None, None, None)
        except Exception as e:      # noqa: BLE001
            log(f"  cleanup: tap: {e}")
    _OPEN_TAPS.clear()
    log("  cleanup: all wire taps stopped")


def warp_port_arg(text: str) -> int:
    """--warp-port / $WARP_ENDPOINT_PORT: an integer in 1..65535, refused
    otherwise. A port WARP does not advertise is ALLOWED, with a warning at
    run start (choose_endpoint_port's caller), for probing a new one."""
    try:
        port = int(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"not a port number: {text!r}")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port {port} is outside 1..65535")
    return port


def choose_endpoint_port(seed: int, override: int | None = None) -> int:
    """This run's WARP endpoint port: *override*, else drawn from *seed*.

    Its own RNG keyed on the seed, so the draw is reproducible from the
    logged seed and does not shift any other value the run's RNG makes.
    """
    if override is not None:
        return override
    return random.Random(f"warp-endpoint-port:{seed}").choice(WARP_ENDPOINT_PORTS)


class WarpPreconditionError(RuntimeError):
    """No WARP identity could be had: a precondition, exit 77, never 1."""


#: BACKSTOP only (see Redactor): shapes and keywords of the secrets wgcf
#: and the WARP API carry, for anything a literal-value redaction never got
#: a chance to learn (a failure before the account file exists).
_SECRET_RE = re.compile(
    # a WireGuard key, padded, unpadded, or base64url
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{43}=?(?![A-Za-z0-9+/=_-])"
    r"|(?<![A-Za-z0-9+/_-])[A-Za-z0-9_-]{43}=?(?![A-Za-z0-9+/=_-])"
    # TOML / YAML / env:  key = value   key: "value"
    r"|(?i:(?P<kw>(?:access_?token|license(?:_key)?|private_?key|token|"
    r"device_?id|account_?id|secret)\s*[=:]\s*))\"?[^\s\",}]+\"?"
    # JSON:  "key": "value"
    r"|(?i:(?P<jk>\"(?:access_?token|token|license(?:_key)?|private_?key|"
    r"key|id|account_?id|device_?id|secret)\"\s*:\s*))\"[^\"]*\""
    # HTTP:  Authorization: Bearer xxx
    r"|(?i:(?P<auth>authorization\s*:\s*bearer\s+))\S+")


def _backstop(text: str) -> str:
    def sub(m):
        return (m.group("kw") or m.group("jk") or m.group("auth") or "") \
            + "<redacted>"
    return _SECRET_RE.sub(sub, text)


class Redactor:
    """Redact the EXACT secret values of this registration, then shapes.

    Literal values first: after register/generate the account file and
    profile are read and every secret string in them -- private key,
    access token, license key, device/account id -- is remembered, with
    its base64url and unpadded spellings, and cut from anything logged.
    Shape matching alone misses formats nobody thought of; the literal
    cannot be missed in any format that carries it verbatim.
    """

    _ACCOUNT_KEYS = re.compile(
        r"^\s*(access_token|private_key|license_key|device_id|account_id|"
        r"token|id)\s*=\s*['\"]?([^'\"\s]+)", re.M | re.I)

    def __init__(self) -> None:
        self.literals: set[str] = set()

    def learn(self, value: str) -> None:
        v = value.strip()
        if len(v) < 6:
            return
        self.literals |= {v, v.rstrip("="),
                          v.replace("+", "-").replace("/", "_"),
                          v.replace("+", "-").replace("/", "_").rstrip("=")}

    def learn_file(self, path: str) -> None:
        try:
            text = open(path).read()
        except OSError:
            return
        for _, val in self._ACCOUNT_KEYS.findall(text):
            self.learn(val)
        for m in re.finditer(r"^\s*PrivateKey\s*=\s*(\S+)", text, re.M):
            self.learn(m.group(1))

    def __call__(self, text: str) -> str:
        for lit in sorted(self.literals, key=len, reverse=True):
            text = text.replace(lit, "<redacted>")
        return _backstop(text)


def scrub(text: str) -> str:
    """Backstop-only redaction, for text no registration produced."""
    return _backstop(text)


def failure_summary(verb: str, rc: int, output: str, redact) -> str:
    """The allowlisted summary of a failed wgcf call: exit code, the HTTP
    status if one is named, and the FIRST line of output after redaction --
    never wgcf's raw output, which is where a secret would be."""
    clean = redact(output)
    # Only a number NEXT TO "HTTP" or "status" is a status: "dial tcp
    # 1.2.3.4:443" must not read as HTTP 443.
    status = re.search(r"(?i)\b(?:HTTP(?:/\d(?:\.\d)?)?|status(?:\s*code)?)"
                       r"[\s:=]*([1-5]\d\d)\b", clean)
    first = next((ln.strip() for ln in clean.splitlines() if ln.strip()), "")
    return (f"`wgcf {verb}` exited {rc}"
            + (f", HTTP {status.group(1)}" if status else "")
            + (f": {first[:200]}" if first else ""))


#: A run's maximum length, for sweeping identity dirs a SIGKILL left behind.
STALE_IDENTITY_DIR_S = 6 * 3600


def sweep_stale_identity_dirs(now: float | None = None) -> int:
    """Remove c64wg-warp-* dirs of THIS user older than any run can last.

    A SIGKILL skips every finally; this is what then removes the dir.
    """
    now = time.time() if now is None else now
    n = 0
    base = tempfile.gettempdir()
    for name in os.listdir(base):
        if not name.startswith("c64wg-warp-"):
            continue
        path = os.path.join(base, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if (os.path.isdir(path) and not os.path.islink(path)
                and st.st_uid == os.getuid()
                and now - st.st_mtime > STALE_IDENTITY_DIR_S):
            shutil.rmtree(path, ignore_errors=True)
            n += 1
    return n


def register_fresh_identity(wgcf: str | None = None,
                            timeout: float | None = None,
                            on_tempdir=None) -> tuple[bytes, str, str]:
    """A brand-new WARP registration: (private key, tunnel ip, peer pub).

    wgcf runs with --config/--profile pointing into a private 0700 temp
    dir, cwd and HOME there too, so nothing lands in the tree or $HOME.
    The profile is parsed into memory and the dir REMOVED before returning,
    on every path (an exception, or SIGTERM turned into SystemExit).

    What that guarantees, honestly: the files are unlinked and the dir is
    gone; the blocks are NOT scrubbed -- on APFS (copy-on-write) an
    overwrite writes new blocks and leaves the old ones, so pretending
    otherwise would be theatre. The key's lifetime on disk is the seconds
    between `generate` and the rmtree, in a 0700 dir; a SIGKILL in that
    window leaves the dir for sweep_stale_identity_dirs().
    *on_tempdir* is for the self-test only: it is told the dir's path.
    """
    wgcf = wgcf or shutil.which("wgcf")
    if not wgcf:
        raise WarpPreconditionError(
            "wgcf not found on PATH (brew install wgcf), and no "
            "--warp-profile / WARP_PROFILE was given")
    d = tempfile.mkdtemp(prefix="c64wg-warp-")
    os.chmod(d, 0o700)
    if on_tempdir:
        on_tempdir(d)
    redact = Redactor()
    try:
        acct = os.path.join(d, "wgcf-account.toml")
        prof = os.path.join(d, "wgcf-profile.conf")
        env = {**os.environ, "HOME": d}
        for verb, argv in (
                ("register", [wgcf, "--config", acct, "register",
                              "--accept-tos"]),
                ("generate", [wgcf, "--config", acct, "generate",
                              "--profile", prof])):
            try:
                r = subprocess.run(argv, cwd=d, env=env, capture_output=True,
                                   text=True, stdin=subprocess.DEVNULL,
                                   timeout=timeout or WGCF_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                raise WarpPreconditionError(
                    f"`wgcf {verb}` did not finish in "
                    f"{timeout or WGCF_TIMEOUT_S:.0f}s (no network?)")
            except OSError as e:
                raise WarpPreconditionError(f"`wgcf {verb}` could not run: {e}")
            redact.learn_file(acct)
            redact.learn_file(prof)
            if r.returncode != 0:
                raise WarpPreconditionError(
                    failure_summary(verb, r.returncode,
                                    (r.stderr or "") + (r.stdout or ""), redact)
                    + " (no network, or Cloudflare refused / rate-limited "
                      "the registration)")
        try:
            return load_warp_profile(prof)
        except (OSError, RuntimeError, ValueError) as e:
            raise WarpPreconditionError(
                f"wgcf's profile could not be parsed: {redact(str(e))}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def obtain_identity(profile: str | None) -> tuple[bytes, str, str, str]:
    """(private key, tunnel ip, peer pub, source) -- or WarpPreconditionError."""
    if profile:
        try:
            return (*load_warp_profile(profile), f"profile {profile}")
        except (OSError, RuntimeError, ValueError) as e:
            raise WarpPreconditionError(
                f"--warp-profile {profile} unusable: {scrub(str(e))}")
    return (*register_fresh_identity(), "fresh wgcf registration")


def pubkey_fingerprint(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:16]


def record_fingerprint(fp: str, path: str | None = None) -> tuple[str, int]:
    """Compare *fp* with the recent runs' and append it: (verdict, n).

    verdict is "repeat" (a FAIL of the fresh-per-run property), "new"
    (checked against *n* earlier keys), or "not compared" (no history: the
    first run, or the file was lost -- logged, never counted as a pass).
    Read-check-append happens under an exclusive flock, so two lanes
    registering at once cannot both miss each other.
    """
    import fcntl
    path = path or RECENT_FP_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.seek(0)
            seen = [ln.strip() for ln in fh if ln.strip()]
            # Test hook only: widen the read-check-append window so the
            # self-test can make two processes interleave inside it.
            pause = float(os.environ.get("C64WG_FP_TEST_PAUSE", "0") or 0)
            if pause:
                time.sleep(pause)
            fh.seek(0)
            fh.truncate()
            fh.write("".join(f"{x}\n" for x in (seen + [fp])[-RECENT_FP_KEEP:]))
    except OSError as e:
        log(f"  (could not read/record key fingerprints at {path}: {e})")
        return "not compared", 0
    if fp in seen:
        return "repeat", len(seen)
    return ("new", len(seen)) if seen else ("not compared", 0)


def selftest_dnsmasq_probe_bridged() -> list[str]:
    """selftest_dnsmasq_probe(), exercised even when no dnsmasq runs.

    In bridged mode the feth rig is usually down, so there is no dnsmasq
    for the probe to see and the shared self-test reports itself
    UNEXERCISED. That is not evidence either way -- a blind probe says the
    same -- so instead of raising the feth rig (a real DHCP server on this
    host, the very thing the guarded check exists to keep off the bridged
    segment) give the probe a DECOY: a process of ours whose command line
    names dnsmasq and a made-up --interface. The probe must report that
    interface. The decoy is our own child, the only process we may kill.
    """
    bad = selftest_dnsmasq_probe()
    if not bad or "UNEXERCISED" not in bad[0]:
        return bad
    tag = f"c64decoy{os.getpid()}"
    decoy = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)",
         "dnsmasq-decoy", f"--interface={tag}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if tag in dnsmasq_interfaces():
                return []
            time.sleep(0.2)
        return [f"no dnsmasq runs, and the probe did not see a decoy "
                f"dnsmasq --interface={tag} either: it is blind"]
    finally:
        decoy.terminate()
        try:
            decoy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            decoy.kill()


def exit_code(results: list, inconclusive: list) -> int:
    """1 if anything FAILED; else 78 if a claim went unevaluated; else 0."""
    if any(not ok for ok, _ in results):
        return 1
    return 78 if inconclusive else 0


def inbound_guard(snap: bytes, our_idx: bytes, recv_len: int) -> str | None:
    """Why *snap* (tp_packet[0:44+recv_len]) is NOT the inbound reply, or None.

    The C64's keepalive (src/wg/timer.s, every 600 jiffies) encrypts IN
    PLACE in tp_packet: a 0-byte payload rewrites [0:32] -- the outbound
    header and the Poly1305 tag (src/wg/ip_build.s:456) -- and leaves the old
    payload beyond it. So a reply read field by field, with the C64 running
    between reads, can score the tag as the inner IPv4 source while the
    destination, UDP header and payload still look right (2026-10-22, the
    namecheap "inner source 55.97.181.112"). An inbound header carries OUR
    receiver index and an IPv4 header; the outbound one carries the peer's.
    """
    if len(snap) < 44 + recv_len:
        return f"short snapshot ({len(snap)} B)"
    if snap[0] != 4:
        return f"type byte {snap[0]}, not 4"
    if snap[4:8] != our_idx:
        return (f"receiver index {snap[4:8].hex()} is not ours "
                f"({our_idx.hex()}): an outbound header")
    if snap[16] != 0x45:
        return f"inner header byte {snap[16]:#04x}, not 0x45"
    total = (snap[18] << 8) | snap[19]
    if total != recv_len + 28:
        return f"inner total length {total}, not {recv_len} + 28"
    return None


def snapshot_inbound(rt, L, recv_len: int, our_idx: bytes
                     ) -> tuple[bytes | None, str | None]:
    """The inbound reply in ONE monitor read, guarded: (snap, None), or
    (None, why) when the buffer is no longer the reply.

    One read is one instant: the monitor halts the 6510 for it, so header,
    lengths and payload cannot come from two different packets.
    """
    ptr = int.from_bytes(rt.read_memory(L["msg_recv_ptr"], 2), "little")
    if ptr != L["tp_packet"] + 44:
        return None, (f"msg_recv_ptr ${ptr:04X} is not tp_packet+44 "
                      f"${L['tp_packet'] + 44:04X}")
    snap = bytes(rt.read_memory(L["tp_packet"], 44 + recv_len))
    why = inbound_guard(snap, our_idx, recv_len)
    return (None, why) if why else (snap, None)


def derive_pubkey(priv: bytes) -> bytes:
    """X25519 public key of *priv*, in-process (32 raw bytes).

    Was `wg pubkey` on stdin: a /opt/homebrew/bin/wg dependency for one
    scalar multiplication the cryptography package already does.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    return (X25519PrivateKey.from_private_bytes(priv).public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw))


def stage_warp_config(tr, L, priv: bytes, pub: bytes, peer_pub: bytes,
                      tunnel_ip: str, *, swap_port: bool = False) -> int:
    """Stage cfg_* for the WARP peer over DMA; returns the TAI64N base used.

    Modelled on tools/test_warp_live.py's _stage_config. cfg_peer_endpoint_port
    is BIG-endian in the ABI (net_abi.inc); *swap_port* stages it the wrong
    way round on purpose, to reproduce the pre-#118 wire symptom.
    """
    tr.write_memory(L["cfg_static_priv"], priv)
    tr.write_memory(L["cfg_static_pub"], pub)
    tr.write_memory(L["cfg_peer_pub"], peer_pub)
    tr.write_memory(L["cfg_preshared_key"], bytes(32))          # no PSK
    tr.write_memory(L["cfg_peer_endpoint_ip"],
                    bytes(int(o) for o in WARP_ENDPOINT_IP.split(".")))
    port_be = bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF])
    tr.write_memory(L["cfg_peer_endpoint_port"],
                    port_be[::-1] if swap_port else port_be)
    tr.write_memory(L["tunnel_ip"], bytes(int(o) for o in tunnel_ip.split(".")))
    tr.write_memory(L["ping_target_ip"],
                    bytes(int(o) for o in PING_TARGET_IP.split(".")))
    # issue #87: a FRESH base time every run, so this run's first initiation
    # is strictly newer than any earlier run's against the same static key.
    # Cloudflare enforces WireGuard's greatest-seen-timestamp rule and drops
    # a repeat in silence.
    tai = int(time.time()) + 10          # TAI-UTC offset; approximate is fine
    tr.write_memory(L["tai64n_base_time"], tai.to_bytes(8, "big"))
    tr.write_memory(L["wg_state"], bytes([SESSION_IDLE]))
    log(f"  cfg staged: c64_pub {pub.hex()[:16]}…  peer {peer_pub.hex()[:16]}…  "
        f"endpoint {WARP_ENDPOINT_IP}:{WARP_ENDPOINT_PORT}"
        f"{' (PORT DELIBERATELY BYTE-SWAPPED)' if swap_port else ''}  "
        f"tunnel {tunnel_ip}  tai64n base {tai}")
    return tai


# ============================================================================
# DNS (host-side wire construction; copied from tools/test_warp_live.py)
# ============================================================================

def build_dns_query(name: str, qtype: int, txn_id: int,
                    bufsize: int = 1400) -> tuple[bytes, bytes]:
    """(question section, full query wire bytes).

    The first value is the QUESTION SECTION ONLY — no header — because it
    is compared against the reply starting at the reply's own offset 12.
    """
    def enc(n: str) -> bytes:
        out = b""
        for label in n.strip(".").split("."):
            if label:
                out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    header = struct.pack(">HHHHHH", txn_id, 0x0100, 1, 0, 0, 1)   # RD, 1Q, OPT
    question = enc(name) + struct.pack(">HH", qtype, 1)           # QCLASS=IN
    opt = b"\x00" + struct.pack(">HHIH", 41, bufsize, 0, 0)       # EDNS0
    return question, header + question + opt


def measure_dns_host(name: str, qtype: int, bufsize: int = 1400
                     ) -> tuple[int, bool]:
    """(reply length, TC bit) as this HOST sees it. Best-effort.

    This is the host's path, which on this bench runs through the host's
    own WARP tunnel — it is the comparison baseline, not ground truth for
    the C64's direct path. -1 on failure so a DNS hiccup does not fail the
    suite before the C64 has been asked anything.
    """
    import socket
    _, wire = build_dns_query(name, qtype, random.randint(0, 0xFFFF), bufsize)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    try:
        s.sendto(wire, (PING_TARGET_IP, 53))
        d, _ = s.recvfrom(65535)
        return len(d), bool(d[2] & 0x02)
    except OSError:
        return -1, False
    finally:
        s.close()


def stage_raw_dma(tr, payload: bytes, L, timeout: float = 20.0) -> bool:
    """wg_c64_input.send_message_dma, but staging RAW bytes.

    send_message_dma upper()s and ASCII-encodes its text, which would
    corrupt binary DNS wire data. Same keystrokes, same buffer, no
    transform. (From tools/test_warp_live.py.)
    """
    limit = ki.input_max_from_labels(L)
    if len(payload) > limit:
        raise ValueError(f"{len(payload)} bytes exceeds this build's "
                         f"MSG_TEXT_MAX of {limit}")
    if not ki.press_key(tr, "M", timeout):
        return False
    if not ki._wait_drained(tr, timeout):
        return False
    time.sleep(0.3)
    base = L["ip_packet_buf"] + ki.IP_UDP_HDR_LEN
    for i in range(0, len(payload), ki.DMA_CHUNK):
        tr.write_memory(base + i, payload[i:i + ki.DMA_CHUNK])
    tr.write_memory(L["msg_input_len"], len(payload).to_bytes(2, "little"))
    return ki.press_key(tr, "\r", timeout)


# ============================================================================
# Structural pre-checks on the BUILT labels
# ============================================================================

REQUIRED_LABELS = [
    "boot_ready", "net_initialized", "ip65_blob_start", "wg_state",
    "hs_timestamp", "cfg_static_priv", "cfg_static_pub", "cfg_peer_pub",
    "cfg_preshared_key", "cfg_peer_endpoint_ip", "cfg_peer_endpoint_port",
    "tunnel_ip", "ping_target_ip", "tai64n_base_time", "wg_local_port",
    "WG_MTU", "ip_packet_buf", "ip_pkt_len", "msg_input_len", "msg_recv_len",
    "msg_recv_ptr", "tp_packet", "tp_payload_len", "tp_send_counter",
]


def load_labels(build_dir: str) -> Labels:
    path = os.path.join(build_dir, "labels.txt")
    if not os.path.exists(path):
        raise SystemExit(f"FATAL: missing {path}")
    L = Labels.from_file(path)
    missing = [n for n in REQUIRED_LABELS if L.address(n) is None]
    if missing:
        raise SystemExit(f"FATAL: labels missing from {path}: {missing}")
    return L


def check_mtu_admits(L, need: int) -> bool:
    """MSG_TEXT_MAX derived from the labels must hold the largest reply.

    Structural, and checked before a VICE is started: without WG_MTU1440
    ip65's caps clamp WG_MTU to 860 and MSG_TEXT_MAX to 832, so a
    1278-byte DNS reply cannot arrive whole no matter what the wire does.
    """
    limit = ki.input_max_from_labels(L)
    return check(limit >= need,
                 f"build admits a {need}-byte tunnel payload "
                 f"(WG_MTU={L['WG_MTU']}, MSG_TEXT_MAX={limit})",
                 f"MSG_TEXT_MAX = ip_pkt_len - ip_packet_buf - 28 = {limit}; "
                 f"need {need}. Build with WG_MTU1440=1.")


def fingerprint(tag: str, prg_path: str, L) -> str:
    data = open(prg_path, "rb").read()
    fp = (f"{tag}: {os.path.relpath(prg_path, PROJECT_ROOT)} "
          f"{len(data)} B sha256 {hashlib.sha256(data).hexdigest()[:16]} "
          f"WG_MTU={L['WG_MTU']} MSG_TEXT_MAX={ki.input_max_from_labels(L)}")
    log("  " + fp)
    return fp


# ============================================================================
# Shared boot -> lease -> handshake sequence
# ============================================================================

SEND_FAILED_NEEDLE = "HANDSHAKE SEND FAILED"       # src/wg/strings.s:135
SEND_ATTEMPTS = int(os.environ.get("WARP_IP65_SEND_ATTEMPTS", "3"))


def press_h_until_sent(rt, tr, L, tag: str
                       ) -> tuple[bool, int, list[str]]:
    """Press H until the Type-1 actually leaves. Returns (ok, attempts, log).

    ip65 does NOT queue a datagram whose next-hop MAC it has not got: it
    emits the ARP request and returns C=1 immediately (ip65/ip.s), and
    session_initiate reports that as HANDSHAKE SEND FAILED and drops back
    to IDLE. On the feth rig the existing suites never see this, because
    the peer IS the host and the host pings the C64 first, which caches
    the host's MAC via arp_process. Bridged, the peer is off-subnet and
    the next hop is the router, so the FIRST initiation after net_init
    reliably fails on a cold cache — and its own ARP request is what
    fills the cache, so the second one succeeds.

    Measured 2026-09-03: with no retry, wg_state simply never left IDLE
    and the suite sat out its whole 900 s budget with an empty wire and
    "HANDSHAKE SEND FAILED" on screen.

    Detection is prompt rather than budget-bound: the loop watches the
    structural signal (wg_state leaving IDLE) and the failure string
    together, re-reading the on-screen occurrence count immediately
    before each press so a repeat failure is distinguishable from the
    previous attempt's message still sitting on screen.
    """
    def screen(tr) -> str:
        """screen_text + resume. The rig's screen_text() does NOT resume,
        and every binary-monitor command pauses the 6510 (issue #54/#55):
        a poll loop that reads the screen and then sleeps leaves the C64
        HALTED for the whole sleep. Measured 2026-09-03: a 2 s cadence
        without this resume stopped the machine dead in the middle of the
        Type-1 scalarmult, and the run looked exactly like slow crypto."""
        t = screen_text(tr)
        tr.resume()
        return t

    notes: list[str] = []
    for attempt in range(1, SEND_ATTEMPTS + 1):
        base_hits = screen(tr).count(SEND_FAILED_NEEDLE)
        if not ki.press_key(rt, "H", timeout=20.0):
            notes.append(f"attempt {attempt}: 'H' was not consumed")
            return False, attempt, notes
        t0 = time.monotonic()
        deadline = t0 + HS_BUDGET_S
        next_screen = t0
        while time.monotonic() < deadline:
            if rt.read_memory(L["wg_state"], 1)[0] != SESSION_IDLE:
                notes.append(f"attempt {attempt}: Type-1 sent after "
                             f"{time.monotonic() - t0:.0f}s")
                log(f"  [{tag}] Type-1 sent on attempt {attempt} "
                    f"({time.monotonic() - t0:.0f}s of crypto)")
                return True, attempt, notes
            # The screen read costs 1000 bytes over the monitor and a
            # pause/resume; the 1-byte wg_state read is what runs at the
            # fast cadence. Ten seconds is far quicker than the crypto.
            if time.monotonic() < next_screen:
                time.sleep(2.0)
                continue
            next_screen = time.monotonic() + 10.0
            if screen(tr).count(SEND_FAILED_NEEDLE) > base_hits:
                notes.append(f"attempt {attempt}: {SEND_FAILED_NEEDLE} after "
                             f"{time.monotonic() - t0:.0f}s (ip65 ARP cache "
                             "miss for the next hop)")
                log(f"  [{tag}] {SEND_FAILED_NEEDLE} on attempt {attempt} "
                    f"({time.monotonic() - t0:.0f}s) — retrying now that "
                    "ip65 has ARPed the gateway")
                break
            time.sleep(2.0)
        else:
            notes.append(f"attempt {attempt}: neither sent nor failed within "
                         f"{HS_BUDGET_S:.0f}s")
            return False, attempt, notes
        time.sleep(3.0)          # let the ARP reply land and be cached
    return False, SEND_ATTEMPTS, notes


def assert_iface_free(iface: str) -> None:
    """Refuse to launch if another lane holds *iface*. Never kills.

    The preflight already checked this, but a build takes about a minute
    and the rig is shared: on 2026-09-03 another lane's VICE claimed en4
    during exactly that window, so my launch failed with a bare "VICE
    exited early". Re-check at the last possible moment and name the
    owner, so the refusal is actionable instead of mystifying.
    """
    procs = vice_on_iface(iface)
    if procs:
        raise SystemExit("REFUSING TO LAUNCH: "
                         + describe_conflict(procs, iface))


SEND_STUB = 0x0340      # free tape buffer: harness owns $0334, $0360, $03F0-1


def _jsr_send(tr, L, dest_ip: str, dest_port_bytes: bytes, payload: bytes
              ) -> int:
    """Stage a datagram and call net_udp_send directly. Returns the carry.

    The menu path pays a full Type-1 (301 s measured on this rig, no-REU
    under VICE warp) BEFORE it ever reaches the send, which makes it a
    hopeless place to demonstrate a wire-format assertion. net_udp_send
    takes the buffer pointer in A/X, which jsr() cannot set, so an 8-byte
    stub loads them and calls it.
    """
    buf = L["ip_packet_buf"]
    tr.write_memory(buf, payload)
    tr.write_memory(L["net_udp_dest_ip"],
                    bytes(int(o) for o in dest_ip.split(".")))
    tr.write_memory(L["net_udp_dest_port"], dest_port_bytes)
    tr.write_memory(L["net_udp_send_len"], len(payload).to_bytes(2, "little"))
    tr.write_memory(SEND_STUB, bytes([
        0xA9, buf & 0xFF,                       # LDA #<buf
        0xA2, (buf >> 8) & 0xFF,                # LDX #>buf
        0x20, L["net_udp_send"] & 0xFF,         # JSR net_udp_send
        (L["net_udp_send"] >> 8) & 0xFF,
        0x60]))                                 # RTS
    regs = jsr(tr, SEND_STUB, timeout=20.0)
    return regs["FL"] & 1


def warm_arp_cache(tr, L, rng, tag: str) -> tuple[bool, int]:
    """Resolve the peer's next hop BEFORE the handshake. (ok, attempts).

    ip65 does not queue a datagram whose next-hop MAC it lacks: it emits
    the ARP request and returns C=1 (ip65/ip.s). For an off-subnet peer —
    every real-world peer — the first send after net_init therefore always
    fails, and session_initiate treats that as a fatal handshake failure.
    Driven from the menu the cost is brutal, because the whole Type-1 is
    computed BEFORE the send is attempted: measured 250 s of X25519 thrown
    away, then another 444 s for the attempt that works.

    So resolve the next hop first, with a throwaway 1-byte datagram sent
    through net_udp_send directly. WireGuard drops a malformed packet, so
    the peer is unaffected, and the ARP reply lands in ip65's cache via
    net_poll exactly as main_loop would deliver it.

    This is a TEST-SIDE workaround for an application defect, not a fix:
    the shipped app still fails its first handshake against any off-subnet
    peer. Recorded so the suite measures the crypto, not the cold cache.
    """
    park_outside_net(tr, L)
    for attempt in range(1, 4):
        c = _jsr_send(tr, L, WARP_ENDPOINT_IP,
                      bytes([WARP_ENDPOINT_PORT >> 8,
                             WARP_ENDPOINT_PORT & 0xFF]),
                      bytes([rng.randrange(256)]))
        for _ in range(60):
            jsr(tr, L["net_poll"], timeout=10.0)
        if c == 0:
            log(f"  [{tag}] next hop resolved after {attempt} probe(s) "
                "— the handshake now pays for crypto only")
            return True, attempt
        log(f"  [{tag}] probe {attempt}: net_udp_send C=1 (ARP miss); "
            "ip65 has now sent the request, retrying")
        time.sleep(1.0)
    return False, 3


def prove_red_port(vice, L, iface: str, rng) -> int:
    """Alarm proof for type1_dport_ok, without paying for the crypto.

    The pre-#118 adapter copied the big-endian ABI port cell straight into
    ip65's little-endian one. That exact wire symptom is reproduced here by
    staging net_udp_dest_port byte-swapped, so the assertion the suite makes
    is shown to FIRE rather than merely to pass on a fixed tree.

    Note honestly what this is: a deliberate one-field corruption that
    reproduces the unfixed tree's OUTPUT, not a build of the unfixed tree.
    """
    tr = vice.tr
    boot_and_net_init(tr, L, dhcp_timeout=DHCP_BUDGET_S)
    ip = c64_ip(tr, L)
    log(f"  C64 at {ip}, gateway {default_gateway(iface)}")
    tr.resume()
    port_be = bytes([WARP_ENDPOINT_PORT >> 8, WARP_ENDPOINT_PORT & 0xFF])
    swapped = ((WARP_ENDPOINT_PORT & 0xFF) << 8) | (WARP_ENDPOINT_PORT >> 8)

    with Tap(f"(udp and host {ip}) or (arp and host {ip})", iface=iface) as tap:
        for label, pb in (("correct (big-endian, as net_abi.inc says)", port_be),
                          ("byte-swapped (the pre-#118 symptom)", port_be[::-1])):
            log(f"\n  --- staging {label} ---")
            # The first send to an off-subnet peer always fails on a cold
            # ARP cache (ip65 emits the request and returns C=1), so send
            # until it takes, exactly as the app must.
            park_outside_net(tr, L)
            for attempt in (1, 2, 3):
                payload = bytes(rng.randrange(256) for _ in range(TYPE1_LEN))
                c = _jsr_send(tr, L, WARP_ENDPOINT_IP, pb, payload)
                log(f"      attempt {attempt}: carry={c} "
                    f"({'refused' if c else 'sent'})")
                for _ in range(40):
                    jsr(tr, L["net_poll"], timeout=10.0)
                if c == 0:
                    break
            time.sleep(1.5)

        sent = [r for r in tap.udp(src=ip, dst=WARP_ENDPOINT_IP)
                if r.length == TYPE1_LEN]
        log(f"\n  {TYPE1_LEN}-byte datagrams at the tap: "
            + ", ".join(f"dport={r.dport}" for r in sent))
        good = [r for r in sent if r.dport == WARP_ENDPOINT_PORT]
        bad = [r for r in sent if r.dport == swapped]
        check(bool(good), f"correct staging puts it on port "
              f"{WARP_ENDPOINT_PORT} (type1_dport_ok would be GREEN)")
        check(bool(bad), f"byte-swapped staging puts it on port {swapped} "
              f"(type1_dport_ok would be RED — the alarm fires)")
        log(f"\n=> type1_dport_ok distinguishes the two: "
            f"{WARP_ENDPOINT_PORT} vs {swapped}. It is not a check that "
            "passes regardless.")
    return 0 if (good and bad) else 1


def boot_lease_handshake(vice, L, priv, pub, peer_pub, tunnel_ip, iface,
                         lan_prefix: str, rng, *, swap_port: bool = False,
                         tag: str = "A") -> tuple[object, str, Tap, bool]:
    """boot -> 'I' -> real lease -> stage WARP -> 'H' -> ACTIVE.

    Returns (ResumingTransport, c64 ip, the tap covering the handshake,
    whether ACTIVE was reached). The tap is left OPEN for the caller.
    """
    tr = vice.tr
    if not wait_boot_ready(tr, L):
        check(False, f"[{tag}] boot_ready set", screen_text(tr))
        raise SystemExit(1)
    check(True, f"[{tag}] boot_ready set")

    log(f"=== [{tag}] Network init ('I' -> ip65 DHCP on the REAL LAN) ===")
    if not check(press_key(tr, "I"), f"[{tag}] 'I' consumed"):
        raise SystemExit(1)
    outcome, text = wait_net_initialized(tr, L, DHCP_BUDGET_S)
    if not check(outcome == "ok",
                 f"[{tag}] net_initialized=1 within {DHCP_BUDGET_S:.0f}s "
                 f"(outcome: {outcome})", text):
        raise SystemExit(1)

    ip = c64_ip(tr, L)
    log(f"  C64 lease: {ip}")
    check(ip.startswith(lan_prefix),
          f"[{tag}] lease {ip} is on the real LAN {lan_prefix}0/24",
          f"host {iface} is {iface_status(iface).get('inet')}, "
          f"gateway {default_gateway(iface)}")
    check(not ip.startswith(RIG_SUBNET_PREFIX),
          f"[{tag}] lease is NOT from the feth rig ({RIG_SUBNET_PREFIX}0/24) "
          "— VICE really is bridged onto the physical segment", ip)

    stage_warp_config(tr, L, priv, pub, peer_pub, tunnel_ip,
                      swap_port=swap_port)
    tr.resume()

    # Warp ON only now: ip65's DHCP retry budget is CPU-counted and warp
    # compresses it below a real OFFER's latency, but the X25519 that
    # follows is pure 6502 and needs every cycle it can get.
    tr.set_warp(True)
    check(tr.get_warp(), f"[{tag}] VICE warp enabled after network init")
    rt = ResumingTransport(tr)

    log(f"=== [{tag}] Resolving the peer's next hop before 'H' ===")
    warmed, probes = warm_arp_cache(vice.tr, L, rng, tag)
    check(warmed, f"[{tag}] ip65 resolved the next hop for "
          f"{WARP_ENDPOINT_IP} in {probes} probe(s)",
          "ip65 returns C=1 on a cold ARP cache; without this the FIRST "
          "'H' always fails after computing the whole Type-1.")

    log(f"=== [{tag}] Handshake with Cloudflare WARP "
        f"({WARP_ENDPOINT_IP}:{WARP_ENDPOINT_PORT}) ===")
    # ARP is in the filter on purpose: ip65's fail-fast next-hop resolution
    # (see press_h_until_sent) is only visible as an ARP request for the
    # gateway, and without it a failed first initiation looks like silence.
    tap = Tap(f"(udp and host {ip}) or (arp and host {ip})", iface=iface)
    _OPEN_TAPS.append(tap)      # BEFORE __enter__: an interrupt in it too
    tap.__enter__()
    t0 = time.monotonic()
    left, attempts, notes = press_h_until_sent(rt, vice.tr, L, tag)
    check(left, f"[{tag}] wg_state left IDLE (Type-1 built and sent) "
          f"after {attempts} initiation attempt(s)",
          "\n".join(notes) + "\n" + screen_text(vice.tr))
    check(attempts <= SEND_ATTEMPTS,
          f"[{tag}] the ARP-primed retry converged within "
          f"{SEND_ATTEMPTS} attempts", "\n".join(notes))
    gw = default_gateway(iface)
    arp_rows = [r for r in tap.raw if "ARP" in r]
    log(f"  [{tag}] ARP at the tap ({len(arp_rows)} rows), next hop {gw}:")
    for r in arp_rows[:6]:
        log(f"      {r}")

    # The wire is the only witness to WHERE the Type-1 went. #118: the
    # ip65 backend copied the big-endian ABI port cell raw into ip65's
    # little-endian one, so 2408 left as 26633 and Cloudflare never saw a
    # packet. Nothing else in this suite can tell that apart from "the
    # peer ignored us".
    time.sleep(3.0)
    t1 = [r for r in tap.udp(ip, WARP_ENDPOINT_IP) if r.length == TYPE1_LEN]
    check(bool(t1), f"[{tag}] a {TYPE1_LEN}-byte Type-1 left for "
          f"{WARP_ENDPOINT_IP} on the wire",
          f"all C64->WARP datagrams: {tap.udp(ip, WARP_ENDPOINT_IP)}\n"
          f"all C64 datagrams: {tap.udp(src=ip)}")
    check(bool(t1) and t1[0].dport == WARP_ENDPOINT_PORT,
          f"[{tag}] type1_dport_ok: Type-1 addressed to port "
          f"{WARP_ENDPOINT_PORT}",
          f"wire dport = {t1[0].dport if t1 else None} "
          f"(pre-#118 byte swap would read "
          f"{((WARP_ENDPOINT_PORT & 0xFF) << 8) | (WARP_ENDPOINT_PORT >> 8)})")
    local = int.from_bytes(rt.read_memory(L["wg_local_port"], 2), "little")
    check(bool(t1) and t1[0].sport == local,
          f"[{tag}] Type-1 left FROM the configured local port {local}",
          f"wire sport = {t1[0].sport if t1 else None}, "
          f"wg_local_port = {local}")

    active = ki.wait_for_state(rt, L["wg_state"], SESSION_ACTIVE, HS_BUDGET_S,
                               poll=1.0)
    secs = time.monotonic() - t0
    check(active, f"[{tag}] session ACTIVE against Cloudflare WARP "
          f"({secs:.0f}s under VICE warp)", screen_text(vice.tr))
    if not active:
        for line in tap.raw[-15:]:
            log(f"      tap: {line}")
    log(f"  handshake wall time: {secs:.1f}s")
    return rt, ip, tap, active


def hs_timestamp_gt(new: bytes, old: bytes) -> bool:
    """Strictly greater as ONE 96-bit big-endian integer.

    hs_timestamp is TAI64N: 8 big-endian seconds bytes then 4 big-endian
    nanosecond bytes, so the whole 12 bytes read as one big-endian integer
    orders exactly as TAI64N does. Equal stamps compare False.
    """
    if len(new) != 12 or len(old) != 12:
        raise ValueError(f"hs_timestamp must be 12 bytes, got "
                         f"{len(new)} / {len(old)}")
    return int.from_bytes(new, "big") > int.from_bytes(old, "big")


# ============================================================================
# main
# ============================================================================

def main() -> int:
    global VERBOSE, WARP_ENDPOINT_PORT
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iface", default=BRIDGED_IFACE,
                    help="LAN interface VICE's pcap driver binds to (default: "
                         "$VICE_BRIDGED_IFACE, else the port carrying "
                         "BRIDGED_NIC_MAC)")
    ap.add_argument("--vice-bin", default=os.environ.get(
        "VICE_ETHERNET_BIN", DEFAULT_VICE_BIN))
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--stages", default="ABCD",
                    help="which stages to run, e.g. AB or ABD")
    ap.add_argument("--rekey", type=int, default=2,
                    help="Stage D: number of rekeys (0 skips)")
    ap.add_argument("--warp-profile", default=DEFAULT_WARP_PROFILE,
                    help="use this wgcf profile instead of registering a "
                         "fresh WARP device (default: $WARP_PROFILE, else "
                         "register)")
    ap.add_argument("--warp-port", type=warp_port_arg,
                    default=warp_port_arg(os.environ["WARP_ENDPOINT_PORT"])
                    if os.environ.get("WARP_ENDPOINT_PORT") else None,
                    help="fixed WARP endpoint port (default: drawn per run "
                         f"from {list(WARP_ENDPOINT_PORTS)} by the seed)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the registration/exit-code unit cases and exit")
    # `is None`, not `or`: --seed 0 / TEST_SEED=0 is a seed, not "random".
    ap.add_argument("--seed", type=int,
                    default=(int(os.environ["TEST_SEED"])
                             if os.environ.get("TEST_SEED", "").strip()
                             else None))
    ap.add_argument("--prove-red", choices=("port", "mtu"), default=None,
                    help="deliberately break one thing to show the alarm")
    ap.add_argument("--measure-dns", action="store_true",
                    help="print host-side DNS reply sizes and exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose
    stages = args.stages.upper()
    if args.self_test:
        return run_self_test()

    # Stage D rekeys the session Stage A established, and lives inside the
    # same VICE instance, so "--stages CD" would silently run nothing for D
    # -- a no-op that reports success. Refuse instead of no-opping.
    if "D" in stages and args.rekey > 0 and not ("A" in stages or "B" in stages):
        raise SystemExit(
            "--stages %s: D rekeys the session A establishes and shares its "
            "VICE, so it cannot run without A. Use --stages ACD (A costs one "
            "handshake, about 8 minutes on this rig)." % stages)

    seed = args.seed if args.seed is not None else random.randint(1, 2**31 - 1)
    rng = random.Random(seed)
    log("test_warp_ip65_vice.py — ip65 vs Cloudflare WARP over BRIDGED VICE")
    log(f"Random seed: {seed} (reproduce with --seed {seed})")
    WARP_ENDPOINT_PORT = choose_endpoint_port(seed, args.warp_port)
    if args.warp_port is not None and args.warp_port not in WARP_ENDPOINT_PORTS:
        log(f"WARNING: --warp-port {args.warp_port} is not one of WARP's "
            f"advertised ports {list(WARP_ENDPOINT_PORTS)}; a silent run "
            "may mean nothing listens there")
    log(f"WARP endpoint {WARP_ENDPOINT_IP}:{WARP_ENDPOINT_PORT} "
        + ("(--warp-port / $WARP_ENDPOINT_PORT override)"
           if args.warp_port is not None else
           f"(drawn from {list(WARP_ENDPOINT_PORTS)} by the seed)"))

    if args.prove_red == "mtu":
        # RED PROOF, no VICE needed: link the SAME sources at MTU 860 and
        # show the structural pre-check refusing the build. WG_MTU1440=0 is
        # SPELLED OUT because the knob defaults to 1 under BACKEND=ip65
        # since v1.2.0 — omitting it builds the 1440 PRG and this proof
        # would report "GREEN (UNEXPECTED)" while proving nothing.
        log("=== --prove-red mtu: linking BACKEND=ip65 REU=0 WG_MTU1440=0 "
            "and re-running the pre-check ===")
        build_ip65(["REU=0", "WG_MTU1440=0",
                    f"BUILD_DIR={os.path.basename(BUILD_RED)}"])
        Lr = load_labels(BUILD_RED)
        fingerprint("red (WG_MTU1440=0)", os.path.join(BUILD_RED,
                                                       "wireguard.prg"), Lr)
        ok = check_mtu_admits(Lr, 1279)
        log(f"\n=> the mtu_admits_replies check is "
            f"{'GREEN (UNEXPECTED)' if ok else 'RED, as it must be'} "
            "on a tree built with WG_MTU1440=0.")
        return 1 if ok else 0

    if args.measure_dns:
        for name, qtype, band in DNS_QUERIES:
            n, tc = measure_dns_host(name, qtype)
            log(f"  {name:20s} qtype={qtype}  host reply {n} B  TC={int(tc)} "
                f"({band})")
        return 0

    # --- Preflight ------------------------------------------------------
    if args.iface is None:
        args.iface, why = resolve_bridged_iface()
        if why:
            log(f"SKIP: bridged ethernet rig not ready: {why}")
            return SKIP_EXIT
    log(f"=== Bridged rig preflight on {args.iface} ===")
    log("  " + describe_bridged(args.iface))
    skip_if_bridged_rig_down(args.iface, args.vice_bin)
    check(True, f"bridged rig ready on {args.iface}")
    bad = selftest_classifier()
    check(not bad, "tcpdump classifier self-test (the fragment arm alarms)",
          "\n".join(bad))
    # The "dnsmasq is not serving the bridged interface" check answers with
    # an empty list when it passes, which is also what a BROKEN probe
    # answers — so prove the probe can see a live dnsmasq before believing
    # its silence. (It could not, until 2026-09-03: pgrep -af is Linux.)
    bad = selftest_dnsmasq_probe_bridged()
    check(not bad, "dnsmasq probe self-test (its empty answer is meaningful; "
          "a decoy when no dnsmasq runs)", "\n".join(bad))
    # Same coincidence class: "no other VICE is on this NIC" is an empty
    # result, and a blind probe returns empty too. Prove it can see one.
    bad = selftest_conflict_probe(args.iface)
    check(not bad, "conflict probe self-test (it can see a decoy and names "
          "the worktree that owns it)", "\n".join(bad))
    check(args.iface not in dnsmasq_interfaces(),
          f"the rig's dnsmasq is NOT serving {args.iface} "
          f"(it is bound to {dnsmasq_interfaces()})")
    host_ip = iface_status(args.iface)["inet"]
    lan_prefix = host_ip.rsplit(".", 1)[0] + "."
    check(not lan_prefix.startswith(RIG_SUBNET_PREFIX),
          f"the bridged segment {lan_prefix}0/24 is not the feth rig's "
          f"{RIG_SUBNET_PREFIX}0/24", host_ip)

    # A failed bridged preflight stops HERE: registering a Cloudflare
    # account for a run that cannot use it costs an account for nothing.
    pre_failed = [label for ok, label in results if not ok]
    if pre_failed:
        log(f"FAIL: bridged preflight failed, not registering a WARP device: "
            f"{pre_failed}")
        return 1
    # The WARP identity: BEFORE any build or VICE launch, so a missing one
    # costs nothing. Only THIS step's failures are preconditions (77).
    if not args.warp_profile:
        swept = sweep_stale_identity_dirs()
        if swept:
            log(f"  swept {swept} stale identity dir(s) a killed run left")
    try:
        priv, tunnel_ip, peer_pub_b64, source = obtain_identity(
            args.warp_profile)
    except WarpPreconditionError as e:
        log(f"SKIP: no WARP identity: {e}")
        return SKIP_EXIT
    log(f"  WARP identity: {source}")
    pub = derive_pubkey(priv)
    fp = pubkey_fingerprint(pub)
    log(f"  our WARP public key fingerprint sha256:{fp} (seed {seed})")
    if source.startswith("fresh"):
        verdict, n = record_fingerprint(fp)
        if verdict == "not compared":
            log("  freshness NOT compared: no earlier fingerprints recorded "
                f"({RECENT_FP_PATH})")
        else:
            check(verdict == "new", f"the fresh registration's key is not one "
                  f"of the {n} most recent runs'", f"sha256:{fp} repeats")
    peer_pub = base64.b64decode(peer_pub_b64)
    check(peer_pub_b64 == WARP_PEER_PUB_B64,
          f"profile peer public key is Cloudflare's ({WARP_PEER_PUB_B64})",
          f"profile says {peer_pub_b64}")
    check(tunnel_ip == TUNNEL_IP, f"profile tunnel address is {TUNNEL_IP}",
          f"profile says {tunnel_ip}")
    log(f"  our WARP public key {base64.b64encode(pub).decode()[:12]}… "
        "(private key not logged)")

    if args.prove_red == "port":
        # Cheap alarm proof: reach net_udp_send directly instead of paying
        # a 301 s Type-1 first. Needs the rig, so it runs after preflight.
        log("\n=== --prove-red port: does type1_dport_ok actually fire? ===")
        L = load_labels(BUILD_A)
        assert_iface_free(args.iface)
        vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                       reu=False)
        vice.__enter__()
        try:
            assert_vice_bound_to(vice.proc, args.iface)
            rc = prove_red_port(vice, L, args.iface, rng)
        finally:
            vice.__exit__(None, None, None)
        passed = sum(1 for ok, _ in results if ok)
        log(f"\nResults: {passed}/{len(results)} passed")
        return rc

    # --- Host-side DNS baseline, measured BEFORE the C64 is asked -------
    dns_host: dict[str, tuple[int, bool]] = {}
    if "C" in stages:
        log("=== Host-side DNS baseline (this host's path, i.e. through the "
            "host's own WARP) ===")
        for name, qtype, band in DNS_QUERIES:
            n, tc = measure_dns_host(name, qtype)
            dns_host[name] = (n, tc)
            log(f"  {name:20s} {n:5d} B  TC={int(tc)}   ({band})")
        need = max((n for n, _ in dns_host.values()), default=0)
        check(need > 0, "host DNS baseline measured", str(dns_host))

    vices: list[EthVice] = []
    timings: list[tuple[str, float]] = []
    t_start = time.monotonic()
    try:
        # ================= Stage A / B =================
        if "A" in stages or "B" in stages:
            log("\n=== Stage A: build (BACKEND=ip65 REU=0 WG_MTU1440=1) ===")
            build_ip65(["REU=0", "WG_MTU1440=1"])
            assert_ip65_build()
            L = load_labels(BUILD_A)
            fingerprint("Stage A/B", os.path.join(BUILD_A, "wireguard.prg"), L)
            check_mtu_admits(L, 1279)

            assert_iface_free(args.iface)
            vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                           reu=False)
            vice.__enter__()
            vices.append(vice)
            argv = assert_vice_bound_to(vice.proc, args.iface)
            check(True, f"VICE launched with pcap bound to {args.iface}",
                  argv)

            t0 = time.monotonic()
            rt, ip, tap, active = boot_lease_handshake(
                vice, L, priv, pub, peer_pub, tunnel_ip, args.iface,
                lan_prefix, rng, tag="A")
            timings.append(("Stage A: boot+DHCP+handshake",
                            time.monotonic() - t0))

            # ---------------- Stage B ----------------
            if "B" in stages and active:
                log("\n=== Stage B: ping 1.1.1.1 through the tunnel ('P') ===")
                n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                if check(ki.press_key(rt, "P", timeout=20.0), "[B] 'P' consumed"):
                    deadline = time.monotonic() + PING_BUDGET_S
                    seen = False
                    while time.monotonic() < deadline:
                        if "PING REPLY OK" in screen_text(vice.tr):
                            seen = True
                            break
                        vice.tr.resume()
                        time.sleep(0.5)
                    check(seen, "[B] PING REPLY OK from 1.1.1.1 through the "
                          "WireGuard tunnel", screen_text(vice.tr)[-400:])
                    n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                    check(n_after > n_before,
                          f"[B] the ping put datagram(s) on the wire "
                          f"({n_before} -> {n_after} C64->WARP)")

                log("\n=== Stage B: chat message ===")
                suffix = "".join(rng.choice(string.ascii_uppercase +
                                            string.digits) for _ in range(12))
                msg = f"{suffix} WGC64"          # randomised body, fixed marker
                before = int.from_bytes(
                    rt.read_memory(L["tp_send_counter"], 2), "little")
                n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                sent = ki.send_message_dma(rt, msg, L, timeout=20.0)
                time.sleep(2.0)
                after = int.from_bytes(
                    rt.read_memory(L["tp_send_counter"], 2), "little")
                n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                check(sent, f"[B] chat message staged and sent ({msg!r})")
                check(after > before,
                      f"[B] tp_send_counter advanced {before} -> {after} "
                      "(no send error)")
                check(n_after > n_before,
                      f"[B] the message left as {n_after - n_before} "
                      "datagram(s) on the wire — one send, not a torn one")
                txt = screen_text(vice.tr)
                check("SEND FAILED" not in txt and "ERROR" not in txt,
                      "[B] no send error on screen", txt[-400:])
                check(tap.fragments() == 0,
                      f"[B] no IP fragments at the tap ({tap.fragments()})",
                      "\n".join(tap.frags[-5:]))

            # ---------------- Stage D ----------------
            if "D" in stages and args.rekey > 0 and active:
                log(f"\n=== Stage D: {args.rekey} rekeys (issue #87, "
                    "production peer) ===")
                ts_prev = bytes(rt.read_memory(L["hs_timestamp"], 12))
                log(f"  hs_timestamp[0] {ts_prev.hex()}")
                for i in range(1, args.rekey + 1):
                    # Re-resolve the next hop first. ki.rekey presses H
                    # once and has no retry, and ip65's ARP cache does age
                    # out -- a rekey that lands on a cold entry fails the
                    # send after computing the whole Type-1, so the flake
                    # would cost ~460 s to even observe. A few seconds here
                    # removes that class entirely.
                    warmed, probes = warm_arp_cache(vice.tr, L, rng,
                                                    f"D{i}")
                    check(warmed, f"[D] rekey {i}: next hop resolved in "
                          f"{probes} probe(s) before pressing H")
                    t0 = time.monotonic()
                    ok = ki.rekey(rt, L["wg_state"], SESSION_ACTIVE,
                                  timeout=HS_BUDGET_S)
                    secs = time.monotonic() - t0
                    timings.append((f"Stage D: rekey {i}", secs))
                    check(ok, f"[D] rekey {i}: left ACTIVE and returned to "
                          f"ACTIVE ({secs:.0f}s)", screen_text(vice.tr))
                    ts_new = bytes(rt.read_memory(L["hs_timestamp"], 12))
                    check(hs_timestamp_gt(ts_new, ts_prev),
                          f"[D] rekey {i}: hs_timestamp strictly increased "
                          "as a 96-bit big-endian integer",
                          f"prev {ts_prev.hex()}\nnew  {ts_new.hex()}")
                    log(f"  hs_timestamp[{i}] {ts_new.hex()}")
                    ts_prev = ts_new
                    if not ok:
                        break

            log(f"\n  Stage A/B/D wire totals: "
                f"{len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))} C64->WARP, "
                f"{len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))} WARP->C64, "
                f"{tap.fragments()} fragment rows")
            tap.__exit__(None, None, None)
            vice.tr.set_warp(False)
            vice.__exit__(None, None, None)
            vices.remove(vice)

        # ================= Stage C =================
        if "C" in stages:
            log("\n=== Stage C: rebuild MSG_PORT=53 BUILD_DIR=build_msgport53 ===")
            build_ip65(["REU=0", "WG_MTU1440=1", "MSG_PORT=53",
                        f"BUILD_DIR={os.path.basename(BUILD_C)}"])
            LC = load_labels(BUILD_C)
            prg_c = os.path.join(BUILD_C, "wireguard.prg")
            fingerprint("Stage C", prg_c, LC)
            need = max([n for n, _ in dns_host.values() if n > 0] or [1279])
            check_mtu_admits(LC, max(need, 1279))

            assert_iface_free(args.iface)
            vice = EthVice(args.vice_bin, port=args.port, iface=args.iface,
                           reu=False, prg_path=prg_c)
            vice.__enter__()
            vices.append(vice)
            assert_vice_bound_to(vice.proc, args.iface)
            t0 = time.monotonic()
            rt, ip, tap, active = boot_lease_handshake(
                vice, LC, priv, pub, peer_pub, tunnel_ip, args.iface,
                lan_prefix, rng, tag="C")
            timings.append(("Stage C: boot+DHCP+handshake",
                            time.monotonic() - t0))

            dns_results: list[dict] = []
            if active:
                # Our receiver index: an INBOUND transport header carries it
                # at [4:8]; the C64's own outbound one carries the peer's.
                our_idx = bytes(rt.read_memory(LC["hs_sender_idx"], 4))
                for name, qtype, band in DNS_QUERIES:
                    log(f"\n--- DNS {name} ({band}) ---")
                    # ONE snapshot of the inbound packet, guarded, re-queried
                    # if a keepalive reused the buffer first (see
                    # snapshot_inbound). recv_len 0 after the budget is
                    # still a FAIL, exactly as before.
                    reply = None
                    for attempt in range(1, DNS_REUSE_RETRIES + 1):
                        txn = rng.randint(0, 0xFFFF)
                        # Advertise the largest reply this build can actually
                        # hold, derived from the labels. A hardcoded 1400 would
                        # make OUR OWN EDNS advertisement the binding limit and
                        # leave the interesting question unanswerable: a TC=1
                        # stub would then be indistinguishable between "1.1.1.1
                        # caps its UDP replies by policy" and "we asked for no
                        # more than 1400". Advertising MSG_TEXT_MAX means
                        # anything the resolver is willing to send fits by
                        # construction, so a reply in the 1280..MSG_TEXT_MAX
                        # band would DISPROVE a ~1280 policy cap, and its
                        # absence is evidence for one.
                        ednsbuf = ki.input_max_from_labels(LC)
                        question, wire = build_dns_query(name, qtype, txn,
                                                         bufsize=ednsbuf)
                        host_len, host_tc = dns_host.get(name, (-1, False))
                        log(f"  txn_id={txn} query wire {len(wire)} B; "
                            f"EDNS bufsize advertised {ednsbuf}; host "
                            f"baseline {host_len} B TC={int(host_tc)}")
                        n_before = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                        # Baseline the REPLY direction too. Without this the
                        # per-query reply count is cumulative over the tap's
                        # whole lifetime, so the second query inherits the
                        # first one's replies and the reported number is
                        # quietly wrong (observed: github.com reported "3
                        # replies" for a single exchange). No assertion
                        # depended on it, but the figure goes in the report.
                        r_before = len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))
                        rt.write_memory(LC["msg_recv_len"], bytes(2))
                        rt.write_memory(LC["tp_payload_len"], bytes(2))
                        staged = stage_raw_dma(rt, wire, LC, timeout=20.0)
                        check(staged, f"[C] {name}: query staged and sent")

                        deadline = time.monotonic() + DNS_BUDGET_S
                        recv_len = 0
                        while time.monotonic() < deadline:
                            recv_len = int.from_bytes(
                                rt.read_memory(LC["msg_recv_len"], 2), "little")
                            if recv_len:
                                break
                            time.sleep(0.25)
                        n_after = len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))
                        if not check(recv_len > 0,
                                     f"[C] {name}: a reply reached the C64 "
                                     f"(msg_recv_len={recv_len})",
                                     screen_text(vice.tr)[-400:]):
                            break
                        reply, why = snapshot_inbound(rt, LC, recv_len, our_idx)
                        if reply is not None:
                            break
                        log(f"  [C] {name}: buffer reused by keepalive before "
                            f"read, attempt {attempt} ({why}) — re-querying "
                            "with a fresh transaction id")
                    if recv_len == 0:
                        continue
                    if reply is None:
                        inconclusive.append(
                            f"[C] {name}: every one of {DNS_REUSE_RETRIES} "
                            "replies was overwritten by an outbound packet "
                            "before it could be read")
                        continue
                    payload = reply[44:44 + min(recv_len, 1450)]
                    # A DNS header is 12 bytes. Without this, a runt reply
                    # would crash the run on payload[6] rather than fail
                    # the assertion it was meant to fail.
                    if not check(len(payload) >= 12,
                                 f"[C] {name}: reply is at least a DNS "
                                 f"header ({len(payload)} B)",
                                 payload.hex()):
                        continue
                    ip_hdr = reply[16:36]
                    udp_hdr = reply[36:44]
                    src_ip = ".".join(str(b) for b in ip_hdr[12:16])
                    dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
                    sport = (udp_hdr[0] << 8) | udp_hdr[1]
                    dport = (udp_hdr[2] << 8) | udp_hdr[3]
                    rtxn = (payload[0] << 8) | payload[1]
                    qr = bool(payload[2] & 0x80)
                    tc = bool(payload[2] & 0x02)
                    ancount = (payload[6] << 8) | payload[7]
                    echo_ok = payload[12:12 + len(question)] == question

                    check(src_ip == PING_TARGET_IP and sport == 53,
                          f"[C] {name}: inner IPv4 source is "
                          f"{PING_TARGET_IP}:53", f"got {src_ip}:{sport}")
                    check(dst_ip == TUNNEL_IP and dport == 53,
                          f"[C] {name}: inner IPv4 destination is "
                          f"{TUNNEL_IP}:53", f"got {dst_ip}:{dport}")
                    check(rtxn == txn,
                          f"[C] {name}: DNS transaction id matches ({txn})",
                          f"reply carried {rtxn}")
                    check(qr, f"[C] {name}: QR bit set (this is a response)")
                    check(echo_ok,
                          f"[C] {name}: the question section is echoed back",
                          f"sent {question.hex()}\ngot  "
                          f"{payload[12:12 + len(question)].hex()}")
                    # Length, cross-checked against an INDEPENDENT source:
                    # the inner UDP header's own length field, which the C64
                    # did not compute (Cloudflare's peer did) and which
                    # msg_recv_len is derived from separately. `recv_len > 0`
                    # was already asserted above, so re-testing it here
                    # would be a check that cannot fail.
                    udp_len = (udp_hdr[4] << 8) | udp_hdr[5]
                    check(udp_len - 8 == recv_len,
                          f"[C] {name}: reply length {recv_len} B agrees with "
                          f"the inner UDP header ({udp_len} - 8)",
                          f"msg_recv_len={recv_len}, inner UDP length="
                          f"{udp_len}; host baseline {host_len} B")
                    check(ancount >= 0,
                          f"[C] {name}: {recv_len} B received "
                          f"(host saw {host_len} B), TC={int(tc)}, "
                          f"ANCOUNT={ancount}")
                    # Datagram counts at the tap, per the standing rule: a
                    # torn send is two. The reply direction matters most
                    # here -- a >1280 B inner reply is precisely where the
                    # outer datagram would fragment if anything did.
                    n_reply = len(tap.udp(src=WARP_ENDPOINT_IP,
                                          dst=ip)) - r_before
                    check(n_after > n_before,
                          f"[C] {name}: the query left as "
                          f"{n_after - n_before} datagram(s) C64->WARP")
                    check(tap.fragments() == 0,
                          f"[C] {name}: no IP fragments at the tap "
                          f"({tap.fragments()})",
                          "\n".join(tap.frags[-5:]))
                    q_rec = {"name": name, "recv_len": recv_len,
                             "host_len": host_len, "tc": tc,
                             "ancount": ancount, "ednsbuf": ednsbuf,
                             "sent": n_after - n_before, "replies": n_reply}
                    dns_results.append(q_rec)
                    log(f"  RESULT {name}: C64 received {recv_len} B "
                        f"(TC={int(tc)}, ANCOUNT={ancount}); host baseline "
                        f"{host_len} B (TC={int(host_tc)}); "
                        f"{n_after - n_before} C64->WARP datagram(s)")
                    if host_len > 0 and recv_len > 1280 >= host_len:
                        log("  *** the C64's direct path carried a reply the "
                            "host's WARP path could not ***")

            if dns_results:
                biggest = max(r["recv_len"] for r in dns_results)
                ceiling = max(r["ednsbuf"] for r in dns_results)
                log("\n  === Stage C verdict on the >1280 B question ===")
                for r in dns_results:
                    log(f"    {r['name']:16s} C64 {r['recv_len']:5d} B "
                        f"TC={int(r['tc'])} ANCOUNT={r['ancount']:3d} | "
                        f"host {r['host_len']:5d} B | advertised "
                        f"{r['ednsbuf']} | {r['sent']} sent, "
                        f"{r['replies']} replies")
                if biggest > 1280:
                    log(f"    => a {biggest} B reply arrived WHOLE on the "
                        "C64's direct path: the ~1280 B ceiling seen on the "
                        "host path is NOT imposed on this path.")
                elif any(r["tc"] for r in dns_results):
                    log(f"    => nothing above 1280 B arrived, and the "
                        f"resolver set TC while we advertised {ceiling} B. "
                        "Our own EDNS buffer was NOT the binding limit, so "
                        "the ceiling is 1.1.1.1's own reply-size policy, "
                        "not an MTU on this path.")
                else:
                    log("    => nothing above 1280 B was requested "
                        "successfully; inconclusive.")

            log(f"\n  Stage C wire totals: "
                f"{len(tap.udp(src=ip, dst=WARP_ENDPOINT_IP))} C64->WARP, "
                f"{len(tap.udp(src=WARP_ENDPOINT_IP, dst=ip))} WARP->C64, "
                f"{tap.fragments()} fragment rows")
            tap.__exit__(None, None, None)
            vice.tr.set_warp(False)
            vice.__exit__(None, None, None)
            vices.remove(vice)
    finally:
        _stop_all(vices)

    log("\n=== Wall time ===")
    for name, secs in timings:
        log(f"  {name:<36s} {secs:8.1f} s")
    passed = sum(1 for ok, _ in results if ok)
    failed = len(results) - passed
    log(f"\nResults: {passed}/{len(results)} passed, {failed} failed "
        f"({time.monotonic() - t_start:.0f}s, seed {seed})")
    for ok, label in results:
        if not ok:
            log(f"  FAILED: {label}")
    for what in inconclusive:
        log(f"  INCONCLUSIVE: {what}")
    return exit_code(results, inconclusive)


# ============================================================================
# --self-test: the registration paths, against a stub wgcf, no network
# ============================================================================

def _stub_wgcf(d: str, body: str) -> str:
    path = os.path.join(d, "wgcf")
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


#: A stub that behaves like wgcf: honours --config/--profile, writes a
#: profile carrying $STUB_PRIV. Fails `generate` when $STUB_FAIL_GENERATE.
_GOOD_STUB = r"""
cfg=""; prof=""; verb=""
while [ $# -gt 0 ]; do
  case "$1" in
    --config) cfg="$2"; shift 2;; --profile) prof="$2"; shift 2;;
    register|generate) verb="$1"; shift;; *) shift;;
  esac
done
[ -n "$STUB_HOME_LOG" ] && echo "$HOME" >> "$STUB_HOME_LOG"
if [ "$verb" = register ]; then
  printf 'device_id = "%s"\naccess_token = "tok-SECRET"' "$STUB_TOKEN" > "$cfg.extra"
  printf 'access_token = "%s"
private_key = "%s"
' "$STUB_TOKEN" "$STUB_PRIV" > "$cfg"
  exit 0
fi
[ -n "$STUB_SLEEP" ] && sleep "$STUB_SLEEP"
[ -n "$STUB_FAIL_GENERATE" ] && { echo "generate: device $STUB_TOKEN rejected (key $STUB_PRIV)" >&2; exit 3; }
printf '[Interface]
PrivateKey = %s
Address = 172.16.0.2/32
[Peer]
PublicKey = %s
'   "$STUB_PRIV" "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" > "$prof"
"""


def run_self_test() -> int:
    """Unit cases for the identity step and its exit codes. No network."""
    import io
    from contextlib import redirect_stdout
    out: list[tuple[bool, str, str]] = []

    def case(ok, name, detail=""):
        out.append((bool(ok), name, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok and detail:
            print(f"        {detail}")

    # 0. The endpoint port: reproducible from the seed, always advertised,
    #    every advertised port reachable, and an override wins.
    seeds = range(1, 2001)
    draws = [choose_endpoint_port(sd) for sd in seeds]
    case(draws == [choose_endpoint_port(sd) for sd in seeds],
         "endpoint-port-is-reproducible-from-the-seed")
    case(set(draws) == set(WARP_ENDPOINT_PORTS),
         "endpoint-port-always-advertised-and-every-port-drawn",
         f"drawn {sorted(set(draws))}")
    case(choose_endpoint_port(7, 4500) == 4500 and choose_endpoint_port(7, 2408) == 2408,
         "endpoint-port-override-wins")

    # 0b. Cleanup stops the taps as well as VICE (an aborted run used to
    #     orphan its tcpdump), and survives one that raises.
    stopped: list[str] = []

    class _Fake:
        def __init__(self, name, boom=False):
            self.name, self.boom = name, boom

        def __exit__(self, *a):
            stopped.append(self.name)
            if self.boom:
                raise RuntimeError("stuck")
    _OPEN_TAPS[:] = [_Fake("tapA", boom=True), _Fake("tapC")]
    buf0 = io.StringIO()
    with redirect_stdout(buf0):
        _stop_all([_Fake("vice")])
    case(stopped == ["vice", "tapA", "tapC"] and not _OPEN_TAPS,
         "cleanup-stops-every-vice-and-every-tap", f"stopped {stopped}")

    # 0c. warm_arp_cache parks the 6510 at main_loop BEFORE its first jsr:
    #     jsr() does not put A/X/Y back, so hijacking net_poll's X-indexed
    #     restore loop writes $0001 and kills the machine (2026-10-22).
    order: list[str] = []

    class _Tr:
        """Halted mid-net_poll ($0AD0) until the park's resume stops it at
        the checkpoint; *stop_at* is where that resume really ends up."""
        def __init__(self, stop_at=0x0870):
            self.pc, self.stop_at, self.cp = 0x0AD0, stop_at, None

        def read_registers(self):
            return {"PC": self.pc}

        def set_checkpoint(self, addr):
            order.append(f"checkpoint {addr:#x}")
            self.cp = addr
            return 7

        def resume(self):
            order.append("resume")

        def wait_for_stopped(self, timeout=None):
            order.append("stopped")
            self.pc = self.stop_at

        def delete_checkpoint(self, n):
            order.append("delete")

    g = globals()
    saved = (g["jsr"], g["_jsr_send"])
    g["jsr"] = lambda tr, addr, **k: order.append(f"jsr {addr:#x}")
    g["_jsr_send"] = lambda *a, **k: (order.append("send"), 0)[1]
    try:
        with redirect_stdout(io.StringIO()):
            warm_arp_cache(_Tr(), {"main_loop": 0x0870, "net_poll": 0x0ACD},
                           random.Random(1), "t")
    finally:
        g["jsr"], g["_jsr_send"] = saved
    first_call = next((i for i, o in enumerate(order)
                       if o == "send" or o.startswith("jsr")), None)
    case(order[:4] == ["checkpoint 0x870", "resume", "stopped", "delete"]
         and first_call == 4,
         "warm-up-parks-at-main-loop-before-any-jsr", f"order {order[:6]}")
    # E3: a park that did not land on main_loop must raise, not carry on.
    try:
        park_outside_net(_Tr(stop_at=0x0D46), {"main_loop": 0x0870})
        case(False, "park-refuses-a-stop-that-is-not-main_loop", "no exception")
    except RuntimeError as e:
        case("$0D46" in str(e), "park-refuses-a-stop-that-is-not-main_loop", str(e))
    # ...and prove_red_port parks before its sends too (E3: that call
    # survived every mutant before). Driven until the first send, then out.
    order.clear()

    class _Stop(Exception):
        pass

    class _Vice:
        tr = _Tr()
    g2 = globals()
    saved2 = {k: g2[k] for k in ("boot_and_net_init", "c64_ip",
                                 "default_gateway", "Tap", "_jsr_send")}

    class _NoTap:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    g2["boot_and_net_init"] = lambda *a, **k: None
    g2["c64_ip"] = lambda *a, **k: "10.0.0.2"
    g2["default_gateway"] = lambda *a, **k: "10.0.0.1"
    g2["Tap"] = _NoTap

    def _send_then_stop(*a, **k):
        order.append("send")
        raise _Stop()
    g2["_jsr_send"] = _send_then_stop
    try:
        with redirect_stdout(io.StringIO()):
            prove_red_port(_Vice(), {"main_loop": 0x0870, "net_poll": 0x0ACD},
                           "en99", random.Random(1))
    except _Stop:
        pass
    finally:
        g2.update(saved2)
    i = order.index("checkpoint 0x870") if "checkpoint 0x870" in order else -1
    case(i >= 0 and order[i:i + 5] == ["checkpoint 0x870", "resume",
                                       "stopped", "delete", "send"],
         "prove-red-port-parks-before-its-first-send", f"order {order[:7]}")

    # 0d. Redaction: every format named in review D1, by the backstop, and a
    #     shapeless literal by the Redactor that learnt it.
    k = os.urandom(32)
    pad = base64.b64encode(k).decode()
    url = base64.urlsafe_b64encode(k).decode()
    tok = base64.b64encode(os.urandom(18)).decode()
    samples = {
        "json": f'{{"token":"{tok}","license":"{tok[:10]}X","id":"{tok[3:]}"}}',
        "yaml": f'access_token: "{tok}"',
        "bearer": f"Authorization: Bearer {tok}",
        "unpadded-key": f"key {pad.rstrip('=')} end",
        "base64url-key": f"key {url} end",
        "toml": f"private_key = '{pad}'",
    }
    for name, text in samples.items():
        scrubbed = scrub(text)
        leaked = [x for x in (tok, tok[:10] + "X", tok[3:], pad.rstrip("="), url)
                  if x in scrubbed]
        case(not leaked, f"redaction-backstop-{name}",
             f"{text!r} -> {scrubbed!r}")
    red = Redactor()
    shapeless = "".join(random.choice("abcdefghjkmnpqrstuvwxyz") for _ in range(20))
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(f'device_id = "{shapeless}"\n')
    try:
        red.learn_file(fh.name)
    finally:
        os.unlink(fh.name)
    case(shapeless not in red(f"device {shapeless} was refused"),
         "redaction-literal-value-learnt-from-the-account-file",
         red(f"device {shapeless} was refused"))
    summ = failure_summary("register", 1,
                           "HTTP/1.1 429 Too Many Requests\n{\"token\":\"x\"}\n"
                           + "debug: " + tok * 3, red)
    case("429" in summ and "exited 1" in summ and tok not in summ
         and "debug" not in summ,
         "failure-summary-is-exit-code-status-and-first-line-only", summ)

    # 0g. E5: a status only next to "HTTP"/"status"; E6: port range, and
    #     --seed 0 / TEST_SEED=0 is seed 0 in both suites, not "random".
    ident = lambda t: t                                     # noqa: E731
    s1 = failure_summary("register", 1, "dial tcp 162.159.192.1:443: i/o timeout", ident)
    s2 = failure_summary("register", 1, "API error: status code 429", ident)
    s3 = failure_summary("register", 1, "HTTP/1.1 503 Service Unavailable", ident)
    case("HTTP" not in s1 and "HTTP 429" in s2 and "HTTP 503" in s3,
         "failure-summary-status-needs-http-or-status-next-to-it",
         f"{s1!r} | {s2!r} | {s3!r}")
    bad_ports = []
    for txt in ("0", "65536", "-1", "abc"):
        try:
            warp_port_arg(txt)
            bad_ports.append(txt)
        except argparse.ArgumentTypeError:
            pass
    case(not bad_ports and warp_port_arg("4500") == 4500
         and warp_port_arg("65535") == 65535 and warp_port_arg("1") == 1,
         "warp-port-must-be-1-to-65535", f"accepted {bad_ports}")
    here = os.path.dirname(os.path.abspath(__file__))
    for suite, needle in (("test_warp_ip65_vice", "Random seed: 0 "),
                          ("test_ip65_arp_first_send_vice", "seed=0 ")):
        for how, argv, env_seed in (("flag", ["--seed", "0"], None),
                                    ("env", [], "0")):
            code = ("import sys; sys.path.insert(0, %r); import %s as T\n"
                    "T.resolve_bridged_iface = lambda *a, **k: (None, 'stop')\n"
                    "for n in ('selftest_classifier', 'selftest_arp', "
                    "'selftest_payload_parser', 'selftest_map_parsers'):\n"
                    "    hasattr(T, n) and setattr(T, n, lambda *a, **k: [])\n"
                    "sys.argv = ['t'] + %r\n"
                    "sys.exit(T.main())\n" % (here, suite, argv))
            env = {k: v for k, v in os.environ.items() if k != "TEST_SEED"}
            if env_seed is not None:
                env["TEST_SEED"] = env_seed
            r = subprocess.run([sys.executable, "-c", code], env=env,
                               capture_output=True, text=True, timeout=60)
            case(needle in r.stdout, f"seed-0-is-seed-0-{suite}-{how}",
                 f"rc={r.returncode} {r.stdout[:200]!r}")

    # 0h. E8: the inbound guard, on the bytes diag captured for the real
    #     namecheap reply, and on the same reply after a keepalive rewrote
    #     tp_packet[0:32] (outbound header + Poly1305 tag); and the exit code.
    good = bytes.fromhex("0400000005547caa00000000000000004500051700004000"
                         "401187c201010101ac100002003500350503d9bb72438180")
    n = 0x0517 - 28
    good += bytes(44 + n - len(good))
    ours = bytes.fromhex("05547caa")
    reused = (b"\x04\x00\x00\x00" + bytes.fromhex("fede6f76") + bytes(8)
              + os.urandom(16) + good[32:])
    case(inbound_guard(good, ours, n) is None,
         "inbound-guard-accepts-the-real-reply")
    why = inbound_guard(reused, ours, n)
    case(why is not None and "not ours" in why,
         "inbound-guard-refuses-a-keepalive-rewritten-buffer", f"{why}")
    case(exit_code([(True, "a")], []) == 0
         and exit_code([(True, "a")], ["x"]) == 78
         and exit_code([(False, "a")], ["x"]) == 1,
         "inconclusive-is-78-never-a-pass-and-a-fail-wins")

    # 0e. Freshness, with the REAL recorder on a temp file: first run not
    #     compared (never a pass), then new, then a repeat is a FAIL.
    with tempfile.TemporaryDirectory() as fd:
        fpp = os.path.join(fd, "sub", "fps")
        v1 = record_fingerprint("aaaa", fpp)
        v2 = record_fingerprint("bbbb", fpp)
        v3 = record_fingerprint("aaaa", fpp)
        for i in range(30):
            record_fingerprint(f"f{i}", fpp)
        kept = open(fpp).read().split()
    case(v1 == ("not compared", 0), "freshness-first-run-is-not-compared", f"{v1}")
    case(v2 == ("new", 1), "freshness-new-key-is-compared", f"{v2}")
    case(v3[0] == "repeat", "freshness-repeat-is-caught", f"{v3}")
    case(len(kept) == RECENT_FP_KEEP and kept[-1] == "f29",
         "freshness-history-is-rolling", f"{len(kept)} kept")
    # The flock: two processes record the SAME fingerprint with their
    # read-check-append windows overlapping (the test hook widens them).
    # Serialised, the second sees the first's and reports a repeat;
    # without the lock both read an empty file and neither does.
    with tempfile.TemporaryDirectory() as fd:
        fpp = os.path.join(fd, "fps")
        code = ("import sys; sys.path.insert(0, %r); "
                "import test_warp_ip65_vice as T; "
                "print(T.record_fingerprint('same', %r)[0])"
                % (os.path.dirname(os.path.abspath(__file__)), fpp))
        env = {**os.environ, "C64WG_FP_TEST_PAUSE": "1.0"}
        kids = [subprocess.Popen([sys.executable, "-c", code], env=env,
                                 stdout=subprocess.PIPE, text=True)
                for _ in range(2)]
        verdicts = sorted(k.communicate(timeout=60)[0].strip() for k in kids)
    case(verdicts == ["not compared", "repeat"],
         "freshness-concurrent-lanes-are-serialised-by-the-lock",
         f"verdicts {verdicts}")

    # 0f. A SIGKILL leaves the identity dir; the next run sweeps it -- only
    #     ours, only c64wg-warp-*, only older than a run can last.
    # Another user's dir is never ours to remove: seen through a uid that
    # is not ours (a real foreign-owned dir would need root to make).
    alien = tempfile.mkdtemp(prefix="c64wg-warp-")
    os.utime(alien, (time.time() - STALE_IDENTITY_DIR_S - 60,) * 2)
    real_getuid = os.getuid
    os.getuid = lambda: real_getuid() + 4242
    try:
        sweep_stale_identity_dirs()
    finally:
        os.getuid = real_getuid
    case(os.path.exists(alien), "sweep-leaves-another-users-dir-alone",
         "a stale dir not owned by this uid was removed")
    shutil.rmtree(alien, ignore_errors=True)
    old = tempfile.mkdtemp(prefix="c64wg-warp-")
    young = tempfile.mkdtemp(prefix="c64wg-warp-")
    other = tempfile.mkdtemp(prefix="c64wg-other-")
    os.utime(old, (time.time() - STALE_IDENTITY_DIR_S - 60,) * 2)
    try:
        sweep_stale_identity_dirs()
        case(not os.path.exists(old) and os.path.exists(young)
             and os.path.exists(other),
             "stale-identity-dirs-swept-and-nothing-else",
             f"old {os.path.exists(old)} young {os.path.exists(young)} "
             f"other {os.path.exists(other)}")
    finally:
        for d in (old, young, other):
            shutil.rmtree(d, ignore_errors=True)

    priv = os.urandom(32)
    priv_b64 = base64.b64encode(priv).decode()
    env_before = dict(os.environ)
    with tempfile.TemporaryDirectory() as bin_d:
        os.environ["STUB_PRIV"] = priv_b64
        # A secret with no recognisable shape: only literal redaction can
        # catch it where wgcf prints it bare.
        token = "".join(random.choice("abcdefghjkmnpqrstuvwxyz23456789")
                        for _ in range(18))
        os.environ["STUB_TOKEN"] = token
        good = _stub_wgcf(bin_d, _GOOD_STUB)

        # 1. wgcf absent: a precondition.
        saved = os.environ.get("PATH", "")
        os.environ["PATH"] = bin_d + "-empty"
        try:
            register_fresh_identity()
            case(False, "wgcf-missing-is-a-precondition", "no exception")
        except WarpPreconditionError as e:
            case("not found" in str(e), "wgcf-missing-is-a-precondition", str(e))
        finally:
            os.environ["PATH"] = saved

        # 2. Cloudflare refuses (429): a precondition, wgcf's text kept,
        #    any key-shaped text cut.
        refuse = _stub_wgcf(tempfile.mkdtemp(dir=bin_d),
                            'echo "429 Too Many Requests $STUB_PRIV" >&2; exit 1\n')
        seen: list[str] = []
        try:
            register_fresh_identity(refuse, on_tempdir=seen.append)
            case(False, "registration-refusal-is-a-precondition", "no exception")
        except WarpPreconditionError as e:
            case("429" in str(e) and priv_b64 not in str(e),
                 "registration-refusal-is-a-precondition-and-scrubbed", str(e))
        case(seen and not os.path.exists(seen[0]),
             "tempdir-removed-after-a-refusal", f"{seen}")

        # 3. The good path: the key comes back, the dir is 0700 and gone
        #    afterwards, and nothing printed carries the key.
        seen.clear()
        modes: list[int] = []

        def note(d):
            seen.append(d)
            modes.append(os.stat(d).st_mode & 0o777)
        home_log = os.path.join(bin_d, "home.log")
        os.environ["STUB_HOME_LOG"] = home_log
        try:
            got = register_fresh_identity(good, on_tempdir=note)
        finally:
            os.environ.pop("STUB_HOME_LOG", None)
        homes = open(home_log).read().split() if os.path.exists(home_log) else []
        case(len(homes) == 2 and set(homes) == {seen[0]},
             "wgcf-runs-with-HOME-in-the-private-dir",
             f"HOME seen {homes}, private dir {seen}")
        case(got[0] == priv and got[1] == "172.16.0.2",
             "fresh-registration-returns-the-generated-key", f"{got[1:]}")
        case(modes == [0o700], "tempdir-is-0700", f"{[oct(m) for m in modes]}")
        case(seen and not os.path.exists(seen[0]),
             "tempdir-removed-after-success", f"{seen}")

        # 4. generate fails after register wrote the account file: the
        #    account secrets and key are wiped with the dir.
        seen.clear()
        os.environ["STUB_FAIL_GENERATE"] = "1"
        try:
            register_fresh_identity(good, on_tempdir=seen.append)
            case(False, "generate-failure-is-a-precondition", "no exception")
        except WarpPreconditionError as e:
            case(priv_b64 not in str(e) and token not in str(e)
                 and "exited 3" in str(e),
                 "generate-failure-is-a-precondition-summarised-and-the-literal-"
                 "token-redacted", str(e))
        finally:
            os.environ.pop("STUB_FAIL_GENERATE", None)
        case(seen and not os.path.exists(seen[0]),
             "tempdir-removed-after-a-mid-way-failure", f"{seen}")

        # 5. SIGTERM mid-registration: the child's finally still wipes.
        #    (Accepted: the stub's own `sleep 20` is the wgcf stand-in's
        #    child and outlives the killed python by up to 20 s, harmlessly.)
        os.environ["STUB_SLEEP"] = "20"
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import signal, sys; sys.path.insert(0, %r); "
             "import test_warp_ip65_vice as T; "
             "signal.signal(signal.SIGTERM, lambda *a: sys.exit(143)); "
             "T.register_fresh_identity(%r, on_tempdir=lambda d: "
             "print(d, flush=True))" % (os.path.dirname(os.path.abspath(__file__)), good)],
            stdout=subprocess.PIPE, text=True)
        tdir = child.stdout.readline().strip()
        time.sleep(1.0)
        child.send_signal(signal.SIGTERM)
        rc = child.wait(timeout=30)
        os.environ.pop("STUB_SLEEP", None)
        case(rc == 143 and tdir and not os.path.exists(tdir),
             "tempdir-removed-on-sigterm", f"rc={rc} dir={tdir!r} "
             f"exists={os.path.exists(tdir) if tdir else None}")

        # 6. Exit codes through main(): a precondition is 77, and a failure
        #    AFTER the identity is in hand is still 1 -- the new 77 path must
        #    not swallow it.
        prof_d = tempfile.mkdtemp(dir=bin_d)
        prof = os.path.join(prof_d, "wgcf-profile.conf")
        with open(prof, "w") as fh:
            fh.write(f"[Interface]\nPrivateKey = {priv_b64}\n"
                     f"Address = 172.16.0.2/32\n")
        driver = (
            "import sys; sys.path.insert(0, %r)\n"
            "import test_warp_ip65_vice as T\n"
            "T.resolve_bridged_iface = lambda: ('en99', None)\n"
            "for n in ('skip_if_bridged_rig_down', 'assert_iface_free'):\n"
            "    setattr(T, n, lambda *a, **k: None)\n"
            "T.describe_bridged = lambda i: i\n"
            "for n in ('selftest_classifier', 'selftest_dnsmasq_probe_bridged',\n"
            "          'selftest_conflict_probe'):\n"
            "    setattr(T, n, lambda *a, **k: [])\n"
            "T.dnsmasq_interfaces = lambda: []\n"
            "T.iface_status = lambda i: {'inet': '10.43.23.99'}\n"
            "T.derive_pubkey = lambda p: bytes(32)\n"
            "T.record_fingerprint = lambda fp, path=None: ('not compared', 0)\n"
            "def boom(*a, **k): raise RuntimeError('simulated post-registration failure')\n"
            "T.build_ip65 = boom\n"
            "_real_stop = T._stop_all\n"
            "def _rec(v): print('STOP_ALL_CALLED', flush=True); _real_stop(v)\n"
            "T._stop_all = _rec\n"
            "sys.argv = ['t', '--stages', 'AB'] + sys.argv[1:]\n"
            "sys.exit(T.main())\n" % os.path.dirname(os.path.abspath(__file__)))
        r = subprocess.run([sys.executable, "-c", driver, "--warp-profile",
                            prof], capture_output=True, text=True, timeout=60)
        case(r.returncode == 1 and "simulated post-registration failure" in r.stderr,
             "post-registration-failure-is-still-exit-1",
             f"rc={r.returncode} {r.stderr[-300:]}")
        # ...and that abort unwinds through main()'s finally into _stop_all,
        # which is what stops every VICE and tap (an aborted run once
        # orphaned its tcpdump).
        case("STOP_ALL_CALLED" in r.stdout,
             "an-abort-inside-the-stages-reaches-_stop_all",
             f"stdout tail {r.stdout[-200:]!r}")
        case(priv_b64 not in r.stdout + r.stderr,
             "the-private-key-never-reaches-the-log-of-a-real-run-path",
             "key found in output")
        r = subprocess.run([sys.executable, "-c", driver, "--warp-profile",
                            os.path.join(prof_d, "absent.conf")],
                           capture_output=True, text=True, timeout=60)
        case(r.returncode == SKIP_EXIT and "no WARP identity" in r.stdout,
             "unusable-profile-is-exit-77", f"rc={r.returncode} {r.stdout[-300:]}")
        # A failed bridged preflight stops BEFORE any registration.
        failing = driver.replace(
            "    setattr(T, n, lambda *a, **k: [])\n",
            "    setattr(T, n, lambda *a, **k: ['probe blind'])\n").replace(
            "sys.argv = ",
            "def _no(*a, **k): raise SystemExit('REGISTERED')\n"
            "T.obtain_identity = _no\nsys.argv = ")
        r = subprocess.run([sys.executable, "-c", failing], capture_output=True,
                           text=True, timeout=60)
        case(r.returncode == 1 and "not registering" in r.stdout
             and "REGISTERED" not in r.stdout + r.stderr,
             "failed-preflight-stops-before-registering",
             f"rc={r.returncode} {r.stdout[-300:]} {r.stderr[-200:]}")
        os.environ["PATH"] = bin_d + "-empty"
        try:
            r = subprocess.run([sys.executable, "-c", driver],
                               capture_output=True, text=True, timeout=60,
                               env={**os.environ, "WARP_PROFILE": ""})
        finally:
            os.environ["PATH"] = saved
        case(r.returncode == SKIP_EXIT and "wgcf not found" in r.stdout,
             "no-wgcf-through-main-is-exit-77", f"rc={r.returncode} {r.stdout[-300:]}")

    os.environ.clear()
    os.environ.update(env_before)
    failed = [n for ok, n, _ in out if not ok]
    print(f"\nSelf-test: {len(out) - len(failed)}/{len(out)} passed"
          + (f"; FAILED {failed}" if failed else ""))
    return 0 if not failed else 1


def _main_with_sigterm() -> int:
    # SIGTERM becomes SystemExit, so the identity's temp dir is wiped and
    # every VICE stopped by the finally blocks instead of left behind.
    signal.signal(signal.SIGTERM, lambda _sig, _frame: sys.exit(143))
    return main()


if __name__ == "__main__":
    sys.exit(_main_with_sigterm())
