#!/usr/bin/env python3
"""Which firmware image is on the U64E — read from `/v1/info`, not inferred.

Until 2026-09-03 `/v1/info` could NOT tell a GideonZ#807 chunked-write spike
image apart from stock 3.15: both report `firmware_version` "3.15", so the
only way to know was to send `$03 $16` (WRITE_SOCKET_CHUNK) and look at the
answer. Upstream has since added **`git_commit_hash`** (alongside
`ethernet_mac` / `wifi_mac`), so the image now identifies itself.

**This does not retire the `$16` probe, and nothing here should be read as
retiring it.** The two answer different questions:

    git_commit_hash   WHICH IMAGE is flashed.  Cheap, read-only, no device
                      lock, answerable before a run starts — and only as
                      good as the build actually matching its recorded hash.
    $03 $16 -> reply  WHETHER THE HANDLER DISPATCHES.  The behavioural fact
                      our chunked send path actually depends on. Costs a
                      device round trip and (for our tools) a real send.

So: use `git_commit_hash` as the preflight build-identity check, and keep
`$8E` (`UCI_ERR_CMD_UNKNOWN`, the firmware's "21,UNKNOWN COMMAND") as the
authoritative behavioural signal in the send path. A tool that trusts the
hash alone will happily run a chunked build against an image whose hash is
merely *unfamiliar to this file*, which is why `describe_build` never
refuses — it reports, and the send path still decides.

Known hashes are recorded here ONLY when this repo measured them. An
allowlist that refuses unknown builds would break on the next legitimate
rebase, so `verdict == "unknown"` is a warning, never an error.

Run::

    python3 tools/u64_firmware.py 10.43.23.81
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Optional, Tuple

INFO_TIMEOUT_S = 10.0

# git_commit_hash -> what this repo MEASURED on that image. Nothing here is
# taken on report: each entry names the run that established it.
KNOWN_BUILDS = {
    "a474a7ed": (
        "chunked",
        "GideonZ#807 spike rebased onto upstream test-merge 883f608d "
        "(fpga 125). $03 $16 present: proven by a full WARP interop run on "
        "2026-09-03 (4 handshakes ACTIVE, chunked 1472 B send path).",
    ),
}

# Verdicts describe what we know about the CHUNKED SEND PATH ($16):
#   "chunked"  — measured present on this exact image
#   "unknown"  — the device names an image this repo has not measured
#   "no-hash"  — firmware predates git_commit_hash; only the $16 probe can tell
#   "unreachable" — /v1/info did not answer
VERDICTS = ("chunked", "unknown", "no-hash", "unreachable")


def fetch_info(host: str, timeout: float = INFO_TIMEOUT_S) -> Optional[dict]:
    """GET /v1/info. Returns the parsed dict, or None if it did not answer.

    Read-only and lock-free: safe to call before acquiring the device lock,
    and safe while another lane holds it.
    """
    url = f"http://{host}/v1/info"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def describe_build(info: Optional[dict]) -> Tuple[str, str]:
    """(verdict, one-line human description) for a `/v1/info` payload.

    Never raises and never refuses: an unrecognised hash is reported, not
    rejected, because the next rebase is legitimate and this file cannot
    know about it yet.
    """
    if info is None:
        return "unreachable", "/v1/info did not answer — device unreachable?"

    ident = " ".join(
        f"{k}={info.get(k)}"
        for k in ("firmware_version", "fpga_version", "core_version", "unique_id")
        if info.get(k) is not None
    )

    commit = info.get("git_commit_hash")
    if not commit:
        return "no-hash", (
            f"{ident} — no git_commit_hash: firmware predates the field, so "
            f"the image cannot be identified from /v1/info. Only sending "
            f"$03 $16 distinguishes a #807 spike from stock."
        )

    known = KNOWN_BUILDS.get(commit)
    if known is None:
        return "unknown", (
            f"{ident} git_commit_hash={commit} — image not measured by this "
            f"repo. Not an error; the $16 send path still decides (net_last_"
            f"error $8E means the handler is absent)."
        )

    _, detail = known
    return "chunked", f"{ident} git_commit_hash={commit} — {detail}"


def log_build(host: str, log, timeout: float = INFO_TIMEOUT_S) -> str:
    """Log the device's build identity at preflight. Returns the verdict.

    Warns on anything but a measured chunked image, and never blocks the
    run: the caller's send path carries the authoritative check.
    """
    verdict, text = describe_build(fetch_info(host, timeout))
    if verdict == "chunked":
        log.info("firmware: %s", text)
    else:
        log.warning("firmware [%s]: %s", verdict, text)
    return verdict


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print(f"usage: {argv[0]} <host>", file=sys.stderr)
        return 2
    verdict, text = describe_build(fetch_info(argv[1]))
    print(f"[{verdict}] {text}")
    return 0 if verdict in ("chunked", "unknown", "no-hash") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
