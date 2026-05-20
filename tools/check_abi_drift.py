#!/usr/bin/env python3
"""
check_abi_drift.py — ABI drift gate for the upcoming library-ingestion refactor.

c64-wireguard's src/crypto_abi.inc declares the public crypto symbols it
expects two sibling libraries to provide:

    fe25519_* / x25519_*            -> c64-x25519
    chacha20_* / poly1305_* / aead_*  -> c64-ChaCha20-Poly1305

This script verifies that every symbol c64-wireguard `.import`s is in fact
`.export`ed by the corresponding sibling repo. It is meant to run as a CI
gate before/after the refactor that swaps the in-tree src/crypto/*.s copies
for a real library-link relationship.

Behavior summary:
  - Parses crypto_abi.inc for `.import <name>` lines.
  - Parses sibling repos for `.export <name>` lines (including
    comma-separated forms like `.export a, b, c`).
  - Prints three tables:
      (1) symbols WG imports AND sibling exports  -- OK / sanity
      (2) symbols WG imports but NO sibling exports -- BREAKAGE
      (3) symbols a sibling exports that WG does not import -- info
  - Exits 0 iff list (2) is empty OR contains only the BLAKE2s family
    (blake2s_*, hmac_blake2s, kdf_*) and a small allowlist of WG-only
    helpers, since BLAKE2s has no sibling library by design.
  - Exits 1 if any fe25519_*/x25519_*/chacha20_*/poly1305_*/aead_* symbol
    is missing from the sibling export surface.

Path-mapping note: the user spec says to parse x25519.inc for `.export`
lines, but x25519.inc is the *consumer* header (only `.import` lines).
The authoritative export surface is the sibling repo's .s files, so this
script scans ALL .s files in c64-x25519/src/ for `.export` lines (the
same way it does for c64-ChaCha20-Poly1305/src/lib/). Override with
--x25519-inc to point at a specific file (or pass a directory).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

DEFAULT_ABI_INC = "/Users/someone/Documents/c64-wireguard/src/crypto_abi.inc"
DEFAULT_X25519_DIR = "/Users/someone/Documents/c64-x25519/src"
DEFAULT_CHACHA_DIR = "/Users/someone/Documents/c64-ChaCha20-Poly1305/src/lib"

IMPORT_RE = re.compile(r"^\s*\.import(?:zp)?\s+(.+?)\s*(?:;.*)?$")
EXPORT_RE = re.compile(r"^\s*\.export(?:zp)?\s+(.+?)\s*(?:;.*)?$")

# Symbols WG imports that legitimately do NOT have a sibling library.
WG_ONLY_PREFIXES = ("blake2s_", "hmac_blake2s", "kdf_")
WG_ONLY_EXACT = {
    "kdf_1", "kdf_2", "kdf_3",
    # fe25519 WG-only helpers explicitly called out in crypto_abi.inc:
    "fe25519_cmp_p", "fe25519_reduce_wide",
}


def _split_symbol_list(rhs: str) -> list[str]:
    """Split an .export/.import RHS like 'a, b, c' into ['a','b','c']."""
    out: list[str] = []
    for tok in rhs.split(","):
        tok = tok.strip()
        # Strip ': absolute = 1' or '= $1234' tails that ca65 allows on .export.
        tok = re.split(r"[\s:=]", tok, maxsplit=1)[0]
        if tok and re.match(r"^[A-Za-z_]\w*$", tok):
            out.append(tok)
    return out


def parse_imports(path: Path) -> set[str]:
    syms: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = IMPORT_RE.match(line)
            if m:
                syms.update(_split_symbol_list(m.group(1)))
    return syms


def parse_exports(paths: list[Path]) -> dict[str, list[Path]]:
    """Return {symbol: [files-where-exported]}. Empty list never happens."""
    provenance: dict[str, list[Path]] = {}
    for p in paths:
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = EXPORT_RE.match(line)
                    if not m:
                        continue
                    for s in _split_symbol_list(m.group(1)):
                        provenance.setdefault(s, []).append(p)
        except OSError as e:
            print(f"warning: could not read {p}: {e}", file=sys.stderr)
    return provenance


def collect_export_files(spec: Path) -> list[Path]:
    """If spec is a file, return [spec]. If a directory, all *.s + *.inc inside."""
    if spec.is_file():
        return [spec]
    if spec.is_dir():
        out: list[Path] = []
        for ext in ("*.s", "*.inc"):
            out.extend(sorted(spec.glob(ext)))
        return out
    print(f"warning: export source {spec} does not exist", file=sys.stderr)
    return []


def is_wg_only(sym: str) -> bool:
    if sym in WG_ONLY_EXACT:
        return True
    return any(sym.startswith(p) for p in WG_ONLY_PREFIXES)


def print_table(title: str, rows: list[str], verbose: bool,
                provenance: dict[str, list[Path]] | None = None,
                wg_root: Path | None = None) -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)
    if not rows:
        print("  (none)")
        print()
        return
    width = max(len(r) for r in rows)
    for sym in sorted(rows):
        if verbose and provenance and sym in provenance:
            files = ", ".join(
                str(f.relative_to(wg_root)) if wg_root and wg_root in f.parents else str(f)
                for f in provenance[sym]
            )
            print(f"  {sym.ljust(width)}  <- {files}")
        else:
            print(f"  {sym}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--abi-inc", default=DEFAULT_ABI_INC,
                    help="Path to c64-wireguard's crypto_abi.inc")
    ap.add_argument("--x25519-inc", default=DEFAULT_X25519_DIR,
                    help="Path to c64-x25519 export source (file or directory)")
    ap.add_argument("--chacha-dir", default=DEFAULT_CHACHA_DIR,
                    help="Path to c64-ChaCha20-Poly1305 export source (file or dir)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Print per-symbol provenance (which file each export came from)")
    args = ap.parse_args()

    abi_path = Path(args.abi_inc)
    if not abi_path.is_file():
        print(f"error: ABI file not found: {abi_path}", file=sys.stderr)
        return 2

    wg_imports = parse_imports(abi_path)

    x25519_files = collect_export_files(Path(args.x25519_inc))
    chacha_files = collect_export_files(Path(args.chacha_dir))

    x25519_exports = parse_exports(x25519_files)
    chacha_exports = parse_exports(chacha_files)

    # Merge sibling export surfaces; track provenance for verbose mode.
    sibling_exports: dict[str, list[Path]] = {}
    for src in (x25519_exports, chacha_exports):
        for s, paths in src.items():
            sibling_exports.setdefault(s, []).extend(paths)
    sibling_set = set(sibling_exports.keys())

    satisfied = sorted(wg_imports & sibling_set)
    missing = sorted(wg_imports - sibling_set)
    extra = sorted(sibling_set - wg_imports)

    print(f"ABI file:      {abi_path}")
    print(f"x25519 source: {args.x25519_inc} ({len(x25519_files)} file(s))")
    print(f"chacha source: {args.chacha_dir} ({len(chacha_files)} file(s))")
    print(f"WG .import symbols: {len(wg_imports)}")
    print(f"Sibling .export symbols: {len(sibling_set)}")
    print()

    print_table("(1) Sibling exports that WG imports -- OK", satisfied,
                args.verbose, sibling_exports)
    print_table("(2) WG imports but no sibling export found -- BREAKAGE candidates",
                missing, args.verbose)
    print_table("(3) Sibling exports that WG does not import -- info", extra,
                args.verbose, sibling_exports)

    # Classify (2): real drift vs. expected-WG-only.
    real_drift = [s for s in missing if not is_wg_only(s)]
    expected_wg_only = [s for s in missing if is_wg_only(s)]

    print("-" * 72)
    print("Verdict")
    print("-" * 72)
    print(f"  WG imports satisfied by sibling: {len(satisfied)}")
    print(f"  WG-only (expected, no sibling):  {len(expected_wg_only)}")
    if expected_wg_only:
        print(f"    {', '.join(expected_wg_only)}")
    print(f"  Real drift (blocking):           {len(real_drift)}")
    if real_drift:
        print(f"    {', '.join(real_drift)}")
        print()
        print("FAIL: sibling library does not export every symbol WG imports.")
        return 1
    print()
    print("PASS: every non-WG-only import is satisfied by a sibling export.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
