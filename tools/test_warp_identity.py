#!/usr/bin/env python3
"""test_warp_identity.py — the bridged WARP suite's identity step, in the gate.

tools/test_warp_ip65_vice.py registers a fresh Cloudflare WARP device per
run. Its live arm needs the bridged rig and Cloudflare and stays out of the
gate, but the identity step's exit semantics and secret handling do not:
this runs that suite's own ``run_self_test()`` (also ``--self-test`` there)
against a STUB wgcf — no network, no VICE.

A separate file, not ``test_warp_ip65_vice.py --self-test`` in the gate's
list, because the gate audits every file it runs for how it starts VICE
(tools/test_vice_reu_matches_build.py), and that suite's live arm starts
VICE its own way on purpose. Importing it here starts nothing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_warp_ip65_vice as warp  # noqa: E402

if __name__ == "__main__":
    sys.exit(warp.run_self_test())
