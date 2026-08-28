; src/net/ip65/ip65_blob.s — ca65 wrapper around the pre-built ip65 binary.
;
; The ip65 library is built by the ACME→cc65 Makefile pipeline into
;   ip65-build/ip65-c64.bin
; which is a WG-specific UDP-only blob pre-linked at $2000 (jump table
; at $2000, code+data through $32EE, BSS at $4000-$4F3F). This wrapper
; .incbin's that blob into the NET_CODE segment so ld65 places it at
; $2000 inside the final PRG.
;
; Do NOT modify ip65-build/ or the ip65 submodule — they remain the
; source of truth for the ip65 binary. This file just glues the pre-
; built blob into the ca65 link.
;
; Segment NET_CODE is defined by cfg/c64-wireguard-ip65.cfg as
;   start = $2000, size = $12F0, file = %O, type = ro
; which causes ld65 to place the blob at $2000.

.segment "NET_CODE"

; Span labels for the §13.7 footprint asserts at the bottom of this file.
.export ip65_blob_start, ip65_blob_end
ip65_blob_start:

; ca65 tries the CURRENT DIRECTORY first for .incbin and falls back to the
; including source file's directory only on a miss. From the repo root the
; two coincide, which is what makes this spelling work — `make` is always
; run from the root here. The two stop coinciding inside a git worktree
; (three levels down), where `../../../` climbs into the PRIMARY checkout
; and every worktree build silently embeds the wrong blob; c64-https hit
; exactly that (their #116) and respelled it as a bare filename plus
; `--bin-include-dir $(abspath $(IP65_BUILD))`. Note `-I` does NOT feed
; .incbin — binary includes have their own search path. We have not made
; that change here; the size assert below at least turns a stale or
; mismatched blob into a link error rather than a wrong artifact.
.incbin "../../../ip65-build/ip65-c64.bin"
ip65_blob_end:

; =============================================================================
; c64-lib-contract SPEC §13.7 — fixed-address blob footprint
;
; ip65 is a position-linked driver blob, not a relocatable §4 segment
; library: ld65 places it as an opaque `.incbin`, so a consumer cannot move
; it by editing its own SEGMENTS{} block. §13.7 requires the footprint to be
; declared as exported equates instead, so consumer cfgs can compose around
; it at assemble time and relocation is understood to be a RELINK of the
; blob (ip65-build/ip65.cfg + `make ip65-libs`), not a cfg edit.
;
; These live here rather than in a net_manifest.s because this is the
; translation unit that owns the `.incbin`, so BLOB_SIZE can be asserted
; against the bytes actually embedded without a cross-TU import. The §13.0
; NET_BACKEND_FAMILIES half of the manifest is deliberately still absent —
; the ip65 backend has no net_last_error channel, so a NET_FAMILY_CORE claim
; would link green over an error surface that does not exist (see the
; non-conformance note in src/net_abi.inc; blocked on c64-lib-contract#148).
;
; Values are measured from OUR blob, NOT copied from SPEC §13.7's snippet —
; that snippet's $1B27 / $0F8C are c64-https's TCP-and-DNS build. Ours is a
; UDP-focused relink of the same libraries and is ~2.1 KB smaller:
;
;   BASE     $2000  — ip65-build/ip65.cfg MEMORY{} `MAIN: start = $2000`,
;                     matched by cfg/c64-wireguard-ip65.cfg's NET_CODE.
;                     Asserted against the link address below.
;   SIZE     $12EF  — 4847 B, the length of ip65-build/ip65-c64.bin, i.e.
;                     JUMPTAB $2000 through the end of DATA at $32EE in
;                     ip65-build/ip65-c64.map. Asserted against the .incbin.
;   BSS_BASE $4000  — ip65-build/ip65.cfg MEMORY{} `BSS: start = $4000`
;                     (file = "", so these bytes are reserved by the image,
;                     not emitted into it).
;   BSS_SIZE $0F40  — 3904 B, the BSS row of ip65-build/ip65-c64.map's
;                     segment list ($4000-$4F3F occupied of the $2000
;                     reserved). Nothing in the ca65 link sees this span —
;                     it is claimed by the blob at runtime, not by a segment
;                     — so unlike SIZE it cannot be link-asserted. Refresh it
;                     by hand whenever the blob is relinked.
;
; The `: absolute` hints are not decorative. BSS_SIZE is the one at risk: a
; future relink that drops it below $100 would make ca65 infer `zeropage`
; while an importing consumer defaults to absolute, and ld65 then warns
; "Address size mismatch" at every import site (SPEC §13.0/§8.4, contract
; #58/#140). Hinting all four keeps that value-dependent.
;
; KNOWN DEFECT recorded by these numbers, NOT fixed here: the blob's BSS
; ($4000-$4F3F) lands inside cfg/c64-wireguard-ip65.cfg's MAIN_AREA_LO
; ($32F0-$7FFF), on top of APP_CODE, APP_DATA and the chacha archive. ip65's
; eth_inp/eth_outp frame buffers sit in that span, so driving this backend on
; real RR-Net hardware would have the driver write over app code. It has gone
; unnoticed because the ip65 path is never exercised — VICE has no RR-Net and
; all device work runs BACKEND=uci. The repo's memory maps claimed the BSS
; was at $A000-$BFFF, which is what these measured equates now contradict;
; making the footprint declarable is exactly what §13.7 is for. The fix is a
; blob relink at a base the cfg actually reserves, which is a change to
; ip65-build/, not to this file.
; =============================================================================
.export LIB_NET_IP65_BLOB_BASE     : absolute
.export LIB_NET_IP65_BLOB_SIZE     : absolute
.export LIB_NET_IP65_BLOB_BSS_BASE : absolute
.export LIB_NET_IP65_BLOB_BSS_SIZE : absolute

LIB_NET_IP65_BLOB_BASE     = $2000
LIB_NET_IP65_BLOB_SIZE     = $12EF      ; 4847 B — refresh on every blob relink
LIB_NET_IP65_BLOB_BSS_BASE = $4000
LIB_NET_IP65_BLOB_BSS_SIZE = $0F40      ; 3904 B — refresh on every blob relink

; The declaration must not be able to drift from the artifact: assert it
; against the bytes ld65 actually embedded. Without this the equate is just a
; number nobody checks, and a blob rebuild would silently invalidate every
; consumer-side fit calculation derived from it.
.assert ip65_blob_end - ip65_blob_start = LIB_NET_IP65_BLOB_SIZE, lderror, "LIB_NET_IP65_BLOB_SIZE no longer matches ip65-build/ip65-c64.bin - remeasure and refresh src/net/ip65/ip65_blob.s (SPEC 13.7)"
.assert ip65_blob_start = LIB_NET_IP65_BLOB_BASE, lderror, "ip65 blob is not linked at LIB_NET_IP65_BLOB_BASE - cfg NET_CODE start and ip65-build/ip65.cfg MAIN start disagree (SPEC 13.7)"
