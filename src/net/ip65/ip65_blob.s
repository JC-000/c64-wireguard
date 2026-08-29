; src/net/ip65/ip65_blob.s — ca65 wrapper around the pre-built ip65 binary.
;
; The ip65 library is built by the ACME→cc65 Makefile pipeline into
;   ip65-build/ip65-c64.bin
; which is a WG-specific UDP-only blob pre-linked at $2000 (jump table
; at $2000, code+data through $32EE, BSS at $A000-$AF3F). This wrapper
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
;   BSS_BASE $A000  — ip65-build/ip65.cfg MEMORY{} `BSS: start = $A000`
;                     (file = "", so these bytes are reserved by the image,
;                     not emitted into it). Mirrored by the IP65_BSS region
;                     in cfg/c64-wireguard-ip65.cfg and asserted against it
;                     below, so the blob's link address and the consumer's
;                     reservation cannot drift apart.
;   BSS_SIZE $0F40  — 3904 B, the BSS row of ip65-build/ip65-c64.map's
;                     segment list ($A000-$AF3F occupied of the $2000
;                     reserved). Nothing in the ca65 link sees this span —
;                     it is claimed by the blob at runtime, not by a segment
;                     — so unlike SIZE it cannot be link-asserted against the
;                     artifact. It IS asserted to fit inside IP65_BSS and to
;                     miss every WG-claimed region. Refresh it by hand
;                     whenever the blob is relinked.
;
; The `: absolute` hints are not decorative. BSS_SIZE is the one at risk: a
; future relink that drops it below $100 would make ca65 infer `zeropage`
; while an importing consumer defaults to absolute, and ld65 then warns
; "Address size mismatch" at every import site (SPEC §13.0/§8.4, contract
; #58/#140). Hinting all four keeps that value-dependent.
;
; RESOLVED LAYOUT (issue #80). The BSS sits at $A000-$AF3F, inside the
; $A000-$BFFF window that cfg/c64-wireguard-ip65.cfg reserves as IP65_BSS and
; that no other MEMORY region there claims. That window is the RAM under the
; C64's BASIC ROM: src/boot.s clears LORAM (`lda proc_port / and #$fe`) as its
; first instruction at `start:` and only sets it again at `quit`, so the span
; reads back as RAM for every instant ip65 can run — including inside KERNAL
; calls, which live at $E000+ and are unaffected by LORAM. Neither the blob
; (rr-net.o / eth64.o / c64combo.o / the ip65 core) nor WG writes $01 anywhere
; else, and no blob symbol resolves into $A000-$BFFF other than this BSS.
; boot.s additionally zeroes the whole $2000 span before anything runs.
;
; The layout it replaced was a live memory-corruption bug, kept here because
; the asserts below exist to stop it recurring. The blob used to link its BSS
; at $4000, inside MAIN_AREA_LO ($32F0-$7FFF), on top of APP_CODE, APP_DATA
; and the chacha archive; ip65's eth_inp/eth_outp frame buffers sit in that
; span, so the driver wrote ethernet frames over application code. Measured on
; the ethernet VICE rig, ONE DHCP exchange overwrote 733 bytes of APP_CODE
; (transport_encrypt, transport_decrypt, the replay-window update,
; transport_send) and 284 bytes of LIB_CHACHA20_POLY1305_CODE (chacha20_block,
; chacha20_quarter_round, cc20_constants), leaving an ethernet broadcast MAC
; at $4000. Nothing faulted: the damage was to the transport path and the AEAD
; primitive, so it would have presented as intermittent bad ciphertext or tag
; failures and been blamed on the crypto (compare #62, WireGuard bytes in the
; VIC registers). It went unnoticed because no suite in tools/ asks for an
; ethernet VICE and every device run is BACKEND=uci — unexercised, not
; unexercisable: VICE emulates RR-Net and c64-test-harness drives it
; (VICE_ETHERNET_BIN; vice_ethernet_mode "rrnet", base $DE00).
;
; Both of this repo's memory maps had claimed $A000-$BFFF all along while the
; blob was at $4000, and nothing checked either number — which is what §13.7
; is for, and why the fix is a RELINK of ip65-build/ip65.cfg plus the
; consumer-side reservation, not an edit to the .incbin.
; =============================================================================
.export LIB_NET_IP65_BLOB_BASE     : absolute
.export LIB_NET_IP65_BLOB_SIZE     : absolute
.export LIB_NET_IP65_BLOB_BSS_BASE : absolute
.export LIB_NET_IP65_BLOB_BSS_SIZE : absolute

LIB_NET_IP65_BLOB_BASE     = $2000
LIB_NET_IP65_BLOB_SIZE     = $12EF      ; 4847 B — refresh on every blob relink
LIB_NET_IP65_BLOB_BSS_BASE = $A000
LIB_NET_IP65_BLOB_BSS_SIZE = $0F40      ; 3904 B — refresh on every blob relink

; The declaration must not be able to drift from the artifact: assert it
; against the bytes ld65 actually embedded. Without this the equate is just a
; number nobody checks, and a blob rebuild would silently invalidate every
; consumer-side fit calculation derived from it.
.assert ip65_blob_end - ip65_blob_start = LIB_NET_IP65_BLOB_SIZE, lderror, "LIB_NET_IP65_BLOB_SIZE no longer matches ip65-build/ip65-c64.bin - remeasure and refresh src/net/ip65/ip65_blob.s (SPEC 13.7)"
.assert ip65_blob_start = LIB_NET_IP65_BLOB_BASE, lderror, "ip65 blob is not linked at LIB_NET_IP65_BLOB_BASE - cfg NET_CODE start and ip65-build/ip65.cfg MAIN start disagree (SPEC 13.7)"

; =============================================================================
; Issue #80 guard — the declared BSS span must miss every WG-claimed region.
;
; This is the check whose absence was the whole bug. The blob's BSS is claimed
; by the driver at RUNTIME, not by a segment, so ld65 sees no allocation there
; and cannot detect a collision on its own: the corrupting layout linked clean,
; with no error and no warning, and stayed that way for the life of the
; backend. The equates above are the only machine-readable statement of where
; those bytes go (SPEC §13.7), so they are what the region symbols get checked
; against.
;
; ld65 publishes __<AREA>_START__ / _SIZE__ / _LAST__ for every `define = yes`
; MEMORY area; contract_asserts.s uses the same pattern for the §6.7 sqtab
; window. START + SIZE is deliberate over _LAST__: the reservation is the whole
; region, not the part a given build happens to fill, so a region that is
; merely under-full today must not read as free space tomorrow.
;
; Disjointness of [a, a+n) and [b, b+m) is `a+n <= b || b+m <= a`. `||` is
; ca65's BOOLEAN or — the operands here are comparisons yielding 0/1, so this
; is the intended meaning; do not "simplify" it to bitwise `|` (see the
; standing `.and` warning at the top of src/contract_asserts.s).
;
; lderror, not error: the region symbols are unresolved at assembly time and
; only ld65 can evaluate these.
; =============================================================================
.import __LOADER_START__,       __LOADER_SIZE__
.import __NET_CODE_START__,     __NET_CODE_SIZE__
.import __MAIN_AREA_LO_START__, __MAIN_AREA_LO_SIZE__
.import __SQTAB_HOLE_START__,   __SQTAB_HOLE_SIZE__
.import __MAIN_AREA_HI_START__, __MAIN_AREA_HI_SIZE__
.import __IP65_BSS_START__,     __IP65_BSS_SIZE__

.macro  IP65_BSS_DISJOINT_FROM  rstart, rsize, msg
        .assert (LIB_NET_IP65_BLOB_BSS_BASE + LIB_NET_IP65_BLOB_BSS_SIZE <= rstart) || (rstart + rsize <= LIB_NET_IP65_BLOB_BSS_BASE), lderror, msg
.endmacro

IP65_BSS_DISJOINT_FROM __LOADER_START__,       __LOADER_SIZE__,       "ip65 blob BSS overlaps LOADER - ip65's frame buffers would overwrite the BASIC stub, boot code and the x25519 data tables (issue #80); relink ip65-build/ip65.cfg"
IP65_BSS_DISJOINT_FROM __NET_CODE_START__,     __NET_CODE_SIZE__,     "ip65 blob BSS overlaps NET_CODE - ip65's frame buffers would overwrite the ip65 blob itself (issue #80); relink ip65-build/ip65.cfg"
IP65_BSS_DISJOINT_FROM __MAIN_AREA_LO_START__, __MAIN_AREA_LO_SIZE__, "ip65 blob BSS overlaps MAIN_AREA_LO - ip65's frame buffers would overwrite app code, the transport path and the chacha archive (issue #80, the original defect); relink ip65-build/ip65.cfg"
IP65_BSS_DISJOINT_FROM __SQTAB_HOLE_START__,   __SQTAB_HOLE_SIZE__,   "ip65 blob BSS overlaps SQTAB_HOLE - ip65's frame buffers and sqtab_init would fight over the quarter-square tables (issue #80); relink ip65-build/ip65.cfg"
IP65_BSS_DISJOINT_FROM __MAIN_AREA_HI_START__, __MAIN_AREA_HI_SIZE__, "ip65 blob BSS overlaps MAIN_AREA_HI - ip65's frame buffers would overwrite x25519 init code and APP_BSS (issue #80); relink ip65-build/ip65.cfg"

; And the positive half: the span must live inside the window the consumer cfg
; actually reserves for it. Disjointness alone would be satisfied by parking
; the BSS anywhere unclaimed — including $C000, $D000 I/O, or off the end of
; RAM — so pin it to IP65_BSS. Base equality also keeps the §13.7 declaration
; honest: an equate that no longer names the blob's real link address is worse
; than no equate, because consumers compose against it.
.assert LIB_NET_IP65_BLOB_BSS_BASE = __IP65_BSS_START__, lderror, "LIB_NET_IP65_BLOB_BSS_BASE disagrees with the cfg's IP65_BSS reservation - ip65-build/ip65.cfg BSS start and cfg/c64-wireguard-ip65.cfg IP65_BSS start have drifted (SPEC 13.7)"
.assert LIB_NET_IP65_BLOB_BSS_SIZE <= __IP65_BSS_SIZE__, lderror, "ip65 blob BSS is larger than the IP65_BSS window reserved for it - it would run past $BFFF into unreserved RAM; grow the reservation in cfg/c64-wireguard-ip65.cfg"
