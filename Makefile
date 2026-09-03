CA65 = ca65
LD65 = ld65
VICE = x64sc

# BACKEND selects the networking backend whose sources + ld65 cfg get linked
# into the final PRG:
#   ip65  — classic RR-Net / ip65 stack (default, requires ip65 symlink +
#           prebuilt ip65-build/ip65-c64.bin blob)
#   uci   — Ultimate 64 UCI ($DF1B-$DF1F) adapter; no ip65 dependency
BACKEND ?= ip65

# --- Sibling-library integration ---
# When USE_X25519_SIBLING=1, the in-tree src/crypto/fe25519.s +
# src/crypto/x25519.s are dropped from the link and replaced by
# build/lib/x25519.a — the c64-x25519 archive built by the library's own
# contract-§6 `make lib` target (see tools/integration/build_x25519.sh).
# The in-tree X25519/fe25519 buffers in src/wg/data.s are suppressed via
# .ifdef USE_X25519_SIBLING; the archive carries its own data segment.
#
# When USE_CHACHA_SIBLING=1, the same swap happens for
# src/crypto/chacha20.s + poly1305.s + aead.s + word32.s, replaced by
# build/lib/chacha20poly1305.a (Profile B, rolled-outer multiply; see
# tools/integration/build_chacha20poly1305.sh).
#
# Both default ON since the contract-aligned release: the siblings are
# the shipped implementation (the two-archive link is also what makes
# every reachable multiply constant-time — in-tree poly1305.s carries
# the issue #16 non-CT mul_8x8). Set both to 0 for the legacy all-in-tree
# build. Mixed configs are refused below: the archives cross-resolve
# (x25519 provides sqtab_init/ct_mul_8x8, chacha defers to it), so each
# half-on combination hits duplicate-export or unresolved-import errors.
USE_X25519_SIBLING ?= 1
USE_CHACHA_SIBLING ?= 1

ifneq ($(USE_X25519_SIBLING),$(USE_CHACHA_SIBLING))
$(error USE_X25519_SIBLING and USE_CHACHA_SIBLING must match (both 1 or both 0); mixed sibling configs no longer link — see tools/integration/*.sh headers)
endif

# --- REU knob ---
# REU=1 (default): c64-x25519 REU profile — mul tables in REU banks
#   0,1,3,4,5; fastest at 1 MHz (~4.3 min scalarmult). Requires an REU
#   (real 1750-class, or Ultimate REU emulation).
# REU=0: X25519_ONCHIP_MUL profile — zero REU anywhere in the PRG
#   (chacha v0.7.0 issues no REU DMA on any path either — its
#   LIB_CHACHA20_POLY1305_REU_BANKS_USED is $00); runs on a stock C64.
#   ~1.7x slower scalarmult at 1 MHz.
# Only meaningful with the siblings ON (the in-tree fe25519 is REU-only).
REU ?= 1

ifeq ($(REU),0)
ifeq ($(USE_X25519_SIBLING),0)
$(error REU=0 requires the sibling build (USE_X25519_SIBLING=1); the in-tree fe25519 has no REU-less multiply)
endif
X25519_PROFILE = onchip
else
X25519_PROFILE = default
endif
export X25519_PROFILE

SRC_DIR    = src
BUILD_DIR  = build
IP65_BUILD = ip65-build
IP65_DIR   = ip65
CFG_DIR    = cfg
LIB_DIR    = $(BUILD_DIR)/lib

PRG     = $(BUILD_DIR)/wireguard.prg
LABELS  = $(BUILD_DIR)/labels.txt
MAP     = $(BUILD_DIR)/wireguard.map
DBG     = $(BUILD_DIR)/wireguard.dbg
IP65_BIN = $(IP65_BUILD)/ip65-c64.bin
CFG_FILE := $(CFG_DIR)/c64-wireguard-$(BACKEND).cfg

X25519_ARCHIVE  = $(LIB_DIR)/x25519.a
CHACHA_ARCHIVE  = $(LIB_DIR)/chacha20poly1305.a

CA65FLAGS = -I $(SRC_DIR) -I $(SRC_DIR)/net/$(BACKEND) --debug-info
# --dbgfile pairs with ca65 --debug-info to emit a source-level debug
# file VICE's monitor can load (`load_labels`/`source-line` commands)
# for stepping by source line and showing local symbol scopes.
LD65FLAGS = -C $(CFG_FILE) -Ln $(LABELS) -m $(MAP) --dbgfile $(DBG)

# Propagate sibling flags to ca65 so src/wg/data.s + src/exports.s
# suppress the in-tree buffer / equate decls that the sibling archive
# now owns.
ifeq ($(USE_X25519_SIBLING),1)
CA65FLAGS += -D USE_X25519_SIBLING=1
endif
ifeq ($(USE_CHACHA_SIBLING),1)
CA65FLAGS += -D USE_CHACHA_SIBLING=1
endif
ifeq ($(REU),0)
CA65FLAGS += -D WG_NO_REU=1
endif

# --- UCI chunked send (issue #70) ---
# UCI_CHUNKED_WRITE=1 makes the UCI adapter send every datagram with the
# firmware's chunked NET_CMD_WRITE_SOCKET_CHUNK ($16, GideonZ/1541ultimate#807
# spike builds; NOT in stock 3.15) in parts of at most 888 bytes, lifting
# NET_UDP_SEND_MAX from 892 to 1472 and the tunnel MTU from 860 to 1440.
# Default 0: the shipped adapter uses plain SOCKET_WRITE and the default
# build is byte-identical to a tree without this flag. UCI only — ip65 has
# no chunked path and its caps are already 1472/1472 (clamped by
# WG_DATAGRAM_CAP for RAM, see src/constants.inc).
UCI_CHUNKED_WRITE ?= 0
ifeq ($(UCI_CHUNKED_WRITE),1)
ifneq ($(BACKEND),uci)
$(error UCI_CHUNKED_WRITE=1 requires BACKEND=uci: the chunked SOCKET_WRITE is a UCI firmware command, ip65 has no equivalent)
endif
CA65FLAGS += -D UCI_CHUNKED_WRITE=1
endif

# --- WG_MTU1440 (issue #70) ---
# WG_MTU1440=1 is the generic, backend-agnostic opt-in that lifts
# WG_DATAGRAM_CAP (src/constants.inc) from 892 to 1472 and hence the tunnel
# MTU from 860 to 1440. Default 0: BOTH backends keep 892 and the default
# build is byte-identical to a tree without this flag. ip65 already
# advertises NET_UDP_SEND_MAX/RECV_MAX 1472/1472, so under BACKEND=ip65 the
# flag alone is enough (its RR-Net path is unmeasured at 1472 and #80 is
# open, hence opt-in). Under BACKEND=uci only the chunked SOCKET_WRITE path
# raises NET_UDP_SEND_MAX to 1472, so a uci build with WG_MTU1440=1 but
# without UCI_CHUNKED_WRITE=1 can never carry a 1440-byte MTU: the §13.3
# capability fit (WG_MTU + 32 <= NET_UDP_SEND_MAX, src/contract_asserts.s)
# is kept by constants.inc clamping WG_MTU back to 860, i.e. the flag would
# be a SILENT no-op — refuse the pairing here, at parse time, with the fix
# spelled out.
WG_MTU1440 ?= 0
ifeq ($(WG_MTU1440),1)
ifeq ($(BACKEND),uci)
ifneq ($(UCI_CHUNKED_WRITE),1)
$(error WG_MTU1440=1 with BACKEND=uci needs the chunked send path: add UCI_CHUNKED_WRITE=1 (requires GideonZ/1541ultimate#807 spike firmware), or use BACKEND=ip65 where the 1472-byte caps are native)
endif
endif
CA65FLAGS += -D WG_MTU1440=1
endif

# --- MSG_PORT (test/warp-interop, issue #87) ---
# Overrides the compile-time msg_port used by the chat message / ping
# path in src/wg/data.s (src/wg/ip_build.s uses it as BOTH src and dst
# UDP port for the inner tunnel packet). Only meaningful for interop
# testing against a real peer where the message needs to land on a
# specific real-world port (e.g. 53 for DNS). Default 9999 is NOT passed
# through to ca65 at all — the -D flag is only emitted when MSG_PORT is
# overridden away from the default — so an unadorned `make` keeps
# data.s on its untouched `.ifndef MSG_PORT` .word $270f path and
# produces a byte-identical PRG to a tree without this knob.
MSG_PORT ?= 9999
ifneq ($(MSG_PORT),9999)
CA65FLAGS += -D MSG_PORT=$(MSG_PORT)
endif

# Common ca65 source set — shared by every backend. The in-tree crypto
# modules that the siblings replace are filtered out below.
COMMON_SRCS_ALL = $(SRC_DIR)/loadaddr.s \
                  $(SRC_DIR)/boot.s \
                  $(SRC_DIR)/exports.s \
                  $(SRC_DIR)/contract_asserts.s \
                  $(SRC_DIR)/crypto/word32.s \
                  $(SRC_DIR)/crypto/entropy.s \
                  $(SRC_DIR)/crypto/blake2s.s \
                  $(SRC_DIR)/crypto/blake2s_kdf.s \
                  $(SRC_DIR)/crypto/chacha20.s \
                  $(SRC_DIR)/crypto/poly1305.s \
                  $(SRC_DIR)/crypto/aead.s \
                  $(SRC_DIR)/crypto/fe25519.s \
                  $(SRC_DIR)/crypto/x25519.s \
                  $(SRC_DIR)/wg/timer.s \
                  $(SRC_DIR)/wg/tai64n.s \
                  $(SRC_DIR)/wg/cookie.s \
                  $(SRC_DIR)/wg/config.s \
                  $(SRC_DIR)/wg/data.s \
                  $(SRC_DIR)/wg/strings.s \
                  $(SRC_DIR)/wg/handshake.s \
                  $(SRC_DIR)/wg/transport.s \
                  $(SRC_DIR)/wg/session.s \
                  $(SRC_DIR)/wg/ip_build.s \
                  $(SRC_DIR)/wg/vic_boost.s \
                  $(SRC_DIR)/wg/disk_config.s

# Drop in-tree crypto sources that the siblings replace.
X25519_REPLACED_SRCS  = $(SRC_DIR)/crypto/fe25519.s $(SRC_DIR)/crypto/x25519.s
CHACHA_REPLACED_SRCS  = $(SRC_DIR)/crypto/chacha20.s \
                        $(SRC_DIR)/crypto/poly1305.s \
                        $(SRC_DIR)/crypto/aead.s \
                        $(SRC_DIR)/crypto/word32.s

ifeq ($(USE_X25519_SIBLING),1)
COMMON_SRCS_DROP_X25519 := $(X25519_REPLACED_SRCS)
else
COMMON_SRCS_DROP_X25519 :=
endif
ifeq ($(USE_CHACHA_SIBLING),1)
COMMON_SRCS_DROP_CHACHA := $(CHACHA_REPLACED_SRCS)
else
COMMON_SRCS_DROP_CHACHA :=
endif

COMMON_SRCS = $(filter-out $(COMMON_SRCS_DROP_X25519) $(COMMON_SRCS_DROP_CHACHA),$(COMMON_SRCS_ALL))

# Sibling archives that get linked into the PRG.
SIBLING_ARCHIVES :=
ifeq ($(USE_X25519_SIBLING),1)
SIBLING_ARCHIVES += $(X25519_ARCHIVE)
endif
ifeq ($(USE_CHACHA_SIBLING),1)
SIBLING_ARCHIVES += $(CHACHA_ARCHIVE)
endif

# Per-backend source list.
IP65_SRCS = $(SRC_DIR)/net/ip65/net.s \
            $(SRC_DIR)/net/ip65/ip65_blob.s
UCI_SRCS  = $(SRC_DIR)/net/uci/net.s \
            $(SRC_DIR)/net/uci/uci_cmd.s

ifeq ($(BACKEND),ip65)
NET_SRCS := $(IP65_SRCS)
else ifeq ($(BACKEND),uci)
NET_SRCS := $(UCI_SRCS)
else
$(error Unknown BACKEND=$(BACKEND); expected ip65 or uci)
endif

CA65_SRCS = $(COMMON_SRCS) $(NET_SRCS)
CA65_OBJS = $(patsubst $(SRC_DIR)/%.s,$(BUILD_DIR)/%.o,$(CA65_SRCS))

# --- Header dependency tracking (issue #66) ---
# Objects must depend on the .inc headers they include, or editing a header
# leaves a stale .o in place and the link silently mixes old and new
# definitions of a shared constant. That failure mode produces a wrong
# artifact rather than a build error, and it also disarms every .assert-based
# conformance guard in the tree: a translation unit that is not reassembled
# cannot fire its asserts.
#
# ca65 emits the dependencies itself (--create-full-dep on the object rule
# below), so nothing here hand-maintains a header list. Each fragment also
# carries an empty rule per prerequisite, which is what keeps a *deleted*
# header from wedging make with "No rule to make target".
#
# The flag-side sibling of this — an object is equally stale when the ca65
# FLAGS change, which no .d fragment can record — is handled further down by
# the CA65_FLAGSTAMP reconciliation (issue #76).
CA65_DEPS = $(CA65_OBJS:.o=.d)

# Under BACKEND=ip65 the ip65 blob is a link-time dependency.  Under
# BACKEND=uci the blob is not needed and the ip65 submodule/symlink is
# not required.
#
# $(CFG_FILE) is listed too (issue #76, ld65 half). It is the only part of
# LD65FLAGS that varies — the other three are fixed output paths — and it was
# NOT a prerequisite before: it appeared solely inside LD65FLAGS, so editing
# cfg/c64-wireguard-*.cfg left the PRG untouched, and the ld65 side needed the
# same treatment as ca65 after all. Naming the file is enough here, though; no
# ld65 flag stamp is required, because unlike CA65FLAGS every value LD65FLAGS
# can take is either a constant or this file, and a BACKEND flip now changes
# both the recorded configuration (whose reconciliation drops every object)
# and which .cfg is named.
ifeq ($(BACKEND),ip65)
PRG_DEPS     := $(CA65_OBJS) $(CFG_FILE) $(IP65_BIN) $(SIBLING_ARCHIVES)
OBJ_EXTRADEP := $(IP65_BIN)
else
PRG_DEPS     := $(CA65_OBJS) $(CFG_FILE) $(SIBLING_ARCHIVES)
OBJ_EXTRADEP :=
endif

.PHONY: all clean run ip65-libs release

# `make` produces build/wireguard.prg + build/labels.txt via ca65/ld65.
# The legacy ACME pipeline was retired after Phase 6 (see git log for
# the migration history).
all: $(PRG)

# Build the full release artifact set (4 PRG variants + 2 D64 images +
# SHA256SUMS) into build/release/. See tools/release/build_release.sh.
# (Declared after `all` — the first rule in the file is the default goal.)
release:
	bash tools/release/build_release.sh

$(PRG): $(PRG_DEPS) | $(BUILD_DIR)
	$(LD65) $(LD65FLAGS) -o $@ $(CA65_OBJS) $(SIBLING_ARCHIVES)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format
	# `al C:XXXX .name` so c64-test-harness Labels.from_file() can parse.
	#
	# Drop labels whose value exceeds $$FFFF first. VICE's `al C:XXXX` form is
	# 16-bit, so a far symbol has no valid representation and the rewrite below
	# would leave it malformed. The offenders are the contract §8.4 precalc
	# `_SIZE` equates, which the canonical macro exports WITHOUT an address-size
	# hint precisely so oversized tables (reu_mul = 131072) export as `far`
	# rather than warning — e.g. `al 020000 .LIB_X25519_PRECALC_reu_mul_SIZE`.
	# They are manifest constants, not addresses, so nothing wants them in a
	# label file. Filtering beats widening the match: there is no 24-bit target.
	sed -i.bak '/^al 0*[1-9a-fA-F][0-9a-fA-F]*[0-9a-fA-F]\{4\} /d' $(LABELS)
	sed -i.bak 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)
	rm -f $(LABELS).bak

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# --- Sibling archive build rules ---
# FORCE-driven: incrementality lives in the sibling Makefiles (cheap
# no-op when up to date), and the REU/profile knob changes what the
# x25519 script produces without changing any prerequisite timestamp.
.PHONY: FORCE
FORCE:

$(X25519_ARCHIVE): FORCE | $(LIB_DIR)
	bash tools/integration/build_x25519.sh

$(CHACHA_ARCHIVE): FORCE | $(LIB_DIR)
	bash tools/integration/build_chacha20poly1305.sh

# --- Assembler-flag dependency tracking (issue #76) ---
# The .d fragments record which FILES an object read, not which FLAGS it was
# assembled with, and every knob this Makefile exposes moves CA65FLAGS without
# touching a single file on disk:
#
#   BACKEND         changes -I $(SRC_DIR)/net/$(BACKEND), which is how
#                   net_caps.inc (§13.3) is resolved — and the two backends
#                   publish different capabilities (uci 892/1472, ip65
#                   1472/1472), from which WG_MTU, MSG_TEXT_MAX and the buffer
#                   sizes in src/wg/data.s derive.
#   REU=0           adds -D WG_NO_REU=1.
#   USE_*_SIBLING   add their own -D and change which sources are linked at all.
#
# With nothing carrying those, every .o looks up to date after a flip and make
# relinks a binary assembled under the PREVIOUS configuration. Same
# silent-wrong-artifact class as #66 — a wrong PRG rather than a build error —
# and it also disarms the .assert conformance guards in src/contract_asserts.s,
# which can only fire in a translation unit that is actually reassembled.
# Measured against the pre-fix Makefile: `make BACKEND=uci REU=0` straight
# after a REU=1 build reassembled ZERO objects and re-emitted the REU=1 PRG
# byte for byte. With #69 making REU=0 the hardware-correct build, that is a
# live way to ship a PRG that is neither profile.
#
# WHY THIS IS A DELETION AND NOT A STAMP PREREQUISITE. The obvious fix — write
# the flags to a stamp file, only when they change, and hang every object off
# it — DOES NOT WORK ON THIS TOOLCHAIN, and fails silently in the same
# direction as the bug it is meant to fix. Apple ships GNU Make 3.81, which
# compares mtimes at ONE-SECOND resolution, and a full assemble+link of this
# tree takes about half a second: the rewritten stamp and the objects it is
# supposed to invalidate land in the same second, make calls it a tie, and the
# stale objects are relinked anyway. Measured, back-to-back, with exactly that
# rule in place: a uci -> ip65 -> uci sequence reassembled 21, then 2, then 0
# of 21 objects. A stamp is only ever as good as the clock's resolution.
#
# So the reconciliation is expressed as what it actually means — the artifacts
# on disk were built under a different configuration, therefore they are not
# artifacts of this one — and simply removes them. No timestamps involved, so
# nothing depends on how fast the build is or how coarse the clock is.
#
# It runs at PARSE TIME, before make stats anything, because that is the only
# point at which a deletion still changes make's mind: a recipe that deletes an
# object mid-build is too late (make 3.81 has already made its decision, and
# only notices on the NEXT invocation — also measured).
#
# Incremental builds are untouched: an unchanged configuration takes the fast
# path of the `[ ... ] ||` below, deletes nothing, and make proceeds normally.
CA65_FLAGSTAMP = $(BUILD_DIR)/.ca65flags
CA65_FLAGTEXT  = $(BACKEND) $(CA65FLAGS)

# Everything under build/ whose content is a function of CA65FLAGS: the objects
# and their .d fragments, plus the four link outputs derived from them (the
# link outputs are in the list because dropping only the objects leaves the
# same one-second tie between a freshly assembled .o and the PRG beside it).
#
# The sibling archives are deliberately NOT here: they are FORCE-rebuilt on
# every make by their own scripts, which read X25519_PROFILE themselves. Nor is
# the ip65 blob, which ca65 never sees CA65FLAGS for. `clean` reuses this list
# and then adds those two.
FLAGGED_ARTIFACTS = $(PRG) $(LABELS) $(MAP) $(DBG) \
                    $(BUILD_DIR)/*.o $(BUILD_DIR)/*.d \
                    $(BUILD_DIR)/net $(BUILD_DIR)/crypto $(BUILD_DIR)/wg

# Skipped under -n/--dry-run (both set the `n` letter in MAKEFLAGS): a dry run
# must not mutate the tree. The cost is that `make -n` right after a flag flip
# under-reports what a real build would do; predicting the rebuild is not worth
# performing part of it.
ifeq (,$(findstring n,$(firstword -$(MAKEFLAGS))))
CA65_FLAGS_RECONCILE := $(shell \
    [ "`cat $(CA65_FLAGSTAMP) 2>/dev/null`" = '$(CA65_FLAGTEXT)' ] || { \
        rm -rf $(FLAGGED_ARTIFACTS); \
        mkdir -p $(BUILD_DIR) && \
        printf '%s\n' '$(CA65_FLAGTEXT)' > $(CA65_FLAGSTAMP); \
    })
endif

# Build ip65 libraries (only if not already built)
ip65-libs:
	cd $(IP65_DIR) && $(MAKE) -C ip65 && $(MAKE) -C drivers

# Build ip65 binary blob
$(IP65_BIN): $(IP65_BUILD)/ip65_stub.s $(IP65_BUILD)/ip65.cfg ip65-libs
	cd $(IP65_BUILD) && $(CA65) -I ../$(IP65_DIR) ip65_stub.s -o ip65_stub.o
	cd $(IP65_BUILD) && $(LD65) -C ip65.cfg -o ip65-c64.bin -m ip65-c64.map \
		ip65_stub.o ../$(IP65_DIR)/ip65/ip65.lib \
		../$(IP65_DIR)/drivers/ip65_c64.lib c64.lib

run: $(PRG)
	$(VICE) -autostart $(PRG)

# Clean both backends' artifacts so switching BACKEND values is safe. (Since
# #76 a switch no longer needs this, but a clean is still a clean.)
#
# The flag stamp needs naming separately: it is a dotfile, so the globs inside
# FLAGGED_ARTIFACTS do not match it. Removing it is what makes a cleaned tree
# indistinguishable from a never-built one — leaving behind the record of a
# configuration whose artifacts are all gone would make the next build's
# reconciliation a no-op that deletes nothing (harmless, but only by accident)
# and would mislead anyone reading build/ to see what the tree was last built
# as.
clean:
	rm -rf $(FLAGGED_ARTIFACTS)
	rm -rf $(LIB_DIR)
	rm -f $(CA65_FLAGSTAMP)
	rm -f $(IP65_BUILD)/ip65_stub.o $(IP65_BUILD)/ip65-c64.bin $(IP65_BUILD)/ip65-c64.map

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s $(OBJ_EXTRADEP) | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) --create-full-dep $(@:.o=.d) -o $@ $<

# Pull in the generated header dependencies (issue #66). Leading `-` so a
# first build, or one after `make clean`, does not complain about the
# fragments not existing yet — the objects are rebuilt from scratch anyway.
-include $(CA65_DEPS)
