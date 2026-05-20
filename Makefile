CA65 = ca65
LD65 = ld65
VICE = x64sc

# BACKEND selects the networking backend whose sources + ld65 cfg get linked
# into the final PRG:
#   ip65  — classic RR-Net / ip65 stack (default, requires ip65 symlink +
#           prebuilt ip65-build/ip65-c64.bin blob)
#   uci   — Ultimate 64 UCI ($DF1B-$DF1F) adapter; no ip65 dependency
BACKEND ?= ip65

# --- Sibling-library integration (Phase D) ---
# When USE_X25519_SIBLING=1, the in-tree src/crypto/fe25519.s +
# src/crypto/x25519.s are dropped from the link and replaced by
# build/lib/x25519.a (assembled from libs/x25519/ pinned to the SHA
# recorded in .gitmodules). The in-tree X25519/fe25519 buffers in
# src/wg/data.s are suppressed via .ifdef USE_X25519_SIBLING so the
# sibling archive's data_x25519_*_raw exports satisfy the imports.
#
# When USE_CHACHA_SIBLING=1, the same swap happens for
# src/crypto/chacha20.s + poly1305.s + aead.s + word32.s, replaced by
# build/lib/chacha20poly1305.a (Profile B — no POLY1305_PROFILE_LONG /
# POLY1305_REU). word32.s is dropped because the sibling supplies its
# own word32_lib.s.
#
# Both default OFF — the in-tree implementations remain the shipped
# default until the sibling integration is signed off.
USE_X25519_SIBLING ?= 0
USE_CHACHA_SIBLING ?= 0

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

# Common ca65 source set — shared by every backend. The in-tree crypto
# modules that the siblings replace are filtered out below.
COMMON_SRCS_ALL = $(SRC_DIR)/loadaddr.s \
                  $(SRC_DIR)/boot.s \
                  $(SRC_DIR)/exports.s \
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

# Under BACKEND=ip65 the ip65 blob is a link-time dependency.  Under
# BACKEND=uci the blob is not needed and the ip65 submodule/symlink is
# not required.
ifeq ($(BACKEND),ip65)
PRG_DEPS     := $(CA65_OBJS) $(IP65_BIN) $(SIBLING_ARCHIVES)
OBJ_EXTRADEP := $(IP65_BIN)
else
PRG_DEPS     := $(CA65_OBJS) $(SIBLING_ARCHIVES)
OBJ_EXTRADEP :=
endif

.PHONY: all clean run ip65-libs

# `make` produces build/wireguard.prg + build/labels.txt via ca65/ld65.
# The legacy ACME pipeline was retired after Phase 6 (see git log for
# the migration history).
all: $(PRG)

$(PRG): $(PRG_DEPS) | $(BUILD_DIR)
	$(LD65) $(LD65FLAGS) -o $@ $(CA65_OBJS) $(SIBLING_ARCHIVES)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format
	# `al C:XXXX .name` so c64-test-harness Labels.from_file() can parse.
	sed -i.bak 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)
	rm -f $(LABELS).bak

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# --- Sibling archive build rules ---
$(X25519_ARCHIVE): | $(LIB_DIR)
	bash tools/integration/build_x25519.sh

$(CHACHA_ARCHIVE): | $(LIB_DIR)
	bash tools/integration/build_chacha20poly1305.sh

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

# Clean both backends' artifacts so switching BACKEND values is safe.
clean:
	rm -f $(PRG) $(LABELS) $(MAP) $(DBG)
	rm -rf $(BUILD_DIR)/net $(BUILD_DIR)/crypto $(BUILD_DIR)/wg
	rm -rf $(LIB_DIR)
	rm -f $(BUILD_DIR)/*.o
	rm -f $(IP65_BUILD)/ip65_stub.o $(IP65_BUILD)/ip65-c64.bin $(IP65_BUILD)/ip65-c64.map

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s $(OBJ_EXTRADEP) | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<
