CA65 = ca65
LD65 = ld65
VICE = x64sc

SRC_DIR    = src
BUILD_DIR  = build
IP65_BUILD = ip65-build
IP65_DIR   = ip65
CFG_DIR    = cfg

PRG     = $(BUILD_DIR)/wireguard.prg
LABELS  = $(BUILD_DIR)/labels.txt
MAP     = $(BUILD_DIR)/wireguard.map
IP65_BIN = $(IP65_BUILD)/ip65-c64.bin
CA65_CFG = $(CFG_DIR)/c64-wireguard-ip65.cfg

CA65FLAGS = -I $(SRC_DIR) -I $(SRC_DIR)/net/ip65 --debug-info
LD65FLAGS = -C $(CA65_CFG) -Ln $(LABELS) -m $(MAP)

# Full ca65 source set — all modules linked into the final PRG.
CA65_SRCS = $(SRC_DIR)/loadaddr.s \
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
            $(SRC_DIR)/wg/disk_config.s \
            $(SRC_DIR)/net/ip65/net.s \
            $(SRC_DIR)/net/ip65/ip65_blob.s
CA65_OBJS = $(patsubst $(SRC_DIR)/%.s,$(BUILD_DIR)/%.o,$(CA65_SRCS))

.PHONY: all clean run ip65-libs

# `make` produces build/wireguard.prg + build/labels.txt via ca65/ld65.
# The legacy ACME pipeline was retired after Phase 6 (see git log for
# the migration history).
all: $(PRG)

$(PRG): $(CA65_OBJS) $(IP65_BIN) | $(BUILD_DIR)
	$(LD65) $(LD65FLAGS) -o $@ $(CA65_OBJS)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format
	# `al C:XXXX .name` so c64-test-harness Labels.from_file() can parse.
	sed -i 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

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

clean:
	rm -f $(PRG) $(LABELS) $(MAP)
	rm -rf $(BUILD_DIR)/net $(BUILD_DIR)/crypto $(BUILD_DIR)/wg
	rm -f $(BUILD_DIR)/*.o
	rm -f $(IP65_BUILD)/ip65_stub.o $(IP65_BUILD)/ip65-c64.bin $(IP65_BUILD)/ip65-c64.map

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s $(IP65_BIN) | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<

