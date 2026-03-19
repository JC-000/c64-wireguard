ACME = acme
CA65 = ca65
LD65 = ld65
VICE = x64sc

SRC_DIR = src
BUILD_DIR = build
IP65_BUILD = ip65-build
IP65_DIR = ip65

PRG = $(BUILD_DIR)/wireguard.prg
LABELS = $(BUILD_DIR)/labels.txt
IP65_BIN = $(IP65_BUILD)/ip65-c64.bin

# ACME sources
ASM_SRCS = $(wildcard $(SRC_DIR)/*.asm)

.PHONY: all clean run ip65-libs

all: $(PRG)

$(PRG): $(ASM_SRCS) $(IP65_BIN) | $(BUILD_DIR)
	cd $(SRC_DIR) && $(ACME) -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

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
	rm -f $(BUILD_DIR)/wireguard.prg $(BUILD_DIR)/labels.txt
	rm -f $(IP65_BUILD)/ip65_stub.o $(IP65_BUILD)/ip65-c64.bin $(IP65_BUILD)/ip65-c64.map
