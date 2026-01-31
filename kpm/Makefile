# ????????????????
MYKPM_VERSION ?= v0.0.0

# KernelPatch ?????????????
ifndef KP_DIR
    KP_DIR = .
endif

# ???????????????
OS_NAME = $(shell uname | tr A-Z a-z)
# ??????
MACHINE = $(shell uname -m)
# ??????
HOST_TAG = $(OS_NAME)-$(MACHINE)
# macOS ARM64 ??????? x86_64 ???
ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif

# NDK ???????
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin

# ?? Android NDK ????
ifndef ANDROID_NDK
    $(error ANDROID_NDK is not set. Please set the ANDROID_NDK environment variable to the path of your Android NDK.)
endif

# NDK ?????
NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)

# ???????
CC := $(NDK_PATH)/aarch64-linux-android31-clang
LD := $(NDK_PATH)/ld.lld

# =============================================================================
# ????
# =============================================================================
# ???????
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

# ?????????
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# ????
CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)$(MYKPM_VER)\"

# =============================================================================
# ????
# =============================================================================
# ??????
BUILD_DIR := build
# ????????
$(shell mkdir -p $(BUILD_DIR))

# ??????
objs := $(BUILD_DIR)/frida_hide.o

# ??????? KPM ??
.PHONY: all
all: $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm

# ???????? KPM ??
$(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm: ${objs}
	@echo "???? KPM ??: $@"
	${CC} -r -o $@ $^
	@echo "KPM ??????: $@"

# ?? C ????????
$(BUILD_DIR)/%.o: %.c
	@echo "????: $<"
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

# =============================================================================
# ?????
# =============================================================================
# ?? KPM ? Android ??
.PHONY: install
install: $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm
	@echo "???? KPM ???..."
	adb wait-for-device
	adb push $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm /sdcard/
	@echo "KPM ??????: /sdcard/frida_hide_$(MYKPM_VERSION).kpm"

# ??????
.PHONY: clean
clean:
	@echo "????????..."
	rm -rf $(BUILD_DIR)
	@echo "????"

# =============================================================================
# ????
# =============================================================================
.PHONY: help
help:
	@echo "FridaHide KPM ????"
	@echo ""
	@echo "????:"
	@echo "  all      - ?? KPM ?? (??)"
	@echo "  install  - ?????? Android ??"
	@echo "  clean    - ??????"
	@echo "  help     - ???????"
	@echo ""
	@echo "????:"
	@echo "  MYKPM_VERSION  - ?? KPM ??? (??: v0.0.0)"
	@echo "  ANDROID_NDK    - Android NDK ?? (????)"
	@echo "  KP_DIR         - KernelPatch ???? (??: .)"
