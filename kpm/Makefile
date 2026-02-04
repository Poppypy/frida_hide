# KPM 版本号
MYKPM_VERSION ?= v0.0.0

# KernelPatch 内核源码目录
KP_DIR := kernel

# 系统检测
OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
HOST_TAG = $(OS_NAME)-$(MACHINE)

ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif

# NDK 路径
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin

ifndef ANDROID_NDK
    $(error ANDROID_NDK is not set)
endif

NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)

# 编译器
CC := $(NDK_PATH)/aarch64-linux-android31-clang
LD := $(NDK_PATH)/ld.lld

# 头文件路径
INCLUDE_FLAGS := -I$(KP_DIR)/kernel/patch/include -I$(KP_DIR)/kernel/include -I$(KP_DIR)/kernel/linux/include -I$(KP_DIR)/kernel/linux/arch/arm64/include -I$(KP_DIR)/kernel/base/include

# 编译选项
CFLAGS = -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

# 构建目录
BUILD_DIR := build

# 目标文件
objs := $(BUILD_DIR)/frida_hide.o

.PHONY: all clean

all: $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm: $(objs)
	@echo "Linking: $@"
	$(CC) -r -o $@ $^
	@echo "Done: $@"

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
