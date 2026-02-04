# KPM 版本号
MYKPM_VERSION ?= v0.0.0

# KernelPatch 目录
KP_DIR := kernel

# 系统检测
OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
HOST_TAG = $(OS_NAME)-$(MACHINE)

ifeq ($(HOST_TAG), darwin-arm64)
    HOST_TAG = darwin-x86_64
endif

# NDK 路径
ifndef ANDROID_NDK
    $(error ANDROID_NDK is not set)
endif

NDK_BIN_DIR := $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin

# 编译器 - 使用 clang
CC := $(NDK_BIN_DIR)/aarch64-linux-android31-clang
LD := $(NDK_BIN_DIR)/ld.lld

# 头文件路径 - 按照官方格式
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 编译选项
CFLAGS := -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

# 构建目录
BUILD_DIR := build

# 目标文件
objs := $(BUILD_DIR)/frida_hide.o

.PHONY: all clean

all: $(BUILD_DIR) $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm: $(objs)
	@echo "Linking: $@"
	$(LD) -r -o $@ $^
	@echo "Done: $@"

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
