# KPM 版本号
MYKPM_VERSION ?= v0.0.0

# KernelPatch 内核源码目录
ifndef KP_DIR
    KP_DIR = .
endif

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

# 头文件路径 - 关键修复
INCLUDE_DIRS := \
    . \
    include \
    patch/include \
    linux/include \
    linux/arch/arm64/include \
    linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 编译选项
CFLAGS = -Wall -O2 \
    -fno-PIC \
    -fno-asynchronous-unwind-tables \
    -fno-stack-protector \
    -fno-common \
    -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

# 构建目录
BUILD_DIR := build
$(shell mkdir -p $(BUILD_DIR))

# 目标文件
objs := $(BUILD_DIR)/frida_hide.o

# 默认目标
.PHONY: all
all: $(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm

# 链接 KPM 文件
$(BUILD_DIR)/frida_hide_$(MYKPM_VERSION).kpm: $(objs)
	@echo "Linking: $@"
	$(CC) -r -o $@ $^
	@echo "Done: $@"

# 编译 C 源文件
$(BUILD_DIR)/%.o: %.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
