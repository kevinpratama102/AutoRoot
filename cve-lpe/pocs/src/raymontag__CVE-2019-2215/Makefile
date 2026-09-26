#
# Makefile for CVE-2019-2215
#
# NDK_ROOT=~/Android/Sdk/ndk/21.0.6113669 make
#

CXX             := clang
CXXFLAGS        := -static -O3 -Wall -Wextra -DDEBUGGING

ARCH            := x86_64
NDK_API         ?= 29
CROSS_COMPILE   := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
TARGET_PLATFORM := $(ARCH)-linux-android

CXX_PATH        := $(CROSS_COMPILE)/bin/$(TARGET_PLATFORM)$(NDK_API)-$(CXX)

EXPLOIT_SRC     := cve-2019-2215.c
EXPLOIT_OUTPUT  := cve-2019-2215-exploit

# default rule
default: all

# phony rules
.PHONY: all

all: clean build-exploit

build-exploit:
	@echo Building: $(EXPLOIT_OUTPUT)
	@$(CXX_PATH) $(CXXFLAGS) -o $(EXPLOIT_OUTPUT) $(EXPLOIT_SRC)

clean:
	@echo Removing: $(EXPLOIT_OUTPUT)
	@rm -f $(EXPLOIT_OUTPUT)

push-exploit:
	@echo Pushing: $(EXPLOIT_OUTPUT) to /data/local/tmp
	@adb push $(EXPLOIT_OUTPUT) /data/local/tmp
