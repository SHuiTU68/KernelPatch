# SPDX-License-Identifier: GPL-2.0
#
# Builds the two ramdisk helpers:
#
#   kpinit-android     - the first stage `init` that loads the KernelPatch LKM
#                        out of the ramdisk (kpinit.c)
#   kpramdisk-android  - the injector that puts kpinit + the LKM into an
#                        init_boot ramdisk (kpramdisk.c)
#
# Both are published as release assets and shipped inside the APatch apk.
#
# The arm64 binaries MUST be linked against Android's bionic libc: build them
# with the Android NDK clang and keep `-static`. A `aarch64-linux-gnu-gcc
# -static` build is a static *glibc* binary, and glibc registers an rseq area
# during startup with a syscall that Android's seccomp filters answer with
# SIGSYS - the process is killed right away and the shell reports the classic
# "Bad system call". Static bionic (what Magisk's busybox uses) only issues raw
# syscalls and runs in any Android process, ramdisk or app sandbox alike.
#
# bionic also refuses to exec an arm64 binary whose TLS segment is aligned to
# less than 64 bytes ("executable's TLS segment is underaligned"), which is
# what a plain `-static` link produces: see tls_align.c, linked into both.
#
#   make                            -> both targets, static bionic arm64
#   make ANDROID_NDK=/opt/android-ndk
#   make TARGET_CC=/path/to/clang   -> any other bionic/musl cross compiler
#   make check-android              -> refuse glibc / dynamic binaries
#   make check                      -> host selftest of the injector

# --- Android NDK -------------------------------------------------------------
# `nttld/setup-ndk` exports ANDROID_NDK_HOME; other helpers use ANDROID_NDK_ROOT.
ifeq ($(strip $(ANDROID_NDK)),)
ANDROID_NDK := $(strip $(ANDROID_NDK_HOME))
endif
ifeq ($(strip $(ANDROID_NDK)),)
ANDROID_NDK := $(strip $(ANDROID_NDK_ROOT))
endif

NDK_HOST_TAG ?= linux-x86_64
# Kept in sync with androidMinSdkVersion of the manager (Android 8.0).
NDK_API ?= 26
NDK_TRIPLE ?= aarch64-linux-android
NDK_BIN := $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin

TARGET_CC ?= $(NDK_BIN)/$(NDK_TRIPLE)$(NDK_API)-clang
HOST_CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter

ANDROID_BINS = kpinit-android kpramdisk-android
KPRAMDISK_OBJS = kpramdisk.c cpio.c bootimg.c lz4legacy.c
# Linked into both Android binaries: it pins the PT_TLS alignment to 64, which
# arm64 bionic insists on before it will start the program (see tls_align.c).
TLS_ANCHOR = tls_align.c

# A stale path (forgotten ANDROID_NDK) should say so instead of dying inside
# the shell with a bare "No such file or directory".
CHECK_TOOLCHAIN = @command -v "$(TARGET_CC)" >/dev/null 2>&1 || [ -x "$(TARGET_CC)" ] || { \
	echo "error: cannot run $(TARGET_CC)" >&2; \
	echo " set ANDROID_NDK (or ANDROID_NDK_HOME) to an Android NDK, or pass TARGET_CC=<bionic cc>" >&2; \
	exit 1; }

all: $(ANDROID_BINS)

kpinit-android: kpinit.c $(TLS_ANCHOR)
	$(CHECK_TOOLCHAIN)
	$(TARGET_CC) $(CFLAGS) -static -o $@ kpinit.c $(TLS_ANCHOR)
	ls -l $@

kpramdisk-android: $(KPRAMDISK_OBJS) $(TLS_ANCHOR) cpio.h bootimg.h lz4legacy.h
	$(CHECK_TOOLCHAIN)
	$(TARGET_CC) $(CFLAGS) -static -o $@ $(KPRAMDISK_OBJS) $(TLS_ANCHOR)
	ls -l $@

# host build of the injector: lets `make check` exercise the real code
kpramdisk: $(KPRAMDISK_OBJS) cpio.h bootimg.h lz4legacy.h
	$(HOST_CC) $(CFLAGS) -o $@ $(KPRAMDISK_OBJS)

# A glibc build only fails at runtime, as a SIGSYS inside the patcher, so gate
# it at build time: the `GLIBC_` version strings and the `rseq` support are
# glibc-only (bionic has neither), and the first stage ramdisk has no dynamic
# linker for a dynamically linked binary to attach to. The TLS alignment is
# checked here too: a wrong one is rejected by the loader before main() runs,
# so it can only be caught at build time.
check-android: $(ANDROID_BINS)
	@fail=0; \
	for f in $(ANDROID_BINS); do \
	  if strings -a $$f | grep -q 'GLIBC_'; then \
	    echo "$$f: linked against glibc (use the Android NDK bionic toolchain)" >&2; \
	    fail=1; \
	  fi; \
	  if strings -a $$f | grep -qE '^(__)?rseq$$'; then \
	    echo "$$f: has glibc's rseq support, Android kills that with SIGSYS" >&2; \
	    fail=1; \
	  fi; \
	  if readelf -lW $$f 2>/dev/null | grep -q INTERP; then \
	    echo "$$f: is dynamically linked, the first stage ramdisk has no linker" >&2; \
	    fail=1; \
	  fi; \
	  tls=$$(readelf -lW $$f 2>/dev/null | awk '$$1 == "TLS" { print $$NF; exit }'); \
	  if [ -n "$$tls" ] && [ $$((tls)) -lt 64 ]; then \
	    echo "$$f: PT_TLS alignment is $$tls, arm64 bionic needs at least 64" >&2; \
	    echo " (bionic aborts the exec: TLS segment is underaligned)" >&2; \
	    echo " link tls_align.c in, or the patcher will fail at runtime" >&2; \
	    fail=1; \
	  fi; \
	done; \
	if [ $$fail -ne 0 ]; then exit 1; fi; \
	echo "check-android: $(ANDROID_BINS) are static, glibc-free and TLS-aligned"

check: kpramdisk
	./kpramdisk selftest

clean:
	rm -f $(ANDROID_BINS) kpramdisk
	rm -rf .selftest

.PHONY: all check check-android clean
