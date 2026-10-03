# SPDX-License-Identifier: GPL-2.0
#
# Builds `kpinit`, the ramdisk boot hook that loads the KernelPatch LKM
# (see kpinit.c).  The resulting binary is published as the `kpinit-android`
# release asset so that APatch can inject it into an init_boot/boot ramdisk.
#
#   make                     -> ramdisk/kpinit-android (static arm64)
#   make TARGET_CC=clang     -> use any cross compiler
TARGET_CC ?= aarch64-linux-gnu-gcc
HOST_CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter

KPRAMDISK_OBJS = kpramdisk.c cpio.c bootimg.c lz4legacy.c

all: kpinit-android kpramdisk-android

kpinit-android: kpinit.c
	$(TARGET_CC) $(CFLAGS) -static -o $@ $<
	ls -l $@

kpramdisk-android: $(KPRAMDISK_OBJS) cpio.h bootimg.h lz4legacy.h
	$(TARGET_CC) $(CFLAGS) -static -o $@ $(KPRAMDISK_OBJS)
	ls -l $@

# host build of the injector: lets `make check` exercise the real code
kpramdisk: $(KPRAMDISK_OBJS) cpio.h bootimg.h lz4legacy.h
	$(HOST_CC) $(CFLAGS) -o $@ $(KPRAMDISK_OBJS)

check: kpramdisk
	./kpramdisk selftest

clean:
	rm -f kpinit-android kpramdisk-android kpramdisk
	rm -rf .selftest

.PHONY: all check clean
