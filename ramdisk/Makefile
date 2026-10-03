# SPDX-License-Identifier: GPL-2.0
#
# Builds `kpinit`, the ramdisk boot hook that loads the KernelPatch LKM
# (see kpinit.c).  The resulting binary is published as the `kpinit-android`
# release asset so that APatch can inject it into an init_boot/boot ramdisk.
#
#   make                     -> ramdisk/kpinit-android (static arm64)
#   make TARGET_CC=clang     -> use any cross compiler
TARGET_CC ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter

all: kpinit-android

kpinit-android: kpinit.c
	$(TARGET_CC) $(CFLAGS) -static -o $@ $<
	ls -l $@

clean:
	rm -f kpinit-android

.PHONY: all clean
