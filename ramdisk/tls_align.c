// SPDX-License-Identifier: GPL-2.0
/*
 * Anchor the alignment of the PT_TLS segment of the ramdisk helpers.
 *
 * Bionic refuses to start an arm64 executable whose TLS segment is aligned to
 * less than 64 bytes:
 *
 *   ./kpramdisk: executable's TLS segment is underaligned: alignment is 8,
 *   needs to be at least 64 for ARM64 Bionic
 *
 * A `-static` bionic link pulls exactly one 8-byte TLS variable (bionic's
 * per-thread globals) out of libc.a, and the linker takes the alignment of the
 * TLS segment from the largest alignment of the TLS input sections -- 8. The
 * loader then aborts before `main` is reached, which is what the manager shows
 * as the ramdisk patcher failing.
 *
 * Defining one 64-byte aligned thread-local object raises that maximum to 64,
 * so the linker emits `TLS ... Align 0x40` and the program can start. It costs
 * 64 bytes of zeroed TLS (the object is zero-initialised, so it lives in .tbss
 * and does not grow the file at all).
 *
 * This is deliberately not a linker flag: there is no portable one, and making
 * it part of the link input keeps the requirement visible in the sources.
 * `make check-android` asserts the result.
 */
#include <stdint.h>

#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define KP_TLS_KEEP __attribute__((retain))
#  endif
#endif
#ifndef KP_TLS_KEEP
#  define KP_TLS_KEEP
#endif

__attribute__((used, aligned(64))) KP_TLS_KEEP
_Thread_local unsigned char kp_tls_alignment_anchor[64];
