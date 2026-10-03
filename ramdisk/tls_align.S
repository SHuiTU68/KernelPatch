/* SPDX-License-Identifier: GPL-2.0
 *
 * Anchor the alignment of the PT_TLS segment of the ramdisk helpers to 64.
 *
 * bionic refuses to start an arm64 executable whose TLS segment is aligned to
 * less than 64 bytes:
 *
 *   ./kpramdisk: executable's TLS segment is underaligned: alignment is 8,
 *   needs to be at least 64 for ARM64 Bionic
 *
 * A `-static` bionic link puts one 8-byte thread-local object from libc.a into
 * the TLS segment, and the segment takes the alignment of its largest member
 * (8), so the loader aborts before main() ever runs and the patcher reports a
 * failure on ./kpramdisk instead of on the boot image.
 *
 * The object below raises that alignment to 64. It is written in assembly on
 * purpose: for Android targets clang compiles `_Thread_local` into *emulated*
 * TLS by default, which turns into a plain 32-byte descriptor in the data
 * segment -- it never reaches .tbss, so it silently does not change anything
 * (that is exactly how the first attempt at this fix failed). Being part of
 * the TLS segment directly is independent of the compiler's TLS model and of
 * any toolchain flag, and it also covers the host/gcc style builds.
 *
 * Cost: 64 bytes of zeroed TLS, and the binaries do not grow at all, because
 * .tbss is nobits. Verified with ld.lld: `TLS ... MemSiz 0x40 Align 0x40`.
 * `make check-android` fails the build if the alignment drops below 64 again.
 */
	.section .tbss,"awT",@nobits
	.balign 64
	.globl kp_tls_alignment_anchor
	.type kp_tls_alignment_anchor, %object
kp_tls_alignment_anchor:
	.zero 64
	.size kp_tls_alignment_anchor, 64