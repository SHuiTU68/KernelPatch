// SPDX-License-Identifier: GPL-2.0
/*
 * lz4legacy - LZ4 "legacy" stream codec, the format Android boot images use
 * for their ramdisk (`magic 0x184C2102`, then blocks of
 * <uint32 le compressed size><compressed data>, each block decoding to at
 * most 8 MiB).
 *
 * Self contained on purpose: kpramdisk has to run as a static binary both on
 * the host and inside APatch, so it cannot depend on liblz4 being present.
 * The compressor is LZ4_compress_default's greedy scheme (single candidate
 * hash table, 64 KiB window, offsets are 16 bit).
 */
#ifndef KP_LZ4LEGACY_H
#define KP_LZ4LEGACY_H

#include <stddef.h>
#include <stdint.h>

#define LZ4_LEGACY_MAGIC 0x184C2102u
#define LZ4_LEGACY_BLOCK (8u * 1024u * 1024u)

/* Worst case stream size for `size` input bytes. */
size_t lz4_legacy_bound(size_t size);

/*
 * Encode `size` bytes into a fresh legacy stream (malloc'ed, caller frees).
 * Returns the stream length, or 0 on allocation failure.
 */
size_t lz4_legacy_compress(const void *in, size_t size, unsigned char **out);

/*
 * Does `in` look like a legacy LZ4 stream?
 */
int lz4_legacy_is_stream(const void *in, size_t size);

/*
 * Decode a legacy stream.  A buffer of *out_size bytes is malloc'ed and the
 * real length is stored in *out_size.  Returns 0 on success, negative on a
 * malformed stream / allocation failure.  Trailing garbage (page padding) is
 * tolerated.
 */
int lz4_legacy_decompress(const void *in, size_t size, unsigned char **out, size_t *out_size);

#endif /* KP_LZ4LEGACY_H */
