// SPDX-License-Identifier: GPL-2.0
#include "lz4legacy.h"

#include <stdlib.h>
#include <string.h>

#define HASH_LOG 16
#define HASH_SIZE (1u << HASH_LOG)
#define MIN_MATCH 4
#define MF_LIMIT 12     /* no match may start in the last 12 bytes */
#define LAST_LITERALS 5 /* no match may end in the last 5 bytes */

static uint32_t rd32(const void *p)
{
    uint32_t v;

    memcpy(&v, p, 4);
    return v;
}

static void wr32(void *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

static uint32_t hash4(uint32_t v)
{
    return (v * 2654435761u) >> (32 - HASH_LOG);
}

size_t lz4_legacy_bound(size_t size)
{
    /* 4 (magic) + per block: 4 (size) + size + size/255 + 16 */
    size_t blocks = (size + LZ4_LEGACY_BLOCK - 1) / LZ4_LEGACY_BLOCK;

    if (!blocks)
        blocks = 1;
    return 4 + (size + size / 255 + 64) * blocks;
}

int lz4_legacy_is_stream(const void *in, size_t size)
{
    return size >= 4 && rd32(in) == LZ4_LEGACY_MAGIC;
}

/* Greedy LZ4 block compressor (one candidate per hash slot, 64 KiB window). */
static size_t compress_block(const uint8_t *in, size_t size, uint8_t *out)
{
    const uint8_t *ip = in, *anchor = in, *iend = in + size;
    const uint8_t *mflimit, *matchlimit;
    const uint8_t **table;
    uint8_t *op = out;

    if (size < MF_LIMIT) { /* too small to hold a match */
        if (size >= 15) {
            size_t l = size - 15;

            *op++ = 15 << 4;
            while (l >= 255) {
                *op++ = 255;
                l -= 255;
            }
            *op++ = (uint8_t)l;
        } else {
            *op++ = (uint8_t)(size << 4);
        }
        memcpy(op, in, size);
        return (size_t)(op - out) + size;
    }

    table = malloc(HASH_SIZE * sizeof(*table));
    if (!table)
        return 0;
    memset(table, 0, HASH_SIZE * sizeof(*table));

    mflimit = iend - MF_LIMIT;
    matchlimit = iend - LAST_LITERALS;

    while (ip < mflimit) {
        uint32_t h = hash4(rd32(ip));
        const uint8_t *ref = table[h];

        table[h] = ip;
        if (!ref || (size_t)(ip - ref) > 65535 || rd32(ref) != rd32(ip)) {
            ip++;
            continue;
        }

        /* extend the match backwards into the pending literals */
        while (ip > anchor && ref > in && ip[-1] == ref[-1]) {
            ip--;
            ref--;
        }

        {
            const uint8_t *m = ip + MIN_MATCH, *r = ref + MIN_MATCH;
            size_t lit = (size_t)(ip - anchor), mlen;
            uint8_t *token = op++;
            uint16_t off;

            while (m < matchlimit && *m == *r) {
                m++;
                r++;
            }
            mlen = (size_t)(m - ip) - MIN_MATCH;

            if (lit >= 15) {
                size_t l = lit - 15;

                *token = 15 << 4;
                while (l >= 255) {
                    *op++ = 255;
                    l -= 255;
                }
                *op++ = (uint8_t)l;
            } else {
                *token = (uint8_t)(lit << 4);
            }
            memcpy(op, anchor, lit);
            op += lit;

            off = (uint16_t)(ip - ref);
            memcpy(op, &off, 2);
            op += 2;

            if (mlen >= 15) {
                size_t l = mlen - 15;

                *token |= 15;
                while (l >= 255) {
                    *op++ = 255;
                    l -= 255;
                }
                *op++ = (uint8_t)l;
            } else {
                *token |= (uint8_t)mlen;
            }
            ip = m;
            anchor = ip;
        }
    }

    /* trailing literals - always present, the format requires them */
    {
        size_t lit = (size_t)(iend - anchor);

        if (lit >= 15) {
            size_t l = lit - 15;

            *op++ = 15 << 4;
            while (l >= 255) {
                *op++ = 255;
                l -= 255;
            }
            *op++ = (uint8_t)l;
        } else {
            *op++ = (uint8_t)(lit << 4);
        }
        memcpy(op, anchor, lit);
        op += lit;
    }

    free(table);
    return (size_t)(op - out);
}

size_t lz4_legacy_compress(const void *in, size_t size, unsigned char **out)
{
    const uint8_t *src = in;
    uint8_t *dst;
    size_t bound = lz4_legacy_bound(size), off_in = 0, off_out = 4;

    dst = malloc(bound ? bound : 1);
    if (!dst)
        return 0;
    wr32(dst, LZ4_LEGACY_MAGIC);

    do {
        size_t chunk = size - off_in;
        size_t comp;

        if (chunk > LZ4_LEGACY_BLOCK)
            chunk = LZ4_LEGACY_BLOCK;
        comp = compress_block(src + off_in, chunk, dst + off_out + 4);
        if (!comp) {
            free(dst);
            return 0;
        }
        wr32(dst + off_out, (uint32_t)comp);
        off_out += 4 + comp;
        off_in += chunk;
    } while (off_in < size);

    *out = dst;
    return off_out;
}

static int decompress_block(const uint8_t *ip, const uint8_t *iend, uint8_t *op, uint8_t *oend,
                            size_t *out_len)
{
    const uint8_t *ostart = op;

    while (ip < iend) {
        unsigned token = *ip++;
        size_t lit = token >> 4, mlen, off;
        const uint8_t *m;

        if (lit == 15) {
            unsigned s;

            do {
                if (ip >= iend)
                    return -1;
                s = *ip++;
                lit += s;
            } while (s == 255);
        }
        if ((size_t)(iend - ip) < lit || (size_t)(oend - op) < lit)
            return -1;
        memcpy(op, ip, lit);
        ip += lit;
        op += lit;

        if (ip >= iend) /* last sequence: literals only */
            break;
        if ((size_t)(iend - ip) < 2)
            return -1;
        off = (size_t)ip[0] | ((size_t)ip[1] << 8);
        ip += 2;

        mlen = token & 0xF;
        if (mlen == 15) {
            unsigned s;

            do {
                if (ip >= iend)
                    return -1;
                s = *ip++;
                mlen += s;
            } while (s == 255);
        }
        mlen += MIN_MATCH;

        if (!off || off > (size_t)(op - ostart) || (size_t)(oend - op) < mlen)
            return -1;
        m = op - off;
        while (mlen--)
            *op++ = *m++;
    }
    *out_len = (size_t)(op - ostart);
    return 0;
}

int lz4_legacy_decompress(const void *in, size_t size, unsigned char **out, size_t *out_size)
{
    const uint8_t *ip = in, *iend = (const uint8_t *)in + size;
    uint8_t *buf = NULL;
    size_t cap = 0, used = 0;

    if (!lz4_legacy_is_stream(in, size))
        return -1;
    ip += 4;

    while ((size_t)(iend - ip) >= 4) {
        uint32_t comp = rd32(ip);
        size_t got = 0;

        ip += 4;
        if (!comp || (size_t)(iend - ip) < comp)
            break; /* zero terminator or trailing padding */

        if (used + LZ4_LEGACY_BLOCK > cap) {
            size_t ncap = cap ? cap + LZ4_LEGACY_BLOCK : 4 * LZ4_LEGACY_BLOCK;
            uint8_t *nb = realloc(buf, ncap);

            if (!nb) {
                free(buf);
                return -1;
            }
            buf = nb;
            cap = ncap;
        }
        if (decompress_block(ip, ip + comp, buf + used, buf + used + LZ4_LEGACY_BLOCK, &got) != 0) {
            free(buf);
            return -1;
        }
        used += got;
        ip += comp;
    }

    if (!buf) {
        buf = malloc(1);
        if (!buf)
            return -1;
    }
    *out = buf;
    *out_size = used;
    return 0;
}