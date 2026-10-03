// SPDX-License-Identifier: GPL-2.0
#include "cpio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NEWC_MAGIC "070701"
#define HDR_LEN 110
#define NAME_TRAILER "TRAILER!!!"

static uint32_t align4(uint32_t v)
{
    return (v + 3u) & ~3u;
}

int cpio_is_newc(const void *buf, size_t size)
{
    return size >= 6 && memcmp(buf, NEWC_MAGIC, 6) == 0;
}

static int hex8(const char *p, uint32_t *out)
{
    uint32_t v = 0;
    int i;

    for (i = 0; i < 8; i++) {
        char c = p[i];

        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (uint32_t)(c - 'A' + 10);
        else
            return -1;
    }
    *out = v;
    return 0;
}

static int cpio_entry_push(cpio *c, cpio_entry **slot)
{
    if (c->count == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 64;
        cpio_entry *n = realloc(c->ents, ncap * sizeof(*n));

        if (!n)
            return -1;
        c->ents = n;
        c->cap = ncap;
    }
    *slot = &c->ents[c->count++];
    memset(*slot, 0, sizeof(**slot));
    return 0;
}

int cpio_parse(const void *buf, size_t size, cpio *out, char *err, size_t errsz)
{
    const unsigned char *p = buf;
    size_t off = 0;

    memset(out, 0, sizeof(*out));
    if (!cpio_is_newc(buf, size)) {
        snprintf(err, errsz, "not a newc archive");
        return -1;
    }

    for (;;) {
        uint32_t f[13];
        cpio_entry *e;
        size_t name_len, file_size;

        if (off + HDR_LEN > size) {
            snprintf(err, errsz, "truncated header at %zu", off);
            goto fail;
        }
        if (memcmp(p + off, NEWC_MAGIC, 6) != 0) {
            snprintf(err, errsz, "bad magic at %zu", off);
            goto fail;
        }
        for (int i = 0; i < 13; i++) {
            if (hex8((const char *)p + off + 6 + i * 8, &f[i]) != 0) {
                snprintf(err, errsz, "bad hex field %d at %zu", i, off);
                goto fail;
            }
        }
        name_len = f[11];
        file_size = f[6];
        if (!name_len || off + HDR_LEN + name_len > size) {
            snprintf(err, errsz, "truncated name at %zu", off);
            goto fail;
        }
        if (memcmp(p + off + HDR_LEN, NAME_TRAILER, sizeof(NAME_TRAILER) - 1) == 0)
            break; /* trailer reached; everything after it is padding */

        if (cpio_entry_push(out, &e) != 0) {
            snprintf(err, errsz, "out of memory");
            goto fail;
        }
        e->name = strndup((const char *)p + off + HDR_LEN, name_len);
        if (!e->name) {
            snprintf(err, errsz, "out of memory");
            goto fail;
        }
        e->ino = f[0];
        e->mode = f[1];
        e->uid = f[2];
        e->gid = f[3];
        e->nlink = f[4];
        e->mtime = f[5];
        e->devmajor = f[7];
        e->devminor = f[8];
        e->rdevmajor = f[9];
        e->rdevminor = f[10];
        e->size = file_size;

        off += HDR_LEN + name_len;
        off = align4((uint32_t)off);
        if (off + file_size > size) {
            snprintf(err, errsz, "truncated data for %s", e->name);
            goto fail;
        }
        if (file_size) {
            e->data = malloc(file_size);
            if (!e->data) {
                snprintf(err, errsz, "out of memory");
                goto fail;
            }
            memcpy(e->data, p + off, file_size);
        }
        off = align4((uint32_t)(off + file_size));
        if (e->ino >= out->next_ino)
            out->next_ino = e->ino + 1;
    }

    if (!out->count) {
        snprintf(err, errsz, "empty archive");
        goto fail;
    }
    return 0;

fail:
    cpio_free(out);
    return -1;
}

void cpio_free(cpio *c)
{
    size_t i;

    for (i = 0; i < c->count; i++) {
        free(c->ents[i].name);
        free(c->ents[i].data);
    }
    free(c->ents);
    memset(c, 0, sizeof(*c));
}

const cpio_entry *cpio_find(const cpio *c, const char *name)
{
    size_t i;

    for (i = 0; i < c->count; i++) {
        if (strcmp(c->ents[i].name, name) == 0)
            return &c->ents[i];
    }
    return NULL;
}

int cpio_exists(const cpio *c, const char *name)
{
    return cpio_find(c, name) != NULL;
}

int cpio_add(cpio *c, const char *name, unsigned int mode, const void *data, size_t size)
{
    cpio_entry *e = (cpio_entry *)cpio_find(c, name);
    unsigned char *copy = NULL;

    if (size) {
        copy = malloc(size);
        if (!copy)
            return -1;
        memcpy(copy, data, size);
    }
    if (!e) {
        if (cpio_entry_push(c, &e) != 0) {
            free(copy);
            return -1;
        }
        e->name = strdup(name);
        if (!e->name) {
            c->count--;
            free(copy);
            return -1;
        }
        e->ino = c->next_ino++;
        e->mode = (uint32_t)mode;
        e->nlink = 1;
        e->mtime = 0;
        e->uid = e->gid = 0;
    } else {
        e->mode = (uint32_t)mode;
    }
    free(e->data);
    e->data = copy;
    e->size = size;
    return 0;
}

int cpio_rename(cpio *c, const char *from, const char *to)
{
    cpio_entry *e = (cpio_entry *)cpio_find(c, from);
    char *n;

    if (!e)
        return -1;
    n = strdup(to);
    if (!n)
        return -1;
    free(e->name);
    e->name = n;
    return 0;
}

void cpio_remove(cpio *c, const char *name)
{
    size_t i;

    for (i = 0; i < c->count; i++) {
        if (strcmp(c->ents[i].name, name) != 0)
            continue;
        free(c->ents[i].name);
        free(c->ents[i].data);
        memmove(&c->ents[i], &c->ents[i + 1], (c->count - i - 1) * sizeof(*c->ents));
        c->count--;
        return;
    }
}

static void put_hex(void *dst, uint32_t v)
{
    static const char h[] = "0123456789ABCDEF";
    char *p = dst;
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = h[v & 0xF];
        v >>= 4;
    }
}

size_t cpio_dump(const cpio *c, void **out)
{
    size_t total = 0, off = 0, i;
    unsigned char *buf;

    /* header + name + padding + data + padding, for every entry */
    for (i = 0; i < c->count; i++) {
        total += HDR_LEN;
        total += strlen(c->ents[i].name) + 1;
        total = align4((uint32_t)total);
        total += c->ents[i].size;
        total = align4((uint32_t)total);
    }
    total += HDR_LEN + sizeof(NAME_TRAILER); /* trailer, includes its NUL */
    total = align4((uint32_t)total);

    buf = calloc(1, total);
    if (!buf)
        return 0;

    for (i = 0; i < c->count; i++) {
        const cpio_entry *e = &c->ents[i];
        size_t name_len = strlen(e->name) + 1;
        unsigned char *h = buf + off;
        uint32_t fs = (uint32_t)e->size;

        memcpy(h, NEWC_MAGIC, 6);
        put_hex(h + 6 + 0 * 8, e->ino);
        put_hex(h + 6 + 1 * 8, e->mode);
        put_hex(h + 6 + 2 * 8, e->uid);
        put_hex(h + 6 + 3 * 8, e->gid);
        put_hex(h + 6 + 4 * 8, e->nlink);
        put_hex(h + 6 + 5 * 8, e->mtime);
        put_hex(h + 6 + 6 * 8, fs);
        put_hex(h + 6 + 7 * 8, e->devmajor);
        put_hex(h + 6 + 8 * 8, e->devminor);
        put_hex(h + 6 + 9 * 8, e->rdevmajor);
        put_hex(h + 6 + 10 * 8, e->rdevminor);
        put_hex(h + 6 + 11 * 8, (uint32_t)name_len);
        put_hex(h + 6 + 12 * 8, 0);
        memcpy(h + HDR_LEN, e->name, name_len);
        off = align4((uint32_t)(off + HDR_LEN + name_len));
        if (fs) {
            memcpy(buf + off, e->data, fs);
            off = align4((uint32_t)(off + fs));
        }
    }

    {
        unsigned char *h = buf + off;

        memcpy(h, NEWC_MAGIC, 6);
        put_hex(h + 6 + 0 * 8, 0);
        put_hex(h + 6 + 1 * 8, 0);
        put_hex(h + 6 + 2 * 8, 0);
        put_hex(h + 6 + 3 * 8, 0);
        put_hex(h + 6 + 4 * 8, 1);
        put_hex(h + 6 + 5 * 8, 0);
        put_hex(h + 6 + 6 * 8, 0);
        put_hex(h + 6 + 7 * 8, 0);
        put_hex(h + 6 + 8 * 8, 0);
        put_hex(h + 6 + 9 * 8, 0);
        put_hex(h + 6 + 10 * 8, 0);
        put_hex(h + 6 + 11 * 8, sizeof(NAME_TRAILER));
        put_hex(h + 6 + 12 * 8, 0);
        memcpy(h + HDR_LEN, NAME_TRAILER, sizeof(NAME_TRAILER));
        off = align4((uint32_t)(off + HDR_LEN + sizeof(NAME_TRAILER)));
    }

    *out = buf;
    return off < total ? total : off;
}