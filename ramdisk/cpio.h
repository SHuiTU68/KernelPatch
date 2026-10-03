// SPDX-License-Identifier: GPL-2.0
/*
 * cpio - the "newc" (SVR4, 070701) archive used by every Android ramdisk.
 * Only what a boot ramdisk needs: read everything, then add / replace /
 * rename / remove entries and write it back.  All metadata of existing
 * entries is preserved byte for byte, so a repack is lossless as long as the
 * entry list is not changed.
 */
#ifndef KP_CPIO_H
#define KP_CPIO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *name; /* relative, no leading '/', no trailing '/' */
    unsigned char *data;
    size_t size;

    uint32_t ino, mode, uid, gid, nlink, mtime;
    uint32_t devmajor, devminor, rdevmajor, rdevminor;

    int present; /* entry was produced by the archive (internal use) */
} cpio_entry;

typedef struct {
    cpio_entry *ents;
    size_t count, cap;
    uint32_t next_ino;
} cpio;

/* Archive magic + accessors. */
int cpio_is_newc(const void *buf, size_t size);

/* Parse an uncompressed newc archive.  Returns 0 on success. */
int cpio_parse(const void *buf, size_t size, cpio *out, char *err, size_t errsz);

void cpio_free(cpio *c);

const cpio_entry *cpio_find(const cpio *c, const char *name);
int cpio_exists(const cpio *c, const char *name);

/*
 * Add or replace `name` (regular file).  `data` is copied.  If the entry
 * already existed its metadata is kept and only data/mode are updated.
 */
int cpio_add(cpio *c, const char *name, unsigned int mode, const void *data, size_t size);

/* Rename an existing entry; fails if `from` does not exist. */
int cpio_rename(cpio *c, const char *from, const char *to);

/* Remove an entry (no-op if it does not exist). */
void cpio_remove(cpio *c, const char *name);

/* Serialise back to newc.  Returns the size, 0 on failure. */
size_t cpio_dump(const cpio *c, void **out);

#endif /* KP_CPIO_H */