// SPDX-License-Identifier: GPL-2.0
/*
 * bootimg - Android boot image (v0 .. v4) ramdisk surgery.
 *
 * Only the ramdisk is rewritten; the kernel / second stage / dtb sections are
 * copied verbatim.  A trailing AVB block (vbmeta struct + footer, as found in
 * dumped partitions) is preserved: the struct is re-aligned behind the new
 * ramdisk and the footer's vbmeta_offset / original_image_size are updated,
 * but the signature itself cannot be recomputed - the patched partition needs
 * verified boot disabled, exactly like a KernelSU/Magisk patched one.
 */
#ifndef KP_BOOTIMG_H
#define KP_BOOTIMG_H

#include <stddef.h>
#include <stdint.h>

#define BOOT_MAGIC "ANDROID!"

typedef struct {
    unsigned char *data;
    size_t size;

    uint32_t header_version;
    uint32_t page_size;
    uint32_t kernel_size;
    uint32_t ramdisk_size;

    size_t header_block;
    size_t kernel_off;
    size_t ramdisk_off;

    int has_avb;
    uint64_t avb_off;
    uint64_t avb_size;

    char err[256];
} bootimg;

int bootimg_load(const char *path, bootimg *img);
void bootimg_free(bootimg *img);

/* Raw (still compressed) ramdisk blob. */
const unsigned char *bootimg_ramdisk(const bootimg *img, size_t *size);

/* Where the section after the padded ramdisk starts. */
size_t bootimg_ramdisk_padded_end(const bootimg *img);

/*
 * Write `img` to `path` with the ramdisk replaced by `ramdisk`/`size`.
 * Returns 0 on success.
 */
int bootimg_write(bootimg *img, const void *ramdisk, size_t size, const char *path);

#endif /* KP_BOOTIMG_H */