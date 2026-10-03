// SPDX-License-Identifier: GPL-2.0
#include "bootimg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AVB_FOOTER_SIZE 64
#define AVB_MAGIC "AVB0"
#define AVB_FOOTER_MAGIC "AVBf"

static uint32_t rd_le32(const void *p)
{
    const unsigned char *b = p;

    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void wr_le32(void *p, uint32_t v)
{
    unsigned char *b = p;

    b[0] = (unsigned char)(v & 0xFF);
    b[1] = (unsigned char)((v >> 8) & 0xFF);
    b[2] = (unsigned char)((v >> 16) & 0xFF);
    b[3] = (unsigned char)((v >> 24) & 0xFF);
}

static uint64_t rd_be64(const void *p)
{
    const unsigned char *b = p;
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++)
        v = (v << 8) | b[i];
    return v;
}

static void wr_be64(void *p, uint64_t v)
{
    unsigned char *b = p;
    int i;

    for (i = 7; i >= 0; i--) {
        b[i] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
}

static size_t align_to(size_t v, size_t a)
{
    return a ? (v + a - 1) / a * a : v;
}

void bootimg_free(bootimg *img)
{
    free(img->data);
    memset(img, 0, sizeof(*img));
}

int bootimg_load(const char *path, bootimg *img)
{
    FILE *f = fopen(path, "rb");
    long len;

    memset(img, 0, sizeof(*img));
    if (!f) {
        snprintf(img->err, sizeof(img->err), "cannot open %s", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) <= 0) {
        snprintf(img->err, sizeof(img->err), "cannot size %s", path);
        fclose(f);
        return -1;
    }
    rewind(f);
    img->data = malloc((size_t)len);
    if (!img->data) {
        snprintf(img->err, sizeof(img->err), "out of memory (%ld bytes)", len);
        fclose(f);
        return -1;
    }
    if (fread(img->data, 1, (size_t)len, f) != (size_t)len) {
        snprintf(img->err, sizeof(img->err), "short read on %s", path);
        fclose(f);
        bootimg_free(img);
        return -1;
    }
    fclose(f);
    img->size = (size_t)len;

    if (img->size < 4096 || memcmp(img->data, BOOT_MAGIC, 8) != 0) {
        snprintf(img->err, sizeof(img->err), "%.200s is not an Android boot image", path);
        bootimg_free(img);
        return -1;
    }

    img->header_version = rd_le32(img->data + 40);
    img->kernel_size = rd_le32(img->data + 8);
    img->header_block = img->header_version >= 3 ? 4096 : 0;
    if (img->header_version >= 3) {
        img->page_size = 4096;
        img->ramdisk_size = rd_le32(img->data + 12);
    } else if (img->header_version <= 2) {
        img->page_size = rd_le32(img->data + 36);
        img->ramdisk_size = rd_le32(img->data + 16);
        img->header_block = img->page_size;
        if (img->page_size < 512 || img->page_size > 65536) {
            snprintf(img->err, sizeof(img->err), "bogus page size %u", img->page_size);
            bootimg_free(img);
            return -1;
        }
    } else {
        snprintf(img->err, sizeof(img->err), "unsupported header version %u", img->header_version);
        bootimg_free(img);
        return -1;
    }

    img->kernel_off = img->header_block;
    img->ramdisk_off = img->kernel_off + align_to(img->kernel_size, img->page_size);
    if (!img->ramdisk_size ||
        img->ramdisk_off + img->ramdisk_size > img->size) {
        snprintf(img->err, sizeof(img->err),
                 "ramdisk out of range (off %zu size %u image %zu)", img->ramdisk_off,
                 img->ramdisk_size, img->size);
        bootimg_free(img);
        return -1;
    }

    /* An AVB footer (big endian) at the very end points at the vbmeta struct. */
    if (img->size > AVB_FOOTER_SIZE + 4096) {
        const unsigned char *ft = img->data + img->size - AVB_FOOTER_SIZE;

        if (memcmp(ft, AVB_FOOTER_MAGIC, 4) == 0) {
            /* magic[4] major[4] minor[4] original_image_size[8] vbmeta_offset[8]
             * vbmeta_size[8] reserved[28] - all big endian */
            uint64_t off = rd_be64(ft + 20), sz = rd_be64(ft + 28);

            if (off + sz <= img->size && sz && memcmp(img->data + off, AVB_MAGIC, 4) == 0) {
                img->has_avb = 1;
                img->avb_off = off;
                img->avb_size = sz;
            }
        }
    }
    return 0;
}

const unsigned char *bootimg_ramdisk(const bootimg *img, size_t *size)
{
    *size = img->ramdisk_size;
    return img->data + img->ramdisk_off;
}

size_t bootimg_ramdisk_padded_end(const bootimg *img)
{
    return img->ramdisk_off + align_to(img->ramdisk_size, img->page_size);
}

int bootimg_write(bootimg *img, const void *ramdisk, size_t size, const char *path)
{
    size_t page = img->page_size;
    size_t ramdisk_end = img->ramdisk_off + align_to(size, page);
    size_t tail_off_old = bootimg_ramdisk_padded_end(img);
    size_t total, avb_at = 0, out = 0;
    unsigned char *buf;
    FILE *f;

    if (ramdisk_end < img->ramdisk_off) {
        snprintf(img->err, sizeof(img->err), "ramdisk too large");
        return -1;
    }

    if (img->header_version >= 3) {
        /* keep the dumped partition size when everything still fits into it,
         * otherwise grow to the next page boundary behind the AVB block */
        total = img->size;
        if (ramdisk_end + (img->has_avb ? img->avb_size : 0) + (img->has_avb ? AVB_FOOTER_SIZE : 0) + page > total)
            total = align_to(ramdisk_end + (img->has_avb ? img->avb_size + AVB_FOOTER_SIZE : 0) + page, page);
    } else {
        /* v0..v2: second stage / dtbo / dtb follow the ramdisk back to back,
         * no absolute offsets to fix up - just move the whole tail */
        total = ramdisk_end + (img->size - tail_off_old);
    }
    if (total < ramdisk_end) {
        snprintf(img->err, sizeof(img->err), "patched image would overflow");
        return -1;
    }

    buf = calloc(1, total);
    if (!buf) {
        snprintf(img->err, sizeof(img->err), "out of memory (%zu bytes)", total);
        return -1;
    }

    /* header: same bytes, new ramdisk size */
    memcpy(buf, img->data, img->header_block);
    wr_le32(buf + (img->header_version >= 3 ? 12 : 16), (uint32_t)size);
    out = img->header_block;

    /* kernel (may be empty on init_boot) */
    memcpy(buf + out, img->data + img->kernel_off, img->kernel_size);
    out += align_to(img->kernel_size, page);

    /* the new ramdisk */
    memcpy(buf + out, ramdisk, size);
    out = ramdisk_end;

    if (img->header_version >= 3) {
        if (img->has_avb) {
            avb_at = out;
            memcpy(buf + avb_at, img->data + img->avb_off, img->avb_size);
            /* footer: same bytes, new payload size + new vbmeta offset */
            memcpy(buf + total - AVB_FOOTER_SIZE, img->data + img->size - AVB_FOOTER_SIZE,
                   AVB_FOOTER_SIZE);
            wr_be64(buf + total - AVB_FOOTER_SIZE + 12, (uint64_t)avb_at);
            wr_be64(buf + total - AVB_FOOTER_SIZE + 20, (uint64_t)avb_at);
        }
    } else {
        memcpy(buf + out, img->data + tail_off_old, img->size - tail_off_old);
    }

    f = fopen(path, "wb");
    if (!f) {
        snprintf(img->err, sizeof(img->err), "cannot write %s", path);
        free(buf);
        return -1;
    }
    if (fwrite(buf, 1, total, f) != total) {
        snprintf(img->err, sizeof(img->err), "short write on %s", path);
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);
    free(buf);
    return 0;
}