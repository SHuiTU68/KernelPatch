// SPDX-License-Identifier: GPL-2.0
/*
 * kpramdisk - inject the KernelPatch ramdisk hook into an Android boot image.
 *
 * This is the KernelPatch equivalent of KernelSU's `ksud boot_patch`
 * (userspace/ksud/src/boot_patch.rs, GPL-2.0, tiann/KernelSU): it rewrites the
 * ramdisk cpio of init_boot.img (or boot.img) exactly like KernelSU does for
 * kernelsu.ko, only with kpinit/kernelpatch.ko instead:
 *
 *   cpio.mv("init", "init.real")      # keep the stock first stage init
 *   cpio.add("init", kpinit, 0755)    # becomes PID 1, loads the module
 *   cpio.add("kernelpatch.ko", <kmi>_kernelpatch.ko, 0755)
 *   cpio.add("kp_config", <params>, 0644)   # optional
 *
 * The kernel, second stage, dtb and the trailing AVB block are copied as is;
 * only the ramdisk section is re-encoded (lz4_legacy or uncompressed, gzip
 * ramdisks are not supported yet).
 *
 * Usage:
 *   kpramdisk info   <boot.img>
 *   kpramdisk list   <boot.img>
 *   kpramdisk inject <boot.img> <out.img> --init <kpinit> --ko <kernelpatch.ko>
 *                    [--params "key=value,key2=value2" | --config <file>]
 *                    [--force]
 */
#include "bootimg.h"
#include "cpio.h"
#include "lz4legacy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define VER "1.0.0"

#define INIT_ENTRY "init"
#define INIT_REAL_ENTRY "init.real"
#define KO_ENTRY "kernelpatch.ko"
#define CONFIG_ENTRY "kp_config"

static unsigned char *read_file(const char *path, size_t *size, char *err, size_t errsz)
{
    FILE *f = fopen(path, "rb");
    long len;
    unsigned char *buf;

    if (!f) {
        snprintf(err, errsz, "cannot open %s", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) <= 0) {
        snprintf(err, errsz, "%s is empty", path);
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t)len);
    if (!buf) {
        snprintf(err, errsz, "out of memory");
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        snprintf(err, errsz, "short read on %s", path);
        fclose(f);
        free(buf);
        return NULL;
    }
    fclose(f);
    *size = (size_t)len;
    return buf;
}

/* The ramdisk as a cpio archive, whatever it was compressed with. */
static int ramdisk_cpio(const bootimg *img, unsigned char **cpio_out, size_t *cpio_size,
                        int *was_lz4, char *err, size_t errsz)
{
    const unsigned char *raw;
    size_t raw_size;

    raw = bootimg_ramdisk(img, &raw_size);
    *was_lz4 = 0;
    *cpio_out = NULL;
    *cpio_size = 0;

    if (lz4_legacy_is_stream(raw, raw_size)) {
        unsigned char *dec = NULL;
        size_t dec_size = 0;

        if (lz4_legacy_decompress(raw, raw_size, &dec, &dec_size) != 0) {
            snprintf(err, errsz, "cannot decompress the lz4 ramdisk");
            return -1;
        }
        *was_lz4 = 1;
        *cpio_out = dec;
        *cpio_size = dec_size;
    } else if (cpio_is_newc(raw, raw_size)) {
        unsigned char *copy = malloc(raw_size);

        if (!copy) {
            snprintf(err, errsz, "out of memory");
            return -1;
        }
        memcpy(copy, raw, raw_size);
        *cpio_out = copy;
        *cpio_size = raw_size;
    } else if (raw_size > 2 && raw[0] == 0x1F && raw[1] == 0x8B) {
        snprintf(err, errsz, "gzip ramdisks are not supported yet (only lz4_legacy / raw)");
        return -1;
    } else {
        snprintf(err, errsz, "unknown ramdisk compression (%02x %02x %02x %02x)", raw[0], raw[1],
                 raw[2], raw[3]);
        return -1;
    }
    return 0;
}

static int cmd_info(const char *path)
{
    bootimg img;

    if (bootimg_load(path, &img) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", img.err);
        return 1;
    }
    printf("boot image      : %s\n", path);
    printf("size            : %zu bytes\n", img.size);
    printf("header version  : %u\n", img.header_version);
    printf("page size       : %u\n", img.page_size);
    printf("kernel          : %u bytes @ %zu\n", img.kernel_size, img.kernel_off);
    printf("ramdisk         : %u bytes @ %zu (padded end %zu)\n", img.ramdisk_size,
           img.ramdisk_off, bootimg_ramdisk_padded_end(&img));
    printf("avb block       : %s", img.has_avb ? "yes" : "no");
    if (img.has_avb)
        printf(" (%llu bytes @ %llu)", (unsigned long long)img.avb_size,
               (unsigned long long)img.avb_off);
    printf("\n");
    bootimg_free(&img);
    return 0;
}

static int cmd_list(const char *path)
{
    bootimg img;
    unsigned char *buf = NULL;
    size_t size = 0;
    cpio c;
    char err[256];
    int lz4 = 0;
    size_t i;

    if (bootimg_load(path, &img) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", img.err);
        return 1;
    }
    if (ramdisk_cpio(&img, &buf, &size, &lz4, err, sizeof(err)) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", err);
        bootimg_free(&img);
        return 1;
    }
    if (cpio_parse(buf, size, &c, err, sizeof(err)) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", err);
        free(buf);
        bootimg_free(&img);
        return 1;
    }
    printf("%s: %zu entries (%s, %zu bytes uncompressed)\n", path, c.count,
           lz4 ? "lz4_legacy" : "raw", size);
    for (i = 0; i < c.count; i++) {
        const cpio_entry *e = &c.ents[i];
        char type = (e->mode & 0170000) == 0040000 ? 'd'
                    : (e->mode & 0170000) == 0120000 ? 'l'
                                                     : '-';

        printf("  %c %06o %8zu  %s%s%s\n", type, e->mode & 07777, e->size, e->name,
               type == 'l' ? " -> " : "", type == 'l' && e->size ? (char *)e->data : "");
    }
    cpio_free(&c);
    free(buf);
    bootimg_free(&img);
    return 0;
}

static void usage(FILE *out)
{
    fprintf(out,
            "kpramdisk " VER " - KernelPatch ramdisk injector (KernelSU boot_patch equivalent)\n"
            "\n"
            "Usage:\n"
            "  kpramdisk info   <boot.img>\n"
            "  kpramdisk list   <boot.img>\n"
            "  kpramdisk inject <boot.img> <out.img> --init <kpinit> --ko <kernelpatch.ko>\n"
            "                   [--params \"k=v,k2=v2\" | --config <file>] [--force]\n"
            "\n"
            "--init is the kpinit binary (release asset `kpinit-android`), --ko the\n"
            "KernelPatch LKM matching the device KMI (e.g. android15-6.6_kernelpatch.ko).\n");
}

static int cmd_inject(int argc, char **argv)
{
    const char *in = NULL, *out = NULL, *init_path = NULL, *ko_path = NULL, *cfg_path = NULL;
    const char *params = NULL;
    int force = 0;
    bootimg img;
    unsigned char *cpio_buf = NULL, *init_bin = NULL, *ko_bin = NULL, *cfg_bin = NULL;
    size_t cpio_size = 0, init_size = 0, ko_size = 0, cfg_size = 0;
    cpio c;
    char err[256];
    int lz4 = 0, ret = 1, i;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--init") && i + 1 < argc)
            init_path = argv[++i];
        else if (!strcmp(argv[i], "--ko") && i + 1 < argc)
            ko_path = argv[++i];
        else if (!strcmp(argv[i], "--config") && i + 1 < argc)
            cfg_path = argv[++i];
        else if (!strcmp(argv[i], "--params") && i + 1 < argc)
            params = argv[++i];
        else if (!strcmp(argv[i], "--force"))
            force = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else if (!in)
            in = argv[i];
        else if (!out)
            out = argv[i];
        else {
            fprintf(stderr, "kpramdisk: unexpected argument %s\n", argv[i]);
            return 2;
        }
    }
    if (!in || !out || !init_path || !ko_path) {
        usage(stderr);
        return 2;
    }

    if (bootimg_load(in, &img) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", img.err);
        return 1;
    }
    if (ramdisk_cpio(&img, &cpio_buf, &cpio_size, &lz4, err, sizeof(err)) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", err);
        bootimg_free(&img);
        return 1;
    }
    if (cpio_parse(cpio_buf, cpio_size, &c, err, sizeof(err)) != 0) {
        fprintf(stderr, "kpramdisk: %s\n", err);
        free(cpio_buf);
        bootimg_free(&img);
        return 1;
    }

    init_bin = read_file(init_path, &init_size, err, sizeof(err));
    ko_bin = read_file(ko_path, &ko_size, err, sizeof(err));
    if (cfg_path)
        cfg_bin = read_file(cfg_path, &cfg_size, err, sizeof(err));
    if (!init_bin || !ko_bin || (cfg_path && !cfg_bin)) {
        fprintf(stderr, "kpramdisk: %s\n", err);
        goto out;
    }

    if (!force && cpio_exists(&c, KO_ENTRY)) {
        fprintf(stderr, "kpramdisk: ramdisk already contains %s - refusing to patch twice\n",
                KO_ENTRY);
        fprintf(stderr, "          (use --force if the image was patched by hand)\n");
        goto out;
    }

    /* 1. keep the original first stage init, exactly as boot_patch.rs does */
    if (cpio_exists(&c, INIT_REAL_ENTRY)) {
        fprintf(stderr,
                "kpramdisk: warning: %s already exists (Magisk/KernelSU patched "
                "ramdisk?)\n          it is left untouched and kpinit will chain to it\n",
                INIT_REAL_ENTRY);
    } else if (cpio_exists(&c, INIT_ENTRY)) {
        if (cpio_rename(&c, INIT_ENTRY, INIT_REAL_ENTRY) != 0) {
            fprintf(stderr, "kpramdisk: cannot rename %s\n", INIT_ENTRY);
            goto out;
        }
    } else {
        fprintf(stderr, "kpramdisk: no %s in the ramdisk (not a first stage ramdisk?)\n",
                INIT_ENTRY);
        goto out;
    }

    /* 2. the three KernelSU-style additions */
    if (cpio_add(&c, INIT_ENTRY, 0100755, init_bin, init_size) != 0 ||
        cpio_add(&c, KO_ENTRY, 0100755, ko_bin, ko_size) != 0) {
        fprintf(stderr, "kpramdisk: out of memory\n");
        goto out;
    }
    if (cfg_bin)
        (void)cpio_add(&c, CONFIG_ENTRY, 0100644, cfg_bin, cfg_size);
    else if (params)
        (void)cpio_add(&c, CONFIG_ENTRY, 0100644, params, strlen(params));

    {
        unsigned char *new_cpio = NULL, *packed = NULL;
        size_t new_cpio_size = cpio_dump(&c, (void **)&new_cpio);
        size_t packed_size;

        if (!new_cpio_size) {
            fprintf(stderr, "kpramdisk: cannot serialise the cpio\n");
            goto out;
        }
        if (lz4) {
            packed_size = lz4_legacy_compress(new_cpio, new_cpio_size, &packed);
            if (!packed_size) {
                fprintf(stderr, "kpramdisk: cannot recompress the ramdisk\n");
                free(new_cpio);
                goto out;
            }
        } else {
            packed = new_cpio;
            packed_size = new_cpio_size;
        }

        printf("kpramdisk: %s: ramdisk %u -> %zu bytes %s, cpio %zu bytes\n", in,
               img.ramdisk_size, packed_size, lz4 ? "(lz4_legacy)" : "(raw)", new_cpio_size);
        printf("           + %s (%zu bytes), %s (%zu bytes)\n", INIT_ENTRY, init_size, KO_ENTRY,
               ko_size);
        if (bootimg_write(&img, packed, packed_size, out) != 0) {
            fprintf(stderr, "kpramdisk: %s\n", img.err);
            if (packed != new_cpio)
                free(new_cpio);
            free(packed);
            goto out;
        }
        printf("           -> %s written\n", out);
        if (img.has_avb)
            printf("           note: AVB data was relocated; the signature does not cover the\n"
                   "           new ramdisk, flash with verification disabled.\n");
        if (packed != new_cpio)
            free(new_cpio);
        free(packed);
        ret = 0;
    }

out:
    free(init_bin);
    free(ko_bin);
    free(cfg_bin);
    cpio_free(&c);
    free(cpio_buf);
    bootimg_free(&img);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* selftest - `make check`, no external tools needed                        */
/* ------------------------------------------------------------------------ */

static int st_fail(const char *what)
{
    printf("selftest: FAIL %s\n", what);
    return 1;
}

static int cmd_selftest(void)
{
    static struct {
        const char *name;
        unsigned mode;
        const char *data;
    } files[] = {
        { "init", 0100755, "REAL-INIT-BINARY" },
        { "system/bin/toolbox", 0100755, "toolbox" },
        { "overlay.d/notes", 0100644, "hello kernelpatch" },
    };
    unsigned char *blob = NULL, *packed = NULL, *img = NULL;
    size_t blob_size = 0, packed_size = 0;
    cpio c, c2;
    char err[256];
    int i, ret = 0;

    /* 1. lz4 legacy round trip on data with matches (offsets > 0 and > 255) */
    {
        size_t i2, n = 300000;
        unsigned char *plain = malloc(n), *dec = NULL;
        size_t dec_size = 0;

        if (!plain)
            return st_fail("oom");
        for (i2 = 0; i2 < n; i2++)
            plain[i2] = (unsigned char)((i2 % 251) ^ (i2 / 1024));
        packed_size = lz4_legacy_compress(plain, n, &packed);
        if (!packed_size || !lz4_legacy_is_stream(packed, packed_size))
            ret |= st_fail("lz4 compress");
        else if (lz4_legacy_decompress(packed, packed_size, &dec, &dec_size) != 0 ||
                 dec_size != n || memcmp(dec, plain, n) != 0)
            ret |= st_fail("lz4 round trip");
        else
            printf("selftest: lz4 legacy round trip OK (%zu -> %zu)\n", n, packed_size);
        free(dec);
        free(plain);
    }
    if (ret)
        goto out;

    /* 2. cpio round trip */
    memset(&c, 0, sizeof(c));
    for (i = 0; i < (int)(sizeof(files) / sizeof(files[0])); i++) {
        if (cpio_add(&c, files[i].name, files[i].mode, files[i].data, strlen(files[i].data) + 1)) {
            ret |= st_fail("cpio add");
            goto out;
        }
    }
    blob_size = cpio_dump(&c, (void **)&blob);
    if (!blob_size) {
        ret |= st_fail("cpio dump");
        goto out;
    }
    if (cpio_parse(blob, blob_size, &c2, err, sizeof(err)) != 0) {
        printf("selftest: %s\n", err);
        ret |= st_fail("cpio parse");
        goto out;
    }
    if (c2.count != c.count || !cpio_exists(&c2, "init") ||
        memcmp(cpio_find(&c2, "init")->data, "REAL-INIT-BINARY", 17) != 0)
        ret |= st_fail("cpio contents");
    else
        printf("selftest: cpio round trip OK (%zu entries, %zu bytes)\n", c2.count, blob_size);
    cpio_free(&c2);
    if (ret)
        goto out;

    /* rename + trailer handling, exactly what inject does */
    if (cpio_rename(&c, "init", "init.real") ||
        cpio_add(&c, "init", 0100755, "KPINIT", 7) ||
        !cpio_exists(&c, "init.real"))
        ret |= st_fail("cpio rename/add");
    cpio_free(&c);
    if (ret)
        goto out;

    /* 3. boot image: repack an image we assemble ourselves */
    if (mkdir(".selftest", 0755) != 0 && errno != EEXIST) {
        ret |= st_fail("mkdir .selftest");
        goto out;
    }
    packed_size = lz4_legacy_compress(blob, blob_size, &packed);
    if (!packed_size) {
        ret |= st_fail("lz4 for image");
        goto out;
    }
    {
        size_t page = 4096, total = page * 4;
        bootimg b;

        img = calloc(1, total);
        if (!img) {
            ret |= st_fail("oom image");
            goto out;
        }
        memcpy(img, BOOT_MAGIC, 8);
        img[12] = (unsigned char)(packed_size & 0xFF);
        img[13] = (unsigned char)((packed_size >> 8) & 0xFF);
        img[14] = (unsigned char)((packed_size >> 16) & 0xFF);
        img[15] = (unsigned char)((packed_size >> 24) & 0xFF);
        img[40] = 4; /* header version */
        memcpy(img + page, packed, packed_size);
        {
            FILE *f = fopen(".selftest/in.img", "wb");

            if (!f || fwrite(img, 1, total, f) != total) {
                if (f)
                    fclose(f);
                ret |= st_fail("write in.img");
                goto out;
            }
            fclose(f);
        }

        if (bootimg_load(".selftest/in.img", &b) != 0) {
            printf("selftest: %s\n", b.err);
            ret |= st_fail("bootimg load");
            goto out;
        }
        if (b.header_version != 4 || b.ramdisk_size != packed_size || b.ramdisk_off != 4096)
            ret |= st_fail("bootimg fields");
        else
            printf("selftest: boot image parsed OK (v%u, ramdisk %u @ %zu)\n", b.header_version,
                   b.ramdisk_size, b.ramdisk_off);
        if (bootimg_write(&b, packed, packed_size, ".selftest/out.img") != 0) {
            printf("selftest: %s\n", b.err);
            ret |= st_fail("bootimg write");
            bootimg_free(&b);
            goto out;
        }
        bootimg_free(&b);
        if (bootimg_load(".selftest/out.img", &b) != 0 || b.ramdisk_size != packed_size) {
            ret |= st_fail("bootimg reload");
            bootimg_free(&b);
            goto out;
        }
        {
            unsigned char *cp2 = NULL;
            size_t sz2 = 0;
            int lz = 0;
            cpio c3;

            if (ramdisk_cpio(&b, &cp2, &sz2, &lz, err, sizeof(err)) != 0 || !lz ||
                sz2 != blob_size || memcmp(cp2, blob, blob_size) != 0 ||
                cpio_parse(cp2, sz2, &c3, err, sizeof(err)) != 0) {
                ret |= st_fail("repacked ramdisk");
            } else {
                printf("selftest: repacked image ramdisk identical OK\n");
                cpio_free(&c3);
            }
            free(cp2);
        }
        bootimg_free(&b);
    }

out:
    free(blob);
    free(packed);
    free(img);
    printf("selftest: %s\n", ret ? "FAILED" : "all good");
    return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
        printf("kpramdisk " VER "\n");
        return 0;
    }
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(stdout);
        return 0;
    }
    if (!strcmp(argv[1], "info") && argc == 3)
        return cmd_info(argv[2]);
    if (!strcmp(argv[1], "list") && argc == 3)
        return cmd_list(argv[2]);
    if (!strcmp(argv[1], "selftest"))
        return cmd_selftest();
    if (!strcmp(argv[1], "inject"))
        return cmd_inject(argc - 2, argv + 2);

    usage(stderr);
    return 2;
}