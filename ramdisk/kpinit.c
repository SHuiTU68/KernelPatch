// SPDX-License-Identifier: GPL-2.0
/*
 * kpinit - KernelPatch ramdisk boot hook.
 *
 * The userspace counterpart of the KernelPatch LKM (`lkm/`): injected into an
 * Android ramdisk (init_boot.img, or boot.img on Android 12), started by the
 * kernel as PID 1, it loads `<kmi>_kernelpatch.ko` on a stock kernel and then
 * hands control over to the untouched init.
 *
 * This is a deliberate C re-implementation of KernelSU's `userspace/ksuinit`
 * (GPL-2.0, tiann/KernelSU) - the injection recipe, the module loader, the
 * kmsg handling and the init handover all follow it 1:1:
 *
 *   cpio: mv "init" -> "init.real"
 *         add "init" -> kpinit            (0755, becomes PID 1)
 *         add "kernelpatch.ko"            (<kmi>_kernelpatch.ko)
 *         add "kp_config"                 (optional module params)
 *
 *   kpinit (PID 1):
 *     1. devtmpfs/proc/sysfs are mounted, /dev/kmsg is created if needed
 *        (mknod char 1:11) and devkmsg rate limiting is disabled
 *     2. if /sys/module/kernelpatch already exists nothing is loaded again
 *     3. every undefined symbol of the .ko is resolved by streaming
 *        /proc/kallsyms (early stop at module symbols) while kptr_restrict is
 *        relaxed, then the symbol table is rewritten in place
 *        (st_shndx = SHN_ABS, st_value = <kernel address>) and the module is
 *        loaded with init_module(2) - KernelSU's "manual relocation", which
 *        makes the per-symbol CRC/vermagic checks moot
 *     4. if the kernel still rejects it with a vermagic mismatch, the
 *        required vermagic is read from /dev/kmsg, written into the module's
 *        .modinfo section and the load is retried once
 *     5. unlink("/init"), symlink("/init.real" | "/system/bin/init", "/init")
 *        and execv("/init") - exactly how ksuinit transfers control
 *
 * Every step is best effort and the handover always happens: a broken module
 * never blocks the boot, and PID 1 never exits (that would panic the kernel).
 *
 * Usage:
 *   kpinit                       (PID 1 only) boot mode, see above
 *   kpinit insmod <module> [params]
 *   kpinit --help | --version
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define KPINIT_VERSION "1.1.0"

/* The module that the ramdisk carries, and where the original init was moved. */
static const char *ko_candidates[] = {
    "/kernelpatch.ko",
    "/overlay.d/kernelpatch.ko",
    "/sbin/kernelpatch.ko",
    NULL,
};
static const char *real_init_candidates[] = {
    "/init.real",
    "/system/bin/init",
    NULL,
};
#define KO_PARAMS_FILE "/kp_config"
/* Module name == .ko file name, used for the "already loaded" check. */
#define KO_MODULE_NAME "kernelpatch"

/* ------------------------------------------------------------------------ */
/* logging (kernel log, KernelSU style)                                     */
/* ------------------------------------------------------------------------ */

static int log_fd = -1;

static bool exists(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0;
}

/* /dev/kmsg only exists once devtmpfs is mounted; otherwise create it. */
static const char *kmsg_path(void)
{
    if (exists("/dev/kmsg"))
        return "/dev/kmsg";
    if (exists("/kmsg"))
        return "/kmsg";
    (void)mkdir("/dev", 0755);
    if (mknod("/kmsg", S_IFCHR | 0666, makedev(1, 11)) == 0)
        return "/kmsg";
    return NULL;
}

static void klog(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    if (log_fd < 0) {
        const char *p = kmsg_path();

        if (p)
            log_fd = open(p, O_WRONLY | O_CLOEXEC);
    }
    if (log_fd >= 0) {
        (void)!write(log_fd, "kpinit: ", 8);
        (void)!write(log_fd, buf, strlen(buf));
    }
    (void)!write(STDERR_FILENO, buf, strlen(buf));
}

static void unlimit_kmsg(void)
{
    int fd = open("/proc/sys/kernel/printk_devkmsg", O_WRONLY | O_CLOEXEC);

    if (fd >= 0) {
        (void)!write(fd, "on\n", 3);
        close(fd);
    }
}

/* ------------------------------------------------------------------------ */
/* /proc/kallsyms (streaming, KernelSU style)                               */
/* ------------------------------------------------------------------------ */

struct candidate {
    const char *name;
    size_t len;
    Elf64_Sym *sym;
};
#define CAND_MAX 256
static struct candidate cands[CAND_MAX];
static size_t cand_count;

#define HT_SIZE 1024
static int ht[HT_SIZE];

static uint32_t fnv1a(const char *s, size_t n)
{
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619u;
    }
    return h;
}

static void ht_put(size_t idx)
{
    uint32_t h = fnv1a(cands[idx].name, cands[idx].len) & (HT_SIZE - 1);

    while (ht[h] >= 0)
        h = (h + 1) & (HT_SIZE - 1);
    ht[h] = (int)idx;
}

static int ht_get(const char *name, size_t len)
{
    uint32_t h = fnv1a(name, len) & (HT_SIZE - 1);

    while (ht[h] >= 0) {
        const struct candidate *c = &cands[ht[h]];

        if (c->len == len && memcmp(c->name, name, len) == 0)
            return ht[h];
        h = (h + 1) & (HT_SIZE - 1);
    }
    return -1;
}

/* KernelSU strips compiler suffixes from kallsyms names as well. */
static size_t symbol_base_len(const char *name, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i++) {
        if (name[i] == '$')
            return i;
        if (i + 6 <= len && memcmp(name + i, ".llvm.", 6) == 0)
            return i;
    }
    return len;
}

/*
 * Match one kallsyms line.  Returns:
 *   1  line consumed
 *   0  module symbols reached -> stop reading
 */
static int kallsyms_line(char *line)
{
    char *p = line, *end;
    unsigned long long addr;
    size_t len, base;
    int idx;

    addr = strtoull(p, &end, 16);
    if (end == p)
        return 1;
    (void)addr;

    p = end;
    while (*p == ' ')
        p++;
    if (!*p)
        return 1;
    p++; /* symbol type */
    while (*p == ' ')
        p++;
    if (!*p || *p == '\n')
        return 1;

    for (end = p; *end && *end != '\n' && *end != ' '; end++)
        ;
    len = (size_t)(end - p);
    /* "<addr> <type> <name> <module>" == module symbol: kernel symbols are done. */
    if (*end == ' ')
        return 0;

    base = symbol_base_len(p, len);
    if (!base)
        return 1;
    idx = ht_get(p, base);
    if (idx < 0)
        return 1;

    cands[idx].sym->st_shndx = SHN_ABS;
    cands[idx].sym->st_value = addr;
    cands[idx].len = 0; /* mark resolved */
    return 1;
}

static int resolve_symbols(unsigned char *buf, size_t size, int *unresolved)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    Elf64_Shdr *sh;
    char *line = NULL;
    char *chunk = NULL;
    size_t cap = 1 << 16, used = 0, carry = 0;
    int i, fd = -1, ret = -1;
    char kptr[32] = { 0 };
    int kptr_fd;

    *unresolved = 0;
    if (size < sizeof(Elf64_Ehdr) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_shoff == 0 ||
        eh->e_shentsize != sizeof(Elf64_Shdr))
        return -1;

    for (i = 0; i < HT_SIZE; i++)
        ht[i] = -1;

    /* 1. collect undefined symbols of the module */
    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > size)
        return -1;
    sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    for (i = 0; i < eh->e_shnum; i++) {
        Elf64_Sym *syms;
        const char *strtab;
        size_t count, j;

        if (sh[i].sh_type != SHT_SYMTAB || sh[i].sh_link >= eh->e_shnum)
            continue;
        if (sh[i].sh_offset + sh[i].sh_size > size)
            return -1;
        if (sh[sh[i].sh_link].sh_offset + sh[sh[i].sh_link].sh_size > size)
            return -1;

        syms = (Elf64_Sym *)(buf + sh[i].sh_offset);
        strtab = (const char *)(buf + sh[sh[i].sh_link].sh_offset);
        count = sh[i].sh_size / sizeof(Elf64_Sym);
        for (j = 1; j < count; j++) {
            const char *name;

            if (syms[j].st_shndx != SHN_UNDEF || syms[j].st_name == 0)
                continue;
            if (syms[j].st_name >= sh[sh[i].sh_link].sh_size)
                continue;
            name = strtab + syms[j].st_name;
            if (!name[0] || cand_count >= CAND_MAX)
                continue;
            cands[cand_count].name = name;
            cands[cand_count].len = strlen(name);
            cands[cand_count].sym = &syms[j];
            ht_put(cand_count);
            cand_count++;
        }
    }
    if (!cand_count) /* no external symbols: nothing to relocate */
        return 0;

    /* 2. stream /proc/kallsyms once and patch the matches */
    /* KernelSU's Kptr guard: expose addresses for the duration of the scan,
     * then restore the previous value (see Kptr/ Drop in lib.rs). */
    kptr_fd = open("/proc/sys/kernel/kptr_restrict", O_RDWR | O_CLOEXEC);
    if (kptr_fd >= 0) {
        if (read(kptr_fd, kptr, sizeof(kptr) - 1) <= 0)
            kptr[0] = '\0';
        if (lseek(kptr_fd, 0, SEEK_SET) == 0)
            (void)!write(kptr_fd, "1", 1);
        close(kptr_fd);
    }

    fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        klog("open /proc/kallsyms failed: %s\n", strerror(errno));
        goto restore;
    }
    line = malloc(cap);
    chunk = malloc(cap);
    if (!line || !chunk)
        goto restore;

    for (;;) {
        ssize_t n = read(fd, chunk, cap - 1);
        size_t i, start;

        if (n <= 0)
            break;
        if (used + (size_t)n + 1 > cap) {
            klog("kallsyms line too long, stopping\n");
            break;
        }
        memcpy(line + used, chunk, (size_t)n);
        used += (size_t)n;
        line[used] = '\0';

        start = 0;
        for (i = 0; i < used; i++) {
            if (line[i] != '\n')
                continue;
            line[i] = '\0';
            if (!carry && !kallsyms_line(line + start))
                goto restore; /* module symbols: kernel symbols are done */
            start = i + 1;
        }
        carry = 0;
        if (start) {
            memmove(line, line + start, used - start);
            used -= start;
        }
    }
    ret = 0;

restore:
    if (fd >= 0)
        close(fd);
    free(line);
    free(chunk);
    if (kptr[0]) {
        int f = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);

        if (f >= 0) {
            (void)!write(f, kptr, strcspn(kptr, "\n"));
            close(f);
        }
    }
    for (i = 0; i < (int)cand_count; i++) {
        if (!cands[i].len)
            continue;
        klog("unresolved kernel symbol: %s\n", cands[i].name);
        (*unresolved)++;
    }
    return ret; /* -1 only on a malformed ELF */
}

/* ------------------------------------------------------------------------ */
/* vermagic fixup (only used when the kernel refuses the module)             */
/* ------------------------------------------------------------------------ */

static size_t align_up(size_t v, size_t a)
{
    if (a < 2)
        return v;
    return (v + a - 1) & ~(a - 1);
}

static int read_new_kmsg(char *out, size_t out_sz)
{
    const char *path = kmsg_path();
    int fd, n;
    off_t sz;

    out[0] = '\0';
    if (!path)
        return -1;
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    sz = lseek(fd, 0, SEEK_END);
    if (sz >= 0)
        (void)lseek(fd, sz, SEEK_SET);
    n = (int)read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return n;
}

/*
 * KernelSU's extract_required_vermagic: the kernel logs
 *   "<mod>: version magic 'X' should be 'Y'"
 * and Y is what the module has to advertise.  The last match wins.
 */
static bool parse_required_vermagic(const char *log, char *out, size_t out_sz)
{
    static const char sep[] = "' should be '";
    const char *p = log, *found = NULL;

    if (!strstr(log, "version magic '"))
        return false;
    while ((p = strstr(p, sep)) != NULL) {
        p += sizeof(sep) - 1;
        if (strchr(p, '\''))
            found = p;
    }
    if (!found)
        return false;
    {
        size_t len = (size_t)(strchr(found, '\'') - found);

        if (!len || len >= out_sz)
            return false;
        memcpy(out, found, len); /* out and log never alias (see below) */
        out[len] = '\0';
    }
    return true;
}

static int replace_vermagic(unsigned char *buf, size_t *len, size_t cap, const char *required)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    Elf64_Shdr *sh;
    const char *shstr;
    size_t shname_len = strlen(".modinfo");
    int i, modinfo = -1;
    unsigned char *old;
    size_t old_sz, new_sz = 0, new_off, need;
    unsigned char *tmp;
    bool replaced = false;

    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > *len)
        return -1;
    if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum)
        return -1;
    sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    if (sh[eh->e_shstrndx].sh_offset + sh[eh->e_shstrndx].sh_size > *len)
        return -1;
    shstr = (const char *)(buf + sh[eh->e_shstrndx].sh_offset);

    for (i = 0; i < eh->e_shnum; i++) {
        const char *name;

        if (sh[i].sh_name >= sh[eh->e_shstrndx].sh_size)
            continue;
        name = shstr + sh[i].sh_name;
        if (strncmp(name, ".modinfo", shname_len + 1) == 0) {
            modinfo = i;
            break;
        }
    }
    if (modinfo < 0)
        return -1;
    if (sh[modinfo].sh_offset + sh[modinfo].sh_size > *len)
        return -1;

    old = buf + sh[modinfo].sh_offset;
    old_sz = sh[modinfo].sh_size;
    /* never larger than the old blob + the replacement entry */
    tmp = malloc(old_sz + strlen(required) + 32);
    if (!tmp)
        return -1;

    for (size_t off = 0; off < old_sz;) {
        size_t elen = strnlen((const char *)(old + off), old_sz - off);

        if (elen) {
            if (strncmp((const char *)(old + off), "vermagic=", 9) == 0) {
                if (!replaced) {
                    memcpy(tmp + new_sz, "vermagic=", 9);
                    new_sz += 9;
                    memcpy(tmp + new_sz, required, strlen(required) + 1);
                    new_sz += strlen(required) + 1;
                    replaced = true;
                }
            } else {
                memcpy(tmp + new_sz, old + off, elen + 1);
                new_sz += elen + 1;
            }
        }
        off += elen + 1;
    }
    if (!replaced) {
        memcpy(tmp + new_sz, "vermagic=", 9);
        new_sz += 9;
        memcpy(tmp + new_sz, required, strlen(required) + 1);
        new_sz += strlen(required) + 1;
    }

    new_off = align_up(*len, sh[modinfo].sh_addralign ? sh[modinfo].sh_addralign : 1);
    need = new_off + new_sz;
    if (need > cap) {
        free(tmp);
        return -1;
    }
    memset(buf + *len, 0, new_off - *len);
    memcpy(buf + new_off, tmp, new_sz);
    free(tmp);

    sh = (Elf64_Shdr *)(buf + eh->e_shoff); /* re-read: buffer did not move, keep it simple */
    sh[modinfo].sh_offset = new_off;
    sh[modinfo].sh_size = new_sz;
    *len = new_off + new_sz;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* module loading                                                           */
/* ------------------------------------------------------------------------ */

static int load_module(const char *path, const char *params)
{
    unsigned char *buf = NULL;
    struct stat st;
    size_t size = 0, cap = 0;
    int fd = -1, unresolved = 0, ret = -1;
    ssize_t got;
    size_t off = 0;
    char kmsg_buf[512];
    char required[128];

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        klog("open %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        klog("stat %s failed\n", path);
        goto out;
    }
    cap = (size_t)st.st_size + 4096; /* room for a rewritten .modinfo */
    buf = malloc(cap);
    if (!buf) {
        klog("oom\n");
        goto out;
    }
    while (off < (size_t)st.st_size) {
        got = read(fd, buf + off, (size_t)st.st_size - off);
        if (got <= 0) {
            klog("short read on %s\n", path);
            goto out;
        }
        off += (size_t)got;
    }
    size = (size_t)st.st_size;

    if (!exists("/proc/kallsyms")) {
        klog("/proc not available, cannot relocate symbols\n");
        goto out;
    }
    if (resolve_symbols(buf, size, &unresolved) != 0) {
        klog("%s is not a valid arm64 module\n", path);
        goto out;
    }
    if (unresolved)
        klog("warning: %d unresolved symbol(s)\n", unresolved);

    ret = (int)syscall(__NR_init_module, buf, (unsigned long)size, params);
    if (ret == 0) {
        klog("loaded %s\n", path);
        ret = 0;
        goto out;
    }
    klog("init_module(%s) failed: %s\n", path, strerror(errno));

    /* KernelSU does the same: learn the required vermagic from the kernel log,
     * rewrite .modinfo and retry by exactly one attempt. */
    if (kmsg_path() && read_new_kmsg(kmsg_buf, sizeof(kmsg_buf)) > 0 &&
        parse_required_vermagic(kmsg_buf, required, sizeof(required))) {
        klog("kernel requires vermagic %s, retrying\n", required);
        if (replace_vermagic(buf, &size, cap, required) == 0 &&
            syscall(__NR_init_module, buf, (unsigned long)size, params) == 0) {
            klog("loaded %s (vermagic fixed)\n", path);
            ret = 0;
            goto out;
        }
        klog("retry with fixed vermagic failed: %s\n", strerror(errno));
    }
    ret = -1;
out:
    if (fd >= 0)
        close(fd);
    free(buf);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* boot glue                                                                */
/* ------------------------------------------------------------------------ */

static void try_mount(const char *src, const char *tgt, const char *type)
{
    if (!exists(tgt))
        (void)mkdir(tgt, 0755);
    /* Already mounted (init re-exec, Magisk, ...) -> EBUSY, ignore. */
    if (mount(src, tgt, type, 0, NULL) != 0 && errno != EBUSY && errno != EPERM)
        klog("mount %s: %s\n", tgt, strerror(errno));
}

static void setup_mounts(void)
{
    try_mount("devtmpfs", "/dev", "devtmpfs");
    try_mount("sysfs", "/sys", "sysfs");
    try_mount("proc", "/proc", "proc");
    unlimit_kmsg();
}

static const char *first_existing(const char **list)
{
    int i;

    for (i = 0; list[i]; i++) {
        if (exists(list[i]))
            return list[i];
    }
    return NULL;
}

static bool already_loaded(void)
{
    return exists("/sys/module/" KO_MODULE_NAME);
}

static char *read_params(void)
{
    int fd = open(KO_PARAMS_FILE, O_RDONLY | O_CLOEXEC);
    char *buf;
    ssize_t n;

    if (fd < 0)
        return strdup("");
    buf = calloc(1, 1024);
    if (!buf) {
        close(fd);
        return strdup("");
    }
    n = read(fd, buf, 1023);
    close(fd);
    if (n < 0)
        buf[0] = '\0';
    return buf;
}

static void hand_over(char **argv)
{
    const char *real = first_existing(real_init_candidates);

    if (!real) {
        klog("no real init found, cannot hand over\n");
        for (;;)
            pause();
    }
    /* Same as ksuinit: /init becomes a symlink to the real init so that the
     * path keeps existing after kpinit replaced itself. */
    (void)unlink("/init");
    if (symlink(real, "/init") != 0)
        klog("symlink /init -> %s failed: %s\n", real, strerror(errno));
    klog("handing over to %s\n", real);
    if (argv)
        argv[0] = (char *)"/init";
    execv("/init", argv ? argv : (char *[]){ (char *)"/init", NULL });
    execv(real, argv ? argv : (char *[]){ (char *)real, NULL });
    klog("execv failed: %s\n", strerror(errno));
    for (;;)
        pause();
}

static void usage(FILE *out)
{
    fprintf(out,
            "kpinit " KPINIT_VERSION " - KernelPatch ramdisk boot hook\n"
            "\n"
            "Usage:\n"
            "  kpinit                        (PID 1) load kernelpatch.ko from the\n"
            "                                ramdisk, then hand over to the real init\n"
            "  kpinit insmod <module> [args] load a kernel module with manual\n"
            "                                symbol relocation\n"
            "  kpinit --version | --help\n");
}

int main(int argc, char **argv)
{
    if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        usage(stdout);
        return 0;
    }
    if (argc >= 2 && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))) {
        printf("kpinit %s\n", KPINIT_VERSION);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "insmod") == 0) {
        int ret;

        if (argc < 3) {
            usage(stderr);
            return 2;
        }
        try_mount("proc", "/proc", "proc");
        try_mount("sysfs", "/sys", "sysfs");
        ret = load_module(argv[2], argc > 3 ? argv[3] : "");
        return ret == 0 ? 0 : 1;
    }

    /* Boot mode.  Only valid as PID 1 (or explicitly forced): otherwise the
     * handover would replace an unrelated process. */
    if (getpid() != 1 && getenv("KPINIT_FORCE") == NULL) {
        fprintf(stderr, "kpinit: not PID 1 - refusing boot handover\n\n");
        usage(stderr);
        return 1;
    }

    klog("kpinit " KPINIT_VERSION " (pid %d) starting\n", (int)getpid());
    setup_mounts();

    if (already_loaded()) {
        klog("kernelpatch module already loaded, skipping\n");
    } else {
        const char *ko = first_existing(ko_candidates);

        if (!ko) {
            klog("no kernelpatch.ko in ramdisk, skipping\n");
        } else if (!exists("/proc/kallsyms")) {
            klog("/proc/kallsyms unavailable, skipping module load\n");
        } else {
            char *params = read_params();

            if (load_module(ko, params ? params : "") != 0)
                klog("module load failed, continuing boot without root\n");
            free(params);
        }
    }

    hand_over(argv);
    return 0; /* not reached */
}