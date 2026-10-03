// SPDX-License-Identifier: GPL-2.0
/*
 * kpinit - KernelPatch ramdisk boot hook.
 *
 * This is the userspace counterpart of the KernelPatch LKM (`lkm/`). It is
 * meant to be injected into an Android boot ramdisk (init_boot.img /
 * boot.img on Android 12) exactly the way KernelSU injects `ksuinit` and
 * Magisk injects `magiskinit`:
 *
 *   cpio.mv("init", "init.real")
 *   cpio.add("init", kpinit)
 *   cpio.add("kernelpatch.ko", <kmi>_kernelpatch.ko)
 *
 * The kernel then starts kpinit as PID 1, kpinit loads the KernelPatch LKM
 * with the KernelSU "manual relocation" trick (no vermagic/modversion check)
 * and finally hands control over to the untouched init (`init.real`).
 *
 * Why not just patch the kernel image?  Patching `boot.img` (what kpimg does)
 * requires a kernel image that can be re-signed / re-flashed and is not
 * always possible (AVB, vendor restrictions, GKI kernel shared across
 * devices, ...).  The ramdisk route keeps the kernel image untouched, exactly
 * like KernelSU/Magisk: everything lives in the ramdisk.
 *
 * The module loader below is a C port of `apd/src/insmod.rs` (which itself is
 * a port of KernelSU's `ksuinit::load_module`):
 *   1. read the .ko,
 *   2. resolve every undefined symbol against /proc/kallsyms,
 *   3. rewrite the symbol table in place: st_shndx = SHN_ABS,
 *      st_value = kernel address,
 *   4. call init_module(2).
 * Because the module ends up carrying a `__versions` section, the kernel
 * skips the vermagic check and never runs the per-symbol CRC check.
 *
 * Usage:
 *   kpinit                     (PID 1 only) set up /proc, load the module,
 *                              exec the real init.  Never fails the boot:
 *                              if anything goes wrong the real init is still
 *                              started.
 *   kpinit insmod <file> [..]  load a module manually (used by apd/tests).
 *   kpinit --help / --version
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define KPINIT_VERSION "1.0.0"

#define KMSG_PATH "/dev/kmsg"

/* Module that the ramdisk carries, and where the original init was moved to. */
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

static int kmsg_fd = -1;

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

    if (kmsg_fd < 0)
        kmsg_fd = open(KMSG_PATH, O_WRONLY | O_CLOEXEC);
    if (kmsg_fd >= 0) {
        (void)!write(kmsg_fd, "kpinit: ", 8);
        (void)!write(kmsg_fd, buf, strlen(buf));
    }
    (void)!write(STDERR_FILENO, buf, strlen(buf));
}

/* ------------------------------------------------------------------------ */
/* /proc/kallsyms                                                           */
/* ------------------------------------------------------------------------ */

static char *ks_buf;
static size_t ks_len;

/* Temporarily relax kptr_restrict so kallsyms exposes real addresses. */
static void kptr_restrict_relax(char *saved, size_t saved_sz)
{
    int fd = open("/proc/sys/kernel/kptr_restrict", O_RDWR | O_CLOEXEC);
    char old[32] = { 0 };
    ssize_t n;

    if (fd < 0)
        return;
    n = read(fd, old, sizeof(old) - 1);
    if (n > 0)
        snprintf(saved, saved_sz, "%s", old);
    if (lseek(fd, 0, SEEK_SET) == 0)
        (void)!write(fd, "1", 1);
    close(fd);
}

static void kptr_restrict_restore(const char *saved)
{
    int fd;

    if (!saved || !saved[0])
        return;
    fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    (void)!write(fd, saved, strlen(saved));
    close(fd);
}

static int kallsyms_load(void)
{
    int fd;
    ssize_t n;
    size_t cap = 1 << 20;

    ks_buf = malloc(cap);
    if (!ks_buf)
        return -1;
    ks_len = 0;

    fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        klog("open /proc/kallsyms failed: %s\n", strerror(errno));
        return -1;
    }
    while ((n = read(fd, ks_buf + ks_len, cap - ks_len - 1)) > 0) {
        ks_len += (size_t)n;
        if (ks_len + 1 >= cap) {
            char *nb = realloc(ks_buf, cap * 2);
            if (!nb)
                break;
            ks_buf = nb;
            cap *= 2;
        }
    }
    close(fd);
    ks_buf[ks_len] = '\0';
    klog("kallsyms: %zu bytes\n", ks_len);
    return ks_len ? 0 : -1;
}

/*
 * Symbol names in kallsyms can carry compiler suffixes; `apd` strips them the
 * same way (everything from '$' or ".llvm." on).
 */
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

static unsigned long long kallsyms_lookup(const char *name)
{
    const char *p = ks_buf;
    size_t want = strlen(name);

    if (!ks_buf)
        return 0;

    while (p && *p) {
        const char *eol = strchr(p, '\n');
        const char *q, *sym;
        size_t slen, blen;
        unsigned long long addr = 0;

        if (!eol)
            break;

        /* <addr> <type> <name> */
        addr = strtoull(p, NULL, 16);
        q = strchr(p, ' ');
        if (!q || q >= eol) {
            p = eol + 1;
            continue;
        }
        q++; /* type char */
        if (q >= eol || *q == ' ') {
            p = eol + 1;
            continue;
        }
        q++; /* space */
        if (q >= eol) {
            p = eol + 1;
            continue;
        }
        sym = q;
        slen = (size_t)(eol - sym);
        blen = symbol_base_len(sym, slen);
        if (blen == want && memcmp(sym, name, want) == 0)
            return addr;
        p = eol + 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* ELF symbol fixup + init_module(2)                                        */
/* ------------------------------------------------------------------------ */

static int patch_module_symbols(unsigned char *buf, size_t size, int *unresolved)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    Elf64_Shdr *sh;
    int i, rc = -1;

    *unresolved = 0;
    if (size < sizeof(Elf64_Ehdr) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ehsize < sizeof(Elf64_Ehdr) || eh->e_shoff == 0 ||
        eh->e_shentsize != sizeof(Elf64_Shdr))
        return -1;
    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > size)
        return -1;

    sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    for (i = 0; i < eh->e_shnum; i++) {
        Elf64_Sym *syms;
        unsigned char *strtab;
        size_t count, j;

        if (sh[i].sh_type != SHT_SYMTAB)
            continue;
        if (sh[i].sh_entsize != sizeof(Elf64_Sym) || sh[i].sh_link >= eh->e_shnum)
            return -1;
        if (sh[i].sh_offset + sh[i].sh_size > size)
            return -1;
        if (sh[sh[i].sh_link].sh_offset + sh[sh[i].sh_link].sh_size > size)
            return -1;

        syms = (Elf64_Sym *)(buf + sh[i].sh_offset);
        strtab = buf + sh[sh[i].sh_link].sh_offset;
        count = sh[i].sh_size / sizeof(Elf64_Sym);

        for (j = 1; j < count; j++) {
            const char *name;
            unsigned long long addr;

            if (syms[j].st_shndx != SHN_UNDEF || syms[j].st_name == 0)
                continue;
            if (syms[j].st_name >= sh[sh[i].sh_link].sh_size)
                continue;
            name = (const char *)strtab + syms[j].st_name;
            addr = kallsyms_lookup(name);
            if (!addr) {
                klog("unresolved kernel symbol: %s\n", name);
                (*unresolved)++;
                continue;
            }
            syms[j].st_shndx = SHN_ABS;
            syms[j].st_value = addr;
        }
        rc = 0;
    }
    return rc;
}

static int load_module(const char *path, const char *params)
{
    unsigned char *buf = NULL;
    struct stat st;
    int fd = -1, unresolved = 0, ret = -1;
    ssize_t got;
    size_t off = 0;
    char saved_kptr[32] = { 0 };

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        klog("open %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        klog("stat %s failed\n", path);
        goto out;
    }
    buf = malloc((size_t)st.st_size);
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

    if (!ks_buf && kallsyms_load() != 0)
        goto out;

    kptr_restrict_relax(saved_kptr, sizeof(saved_kptr));

    if (patch_module_symbols(buf, (size_t)st.st_size, &unresolved) != 0) {
        klog("%s is not a valid arm64 module\n", path);
        goto out;
    }
    if (unresolved)
        klog("warning: %d unresolved symbol(s)\n", unresolved);

    kptr_restrict_restore(saved_kptr);

    ret = (int)syscall(__NR_init_module, buf, (unsigned long)st.st_size, params);
    if (ret != 0) {
        klog("init_module(%s) failed: %s\n", path, strerror(errno));
        ret = -1;
    } else {
        klog("loaded %s\n", path);
        ret = 0;
    }
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
    struct stat st;

    if (stat(tgt, &st) != 0) {
        if (mkdir(tgt, 0755) != 0 && errno != EEXIST)
            klog("mkdir %s: %s\n", tgt, strerror(errno));
    }
    /* Already mounted (init re-exec, Magisk, ...) -> EBUSY, ignore. */
    if (mount(src, tgt, type, 0, NULL) != 0 && errno != EBUSY && errno != EPERM)
        klog("mount %s: %s\n", tgt, strerror(errno));
}

static void setup_mounts(void)
{
    try_mount("devtmpfs", "/dev", "devtmpfs");
    try_mount("proc", "/proc", "proc");
    try_mount("sysfs", "/sys", "sysfs");
}

static const char *first_existing(const char **list)
{
    int i;

    for (i = 0; list[i]; i++) {
        if (access(list[i], R_OK) == 0)
            return list[i];
    }
    return NULL;
}

static const char *load_default_module(void)
{
    const char *ko = first_existing(ko_candidates);

    if (!ko) {
        klog("no kernelpatch.ko in ramdisk, skipping\n");
        return NULL;
    }
    if (load_module(ko, "") != 0)
        klog("module load failed, continuing boot without root\n");
    return ko;
}

static void exec_real_init(char **argv)
{
    const char *init = first_existing(real_init_candidates);

    if (init) {
        klog("handing over to %s\n", init);
        if (argv)
            argv[0] = (char *)init;
        execv(init, argv ? argv : (char *[]){ (char *)init, NULL });
        klog("execv(%s) failed: %s\n", init, strerror(errno));
    } else {
        klog("no real init found in ramdisk\n");
    }
    /* Never let PID 1 exit: that would panic the kernel. */
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
            "                                ramdisk, then exec the real init\n"
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
        char saved[32] = { 0 };

        if (argc < 3) {
            usage(stderr);
            return 2;
        }
        try_mount("proc", "/proc", "proc");
        if (kallsyms_load() != 0)
            return 1;
        kptr_restrict_relax(saved, sizeof(saved));
        if (load_module(argv[2], argc > 3 ? argv[3] : "") != 0)
            return 1;
        kptr_restrict_restore(saved);
        return 0;
    }

    /* Boot hook mode.  Only valid as PID 1 (or explicitly forced), because
     * otherwise `execv` would silently replace an unrelated process. */
    if (getpid() != 1 && getenv("KPINIT_FORCE") == NULL) {
        fprintf(stderr, "kpinit: not PID 1 - refusing boot handover\n\n");
        usage(stderr);
        return 1;
    }

    klog("kpinit " KPINIT_VERSION " (pid %d) starting\n", (int)getpid());
    setup_mounts();
    if (kallsyms_load() == 0)
        load_default_module();
    else
        klog("kallsyms unavailable, skipping module load\n");
    exec_real_init(argv);

    return 0; /* not reached */
}
