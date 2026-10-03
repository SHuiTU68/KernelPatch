# KernelPatch ramdisk delivery (`kpinit` + `kpramdisk`)

This directory is the KernelSU-style delivery path of KernelPatch, sitting next
to the image-patched `kpimg`:

| | delivery | what is touched |
|---|---|---|
| `kpimg` | kernel image (kptools patches the boot kernel, kpimg takes over the boot flow) | `boot.img` kernel |
| `lkm/` + `kpinit` + `kpramdisk` | Android ramdisk (`init_boot.img`, or `boot.img` on Android 12) | ramdisk only |

Both sides are deliberate C re-implementations of KernelSU's userspace
(GPL-2.0, [tiann/KernelSU](https://github.com/tiann/KernelSU)):

| KernelSU | here |
|---|---|
| `userspace/ksuinit` (`main.rs`, `init.rs`, `lib.rs`) | `kpinit.c` — PID 1 hook, loads the LKM |
| `userspace/ksud boot_patch` (`boot_patch.rs`) | `kpramdisk.c` — injects it into the ramdisk |
| `kernelsu.ko` / `ksu_config` | `kernelpatch.ko` / `kp_config` |

## Pipeline

```text
init_boot.img ──► kpramdisk inject ──► patched init_boot.img
                       │  cpio.mv("init", "init.real")
                       │  cpio.add("init", kpinit, 0755)
                       │  cpio.add("kernelpatch.ko", <kmi>_kernelpatch.ko, 0755)
                       │  cpio.add("kp_config", "<params>", 0644)      (optional)
                       ▼
              kernel starts kpinit as PID 1
                       │  1. mounts devtmpfs/proc/sysfs, makes /dev/kmsg usable
                       │  2. skips everything if /sys/module/kernelpatch exists
                       │  3. resolves every undefined symbol of the .ko by
                       │     streaming /proc/kallsyms (kptr_restrict relaxed and
                       │     restored), rewrites the symbol table in place
                       │     (st_shndx = SHN_ABS, st_value = <kernel addr>)
                       │  4. init_module(2) — KernelSU's manual relocation, which
                       │     makes the per-symbol CRC/vermagic checks moot
                       │  5. on a vermagic mismatch: read the required value from
                       │     /dev/kmsg, rewrite .modinfo, retry exactly once
                       │  6. unlink("/init") + symlink("/init.real" | "/system/bin/init")
                       │     + execv("/init") — the KernelSU handover
                       ▼
                untouched Android init continues the boot
```

Every step is best effort: a missing/mismatching module is logged to
`/dev/kmsg` and the system still boots. `kpinit` never exits (a dead PID 1
panics the kernel).

## Build

The arm64 binaries are linked against **bionic**, never glibc: build them with
the Android NDK clang and keep `-static`. A `aarch64-linux-gnu-gcc -static`
binary is a static glibc build, and glibc registers an rseq area during startup
with a syscall that Android's seccomp filters answer with `SIGSYS` — the
process dies instantly and the patcher reports the classic *Bad system call*,
so the init_boot path can never work.

bionic additionally refuses to start an arm64 binary whose `PT_TLS` segment is
aligned to less than 64 bytes (*executable's TLS segment is underaligned:
alignment is 8, needs to be at least 64 for ARM64 Bionic*). A plain `-static`
bionic link lands exactly there: the one 8-byte thread-local object that is
pulled out of `libc.a` sets the alignment of the TLS segment to 8, and the
loader aborts before `main()` ever runs — the patcher then fails on
`./kpramdisk` instead of on the boot image. `tls_align.c` is linked into both
binaries and pins the alignment to 64 with a single 64-byte aligned
thread-local object, and `make check-android` fails the build if it ever drops
below 64 again.

```sh
cd ramdisk
make                      # NDK clang, static bionic arm64
make ANDROID_NDK=/opt/android-ndk
make check-android        # fails on a glibc / dynamic / underaligned build
make check                # host build + lz4/cpio/boot image round trip selftest
```

CI (`.github/workflows/build-kpinit.yml`) sets up NDK r26b, builds on every
change under `ramdisk/**`, runs `check-android` (static, glibc-free,
TLS alignment >= 64) + `make check`, and uploads
`kpinit-android` + `kpramdisk-android` to the release of the current `version`
file — APatch downloads them next to `kpimg-android` / `kptools-android`.

## Usage

```sh
# inspect
kpramdisk info  init_boot.img
kpramdisk list  init_boot.img              # cpio entries (+ symlink targets)

# patch (kpinit-android + the LKM of the device KMI)
kpramdisk inject init_boot.img patched.img \
    --init kpinit-android \
    --ko   android15-6.6_kernelpatch.ko \
    --params "skey=my-superkey"

# runtime loading, e.g. from an already rooted device
kpinit insmod /data/local/tmp/android15-6.6_kernelpatch.ko
```

`kpramdisk` refuses to patch an image twice (the ramdisk already carries
`kernelpatch.ko`) unless `--force` is given, and it never overwrites an
existing `init.real` — a ramdisk that already went through Magisk or KernelSU
is left intact and `kpinit` simply chains to whatever `/init.real` is there.

Supported ramdisks: `lz4_legacy` (the GKI norm) and uncompressed cpio.
gzip ramdisks are rejected with a clear error (not needed on GKI devices).

## Verified

* `kpramdisk` on a real device dump (Pixel-style `init_boot_a.img`,
  header v4, lz4_legacy, 36 cpio entries, Magisk-patched, kernel
  `6.6.118-android15` → KMI `android15-6.6`):

  ```text
  ramdisk 2930533 -> 3563637 bytes (lz4_legacy), cpio 4979432 bytes
  + init (708192 bytes), kernelpatch.ko (172112 bytes)
  AVB block: 832 bytes relocated behind the new ramdisk, footer updated,
             image size kept at 8388608 bytes
  ```

* the repacked ramdisk decodes with the reference `lz4` CLI (4 979 432 bytes);
  all 36 original entries are byte-identical after the round trip, `init`
  became `init.real`, and `init`/`kernelpatch.ko`/`kp_config` match their
  source files (sha-compared).
* `make check` covers the lz4 stream codec, the cpio reader/writer and a
  full assemble → parse → repack → re-parse cycle of a boot image.

* the check is repeatable on any patched image with `verify_patch.py` — an
  independent verifier that decodes the ramdisk with the reference `lz4` CLI
  and compares both archives entry by entry. It was run both against the
  locally built binaries and against the CI-built release assets
  (`kpramdisk-android` + `kpinit-android` of the current release, which produce
  byte-identical output):

  ```text
  $ kpramdisk inject init_boot_a.img patched.img \
        --init kpinit-android --ko android15-6.6_kernelpatch.ko \
        --params "skey=release-key"
  $ python3 verify_patch.py init_boot_a.img patched.img \
        kpinit-android android15-6.6_kernelpatch.ko "skey=release-key"
  stock entries   : 36
  patched entries : 39
  init -> init.real identical : True (200656 bytes)
  init             == kpinit-android : True (702416 bytes)
  kernelpatch.ko   == android15-6.6_kernelpatch.ko : True (172112 bytes)
  kp_config        == b'skey=release-key' : True (mode 0o100644)
  avb footer -> 832 bytes @ 3567616, after ramdisk : True
  RESULT: ALL GOOD
  ```

## Status / caveats

* loader, injector and handover are implemented and compile warning-free for
  aarch64 and host; the **boot path itself has not been exercised on a device**
  yet (needs a flash with verification disabled).
* `--ko` must match the running KMI (`android15-6.6` for Linux 6.6
  `-android15`). A mismatch fails cleanly, the vermagic retry recovers only
  when the kernel accepts the rewritten value.
* **AVB**: the vbmeta struct is relocated and the footer rewritten, but the
  signature cannot be recomputed — flash with verified boot disabled, exactly
  like a Magisk/KernelSU patched image. Keep a backup of the unpatched
  partition: a broken ramdisk is a bootloop, and this is PID 1 code.
* the LKM is still the *framework* one (`lkm/README.md` lists the TODOs:
  `SUPERCALL_SU_TASK`, kpm loader, kstorage, allowlist persistence, SELinux
  translabel, inline-hook infra), so a successful ramdisk boot provides the
  KernelPatch supercall channel, not yet a full-featured root.
