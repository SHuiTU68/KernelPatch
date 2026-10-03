# KernelPatch ramdisk hook (`kpinit`)

`kpinit` is the second delivery path of KernelPatch, next to the
image-patched `kpimg`:

| | delivery | what is touched |
|---|---|---|
| `kpimg` | kernel image (kptools patches the boot image kernel, kpimg takes over the boot flow) | `boot.img` kernel |
| `lkm/` + `kpinit` | Android ramdisk (`init_boot.img`, or `boot.img` on Android 12) | ramdisk only |

The KernelPatch LKM (`lkm/`, published as `<kmi>_kernelpatch.ko`) already
provides the whole supercall/SU channel on a **stock kernel**, it only needs
somebody to load it early at boot.  `kpinit` is that somebody, exactly like
KernelSU's `ksuinit` or Magisk's `magiskinit`.

## How the injection looks

The patcher has to rewrite the ramdisk cpio (newc format):

```text
cpio.mv("init",     "init.real")        # keep the stock first-stage init
cpio.add("init",    kpinit)             # becomes PID 1
cpio.add("kernelpatch.ko", <kmi>_kernelpatch.ko)
```

At boot the kernel starts `kpinit` as PID 1, kpinit:

1. mounts `devtmpfs` / `proc` / `sysfs` (needed to read `/proc/kallsyms`),
2. resolves every undefined symbol of `kernelpatch.ko` against
   `/proc/kallsyms` and rewrites the symbol table in place
   (`st_shndx = SHN_ABS`, `st_value = <kernel address>`),
3. calls `init_module(2)` — because the module still carries a `__versions`
   section the kernel skips the vermagic check, and the manual relocation
   makes the per-symbol CRC check moot, so an unsigned `.ko` builds from
   Android's DDK loads on a stock kernel,
4. `execv()`s `/init.real` so the untouched Android init continues the boot.

Every step is best effort: if the module cannot be loaded (wrong KMI, module
support disabled, `CONFIG_MODULE_SIG_FORCE=y`) kpinit logs the reason to
`/dev/kmsg` and **still boots the system** without root.  It never exits, so
a failed handover can not panic the kernel.

This is the same mechanism `apd insmod` uses (`apd/src/insmod.rs` in APatch,
a port of KernelSU's `ksuinit::load_module`); `kpinit` is the C/static
standalone version that can live in a ramdisk without any userland.

## Build

```sh
cd ramdisk
make                      # -> ramdisk/kpinit-android (static aarch64)
make TARGET_CC=clang
```

CI (`.github/workflows/build-kpinit.yml`) builds it on every change under
`ramdisk/**` and uploads `kpinit-android` to the release of the current
`version` file — APatch downloads it next to `kpimg-android` /
`kptools-android`.

## Manual use / debugging

```sh
kpinit --version
kpinit insmod /path/to/kernelpatch.ko        # same loader, no init handover
kpinit                                       # boot mode, refuses to run if not PID 1
```

## Status

* loader + init handover: implemented, compiles clean, boot path not yet
  exercised on a device with a real KMI module.
* The `.ko` is the *framework* LKM (`lkm/README.md` lists its TODOs:
  `SUPERCALL_SU_TASK`, kpm loader, kstorage, allowlist persistence,
  SELinux translabel, inline-hook infra).
* Not implemented: ramdisk cpio/gzip|lz4 editing (that lives on the patcher
  side — APatch), AVB/vbmeta handling (the patched ramdisk is only usable on
  a device with a disabled/unlocked verified boot chain).

## Caveats

* **Do not inject twice.**  A ramdisk that already contains Magisk
  (`.backup/.magisk`, `overlay.d/sbin/magisk.xz`) or KernelSU already
  replaced `init`.  Injecting kpinit on top of that would chain
  kpinit -> magiskinit -> init.real, which works (kpinit always hands over to
  whatever `/init.real` or `/system/bin/init` exists), but the patcher should
  at least warn and never overwrite a foreign `/init.real`.
* Keep a flashable image of the unpatched `init_boot`/`boot` partition: a
  broken ramdisk is a bootloop, and this is PID 1 code.
* The `.ko` must match the running kernel's KMI (`android15-6.6` for
  Linux 6.6 `6.6.x-android15`, ...).  Loading a mismatched module fails
  cleanly (kpinit ignores it) but gives no root.
