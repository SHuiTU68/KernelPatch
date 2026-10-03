// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * The ko is compiled against a fixed KMI, so struct cred fields are directly
 * addressable (KP's kpimg needs runtime cred_offset instead). Full root =
 * all capabilities + uid/gid switch via a freshly prepared cred. The SELinux
 * translabel helper is resolved at runtime like KP does.
 */
#include "accctl.h"

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"

#include <hook.h>

/* security_secctx_to_secid is EXPORT_SYMBOL on 5.15 — link it directly. */
extern int security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);

/* selinux_blob_sizes is a global; resolve via kallsyms. cred->security is a
 * pointer to the LSM cred blob; the selinux part lives at +lbs_cred. */
struct kp_lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

static struct kp_lsm_blob_sizes *kp_selinux_blob_sizes;

/* task_security_struct { osid, sid, ... } — RANDSTRUCT is off, so sid is the
 * second u32 (offset 4). */
struct kp_task_sec {
	u32 osid;
	u32 sid;
};

int kp_accctl_init(void)
{
	kp_selinux_blob_sizes = (struct kp_lsm_blob_sizes *)kp_resolve_symbol("selinux_blob_sizes");
	if (!kp_selinux_blob_sizes) {
		logke("failed to resolve selinux_blob_sizes; selinux translabel disabled\n");
		return 0;
	}
	logki("selinux blob sizes: lbs_cred=%d\n", kp_selinux_blob_sizes->lbs_cred);
	return 0;
}

/* ---- all-allow scontext (SELinux avc_denied bypass) -------------------- *
 *
 * A translabelled su cred alone is not enough. The stock AOSP kernel domain
 * (u:r:kernel:s0) has no rules allowing it to exec /system/bin/sh, connect
 * sockets or run ART, so a root process dropped into it dies immediately
 * (observed: libsu RootServer ClassNotFoundException). The kpimg (kernel
 * image) path solves this by hooking SELinux' avc_denied so the resolved
 * all_allow_sid is always allowed -- see kernel/patch/common/accctl.c. This is
 * the same trick for the LKM (ramdisk/init_boot) path, which had only the
 * magisk domain because it never had the bypass.
 *
 * Safety: the sid is armed only after the hook is verified installed, so a
 * missing symbol or a failed hook degrades to the magisk domain instead of
 * producing a half-broken su (see kp_get_default_su_sctx / kp_commit_su).
 */
char kp_all_allow_sctx[SUPERCALL_SCONTEXT_LEN];
static u32 kp_all_allow_sid;

static bool kp_bypass_installed;
static unsigned long kp_avc_denied_addr;
static int (*kp_avc_denied_backup)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
				   uintptr_t, uintptr_t, uintptr_t, uintptr_t,
				   uintptr_t);

bool kp_selinux_bypass_active(void)
{
	return kp_bypass_installed;
}

const char *kp_get_all_allow_sctx(void)
{
	return kp_all_allow_sctx;
}

int kp_set_all_allow_sctx(const char *sctx)
{
	u32 sid = 0;
	int rc;

	if (!sctx || !sctx[0]) {
		kp_all_allow_sctx[0] = '\0';
		kp_all_allow_sid = 0;
		logki("all-allow scontext cleared\n");
		return 0;
	}

	if (!kp_bypass_installed) {
		logkw("all-allow scontext %s refused: avc_denied bypass inactive\n", sctx);
		return -EOPNOTSUPP;
	}

	rc = security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("all-allow scontext %s unresolvable: %d\n", sctx, rc);
		return rc ? rc : -EINVAL;
	}

	strscpy(kp_all_allow_sctx, sctx, sizeof(kp_all_allow_sctx));
	kp_all_allow_sid = sid;
	logki("all-allow scontext: %s (sid %u)\n", kp_all_allow_sctx, sid);
	return 0;
}

const char *kp_get_default_su_sctx(void)
{
	if (kp_all_allow_sctx[0])
		return kp_all_allow_sctx;
	return ALL_ALLOW_SCONTEXT_MAGISK;
}

/* Replacement for SELinux' avc_denied(). Whether the (removed in 6.4) struct
 * selinux_state * is the first argument differs per KMI, and it cannot be
 * probed at compile time here: a first argument above 4G can never be a u32
 * ssid, so both layouts are handled at runtime. */
__attribute__((no_sanitize("cfi")))
static int kp_avc_denied_replace(uintptr_t a0, uintptr_t a1, uintptr_t a2,
				 uintptr_t a3, uintptr_t a4, uintptr_t a5,
				 uintptr_t a6, uintptr_t a7, uintptr_t a8)
{
	uintptr_t avd = a8;
	u32 ssid = (u32)a1;

	if (a0 <= 0xffffffffUL) {
		/* No selinux_state param: a0 is the ssid, a7 the decision. */
		ssid = (u32)a0;
		avd = a7;
	}

	/* Kernel threads are already labelled u:r:kernel:s0 by the stock policy
	 * and are explicitly excluded, so the bypass can never widen their
	 * (unrelated) checks -- only the su process that we put in that domain
	 * inherits it. */
	if (kp_all_allow_sid && ssid == kp_all_allow_sid && avd &&
	    !(current->flags & PF_KTHREAD)) {
		u32 *decision = (u32 *)avd;

		decision[0] = 0xffffffff; /* allowed */
		decision[1] = 0;          /* auditallow */
		decision[2] = 0;          /* auditdeny */
		return 0;
	}

	if (!kp_avc_denied_backup)
		return 0;
	return kp_avc_denied_backup(a0, a1, a2, a3, a4, a5, a6, a7, a8);
}

int kp_bypass_selinux_init(void)
{
	unsigned long addr;
	int rc;

	addr = (unsigned long)kp_resolve_symbol_variant("avc_denied");
	if (!addr)
		addr = kp_resolve_symbol("avc_denied");
	if (!addr) {
		logkw("avc_denied not found; SELinux bypass unavailable\n");
		return -ENOENT;
	}

	rc = hook((void *)addr, (void *)kp_avc_denied_replace,
		  (void **)&kp_avc_denied_backup);
	if (rc) {
		logkw("hook avc_denied (%px) failed: %d\n", (void *)addr, rc);
		return rc;
	}

	kp_avc_denied_addr = addr;
	kp_bypass_installed = true;
	logki("SELinux bypass installed (avc_denied at %px)\n", (void *)addr);

	/* Default target: the kernel domain, so a su granted by an init_boot /
	 * ramdisk patched device no longer has to borrow the magisk domain. The
	 * manager can retarget it with SUPERCALL_SU_SET_ALLOW_SCTX or by writing
	 * /data/adb/ap/su_sctx (read at module init). */
	rc = kp_set_all_allow_sctx(ALL_ALLOW_SCONTEXT_KERNEL);
	if (rc)
		logkw("default all-allow scontext failed: %d\n", rc);
	return 0;
}

void kp_bypass_selinux_exit(void)
{
	if (kp_avc_denied_addr) {
		unhook((void *)kp_avc_denied_addr);
		kp_avc_denied_addr = 0;
		kp_avc_denied_backup = NULL;
		kp_bypass_installed = false;
		kp_all_allow_sctx[0] = '\0';
		kp_all_allow_sid = 0;
	}
}

/* Translabel a freshly-prepared cred to the given SELinux context (5.15 has no
 * set_security_override_from_ctx; it was removed in GKI). Resolve the context
 * to a sid and write tsec->sid directly. */
static int kp_selinux_set_cred_context(struct cred *new, const char *sctx)
{
	struct kp_task_sec *tsec;
	u32 sid;
	int rc;

	if (!kp_selinux_blob_sizes || !sctx || !sctx[0])
		return -EINVAL;

	rc = security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("secctx_to_secid(%s) failed: %d sid=%u\n", sctx, rc, sid);
		return rc ? rc : -EINVAL;
	}

	tsec = (struct kp_task_sec *)((char *)new->security + kp_selinux_blob_sizes->lbs_cred);
	tsec->sid = sid;
	return 0;
}

/* Fill every capability in a kernel_cap_t. */
static void fill_caps(struct cred *new)
{
	kernel_cap_t all = CAP_FULL_SET;
	new->cap_effective = all;
	new->cap_permitted = all;
	new->cap_inheritable = all;
	new->cap_bset = all;
	new->cap_ambient = all;
}

static void su_cred(struct cred *new, uid_t uid)
{
	fill_caps(new);
	new->uid = make_kuid(current_user_ns(), uid);
	new->euid = new->uid;
	new->fsuid = new->uid;
	new->suid = new->uid;
	new->gid = make_kgid(current_user_ns(), uid);
	new->egid = new->gid;
	new->fsgid = new->gid;
	new->sgid = new->gid;
}

/* no_sanitize("cfi") keeps indirect calls in this function from tripping
 * __cfi_check on traditional-CFI 5.15 kernels. */
__attribute__((no_sanitize("cfi")))
static int commit_common_su(uid_t to_uid, const char *sctx)
{
	struct cred *new = prepare_creds();
	if (!new)
		return -ENOMEM;

	su_cred(new, to_uid);

	/* Translabel to sctx (e.g. u:r:magisk:s0 / u:r:kp:s0). Without this the
	 * granted process keeps its untrusted_app SELinux domain while running as
	 * uid 0 with all caps — Android blocks it and the app fails to open. If
	 * translabel fails, abort the creds so the caller falls back to another
	 * domain instead of committing an untranslabelled root. */
	if (sctx && sctx[0]) {
		int rc = kp_selinux_set_cred_context(new, sctx);
		if (rc) {
			logkw("selinux set context(%s) failed: %d\n", sctx, rc);
			abort_creds(new);
			return rc;
		}
	}

	commit_creds(new);
	return 0;
}

/* Resolve the scontext a grant should end up in.
 *
 * u:r:kernel:s0 is only usable while the AVC bypass is armed: without it the
 * stock kernel domain has no rules to exec /system/bin/sh, open sockets or run
 * ART, so a process put there dies. Falling back to the magisk domain keeps a
 * device without the bypass (e.g. an old kernel where avc_denied was not
 * found) fully working instead of granting a root that cannot do anything. */
static const char *kp_effective_su_sctx(const char *sctx)
{
	if (!sctx || !sctx[0])
		return kp_get_default_su_sctx();
	if (!kp_selinux_bypass_active() && strcmp(sctx, ALL_ALLOW_SCONTEXT_KERNEL) == 0) {
		logkw("kernel domain requested without the SELinux bypass; using magisk\n");
		return ALL_ALLOW_SCONTEXT_MAGISK;
	}
	return sctx;
}

__attribute__((no_sanitize("cfi")))
int kp_commit_su(uid_t to_uid, const char *sctx)
{
	const char *def;
	int rc;

	/* Disable seccomp on the caller, matching KP's commit_common_su. */
	current_thread_info()->flags &= ~_TIF_SECCOMP;

	def = kp_effective_su_sctx(sctx);

	if (kp_selinux_blob_sizes) {
		rc = commit_common_su(to_uid, def);
		if (!rc) {
			logki("commit_su: to_uid=%u sctx=%s\n", to_uid, def);
			return 0;
		}
		logkw("sctx %s translabel failed (%d)\n", def, rc);
		if (strcmp(def, ALL_ALLOW_SCONTEXT_MAGISK)) {
			rc = commit_common_su(to_uid, ALL_ALLOW_SCONTEXT_MAGISK);
			if (!rc) {
				logki("commit_su: to_uid=%u magisk domain (fallback)\n", to_uid);
				return 0;
			}
			logkw("magisk domain translabel failed (%d)\n", rc);
		}
	}

	/* Last resort: a raw kernel cred still gives uid 0 + all caps. */
	{
		struct cred *new = prepare_kernel_cred(NULL);
		if (!new)
			return -ENOMEM;
		commit_creds(new);
	}
	logki("commit_su: to_uid=%u kernel cred\n", to_uid);
	return 0;
}

int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
	struct task_struct *task;
	const struct cred *old;
	struct cred *new;

	task = find_get_task_by_vpid(pid);
	if (!task) {
		logke("task_su: no task pid %d\n", pid);
		return -ESRCH;
	}

	new = prepare_creds();
	if (!new) {
		put_task_struct(task);
		return -ENOMEM;
	}
	su_cred(new, to_uid);
	/* Honour the requested/default domain here too: this used to be ignored,
	 * which left pid-targeted grants stuck in the called task's old domain. */
	sctx = kp_effective_su_sctx(sctx);
	if (sctx && sctx[0] && kp_selinux_blob_sizes &&
	    kp_selinux_set_cred_context(new, sctx))
		logkw("task_su: translabel %s failed, keeping old domain\n", sctx);

	rcu_read_lock();
	old = task->cred;
	rcu_assign_pointer(task->cred, new);
	rcu_assign_pointer(task->real_cred, new);
	rcu_read_unlock();
	put_cred(old);

	put_task_struct(task);
	logki("task_su: pid %d -> uid %u\n", pid, to_uid);
	return 0;
}
