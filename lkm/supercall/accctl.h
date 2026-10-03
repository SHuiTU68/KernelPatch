/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Credential switching. Ported from kernel/patch/common/accctl.c but uses the
 * real struct cred fields directly (the ko is KMI-bound, so offsets match),
 * avoiding KP's hardcoded cred_offset. SELinux translabel (set_security_
 * override_from_ctx) is TODO — it needs KP's sepolicy machinery.
 */
#ifndef _KP_LKM_ACCCTL_H_
#define _KP_LKM_ACCCTL_H_
#include <linux/types.h>

/* Resolve the SELinux translabel helper at init. */
int kp_accctl_init(void);

/* ---- all-allow scontext (SELinux avc_denied bypass) -------------------- */

/* Install the avc_denied hook that makes the all-allow SELinux context
 * effectively unconfined. Must be called after kp_hook_runtime_init(). */
int kp_bypass_selinux_init(void);

/* Remove the hook (call on module exit). */
void kp_bypass_selinux_exit(void);

/* True once the avc_denied hook is installed. */
bool kp_selinux_bypass_active(void);

/* Configured all-allow context ("" when unset). */
const char *kp_get_all_allow_sctx(void);

/* Point the bypass at @sctx (NULL/"" clears it). Fails with -EOPNOTSUPP while
 * the bypass is not installed, so a half-working setup is impossible. */
int kp_set_all_allow_sctx(const char *sctx);

/* Default context for a granted root: the all-allow context when armed,
 * otherwise the magisk domain. Never returns "". */
const char *kp_get_default_su_sctx(void);

/* Grant root to the current task (uid/gid -> to_uid, all caps). */
int kp_commit_su(uid_t to_uid, const char *sctx);

/* Grant root to another task by pid. */
int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx);

#endif /* _KP_LKM_ACCCTL_H_ */
