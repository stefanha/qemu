/*
 * Seccomp sandboxing for virtiofsd
 *
 * Copyright (C) 2019 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <errno.h>
#include <seccomp.h>
#include <glib.h>
#include "fuse_i.h"
#include "fuse_log.h"
#include "seccomp.h"

static const int syscall_whitelist[] = {
	/* TODO ireg sem*() syscalls */
	SCMP_SYS(brk),
	SCMP_SYS(clone),
	SCMP_SYS(close),
	SCMP_SYS(copy_file_range),
	SCMP_SYS(dup),
	SCMP_SYS(eventfd2),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fallocate),
	SCMP_SYS(fchmodat),
	SCMP_SYS(fchownat),
	SCMP_SYS(fcntl),
	SCMP_SYS(fdatasync),
	SCMP_SYS(fgetxattr),
	SCMP_SYS(flistxattr),
	SCMP_SYS(flock),
	SCMP_SYS(fremovexattr),
	SCMP_SYS(fsetxattr),
	SCMP_SYS(fstat),
	SCMP_SYS(fstatfs),
	SCMP_SYS(fsync),
	SCMP_SYS(ftruncate),
	SCMP_SYS(futex),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
	SCMP_SYS(geteuid),
	SCMP_SYS(getpid),
	SCMP_SYS(gettid),
	SCMP_SYS(gettimeofday),
	SCMP_SYS(linkat),
	SCMP_SYS(lseek),
	SCMP_SYS(madvise),
	SCMP_SYS(mkdirat),
	SCMP_SYS(mknodat),
	SCMP_SYS(mmap),
	SCMP_SYS(mprotect),
	SCMP_SYS(mremap),
	SCMP_SYS(munmap),
	SCMP_SYS(newfstatat),
	SCMP_SYS(open),
	SCMP_SYS(openat),
	SCMP_SYS(ppoll),
	SCMP_SYS(preadv),
	SCMP_SYS(pwrite64),
	SCMP_SYS(read),
	SCMP_SYS(readlinkat),
	SCMP_SYS(recvmsg),
	SCMP_SYS(renameat),
	SCMP_SYS(renameat2),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sendmsg),
	SCMP_SYS(setresgid),
	SCMP_SYS(setresuid),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(symlinkat),
	SCMP_SYS(time), /* Rarely needed, except on static builds */
	SCMP_SYS(tgkill),
	SCMP_SYS(unlinkat),
	SCMP_SYS(utimensat),
	SCMP_SYS(write),
};

/* Syscalls used when --syslog is enabled */
static const int syscall_whitelist_syslog[] = {
	SCMP_SYS(sendto),
};

static void add_whitelist(scmp_filter_ctx ctx, const int syscalls[],
			  size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
				     syscalls[i], 0) != 0) {
			fuse_log(FUSE_LOG_ERR, "seccomp_rule_add syscall %d failed\n",
				 syscalls[i]);
			exit(1);
		}
	}
}

void setup_seccomp(bool enable_syslog)
{
	scmp_filter_ctx ctx;

#ifdef SCMP_ACT_KILL_PROCESS
 	ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	/* Handle a newer libseccomp but an older kernel */
	if (!ctx && errno == EOPNOTSUPP) {
		ctx = seccomp_init(SCMP_ACT_KILL);
	}
#else
	ctx = seccomp_init(SCMP_ACT_KILL);
#endif
	if (!ctx) {
		fuse_log(FUSE_LOG_ERR, "seccomp_init() failed\n");
		exit(1);
	}

	add_whitelist(ctx, syscall_whitelist, G_N_ELEMENTS(syscall_whitelist));
	if (enable_syslog) {
		add_whitelist(ctx, syscall_whitelist_syslog,
			      G_N_ELEMENTS(syscall_whitelist_syslog));
	}

	/* libvhost-user calls this for post-copy migration, we don't need it */
	if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(userfaultfd), 0) != 0) {
		fuse_log(FUSE_LOG_ERR, "seccomp_rule_add userfaultfd failed\n");
		exit(1);
	}

	if (seccomp_load(ctx) < 0) {
		fuse_log(FUSE_LOG_ERR, "seccomp_load() failed\n");
		exit(1);
	}

	seccomp_release(ctx);
}
