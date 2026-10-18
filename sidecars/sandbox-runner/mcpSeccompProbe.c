/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

static int exact(long result, int expected) { return result == -1 && errno == expected; }

int main(void) {
  struct clone_args args = { .flags = CLONE_NEWUSER };
  errno = 0; int clone3_ok = exact(syscall(SYS_clone3, &args, sizeof(args)), ENOSYS);
  errno = 0; int clone_ok = exact(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0), EPERM);
  errno = 0; int unshare_ok = exact(unshare(CLONE_NEWUSER), EPERM);
  errno = 0; int setns_ok = exact(setns(-1, CLONE_NEWUSER), EPERM);
  errno = 0; int mount_ok = exact(mount("none", "/tmp", "tmpfs", 0, 0), EPERM);
  errno = 0; int fsopen_ok = exact(syscall(SYS_fsopen, "tmpfs", 0), ENOSYS);
  printf("{\"clone3Enosys\":%s,\"cloneNewuserEperm\":%s,\"fsopenEnosys\":%s,\"mountEperm\":%s,\"setnsEperm\":%s,\"unshareEperm\":%s}\n",
    clone3_ok ? "true" : "false", clone_ok ? "true" : "false", fsopen_ok ? "true" : "false",
    mount_ok ? "true" : "false", setns_ok ? "true" : "false", unshare_ok ? "true" : "false");
  return clone3_ok && clone_ok && unshare_ok && setns_ok && mount_ok && fsopen_ok ? 0 : 1;
}
