/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * Namespace and mount restrictions adapted from Flatpak's sandbox filter:
 * https://github.com/flatpak/flatpak/blob/main/common/flatpak-run.c
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int deny(scmp_filter_ctx ctx, const char *name, uint32_t action) {
  int syscall_number = seccomp_syscall_resolve_name_arch(seccomp_arch_native(), name);
  if (syscall_number == __NR_SCMP_ERROR) return -EOPNOTSUPP;
  /* A negative pseudo number means libseccomp knows the syscall name, but the
   * native ABI has no syscall to invoke. There is nothing to filter there. */
  if (syscall_number < 0) return 0;
  return seccomp_rule_add_exact(ctx, action, syscall_number, 0);
}

static int deny_clone_newuser(scmp_filter_ctx ctx) {
  int syscall_number = seccomp_syscall_resolve_name_arch(seccomp_arch_native(), "clone");
  if (syscall_number == __NR_SCMP_ERROR || syscall_number < 0) return -EOPNOTSUPP;
  return seccomp_rule_add_exact(ctx, SCMP_ACT_ERRNO(EPERM), syscall_number, 1,
    SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER));
}

int main(int argc, char **argv) {
  if (argc != 2) return 64;
#if !defined(__aarch64__) && !defined(__x86_64__)
  return 65;
#endif
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
  if (fd < 0) return 66;
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) { close(fd); return 67; }
  int rc = 0;
  const char *eperm[] = { "unshare", "setns", "mount", "umount", "umount2", "pivot_root", "chroot" };
  const char *enosys[] = { "clone3", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr" };
  for (size_t i = 0; i < sizeof(eperm) / sizeof(eperm[0]) && rc == 0; i++) rc = deny(ctx, eperm[i], SCMP_ACT_ERRNO(EPERM));
  for (size_t i = 0; i < sizeof(enosys) / sizeof(enosys[0]) && rc == 0; i++) rc = deny(ctx, enosys[i], SCMP_ACT_ERRNO(ENOSYS));
  if (rc == 0) rc = deny_clone_newuser(ctx);
  if (rc == 0) rc = seccomp_export_bpf(ctx, fd);
  seccomp_release(ctx);
  if (close(fd) != 0 && rc == 0) rc = -errno;
  if (rc != 0) { unlink(argv[1]); return 68; }
  return 0;
}
