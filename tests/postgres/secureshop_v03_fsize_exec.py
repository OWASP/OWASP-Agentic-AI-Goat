"""Pinned same-PID exec boundary for the V03 prerequisite owner, not authority.

The parent admits the command and records both argv forms. RLIMIT_FSIZE applies
to every regular file written by this child, not an aggregate filesystem quota.
"""
import hashlib
import os
import pathlib
import re
import resource
import stat
import sys

LIMIT = 8 * 1024 * 1024


def execute(argv, expected):
    if not argv or not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise RuntimeError('Exact executable pin required')
    executable = pathlib.Path(argv[0])
    if (not executable.is_absolute() or executable.is_symlink()
            or executable.resolve() != executable or not executable.is_file()):
        raise RuntimeError('Canonical executable required')
    if hashlib.sha256(executable.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Executable pin changed')
    for fd in (1, 2):
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError('Owned regular output required')
    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if hard != resource.RLIM_INFINITY and hard < LIMIT:
        raise RuntimeError('Inherited hard limit too small')
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    os.execv(str(executable), argv)


if __name__ == '__main__':
    if len(sys.argv) < 4 or sys.argv[2] != '--':
        raise RuntimeError('Closed wrapper argv required')
    execute(sys.argv[3:], sys.argv[1])
