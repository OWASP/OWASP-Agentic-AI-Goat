"""Permission repair for a disposable copy of read-only reviewed source."""

import os
import stat
from pathlib import Path


def make_copied_directories_owner_writable(copied_root):
    """Make only directories in a private copied tree writable by its owner."""
    root = Path(copied_root)
    if not root.is_absolute():
        raise RuntimeError('copied source root must be absolute')
    try:
        root_status = root.lstat()
    except FileNotFoundError as error:
        raise RuntimeError('copied source root is unavailable') from error
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise RuntimeError('copied source root must be a real directory')

    resolved_root = root.resolve(strict=True)
    directories = [root]
    # Complete validation before the first chmod. A copied directory symlink
    # must never redirect a permission change outside this private tree.
    for current, names, _files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        current_status = current_path.lstat()
        if stat.S_ISLNK(current_status.st_mode) or not stat.S_ISDIR(current_status.st_mode):
            raise RuntimeError('copied source tree contains an invalid directory')
        for name in names:
            child = current_path / name
            child_status = child.lstat()
            if stat.S_ISLNK(child_status.st_mode) or not stat.S_ISDIR(child_status.st_mode):
                raise RuntimeError('copied source tree contains a directory symlink')
            resolved_child = child.resolve(strict=True)
            if os.path.commonpath((str(resolved_root), str(resolved_child))) != str(resolved_root):
                raise RuntimeError('copied source directory escapes its private root')
            directories.append(child)

    for directory in directories:
        status = directory.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise RuntimeError('copied source directory changed during permission repair')
        os.chmod(directory, stat.S_IMODE(status.st_mode) | stat.S_IWUSR | stat.S_IXUSR,
                 follow_symlinks=False)


