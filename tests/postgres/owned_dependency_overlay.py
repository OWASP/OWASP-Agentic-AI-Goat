"""Exact dependency metadata overlay within a launcher-owned runtime copy."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile


def install_owned_metadata(source, destination, owned_root, expected_sha256):
    source, destination, root = Path(source), Path(destination), Path(owned_root)
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError('canonical owned runtime root required')
    if not destination.is_absolute() or '..' in destination.parts:
        raise ValueError('canonical destination without traversal required')
    if not destination.is_relative_to(root) or destination == root:
        raise ValueError('destination must be inside owned runtime root')
    if not destination.parent.resolve(strict=True).is_relative_to(root):
        raise ValueError('resolved destination parent escaped owned root')
    current = destination
    while current != root:
        if current.is_symlink():
            raise ValueError('symlink destination ancestry forbidden')
        if current.parent == current:
            raise ValueError('destination ancestry never reached owned root')
        current = current.parent
    if source.is_symlink() or not source.is_file() or not destination.is_file():
        raise ValueError('regular existing metadata files required')
    if source.resolve() == destination.resolve():
        raise ValueError('source must not be the runtime destination')
    payload = source.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError('approved source hash mismatch')
    before = destination.stat()
    if before.st_uid != os.getuid() or not stat.S_ISREG(before.st_mode):
        raise ValueError('destination must be owned regular file')
    if hashlib.sha256(destination.read_bytes()).hexdigest() == expected_sha256:
        return 'unchanged'
    # Never chmod the source, destination or parent. An unwritable parent fails
    # closed; a writable owned directory permits atomic replacement of its file.
    parent = destination.parent.stat()
    if parent.st_uid != os.getuid():
        raise ValueError('destination directory must be owned')
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix='.dependency-overlay-', dir=destination.parent)
        temporary = Path(name)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(stat.S_IMODE(before.st_mode))
        now = destination.lstat()
        if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(now.st_mode):
            raise ValueError('destination changed during metadata preparation')
        os.replace(temporary, destination)
        return 'replaced'
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def prepare_owned_runtime_directories(frozen_source, destination, evidence_root):
    """Make only a fresh launcher's owned source-copy directories writable.

    Call before dependency symlinks are installed. All regular file modes/bytes
    stay unchanged. Frozen source and dependency trees are outside this boundary.
    """
    source, root, parent = map(Path, (frozen_source, destination, evidence_root))
    for value in (source, root, parent):
        if not value.is_absolute() or '..' in value.parts or value.is_symlink() or value.resolve(strict=True) != value:
            raise ValueError('canonical non-symlink copy paths required')
    if root.parent != parent or root.name != 'source' or root == source or root.is_relative_to(source) or source.is_relative_to(root):
        raise ValueError('fresh source copy must be direct child of separate evidence root')
    if parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
        raise ValueError('private owned evidence directory required')
    paths = [root, *root.rglob('*')]
    directories = []
    # Validate the complete copy BEFORE changing any directory. Dependency links
    # must not exist yet; never follow an arbitrary path into a frozen tree.
    for item in paths:
        info = item.lstat()
        if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
            raise ValueError('only owned non-symlink runtime copy entries permitted')
        if stat.S_ISDIR(info.st_mode):
            directories.append((item, info))
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError('special runtime copy entry forbidden')
    for item, before in directories:
        now = item.lstat()
        if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('runtime directory changed during preparation')
        item.chmod(stat.S_IMODE(before.st_mode) | 0o700)
    return len(directories)


def vite_config_arguments(containment):
    # The frozen .vite-temp directory must never receive config bundles. The
    # reviewed application config is .mjs and can use Node's native ESM loader.
    return ['--configLoader', 'native'] if containment else []
