"""V27 live-profile-bound retirement of Chrome's two singleton temp entries."""
import os
import stat
import time
from pathlib import Path

_KEY = object()
class SingletonNotReady(FileNotFoundError):
    """Only expected Chrome startup entries are not present yet."""

def identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode)

def directory(path):
    path = Path(path)
    if path.resolve() != path:
        raise RuntimeError('Chrome singleton directory alias')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
    except BaseException:
        os.close(fd)
        raise
    try:
        value = os.fstat(fd)
        if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700:
            raise RuntimeError('Chrome singleton directory ownership')
        return fd
    except BaseException:
        os.close(fd)
        raise

def link(fd, name):
    try:
        value = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError as error:
        raise SingletonNotReady(name) from error
    if not stat.S_ISLNK(value.st_mode) or value.st_uid != os.getuid():
        raise RuntimeError('Chrome singleton link ownership')
    target = os.readlink(name, dir_fd=fd)
    if identity(value) != identity(os.stat(name, dir_fd=fd, follow_symlinks=False)):
        raise RuntimeError('Chrome singleton link changed')
    return target, identity(value)

class CapturedSingleton:
    def __init__(self, key, root, name, root_id, dir_id, entries, cookie):
        if key is not _KEY:
            raise RuntimeError('Chrome singleton capture authority')
        self.root, self.name, self.root_id = root, name, root_id
        self.dir_id, self.entries, self.cookie = dir_id, entries, cookie

def capture(profile, temp_root):
    """Only an exact live profile link grants authority; no directory discovery."""
    profile, temp_root = Path(profile), Path(temp_root)
    pfd = directory(profile)
    try:
        socket_path, _ = link(pfd, 'SingletonSocket')
        cookie, _ = link(pfd, 'SingletonCookie')
        target = Path(socket_path)
        if not target.is_absolute() or target.name != 'SingletonSocket' \
                or target.parent.parent != temp_root \
                or not target.parent.name.startswith('com.google.Chrome.'):
            raise RuntimeError('Chrome singleton socket outside owned temp root')
        rfd = directory(temp_root)
        try:
            try:
                dfd = os.open(target.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
            except FileNotFoundError as error:
                raise SingletonNotReady('singleton directory') from error
            try:
                info = os.fstat(dfd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 \
                        or set(os.listdir(dfd)) - {'SingletonCookie', 'SingletonSocket'}:
                    raise RuntimeError('Chrome singleton unexpected directory contents')
                actual_cookie, cookie_id = link(dfd, 'SingletonCookie')
                try:
                    sock = os.stat('SingletonSocket', dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError as error:
                    raise SingletonNotReady('SingletonSocket') from error
                if actual_cookie != cookie or not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != os.getuid():
                    raise RuntimeError('Chrome singleton live profile mismatch')
                if link(pfd, 'SingletonSocket')[0] != socket_path or link(pfd, 'SingletonCookie')[0] != cookie:
                    raise RuntimeError('Chrome singleton profile changed')
                return CapturedSingleton(_KEY, temp_root, target.parent.name,
                    identity(os.fstat(rfd)), identity(info),
                    {'SingletonCookie': cookie_id, 'SingletonSocket': identity(sock)}, cookie)
            finally:
                os.close(dfd)
        finally:
            os.close(rfd)
    finally:
        os.close(pfd)

def capture_until(profile, temp_root, verify_live, deadline, stop, clock=time.monotonic):
    """Share the birth watcher's existing absolute deadline; no new budget."""
    while not stop.is_set() and clock() < deadline:
        live = verify_live()
        try:
            proof = capture(profile, temp_root)
        except SingletonNotReady:
            stop.wait(min(0.025, max(0, deadline-clock())))
            continue
        verify_live()
        if stop.is_set() or clock() >= deadline:
            break
        return live, proof
    raise RuntimeError('Policy browser singleton capture deadline or owner stopped')

def retire(captured, record, api):
    if not isinstance(captured, CapturedSingleton):
        raise RuntimeError('Chrome singleton uncaptured')
    for pid in {record['pid'], record['parentPid'], record['pgid']}:
        if api.identity(pid) is not None or api.group_pids(pid):
            raise RuntimeError('Chrome singleton process remains')
    rfd = directory(captured.root)
    try:
        if identity(os.fstat(rfd)) != captured.root_id:
            raise RuntimeError('Chrome singleton temp root changed')
        try:
            dfd = os.open(captured.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rfd)
        except FileNotFoundError:
            return {'singletonTempAbsent': True, 'removed': []}
        try:
            if identity(os.fstat(dfd)) != captured.dir_id:
                raise RuntimeError('Chrome singleton directory changed')
            names = os.listdir(dfd)
            if set(names) - set(captured.entries):
                raise RuntimeError('Chrome singleton unexpected entry')
            for name in names:
                if identity(os.stat(name, dir_fd=dfd, follow_symlinks=False)) != captured.entries[name]:
                    raise RuntimeError('Chrome singleton entry changed')
                if name == 'SingletonCookie' and os.readlink(name, dir_fd=dfd) != captured.cookie:
                    raise RuntimeError('Chrome singleton cookie changed')
            for name in names:
                if identity(os.stat(name, dir_fd=dfd, follow_symlinks=False)) != captured.entries[name]:
                    raise RuntimeError('Chrome singleton entry changed before retirement')
                os.unlink(name, dir_fd=dfd)
            if identity(os.stat(captured.name, dir_fd=rfd, follow_symlinks=False)) != captured.dir_id:
                raise RuntimeError('Chrome singleton directory changed before retirement')
            os.rmdir(captured.name, dir_fd=rfd)
            return {'singletonTempAbsent': True, 'removed': sorted(names)}
        finally:
            os.close(dfd)
    finally:
        os.close(rfd)
