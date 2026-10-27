"""Read-only Darwin process-group inventory without executing setuid ps.

This module never signals processes. Callers retain launch/group authority;
two BSD identity reads fence each session lookup against PID reuse.
"""

import ctypes
import errno
import os
import sys
import time
import math


PROC_ALL_PIDS = 1
PROC_PGRP_ONLY = 2
PROC_PIDTBSDINFO = 3
SZOMB = 5
MAX_ARG_BYTES = 4 * 1024 * 1024


class ProcBsdInfo(ctypes.Structure):
    # Darwin SDK sys/proc_info.h, MAXCOMLEN=16; native ABI, not packed.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid',
        'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
                ('start_usec', ctypes.c_uint64)]


class ProcBsdShortInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ('pid', 'ppid', 'pgid', 'status')]
    _fields_ += [('comm', ctypes.c_char * 16)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'flags', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]


class LibProc:
    def __init__(self):
        if ctypes.sizeof(ProcBsdInfo) != 136 or ctypes.sizeof(ProcBsdShortInfo) != 64:
            raise RuntimeError('Darwin process inventory ABI unavailable')
        self.library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.library.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_int]
        self.library.proc_listpids.restype = ctypes.c_int
        self.library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int,
                                            ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.library.proc_pidinfo.restype = ctypes.c_int
        self.system = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        self.system.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                      ctypes.c_void_p, ctypes.c_size_t]
        self.system.sysctl.restype = ctypes.c_int

    def group_pids(self, pgid):
        return self._pids(PROC_PGRP_ONLY, pgid)

    def all_pids(self):
        return self._pids(PROC_ALL_PIDS, 0)

    def _pids(self, kind, value):
        # A full buffer cannot prove completeness. Retry with bounded growth.
        capacity = 256
        while capacity <= 65536:
            buffer = (ctypes.c_int * capacity)()
            size = ctypes.sizeof(buffer)
            ctypes.set_errno(0)
            returned = self.library.proc_listpids(kind, value, buffer, size)
            error = ctypes.get_errno()
            if returned < 0 or error or returned > size or returned % ctypes.sizeof(ctypes.c_int):
                raise RuntimeError('Owned test process group inventory unavailable')
            if returned == size:
                capacity *= 2
                continue
            pids = list(buffer[:returned // ctypes.sizeof(ctypes.c_int)])
            if any(pid < 0 or (pid == 0 and kind != PROC_ALL_PIDS) for pid in pids) \
                    or len(pids) != len(set(pids)):
                raise RuntimeError('Owned test process group inventory malformed')
            # PID 0 is the kernel task, not an executable browser process.
            return [pid for pid in pids if pid != 0]
        raise RuntimeError('Owned test process group inventory truncated')

    def identity(self, pid):
        info = ProcBsdInfo()
        ctypes.set_errno(0)
        returned = self.library.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0,
                                            ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        if returned <= 0 and error == errno.ESRCH:
            return None
        if returned != ctypes.sizeof(info) or error:
            raise RuntimeError('Owned test process group inventory unavailable')
        if info.pid != pid or not info.start_sec or info.start_usec >= 1000000:
            raise RuntimeError('Owned test process group inventory malformed')
        return info

    def short_identity(self, pid):
        # Unlike full BSD info, this flavor admits protected foreign processes.
        info = ProcBsdShortInfo()
        ctypes.set_errno(0)
        returned = self.library.proc_pidinfo(pid, 13, 0, ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        if returned <= 0 and error == errno.ESRCH:
            return None
        if returned != ctypes.sizeof(info) or error:
            raise RuntimeError('Darwin process metadata unavailable')
        if info.pid != pid:
            raise RuntimeError('Darwin process metadata malformed')
        return info

    def arguments(self, pid):
        # CTL_KERN / KERN_PROCARGS2. The buffer also contains environment
        # bytes; parse exactly argc and never return/log the environment.
        mib = (ctypes.c_int * 3)(1, 49, pid)
        size = ctypes.c_size_t()
        ctypes.set_errno(0)
        result = self.system.sysctl(mib, 3, None, ctypes.byref(size), None, 0)
        error = ctypes.get_errno()
        if result != 0 or error:
            raise OSError(error or errno.EIO, 'Darwin process arguments unavailable')
        if not 5 <= size.value <= MAX_ARG_BYTES:
            raise RuntimeError('Darwin process arguments size invalid')
        buffer = ctypes.create_string_buffer(size.value)
        capacity = size.value
        ctypes.set_errno(0)
        result = self.system.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0)
        error = ctypes.get_errno()
        if result != 0 or error:
            raise OSError(error or errno.EIO, 'Darwin process arguments unavailable')
        if not 5 <= size.value <= capacity:
            raise RuntimeError('Darwin process arguments truncated')
        return parse_arguments(buffer.raw[:size.value])


def parse_arguments(raw):
    """Decode KERN_PROCARGS2's executable/padding/argc strings, not env."""
    if not isinstance(raw, bytes) or not 5 <= len(raw) <= MAX_ARG_BYTES:
        raise RuntimeError('Darwin process arguments malformed')
    count = int.from_bytes(raw[:4], sys.byteorder, signed=True)
    if not 1 <= count <= 65536:
        raise RuntimeError('Darwin process argument count invalid')
    executable_end = raw.find(b'\0', 4)
    if executable_end <= 4:
        raise RuntimeError('Darwin process executable missing')
    cursor = executable_end + 1
    while cursor < len(raw) and raw[cursor] == 0:
        cursor += 1
    arguments = []
    for _ in range(count):
        end = raw.find(b'\0', cursor)
        if end < 0:
            raise RuntimeError('Darwin process arguments truncated')
        arguments.append(os.fsdecode(raw[cursor:end]))
        cursor = end + 1
    return tuple(arguments)


def _before_deadline(deadline, operation, *args):
    # Synchronous kernel calls cannot be forcibly cancelled. Check both sides
    # and every iteration; a late observation must never become absence proof.
    def check():
        if deadline is not None and (type(deadline) not in (int, float)
                or not math.isfinite(deadline) or time.monotonic() >= deadline):
            raise RuntimeError('Darwin process inventory deadline expired')
    check()
    result = operation(*args)
    check()
    return result


def process_records(*, include_arguments=False, uid=None, api=None, getsid=None, deadline=None):
    """Full PID/group/session roster plus argv for live current-user processes.

    Command-line scans include effective/real-UID peers outside the original
    group/session. Foreign-UID metadata remains for journal identity-reuse
    checks. Unreadable privileged processes retaining our real UID deny the
    command-line scan; metadata-only checks remain available.
    Unreadable live current-user argv is uncertainty, never absence proof.
    """
    uid = os.getuid() if uid is None else uid
    api = LibProc() if api is None else api
    getsid = os.getsid if getsid is None else getsid
    rows = []
    for pid in _before_deadline(deadline, api.all_pids):
        short = _before_deadline(deadline, api.short_identity, pid)
        if short is None:
            continue
        owned = short.uid == uid
        read_identity = api.identity if owned else api.short_identity
        first = _before_deadline(deadline, read_identity, pid) if owned else short
        if first is None:
            continue
        if (short.pid, short.pgid, short.uid, short.ruid) != \
                (first.pid, first.pgid, first.uid, first.ruid):
            raise RuntimeError('Darwin process identity changed')
        try:
            session = _before_deadline(deadline, getsid, pid)
        except ProcessLookupError:
            continue
        except OSError as error:
            raise RuntimeError('Darwin process session unavailable') from error
        arguments = None
        argument_error = None
        if include_arguments and (owned or first.ruid == uid) and first.status != SZOMB:
            try:
                arguments = _before_deadline(deadline, api.arguments, pid)
            except OSError as error:
                argument_error = error
        second = _before_deadline(deadline, read_identity, pid)
        if second is None:
            continue
        if (first.pid, first.uid, first.ruid, first.pgid) != \
                (second.pid, second.uid, second.ruid, second.pgid) \
                or first.pid != pid or first.pgid <= 0 or session <= 0:
            raise RuntimeError('Darwin process identity changed')
        if owned and (first.start_sec, first.start_usec) != (second.start_sec, second.start_usec):
            raise RuntimeError('Darwin process identity changed')
        if argument_error is not None and second.status != SZOMB:
            raise RuntimeError('Darwin relevant live process arguments unavailable') from argument_error
        rows.append({'pid': pid, 'pgid': first.pgid, 'sessionId': session,
                     'uid': first.uid, 'start': (first.start_sec, first.start_usec) if owned else None,
                     'arguments': arguments})
    return rows


def owned_group_members(pgid, *, uid=None, api=None, getsid=None, births=None, deadline=None):
    """Return live owned members; unknown/changed identities fail closed.

    ``births`` optionally retains observed PID births across cleanup polls. It
    does not manufacture the original launch identity of an already reaped PID.
    """
    if type(pgid) is not int or not 1 < pgid <= 2147483647:
        raise RuntimeError('Owned test process group identity changed')
    uid = os.getuid() if uid is None else uid
    api = LibProc() if api is None else api
    getsid = os.getsid if getsid is None else getsid
    births = {} if births is None else births
    members = []
    for pid in _before_deadline(deadline, api.group_pids, pgid):
        first = _before_deadline(deadline, api.identity, pid)
        if first is None:
            continue  # Kernel ESRCH, not permission denial or a partial read.
        if first.uid != uid or first.pgid != pgid:
            raise RuntimeError('Owned test process group identity changed')
        try:
            session = _before_deadline(deadline, getsid, pid)
        except ProcessLookupError:
            continue
        except OSError as error:
            raise RuntimeError('Owned test process group inventory unavailable') from error
        second = _before_deadline(deadline, api.identity, pid)
        if second is None:
            continue
        identity = (first.pid, first.uid, first.pgid, first.start_sec, first.start_usec)
        if identity != (second.pid, second.uid, second.pgid, second.start_sec, second.start_usec) \
                or session != pgid:
            raise RuntimeError('Owned test process group identity changed')
        birth = (first.start_sec, first.start_usec)
        if pid in births and births[pid] != birth:
            raise RuntimeError('Owned test process group identity changed')
        births[pid] = birth
        # Zombies are ignored only after the same ownership/session checks.
        if second.status != SZOMB:
            members.append(pid)
    return members
