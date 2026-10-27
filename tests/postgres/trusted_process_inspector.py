"""Private inherited-channel browser absence checks; never signals or writes.

The outside coordinator owns the launcher child. Only that launcher receives
the socket; it must consume it before launching workers. This is a bounded
read-only capability, not a listener, command runner, or disk-receipt protocol.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import time
import math


FD_ENV = 'DVAIA_PROCESS_INSPECTOR_FD'
MAX_FRAME = 8192
_CLIENT = None


def _exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise RuntimeError('Invalid inspector message schema')


def _deadline(sock, deadline):
    if deadline is None: return
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise RuntimeError('Inspector deadline invalid')
    left = deadline - time.monotonic()
    if left <= 0: raise RuntimeError('Inspector deadline expired')
    sock.settimeout(min(15, left))


def _read(sock, size, deadline=None):
    result = bytearray()
    while len(result) < size:
        _deadline(sock, deadline)
        part = sock.recv(size - len(result))
        _deadline(sock, deadline)
        if not part:
            raise RuntimeError('Inspector channel closed')
        result.extend(part)
    return bytes(result)


def receive(sock, deadline=None):
    size = struct.unpack('!I', _read(sock, 4, deadline))[0]
    if not 0 < size <= MAX_FRAME:
        raise RuntimeError('Inspector frame exceeds bound')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError('Duplicate inspector field')
            value[key] = item
        return value
    try:
        value = json.loads(_read(sock, size, deadline), object_pairs_hook=unique)
        _deadline(sock, deadline)
        return value
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError('Malformed inspector frame') from exc


def send(sock, value, deadline=None):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if not 0 < len(data) <= MAX_FRAME:
        raise RuntimeError('Inspector frame exceeds bound')
    _deadline(sock, deadline)
    sock.sendall(struct.pack('!I', len(data)) + data)
    _deadline(sock, deadline)


def peer_identity(sock):
    if sys.platform != 'darwin' or sock.family != socket.AF_UNIX \
            or sock.type != socket.SOCK_STREAM:
        raise RuntimeError('Darwin private socket required')
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    library.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                                  ctypes.POINTER(ctypes.c_uint)]
    library.getpeereid.restype = ctypes.c_int
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if library.getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        raise RuntimeError('Inspector peer credentials unavailable')
    pid = struct.unpack('=i', sock.getsockopt(0, 2, 4))[0]  # LOCAL_PEERPID
    return pid, uid.value


class Client:
    def __init__(self, sock):
        self.sock = sock
        self.pid = os.getpid()
        self.parent = os.getppid()
        self.sequence = 0
        sock.set_inheritable(False)
        sock.settimeout(15)
        if peer_identity(sock) != (self.parent, os.getuid()):
            sock.close()
            raise RuntimeError('Inspector must be the same-user direct parent')

    def absent(self, runtime, mode, identity=None, *, deadline=None):
        if self.sock.fileno() < 0:
            raise RuntimeError('Inspector channel unavailable after prior failure')
        if os.getpid() != self.pid or os.getppid() != self.parent:
            raise RuntimeError('Inspector capability cannot transfer to workers')
        self.sequence += 1
        request = dict(version=1, sequence=self.sequence, nonce=secrets.token_hex(32),
                       pid=self.pid, runtime=str(runtime), mode=mode,
                       identity={} if identity is None else identity)
        try:
            previous_timeout = self.sock.gettimeout() if deadline is not None else None
            send(self.sock, request, deadline)
            response = receive(self.sock, deadline)
            _exact(response, ('request', 'absent', 'error'))
            if json.dumps(response['request'], sort_keys=True) != json.dumps(request, sort_keys=True) \
                    or type(response['absent']) is not bool \
                    or response['error'] is not None:
                raise RuntimeError('Inspector response invalid or inspection failed')
            _deadline(self.sock, deadline)
            if deadline is not None: self.sock.settimeout(previous_timeout)
            return response['absent']
        except Exception:
            self.sock.close()
            raise


def consume_environment():
    """Call once at launcher startup, before any subprocess or clean-env map."""
    global _CLIENT
    raw = os.environ.pop(FD_ENV, None)
    if raw is None:
        return _CLIENT
    if _CLIENT is not None or not re.fullmatch(r'[0-9]{1,9}', raw) or int(raw) < 3:
        raise RuntimeError('Invalid or repeated inspector descriptor')
    _CLIENT = Client(socket.socket(fileno=int(raw)))
    return _CLIENT


def current_client():
    if FD_ENV in os.environ:
        raise RuntimeError('Inspector descriptor was not consumed before launch')
    return _CLIENT


def private_directory(path):
    if path.resolve() != path or path.is_symlink():
        raise RuntimeError('Canonical inspector directory required')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Private owned inspector directory required')


def validate_scope(repo, request):
    runtime = Path(request['runtime'])
    parent = repo / 'tasks' / 'qualification'
    try:
        relative = runtime.relative_to(parent)
    except ValueError as exc:
        raise RuntimeError('Inspector runtime outside qualification root') from exc
    parts = relative.parts
    if len(parts) not in (2, 3) or not re.fullmatch(r'run-[A-Za-z0-9_-]+', parts[0]) \
            or parts[-1] != 'runtime' or (len(parts) == 3 and parts[1] not in
                ('persona-inbox-rendered', 'standalone-ssrf-rendered')):
        raise RuntimeError('Unsupported inspector runtime')
    for directory in (parent, *(parent.joinpath(*parts[:n]) for n in range(1, len(parts) + 1))):
        private_directory(directory)
    if request['mode'] == 'temporary-profiles':
        if len(parts) != 2 or request['identity'] != {}:
            raise RuntimeError('Invalid temporary profile scope')
        private_directory(runtime / 'tmp')
        return runtime / 'tmp', None
    if request['mode'] != 'journal-profile' or len(parts) != 3:
        raise RuntimeError('Unsupported inspector operation')
    identity = request['identity']
    _exact(identity, ('pid', 'pgid', 'sessionId', 'uid'))
    if any(type(identity[k]) is not int or identity[k] <= 0 for k in ('pid', 'pgid', 'sessionId')) \
            or type(identity['uid']) is not int or identity['uid'] != os.getuid() \
            or identity['pgid'] != identity['sessionId']:
        raise RuntimeError('Invalid journal process identity')
    journal = runtime / 'browser-process.json'
    info = journal.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
        raise RuntimeError('Private browser journal required')
    value = json.loads(journal.read_text())
    if any(value.get(k) != v for k, v in identity.items()) \
            or value.get('profile') != str(runtime / 'browser-profile') \
            or any(value.get(k) != identity['pgid'] for k in
                   ('qualificationPid', 'qualificationPgid', 'qualificationSessionId')):
        raise RuntimeError('Inspector journal binding mismatch')
    return runtime / 'browser-profile', identity


def inspect_absence(profile, identity, *, required_pid=None, run=subprocess.run, getsid=os.getsid):
    """Fixed complete-width roster only; broad command lines stay in memory."""
    result = run(['/bin/ps', '-Aww', '-o', 'pid=,ppid=,pgid=,uid=,command='],
                 capture_output=True, text=True, timeout=10, check=True,
                 env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if result.stderr or not result.stdout or len(result.stdout) > 16 * 1024 * 1024:
        raise RuntimeError('Process roster incomplete or denied')
    seen = set()
    remains = False
    pattern = re.compile(r'--user-data-dir=[\"\']?' + re.escape(str(profile)) + r'/')
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=4)
        if len(fields) != 5 or any(not re.fullmatch(r'-?[0-9]+', f) for f in fields[:4]):
            raise RuntimeError('Malformed complete process roster')
        pid, ppid, pgid, uid = map(int, fields[:4])
        if pid <= 0 or ppid < 0 or pgid < 0 or pid in seen:
            raise RuntimeError('Invalid complete process roster identity')
        seen.add(pid)
        if identity is None:
            remains |= bool(pattern.search(fields[4]))
        else:
            # A reused PID or foreign-UID group is not safe absence.
            remains |= pid == identity['pid'] or pgid == identity['pgid'] \
                or str(profile) in fields[4]
            try:
                remains |= getsid(pid) == identity['sessionId']
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise RuntimeError('Process session inventory denied') from exc
    if os.getpid() not in seen:
        raise RuntimeError('Process roster omitted inspector')
    if required_pid is not None and required_pid not in seen:
        raise RuntimeError('Process roster omitted launcher')
    return not remains


class Inspector:
    def __init__(self, repo, child_pid, *, api=None, inspect=inspect_absence):
        from darwin_process_inventory import LibProc
        self.repo = Path(repo).resolve()
        self.child_pid = child_pid
        self.api = api or LibProc()
        self.inspect = inspect
        self.sequence = 0
        self.nonces = set()
        self.run_root = None
        self.birth = None
        self.verify_child()

    def verify_child(self):
        row = self.api.identity(self.child_pid)
        if row is None or row.ppid != os.getpid() or row.uid != os.getuid() \
                or row.ruid != os.getuid():
            raise RuntimeError('Inspector no longer owns the same-user launcher')
        birth = (row.start_sec, row.start_usec)
        if self.birth is not None and self.birth != birth:
            raise RuntimeError('Inspector launcher PID was reused')
        self.birth = birth

    def handle(self, request):
        self.failure_stage = 'request-schema'
        _exact(request, ('version', 'sequence', 'nonce', 'pid', 'runtime', 'mode', 'identity'))
        self.failure_stage = 'request-identity'
        if type(request['version']) is not int or request['version'] != 1 \
                or type(request['sequence']) is not int or request['sequence'] != self.sequence + 1 \
                or type(request['pid']) is not int or request['pid'] != self.child_pid \
                or not isinstance(request['nonce'], str) \
                or not re.fullmatch(r'[a-f0-9]{64}', request['nonce']) \
                or request['nonce'] in self.nonces or not isinstance(request['runtime'], str):
            raise RuntimeError('Inspector request identity or replay violation')
        self.failure_stage = 'child-before'
        self.verify_child()
        self.failure_stage = 'scope'
        profile, identity = validate_scope(self.repo, request)
        self.failure_stage = 'run-binding'
        run_root = Path(request['runtime']).relative_to(self.repo / 'tasks' / 'qualification').parts[0]
        if self.run_root is not None and self.run_root != run_root:
            raise RuntimeError('Inspector cannot transfer between qualification runs')
        self.run_root = run_root
        self.sequence += 1
        self.nonces.add(request['nonce'])
        self.failure_stage = 'process-inventory'
        absent = self.inspect(profile, identity, required_pid=self.child_pid)
        self.failure_stage = 'child-after'
        self.verify_child()
        self.failure_stage = 'complete'
        return {'request': request, 'absent': absent, 'error': None}
