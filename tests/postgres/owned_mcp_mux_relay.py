#!/usr/bin/env python3
"""V39-only owned loopback relay over an already-running, verified Lima SSH mux.

The relay never creates an SSH master or a shared-master port forward. Its own
PID owns the listener; each connection opens one bounded `ssh -W` channel.
"""
import argparse
import ctypes
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import stat
import subprocess
import threading
import time

from darwin_process_inventory import LibProc


MAX_CONNECTIONS = 128
MAX_CONCURRENT = 16
MAX_BYTES_PER_DIRECTION = 8 * 1024 * 1024
MAX_CONNECTION_SECONDS = 120
MUX_SUFFIX = Path('tasks/l/colima-goat-q/ssh.sock')
CONFIG_SUFFIX = Path('.qualification/ssh_config')
LIMA_CONFIG_SUFFIX = Path('tasks/l/colima-goat-q/ssh.config')
SSH = '/usr/bin/ssh'
LSOF = '/usr/sbin/lsof'
CONFIG_KEYS = frozenset(('host', 'identityfile', 'stricthostkeychecking',
    'userknownhostsfile', 'nohostauthenticationforlocalhost',
    'preferredauthentications', 'compression', 'batchmode', 'identitiesonly',
    'gssapiauthentication', 'ciphers', 'user', 'controlmaster', 'controlpath',
    'controlpersist', 'hostname', 'port'))


def _sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def _directive(config, key):
    rows = [shlex.split(line) for line in Path(config).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]
    values = [row[1] for row in rows if len(row) == 2 and row[0].lower() == key.lower()]
    if len(values) != 1:
        raise RuntimeError('Closed Lima SSH configuration required')
    return values[0]


def _closed_config(config, host):
    rows = [shlex.split(line) for line in Path(config).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]
    if (not rows or rows[0] != ['Host', host] or len(rows) != len(CONFIG_KEYS)
            or {row[0].lower() for row in rows if len(row) == 2} != CONFIG_KEYS
            or any(len(row) != 2 for row in rows)):
        raise RuntimeError('Closed Lima SSH configuration required')
    return [(key.lower(), value) for key, value in rows[1:]]


def _pid_path(pid):
    library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    output = ctypes.create_string_buffer(4096)
    if library.proc_pidpath(pid, output, len(output)) <= 0:
        raise RuntimeError('SSH master executable unavailable')
    return os.fsdecode(output.value)


def mux_command(authority, *remote):
    """No socket means ProxyCommand=/usr/bin/false, never a direct fallback."""
    return [SSH, '-F', authority['config'], '-o', 'ControlMaster=no',
            '-S', authority['socket'], '-o', 'ProxyCommand=/usr/bin/false',
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-T',
            'colima-goat-q', *remote]


def admit_existing_mux(source, expected=None, *, run=subprocess.run, api=None,
                       pid_path=_pid_path):
    source = Path(source)
    if not source.is_absolute() or source.is_symlink() or source.resolve() != source:
        raise RuntimeError('Canonical V39 source required')
    config, lima_config, path = (source / CONFIG_SUFFIX, source / LIMA_CONFIG_SUFFIX,
                                 source / MUX_SUFFIX)
    for file in (config, lima_config):
        info = file.lstat()
        if (not stat.S_ISREG(info.st_mode) or file.is_symlink() or file.resolve() != file
                or info.st_uid != os.getuid()):
            raise RuntimeError('Owned canonical Lima SSH configuration required')
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or path.is_symlink() or path.resolve() != path
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise RuntimeError('Existing private Lima mux required')
    if _closed_config(config, 'colima-goat-q') != \
            _closed_config(lima_config, 'lima-colima-goat-q'):
        raise RuntimeError('Lima SSH configuration mismatch')
    for key in ('HostName', 'Port', 'User', 'IdentityFile'):
        if _directive(config, key) != _directive(lima_config, key):
            raise RuntimeError('Lima SSH configuration mismatch')
    if (_directive(config, 'HostName') != '127.0.0.1'
            or _directive(config, 'Port') != '59355'
            or _directive(config, 'User') != 'lima'
            or _directive(config, 'ControlPath') != str(path)):
        raise RuntimeError('Exact Lima SSH endpoint required')
    identity = Path(_directive(config, 'IdentityFile'))
    if (not identity.is_absolute() or not identity.is_relative_to(source / 'tasks/l')
            or identity.is_symlink() or identity.resolve() != identity):
        raise RuntimeError('Repository-local Lima identity required')
    identity_info = identity.lstat()
    if (not stat.S_ISREG(identity_info.st_mode) or identity_info.st_uid != os.getuid()
            or stat.S_IMODE(identity_info.st_mode) != 0o600):
        raise RuntimeError('Private Lima identity required')
    authority = {'config': str(config), 'socket': str(path),
                 'configSha256': _sha(config), 'limaConfigSha256': _sha(lima_config),
                 'socketDevice': info.st_dev, 'socketInode': info.st_ino}
    probe = run(mux_command(authority)[:-2] + ['-O', 'check', 'colima-goat-q'],
                capture_output=True, text=True, timeout=5, check=True)
    match = re.fullmatch(r'Master running \(pid=([1-9][0-9]*)\)\s*',
                         (probe.stdout or '') + (probe.stderr or ''))
    if not match:
        raise RuntimeError('Exact existing SSH master required')
    pid = int(match[1])
    api = api or LibProc()
    first = api.identity(pid)
    if first is None or first.uid != os.getuid() or first.ruid != os.getuid() \
            or pid_path(pid) != SSH:
        raise RuntimeError('Owned SSH master identity required')
    endpoint = run([LSOF, '-nP', '-a', '-p', str(pid), '-iTCP:59355'],
                   capture_output=True, text=True, timeout=5, check=True)
    if (len(endpoint.stdout.encode()) > 8192 or
            not re.search(r'127\.0\.0\.1:[0-9]+->127\.0\.0\.1:59355 \(ESTABLISHED\)',
                          endpoint.stdout)):
        raise RuntimeError('SSH master endpoint mismatch')
    second = api.identity(pid)
    if second is None or (first.start_sec, first.start_usec) != \
            (second.start_sec, second.start_usec):
        raise RuntimeError('SSH master changed during admission')
    authority.update(masterPid=pid, masterBirth=(first.start_sec, first.start_usec))
    if expected is not None and authority != expected:
        raise RuntimeError('Existing SSH mux changed')
    again = path.lstat()
    if (again.st_dev, again.st_ino, again.st_uid, again.st_mode) != \
            (info.st_dev, info.st_ino, info.st_uid, info.st_mode) or \
            _sha(config) != authority['configSha256'] or \
            _sha(lima_config) != authority['limaConfigSha256']:
        raise RuntimeError('SSH mux changed during admission')
    return authority


def closed_target(address, port):
    target = ipaddress.ip_address(address)
    if (target.version != 4 or not target.is_private or target.is_loopback
            or target.is_link_local or type(port) is not int or port != 8094):
        raise ValueError('Owned V39 executor target required')
    return f'{target}:{port}'


def channel_command(authority, address, port):
    return mux_command(authority)[:-1] + ['-W', closed_target(address, port), 'colima-goat-q']


def relay_connection(client, argv, stop, children, guard, *, before_spawn=None):
    """Nonblocking, backpressured, one-channel byte pump; no protocol rewrites."""
    child = None
    incoming, outgoing = bytearray(), bytearray()
    client_eof = channel_eof = input_closed = output_closed = False
    sent_to_channel = sent_to_client = 0
    deadline = time.monotonic() + MAX_CONNECTION_SECONDS
    try:
        if stop.is_set():
            return 'never_attempted'
        if before_spawn is not None:
            before_spawn()
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        with guard: children.add(child)
        client.setblocking(False)
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        while not stop.is_set() and time.monotonic() < deadline:
            reads = ([client] if not client_eof and len(incoming) < 65536 else []) + \
                    ([child.stdout] if not channel_eof and len(outgoing) < 65536 else [])
            writes = ([child.stdin] if incoming and not input_closed else []) + \
                     ([client] if outgoing and not output_closed else [])
            ready_r, ready_w, _ = select.select(reads, writes, [], .25)
            if client in ready_r:
                data = client.recv(16384)
                if data: incoming.extend(data)
                else: client_eof = True
            if child.stdout in ready_r:
                data = os.read(child.stdout.fileno(), 16384)
                if data: outgoing.extend(data)
                else: channel_eof = True
            if (sent_to_channel + len(incoming) > MAX_BYTES_PER_DIRECTION
                    or sent_to_client + len(outgoing) > MAX_BYTES_PER_DIRECTION):
                raise RuntimeError('V39 mux channel byte cap exceeded')
            if child.stdin in ready_w:
                count = os.write(child.stdin.fileno(), incoming)
                del incoming[:count]
                sent_to_channel += count
            if client in ready_w:
                count = client.send(outgoing)
                del outgoing[:count]
                sent_to_client += count
            if client_eof and not incoming and not input_closed:
                child.stdin.close(); input_closed = True
            if channel_eof and not outgoing and not output_closed:
                client.shutdown(socket.SHUT_WR); output_closed = True
            if input_closed and output_closed and child.poll() is not None:
                return
        if stop.is_set():
            return
        raise RuntimeError('V39 mux channel ended without bounded closure')
    finally:
        client.close()
        if child is not None:
            reaped = False
            try:
                if child.poll() is None:
                    child.terminate()
                    try: child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill(); child.wait(timeout=2)
                reaped = child.poll() is not None
            finally:
                if reaped:
                    with guard: children.discard(child)
                if child.stdout is not None: child.stdout.close()
                if child.stdin is not None and not child.stdin.closed: child.stdin.close()


def serve(source, authority, address, port, bind_port, stop=None):
    closed_target(address, port)
    if type(bind_port) is not int or not 1024 <= bind_port <= 65535:
        raise ValueError('Closed owned loopback port required')
    stop = stop or threading.Event()
    children, threads = set(), []
    guard = threading.Lock()
    slots = threading.BoundedSemaphore(MAX_CONCURRENT)
    failures = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(('127.0.0.1', bind_port))
        listener.listen(MAX_CONCURRENT)
        listener.settimeout(.25)

        def work(client):
            try:
                admit_existing_mux(source, authority)
                if stop.is_set():
                    return
                relay_connection(client, channel_command(authority, address, port), stop, children, guard)
            except Exception as error:
                failures.append(type(error).__name__)
                stop.set()
            finally:
                client.close()
                slots.release()

        accepted = 0
        while not stop.is_set():
            if accepted >= MAX_CONNECTIONS:
                raise RuntimeError('V39 mux channel count exceeded')
            try: client, _ = listener.accept()
            except socket.timeout: continue
            if not slots.acquire(blocking=False):
                client.close(); raise RuntimeError('V39 mux channel concurrency exceeded')
            thread = threading.Thread(target=work, args=(client,), daemon=True)
            try:
                thread.start()
            except BaseException:
                client.close()
                slots.release()
                raise
            threads.append(thread)
            accepted += 1
    finally:
        stop.set(); listener.close()
        with guard: owned_children = tuple(children)
        cleanup_errors = []
        cleanup_deadline = time.monotonic() + 3
        for child in owned_children:
            try:
                if child.poll() is None: child.terminate()
            except Exception as error: cleanup_errors.append(type(error).__name__)
        for child in owned_children:
            try:
                if child.poll() is None:
                    child.wait(timeout=max(0, cleanup_deadline-time.monotonic()))
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=max(0, cleanup_deadline-time.monotonic()))
            except Exception as error: cleanup_errors.append(type(error).__name__)
        for thread in threads:
            try: thread.join(timeout=max(0, cleanup_deadline-time.monotonic()))
            except Exception as error: cleanup_errors.append(type(error).__name__)
        if (cleanup_errors or any(thread.is_alive() for thread in threads)
                or any(child.poll() is None for child in owned_children)):
            raise RuntimeError('V39 mux channel cleanup incomplete')
    if failures:
        raise RuntimeError('V39 mux channel failed')


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'address', 'master-pid', 'master-start-sec',
                 'master-start-usec', 'config-sha256', 'lima-config-sha256',
                 'socket-device', 'socket-inode'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--target-port', type=int, required=True)
    parser.add_argument('--bind-port', type=int, required=True)
    args = parser.parse_args()
    source = Path(args.source)
    expected = {'config': str(source / CONFIG_SUFFIX), 'socket': str(source / MUX_SUFFIX),
                'configSha256': args.config_sha256,
                'limaConfigSha256': args.lima_config_sha256,
                'socketDevice': int(args.socket_device), 'socketInode': int(args.socket_inode),
                'masterPid': int(args.master_pid),
                'masterBirth': (int(args.master_start_sec), int(args.master_start_usec))}
    admit_existing_mux(source, expected)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    serve(source, expected, args.address, args.target_port, args.bind_port, stop)


if __name__ == '__main__':
    main()
