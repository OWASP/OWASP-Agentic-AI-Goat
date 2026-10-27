"""Versioned V30 outside-owned agent-host capability. Importing creates no resources.

The coordinator (not the sandboxed fixture) owns the real child and its reaping.
Only the reviewed full-catalog profile is admitted; historical v2 remains closed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import time

from darwin_process_inventory import LibProc, owned_group_members
from admin_browser_current_main_admission import inventory as dependency_inventory
from sql_nosql_docker_ownership import inspect_owned, validate_container_layout, verify_daemon
from trusted_process_inspector import peer_identity

LIVE_ENABLED = False
FULL_LIVE_ENABLED = True
LAUNCHER_FD_ENV = 'DVAIA_V30_HOST_LAUNCHER_FD'
WORKER_FD_ENV = 'DVAIA_V30_HOST_WORKER_FD'
NONCE_ENV = 'DVAIA_V30_HOST_NONCE'
MAX_FRAME = 16384
COHORT = 'secureshop-v30-original-customer-disclosure-current-main-v1'
PROFILE = 'search-continuation-v2'
FULL_PROFILE = 'full-catalog-owned-v3'
PROFILES = (PROFILE, FULL_PROFILE)
NODE_RELATIVE = 'tasks/runtime/node/node_modules/node/bin/node'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER_SHA256 = '8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025'
DAEMON = '945f6fce-3aaf-4d8f-a483-170464fb2416'
IMAGE = 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
FIXTURE = 'tests/postgres/secureshopCustomerDisclosureActual.integration.test.js'
POOL_LIMITS = {'PG_POOL_MAX_CONTROL': '6', 'PG_POOL_MAX_WORKSHOP': '4',
               'PG_POOL_MAX_MIGRATION': '1', 'PG_POOL_MAX_LEASE': '3', 'PG_POOL_BUDGET': '60'}
GRANT_KEYS = {'run', 'nodePath', 'nodeSha256', 'sourceManifestSha256', 'pgNonce',
              'pgPort', 'hostPort', 'commerceUrl', 'agentsUrl', 'containerId', 'owner'}


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise RuntimeError('V30_CONTROLLER_REJECTED')


def hexadecimal(value, size=64):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{%d}' % size, value) is not None


def uuid(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) is not None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def unique_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise RuntimeError('V30_CONTROLLER_REJECTED')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('V30_CONTROLLER_REJECTED')))


def send(sock, value, *, timeout=2, max_frame=MAX_FRAME):
    raw = encoded(value)
    if not 0 < len(raw) <= max_frame or not 0 < timeout <= 60:
        raise RuntimeError('V30_CONTROLLER_REJECTED')
    # Python sendall's socket timeout covers the entire send, not each chunk.
    sock.settimeout(timeout)
    sock.sendall(struct.pack('!I', len(raw)) + raw)


def receive(sock, *, timeout=2, max_frame=MAX_FRAME):
    if not 0 < timeout <= 60: raise TimeoutError('V30_CONTROLLER_FRAME_TIMEOUT')
    deadline = time.monotonic() + timeout
    def take(size):
        raw = bytearray()
        while len(raw) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('V30_CONTROLLER_FRAME_TIMEOUT')
            sock.settimeout(remaining)
            part = sock.recv(size - len(raw))
            if time.monotonic() >= deadline: raise TimeoutError('V30_CONTROLLER_FRAME_TIMEOUT')
            if not part:
                raise EOFError('V30_CONTROLLER_CLOSED')
            raw.extend(part)
        return raw
    size = struct.unpack('!I', take(4))[0]
    if not 0 < size <= max_frame:
        raise RuntimeError('V30_CONTROLLER_REJECTED')
    return unique_json(take(size))


class ControllerClient:
    """Launcher-only, sequential inherited capability; never inherited by host."""
    def __init__(self, fd, nonce):
        if type(fd) is not int or fd < 3 or not hexadecimal(nonce):
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        self.sock = socket.socket(fileno=fd)
        if self.sock.family != socket.AF_UNIX or self.sock.type != socket.SOCK_STREAM:
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        self.sock.set_inheritable(False)
        self.sock.settimeout(30)
        if peer_identity(self.sock) != (os.getppid(), os.getuid()):
            self.sock.close()
            raise RuntimeError('V30_CONTROLLER_PARENT')
        self.nonce, self.pid, self.sequence = nonce, os.getpid(), 0

    def request(self, op, payload):
        if os.getpid() != self.pid:
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        self.sock.settimeout(60 if op in ('grant', 'start') else 30)
        self.sequence += 1
        request = {'version': 1, 'sequence': self.sequence, 'nonce': self.nonce,
                   'pid': self.pid, 'op': op, 'payload': payload}
        send(self.sock, request)
        response = receive(self.sock, timeout=60 if op in ('grant', 'start') else 30)
        exact(response, ('version', 'sequence', 'nonce', 'op', 'ok', 'result', 'error'))
        if any(response[key] != request[key] for key in ('version', 'sequence', 'nonce', 'op')) \
                or type(response['version']) is not int or type(response['sequence']) is not int \
                or response['ok'] is not True or response['error'] is not None:
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        return response['result']

    def close(self):
        self.sock.close()


def consume_launcher_environment(environment=None):
    env = os.environ if environment is None else environment
    raw = [env.pop(key, None) for key in (LAUNCHER_FD_ENV, WORKER_FD_ENV, NONCE_ENV)]
    if raw == [None, None, None]:
        return None
    if any(type(value) is not str for value in raw) or not hexadecimal(raw[2]) \
            or any(not re.fullmatch(r'[0-9]{1,9}', value) or int(value) < 3 for value in raw[:2]) \
            or raw[0] == raw[1]:
        raise RuntimeError('V30_CONTROLLER_REJECTED')
    worker_fd = int(raw[1])
    os.set_inheritable(worker_fd, False)
    return ControllerClient(int(raw[0]), raw[2]), worker_fd, raw[2]


def private(path, *, directory=False):
    path = Path(path)
    info = path.lstat()
    if path.resolve(strict=True) != path or path.is_symlink() or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) \
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) \
            or (not directory and info.st_nlink != 1):
        raise RuntimeError('V30_CONTROLLER_PRIVATE_PATH')
    return info


def canonical_file(root, relative):
    if type(relative) is not str or not relative or '\\' in relative:
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    path = root / relative
    if Path(relative).is_absolute() or any(part in ('', '.', '..') for part in relative.split('/')) \
            or path.resolve(strict=True) != path or not path.is_file() or path.is_symlink():
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    return path


def validate_grant(repo, grant, *, check_dependencies=True):
    exact(grant, GRANT_KEYS)
    repo = Path(repo)
    if repo.resolve(strict=True) != repo:
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    run = Path(grant['run'])
    if run.parent != repo / 'tasks/qualification' or not re.fullmatch(r'run-[A-Za-z0-9_-]+', run.name):
        raise RuntimeError('V30_CONTROLLER_PRIVATE_PATH')
    for directory in (run.parent, run, run / 'runtime', run / 'runtime/tmp'):
        private(directory, directory=True)
    for field in ('pgPort', 'hostPort'):
        if type(grant[field]) is not int or not 1024 <= grant[field] <= 65535 or grant[field] == 11434:
            raise RuntimeError('V30_CONTROLLER_PORT')
    if grant['pgPort'] == grant['hostPort'] or not hexadecimal(grant['pgNonce'], 12) \
            or not hexadecimal(grant['containerId']) or not uuid(grant['owner']):
        raise RuntimeError('V30_CONTROLLER_GRANT')
    for key, store in (('commerceUrl', 'secureshop'), ('agentsUrl', 'secureshop_agents')):
        expected = f"postgresql://dvaia_{store}_runtime@127.0.0.1:{grant['pgPort']}/dvaia_test_agent_host_{grant['pgNonce']}_{store}"
        if grant[key] != expected:
            raise RuntimeError('V30_CONTROLLER_DATABASE')
    node = canonical_file(repo, NODE_RELATIVE)
    if grant['nodePath'] != str(node) or grant['nodeSha256'] != NODE_SHA256 or sha(node) != NODE_SHA256:
        raise RuntimeError('V30_CONTROLLER_NODE')
    manifest = run / 'source-before.json'
    info = private(manifest)
    if not 0 < info.st_size <= 32 * 1024 * 1024 or not hexadecimal(grant['sourceManifestSha256']) \
            or sha(manifest) != grant['sourceManifestSha256']:
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    source = unique_json(manifest.read_bytes())
    exact(source, ('cohort', 'sourcePins', 'dependencyInventory'))
    if source['cohort'] != COHORT or type(source['sourcePins']) is not dict \
            or not {'agent-host/index.js', FIXTURE, 'server/services/secureshop/agentHostSupervisor.js'} <= set(source['sourcePins']):
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    for relative, digest in source['sourcePins'].items():
        if not hexadecimal(digest) or sha(canonical_file(repo, relative)) != digest:
            raise RuntimeError('V30_CONTROLLER_SOURCE')
    if check_dependencies and dependency_inventory(repo / 'node_modules') != source['dependencyInventory']:
        raise RuntimeError('V30_CONTROLLER_DEPENDENCIES')
    return grant


def combined_policy(repo, pg_port, host_port):
    for port in (pg_port, host_port):
        if type(port) is not int or not 1024 <= port <= 65535 or port == 11434:
            raise RuntimeError('V30_CONTROLLER_PORT')
    if pg_port == host_port or any(c in str(repo) for c in ('"', '\\', '\n', '\r')):
        raise RuntimeError('V30_CONTROLLER_POLICY')
    return '(version 1)\n(allow default)\n(deny file-write*)\n' \
        + f'(allow file-write* (subpath "{repo}") (literal "/dev/null") (literal "/dev/tty"))\n' \
        + '(deny network*)\n' \
        + f'(allow network-outbound (remote tcp "localhost:{pg_port}"))\n' \
        + f'(allow network-bind (local tcp "localhost:{host_port}"))\n' \
        + f'(allow network-inbound (local tcp "localhost:{host_port}"))\n'


def host_environment(grant, instance_id):
    if not uuid(instance_id):
        raise RuntimeError('V30_CONTROLLER_INSTANCE')
    run = Path(grant['run'])
    return {'PATH': '/usr/bin:/bin', 'NODE_ENV': 'test', 'PLATFORM_DATABASE_ENGINE': 'postgres',
            'WORKSHOP_DATABASE_ENGINE': 'postgres', 'SS_AGENT_HOST_BIND_HOST': '127.0.0.1',
            'SS_AGENT_HOST_PORT': str(grant['hostPort']), 'SS_AGENT_HOST_INSTANCE_ID': instance_id,
            'SECURESHOP_DATABASE_URL': grant['commerceUrl'],
            'SECURESHOP_AGENTS_DATABASE_URL': grant['agentsUrl'],
            'LOGS_DIR': str(run / 'host-logs'), 'TMPDIR': str(run / 'runtime/tmp'), **POOL_LIMITS}


PROBE = r"""'use strict';
const net=require('node:net');
const pg=Number(process.env.V30_PROBE_PG_PORT),port=Number(process.env.V30_PROBE_HOST_PORT);
const connect=(host,port)=>new Promise(resolve=>{const s=net.connect({host,port});
 let done=false;const finish=value=>{if(done)return;done=true;s.destroy();resolve(value)};
 s.once('connect',()=>finish('CONNECTED'));s.once('error',e=>finish(e.code));s.setTimeout(1500,()=>finish('TIMEOUT'));});
(async()=>{let accepted=false;const server=net.createServer(socket=>{accepted=true;socket.destroy()});
 await new Promise((resolve,reject)=>server.once('error',reject).listen(port,'127.0.0.1',resolve));
 const postgres=await connect('127.0.0.1',pg),model=await connect('127.0.0.1',11434),external=await connect('192.0.2.1',443);
 const end=Date.now()+2000;while(!accepted&&Date.now()<end)await new Promise(resolve=>setTimeout(resolve,10));
 await new Promise(resolve=>server.close(resolve));process.stdout.write(JSON.stringify({pid:process.pid,postgres,model,external,loopbackBound:true,loopbackInboundVerified:accepted})+'\n');
})().catch(()=>{process.exitCode=1});
"""


class Archive:
    """Private durable bounded metadata only; no env, URLs, logs or credentials."""
    def __init__(self, run):
        self.run, self.handles, self.used = Path(run), {}, 0
        try:
            for name in ('v30-host-controller.json', 'v30-host-controller.jsonl', 'v30-agent-host-combined.sb'):
                self.handles[name] = os.open(self.run / name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
            descriptor = os.open(self.run, os.O_RDONLY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        except BaseException:
            self.close()
            raise

    def write(self, name, raw, append=False):
        private(self.run, directory=True)
        fd = self.handles[name]
        first, linked = os.fstat(fd), (self.run / name).lstat()
        if (first.st_dev, first.st_ino) != (linked.st_dev, linked.st_ino):
            raise RuntimeError('V30_CONTROLLER_ARTIFACT_CHANGED')
        private(self.run / name)
        if len(raw) > 65536 or (append and self.used + len(raw) > 1048576):
            raise RuntimeError('V30_CONTROLLER_ARTIFACT_BOUND')
        if not append:
            os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET)
        else:
            self.used += len(raw); os.lseek(fd, 0, os.SEEK_END)
        offset = 0
        while offset < len(raw):
            size = os.write(fd, raw[offset:])
            if size <= 0: raise RuntimeError('V30_CONTROLLER_SHORT_WRITE')
            offset += size
        os.fsync(fd)
        return hashlib.sha256(raw).hexdigest()

    def close(self):
        failures = []
        for fd in self.handles.values():
            try: os.close(fd)
            except OSError as error: failures.append(error)
        self.handles.clear()
        if failures: raise RuntimeError('V30_CONTROLLER_ARTIFACT_CLOSE')


def identity_tuple(row):
    return (row.pid, row.ppid, row.uid, row.ruid, row.pgid, row.start_sec, row.start_usec)


class DarwinDriver:
    """Only fixed reviewed commands; construction itself is read-only."""
    def __init__(self, repo, launcher_pid, *, api=None, expected_profile=PROFILE):
        if expected_profile not in PROFILES:
            raise RuntimeError('V30_CONTROLLER_PROFILE')
        self.repo, self.launcher_pid = Path(repo), launcher_pid
        self.expected_profile = expected_profile
        self.api = api or LibProc()
        self.launcher_birth = None
        self.worker_pid = None; self.worker_birth = None
        self.child = None; self.births = {}; self.pending = []; self.pending_resources = {}
        self.host_started = None

    def launcher(self):
        first = self.api.identity(self.launcher_pid)
        if first is None or first.uid != os.getuid() or first.ruid != os.getuid() or first.ppid != os.getpid():
            raise RuntimeError('V30_CONTROLLER_LAUNCHER')
        birth = (first.start_sec, first.start_usec)
        if self.launcher_birth is not None and self.launcher_birth != birth:
            raise RuntimeError('V30_CONTROLLER_LAUNCHER')
        args = self.api.arguments(self.launcher_pid)
        launcher_names = {'tests/postgres/run-secureshop-agent-host-transport-main.py',
                          str(self.repo / 'tests/postgres/run-secureshop-agent-host-transport-main.py')}
        if (not any(arg in launcher_names for arg in args)
                or args.count('--cohort') != 1
                or args.index('--cohort') + 1 >= len(args)
                or args[args.index('--cohort') + 1] != 'v30-original-disclosure'
                or args.count('--v30-original-profile') != 1
                or args.index('--v30-original-profile') + 1 >= len(args)
                or args[args.index('--v30-original-profile') + 1] != self.expected_profile):
            raise RuntimeError('V30_CONTROLLER_LAUNCHER')
        second = self.api.identity(self.launcher_pid)
        if second is None or identity_tuple(first) != identity_tuple(second):
            raise RuntimeError('V30_CONTROLLER_LAUNCHER')
        self.launcher_birth = birth

    def bind_worker(self, pid, grant):
        self.launcher()
        if type(pid) is not int or pid <= 1 or self.worker_pid is not None:
            raise RuntimeError('V30_CONTROLLER_WORKER')
        first = self.api.identity(pid)
        if first is None or first.ppid != self.launcher_pid or first.uid != os.getuid() or first.ruid != os.getuid():
            raise RuntimeError('V30_CONTROLLER_WORKER')
        args = self.api.arguments(pid)
        expected = [grant['nodePath'], '--test', '--test-isolation=none', '--test-reporter=tap', str(self.repo / FIXTURE)]
        # The one scoped command is agreed with the launcher; no forked test worker.
        if list(args) != expected:
            raise RuntimeError('V30_CONTROLLER_WORKER')
        second = self.api.identity(pid)
        if second is None or identity_tuple(first) != identity_tuple(second):
            raise RuntimeError('V30_CONTROLLER_WORKER')
        self.worker_pid, self.worker_birth = pid, (first.start_sec, first.start_usec)

    def worker(self):
        if self.worker_pid is None:
            raise RuntimeError('V30_CONTROLLER_WORKER')
        row = self.api.identity(self.worker_pid)
        if row is None or row.ppid != self.launcher_pid or (row.start_sec, row.start_usec) != self.worker_birth:
            raise RuntimeError('V30_CONTROLLER_WORKER')
        self.launcher()

    def _live(self):
        admitted = FULL_LIVE_ENABLED if self.expected_profile == FULL_PROFILE else LIVE_ENABLED
        if not admitted:
            raise RuntimeError('V30_CONTROLLER_UNQUALIFIED')

    def _capture(self, argv, env, timeout=8, cap=1048576, after_spawn=None):
        self._live()
        child = subprocess.Popen(argv, cwd=self.repo, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        self.pending.append(child)
        data = [bytearray(), bytearray()]; selector = None; deadline = time.monotonic() + timeout
        try:
            if after_spawn is not None: after_spawn()
            selector = selectors.DefaultSelector()
            for index, pipe in enumerate((child.stdout, child.stderr)):
                os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map():
                if time.monotonic() >= deadline: raise TimeoutError('V30_CONTROLLER_COMMAND_TIMEOUT')
                for key, _ in selector.select(min(.1, deadline-time.monotonic())):
                    part = os.read(key.fileobj.fileno(), 8192)
                    if not part: selector.unregister(key.fileobj); continue
                    data[key.data].extend(part)
                    if sum(map(len, data)) > cap: raise RuntimeError('V30_CONTROLLER_COMMAND_BOUND')
            code = child.wait(timeout=max(.001, deadline-time.monotonic()))
            return child.pid, code, bytes(data[0]), bytes(data[1])
        finally:
            cleanup_errors = []
            self.pending_resources[child] = (selector, child.stdout, child.stderr)
            try:
                if child.poll() is None: child.kill()
            except Exception as error: cleanup_errors.append(error)
            try:
                reaped = type(child.wait(timeout=2)) is int
                if not reaped: raise RuntimeError('V30_CONTROLLER_COMMAND_UNREAPED')
            except Exception as error: cleanup_errors.append(error)
            for resource in (selector, child.stdout, child.stderr):
                try:
                    if resource is not None: resource.close()
                except Exception as error: cleanup_errors.append(error)
            if not cleanup_errors:
                self.pending.remove(child); self.pending_resources.pop(child, None)
            else: raise RuntimeError('V30_CONTROLLER_COMMAND_CLEANUP') from cleanup_errors[0]

    def verify_pg(self, grant):
        docker = canonical_file(self.repo, 'tasks/runtime/container/bin/docker')
        if sha(docker) != DOCKER_SHA256: raise RuntimeError('V30_CONTROLLER_DOCKER')
        def command(args):
            _, code, out, err = self._capture([str(docker), '--host', 'unix://' + str(self.repo / '.qualification/goat-q/docker.sock'), *args],
                {'PATH': '/usr/bin:/bin', 'DOCKER_CONFIG': str(Path(grant['run']) / 'runtime')}, timeout=8)
            return subprocess.CompletedProcess(args, code, out.decode(), err.decode())
        verify_daemon(command, DAEMON)
        row = inspect_owned(command, name='dvaia-v30-original-disclosure-' + grant['pgNonce'],
            labels={'dvaia.owner': grant['owner'], 'dvaia.cohort': COHORT}, image=IMAGE, captured_id=grant['containerId'])
        if row is None or validate_container_layout(row) != grant['pgPort']:
            raise RuntimeError('V30_CONTROLLER_DATABASE')

    def probe(self, grant, profile):
        env = {'PATH': '/usr/bin:/bin', 'TMPDIR': str(Path(grant['run']) / 'runtime/tmp'),
               'V30_PROBE_PG_PORT': str(grant['pgPort']), 'V30_PROBE_HOST_PORT': str(grant['hostPort'])}
        def inbound():
            deadline = time.monotonic() + 2
            while True:
                with socket.socket() as client:
                    client.settimeout(min(.2, max(.001, deadline-time.monotonic())))
                    result = client.connect_ex(('127.0.0.1', grant['hostPort']))
                if result == 0: return
                if result != 61 or time.monotonic() >= deadline:
                    raise RuntimeError('V30_CONTROLLER_PROBE_INBOUND')
                time.sleep(.01)
        pid, code, out, err = self._capture(['/usr/bin/sandbox-exec', '-f', str(profile), grant['nodePath'], '-e', PROBE], env, cap=4096, after_spawn=inbound)
        if code != 0 or err: raise RuntimeError('V30_CONTROLLER_PROBE')
        value = unique_json(out); exact(value, ('pid', 'postgres', 'model', 'external', 'loopbackBound', 'loopbackInboundVerified'))
        if value['pid'] != pid or value['postgres'] != 'CONNECTED' or value['loopbackBound'] is not True \
                or value['loopbackInboundVerified'] is not True \
                or any(value[key] not in ('EPERM', 'EACCES') for key in ('model', 'external')):
            raise RuntimeError('V30_CONTROLLER_PROBE')
        return {'version': 1, 'policySha256': sha(profile), 'probePid': pid,
                'probeTerminal': {'exitCode': code, 'signalCode': None},
                'postgresAllowed': True, 'modelDenied': True, 'externalDenied': True,
                'loopbackBound': True, 'loopbackInboundVerified': True}

    def start(self, grant, profile, instance_id):
        self._live()
        if self.child is not None: raise RuntimeError('V30_CONTROLLER_RESTART_DENIED')
        private(Path(grant['run']) / 'host-logs', directory=True)
        self.child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(profile), grant['nodePath'], 'agent-host/index.js'],
            cwd=self.repo, env=host_environment(grant, instance_id), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        row = self.api.identity(self.child.pid)
        if row is None or row.ppid != os.getpid() or row.pgid != row.pid or row.uid != os.getuid() \
                or row.ruid != os.getuid() or os.getsid(row.pid) != row.pid:
            raise RuntimeError('V30_CONTROLLER_HOST_BIRTH')
        self.births[row.pid] = (row.start_sec, row.start_usec)
        self.host_started = time.monotonic()
        deadline = self.host_started + 2
        while True:
            current = self.api.identity(row.pid)
            if current is None or identity_tuple(current) != identity_tuple(row):
                raise RuntimeError('V30_CONTROLLER_HOST_BIRTH')
            if list(self.api.arguments(row.pid)) == [grant['nodePath'], 'agent-host/index.js']:
                break
            if time.monotonic() >= deadline or self.child.poll() is not None:
                raise RuntimeError('V30_CONTROLLER_HOST_EXEC')
            time.sleep(.01)
        return row.pid, list(self.births[row.pid])

    def host_identity(self):
        if self.child is None: return None, None
        birth = self.births.get(self.child.pid)
        return self.child.pid, list(birth) if birth is not None else None

    def terminal(self):
        if self.child is None: return None
        code = self.child.poll()
        if code is None: return None
        self.child.wait(timeout=.1)
        return {'exitCode': code if code >= 0 else None,
                'signalCode': signal.Signals(-code).name if code < 0 else None}

    def signal(self, name):
        if name not in ('SIGTERM', 'SIGKILL') or self.child is None:
            raise RuntimeError('V30_CONTROLLER_SIGNAL')
        if self.child.pid not in self.births:
            # Still our unreaped direct Popen child; never adopt an unknown group.
            self.child.send_signal(getattr(signal, name)); return
        members = owned_group_members(self.child.pid, api=self.api, births=self.births)
        if members: os.killpg(self.child.pid, getattr(signal, name))

    def stop(self, grant):
        deadline = time.monotonic() + 20; failures = []
        def attempt(callback):
            try: return callback()
            except Exception as error: failures.append(error); return None
        for child in tuple(self.pending):
            def reap_pending():
                errors = []
                try:
                    if child.poll() is None: child.kill()
                except Exception as error: errors.append(error)
                try:
                    if type(child.wait(timeout=max(.001, min(2, deadline-time.monotonic())))) is not int:
                        raise RuntimeError('V30_CONTROLLER_COMMAND_UNREAPED')
                except Exception as error: errors.append(error)
                for resource in self.pending_resources.get(child, ()):
                    try:
                        if resource is not None: resource.close()
                    except Exception as error: errors.append(error)
                if errors: raise RuntimeError('V30_CONTROLLER_COMMAND_CLEANUP') from errors[0]
                self.pending.remove(child)
                self.pending_resources.pop(child, None)
            attempt(reap_pending)
        if self.child is not None:
            attempt(lambda: self.signal('SIGTERM'))
            try: self.child.wait(timeout=max(.001, min(8, deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                attempt(lambda: self.signal('SIGKILL'))
                attempt(lambda: self.child.wait(timeout=max(.001, min(5, deadline-time.monotonic()))))
            except Exception as error: failures.append(error)
            def group_absent():
                if self.child.pid in self.births:
                    if owned_group_members(self.child.pid, api=self.api, births=self.births):
                        self.signal('SIGKILL')
                    while owned_group_members(self.child.pid, api=self.api, births=self.births):
                        if time.monotonic() >= deadline: raise RuntimeError('V30_CONTROLLER_GROUP_REMAINS')
                        time.sleep(.05)
                elif self.child.poll() is None or self.api.group_pids(self.child.pid):
                    # Missing birth cannot authorize a group signal. Only real
                    # direct-child reaping AND independent empty group suffice.
                    raise RuntimeError('V30_CONTROLLER_HOST_BIRTH')
            attempt(group_absent)
        if grant and self.child is not None:
            def endpoint_absent():
                with socket.socket() as endpoint:
                    endpoint.settimeout(.5)
                    result = endpoint.connect_ex(('127.0.0.1', grant['hostPort']))
                if result != 61:  # Darwin ECONNREFUSED only; timeout is not absence.
                    raise RuntimeError('V30_CONTROLLER_ENDPOINT_REMAINS')
            attempt(endpoint_absent)
        if failures: raise RuntimeError('V30_CONTROLLER_CLEANUP_INCOMPLETE') from failures[0]
        return self.terminal()


class Controller:
    def __init__(self, repo, launcher_pid, nonce, driver, *, validator=validate_grant, archive_factory=Archive):
        if not hexadecimal(nonce): raise RuntimeError('V30_CONTROLLER_NONCE')
        self.repo, self.launcher_pid, self.nonce = Path(repo), launcher_pid, nonce
        self.driver, self.validator, self.archive_factory = driver, validator, archive_factory
        self.sequences = {'launcher': 0, 'worker': 0}; self.grant = self.archive = None
        self.worker_pid = None; self.started = False; self.policy = None; self.grant_digest = None
        self.receipt_sha = None
        self.state = {'phase': 'granted', 'pid': None, 'birth': None, 'instanceId': None,
                      'hostPort': None, 'terminal': None, 'networkProof': None, 'cleanupVerified': False}

    def _persist(self, event):
        if self.archive is None: return
        self.archive.write('v30-host-controller.jsonl', encoded({'version': 1, 'event': event,
            'grantSha256': self.grant_digest, 'state': self.state}) + b'\n', append=True)
        body = {'version': 1, 'grantSha256': self.grant_digest, 'launcherPid': self.launcher_pid,
                'workerPid': self.worker_pid, 'state': self.state}
        self.receipt_sha = self.archive.write('v30-host-controller.json', encoded(body) + b'\n')

    def status(self):
        terminal = self.driver.terminal()
        if terminal is not None and self.state['terminal'] != terminal:
            self.state.update(terminal=terminal, phase='terminal'); self._persist('reaped')
        return {**self.state, 'receiptSha256': self.receipt_sha}

    def stop(self):
        try:
            terminal = self.driver.stop(self.grant)
            pid, birth = self.driver.host_identity()
            if pid is not None:
                self.state.update(pid=pid, birth=birth)
            else:
                # An attempted instance is not a spawned host. Its attempted
                # identity remains in the pre-effect journal, never in terminal
                # process-absence proof.
                self.state.update(pid=None, birth=None, instanceId=None)
            self.state.update(terminal=terminal, phase='terminal', cleanupVerified=True)
            self._persist('cleanup-complete')
            return self.status()
        except BaseException:
            pid, birth = self.driver.host_identity()
            if pid is not None:
                self.state.update(pid=pid, birth=birth)
            self.state.update(phase='failed', cleanupVerified=False)
            self._persist('cleanup-incomplete')
            raise

    def handle(self, channel, request):
        exact(request, ('version', 'sequence', 'nonce', 'pid', 'op', 'payload'))
        if channel not in self.sequences or type(request['version']) is not int or request['version'] != 1 \
                or type(request['sequence']) is not int or request['sequence'] != self.sequences[channel] + 1 \
                or request['sequence'] > 4096 \
                or request['nonce'] != self.nonce or type(request['pid']) is not int:
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        self.sequences[channel] += 1
        op, value = request['op'], request['payload']
        if channel == 'launcher':
            if request['pid'] != self.launcher_pid: raise RuntimeError('V30_CONTROLLER_REJECTED')
            self.driver.launcher()
            if op == 'grant':
                if self.grant is not None: raise RuntimeError('V30_CONTROLLER_REJECTED')
                self.validator(self.repo, value)
                self.grant = dict(value); self.grant_digest = hashlib.sha256(encoded(value)).hexdigest()
                self.policy = combined_policy(self.repo, value['pgPort'], value['hostPort'])
                self.archive = self.archive_factory(value['run'])
                self.archive.write('v30-agent-host-combined.sb', self.policy.encode())
                self.state['hostPort'] = value['hostPort']; self._persist('granted')
                return {'grantSha256': self.grant_digest, 'hostPort': value['hostPort'],
                        'networkPolicySha256': hashlib.sha256(self.policy.encode()).hexdigest()}
            if op == 'bind-worker':
                exact(value, ('pid',))
                if self.grant is None or self.worker_pid is not None: raise RuntimeError('V30_CONTROLLER_REJECTED')
                self.driver.bind_worker(value['pid'], self.grant)
                self.worker_pid = value['pid']; self.state['phase'] = 'bound'; self._persist('worker-bound')
                return {'workerPid': self.worker_pid}
            if op in ('status', 'stop'):
                exact(value, ())
                return self.stop() if op == 'stop' else self.status()
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        if request['pid'] != self.worker_pid or self.worker_pid is None:
            raise RuntimeError('V30_CONTROLLER_REJECTED')
        self.driver.worker()
        if op in ('hello', 'status', 'release'):
            exact(value, ())
            return self.stop() if op == 'release' else self.status()
        if op == 'start':
            exact(value, ('instanceId',))
            if self.started or self.state['phase'] != 'bound' or not uuid(value['instanceId']):
                raise RuntimeError('V30_CONTROLLER_RESTART_DENIED')
            self.started = True  # Consumed before any probe or spawn, even on failure.
            self.state['instanceId'] = value['instanceId']
            self._persist('start-attempted')
            self.validator(self.repo, self.grant)
            self._persist('start-source-verified')
            self.driver.verify_pg(self.grant)
            self._persist('start-pg-verified')
            profile = Path(self.grant['run']) / 'v30-agent-host-combined.sb'
            if sha(profile) != hashlib.sha256(self.policy.encode()).hexdigest():
                raise RuntimeError('V30_CONTROLLER_POLICY')
            self._persist('start-policy-verified')
            self.state['networkProof'] = self.driver.probe(self.grant, profile)
            self._persist('network-probed')
            self.driver.worker()
            logs = Path(self.grant['run']) / 'host-logs'
            logs.mkdir(mode=0o700, exist_ok=True); private(logs, directory=True)
            pid, birth = self.driver.start(self.grant, profile, value['instanceId'])
            self.state.update(phase='running', pid=pid, birth=birth, instanceId=value['instanceId'])
            self._persist('host-spawned')
            return self.status()
        if op == 'signal':
            exact(value, ('signal',))
            if value['signal'] not in ('SIGTERM', 'SIGKILL') or not self.started:
                raise RuntimeError('V30_CONTROLLER_REJECTED')
            self.driver.signal(value['signal']); self._persist('host-signalled')
            return self.status()
        raise RuntimeError('V30_CONTROLLER_REJECTED')

    def response(self, channel, request):
        result = self.handle(channel, request)
        return {key: request[key] for key in ('version', 'sequence', 'nonce', 'op')} | \
            {'ok': True, 'result': result, 'error': None}

    def close(self):
        try: self.stop()
        finally:
            if self.archive: self.archive.close()
