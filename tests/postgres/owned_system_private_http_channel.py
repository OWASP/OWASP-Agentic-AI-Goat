"""Closed System channel component; no standalone launcher or receipt authority.

The future owning guest launcher must supply the namespace and journal FDs after
validating its live driver capability.  Importing this module has no effects.
The pump is deliberately HTTP-transparent: it never parses/logs credentials,
changes the original executor protocol, retries, or selects a destination.
"""
import ctypes
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import re
import select
import selectors
import socket
import stat
import subprocess
import threading
import time
import uuid

PORT = 8090
MAX_BYTES = 8 * 1024 * 1024
BUFFER_BYTES = 65536
MAX_SECONDS = 120
# Original policy-instruction-browser MAIN run_node bound is 900 seconds; its
# inner original browser test remains 600 seconds. This is not a new actor cap.
COHORT_SECONDS = 900
# Infrastructure only: <=10s activation inside original wrapper, then unchanged
# 1200s browser. The owning parent must verify full1200 before child dispatch.
DIAGNOSTIC_INFRASTRUCTURE_SECONDS = 1210
LIVE_ENABLED = False
PROFILE_SHA = 'dbd654c9ec9c10de04c77b76fc55c57ef5750a8cbe19870e132fc145f86a89d2'


def digest(raw):
    import hashlib
    return hashlib.sha256(raw).hexdigest()


def birth(pid):
    require(type(pid) is int and pid > 1, 'SYSTEM_PROCESS_PID')
    with open('/proc/' + str(pid) + '/stat', encoding='ascii') as source:
        return source.read().rsplit(')', 1)[1].split()[19]


def process_current(capture, namespace):
    require(type(capture) is dict and set(capture) == {'pid', 'startTicks', 'exe'}
            and type(capture['startTicks']) is str and re.fullmatch('[1-9][0-9]*', capture['startTicks']),
            'SYSTEM_PROCESS_CAPTURE')
    pid = capture['pid']
    require(birth(pid) == capture['startTicks']
            and os.readlink('/proc/' + str(pid) + '/exe') == capture['exe']
            and os.stat('/proc/' + str(pid) + '/ns/net').st_ino == namespace
            and birth(pid) == capture['startTicks'], 'SYSTEM_PROCESS_CHANGED')


def fixed_binding(value):
    """Shape check only, never capability admission or live permission."""
    require(type(value) is dict and set(value) == {'version', 'target', 'runId', 'imageId',
            'inputSha256', 'daemonId', 'physical'}, 'SYSTEM_BINDING')
    require(value['version'] == 1 and value['target'] in ('original-v24-system', 'original-v24-policy', 'original-v03-diagnostic')
            and re.fullmatch('[a-f0-9]{32}', value['runId'])
            and re.fullmatch('sha256:[a-f0-9]{64}', value['imageId'])
            and re.fullmatch('[a-f0-9]{64}', value['inputSha256'])
            and re.fullmatch('[a-zA-Z0-9:-]{20,128}', value['daemonId']), 'SYSTEM_BINDING')
    root = '/var/tmp/dvaia-v23-build-' + value['runId'] + '/fs'
    physical = value['physical']
    require(type(physical) is dict and set(physical) == {'privateDockerHost', 'namespaceInode',
            'filesystemIdentity', 'daemonProcess', 'namespaceHolder'}
            and physical['privateDockerHost'] == 'unix://' + root + '/docker.sock'
            and re.fullmatch(r'net:\[[1-9][0-9]*\]', physical['namespaceInode']), 'SYSTEM_BINDING')
    for key, exe in (('daemonProcess', '/usr/bin/dockerd'), ('namespaceHolder', '/usr/bin/sleep')):
        item = physical[key]
        require(type(item) is dict and set(item) == {'pid', 'startTicks', 'exe'}
                and type(item['pid']) is int and item['pid'] > 1 and item['exe'] == exe
                and type(item['startTicks']) is str and re.fullmatch('[1-9][0-9]*', item['startTicks']),
                'SYSTEM_BINDING')
    require(physical['daemonProcess']['pid'] != physical['namespaceHolder']['pid'], 'SYSTEM_BINDING')
    filesystem = physical['filesystemIdentity']
    require(type(filesystem) is dict and set(filesystem) == {'device', 'inode'}
            and type(filesystem['device']) is int and filesystem['device'] >= 0
            and type(filesystem['inode']) is int and filesystem['inode'] > 0, 'SYSTEM_BINDING')
    return Path(root), int(physical['namespaceInode'][5:-1])


def bounded_command(argv, deadline, stopped=lambda: False, *, record=None, capture=None, completed=False):
    """Fixed-command caller owns every child immediately; separate cleanup debt."""
    active(deadline, stopped)
    if record: record({'stage':'intent'})
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C'})
    selector, failure = None, None
    output, diagnostics, debt = bytearray(), bytearray(), []
    try:
        if record:
            record({'stage':'spawned','pid':child.pid,'birth':capture(child.pid) if capture else birth(child.pid)})
        selector = selectors.DefaultSelector()
        for stream, buffer in ((child.stdout, output), (child.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, buffer)
        while selector.get_map():
            active(deadline, stopped)
            for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                data = os.read(key.fd, 16384)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                require(len(output)+len(diagnostics)+len(data) <= 1048576, 'SYSTEM_COMMAND_BYTES')
                key.data.extend(data)
        child.wait(timeout=max(.001, deadline-time.monotonic()))
        require(child.returncode == 0, 'SYSTEM_COMMAND_FAILED')
        active(deadline, stopped)
    except BaseException as error:
        failure = error
    finally:
        if child.poll() is None:
            try:
                child.kill()
            except BaseException:
                debt.append('kill')
            try:
                child.wait(timeout=5)
            except BaseException:
                debt.append('reap')
        # No signal after a reaped leader: a surviving group is retained debt.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        except BaseException:
            debt.append('group-unknown')
        else:
            debt.append('group-present')
        for close in ([selector.close] if selector else []) + [child.stdout.close, child.stderr.close]:
            try:
                close()
            except BaseException:
                debt.append('descriptor')
    if debt:
        failure = failure or RuntimeError('SYSTEM_COMMAND_RETIREMENT')
        failure.cleanupDebt = {'pid': child.pid, 'items': debt}
    if record:
        try:
            record({'stage':'terminal','pid':child.pid,'exitCode':child.returncode,
                    'cleanupDebt':debt,'failed':failure is not None})
        except BaseException as error:
            if failure is None: failure = error
            failure.cleanupDebt = {'pid':child.pid,'items':debt+['journal-terminal']}
    if failure:
        raise failure
    if completed:
        return subprocess.CompletedProcess(argv, child.returncode, bytes(output).decode('utf8','strict'),
                                           bytes(diagnostics).decode('utf8','strict'))
    return bytes(output)


class GuestRuntime:
    """Fixed guest lifecycle implementation, not a public authority factory.

    The owning driver must admit the host-side branded capability before sending
    this code. Real process/filesystem/daemon/image checks also run before every
    effect. JSON shape or a past successful receipt alone cannot open the public
    entry point (which is deliberately absent).
    """
    def __init__(self, binding, deadline, stopped=lambda: False):
        self.root, self.namespace = fixed_binding(binding)
        check_deadline(deadline)
        self.binding, self.deadline = binding, deadline
        self.stopped = stopped
        self.cleaning = False
        self.policy = binding['target'] == 'original-v24-policy'
        self.diagnostic = binding['target'] == 'original-v03-diagnostic'
        self.slot = 'diagnostic' if self.diagnostic else 'policy' if self.policy else 'system'
        self.name = 'dvaia-'+self.slot+'-runtime-' + binding['runId']
        self.profile = self.name
        self.entrypoint = ['/usr/local/bin/node', '/qualification/diagnostic-listener-entry.js' if self.diagnostic else '/app/policy-render/listener.js' if self.policy else '/qualification/owned-system/http-listener.js']

    def filename(self, name):
        # Only the literal renderer target receives a separate durable namespace.
        return self.slot+'-'+name[7:] if (self.policy or self.diagnostic) and name.startswith('system-') else name

    def runtime_capture(self, verify=True):
        if not self.policy:
            return self.binding['physical']['namespaceHolder'], self.namespace
        row = json.loads(self.private_read('system-runtime-process.json'))
        require(type(row) is dict and set(row) == {'process','namespaceInode','containerId'}
                and re.fullmatch('[a-f0-9]{64}', row['containerId'])
                and type(row['namespaceInode']) is int and row['namespaceInode'] > 0, 'POLICY_RUNTIME_CAPTURE')
        require(row['namespaceInode'] not in (self.namespace, os.stat('/proc/1/ns/net').st_ino,
                os.stat('/proc/self/ns/net').st_ino), 'POLICY_RUNTIME_NAMESPACE')
        require(row['process'].get('exe') == '/usr/local/bin/node', 'POLICY_RUNTIME_PROCESS')
        if verify:
            process_current(row['process'], row['namespaceInode'])
        return row['process'], row['namespaceInode']

    def private_read(self, name, limit=8192):
        path = self.root/self.filename(name)
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit, 'SYSTEM_PRIVATE_FILE')
            raw = os.read(fd, limit+1)
            require(len(raw) == info.st_size, 'SYSTEM_PRIVATE_FILE')
            return raw
        finally:
            os.close(fd)

    def write_new(self, name, raw):
        require(len(raw) <= 32768, 'SYSTEM_PRIVATE_BYTES')
        fd = os.open(self.root/self.filename(name), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                require(written > 0, 'SYSTEM_PRIVATE_WRITE')
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def docker(self, *args):
        return self.command(['/usr/bin/docker', '--host', self.binding['physical']['privateDockerHost'], *args])

    def command(self, argv):
        # A new immutable obligation survives Python/SSH exit and is inspected by
        # subsequent cleanup. No argv, credentials or command output is journaled.
        name = 'system-command-'+uuid.uuid4().hex+'.jsonl'
        self.write_new(name, b'')
        fd = os.open(self.root/self.filename(name), os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        try:
            return bounded_command(argv, self.deadline, self.stopped,
                record=lambda row: journal(fd, dict(row, runId=self.binding['runId'])))
        finally:
            os.close(fd)

    def commands_absent(self):
        paths = list(self.root.glob(self.slot+'-command-*.jsonl'))
        require(len(paths) <= 2048, 'SYSTEM_COMMAND_INVENTORY')
        for path in paths:
            require(re.fullmatch(self.slot+'-command-[a-f0-9]{32}\\.jsonl', path.name), 'SYSTEM_COMMAND_INVENTORY')
            rows = [json.loads(line) for line in self.private_read(path.name).splitlines()]
            require(len(rows) == 3 and [r.get('stage') for r in rows] == ['intent','spawned','terminal']
                    and all(r.get('runId') == self.binding['runId'] for r in rows)
                    and rows[1]['pid'] == rows[2]['pid'] and rows[2]['cleanupDebt'] == [],
                    'SYSTEM_COMMAND_RETIREMENT_UNPROVEN')
            try: current = birth(rows[1]['pid'])
            except FileNotFoundError: current = None
            require(current != rows[1]['birth'], 'SYSTEM_COMMAND_REMAINS')
            try: os.killpg(rows[1]['pid'], 0)
            except ProcessLookupError: pass
            else: raise RuntimeError('SYSTEM_COMMAND_GROUP_REMAINS')

    def guard(self):
        active(self.deadline, self.stopped)
        require(os.geteuid() == 0, 'SYSTEM_GUEST_ROOT')
        current = Path('/')
        for part in self.root.parts[1:]:
            current /= part
            info = current.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not stat.S_ISLNK(info.st_mode), 'SYSTEM_GUEST_PATH')
        expected = self.binding['physical']['filesystemIdentity']
        info = self.root.stat()
        require((info.st_dev, info.st_ino) == (expected['device'], expected['inode']), 'SYSTEM_GUEST_FILESYSTEM')
        require(stat.S_IMODE(self.root.parent.stat().st_mode) == 0o700, 'SYSTEM_GUEST_OWNER')
        owner_fd = os.open(self.root.parent/'owner', os.O_RDONLY|os.O_NOFOLLOW)
        try:
            owner = os.fstat(owner_fd)
            require(stat.S_ISREG(owner.st_mode) and owner.st_uid == 0 and owner.st_nlink == 1
                    and stat.S_IMODE(owner.st_mode) == 0o600 and owner.st_size == 32
                    and os.read(owner_fd, 33) == self.binding['runId'].encode(), 'SYSTEM_GUEST_OWNER')
        finally:
            os.close(owner_fd)
        if not self.cleaning:
            self.lease()
        require(self.namespace not in (os.stat('/proc/1/ns/net').st_ino,
                                       os.stat('/proc/self/ns/net').st_ino), 'SYSTEM_SHARED_NAMESPACE')
        for key in ('daemonProcess', 'namespaceHolder'):
            process_current(self.binding['physical'][key], self.namespace)
        info = json.loads(self.docker('info', '--format', '{{json .}}'))
        require(info['ID'] == self.binding['daemonId'] and info['DockerRootDir'] == str(self.root/'data'), 'SYSTEM_DAEMON')
        images = json.loads(self.docker('image', 'inspect', self.binding['imageId']))
        require(len(images) == 1, 'SYSTEM_IMAGE')
        image = images[0]
        require(image['Id'] == self.binding['imageId'] and image['Architecture'] == 'arm64'
                and image['Os'] == 'linux' and image['Config']['User'] == '10001:10001'
                and image['Config']['Entrypoint'] == self.entrypoint
                and image['Config']['Labels'].get('dvaia.'+self.slot+'.inputs') == self.binding['inputSha256']
                and image['Config']['Labels'].get('dvaia.build-run') == self.binding['runId'], 'SYSTEM_IMAGE')

    def profile_names(self):
        with open('/sys/kernel/security/apparmor/profiles', encoding='ascii') as source:
            raw = source.read(1048577)
        require(len(raw) <= 1048576, 'SYSTEM_PROFILE_INVENTORY')
        return {line.rsplit(' (', 1)[0] for line in raw.splitlines()}

    def lease(self, runtime_deadline=None):
        if self.diagnostic:
            return self.diagnostic_lease(runtime_deadline)
        fd = os.open(self.root.parent/'system-lease.json', os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096, 'SYSTEM_LEASE')
            raw = os.read(fd, 4097)
            require(len(raw) == info.st_size, 'SYSTEM_LEASE')
            row = json.loads(raw)
        finally: os.close(fd)
        require(set(row) == {'version','target','runId','clock','startedAtMs','expiresAtMs'}
                and row['version'] == 1 and row['target'] == 'original-v24-system-total-lease-v1'
                and row['runId'] == self.binding['runId'] and row['clock'] == 'linux-monotonic-ms'
                and type(row['startedAtMs']) is int and row['startedAtMs'] >= 0
                and type(row['expiresAtMs']) is int and row['expiresAtMs'] == row['startedAtMs']+3636000
                and row['startedAtMs'] <= time.monotonic_ns()//1000000 < row['expiresAtMs'], 'SYSTEM_LEASE')
        if runtime_deadline is not None:
            require(runtime_deadline*1000 <= row['expiresAtMs']-936000, 'SYSTEM_LEASE_RUNTIME_RESERVE')

    def diagnostic_lease(self, runtime_deadline=None):
        # Created once from a conservatively mapped absolute parent endpoint.
        # This durable record is not public execution authority.
        fd = os.open(self.root.parent/'v03-combined-lease.json', os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 4096, 'DIAGNOSTIC_LEASE_FILE')
            raw = os.read(fd, 4097)
            after = os.fstat(fd)
            require(len(raw) == info.st_size and all(getattr(info,key) == getattr(after,key)
                    for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'DIAGNOSTIC_LEASE_FILE')
            row = json.loads(raw)
        finally:
            os.close(fd)
        with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as stream:
            boot = stream.read(38).strip()
        require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot), 'DIAGNOSTIC_LEASE_BOOT')
        require(type(row) is dict and set(row) == {'version','target','runId','parentRunId','clock','startedAtMs','expiresAtMs','combinedPlanSha256','guestBootId'}
                and type(row['version']) is int and row['version'] == 1 and row['target'] == 'original-v03-combined-preparation-lease-v1'
                and row['guestBootId'] == boot
                and row['runId'] == self.binding['runId'] and row['clock'] == 'linux-monotonic-ms'
                and type(row['parentRunId']) is str and re.fullmatch('[a-f0-9]{32}', row['parentRunId'])
                and digest((row['parentRunId']+':v03-diagnostic').encode('ascii'))[:32] == self.binding['runId']
                and type(row['combinedPlanSha256']) is str and re.fullmatch('[a-f0-9]{64}', row['combinedPlanSha256'])
                and type(row['startedAtMs']) is int and type(row['expiresAtMs']) is int
                and 0 <= row['startedAtMs'] < row['expiresAtMs'] <= row['startedAtMs']+11096000
                and row['startedAtMs'] <= time.monotonic_ns()//1000000 < row['expiresAtMs'], 'DIAGNOSTIC_LEASE')
        if runtime_deadline is not None:
            require(type(runtime_deadline) in (int,float) and math.isfinite(runtime_deadline)
                    and self.deadline <= runtime_deadline
                    and runtime_deadline*1000 <= row['expiresAtMs']-4536000, 'DIAGNOSTIC_LEASE_RUNTIME_RESERVE')
        return row

    def claim_diagnostic_cohort(self, phase):
        require(self.diagnostic, 'DIAGNOSTIC_COHORT_TARGET')
        self.guard()
        require(type(phase) is dict and set(phase) == {'parentRunId','runId','combinedPlanSha256','guestBootId','phase','startedAtMs','deadlineMs'}
                and phase['phase'] == 'cohortClaim' and phase['runId'] == self.binding['runId']
                and type(phase['startedAtMs']) is int and type(phase['deadlineMs']) is int
                and phase['deadlineMs']-phase['startedAtMs'] == 1210000, 'DIAGNOSTIC_COHORT_BINDING')
        now = time.monotonic_ns()//1000000
        require(0 <= now-phase['startedAtMs'] < 10000 and phase['deadlineMs']-now >= 1200000,
                'DIAGNOSTIC_COHORT_DEADLINE')
        deadline = phase['deadlineMs']/1000
        lease = self.diagnostic_lease(deadline)
        require(all(phase[key] == lease[key] for key in ('parentRunId','runId','combinedPlanSha256','guestBootId')),
                'DIAGNOSTIC_COHORT_BINDING')
        preparation = float(self.private_read('system-runtime.deadline', 64))
        require(deadline <= preparation, 'DIAGNOSTIC_COHORT_PREPARATION_BOUND')
        # Exclusive publication rejects a second claim, even with equal bytes.
        self.write_new('system-cohort.deadline', str(deadline).encode('ascii'))
        return {'version':1,'runId':self.binding['runId'],'target':self.binding['target'],'claimed':True}

    def start(self, token, original_profile, runtime_deadline):
        if self.diagnostic:
            self.diagnostic_lease(runtime_deadline)
        else:
            check_runtime_deadline(runtime_deadline)
        require(runtime_deadline >= self.deadline, 'SYSTEM_RUNTIME_DEADLINE')
        require(token is None if self.policy else type(token) is str and re.fullmatch('[A-Za-z0-9_-]{43,128}', token), 'SYSTEM_TOKEN')
        require(type(original_profile) is bytes and digest(original_profile) == PROFILE_SHA, 'SYSTEM_PROFILE_SOURCE')
        self.guard()
        self.lease(runtime_deadline)
        if self.policy:
            # The original System start owns the only cohort deadline. The
            # renderer cannot receive a fresh900s lease from a later request.
            fd = os.open(self.root/'system-runtime.deadline', os.O_RDONLY|os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 64, 'POLICY_COHORT_FILE')
                raw = os.read(fd,65)
                require(len(raw) == info.st_size and float(raw) == runtime_deadline, 'POLICY_COHORT_CHANGED')
            finally: os.close(fd)
        require(not self.docker('ps', '-a', '--filter', 'name=^/'+self.name+'$', '--format', '{{.ID}}').strip(), 'SYSTEM_CONTAINER_COLLISION')
        require(not any(name == self.profile or name.startswith(self.profile+'//') for name in self.profile_names()), 'SYSTEM_PROFILE_COLLISION')
        # Durable intent precedes profile loading and ambiguous container create.
        self.write_new('system-runtime-intent.json', json.dumps({'version':1, 'binding':self.binding,
            'name':self.name, 'profile':self.profile}, sort_keys=True).encode())
        self.write_new('system-runtime.deadline', str(runtime_deadline).encode('ascii'))
        self.write_new('system-runtime.apparmor', original_profile.replace(b'@@SUPERVISOR_PROFILE@@', self.profile.encode()))
        environment = ('SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN='+token+
            '\nSECURESHOP_SYSTEM_DIAGNOSTIC_HOST=127.0.0.1\nSECURESHOP_SYSTEM_DIAGNOSTIC_PORT=8090\n' if self.diagnostic else
            'SECURESHOP_POLICY_RENDER_ENABLED=true\nSECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1\n' if self.policy else
            'SECURESHOP_SYSTEM_CONFIG_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_CONFIG_TOKEN='+token+
            '\nSECURESHOP_SYSTEM_CONFIG_HOST=127.0.0.1\nSECURESHOP_SYSTEM_CONFIG_PORT=8090\n')
        self.write_new('system-runtime.env', environment.encode())
        self.guard()
        self.command(['/sbin/apparmor_parser', '-a', str(self.root/self.filename('system-runtime.apparmor'))])
        require(self.profile in self.profile_names() and self.profile+'//bwrap' in self.profile_names(), 'SYSTEM_PROFILE_LOAD')
        self.guard()
        self.write_new('system-runtime-create-attempt.json', b'{"attempted":true}')
        raw_id = self.docker('create', '--pull', 'never', '--name', self.name, '--label', 'dvaia.'+self.slot+'.runtime='+self.binding['runId'],
                    '--network', 'none' if self.policy else 'host', '--read-only', '--user', '10001:10001', '--memory', '512m', '--cpus', '1',
                    '--pids-limit', '128', *(['--cap-drop','ALL'] if self.policy else []),
                    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m' if self.policy else '/tmp:rw,nosuid,nodev,size=128m', '--security-opt', 'seccomp=unconfined',
                    '--security-opt', 'apparmor='+self.profile, '--log-driver', 'local', '--log-opt', 'max-size=1m',
                    '--log-opt', 'max-file=1', '--log-opt', 'compress=false',
                    '--env-file', str(self.root/self.filename('system-runtime.env')), self.binding['imageId'])
        require(re.fullmatch(b'[a-f0-9]{64}\n?', raw_id), 'SYSTEM_CREATE_RESULT')
        self.write_new('system-runtime-created-id', raw_id.strip())
        created = self.inspect(False)
        require(created['containerId'] == raw_id.decode('ascii').strip(), 'SYSTEM_CREATE_RESULT')
        self.write_new('system-runtime-container.json', json.dumps(created, sort_keys=True).encode())
        self.guard()
        self.docker('start', created['containerId'])
        if self.policy:
            # Capture only the actual exact inspected container; never a supplied PID.
            row = self.container_row(True)
            pid = row['State']['Pid']
            capture = {'pid':pid, 'startTicks':birth(pid), 'exe':'/usr/local/bin/node'}
            namespace = os.stat('/proc/'+str(pid)+'/ns/net').st_ino
            require(namespace not in (self.namespace, os.stat('/proc/1/ns/net').st_ino,
                    os.stat('/proc/self/ns/net').st_ino), 'POLICY_RUNTIME_NAMESPACE')
            process_current(capture, namespace)
            self.write_new('system-runtime-process.json', json.dumps({'process':capture,
                'namespaceInode':namespace,'containerId':created['containerId']},sort_keys=True).encode())
        result = self.inspect(True)
        self.wait_listener()
        if self.diagnostic:
            self.wait_diagnostic_readiness()
        return result

    def wait_diagnostic_readiness(self):
        # Before the cohort claim, no general-purpose HTTP channel is admitted.
        # The only startup request is the original authenticated health GET.
        self.guard()
        holder, namespace = self.runtime_capture()
        source = diagnostic_readiness_program(str(self.root/self.filename('system-runtime.env')),
                                              namespace, self.deadline)
        self.command(['/usr/bin/nsenter','--net=/proc/'+str(holder['pid'])+'/ns/net',
                      '/usr/bin/python3','-I','-S','-B','-c',source])
        active(self.deadline,self.stopped)

    def wait_listener(self):
        # Only connection establishment is polled, before a bridge can accept
        # any HTTP request. No HTTP bytes/tool requests are ever replayed.
        self.guard()
        holder, namespace = self.runtime_capture()
        source = '''import socket,time,errno,os
if os.stat('/proc/self/ns/net').st_ino!=EXPECTED_NAMESPACE: raise RuntimeError('SYSTEM_STARTUP_NAMESPACE')
deadline=min(float(DEADLINE),time.monotonic()+40)
while True:
 if time.monotonic()>=deadline: raise RuntimeError('SYSTEM_STARTUP_DEADLINE')
 sock=socket.socket()
 sock.settimeout(min(.25,max(.001,deadline-time.monotonic())))
 try:
  sock.connect(('127.0.0.1',8090))
  break
 except OSError as error:
  if error.errno!=errno.ECONNREFUSED: raise
 finally: sock.close()
 time.sleep(min(.05,max(0,deadline-time.monotonic())))
'''.replace('DEADLINE', repr(self.deadline)).replace('EXPECTED_NAMESPACE',repr(namespace))
        self.command(['/usr/bin/nsenter','--net=/proc/'+str(holder['pid'])+'/ns/net',
                      '/usr/bin/python3','-I','-S','-B','-c',source])
        active(self.deadline,self.stopped)

    def container_row(self, running):
        self.guard()
        rows = json.loads(self.docker('container', 'inspect', self.name))
        require(len(rows) == 1, 'SYSTEM_CONTAINER')
        row = rows[0]
        config, host = row['Config'], row['HostConfig']
        require(re.fullmatch('[a-f0-9]{64}', row['Id']) and row['Image'] == self.binding['imageId']
                and row['Name'] == '/'+self.name and config['Labels'].get('dvaia.'+self.slot+'.runtime') == self.binding['runId']
                and config['User'] == '10001:10001' and config['Entrypoint'] == self.entrypoint
                and host['NetworkMode'] == ('none' if self.policy else 'host') and not host.get('PortBindings') and not row.get('Mounts')
                and host['ReadonlyRootfs'] is True and host['Memory'] == 536870912 and host['NanoCpus'] == 1000000000
                and host['PidsLimit'] == 128 and host['Tmpfs'] == {'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m' if self.policy else 'rw,nosuid,nodev,size=128m'}
                and set(host['SecurityOpt']) == {'seccomp=unconfined','apparmor='+self.profile}
                and row['State']['Running'] is running, 'SYSTEM_CONTAINER')
        if self.policy:
            env = config.get('Env', [])
            networks = row.get('NetworkSettings', {})
            require(host.get('CapDrop') == ['ALL'] and not host.get('CapAdd') and not host.get('Privileged')
                    and not host.get('PidMode') and host.get('IpcMode') != 'host' and host.get('UsernsMode') != 'host'
                    and type(networks.get('Networks')) is dict and set(networks['Networks']) == {'none'}
                    and not any((networks.get('Ports') or {}).values())
                    and all(sum(v.startswith(key+'=') for v in env) == 1 and key+'='+value in env for key,value in
                        [('SECURESHOP_POLICY_RENDER_ENABLED','true'),('SECURESHOP_POLICY_RENDER_MAX_CONCURRENT','1')]), 'POLICY_CONTAINER')
        if running and not self.policy:
            require(os.stat('/proc/'+str(row['State']['Pid'])+'/ns/net').st_ino == self.namespace, 'SYSTEM_CONTAINER_NAMESPACE')
        active(self.deadline, self.stopped)
        return row

    def inspect(self, running):
        row = self.container_row(running)
        namespace = self.namespace
        if self.policy and running:
            capture, namespace = self.runtime_capture()
            recorded = json.loads(self.private_read('system-runtime-process.json'))
            require(row['State']['Pid'] == capture['pid'] and row['Id'] == recorded['containerId'], 'POLICY_RUNTIME_CHANGED')
        return {'version':1, 'runId':self.binding['runId'], 'containerId':row['Id'],
                'imageId':row['Image'], 'running':running, 'namespaceInode':namespace,
                **({'target':self.binding['target']} if self.policy or self.diagnostic else {})}

    def channels_absent(self, channel_ids):
        require(type(channel_ids) is list and len(channel_ids) <= 64 and len(set(channel_ids)) == len(channel_ids)
                and all(type(value) is str and re.fullmatch('[a-f0-9]{32}', value) for value in channel_ids), 'SYSTEM_CHANNEL_IDS')
        expected = {self.slot+'-channel-'+value+'.jsonl' for value in channel_ids}
        require({path.name for path in self.root.glob(self.slot+'-channel-*.jsonl')} == expected, 'SYSTEM_CHANNEL_INVENTORY')
        namespace = self.runtime_capture(False)[1] if channel_ids and self.policy else self.namespace
        failures = []
        for name in sorted(expected):
            rows = [json.loads(line) for line in self.private_read(name).splitlines()]
            require(len(rows) == 2, 'SYSTEM_CHANNEL_TERMINAL')
            first, last = rows
            require(set(first) == {'version','runId','channelId','pid','startTicks','namespaceInode','stage'}
                    and set(last) == set(first)|{'outcome','sentBytes','receivedBytes'}
                    and first.get('version') == 1 and first.get('stage') == 'started' and last.get('stage') == 'terminal'
                    and first.get('runId') == self.binding['runId']
                    and first.get('channelId') == name[len(self.slot+'-channel-'):-len('.jsonl')]
                    and first.get('namespaceInode') == namespace
                    and all(last.get(key) == first.get(key) for key in ('version','runId','channelId','pid','startTicks','namespaceInode')),
                    'SYSTEM_CHANNEL_TERMINAL')
            require(last['outcome'] in ('complete','failed') and type(first['pid']) is int and first['pid'] > 1
                    and type(first['startTicks']) is str and re.fullmatch('[1-9][0-9]*', first['startTicks'])
                    and all(type(last[key]) is int and 0 <= last[key] <= MAX_BYTES for key in ('sentBytes','receivedBytes')),
                    'SYSTEM_CHANNEL_TERMINAL')
            if last['outcome'] != 'complete':
                failures.append(first['channelId'])
            try:
                current = birth(first['pid'])
            except FileNotFoundError:
                current = None
            require(current != first['startTicks'], 'SYSTEM_CHANNEL_STILL_LIVE')
        return failures

    def stop(self, channel_ids):
        # Expiry forbids new work, not identity-checked retirement.
        self.cleaning = True
        self.guard()
        self.commands_absent()
        self.channels_absent(channel_ids)  # local SSH EOF alone never suffices
        intent = json.loads(self.private_read('system-runtime-intent.json'))
        require(intent == {'version':1, 'binding':self.binding, 'name':self.name, 'profile':self.profile}, 'SYSTEM_RUNTIME_INTENT')
        listed = self.docker('ps', '-a', '--filter', 'name=^/'+self.name+'$', '--format', '{{.ID}}').strip()
        try:
            attempt = self.private_read('system-runtime-create-attempt.json')
        except FileNotFoundError:
            attempt = None
        try:
            known_id = self.private_read('system-runtime-created-id').decode('ascii')
            require(re.fullmatch('[a-f0-9]{64}', known_id), 'SYSTEM_CREATE_RESULT')
        except FileNotFoundError:
            known_id = None
        # A lost create response plus absent container cannot prove the daemon
        # has finished processing the original request. Keep the owning runtime.
        require(not attempt or known_id is not None or bool(listed), 'SYSTEM_CREATE_OUTCOME_UNCERTAIN')
        if listed:
            rows = json.loads(self.docker('container', 'inspect', self.name))
            require(len(rows) == 1 and rows[0]['Image'] == self.binding['imageId']
                    and rows[0]['Name'] == '/'+self.name and re.fullmatch('[a-f0-9]{64}', rows[0]['Id'])
                    and rows[0]['Config']['Labels'].get('dvaia.'+self.slot+'.runtime') == self.binding['runId'], 'SYSTEM_CLEANUP_OWNER')
            require(known_id is None or rows[0]['Id'] == known_id, 'SYSTEM_CLEANUP_CONTAINER_CHANGED')
            self.docker('rm', '-f', rows[0]['Id'])
        require(not self.docker('ps', '-a', '--filter', 'name=^/'+self.name+'$', '--format', '{{.ID}}').strip(), 'SYSTEM_CONTAINER_REMAINS')
        profiles = self.profile_names()
        if self.profile in profiles or self.profile+'//bwrap' in profiles:
            original = self.private_read('system-runtime.apparmor', 32768).replace(self.profile.encode(), b'@@SUPERVISOR_PROFILE@@')
            require(digest(original) == PROFILE_SHA, 'SYSTEM_PROFILE_SOURCE')
            self.command(['/sbin/apparmor_parser', '-R', str(self.root/self.filename('system-runtime.apparmor'))])
        require(not any(name == self.profile or name.startswith(self.profile+'//') for name in self.profile_names()), 'SYSTEM_PROFILE_REMAINS')
        failures = self.channels_absent(channel_ids)
        self.commands_absent()
        return {'version':1, 'runId':self.binding['runId'], 'containerAbsent':True,
                'profileAbsent':True, 'remoteChannelsAbsent':True, 'channelFailures':failures, 'builderReleaseAllowed':False,
                **({'target':self.binding['target']} if self.policy or self.diagnostic else {})}


def diagnostic_readiness_program(environment_path, namespace, deadline):
    require(type(environment_path) is str and re.fullmatch(
        '/var/tmp/dvaia-v23-build-[a-f0-9]{32}/fs/diagnostic-runtime.env', environment_path), 'DIAGNOSTIC_READINESS_PATH')
    require(type(namespace) is int and namespace > 0 and type(deadline) in (int,float)
            and math.isfinite(deadline), 'DIAGNOSTIC_READINESS_INPUT')
    return 'ENV_PATH='+repr(environment_path)+'\nEXPECTED_NAMESPACE='+repr(namespace)+'\nDEADLINE='+repr(deadline)+'\n'+r'''
import os,stat,time,json,http.client
if os.stat('/proc/self/ns/net').st_ino != EXPECTED_NAMESPACE: raise RuntimeError('DIAGNOSTIC_READINESS_NAMESPACE')
fd=os.open(ENV_PATH,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 info=os.fstat(fd)
 if not(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=4096): raise RuntimeError('DIAGNOSTIC_READINESS_ENV')
 raw=os.read(fd,4097)
 if len(raw)!=info.st_size: raise RuntimeError('DIAGNOSTIC_READINESS_ENV')
finally:os.close(fd)
lines=raw.decode('ascii').splitlines()
if len(lines)!=4: raise RuntimeError('DIAGNOSTIC_READINESS_ENV')
values=dict(line.split('=',1) for line in lines)
if set(values)!={'SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED','SECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN','SECURESHOP_SYSTEM_DIAGNOSTIC_HOST','SECURESHOP_SYSTEM_DIAGNOSTIC_PORT'} or values['SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED']!='true' or values['SECURESHOP_SYSTEM_DIAGNOSTIC_HOST']!='127.0.0.1' or values['SECURESHOP_SYSTEM_DIAGNOSTIC_PORT']!='8090': raise RuntimeError('DIAGNOSTIC_READINESS_ENV')
import re
token=values['SECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN']
if not re.fullmatch('[A-Za-z0-9_-]{43,128}',token): raise RuntimeError('DIAGNOSTIC_READINESS_ENV')
end=min(DEADLINE,time.monotonic()+40)
expected={'version':'secureshop-owned-system-diagnostic-http.v1','ready':True,'isolation':'bwrap-system-diagnostic-v1','diagnosticCapability':'secureshop-owned-system-diagnostic.v1'}
while time.monotonic()<end:
 connection=http.client.HTTPConnection('127.0.0.1',8090,timeout=min(2,max(.001,end-time.monotonic())))
 try:
  connection.request('GET','/secureshop/system/diagnostic-health',headers={'Authorization':'Bearer '+token})
  response=connection.getresponse();body=response.read(32769)
  if response.status==200 and len(body)<=32768 and json.loads(body)==expected:break
 except (OSError,ValueError,http.client.HTTPException):pass
 finally:connection.close()
 time.sleep(min(.25,max(0,end-time.monotonic())))
else:raise RuntimeError('DIAGNOSTIC_READINESS_UNAVAILABLE')
'''


def channel_program(binding, channel_id, expected_source_sha=None):
    """Fixed guest code sent only over an already-admitted SSH mux.

    The guest runtime deadline is captured once by the owning driver, not reset
    per connection. No command-line token, arbitrary destination or shared-master
    forwarding is permitted. This function does not authorize or execute code.
    """
    fixed_binding(binding)
    require(type(channel_id) is str and re.fullmatch('[a-f0-9]{32}', channel_id), 'SYSTEM_CHANNEL_ID')
    source_bytes = Path(__file__).read_bytes()
    require(len(source_bytes) <= 65536 and (expected_source_sha is None or digest(source_bytes) == expected_source_sha), 'SYSTEM_CHANNEL_SOURCE')
    source = source_bytes.decode('utf8','strict')
    # The module's CLI fence is not executed when embedded as a library.
    source = source.split("\nif __name__ == '__main__':", 1)[0]
    return source + '\n' + r'''
import signal
BINDING = json.loads(BINDING_JSON)
CHANNEL_ID = CHANNEL_LITERAL
ROOT, NAMESPACE = fixed_binding(BINDING)
DIAGNOSTIC = BINDING['target'] == 'original-v03-diagnostic'
SLOT = 'diagnostic' if DIAGNOSTIC else 'policy' if BINDING['target'] == 'original-v24-policy' else 'system'
deadline_fd = os.open(ROOT/(SLOT+('-cohort.deadline' if DIAGNOSTIC else '-runtime.deadline')), os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    info = os.fstat(deadline_fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 64, 'SYSTEM_RUNTIME_DEADLINE')
    DEADLINE = float(os.read(deadline_fd, 65).decode('ascii'))
finally:
    os.close(deadline_fd)
check_runtime_deadline(DEADLINE, BINDING['target'])
CHANNEL_DEADLINE = min(DEADLINE, time.monotonic()+MAX_SECONDS)
runtime = GuestRuntime(BINDING, CHANNEL_DEADLINE)
runtime.guard()
runtime.inspect(True)
holder, NAMESPACE = runtime.runtime_capture()
namespace_fd = os.open('/proc/'+str(holder['pid'])+'/ns/net', os.O_RDONLY)
try:
    process_current(holder, NAMESPACE)
    require(os.fstat(namespace_fd).st_ino == NAMESPACE, 'SYSTEM_CHANNEL_NAMESPACE')
    journal_fd = os.open(ROOT/(SLOT+'-channel-'+CHANNEL_ID+'.jsonl'),
                         os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_APPEND|os.O_NOFOLLOW, 0o600)
    try:
        directory_fd = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        stop = [False]
        def interrupted(*_): stop[0] = True
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        import pwd
        account = pwd.getpwnam('lima')
        require(account.pw_uid > 0 and account.pw_gid > 0, 'SYSTEM_CHANNEL_ACCOUNT')
        serve_inherited(namespace_fd=namespace_fd, journal_fd=journal_fd,
                        namespace_inode=NAMESPACE, uid=account.pw_uid, gid=account.pw_gid,
                        run_id=BINDING['runId'], channel_id=CHANNEL_ID,
                        deadline=CHANNEL_DEADLINE, stopped=lambda: stop[0])
    finally: os.close(journal_fd)
finally: os.close(namespace_fd)
'''.replace('BINDING_JSON', repr(json.dumps(binding, sort_keys=True))).replace('CHANNEL_LITERAL', repr(channel_id))


class PrivateBridge:
    """Local loopback -> fixed existing-mux -> guest-private-loopback.

    This is an unadmitted component until the owning JS driver links its branded
    capability. close() reports LOCAL absence only. Guest journal/birth absence
    and container/profile teardown must separately precede producer release.
    """
    def __init__(self, root, authority, binding, deadline, journal_fd):
        fixed_binding(binding)
        check_runtime_deadline(deadline, binding['target'])
        self.root, self.authority, self.binding = root, authority, binding
        self.source_sha = digest(Path(__file__).read_bytes())
        self.deadline, self.journal_fd = deadline, journal_fd
        self.stop_event, self.lock = threading.Event(), threading.Lock()
        self.children, self.clients, self.threads, self.channels, self.failures = set(), set(), [], [], []
        self.listener, self.accept_thread = None, None
        self.probe_debt = False

    def probe(self, argv, **options):
        return self._probe(argv, options, self.deadline, self.stop_event.is_set)

    def _probe(self, argv, options, deadline, stopped):
        # admit_existing_mux supplies only its two fixed SSH/lsof probes. Keep
        # their output private/in-memory; record ownership and retirement only.
        require(options == {'capture_output':True,'text':True,'timeout':5,'check':True},
                'SYSTEM_MUX_PROBE_OPTIONS')
        from darwin_process_inventory import LibProc
        probe_id = uuid.uuid4().hex
        def capture(pid):
            item = LibProc().identity(pid)
            require(item is not None and item.uid == os.getuid(), 'SYSTEM_MUX_PROBE_BIRTH')
            return [item.start_sec, item.start_usec]
        def record(row):
            with self.lock:
                journal(self.journal_fd, dict(row, probeId=probe_id, runId=self.binding['runId']))
        try:
            return bounded_command(argv, min(deadline,time.monotonic()+5),
                stopped, record=record, capture=capture, completed=True)
        except BaseException as error:
            self.failures.append('MUX_PROBE_FAILED')
            if getattr(error, 'cleanupDebt', None):
                self.failures.append('MUX_PROBE_RETIREMENT_UNPROVEN')
                self.probe_debt = True
            self.stop_event.set()
            raise

    def postflight(self):
        import owned_mcp_mux_relay as mux
        end=time.monotonic()+5
        mux.admit_existing_mux(self.root, expected=self.authority,
            run=lambda argv,**options:self._probe(argv,options,end,lambda:False))

    def start(self):
        # Delayed import: importing guest component on Linux has no Darwin API.
        import owned_mcp_mux_relay as mux
        mux.admit_existing_mux(self.root, expected=self.authority, run=self.probe)
        active(self.deadline, self.stop_event.is_set)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(('127.0.0.1', 0))
            self.listener.listen(4)
            self.listener.settimeout(.05)
            self.port = self.listener.getsockname()[1]
            self.accept_thread = threading.Thread(target=self.accept, daemon=True)
            self.accept_thread.start()
        except BaseException:
            self.listener.close()
            raise
        return self.port

    def accept(self):
        try:
            while not self.stop_event.is_set():
                active(self.deadline, self.stop_event.is_set)
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with self.lock:
                    if self.stop_event.is_set() or len(self.clients) >= 4 or len(self.channels) >= 64:
                        client.close()
                        raise RuntimeError('SYSTEM_BRIDGE_LIMIT')
                    self.clients.add(client)
                    channel_id = uuid.uuid4().hex
                    self.channels.append(channel_id)
                    try:
                        journal(self.journal_fd, {'version':1,'stage':'channel-intent',
                            'runId':self.binding['runId'],'channelId':channel_id})
                        worker = threading.Thread(target=self.work, args=(client,channel_id), daemon=True)
                        worker.start()
                        self.threads.append(worker)
                    except BaseException:
                        self.clients.discard(client)
                        client.close()
                        raise
        except BaseException as error:
            if not self.stop_event.is_set():
                self.failures.append(type(error).__name__)
            self.stop_event.set()

    def work(self, client, channel_id):
        child = None
        channel_deadline = min(self.deadline, time.monotonic()+MAX_SECONDS)
        import owned_mcp_mux_relay as mux
        import shlex
        try:
            mux.admit_existing_mux(self.root, expected=self.authority, run=self.probe)
            active(channel_deadline, self.stop_event.is_set)
            program = channel_program(self.binding, channel_id, self.source_sha)
            remote = shlex.join(['sudo','-n','/usr/bin/python3','-I','-S','-B','-c',program])
            argv = mux.mux_command(self.authority, remote)
            active(channel_deadline, self.stop_event.is_set)
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
            with self.lock:
                self.children.add(child)
            client.setblocking(False)
            os.set_blocking(child.stdin.fileno(), False)
            os.set_blocking(child.stdout.fileno(), False)
            incoming, outgoing = bytearray(), bytearray()
            input_open = output_open = True
            sent = received = 0
            while output_open or outgoing or incoming:
                active(channel_deadline, self.stop_event.is_set)
                reads = ([client] if input_open and len(incoming)<BUFFER_BYTES else []) + ([child.stdout] if output_open and len(outgoing)<BUFFER_BYTES else [])
                writes = ([child.stdin] if incoming else []) + ([client] if outgoing else [])
                ready, writable, _ = select.select(reads, writes, [], .05)
                active(channel_deadline, self.stop_event.is_set)
                for stream in ready:
                    data = os.read(stream.fileno(), min(16384,BUFFER_BYTES-len(incoming if stream is client else outgoing)))
                    if stream is client:
                        if not data: input_open = False
                        sent += len(data)
                        require(sent<=MAX_BYTES, 'SYSTEM_BRIDGE_BYTES')
                        incoming.extend(data)
                    else:
                        if not data: output_open = False
                        received += len(data)
                        require(received<=MAX_BYTES, 'SYSTEM_BRIDGE_BYTES')
                        outgoing.extend(data)
                for stream in writable:
                    buffer = incoming if stream is child.stdin else outgoing
                    count = os.write(stream.fileno(), buffer)
                    require(count>0, 'SYSTEM_BRIDGE_WRITE')
                    del buffer[:count]
                if not input_open and not incoming and not child.stdin.closed:
                    child.stdin.close()
            child.wait(timeout=max(.001, min(5,channel_deadline-time.monotonic())))
            require(child.returncode == 0, 'SYSTEM_BRIDGE_EXIT')
        except BaseException as error:
            self.failures.append(type(error).__name__)
            self.stop_event.set()
        finally:
            client.close()
            with self.lock:
                self.clients.discard(client)
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                    # Reaping is local only. Exact remote absence is still owed.
                    try: os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        with self.lock: self.children.discard(child)
                    else: self.failures.append('LOCAL_GROUP_REMAINS')
                except BaseException:
                    self.failures.append('LOCAL_CHILD_DEBT')
                for stream in (child.stdin, child.stdout):
                    try: stream.close()
                    except BaseException: self.failures.append('LOCAL_DESCRIPTOR_DEBT')

    def close(self):
        self.stop_event.set()
        end = time.monotonic()+5
        if self.listener is not None:
            self.listener.close()
        with self.lock:
            clients = list(self.clients)
        for client in clients:
            try: client.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            client.close()
        for worker in ([self.accept_thread] if self.accept_thread else []) + list(self.threads):
            worker.join(max(0,end-time.monotonic()))
        pending = [worker for worker in ([self.accept_thread] if self.accept_thread else [])+self.threads if worker.is_alive()]
        with self.lock:
            debt = bool(self.children or self.clients or pending or self.probe_debt
                        or 'LOCAL_DESCRIPTOR_DEBT' in self.failures)
        return {'version':1,'runId':self.binding['runId'],'channelIds':list(self.channels),
                'localRetired':not debt,'retirementUnproven':debt,
                'remoteRetired':False,'builderReleaseAllowed':False,'failures':list(self.failures)}


def bridge_controller(root, authority, binding, deadline, journal_fd):
    """Fixed controller for a future driver-owned process/group and pipe.

    stdin is solely a stop/owner-EOF channel; stdout carries bounded ready and
    terminal observations. It never transfers the executor bearer secret. Local
    journal intent/terminal are durable; caller must still reap THIS controller.
    """
    check_runtime_deadline(deadline)
    journal(journal_fd, {'version':1,'stage':'bridge-starting','runId':binding['runId']})
    bridge = PrivateBridge(root, authority, binding, deadline, journal_fd)
    failure = None
    import signal
    interrupted_flag = [False]
    def interrupted(*_):
        interrupted_flag[0] = True
        bridge.stop_event.set()
    old = {}
    try:
        for sig in (signal.SIGTERM,signal.SIGINT): old[sig] = signal.signal(sig, interrupted)
        port = bridge.start()
        journal(journal_fd, {'version':1,'stage':'bridge-ready','runId':binding['runId'],'port':port})
        raw = (json.dumps({'version':1,'stage':'ready','port':port},separators=(',',':'))+'\n').encode()
        write_pipe(1,raw,deadline)
        while not bridge.stop_event.is_set():
            active(deadline, bridge.stop_event.is_set)
            ready,_,_ = select.select([0],[],[],min(.05,max(0,deadline-time.monotonic())))
            if ready:
                require(os.read(0,2) in (b'',b'S'), 'SYSTEM_BRIDGE_CONTROL')
                break
    except BaseException as error:
        failure = error
    finally:
        receipt = bridge.close()
        if binding['target'] in ('original-v24-policy', 'original-v03-diagnostic'): receipt['target'] = binding['target']
        try:
            bridge.postflight()
        except BaseException as error:
            failure = failure or error
            receipt['failures'] = list(bridge.failures)+['MUX_POSTFLIGHT_FAILED']
            if bridge.probe_debt:
                receipt['retirementUnproven'] = True
                receipt['localRetired'] = False
        for sig, handler in old.items():
            try: signal.signal(sig,handler)
            except BaseException as error:
                failure = failure or error
                receipt['retirementUnproven'] = True
                receipt['localRetired'] = False
        if interrupted_flag[0]:
            failure = failure or RuntimeError('SYSTEM_BRIDGE_INTERRUPTED')
        try:
            journal(journal_fd, {'stage':'bridge-terminal', **receipt})
        except BaseException as error:
            failure = failure or error
            receipt['retirementUnproven'] = True
            receipt['localRetired'] = False
    raw=(json.dumps({'stage':'terminal', **receipt},separators=(',',':'))+'\n').encode()
    require(len(raw)<=16384,'SYSTEM_BRIDGE_TERMINAL_WRITE')
    write_pipe(1,raw,time.monotonic()+1)
    if failure: raise failure
    require(receipt['localRetired'] and not receipt['failures'],'SYSTEM_BRIDGE_FAILED')
    return receipt


def write_pipe(fd, raw, deadline):
    before = os.get_blocking(fd)
    try:
        os.set_blocking(fd,False)
        view=memoryview(raw)
        while view:
            active(deadline,lambda:False)
            _,ready,_=select.select([],[fd],[],min(.05,max(0,deadline-time.monotonic())))
            if not ready:continue
            try:count=os.write(fd,view)
            except BlockingIOError:continue
            require(count>0,'SYSTEM_PIPE_WRITE')
            view=view[count:]
    finally:
        os.set_blocking(fd,before)


def require(value, code):
    if not value:
        raise RuntimeError(code)


def active(deadline, stopped):
    require(not stopped(), 'SYSTEM_CHANNEL_CANCELLED')
    require(time.monotonic() < deadline, 'SYSTEM_CHANNEL_DEADLINE')


def check_deadline(deadline):
    require(type(deadline) in (int, float) and math.isfinite(deadline)
            and 0 < deadline - time.monotonic() <= MAX_SECONDS,
            'SYSTEM_CHANNEL_DEADLINE')


def check_runtime_deadline(deadline, target='original-v24-system'):
    require(target in ('original-v24-system','original-v24-policy','original-v03-diagnostic'), 'SYSTEM_RUNTIME_TARGET')
    require(type(deadline) in (int, float) and math.isfinite(deadline)
            and 0 < deadline-time.monotonic() <= (DIAGNOSTIC_INFRASTRUCTURE_SECONDS if target == 'original-v03-diagnostic' else COHORT_SECONDS), 'SYSTEM_RUNTIME_DEADLINE')


def pump(input_fd, output_fd, upstream, *, deadline, stopped):
    """Bounded duplex transfer on already-owned descriptors, no retry/connect.

    Returns byte counts only; the caller still owns/joins the process and proves
    guest absence.  Local EOF is half-closed, allowing the complete response.
    All descriptor flags are restored; a blocked peer cannot outlive deadline.
    """
    check_deadline(deadline)
    active(deadline, stopped)
    descriptors = (input_fd, output_fd, upstream.fileno())
    require(len(set(descriptors)) == 3, 'SYSTEM_CHANNEL_FD_ALIAS')
    prior = {fd: os.get_blocking(fd) for fd in descriptors}
    to_remote, to_local = bytearray(), bytearray()
    sent = received = 0
    input_open = remote_open = True
    half_closed = False
    try:
        for fd in descriptors:
            os.set_blocking(fd, False)
        while remote_open or to_local or to_remote:
            active(deadline, stopped)
            if not input_open and not to_remote and not half_closed:
                upstream.shutdown(socket.SHUT_WR)
                half_closed = True
            reads = []
            if input_open and len(to_remote) < BUFFER_BYTES:
                reads.append(input_fd)
            if remote_open and len(to_local) < BUFFER_BYTES:
                reads.append(upstream.fileno())
            writes = ([upstream.fileno()] if to_remote else []) + ([output_fd] if to_local else [])
            ready, writable, _ = select.select(reads, writes, [], min(.05, max(0, deadline-time.monotonic())))
            active(deadline, stopped)
            for fd in ready:
                target = to_remote if fd == input_fd else to_local
                try:
                    data = os.read(fd, min(16384, BUFFER_BYTES-len(target)))
                except BlockingIOError:
                    continue
                if not data:
                    if fd == input_fd:
                        input_open = False
                    else:
                        remote_open = False
                        require(not to_remote, 'SYSTEM_CHANNEL_EARLY_REMOTE_EOF')
                        input_open = False
                    continue
                if fd == input_fd:
                    sent += len(data)
                else:
                    received += len(data)
                require(sent <= MAX_BYTES and received <= MAX_BYTES, 'SYSTEM_CHANNEL_BYTES')
                target.extend(data)
            for fd in writable:
                active(deadline, stopped)
                target = to_remote if fd == upstream.fileno() else to_local
                try:
                    size = os.write(fd, target)
                except BlockingIOError:
                    continue
                require(size > 0, 'SYSTEM_CHANNEL_WRITE')
                del target[:size]
        active(deadline, stopped)
        return {'sentBytes': sent, 'receivedBytes': received}
    finally:
        # Descriptor restoration failure is a real failure, never a clean exit.
        faults = []
        for fd, blocking in prior.items():
            try:
                os.set_blocking(fd, blocking)
            except OSError as error:
                faults.append(error)
        if faults:
            raise RuntimeError('SYSTEM_CHANNEL_DESCRIPTOR_DEBT') from faults[0]


def enter_namespace(namespace_fd, expected_inode, uid, gid):
    """Guest-only FD-based entry; pathname/JSON cannot substitute for an FD.

    The still-owning driver must additionally attest holder/daemon birth before
    opening this FD. This component prevents entry into either shared namespace.
    """
    require(os.geteuid() == 0 and type(uid) is int and uid > 0
            and type(gid) is int and gid > 0 and type(expected_inode) is int
            and expected_inode > 0, 'SYSTEM_CHANNEL_IDENTITY')
    info = os.fstat(namespace_fd)
    require(info.st_ino == expected_inode
            and os.readlink('/proc/self/fd/' + str(namespace_fd)) == 'net:[' + str(expected_inode) + ']'
            and expected_inode not in (os.stat('/proc/self/ns/net').st_ino,
                                       os.stat('/proc/1/ns/net').st_ino), 'SYSTEM_CHANNEL_NAMESPACE')
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.setns(namespace_fd, 0x40000000) == 0, 'SYSTEM_CHANNEL_SETNS')
    require(os.stat('/proc/self/ns/net').st_ino == expected_inode, 'SYSTEM_CHANNEL_NAMESPACE')
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    require(os.geteuid() == uid and os.getegid() == gid and not os.getgroups(), 'SYSTEM_CHANNEL_DROP')
    require(libc.prctl(38, 1, 0, 0, 0) == 0, 'SYSTEM_CHANNEL_NO_NEW_PRIVS')


def journal(fd, row):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_APPEND
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 32768,
            'SYSTEM_CHANNEL_JOURNAL')
    data = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(data) <= 16384 and info.st_size + len(data) <= 32768, 'SYSTEM_CHANNEL_JOURNAL_LIMIT')
    while data:
        count = os.write(fd, data)
        require(count > 0, 'SYSTEM_CHANNEL_JOURNAL_WRITE')
        data = data[count:]
    os.fsync(fd)


def serve_inherited(*, namespace_fd, journal_fd, namespace_inode, uid, gid,
                    run_id, channel_id, deadline, stopped):
    """Executable guest component, callable only by the future owning launcher.

    Its journal is evidence, not admission authority. A terminal row is not a
    reaping proof; the driver must separately inspect exact PID/birth absence.
    """
    import re
    require(re.fullmatch('[a-f0-9]{32}', run_id) and re.fullmatch('[a-f0-9]{32}', channel_id),
            'SYSTEM_CHANNEL_OWNER')
    check_deadline(deadline)
    active(deadline, stopped)
    pid = os.getpid()
    with open('/proc/self/stat', encoding='ascii') as source:
        fields = source.read().rsplit(')', 1)[1].split()
    identity = {'version': 1, 'runId': run_id, 'channelId': channel_id,
                'pid': pid, 'startTicks': fields[19], 'namespaceInode': namespace_inode}
    journal(journal_fd, dict(identity, stage='started'))
    upstream = None
    outcome = 'failed'
    counts = {'sentBytes': 0, 'receivedBytes': 0}
    try:
        active(deadline, stopped)
        enter_namespace(namespace_fd, namespace_inode, uid, gid)
        active(deadline, stopped)
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setblocking(False)
        code = upstream.connect_ex(('127.0.0.1', PORT))
        require(code in (0, errno.EINPROGRESS, errno.EWOULDBLOCK), 'SYSTEM_CHANNEL_CONNECT')
        while code:
            active(deadline, stopped)
            _, writable, _ = select.select([], [upstream], [], min(.05, max(0, deadline-time.monotonic())))
            if writable:
                require(upstream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, 'SYSTEM_CHANNEL_CONNECT')
                break
        active(deadline, stopped)
        counts = pump(0, 1, upstream, deadline=deadline, stopped=stopped)
        outcome = 'complete'
        return counts
    finally:
        if upstream is not None:
            upstream.close()
        journal(journal_fd, dict(identity, stage='terminal', outcome=outcome, **counts))


if __name__ == '__main__':
    raise SystemExit('SYSTEM_PRIVATE_DRIVER_NOT_ADMITTED')
