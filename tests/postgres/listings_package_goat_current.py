"""Closed, repository-owned goat-q authority for a fresh Listings package.

This module does not launch a build on import or during admission.  The
historical Colima/home authority and Buildx pin remain separate.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

from secureshop_current_host_admission import evidence_parent


PROFILE = 'goat-q'
LIVE_ENABLED = False  # An owned BuildKit cache/builder retirement proof is still required.
INSTANCE = 'colima-goat-q'
SSH_HOST = 'lima-colima-goat-q'
GUEST_BUILDX = '/usr/libexec/docker/cli-plugins/docker-buildx'
GUEST_BUILDX_SHA256 = 'd900f1cc8370db2e23a23d4a73740e80ca71d9c76720968795669a17d6af2e46'
GUEST_DOCKER = '/usr/bin/docker'
GUEST_DOCKER_SHA256 = '9d8163c26d97f7a12c1fcd091204aa9528f82aab395a9a49ba6f533e8380218e'
GUEST_SOCKET = '/run/docker.sock'
GUEST_ENV = ('/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/nonexistent',
             'DOCKER_CONFIG=/nonexistent', 'DOCKER_HOST=unix:///run/docker.sock')
HOST_SSH_SHA256 = '470f812f6e71ee4ca1b49c79f9c2982c054493e22502d4648bd010feb4b2a9b2'
HEX = re.compile(r'[a-f0-9]{64}\Z')
DAEMON = re.compile(r'[a-f0-9-]{16,}\Z')


def private_lifetime_plan(run_id, source_sha256, runtime_digest):
    """Closed prospective consumer contract, not a daemon/image capability.

    Metadata planning reuses the original loop-mounted private daemon. Neither
    a successful archive nor an arbitrary socket string admits a consumer.
    """
    if (not re.fullmatch(r'[a-f0-9]{32}', run_id or '')
            or not HEX.fullmatch(source_sha256 or '')
            or not HEX.fullmatch(runtime_digest or '')):
        raise RuntimeError('Exact Listings private lifetime identity required')
    root = '/var/tmp/owasp-ai-goat-v23-build-' + run_id
    return {'version': 1, 'target': 'listings-package', 'runId': run_id,
        'sourceSha256': source_sha256, 'runtimeDigest': runtime_digest,
        'guestRoot': root, 'privateDockerHost': 'unix://' + root + '/fs/docker.sock',
        'storageCapBytes': 6 * 1024**3, 'archiveCapBytes': 1024**3,
        'sharedImageLoadAllowed': False, 'sharedNetworkAttachmentAllowed': False,
        'imageLifetime': 'private-daemon-until-consumer-retired',
        'retirementOrder': ['consumer', 'package-container', 'package-volume',
                            'package-profile', 'private-daemon', 'retained-export',
                            'private-storage', 'shared-inventory'],
        'requiredProofs': ['exact-source-image-labels', 'private-daemon-birth',
                           'consumer-private-endpoint', 'consumer-processes-absent',
                           'shared-postgres-unchanged'],
        'executionApproved': False, 'consumerIntegrationComplete': False}
GUEST_PROBE = r'''import hashlib,json,os,stat,subprocess,sys
def regular(p):
 s=os.lstat(p)
 assert stat.S_ISREG(s.st_mode) and s.st_size<=128*1024*1024
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  assert os.fstat(fd).st_ino==s.st_ino and os.fstat(fd).st_dev==s.st_dev
  h=hashlib.sha256()
  while True:
   block=os.read(fd,1024*1024)
   if not block: break
   h.update(block)
 finally: os.close(fd)
 return {'path':p,'realpath':os.path.realpath(p),'uid':s.st_uid,
  'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink,'regular':True,'sha256':h.hexdigest()}
socket=sys.argv[3];ss=os.lstat(socket)
value={'buildx':regular(sys.argv[1]),'docker':regular(sys.argv[2]),
 'socket':{'path':socket,'realpath':os.path.realpath(socket),'uid':ss.st_uid,
  'mode':stat.S_IMODE(ss.st_mode),'socket':stat.S_ISSOCK(ss.st_mode)},
 'daemonId':subprocess.run(['/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME=/nonexistent',
  'DOCKER_CONFIG=/nonexistent','DOCKER_HOST=unix:///run/docker.sock',sys.argv[2],
  'info','--format','{{.ID}}'],check=True,capture_output=True,text=True,timeout=10).stdout.strip()}
print(json.dumps(value,sort_keys=True))'''


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def owned_regular(path, uid, mode=None):
    path = Path(path)
    state = path.lstat()
    if (path.is_symlink() or path.resolve() != path or not stat.S_ISREG(state.st_mode)
            or state.st_uid != uid or state.st_nlink != 1
            or state.st_mode & 0o022 or (mode is not None and stat.S_IMODE(state.st_mode) != mode)):
        raise RuntimeError('Canonical owned Listings authority file required')
    return path


def ssh_configuration(source):
    source = Path(source)
    base = source / 'tasks' / 'l'
    instance = base / INSTANCE
    for directory in (base, instance):
        state = directory.lstat()
        if (directory.is_symlink() or directory.resolve() != directory or not stat.S_ISDIR(state.st_mode)
                or state.st_uid != os.getuid() or state.st_mode & 0o022):
            raise RuntimeError('Repository-managed VM identity required')
    config = owned_regular(instance / 'ssh.config', os.getuid(), 0o600)
    identity = owned_regular(base / '_config' / 'user', os.getuid(), 0o600)
    rows = [line.strip().split(None, 1) for line in config.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]
    if any(len(row) != 2 for row in rows):
        raise RuntimeError('VM SSH configuration malformed')
    values = {}
    allowed = {'Host', 'IdentityFile', 'StrictHostKeyChecking', 'UserKnownHostsFile',
        'NoHostAuthenticationForLocalhost', 'PreferredAuthentications', 'Compression',
        'BatchMode', 'IdentitiesOnly', 'GSSAPIAuthentication', 'Ciphers', 'User',
        'ControlMaster', 'ControlPath', 'ControlPersist', 'Hostname', 'Port'}
    for key, value in rows:
        if key not in allowed or key in values:
            raise RuntimeError('VM SSH configuration has unexpected authority')
        values[key] = value.strip('"')
    expected = {'Host': SSH_HOST, 'IdentityFile': str(identity), 'User': 'lima',
        'Hostname': '127.0.0.1', 'ControlPath': str(instance / 'ssh.sock'),
        'BatchMode': 'yes', 'IdentitiesOnly': 'yes', 'GSSAPIAuthentication': 'no'}
    if (set(values) != allowed or any(values.get(key) != value for key, value in expected.items())
            or not values.get('Port', '').isdigit() or not 1 <= int(values['Port']) <= 65535):
        raise RuntimeError('Exact repository VM SSH authority required')
    ssh = owned_regular('/usr/bin/ssh', 0)
    if sha256(ssh) != HOST_SSH_SHA256:
        raise RuntimeError('Pinned host SSH executable required')
    return {'config': str(config), 'configSha256': sha256(config),
        'identitySha256': sha256(identity), 'ssh': str(ssh), 'sshSha256': HOST_SSH_SHA256}


class CurrentHost:
    LIVE_ENABLED = LIVE_ENABLED
    def __init__(self, source, daemon_id, runner=subprocess.run):
        self.source = Path(source)
        if (not self.source.is_absolute() or self.source.is_symlink()
                or self.source.resolve() != self.source or not DAEMON.fullmatch(daemon_id or '')):
            raise RuntimeError('Exact current Listings workspace/daemon required')
        self.daemon_id = daemon_id
        self.ssh = ssh_configuration(self.source)
        self.runner = runner
        self.evidence_parent = evidence_parent(self.source)

    def argv(self, arguments):
        if not isinstance(arguments, (list, tuple)) or any(not isinstance(v, str) for v in arguments):
            raise RuntimeError('Fixed guest command required')
        return [self.ssh['ssh'], '-F', self.ssh['config'], SSH_HOST, shlex.join(arguments)]

    def guest_identity(self):
        result = self.runner(self.argv(['/usr/bin/python3', '-c', GUEST_PROBE,
                                        GUEST_BUILDX, GUEST_DOCKER, GUEST_SOCKET]),
            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=20, check=True)
        if len(result.stdout) > 4096:
            raise RuntimeError('Bounded guest identity required')
        row = json.loads(result.stdout)
        buildx = {'path': GUEST_BUILDX, 'realpath': GUEST_BUILDX, 'uid': 0,
            'mode': 0o755, 'nlink': 1, 'regular': True,
            'sha256': GUEST_BUILDX_SHA256}
        docker = {'path': GUEST_DOCKER, 'realpath': GUEST_DOCKER, 'uid': 0,
            'mode': 0o755, 'nlink': 1, 'regular': True,
            'sha256': GUEST_DOCKER_SHA256}
        socket = {'path': GUEST_SOCKET, 'realpath': GUEST_SOCKET, 'uid': 0,
            'mode': 0o660, 'socket': True}
        expected = {'buildx': buildx, 'docker': docker, 'socket': socket,
                    'daemonId': self.daemon_id}
        if type(row) is not dict or row != expected:
            raise RuntimeError('Pinned root-owned VM Buildx and Docker daemon required')
        if sha256(self.ssh['config']) != self.ssh['configSha256']:
            raise RuntimeError('VM SSH authority drift')
        identity = self.source / 'tasks/l/_config/user'
        if sha256(identity) != self.ssh['identitySha256']:
            raise RuntimeError('VM SSH identity drift')
        return {'path': GUEST_BUILDX, 'sha256': GUEST_BUILDX_SHA256,
            'dockerPath': GUEST_DOCKER, 'dockerSha256': GUEST_DOCKER_SHA256,
            'dockerSocket': GUEST_SOCKET,
            'sshConfigSha256': self.ssh['configSha256'],
            'sshIdentitySha256': self.ssh['identitySha256'], 'daemonId': self.daemon_id}

    def build_argv(self, parts, *, builder=None):
        if not isinstance(parts, list) or not parts or parts[0] != 'build':
            raise RuntimeError('Exact Listings build operation required')
        # The daemon's default builder has shared cache without an exact owned
        # retirement path. A separately proved nonce-owned builder is mandatory.
        if not re.fullmatch(r'owasp-ai-goat-listings-builder-[a-f0-9]{12}', builder or ''):
            raise RuntimeError('Exact nonce-owned BuildKit builder required')
        return self.argv([*GUEST_ENV, GUEST_BUILDX, 'build', '--builder', builder,
                          '--load', '--no-cache', *parts[1:]])

    def profile_plan(self, nonce):
        if not re.fullmatch(r'[a-f0-9]{12}', nonce or ''):
            raise RuntimeError('Fresh Listings profile nonce required')
        name = 'owasp-ai-goat-owned-listings-' + nonce
        template = self.source / 'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'
        if template.is_symlink() or template.resolve() != template or template.stat().st_size > 65536:
            raise RuntimeError('Canonical Listings profile template required')
        data = template.read_bytes().replace(b'@@SUPERVISOR_PROFILE@@', name.encode())
        return {'name': name, 'bytes': base64.b64encode(data).decode(),
            'sha256': hashlib.sha256(data).hexdigest(), 'platform': 'darwin',
            'sshConfig': self.ssh['config'], 'sshHost': SSH_HOST}
