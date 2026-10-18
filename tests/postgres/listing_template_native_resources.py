"""Optional V58 resources: reuse the qualified no-copy package lifecycle only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

FLAGS = ('renderedSavedTemplateModelEffect', 'renderedSavedTemplateJudgeCredit',
         'renderedSavedTemplateRecoveryNoReplay', 'renderedSavedTemplateFixedDenied',
         'renderedSavedTemplateSiblingPrivate', 'renderedSavedTemplateResetFenced')
_PACKAGE = None


def package():
    global _PACKAGE
    if _PACKAGE is None:
        path = Path(__file__).with_name('run-listing-template-native-isolated.py')
        spec = importlib.util.spec_from_file_location('listing_template_package_qualification', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _PACKAGE = module
    return _PACKAGE


def source_files():
    return set(package().FILES) | {
        'tests/postgres/listing_template_native_resources.py',
        'tests/postgres/run-listing-template-native-isolated.py',
        'tests/postgres/listings_package_candidate.py',
        'tests/postgres/listings_native_resources.py',
        'tests/postgres/sql_nosql_docker_ownership.py'}


def capture(path, expected, source):
    path = Path(path)
    if (not path.is_absolute() or path.resolve() != path or path.is_relative_to(source)
            or not re.fullmatch(r'[a-f0-9]{64}', expected or '')):
        raise RuntimeError('Exact external template qualification required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > 1048576):
            raise RuntimeError('Private bounded template qualification required')
        raw = os.read(fd, 1048577)
        after = os.fstat(fd)
        named = path.lstat()
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink)
        if (identity(before) != identity(after) or identity(after) != identity(named)
                or len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected):
            raise RuntimeError('Template qualification changed')
    finally:
        os.close(fd)
    return {'path': str(path), 'sha256': expected, 'identity': identity(after), 'value': json.loads(raw)}


def admit(args, source):
    filename = getattr(args, 'listing_template_qualification', None)
    sha = getattr(args, 'listing_template_qualification_sha256', None)
    if filename is None and sha is None:
        return None
    if args.cohort != 'standalone-listings-browser' or not filename or not sha:
        raise RuntimeError('Paired template qualification is exclusive to Listings browser')
    admitted = capture(filename, sha, source)
    q = package()
    result = admitted['value']
    cleanup = {'containerAbsent': True, 'networkAbsent': True, 'imageAbsent': True, 'profileAbsent': True}
    if (not isinstance(result, dict) or result.get('version') != 1
            or result.get('passed') is not True or result.get('candidateOnly') is not True
            or result.get('installedActivation') is not False or result.get('sourceCopy') is not False
            or result.get('sourceUnchanged') is not True or result.get('cleanup') != cleanup
            or any(key in result for key in ('error', 'cleanupError', 'sourceError'))
            or result.get('checksObserved') != {'health': True, 'inert': True, 'commandWitness': True,
                                               'fixedWorkflowDenial': 'outside-package-scope'}
            or result.get('files') != q.manifest(source)
            or result.get('provenance') != q.provenance(source, args.node, args.docker)):
        raise RuntimeError('Current successfully qualified template package required')
    return admitted


def assert_admission(admitted, args, source):
    current = admit(args, source)
    if current != admitted:
        raise RuntimeError('Retained template qualification identity changed')


class TemplateResources:
    """Allocate state before attempts so caller's finally owns every lost ACK."""
    def __init__(self, args, source, evidence, admitted):
        self.args, self.source, self.admitted = args, source, admitted
        self.q = package()
        self.evidence = evidence / 'listing-template'
        self.evidence.mkdir(mode=0o700)
        nonce = uuid.uuid4().hex[:12]
        self.spec = self.q.plan(source, nonce)
        self.nonce = nonce
        self.state = {key: self.spec[key] for key in ('container', 'network', 'image')}
        self.state.update(labels={**self.spec['labels'], 'dvaia.qualification.owner': str(uuid.uuid4())}, attempted=[])
        self.env = self.q.build_environment(self.evidence, args.docker, args.node, admitted['value']['provenance']['buildx'])
        self.persist()

    def persist(self):
        self.q.atomic_json(self.evidence / 'resources.json', self.state)

    def attempt(self, kind):
        self.state['attempted'].append(kind)
        self.persist()

    def current(self, kind):
        return self.q.current_resource(self.args.docker, self.args.docker_host, kind, self.state, self.env)

    def daemon(self):
        self.q.daemon_ok(self.args.docker, self.args.docker_host, self.args.docker_daemon, self.env)

    def start(self):
        q, args, state = self.q, self.args, self.state
        assert_admission(self.admitted, args, self.source)
        self.daemon()
        for kind in ('container', 'network', 'image'):
            if q.inspect(args.docker, args.docker_host, kind, state[kind], self.env) is not None:
                raise RuntimeError('Template qualification resource name occupied')
        state['profile'] = q.profile_plan(self.source, args.node, args.docker_host, self.nonce)
        self.attempt('profile')
        q.profile_op(self.env, state['profile'], 'install')
        labels = sum((['--label', key + '=' + value] for key, value in state['labels'].items()), [])
        command = [args.docker, '--host', args.docker_host]
        self.attempt('image')
        q.run(command, ['build', '--pull=false', '--network=default', *labels, '-f', 'listing-template/Dockerfile',
                        '-t', state['image'], '-'], self.env, q.context_bytes(self.source, self.spec['files']), 300)
        if self.current('image') is None:
            raise RuntimeError('Template image build unconfirmed')
        self.persist()
        self.daemon()
        self.attempt('network')
        q.run(command, ['network', 'create', *labels, state['network']], self.env)
        if self.current('network') is None:
            raise RuntimeError('Template network creation unconfirmed')
        self.persist()
        state['port'] = q.available_port()
        self.daemon()
        self.attempt('container')
        q.run(command, ['run', '--detach', '--pull', 'never', '--name', state['container'], *labels,
            '--network', state['network'], '--read-only', '--user', '10001:10001', '--memory', '512m',
            '--cpus', '1', '--pids-limit', '128', '--cap-drop', 'ALL',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m',
            '--security-opt', 'seccomp=unconfined', '--security-opt', 'apparmor=' + state['profile']['name'],
            '--publish', f"127.0.0.1:{state['port']}:8090", state['imageId']], self.env)
        if self.current('container') is None:
            raise RuntimeError('Template container creation unconfirmed')
        self.persist()
        deadline = time.monotonic() + 20
        while True:
            try:
                self.health()
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Template health unavailable')
                time.sleep(.2)
        self.verify()
        return f"http://127.0.0.1:{state['port']}"

    def health(self):
        status, health = self.q.http(self.state['port'], '/health')
        if status != 200 or health != {'status': 'ok', 'listingTemplate': {
                'enabled': True, 'available': True, 'isolation': 'bwrap-listing-template-v1'}}:
            raise RuntimeError('Template health identity mismatch')

    def verify(self):
        assert_admission(self.admitted, self.args, self.source)
        self.daemon()
        for kind in ('image', 'container', 'network'):
            if self.current(kind) is None:
                raise RuntimeError('Template resource disappeared')
        self.q.attachment_check(self.args.docker, self.args.docker_host, self.state, self.env, allow_owned=True)
        self.health()
        self.persist()

    def cleanup(self):
        return self.q.cleanup_resources(self.args.docker, self.args.docker_host, self.args.docker_daemon,
                                       self.state, self.env, self.persist, self.q.profile_op)
