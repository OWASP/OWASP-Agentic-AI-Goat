#!/usr/bin/env python3
"""Closed, identity-only external-mail repository qualification; no SMTP."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TEST = 'tests/postgres/secureshopExternalMailRepository.integration.test.js'
DOCKER = ROOT / 'tasks/runtime/container/bin/docker'
NODE = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
SOCKET = ROOT / '.qualification/goat-q/docker.sock'
DAEMON = '945f6fce-3aaf-4d8f-a483-170464fb2416'
IMAGE = 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
SCOPE = 'secureshop-external-mail-identity-repository-v1'
DOCKER_SHA256 = '8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
SOURCES = (
    'db/postgres/migrate.js',
    'server/database/postgres/index.js',
    'server/database/postgres/poolBudget.js',
    'server/database/postgres/secureshopExternalMailRepository.js',
    'server/services/secureshopExternalMail.js',
    'server/services/secureshopExternalMailContract.js',
    'tests/postgres/secureshopExternalMailRepository.integration.test.js',
    'tests/postgres/run-secureshop-external-mail-repository.py',
    'tests/postgres/test_secureshop_external_mail_launcher.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/darwin_process_inventory.py',
    'package.json', 'package-lock.json',
)


def load(relative, name):
    path = HERE / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


docker_ownership = load('sql_nosql_docker_ownership.py', 'external_mail_docker_ownership')
process_ownership = load('sql_nosql_process_ownership.py', 'external_mail_process_ownership')
process_inventory = load('darwin_process_inventory.py', 'external_mail_process_inventory')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_snapshot():
    files = [*SOURCES, *(str(path.relative_to(ROOT)) for path in
        sorted((ROOT / 'db/postgres/identity-migrations').glob('*.sql')))]
    if not files[-1].endswith('/0153_secureshop_external_test_mail.sql'):
        raise RuntimeError('Identity 0153 must be the canonical tail')
    result = {}
    for name in files:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Exact repository source unavailable: ' + name)
        result[name] = digest(path)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    return result, hashlib.sha256(encoded).hexdigest()


def settings():
    for path in (ROOT, DOCKER, NODE, SOCKET):
        if path.is_symlink() or path.resolve() != path:
            raise RuntimeError('Source/runtime path alias rejected')
    if not DOCKER.is_file() or not NODE.is_file() or not SOCKET.is_socket():
        raise RuntimeError('Existing repository runtime or daemon unavailable')
    docker_sha, node_sha = digest(DOCKER), digest(NODE)
    if docker_sha != DOCKER_SHA256 or node_sha != NODE_SHA256:
        raise RuntimeError('Reviewed repository runtime executable mismatch')
    return {'dockerSha256': docker_sha, 'nodeSha256': node_sha,
        'dependencySha256': dependency_snapshot()}


def dependency_snapshot():
    root = ROOT / 'node_modules'
    pending = ['pg', 'bcryptjs']
    seen = set()
    hashes = {}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        package = root / name
        manifest = package / 'package.json'
        if package.is_symlink() or not manifest.is_file() or manifest.is_symlink():
            raise RuntimeError('Installed dependency unavailable: ' + name)
        value = json.loads(manifest.read_text())
        if value.get('name') != name:
            raise RuntimeError('Installed dependency identity mismatch: ' + name)
        pending.extend(sorted((value.get('dependencies') or {}).keys()))
        pending.extend(sorted(key for key in (value.get('optionalDependencies') or {})
            if (root / key).is_dir()))
        for leaf in sorted(package.rglob('*')):
            if leaf.is_symlink():
                raise RuntimeError('Installed dependency symlink rejected')
            if leaf.is_file():
                hashes[str(leaf.relative_to(root))] = digest(leaf)
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def snapshot_sha(source_sha, runtime):
    encoded = json.dumps({'sourceSha256': source_sha, 'runtime': runtime},
        sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def arguments(argv=None):
    parser = argparse.ArgumentParser()
    gate = parser.add_mutually_exclusive_group(required=True)
    gate.add_argument('--plan', action='store_true')
    gate.add_argument('--run', action='store_true')
    parser.add_argument('--expected-snapshot-sha256')
    result = parser.parse_args(argv)
    if result.plan and result.expected_snapshot_sha256 is not None:
        parser.error('--plan cannot carry an admission pin')
    if result.run and (not isinstance(result.expected_snapshot_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', result.expected_snapshot_sha256)):
        parser.error('--run requires exact reviewed snapshot SHA256')
    return result


def private_json(path, value):
    encoded = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(encoded) > 1048576:
        raise RuntimeError('Bounded external-mail receipt exceeded')
    temporary = path.with_name(path.name + '.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def clean_environment(run):
    runtime = run / 'runtime'
    paths = {name: runtime / name for name in ('home', 'tmp', 'xdg', 'npm')}
    for path in (runtime, *paths.values()):
        path.mkdir(mode=0o700)
    return {'PATH': str(NODE.parent) + ':/usr/bin:/bin', 'HOME': str(paths['home']),
        'TMPDIR': str(paths['tmp']), 'TMP': str(paths['tmp']), 'TEMP': str(paths['tmp']),
        'XDG_CACHE_HOME': str(paths['xdg']), 'npm_config_cache': str(paths['npm']),
        'PYTHONDONTWRITEBYTECODE': '1', 'NODE_ENV': 'test',
        'PG_TEST_DISPOSABLE': 'yes', 'AWS_EC2_METADATA_DISABLED': 'true',
        'AI_PROVIDER': 'mock', 'MCP_SIDECARS_AUTOSTART': 'false'}


def validate_tap(path, code):
    output = path.read_text(errors='replace')
    if code != 0 or re.search(r'^\s*not ok\b', output, re.M):
        raise RuntimeError('External-mail native assertion failed')
    for key, expected in {'tests': 1, 'pass': 1, 'fail': 0, 'skipped': 0, 'cancelled': 0}.items():
        if len(re.findall(r'^# ' + key + r' ' + str(expected) + r'$', output, re.M)) != 1:
            raise RuntimeError('Exact non-skipped external-mail TAP required')
    if not re.search(r'^# Subtest: identity0153 fresh and populated migration preserve history, runtime grants and retained mail claims$', output, re.M):
        raise RuntimeError('Original external-mail assertion missing')
    return digest(path)


def accepted(result):
    return result.get('passed') is True and result.get('cleanupErrors') == [] \
        and result.get('sourceUnchanged') is True \
        and result.get('runtimeUnchanged') is True \
        and result.get('containerCleanup', {}).get('status') == 'removed_absence_verified' \
        and isinstance(result.get('tapSha256'), str) \
        and re.fullmatch('[a-f0-9]{64}', result['tapSha256']) is not None


def main(argv=None):
    args = arguments(argv)
    files_before, source_sha = source_snapshot()
    runtime_before = settings()
    snapshot_before = snapshot_sha(source_sha, runtime_before)
    if args.plan:
        print(json.dumps({'scope': SCOPE, 'plan': True, 'nativeStarted': False,
            'sourceCopies': False, 'actualSmtp': False, 'model': False, 'browser': False,
            'databaseCount': 2, 'roleCount': 2, 'sourceSha256': source_sha,
            'runtime': runtime_before, 'snapshotSha256': snapshot_before}, sort_keys=True))
        return 0
    if snapshot_before != args.expected_snapshot_sha256:
        raise RuntimeError('Reviewed external-mail source pin required before native allocation')
    parent = ROOT / 'tasks/qualification'
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent:
        raise RuntimeError('Exact repository evidence parent required')
    run = Path(tempfile.mkdtemp(prefix='run-external-mail-', dir=parent))
    run.chmod(0o700)
    env = clean_environment(run)
    nonce = uuid.uuid4().hex[:12]
    name = 'owasp-ai-goat-external-mail-' + nonce
    labels = {'owasp-ai-goat.qualification': SCOPE, 'owasp-ai-goat.owner-uid': str(os.getuid()), 'owasp-ai-goat.run-nonce': nonce}
    docker = [str(DOCKER), '--host', 'unix://' + str(SOCKET)]
    result = {'scope': SCOPE, 'passed': False, 'nativeStarted': False, 'sourceCopies': False,
        'actualSmtp': False, 'model': False, 'browser': False, 'containerName': name,
        'sourceBefore': files_before, 'sourceSha256': source_sha, 'snapshotSha256': snapshot_before,
        'runtimeBefore': runtime_before,
        'cleanupErrors': []}
    child = None
    captured = None
    attempted = False
    processes = None
    child_births = {}

    def command(parts, *, timeout=30):
        return subprocess.run(docker + parts, env=env, capture_output=True, text=True, timeout=timeout)

    def checked(parts, *, timeout=30):
        response = command(parts, timeout=timeout)
        if response.returncode:
            raise RuntimeError('Owned Docker command failed: ' + parts[0])
        return response.stdout.strip()

    def record_child(value):
        if value['status'] == 'registered':
            api = process_inventory.LibProc()
            row = api.identity(value['pid'])
            if row is not None:
                if row.uid != os.getuid() or row.ruid != os.getuid() \
                        or row.ppid != os.getpid() or row.pgid != value['pid'] \
                        or os.getsid(value['pid']) != value['pid']:
                    raise RuntimeError('Owned Node process birth mismatch')
                child_births[value['pid']] = (row.start_sec, row.start_usec)
        private_json(run / ('child-' + value['status'] + '.json'), value)

    def stop_owned_child(owned, pgid, session_id):
        if owned.pid != pgid or owned.pid != session_id or pgid <= 1:
            raise RuntimeError('Owned Node group identity mismatch')
        tracked = {pgid: child_births[pgid]} if pgid in child_births else {}
        def members():
            return process_inventory.owned_group_members(pgid, births=tracked)
        live = members()
        if live and pgid not in child_births:
            raise RuntimeError('Uncaptured Node birth cannot authorize a signal')
        for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
            if not live:
                break
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                owned.poll()
                live = members()
                if not live:
                    break
                time.sleep(0.05)
        if owned.poll() is None:
            try:
                owned.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if members() or owned.poll() is None:
            raise RuntimeError('Owned Node process group absence unproved')

    try:
        processes = process_ownership.OwnedProcesses(stop_owned_child, record_child)
        processes.install()
        private_json(run / 'intent.json', {'name': name, 'labels': labels, 'image': IMAGE,
            'daemon': DAEMON, 'scope': SCOPE})
        docker_ownership.verify_daemon(command, DAEMON)
        docker_ownership.verify_image(command, IMAGE)
        if docker_ownership.inspect_owned(command, name=name, labels=labels, image=IMAGE) is not None:
            raise RuntimeError('Exact owned container name already exists')
        attempted = True
        created = checked(['run', '--detach', '--pull', 'never', '--name', name,
            *(part for key, value in labels.items() for part in ('--label', key + '=' + value)),
            '--memory', '512m', '--cpus', '2', '--pids-limit', '256',
            '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
            '-e', 'POSTGRES_USER=external_mail_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', IMAGE,
            '-c', 'shared_buffers=16MB', '-c', 'max_connections=40', '-c', 'max_wal_size=16MB',
            '-c', 'min_wal_size=4MB'], timeout=45)
        if not docker_ownership.CONTAINER.fullmatch(created):
            raise RuntimeError('Exact created container ID missing')
        captured = created
        row = docker_ownership.inspect_owned(command, name=name, labels=labels,
            image=IMAGE, captured_id=captured)
        port = docker_ownership.validate_container_layout(row)
        result.update(nativeStarted=True, containerId=captured, port=port)
        private_json(run / 'container-created.json', {'containerId': captured,
            'name': name, 'port': port, 'labels': labels})
        ready_until = time.monotonic() + 30
        while command(['exec', captured, 'pg_isready', '-h', '127.0.0.1',
                       '-U', 'external_mail_admin'], timeout=4).returncode:
            if time.monotonic() >= ready_until:
                raise RuntimeError('Owned PostgreSQL readiness timeout')
            time.sleep(0.25)
        def sql(statement):
            checked(['exec', captured, 'psql', '-h', '127.0.0.1', '-U', 'external_mail_admin',
                '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', statement])
        for role in ('migration', 'runtime'):
            sql(f'CREATE ROLE dvaia_identity_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        for store in ('fresh', 'populated'):
            database = f'owasp_ai_goat_test_external_mail_{store}_{nonce}'
            sql(f'CREATE DATABASE {database} OWNER dvaia_identity_migration')
            sql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime')
            for role in ('migration', 'runtime'):
                env[f'PG_EXTERNAL_MAIL_{store.upper()}_{role.upper()}_URL'] = (
                    f'postgresql://dvaia_identity_{role}@127.0.0.1:{port}/{database}')
        tap = run / 'result.tap'
        with tap.open('x') as output:
            os.chmod(tap, 0o600)
            child = processes.launch([str(NODE), '--test', '--test-reporter=tap', TEST],
                name='identity-repository', cwd=ROOT, env=env, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=180)
            finally:
                processes.finish(child)
        result['tapSha256'] = validate_tap(tap, code)
        result['passed'] = True
    except BaseException as error:
        result['failure'] = {'kind': type(error).__name__,
            'stage': 'owned-identity-repository', 'code': getattr(error, 'code', None)}
    finally:
        if processes is not None:
            processes.mask_cleanup_signals()
            try:
                processes.cleanup()
            except BaseException as error:
                result['cleanupErrors'].append('owned-child:' + type(error).__name__)
            processes.restore()
        if attempted:
            try:
                result['containerCleanup'] = docker_ownership.cleanup_owned(command,
                    daemon_id=DAEMON, name=name, labels=labels, image=IMAGE, captured_id=captured)
                if captured is not None:
                    remaining = command(['ps', '-aq', '--no-trunc'])
                    if remaining.returncode or captured in remaining.stdout.splitlines():
                        raise RuntimeError('Captured container ID remains after name retirement')
            except BaseException as error:
                result['cleanupErrors'].append('owned-container:' + type(error).__name__)
        try:
            result['sourceUnchanged'] = source_snapshot() == (files_before, source_sha)
            result['runtimeUnchanged'] = settings() == runtime_before
        except BaseException as error:
            result['sourceUnchanged'] = False
            result['runtimeUnchanged'] = False
            result['cleanupErrors'].append('postflight:' + type(error).__name__)
        result['passed'] = accepted(result)
        private_json(run / 'result.json', result)
    print(str(run / 'result.json'))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
