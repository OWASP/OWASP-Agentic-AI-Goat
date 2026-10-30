#!/usr/bin/env python3
"""Closed four-store external-mail authority qualification; never sends SMTP."""
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
TEST = 'tests/postgres/secureshopExternalMailAuthority.integration.test.js'
TITLE = 'native external test mail preserves parent authority claims and lifecycle fences without SMTP'
DOCKER = ROOT / 'tasks/runtime/container/bin/docker'
NODE = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
SOCKET = ROOT / '.qualification/goat-q/docker.sock'
DAEMON = '945f6fce-3aaf-4d8f-a483-170464fb2416'
IMAGE = 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
SCOPE = 'secureshop-external-mail-authority-v1'
DOCKER_SHA256 = '8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
STORES = {'IDENTITY': 'identity', 'AGENTS': 'secureshop_agents',
    'REVIEW': 'secureshop_review', 'COMMERCE': 'secureshop'}
DATABASE_PREFIX = 'owasp_ai_goat_test_extmail_auth_'
SOURCE_FILES = (
    TEST, 'tests/postgres/secureshopManualRagNativeSetup.js',
    'tests/fixtures/secureshopNativeEvidencePath.js',
    'tests/postgres/run-secureshop-external-mail-authority.py',
    'tests/postgres/test_secureshop_external_mail_authority_launcher.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/darwin_process_inventory.py',
    'package.json', 'package-lock.json',
)


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, HERE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


docker_ownership = load('sql_nosql_docker_ownership.py', 'external_authority_docker')
process_ownership = load('sql_nosql_process_ownership.py', 'external_authority_process')
process_inventory = load('darwin_process_inventory.py', 'external_authority_inventory')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_snapshot():
    names = set(SOURCE_FILES)
    for directory, suffixes in (
            ('server', ('.js', '.mjs', '.json')),
            ('db/postgres', ('.js', '.sql', '.json')),
            ('sidecars/sandbox-runner', ('.js', '.mjs', '.json')),
            ('tests/fixtures', ('.js', '.mjs', '.json'))):
        base = ROOT / directory
        names.update(str(path.relative_to(ROOT)) for path in base.rglob('*')
            if path.is_file() and path.suffix in suffixes)
    result = {}
    for name in sorted(names):
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Exact repository source unavailable: ' + name)
        result[name] = digest(path)
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    return result, hashlib.sha256(encoded).hexdigest()


def dependency_snapshot():
    root = ROOT / 'node_modules'
    # Installed npm packages may be nested (express/router/path-to-regexp), so
    # index every existing package identity once and hash every installed copy
    # of an admitted name. This preserves Node's version-specific resolutions.
    packages = {}
    for manifest in root.rglob('package.json'):
        if manifest.is_symlink() or not manifest.is_file():
            raise RuntimeError('Installed dependency manifest alias rejected')
        value = json.loads(manifest.read_text())
        name = value.get('name')
        if isinstance(name, str) and name:
            packages.setdefault(name, []).append((manifest.parent, value))
    # The four-store setup conditionally requires original server modules. Include
    # every installed package named by this closed source inventory, then its
    # package-declared dependencies; never claim only the three entry imports.
    pending = ['pg', 'express', 'bcryptjs']
    bare = re.compile(r'''\brequire\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)''')
    source, _ = source_snapshot()
    for name in source:
        if not name.endswith(('.js', '.mjs')):
            continue
        for specifier in bare.findall((ROOT / name).read_text(errors='replace')):
            if specifier.startswith('node:'):
                continue
            package_name = '/'.join(specifier.split('/')[:2]) if specifier.startswith('@') \
                else specifier.split('/')[0]
            if package_name in packages:
                pending.append(package_name)
    seen, hashes = set(), {}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        candidates = packages.get(name)
        if not candidates:
            raise RuntimeError('Installed dependency unavailable: ' + name)
        for package, value in candidates:
            if package.is_symlink() or package.resolve() != package:
                raise RuntimeError('Installed dependency alias rejected: ' + name)
            pending.extend(sorted((value.get('dependencies') or {}).keys()))
            pending.extend(sorted(key for key in (value.get('optionalDependencies') or {})
                if key in packages))
            for leaf in sorted(package.rglob('*')):
                if '.bin' in leaf.relative_to(package).parts:
                    continue  # npm-generated command links are not module source.
                if leaf.is_symlink():
                    raise RuntimeError('Installed dependency symlink rejected: ' + str(leaf.relative_to(root)))
                if leaf.is_file():
                    hashes[str(leaf.relative_to(root))] = digest(leaf)
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


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


def snapshot_sha(source_sha, runtime):
    return hashlib.sha256(json.dumps({'sourceSha256': source_sha, 'runtime': runtime},
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def database_name(nonce, store):
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{12}', nonce) \
            or store not in STORES.values():
        raise RuntimeError('Closed disposable store identity required')
    name = DATABASE_PREFIX + nonce + '_' + store
    if len(name.encode('utf-8')) > 63:
        raise RuntimeError('PostgreSQL identifier exceeds 63 bytes')
    return name


def arguments(argv=None):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan', action='store_true')
    group.add_argument('--run', action='store_true')
    parser.add_argument('--expected-snapshot-sha256')
    args = parser.parse_args(argv)
    if args.plan and args.expected_snapshot_sha256 is not None:
        parser.error('--plan cannot carry an admission pin')
    if args.run and (not isinstance(args.expected_snapshot_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', args.expected_snapshot_sha256)):
        parser.error('--run requires exact reviewed snapshot SHA256')
    return args


def private_json(path, value):
    payload = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(payload) > 4 * 1024 * 1024:
        raise RuntimeError('Bounded authority receipt exceeded')
    temporary = path.with_name(path.name + '.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
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
        'PG_TEST_DISPOSABLE': 'yes', 'PG_EXTERNAL_MAIL_AUTHORITY_NATIVE': 'yes',
        'PG_EXTERNAL_MAIL_AUTHORITY_EVIDENCE_PATH': str(run / 'external-mail-authority-evidence.json'),
        'OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE': str(ROOT), 'DOCKER_HOST': 'unix://' + str(SOCKET),
        'AWS_EC2_METADATA_DISABLED': 'true', 'AI_PROVIDER': 'mock',
        'MCP_SIDECARS_AUTOSTART': 'false'}


def validate_tap(path, code):
    output = path.read_text(errors='replace')
    if code != 0 or re.search(r'^\s*not ok\b', output, re.M):
        raise RuntimeError('External-mail authority native assertion failed')
    for key, expected in {'tests': 1, 'pass': 1, 'fail': 0, 'skipped': 0, 'cancelled': 0}.items():
        if len(re.findall(r'^# ' + key + r' ' + str(expected) + r'$', output, re.M)) != 1:
            raise RuntimeError('Exact non-skipped external-mail authority TAP required')
    if not re.search(r'^# Subtest: ' + re.escape(TITLE) + r'$', output, re.M):
        raise RuntimeError('Original external-mail authority assertion missing')
    return digest(path)


def validate_evidence(path):
    if path.is_symlink() or not path.is_file() or path.resolve() != path \
            or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077 \
            or path.stat().st_size > 2 * 1024 * 1024:
        raise RuntimeError('Exact bounded authority evidence unavailable')
    script = "const fs=require('node:fs');const v=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));require('./" + TEST + "').assertEvidence(v);"
    checked = subprocess.run([str(NODE), '-e', script, str(path)], cwd=ROOT,
        env={'PATH': str(NODE.parent) + ':/usr/bin:/bin', 'HOME': str(path.parent / 'runtime/home'),
            'TMPDIR': str(path.parent / 'runtime/tmp'), 'NODE_ENV': 'test'},
        capture_output=True, timeout=15)
    if checked.returncode:
        raise RuntimeError('Original authority evidence replay failed')
    return digest(path)


def accepted(result):
    return result.get('passed') is True and result.get('cleanupErrors') == [] \
        and result.get('sourceUnchanged') is True and result.get('runtimeUnchanged') is True \
        and result.get('containerCleanup', {}).get('status') == 'removed_absence_verified' \
        and all(isinstance(result.get(key), str) and re.fullmatch('[a-f0-9]{64}', result[key])
            for key in ('tapSha256', 'evidenceSha256'))


def main(argv=None):
    args = arguments(argv)
    files_before, source_sha = source_snapshot()
    runtime_before = settings()
    snapshot_before = snapshot_sha(source_sha, runtime_before)
    if args.plan:
        print(json.dumps({'scope': SCOPE, 'plan': True, 'nativeStarted': False,
            'sourceCopies': False, 'actualSmtp': False, 'model': False, 'browser': False,
            'databaseCount': 4, 'roleCount': 8, 'sourceSha256': source_sha,
            'runtime': runtime_before, 'snapshotSha256': snapshot_before}, sort_keys=True))
        return 0
    if snapshot_before != args.expected_snapshot_sha256:
        raise RuntimeError('Reviewed external-mail authority source pin required before native allocation')
    parent = ROOT / 'tasks/qualification'
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent:
        raise RuntimeError('Exact repository evidence parent required')
    run = Path(tempfile.mkdtemp(prefix='run-external-mail-authority-', dir=parent))
    run.chmod(0o700)
    env = clean_environment(run)
    nonce = uuid.uuid4().hex[:12]
    name = 'owasp-ai-goat-external-mail-authority-' + nonce
    labels = {'owasp-ai-goat.qualification': SCOPE, 'owasp-ai-goat.owner-uid': str(os.getuid()), 'owasp-ai-goat.run-nonce': nonce}
    docker = [str(DOCKER), '--host', 'unix://' + str(SOCKET)]
    result = {'scope': SCOPE, 'passed': False, 'nativeStarted': False,
        'sourceCopies': False, 'actualSmtp': False, 'model': False, 'browser': False,
        'containerName': name, 'sourceBefore': files_before, 'sourceSha256': source_sha,
        'snapshotSha256': snapshot_before, 'runtimeBefore': runtime_before, 'cleanupErrors': []}
    child, captured, attempted, processes = None, None, False, None
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
            row = process_inventory.LibProc().identity(value['pid'])
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
            '-c', 'shared_buffers=16MB', '-c', 'max_connections=60', '-c', 'max_wal_size=16MB',
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
        for store, physical in STORES.items():
            for role in ('migration', 'runtime'):
                sql(f'CREATE ROLE dvaia_{physical}_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            database = database_name(nonce, physical)
            sql(f'CREATE DATABASE {database} OWNER dvaia_{physical}_migration')
            sql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_{physical}_migration,dvaia_{physical}_runtime')
            for role in ('migration', 'runtime'):
                env[f'PG_EXTERNAL_MAIL_{store}_{role.upper()}_URL'] = (
                    f'postgresql://dvaia_{physical}_{role}@127.0.0.1:{port}/{database}')
        tap = run / 'result.tap'
        with tap.open('x') as output:
            os.chmod(tap, 0o600)
            child = processes.launch([str(NODE), '--test', '--test-reporter=tap', TEST],
                name='external-mail-authority', cwd=ROOT, env=env, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=150)
            finally:
                processes.finish(child)
        result['tapSha256'] = validate_tap(tap, code)
        result['evidenceSha256'] = validate_evidence(run / 'external-mail-authority-evidence.json')
        result['passed'] = True
    except BaseException as error:
        result['failure'] = {'kind': type(error).__name__,
            'stage': 'owned-four-store-authority', 'code': getattr(error, 'code', None)}
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
