#!/usr/bin/env python3
"""Strict one-use launcher for the detached legacy AI history source snapshot.

The launcher accepts only an immutable reviewed package, a pinned managed Node
runtime, a pinned PostgreSQL image, and an exact root-owned one-use grant. It
creates one fresh disposable legacy database, runs the snapshot integration
test, and proves process, database, and container cleanup. It never reads the
canonical workspace's environment or application databases and never registers
this disposable profile in the canonical migration prefix.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


STAGE = 'legacy-ai-history-source-snapshot-r1'
SCOPE = 'legacy_ai_history_source_snapshot'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
NODE_VERSION = 'v26.8.2'
MIGRATION_ROLE = 'dvaia_legacy_challenge_migration'
RUNTIME_ROLE = 'dvaia_legacy_challenge_runtime'
CLEANUP_RECONCILE_ATTEMPTS = 10
CLEANUP_RECONCILE_DELAY_SECONDS = 0.5
TEST_PATH = 'tests/postgres/legacyAiHistorySourceSnapshot.integration.test.js'
LAUNCHER_PATH = 'tests/postgres/run-legacy-ai-history-source-snapshot-isolated.py'
CONTRACT_PATH = 'tests/postgres/test_legacy_ai_history_source_snapshot_launcher.py'
SOURCE_PATH = 'server/database/postgres/legacyAiHistorySourceSnapshot.js'
def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def save_json(path, value):
    path = Path(path)
    pending = Path(str(path) + f'.{os.getpid()}.pending')
    with pending.open('w') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.chmod(pending, 0o600)
    os.replace(pending, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_grant(grant, expected):
    if not isinstance(grant, dict) or grant.get('status') != 'granted' \
            or any(grant.get(key) != value for key, value in expected.items()):
        raise RuntimeError('exact one-use grant binding mismatch')
    return grant


def consume_grant(grant_path, expected, evidence_path):
    grant_path = Path(grant_path)
    lock = Path(str(grant_path) + '.consume-lock')
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise RuntimeError('grant already consumed') from error
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('status') != 'granted':
            raise RuntimeError('grant already consumed')
        grant = validate_grant(grant, expected)
        grant.update(status='consumed', runStatus='waiting_owner_handle', consumedAt=utc_now(),
                     consumerPid=os.getpid(), launcherPid=os.getpid(),
                     evidence=str(evidence_path), containerName=expected['containerName'])
        save_json(grant_path, grant)
    finally:
        lock.rmdir()
    return grant


def wait_for_owner_handle(grant_path, owner_handle, timeout=60, poll=.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        registered = json.loads(Path(grant_path).read_text()).get('ownerHandle')
        if registered is not None:
            if registered != owner_handle:
                raise RuntimeError('registered owner handle mismatch')
            return registered
        time.sleep(poll)
    raise RuntimeError('owner handle registration timeout')


def record_terminal_grant(grant_path, grant_id, owner_handle, run_status, evidence, cleanup,
                          process_id=None):
    path = Path(grant_path)
    grant = json.loads(path.read_text())
    if grant.get('grantId') != grant_id or grant.get('status') != 'consumed' \
            or grant.get('consumerPid') != (process_id or os.getpid()) \
            or grant.get('ownerHandle') != owner_handle:
        raise RuntimeError('consumed grant ownership changed before terminal update')
    grant.update(runStatus=run_status, terminalAt=utc_now(), evidence=str(evidence), cleanup=cleanup)
    save_json(path, grant)
    return grant


def run(command, **kwargs):
    return subprocess.run(command, check=False, text=True, **kwargs)


def resolve_without_symlinks(value, label, *, must_exist=True):
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError(f'absolute {label} path required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if os.path.lexists(cursor) and cursor.is_symlink():
            raise RuntimeError(f'{label} symlink ancestry forbidden')
    return path.resolve(strict=must_exist)


def _dependency_path(relative):
    return relative == 'source/node_modules' or relative.startswith('source/node_modules/') \
        or relative == 'source/client/node_modules' or relative.startswith('source/client/node_modules/')


def package_inventory(package):
    package = Path(package)
    source = package / 'source'
    source_files, dependency_files, dependency_links = {}, {}, {}
    source_directories, dependency_directories = [], []
    if source.is_symlink() or not source.is_dir() or source.stat().st_mode & 0o222:
        raise RuntimeError('copied read-only package source required')
    for path in source.rglob('*'):
        relative = path.relative_to(package).as_posix()
        dependency = _dependency_path(relative)
        if path.is_symlink():
            if not dependency:
                raise RuntimeError(f'source symlink forbidden: {relative}')
            target = os.readlink(path)
            if Path(target).is_absolute():
                raise RuntimeError(f'absolute dependency symlink forbidden: {relative}')
            resolved = path.resolve(strict=True)
            roots = [source / 'node_modules', source / 'client/node_modules']
            if not any(root.is_dir() and resolved.is_relative_to(root.resolve()) for root in roots):
                raise RuntimeError(f'external dependency symlink forbidden: {relative}')
            dependency_links[relative] = target
        elif path.is_file():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen file forbidden: {relative}')
            (dependency_files if dependency else source_files)[relative] = sha256(path)
        elif path.is_dir():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen directory forbidden: {relative}')
            (dependency_directories if dependency else source_directories).append(relative)
        else:
            raise RuntimeError(f'special package leaf forbidden: {relative}')
    return {
        'sourceFiles': source_files,
        'dependencyFiles': dependency_files,
        'dependencySymlinks': dependency_links,
        'sourceDirectories': sorted(source_directories),
        'dependencyDirectories': sorted(dependency_directories),
    }


def verify_manifest(package, manifest_path):
    package, manifest_path = Path(package), Path(manifest_path)
    if package.is_symlink() or not package.is_dir() or manifest_path != package / 'manifest.json' \
            or manifest_path.is_symlink() or not manifest_path.is_file() \
            or manifest_path.stat().st_mode & 0o222:
        raise RuntimeError('exact read-only package manifest required')
    if {entry.name for entry in package.iterdir()} != {'source', 'manifest.json'}:
        raise RuntimeError('package inventory must contain only source and manifest.json')
    manifest = json.loads(manifest_path.read_text())
    expected = {'stage': STAGE, 'scope': SCOPE, 'qualification': 'native-legacy-ai-history-source-snapshot',
        'suite': {'name': 'legacyAiHistorySourceSnapshot', 'test': TEST_PATH, 'timeoutSeconds': 180},
        'mutableSourcePaths': []}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError('source snapshot manifest boundary invalid')
    observed = package_inventory(package)
    for field, value in observed.items():
        if manifest.get(field) != value or manifest.get(field + 'Sha256') != json_digest(value):
            raise RuntimeError(f'manifest inventory mismatch: {field}')
    required = {f'source/{name}' for name in (TEST_PATH, LAUNCHER_PATH, CONTRACT_PATH,
        SOURCE_PATH, 'server/database/postgres/index.js',
        'server/database/postgres/poolBudget.js', 'db/postgres/migrate.js',
        'db/postgres/workshop-migrations/legacy_challenge/0001_schema.sql',
        'db/postgres/workshop-migrations/legacy_challenge/0002_import_provenance.sql',
        'db/postgres/workshop-migrations/legacy_challenge/0003_student_deletion.sql',
        'package.json', 'package-lock.json')}
    if set(observed['sourceFiles']) != required:
        raise RuntimeError('source snapshot source closure must be exact')
    if 'source/node_modules/pg/package.json' not in observed['dependencyFiles']:
        raise RuntimeError('frozen PostgreSQL dependency missing')
    return manifest

def verify_postflight_identity(package, manifest_path, expected_manifest, expected_manifest_sha,
                               node, expected_node_sha, docker_cli, expected_docker_cli_sha):
    observed_manifest = verify_manifest(package, manifest_path)
    if observed_manifest != expected_manifest or sha256(manifest_path) != expected_manifest_sha \
            or sha256(node) != expected_node_sha or sha256(docker_cli) != expected_docker_cli_sha:
        raise RuntimeError('postflight source/runtime identity changed')


def validate_container_id(value):
    if not re.fullmatch(r'[0-9a-f]{64}', value or ''):
        raise RuntimeError('invalid owned container id')
    return value


def process_group_absent(pgid):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def process_absent(pid):
    if not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def terminate_group(pgid, process=None, grace=10):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
    deadline = time.monotonic() + min(grace, 3)
    while time.monotonic() < deadline:
        if process_group_absent(pgid):
            return True
        time.sleep(.1)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGKILL)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
    return process_group_absent(pgid)


def docker_missing_exact_target(message, target):
    return re.search(rf'No such (?:object|container): {re.escape(target)}\r?$',
                     message or '', flags=re.MULTILINE) is not None


def docker_object_absent(docker, target):
    result = run(docker + ['inspect', target], capture_output=True, timeout=20)
    if result.returncode == 0:
        return False
    message = (result.stdout or '') + (result.stderr or '')
    if result.returncode == 1 and docker_missing_exact_target(message, target):
        return True
    raise RuntimeError('Docker object absence could not be verified')


def verify_docker_daemon(docker):
    result = run(docker + ['info', '--format', '{{json .}}'], capture_output=True, timeout=30)
    try:
        info = json.loads(result.stdout) if result.returncode == 0 else None
    except (TypeError, ValueError):
        info = None
    if not info or info.get('ID') != DOCKER_DAEMON_ID \
            or info.get('Name') != 'colima-dvaia-pg-verify' \
            or info.get('Architecture') != 'aarch64':
        raise RuntimeError('exact Colima verification daemon required')
    return info


def remove_owned_container(docker, container_name, container_id, labels, expected_image=None,
                           require_seen=False):
    target = container_id or container_name
    inspected = None
    for attempt in range(CLEANUP_RECONCILE_ATTEMPTS):
        inspected = run(docker + ['inspect', target], capture_output=True, timeout=20)
        if not inspected.returncode:
            break
        message = (inspected.stdout or '') + (inspected.stderr or '')
        if inspected.returncode == 1 and docker_missing_exact_target(message, target):
            if attempt + 1 < CLEANUP_RECONCILE_ATTEMPTS:
                time.sleep(CLEANUP_RECONCILE_DELAY_SECONDS)
                continue
            if require_seen:
                raise RuntimeError('owned container create outcome unresolved')
            return None
        raise RuntimeError('owned container inspection failed during cleanup')
    try:
        values = json.loads(inspected.stdout)
        info = values[0] if len(values) == 1 else None
    except (ValueError, TypeError):
        info = None
    actual_labels = ((info or {}).get('Config') or {}).get('Labels') or {}
    actual_id = (info or {}).get('Id')
    if not isinstance(actual_id, str) or not re.fullmatch(r'[0-9a-f]{64}', actual_id) \
            or (container_id is not None and actual_id != container_id) \
            or (info or {}).get('Name') != '/' + container_name \
            or (expected_image is not None and (info or {}).get('Image') != expected_image) \
            or any(actual_labels.get(key) != value for key, value in labels.items()):
        raise RuntimeError('unowned container cleanup refused')
    removed = run(docker + ['rm', '--force', actual_id], capture_output=True, timeout=60)
    if removed.returncode:
        raise RuntimeError('owned container removal failed')
    return actual_id


def database_name(nonce):
    if not re.fullmatch(r'[0-9a-f]{12}', nonce):
        raise ValueError('12-character lowercase hexadecimal nonce required')
    return f'dvaia_test_legacy_ai_snapshot_{nonce}'


def verify_tap(log_path):
    content = Path(log_path).read_text()
    passed = re.search(r'(?m)^# pass (\d+)\s*$', content)
    if not passed or int(passed.group(1)) < 1 \
            or not re.search(r'(?m)^# fail 0\s*$', content) \
            or not re.search(r'(?m)^# skipped 0\s*$', content):
        raise RuntimeError('source snapshot TAP did not prove passes, zero fail, zero skipped')
    return sha256(log_path)


def expected_grant(args, manifest, owner_handle, node_sha, manifest_sha):
    package = Path(args.package_root).resolve(); handle = Path(args.owner_handle_file).resolve()
    return {'grantId': args.grant_id, 'owner': '/root', 'allowedLaunches': 1,
        'dockerHost': DOCKER_HOST, 'containerNonce': args.container_nonce,
        'containerName': f'dvaia-legacy-ai-source-snapshot-{args.container_nonce}',
        'databaseName': f'dvaia_test_legacy_ai_snapshot_{args.container_nonce}',
        'canonicalWorkspaceRoot': str(Path(args.canonical_workspace).resolve()),
        'candidateSourceRoot': str(package / 'source'),
        'candidateManifestSha256': manifest_sha,
        'dockerCliPath': str(Path(args.docker_cli).resolve()),
        'dockerCliSha256': args.docker_cli_sha256,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'dependencySymlinksSha256': manifest['dependencySymlinksSha256'],
        'managedNodePath': str(Path(args.managed_node).resolve()), 'managedNodeSha256': node_sha,
        'postgresImageRef': POSTGRES_IMAGE, 'postgresImageId': POSTGRES_IMAGE_ID,
        'stage': STAGE, 'scope': SCOPE, 'evidenceRoot': str(Path(args.evidence_root).resolve()),
        'expectedOwnerHandle': owner_handle, 'ownerHandlePath': str(handle),
        'ownerHandleFileSha256': sha256(handle), 'expectedLauncherPid': os.getpid(), 'ownerHandle': None}


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('package-root', 'manifest', 'managed-node', 'docker-host',
                 'postgres-image-id', 'container-nonce', 'evidence-root', 'grant-file',
                 'grant-id', 'owner', 'owner-handle-file', 'canonical-workspace', 'scope',
                 'docker-cli', 'docker-cli-sha256'):
        parser.add_argument('--' + name, required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    package = resolve_without_symlinks(args.package_root, 'package')
    source = package / 'source'
    manifest_path = resolve_without_symlinks(args.manifest, 'manifest')
    node = resolve_without_symlinks(args.managed_node, 'managed Node')
    grant_path = resolve_without_symlinks(args.grant_file, 'grant')
    handle_path = resolve_without_symlinks(args.owner_handle_file, 'owner handle')
    evidence_path = resolve_without_symlinks(args.evidence_root, 'evidence', must_exist=False)
    canonical = resolve_without_symlinks(args.canonical_workspace, 'canonical workspace')
    docker_cli = resolve_without_symlinks(args.docker_cli, 'Docker CLI')
    if args.owner != '/root' or args.scope != SCOPE or args.docker_host != DOCKER_HOST \
            or args.postgres_image_id != POSTGRES_IMAGE_ID \
            or not re.fullmatch(r'[0-9a-f]{12}', args.container_nonce):
        raise RuntimeError('root launcher binding invalid')
    if not canonical.is_dir() or canonical.is_symlink() or evidence_path.is_relative_to(package) \
            or not docker_cli.is_file() or docker_cli.stat().st_mode & 0o111 == 0:
        raise RuntimeError('canonical/evidence path binding invalid')
    if sha256(docker_cli) != args.docker_cli_sha256:
        raise RuntimeError('Docker CLI identity mismatch')
    manifest = verify_manifest(package, manifest_path)
    if node.is_symlink() or not node.is_file():
        raise RuntimeError('managed Node regular file required')
    node_version = run([str(node), '--version'], capture_output=True, timeout=10)
    if node_version.returncode or node_version.stdout.strip() != NODE_VERSION:
        raise RuntimeError('managed Node version mismatch')
    node_sha, manifest_sha = sha256(node), sha256(manifest_path)
    if handle_path.is_symlink() or not handle_path.is_file() or handle_path.stat().st_mode & 0o077:
        raise RuntimeError('private owner handle file required')
    handle_text = handle_path.read_text().strip()
    if not handle_text.isdecimal() or int(handle_text) <= 0:
        raise RuntimeError('positive opaque owner handle required')
    owner_handle = int(handle_text)
    if os.path.lexists(evidence_path):
        raise RuntimeError('fresh evidence root required')
    parent = evidence_path.parent
    parent_stat = parent.lstat()
    if parent.is_symlink() or not parent.is_dir() or parent_stat.st_uid != os.getuid() \
            or parent_stat.st_mode & 0o077:
        raise RuntimeError('private evidence parent required')
    expected = expected_grant(args, manifest, owner_handle, node_sha, manifest_sha)
    if grant_path.is_symlink() or not grant_path.is_file() or grant_path.stat().st_mode & 0o077:
        raise RuntimeError('private grant file required')
    consume_grant(grant_path, expected, evidence_path)

    evidence_path.mkdir(mode=0o700)
    ownership_path = evidence_path / 'ownership.json'
    container_name = expected['containerName']
    database = expected['databaseName']
    labels = {
        'dvaia.owner': '/root',
        'dvaia.grant': args.grant_id,
        'dvaia.scope': SCOPE,
        'dvaia.nonce': args.container_nonce,
        'dvaia.manifest': manifest_sha,
        'dvaia.image': POSTGRES_IMAGE_ID,
    }
    state = {
        'version': 1,
        'stage': STAGE,
        'scope': SCOPE,
        'owner': '/root',
        'ownerHandle': owner_handle,
        'grantId': args.grant_id,
        'launcherPid': os.getpid(),
        'createdAt': utc_now(),
        'runStatus': 'owner_handle_pending',
        'manifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'managedNodePath': str(node),
        'managedNodeSha256': node_sha,
        'postgresImageRef': POSTGRES_IMAGE,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'dockerHost': DOCKER_HOST,
        'activation': 'detached-source-snapshot-only',
        'resourcePlan': {
            'containerName': container_name,
            'containerLabels': labels,
            'databaseName': database,
            'migrationRole': MIGRATION_ROLE,
            'runtimeRole': RUNTIME_ROLE,
            'applicationLogs': str(evidence_path / 'application-logs'),
            'applicationData': str(evidence_path / 'application-data'),
        },
        'processes': {},
        'suite': {'name': 'legacyAiHistorySourceSnapshot', 'test': TEST_PATH},
    }

    def persist():
        save_json(ownership_path, state)

    persist()
    docker = [str(docker_cli), '--host', DOCKER_HOST]
    container_id = None
    active_process = None
    active_pgid = None
    passed = False
    cleanup_errors = []

    def handle_signal(signum, _frame):
        raise InterruptedError(f'received signal {signum}')

    previous_handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous_handlers:
        signal.signal(signum, handle_signal)

    def psql(sql, selected_database='postgres', timeout=60):
        result = run(docker + ['exec', container_id, 'psql', '-U', 'dvaia_bootstrap',
            '-d', selected_database, '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True,
            timeout=timeout)
        if result.returncode:
            raise RuntimeError('owned PostgreSQL command failed: ' + (result.stderr or '')[-1000:])
        return result.stdout

    try:
        print('WAITING_OWNER_HANDLE', flush=True)
        wait_for_owner_handle(grant_path, owner_handle)
        state['runStatus'] = 'owner_registered'
        persist()

        daemon_info = verify_docker_daemon(docker)
        state['dockerDaemon'] = {'id': daemon_info['ID'], 'name': daemon_info['Name'],
            'architecture': daemon_info['Architecture']}
        persist()
        image = run(docker + ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE],
            capture_output=True, timeout=20)
        if image.returncode or image.stdout.strip() != POSTGRES_IMAGE_ID:
            raise RuntimeError('PostgreSQL image identity mismatch')
        if not docker_object_absent(docker, container_name):
            raise RuntimeError('owned container name already exists')
        state['containerCreateAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'name': container_name, 'expectedLabels': labels}
        persist()
        created = run(docker + ['run', '--detach', '--pull', 'never', '--name', container_name,
            *sum((['--label', f'{key}={value}'] for key, value in labels.items()), []),
            '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_USER=dvaia_bootstrap', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-p', '127.0.0.1::5432', args.postgres_image_id,
            '-c', 'shared_buffers=24MB', '-c', 'max_connections=32'],
            capture_output=True, timeout=60)
        state['containerCreateAttempt'].update(status='returned', returnCode=created.returncode,
            stdoutSha256=hashlib.sha256((created.stdout or '').encode()).hexdigest(),
            stderrSha256=hashlib.sha256((created.stderr or '').encode()).hexdigest())
        persist()
        if created.returncode:
            raise RuntimeError('owned PostgreSQL container creation failed')
        created_id = created.stdout.strip()
        container_id = validate_container_id(created_id)
        state.update(containerId=container_id, runStatus='container_started')
        persist()
        for _ in range(120):
            ready = run(docker + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'dvaia_bootstrap'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('owned PostgreSQL readiness timeout')
        binding = run(docker + ['port', container_id, '5432/tcp'], capture_output=True, timeout=20)
        if binding.returncode or not re.fullmatch(r'127\.0\.0\.1:\d+\s*', binding.stdout):
            raise RuntimeError('loopback PostgreSQL binding required')
        postgres_port = int(binding.stdout.strip().rsplit(':', 1)[1])
        state['postgresLoopbackPort'] = postgres_port
        state['databaseProvisioningAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'databaseName': database, 'roles': [MIGRATION_ROLE, RUNTIME_ROLE]}
        persist()
        psql(f'CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE DATABASE {database} OWNER {MIGRATION_ROLE}')
        psql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
             f'GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE},{RUNTIME_ROLE}')
        state['databaseProvisioningAttempt']['status'] = 'complete'
        persist()

        home = evidence_path / 'home'
        temporary = evidence_path / 'tmp'
        application_logs = evidence_path / 'application-logs'
        application_data = evidence_path / 'application-data'
        for directory in (home, temporary, application_logs, application_data):
            directory.mkdir(mode=0o700)
        base_env = {key: os.environ[key] for key in ('PATH',) if key in os.environ}
        base_env.update(HOME=str(home), TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
            NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
            DVAIA_ISOLATED_TEST_WORKSPACE=str(source), LOGS_DIR=str(application_logs),
            DVAIA_APP_DATA_ROOT=str(application_data),
            PG_LEGACY_AI_HISTORY_SOURCE_MIGRATION_URL=
                f'postgresql://{MIGRATION_ROLE}@127.0.0.1:{postgres_port}/{database}',
            PG_LEGACY_AI_HISTORY_SOURCE_RUNTIME_URL=
                f'postgresql://{RUNTIME_ROLE}@127.0.0.1:{postgres_port}/{database}')
        log_path = evidence_path / 'legacyAiHistorySourceSnapshot.tap'
        state['suite'].update(status='starting', database=database, log=str(log_path),
            startedAt=utc_now())
        persist()
        with log_path.open('w') as output:
            os.chmod(log_path, 0o600)
            active_process = subprocess.Popen([str(node), '--test', '--test-concurrency=1',
                '--test-reporter=tap', TEST_PATH], cwd=source, env=base_env,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            active_pgid = os.getpgid(active_process.pid)
            state['processes']['test'] = {'pid': active_process.pid, 'pgid': active_pgid,
                'status': 'running', 'startedAt': utc_now()}
            state['suite']['status'] = 'running'
            persist()
            try:
                exit_code = active_process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                terminate_group(active_pgid, active_process, grace=8)
                raise RuntimeError('source snapshot test timed out')
        group_absent = terminate_group(active_pgid, active_process, grace=3)
        state['processes']['test'].update(status='exited', exitCode=exit_code,
            groupAbsent=group_absent, completedAt=utc_now())
        active_process = None
        active_pgid = None
        if exit_code or not group_absent:
            persist()
            raise RuntimeError('source snapshot test failed or left its process group')
        log_sha = verify_tap(log_path)
        os.chmod(log_path, 0o400)
        state['suite'].update(status='passed', logSha256=log_sha, completedAt=utc_now())
        state['runStatus'] = 'suite_passed'
        persist()
        passed = True
    except BaseException as error:
        state.update(runStatus='suite_failed', failure=f'{type(error).__name__}: {error}'[:1000])
        persist()
        raise
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if active_pgid:
            try:
                absent = terminate_group(active_pgid, active_process, grace=8)
                state['processes'].setdefault('test', {}).update(groupAbsent=absent,
                    exitCode=active_process.poll() if active_process else None)
            except Exception as error:
                cleanup_errors.append(f'active process cleanup: {error}'[:500])
        if container_id or state.get('containerCreateAttempt'):
            try:
                state['databaseCleanupAttempt'] = {'status': 'started', 'startedAt': utc_now(),
                    'databaseName': database}
                persist()
                if container_id:
                    dropped = run(docker + ['exec', container_id, 'psql', '-U', 'dvaia_bootstrap',
                        '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c',
                        f'DROP DATABASE IF EXISTS {database} WITH (FORCE)'], capture_output=True,
                        timeout=60)
                    remaining = run(docker + ['exec', container_id, 'psql', '-U', 'dvaia_bootstrap',
                        '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                        f"SELECT datname FROM pg_database WHERE datname='{database}'"],
                        capture_output=True, timeout=30)
                    state['databaseCleanupAttempt'].update(status='complete',
                        dropReturnCode=dropped.returncode,
                        absenceQueryReturnCode=remaining.returncode,
                        databaseAbsent=remaining.returncode == 0 and not remaining.stdout.strip())
                    if dropped.returncode or remaining.returncode or remaining.stdout.strip():
                        raise RuntimeError('owned database cleanup was not proven')
            except Exception as error:
                cleanup_errors.append(f'database cleanup: {error}'[:500])
        try:
            verify_docker_daemon(docker)
            removed_id = remove_owned_container(docker, container_name, container_id, labels,
                                                expected_image=POSTGRES_IMAGE_ID,
                                                require_seen=container_id is None
                                                and state.get('containerCreateAttempt') is not None)
            state['containerCleanupId'] = removed_id
            if container_id is None and removed_id is not None:
                container_id = removed_id
        except Exception as error:
            cleanup_errors.append(f'container cleanup: {error}'[:500])
        try:
            state['containerNameAbsent'] = docker_object_absent(docker, container_name)
        except Exception as error:
            state['containerNameAbsent'] = False
            cleanup_errors.append(f'container name absence: {error}'[:500])
        if container_id:
            try:
                state['containerIdAbsent'] = docker_object_absent(docker, container_id)
            except Exception as error:
                state['containerIdAbsent'] = False
                cleanup_errors.append(f'container id absence: {error}'[:500])
        else:
            state['containerIdAbsent'] = None
        state['databaseAbsent'] = state.get('databaseCleanupAttempt', {}).get('databaseAbsent') is True \
            or state.get('containerNameAbsent') is True and state.get('containerIdAbsent') in (True, None)
        try:
            verify_postflight_identity(package, manifest_path, manifest, manifest_sha, node, node_sha,
                                       docker_cli, args.docker_cli_sha256)
            state['postflightManifestVerified'] = True
        except Exception as error:
            state['postflightManifestVerified'] = False
            cleanup_errors.append(f'postflight manifest: {error}'[:500])
        for process in state['processes'].values():
            if isinstance(process.get('pgid'), int):
                process['groupAbsent'] = process_group_absent(process['pgid'])
            if isinstance(process.get('pid'), int):
                process['pidAbsent'] = process_absent(process['pid'])
        state['allProcessGroupsAbsent'] = all(row.get('groupAbsent') is True
            for row in state['processes'].values())
        state['allProcessIdsAbsent'] = all(row.get('pidAbsent') is True
            for row in state['processes'].values())
        state['cleanupErrors'] = cleanup_errors
        state['applicationLogFiles'] = {
            path.relative_to(evidence_path / 'application-logs').as_posix(): sha256(path)
            for path in (evidence_path / 'application-logs').rglob('*')
            if path.is_file() and not path.is_symlink()
        } if (evidence_path / 'application-logs').is_dir() else {}
        state['completedAt'] = utc_now()
        clean = not cleanup_errors and state.get('containerNameAbsent') is True \
            and state.get('containerIdAbsent') in (True, None) \
            and state.get('databaseAbsent') is True \
            and state.get('allProcessGroupsAbsent') is True \
            and state.get('allProcessIdsAbsent') is True \
            and state.get('postflightManifestVerified') is True
        state['runStatus'] = 'terminal_pass_cleaned' if passed and clean \
            else 'terminal_fail_cleaned' if clean else 'terminal_fail_cleanup_uncertain'
        persist()
        try:
            terminal_grant = record_terminal_grant(
                grant_path, args.grant_id, owner_handle,
                'terminal_pass' if state['runStatus'] == 'terminal_pass_cleaned' else 'terminal_fail',
                evidence_path, {'clean': clean, 'errors': cleanup_errors,
                    'containerNameAbsent': state.get('containerNameAbsent'),
                    'containerIdAbsent': state.get('containerIdAbsent'),
                    'databaseAbsent': state.get('databaseAbsent'),
                    'allProcessGroupsAbsent': state.get('allProcessGroupsAbsent'),
                    'allProcessIdsAbsent': state.get('allProcessIdsAbsent')})
            terminal_grant.update(containerId=container_id, resultSha256=state['suite'].get('logSha256'))
            save_json(grant_path, terminal_grant)
            state['terminalGrantRecorded'] = True
            persist()
        except Exception as error:
            state['terminalGrantRecorded'] = False
            state['cleanupErrors'].append(f'terminal grant update: {error}'[:500])
            state['runStatus'] = 'terminal_fail_cleanup_uncertain'
            persist()
            clean = False
        if not passed or not clean:
            raise RuntimeError('source snapshot qualification did not pass with verified cleanup')
    print(json.dumps({'status': state['runStatus'], 'evidence': str(evidence_path),
        'logSha256': state['suite'].get('logSha256')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'launcher failure: {error}', file=sys.stderr)
        raise SystemExit(1)
