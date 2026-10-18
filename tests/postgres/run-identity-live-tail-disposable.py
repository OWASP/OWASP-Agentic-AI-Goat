#!/usr/bin/env python3
"""Single-use owned PostgreSQL gate for the identity 0058-to-0066 tail."""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCOPE = 'identity-live-tail-native-v1'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
LEGACY_NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
CURRENT_MAIN_NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
DOCKER = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
PSQL = Path('/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/psql')
EXECUTABLE_HASHES = {
    LEGACY_NODE: '8bebc3d846767864093af8619b1a6dc2ff01dea4f643b8bdb5e8cbd51bf6756d',
    CURRENT_MAIN_NODE: '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861',
    DOCKER: '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e',
    PSQL: '9a8f53ac0523bca2a7c563003f0735122ebfd49ae2610547177b77f9d62f675e',
}
MAX_RESULT_BYTES = 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]
IDENTITY_MIGRATIONS = sorted(
    path.relative_to(ROOT).as_posix()
    for path in (ROOT / 'db/postgres/identity-migrations').glob('*.sql')
)
CONTROLLED_SOURCES = [
    'tests/identityLiveTailQualification.test.js',
    'tests/postgres/run-identity-live-tail-disposable.py',
] + IDENTITY_MIGRATIONS
SOURCE_IMPORTS = [
    'db/postgres/migrate.js',
    'server/database/postgres/index.js',
    'server/database/postgres/poolBudget.js',
    'package-lock.json',
]
parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--owner-handle-file', required=True)
parser.add_argument('--current-main', action='store_true',
                    help='Run the pinned current checkout without a source or dependency copy')
args = parser.parse_args()
NODE = CURRENT_MAIN_NODE if args.current_main else LEGACY_NODE
handle_path = Path(args.owner_handle_file)
deadline = time.monotonic() + 30
while not handle_path.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('Actual exec owner handle was not supplied')
    time.sleep(0.1)
owner_handle = int(handle_path.read_text().strip())

source = ROOT
grant_path = Path(args.grant_file).resolve()
evidence = Path(tempfile.mkdtemp(prefix='dvaia-identity-live-tail-'))
workspace = source if args.current_main else evidence / 'source'
if not args.current_main:
    workspace.mkdir(mode=0o700)
os.chmod(evidence, 0o700)
base_env = {key: os.environ[key] for key in ['HOME', 'TMPDIR'] if key in os.environ}
if args.current_main:
    for name in ('home', 'tmp'):
        (evidence / name).mkdir(mode=0o700)
    base_env.update(HOME=str(evidence / 'home'), TMPDIR=str(evidence / 'tmp'))
base_env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
base_env['NODE_PATH'] = str(workspace / 'node_modules')
docker = [str(DOCKER), '--host', args.docker_host]
nonce = uuid.uuid4().hex[:12]
container = f'dvaia-identity-tail-{nonce}'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.tap'
state = {
    'scope': SCOPE,
    'container': container,
    'dockerHost': args.docker_host,
    'evidence': str(evidence),
    'grantId': args.grant_id,
    'launcherPid': os.getpid(),
    'ownerHandle': owner_handle,
    'createdAt': datetime.now(timezone.utc).isoformat(),
    'sourceMode': 'current-main' if args.current_main else 'private-copy',
    'sourceCopy': not args.current_main,
    'sourceRoot': str(source),
    'started': False,
    'runStatus': 'starting',
    'cleanup': None,
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dependency_snapshot(node_modules, roots=('pg',)):
    pending = list(roots)
    packages = []
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        package = node_modules / name
        manifest_path = package / 'package.json'
        if not package.is_dir() or not manifest_path.is_file():
            raise RuntimeError(f'required installed dependency unavailable: {name}')
        manifest = json.loads(manifest_path.read_text())
        if manifest.get('name') != name:
            raise RuntimeError(f'installed dependency identity mismatch: {name}')
        packages.append(name)
        requested = set((manifest.get('dependencies') or {}).keys())
        requested.update(name for name in (manifest.get('optionalDependencies') or {})
                         if (node_modules / name).is_dir())
        pending.extend(sorted(requested))
    hashes = {}
    for name in sorted(packages):
        package = node_modules / name
        for path in sorted(package.rglob('*')):
            relative = path.relative_to(node_modules).as_posix()
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise RuntimeError(f'unsupported installed dependency leaf: {relative}')
            if path.is_file():
                hashes[relative] = sha256(path)
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return sorted(packages), hashes, hashlib.sha256(encoded).hexdigest()


for executable, label in [(NODE, 'Node'), (DOCKER, 'Docker'), (PSQL, 'psql')]:
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError(f'pinned absolute {label} executable unavailable')
    if sha256(executable) != EXECUTABLE_HASHES[executable]:
        raise RuntimeError(f'pinned absolute {label} executable hash mismatch')

def source_snapshot(root):
    migrations = sorted(path.relative_to(root).as_posix()
                        for path in (root / 'db/postgres/identity-migrations').glob('*.sql'))
    if migrations != IDENTITY_MIGRATIONS:
        raise RuntimeError('identity migration inventory changed')
    paths = CONTROLLED_SOURCES + SOURCE_IMPORTS
    if any((root / relative).is_symlink() or not (root / relative).is_file() for relative in paths):
        raise RuntimeError('identity source inventory unavailable')
    return {relative: sha256(root / relative) for relative in paths}


source_hashes = source_snapshot(source)
dependency_packages, dependency_hashes, dependency_digest = dependency_snapshot(source / 'node_modules')


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def write_state():
    atomic_json(ownership_path, state)


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def tap_summary(path, exit_code):
    raw = path.read_bytes()
    text = raw.decode('utf-8', errors='replace')
    counts = {}
    subtests = []
    current = None
    for line in text.splitlines():
        if line.startswith('# '):
            key, separator, value = line[2:].partition(' ')
            if separator and key in {'tests', 'pass', 'fail', 'skipped'} and value.isdigit():
                counts[key] = int(value)
        if (line.startswith('ok ') or line.startswith('not ok ')) and len(subtests) < 8:
            status = 'failed' if line.startswith('not ok ') else 'passed'
            name = ''.join(char for char in line.partition(' - ')[2][:160] if char.isprintable())
            current = {'status': status, 'name': name}
            subtests.append(current)
            continue
        if current is not None and current['status'] == 'failed':
            stripped = line.strip()
            if stripped.startswith('location:') and 'location' not in current:
                value = stripped.partition(':')[2].strip().strip("'\"")
                current['location'] = ''.join(char for char in value[:200] if char.isprintable())
            elif stripped.startswith('error:') and 'error' not in current:
                value = stripped.partition(':')[2].strip().strip("'\"")
                upper = value.upper()
                if value not in {'|', '|-', '>', '>-'} and not any(
                        token in upper for token in ('SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'CREATE ', 'ALTER ')):
                    current['error'] = ''.join(char for char in value[:160] if char.isprintable())
    return {
        'scope': SCOPE,
        'status': 'passed' if exit_code == 0 else 'failed',
        'exitCode': exit_code,
        'resultBytes': len(raw),
        'resultSha256': hashlib.sha256(raw).hexdigest(),
        'counts': counts,
        'subtests': subtests,
    }


write_state()
child = None
child_pgid = None
started = False


def stop_child():
    global child, child_pgid
    if child_pgid is None:
        return True
    if child is not None:
        child.poll()
    try:
        os.killpg(child_pgid, 0)
    except ProcessLookupError:
        return True
    os.killpg(child_pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if child is not None:
            child.poll()
        try:
            os.killpg(child_pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    os.killpg(child_pgid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if child is not None:
            child.poll()
        try:
            os.killpg(child_pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def interrupted(signum, _frame):
    stop_child()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)


def admit_source(current_main, source, workspace, source_hashes, packages, dependency_hashes, dependency_digest):
    if current_main:
        if workspace != source or source_snapshot(source) != source_hashes:
            raise RuntimeError('current-main source changed before admission')
        observed_packages, observed_hashes, observed_digest = dependency_snapshot(source / 'node_modules')
        if (observed_packages != packages or observed_hashes != dependency_hashes
                or observed_digest != dependency_digest):
            raise RuntimeError('current-main dependency closure changed before admission')
        return sorted(source_hashes), source_hashes
    for relative in CONTROLLED_SOURCES + SOURCE_IMPORTS:
        destination = workspace / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(destination.parent, 0o700)
        shutil.copyfile(source / relative, destination)
        os.chmod(destination, 0o500 if relative.endswith('.py') else 0o400)
    for directory in [workspace] + [path for path in workspace.rglob('*') if path.is_dir()]:
        os.chmod(directory, 0o700)
    inventory = sorted(path.relative_to(workspace).as_posix()
                       for path in workspace.rglob('*') if path.is_file())
    if inventory != sorted(CONTROLLED_SOURCES + SOURCE_IMPORTS):
        raise RuntimeError('private source copy inventory mismatch')
    copied_hashes = {relative: sha256(workspace / relative) for relative in inventory}
    if copied_hashes != source_hashes:
        raise RuntimeError('private source copy hash mismatch')
    private_node_modules = workspace / 'node_modules'
    private_node_modules.mkdir(mode=0o700)
    for package_name in packages:
        source_package = source / 'node_modules' / package_name
        destination_package = private_node_modules / package_name
        destination_package.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copytree(source_package, destination_package)
    for path in private_node_modules.rglob('*'):
        os.chmod(path, 0o700 if path.is_dir() else 0o400)
    copied_packages, copied_dependency_hashes, copied_dependency_digest = dependency_snapshot(private_node_modules)
    if (copied_packages != packages or copied_dependency_hashes != dependency_hashes
            or copied_dependency_digest != dependency_digest):
        raise RuntimeError('private dependency closure mismatch')
    return inventory, copied_hashes


inventory, admitted_hashes = admit_source(args.current_main, source, workspace, source_hashes,
    dependency_packages, dependency_hashes, dependency_digest)
state['sourceHashes'] = admitted_hashes
state['sourceInventory'] = inventory
state['dependencyPackages'] = dependency_packages
state['dependencyFileCount'] = len(dependency_hashes)
state['dependencyDigest'] = dependency_digest
write_state()

# Admission is consumed only after the selected source and dependency closure
# has been rehashed. Every subsequent operation is inside owned cleanup.
with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id
            or grant.get('owner') != '/root'
            or grant.get('scope') != SCOPE
            or grant.get('status') != 'granted'
            or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != args.docker_host
            or grant.get('postgresImageId') != POSTGRES_IMAGE_ID
            or grant.get('nodePath') != str(NODE)
            or (args.current_main and grant.get('sourceMode') != 'current-main')
            or grant.get('dockerPath') != str(DOCKER)
            or grant.get('psqlPath') != str(PSQL)
            or grant.get('expectedSourceHashes') != source_hashes
            or grant.get('expectedDependencyDigest') != dependency_digest
            or grant.get('expectedDependencyFileCount') != len(dependency_hashes)
            or grant.get('expectedDependencyPackages') != dependency_packages):
        raise RuntimeError('single-use identity-tail native grant is absent, mismatched, or consumed')
    grant.update({
        'status': 'consumed',
        'consumedAt': datetime.now(timezone.utc).isoformat(),
        'ownerHandle': owner_handle,
        'launcherPid': os.getpid(),
        'container': container,
        'evidence': str(evidence),
        'runStatus': 'starting',
        'sourceMode': state['sourceMode'],
        'sourceCopy': state['sourceCopy'],
    })
    grant_file.seek(0)
    json.dump(grant, grant_file, indent=2)
    grant_file.write('\n')
    grant_file.truncate()
    grant_file.flush()
    os.fsync(grant_file.fileno())

try:
    image_id = run(docker + ['image', 'inspect', POSTGRES_IMAGE_ID, '--format', '{{.Id}}'],
                   capture_output=True, text=True).stdout.strip()
    if image_id != POSTGRES_IMAGE_ID:
        raise RuntimeError('cached PostgreSQL image identity mismatch')
    state['imageId'] = image_id
    write_state()
    run(docker + [
        'run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=identity_tail_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', POSTGRES_IMAGE_ID,
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=32',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB',
    ], stdout=subprocess.DEVNULL)
    started = True
    state['started'] = True
    inspect = json.loads(run(docker + ['inspect', container], capture_output=True, text=True).stdout)[0]
    if inspect.get('Mounts'):
        raise RuntimeError('Owned PostgreSQL container unexpectedly has persistent mounts')
    state['mounts'] = inspect.get('Mounts', [])
    state['containerId'] = inspect['Id']
    if inspect['Image'] != POSTGRES_IMAGE_ID:
        raise RuntimeError('started PostgreSQL image identity mismatch')
    port = int(run(docker + ['port', container, '5432'], capture_output=True, text=True)
               .stdout.strip().rsplit(':', 1)[1])
    state['port'] = port
    write_state()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        probe = subprocess.run(
            [str(PSQL), '-h', '127.0.0.1', '-p', str(port), '-U', 'identity_tail_admin',
             '-d', 'postgres', '-Atqc', 'SELECT 1'],
            env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2,
        )
        if probe.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned PostgreSQL did not become TCP SQL-ready')

    admin = [str(PSQL), '-h', '127.0.0.1', '-p', str(port), '-U', 'identity_tail_admin',
             '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    roles = ['dvaia_identity_migration', 'dvaia_identity_runtime']
    for role in roles:
        run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    databases = {
        'qualification': (f'dvaia_test_identity_qualification_{nonce}', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
        'fresh': (f'dvaia_test_identity_fresh_{nonce}', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
    }
    urls = {}
    for key, (database, migration_role, runtime_role) in databases.items():
        run(admin + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
        run(admin + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                           f'GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],
            stdout=subprocess.DEVNULL)
        urls[(key, 'migration')] = f'postgresql://{migration_role}@127.0.0.1:{port}/{database}'
        urls[(key, 'runtime')] = f'postgresql://{runtime_role}@127.0.0.1:{port}/{database}'
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
               DVAIA_IDENTITY_LAUNCHER='1',
               DVAIA_IDENTITY_QUALIFICATION_MIGRATION_URL=urls[('qualification', 'migration')],
               DVAIA_IDENTITY_QUALIFICATION_RUNTIME_URL=urls[('qualification', 'runtime')],
               DVAIA_IDENTITY_FRESH_MIGRATION_URL=urls[('fresh', 'migration')],
               DVAIA_IDENTITY_FRESH_RUNTIME_URL=urls[('fresh', 'runtime')])
    state['nodeVersion'] = run([str(NODE), '--version'], capture_output=True, text=True).stdout.strip()
    if state['nodeVersion'] != ('v26.10.0' if args.current_main else 'v26.9.0'):
        raise RuntimeError('pinned managed Node version mismatch')
    state['runStatus'] = 'starting_test'
    state['childIntent'] = {
        'command': [str(NODE), '--test', '--test-reporter=tap',
                    'tests/identityLiveTailQualification.test.js'],
        'cwd': str(workspace),
    }
    write_state()
    with result_path.open('x') as log:
        os.chmod(result_path, 0o600)
        child = subprocess.Popen(
            [str(NODE), '--test', '--test-reporter=tap',
             'tests/identityLiveTailQualification.test.js'],
            cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        child_pgid = child.pid
        state['testPid'] = child.pid
        state['testPgid'] = child_pgid
        state['runStatus'] = 'running'
        write_state()
        child_deadline = time.monotonic() + 270
        while child.poll() is None:
            if result_path.stat().st_size > MAX_RESULT_BYTES:
                raise RuntimeError('identity qualification TAP exceeded the byte ceiling')
            if time.monotonic() >= child_deadline:
                raise subprocess.TimeoutExpired(state['childIntent']['command'], 270)
            time.sleep(0.05)
        code = child.returncode
    if result_path.stat().st_size > MAX_RESULT_BYTES:
        raise RuntimeError('identity qualification TAP exceeded the byte ceiling')
    if args.current_main:
        if source_snapshot(source) != source_hashes:
            raise RuntimeError('current-main source changed during qualification')
        after_packages, after_hashes, after_digest = dependency_snapshot(source / 'node_modules')
        if (after_packages != dependency_packages or after_hashes != dependency_hashes
                or after_digest != dependency_digest):
            raise RuntimeError('current-main dependency closure changed during qualification')
        state['sourcePostflight'] = True
        state['dependencyPostflight'] = True
    print(json.dumps(tap_summary(result_path, code), sort_keys=True), flush=True)
    if code:
        raise RuntimeError(f'identity-tail qualification failed ({code})')
    state['runStatus'] = 'passed'
except BaseException as error:
    state['runStatus'] = 'failed'
    state['error'] = f'{type(error).__name__}: {error}'
    raise
finally:
    state['testProcessGroupAbsent'] = stop_child()
    if not state['testProcessGroupAbsent']:
        state['runStatus'] = 'cleanup_failed'
    if started:
        try:
            details = json.loads(run(docker + ['inspect', container], capture_output=True, text=True).stdout)[0]
            atomic_json(evidence / 'container-state.json', {
                'Name': details.get('Name'), 'State': details.get('State'), 'Mounts': details.get('Mounts'),
            })
            logs = subprocess.run(docker + ['logs', container], env=base_env,
                                  capture_output=True, text=True, timeout=30)
            (evidence / 'container.log').write_text(logs.stdout + logs.stderr)
            os.chmod(evidence / 'container.log', 0o600)
        except BaseException as inspect_error:
            state['inspectError'] = f'{type(inspect_error).__name__}: {inspect_error}'
        cleanup = subprocess.run(docker + ['rm', '--force', container], env=base_env,
                                 capture_output=True, text=True, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^/{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        state['cleanup'] = {
            'returncode': cleanup.returncode,
            'stdout': cleanup.stdout.strip(),
            'stderr': cleanup.stderr.strip(),
            'absenceVerified': not bool(remaining),
        }
        if cleanup.returncode or remaining:
            state['runStatus'] = 'cleanup_failed'
    else:
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^/{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        state['cleanup'] = {'absenceVerified': not bool(remaining)}
        if remaining:
            state['runStatus'] = 'cleanup_failed'
    state['completedAt'] = datetime.now(timezone.utc).isoformat()
    write_state()
    with grant_path.open('r+') as grant_file:
        fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
        grant = json.load(grant_file)
        if grant.get('grantId') == args.grant_id and grant.get('launcherPid') == os.getpid():
            grant.update({
                'runStatus': state['runStatus'],
                'completedAt': state['completedAt'],
                'cleanup': state['cleanup'],
                'ownershipSha256': hashlib.sha256(ownership_path.read_bytes()).hexdigest(),
                'resultSha256': hashlib.sha256(result_path.read_bytes()).hexdigest()
                    if result_path.exists() else None,
                'sourceHashes': state['sourceHashes'],
            })
            grant_file.seek(0)
            json.dump(grant, grant_file, indent=2)
            grant_file.write('\n')
            grant_file.truncate()
            grant_file.flush()
            os.fsync(grant_file.fileno())
    print(f'Owned identity-tail cleanup complete; evidence retained: {evidence}', flush=True)
    if state['runStatus'] == 'cleanup_failed':
        raise RuntimeError('Owned PostgreSQL cleanup did not complete')
