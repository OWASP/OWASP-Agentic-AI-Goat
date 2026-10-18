#!/usr/bin/env python3
"""Single-use owned PostgreSQL gate for the two unregistered copy/default candidates."""
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

SCOPE = 'teaching-copy-assets-candidates-native-r2'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
PSQL = Path('/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/psql')
EXECUTABLE_HASHES = {
    NODE: '8bebc3d846767864093af8619b1a6dc2ff01dea4f643b8bdb5e8cbd51bf6756d',
    DOCKER: '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e',
    PSQL: '9a8f53ac0523bca2a7c563003f0735122ebfd49ae2610547177b77f9d62f675e',
}
MAX_RESULT_BYTES = 1024 * 1024
CONTROLLED_SOURCES = [
    'db/postgres/identity-migrations/0066_dpi_teaching_copy_alignment.sql',
    'db/postgres/workshop-migrations/secureshop/0003_local_product_assets.sql',
    'tests/postgres/dpiTeachingCopyAlignment.integration.test.js',
    'tests/postgres/secureshopLocalProductAssets.integration.test.js',
    'tests/postgres/ctfHistoricalWrapperMigration.integration.test.js',
    'tests/postgres/run-teaching-copy-assets-candidates-isolated.py',
]
SOURCE_IMPORTS = [
    'db/postgres/identity-migrations/0001_identity.sql',
    'db/postgres/identity-migrations/0002_workshop_platform.sql',
    'db/postgres/identity-migrations/0036_dpi_teaching_scope.sql',
    'db/postgres/identity-migrations/0043_dpi_evidence_guidance.sql',
    'db/postgres/workshop-migrations/secureshop/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop/0002_import_history.sql',
    'db/postgres/workshop-migrations/ctf/0001_schema.sql',
    'db/postgres/workshop-migrations/ctf/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0003_stage_default_provenance.sql',
    'db/postgres/workshop-migrations/ctf/0004_system_prompt_default_provenance.sql',
    'server/data/promptInjectionSolutions.js',
    'server/config/workshopCatalog.js',
    'server/config/secureshopCurriculum.js',
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
args = parser.parse_args()
handle_path = Path(args.owner_handle_file)
deadline = time.monotonic() + 30
while not handle_path.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError('Actual exec owner handle was not supplied')
    time.sleep(0.1)
owner_handle = int(handle_path.read_text().strip())

source = Path(__file__).resolve().parents[2]
grant_path = Path(args.grant_file).resolve()
evidence = Path(tempfile.mkdtemp(prefix='dvaia-copy-assets-candidates-'))
workspace = evidence / 'source'
workspace.mkdir(mode=0o700)
os.chmod(evidence, 0o700)
base_env = {key: os.environ[key] for key in ['HOME', 'TMPDIR'] if key in os.environ}
base_env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
base_env['NODE_PATH'] = str(workspace / 'node_modules')
docker = [str(DOCKER), '--host', args.docker_host]
nonce = uuid.uuid4().hex[:12]
container = f'dvaia-copy-assets-{nonce}'
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

source_hashes = {relative: sha256(source / relative)
                 for relative in CONTROLLED_SOURCES + SOURCE_IMPORTS}
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


write_state()
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
            or grant.get('dockerPath') != str(DOCKER)
            or grant.get('psqlPath') != str(PSQL)
            or grant.get('expectedSourceHashes') != source_hashes
            or grant.get('expectedDependencyDigest') != dependency_digest
            or grant.get('expectedDependencyFileCount') != len(dependency_hashes)
            or grant.get('expectedDependencyPackages') != dependency_packages):
        raise RuntimeError('single-use copy/assets candidate native grant is absent, mismatched, or consumed')
    grant.update({
        'status': 'consumed',
        'consumedAt': datetime.now(timezone.utc).isoformat(),
        'ownerHandle': owner_handle,
        'launcherPid': os.getpid(),
        'container': container,
        'evidence': str(evidence),
        'runStatus': 'starting',
    })
    grant_file.seek(0)
    json.dump(grant, grant_file, indent=2)
    grant_file.write('\n')
    grant_file.truncate()
    grant_file.flush()
    os.fsync(grant_file.fileno())

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
state['sourceHashes'] = copied_hashes
state['sourceInventory'] = inventory
private_node_modules = workspace / 'node_modules'
private_node_modules.mkdir(mode=0o700)
for package_name in dependency_packages:
    source_package = source / 'node_modules' / package_name
    destination_package = private_node_modules / package_name
    destination_package.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copytree(source_package, destination_package)
for path in private_node_modules.rglob('*'):
    os.chmod(path, 0o700 if path.is_dir() else 0o400)
copied_packages, copied_dependency_hashes, copied_dependency_digest = dependency_snapshot(private_node_modules)
if (copied_packages != dependency_packages or copied_dependency_hashes != dependency_hashes
        or copied_dependency_digest != dependency_digest):
    raise RuntimeError('private dependency closure mismatch')
state['dependencyPackages'] = dependency_packages
state['dependencyFileCount'] = len(dependency_hashes)
state['dependencyDigest'] = dependency_digest
write_state()

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
        '-e', 'POSTGRES_USER=copy_assets_admin',
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
            [str(PSQL), '-h', '127.0.0.1', '-p', str(port), '-U', 'copy_assets_admin',
             '-d', 'postgres', '-Atqc', 'SELECT 1'],
            env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2,
        )
        if probe.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned PostgreSQL did not become TCP SQL-ready')

    admin = [str(PSQL), '-h', '127.0.0.1', '-p', str(port), '-U', 'copy_assets_admin',
             '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    roles = ['dvaia_identity_migration', 'dvaia_identity_runtime',
             'dvaia_secureshop_migration', 'dvaia_secureshop_runtime',
             'dvaia_ctf_migration', 'dvaia_ctf_runtime']
    for role in roles:
        run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    databases = {
        'dpi': (f'dvaia_dpi_copy_{nonce}', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
        'assets': (f'dvaia_secureshop_assets_{nonce}', 'dvaia_secureshop_migration', 'dvaia_secureshop_runtime'),
        'ctf': (f'dvaia_ctf_wrapper_{nonce}', 'dvaia_ctf_migration', 'dvaia_ctf_runtime'),
    }
    urls = {}
    for key, (database, migration_role, runtime_role) in databases.items():
        run(admin + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
        run(admin + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                           f'GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],
            stdout=subprocess.DEVNULL)
        urls[key] = f'postgresql://{migration_role}@127.0.0.1:{port}/{database}'
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
               PG_DPI_COPY_MIGRATION_URL=urls['dpi'],
               PG_SECURESHOP_LOCAL_ASSETS_MIGRATION_URL=urls['assets'],
               PG_CTF_WRAPPER_MIGRATION_URL=urls['ctf'])
    state['nodeVersion'] = run([str(NODE), '--version'], capture_output=True, text=True).stdout.strip()
    if state['nodeVersion'] != 'v26.9.0':
        raise RuntimeError('pinned managed Node version mismatch')
    state['runStatus'] = 'starting_test'
    state['childIntent'] = {
        'command': [str(NODE), '--test', '--test-reporter=tap',
                    'tests/postgres/dpiTeachingCopyAlignment.integration.test.js',
                    'tests/postgres/secureshopLocalProductAssets.integration.test.js',
                    'tests/postgres/ctfHistoricalWrapperMigration.integration.test.js'],
        'cwd': str(workspace),
    }
    write_state()
    with result_path.open('w') as log:
        child = subprocess.Popen(
            [str(NODE), '--test', '--test-reporter=tap',
             'tests/postgres/dpiTeachingCopyAlignment.integration.test.js',
             'tests/postgres/secureshopLocalProductAssets.integration.test.js',
             'tests/postgres/ctfHistoricalWrapperMigration.integration.test.js'],
            cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        child_pgid = child.pid
        state['testPid'] = child.pid
        state['testPgid'] = child_pgid
        state['runStatus'] = 'running'
        write_state()
        child_deadline = time.monotonic() + 150
        while child.poll() is None:
            if result_path.stat().st_size > MAX_RESULT_BYTES:
                raise RuntimeError('candidate qualification TAP exceeded the byte ceiling')
            if time.monotonic() >= child_deadline:
                raise subprocess.TimeoutExpired(state['childIntent']['command'], 150)
            time.sleep(0.05)
        code = child.returncode
    if result_path.stat().st_size > MAX_RESULT_BYTES:
        raise RuntimeError('candidate qualification TAP exceeded the byte ceiling')
    print(result_path.read_text(), flush=True)
    if code:
        raise RuntimeError(f'copy/assets candidate qualification failed ({code})')
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
    print(f'Owned container cleanup complete; evidence retained: {evidence}', flush=True)
    if state['runStatus'] == 'cleanup_failed':
        raise RuntimeError('Owned PostgreSQL cleanup did not complete')
