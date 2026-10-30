#!/usr/bin/env python3
"""Qualify the unregistered DPI guidance draft through the production PG loader."""
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

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--owner-handle-file', required=True)
args = parser.parse_args()
handle_path = Path(args.owner_handle_file)
deadline = time.monotonic() + 30
while not handle_path.exists():
    if time.monotonic() >= deadline: raise RuntimeError('Actual exec owner handle was not supplied')
    time.sleep(0.1)
owner_handle = int(handle_path.read_text().strip())

source = Path(__file__).resolve().parents[2]
grant_path = Path(args.grant_file).resolve()
evidence = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-dpi-guidance-'))
workspace = evidence / 'source'
workspace.mkdir()
os.chmod(evidence, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
managed_node = Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin')
if managed_node.exists():
    base_env['PATH'] = f'{managed_node}:{base_env.get("PATH", "")}'
docker = ['docker', '--host', args.docker_host]
container = f'owasp-ai-goat-dpi-guidance-{uuid.uuid4().hex[:12]}'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
state = {
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
ownership_path.write_text(json.dumps(state, indent=2) + '\n')
os.chmod(ownership_path, 0o600)


def write_state():
    if ownership_path.exists():
        try:
            existing_handle = json.loads(ownership_path.read_text()).get('ownerHandle')
            if existing_handle not in (None, os.getpid()):
                state['ownerHandle'] = existing_handle
        except (OSError, ValueError):
            pass
    ownership_path.write_text(json.dumps(state, indent=2) + '\n')
    os.chmod(ownership_path, 0o600)


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id
            or grant.get('owner') != '/root'
            or grant.get('status') != 'granted'
            or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != args.docker_host):
        raise RuntimeError('single-use DPI guidance native grant is absent, mismatched, or consumed')
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
started = False


def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            child.wait(timeout=5)


def interrupted(signum, _frame):
    stop_child()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)


def ignore(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'covedpie', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env')
            or any(name.endswith(suffix) for suffix in ('.db', '.db-wal', '.db-shm', '.log'))]


for directory in ['server', 'db', 'tests', 'docs']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
state['sourceHashes'] = {}
for relative in [
        'docs/modernization/drafts/dpi-evidence-guidance.sql',
        'tests/postgres/dpiEvidenceGuidance.integration.test.js',
        'tests/postgres/run-dpi-evidence-guidance-isolated.py']:
    state['sourceHashes'][relative] = hashlib.sha256((workspace / relative).read_bytes()).hexdigest()
write_state()

try:
    run(docker + [
        'run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=dpi_guidance_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=32',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB',
    ], stdout=subprocess.DEVNULL)
    started = True
    state['started'] = True
    inspect = json.loads(run(docker + ['inspect', container], capture_output=True, text=True).stdout)[0]
    state['mounts'] = inspect.get('Mounts', [])
    state['containerId'] = inspect['Id']
    state['imageId'] = inspect['Image']
    write_state()
    port = int(run(docker + ['port', container, '5432'], capture_output=True, text=True)
               .stdout.strip().rsplit(':', 1)[1])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(
                ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'dpi_guidance_admin',
                 '-d', 'postgres', '-Atqc', 'SELECT 1'],
                env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except subprocess.TimeoutExpired:
            probe = None
        if probe is not None and probe.returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned PostgreSQL did not become TCP SQL-ready')

    admin = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'dpi_guidance_admin',
             '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    for role in ['dvaia_identity_migration', 'dvaia_identity_runtime']:
        run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    urls = {}
    for kind in ['fresh', 'populated', 'custom']:
        database = f'owasp_ai_goat_dpi_guidance_{kind}'
        run(admin + ['-c', f'CREATE DATABASE {database} OWNER dvaia_identity_migration'], stdout=subprocess.DEVNULL)
        run(admin + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                           f'GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime'],
            stdout=subprocess.DEVNULL)
        urls[kind.upper()] = {
            'MIGRATION': f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}',
            'RUNTIME': f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}',
        }
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true')
    for kind, pair in urls.items():
        for role, url in pair.items():
            env[f'PG_DPI_GUIDANCE_{kind}_{role}_URL'] = url
    state['nodeVersion'] = run(['node', '--version'], capture_output=True, text=True).stdout.strip()
    state['runStatus'] = 'running'
    write_state()
    with result_path.open('w') as log:
        child = subprocess.Popen(
            ['node', '--test', '--test-reporter=tap',
             'tests/postgres/dpiEvidenceGuidance.integration.test.js'],
            cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        state['testPid'] = child.pid
        write_state()
        code = child.wait(timeout=90)
    print(result_path.read_text(), flush=True)
    if code:
        raise RuntimeError(f'DPI guidance qualification failed ({code})')
    state['runStatus'] = 'passed'
except BaseException as error:
    state['runStatus'] = 'failed'
    state['error'] = f'{type(error).__name__}: {error}'
    raise
finally:
    stop_child()
    if started:
        try:
            details = json.loads(run(docker + ['inspect', container], capture_output=True, text=True).stdout)[0]
            (evidence / 'container-state.json').write_text(json.dumps({
                'Name': details.get('Name'), 'State': details.get('State'), 'Mounts': details.get('Mounts'),
            }, indent=2) + '\n')
            os.chmod(evidence / 'container-state.json', 0o600)
            logs = subprocess.run(docker + ['logs', container], env=base_env,
                                  capture_output=True, text=True, timeout=30)
            (evidence / 'container.log').write_text(logs.stdout + logs.stderr)
            os.chmod(evidence / 'container.log', 0o600)
        except BaseException as inspect_error:
            state['inspectError'] = f'{type(inspect_error).__name__}: {inspect_error}'
        cleanup = subprocess.run(docker + ['rm', '--force', container], env=base_env,
                                 capture_output=True, text=True, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        state['cleanup'] = {
            'returncode': cleanup.returncode,
            'stdout': cleanup.stdout.strip(),
            'stderr': cleanup.stderr.strip(),
            'absenceVerified': not bool(remaining),
        }
        if cleanup.returncode or remaining:
            state['runStatus'] = 'cleanup_failed'
    if not started:
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^/{container}$', '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        state['cleanup'] = {'absenceVerified': not bool(remaining), 'absenceQueryReturnCode': 0}
        if remaining: state['runStatus'] = 'cleanup_failed'
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
                'resultSha256': hashlib.sha256(result_path.read_bytes()).hexdigest() if result_path.exists() else None,
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
