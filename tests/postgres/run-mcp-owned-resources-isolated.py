#!/usr/bin/env python3
"""Run the draft MCP owned-resource DB contract in one owned PG18 container."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--grant-file', default='tasks/native-verification-slot.json')
parser.add_argument('--owner-handle', required=True)
args = parser.parse_args()
if not args.owner_handle.isdecimal() or int(args.owner_handle) <= 0:
    raise SystemExit('--owner-handle must be the positive exec session ID returned by the launcher call')
owner_handle = int(args.owner_handle)
source = Path(__file__).resolve().parents[2]
grant_path = (source / args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-mcp-owned-resources-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
managed_node = Path(base_env.get('HOME', '/nonexistent')) / '.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin'
base_env['PATH'] = str(managed_node) + os.pathsep + base_env.get('PATH', '')
docker = ['docker', '--host', args.docker_host]
container = 'owasp-ai-goat-mcp-owned-resources-' + uuid.uuid4().hex[:12]
ownership_path = root / 'ownership.json'
tracked = [
    'db/postgres/workshop-migrations/mcp/0001_schema.sql',
    'db/postgres/workshop-migrations/mcp/0002_import_provenance.sql',
    'db/postgres/workshop-migrations/mcp/0003_owner_binding.sql',
    'docs/modernization/drafts/mcp-owned-resources.sql',
    'server/database/postgres/index.js',
    'server/database/postgres/mcpResourceRepository.js',
    'server/database/postgres/mcpWorkshopDb.js',
    'server/database/postgres/workshopSupport.js',
    'server/services/mcp/durableMailResources.js',
    'tests/postgres/mcpOwnedResources.integration.test.js',
    'tests/postgres/run-mcp-owned-resources-isolated.py',
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


ownership = {'version': 1, 'owner': '/root/workshop_authenticity', 'launcherPid': os.getpid(),
    'ownerHandle': owner_handle,
    'workspace': str(root), 'container': container, 'grantId': args.grant_id,
    'grantFile': str(grant_path), 'status': 'prepared', 'startedAt': datetime.now(timezone.utc).isoformat(),
    'sourceSha256': {name: digest(source / name) for name in tracked}, 'cleanup': None}
started = False
child = None


def persist_ownership():
    pending = ownership_path.with_suffix('.json.pending')
    pending.write_text(json.dumps(ownership, sort_keys=True) + '\n')
    os.replace(pending, ownership_path)


def consume_grant():
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant is already being consumed') from cause
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('grantId') != args.grant_id or grant.get('status') != 'granted' \
                or grant.get('owner') != '/root/workshop_authenticity' or grant.get('allowedLaunches') != 1:
            raise RuntimeError('Exact unconsumed native verification grant is required')
        grant['status'] = 'consumed'
        grant['consumedAt'] = datetime.now(timezone.utc).isoformat()
        grant['consumerPid'] = os.getpid()
        grant['ownerHandle'] = owner_handle
        grant['runStatus'] = 'running'
        grant['evidence'] = str(root)
        grant['container'] = container
        pending = grant_path.with_suffix(grant_path.suffix + '.pending')
        pending.write_text(json.dumps(grant, indent=2, sort_keys=True) + '\n')
        os.replace(pending, grant_path)
        ownership['grantConsumedAt'] = grant['consumedAt']
        ownership['status'] = 'grant_consumed'
        persist_ownership()
    finally:
        grant_lock.rmdir()


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def ignore(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
            any(name.endswith(suffix) for suffix in
                ['.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'])]


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


persist_ownership()
signal.signal(signal.SIGTERM, interrupted)
consume_grant()
for directory in ['server', 'db', 'tests', 'docs']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=mcp_owned_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=24', '-c', 'max_wal_size=16MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    ownership['status'] = 'container_started'
    persist_ownership()
    deadline = time.monotonic() + 20
    stable = 0
    while time.monotonic() < deadline:
        ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-h', '127.0.0.1',
            '-U', 'mcp_owned_admin'], env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if ready.returncode == 0:
            running = run(docker + ['inspect', '--format', '{{.State.Running}}', container],
                capture_output=True, text=True).stdout.strip() == 'true'
            stable = stable + 1 if running else 0
            if stable >= 3:
                break
        else:
            stable = 0
        time.sleep(.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')
    port = int(run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'mcp_owned_admin', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    for role in ['dvaia_mcp_migration', 'dvaia_mcp_runtime']:
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    database = 'owasp_ai_goat_test_mcp_owned_resources'
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER dvaia_mcp_migration'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_mcp_migration,dvaia_mcp_runtime'], stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
      OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
      PG_MCP_OWNED_RESOURCES_TEST_MIGRATION_URL=f'postgresql://{quote("dvaia_mcp_migration")}@127.0.0.1:{port}/{database}',
      PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL=f'postgresql://{quote("dvaia_mcp_runtime")}@127.0.0.1:{port}/{database}')
    result = root / 'result.log'
    with result.open('w') as log:
        ownership['status'] = 'test_running'
        ownership['testPid'] = None
        ownership['nodeVersion'] = run(['node', '--version'], capture_output=True, text=True).stdout.strip()
        persist_ownership()
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
          'tests/postgres/mcpOwnedResources.integration.test.js'], cwd=workspace, env=env,
          stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        ownership['testPid'] = child.pid
        persist_ownership()
        try:
            code = child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            stop_child()
            raise RuntimeError('MCP owned-resource integration timed out')
    print(result.read_text(), flush=True)
    ownership['testExitCode'] = code
    ownership['resultSha256'] = digest(result)
    ownership['terminalAt'] = datetime.now(timezone.utc).isoformat()
    ownership['terminalStatus'] = 'terminal_pass' if code == 0 else 'terminal_fail'
    ownership['status'] = ownership['terminalStatus']
    persist_ownership()
    if code:
        raise RuntimeError(f'MCP owned-resource integration failed ({code})')
finally:
    stop_child()
    ownership.setdefault('terminalStatus', 'terminal_fail')
    cleanup_failed = False
    if started:
        removed = subprocess.run(docker + ['rm', '--force', container], env=base_env,
          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        absence = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
          '--format', '{{.Names}}'], env=base_env, capture_output=True, text=True, timeout=20)
        remaining = absence.stdout.strip()
        ownership['cleanup'] = {'removeReturnCode': removed.returncode,
            'absenceQueryReturnCode': absence.returncode,
            'exactNameAbsent': absence.returncode == 0 and remaining == ''}
        cleanup_failed = bool(remaining or removed.returncode != 0 or absence.returncode != 0)
    else:
        absence = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
          '--format', '{{.Names}}'], env=base_env, capture_output=True, text=True, timeout=20)
        remaining = absence.stdout.strip()
        ownership['cleanup'] = {'removeReturnCode': None,
            'absenceQueryReturnCode': absence.returncode,
            'exactNameAbsent': absence.returncode == 0 and remaining == '',
            'containerStartNotConfirmed': True}
        cleanup_failed = bool(remaining or absence.returncode != 0)
    ownership['cleanupStatus'] = 'cleanup_failed' if cleanup_failed else 'cleanup_complete'
    ownership['status'] = ownership['terminalStatus']
    ownership['finishedAt'] = datetime.now(timezone.utc).isoformat()
    persist_ownership()
    grant = json.loads(grant_path.read_text())
    if grant.get('grantId') == args.grant_id and grant.get('owner') == ownership['owner'] \
            and grant.get('status') == 'consumed' and grant.get('ownerHandle') == owner_handle:
        grant.update({'runStatus': ownership['terminalStatus'], 'completedAt': ownership['finishedAt'],
            'launcherPid': ownership['launcherPid'], 'container': container, 'evidence': str(root),
            'cleanup': ownership['cleanup'], 'sourceHashes': ownership['sourceSha256'],
            'ownershipSha256': digest(ownership_path)})
        if ownership.get('resultSha256'):
            grant['resultSha256'] = ownership['resultSha256']
        pending = grant_path.with_suffix(grant_path.suffix + '.pending')
        pending.write_text(json.dumps(grant, indent=2, sort_keys=True) + '\n')
        os.replace(pending, grant_path)
    print(f'Owned container {container} cleanup recorded at {ownership_path}; evidence retained: {root}', flush=True)
    if cleanup_failed:
        raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
