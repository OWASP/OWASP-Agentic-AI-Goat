#!/usr/bin/env python3
"""Qualify the mounted Excessive Agency route using owned PostgreSQL storage."""

import argparse
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
parser.add_argument('--docker-host', required=True,
                    help='Docker socket used only for the uniquely named PostgreSQL container')
parser.add_argument('--live', action='store_true',
                    help='Use local Ollama llama3.1:8b for the actor and Judge')
parser.add_argument('--ui', action='store_true',
                    help='Run the rendered React Excessive Agency workflow')
parser.add_argument('--objective', choices=['9'], help='Bounded live representative only')
args = parser.parse_args()
if args.objective and (not args.live or args.ui): parser.error('--objective requires --live without --ui')

source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='dvaia-ea-route-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-ea-route-test-' + uuid.uuid4().hex[:12]
container_started = False


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def ignore(_directory, names):
    return [name for name in names if name in {
        '.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
        'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__',
    } or name.startswith('.env') or any(name.endswith(suffix) for suffix in [
        '.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log',
    ])]


def interrupted(signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def owned_group_members(pgid, session_id):
    listing = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
                             capture_output=True, text=True, check=True, timeout=2).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == session_id:
                members.append((pid, uid))
        except ProcessLookupError:
            continue
    foreign = [pid for pid, uid in members if uid != os.getuid()]
    if foreign:
        raise RuntimeError(f'Refusing to signal process group {pgid}; it contains foreign processes')
    return [pid for pid, _uid in members]


def stop_owned_group(child, pgid, session_id):
    if owned_group_members(pgid, session_id):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while owned_group_members(pgid, session_id) and time.monotonic() < deadline:
        child.poll()
        time.sleep(0.05)
    if owned_group_members(pgid, session_id):
        os.killpg(pgid, signal.SIGKILL)
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Owned Node process group did not terminate') from error
    if owned_group_members(pgid, session_id):
        raise RuntimeError('Owned Node process group cleanup did not complete')


signal.signal(signal.SIGTERM, interrupted)
for directory in ['server', 'db', 'tests']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
if args.ui:
    shutil.copytree(source / 'client', workspace / 'client', ignore=ignore)
    client_modules = workspace / 'client' / 'node_modules'
    if client_modules.exists() or client_modules.is_symlink():
        client_modules.unlink()
    client_modules.symlink_to(source / 'client' / 'node_modules', target_is_directory=True)

try:
    run(docker + [
        'run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=ea_route_test_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=48',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB',
    ], stdout=subprocess.DEVNULL)
    container_started = True
    ownership = run(docker + ['inspect', '--format',
                    'id={{.Id}} tmpfs={{json .HostConfig.Tmpfs}} mounts={{json .Mounts}}',
                    container], capture_output=True, text=True).stdout.strip()
    (root / 'container-ownership.txt').write_text(ownership + '\n')
    if ('"/var/lib/postgresql":"rw,size=268435456"' not in ownership
            or 'mounts=[]' not in ownership):
        raise RuntimeError('Owned PostgreSQL container does not have the expected isolated tmpfs')
    deadline = time.monotonic() + 20
    consecutive_ready = 0
    while time.monotonic() < deadline:
        try:
            ready = subprocess.run(docker + ['exec', container, 'psql', '-U', 'ea_route_test_admin',
                                   '-d', 'postgres', '-c', 'SELECT 1'], env=base_env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=min(2, max(0.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            ready = None
        if ready is not None and ready.returncode == 0:
            consecutive_ready += 1
            if consecutive_ready >= 5:
                break
        else:
            consecutive_ready = 0
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')

    address = run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip()
    port = int(address.rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'ea_route_test_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', EA_ROUTE_ISOLATED='1',
               EA_ROUTE_UI='1' if args.ui else '0',
               EA_ROUTE_LIVE='1' if args.live else '0', EA_ROUTE_OBJECTIVE=args.objective or '',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
               PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               AI_PROVIDER='ollama' if args.live else 'deterministic-fixture',
               JUDGE_PROVIDER='ollama' if args.live else 'deterministic-fixture',
               OLLAMA_MODEL='llama3.1:8b', JUDGE_MODEL='llama3.1:8b',
               OLLAMA_BASE_URL='http://127.0.0.1:11434' if args.live else 'http://127.0.0.1:1',
               JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex, SESSION_SECRET=uuid.uuid4().hex+uuid.uuid4().hex,
               AWS_EC2_METADATA_DISABLED='true', MCP_WORKSHOP_AUTOSTART='false',
               MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false', HF_HUB_OFFLINE='1',
               SANDBOX_RUNNER_URL='http://127.0.0.1:1', SSRF_TARGET_URL='http://127.0.0.1:1',
               ROGUE_MCP_URL='http://127.0.0.1:1', MAILPIT_API_URL='http://127.0.0.1:1',
               MAILPIT_SMTP_HOST='127.0.0.1', MAILPIT_SMTP_PORT='1')

    databases = [
        ('identity', 'dvaia_test_ea_route_identity'),
        ('excessive_agency', 'dvaia_test_ea_route_lab'),
    ]
    if args.ui:
        databases.append(('ctf', 'dvaia_test_ea_route_ctf'))
    for family, database in databases:
        migration = f'dvaia_{family}_migration'
        runtime = f'dvaia_{family}_runtime'
        for role in [migration, runtime]:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB '
                                  'NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                          f'GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'],
            stdout=subprocess.DEVNULL)
        env_name = {'identity': 'IDENTITY', 'excessive_agency': 'EXCESSIVE_AGENCY', 'ctf': 'CTF'}[family]
        env[f'{env_name}_MIGRATION_DATABASE_URL'] = (
            f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}')
        env[f'{env_name}_DATABASE_URL'] = (
            f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}')

    if args.live:
        response = run(['curl', '--fail', '--silent', '--show-error', '--max-time', '5',
                        'http://127.0.0.1:11434/api/tags'], capture_output=True, text=True)
        if 'llama3.1:8b' not in response.stdout:
            raise RuntimeError('Local Ollama does not advertise llama3.1:8b')

    print(f'Owned EA route workspace: {workspace}', flush=True)
    child = None
    child_pgid = None
    child_session = None
    timed_out = False
    try:
        with (root / 'result.log').open('w') as log:
            child = subprocess.Popen([
                'node', '--test', '--test-reporter=tap', '--test-concurrency=1',
                ('tests/postgres/excessiveAgencyRenderedUi.integration.test.js' if args.ui
                 else 'tests/postgres/excessiveAgencyRoute.integration.test.js'),
            ], cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True)
            child_pgid = os.getpgid(child.pid)
            child_session = os.getsid(child.pid)
            try:
                returncode = child.wait(timeout=960 if args.live else (300 if args.ui else 180))
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = None
    finally:
        if child is not None and child_pgid is not None and child_session is not None:
            stop_owned_group(child, child_pgid, child_session)
    print((root / 'result.log').read_text(), flush=True)
    if timed_out:
        raise RuntimeError('EA route integration timed out')
    if returncode:
        raise RuntimeError(f'EA route integration failed ({returncode})')
finally:
    if container_started:
        removed = subprocess.run(docker + ['rm', '--force', '--volumes', container], env=base_env,
                                 capture_output=True, text=True, timeout=30)
        (root / 'container-cleanup.txt').write_text(
            f'returncode={removed.returncode}\nstdout={removed.stdout}stderr={removed.stderr}')
        if removed.returncode != 0:
            raise RuntimeError('Owned PostgreSQL container removal failed')
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining:
            raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
        with (root / 'container-cleanup.txt').open('a') as evidence:
            evidence.write('absence_verified=true\n')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
