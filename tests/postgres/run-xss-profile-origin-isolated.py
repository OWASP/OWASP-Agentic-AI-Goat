#!/usr/bin/env python3
"""Qualify the promoted XSS profile-origin migration in an owned PostgreSQL 18 container."""
import argparse
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
args = parser.parse_args()

source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-xss-profile-origin-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'owasp-ai-goat-xss-profile-origin-' + uuid.uuid4().hex[:12]
started = False
child = None
child_pgid = None
child_sid = None

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

def ignore(_directory, names):
    blocked = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
               'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    suffixes = ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log')
    return [name for name in names if name in blocked or name.startswith('.env') or name.endswith(suffixes)]

def group_members(pgid, sid):
    listing = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
                             capture_output=True, text=True, check=True, timeout=2).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == sid:
                members.append((pid, uid))
        except ProcessLookupError:
            pass
    if any(uid != os.getuid() for _pid, uid in members):
        raise RuntimeError('Refusing to signal a process group containing a foreign process')
    return [pid for pid, _uid in members]

def stop_group():
    if child is None or child_pgid is None or child_sid is None:
        return
    if group_members(child_pgid, child_sid):
        os.killpg(child_pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while group_members(child_pgid, child_sid) and time.monotonic() < deadline:
        time.sleep(.05)
    if group_members(child_pgid, child_sid):
        os.killpg(child_pgid, signal.SIGKILL)
    child.wait(timeout=5)
    if group_members(child_pgid, child_sid):
        raise RuntimeError('Owned test process group cleanup did not complete')

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)

for directory in ('server', 'db', 'tests'):
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=xss_origin_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=24',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'xss_origin_admin'], env=base_env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2)
        except subprocess.TimeoutExpired:
            ready = None
        if ready is not None and ready.returncode == 0:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')

    port = int(run(docker + ['port', container, '5432'], capture_output=True,
                   text=True).stdout.strip().rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'xss_origin_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    for role in ('dvaia_xss_migration', 'dvaia_xss_runtime'):
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    database = 'owasp_ai_goat_test_xss_profile_origin'
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER dvaia_xss_migration'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
          f'GRANT CONNECT ON DATABASE {database} TO dvaia_xss_migration,dvaia_xss_runtime'], stdout=subprocess.DEVNULL)

    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
        OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), PLATFORM_DATABASE_ENGINE='postgres',
        WORKSHOP_DATABASE_ENGINE='postgres', AI_PROVIDER='mock', JUDGE_PROVIDER='mock',
        AWS_EC2_METADATA_DISABLED='true', MCP_WORKSHOP_AUTOSTART='false',
        MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false', HF_HUB_OFFLINE='1',
        PG_XSS_PROFILE_ORIGIN_MIGRATION_URL=f'postgresql://dvaia_xss_migration@127.0.0.1:{port}/{database}',
        PG_XSS_PROFILE_ORIGIN_RUNTIME_URL=f'postgresql://dvaia_xss_runtime@127.0.0.1:{port}/{database}')
    print(f'Owned XSS profile-origin workspace: {workspace}', flush=True)
    with (root / 'result.log').open('w') as log:
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap', '--test-concurrency=1',
            'tests/postgres/xssProfileOrigin.integration.test.js'], cwd=workspace, env=env,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        child_pgid = os.getpgid(child.pid)
        child_sid = os.getsid(child.pid)
        try:
            returncode = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            returncode = None
        finally:
            stop_group()
    print((root / 'result.log').read_text(), flush=True)
    if returncode is None:
        raise RuntimeError('XSS profile-origin qualification timed out')
    if returncode:
        raise RuntimeError(f'XSS profile-origin qualification failed ({returncode})')
finally:
    try:
        stop_group()
    finally:
        if started:
            subprocess.run(docker + ['rm', '--force', container], env=base_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
            if remaining:
                raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
        print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
