#!/usr/bin/env python3
"""Qualify isolated legacy session disclosure with owned PostgreSQL databases."""

import argparse
import hashlib
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
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='dvaia-session-disclosure-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-session-disclosure-' + uuid.uuid4().hex[:12]
started = False
PROMOTED_MIGRATION_SHA256 = '532b3f33afead775cd02322d04cb8a6aeb3bc179bcade5f7fe862661612f6d80'


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def ignore(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
            any(name.endswith(suffix) for suffix in
                ['.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'])]


def interrupted(signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def stop_group(child):
    if child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            child.wait(timeout=5)


signal.signal(signal.SIGTERM, interrupted)
for directory in ['server', 'db', 'tests']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
migration_dir = workspace / 'db/postgres/workshop-migrations/session_disclosure'
promoted_migration = migration_dir / '0001_schema.sql'
if not promoted_migration.is_file() or promoted_migration.is_symlink():
    raise RuntimeError('Promoted session disclosure migration is missing or unsafe')
if hashlib.sha256(promoted_migration.read_bytes()).hexdigest() != PROMOTED_MIGRATION_SHA256:
    raise RuntimeError('Promoted session disclosure migration differs from the qualified schema')

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=session_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=48', '-c', 'max_wal_size=16MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'session_test_admin'],
                               env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=2)
        if ready.returncode == 0:
            break
        time.sleep(.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')
    address = run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip()
    port = int(address.rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'session_test_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               SESSION_DISCLOSURE_ISOLATED='1', DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
               PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               JWT_SECRET='owned-session-disclosure-test-secret',
               SESSION_DISCLOSURE_TEST_MIGRATION_DIR=str(migration_dir),
               MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false',
               SS_ENABLE='false', AWS_EC2_METADATA_DISABLED='true')
    for schema, prefix, database in [
        ('identity', 'IDENTITY', 'dvaia_test_session_identity'),
        ('session_disclosure', 'SESSION_DISCLOSURE', 'dvaia_test_session_disclosure')]:
        migration = f'dvaia_{schema}_migration'
        runtime = f'dvaia_{schema}_runtime'
        for role in [migration, runtime]:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                              'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                          f'GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'],
            stdout=subprocess.DEVNULL)
        env[f'{prefix}_MIGRATION_DATABASE_URL'] = \
            f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}'
        env[f'{prefix}_DATABASE_URL'] = \
            f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}'
    child = None
    try:
        with (root / 'result.log').open('w') as log:
            child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
                'tests/postgres/legacySessionDisclosure.integration.test.js'], cwd=workspace,
                env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            code = child.wait(timeout=180)
    finally:
        if child is not None:
            stop_group(child)
    print((root / 'result.log').read_text(), flush=True)
    if code:
        raise RuntimeError(f'Session disclosure integration failed ({code})')
finally:
    if started:
        subprocess.run(docker + ['rm', '--force', container], env=base_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining:
            raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
