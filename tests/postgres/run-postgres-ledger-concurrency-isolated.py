#!/usr/bin/env python3
"""Qualify the retained-client ledger query lane in one owned disposable PostgreSQL 18."""
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
parser.add_argument('--docker-host', required=True)
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='dvaia-postgres-ledger-concurrency-'))
workspace = root / 'source'
workspace.mkdir(); os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-postgres-ledger-concurrency-' + uuid.uuid4().hex[:12]
started = False
child = None

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL); child.wait(timeout=5)

def interrupted(signum, _frame):
    stop_child(); raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, interrupted)
for relative in [
    'server/agent-runtime/postgresRunLedger.js', 'server/agent-runtime/runCoordinator.js',
    'server/agent-runtime/runTraceStore.js', 'server/database/postgres/identityRepository.js',
    'server/database/postgres/identityValidation.js', 'server/database/postgres/index.js',
    'server/database/postgres/poolBudget.js', 'db/postgres/migrate.js',
    'tests/postgres/postgresRunLedgerConcurrency.integration.test.js',
]:
    target = workspace / relative; target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / relative, target)
shutil.copytree(source / 'db/postgres/identity-migrations', workspace / 'db/postgres/identity-migrations')
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456', '-e', 'POSTGRES_USER=ledger_test_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', 'postgres:18', '-c', 'shared_buffers=16MB',
        '-c', 'max_connections=32', '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'],
        stdout=subprocess.DEVNULL)
    started = True
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'ledger_test_admin'],
                env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except subprocess.TimeoutExpired: ready = None
        if ready is not None and ready.returncode == 0: break
        time.sleep(.25)
    else: raise RuntimeError('Owned PostgreSQL container did not become ready')
    port = int(run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'ledger_test_admin', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    migration_role, runtime_role = 'dvaia_identity_migration', 'dvaia_identity_runtime'
    database = 'dvaia_test_postgres_ledger_concurrency'
    for role in [migration_role, runtime_role]:
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'], stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
        PG_LEDGER_CONCURRENCY_MIGRATION_URL=f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
        PG_LEDGER_CONCURRENCY_RUNTIME_URL=f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}')
    log_path = root / 'result.log'
    with log_path.open('w') as log:
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
            'tests/postgres/postgresRunLedgerConcurrency.integration.test.js'], cwd=workspace,
            env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        code = child.wait(timeout=120)
    print(log_path.read_text(), flush=True)
    if code: raise RuntimeError(f'PostgreSQL ledger concurrency integration failed ({code})')
finally:
    stop_child()
    if started:
        subprocess.run(docker + ['rm', '--force', container], env=base_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$', '--format', '{{.Names}}'],
            capture_output=True, text=True).stdout.strip()
        if remaining: raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
