#!/usr/bin/env python3
"""Qualify the draft SecureShop conversation retirement in owned PostgreSQL 18."""
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
root = Path(tempfile.mkdtemp(prefix='dvaia-secureshop-conversation-lifecycle-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
run_id = uuid.uuid4().hex[:12]
container = f'dvaia-secureshop-conversation-lifecycle-{run_id}'
started = False
child = None

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

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
for relative in [
    'server/database/postgres/secureshopBoundConversationsRepository.js',
    'server/database/postgres/secureshopTurnRequestsRepository.js',
    'server/database/postgres/secureshopConversationLifecycleRepository.js',
    'server/database/postgres/secureshopConversationCleanupCheckpointRepository.js',
    'server/database/postgres/secureshopResetCleanupAuthorityRepository.js',
    'server/database/postgres/secureshopLaunchRepository.js',
    'server/database/postgres/identityRepository.js',
    'server/database/postgres/identityValidation.js',
    'server/database/postgres/index.js',
    'server/database/postgres/poolBudget.js',
    'server/services/secureshopConversationBinding.js',
    'server/services/secureshopBoundTraceRecord.js',
    'server/services/secureshopTurnRequest.js',
    'server/services/secureshopConversationLifecycle.js',
    'server/services/secureshopBoundConversation.js',
    'server/services/secureshopBoundTurns.js',
    'server/agent-runtime/runCoordinator.js',
    'server/agent-runtime/postgresRunLedger.js',
    'server/agent-runtime/runTraceStore.js',
    'db/postgres/migrate.js',
    'db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
    'docs/modernization/drafts/secureshop-turn-admission.sql',
    'docs/modernization/drafts/secureshop-conversation-generation-retirement.sql',
    'docs/modernization/drafts/secureshop-conversation-cleanup-checkpoint.sql',
    'tests/postgres/secureshopConversationLifecycle.integration.test.js',
]:
    target = workspace / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / relative, target)
shutil.copytree(source / 'db/postgres/identity-migrations',
                workspace / 'db/postgres/identity-migrations')
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=lifecycle_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=32', '-c', 'max_wal_size=16MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'lifecycle_test_admin'],
                env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0:
                break
        except subprocess.TimeoutExpired:
            pass
        time.sleep(.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')
    port = int(run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'lifecycle_test_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    migration_role = 'dvaia_secureshop_agents_migration'
    runtime_role = 'dvaia_secureshop_agents_runtime'
    database = f'dvaia_test_secureshop_lifecycle_{run_id}'
    identity_migration_role = 'dvaia_identity_migration'
    identity_runtime_role = 'dvaia_identity_runtime'
    identity_database = f'dvaia_test_secureshop_lifecycle_identity_{run_id}'
    for role in [migration_role, runtime_role, identity_migration_role, identity_runtime_role]:
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                          'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'CREATE DATABASE {identity_database} OWNER {identity_migration_role}'],
        stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                      f'GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],
        stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {identity_database} FROM PUBLIC; '
                      f'GRANT CONNECT ON DATABASE {identity_database} '
                      f'TO {identity_migration_role}, {identity_runtime_role}'], stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
        DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
        PG_SECURESHOP_LIFECYCLE_TEST_MIGRATION_URL=
        f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
        PG_SECURESHOP_LIFECYCLE_TEST_RUNTIME_URL=
        f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}',
        PG_SECURESHOP_LIFECYCLE_TEST_IDENTITY_MIGRATION_URL=
        f'postgresql://{quote(identity_migration_role)}@127.0.0.1:{port}/{identity_database}',
        PG_SECURESHOP_LIFECYCLE_TEST_IDENTITY_RUNTIME_URL=
        f'postgresql://{quote(identity_runtime_role)}@127.0.0.1:{port}/{identity_database}')
    log_path = root / 'result.log'
    with log_path.open('w') as log:
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
            'tests/postgres/secureshopConversationLifecycle.integration.test.js'],
            cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        code = child.wait(timeout=90)
    print(log_path.read_text(), flush=True)
    if code:
        raise RuntimeError(f'SecureShop conversation lifecycle integration failed ({code})')
finally:
    stop_child()
    if started:
        subprocess.run(docker + ['rm', '--force', container], env=base_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
            '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining:
            raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
