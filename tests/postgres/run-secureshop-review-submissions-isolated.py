#!/usr/bin/env python3
"""Run the learner review submission proof in one owned disposable PG18 container."""

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
root = Path(tempfile.mkdtemp(prefix='dvaia-secureshop-review-submissions-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-secureshop-review-submissions-' + uuid.uuid4().hex[:12]
started = False


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


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
for relative in [
    'server/database/postgres/index.js',
    'server/database/postgres/poolBudget.js',
    'server/database/postgres/secureshopBoundReviewRepository.js',
    'db/postgres/workshop-migrations/secureshop_review/0001_schema.sql',
    'db/postgres/workshop-migrations/secureshop_review/0002_cleanup_receipts.sql',
    'docs/modernization/drafts/secureshop-review-learner-submissions.sql',
    'tests/postgres/secureshopReviewSubmissions.integration.test.js',
]:
    target = workspace / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / relative, target)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=review_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=32', '-c', 'max_wal_size=16MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'review_test_admin'],
                               env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=2)
        if ready.returncode == 0:
            break
        time.sleep(.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')
    address = run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip()
    port = int(address.rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'review_test_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    migration_role = 'dvaia_secureshop_review_migration'
    runtime_role = 'dvaia_secureshop_review_runtime'
    database = 'dvaia_test_secureshop_review'
    for role in [migration_role, runtime_role]:
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                          'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                      f'GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],
        stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
               PG_SECURESHOP_REVIEW_SUBMISSION_MIGRATION_URL=
               f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
               PG_SECURESHOP_REVIEW_SUBMISSION_RUNTIME_URL=
               f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}')
    child = None
    try:
        with (root / 'result.log').open('w') as log:
            child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
                'tests/postgres/secureshopReviewSubmissions.integration.test.js'], cwd=workspace,
                env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            code = child.wait(timeout=120)
    finally:
        if child is not None:
            stop_group(child)
    print((root / 'result.log').read_text(), flush=True)
    if code:
        raise RuntimeError(f'Learner review submission integration failed ({code})')
finally:
    if started:
        subprocess.run(docker + ['rm', '--force', container], env=base_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining:
            raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
