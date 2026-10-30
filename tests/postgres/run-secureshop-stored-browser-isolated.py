#!/usr/bin/env python3
"""Run SecureShop stored-browser parent/frame qualification in owned PostgreSQL 18."""

import argparse
from datetime import datetime, timezone
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
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-stored-browser-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
managed_node = Path(base_env.get('HOME', '/nonexistent')) / '.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin'
base_env['PATH'] = str(managed_node) + os.pathsep + base_env.get('PATH', '')
docker = ['docker', '--host', args.docker_host]
container = 'owasp-ai-goat-secureshop-stored-browser-' + uuid.uuid4().hex[:12]
ownership_path = root / 'ownership.json'
ownership = {
    'version': 1,
    'launcherPid': os.getpid(),
    'workspace': str(root),
    'container': container,
    'status': 'prepared',
    'startedAt': datetime.now(timezone.utc).isoformat(),
    'cleanup': None,
}
started = False
child = None

def persist_ownership():
    pending = ownership_path.with_suffix('.json.pending')
    pending.write_text(json.dumps(ownership, sort_keys=True) + '\n')
    os.replace(pending, ownership_path)

persist_ownership()

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

signal.signal(signal.SIGTERM, interrupted)
for directory in ['server', 'db', 'tests', 'docs', 'client']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
(workspace / 'client/node_modules').symlink_to(source / 'client/node_modules', target_is_directory=True)

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=stored_browser_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=64', '-c', 'max_wal_size=16MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    ownership['status'] = 'container_started'
    persist_ownership()
    deadline = time.monotonic() + 25
    stable_probes = 0
    while time.monotonic() < deadline:
        try:
            ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'stored_browser_admin'],
                env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except subprocess.TimeoutExpired:
            ready = None
        if ready is not None and ready.returncode == 0:
            running = run(docker + ['inspect', '--format', '{{.State.Running}}', container],
                          capture_output=True, text=True).stdout.strip() == 'true'
            stable_probes = stable_probes + 1 if running else 0
            if stable_probes >= 3:
                break
        else:
            stable_probes = 0
        time.sleep(.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')
    port = int(run(docker + ['port', container, '5432'], capture_output=True,
        text=True).stdout.strip().rsplit(':', 1)[1])
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'stored_browser_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    stores = [('identity', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
              ('review', 'dvaia_secureshop_review_migration', 'dvaia_secureshop_review_runtime'),
              ('agents', 'dvaia_secureshop_agents_migration', 'dvaia_secureshop_agents_runtime'),
              ('commerce', 'dvaia_secureshop_migration', 'dvaia_secureshop_runtime')]
    urls = {}
    for label, migration_role, runtime_role in stores:
        for role in [migration_role, runtime_role]:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                              'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
        database = f'owasp_ai_goat_test_secureshop_stored_browser_{label}'
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                          f'GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],
            stdout=subprocess.DEVNULL)
        urls[label] = {
            'migration': f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
            'runtime': f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}',
        }
    env = dict(base_env, NODE_ENV='test', PLATFORM_DATABASE_ENGINE='postgres',
               WORKSHOP_DATABASE_ENGINE='postgres',
               PG_TEST_DISPOSABLE='yes', LIVE_OLLAMA_TEST='1',
               OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
               OLLAMA_BASE_URL=os.environ.get('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'),
               OLLAMA_MODEL='llama3.1:8b', JUDGE_PROVIDER='ollama', JUDGE_MODEL='llama3.1:8b',
               PG_SECURESHOP_STORED_BROWSER_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
               PG_SECURESHOP_STORED_BROWSER_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],
               PG_SECURESHOP_STORED_BROWSER_REVIEW_MIGRATION_URL=urls['review']['migration'],
               PG_SECURESHOP_STORED_BROWSER_REVIEW_RUNTIME_URL=urls['review']['runtime'],
               PG_SECURESHOP_STORED_BROWSER_AGENTS_MIGRATION_URL=urls['agents']['migration'],
               PG_SECURESHOP_STORED_BROWSER_AGENTS_RUNTIME_URL=urls['agents']['runtime'],
               PG_SECURESHOP_STORED_BROWSER_COMMERCE_MIGRATION_URL=urls['commerce']['migration'],
               PG_SECURESHOP_STORED_BROWSER_COMMERCE_RUNTIME_URL=urls['commerce']['runtime'])
    log_path = root / 'result.log'
    run(['npm', '--prefix', 'client', 'run', 'build'], cwd=workspace,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with log_path.open('w') as log:
        ownership['status'] = 'test_running'
        ownership['testPid'] = None
        persist_ownership()
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
            'tests/postgres/secureshopStoredBrowserRendered.integration.test.js'],
            cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        ownership['testPid'] = child.pid
        persist_ownership()
        try:
            code = child.wait(timeout=300)
        except subprocess.TimeoutExpired:
            stop_child()
            raise RuntimeError('SecureShop stored browser integration timed out')
    print(log_path.read_text(), flush=True)
    if code:
        raise RuntimeError(f'SecureShop stored browser integration failed ({code})')
finally:
    stop_child()
    if started:
        removed = subprocess.run(docker + ['rm', '--force', container], env=base_env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                  '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
        ownership['cleanup'] = {'removeReturnCode': removed.returncode,
                                'exactNameAbsent': remaining == ''}
        ownership['status'] = 'cleaned' if removed.returncode == 0 and not remaining else 'cleanup_failed'
        ownership['finishedAt'] = datetime.now(timezone.utc).isoformat()
        persist_ownership()
        if remaining:
            raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
    else:
        ownership['cleanup'] = {'removeReturnCode': None, 'exactNameAbsent': True,
                                'containerNeverStarted': True}
        ownership['status'] = 'cleaned_without_container'
        ownership['finishedAt'] = datetime.now(timezone.utc).isoformat()
        persist_ownership()
    print(f'Owned container {container} cleanup recorded at {ownership_path}; '
          f'evidence retained: {root}', flush=True)
