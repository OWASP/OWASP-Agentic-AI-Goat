#!/usr/bin/env python3
"""Qualify the mounted CSRF browser route in owned source and PostgreSQL storage."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument('--live', action='store_true', help='Use local llama3.1:8b actor and Judge')
parser.add_argument('--ui', action='store_true', help='Qualify the rendered application through real login and controls')
parser.add_argument('--docker-host', help='Create a dedicated PostgreSQL container on this Docker socket')
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='dvaia-csrf-browser-route-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR', 'PUPPETEER_EXECUTABLE_PATH', 'PUPPETEER_CACHE_DIR'] if key in os.environ}

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

def interrupted(signum, frame):
    # Unwind through the same owned-resource cleanup on CI cancellation.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, interrupted)

def ignore(directory, names):
    return [name for name in names if name in {
        '.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files', 'workshop_data',
        'vector-indexes', 'coverage', '.cache', '__pycache__',
    } or name.startswith('.env') or any(name.endswith(suffix) for suffix in [
        '.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log',
    ])]

for directory in ['server', 'db', 'tests'] + (['client'] if args.ui else []):
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
if args.ui:
    (workspace / 'client' / 'node_modules').symlink_to(source / 'client' / 'node_modules', target_is_directory=True)
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
native_start_attempted = False
container = None
docker = ['docker', '--host', args.docker_host] if args.docker_host else None
try:
    if docker:
        container = 'dvaia-csrf-route-test-' + uuid.uuid4().hex[:12]
        run(docker + ['run', '--detach', '--name', container, '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
                     '-e', 'POSTGRES_USER=csrf_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
                     '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432',
                     'postgres:18', '-c', 'shared_buffers=16MB', '-c', 'max_connections=40',
                     '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
        ready_deadline = time.monotonic() + 20
        while time.monotonic() < ready_deadline:
            try:
                check = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'csrf_test_admin'],
                                       env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=min(2, max(0.1, ready_deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                check = None
            if check is not None and check.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('Owned container did not become ready')
        address = run(docker + ['port', container, '5432'], capture_output=True, text=True).stdout.strip()
        port = int(address.rsplit(':', 1)[1])
    else:
        with (root / 'init.log').open('w') as log:
            run(['initdb', '-D', str(root / 'data'), '-U', 'csrf_test_admin', '-A', 'trust',
                 '--no-locale', '--encoding=UTF8', '--wal-segsize=1'], stdout=log, stderr=subprocess.STDOUT)
        native_start_attempted = True
        run(['pg_ctl', '-D', str(root / 'data'), '-l', str(root / 'postgres.log'), '-o',
             f'-h 127.0.0.1 -p {port} -k {root} -c shared_buffers=16MB -c max_connections=40',
             '-w', 'start'], stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
               PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               AI_PROVIDER='ollama' if args.live else 'mock',
               JUDGE_PROVIDER='ollama' if args.live else 'mock',
               CSRF_BROWSER_ROUTE_LIVE='1' if args.live else '0',
               OLLAMA_MODEL='llama3.1:8b', JUDGE_MODEL='llama3.1:8b',
               OLLAMA_BASE_URL='http://127.0.0.1:11434' if args.live else 'http://127.0.0.1:1',
               AWS_EC2_METADATA_DISABLED='true', MCP_WORKSHOP_AUTOSTART='false',
               SS_ENABLE='false', HF_HUB_OFFLINE='1',
               SANDBOX_RUNNER_URL='http://127.0.0.1:1', SSRF_TARGET_URL='http://127.0.0.1:1',
               ROGUE_MCP_URL='http://127.0.0.1:1', MAILPIT_API_URL='http://127.0.0.1:1',
               MAILPIT_SMTP_HOST='127.0.0.1', MAILPIT_SMTP_PORT='1')
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'csrf_test_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    for family in ['identity', 'csrf'] + (['ctf'] if args.ui else []):
        migration, runtime = f'dvaia_{family}_migration', f'dvaia_{family}_runtime'
        database = f'dvaia_test_csrf_browser_route_{family}'
        for role in [migration, runtime]:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'], stdout=subprocess.DEVNULL)
        for kind, role in [('MIGRATION', migration), ('RUNTIME', runtime)]:
            env[f'PG_CSRF_BROWSER_ROUTE_{family.upper()}_{kind}_URL'] = f'postgresql://{quote(role)}@127.0.0.1:{port}/{database}'
    print(f'Owned CSRF browser route workspace: {workspace}', flush=True)
    with (root / 'result.log').open('w') as log:
        test_file = 'csrfRenderedUi.integration.test.js' if args.ui else 'csrfBrowserRoute.integration.test.js'
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap', '--test-concurrency=1',
                                  'tests/postgres/' + test_file],
                                 cwd=workspace, env=env, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            returncode = child.wait(timeout=330)
        finally:
            # The group includes the test worker and Chromium descendants.
            # Allow test cleanup first, then bound shutdown on failure/cancel.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
    print((root / 'result.log').read_text(), flush=True)
    if returncode:
        raise RuntimeError(f'CSRF browser route test failed ({returncode})')
finally:
    if container:
        run(docker + ['rm', '--force', container], stdout=subprocess.DEVNULL)
        remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$', '--format', '{{.Names}}'],
                        capture_output=True, text=True).stdout.strip()
        if remaining:
            raise RuntimeError('Owned container cleanup did not complete')
    if native_start_attempted:
        # A timed-out or failed `pg_ctl start` may still have launched the
        # postmaster. Always attempt owned-cluster shutdown once start was
        # requested, then verify that it is no longer running.
        try:
            subprocess.run(['pg_ctl', '-D', str(root / 'data'), '-m', 'fast', '-w', 'stop'],
                           env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60)
        except subprocess.TimeoutExpired:
            # Escalate only this exact owned data directory; never target a
            # host-wide PostgreSQL process name or port.
            subprocess.run(['pg_ctl', '-D', str(root / 'data'), '-m', 'immediate', '-w', 'stop'],
                           env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=20)
        status = subprocess.run(['pg_ctl', '-D', str(root / 'data'), 'status'], env=base_env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if status.returncode == 0:
            raise RuntimeError('Owned native PostgreSQL cleanup did not complete')
    print(f'Owned cluster cleanup complete; evidence retained: {root}', flush=True)
