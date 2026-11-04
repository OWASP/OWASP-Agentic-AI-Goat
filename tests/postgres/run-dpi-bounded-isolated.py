#!/usr/bin/env python3
"""Controlled bounded-DPI qualification in one newly owned local PostgreSQL container.

Never accepts application database URLs. Requires a cached PostgreSQL 18 image;
creates only two owned databases and always removes the exact labelled container.
No actor or Judge model is invoked: the Node suite injects controlled providers.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

SOURCE = Path(__file__).resolve().parents[2]
ROOT = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-dpi-bounded-'))
os.chmod(ROOT, 0o700)
DOCKER = shutil.which('docker')
NODE = shutil.which('node')
if not DOCKER or not NODE:
    raise SystemExit('Docker and Node must be installed')
DOCKER_ENV = {key: os.environ[key] for key in ('PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT') if key in os.environ}
TOKEN = uuid.uuid4().hex
NAME = 'owasp-ai-goat-dpi-bounded-' + TOKEN[:12]
LABEL = 'owasp-ai-goat.test.owner'
STATE = {'scope': 'controlled-bounded-dpi-only', 'root': str(ROOT), 'container': NAME,
         'owner': TOKEN, 'passed': False, 'cleanup': False, 'actualModelCalls': 0}
CONTAINER = None
CHILD = None

def interrupted(signum, _frame):
    raise RuntimeError('Owned qualification interrupted by signal ' + str(signum))

signal.signal(signal.SIGTERM, interrupted)

def command(args, **kwargs):
    return subprocess.run(args, check=True, env=DOCKER_ENV, timeout=kwargs.pop('timeout', 60), **kwargs)

def docker(*args, **kwargs):
    return command([DOCKER, *args], **kwargs)

def captured(*args):
    return docker(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

def persist():
    (ROOT / 'result.json').write_text(json.dumps(STATE, indent=2) + '\n')
    os.chmod(ROOT / 'result.json', 0o600)

def owned_group_present(pgid):
    listing = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,uid='], check=True,
                             stdout=subprocess.PIPE, text=True, timeout=5).stdout
    members = [line.split() for line in listing.splitlines() if len(line.split()) == 3
               and int(line.split()[1]) == pgid]
    if any(int(row[2]) != os.getuid() for row in members):
        raise RuntimeError('Refusing foreign process in owned qualification group')
    return bool(members)


def cleanup_owned_child(child):
    if child is None:
        return True
    # Only call for the Popen(start_new_session=True) created by this launcher.
    pgid = child.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while owned_group_present(pgid) and time.monotonic() < deadline:
        child.poll()
        time.sleep(.05)
    if owned_group_present(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    child.wait(timeout=5)
    deadline = time.monotonic() + 5
    while owned_group_present(pgid) and time.monotonic() < deadline:
        time.sleep(.05)
    if owned_group_present(pgid):
        raise RuntimeError('Owned Node process group remains after cleanup')
    return True


def stage():
    destination = ROOT / 'source'
    destination.mkdir(mode=0o700)
    excluded = {'node_modules', 'logs', 'uploads', 'vector-indexes', 'sensitive_files', 'workshop_data', '__pycache__'}
    def ignore(directory, entries):
        return [entry for entry in entries if entry in excluded or entry.startswith('.env')
                or entry in ('platform_secrets.json', 'secrets.env')
                or entry.endswith(('.db', '.db-wal', '.db-shm', '.sqlite', '.sqlite3', '.log', '.pyc'))]
    for relative in ('server', 'db', 'shared', 'scripts/lib'):
        src = SOURCE / relative
        if src.exists():
            shutil.copytree(src, destination / relative, ignore=ignore)
    (destination / 'tests/postgres').mkdir(parents=True)
    shutil.copy2(SOURCE / 'tests/postgres/dpiBoundedObjectives.integration.test.js', destination / 'tests/postgres/dpiBoundedObjectives.integration.test.js')
    for filename in ('package.json', 'package-lock.json'):
        shutil.copy2(SOURCE / filename, destination / filename)
    (destination / 'node_modules').symlink_to(SOURCE / 'node_modules', target_is_directory=True)
    return destination

try:
    STATE['daemon'] = captured('info', '--format', '{{.Name}}')
    image = json.loads(captured('image', 'inspect', 'postgres:18'))[0]
    STATE['imageId'] = image['Id']
    workspace = stage()
    CONTAINER = captured('run', '--detach', '--pull', 'never', '--name', NAME,
                         '--label', LABEL + '=' + TOKEN, '--memory', '768m', '--cpus', '2', '--pids-limit', '128',
                         '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
                         '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432', image['Id'],
                         '-c', 'shared_buffers=16MB', '-c', 'max_connections=30', '-c', 'max_wal_size=64MB', '-c', 'min_wal_size=32MB')
    info = json.loads(captured('inspect', CONTAINER))[0]
    if info['Id'] != CONTAINER or info['Config']['Labels'].get(LABEL) != TOKEN or info['Mounts']:
        raise RuntimeError('New container ownership/isolation mismatch')
    for _ in range(100):
        result = subprocess.run([DOCKER, 'exec', CONTAINER, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], env=DOCKER_ENV,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        if result.returncode == 0:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('Owned PostgreSQL did not become ready')
    port = int(captured('port', CONTAINER, '5432/tcp').rsplit(':', 1)[1])
    def sql(statement):
        docker('exec', CONTAINER, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', statement,
               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    sql('CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;')
    env = {'PATH': str(Path(NODE).resolve().parent) + ':/usr/bin:/bin', 'NODE_ENV': 'test', 'AI_PROVIDER': 'mock',
           'AWS_EC2_METADATA_DISABLED': 'true', 'PLATFORM_DATABASE_ENGINE': 'postgres', 'WORKSHOP_DATABASE_ENGINE': 'postgres',
           'PG_TEST_DISPOSABLE': 'yes', 'DPI_BOUNDED_NATIVE': '1', 'LOGS_DIR': str(ROOT / 'logs'),
           'OWASP_AI_GOAT_APP_DATA_ROOT': str(ROOT / 'appdata')}
    for variant in ('FRESH', 'POPULATED'):
        database = 'owasp_ai_goat_test_dpi_bounded_' + variant.lower()
        sql('CREATE DATABASE ' + database + ' OWNER dvaia_identity_migration')
        sql('REVOKE CONNECT ON DATABASE ' + database + ' FROM PUBLIC; GRANT CONNECT ON DATABASE ' + database + ' TO dvaia_identity_migration,dvaia_identity_runtime')
        for role in ('MIGRATION', 'RUNTIME'):
            env['DPI_BOUNDED_' + variant + '_' + role + '_URL'] = 'postgresql://dvaia_identity_' + role.lower() + '@127.0.0.1:' + str(port) + '/' + database
    with (ROOT / 'tests.log').open('w') as log:
        CHILD = subprocess.Popen([str(Path(NODE).resolve()), '--test', '--test-concurrency=1', 'tests/postgres/dpiBoundedObjectives.integration.test.js'],
                                 cwd=workspace, env=env, stdout=log, stderr=log, start_new_session=True)
        exit_code = CHILD.wait(timeout=180)
    STATE['exitCode'] = exit_code
    STATE['passed'] = exit_code == 0
    if exit_code:
        raise RuntimeError('Controlled PostgreSQL qualification failed; see ' + str(ROOT / 'tests.log'))
finally:
    cleanup_error = None
    try:
        STATE['childGroupAbsent'] = cleanup_owned_child(CHILD)
    except Exception as error:
        STATE['childGroupAbsent'] = False
        cleanup_error = error
    # Container retirement must run even if child/group retirement failed.
    try:
        if CONTAINER:
            info = json.loads(captured('inspect', CONTAINER))[0]
            if info['Id'] != CONTAINER or info['Config']['Labels'].get(LABEL) != TOKEN:
                raise RuntimeError('Refusing cleanup of changed container ownership')
            docker('rm', '--force', CONTAINER, stdout=subprocess.DEVNULL)
            remaining = captured('ps', '-a', '--filter', 'id=' + CONTAINER, '--format', '{{.ID}}')
            if remaining:
                raise RuntimeError('Owned container remains after cleanup')
        STATE['containerAbsent'] = True
    except Exception as error:
        STATE['containerAbsent'] = False
        cleanup_error = cleanup_error or error
    STATE['cleanup'] = STATE['childGroupAbsent'] and STATE['containerAbsent']
    if cleanup_error:
        STATE['passed'] = False
        STATE['cleanupError'] = str(cleanup_error)
    persist()
    print(json.dumps(STATE))
    if cleanup_error:
        raise cleanup_error
