#!/usr/bin/env python3
"""Single-use owned PG18 qualifier for the PostgreSQL account recovery."""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
args = parser.parse_args()
expected_docker_host = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
if args.docker_host != expected_docker_host:
    raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')

source = Path(__file__).resolve().parents[2]
grant_path = Path(args.grant_file).resolve()
if grant_path != (source / 'tasks/native-verification-slot.json').resolve():
    raise SystemExit('the durable repository grant file is required')
evidence = Path(tempfile.mkdtemp(prefix='dvaia-account-recovery-'))
workspace = evidence / 'source'
workspace.mkdir()
os.chmod(evidence, 0o700)
node_bin = Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{node_bin}:{base_env.get("PATH", "")}'
docker = ['docker', '--host', args.docker_host]
container = f'dvaia-account-recovery-{uuid.uuid4().hex[:12]}'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
state = {
    'owner': '/root/secureshop_architecture', 'container': container,
    'dockerHost': args.docker_host, 'evidence': str(evidence), 'grantId': args.grant_id,
    'launcherPid': os.getpid(), 'ownerHandle': None,
    'createdAt': datetime.now(timezone.utc).isoformat(), 'runStatus': 'preparing',
    'cleanup': None,
}

def write_state():
    ownership_path.write_text(json.dumps(state, indent=2) + '\n')
    os.chmod(ownership_path, 0o600)

write_state()

def run(command, **kwargs):
    kwargs.setdefault('timeout', 90)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id or grant.get('owner') != '/root/secureshop_architecture'
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != expected_docker_host):
        raise RuntimeError('single-use account recovery grant is absent, mismatched, or consumed')
    grant.update({'status': 'consumed', 'consumedAt': datetime.now(timezone.utc).isoformat(),
                  'launcherPid': os.getpid(), 'ownerHandle': None,
                  'container': container, 'evidence': str(evidence), 'runStatus': 'preparing'})
    grant_file.seek(0); json.dump(grant, grant_file, indent=2); grant_file.write('\n')
    grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())

# functions.exec learns its persistent session ID only after this process has
# started. The coordinator records that handle in the consumed grant. Docker
# remains untouched until this launcher observes the distinct numeric handle.
for _ in range(600):
    with grant_path.open() as grant_file:
        fcntl.flock(grant_file.fileno(), fcntl.LOCK_SH)
        registered = json.load(grant_file)
    owner_handle = registered.get('ownerHandle')
    if (registered.get('grantId') == args.grant_id
            and registered.get('launcherPid') == os.getpid()
            and isinstance(owner_handle, int) and owner_handle > 0
            and owner_handle != os.getpid()):
        state['ownerHandle'] = owner_handle
        state['runStatus'] = 'owner_registered'
        write_state()
        break
    time.sleep(.1)
else:
    state['runStatus'] = 'owner_registration_failed'
    state['cleanup'] = {'removeExitCode': None, 'containerAbsent': True,
                        'completedAt': datetime.now(timezone.utc).isoformat()}
    write_state()
    with grant_path.open('r+') as grant_file:
        fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
        failed_grant = json.load(grant_file)
        if failed_grant.get('grantId') == args.grant_id and failed_grant.get('launcherPid') == os.getpid():
            failed_grant.update({'runStatus': state['runStatus'], 'cleanup': state['cleanup'],
                                 'terminalAt': datetime.now(timezone.utc).isoformat()})
            grant_file.seek(0); json.dump(failed_grant, grant_file, indent=2); grant_file.write('\n')
            grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())
    raise RuntimeError('actual exec session owner handle was not registered before launch')

child = None
started = False

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
signal.signal(signal.SIGINT, interrupted)

def ignore(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env')
            or any(name.endswith(suffix) for suffix in ('.db', '.db-wal', '.db-shm', '.log'))]

for directory in ('server', 'db', 'tests', 'scripts'):
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)
tracked = [
    'server/database/postgres/identityRepository.js',
    'scripts/admin/reset-auth-defaults.js',
    'tests/accountRecoveryCli.test.js',
    'tests/postgres/accountRecovery.integration.test.js',
    'tests/postgres/run-account-recovery-isolated.py',
]
state['sourceHashes'] = {name: hashlib.sha256((workspace / name).read_bytes()).hexdigest() for name in tracked}
state['nodeVersion'] = run(['node', '--version'], stdout=subprocess.PIPE, text=True).stdout.strip()
write_state()

try:
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=account_recovery_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=24',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True
    state['runStatus'] = 'container_started'
    inspect = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE, text=True).stdout)[0]
    state['containerId'] = inspect['Id']
    state['ownedMounts'] = inspect.get('Mounts', [])
    write_state()
    port = None
    for _ in range(120):
        inspected = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE, text=True).stdout)[0]
        binding = inspected.get('NetworkSettings', {}).get('Ports', {}).get('5432/tcp')
        if binding: port = binding[0]['HostPort']
        if port:
            ready = subprocess.run(['pg_isready', '-h', '127.0.0.1', '-p', str(port),
                '-U', 'account_recovery_admin', '-d', 'postgres'], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0: break
        time.sleep(.25)
    else: raise RuntimeError('owned PostgreSQL did not become TCP ready')

    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'account_recovery_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    run(psql + ['-c', "CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;"])
    database = 'dvaia_test_account_recovery'
    run(psql + ['-c', f'CREATE DATABASE {database} OWNER dvaia_identity_migration'])
    run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_identity_migration,dvaia_identity_runtime'])

    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
               DVAIA_ISOLATED_TEST_WORKSPACE=str(evidence),
               PG_ACCOUNT_RECOVERY_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}',
               PG_ACCOUNT_RECOVERY_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}')
    state['runStatus'] = 'running'; write_state()
    with result_path.open('w') as log:
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
            'tests/postgres/accountRecovery.integration.test.js'], cwd=workspace,
            env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        state['testPid'] = child.pid; write_state()
        exit_code = child.wait(timeout=60)
    state['testExitCode'] = exit_code
    if exit_code != 0: raise RuntimeError(f'native test exited {exit_code}')
    state['runStatus'] = 'passed'
except BaseException as error:
    state['runStatus'] = 'failed'; state['errorType'] = type(error).__name__
    stop_child()
    if started:
        try:
            details = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE, text=True).stdout)[0]
            state['containerStateBeforeCleanup'] = {
                'status': details.get('State', {}).get('Status'),
                'exitCode': details.get('State', {}).get('ExitCode'),
                'oomKilled': details.get('State', {}).get('OOMKilled'),
            }
            (evidence / 'docker.log').write_bytes(run(docker + ['logs', container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout)
        except Exception as inspect_error: state['inspectErrorType'] = type(inspect_error).__name__
    raise
finally:
    if result_path.exists():
        state['resultSha256'] = hashlib.sha256(result_path.read_bytes()).hexdigest()
    cleanup_rc = None
    if started:
        cleanup_rc = subprocess.run(docker + ['rm', '-f', '-v', container], env=base_env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    absent = subprocess.run(docker + ['inspect', container], env=base_env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    state['cleanup'] = {'removeExitCode': cleanup_rc, 'containerAbsent': absent,
                        'completedAt': datetime.now(timezone.utc).isoformat()}
    write_state()
    try:
        with grant_path.open('r+') as grant_file:
            fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
            grant = json.load(grant_file)
            if grant.get('grantId') == args.grant_id:
                grant.update({'runStatus': state['runStatus'], 'terminalAt': datetime.now(timezone.utc).isoformat(),
                              'cleanup': state['cleanup'], 'evidence': str(evidence)})
                grant_file.seek(0); json.dump(grant, grant_file, indent=2); grant_file.write('\n')
                grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())
    except Exception: pass

print(str(evidence))
