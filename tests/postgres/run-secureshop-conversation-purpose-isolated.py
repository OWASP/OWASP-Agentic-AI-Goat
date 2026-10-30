#!/usr/bin/env python3
"""Single-use copied-source PostgreSQL 18 gate for reserved agents0013."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from native_source_provenance import verify_source_copy
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
OWNER = '/root/purpose_native_review'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin')
STAGED = {
    'db/postgres/workshop-migrations/secureshop_agents/0011_secureshop_mcp_trust.sql':
        'docs/modernization/drafts/secureshop-mcp-trust-agents.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql':
        'docs/modernization/drafts/secureshop-controlled-ssrf-agents.sql',
    'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql':
        'docs/modernization/drafts/secureshop-conversation-purpose-agents.sql',
}
TRACKED = [
    *STAGED.values(),
    'db/postgres/migrate.js',
    *[f'db/postgres/workshop-migrations/secureshop_agents/{name}' for name in (
        '0001_schema.sql', '0002_vectors.sql', '0003_import_history.sql',
        '0004_embedding_identity.sql', '0005_conversation_binding.sql',
        '0006_secureshop_turn_admission.sql',
        '0007_secureshop_conversation_generation_retirement.sql',
        '0008_secureshop_bound_persona_sessions.sql',
        '0009_secureshop_bound_persona_renewal.sql',
        '0010_secureshop_persona_inbox.sql',
    )],
    'server/database/postgres/secureshopBoundConversationsRepository.js',
    'server/database/postgres/secureshopConversationLifecycleRepository.js',
    'server/services/secureshopBoundTraceRecord.js',
    'server/services/secureshopConversationBinding.js',
    'server/services/secureshopConversationPurpose.js',
    'tests/postgres/native_source_provenance.py',
    'tests/postgres/sensitive_info_recovery_safety.py',
    'tests/postgres/secureshopConversationPurpose.integration.test.js',
    'tests/postgres/run-secureshop-conversation-purpose-isolated.py',
]

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
args = parser.parse_args()
if args.docker_host != EXPECTED_DOCKER:
    raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
grant_path = Path(args.grant_file).resolve()
if grant_path != (SOURCE / 'tasks/native-verification-slot.json').resolve():
    raise SystemExit('the durable repository grant file is required')
if any((SOURCE / destination).exists() for destination in STAGED):
    raise RuntimeError('a reserved agents0011-0013 migration is already registered; this draft qualifier is stale')

evidence = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-conversation-purpose-'))
os.chmod(evidence, 0o700)
workspace = evidence / 'source'
workspace.mkdir()
container = f'owasp-ai-goat-secureshop-conversation-purpose-{uuid.uuid4().hex[:12]}'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{NODE_BIN}:{base_env.get("PATH", "")}'
docker = ['docker', '--host', args.docker_host]
state = {'version': 1, 'owner': OWNER, 'grantId': args.grant_id,
         'dockerHost': args.docker_host, 'container': container, 'evidence': str(evidence),
         'launcherPid': os.getpid(), 'ownerHandle': None,
         'createdAt': datetime.now(timezone.utc).isoformat(), 'runStatus': 'preparing',
         'cleanup': None}
frozen_hashes = None

def write_state():
    pending = ownership_path.with_suffix('.json.pending')
    pending.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
    os.chmod(pending, 0o600)
    os.replace(pending, ownership_path)

def run(command, **kwargs):
    kwargs.setdefault('timeout', 90)
    return subprocess.run(command, check=True, env=kwargs.pop('env', base_env), **kwargs)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def exact_container_absence():
    listed = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^/{container}$',
        '--format', '{{.Names}}'], env=base_env, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, timeout=30)
    if listed.returncode != 0:
        raise RuntimeError('exact-name container query failed')
    return not listed.stdout.strip()

def ignored(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    suffixes = ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log')
    return [name for name in names if name in denied or name.startswith('.env')
            or any(name.endswith(suffix) for suffix in suffixes)]

write_state()
result_path.touch(mode=0o600)
child = None
creation_attempted = False
signal_gate = SignalGate()
signal.signal(signal.SIGTERM, signal_gate.handler)
signal.signal(signal.SIGINT, signal_gate.handler)

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            child.wait(timeout=5)

node_version = run([str(NODE_BIN / 'node'), '--version'], stdout=subprocess.PIPE,
                   text=True).stdout.strip()
if node_version != 'v26.8.2':
    raise RuntimeError('managed Node 26.8.2 is required')
state['nodeVersion'] = node_version
if not exact_container_absence():
    raise RuntimeError('owned container name unexpectedly already exists')

with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    source_hashes = {name: digest(SOURCE / name) for name in TRACKED}
    if (grant.get('grantId') != args.grant_id or grant.get('owner') != OWNER
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != EXPECTED_DOCKER
            or grant.get('sourceHashes') != source_hashes):
        raise RuntimeError('single-use purpose qualifier grant is absent, mismatched, or consumed')
    frozen_hashes = source_hashes
    grant.update({'status': 'consumed', 'consumedAt': datetime.now(timezone.utc).isoformat(),
                  'consumerPid': os.getpid(), 'ownerHandle': None, 'container': container,
                  'evidence': str(evidence), 'runStatus': 'preparing'})
    grant_file.seek(0)
    json.dump(grant, grant_file, indent=2, sort_keys=True)
    grant_file.write('\n')
    grant_file.truncate()
    grant_file.flush()
    os.fsync(grant_file.fileno())

for _ in range(600):
    with grant_path.open() as grant_file:
        fcntl.flock(grant_file.fileno(), fcntl.LOCK_SH)
        registered = json.load(grant_file)
    handle = registered.get('ownerHandle')
    if (registered.get('grantId') == args.grant_id
            and registered.get('consumerPid') == os.getpid()
            and isinstance(handle, int) and handle > 0 and handle != os.getpid()):
        state['ownerHandle'] = handle
        state['runStatus'] = 'owner_registered'
        write_state()
        break
    time.sleep(.1)
else:
    state['runStatus'] = 'owner_registration_failed'
    state['cleanup'] = {'containerAbsent': True, 'containerNeverStarted': True}
    write_state()
    raise RuntimeError('actual exec session owner handle was not registered before Docker')

for directory in ('server', 'db', 'tests', 'docs'):
    shutil.copytree(SOURCE / directory, workspace / directory, ignore=ignored)
(workspace / 'node_modules').symlink_to(SOURCE / 'node_modules', target_is_directory=True)
copied = verify_source_copy(SOURCE, workspace, TRACKED,
    granted=frozen_hashes)
for destination, draft in STAGED.items():
    target = workspace / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(workspace / draft, target)
    if digest(target) != copied[draft]:
        raise RuntimeError(f'staged migration differs from frozen draft: {destination}')
state['sourceSha256'] = copied
state['stagedMigrations'] = {destination: digest(workspace / destination) for destination in STAGED}
state['snapshotVerifiedBeforeDocker'] = True
write_state()

try:
    creation_attempted = True
    state['containerCreationAttempted'] = True
    write_state()
    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=purpose_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432',
        'postgres:18', '-c', 'shared_buffers=16MB', '-c', 'max_connections=32',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    state['runStatus'] = 'container_started'
    write_state()
    details = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE,
                             text=True).stdout)[0]
    if details.get('Mounts'):
        raise RuntimeError('owned PostgreSQL unexpectedly has host mounts')
    port = int(run(docker + ['port', container, '5432'], stdout=subprocess.PIPE,
                   text=True).stdout.strip().rsplit(':', 1)[1])
    for _ in range(120):
        ready = subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(port),
            '-U', 'purpose_test_admin', '-d', 'postgres', '-Atqc', 'SELECT 1'], env=base_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if ready.returncode == 0:
            break
        time.sleep(.25)
    else:
        raise RuntimeError('owned PostgreSQL did not become TCP SQL-ready')
    admin = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'purpose_test_admin',
             '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    migration_role = 'dvaia_secureshop_agents_migration'
    runtime_role = 'dvaia_secureshop_agents_runtime'
    for role in (migration_role, runtime_role):
        run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                           'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    urls = {}
    for variant in ('fresh', 'populated'):
        database = f'owasp_ai_goat_test_secureshop_purpose_{variant}'
        run(admin + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'],
            stdout=subprocess.DEVNULL)
        run(admin + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                           f'GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],
            stdout=subprocess.DEVNULL)
        urls[variant] = {
            'migration': f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
            'runtime': f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}',
        }
    env = dict(base_env, NODE_ENV='test', PLATFORM_DATABASE_ENGINE='postgres',
               WORKSHOP_DATABASE_ENGINE='postgres', PG_TEST_DISPOSABLE='yes',
               OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true')
    for variant in ('fresh', 'populated'):
        prefix = f'PG_SECURESHOP_CONVERSATION_PURPOSE_{variant.upper()}_'
        env[prefix + 'MIGRATION_URL'] = urls[variant]['migration']
        env[prefix + 'RUNTIME_URL'] = urls[variant]['runtime']
    with result_path.open('w') as log:
        os.chmod(result_path, 0o600)
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
            'tests/postgres/secureshopConversationPurpose.integration.test.js'], cwd=workspace,
            env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        state['testPid'] = child.pid
        state['runStatus'] = 'test_running'
        write_state()
        try:
            code = child.wait(timeout=90)
        except subprocess.TimeoutExpired:
            stop_child()
            raise RuntimeError('conversation purpose integration timed out')
    if code:
        raise RuntimeError(f'conversation purpose integration failed ({code})')
    state['resultSha256'] = digest(result_path)
    state['runStatus'] = 'passed'
    write_state()
except BaseException as error:
    state['runStatus'] = 'failed'
    state['errorType'] = type(error).__name__
    if result_path.exists():
        state['resultSha256'] = digest(result_path)
    write_state()
    raise
finally:
    signal_gate.protect_cleanup()
    errors = []
    remove_code = None
    absent = None
    try:
        stop_child()
    except Exception as error:
        errors.append(f'child:{type(error).__name__}')
    if creation_attempted:
        try:
            removed = subprocess.run(docker + ['rm', '-f', '-v', container], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            remove_code = removed.returncode
        except Exception as error:
            errors.append(f'remove:{type(error).__name__}')
    try:
        absent = exact_container_absence()
    except Exception as error:
        errors.append(f'absence:{type(error).__name__}')
    state['cleanup'] = {'removeExitCode': remove_code, 'containerAbsent': absent,
        'containerCleanupDebt': absent is not True, 'errors': errors,
        'signals': signal_gate.received, 'completedAt': datetime.now(timezone.utc).isoformat()}
    cleanup_failed = bool(errors or absent is not True or (creation_attempted and remove_code != 0))
    if state['runStatus'] == 'passed' and cleanup_failed:
        state['runStatus'] = 'failed'
        state['errorType'] = 'CleanupFailed'
    write_state()
    try:
        with grant_path.open('r+') as grant_file:
            fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
            grant = json.load(grant_file)
            if grant.get('grantId') == args.grant_id and grant.get('consumerPid') == os.getpid():
                grant.update({'runStatus': state['runStatus'],
                    'terminalAt': datetime.now(timezone.utc).isoformat(),
                    'cleanup': state['cleanup'], 'evidence': str(evidence),
                    'resultSha256': state.get('resultSha256'),
                    'ownershipSha256': digest(ownership_path)})
                grant_file.seek(0)
                json.dump(grant, grant_file, indent=2, sort_keys=True)
                grant_file.write('\n')
                grant_file.truncate()
                grant_file.flush()
                os.fsync(grant_file.fileno())
    except Exception:
        pass

print(evidence, flush=True)
if cleanup_failed:
    raise RuntimeError('owned qualifier cleanup is incomplete')
