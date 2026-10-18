#!/usr/bin/env python3
"""Single-use owned PG18 gate for the reviewed persona activation candidate."""
import argparse, fcntl, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER = '/root/secureshop_architecture'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')

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

evidence = Path(tempfile.mkdtemp(prefix='dvaia-secureshop-persona-activation-'))
os.chmod(evidence, 0o700)
workspace = evidence / 'source'
workspace.mkdir()
container = f'dvaia-secureshop-persona-activation-{uuid.uuid4().hex[:12]}'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{NODE_BIN}:{base_env.get("PATH", "")}'
docker = ['docker', '--host', args.docker_host]
state = {'owner': OWNER, 'grantId': args.grant_id, 'dockerHost': args.docker_host,
         'container': container, 'evidence': str(evidence), 'launcherPid': os.getpid(),
         'ownerHandle': None, 'createdAt': datetime.now(timezone.utc).isoformat(),
         'runStatus': 'preparing', 'cleanup': None}

def write_state():
    ownership_path.write_text(json.dumps(state, indent=2) + '\n')
    os.chmod(ownership_path, 0o600)

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

write_state()
result_path.touch()
os.chmod(result_path, 0o600)
child = None
creation_attempted = False
signal_gate = SignalGate()
signal.signal(signal.SIGTERM, signal_gate.handler)
signal.signal(signal.SIGINT, signal_gate.handler)

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            child.wait(timeout=5)

if run([str(NODE_BIN / 'node'), '--version'], stdout=subprocess.PIPE,
       text=True).stdout.strip() != 'v26.8.2':
    raise RuntimeError('managed Node 26.8.2 is required')
if not exact_container_absence():
    raise RuntimeError('owned container name unexpectedly already exists')

with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id or grant.get('owner') != OWNER
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != EXPECTED_DOCKER):
        raise RuntimeError('single-use persona activation grant is absent, mismatched, or consumed')
    grant.update({'status': 'consumed', 'consumedAt': datetime.now(timezone.utc).isoformat(),
      'launcherPid': os.getpid(), 'ownerHandle': None, 'container': container,
      'evidence': str(evidence), 'runStatus': 'preparing'})
    grant_file.seek(0); json.dump(grant, grant_file, indent=2); grant_file.write('\n')
    grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())

def register_owner():
    # Docker may start only after the orchestrator records the returned exec session.
    for _ in range(600):
        with grant_path.open() as grant_file:
            fcntl.flock(grant_file.fileno(), fcntl.LOCK_SH)
            registered = json.load(grant_file)
        handle = registered.get('ownerHandle')
        if (registered.get('grantId') == args.grant_id
                and registered.get('launcherPid') == os.getpid()
                and isinstance(handle, int) and handle > 0 and handle != os.getpid()):
            state['ownerHandle'] = handle
            state['runStatus'] = 'owner_registered'
            write_state()
            return
        time.sleep(.1)
    raise RuntimeError('actual exec session owner handle was not registered before Docker')

def ignore(_directory, names):
    denied = {'.git', 'node_modules', 'logs', 'uploads', 'sensitive_files', 'workshop_data',
      'vector-indexes', 'coverage', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
      any(name.endswith(suffix) for suffix in
        ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'))]

apply_script = """
const fs=require('node:fs');
const candidate=require('./docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const paths={application:'server/services/secureshopBoundApplication.js',composition:'server/services/secureshopBoundReviewComposition.js',curriculum:'server/config/secureshopCurriculum.js'};
const source=Object.fromEntries(Object.entries(paths).map(([key,value])=>[key,fs.readFileSync(value,'utf8')]));
const built=candidate.buildCandidates(source);
for(const [key,value] of Object.entries(paths))fs.writeFileSync(value,built[key]);
fs.copyFileSync('docs/modernization/drafts/secureshopPersonaInboxActivationPolicy.candidate.js','server/services/secureshopPersonaInboxActivationPolicy.js');
"""
tracked = [
  'docs/modernization/drafts/secureshopPersonaInboxActivationCandidate.js',
  'docs/modernization/drafts/secureshopPersonaInboxActivationPolicy.candidate.js',
  'db/postgres/migrate.js',
  'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql',
  'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql',
  'server/database/postgres/identityRepository.js',
  'server/database/postgres/workshopPlatformSeed.js',
  'server/database/postgres/secureshopAgentsDb.js',
  'server/database/postgres/secureshopReviewDb.js',
  'server/database/postgres/secureshopInitialization.js',
  'server/database/postgres/secureshopLaunchRepository.js',
  'server/database/postgres/secureshopPersonaInboxRepository.js',
  'server/services/secureshopBoundApplication.js',
  'server/services/secureshopBoundReviewComposition.js',
  'server/services/secureshopPersonaInboxActivationPolicy.js',
  'server/services/secureshopPersonaInboxAvailability.js',
  'server/services/secureshopPersonaInboxApplication.js',
  'server/services/secureshopPersonaInboxComposition.js',
  'server/services/secureshopBoundPersonaAuth.js',
  'server/services/secureshopCleanupComposition.js',
  'server/services/secureshopLaunchResetCoordinator.js',
  'server/services/postgresIdentityAdapter.js',
  'server/middleware/adminAuth.js',
  'server/middleware/postgresAdminAuth.js',
  'server/middleware/secureshopLaunch.js',
  'server/routes/secureshopPlatformLaunch.js',
  'server/routes/secureshop/boundGateway.js',
  'server/routes/secureshop/boundPersonaInbox.js',
  'server/config/secureshopCurriculum.js',
  'tests/postgres/secureshopPersonaActivation.integration.test.js',
  'tests/postgres/run-secureshop-persona-activation-isolated.py',
]

def prepare_workspace():
    for directory in ('server', 'db', 'tests', 'docs'):
        shutil.copytree(SOURCE / directory, workspace / directory, ignore=ignore)
    (workspace / 'client/build/secureshop-review-renderer').mkdir(parents=True)
    for artifact in (SOURCE / 'client/build/secureshop-review-renderer').iterdir():
        if artifact.is_file():
            shutil.copy2(artifact, workspace / 'client/build/secureshop-review-renderer' / artifact.name)
    (workspace / 'node_modules').symlink_to(SOURCE / 'node_modules', target_is_directory=True)
    run([str(NODE_BIN / 'node'), '-e', apply_script], cwd=workspace)
    inventory = set(tracked)
    for pattern in (
      'db/postgres/identity-migrations/*.sql',
      'db/postgres/workshop-migrations/secureshop/*.sql',
      'db/postgres/workshop-migrations/secureshop_agents/*.sql',
      'db/postgres/workshop-migrations/secureshop_review/*.sql',
      'server/agent-runtime/**/*.js',
      'server/database/postgres/identity*.js',
      'server/database/postgres/secureshop*.js',
      'server/services/secureshop*.js',
      'server/routes/secureshop/**/*.js',
    ):
        inventory.update(str(item.relative_to(workspace)) for item in workspace.glob(pattern)
          if item.is_file())
    state['nodeVersion'] = 'v26.8.2'
    state['sourceSha256'] = {name: digest(workspace / name) for name in sorted(inventory)}
    write_state()

cleanup_failed = False
try:
    register_owner()
    prepare_workspace()
    creation_attempted = True
    state['containerCreationAttempted'] = True
    write_state()
    run(docker + ['run', '--detach', '--name', container,
      '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
      '-e', 'POSTGRES_USER=persona_activation_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
      '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
      '-c', 'shared_buffers=16MB', '-c', 'max_connections=72', '-c', 'max_wal_size=24MB',
      '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    state['runStatus'] = 'container_started'; write_state()
    details = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE,
      text=True).stdout)[0]
    if details.get('Mounts'):
        raise RuntimeError('owned PostgreSQL unexpectedly has host mounts')
    port = int(run(docker + ['port', container, '5432'], stdout=subprocess.PIPE,
      text=True).stdout.strip().rsplit(':', 1)[1])
    for _ in range(120):
        ready = subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(port),
          '-U', 'persona_activation_admin', '-d', 'postgres', '-Atqc', 'SELECT 1'],
          env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if ready.returncode == 0: break
        time.sleep(.25)
    else:
        raise RuntimeError('owned PostgreSQL did not become TCP SQL-ready')
    admin = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'persona_activation_admin',
      '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    stores = [
      ('identity', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
      ('agents', 'dvaia_secureshop_agents_migration', 'dvaia_secureshop_agents_runtime'),
      ('review', 'dvaia_secureshop_review_migration', 'dvaia_secureshop_review_runtime'),
      ('commerce', 'dvaia_secureshop_migration', 'dvaia_secureshop_runtime'),
    ]
    for role in sorted({role for _, migration, runtime in stores for role in (migration, runtime)}):
        run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    urls = {}
    for store, migration_role, runtime_role in stores + [
      ('partial_agents', 'dvaia_secureshop_agents_migration', 'dvaia_secureshop_agents_runtime')]:
        database = f'dvaia_test_secureshop_persona_activation_{store}'
        run(admin + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
        run(admin + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role},{runtime_role}'],
            stdout=subprocess.DEVNULL)
        urls[store] = {
          'migration': f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
          'runtime': f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}',
        }
    env = dict(base_env, NODE_ENV='test', PLATFORM_DATABASE_ENGINE='postgres',
      WORKSHOP_DATABASE_ENGINE='postgres', SECURESHOP_ENABLED='true', PG_TEST_DISPOSABLE='yes',
      DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), JWT_SECRET='owned-persona-activation-secret-at-least-32-bytes')
    mapping = {'IDENTITY': 'identity', 'AGENTS': 'agents', 'REVIEW': 'review', 'COMMERCE': 'commerce'}
    standard = {
      'IDENTITY_DATABASE_URL': urls['identity']['runtime'],
      'IDENTITY_MIGRATION_DATABASE_URL': urls['identity']['migration'],
      'SECURESHOP_AGENTS_DATABASE_URL': urls['agents']['runtime'],
      'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL': urls['agents']['migration'],
      'SECURESHOP_REVIEW_DATABASE_URL': urls['review']['runtime'],
      'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL': urls['review']['migration'],
      'SECURESHOP_DATABASE_URL': urls['commerce']['runtime'],
      'SECURESHOP_MIGRATION_DATABASE_URL': urls['commerce']['migration'],
    }
    env.update(standard)
    for label, store in mapping.items():
        env[f'PG_SECURESHOP_PERSONA_ACTIVATION_{label}_MIGRATION_URL'] = urls[store]['migration']
        env[f'PG_SECURESHOP_PERSONA_ACTIVATION_{label}_RUNTIME_URL'] = urls[store]['runtime']
    env['PG_SECURESHOP_PERSONA_ACTIVATION_PARTIAL_AGENTS_MIGRATION_URL'] = urls['partial_agents']['migration']
    env['PG_SECURESHOP_PERSONA_ACTIVATION_PARTIAL_AGENTS_RUNTIME_URL'] = urls['partial_agents']['runtime']
    env.pop('SS_PERSONA_INBOX_READY', None)
    with result_path.open('w') as log:
        os.chmod(result_path, 0o600)
        child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
          'tests/postgres/secureshopPersonaActivation.integration.test.js'], cwd=workspace,
          env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        state['testPid'] = child.pid; state['runStatus'] = 'test_running'; write_state()
        try: code = child.wait(timeout=150)
        except subprocess.TimeoutExpired:
            stop_child()
            raise RuntimeError('persona activation integration timed out')
    if code:
        raise RuntimeError(f'persona activation integration failed ({code})')
    state['resultSha256'] = digest(result_path)
    state['runStatus'] = 'passed'
    write_state()
except BaseException as error:
    state['runStatus'] = 'failed'; state['errorType'] = type(error).__name__
    if result_path.exists():
        state['resultSha256'] = digest(result_path)
    if creation_attempted:
        try:
            details = json.loads(run(docker + ['inspect', container], stdout=subprocess.PIPE,
              text=True).stdout)[0]
            state['containerFailure'] = {'oomKilled': details['State'].get('OOMKilled'),
              'exitCode': details['State'].get('ExitCode')}
            logs = subprocess.run(docker + ['logs', '--tail', '80', container], env=base_env,
              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
            (evidence / 'container.log').write_text(logs.stdout)
            os.chmod(evidence / 'container.log', 0o600)
        except Exception as diagnostic:
            state['diagnosticError'] = type(diagnostic).__name__
    write_state()
    raise
finally:
    signal_gate.protect_cleanup()
    errors = []; remove_code = None; absent = None
    try: stop_child()
    except Exception as error: errors.append(f'child:{type(error).__name__}')
    if creation_attempted:
        try:
            removed = subprocess.run(docker + ['rm', '-f', '-v', container], env=base_env,
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            remove_code = removed.returncode
        except Exception as error: errors.append(f'remove:{type(error).__name__}')
    try: absent = exact_container_absence()
    except Exception as error: errors.append(f'absence:{type(error).__name__}')
    state['cleanup'] = {'removeExitCode': remove_code, 'containerAbsent': absent,
      'containerCleanupDebt': absent is not True, 'errors': errors,
      'signals': signal_gate.received, 'completedAt': datetime.now(timezone.utc).isoformat()}
    cleanup_failed = bool(errors or absent is not True or (creation_attempted and remove_code != 0))
    if state['runStatus'] == 'passed' and cleanup_failed:
        state['runStatus'] = 'failed'; state['errorType'] = 'CleanupFailed'
    write_state()
    try:
        with grant_path.open('r+') as grant_file:
            fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
            grant = json.load(grant_file)
            if grant.get('grantId') == args.grant_id:
                grant.update({'runStatus': state['runStatus'],
                  'terminalAt': datetime.now(timezone.utc).isoformat(),
                  'cleanup': state['cleanup'], 'evidence': str(evidence)})
                grant_file.seek(0); json.dump(grant, grant_file, indent=2); grant_file.write('\n')
                grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())
    except Exception: pass

print(evidence, flush=True)
if cleanup_failed:
    raise RuntimeError('owned qualifier cleanup is incomplete')
