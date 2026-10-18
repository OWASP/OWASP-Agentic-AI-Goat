#!/usr/bin/env python3
"""One-use owned PG18 + strict CodeBot sidecar + llama3.1:8b qualifier."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sensitive_info_recovery_safety import SignalGate

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER = '/root/startup_regression_repair'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path.home() / '.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin'
PREFIX = {}
REVIEWED_HIDDEN_TEACHING_FIXTURES = (
    'sidecars/sandbox-runner/labfs/opt/app/config/.env',
)
STATIC_TRACKED = [
    'package.json', 'package-lock.json',
    'tests/postgres/run-codebot-owned-workflow-isolated.py',
    'tests/postgres/codeBotLiveWorkflow.integration.test.js',
    'tests/postgres/codeBotProductionHttp.integration.test.js',
    'tests/postgres/sensitive_info_recovery_safety.py',
    'server/routes/supplyChainWorkshop.js',
    'server/services/supplyChainWorkshopAgent.js',
    'server/services/supplyChain/codeBotExecutionBoundary.js',
    'server/services/supplyChain/codeBotSandboxRuntime.js',
    'server/agent-runtime/codeBotGraph.js',
    'server/agent-runtime/codeBotJudge.js',
    'server/agent-runtime/codeBotRequestJournal.js',
    'server/agent-runtime/runCoordinator.js',
    'server/agent-runtime/postgresRunLedger.js',
    'server/agent-runtime/ownerWorkflowRoutes.js',
    'server/services/postgresIdentityAdapter.js',
    'server/services/platformSigningConfiguration.js',
    'server/database/postgres/identityRepository.js',
    'server/database/postgres/supplyChainWorkshopDb.js',
    'server/data/supplyChainSolutions.js',
    'sidecars/sandbox-runner/Dockerfile',
    'sidecars/sandbox-runner/package.json',
    'sidecars/sandbox-runner/index.js',
    'sidecars/sandbox-runner/entrypoint.sh',
    'sidecars/sandbox-runner/mcpTargets.js',
    'sidecars/sandbox-runner/ownedTargetApi.js',
    'sidecars/sandbox-runner/mcpSeccompFilter.c',
    'sidecars/sandbox-runner/mcpSeccompProbe.c',
    'scripts/render-mcp-sandbox-apparmor.js',
    *PREFIX.keys(),
]

def literal_dependencies(entries):
    """Collect local literal require() edges used by the mounted qualifier."""
    require_pattern = re.compile(r"require\(\s*['\"](\.[^'\"]+)['\"]\s*\)")
    found = set(entries);queue = list(entries)
    while queue:
        relative = queue.pop()
        source = SOURCE / relative
        if source.suffix != '.js' or not source.is_file(): continue
        for requested in require_pattern.findall(source.read_text()):
            base = (source.parent / requested)
            candidates = [base, Path(str(base) + '.js'), Path(str(base) + '.json'), base / 'index.js']
            dependency = next((candidate for candidate in candidates if candidate.is_file()), None)
            if dependency is None: continue
            try: name = str(dependency.resolve().relative_to(SOURCE.resolve()))
            except ValueError: raise RuntimeError(f'local dependency escaped source: {requested}')
            if name not in found: found.add(name);queue.append(name)
    return found

TRACKED = sorted(literal_dependencies(STATIC_TRACKED)
    | {str(path.relative_to(SOURCE)) for path in (SOURCE / 'db/postgres/identity-migrations').glob('*.sql')}
    | {str(path.relative_to(SOURCE)) for path in (SOURCE / 'sidecars/sandbox-runner').rglob('*')
       if path.is_file() and '__pycache__' not in path.parts})

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host')
parser.add_argument('--grant-file')
parser.add_argument('--grant-id')
parser.add_argument('--print-source-manifest', action='store_true')
parser.add_argument('--node', default=str(NODE_BIN / 'node'))
parser.add_argument('--scope', choices=['all','representative'], default='all')
parser.add_argument('--readiness-only', action='store_true')
parser.add_argument('--http-wiring-only', action='store_true')
args = parser.parse_args()
node_path = Path(args.node).expanduser().resolve()
if node_path.name != 'node' or not node_path.is_file():
    parser.error('An existing managed Node executable is required')
NODE_BIN = node_path.parent
if args.readiness_only and args.http_wiring_only:
    parser.error('--readiness-only and --http-wiring-only are mutually exclusive')
if args.print_source_manifest:
    print(json.dumps({name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
                      for name in TRACKED}, indent=2, sort_keys=True))
    raise SystemExit(0)
if not args.docker_host or not args.grant_file or not args.grant_id:
    parser.error('--docker-host, --grant-file, and --grant-id are required for a native run')
if args.docker_host != EXPECTED_DOCKER:
    raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
grant_path = Path(args.grant_file).resolve()
if grant_path != (SOURCE / 'tasks/native-verification-slot.json').resolve():
    raise SystemExit('the durable repository grant file is required')

evidence_parent = Path.home() / '.dvaia' / 'native-verification'
evidence_parent.mkdir(parents=True, exist_ok=True);os.chmod(evidence_parent, 0o700)
evidence = Path(tempfile.mkdtemp(prefix='dvaia-codebot-owned-', dir=evidence_parent));os.chmod(evidence, 0o700)
workspace = evidence / 'source'
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log';result_path.touch();os.chmod(result_path, 0o600)
build_path = evidence / 'sandbox-build.log';build_path.touch();os.chmod(build_path, 0o600)
suffix = uuid.uuid4().hex[:12]
containers = {'postgres': f'dvaia-codebot-pg-{suffix}', 'sandbox': f'dvaia-codebot-sandbox-{suffix}'}
image = f'dvaia-codebot-sandbox-node26:{suffix}'
profile_name = f'dvaia-mcp-sandbox-{suffix}'
profile_path = evidence / f'{profile_name}.apparmor'
ssh_config = Path.home() / '.colima/_lima/colima-dvaia-pg-verify/ssh.config'
ssh_host = 'lima-colima-dvaia-pg-verify'
remote_dir = f'/tmp/{profile_name}'
remote_profile = f'{remote_dir}/policy.apparmor'
remote_marker = f'{remote_dir}/owner'
remote_owner = secrets.token_hex(64)
local_marker = evidence / 'apparmor-owner';local_marker.write_text(remote_owner);os.chmod(local_marker, 0o600)
ssh = ['ssh', '-F', str(ssh_config), ssh_host, '--']
scp = ['scp', '-F', str(ssh_config)]
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{NODE_BIN}:{base_env.get("PATH", "")}'
docker = ['docker', '--host', args.docker_host]
gate = SignalGate();signal.signal(signal.SIGTERM, gate.handler);signal.signal(signal.SIGINT, gate.handler)
child = None
started = []
creation_attempted = set()
image_build_attempted = False
remote_creation_attempted = False
remote_owned = False
profile_load_attempted = False

def now(): return datetime.now(timezone.utc).isoformat()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def public_error(error): return re.sub(r'(https?://[^\s?]+)\?[^\s]+', r'\1?[redacted]', str(error))
def atomic_json(path, value):
    pending = path.with_suffix(path.suffix + f'.{os.getpid()}.pending')
    with pending.open('w') as output:
        os.chmod(pending, 0o600)
        output.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
        output.flush();os.fsync(output.fileno())
    os.replace(pending, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)

def acquire_lock(path, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try: path.mkdir(mode=0o700);return
        except FileExistsError:
            if time.monotonic() >= deadline: raise RuntimeError('native verification grant lock is unavailable')
            time.sleep(.02)

def run(command, **kwargs):
    kwargs.setdefault('timeout', 180)
    return subprocess.run(command, check=True, env=kwargs.pop('env', base_env), **kwargs)

state = {'version': 1, 'owner': OWNER, 'grantId': args.grant_id,
         'dockerHost': args.docker_host, 'launcherPid': os.getpid(), 'consumerPid': os.getpid(),
         'ownerHandle': None, 'evidence': str(evidence), 'containers': containers, 'image': image,
         'status': 'preparing', 'createdAt': now(), 'cleanup': None,
         'apparmor': {'profileName': profile_name, 'remoteDirectory': remote_dir,
                      'loaded': False, 'loadVerified': False}}
def persist():
    atomic_json(ownership_path, state)
persist()

def exact_absence(name):
    query = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^/{name}$', '--format', '{{.Names}}'],
                           env=base_env, capture_output=True, text=True, timeout=30)
    if query.returncode != 0: raise RuntimeError('exact-name container query failed')
    return not query.stdout.strip()

def image_absence():
    query = subprocess.run(docker + ['images', '--filter', f'reference={image}', '--format', '{{.Repository}}:{{.Tag}}'],
                           env=base_env, capture_output=True, text=True, timeout=30)
    if query.returncode != 0: raise RuntimeError('exact image query failed')
    return not query.stdout.strip()

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL);child.wait(timeout=5)

def ignored(_directory, names):
    denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
              'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env')
            or any(name.endswith(suffix) for suffix in ('.db', '.db-wal', '.db-shm', '.sqlite', '.sqlite3', '.log'))]

def prepare_source(expected):
    for name in TRACKED:
        source = SOURCE / name
        if not source.is_file(): raise RuntimeError(f'tracked source is unavailable: {name}')
        if expected.get(name) != digest(source): raise RuntimeError(f'granted source hash changed: {name}')
    for directory in ('server', 'db', 'tests', 'docs', 'sidecars', 'scripts'):
        shutil.copytree(SOURCE / directory, workspace / directory, ignore=ignored)
    shutil.copy2(SOURCE / 'package.json', workspace / 'package.json')
    shutil.copy2(SOURCE / 'package-lock.json', workspace / 'package-lock.json')
    # The broad copy deliberately excludes application .env files. Restore only
    # the reviewed synthetic sidecar fixture whose literal bytes are grant-pinned.
    for name in REVIEWED_HIDDEN_TEACHING_FIXTURES:
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, target)
    (workspace / 'node_modules').symlink_to(SOURCE / 'node_modules', target_is_directory=True)
    missing = [name for name in TRACKED if not (workspace / name).is_file()]
    if missing:
        raise RuntimeError(f'copied CodeBot source inventory is incomplete: {missing}')
    for source, target in PREFIX.items():
        target_path = workspace / target
        if target_path.exists(): raise RuntimeError(f'draft target already registered: {target}')
        shutil.copy2(workspace / source, target_path)
    copied = {name: digest(workspace / name) for name in TRACKED}
    if copied != expected: raise RuntimeError('copied CodeBot source does not match granted bytes')
    staged = {target: digest(workspace / target) for target in PREFIX.values()}
    for source, target in PREFIX.items():
        if staged[target] != expected[source]: raise RuntimeError(f'staged migration changed: {target}')
    state.update(sourceSha256=copied, stagedMigrationSha256=staged)
    persist()

def consume_grant():
    lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
    acquire_lock(lock)
    try:
        grant = json.loads(grant_path.read_text())
        expected = grant.get('sourceHashes')
        if grant.get('grantId') != args.grant_id or grant.get('owner') != OWNER \
                or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1 \
                or grant.get('dockerHost') != EXPECTED_DOCKER or not isinstance(expected, dict) \
                or set(expected) != set(TRACKED):
            raise RuntimeError('exact single-use CodeBot native grant is absent or mismatched')
        grant.update(status='consumed', runStatus='preparing', consumedAt=now(), consumerPid=os.getpid(),
                     launcherPid=os.getpid(), ownerHandle=None, evidence=str(evidence),
                     containers=containers, image=image)
        atomic_json(grant_path, grant)
        return expected
    finally: lock.rmdir()

def register_owner():
    for _ in range(600):
        with grant_path.open() as source:
            fcntl.flock(source.fileno(), fcntl.LOCK_SH);grant = json.load(source)
        handle = grant.get('ownerHandle')
        if grant.get('grantId') == args.grant_id and grant.get('consumerPid') == os.getpid() \
                and isinstance(handle, int) and handle > 0 and handle != os.getpid():
            state.update(ownerHandle=handle, status='owner_registered');persist();return
        time.sleep(.1)
    raise RuntimeError('actual exec session owner handle was not registered before Docker')

def update_grant():
    lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
    acquire_lock(lock)
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('grantId') == args.grant_id and grant.get('consumerPid') == os.getpid():
            grant.update(runStatus=state['status'], terminalAt=now(), cleanup=state['cleanup'], evidence=str(evidence))
            atomic_json(grant_path, grant)
        else: raise RuntimeError('consumed CodeBot grant changed before terminal update')
    finally: lock.rmdir()

def capture_failure_diagnostics():
    diagnostics = {}
    for key, name in containers.items():
        if name not in creation_attempted: continue
        item = {}
        try:
            details = json.loads(run(docker + ['inspect', name], capture_output=True, text=True, timeout=20).stdout)[0]
            item['inspect'] = {
                'id': details.get('Id'), 'name': details.get('Name'),
                'state': {field: details.get('State', {}).get(field)
                          for field in ('Status', 'Running', 'OOMKilled', 'ExitCode')},
                'mounts': [{'type': mount.get('Type'), 'destination': mount.get('Destination')}
                           for mount in details.get('Mounts') or []],
                'tmpfs': sorted((details.get('HostConfig', {}).get('Tmpfs') or {}).keys()),
            }
        except Exception as error: item['inspectError'] = type(error).__name__
        try:
            result = subprocess.run(docker + ['logs', '--tail', '200', name], env=base_env,
                                    capture_output=True, text=True, timeout=20)
            log_path = evidence / f'{key}-container.log'
            log_path.write_text((result.stdout + result.stderr)[-131072:]);os.chmod(log_path, 0o600)
            item['logSha256'] = digest(log_path);item['logExitCode'] = result.returncode
        except Exception as error: item['logError'] = type(error).__name__
        diagnostics[key] = item
    state['failureDiagnostics'] = diagnostics

failed = None
try:
    state['nodeVersion'] = run([str(NODE_BIN / 'node'), '--version'], capture_output=True, text=True).stdout.strip()
    if state['nodeVersion'] != 'v26.9.0':
        raise RuntimeError('managed Node 26.9.0 is required')
    expected = consume_grant();register_owner();prepare_source(expected)
    if not ssh_config.is_file(): raise RuntimeError('exact Colima verification SSH config is required')
    run([str(NODE_BIN / 'node'), str(workspace / 'scripts/render-mcp-sandbox-apparmor.js'),
         str(workspace / 'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),
         str(profile_path), profile_name], timeout=30)
    os.chmod(profile_path, 0o600)
    profile_query = subprocess.run(ssh + ['sudo', 'grep', '-F', profile_name,
        '/sys/kernel/security/apparmor/profiles'], env=base_env, capture_output=True, text=True, timeout=20)
    if profile_query.returncode != 1 or profile_query.stdout.strip():
        raise RuntimeError('owned AppArmor profile unexpectedly exists before launch')
    remote_query = subprocess.run(ssh + ['test', '-e', remote_dir], env=base_env,
                                  capture_output=True, text=True, timeout=20)
    if remote_query.returncode != 1: raise RuntimeError('owned remote policy directory unexpectedly exists')
    remote_creation_attempted = True
    run(ssh + ['mkdir', '-m', '0700', '--', remote_dir], timeout=20);remote_owned = True
    run(scp + [str(local_marker), f'{ssh_host}:{remote_marker}'], timeout=20)
    if run(ssh + ['cat', '--', remote_marker], capture_output=True, text=True, timeout=20).stdout != remote_owner:
        raise RuntimeError('owned remote AppArmor marker differs')
    run(scp + [str(profile_path), f'{ssh_host}:{remote_profile}'], timeout=30)
    run(ssh + ['chmod', '0600', remote_profile], timeout=20)
    run(ssh + ['sudo', 'apparmor_parser', '--skip-kernel-load', remote_profile], timeout=30)
    profile_load_attempted = True
    run(ssh + ['sudo', 'apparmor_parser', '-r', remote_profile], timeout=30)
    label = run(ssh + ['sudo', 'grep', '-F', profile_name,
        '/sys/kernel/security/apparmor/profiles'], capture_output=True, text=True, timeout=20).stdout
    if f'{profile_name} (enforce)' not in label:
        raise RuntimeError('owned AppArmor profile did not load in enforce mode')
    state['apparmor'].update(loaded=True, loadVerified=True);persist()
    daemon = json.loads(run(docker + ['info', '--format', '{{json .}}'], capture_output=True, text=True, timeout=30).stdout)
    if daemon.get('Name') != 'colima-dvaia-pg-verify' or daemon.get('Architecture') != 'aarch64':
        raise RuntimeError('exact Colima verification daemon identity is required')
    if not all(exact_absence(name) for name in containers.values()) or not image_absence():
        raise RuntimeError('owned native resources unexpectedly exist before launch')
    state['status'] = 'building_sandbox';image_build_attempted = True;state['imageBuildAttempted'] = True;persist()
    with build_path.open('w') as log:
        run(docker + ['build', '--tag', image, str(workspace / 'sidecars/sandbox-runner')],
            stdout=log, stderr=subprocess.STDOUT, timeout=600)
    state['sandboxBuildSha256'] = digest(build_path);persist()
    if not args.readiness_only:
        creation_attempted.add(containers['postgres']);state['containerCreationAttempted'] = sorted(creation_attempted);persist()
        run(docker + ['run', '--detach', '--name', containers['postgres'],
            '--tmpfs', '/var/lib/postgresql:rw,size=536870912', '-e', 'POSTGRES_USER=codebot_admin',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p', '127.0.0.1::5432', 'postgres:18', '-c', 'shared_buffers=16MB',
            '-c', 'max_connections=60', '-c', 'max_wal_size=32MB', '-c', 'min_wal_size=4MB'],
            stdout=subprocess.DEVNULL);started.append(containers['postgres'])
    creation_attempted.add(containers['sandbox']);state['containerCreationAttempted'] = sorted(creation_attempted);persist()
    run(docker + ['run', '--detach', '--name', containers['sandbox'],
        '--security-opt', 'seccomp=unconfined', '--security-opt', f'apparmor={profile_name}',
        '-p', '127.0.0.1::8090', image], stdout=subprocess.DEVNULL)
    started.append(containers['sandbox']);state['status'] = 'containers_started';persist()
    for key, name in containers.items():
        if name not in started: continue
        details = json.loads(run(docker + ['inspect', name], capture_output=True, text=True).stdout)[0]
        mounts = details.get('Mounts') or []
        if any(mount.get('Type') != 'tmpfs' for mount in mounts):
            raise RuntimeError(f'{name} unexpectedly has a host-backed mount')
        destinations = {mount.get('Destination') for mount in mounts if mount.get('Type') == 'tmpfs'}
        configured_tmpfs = set((details.get('HostConfig', {}).get('Tmpfs') or {}).keys())
        expected_tmpfs = {'/var/lib/postgresql'} if key == 'postgres' else set()
        if destinations | configured_tmpfs != expected_tmpfs:
            raise RuntimeError(f'{name} has an unexpected tmpfs configuration')
        security_options = set(details.get('HostConfig', {}).get('SecurityOpt') or [])
        cap_add = details.get('HostConfig', {}).get('CapAdd') or []
        if key == 'sandbox' and (security_options != {'seccomp=unconfined', f'apparmor={profile_name}'} or cap_add):
            raise RuntimeError('sandbox AppArmor or capability boundary differs')
        state.setdefault('mountAudit', {})[key] = {
            'hostBackedMounts': 0, 'tmpfsDestinations': sorted(destinations | configured_tmpfs),
            **({'securityOptions': sorted(security_options), 'capAdd': cap_add} if key == 'sandbox' else {}),
        }
    persist()
    sandbox_port = int(run(docker + ['port', containers['sandbox'], '8090'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
    pg_port = None
    if not args.readiness_only:
        pg_port = int(run(docker + ['port', containers['postgres'], '5432'], capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1])
        for _ in range(120):
            probe = subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'codebot_admin',
                                    '-d', 'postgres', '-Atqc', 'SELECT 1'], env=base_env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0: break
            time.sleep(.25)
        else: raise RuntimeError('owned PostgreSQL did not become TCP SQL-ready')
    runner_health = None
    for _ in range(120):
        probe = subprocess.run([str(NODE_BIN / 'node'), '-e',
            f"fetch('http://127.0.0.1:{sandbox_port}/health').then(r=>r.json()).then(x=>{{console.log(JSON.stringify(x));process.exit(x.codebotAvailable?0:2)}}).catch(()=>process.exit(3))"],
            env=base_env, capture_output=True, text=True, timeout=3)
        if probe.stdout.strip():
            try: runner_health = json.loads(probe.stdout)
            except json.JSONDecodeError: pass
        if probe.returncode == 0:
            break
        time.sleep(.25)
    state['runnerHealth'] = runner_health;persist()
    if not runner_health or runner_health.get('codebotIsolation') != 'bwrap-codebot-v1':
        raise RuntimeError('strict CodeBot sandbox did not become ready')
    if args.readiness_only:
        result_path.write_text(json.dumps({'status': 'pass', 'scope': 'strict_readiness',
                                           'runnerHealth': runner_health}, sort_keys=True) + '\n')
        os.chmod(result_path, 0o600)
    else:
        admin = ['psql', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'codebot_admin',
                 '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        for role in ('dvaia_identity_migration', 'dvaia_identity_runtime',
                     'dvaia_supply_chain_migration', 'dvaia_supply_chain_runtime'):
            run(admin + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
                stdout=subprocess.DEVNULL)
        wiring = args.http_wiring_only
        env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres',
                   SANDBOX_RUNNER_URL=f'http://127.0.0.1:{sandbox_port}', CODEBOT_SANDBOX_RUNNER_URL=f'http://127.0.0.1:{sandbox_port}', CODEBOT_OWNED_EXECUTION_ENABLED='true', CODEBOT_LIVE_SCOPE=args.scope, AWS_EC2_METADATA_DISABLED='true',
                   PG_LIVE_ADMIN_URL=f'postgresql://codebot_admin@127.0.0.1:{pg_port}/postgres',
                   LOGS_DIR=str(evidence / 'logs'), DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
                   **({'RUN_CODEBOT_HTTP_WIRING': '1', 'CODEBOT_HTTP_ISOLATED': '1',
                       'CODEBOT_WIRING_EVIDENCE_SCOPE': 'deterministic_http_only',
                       'CODEBOT_WIRING_ATTESTED_ISOLATION': 'bwrap-codebot-v1', 'AI_PROVIDER': 'mock'} if wiring else {
                       'RUN_LIVE_CODEBOT_WORKFLOW': '1', 'CODEBOT_LIVE_ISOLATED': '1', 'AI_PROVIDER': 'ollama',
                       'OLLAMA_BASE_URL': 'http://127.0.0.1:11434', 'OLLAMA_MODEL': 'llama3.1:8b'}))
        qualifier = ('tests/postgres/codeBotProductionHttp.integration.test.js' if wiring
                     else 'tests/postgres/codeBotLiveWorkflow.integration.test.js')
        with result_path.open('w') as output:
            child = subprocess.Popen([str(NODE_BIN / 'node'), '--test', '--test-reporter=tap',
                qualifier], cwd=workspace, env=env,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            state.update(status='test_running', testPid=child.pid, postgresPort=pg_port,
                         sandboxPort=sandbox_port, runnerHealth=runner_health,
                         scope='deterministic_http_only' if wiring else ('actual_model_representative_transform_and_sibling' if args.scope=='representative' else 'actual_model_six_objectives'));persist()
            try: code = child.wait(timeout=420)
            except subprocess.TimeoutExpired: stop_child();raise RuntimeError('CodeBot native qualifier timed out')
        if code != 0: raise RuntimeError(f'CodeBot native qualifier failed ({code})')
    state.update(status='passed', resultSha256=digest(result_path));persist()
except BaseException as error:
    failed = error
    capture_failure_diagnostics()
    state.update(status='failed', errorType=type(error).__name__, error=public_error(error),
                 resultSha256=digest(result_path));persist()
finally:
    gate.protect_cleanup();errors = []
    try: stop_child()
    except Exception as error: errors.append(f'child:{type(error).__name__}')
    cleanup = {}
    for key, name in reversed(list(containers.items())):
        remove = None
        if name in creation_attempted:
            try: remove = subprocess.run(docker + ['rm', '-f', '-v', name], env=base_env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30).returncode
            except Exception as error: errors.append(f'{key}Remove:{type(error).__name__}')
        try: absent = exact_absence(name)
        except Exception as error: absent = None;errors.append(f'{key}Absence:{type(error).__name__}')
        cleanup[key] = {'removeExitCode': remove, 'exactAbsent': absent}
    image_remove = None
    if image_build_attempted:
        try: image_remove = subprocess.run(docker + ['image', 'rm', '-f', image], env=base_env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode
        except Exception as error: errors.append(f'imageRemove:{type(error).__name__}')
    try: image_absent = image_absence()
    except Exception as error: image_absent = None;errors.append(f'imageAbsence:{type(error).__name__}')
    cleanup['image'] = {'removeExitCode': image_remove, 'exactAbsent': image_absent}
    unload = None;remote_remove = None;profile_absent = None;remote_absent = None
    try:
        loaded_query = subprocess.run(ssh + ['sudo', 'grep', '-F', profile_name,
            '/sys/kernel/security/apparmor/profiles'], env=base_env, capture_output=True, text=True, timeout=20)
        is_loaded = loaded_query.returncode == 0 and f'{profile_name} (enforce)' in loaded_query.stdout
        if loaded_query.returncode not in (0, 1): raise RuntimeError('profile query failed')
        if is_loaded:
            if not remote_owned or run(ssh + ['cat', '--', remote_marker], capture_output=True,
                                       text=True, timeout=20).stdout != remote_owner:
                raise RuntimeError('owned AppArmor cleanup marker differs')
            unload = subprocess.run(ssh + ['sudo', 'apparmor_parser', '-R', remote_profile],
                                    env=base_env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=30).returncode
            if unload != 0: errors.append('apparmorUnload:Nonzero')
    except Exception as error: errors.append(f'apparmorUnload:{type(error).__name__}')
    if remote_creation_attempted and remote_owned:
        try:
            remote_remove = subprocess.run(ssh + ['rm', '-rf', '--', remote_dir], env=base_env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           timeout=20).returncode
            if remote_remove != 0: errors.append('apparmorRemoteRemove:Nonzero')
        except Exception as error: errors.append(f'apparmorRemoteRemove:{type(error).__name__}')
    try:
        query = subprocess.run(ssh + ['sudo', 'grep', '-F', profile_name,
            '/sys/kernel/security/apparmor/profiles'], env=base_env, capture_output=True, text=True, timeout=20)
        profile_absent = query.returncode == 1 and not query.stdout.strip()
        if query.returncode not in (0, 1): errors.append('apparmorAbsence:QueryFailed')
    except Exception as error: errors.append(f'apparmorAbsence:{type(error).__name__}')
    try:
        query = subprocess.run(ssh + ['test', '-e', remote_dir], env=base_env,
                               capture_output=True, text=True, timeout=20)
        remote_absent = query.returncode == 1
        if query.returncode not in (0, 1): errors.append('apparmorRemoteAbsence:QueryFailed')
    except Exception as error: errors.append(f'apparmorRemoteAbsence:{type(error).__name__}')
    apparmor_cleanup = {'profileName': profile_name, 'unloadExitCode': unload,
                        'exactAbsent': profile_absent, 'remoteDirectory': remote_dir,
                        'remoteRemoveExitCode': remote_remove, 'remoteExactAbsent': remote_absent}
    state['cleanup'] = {'resources': cleanup, 'apparmor': apparmor_cleanup,
                        'errors': errors, 'signals': gate.received, 'completedAt': now()}
    if state['status'] == 'passed' and (errors or not all(item['exactAbsent'] is True for item in cleanup.values())
                                      or profile_absent is not True or remote_absent is not True):
        state.update(status='failed', errorType='CleanupFailed')
    persist()
    try: update_grant()
    except Exception as error:
        state['cleanup']['errors'].append(f'grantUpdate:{type(error).__name__}')
        state.update(status='failed', errorType=state.get('errorType') or 'GrantUpdateFailed');persist()

print(evidence, flush=True)
if failed: raise failed
if state['status'] != 'passed': raise RuntimeError('owned CodeBot qualifier cleanup is incomplete')
