#!/usr/bin/env python3
"""Disposable full-index qualification for the owned SecureShop System reader."""

import hashlib
import importlib.util
import json
import os
import pathlib
import secrets
import signal
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
NODE = pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
DOCKER = ['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker',
          '--host', 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
PG_IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
MIGRATIONS = {
    'db/postgres/workshop-migrations/secureshop_agents/0028_system_config_candidate.sql':
        '763f74019607563acff42399add166a5e9f5bbf4e70276c34404795b13416ee9',
    'db/postgres/workshop-migrations/secureshop_agents/0029_system_config_retirement_guard.sql':
        '03682ee52e5c61625d6d5983ad433b74f77a6343f4f01ad3643969b7e84a5ad7',
}

if len(sys.argv) != 2 or sys.argv[1] not in ('--plan', '--run'):
    raise SystemExit('Usage: qualify-secureshop-system-config-enabled-index.py --plan|--run')

suffix = secrets.token_hex(6)
owner = secrets.token_hex(16)
pg_name = f'dvaia-system-index-pg-{suffix}'
evidence = pathlib.Path.home() / '.dvaia/native-verification' / f'dvaia-system-enabled-index-{suffix}'
task_result = REPO / 'tasks' / f'secureshop-system-enabled-index-native-{suffix}.json'

if sys.argv[1] == '--plan':
    print(json.dumps({'node': str(NODE), 'expectedNode': 'v26.9.0', 'docker': DOCKER,
                      'postgresImage': PG_IMAGE, 'canonicalMigrations': MIGRATIONS,
                      'ownedResources': {'postgres': pg_name,
                        'systemExecutorPrefix': f'dvaia-system-http-{owner[:12]}'},
                      'limits': {'parentDeadlineSeconds': 720, 'testDeadlineSeconds': 360,
                        'postgres': {'memory': '1g', 'cpus': 2, 'pids': 256,
                          'maxConnections': 100},
                        'systemExecutor': {'memory': '512m', 'cpus': 1, 'pids': 128,
                          'readOnlyRoot': True, 'hostMounts': 0},
                        'backendPoolBudget': 78, 'fixturePoolBudget': 6,
                        'agentHostConnectionAllowance': 4},
                      'scope': ['explicit-false/no-probe', 'enabled actual reader and durable readback',
                        'opaque production-browser loss/recovery/session denial',
                        'unavailable-reader startup rejection', 'repository privilege startup rejection'],
                      'actualModelCalls': 0, 'installedMutation': False}, indent=2))
    raise SystemExit(0)

sys.path.insert(0, str(REPO / 'tests/postgres'))
from sensitive_info_recovery_safety import SignalGate

root = pathlib.Path(tempfile.mkdtemp(prefix='dvaia-system-enabled-index-'))
os.chmod(root, 0o700)
workspace = root / 'source'
runtime = root / 'runtime'
env = {'PATH': f'{NODE.parent}:/usr/bin:/bin', 'HOME': os.environ['HOME'], 'TMPDIR': str(root)}
result = {'version': 1, 'status': 'failed', 'installedMutation': False, 'browser': False,
          'actualModel': False, 'architecture': 'arm64', 'node': 'v26.9.0',
          'canonicalMigrations': MIGRATIONS, 'resources': {'postgres': pg_name},
          'evidence': str(evidence), 'workspace': str(workspace),
          'startedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
gate = SignalGate()
signal.signal(signal.SIGTERM, gate.handler)
signal.signal(signal.SIGINT, gate.handler)
children = []
pg_created = False
executor = None

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def write(path, value):
    path = pathlib.Path(path)
    pending = path.with_name(path.name + f'.{os.getpid()}.pending')
    pending.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(pending, 0o600)
    pending.replace(path)

def persist():
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    write(evidence / 'progress.json', result)

def run(args, timeout=120, cwd=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, capture_output=True,
                          text=True, timeout=timeout).stdout.strip()

def docker(args, timeout=120):
    return run(DOCKER + args, timeout=timeout)

def pg_absent():
    return not docker(['ps', '--all', '--filter', f'name=^/{pg_name}$', '--format', '{{.Names}}'])

def owned_group_members(pgid):
    rows = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=env, check=True,
      capture_output=True, text=True, timeout=5).stdout.splitlines()
    members = []
    for row in rows:
        fields = row.split()
        if len(fields) == 3 and int(fields[1]) == pgid:
            if int(fields[2]) != os.getuid():
                raise RuntimeError('refusing foreign process-group cleanup')
            members.append(int(fields[0]))
    return members

def alarm(_signum, _frame):
    raise TimeoutError('hard parent qualification deadline exceeded')

signal.signal(signal.SIGALRM, alarm)
signal.alarm(720)
exit_code = 1
try:
    evidence.mkdir(parents=True, mode=0o700)
    info = json.loads(docker(['info', '--format', '{{json .}}'], timeout=30))
    if info.get('Name') != 'colima-dvaia-pg-verify' or info.get('Architecture') != 'aarch64':
        raise RuntimeError('Docker authority or architecture mismatch')
    if run([str(NODE), '--version']) != 'v26.9.0':
        raise RuntimeError('Node 26.9.0 is required')
    inspected = json.loads(docker(['image', 'inspect', PG_IMAGE]))[0]
    if inspected['Id'] != PG_IMAGE:
        raise RuntimeError('PostgreSQL image digest mismatch')
    if not pg_absent():
        raise RuntimeError('owned PostgreSQL identity already exists')

    subprocess.run([str(NODE), '-e',
      "require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",
      str(REPO), str(workspace)], cwd=REPO, env=env, check=True, timeout=120)
    (workspace / 'node_modules').symlink_to(REPO / 'node_modules', target_is_directory=True)
    (workspace / 'client/node_modules').symlink_to(REPO / 'client/node_modules', target_is_directory=True)
    for name, digest in MIGRATIONS.items():
        if sha(workspace / name) != digest:
            raise RuntimeError(f'canonical migration bytes drifted: {name}')

    client_build_log = evidence / 'client-build.log'
    with client_build_log.open('w') as output:
        client_build = subprocess.Popen([str(NODE.parent / 'npm'), '--prefix', 'client', 'run', 'build'],
          cwd=workspace, env=env, stdout=output, stderr=output, start_new_session=True)
        children.append(client_build)
        if client_build.wait(timeout=180) != 0:
            raise RuntimeError('production client build failed')
    build_log = evidence / 'review-renderer-build.log'
    with build_log.open('w') as output:
        build = subprocess.Popen([str(NODE.parent / 'npm'), '--prefix', 'client',
          'run', 'build:review-renderer'], cwd=workspace, env=env,
          stdout=output, stderr=output, start_new_session=True)
        children.append(build)
        if build.wait(timeout=120) != 0:
            raise RuntimeError('review renderer build failed')

    source_hashes = {str(item.relative_to(workspace)): sha(item)
      for item in workspace.rglob('*') if item.is_file() and not item.is_symlink()}
    write(evidence / 'source-hashes.json', source_hashes)
    for item in workspace.rglob('*'):
        if not item.is_symlink():
            item.chmod(0o555 if item.is_dir() else 0o444)
    workspace.chmod(0o555)

    spec = importlib.util.spec_from_file_location('frozen_system_config_owned_executor',
      workspace / 'tests/postgres/system_config_owned_executor.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    executor = module.OwnedSystemExecutor(evidence, workspace, DOCKER, env, owner, persist)
    result['executor'] = executor.state
    executor_origin, executor_token = executor.start()
    result['executor'] = executor.state
    persist()

    docker(['run', '--detach', '--pull', 'never', '--name', pg_name,
      '--label', f'dvaia.test.owner={owner}', '--memory', '1g', '--cpus', '2',
      '--pids-limit', '256', '--tmpfs', '/var/lib/postgresql:rw,size=1073741824',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-p', '127.0.0.1::5432', PG_IMAGE,
      '-c', 'max_connections=100', '-c', 'max_wal_size=64MB', '-c', 'min_wal_size=32MB'])
    pg_created = True
    for _ in range(80):
        try:
            docker(['exec', pg_name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'])
            break
        except subprocess.CalledProcessError:
            time.sleep(.25)
    else:
        raise RuntimeError('PostgreSQL did not become ready')
    pg_port = docker(['port', pg_name, '5432/tcp']).split(':')[-1]
    base = DOCKER + ['exec', pg_name, 'psql', '-h', '127.0.0.1', '-U', 'postgres',
      '-v', 'ON_ERROR_STOP=1', '-c']
    manifest = json.loads(run([str(NODE), '-e',
      "process.stdout.write(JSON.stringify(require('./db/postgres/initialize-application').requiredStoreManifest))"],
      cwd=workspace))
    if len(manifest) != 16:
        raise RuntimeError('expected exact sixteen-store manifest')
    for row in manifest:
        schema, database = row['schema'], f'dvaia_test_full_backend_{row["schema"]}'
        run(base + [f'CREATE ROLE dvaia_{schema}_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; '
          f'CREATE ROLE {row["runtimeRole"]} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'])
        run(base + [f'CREATE DATABASE {database} OWNER dvaia_{schema}_migration'])
        env[row['runtimeVariable']] = f'postgresql://{row["runtimeRole"]}@127.0.0.1:{pg_port}/{database}'
        env[row['migrationVariable']] = f'postgresql://dvaia_{schema}_migration@127.0.0.1:{pg_port}/{database}'

    runtime.mkdir(mode=0o700)
    env.update(PG_TEST_DISPOSABLE='yes', PG_SECURESHOP_SYSTEM_ENABLED_INDEX='1',
      PG_SECURESHOP_SYSTEM_EXECUTOR_ORIGIN=executor_origin,
      PG_SECURESHOP_SYSTEM_EXECUTOR_TOKEN=executor_token,
      DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace.resolve()),
      DVAIA_FULL_BACKEND_RUNTIME_ROOT=str(runtime.resolve()), PG_POOL_BUDGET='78')
    tests_log = evidence / 'tests.log'
    with tests_log.open('w') as output:
        child = subprocess.Popen([str(NODE), '--test', '--test-reporter=tap',
          'tests/postgres/secureshopSystemConfigEnabledIndex.integration.test.js'],
          cwd=workspace, env=env, stdout=output, stderr=output, start_new_session=True)
        children.append(child)
        test_exit = child.wait(timeout=360)
    if test_exit != 0:
        raise RuntimeError(f'System enabled-index fixture failed with exit {test_exit}')
    application_result = json.loads((runtime / 'system-config-enabled-index-result.json').read_text())
    result.update(status='passed', browser=True, application=application_result,
      sourceHashesSha256=hashlib.sha256(json.dumps(source_hashes, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest(), testsLogSha256=sha(tests_log))
    exit_code = 0
except Exception as error:
    result['error'] = {'type': type(error).__name__, 'message': str(error)[:3000]}
finally:
    signal.alarm(0)
    gate.protect_cleanup()
    cleanup_errors = []
    # Retain the bounded browser/application receipts before the disposable
    # runtime is released so a failed rendered gate remains independently
    # diagnosable without retaining database or process resources.
    for artifact in ('enabled-system-browser-result.json', 'enabled-system-browser-failure.json',
                     'enabled-system-browser-failure.png', 'enabled-system-recovered-desktop.png',
                     'enabled-system-recovered-desktop-parent.png',
                     'enabled-system-recovered-narrow.png', 'enabled-system-recovered-narrow-parent.png',
                     'system-config-enabled-index-result.json'):
        try:
            source_artifact = runtime / artifact
            if source_artifact.is_file():
                target_artifact = evidence / artifact
                target_artifact.write_bytes(source_artifact.read_bytes())
                os.chmod(target_artifact, 0o600)
        except Exception as error:
            cleanup_errors.append(f'artifact:{artifact}:{type(error).__name__}:{str(error)[:500]}')
    for child in children:
        try:
            if owned_group_members(child.pid):
                os.killpg(child.pid, signal.SIGTERM)
                deadline = time.monotonic() + 8
                while owned_group_members(child.pid) and time.monotonic() < deadline:
                    time.sleep(.05)
                if owned_group_members(child.pid):
                    os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
            if child.poll() is None: child.wait(timeout=5)
        except Exception as error:
            cleanup_errors.append(f'process:{type(error).__name__}')
    if pg_created:
        try:
            logs = subprocess.run(DOCKER + ['logs', '--tail', '200', pg_name], env=env,
              capture_output=True, text=True, timeout=20)
            (evidence / 'postgres.log').write_text(logs.stdout + '\n' + logs.stderr)
            os.chmod(evidence / 'postgres.log', 0o600)
        except Exception as error:
            cleanup_errors.append(f'postgres-diagnostics:{type(error).__name__}:{str(error)[:500]}')
        try:
            details = json.loads(docker(['inspect', pg_name]))[0]
            if details['Config']['Labels'].get('dvaia.test.owner') != owner:
                raise RuntimeError('refusing foreign PostgreSQL cleanup')
            docker(['rm', '--force', '--volumes', pg_name], timeout=30)
        except Exception as error:
            cleanup_errors.append(f'postgres:{type(error).__name__}')
    if executor is not None:
        try:
            if not executor.close(): cleanup_errors.append('executor-cleanup')
        except BaseException as error:
            cleanup_errors.append(f'executor:{type(error).__name__}')
        result['executor'] = executor.state
    try: postgres_absent = pg_absent()
    except Exception: postgres_absent = False
    process_groups = []
    for child in children:
        try: process_groups.append({'pgid': child.pid, 'absent': not owned_group_members(child.pid)})
        except Exception:
            process_groups.append({'pgid': child.pid, 'absent': False})
    if not all(item['absent'] for item in process_groups): cleanup_errors.append('process-group-remains')
    result['cleanup'] = {'postgresAbsent': postgres_absent, 'errors': cleanup_errors,
      'processes': [{'pid': child.pid, 'exited': child.poll() is not None} for child in children],
      'processGroups': process_groups,
      'executor': executor.state.get('cleanup') if executor is not None else None}
    result['signals'] = gate.received
    result['completedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    if cleanup_errors or not postgres_absent:
        result['status'] = 'failed'; exit_code = 1
    write(evidence / 'result.json', result)
    write(task_result, result)
    print(json.dumps({'status': result['status'], 'evidence': str(evidence),
      'taskResult': str(task_result), 'cleanup': result['cleanup']}))

raise SystemExit(exit_code)
