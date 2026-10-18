#!/usr/bin/env python3
"""Disposable full-index qualification for launch-owned SecureShop policies."""

import hashlib
import json
import os
import pathlib
import secrets
import shutil
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
CANDIDATE = pathlib.Path('docs/modernization/drafts/secureshop-bound-prompt-policies/0027_bound_prompt_policies.candidate.sql')
CANDIDATE_SHA256 = '1c7d4f120b2b7081103fc165597b555ddaf7c9ea472456a0458df31050761f58'

if len(sys.argv) != 2 or sys.argv[1] not in ('--plan', '--run'):
    raise SystemExit('Usage: qualify-secureshop-prompt-policy-enabled-index.py --plan|--run')

suffix = secrets.token_hex(6)
pg_name = f'dvaia-policy-index-pg-{suffix}'
renderer_name = f'dvaia-policy-index-renderer-{suffix}'
renderer_image = f'dvaia-policy-index-renderer:{suffix}'
renderer_network = f'dvaia-policy-index-net-{suffix}'
evidence = pathlib.Path.home() / '.dvaia/native-verification' / f'dvaia-policy-enabled-index-{suffix}'
task_result = REPO / 'tasks' / f'secureshop-policy-enabled-index-native-{suffix}.json'

if sys.argv[1] == '--plan':
    print(json.dumps({'node': str(NODE), 'expectedNode': 'v26.9.0', 'docker': DOCKER,
                      'postgresImage': PG_IMAGE, 'candidate': str(CANDIDATE),
                      'candidateSha256': CANDIDATE_SHA256,
                      'ownedResources': [pg_name, renderer_name, renderer_image, renderer_network],
                      'limits': {'parentDeadlineSeconds': 480, 'postgres': {'memory': '1g', 'cpus': 2,
                        'pids': 256, 'maxConnections': 100}, 'renderer': {'memory': '512m', 'cpus': 1,
                        'pids': 128}, 'applicationPoolBudget': 78}}, indent=2))
    raise SystemExit(0)

sys.path.insert(0, str(REPO / 'tests/postgres'))
from sensitive_info_recovery_safety import SignalGate

root = pathlib.Path(tempfile.mkdtemp(prefix='dvaia-policy-enabled-index-'))
os.chmod(root, 0o700)
workspace = root / 'source'
runtime = root / 'runtime'
env = {'PATH': f'{NODE.parent}:/usr/bin:/bin', 'HOME': os.environ['HOME'], 'TMPDIR': str(root)}
result = {'version': 1, 'status': 'failed', 'candidateOnly': True, 'installedMutation': False,
          'browser': False, 'actualModel': False, 'architecture': 'arm64', 'node': 'v26.9.0',
          'candidateSha256': CANDIDATE_SHA256, 'resources': {'postgres': pg_name,
          'renderer': renderer_name, 'rendererImage': renderer_image, 'rendererNetwork': renderer_network},
          'evidence': str(evidence), 'startedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
gate = SignalGate()
signal.signal(signal.SIGTERM, gate.handler)
signal.signal(signal.SIGINT, gate.handler)
children = []
created = set()

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def write(path, value):
    path = pathlib.Path(path)
    pending = path.with_name(path.name + f'.{os.getpid()}.pending')
    pending.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(pending, 0o600)
    pending.replace(path)

def run(args, timeout=120, cwd=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True, capture_output=True,
                          text=True, timeout=timeout).stdout.strip()

def docker(args, timeout=120):
    return run(DOCKER + args, timeout=timeout)

def absent(kind, name):
    if kind == 'container':
        return not docker(['ps', '--all', '--filter', f'name=^/{name}$', '--format', '{{.Names}}'])
    if kind == 'image':
        return not docker(['images', '--filter', f'reference={name}', '--format', '{{.Repository}}:{{.Tag}}'])
    if kind == 'network':
        return not docker(['network', 'ls', '--filter', f'name=^/{name}$', '--format', '{{.Name}}'])
    raise ValueError(kind)

def alarm(_signum, _frame):
    raise TimeoutError('hard parent qualification deadline exceeded')

signal.signal(signal.SIGALRM, alarm)
signal.alarm(480)
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
    for kind, name in [('container', pg_name), ('container', renderer_name),
                       ('image', renderer_image), ('network', renderer_network)]:
        if not absent(kind, name):
            raise RuntimeError(f'owned {kind} already exists')

    subprocess.run([str(NODE), '-e',
      "require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",
      str(REPO), str(workspace)], cwd=REPO, env=env, check=True, timeout=120)
    (workspace / 'node_modules').symlink_to(REPO / 'node_modules', target_is_directory=True)
    (workspace / 'client/node_modules').symlink_to(REPO / 'client/node_modules', target_is_directory=True)
    candidate = workspace / CANDIDATE
    if sha(candidate) != CANDIDATE_SHA256:
        raise RuntimeError('candidate0027 bytes drifted')
    registered = workspace / 'db/postgres/workshop-migrations/secureshop_agents/0027_bound_prompt_policies.sql'
    if registered.exists():
        raise RuntimeError('candidate0027 unexpectedly registered in source')
    shutil.copyfile(candidate, registered)
    if sha(registered) != CANDIDATE_SHA256:
        raise RuntimeError('isolated candidate registration changed bytes')

    build_log = evidence / 'review-renderer-build.log'
    with build_log.open('w') as output:
        build = subprocess.Popen([str(NODE.parent / 'npm'), '--prefix', 'client', 'run', 'build:review-renderer'],
          cwd=workspace, env=env, stdout=output, stderr=output, start_new_session=True)
        children.append(build)
        if build.wait(timeout=120) != 0:
            raise RuntimeError('review renderer build failed')

    # The host entry point needs a loopback-published HTTP origin. The outer
    # service network is transport only; every untrusted template still enters
    # the separately attested empty network namespace in the packaged executor.
    docker(['network', 'create', '--label', f'dvaia.qualification={suffix}', renderer_network])
    created.add(('network', renderer_network))
    image_build = subprocess.run(DOCKER + ['build', '--pull=false', '-f',
      'sidecars/sandbox-runner/Dockerfile', '-t', renderer_image, 'sidecars/sandbox-runner'], cwd=workspace,
      env=env, capture_output=True, text=True, timeout=300)
    (evidence / 'renderer-image-build.log').write_text(image_build.stdout + '\n' + image_build.stderr)
    os.chmod(evidence / 'renderer-image-build.log', 0o600)
    if image_build.returncode != 0:
        raise RuntimeError('packaged renderer image build failed')
    created.add(('image', renderer_image))
    renderer_id = json.loads(docker(['image', 'inspect', renderer_image]))[0]['Id']
    docker(['run', '--detach', '--name', renderer_name, '--label', f'dvaia.qualification={suffix}',
      '--network', renderer_network, '--memory', '512m', '--cpus', '1', '--pids-limit', '128',
      '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
      '--security-opt', 'seccomp=unconfined', '--security-opt', 'apparmor=dvaia-mcp-sandbox',
      '--env', 'SECURESHOP_POLICY_RENDER_ENABLED=true', '--env', 'SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=2',
      '-p', '127.0.0.1::8090', renderer_image])
    created.add(('container', renderer_name))
    renderer_port = docker(['port', renderer_name, '8090/tcp']).split(':')[-1]
    renderer_origin = f'http://127.0.0.1:{renderer_port}'
    health_program = """const end=Date.now()+20000;(async()=>{for(;;){try{const r=await fetch(process.argv[1]+'/health');const j=await r.json();if(j.policyRenderer?.enabled===true&&j.policyRenderer.available===true&&j.policyRenderer.isolation==='bwrap-policy-template-v1')return process.stdout.write(JSON.stringify(j));}catch{}if(Date.now()>end)throw Error('renderer health timeout');await new Promise(r=>setTimeout(r,100));}})().catch(e=>{console.error(e);process.exit(1)});"""
    renderer_health = json.loads(run([str(NODE), '-e', health_program, renderer_origin], timeout=25))

    docker(['run', '--detach', '--pull', 'never', '--name', pg_name,
      '--label', f'dvaia.qualification={suffix}', '--memory', '1g', '--cpus', '2', '--pids-limit', '256',
      '--tmpfs', '/var/lib/postgresql:rw,size=1073741824', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
      '-p', '127.0.0.1::5432', PG_IMAGE, '-c', 'max_connections=100', '-c', 'max_wal_size=64MB',
      '-c', 'min_wal_size=32MB'])
    created.add(('container', pg_name))
    for _ in range(80):
        try:
            docker(['exec', pg_name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres']); break
        except subprocess.CalledProcessError:
            time.sleep(.25)
    else:
        raise RuntimeError('PostgreSQL did not become ready')
    pg_port = docker(['port', pg_name, '5432/tcp']).split(':')[-1]
    base = DOCKER + ['exec', pg_name, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c']
    manifest = json.loads(run([str(NODE), '-e',
      "process.stdout.write(JSON.stringify(require('./db/postgres/initialize-application').requiredStoreManifest))"], cwd=workspace))
    if len(manifest) != 16:
        raise RuntimeError('expected exact sixteen-store manifest')
    for row in manifest:
        schema, database = row['schema'], f'dvaia_test_full_backend_{row["schema"]}'
        run(base + [f'CREATE ROLE dvaia_{schema}_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {row["runtimeRole"]} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'])
        run(base + [f'CREATE DATABASE {database} OWNER dvaia_{schema}_migration'])
        env[row['runtimeVariable']] = f'postgresql://{row["runtimeRole"]}@127.0.0.1:{pg_port}/{database}'
        env[row['migrationVariable']] = f'postgresql://dvaia_{schema}_migration@127.0.0.1:{pg_port}/{database}'

    runtime.mkdir(mode=0o700)
    env.update(PG_TEST_DISPOSABLE='yes', PG_SECURESHOP_POLICY_ENABLED_INDEX='1',
      PG_SECURESHOP_POLICY_RENDERER_ORIGIN=renderer_origin,
      PG_SECURESHOP_POLICY_CANDIDATE_SHA256=CANDIDATE_SHA256,
      DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace.resolve()),
      DVAIA_FULL_BACKEND_RUNTIME_ROOT=str(runtime.resolve()), PG_POOL_BUDGET='78')
    source_hashes = {str(p.relative_to(workspace)): sha(p) for p in workspace.rglob('*') if p.is_file() and not p.is_symlink()}
    write(evidence / 'source-hashes.json', source_hashes)
    for item in workspace.rglob('*'):
        if not item.is_symlink():
            item.chmod(0o555 if item.is_dir() else 0o444)
    workspace.chmod(0o555)

    tests_log = evidence / 'tests.log'
    with tests_log.open('w') as output:
        child = subprocess.Popen([str(NODE), '--test',
          'tests/postgres/secureshopPromptPolicyEnabledIndex.integration.test.js'], cwd=workspace,
          env=env, stdout=output, stderr=output, start_new_session=True)
        children.append(child)
        test_exit = child.wait(timeout=360)
    if test_exit != 0:
        raise RuntimeError(f'enabled-index fixture failed with exit {test_exit}')
    application_result = json.loads((runtime / 'policy-enabled-index-result.json').read_text())
    result.update(status='passed', rendererImageId=renderer_id,
      rendererHealth=renderer_health['policyRenderer'], application=application_result,
      sourceHashesSha256=hashlib.sha256(json.dumps(source_hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
      testsLogSha256=sha(tests_log))
    exit_code = 0
except Exception as error:
    result['error'] = {'type': type(error).__name__, 'message': str(error)[:3000]}
finally:
    signal.alarm(0)
    gate.protect_cleanup()
    cleanup_errors = []
    for child in children:
        try:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try: child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
        except Exception as error:
            cleanup_errors.append(f'process:{type(error).__name__}')
    for name in (renderer_name, pg_name):
        if ('container', name) in created:
            try:
                logs = subprocess.run(DOCKER + ['logs', '--tail', '200', name], env=env,
                  capture_output=True, text=True, timeout=20)
                (evidence / f'{name}.log').write_text(logs.stdout + '\n' + logs.stderr)
                os.chmod(evidence / f'{name}.log', 0o600)
            except Exception as error:
                cleanup_errors.append(f'{name}:diagnostics:{type(error).__name__}:{str(error)[:500]}')
            try:
                details = json.loads(docker(['inspect', name]))[0]
                if details['Config']['Labels'].get('dvaia.qualification') != suffix:
                    raise RuntimeError('refusing foreign container cleanup')
                docker(['rm', '--force', '--volumes', name], timeout=30)
            except Exception as error: cleanup_errors.append(f'{name}:{type(error).__name__}')
    if ('image', renderer_image) in created:
        try: docker(['image', 'rm', '--force', renderer_image], timeout=60)
        except Exception as error: cleanup_errors.append(f'image:{type(error).__name__}')
    if ('network', renderer_network) in created:
        try: docker(['network', 'rm', renderer_network], timeout=30)
        except Exception as error: cleanup_errors.append(f'network:{type(error).__name__}')
    absence = {}
    for kind, name in [('container', pg_name), ('container', renderer_name),
                       ('image', renderer_image), ('network', renderer_network)]:
        try: absence[f'{kind}:{name}'] = absent(kind, name)
        except Exception: absence[f'{kind}:{name}'] = False
    result['cleanup'] = {'absence': absence, 'errors': cleanup_errors,
      'processes': [{'pid': child.pid, 'exited': child.poll() is not None} for child in children]}
    result['signals'] = gate.received
    result['completedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    if cleanup_errors or not all(absence.values()):
        result['status'] = 'failed'; exit_code = 1
    write(evidence / 'result.json', result)
    write(task_result, result)
    print(json.dumps({'status': result['status'], 'evidence': str(evidence),
                      'taskResult': str(task_result), 'cleanup': result['cleanup']}))

raise SystemExit(exit_code)
