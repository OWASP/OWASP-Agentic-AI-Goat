#!/usr/bin/env python3
"""Bounded, owned PostgreSQL qualification for the audit-search lifecycle."""
import argparse, hashlib, json, os, re, signal, subprocess, sys, tempfile, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NODE = Path.home() / '.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node'
DOCKER = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
POSTGRES_IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER_SHA256 = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
TEST_FILE = 'tests/postgres/secureshopAuditSearchLifecycle.integration.test.js'
ASSERTION = 'actual owned database lifecycle persists receipts and contains raw SQL'
SOURCE_FILES = [TEST_FILE, 'tests/postgres/run-secureshop-audit-search-lifecycle.py', 'package.json', 'package-lock.json',
                'node_modules/.package-lock.json', 'sidecars/audit-sql-target', 'server/services', 'server/agent-runtime',
                'server/database']
PARENT_TIMEOUT, CHILD_TIMEOUT = 300, 180


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inventory():
    paths = set()
    for entry in SOURCE_FILES:
        path = ROOT / entry
        if path.is_dir(): paths.update(item.relative_to(ROOT) for item in path.rglob('*') if item.is_file())
        elif path.is_file(): paths.add(path.relative_to(ROOT))
        else: raise RuntimeError(f'missing source/dependency path: {entry}')
    return {str(path): digest(ROOT / path) for path in sorted(paths)}


def command(args, *, env, timeout=30, check=True, **kwargs):
    return subprocess.run(args, env=env, timeout=timeout, check=check, text=True, capture_output=True, **kwargs)


def tap_summary(text):
    values = {}
    for key in ('tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo'):
        matches = re.findall(rf'^# {key} (\d+)$', text, re.MULTILINE)
        if len(matches) != 1: raise RuntimeError(f'TAP {key} summary must occur exactly once')
        values[key] = int(matches[0])
    required = ('tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo')
    if any(key not in values for key in required): raise RuntimeError('test output has no complete TAP summary')
    if values['tests'] < 1 or values['pass'] < 1 or values['fail'] or values['skipped'] or values['cancelled'] or values['todo']:
        raise RuntimeError(f'non-skipped passing test required: {values}')
    if values['tests'] != 1 or values['pass'] != 1:
        raise RuntimeError(f'exactly one named lifecycle assertion required: {values}')
    if re.search(r'^not ok(?:\s|$)', text, re.MULTILINE):
        raise RuntimeError('TAP contains a not-ok assertion')
    if len(re.findall(r'^1\.\.1$', text, re.MULTILINE)) != 1:
        raise RuntimeError('TAP must contain one top-level 1..1 plan')
    if f'# Subtest: {ASSERTION}' not in text or not re.search(rf'^ok \d+ - {re.escape(ASSERTION)}$', text, re.MULTILINE):
        raise RuntimeError('named audit-search lifecycle TAP assertion missing')
    if 'OWNED_AUDIT_DATABASE_LIFECYCLE_NATIVE_PASSED' not in text:
        raise RuntimeError('native lifecycle completion marker missing')
    return values


def exact_name_absent(docker, env, name):
    result = command(docker + ['ps', '-aq', '--filter', f'name=^/{name}$', '--no-trunc'], env=env, timeout=20)
    return not result.stdout.strip()


def exact_id_absent(docker, env, container_id):
    result = command(docker + ['ps', '-aq', '--no-trunc', '--filter', f'id={container_id}'], env=env, timeout=20)
    return not result.stdout.strip()


def owned_members(pgid, env):
    listing = command(['ps', '-axo', 'pid=,pgid=,uid='], env=env, timeout=10).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 3 and int(fields[1]) == pgid:
            if int(fields[2]) != os.getuid(): raise RuntimeError(f'refusing foreign process in owned group {pgid}')
            members.append(int(fields[0]))
    return members


def stop_child(child, env):
    if child is None: return True
    pgid = getattr(child, '_owned_pgid', None)
    if pgid is None:
        try: pgid = os.getpgid(child.pid)
        except ProcessLookupError: return child.poll() is not None
    if owned_members(pgid, env): os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while owned_members(pgid, env) and time.monotonic() < deadline:
        child.poll(); time.sleep(.05)
    if owned_members(pgid, env): os.killpg(pgid, signal.SIGKILL)
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired: return False
    return not owned_members(pgid, env)


def plan():
    print(json.dumps({'mode': 'plan', 'candidateOnly': True, 'nativeStarted': False, 'sourceCopy': False,
      'node': str(NODE), 'requiredNodeVersion': 'v26.10.0', 'docker': str(DOCKER),
      'dockerHost': DOCKER_HOST, 'postgresImage': POSTGRES_IMAGE, 'test': TEST_FILE,
      'parentTimeoutSeconds': PARENT_TIMEOUT, 'childTimeoutSeconds': CHILD_TIMEOUT}, indent=2))


def verify_host(docker, env):
    if not NODE.is_file() or NODE.is_symlink(): raise RuntimeError('managed Node v26.10.0 regular file required')
    if digest(NODE) != NODE_SHA256: raise RuntimeError('managed Node binary digest mismatch')
    if command([str(NODE), '--version'], env=env, timeout=10).stdout.strip() != 'v26.10.0': raise RuntimeError('managed Node v26.10.0 required')
    if not DOCKER.is_file() or DOCKER.is_symlink(): raise RuntimeError('reviewed Docker executable required')
    if digest(DOCKER) != DOCKER_SHA256: raise RuntimeError('Docker executable digest mismatch')
    daemon = command(docker + ['info', '--format', '{{.Name}}'], env=env, timeout=20).stdout.strip()
    if daemon != 'colima-owasp-ai-goat-pg-verify': raise RuntimeError('reviewed isolated Docker daemon required')
    daemon_id = command(docker + ['info', '--format', '{{.ID}}'], env=env, timeout=20).stdout.strip()
    if daemon_id != DOCKER_DAEMON_ID: raise RuntimeError('reviewed Docker daemon ID mismatch')
    image = command(docker + ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE], env=env, timeout=20).stdout.strip()
    if image != POSTGRES_IMAGE: raise RuntimeError('immutable PostgreSQL image identity mismatch')
    return daemon, daemon_id, image


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--plan', action='store_true'); args = parser.parse_args()
    if args.plan: plan(); return 0
    evidence = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-audit-search-', dir=os.getenv('TMPDIR', '/tmp'))); os.chmod(evidence, 0o700)
    nonce, owner = uuid.uuid4().hex[:12], uuid.uuid4().hex
    name, database = f'owasp-ai-goat-audit-search-{nonce}', f'owasp_ai_goat_test_audit_search_{nonce}'
    docker = [str(DOCKER), '--host', DOCKER_HOST]
    env = {'PATH': f'{NODE.parent}:/usr/bin:/bin', 'HOME': os.environ.get('HOME', str(Path.home())), 'TMPDIR': str(evidence)}
    result = {'name': name, 'owner': owner, 'candidateOnly': True, 'actualModel': False,
              'actualNetworkEffects': False, 'evidence': str(evidence), 'status': 'preparing'}
    before = source_inventory(); child = None; container_id = None; creation_attempted = False
    def parent_timeout(_signum, _frame): raise TimeoutError(f'audit-search launcher exceeded {PARENT_TIMEOUT}s')
    signal.signal(signal.SIGALRM, parent_timeout); signal.alarm(PARENT_TIMEOUT)
    try:
        daemon, daemon_id, image = verify_host(docker, env)
        result.update(nodeVersion='v26.10.0', nodeSha256=NODE_SHA256, dockerDaemon=daemon,
                      dockerSha256=DOCKER_SHA256, dockerDaemonId=daemon_id, imageId=image)
        if not exact_name_absent(docker, env, name): raise RuntimeError('owned container name unexpectedly exists')
        command([str(NODE), '--check', TEST_FILE], env=env, timeout=20, cwd=ROOT)
        creation_attempted = True
        run_result = command(docker + ['run', '--detach', '--pull', 'never', '--name', name, '--label', f'owasp-ai-goat.test.owner={owner}',
          '--memory', '512m', '--cpus', '1', '--pids-limit', '128', '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
          '-e', 'POSTGRES_USER=http_test_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
          '-p', '127.0.0.1::5432', POSTGRES_IMAGE, '-c', 'shared_buffers=16MB', '-c', 'max_connections=24',
          '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], env=env, timeout=30)
        container_id = run_result.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container_id): container_id = command(docker + ['inspect', '--format', '{{.Id}}', name], env=env, timeout=20).stdout.strip()
        details = json.loads(command(docker + ['inspect', container_id], env=env, timeout=20).stdout)[0]
        if details['Id'] != container_id or details['Config']['Labels'].get('owasp-ai-goat.test.owner') != owner: raise RuntimeError('owned container ID/label verification failed')
        result.update(containerId=container_id, containerLabel={'owasp-ai-goat.test.owner': owner})
        for _ in range(80):
            ready = subprocess.run(docker + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1', '-U', 'http_test_admin'], env=env, capture_output=True, timeout=5)
            if ready.returncode == 0: break
            time.sleep(.25)
        else: raise RuntimeError('owned PostgreSQL not ready')
        command(docker + ['exec', '-i', container_id, 'psql', '-h', '127.0.0.1', '-U', 'http_test_admin', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'], env=env, timeout=30, input=f'DROP DATABASE http_test_admin; CREATE DATABASE {database};')
        port = command(docker + ['port', container_id, '5432/tcp'], env=env, timeout=20).stdout.strip().rsplit(':', 1)[1]
        verify_host(docker, env)
        env.update(PG_AUDIT_SEARCH_DESIGN='yes', PG_AUDIT_SEARCH_URL=f'postgresql://search_learner@127.0.0.1:{port}/{database}')
        log = evidence / 'test.stdout.log'
        with log.open('w') as output:
            child = subprocess.Popen([str(NODE), '--test', '--test-reporter=tap', TEST_FILE], cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            child._owned_pgid = os.getpgid(child.pid)
            try: code = child.wait(timeout=CHILD_TIMEOUT)
            except subprocess.TimeoutExpired:
                stop_child(child, env); raise RuntimeError(f'audit-search native test timed out after {CHILD_TIMEOUT}s')
        result['tap'] = tap_summary(log.read_text())
        if code: raise RuntimeError(f'audit-search native test failed ({code})')
        result.update(testExitCode=code, status='passed')
    except BaseException as error:
        result.update(status='failed', errorType=type(error).__name__, error=str(error)); raise
    finally:
        signal.alarm(0)
        cleanup_errors = []
        try: child_clean = stop_child(child, env) if child is not None else True
        except Exception as error: cleanup_errors.append(f'child:{type(error).__name__}'); child_clean = False
        try:
            verify_host(docker, env); cleanup_daemon_verified = True
        except Exception as error:
            cleanup_errors.append(f'daemon:{type(error).__name__}'); cleanup_daemon_verified = False
        if cleanup_daemon_verified and creation_attempted and not container_id:
            try:
                inspected = json.loads(command(docker + ['inspect', name], env=env, timeout=20).stdout)[0]
                if inspected['Config']['Labels'].get('owasp-ai-goat.test.owner') != owner: raise RuntimeError('refusing non-owned creation-ack recovery')
                container_id = inspected['Id']
            except subprocess.CalledProcessError:
                pass
            except Exception as error: cleanup_errors.append(f'creation:{type(error).__name__}')
        remove_code = None
        if cleanup_daemon_verified and creation_attempted and container_id:
            try:
                inspected = json.loads(command(docker + ['inspect', container_id], env=env, timeout=20).stdout)[0]
                if inspected['Id'] != container_id or inspected['Config']['Labels'].get('owasp-ai-goat.test.owner') != owner: raise RuntimeError('refusing cleanup of non-owned container')
                remove_code = subprocess.run(docker + ['rm', '-f', '-v', container_id], env=env, capture_output=True, timeout=30).returncode
            except Exception as error: cleanup_errors.append(f'container:{type(error).__name__}')
        try:
            name_absent = exact_name_absent(docker, env, name) if cleanup_daemon_verified and creation_attempted else not creation_attempted
            id_absent = exact_id_absent(docker, env, container_id) if cleanup_daemon_verified and creation_attempted and container_id else not creation_attempted
        except Exception as error:
            cleanup_errors.append(f'absence:{type(error).__name__}'); name_absent = id_absent = False
        try:
            after = source_inventory(); result['sourceUnchanged'] = before == after
        except Exception as error:
            after = {}; result['sourceUnchanged'] = False; cleanup_errors.append(f'source:{type(error).__name__}')
        result['cleanup'] = {'containerId': container_id, 'removeExitCode': remove_code, 'containerNameAbsent': name_absent,
          'containerIdAbsent': id_absent, 'childProcessGroupAbsent': child_clean, 'errors': cleanup_errors}
        if result.get('status') == 'passed' and (cleanup_errors or not name_absent or not id_absent or not child_clean or not result['sourceUnchanged'] or remove_code != 0): result['status'] = 'failed'
        (evidence / 'result.json').write_text(json.dumps({'before': before, 'after': after, **result}, indent=2) + '\n')
        print(json.dumps({'evidence': str(evidence), 'status': result['status'], 'cleanup': result['cleanup']}), flush=True)
        if result['status'] != 'passed' and not sys.exc_info()[0]: raise RuntimeError('audit-search qualification cleanup failed')


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr); raise
