#!/usr/bin/env python3
"""Run the mounted XSS email route against owned PostgreSQL and Mailpit containers."""
import argparse, hashlib, json, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, build_opener, ProxyHandler
from xss_launcher_cleanup import cleanup_owned_containers
from xss_qualification_package import validate_package, verify_copy

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--package', required=True, help='immutable package directory containing source/')
parser.add_argument('--manifest', required=True, help='immutable package manifest')
parser.add_argument('--manifest-sha256', required=True)
parser.add_argument('--live', action='store_true', help='use the configured local llama3.1:8b actor and Judge')
parser.add_argument('--builder', action='store_true', help='qualify all four separate email-builder levels with actual models')
parser.add_argument('--ui', action='store_true', help='run the rendered React XSS email workflow')
parser.add_argument('--scenario', choices=['email', 'reflected', 'stored_user', 'stored_llm'], default='email',
                    help='rendered XSS scenario selected by --ui')
args = parser.parse_args()
if args.builder and (args.ui or not args.live):
    parser.error('--builder requires --live and cannot be combined with --ui')
EXPECTED_DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
EXPECTED_DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
if args.docker_host != EXPECTED_DOCKER_HOST:
    raise RuntimeError('Exact owned Colima verification Docker host is required')
package = Path(args.package)
manifest_path = Path(args.manifest)
manifest = validate_package(package, manifest_path, args.manifest_sha256)
source = package / 'source'
rendered_tests = {
    'email': 'tests/postgres/xssEmailRenderedUi.integration.test.js',
    'reflected': 'tests/postgres/xssReflectedRenderedUi.integration.test.js',
    'stored_user': 'tests/postgres/xssStoredUserRenderedUi.integration.test.js',
    'stored_llm': 'tests/postgres/xssStoredLlmRenderedUi.integration.test.js',
}
test_file = ('tests/postgres/xssEmailBuilderRoute.integration.test.js' if args.builder
             else rendered_tests[args.scenario] if args.ui
             else 'tests/postgres/xssEmailRoute.integration.test.js')
if not (source / test_file).is_file() or (source / test_file).is_symlink():
    raise RuntimeError(f'Selected XSS test is absent from the immutable package: {test_file}')
root = Path(tempfile.mkdtemp(prefix='dvaia-xss-email-route-')).resolve()
workspace = root / 'source'; workspace.mkdir(); os.chmod(root, 0o700)
runtime_root = root / 'runtime'; runtime_root.mkdir(mode=0o700)
for runtime_dir in (runtime_root / 'logs', runtime_root / 'artifacts', runtime_root / 'vite-cache'):
    runtime_dir.mkdir(mode=0o700)
private_home = root / 'home'; private_home.mkdir(mode=0o700)
private_tmp = root / 'tmp'; private_tmp.mkdir(mode=0o700)
base_env = {key: os.environ[key] for key in ['PATH'] if key in os.environ}
base_env.update(HOME=str(private_home), TMPDIR=str(private_tmp), PUPPETEER_CACHE_DIR=str(private_home / '.cache' / 'puppeteer'))
if os.environ.get('PUPPETEER_EXECUTABLE_PATH'):
    base_env['PUPPETEER_EXECUTABLE_PATH'] = os.environ['PUPPETEER_EXECUTABLE_PATH']
DOCKER_CLI = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_CLI_SHA256 = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
if not DOCKER_CLI.is_file() or DOCKER_CLI.is_symlink() \
        or hashlib.sha256(DOCKER_CLI.read_bytes()).hexdigest() != DOCKER_CLI_SHA256:
    raise RuntimeError('Exact reviewed Docker executable required')
docker = [str(DOCKER_CLI), '--host', args.docker_host]
MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.9.0-darwin-arm64/bin/node')
NODE_VERSION = 'v26.9.0'
NODE_SHA256 = '8bebc3d846767864093af8619b1a6dc2ff01dea4f643b8bdb5e8cbd51bf6756d'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
MAILPIT_IMAGE = 'axllent/mailpit:latest'
MAILPIT_IMAGE_ID = 'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
postgres_name = 'dvaia-xss-email-route-pg-' + uuid.uuid4().hex[:12]
mailpit_name = 'dvaia-xss-email-route-mail-' + uuid.uuid4().hex[:12]
run_nonce = uuid.uuid4().hex
started = []
container_ids = {}

def interrupted(signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGHUP, interrupted)

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

def verify_image(image, expected=None):
    result = run(docker + ['image', 'inspect', '--format', '{{.Id}}', image], capture_output=True, text=True)
    image_id = result.stdout.strip()
    if result.returncode or not image_id.startswith('sha256:'):
        raise RuntimeError(f'Pinned image is unavailable: {image}')
    if expected and image_id != expected:
        raise RuntimeError(f'Pinned image identity mismatch: {image}')
    return image_id

def verify_node():
    if not NODE.is_file() or NODE.is_symlink():
        raise RuntimeError('Managed Node runtime is required')
    version = subprocess.run([str(NODE), '--version'], env=base_env, capture_output=True, text=True, timeout=10)
    digest = hashlib.sha256(NODE.read_bytes()).hexdigest()
    if version.returncode or version.stdout.strip() != NODE_VERSION or digest != NODE_SHA256:
        raise RuntimeError('Managed Node identity mismatch')
    base_env['PATH'] = str(NODE.parent) + os.pathsep + base_env.get('PATH', '')
    return {'path': str(NODE), 'version': NODE_VERSION, 'sha256': digest}

def verify_browser():
    executable = os.environ.get('PUPPETEER_EXECUTABLE_PATH')
    expected = os.environ.get('PUPPETEER_EXECUTABLE_SHA256')
    if not executable or not expected or len(expected) != 64 or not Path(executable).is_file() \
            or Path(executable).is_symlink():
        raise RuntimeError('Pinned browser executable and SHA256 are required')
    digest = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    if digest != expected:
        raise RuntimeError('Pinned browser executable identity mismatch')
    return {'path': executable, 'sha256': digest}

def verify_ollama():
    request = Request('http://127.0.0.1:11434/api/tags', method='GET')
    try:
        with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
            if response.status != 200: raise RuntimeError('Ollama tags endpoint returned non-200')
            payload = json.loads(response.read(1024 * 1024 + 1))
    except Exception as error:
        raise RuntimeError('Pinned loopback Ollama model unavailable') from error
    models = payload.get('models') if isinstance(payload, dict) else None
    matches = [row for row in (models or []) if isinstance(row, dict) and (row.get('name') == MODEL or row.get('model') == MODEL)]
    if len(matches) != 1 or matches[0].get('digest') != MODEL_DIGEST:
        raise RuntimeError('Exact pinned Ollama model digest unavailable')
    return {'model': MODEL, 'digest': MODEL_DIGEST, 'endpoint': 'http://127.0.0.1:11434'}

def verify_container(name, image_id, expected_id=None):
    result = subprocess.run(docker + ['inspect', '--type', 'container', name], env=base_env,
        capture_output=True, text=True, timeout=20)
    if result.returncode:
        if result.stderr.strip() in (f'Error: No such object: {name}', f'Error: No such container: {name}'):
            return None
        raise RuntimeError(f'Container identity could not be established: {name}')
    try:
        row = json.loads(result.stdout)[0]
        labels = row['Config']['Labels'] or {}
        if result.returncode or (expected_id and row['Id'] != expected_id) or row['Image'] != image_id \
                or labels.get('dvaia.scope') != 'xss-reflected' \
                or labels.get('dvaia.owner') != str(os.getuid()) or labels.get('dvaia.run-nonce') != run_nonce:
            raise ValueError()
        return row['Id']
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError):
        raise RuntimeError(f'Owned container identity mismatch: {name}') from None

def ignore(_directory, names):
    excluded = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files', 'workshop_data',
                'vector-indexes', 'coverage', '.cache', '__pycache__'}
    suffixes = ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log')
    return [name for name in names if name in excluded or name.startswith('.env') or name.endswith(suffixes)]

def published_port(name, container_port):
    value = run(docker + ['port', name, container_port], capture_output=True, text=True).stdout.strip()
    if not value:
        raise RuntimeError(f'Owned container did not publish {container_port}')
    return int(value.splitlines()[-1].rsplit(':', 1)[1])

def wait_postgres():
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(docker + ['exec', postgres_name, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'xss_email_route_admin'], env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=min(2, max(.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            result = None
        if result is not None and result.returncode == 0: return
        time.sleep(.25)
    raise RuntimeError('Owned PostgreSQL did not become ready')

def wait_mailpit(port):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '1',
                f'http://127.0.0.1:{port}/api/v1/info'], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=min(2, max(.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            result = None
        if result is not None and result.returncode == 0: return
        time.sleep(.2)
    raise RuntimeError('Owned Mailpit did not become ready')

def owned_group_members(pgid, session_id):
    listing = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
        capture_output=True, text=True, check=True, timeout=2).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid: continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == session_id: members.append((pid, uid))
        except ProcessLookupError:
            pass
    if any(uid != os.getuid() for _pid, uid in members):
        raise RuntimeError(f'Refusing to signal process group {pgid} with a foreign process')
    return [pid for pid, _uid in members]

def stop_group(child, pgid, session_id):
    if owned_group_members(pgid, session_id): os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while owned_group_members(pgid, session_id) and time.monotonic() < deadline:
        time.sleep(.05)
    if owned_group_members(pgid, session_id): os.killpg(pgid, signal.SIGKILL)
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired: raise RuntimeError('Owned Node process did not terminate after SIGKILL')
    if owned_group_members(pgid, session_id): raise RuntimeError('Owned Node process group cleanup did not complete')

shutil.copytree(source, workspace, symlinks=True, dirs_exist_ok=True)

def freeze_tree(path):
    for item in Path(path).rglob('*'):
        if item.is_symlink():
            continue
        try:
            if item.is_dir():
                os.chmod(item, 0o555)
            else:
                os.chmod(item, 0o444 | (item.stat().st_mode & 0o111))
        except FileNotFoundError:
            pass
    os.chmod(path, 0o555)
def verify_links(path, allowed_root):
    for item in Path(path).rglob('*'):
        if item.is_symlink() and not item.resolve(strict=True).is_relative_to(Path(allowed_root).resolve()):
            raise RuntimeError(f'Dependency symlink escapes frozen snapshot: {item}')
freeze_tree(workspace)
verify_links(workspace, workspace)
verify_copy(workspace, manifest)

node_identity = verify_node()
browser_identity = verify_browser()
base_env['PUPPETEER_EXECUTABLE_SHA256'] = browser_identity['sha256']
daemon = run(docker + ['info', '--format', '{{json .}}'], capture_output=True, text=True)
try: daemon_info = json.loads(daemon.stdout)
except (TypeError, ValueError): daemon_info = None
if daemon.returncode or not daemon_info or daemon_info.get('ID') != EXPECTED_DOCKER_DAEMON_ID \
        or daemon_info.get('Name') != 'colima-dvaia-pg-verify' or daemon_info.get('Architecture') != 'aarch64':
    raise RuntimeError('Exact Colima verification daemon required')
postgres_image_id = verify_image(POSTGRES_IMAGE, POSTGRES_IMAGE_ID)
mailpit_image_id = verify_image(MAILPIT_IMAGE, MAILPIT_IMAGE_ID)
model_identity = verify_ollama() if args.live else None
(root / 'launcher-preflight.json').write_text(json.dumps({
    'dockerHost': args.docker_host, 'dockerDaemon': {'id': daemon_info['ID'], 'name': daemon_info.get('Name'), 'architecture': daemon_info.get('Architecture')},
    'node': node_identity, 'browser': browser_identity, 'manifestSha256': args.manifest_sha256,
    'dockerCli': {'path': str(DOCKER_CLI), 'sha256': DOCKER_CLI_SHA256},
    'postgresImage': postgres_image_id, 'mailpitImage': mailpit_image_id, 'ollama': model_identity,
}, indent=2, sort_keys=True) + '\n')

try:
    started.extend([postgres_name, mailpit_name])
    created = run(docker + ['run', '--detach', '--pull', 'never', '--name', postgres_name,
        '--label', 'dvaia.scope=xss-reflected', '--label', f'dvaia.owner={os.getuid()}', '--label', f'dvaia.run-nonce={run_nonce}',
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456', '-e', 'POSTGRES_USER=xss_email_route_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', postgres_image_id, '-c', 'shared_buffers=16MB', '-c', 'max_connections=50',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], capture_output=True, text=True)
    container_ids[postgres_name] = verify_container(postgres_name, postgres_image_id); wait_postgres()
    pg_port = published_port(postgres_name, '5432/tcp')
    run(docker + ['run', '--detach', '--pull', 'never', '--name', mailpit_name,
        '--label', 'dvaia.scope=xss-reflected', '--label', f'dvaia.owner={os.getuid()}', '--label', f'dvaia.run-nonce={run_nonce}', '--read-only',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=16777216', '-p', '127.0.0.1::1025',
        '-p', '127.0.0.1::8025', mailpit_image_id], stdout=subprocess.DEVNULL)
    container_ids[mailpit_name] = verify_container(mailpit_name, mailpit_image_id)
    smtp_port = published_port(mailpit_name, '1025/tcp')
    api_port = published_port(mailpit_name, '8025/tcp'); wait_mailpit(api_port)

    psql = ['psql', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'xss_email_route_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    roles = ['dvaia_identity_migration', 'dvaia_identity_runtime', 'dvaia_xss_migration', 'dvaia_xss_runtime']
    if args.ui: roles.extend(['dvaia_ctf_migration', 'dvaia_ctf_runtime'])
    for role in roles:
        run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
            stdout=subprocess.DEVNULL)
    databases = [('dvaia_test_xss_email_route_identity', roles[0], roles[1]),
                 ('dvaia_test_xss_email_route_xss', roles[2], roles[3])]
    if args.ui: databases.append(('dvaia_test_xss_email_route_ctf', roles[4], roles[5]))
    for database, migration, runtime in databases:
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
             f'GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'], stdout=subprocess.DEVNULL)

    def url(role, database):
        return f'postgresql://{quote(role)}@127.0.0.1:{pg_port}/{database}'
    env = dict(base_env, XSS_EMAIL_BUILDER_ISOLATED='yes' if args.builder else 'no', NODE_ENV='test', PG_TEST_DISPOSABLE='yes', XSS_EMAIL_ROUTE_ISOLATED='yes',
        XSS_EMAIL_ROUTE_UI='yes' if args.ui and args.scenario == 'email' else 'no',
        XSS_REFLECTED_ROUTE_UI='yes' if args.ui and args.scenario == 'reflected' else 'no',
        XSS_STORED_USER_ROUTE_UI='yes' if args.ui and args.scenario == 'stored_user' else 'no',
        XSS_STORED_LLM_ROUTE_UI='yes' if args.ui and args.scenario == 'stored_llm' else 'no',
        DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), DVAIA_XSS_RENDERED_RUNTIME_ROOT=str(runtime_root),
        LOGS_DIR=str(runtime_root / 'logs'),
        PLATFORM_DATABASE_ENGINE='postgres',
        WORKSHOP_DATABASE_ENGINE='postgres', XSS_MAIL_PROVIDER='mailpit', MAILPIT_SMTP_HOST='127.0.0.1',
        MAILPIT_SMTP_PORT=str(smtp_port), MAILPIT_API_URL=f'http://127.0.0.1:{api_port}/',
        JWT_SECRET='owned-xss-email-route-fixture-secret-at-least-32-bytes', AWS_EC2_METADATA_DISABLED='true',
        MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false', HF_HUB_OFFLINE='1',
        SANDBOX_RUNNER_URL='http://127.0.0.1:1', SSRF_TARGET_URL='http://127.0.0.1:1', ROGUE_MCP_URL='http://127.0.0.1:1')
    env.update(PG_XSS_EMAIL_ROUTE_IDENTITY_MIGRATION_URL=url(roles[0], databases[0][0]),
        PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL=url(roles[1], databases[0][0]),
        PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL=url(roles[2], databases[1][0]),
        PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL=url(roles[3], databases[1][0]))
    if args.ui:
        env.update(PG_XSS_EMAIL_ROUTE_CTF_MIGRATION_URL=url(roles[4], databases[2][0]),
            PG_XSS_EMAIL_ROUTE_CTF_RUNTIME_URL=url(roles[5], databases[2][0]))
    if args.live:
        env.update(XSS_EMAIL_ROUTE_LIVE='1', AI_PROVIDER='ollama', JUDGE_PROVIDER='ollama',
            OLLAMA_BASE_URL='http://127.0.0.1:11434', OLLAMA_MODEL='llama3.1:8b', JUDGE_MODEL='llama3.1:8b')
    else:
        env.update(XSS_EMAIL_ROUTE_LIVE='0', AI_PROVIDER='mock', JUDGE_PROVIDER='mock')

    print(f'Owned mounted XSS email workspace: {workspace}', flush=True)
    child = subprocess.Popen([str(NODE), '--test', '--test-reporter=tap', '--test-concurrency=1', test_file], cwd=workspace, env=env,
        stdout=(root / 'result.log').open('w'), stderr=subprocess.STDOUT, start_new_session=True)
    pgid, session_id = os.getpgid(child.pid), os.getsid(child.pid)
    (root / 'child-process.json').write_text(json.dumps({
        'pid': child.pid, 'pgid': pgid, 'sessionId': session_id, 'uid': os.getuid(),
    }, sort_keys=True) + '\n')
    timed_out = False
    try:
        try: returncode = child.wait(timeout=330 if args.live else (240 if args.ui else 150))
        except subprocess.TimeoutExpired: timed_out = True; returncode = None
    finally:
        stop_group(child, pgid, session_id)
        (root / 'child-process-terminal.json').write_text(json.dumps({
            'pid': child.pid, 'pgid': pgid, 'sessionId': session_id,
            'returncode': child.returncode, 'remainingMembers': owned_group_members(pgid, session_id),
        }, sort_keys=True) + '\n')
    print((root / 'result.log').read_text(), flush=True)
    if timed_out: raise RuntimeError('Mounted XSS email route integration timed out')
    if returncode: raise RuntimeError(f'Mounted XSS email route integration failed ({returncode})')
    verify_copy(workspace, manifest)
finally:
    failures = []
    result_path = root / 'result.log'
    if result_path.exists():
        (root / 'terminal-evidence.json').write_text(json.dumps({
            'scope': 'xss-rendered' if args.ui else 'xss-mounted-route',
            'testFile': test_file, 'scenario': args.scenario, 'live': args.live,
            'resultSha256': hashlib.sha256(result_path.read_bytes()).hexdigest(),
            'containerIds': container_ids,
        }, indent=2, sort_keys=True) + '\n')
    def inspect(name):
        current_id = verify_container(name, postgres_image_id if name == postgres_name else mailpit_image_id, container_ids.get(name))
        return None if current_id is None else {'id': current_id}
    def remove(name, captured_id):
        result = subprocess.run(docker + ['rm', '--force', captured_id], env=base_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode: raise RuntimeError('container removal failed')
    def absent(name, _captured_id):
        remaining = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^{name}$', '--format', '{{.Names}}'],
            env=base_env, capture_output=True, text=True, timeout=30)
        if remaining.returncode: raise RuntimeError('container absence probe failed')
        return remaining.stdout.strip() == ''
    _results, cleanup_failures = cleanup_owned_containers(started, inspect, remove, absent)
    failures.extend(cleanup_failures)
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
    if failures: raise RuntimeError('; '.join(failures))
