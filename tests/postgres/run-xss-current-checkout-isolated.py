#!/usr/bin/env python3
"""Qualify the current XSS checkout using only owned disposable resources."""
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

sys.dont_write_bytecode = True
from xss_launcher_cleanup import cleanup_owned_containers


EXPECTED_DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
EXPECTED_DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
DOCKER_CLI = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_CLI_SHA256 = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
NODE = Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_VERSION = 'v26.10.0'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
BROWSER = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
BROWSER_SHA256 = 'ccffd5c5fe77ba3212e07c2c69091f8048b73c396b4647ecaa150e1e01a04954'
MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
MAILPIT_IMAGE = 'axllent/mailpit:latest'
MAILPIT_IMAGE_ID = 'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
COHORTS = {
    'route': ('tests/postgres/xssEmailRoute.integration.test.js', False, False),
    'builder': ('tests/postgres/xssEmailBuilderRoute.integration.test.js', False, True),
    'email': ('tests/postgres/xssEmailRenderedUi.integration.test.js', True, False),
    'reflected': ('tests/postgres/xssReflectedRenderedUi.integration.test.js', True, False),
    'stored_user': ('tests/postgres/xssStoredUserRenderedUi.integration.test.js', True, False),
    'stored_llm': ('tests/postgres/xssStoredLlmRenderedUi.integration.test.js', True, False),
}
ALL16 = ('builder', 'reflected', 'stored_user', 'stored_llm', 'email')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--docker-host', required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--cohort', choices=COHORTS)
    selection.add_argument('--all16', action='store_true', help='run the five current XSS cohorts in fresh isolation')
    parser.add_argument('--live', action='store_true', help='require the exact local llama3.1:8b actor and Judge')
    return parser.parse_args()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_regular(path, digest, label):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or sha256(path) != digest:
        raise RuntimeError(f'Exact reviewed {label} required')


def source_binding(workspace):
    roots = [
        'server/agent-runtime', 'server/config', 'server/data', 'server/database/postgres',
        'server/middleware', 'server/routes', 'server/services', 'client/src', 'db/postgres',
        'tests/postgres', 'node_modules/bcryptjs', 'node_modules/express', 'node_modules/express-session',
        'node_modules/jsonwebtoken', 'node_modules/nodemailer', 'node_modules/pg', 'node_modules/puppeteer',
        'node_modules/puppeteer-core', 'node_modules/zod', 'client/node_modules/vite',
        'client/node_modules/@vitejs/plugin-react', 'client/node_modules/react',
        'client/node_modules/react-dom', 'client/node_modules/react-router-dom',
    ]
    files = [workspace / name for name in (
        'package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json',
        'client/vite.config.mjs',
    )]
    for relative in roots:
        root = workspace / relative
        if not root.is_dir() or root.is_symlink():
            raise RuntimeError(f'Required current-checkout source/dependency root unavailable: {relative}')
        for item in root.rglob('*'):
            if '__pycache__' in item.parts or item.suffix in ('.pyc', '.pyo'):
                continue
            if item.is_symlink():
                raise RuntimeError(f'Current-checkout source/dependency symlink forbidden: {item}')
            if item.is_file():
                files.append(item)
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda value: value.relative_to(workspace).as_posix()):
        if not item.is_file() or item.is_symlink():
            raise RuntimeError(f'Current-checkout binding file unavailable: {item}')
        relative = item.relative_to(workspace).as_posix().encode()
        digest.update(len(relative).to_bytes(8, 'big'))
        digest.update(relative)
        size = item.stat().st_size
        digest.update(size.to_bytes(8, 'big'))
        with item.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
    return {'sha256': digest.hexdigest(), 'files': len(files)}


def checkout_state(workspace, environment):
    result = subprocess.run(['git', 'status', '--porcelain=v1', '-z', '--untracked-files=all'], cwd=workspace,
        env=environment, capture_output=True, timeout=30, check=True)
    return hashlib.sha256(result.stdout).hexdigest()


def orchestrate_all16(args, workspace):
    if not args.live:
        raise RuntimeError('--all16 requires --live; controlled providers are not all-16 qualification')
    initial = source_binding(workspace)
    state_env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
    initial_state = checkout_state(workspace, state_env)
    for cohort in ALL16:
        command = [sys.executable, str(Path(__file__).resolve()), '--docker-host', args.docker_host,
                   '--cohort', cohort, '--live']
        subprocess.run(command, cwd=workspace, env=state_env, check=True)
    if source_binding(workspace) != initial or checkout_state(workspace, state_env) != initial_state:
        raise RuntimeError('Current checkout changed during all-16 qualification')


def main(args):
    if args.docker_host != EXPECTED_DOCKER_HOST:
        raise RuntimeError('Exact owned Colima verification Docker host is required')
    def interrupted(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + signum)
    for handled in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(handled, interrupted)
    workspace = Path(__file__).resolve().parents[2]
    if args.all16:
        orchestrate_all16(args, workspace)
        return
    if not args.live:
        raise RuntimeError('Current-checkout qualification requires --live')
    cohort = args.cohort
    test_file, needs_ctf, builder = COHORTS[cohort]
    if not (workspace / test_file).is_file():
        raise RuntimeError(f'Current checkout lacks selected XSS test: {test_file}')

    root = Path(tempfile.mkdtemp(prefix=f'dvaia-xss-current-{cohort}-')).resolve()
    os.chmod(root, 0o700)
    runtime_root = root / 'runtime'; runtime_root.mkdir(mode=0o700)
    for name in ('logs', 'artifacts', 'vite-cache', 'browser-ui', 'browser-grader'):
        (runtime_root / name).mkdir(mode=0o700)
    private_home = root / 'home'; private_home.mkdir(mode=0o700)
    private_tmp = root / 'tmp'; private_tmp.mkdir(mode=0o700)
    empty_env = root / 'empty.env'; empty_env.write_bytes(b''); os.chmod(empty_env, 0o600)
    base_env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(private_home),
                'TMPDIR': str(private_tmp), 'PUPPETEER_CACHE_DIR': str(private_home / '.cache' / 'puppeteer')}
    verify_regular(DOCKER_CLI, DOCKER_CLI_SHA256, 'Docker executable')
    verify_regular(NODE, NODE_SHA256, 'Node executable')
    verify_regular(BROWSER, BROWSER_SHA256, 'browser executable')
    version = subprocess.run([str(NODE), '--version'], env=base_env, capture_output=True, text=True, timeout=10, check=True)
    if version.stdout.strip() != NODE_VERSION:
        raise RuntimeError('Managed Node version mismatch')
    base_env['PATH'] = str(NODE.parent) + os.pathsep + base_env['PATH']
    docker = [str(DOCKER_CLI), '--host', args.docker_host]

    def run(command, **kwargs):
        kwargs.setdefault('timeout', 60)
        return subprocess.run(command, check=True, env=base_env, **kwargs)

    daemon = json.loads(run(docker + ['info', '--format', '{{json .}}'], capture_output=True, text=True).stdout)
    if daemon.get('ID') != EXPECTED_DOCKER_DAEMON_ID or daemon.get('Name') != 'colima-dvaia-pg-verify' \
            or daemon.get('Architecture') != 'aarch64':
        raise RuntimeError('Exact Colima verification daemon required')

    def image_id(image, expected):
        found = run(docker + ['image', 'inspect', '--format', '{{.Id}}', image], capture_output=True, text=True).stdout.strip()
        if found != expected:
            raise RuntimeError(f'Pinned image identity mismatch: {image}')
        return found

    postgres_image = image_id(POSTGRES_IMAGE, POSTGRES_IMAGE_ID)
    mailpit_image = image_id(MAILPIT_IMAGE, MAILPIT_IMAGE_ID)
    with build_opener(ProxyHandler({})).open(Request('http://127.0.0.1:11434/api/tags'), timeout=10) as response:
        tags = json.loads(response.read(1024 * 1024 + 1))
    matches = [row for row in tags.get('models', []) if row.get('name') == MODEL or row.get('model') == MODEL]
    if len(matches) != 1 or matches[0].get('digest') != MODEL_DIGEST:
        raise RuntimeError('Exact pinned Ollama model digest unavailable')
    before_binding = source_binding(workspace)
    before_state = checkout_state(workspace, base_env)
    private_files = {name: sha256(workspace / name) for name in ('.env', '.env.local') if (workspace / name).is_file()}
    (root / 'launcher-preflight.json').write_text(json.dumps({
        'cohort': cohort, 'workspace': str(workspace), 'sourceBinding': before_binding,
        'checkoutStateSha256': before_state, 'dockerHost': args.docker_host,
        'dockerDaemon': {'id': daemon['ID'], 'name': daemon['Name'], 'architecture': daemon['Architecture']},
        'node': {'path': str(NODE), 'version': NODE_VERSION, 'sha256': NODE_SHA256},
        'browser': {'path': str(BROWSER), 'sha256': BROWSER_SHA256},
        'dockerCli': {'path': str(DOCKER_CLI), 'sha256': DOCKER_CLI_SHA256},
        'postgresImage': postgres_image, 'mailpitImage': mailpit_image,
        'ollama': {'endpoint': 'http://127.0.0.1:11434', 'model': MODEL, 'digest': MODEL_DIGEST},
    }, indent=2, sort_keys=True) + '\n')

    run_nonce = uuid.uuid4().hex
    postgres_name = 'dvaia-xss-current-pg-' + uuid.uuid4().hex[:12]
    mailpit_name = 'dvaia-xss-current-mail-' + uuid.uuid4().hex[:12]
    started = []
    container_ids = {}

    def verify_container(name, image, expected_id=None):
        result = subprocess.run(docker + ['inspect', '--type', 'container', name], env=base_env,
            capture_output=True, text=True, timeout=20)
        if result.returncode:
            if 'No such' in result.stderr:
                return None
            raise RuntimeError(f'Container identity could not be established: {name}')
        row = json.loads(result.stdout)[0]; labels = row['Config']['Labels'] or {}
        if (expected_id and row['Id'] != expected_id) or row['Image'] != image \
                or labels.get('dvaia.scope') != 'xss-current-checkout' \
                or labels.get('dvaia.owner') != str(os.getuid()) or labels.get('dvaia.run-nonce') != run_nonce:
            raise RuntimeError(f'Owned container identity mismatch: {name}')
        return row['Id']

    def published_port(name, container_port):
        value = run(docker + ['port', name, container_port], capture_output=True, text=True).stdout.strip()
        return int(value.splitlines()[-1].rsplit(':', 1)[1])

    def wait_postgres():
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            result = subprocess.run(docker + ['exec', postgres_name, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'xss_email_route_admin'], env=base_env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2)
            if result.returncode == 0:
                return
            time.sleep(.25)
        raise RuntimeError('Owned PostgreSQL did not become ready')

    def wait_mailpit(port):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                with build_opener(ProxyHandler({})).open(f'http://127.0.0.1:{port}/api/v1/info', timeout=1) as response:
                    if response.status == 200:
                        return
            except Exception:
                pass
            time.sleep(.2)
        raise RuntimeError('Owned Mailpit did not become ready')

    child = None; pgid = None; session_id = None

    def group_members():
        if pgid is None:
            return []
        listing = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
            capture_output=True, text=True, timeout=3, check=True).stdout
        members = []
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 3 and int(fields[1]) == pgid:
                pid, uid = int(fields[0]), int(fields[2])
                try:
                    if os.getsid(pid) == session_id:
                        members.append((pid, uid))
                except ProcessLookupError:
                    pass
        if any(uid != os.getuid() for _pid, uid in members):
            raise RuntimeError('Refusing to signal a process group with a foreign process')
        return [pid for pid, _uid in members]

    def stop_group():
        if child is None:
            return
        if group_members():
            os.killpg(pgid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while group_members() and time.monotonic() < deadline:
            time.sleep(.05)
        if group_members():
            os.killpg(pgid, signal.SIGKILL)
        child.wait(timeout=5)
        if group_members():
            raise RuntimeError('Owned Node process group cleanup did not complete')

    try:
        labels = ['--label', 'dvaia.scope=xss-current-checkout', '--label', f'dvaia.owner={os.getuid()}',
                  '--label', f'dvaia.run-nonce={run_nonce}']
        started.append(postgres_name)
        run(docker + ['run', '--detach', '--pull', 'never', '--name', postgres_name, *labels,
            '--tmpfs', '/var/lib/postgresql:rw,size=268435456', '-e', 'POSTGRES_USER=xss_email_route_admin',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p', '127.0.0.1::5432', postgres_image, '-c', 'shared_buffers=16MB', '-c', 'max_connections=50',
            '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
        container_ids[postgres_name] = verify_container(postgres_name, postgres_image); wait_postgres()
        pg_port = published_port(postgres_name, '5432/tcp')
        started.append(mailpit_name)
        run(docker + ['run', '--detach', '--pull', 'never', '--name', mailpit_name, *labels, '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=16777216', '-p', '127.0.0.1::1025',
            '-p', '127.0.0.1::8025', mailpit_image], stdout=subprocess.DEVNULL)
        container_ids[mailpit_name] = verify_container(mailpit_name, mailpit_image)
        smtp_port = published_port(mailpit_name, '1025/tcp'); api_port = published_port(mailpit_name, '8025/tcp')
        wait_mailpit(api_port)

        psql = ['psql', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'xss_email_route_admin',
                '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        roles = ['dvaia_identity_migration', 'dvaia_identity_runtime', 'dvaia_xss_migration', 'dvaia_xss_runtime']
        if needs_ctf:
            roles += ['dvaia_ctf_migration', 'dvaia_ctf_runtime', 'dvaia_ctf_delivery']
        for role in roles:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],
                stdout=subprocess.DEVNULL)
        databases = [('dvaia_test_xss_email_route_identity', roles[0], roles[1]),
                     ('dvaia_test_xss_email_route_xss', roles[2], roles[3])]
        if needs_ctf:
            databases.append(('dvaia_test_xss_email_route_ctf', roles[4], roles[5]))
        for database, migration, runtime in databases:
            run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
            run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                 f'GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'], stdout=subprocess.DEVNULL)

        def url(role, database):
            return f'postgresql://{quote(role)}@127.0.0.1:{pg_port}/{database}'

        receipt = root / 'current-checkout-receipt.json'
        receipt.write_text(json.dumps({
            'version': 1, 'cohort': cohort, 'workspace': str(workspace),
            'workspaceDev': str(workspace.stat().st_dev), 'workspaceIno': str(workspace.stat().st_ino),
            'runtimeRoot': str(runtime_root), 'sourceDigest': before_binding['sha256'], 'runNonce': run_nonce,
            'databasePort': pg_port, 'mailpitSmtpPort': smtp_port, 'mailpitApiPort': api_port,
        }, sort_keys=True) + '\n')
        os.chmod(receipt, 0o600)
        receipt_digest = sha256(receipt)
        env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', XSS_EMAIL_ROUTE_ISOLATED='yes',
            XSS_EMAIL_BUILDER_ISOLATED='yes' if builder else 'no', XSS_EMAIL_ROUTE_LIVE='1',
            XSS_EMAIL_ROUTE_UI='yes' if cohort == 'email' else 'no',
            XSS_REFLECTED_ROUTE_UI='yes' if cohort == 'reflected' else 'no',
            XSS_STORED_USER_ROUTE_UI='yes' if cohort == 'stored_user' else 'no',
            XSS_STORED_LLM_ROUTE_UI='yes' if cohort == 'stored_llm' else 'no',
            DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace), DVAIA_XSS_RENDERED_RUNTIME_ROOT=str(runtime_root),
            DVAIA_XSS_CURRENT_CHECKOUT='yes', DVAIA_XSS_CURRENT_CHECKOUT_RECEIPT=str(receipt),
            DVAIA_XSS_CURRENT_CHECKOUT_RECEIPT_SHA256=receipt_digest, DVAIA_EMPTY_DOTENV_PATH=str(empty_env),
            LOGS_DIR=str(runtime_root / 'logs'), PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
            XSS_MAIL_PROVIDER='mailpit', MAILPIT_SMTP_HOST='127.0.0.1', MAILPIT_SMTP_PORT=str(smtp_port),
            MAILPIT_API_URL=f'http://127.0.0.1:{api_port}/',
            JWT_SECRET='owned-xss-current-fixture-secret-at-least-32-bytes', AWS_EC2_METADATA_DISABLED='true',
            MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false', HF_HUB_OFFLINE='1',
            SANDBOX_RUNNER_URL='http://127.0.0.1:1', SSRF_TARGET_URL='http://127.0.0.1:1',
            ROGUE_MCP_URL='http://127.0.0.1:1', AI_PROVIDER='ollama', JUDGE_PROVIDER='ollama',
            OLLAMA_BASE_URL='http://127.0.0.1:11434', OLLAMA_MODEL=MODEL, JUDGE_MODEL=MODEL,
            PUPPETEER_EXECUTABLE_PATH=str(BROWSER), PUPPETEER_EXECUTABLE_SHA256=BROWSER_SHA256,
            XSS_RENDERED_CHROME_EXECUTABLE=str(BROWSER), XSS_RENDERED_CHROME_SHA256=BROWSER_SHA256)
        env.update(PG_XSS_EMAIL_ROUTE_IDENTITY_MIGRATION_URL=url(roles[0], databases[0][0]),
            PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL=url(roles[1], databases[0][0]),
            PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL=url(roles[2], databases[1][0]),
            PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL=url(roles[3], databases[1][0]))
        if needs_ctf:
            env.update(PG_XSS_EMAIL_ROUTE_CTF_MIGRATION_URL=url(roles[4], databases[2][0]),
                PG_XSS_EMAIL_ROUTE_CTF_RUNTIME_URL=url(roles[5], databases[2][0]))

        result_log = root / 'result.log'
        child = subprocess.Popen([str(NODE), '--require', str(workspace / 'tests/postgres/xssNoWorkspaceEnv.js'),
            '--test', '--test-reporter=tap', '--test-concurrency=1', test_file], cwd=workspace, env=env,
            stdout=result_log.open('w'), stderr=subprocess.STDOUT, start_new_session=True)
        pgid, session_id = os.getpgid(child.pid), os.getsid(child.pid)
        timed_out = False
        try:
            try:
                returncode = child.wait(timeout=420 if cohort in ('builder', 'stored_user', 'stored_llm') else 360)
            except subprocess.TimeoutExpired:
                timed_out = True; returncode = None
        finally:
            stop_group()
        print(result_log.read_text(), flush=True)
        if timed_out:
            raise RuntimeError(f'Current-checkout XSS {cohort} qualification timed out')
        if returncode:
            raise RuntimeError(f'Current-checkout XSS {cohort} qualification failed ({returncode})')
        after_binding = source_binding(workspace)
        after_state = checkout_state(workspace, base_env)
        if after_binding != before_binding or after_state != before_state:
            raise RuntimeError('Current checkout changed during qualification')
        if any(sha256(workspace / name) != digest for name, digest in private_files.items()):
            raise RuntimeError('Private workspace environment changed during qualification')
    finally:
        result_path = root / 'result.log'
        (root / 'terminal-evidence.json').write_text(json.dumps({
            'cohort': cohort, 'testFile': test_file, 'live': True,
            'resultSha256': sha256(result_path) if result_path.exists() else None,
            'containerIds': container_ids,
        }, indent=2, sort_keys=True) + '\n')

        def inspect(name):
            image = postgres_image if name == postgres_name else mailpit_image
            current = verify_container(name, image, container_ids.get(name))
            return None if current is None else {'id': current}

        def remove(_name, captured):
            result = subprocess.run(docker + ['rm', '--force', captured], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if result.returncode:
                raise RuntimeError('container removal failed')

        def absent(name, _captured):
            result = subprocess.run(docker + ['ps', '-a', '--filter', f'name=^{name}$', '--format', '{{.Names}}'],
                env=base_env, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError('container absence probe failed')
            return result.stdout.strip() == ''

        _results, failures = cleanup_owned_containers(started, inspect, remove, absent)
        print(f'Owned XSS current-checkout cleanup complete; evidence retained: {root}', flush=True)
        if failures:
            raise RuntimeError('; '.join(failures))


if __name__ == '__main__':
    try:
        main(parse_args())
    except Exception as error:
        print(f'XSS current-checkout qualification failed: {error}', file=sys.stderr)
        raise
