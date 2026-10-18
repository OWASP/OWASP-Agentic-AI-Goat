#!/usr/bin/env python3
"""Run XSS email dispatch provenance against an owned PostgreSQL 18 container."""
import argparse, os, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import quote

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--mailpit', action='store_true', help='also run the native dispatch test against an owned Mailpit')
args = parser.parse_args()
source = Path(__file__).resolve().parents[2]
root = Path(tempfile.mkdtemp(prefix='dvaia-xss-email-dispatch-'))
workspace = root / 'source'; workspace.mkdir(); os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-xss-email-test-' + uuid.uuid4().hex[:12]
mailpit_container = 'dvaia-xss-email-mailpit-' + uuid.uuid4().hex[:12]
postgres_started = False
mailpit_started = False

def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)

def published_port(name, container_port):
    output = run(docker + ['port', name, str(container_port)], capture_output=True, text=True).stdout.strip()
    if not output:
        raise RuntimeError(f'Owned container did not publish port {container_port}')
    return int(output.splitlines()[-1].rsplit(':', 1)[1])

def ignore(_directory, names):
    return [name for name in names if name in {'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data','vector-indexes','coverage','.cache','__pycache__'}
            or name.startswith('.env') or any(name.endswith(suffix) for suffix in ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]

def interrupted(signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, interrupted)

def owned_group_members(pgid, session_id):
    listing = subprocess.run(['ps','-axo','pid=,pgid=,uid='], env=base_env,
        capture_output=True, text=True, check=True, timeout=2).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == session_id:
                members.append((pid, uid))
        except ProcessLookupError:
            continue
    foreign = [pid for pid, uid in members if uid != os.getuid()]
    if foreign:
        raise RuntimeError(f'Refusing to signal process group {pgid}; it contains foreign processes')
    return [pid for pid, _uid in members]

def signal_owned_group(pgid, session_id, requested_signal):
    if not owned_group_members(pgid, session_id):
        return False
    os.killpg(pgid, requested_signal)
    return True

def stop_owned_group(child, pgid, session_id):
    signal_owned_group(pgid, session_id, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while owned_group_members(pgid, session_id) and time.monotonic() < deadline:
        child.poll()
        time.sleep(.05)
    if owned_group_members(pgid, session_id):
        signal_owned_group(pgid, session_id, signal.SIGKILL)
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Owned Node process group did not terminate after SIGKILL')
    verify_deadline = time.monotonic() + 2
    while owned_group_members(pgid, session_id) and time.monotonic() < verify_deadline:
        time.sleep(.05)
    if owned_group_members(pgid, session_id):
        raise RuntimeError('Owned Node process group cleanup did not complete')

for directory in ['server','db','tests']:
    shutil.copytree(source / directory, workspace / directory, ignore=ignore)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + ['run','--detach','--name',container,'--tmpfs','/var/lib/postgresql:rw,size=268435456',
        '-e','POSTGRES_USER=xss_email_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
        '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
        '-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    postgres_started = True
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            ready = subprocess.run(docker + ['exec',container,'pg_isready','-h','127.0.0.1','-U','xss_email_test_admin'], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=min(2, max(.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            ready = None
        if ready is not None and ready.returncode == 0: break
        time.sleep(.25)
    else: raise RuntimeError('Owned PostgreSQL container did not become ready')
    address = run(docker + ['port',container,'5432'], capture_output=True, text=True).stdout.strip()
    port = int(address.rsplit(':',1)[1])
    psql = ['psql','-h','127.0.0.1','-p',str(port),'-U','xss_email_test_admin','-d','postgres','-v','ON_ERROR_STOP=1']
    migration, runtime = 'dvaia_identity_migration', 'dvaia_identity_runtime'
    database = 'dvaia_test_xss_email_dispatch_identity'
    for role in [migration,runtime]:
        run(psql + ['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
    run(psql + ['-c',f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
    run(psql + ['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'], stdout=subprocess.DEVNULL)
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes', DVAIA_ISOLATED_TEST_WORKSPACE=str(workspace),
        PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres', AI_PROVIDER='mock', JUDGE_PROVIDER='mock',
        AWS_EC2_METADATA_DISABLED='true', MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false', HF_HUB_OFFLINE='1',
        SANDBOX_RUNNER_URL='http://127.0.0.1:1', SSRF_TARGET_URL='http://127.0.0.1:1', ROGUE_MCP_URL='http://127.0.0.1:1',
        MAILPIT_API_URL='http://127.0.0.1:1', MAILPIT_SMTP_HOST='127.0.0.1', MAILPIT_SMTP_PORT='1')
    env['PG_XSS_EMAIL_DISPATCH_MIGRATION_URL'] = f'postgresql://{quote(migration)}@127.0.0.1:{port}/{database}'
    env['PG_XSS_EMAIL_DISPATCH_RUNTIME_URL'] = f'postgresql://{quote(runtime)}@127.0.0.1:{port}/{database}'
    if args.mailpit:
        run(docker + ['run','--detach','--pull','never','--name',mailpit_container,
            '--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16777216',
            '-p','127.0.0.1::1025','-p','127.0.0.1::8025','axllent/mailpit:latest'], stdout=subprocess.DEVNULL)
        mailpit_started = True
        smtp_port = published_port(mailpit_container, '1025/tcp')
        api_port = published_port(mailpit_container, '8025/tcp')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            probe = subprocess.run(['curl','--fail','--silent','--show-error','--max-time','1',
                f'http://127.0.0.1:{api_port}/api/v1/info'], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if probe.returncode == 0: break
            time.sleep(.2)
        else: raise RuntimeError('Owned Mailpit container did not become ready')
        env.update(XSS_EMAIL_DISPATCH_MAILPIT='yes', MAILPIT_SMTP_HOST='127.0.0.1',
            MAILPIT_SMTP_PORT=str(smtp_port), MAILPIT_API_URL=f'http://127.0.0.1:{api_port}/')
    print(f'Owned XSS email dispatch workspace: {workspace}', flush=True)
    child = None
    child_pgid = None
    child_session_id = None
    timed_out = False
    try:
        with (root / 'result.log').open('w') as log:
            child = subprocess.Popen(['node','--test','--test-reporter=tap','--test-concurrency=1',
                'tests/postgres/xssEmailDispatch.integration.test.js'], cwd=workspace, env=env,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            child_pgid = os.getpgid(child.pid)
            child_session_id = os.getsid(child.pid)
            try:
                returncode = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
                returncode = None
    finally:
        if child is not None and child_pgid is not None and child_session_id is not None:
            stop_owned_group(child, child_pgid, child_session_id)
    print((root / 'result.log').read_text(), flush=True)
    if timed_out: raise RuntimeError('XSS email dispatch integration timed out after 180 seconds')
    if returncode: raise RuntimeError(f'XSS email dispatch integration failed ({returncode})')
finally:
    if mailpit_started:
        subprocess.run(docker + ['rm','--force',mailpit_container], env=base_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining_mailpit = run(docker + ['ps','-a','--filter',f'name=^{mailpit_container}$','--format','{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining_mailpit: raise RuntimeError('Owned Mailpit cleanup did not complete')
    if postgres_started:
        subprocess.run(docker + ['rm','--force',container], env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        remaining = run(docker + ['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'], capture_output=True, text=True).stdout.strip()
        if remaining: raise RuntimeError('Owned container cleanup did not complete')
    print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)
