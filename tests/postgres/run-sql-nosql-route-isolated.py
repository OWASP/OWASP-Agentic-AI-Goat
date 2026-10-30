#!/usr/bin/env python3
"""Run mounted ARIA/NOVA qualification in an owned source copy and PG18 tmpfs."""

import argparse
import sys
sys.dont_write_bytecode = True
from sql_nosql_package_contract import validate_package, digest, prepare_evidence_root
from sql_nosql_process_ownership import OwnedProcesses
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, validate_container_layout, cleanup_owned, CONTAINER
import json
from sql_nosql_route_contract import OBJECTIVES, selected_objectives, cohort_timeout_seconds, validate_model_inventory
import os
from pathlib import Path
import signal
import secrets
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--docker-daemon-id', required=True)
parser.add_argument('--postgres-image-id', required=True)
parser.add_argument('--package', required=True, help='Absolute frozen package/source directory')
parser.add_argument('--manifest', required=True)
parser.add_argument('--manifest-sha256', required=True)
parser.add_argument('--node', required=True)
parser.add_argument('--node-sha256', required=True)
parser.add_argument('--evidence-root', help='Absolute pre-created empty owned directory outside source/package')
parser.add_argument('--objectives', default=','.join(OBJECTIVES))
parser.add_argument('--observation-controls', action='store_true', help='Qualify actual duplicate membership and repeated observation controls')
parser.add_argument('--lifecycle', action='store_true', help='Also qualify reset-before-Judge and earned sibling preservation for each selected family')
parser.add_argument('--fixed-session', action='store_true', help='Also qualify fixed-mode and session history boundaries for each selected family')
parser.add_argument('--credit-gate', action='store_true', help='Run only actual positive credit and provider-free scripted denial for selected objectives')
parser.add_argument('--credit-gate-control-only', action='store_true', help='Run only provider-free scripted credit denials for the exact credit-gate objectives')
parser.add_argument('--bootstrap-only', action='store_true', help='Stop after owned schema/seed bootstrap and cleanup without model inventory or cohort')
args = parser.parse_args()
selected_ids = selected_objectives(args.objectives)
if args.credit_gate and selected_ids != ('sqli_1', 'nosqli_1'):
    raise ValueError('Credit gate requires exactly sqli_1,nosqli_1')
if args.credit_gate_control_only and (not args.credit_gate or selected_ids != ('sqli_1', 'nosqli_1')):
    raise ValueError('Control-only requires the exact two-objective credit gate')
cohort_timeout = cohort_timeout_seconds(selected_ids, lifecycle=args.lifecycle, fixed_session=args.fixed_session,
    observation_controls=args.observation_controls, credit_gate=args.credit_gate)

workspace = Path(args.package)
manifest_path = Path(args.manifest)
node = Path(args.node)
manifest = validate_package(workspace, manifest_path, args.manifest_sha256, node, args.node_sha256)
for filename in ('run-sql-nosql-route-isolated.py', 'sql_nosql_route_contract.py', 'sql_nosql_package_contract.py', 'sql_nosql_docker_ownership.py', 'sql_nosql_process_ownership.py'):
    if digest(Path(__file__).parent / filename) != manifest['files']['tests/postgres/' + filename]:
        raise RuntimeError('Executing launcher contracts differ from immutable package')
with tempfile.TemporaryDirectory(prefix='owasp-ai-goat-sql-nosql-offline-') as offline_logs:
    offline_env = dict((key, os.environ[key]) for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ)
    offline_env.update(NODE_ENV='test', SQL_NOSQL_OFFLINE_COMPOSITION='1',
        PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
        LOGS_DIR=offline_logs, JWT_SECRET='offline-composition-only-00000000000000000000000000000000',
        IDENTITY_DATABASE_URL='postgresql://offline@127.0.0.1:1/offline',
        AWS_EC2_METADATA_DISABLED='true')
    offline = subprocess.run([str(node), 'tests/postgres/sql-nosql-offline-composition-smoke.js'],
        cwd=workspace, env=offline_env, capture_output=True, text=True, timeout=30)
    if offline.returncode or offline.stdout.strip() != 'SQL_NOSQL_OFFLINE_COMPOSITION_READY':
        raise RuntimeError('Offline SQL/NOVA route/grader composition closure failed')
root = prepare_evidence_root(args.evidence_root, [workspace.parent, Path(__file__).resolve().parents[2]]) if args.evidence_root else Path(tempfile.mkdtemp(prefix='owasp-ai-goat-sql-nosql-route-')).resolve()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
run_nonce = uuid.uuid4().hex
container = 'owasp-ai-goat-sql-nosql-route-' + run_nonce
labels = {'owasp-ai-goat.qualification.scope': 'sql_nosql_route_actual8b', 'owasp-ai-goat.qualification.nonce': run_nonce, 'owasp-ai-goat.qualification.uid': str(os.getuid())}
creation_intended = False
captured_id = None

def docker_command(arguments):
    return subprocess.run(docker + arguments, env=base_env, capture_output=True, text=True, timeout=30)

def record_ownership(name, value):
    target = root / name
    with target.open('w') as output:
        os.chmod(target, 0o600)
        json.dump(value, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def members(pgid, session_id):
    output = subprocess.run(['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
                            capture_output=True, text=True, check=True, timeout=2).stdout
    result = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid, uid = int(fields[0]), int(fields[2])
        try:
            if os.getsid(pid) == session_id:
                result.append((pid, uid))
        except ProcessLookupError:
            pass
    if any(uid != os.getuid() for _pid, uid in result):
        raise RuntimeError('Refusing to signal a process group containing foreign processes')
    return [pid for pid, _uid in result]


def stop_group(child, pgid, session_id):
    if members(pgid, session_id):
        os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while members(pgid, session_id) and time.monotonic() < deadline:
        child.poll()
        time.sleep(0.05)
    if members(pgid, session_id):
        os.killpg(pgid, signal.SIGKILL)
    child.wait(timeout=5)
    if members(pgid, session_id):
        raise RuntimeError('Owned Node process group cleanup did not complete')


owned_processes = OwnedProcesses(stop_group, lambda value: record_ownership('process-' + value['name'] + '.json', value))
owned_processes.install()

try:
    verify_daemon(docker_command, args.docker_daemon_id)
    verify_image(docker_command, args.postgres_image_id)
    record_ownership('container-intent.json', {'name': container, 'labels': labels,
        'imageId': args.postgres_image_id, 'daemonId': args.docker_daemon_id, 'status': 'creation_intended'})
    creation_intended = True
    label_args = [argument for key, value in labels.items() for argument in ['--label', key + '=' + value]]
    created = run(docker + ['run', '--detach', '--name', container] + label_args + [
        '--memory', '536870912', '--cpus', '2', '--pids-limit', '256',
        '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
        '-e', 'POSTGRES_USER=sql_nosql_route_admin',
        '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
        '-p', '127.0.0.1::5432', args.postgres_image_id,
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=48',
        '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], capture_output=True, text=True)
    captured_id = created.stdout.strip()
    if not CONTAINER.fullmatch(captured_id):
        captured_id = None
        raise RuntimeError('Docker did not return a full container identity')
    record_ownership('container-created.json', {'name': container, 'containerId': captured_id, 'labels': labels})
    ownership = inspect_owned(docker_command, name=container, labels=labels,
        image=args.postgres_image_id, captured_id=captured_id)
    if ownership is None:
        raise RuntimeError('Created container is absent')
    owned_port = validate_container_layout(ownership)
    record_ownership('container-ownership.json', {'containerId': captured_id, 'loopbackPort': owned_port,
        'imageId': args.postgres_image_id, 'labels': labels, 'layoutVerified': True})
    deadline = time.monotonic() + 20
    ready_count = 0
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(docker + ['exec', container, 'psql', '-U', 'sql_nosql_route_admin',
                '-d', 'postgres', '-c', 'SELECT 1'], env=base_env, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2)
        except subprocess.TimeoutExpired:
            probe = None
        ready_count = ready_count + 1 if probe is not None and probe.returncode == 0 else 0
        if ready_count >= 5:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError('Owned PostgreSQL container did not become ready')

    port = owned_port
    psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'sql_nosql_route_admin',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    env = dict(base_env, NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
        SQL_NOSQL_ROUTE_ISOLATED='1', OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),
        PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
        AI_PROVIDER='ollama', JUDGE_PROVIDER='ollama', OLLAMA_MODEL='llama3.1:8b',
        JUDGE_MODEL='llama3.1:8b', OLLAMA_BASE_URL='http://127.0.0.1:11434',
        JWT_SECRET=secrets.token_hex(32), AWS_EC2_METADATA_DISABLED='true',
        MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false',
        HF_HUB_OFFLINE='1', SANDBOX_RUNNER_URL='http://127.0.0.1:1',
        SSRF_TARGET_URL='http://127.0.0.1:1', ROGUE_MCP_URL='http://127.0.0.1:1',
        MAILPIT_API_URL='http://127.0.0.1:1', MAILPIT_SMTP_HOST='127.0.0.1',
        MAILPIT_SMTP_PORT='1', LOGS_DIR=str(root / 'logs'))
    env['SQL_NOSQL_ROUTE_OBJECTIVES'] = ','.join(selected_ids)
    env['SQL_NOSQL_ROUTE_OBSERVATION_CONTROLS'] = '1' if args.observation_controls else '0'
    env['SQL_NOSQL_ROUTE_LIFECYCLE'] = '1' if args.lifecycle else '0'
    env['SQL_NOSQL_ROUTE_FIXTURE_NONCE'] = run_nonce
    env['SQL_NOSQL_ROUTE_FIXED_SESSION'] = '1' if args.fixed_session else '0'
    env['SQL_NOSQL_ROUTE_CREDIT_GATE'] = '1' if args.credit_gate else '0'
    env['SQL_NOSQL_ROUTE_CREDIT_GATE_CONTROL_ONLY'] = '1' if args.credit_gate_control_only else '0'
    for family, database in [('identity', 'owasp_ai_goat_test_sql_nosql_route_identity'),
                             ('aria', 'owasp_ai_goat_test_sql_nosql_route_aria'),
                             ('nova', 'owasp_ai_goat_test_sql_nosql_route_nova')]:
        migration, runtime = f'dvaia_{family}_migration', f'dvaia_{family}_runtime'
        for role in [migration, runtime]:
            run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'], stdout=subprocess.DEVNULL)
        run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'], stdout=subprocess.DEVNULL)
        prefix = {'identity': 'IDENTITY', 'aria': 'SQL_WORKSHOP', 'nova': 'NOSQL_WORKSHOP'}[family]
        env[f'{prefix}_MIGRATION_DATABASE_URL'] = f'postgresql://{migration}@127.0.0.1:{port}/{database}'
        env[f'{prefix}_DATABASE_URL'] = f'postgresql://{runtime}@127.0.0.1:{port}/{database}'

    # Keep migration authority in a separate, non-model process.
    bootstrap_env = {key: value for key, value in env.items()
                     if key in base_env or key in {
                         'NODE_ENV', 'PG_TEST_DISPOSABLE', 'SQL_NOSQL_ROUTE_ISOLATED',
                         'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE', 'PLATFORM_DATABASE_ENGINE',
                         'WORKSHOP_DATABASE_ENGINE', 'SQL_NOSQL_ROUTE_FIXED_SESSION', 'SQL_NOSQL_ROUTE_FIXTURE_NONCE', 'LOGS_DIR'}
                     or key.endswith('_DATABASE_URL')}
    bootstrap_log = root / 'bootstrap.log'
    with bootstrap_log.open('w') as output:
        os.chmod(bootstrap_log, 0o600)
        bootstrap = owned_processes.launch([str(node), 'tests/postgres/bootstrap-sql-nosql-route.js'],
            name='bootstrap', cwd=workspace, env=bootstrap_env, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True)
        bootstrap_pgid = bootstrap_session = bootstrap.pid
        try:
            bootstrap_code = bootstrap.wait(timeout=180)
        finally:
            owned_processes.finish(bootstrap)
    if bootstrap_code != 0 or bootstrap_log.read_text().strip() != 'SQL_NOSQL_ROUTE_BOOTSTRAP_READY':
        raise RuntimeError('Separate SQL/NOVA bootstrap failed; inspect owned bootstrap.log')
    env = {key: value for key, value in env.items() if 'MIGRATION' not in key}
    env['SQL_NOSQL_ROUTE_BOOTSTRAPPED'] = '1'

    if args.bootstrap_only:
        print(f'Owned SQL/NOVA bootstrap-only workspace passed: {workspace}', flush=True)
    else:
        model_before = None
        if not args.credit_gate_control_only:
            tags = run(['curl', '--fail', '--silent', '--show-error', '--max-time', '5',
                        'http://127.0.0.1:11434/api/tags'], capture_output=True, text=True)
            model_before = validate_model_inventory(tags.stdout)
            (root / 'model-before.json').write_text(json.dumps(model_before) + '\n')

        print(f'Owned SQL/NOVA route workspace: {workspace}', flush=True)
        child = owned_processes.launch([str(node), '--test', '--test-reporter=tap', '--test-concurrency=1',
            'tests/postgres/sqlNoSqlRoute.integration.test.js'], name='cohort', cwd=workspace, env=env,
            stdout=(root / 'result.log').open('w'), stderr=subprocess.STDOUT, start_new_session=True)
        pgid = session_id = child.pid
        timed_out = False
        try:
            try:
                returncode = child.wait(timeout=cohort_timeout + 120)
            except subprocess.TimeoutExpired:
                timed_out, returncode = True, None
        finally:
            owned_processes.finish(child)
        if not args.credit_gate_control_only:
            tags_after = run(['curl', '--fail', '--silent', '--show-error', '--max-time', '5',
                              'http://127.0.0.1:11434/api/tags'], capture_output=True, text=True)
            model_after = validate_model_inventory(tags_after.stdout)
            (root / 'model-after.json').write_text(json.dumps(model_after) + '\n')
            if model_after != model_before:
                raise RuntimeError('Model identity changed during qualification')
        print((root / 'result.log').read_text(), flush=True)
        if timed_out:
            raise RuntimeError('SQL/NOVA route integration timed out')
        if returncode:
            raise RuntimeError(f'SQL/NOVA route integration failed ({returncode})')
finally:
    owned_processes.mask_cleanup_signals()
    cleanup_errors = []
    try:
        try:
            owned_processes.cleanup()
        except BaseException as error:
            cleanup_errors.append(error)
        if creation_intended:
            try:
                cleanup = cleanup_owned(docker_command, daemon_id=args.docker_daemon_id,
                    name=container, labels=labels, image=args.postgres_image_id, captured_id=captured_id)
                record_ownership('container-cleanup.json', cleanup)
            except BaseException as error:
                cleanup_errors.append(error)
                record_ownership('container-cleanup.json', {'status': 'cleanup_unverified',
                    'name': container, 'containerId': captured_id, 'failureCode': 'OWNERSHIP_OR_REMOVAL_FAILED'})
    finally:
        try:
            observed = validate_package(workspace, manifest_path, args.manifest_sha256, node, args.node_sha256)
            if observed != manifest:
                raise RuntimeError('Postflight immutable package changed')
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            owned_processes.restore()
    if cleanup_errors:
        raise RuntimeError('Qualification cleanup or immutable identity verification failed') from cleanup_errors[0]
    print(f'Owned cleanup complete; evidence retained: {root}', flush=True)
