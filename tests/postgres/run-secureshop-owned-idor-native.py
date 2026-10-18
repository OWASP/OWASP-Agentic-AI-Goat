#!/usr/bin/env python3
"""Qualify owned IDOR migrations in one disposable PG container."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[2]
CASE = 'tests/postgres/secureshopOwnedIdorLesson.native.js'
DRAFT = 'docs/secureshop/drafts/0048_owned_idor_lesson_receipts.sql'
DRAFT_SHA256 = '666390897e178442b86202223b62ea9f769d0fb8d4e65384484fa776a42123ad'
DOCKER_HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DOCKER_BIN = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_SHA256 = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
DOCKER_DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
NODE_BIN = Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
TEST_NAME = 'owned IDOR migration qualifies only in five disposable stores with controlled mode tokens'
FAMILIES = {'IDENTITY': 'identity', 'AGENTS': 'secureshop_agents',
            'COMMERCE': 'secureshop', 'REVIEW': 'secureshop_review',
            'FRESH': 'secureshop_review'}

PURPOSE_CASE = 'tests/postgres/secureshopIdorPurposeMigration.integration.test.js'
PURPOSE_CASE_SHA256 = 'ca171a05c2e8f6c0077529c407aec104d887dc7f2a818a68880268891cf81880'
PURPOSE_DRAFT = 'docs/secureshop/drafts/0086_idor_lesson_conversation_purpose.sql'
PURPOSE_SHA256 = '7124a0dc9072770a3626afd3e5b51d403721fbd00a67c56dfdb179a9074d5a10'
PURPOSE_TEST_NAME = 'agents0086 qualifies fresh, populated0085 and no-op purpose admission without changing prior history'


def selected_cohort(purpose_only=False):
    if purpose_only:
        return {'case': PURPOSE_CASE, 'testName': PURPOSE_TEST_NAME,
                'families': {'FRESH': 'secureshop_agents', 'POPULATED': 'secureshop_agents'},
                'prefix': 'PG_SECURESHOP_IDOR_PURPOSE_', 'databasePrefix': 'dvaia_test_idor_purpose_',
                'gate': 'SECURESHOP_IDOR_PURPOSE_MIGRATION_NATIVE',
                'draft': PURPOSE_DRAFT, 'migrationSha256': PURPOSE_SHA256,
                'active': 'db/postgres/workshop-migrations/secureshop_agents/0086_idor_lesson_conversation_purpose.sql'}
    return {'case': CASE, 'testName': TEST_NAME, 'families': FAMILIES,
            'prefix': 'OWNED_IDOR_NATIVE_', 'databasePrefix': 'dvaia_test_owned_idor_',
            'gate': 'OWNED_IDOR_LESSON_NATIVE', 'draft': DRAFT, 'migrationSha256': DRAFT_SHA256,
            'active': 'db/postgres/workshop-migrations/secureshop_review/' + Path(DRAFT).name}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executables_match():
    return sha(NODE_BIN) == NODE_SHA256 and sha(DOCKER_BIN) == DOCKER_SHA256


def inventory(purpose_only=False):
    inventory_file = SOURCE / 'tests/postgres/run-persona-transition-main-isolated.py'
    spec = importlib.util.spec_from_file_location('owned_idor_source_inventory', inventory_file)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    extras = [CASE, DRAFT, 'tests/secureshopBoundIdorLessonRepository.test.js',
              'tests/postgres/run-secureshop-owned-idor-native.py',
              'tests/postgres/test_secureshop_owned_idor_native_launcher.py',
              'tests/postgres/run-persona-transition-main-isolated.py',
              'tests/postgres/run-mail-browser-main.py',
              'package.json', 'package-lock.json']
    if purpose_only:
        extras += [PURPOSE_CASE, PURPOSE_DRAFT, 'tests/helpers/secureshopAgentsMigrationView.js']
    return support.source_inventory([SOURCE / name for name in extras])


def dependency_inventory():
    inventory_file = SOURCE / 'tests/postgres/run-mail-browser-main.py'
    spec = importlib.util.spec_from_file_location('owned_idor_dependency_inventory', inventory_file)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    return support.inventory(SOURCE / 'node_modules')


def inventory_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def command(argv, *, timeout=30, env=None, input_text=None):
    return subprocess.run(argv, check=True, timeout=timeout, env=env,
                          input=input_text, text=True, capture_output=True)


def docker_call(docker, args, *, timeout=30):
    return command([*docker, *args], timeout=timeout, env=BASE_ENV).stdout.strip()


def verify_daemon(docker):
    if docker_call(docker, ['info', '--format', '{{.ID}}'], timeout=10) != DOCKER_DAEMON:
        raise RuntimeError('Reviewed Docker daemon identity mismatch')


def tap_passed(raw, test_name=TEST_NAME):
    if len(raw) > 512 * 1024:
        return False
    lines = raw.splitlines()
    if (lines.count(f'# Subtest: {test_name}') != 1
            or lines.count(f'ok 1 - {test_name}') != 1
            or len([line for line in lines if line.startswith(('ok ', 'not ok '))]) != 1):
        return False
    if re.search(r'^not ok ', raw, re.M):
        return False
    expected = {'tests': 1, 'pass': 1, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0}
    return all(len(re.findall(rf'^# {key} {value}$', raw, re.M)) == 1
               for key, value in expected.items()) and len(re.findall(r'^1\.\.1$', raw, re.M)) == 1


def inspect_owned(docker, name, owner):
    result = subprocess.run([*docker, 'inspect', '--type', 'container', name],
                            timeout=10, env=BASE_ENV, capture_output=True, text=True)
    if result.returncode:
        if 'No such object:' in result.stderr or 'No such container:' in result.stderr:
            return None
        raise RuntimeError('Unable to inspect owned PostgreSQL container')
    values = json.loads(result.stdout)
    if len(values) != 1:
        raise RuntimeError('Ambiguous owned PostgreSQL container')
    value = values[0]
    host = value.get('HostConfig', {})
    if (value.get('Name') != '/' + name or value.get('Image') != POSTGRES_IMAGE_ID
            or value.get('Config', {}).get('Labels', {}).get('dvaia.test.owner') != owner
            or host.get('Memory') != 1073741824 or host.get('NanoCpus') != 2000000000
            or host.get('PidsLimit') != 128
            or host.get('Tmpfs', {}).get('/var/lib/postgresql') != 'rw,size=536870912'
            or host.get('Privileged') is True or host.get('NetworkMode') == 'host'
            or any(mount.get('Type') in ('bind', 'volume') for mount in value.get('Mounts', []))):
        raise RuntimeError('Container name is owned by a different run')
    return value


def inspect_captured_id(docker, identifier):
    result = subprocess.run([*docker, 'inspect', '--type', 'container', identifier],
                            timeout=10, env=BASE_ENV, capture_output=True, text=True)
    if result.returncode:
        if ('No such object:' in result.stderr or 'No such container:' in result.stderr):
            return None
        raise RuntimeError('Unable to inspect captured PostgreSQL container')
    values = json.loads(result.stdout)
    if len(values) != 1 or values[0].get('Id') != identifier:
        raise RuntimeError('Captured PostgreSQL container identity mismatch')
    return values[0]


def cleanup_owned_container(docker, name, owner, captured_id):
    verify_daemon(docker)
    owned = inspect_owned(docker, name, owner)
    retiring_id = owned.get('Id') if owned is not None else captured_id
    if owned is not None:
        if captured_id is not None and owned.get('Id') != captured_id:
            raise RuntimeError('Owned container ID changed before cleanup')
        docker_call(docker, ['rm', '-f', owned['Id']], timeout=30)
    name_absent = inspect_owned(docker, name, owner) is None
    id_absent = retiring_id is None or inspect_captured_id(docker, retiring_id) is None
    if name_absent and not id_absent:
        raise RuntimeError('Captured owned container was renamed before cleanup')
    return name_absent, id_absent


def owned_group_members(pgid):
    listing = command(['/bin/ps', '-axo', 'pid=,pgid=,uid='], timeout=5,
                      env=BASE_ENV).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if (len(fields) != 3 or not fields[0].isdecimal() or not fields[1].isdecimal()
                or re.fullmatch(r'-?\d+', fields[2]) is None):
            raise RuntimeError('Cannot establish process-group ownership')
        pid, group, uid = map(int, fields)
        if group == pgid:
            if uid != os.getuid():
                raise RuntimeError('Foreign member in owned process group')
            members.append(pid)
    return members


def stop_owned_group(pgid):
    if pgid is None:
        return True
    for signum in (signal.SIGTERM, signal.SIGKILL):
        if not owned_group_members(pgid):
            return True
        os.killpg(pgid, signum)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not owned_group_members(pgid):
                return True
            time.sleep(.05)
    return not owned_group_members(pgid)


def main():
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan', action='store_true')
    action.add_argument('--run', action='store_true')
    parser.add_argument('--purpose-only', action='store_true')
    args = parser.parse_args()
    cohort = selected_cohort(args.purpose_only)
    if not executables_match():
        raise SystemExit('Reviewed native executable hash mismatch')
    if args.purpose_only and sha(SOURCE / PURPOSE_CASE) != PURPOSE_CASE_SHA256:
        raise SystemExit('Reviewed purpose fixture hash mismatch')
    if sha(SOURCE / cohort['draft']) != cohort['migrationSha256']:
        raise SystemExit('Pending draft SHA differs from reviewed bytes')
    active = SOURCE / cohort['active']
    if not active.is_file() or sha(active) != cohort['migrationSha256']:
        raise SystemExit('Active migration must match reviewed draft bytes')
    pins = inventory(args.purpose_only)
    if args.plan:
        print(json.dumps({'status': 'plan', 'scope': 'controlled native PostgreSQL only',
                          'workspace': str(SOURCE), 'case': cohort['case'], 'migrationSha256': cohort['migrationSha256'],
                          'sourceCount': len(pins), 'imageId': POSTGRES_IMAGE_ID,
                          'nodeBin': str(NODE_BIN), 'nodeSha256': NODE_SHA256,
                          'dockerBin': str(DOCKER_BIN), 'dockerSha256': DOCKER_SHA256,
                          'dockerHost': DOCKER_HOST, 'dockerDaemon': DOCKER_DAEMON,
                          'stores': cohort['families'], 'modelCalls': 0}, sort_keys=True))
        return
    def interrupted(signum, _frame):
        raise RuntimeError(f'Native launcher interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    dependencies = dependency_inventory()
    docker = [str(DOCKER_BIN), '--host', DOCKER_HOST]
    verify_daemon(docker)
    image = json.loads(docker_call(docker, ['image', 'inspect', POSTGRES_IMAGE_ID], timeout=10))
    if len(image) != 1 or image[0].get('Id') != POSTGRES_IMAGE_ID:
        raise RuntimeError('Local PostgreSQL image ID mismatch')
    root = Path(tempfile.mkdtemp(prefix='dvaia-owned-idor-native-')).resolve()
    root.chmod(0o700)
    owner = secrets.token_hex(6)
    name = 'dvaia-owned-idor-' + owner
    log = root / 'node.tap'
    result_path = root / 'result.json'
    runtime_home = root / 'runtime-home'
    runtime_tmp = root / 'runtime-tmp'
    runtime_home.mkdir(mode=0o700)
    runtime_tmp.mkdir(mode=0o700)
    result = {'status': 'preparing', 'owner': owner, 'container': name,
              'sourceSha256': pins, 'case': cohort['case'],
              'draftSha256': cohort['migrationSha256'],
              'dependencySha256': inventory_sha(dependencies),
              'dependencyCount': len(dependencies),
              'scope': 'controlled native migration/repository; no model or browser'}
    container_id = None
    child = None
    cleanup = {'containerRemoved': False, 'capturedIdAbsent': False,
               'sourceUnchanged': False, 'dependenciesUnchanged': False,
               'executablesUnchanged': False, 'nodeGroupAbsent': False}
    try:
        raw = docker_call(docker, ['run', '-d', '--pull', 'never', '--name', name,
                                   '--label', 'dvaia.test.owner=' + owner,
                                   '--memory', '1g', '--cpus', '2', '--pids-limit', '128',
                                   '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
                                   '-e', 'POSTGRES_USER=owned_idor_admin',
                                   '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
                                   '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
                                   '-p', '127.0.0.1::5432', POSTGRES_IMAGE_ID,
                                   '-c', 'shared_buffers=16MB', '-c', 'max_connections=48',
                                   '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'], timeout=40)
        verify_daemon(docker)
        observed = inspect_owned(docker, name, owner)
        if observed is None or observed.get('Id') != raw:
            raise RuntimeError('Owned container identity mismatch after create')
        container_id = raw
        for _ in range(80):
            ready = subprocess.run([*docker, 'exec', container_id, 'pg_isready', '-U',
                                    'owned_idor_admin'], env=BASE_ENV, timeout=2,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Owned PostgreSQL did not become ready')
        address = docker_call(docker, ['port', container_id, '5432'], timeout=10)
        if len(address.splitlines()) != 1 or not address.startswith('127.0.0.1:'):
            raise RuntimeError('PostgreSQL must publish one loopback port')
        port = int(address.rsplit(':', 1)[1])
        if not 1024 <= port <= 65535:
            raise RuntimeError('Invalid owned loopback port')
        psql = [*docker, 'exec', container_id, 'psql', '-U', 'owned_idor_admin',
                '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        url_env = {}
        sql = []
        for family in sorted(set(cohort['families'].values())):
            for role in ('migration', 'runtime'):
                sql.append(f'CREATE ROLE dvaia_{family}_{role} LOGIN NOSUPERUSER NOCREATEDB '
                           'NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
        command(psql + ['-c', '\n'.join(sql)], timeout=20, env=BASE_ENV)
        for store, family in cohort['families'].items():
            database = f"{cohort['databasePrefix']}{owner}_{store.lower()}"
            migration = f'dvaia_{family}_migration'
            runtime = f'dvaia_{family}_runtime'
            command(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration}'],
                    timeout=20, env=BASE_ENV)
            command(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                             f'GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}'],
                    timeout=20, env=BASE_ENV)
            for role, user in [('RUNTIME', runtime), ('MIGRATION', migration)]:
                url_env[f"{cohort['prefix']}{store}_{role}_URL"] = \
                    f'postgresql://{user}@127.0.0.1:{port}/{database}'
        if inventory(args.purpose_only) != pins:
            raise RuntimeError('Source changed before native test')
        env = dict(BASE_ENV, HOME=str(runtime_home), TMPDIR=str(runtime_tmp),
                   TMP=str(runtime_tmp), TEMP=str(runtime_tmp),
                   XDG_CACHE_HOME=str(runtime_home), NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
                   DVAIA_CURRENT_MAIN_WORKSPACE=str(SOURCE),
                   AWS_EC2_METADATA_DISABLED='true', **url_env)
        env[cohort['gate']] = '1'
        env[cohort['prefix'] + 'OWNER'] = owner
        with log.open('w') as stream:
            log.chmod(0o600)
            child = subprocess.Popen([str(NODE_BIN), '--test', '--test-reporter=tap', cohort['case']],
                                     cwd=SOURCE, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            if os.getpgid(child.pid) != child.pid:
                raise RuntimeError('Native child lacks owned process group')
            result['nodePgid'] = child.pid
            result['testExitCode'] = child.wait(timeout=180)
        result['tapSha256'] = sha(log)
        result['tapAccepted'] = tap_passed(log.read_text(), cohort['testName'])
        result['status'] = 'passed' if result['testExitCode'] == 0 and result['tapAccepted'] else 'failed'
    except Exception as error:
        result['status'] = 'failed'
        result['error'] = {'type': type(error).__name__, 'message': str(error)[:500]}
    finally:
        try:
            cleanup['nodeGroupAbsent'] = stop_owned_group(child.pid if child else None)
            if child is not None and child.poll() is None:
                child.wait(timeout=5)
        except Exception as error:
            cleanup['nodeError'] = str(error)[:500]
        try:
            cleanup['containerRemoved'], cleanup['capturedIdAbsent'] = \
                cleanup_owned_container(docker, name, owner, container_id)
        except Exception as error:
            cleanup['error'] = str(error)[:500]
        try:
            cleanup['sourceUnchanged'] = inventory(args.purpose_only) == pins
        except Exception as error:
            cleanup['sourceError'] = str(error)[:500]
        try:
            cleanup['dependenciesUnchanged'] = dependency_inventory() == dependencies
        except Exception as error:
            cleanup['dependencyError'] = str(error)[:500]
        try:
            cleanup['executablesUnchanged'] = executables_match()
        except Exception as error:
            cleanup['executableError'] = str(error)[:500]
        result['cleanup'] = cleanup
        result_path.write_text(json.dumps(result, indent=2) + '\n')
        result_path.chmod(0o600)
    print(json.dumps({'status': result['status'], 'result': str(result_path),
                      'tap': str(log), 'cleanup': cleanup}, sort_keys=True))
    if result['status'] != 'passed' or not all(value is True for value in cleanup.values()):
        raise SystemExit(1)


BASE_ENV = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
BASE_ENV['PATH'] = '/usr/local/bin:/usr/bin:/bin:' + BASE_ENV.get('PATH', '')

if __name__ == '__main__':
    main()
