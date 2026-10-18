#!/usr/bin/env python3
"""Main-checkout-only qualification for workshop teaching-content migration 0023."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, subprocess, tempfile, time, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
DOCKER = ['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker', '--host', 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
FIXTURE = 'tests/postgres/workshopTeachingContentMigration.integration.test.js'
MIGRATION = 'db/postgres/identity-migrations/0023_workshop_teaching_content.sql'
OBJECTIVE_FIXTURE = 'tests/postgres/objectiveDescriptions.integration.test.js'
OBJECTIVE_MIGRATION = 'db/postgres/identity-migrations/0132_objective_descriptions.sql'

def arguments(argv=None):
    parser = argparse.ArgumentParser()
    gate = parser.add_mutually_exclusive_group()
    gate.add_argument('--run', action='store_true')
    gate.add_argument('--plan', action='store_true')
    parser.add_argument('--objective-descriptions', action='store_true',
                        help='Qualify identity migration 0132 and admin objective content')
    return parser.parse_args(argv)

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def main():
    args = arguments()
    objective_case = args.objective_descriptions
    fixture = OBJECTIVE_FIXTURE if objective_case else FIXTURE
    migration = OBJECTIVE_MIGRATION if objective_case else MIGRATION
    expected_tests = 2 if objective_case else 1
    if not args.run:
        print(json.dumps({
            'plan': True,
            'fixture': fixture,
            'migration': migration,
            'databasePattern': ('dvaia_test_objective_description_{fresh,populated}_<nonce>'
                                if objective_case else 'dvaia_test_teaching_content_<nonce>'),
            'expectedTests': expected_tests,
            'expectedSkipped': 0,
            'sourceCopies': False,
            'actualModel': False,
        }))
        return 0

    helper_path = ROOT / 'tests/postgres/run-secureshop-audit-central-isolated.py'
    spec = importlib.util.spec_from_file_location('teaching_content_lifecycle', helper_path)
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    inventory_path = ROOT / 'tests/postgres/run-mail-browser-main.py'
    spec = importlib.util.spec_from_file_location('teaching_content_dependencies', inventory_path)
    inventories = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventories)

    if sha(DOCKER[0]) != '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e':
        raise RuntimeError('Docker CLI pin mismatch')
    if sha(NODE) != NODE_SHA:
        raise RuntimeError('Node pin mismatch')
    expected_migration_sha = ('f16e20355c537288356a61d4852ee67ad7ad43c797f629af047474142509e801'
                              if objective_case else
                              'b7fc060900c4100e27ec8558fb0ba9ab0982d7f6364af8c5a72904054b0d2d2e')
    if sha(ROOT / migration) != expected_migration_sha:
        raise RuntimeError('Migration pin mismatch')

    evidence = pathlib.Path(tempfile.mkdtemp(prefix=(
        'objective-descriptions-main-' if objective_case else 'workshop-teaching-content-main-'))).resolve()
    evidence.chmod(0o700)
    if evidence.is_relative_to(ROOT):
        raise RuntimeError('Evidence/runtime must be outside main source')
    env = lifecycle.owned_environment(evidence, NODE)
    workspace = evidence / 'runtime/workspace'
    workspace.mkdir(mode=0o700)
    env['DVAIA_ISOLATED_TEST_WORKSPACE'] = str(workspace)
    logs = evidence / 'logs'
    logs.mkdir(mode=0o700)
    env['LOGS_DIR'] = str(logs)
    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres',
               WORKSHOP_DATABASE_ENGINE='postgres', AI_PROVIDER='mock', AWS_EC2_METADATA_DISABLED='true',
               HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', MCP_WORKSHOP_AUTOSTART='false',
               MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false')

    def run(command, **kwargs):
        return subprocess.run(command, env=env, cwd=ROOT, check=True, capture_output=True,
                              text=True, timeout=30, **kwargs)
    def daemon():
        if run(DOCKER + ['info', '--format', '{{.ID}}']).stdout.strip() != DAEMON:
            raise RuntimeError('Docker daemon mismatch')

    nonce = uuid.uuid4().hex
    name = ('dvaia-objective-descriptions-' if objective_case else 'dvaia-teaching-content-') + nonce[:12]
    children = []
    attempted = False
    container_id = None
    source_paths = [pathlib.Path(__file__).resolve(), ROOT / fixture, ROOT / migration,
                    helper_path, pathlib.Path(lifecycle.helpers.__file__), inventory_path,
                    ROOT / 'package.json', ROOT / 'package-lock.json']
    if objective_case:
        source_paths.extend(path for path in (ROOT / 'db/postgres/identity-migrations').glob('*.sql')
                            if path.name <= '0132_objective_descriptions.sql')
        source_paths.extend(ROOT / name for name in (
            'db/postgres/migrate.js', 'db/postgres/workshopChallengeFixtures.js',
            'server/database/postgres/index.js',
            'server/database/postgres/workshopPlatformSeed.js',
            'server/database/postgres/workshopPlatformSeedCore.js',
            'server/database/postgres/workshopConfigRepository.js',
            'server/database/postgres/catalogDefaultProvenance.js',
            'server/database/postgres/workshopPlatformSupport.js',
            'server/config/workshopCatalog.js', 'server/data/workshopHints.js',
            'server/data/xssWorkshopSolutions.js'))
    source_paths = list(set(source_paths))
    pins = {str(path.relative_to(ROOT)): sha(path) for path in sorted(source_paths)}
    dependencies = inventories.inventory(ROOT / 'node_modules')
    lifecycle.helpers.write_private_json(evidence / 'dependencies-before.json', dependencies)
    result = {
        'fixture': fixture,
        'migration': migration,
        'actualModel': False,
        'rendered': False,
        'optionalHttpServices': False,
        'qualificationScope': ('identity migration 0132 fresh and populated catalogs, learner evidence, admin content, role grants, and replay no-op in two owned disposable PostgreSQL databases'
                               if objective_case else 'identity migration 0023 exact-default update, instructor-content preservation, and replay no-op in one owned disposable PostgreSQL database'),
        'sourceHashes': pins,
        'container': name,
        'image': IMAGE,
        'daemon': DAEMON,
        'runtime': {'node': str(NODE), 'sha256': NODE_SHA},
        'dockerCliSha256': sha(DOCKER[0]),
        'sourceRoot': str(ROOT),
        'dataCwd': str(ROOT),
    }
    def save():
        lifecycle.helpers.write_private_json(evidence / 'result.json', result)
    def inspect_owned():
        daemon()
        ids = run(DOCKER + ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).stdout.split()
        if not ids:
            if container_id and container_id in run(DOCKER + ['ps', '-aq', '--no-trunc']).stdout.split():
                raise RuntimeError('Captured container renamed; cleanup withheld')
            return None
        if len(ids) != 1:
            raise RuntimeError('Ambiguous container')
        row = json.loads(run(DOCKER + ['inspect', ids[0]]).stdout)[0]
        ports = row.get('HostConfig', {}).get('PortBindings', {}).get('5432/tcp', [])
        if (row['Name'] != '/' + name or row['Image'] != IMAGE
                or row['Config'].get('Labels', {}).get('dvaia.owner') != nonce
                or (container_id is not None and row['Id'] != container_id)
                or len(ports) != 1 or ports[0]['HostIp'] != '127.0.0.1'
                or row.get('HostConfig', {}).get('Memory') != 536870912
                or row.get('HostConfig', {}).get('NanoCpus') != 2000000000
                or row.get('HostConfig', {}).get('PidsLimit') != 256
                or row.get('HostConfig', {}).get('Tmpfs', {}).get('/var/lib/postgresql') != 'rw,size=536870912'
                or row.get('HostConfig', {}).get('Privileged') is True
                or row.get('HostConfig', {}).get('NetworkMode') == 'host'
                or any(m.get('Type') in ('bind', 'volume') for m in row.get('Mounts', []))):
            raise RuntimeError('Container ownership mismatch')
        return row['Id']

    def interrupted(signum, _frame):
        raise RuntimeError('Interrupted ' + str(signum))
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        save()
        daemon()
        if run(DOCKER + ['image', 'inspect', IMAGE, '--format', '{{.Id}}']).stdout.strip() != IMAGE:
            raise RuntimeError('Postgres image mismatch')
        if run(DOCKER + ['ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip():
            raise RuntimeError('Container namespace occupied')
        attempted = True
        run(DOCKER + ['run', '-d', '--pull', 'never', '--name', name, '--label', 'dvaia.owner=' + nonce,
            '--memory', '512m', '--cpus', '2', '--pids-limit', '256', '--tmpfs',
            '/var/lib/postgresql:rw,size=536870912', '-e', 'POSTGRES_USER=merchant_admin',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p', '127.0.0.1::5432', IMAGE, '-c', 'max_connections=32', '-c', 'shared_buffers=16MB',
            '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'])
        container_id = inspect_owned()
        result['containerId'] = container_id
        save()
        for _ in range(80):
            probe = subprocess.run(DOCKER + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'merchant_admin'], env=env, capture_output=True, timeout=5)
            if probe.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Postgres readiness deadline')
        port = run(DOCKER + ['port', container_id, '5432']).stdout.strip().rsplit(':', 1)[1]
        if not port.isdecimal():
            raise RuntimeError('Invalid owned port')
        run(DOCKER + ['exec', container_id, 'psql', '-U', 'merchant_admin', '-d', 'postgres',
            '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'])
        databases = ([(kind, 'dvaia_test_objective_description_' + kind.lower() + '_' + nonce[:12])
                     for kind in ('FRESH', 'POPULATED')] if objective_case else
                     [('TEACHING_CONTENT_TEST', 'dvaia_test_teaching_content_' + nonce[:12])])
        for kind, database in databases:
            run(DOCKER + ['exec', container_id, 'psql', '-U', 'merchant_admin', '-d', 'postgres',
                '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + database + ' OWNER dvaia_identity_migration'])
            run(DOCKER + ['exec', container_id, 'psql', '-U', 'merchant_admin', '-d', 'postgres',
                '-v', 'ON_ERROR_STOP=1', '-c', 'REVOKE CONNECT ON DATABASE ' + database +
                ' FROM PUBLIC; GRANT CONNECT ON DATABASE ' + database +
                ' TO dvaia_identity_migration,dvaia_identity_runtime'])
            variable_prefix = ('PG_OBJECTIVE_DESCRIPTIONS_' + kind if objective_case else
                               'PG_TEACHING_CONTENT_TEST')
            env[variable_prefix + '_MIGRATION_URL'] = f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}'
            env[variable_prefix + '_RUNTIME_URL'] = f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}'
        output = lifecycle.run_owned_child([str(NODE), '--test', '--test-concurrency=1',
            '--test-reporter=tap', str(ROOT / fixture)], cwd=ROOT, env=env, evidence=evidence,
            children=children, timeout=240 if objective_case else 120)
        result.update(exitCode=output.returncode,
                      stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),
                      stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        for field, value in [('tests', expected_tests), ('pass', expected_tests),
                             ('fail', 0), ('cancelled', 0), ('skipped', 0)]:
            if not re.search(r'^# ' + field + ' ' + str(value) + r'$', output.stdout, re.M):
                raise RuntimeError('Unexpected TAP ' + field)
        if output.returncode:
            raise RuntimeError('Native fixture failed')
        result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        if isinstance(error, subprocess.CalledProcessError):
            lifecycle.helpers.write_private_json(evidence / 'pretest-command-failure.json', {
                'stdout': error.stdout, 'stderr': error.stderr, 'returncode': error.returncode})
    finally:
        errors = []
        for child in reversed(children):
            try:
                lifecycle.helpers.stop_group(child)
            except BaseException as error:
                errors.append('Child cleanup: ' + str(error))
        if attempted:
            try:
                daemon()
                verified = inspect_owned()
                if verified:
                    container_id = verified
                    run(DOCKER + ['rm', '-f', container_id])
                if container_id and container_id in run(DOCKER + ['ps', '-aq', '--no-trunc']).stdout.split():
                    raise RuntimeError('Captured container remains')
                if run(DOCKER + ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).stdout.strip():
                    raise RuntimeError('Reserved name occupied after retirement')
                result['containerAbsent'] = True
            except BaseException as error:
                errors.append('Container cleanup withheld/failed: ' + str(error))
        if not errors:
            errors.extend(lifecycle.cleanup_owned([], [], DOCKER, evidence))
        result['childGroupsAbsent'] = not any(value.startswith('Child cleanup:') for value in errors)
        result['cleanupErrors'] = errors
        try:
            after = {str(path.relative_to(ROOT)): sha(path) for path in sorted(source_paths)}
            dependency_after = inventories.inventory(ROOT / 'node_modules')
            lifecycle.helpers.write_private_json(evidence / 'dependencies-after.json', dependency_after)
            result['sourceHashesAfter'] = after
            result['sourceUnchanged'] = after == pins
            result['dependenciesUnchanged'] = dependency_after == dependencies
        except BaseException as error:
            result['sourceUnchanged'] = False
            result['dependenciesUnchanged'] = False
            errors.append('Postflight inventory: ' + str(error))
        result['passed'] = result.get('passed', False) and not errors and result['sourceUnchanged'] and result['dependenciesUnchanged']
        save()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(str(evidence / 'result.json'))
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
