#!/usr/bin/env python3
"""Current-checkout V06 journal database/repository qualification; no source copy."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, subprocess, tempfile, time, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER_BINARY = pathlib.Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_SHA = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER = [str(DOCKER_BINARY), '--host', HOST]
SUITES = {
    'v19': {
        'fixture': 'tests/postgres/secureshopV19FileSummaryNative.integration.test.js',
        'prefix': 'PG_SECURESHOP_V19_',
        'stores': [('AGENTS_FRESH', 'agents'), ('AGENTS_POPULATED', 'agents'), ('IDENTITY_GRAPH', 'identity')],
        'database_stem': 'dvaia_test_v19_',
        'container_stem': 'dvaia-v19-',
        'gate': 'SECURESHOP_V19_NATIVE',
        'graph': True,
        'ownedFileEffect': True,
        'qualification': ('V19/V44 disposable PostgreSQL 0107/0108/0109 fresh/populated/no-op purpose admission, preserved operator ACL/sibling '
                          'evidence, default composed graphs/policy/turn/effect, owned filesystem read/replay and fixed no-read; '
                          'controlled provider/persona/scene inputs, no actual model, browser, Judge or credit claim'),
        'extra': [
            'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js',
            'db/postgres/workshop-migrations/secureshop_agents/0107_file_summary_conversation_purpose.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0108_file_summary_registry_successor.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0109_file_path_summary_conversation_purpose.sql',
            'server/services/secureshopBoundFilePathSummaryGraph.js',
            'server/services/secureshopV44FilePathSummaryExecutionConfig.js',
            'server/services/secureshopV44FilePathSummarySourceReader.js',
            'server/services/secureshopReservedFiles.js',
            'server/services/secureshopReservedFileTools.js',
            'server/database/postgres/secureshopBoundPersonaAuthority.js',
            'server/database/postgres/secureshopSceneRepository.js',
            'server/database/postgres/secureshopModeRepository.js',
            'server/services/secureshopFileSummaryComposition.js',
            'server/services/secureshopBoundFileSummaryGraph.js',
            'server/services/secureshopFileSummaryAttachment.js',
            'server/services/secureshopFileSummaryExecutionConfig.js',
            'server/services/secureshopConversationPurpose.js',
            'server/services/secureshopFeatureModeAuthority.js',
            'server/services/secureshopBoundAclRegistry.js',
            'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
            'server/database/postgres/secureshopBoundAclRepository.js',
            'server/database/postgres/secureshopBoundAuditRepository.js',
            'server/database/postgres/secureshopBoundPersonaRepository.js',
            'server/database/postgres/secureshopLaunchRepository.js',
            'server/database/postgres/secureshopTurnRequestsRepository.js',
            'server/database/postgres/secureshopBoundConversationsRepository.js',
            'server/agent-runtime/runCoordinator.js',
            'server/agent-runtime/postgresRunLedger.js',
            'sidecars/sandbox-runner/secureshopFiles.js',
        ],
    },
    'assessment': {
        'fixture': 'tests/postgres/secureshopV06UploadAssessmentNative.integration.test.js',
        'prefix': 'PG_SECURESHOP_UPLOAD_ASSESSMENT_',
        'stores': [('IDENTITY_FRESH', 'identity'), ('IDENTITY_POPULATED', 'identity'),
                   ('IDENTITY_ASSESSMENT', 'identity'), ('AGENTS', 'agents'), ('REVIEW', 'review')],
        'database_stem': 'dvaia_test_upload_assessment_',
        'container_stem': 'dvaia-upload-assessment-',
        'gate': 'SECURESHOP_UPLOAD_ASSESSMENT_NATIVE',
        'qualification': ('V06 disposable PostgreSQL platform/standalone seed provenance and canonical '
                          'qualified/default-disabled exact pending promotion, instructor/tenant/sibling/nonempty history/no-op preservation and '
                          'turn/trace/graph/upload receipt/owned-file integrity/retained-packet/recovery fences; controlled trace identity '
                          'and unavailable retry only, no upload handler, model, genuine Judge, browser or credit claim'),
        'extra': [
            'tests/fixtures/secureshopV06CandidateCatalog.js',
            'server/config/secureshopCurriculum.js',
            'server/database/postgres/workshopPlatformSeed.js',
            'server/database/postgres/secureshopAssessmentSeed.js',
            'server/database/postgres/secureshopV06UploadTurnReader.js',
            'server/database/postgres/secureshopBoundConversationsRepository.js',
            'server/database/postgres/secureshopBoundUploadAssetRepository.js',
            'server/services/secureshopV06UploadEvidence.js',
            'server/services/secureshopV06UploadSourceReader.js',
            'server/services/secureshopV06UploadAssessment.js',
            'server/services/secureshopAssessmentRecovery.js',
        ],
    },
    'v03': {
        'fixture': 'tests/postgres/secureshopV03ListingOptimizeNative.integration.test.js',
        'prefix': 'PG_SECURESHOP_V03_OPTIMIZE_',
        'stores': [('AGENTS_FRESH', 'agents'), ('AGENTS_POPULATED', 'agents'),
                   ('REVIEW_FRESH', 'review'), ('REVIEW_POPULATED', 'review')],
        'database_stem': 'dvaia_test_v03_optimize_',
        'container_stem': 'dvaia-v03-optimize-',
        'gate': 'SECURESHOP_V03_OPTIMIZE_NATIVE',
        'qualification': ('V03 disposable PostgreSQL REVIEW0054 and AGENTS0105-0106 migration, registry and '
                          'journal lifecycle only; controlled diagnostic receipt, no external command/network effect, '
                          'model, browser, Judge or credit claim'),
        'extra': [
            'db/postgres/workshop-migrations/secureshop_review/0054_owned_listing_image_optimize.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0105_listing_optimize_conversation_purpose.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0106_listing_optimize_registry_successor.sql',
            'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
            'server/database/postgres/secureshopListingJournalRepository.js',
            'server/services/secureshopBoundAclRegistry.js',
            'server/services/secureshopConversationBinding.js',
            'server/services/secureshopSceneBinding.js',
            'server/services/secureshopListingsTargetBinding.js',
            'server/services/secureshopListingRequestContract.js',
            'server/services/secureshopListingJournalContract.js',
            'server/services/secureshopListingOptimizeExecutor.js',
            'sidecars/sandbox-runner/owned-system/diagnostic-contract.js',
            'sidecars/sandbox-runner/owned-system/diagnostic-result.js',
            'sidecars/sandbox-runner/owned-system/diagnostic-wire.js',
        ],
    },
    'journal': {
        'fixture': 'tests/postgres/secureshopBoundUploadJournal.integration.test.js',
        'prefix': 'PG_SECURESHOP_BOUND_UPLOAD_',
        'stores': [('FRESH', 'review'), ('POPULATED', 'review')],
        'database_stem': 'dvaia_test_bound_upload_',
        'container_stem': 'dvaia-bound-upload-',
        'gate': 'SECURESHOP_BOUND_UPLOAD_NATIVE',
        'qualification': ('V06 disposable PostgreSQL migration/repository journal only; '
                          'no physical upload/file, graph, model, browser, Judge or credit claim'),
        'extra': [
            'server/database/postgres/secureshopBoundUploadRepository.js',
            'server/services/secureshopBoundUploadReceipt.js',
        ],
    },
    'successor': {
        'fixture': 'tests/postgres/secureshopUploadSuccessor.integration.test.js',
        'prefix': 'PG_SECURESHOP_UPLOAD_SUCCESSOR_',
        'stores': [('AGENTS_FRESH', 'agents'), ('AGENTS_POPULATED', 'agents'), ('REVIEW', 'review')],
        'database_stem': 'dvaia_test_upload_successor_',
        'container_stem': 'dvaia-upload-successor-',
        'gate': 'SECURESHOP_UPLOAD_SUCCESSOR_NATIVE',
        'qualification': ('V06 disposable PostgreSQL 0102-0104 and repository/reset-adapter joins only; '
                          'controlled storage callbacks, no physical upload/file, graph, model, browser, Judge or credit claim'),
        'extra': [
            'db/postgres/workshop-migrations/secureshop_agents/0102_avatar_upload_conversation_purpose.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0103_avatar_upload_registry_successor.sql',
            'db/postgres/workshop-migrations/secureshop_agents/0104_avatar_upload_registry_guard_repair.sql',
            'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
            'server/database/postgres/secureshopBoundUploadRepository.js',
            'server/services/secureshopBoundUploadAdmission.js',
            'server/services/secureshopBoundUploadReceipt.js',
            'server/services/secureshopBoundUploadResetAdapter.js',
            'server/services/secureshopBoundAclRegistry.js',
        ],
    },
}

def arguments(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', choices=sorted(SUITES), default='journal')
    parser.add_argument('--upload-polyglot', action='store_true')
    gate = parser.add_mutually_exclusive_group(required=True)
    gate.add_argument('--plan', action='store_true')
    gate.add_argument('--run', action='store_true')
    args=parser.parse_args(argv)
    if args.upload_polyglot and args.suite!='assessment':parser.error('--upload-polyglot requires existing assessment suite')
    return args

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def database_role(role_base, role):
    prefix = 'dvaia_identity' if role_base == 'identity' else 'dvaia_secureshop_' + role_base
    return prefix + '_' + role

def main(argv=None):
    args = arguments(argv)
    config = dict(SUITES[args.suite])
    if args.upload_polyglot:
        config['qualification']='V07 qualified/default-disabled catalog fresh/pending promotion/populated/no-op with target and sibling controlled immutable history and instructor preservation, normal administrator admission; controlled PostgreSQL 0112 fresh/populated/no-op, original upload and preview model graph/source/receipt/assessment persistence, fixed/replay/reset/sibling fences; controlled worker/provider/Judge, no actual execution/model/browser/credit claim'
        config['extra']=[*config['extra'],'sidecars/sandbox-runner/owned-system/upload-preview-contract.js','db/postgres/workshop-migrations/secureshop_agents/0112_upload_preview_registry_successor.sql']
    fixture = config['fixture']
    command = [str(pathlib.Path(__file__).resolve()), '--suite', args.suite,*(['--upload-polyglot'] if args.upload_polyglot else []), '--run']
    if args.plan:
        print(json.dumps({'plan': True, 'suite': args.suite, 'fixture': fixture, 'expectedTests': 2,
            'stores': [store for store, _role in config['stores']],
            'databasePattern': config['database_stem'] + '<nonce>_<store>',
            'sourceRoot': str(ROOT), 'sourceCopies': False, 'actualUpload': False, 'actualNetworkEffects': False, 'actualModel': False,
            'graph': config.get('graph', False), 'ownedFileEffect': config.get('ownedFileEffect', False),
            'browser': False, 'judgeOrCredit': False, **({'polyglotPreviewControlled':True,'qualificationScope':config['qualification']} if args.upload_polyglot else {}), 'dockerBinary': str(DOCKER_BINARY),
            'dockerHost': HOST, 'daemonId': DAEMON, 'postgresImage': IMAGE, 'runCommand': command}))
        return 0

    inventory_source = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
    inventory = load('bound_upload_source_inventory', inventory_source).source_inventory
    lifecycle_path = ROOT / 'tests/postgres/run-secureshop-audit-central-isolated.py'
    lifecycle = load('bound_upload_lifecycle', lifecycle_path)
    dependency_source = ROOT / 'tests/postgres/run-mail-browser-main.py'
    dependency_inventory = load('bound_upload_dependency_inventory', dependency_source).inventory
    if ROOT.resolve() != ROOT:
        raise RuntimeError('Exact current main checkout required')
    if sha(DOCKER_BINARY) != DOCKER_SHA:
        raise RuntimeError('Docker CLI pin mismatch')
    if sha(NODE) != NODE_SHA:
        raise RuntimeError('Managed Node pin mismatch')
    evidence = pathlib.Path(tempfile.mkdtemp(prefix='dvaia-' + args.suite + '-main-')).resolve()
    evidence.chmod(0o700)
    if evidence.is_relative_to(ROOT):
        raise RuntimeError('Evidence/runtime must be outside the main source')
    env = lifecycle.owned_environment(evidence, NODE)
    runtime = evidence / 'runtime' / 'workspace'
    runtime.mkdir(mode=0o700)
    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes',
        DVAIA_ISOLATED_TEST_WORKSPACE=str(runtime), PLATFORM_DATABASE_ENGINE='postgres',
        WORKSHOP_DATABASE_ENGINE='postgres', AI_PROVIDER='mock', AWS_EC2_METADATA_DISABLED='true',
        HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', MCP_WORKSHOP_AUTOSTART='false',
        MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false')
    env[config['gate']] = '1'
    if args.upload_polyglot:env['SECURESHOP_UPLOAD_POLYGLOT_NATIVE']='1'
    nonce = uuid.uuid4().hex
    owner = nonce
    name = config['container_stem'] + nonce[:12]
    result = {'version': 1, 'suite': args.suite, 'fixture': fixture, 'expectedTests': 2, 'sourceRoot': str(ROOT),
        'sourceCopies': False, 'actualUpload': False, 'actualNetworkEffects': False, 'actualModel': False, 'graph': config.get('graph', False),
        'ownedFileEffect': config.get('ownedFileEffect', False), 'browser': False, 'judgeOrCredit': False, 'dockerHost': HOST, 'daemonId': DAEMON,
        'postgresImage': IMAGE, 'container': name, 'qualificationScope': config['qualification'],**({'polyglotPreviewControlled':True} if args.upload_polyglot else {})}
    children = []
    attempted = False
    container_id = None

    extra = [pathlib.Path(__file__).resolve(), ROOT / fixture, inventory_source, lifecycle_path,
        pathlib.Path(lifecycle.helpers.__file__), dependency_source, ROOT / 'package.json', ROOT / 'package-lock.json',
        *(ROOT / relative for relative in config['extra']), ROOT / 'db/postgres/migrate.js',
        ROOT / 'server/database/postgres/index.js', ROOT / 'server/database/postgres/poolBudget.js']
    pins = inventory(extra)
    dependencies = dependency_inventory(ROOT / 'node_modules')
    lifecycle.helpers.write_private_json(evidence / 'dependencies-before.json', dependencies)
    result['sourceHashes'] = pins
    result['dependencyInventorySha256'] = hashlib.sha256(json.dumps(dependencies,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def save():
        lifecycle.helpers.write_private_json(evidence / 'result.json', result)

    def run(command, timeout=30):
        return subprocess.run(command, cwd=ROOT, env=env, check=True, text=True,
            capture_output=True, timeout=timeout)

    def verify_daemon():
        if run(DOCKER + ['info', '--format', '{{.ID}}']).stdout.strip() != DAEMON:
            raise RuntimeError('Docker daemon identity mismatch')

    def matching_ids():
        return run(DOCKER + ['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).stdout.split()

    def inspect_owned():
        nonlocal container_id
        verify_daemon()
        ids = matching_ids()
        if not ids:
            if container_id and container_id in run(DOCKER + ['ps', '-aq', '--no-trunc']).stdout.split():
                raise RuntimeError('Captured container renamed; cleanup withheld')
            return None
        if len(ids) != 1:
            raise RuntimeError('Ambiguous owned container')
        row = json.loads(run(DOCKER + ['inspect', ids[0]]).stdout)[0]
        ports = row.get('HostConfig', {}).get('PortBindings', {}).get('5432/tcp', [])
        labels = row.get('Config', {}).get('Labels') or {}
        host = row.get('HostConfig', {})
        if (row.get('Id') != ids[0] or row.get('Name') != '/' + name or row.get('Image') != IMAGE
                or labels.get('dvaia.test.owner') != owner or (container_id and row.get('Id') != container_id)
                or len(ports) != 1 or ports[0].get('HostIp') != '127.0.0.1'
                or host.get('Memory') != 536870912 or host.get('NanoCpus') != 2000000000
                or host.get('PidsLimit') != 256
                or host.get('Tmpfs', {}).get('/var/lib/postgresql') != 'rw,size=536870912'
                or host.get('Privileged') is True or host.get('NetworkMode') == 'host'
                or any(item.get('Type') in ('bind', 'volume') for item in row.get('Mounts', []))):
            raise RuntimeError('Owned container identity/layout mismatch')
        container_id = row['Id']
        return container_id

    def interrupted(signum, _frame):
        raise RuntimeError('Interrupted ' + str(signum))

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        save()
        verify_daemon()
        if run(DOCKER + ['image', 'inspect', IMAGE, '--format', '{{.Id}}']).stdout.strip() != IMAGE:
            raise RuntimeError('Immutable PostgreSQL image mismatch')
        if matching_ids():
            raise RuntimeError('Owned container namespace already occupied')
        attempted = True
        run(DOCKER + ['run', '-d', '--pull', 'never', '--name', name,
            '--label', 'dvaia.test.owner=' + owner, '--memory', '512m', '--cpus', '2',
            '--pids-limit', '256', '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_USER=bound_upload_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', IMAGE,
            '-c', 'max_connections=48', '-c', 'shared_buffers=16MB', '-c', 'max_wal_size=16MB',
            '-c', 'min_wal_size=4MB'])
        container_id = inspect_owned()
        result['containerId'] = container_id
        save()
        for _ in range(100):
            probe = subprocess.run(DOCKER + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'bound_upload_admin'], env=env, capture_output=True, timeout=5)
            if probe.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Owned PostgreSQL readiness deadline')
        port = run(DOCKER + ['port', container_id, '5432/tcp']).stdout.strip().rsplit(':', 1)[1]
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise RuntimeError('Invalid owned loopback port')
        role_bases = sorted({role_base for _store, role_base in config['stores']})
        role_sql = ' '.join('CREATE ROLE ' + database_role(role_base, role) +
            ' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'
            for role_base in role_bases for role in ('migration', 'runtime'))
        run(DOCKER + ['exec', container_id, 'psql', '-U', 'bound_upload_admin', '-d', 'postgres',
            '-v', 'ON_ERROR_STOP=1', '-c', role_sql])
        for store, role_base in config['stores']:
            database = config['database_stem'] + nonce[:12] + '_' + store.lower()
            run(DOCKER + ['exec', container_id, 'psql', '-U', 'bound_upload_admin', '-d', 'postgres',
                '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + database +
                ' OWNER ' + database_role(role_base, 'migration')])
            run(DOCKER + ['exec', container_id, 'psql', '-U', 'bound_upload_admin', '-d', 'postgres',
                '-v', 'ON_ERROR_STOP=1', '-c', 'REVOKE CONNECT ON DATABASE ' + database +
                ' FROM PUBLIC; GRANT CONNECT ON DATABASE ' + database +
                ' TO ' + database_role(role_base, 'migration') + ',' + database_role(role_base, 'runtime')])
            env[config['prefix'] + store + '_MIGRATION_URL'] = ('postgresql://' + database_role(role_base, 'migration') + '@127.0.0.1:'
                + port + '/' + database)
            env[config['prefix'] + store + '_RUNTIME_URL'] = ('postgresql://' + database_role(role_base, 'runtime') + '@127.0.0.1:'
                + port + '/' + database)
        output = lifecycle.run_owned_child([str(NODE), '--test', '--test-concurrency=1',
            '--test-reporter=tap', str(ROOT / fixture)], cwd=ROOT, env=env, evidence=evidence,
            children=children, timeout=300)
        result.update(exitCode=output.returncode,
            stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),
            stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        for field, value in [('tests', 2), ('pass', 2), ('fail', 0), ('cancelled', 0), ('skipped', 0)]:
            if not re.search(r'^# ' + field + ' ' + str(value) + r'$', output.stdout, re.M):
                raise RuntimeError('Unexpected TAP ' + field)
        if output.returncode:
            raise RuntimeError('Native ' + args.suite + ' fixture failed')
        result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        if isinstance(error, subprocess.CalledProcessError):
            lifecycle.helpers.write_private_json(evidence / 'command-failure.json',
                {'returncode': error.returncode, 'stdout': error.stdout, 'stderr': error.stderr})
    finally:
        errors = []
        for child in reversed(children):
            try:
                lifecycle.helpers.stop_group(child)
            except BaseException as error:
                errors.append('Child cleanup: ' + str(error))
        if attempted:
            try:
                verified = inspect_owned()
                if verified:
                    run(DOCKER + ['rm', '-f', '-v', verified])
                all_ids = run(DOCKER + ['ps', '-aq', '--no-trunc']).stdout.split()
                if container_id and container_id in all_ids:
                    raise RuntimeError('Captured owned container remains')
                if matching_ids():
                    raise RuntimeError('Owned container name remains occupied')
                result['containerAbsent'] = True
            except BaseException as error:
                errors.append('Container cleanup withheld/failed: ' + str(error))
        result['childGroupsAbsent'] = not any(value.startswith('Child cleanup:') for value in errors)
        try:
            after = inventory(extra)
            dependencies_after = dependency_inventory(ROOT / 'node_modules')
            lifecycle.helpers.write_private_json(evidence / 'dependencies-after.json', dependencies_after)
            result['sourceHashesAfter'] = after
            result['sourceUnchanged'] = after == pins
            result['dependenciesUnchanged'] = dependencies_after == dependencies
        except BaseException as error:
            result['sourceUnchanged'] = False
            result['dependenciesUnchanged'] = False
            errors.append('Postflight inventory: ' + str(error))
        result['cleanupErrors'] = errors
        result['passed'] = (result.get('passed') is True and not errors and
            result.get('containerAbsent') is True and result['childGroupsAbsent'] is True and
            result['sourceUnchanged'] is True and result['dependenciesUnchanged'] is True)
        save()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(str(evidence / 'result.json'))
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
