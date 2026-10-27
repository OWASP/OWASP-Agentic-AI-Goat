#!/usr/bin/env python3
"""Current-checkout V06 journal database/repository qualification; no source copy."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, stat, subprocess, tempfile, time, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER_BINARY = pathlib.Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')
DOCKER_SHA = '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
HOST = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER = [str(DOCKER_BINARY), '--host', HOST]
V03_CURRENT_HOST_LIVE = True
V03_WRAPPER = ROOT / 'tests/postgres/secureshop_v03_fsize_exec.py'
V03_TITLES = (
    '0105-0106 qualify exact production migration history, v31 registry transition and runtime privileges',
    '0054 qualifies fresh/populated/no-op and real optimize, fixed denial, sibling and lifecycle-reset journal behavior',
)
V03_LIMITS = {'totalSeconds': 1555, 'workSeconds': 1335, 'retirementSeconds': 20,
    'cleanupSeconds': 180, 'outputFileBytes': 8388608, 'maxCommands': 124,
    'metadataBytes': 16 * 1024 * 1024}


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def v03_admission_argv(command):
    result = []
    seen = set()
    index = 0
    while index < len(command):
        item = command[index]
        if item in ('--v03-admission', '--v03-admission-sha256'):
            if item in seen or index + 1 >= len(command):
                raise RuntimeError('Duplicate/incomplete admission argv')
            seen.add(item)
            index += 2
        else:
            result.append(item)
            index += 1
    return result


class V03Lease:
    """One monotonic lease; phase changes never extend its absolute end."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.start = clock()
        self.end = self.start + 1555
        self.phase = 'work'
        self.work_end = self.start + 1335
        self.retire_end = self.start + 1355
        self.counts = {'work': 0, 'cleanup': 0}

    def cleanup(self):
        if self.phase != 'work':
            raise RuntimeError('V03 cleanup phase cannot be renewed')
        self.phase = 'cleanup'
        self.work_end = min(self.clock() + 180, self.end - 20)
        self.retire_end = min(self.work_end + 20, self.end)

    def command(self, timeout):
        remaining = self.remaining(timeout)
        maximum = 118 if self.phase == 'work' else 6
        if self.counts[self.phase] >= maximum:
            raise RuntimeError('V03 absolute phase deadline/command bound')
        self.counts[self.phase] += 1
        return remaining

    def remaining(self, maximum):
        remaining = self.work_end - self.clock()
        if remaining <= 0:
            raise RuntimeError('V03 absolute phase deadline')
        return min(maximum, remaining)

    def retirement(self, maximum):
        remaining = self.retire_end - self.clock()
        if remaining <= 0:
            raise RuntimeError('V03 absolute retirement deadline')
        return min(maximum, remaining)

    def check(self):
        if self.clock() >= self.end:
            raise RuntimeError('V03 absolute total deadline')


def v03_packet(path, expected_sha, expected):
    """Read one private, bounded, canonical packet; caller supplies exact binding."""
    p = pathlib.Path(path)
    parent = ROOT / 'tasks/qualification'
    if (str(p) != path or not p.is_absolute() or p.resolve() != p
            or not p.is_relative_to(parent) or p.name != 'admission.json'):
        raise RuntimeError('Exact V03 admission path required')
    for directory in (p.parent, *p.parent.parents):
        if not directory.is_relative_to(parent):
            break
        row = directory.lstat()
        if not stat.S_ISDIR(row.st_mode) or row.st_uid != os.getuid() or row.st_mode & 0o077:
            raise RuntimeError('Private owned V03 admission directory required')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        row = os.fstat(fd)
        if (not stat.S_ISREG(row.st_mode) or row.st_uid != os.getuid()
                or row.st_mode & 0o077 or row.st_nlink != 1 or row.st_size > 65536):
            raise RuntimeError('Private bounded V03 admission file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(65537)
        if hashlib.sha256(raw).hexdigest() != expected_sha or json.loads(raw) != expected:
            raise RuntimeError('V03 admission binding mismatch')
        return expected
    finally:
        os.close(fd)


def v03_assertions(output):
    for field, value in [('tests', 2), ('pass', 2), ('fail', 0), ('cancelled', 0), ('skipped', 0)]:
        if re.findall(r'^# ' + field + r' (\d+)$', output, re.M) != [str(value)]:
            raise RuntimeError('Unexpected V03 TAP ' + field)
    if re.findall(r'^ok \d+ - (.+)$', output, re.M) != list(V03_TITLES):
        raise RuntimeError('Exact original V03 assertions required')
    return list(V03_TITLES)


def v03_settled(records):
    return all(row['closed'] and row['groupAbsent'] and row['terminalPublished']
        and not row['evidenceDebt'] for row in records)


def v03_wrapped(command, executables, python, wrapper_pin):
    if (not command or command[0] not in executables
            or len(json.dumps(command).encode()) > 32768
            or sha(V03_WRAPPER) != wrapper_pin or sha(python[0]) != python[1]
            or sha(command[0]) != executables[command[0]]):
        raise RuntimeError('V03 executable/argv binding changed')
    return [python[0], '-B', str(V03_WRAPPER), executables[command[0]], '--', *command]
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
    parser.add_argument('--v03-current-host-profile')
    for key in ('node', 'node-sha256', 'docker', 'docker-sha256', 'docker-host',
                'docker-daemon', 'image-id', 'evidence-parent'):
        parser.add_argument('--v03-' + key)
    for key in ('run-id', 'admission', 'admission-sha256'):
        parser.add_argument('--v03-' + key)
    gate = parser.add_mutually_exclusive_group(required=True)
    gate.add_argument('--plan', action='store_true')
    gate.add_argument('--run', action='store_true')
    tokens = list(sys.argv[1:] if argv is None else argv)
    options = [item.split('=', 1)[0] for item in tokens if item.startswith('--v03-')]
    if len(set(options)) != len(options):
        parser.error('Duplicate V03 option')
    args=parser.parse_args(tokens)
    fields = ('node', 'node_sha256', 'docker', 'docker_sha256', 'docker_host',
              'docker_daemon', 'image_id', 'evidence_parent')
    selected = args.v03_current_host_profile is not None
    if selected and (args.suite != 'v03' or args.upload_polyglot or
            not all(getattr(args, 'v03_' + key) for key in fields)):
        parser.error('Complete exclusive V03 current-host authority required')
    if not selected and any(getattr(args, 'v03_' + key) is not None for key in fields):
        parser.error('V03 authority requires explicit current-host profile')
    live_fields = [args.v03_run_id, args.v03_admission, args.v03_admission_sha256]
    if any(live_fields) and (not selected or not all(live_fields)
            or not re.fullmatch('[0-9a-f]{32}', args.v03_run_id)
            or not re.fullmatch('[0-9a-f]{64}', args.v03_admission_sha256)):
        parser.error('Complete exact V03 run/admission binding required')
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
    # Scoped local bindings preserve every historical suite default.
    node, node_sha = globals()['NODE'], globals()['NODE_SHA']
    docker_binary, docker_sha = globals()['DOCKER_BINARY'], globals()['DOCKER_SHA']
    host, daemon, image = globals()['HOST'], globals()['DAEMON'], globals()['IMAGE']
    admitted_parent = None
    if args.v03_current_host_profile is not None:
        from secureshop_current_host_admission import validate_current_host, evidence_parent
        validate_current_host(workspace=ROOT, profile=args.v03_current_host_profile,
            docker_host=args.v03_docker_host, node=args.v03_node,
            node_sha256=args.v03_node_sha256, docker=args.v03_docker,
            docker_sha256=args.v03_docker_sha256, daemon_id=args.v03_docker_daemon,
            image_id=args.v03_image_id)
        admitted_parent = evidence_parent(ROOT, args.v03_evidence_parent)
        node, node_sha = pathlib.Path(args.v03_node), args.v03_node_sha256
        docker_binary, docker_sha = pathlib.Path(args.v03_docker), args.v03_docker_sha256
        host, daemon, image = args.v03_docker_host, args.v03_docker_daemon, args.v03_image_id
        # Source-only stage. Live activation needs separate process-owner and
        # fresh prerequisite receipt review; this patch grants no execution.
        if args.run and not V03_CURRENT_HOST_LIVE:
            raise RuntimeError('V03 current-host prerequisite live admission remains closed')
        if args.run and not args.v03_admission:
            raise RuntimeError('Explicit V03 prerequisite admission required')
    NODE, NODE_SHA = node, node_sha
    DOCKER_BINARY, DOCKER_SHA = docker_binary, docker_sha
    HOST, DAEMON, IMAGE = host, daemon, image
    DOCKER = [str(DOCKER_BINARY), '--host', HOST]
    config = dict(SUITES[args.suite])
    if args.upload_polyglot:
        config['qualification']='V07 qualified/default-disabled catalog fresh/pending promotion/populated/no-op with target and sibling controlled immutable history and instructor preservation, normal administrator admission; controlled PostgreSQL 0112 fresh/populated/no-op, original upload and preview model graph/source/receipt/assessment persistence, fixed/replay/reset/sibling fences; controlled worker/provider/Judge, no actual execution/model/browser/credit claim'
        config['extra']=[*config['extra'],'sidecars/sandbox-runner/owned-system/upload-preview-contract.js','db/postgres/workshop-migrations/secureshop_agents/0112_upload_preview_registry_successor.sql']
    fixture = config['fixture']
    command = [str(pathlib.Path(__file__).resolve()), '--suite', args.suite,*(['--upload-polyglot'] if args.upload_polyglot else []), '--run']
    if admitted_parent is not None:
        command[1:1] = [item for key in ('current-host-profile', 'node', 'node-sha256',
            'docker', 'docker-sha256', 'docker-host', 'docker-daemon', 'image-id',
            'evidence-parent') for item in ('--v03-' + key,
            getattr(args, 'v03_' + key.replace('-', '_')))]
        if args.v03_admission:
            command += [item for key in ('run-id', 'admission', 'admission-sha256')
                for item in ('--v03-' + key, getattr(args, 'v03_' + key.replace('-', '_')))]
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
    lease = None
    if admitted_parent is not None:
        nonce = args.v03_run_id
        extra = [pathlib.Path(__file__).resolve(), ROOT / fixture, inventory_source, lifecycle_path,
            pathlib.Path(lifecycle.helpers.__file__), dependency_source, ROOT / 'package.json', ROOT / 'package-lock.json',
            *(ROOT / relative for relative in config['extra']), ROOT / 'db/postgres/migrate.js',
            ROOT / 'server/database/postgres/index.js', ROOT / 'server/database/postgres/poolBudget.js']
        extra += [V03_WRAPPER, ROOT / 'tests/postgres/secureshop_current_host_admission.py',
            ROOT / 'tests/postgres/darwin_process_inventory.py']
        pins = inventory(extra)
        dependencies = dependency_inventory(ROOT / 'node_modules')
        physical_python = pathlib.Path(sys.executable).resolve()
        if not physical_python.is_file() or not os.access(physical_python, os.X_OK):
            raise RuntimeError('Physical Python executable required')
        python_pin = (str(physical_python), sha(physical_python))
        wrapper_pin = sha(V03_WRAPPER)
        executables = {str(NODE): NODE_SHA, str(DOCKER_BINARY): DOCKER_SHA}
        binding = {'schema': 'v03-prerequisite-current-host-admission-v1', 'runId': nonce,
            'sourceRoot': str(ROOT), 'suite': 'v03', 'fixture': fixture,
            'assertions': list(V03_TITLES), 'limits': V03_LIMITS,
            'sourceSha256': canonical_digest(pins),
            'dependenciesSha256': canonical_digest(dependencies),
            'python': {'path': python_pin[0], 'sha256': python_pin[1]},
            'wrapperSha256': wrapper_pin, 'executables': executables,
            'profile': args.v03_current_host_profile, 'dockerHost': HOST,
            'daemonId': DAEMON, 'imageId': IMAGE, 'evidenceParent': str(admitted_parent),
            'argvSha256': canonical_digest(v03_admission_argv(command))}
        v03_packet(args.v03_admission, args.v03_admission_sha256, binding)
        lease = V03Lease()
    evidence = pathlib.Path(tempfile.mkdtemp(prefix='dvaia-' + args.suite + '-main-',
        **({'dir': admitted_parent} if admitted_parent is not None else {}))).resolve()
    evidence.chmod(0o700)
    if admitted_parent is None and evidence.is_relative_to(ROOT):
        raise RuntimeError('Evidence/runtime must be outside the main source')
    if admitted_parent is not None and evidence.parent != admitted_parent:
        raise RuntimeError('Exact V03 evidence parent required')
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
    nonce = args.v03_run_id if admitted_parent is not None else uuid.uuid4().hex
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
    if admitted_parent is not None:
        extra += [V03_WRAPPER, ROOT / 'tests/postgres/secureshop_current_host_admission.py',
            ROOT / 'tests/postgres/darwin_process_inventory.py']
    if admitted_parent is None:
        pins = inventory(extra)
        dependencies = dependency_inventory(ROOT / 'node_modules')
    result['sourceHashes'] = pins
    result['dependencyInventorySha256'] = hashlib.sha256(json.dumps(dependencies,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def private_json(path, value):
        if admitted_parent is not None and len(json.dumps(value).encode()) > V03_LIMITS['metadataBytes']:
            raise RuntimeError('V03 metadata byte bound')
        lifecycle.helpers.write_private_json(path, value)

    private_json(evidence / 'dependencies-before.json', dependencies)

    if admitted_parent is not None:
        result.update(schema='v03-prerequisite-current-host-v1', runId=nonce,
            admissionSha256=args.v03_admission_sha256, admission=binding,
            originalAssertions=list(V03_TITLES), qualificationComplete=False)

    def save():
        private_json(evidence / 'result.json', result)

    def run(command, timeout=30):
        if admitted_parent is not None:
            return owned_call(command, timeout=timeout)
        return subprocess.run(command, cwd=ROOT, env=env, check=True, text=True,
            capture_output=True, timeout=timeout)

    owned_records = []
    def owned_call(command, timeout=30, check=True):
        # Physical outside execution; file-backed output, bounded readback.
        from darwin_process_inventory import LibProc
        api = LibProc()
        def identity(pid):
            row = api.identity(pid)
            return None if row is None else (row.pid, row.ppid, row.pgid,
                row.uid, row.start_sec, row.start_usec)
        label = 'owned-command-' + str(len(owned_records))
        paths = [evidence / (label + '.' + suffix + '.log') for suffix in ('stdout', 'stderr')]
        record = {'argv': command, 'pid': None, 'birth': None, 'closed': False,
            'groupAbsent': False, 'errors': [], 'outputLimitBytes': 8 * 1024 * 1024,
            'terminalPublished': False, 'evidenceDebt': True, 'overflow': False}
        owned_records.append(record)
        child = None
        try:
            timeout = lease.command(timeout)
            actual_command = v03_wrapped(command, executables, python_pin, wrapper_pin)
            record.update(requestedArgv=command, actualArgv=actual_command,
                wrapperSha256=wrapper_pin, phase=lease.phase,
                absoluteWorkDeadline=lease.work_end, absoluteRetirementDeadline=lease.retire_end)
            with lifecycle.helpers.open_private_log(paths[0]) as out, lifecycle.helpers.open_private_log(paths[1]) as err:
                try:
                    timeout = lease.remaining(timeout)
                    child = subprocess.Popen(actual_command, cwd=ROOT, env=env,
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                        start_new_session=True, text=True)
                    record['pid'] = child.pid
                    record['birth'] = identity(child.pid)
                    private_json(evidence / (label + '-intent.json'), record)
                    # A successfully joined fast child can vanish before LibProc.
                    # Never assign it a fabricated birth or signal an unknown PID.
                    if record['birth'] is not None and record['birth'][2] != child.pid:
                        raise RuntimeError('V03 child group mismatch')
                    if record['birth'] is None and child.poll() is None:
                        raise RuntimeError('V03 live child birth unavailable')
                    end = min(time.monotonic() + timeout, lease.work_end)
                    while child.poll() is None:
                        if any(p.stat().st_size > record['outputLimitBytes'] for p in paths):
                            raise RuntimeError('V03 output limit exceeded')
                        if time.monotonic() >= end:
                            raise subprocess.TimeoutExpired(command, timeout)
                        try: child.wait(timeout=min(.1, max(.001, end-time.monotonic())))
                        except subprocess.TimeoutExpired: pass
                except BaseException as error:
                    record['errors'].append(type(error).__name__ + ': ' + str(error))
                finally:
                    if child is not None:
                        try:
                            if child.poll() is None:
                                if record['birth'] is None or identity(child.pid) != record['birth']:
                                    # Bounded join only; unknown identity is never signal authority.
                                    child.wait(timeout=lease.retirement(1))
                                else:
                                    grace = lease.retirement(10)
                                    os.killpg(child.pid, signal.SIGTERM)
                                    try: child.wait(timeout=grace)
                                    except subprocess.TimeoutExpired:
                                        if identity(child.pid) != record['birth']:
                                            raise RuntimeError('V03 birth changed; kill withheld')
                                        grace = lease.retirement(10)
                                        os.killpg(child.pid, signal.SIGKILL)
                                        child.wait(timeout=grace)
                            record['closed'] = child.poll() is not None
                            record['exitCode'] = child.returncode
                        except BaseException as error:
                            record['errors'].append('retirement:' + type(error).__name__)
                        try: record['groupAbsent'] = not api.group_pids(child.pid)
                        except BaseException as error:
                            record['errors'].append('inventory:' + type(error).__name__)
        except BaseException as error:
            record['errors'].append('logging-or-spawn:' + type(error).__name__)
        finally:
            # Classify before publication, including fast-child output overflow.
            captured = []
            record['output'] = []
            try:
                for p in paths:
                    size = p.stat().st_size
                    with p.open('rb') as stream:
                        raw = stream.read(record['outputLimitBytes'])
                    overflow = size >= record['outputLimitBytes']
                    record['overflow'] = record['overflow'] or overflow
                    record['output'].append({'path': str(p), 'observedBytes': size,
                        'capturedBytes': len(raw), 'capturedSha256': hashlib.sha256(raw).hexdigest(),
                        'truncated': overflow})
                    captured.append(raw.decode('utf-8'))
                if record['overflow']:
                    record['errors'].append('output-limit-exceeded')
                if check and record.get('exitCode') != 0:
                    record['errors'].append('nonzero-exit')
                if time.monotonic() >= lease.work_end:
                    record['errors'].append('absolute-phase-deadline')
                lease.check()
            except BaseException as error:
                record['errors'].append('output-classification:' + type(error).__name__)
            terminal = evidence / (label + '-terminal.json')
            try:
                published = json.loads(json.dumps({**record,
                    'terminalPublished': True, 'evidenceDebt': False}))
                private_json(terminal, published)
                if json.loads(terminal.read_text()) != published:
                    raise RuntimeError('Terminal publication readback mismatch')
                record.update(terminalPublished=True, evidenceDebt=False,
                    terminalSha256=sha(terminal))
            except BaseException as error:
                record['errors'].append('terminal-publication:' + type(error).__name__)
        if record['errors'] or record['evidenceDebt'] or not record['closed'] or not record['groupAbsent']:
            raise RuntimeError('V03 owned command failed or retirement unproven')
        output, error = captured
        completed = subprocess.CompletedProcess(command, child.returncode, output, error)
        if check: completed.check_returncode()
        return completed

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
        if lease is not None:
            v03_packet(args.v03_admission, args.v03_admission_sha256, binding)
            if inventory(extra) != pins or dependency_inventory(ROOT / 'node_modules') != dependencies:
                raise RuntimeError('V03 pre-allocation source/dependency drift')
            lease.check()
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
            readiness_command = DOCKER + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'bound_upload_admin']
            probe = (owned_call(readiness_command, timeout=5, check=False)
                if admitted_parent is not None else subprocess.run(readiness_command,
                env=env, capture_output=True, timeout=5))
            if probe.returncode == 0:
                break
            if lease is not None and lease.work_end - time.monotonic() < .25:
                raise RuntimeError('V03 readiness absolute deadline')
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
        output = (owned_call([str(NODE), '--test', '--test-concurrency=1',
            '--test-reporter=tap', str(ROOT / fixture)], timeout=300, check=False)
            if admitted_parent is not None else lifecycle.run_owned_child([str(NODE), '--test', '--test-concurrency=1',
            '--test-reporter=tap', str(ROOT / fixture)], cwd=ROOT, env=env, evidence=evidence,
            children=children, timeout=300))
        result.update(exitCode=output.returncode,
            stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),
            stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        for field, value in [('tests', 2), ('pass', 2), ('fail', 0), ('cancelled', 0), ('skipped', 0)]:
            if not re.search(r'^# ' + field + ' ' + str(value) + r'$', output.stdout, re.M):
                raise RuntimeError('Unexpected TAP ' + field)
        if output.returncode:
            raise RuntimeError('Native ' + args.suite + ' fixture failed')
        if admitted_parent is not None:
            result['observedAssertions'] = v03_assertions(output.stdout)
            result['tapCounts'] = {'tests': 2, 'pass': 2, 'fail': 0, 'cancelled': 0, 'skipped': 0}
        result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=type(error).__name__ + ': ' + str(error))
        if isinstance(error, subprocess.CalledProcessError):
            private_json(evidence / 'command-failure.json',
                {'returncode': error.returncode, 'stdout': error.stdout, 'stderr': error.stderr})
    finally:
        errors = []
        if lease is not None:
            lease.cleanup()
        for child in reversed(children):
            try:
                lifecycle.helpers.stop_group(child)
            except BaseException as error:
                errors.append('Child cleanup: ' + str(error))
        if admitted_parent is not None and not v03_settled(owned_records):
            errors.append('Current-host child retirement debt; container retained')
        if attempted and (admitted_parent is None or not errors):
            try:
                verified = inspect_owned()
                if verified:
                    if admitted_parent is not None and not v03_settled(owned_records):
                        raise RuntimeError('V03 inspection child evidence debt; removal withheld')
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
        if admitted_parent is not None:
            result['childGroupsAbsent'] = all(row['closed'] and row['groupAbsent']
                for row in owned_records)
            if any(row['evidenceDebt'] or not row['terminalPublished'] for row in owned_records):
                errors.append('Current-host terminal evidence debt')
            result['currentHostOwnership'] = {'version': 1, 'children': owned_records,
                'profile': args.v03_current_host_profile, 'evidenceParent': str(admitted_parent)}
        try:
            after = inventory(extra)
            dependencies_after = dependency_inventory(ROOT / 'node_modules')
            private_json(evidence / 'dependencies-after.json', dependencies_after)
            result['sourceHashesAfter'] = after
            result['sourceUnchanged'] = after == pins
            result['dependenciesUnchanged'] = dependencies_after == dependencies
            if lease is not None:
                v03_packet(args.v03_admission, args.v03_admission_sha256, binding)
                lease.check()
        except BaseException as error:
            result['sourceUnchanged'] = False
            result['dependenciesUnchanged'] = False
            errors.append('Postflight inventory: ' + str(error))
        result['cleanupErrors'] = errors
        result['passed'] = (result.get('passed') is True and not errors and
            result.get('containerAbsent') is True and result['childGroupsAbsent'] is True and
            result['sourceUnchanged'] is True and result['dependenciesUnchanged'] is True)
        if lease is not None:
            result['lease'] = {'startMonotonic': lease.start, 'endMonotonic': lease.end,
                'completedMonotonic': time.monotonic(), 'commands': lease.counts,
                'limits': V03_LIMITS}
            result['qualificationComplete'] = result['passed']
        save()
        if lease is not None:
            try:
                lease.check()
            except RuntimeError as error:
                result.update(passed=False, qualificationComplete=False)
                result['cleanupErrors'].append(str(error))
                save()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(str(evidence / 'result.json'))
    return 0 if result['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
