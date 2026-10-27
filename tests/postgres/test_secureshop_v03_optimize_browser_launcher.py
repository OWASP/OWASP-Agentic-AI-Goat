"""Resource-free controls for the V03 actual browser launcher."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')
HOST = Path(__file__).with_name('secureshopStandaloneRoleChoicesRendered.integration.test.js')
WRAPPER = Path(__file__).with_name('run-listings-package-v03-isolated.py')

def load_launcher(name):
    spec=importlib.util.spec_from_file_location(name, SOURCE)
    launcher=importlib.util.module_from_spec(spec)
    sys.path.insert(0,str(SOURCE.parent))
    try: spec.loader.exec_module(launcher)
    finally: sys.path.pop(0)
    return launcher

def load_wrapper(name):
    spec=importlib.util.spec_from_file_location(name, WRAPPER)
    wrapper=importlib.util.module_from_spec(spec)
    sys.path.insert(0,str(WRAPPER.parent))
    try: spec.loader.exec_module(wrapper)
    finally: sys.path.pop(0)
    return wrapper

def constants():
    tree = ast.parse(SOURCE.read_text())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError): pass
    return values


def test_v03_private_fd_flags_are_exclusive_and_native_gate_remains_closed():
    launcher = load_launcher('v03_private_fd_selection')
    base = dict(cohort=launcher.V03_OPTIMIZE_BROWSER, plan=False,
        v03_private_run_id='a'*32, v03_private_plan_sha256='b'*64,
        v03_private_channel_fd=3, v03_private_admission_fd=4,
        listings_image_id=None, listings_runtime_digest=None)
    assert launcher.v03_private_selected(types.SimpleNamespace(**base)) is True
    assert launcher.V03_PRIVATE_MAIN_LIVE_ENABLED is False
    try:
        launcher.validate_static(types.SimpleNamespace(**base))
    except RuntimeError as error:
        assert str(error) == 'V03 private parent MAIN admission remains closed'
    else:
        raise AssertionError('V03 private MAIN must remain closed before producer review')
    for change in (dict(cohort='standalone-listings-browser'),
                   dict(v03_private_plan_sha256=None),
                   dict(v03_private_channel_fd=5),
                   dict(v03_private_admission_fd=5),
                   dict(listings_image_id='sha256:'+'c'*64),
                   dict(listings_runtime_digest='d'*64)):
        row = types.SimpleNamespace(**{**base, **change})
        try:
            launcher.v03_private_selected(row)
        except RuntimeError as error:
            assert str(error) == 'Exact V03 private parent FD admission required'
        else:
            raise AssertionError('Invalid or mixed V03 parent authority was admitted')
    historical = types.SimpleNamespace(cohort=launcher.V03_OPTIMIZE_BROWSER)
    assert launcher.v03_private_selected(historical) is False


def test_private_pg_authority_precedes_creation_and_binding_precedes_readiness():
    text = SOURCE.read_text()
    start = text.index("stage = 'v03-private-parent-admission'", text.index('def main('))
    intent = text.index('v03_private_facade.postgres_create_intent(', start)
    create = text.index("stage = 'container-create'", start)
    bind = text.index('v03_private_facade.bind_postgres(', create)
    ready = text.index("stage = 'postgres-tcp-readiness'", create)
    assert start < intent < create < bind < ready
    assert text.count("stage = 'v03-private-parent-admission'") == 1


def test_private_work_exit_is_not_qualification_and_requires_local_cleanup_handoff():
    launcher = load_launcher('v03_pending_work_exit')
    cleanup = {'browserProfilesAbsent': True, 'browserProcessesAbsent': True,
        'v03Private': {'handoffAccepted': True, 'evidenceDebt': False,
                       'cleanupPending': True, 'qualificationComplete': False}}
    assert launcher.v03_private_work_succeeded(True, None, cleanup, [], []) is True
    for key in ('browserProfilesAbsent', 'browserProcessesAbsent'):
        assert launcher.v03_private_work_succeeded(True, None, {**cleanup, key: False}, [], []) is False
    for change in ({'handoffAccepted': False}, {'evidenceDebt': True}, {'qualificationComplete': True}):
        altered = {**cleanup, 'v03Private': {**cleanup['v03Private'], **change}}
        assert launcher.v03_private_work_succeeded(True, None, altered, [], []) is False
    assert launcher.v03_private_work_succeeded(True, {'type': 'failure'}, cleanup, [], []) is False
    assert launcher.v03_private_work_succeeded(True, None, cleanup, ['debt'], []) is False
    assert launcher.v03_private_work_succeeded(True, None, cleanup, [], ['fd']) is False
    assert 'receipt.update(passed=False, qualificationComplete=False, cleanupPending=True,' in SOURCE.read_text()


def test_v03_private_facade_receives_main_captured_pins_not_packet_values():
    launcher = load_launcher('v03_private_facade_admission')
    source = SOURCE.parents[2]
    node = source / 'tasks/runtime/node/node_modules/node/bin/node'
    node_sha = launcher.digest(node)
    args = types.SimpleNamespace(cohort=launcher.V03_OPTIMIZE_BROWSER,
        v03_private_run_id='a'*32, v03_private_plan_sha256='b'*64,
        v03_private_channel_fd=3, v03_private_admission_fd=4,
        listings_image_id=None, listings_runtime_digest=None, node=str(node))
    import v03_private_executors
    sentinel = object()
    with patch.object(launcher, 'V03_PRIVATE_MAIN_LIVE_ENABLED', True), \
         patch.object(v03_private_executors.V03PrivateExecutors,
             'from_admission_fds', return_value=sentinel) as consume:
        pins = {'sourcePins': {'tests/postgres/v03_private_executors.py': 'c'*64}}
        assert launcher.v03_private_admit(args, source, pins, node_sha) is sentinel
        consume.assert_called_once_with(root=str(source), run_id='a'*32,
            plan_sha256='b'*64, source_pins={**pins['sourcePins'],
                'tasks/runtime/node/node_modules/node/bin/node': node_sha},
            channel_fd=3, admission_fd=4)
    try:
        launcher.v03_private_admit(args, source, {'sourcePins': {}}, node_sha)
    except RuntimeError as error:
        assert str(error) == 'V03 private parent MAIN admission remains closed'
    else:
        raise AssertionError('V03 private facade must stay live-gated closed')


def fresh_v03_control():
    launcher = load_launcher('v03_fresh_control')
    root = SOURCE.parents[2]
    approved = copy.deepcopy(launcher.V03_OPTIMIZE_FRESH_APPROVED)
    args = types.SimpleNamespace(v03_native_proof_kind='current-host-v1')
    for key, path_field, hash_field in (
        ('tap', 'v03_native_receipt', 'v03_native_receipt_sha256'),
        ('result', 'v03_native_result', 'v03_native_result_sha256'),
        ('sourceAdmission', 'v03_source_admission', 'v03_source_admission_sha256'),
        ('terminal', 'v03_outer_terminal', 'v03_outer_terminal_sha256'),
        ('full', 'v03_independent_full', 'v03_independent_full_sha256')):
        setattr(args, path_field, str(root / approved[key][0]))
        setattr(args, hash_field, approved[key][1])
    return launcher, root, approved, args


def synthetic_v03_control():
    """Sealed small in-memory documents: ordinary controls need no private run history."""
    launcher = load_launcher('v03_fresh_synthetic')
    root = SOURCE.parents[2]
    prefix = 'tasks/tmp/v03-synthetic-controlled'
    pack = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    sha = lambda data: hashlib.sha256(data).hexdigest()
    paths = {key:f'{prefix}/{key}.json' for key in ('sourceAdmission','admission','result','terminal','full')}
    paths['tap'] = f'{prefix}/owned-command-0.stdout.log'
    source_map = dict(launcher.V03_OPTIMIZE_NATIVE_PINS)
    dependencies = {'controlled':'dependency'}
    source_sha, dependencies_sha = sha(pack(source_map)), sha(pack(dependencies))
    run_id = '1' * 32
    node = str(root / 'tasks/runtime/node/node_modules/node/bin/node')
    docker = str(root / 'tasks/runtime/container/bin/docker')
    python = '/controlled/producer-python'
    outer_python = '/controlled/outer-python'
    fixture_argv = [node,'--test','--test-concurrency=1','--test-reporter=tap',
                    str(root / launcher.V03_OPTIMIZE_NATIVE_TEST)]
    admission = {'schema':'v03-prerequisite-current-host-admission-v1','runId':run_id,
        'sourceSha256':source_sha,'dependenciesSha256':dependencies_sha,
        'fixture':launcher.V03_OPTIMIZE_NATIVE_TEST,
        'assertions':list(launcher.V03_OPTIMIZE_NATIVE_ASSERTIONS),'sourceRoot':str(root),
        'executables':{node:'2'*64,docker:'3'*64},'python':{'path':python,'sha256':'4'*64},
        'daemonId':'controlled-daemon','dockerHost':'controlled-docker-host',
        'imageId':'controlled-image','profile':'controlled-profile',
        'evidenceParent':str(root / 'tasks/qualification'),'wrapperSha256':'6'*64}
    tap_lines = ['TAP version 13']
    for number, title in enumerate(launcher.V03_OPTIMIZE_NATIVE_ASSERTIONS,1):
        tap_lines += [f'# Subtest: {title}',f'ok {number} - {title}']
    tap_lines += ['1..2','# tests 2','# pass 2','# fail 0','# cancelled 0','# skipped 0']
    tap = ('\n'.join(tap_lines)+'\n').encode()
    documents = {paths['admission']:pack(admission),paths['tap']:tap}
    artifact_names = ('source-before.json','source-after.json',
                      'dependencies-before.json','dependencies-after.json')
    for name in artifact_names:
        documents[f'{prefix}/{name}'] = pack(source_map if name.startswith('source') else dependencies)
    artifacts = {name:{'bytes':len(documents[f'{prefix}/{name}']),
                       'sha256':sha(documents[f'{prefix}/{name}'])} for name in artifact_names}
    artifacts['admission.json'] = {'bytes':len(documents[paths['admission']]),
                                    'sha256':sha(documents[paths['admission']])}
    canonical = ['/controlled/producer','--v03-run-id',run_id,'--v03-admission',
                 str(root / paths['admission']),'--v03-admission-sha256',sha(documents[paths['admission']])]
    admission['argvSha256'] = sha(pack(canonical[:-4]))
    documents[paths['admission']] = pack(admission)
    artifacts['admission.json'] = {'bytes':len(documents[paths['admission']]),
                                   'sha256':sha(documents[paths['admission']])}
    canonical[-1] = artifacts['admission.json']['sha256']
    source_admission = {'version':1,'runId':run_id,'sourceSha256':source_sha,
        'dependenciesSha256':dependencies_sha,'sourceBeforeAfterEqual':True,
        'dependenciesBeforeAfterEqual':True,'nativeStarted':False,'artifacts':artifacts,
        'physicalArgv':[outer_python,'-B',*canonical],'canonicalRunCommand':canonical,
        'explicitPins':{},'executables':{node:'2'*64,docker:'3'*64,python:'4'*64,outer_python:'5'*64}}
    documents[paths['sourceAdmission']] = pack(source_admission)
    children = []
    original_hashes = {}
    for index in range(26):
        child = {'phase':'work','requestedArgv':fixture_argv if index == 0 else ['controlled',str(index)],
                 'closed':True,'groupAbsent':True,'terminalPublished':True,'errors':[],
                 'evidenceDebt':False,'overflow':False,'exitCode':0 if index == 0 else 2,
                 'birth':[index,1], 'output':[
                    {'path':str(root / paths['tap']),'capturedSha256':sha(tap),
                     'capturedBytes':len(tap),'observedBytes':len(tap),'truncated':False},
                    {'path':str(root / f'{prefix}/owned-command-0.stderr.log'),
                     'capturedSha256':sha(b''),'capturedBytes':0,'observedBytes':0,'truncated':False}]
                    if index == 0 else []}
        if index == 0:
            child['argv'] = fixture_argv
            child['actualArgv'] = [python,'-B',str(root / 'tests/postgres/secureshop_v03_fsize_exec.py'),
                                   '2'*64,'--',*fixture_argv]
            child['wrapperSha256'] = '6'*64
        relative = f'{prefix}/owned-command-{index}-terminal.json'
        documents[relative] = pack(child)
        child['terminalSha256'] = sha(documents[relative])
        original_hashes[relative] = child['terminalSha256']
        children.append(child)
    lease = {'commands':{'work':26,'cleanup':0}}
    result = {'schema':'v03-prerequisite-current-host-v1','version':1,'suite':'v03',
        'runId':run_id,'admissionSha256':sha(documents[paths['admission']]),'admission':admission,
        'fixture':launcher.V03_OPTIMIZE_NATIVE_TEST,'expectedTests':2,'exitCode':0,
        'cleanupErrors':[],'originalAssertions':list(launcher.V03_OPTIMIZE_NATIVE_ASSERTIONS),
        'observedAssertions':list(launcher.V03_OPTIMIZE_NATIVE_ASSERTIONS),
        'tapCounts':{'tests':2,'pass':2,'fail':0,'skipped':0,'cancelled':0},
        'passed':True,'qualificationComplete':True,'sourceUnchanged':True,
        'dependenciesUnchanged':True,'containerAbsent':True,'childGroupsAbsent':True,
        'actualModel':False,'actualNetworkEffects':False,'actualUpload':False,
        'browser':False,'graph':False,'judgeOrCredit':False,'sourceCopies':False,
        'sourceHashes':source_map,'sourceHashesAfter':source_map,
        'dependencyInventorySha256':dependencies_sha,'stdoutSha256':sha(tap),
        'stderrSha256':sha(b''),'currentHostOwnership':{'children':children},
        'daemonId':'controlled-daemon','containerId':'controlled-container','lease':lease,
        'sourceRoot':str(root),'dockerHost':'controlled-docker-host',
        'postgresImage':'controlled-image'}
    result['currentHostOwnership'].update(profile='controlled-profile',
        evidenceParent=str(root / 'tasks/qualification'))
    documents[paths['result']] = pack(result)
    outer = {'runId':run_id,'exitCode':0,'joined':True,'coordinatorFailure':None}
    documents[paths['terminal']] = pack(outer)
    for key in ('sourceAdmission','result','tap','terminal'):
        original_hashes[paths[key]] = sha(documents[paths[key]])
    full = {'kind':'independent-v03-original-prerequisite-current-closure','runId':run_id,
        'originalExitCode':0,'originalError':None,'runMatches':[],
        'fullCurrentClosureVerified':True,'qualificationPassed':True,
        'sourceDependenciesUnchanged':True,'imageUnchanged':True,
        'sourceDigest':source_sha,'dockerDaemon':'controlled-daemon',
        'exactPgAbsent':'controlled-container','originalLease':lease,
        'originalFileHashes':original_hashes}
    documents[paths['full']] = pack(full)
    approved = {'runId':run_id,'sourceSha256':source_sha,'dependenciesSha256':dependencies_sha,
                **{key:(rel,sha(documents[rel])) for key,rel in paths.items()}}
    args = types.SimpleNamespace(v03_native_proof_kind='current-host-v1')
    for key,path_field,hash_field in (
        ('tap','v03_native_receipt','v03_native_receipt_sha256'),
        ('result','v03_native_result','v03_native_result_sha256'),
        ('sourceAdmission','v03_source_admission','v03_source_admission_sha256'),
        ('terminal','v03_outer_terminal','v03_outer_terminal_sha256'),
        ('full','v03_independent_full','v03_independent_full_sha256')):
        setattr(args,path_field,str(root / paths[key]))
        setattr(args,hash_field,approved[key][1])
    def reader(source,raw,relative,expected,limit):
        assert str(raw) == str(source / relative)
        data = documents[relative]
        assert sha(data) == expected and len(data) <= limit
        return data
    return launcher,root,approved,args,documents,reader


def test_v03_fresh_exact_accepted_prerequisite_and_historical_dispatch():
    launcher, root, approved, args, documents, reader = synthetic_v03_control()
    with patch.object(launcher, 'v03_fresh_private_bytes', side_effect=reader):
        accepted = launcher.validate_v03_fresh_native_receipt(args, root, approved)
    assert accepted['proofKind'] == 'current-host-v1'
    assert accepted['counts'] == {'tests':2, 'pass':2, 'fail':0, 'skipped':0, 'cancelled':0}
    legacy = types.SimpleNamespace(v03_native_receipt='old.tap', v03_native_receipt_sha256='old',
        v03_native_result='old.json', v03_native_result_sha256='old')
    sentinel = object()
    with patch.object(launcher, 'validate_v03_historical_native_receipt', return_value=sentinel) as old:
        assert launcher.validate_v03_native_receipt(legacy, root) is sentinel
        old.assert_called_once_with(legacy, root)
    args.v03_independent_full_sha256 = '0' * 64
    with patch.object(launcher, 'v03_fresh_private_bytes', side_effect=reader):
        try: launcher.validate_v03_fresh_native_receipt(args, root, approved)
        except RuntimeError as error: assert 'digest' in str(error)
        else: assert False, 'wrong FULL digest admitted'
    if os.environ.get('SECURESHOP_V03_ACCEPTED_PROOF_CONTROL') == '1':
        actual, actual_root, _, actual_args = fresh_v03_control()
        assert actual.validate_v03_native_receipt(actual_args, actual_root)['proofKind'] == 'current-host-v1'


def test_v03_fresh_resealed_semantic_denials():
    launcher, root, approved, args, base_documents, original_reader = synthetic_v03_control()
    for target, mutate, expected, reseal_child in (
        ('result', lambda row: row.update(runId='0' * 32), 'result', False),
        ('result', lambda row: row['currentHostOwnership']['children'][0].update(groupAbsent=False), 'child', False),
        ('result', lambda row: row['sourceHashes'].update({launcher.V03_OPTIMIZE_NATIVE_TEST:'0' * 64}), 'result', False),
        ('result', lambda row: row.update(daemonId='wrong-daemon'), 'result', False),
        ('result', lambda row: row['currentHostOwnership'].update(profile='wrong-profile'), 'child', False),
        ('result', lambda row: row['currentHostOwnership']['children'][0]['actualArgv'].__setitem__(0,'wrong-python'), 'wrapper', True),
        ('sourceAdmission', lambda row: row.update(version=2), 'source admission', False),
        ('terminal', lambda row: row.update(exitCode=1), 'terminal', False),
        ('full', lambda row: row.update(originalLease={}), 'terminal', False),
        ('full', lambda row: row.update(exactPgAbsent='wrong-container'), 'terminal', False)):
        candidate = copy.deepcopy(approved)
        option = copy.deepcopy(args)
        documents = dict(base_documents)
        relative = candidate[target][0]
        row = json.loads(documents[relative])
        mutate(row)
        terminal_update = None
        if reseal_child:
            terminal_rel = str(Path(candidate['result'][0]).parent / 'owned-command-0-terminal.json')
            child = row['currentHostOwnership']['children'][0]
            terminal_update = json.dumps({k:v for k,v in child.items() if k != 'terminalSha256'},
                                         sort_keys=True,separators=(',', ':')).encode()
            child['terminalSha256'] = hashlib.sha256(terminal_update).hexdigest()
            documents[terminal_rel] = terminal_update
        encoded = json.dumps(row, sort_keys=True, separators=(',', ':')).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        candidate[target] = (relative, digest)
        documents[relative] = encoded
        if target in ('result', 'terminal', 'sourceAdmission'):
            full_rel = candidate['full'][0]
            full_row = json.loads(documents[full_rel])
            full_row['originalFileHashes'][relative] = digest
            if terminal_update is not None:
                full_row['originalFileHashes'][terminal_rel] = hashlib.sha256(terminal_update).hexdigest()
            full_encoded = json.dumps(full_row, sort_keys=True, separators=(',', ':')).encode()
            candidate['full'] = (full_rel, hashlib.sha256(full_encoded).hexdigest())
            documents[full_rel] = full_encoded
        for key, field in (('result', 'v03_native_result_sha256'),
                           ('sourceAdmission', 'v03_source_admission_sha256'),
                           ('terminal', 'v03_outer_terminal_sha256'),
                           ('full', 'v03_independent_full_sha256')):
            setattr(option, field, candidate[key][1])
        def sealed_reader(source, raw, rel, sha, limit):
            data = documents.get(rel)
            if data is None: return original_reader(source, raw, rel, sha, limit)
            assert hashlib.sha256(data).hexdigest() == sha
            assert len(data) <= limit
            return data
        with patch.object(launcher, 'v03_fresh_private_bytes', side_effect=sealed_reader):
            try: launcher.validate_v03_fresh_native_receipt(option, root, candidate)
            except RuntimeError as error: assert expected in str(error), (target, error)
            else: assert False, f'resealed {target} semantic mutation admitted'


def test_v03_fresh_reader_nonblocking_fifo_alias_and_ancestor_denials():
    launcher, root, _, _, _, _ = synthetic_v03_control()
    with tempfile.TemporaryDirectory(dir=root / 'tasks/tmp') as temp:
        folder = Path(temp)
        fifo = folder / 'evidence.json'
        os.mkfifo(fifo, 0o600)
        relative = fifo.relative_to(root).as_posix()
        try: launcher.v03_fresh_private_bytes(root, fifo, relative, '0' * 64, 4096)
        except RuntimeError as error: assert 'Private bounded' in str(error)
        else: assert False, 'FIFO open must fail without blocking or a writer'
        actual = folder / 'real'
        actual.mkdir()
        alias = folder / 'alias'
        alias.symlink_to(actual, target_is_directory=True)
        target = alias / 'evidence.json'
        try: launcher.v03_fresh_private_bytes(root, target, target.relative_to(root).as_posix(), '0' * 64, 4096)
        except RuntimeError as error: assert 'alias' in str(error)
        else: assert False, 'symlink ancestor admitted'
        rewritten = str(fifo.parent) + '/./evidence.json'
        try: launcher.v03_fresh_private_bytes(root, rewritten, relative, '0' * 64, 4096)
        except RuntimeError as error: assert 'path and bound' in str(error)
        else: assert False, 'noncanonical caller path admitted'

def test_v03_exact_cohort_and_reviewed_pins():
    value = constants()
    assert value['V03_OPTIMIZE_BROWSER'] == 'merchant-listing-image-optimize-v03-browser'
    assert value['V03_OPTIMIZE_TEST'] == 'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'
    expected = {
        'HELPER':'209ba96c55b676c8c6c4a635a720876525ff9f3984c75e5419243a496b3e1193',
        'HELPER_CONTROL':'3a089280898a65867464ce3dd4007a38ea8c12da165c9d3e967b3ad2c2edd635',
        'SANDBOX_CONTROL':'bef21a8f6217ebcae0a601fbf4f3a4cf8edfc205d5747594479a55652a5ceb62',
        'CONTRACT':'bff5eea4526babd95205451f3851eddf18c6e217d64a96f109746dc492183f59',
        'EVIDENCE':'d90f732142a403161e6c42ab99bee137defab599d7d82497e7dabc1eabfa80fb',
        'SCENARIO':'0e7652ae8356e49754d05ed35acc0db474f1f30e857e0e5391781a5b9c9049ac',
        'CALLER':'9eb99bf8109ba24b54e46ed88ff68fa676035f8fd52dbd74645cd028b4d0f2fa',
        'EVIDENCE_CONTROL':'4e25cb469da5fb35721eacb36977f8bd24d0d2da6bfe7e60e6782eacf3536916'}
    for suffix, digest in expected.items():
        assert value['V03_OPTIMIZE_'+suffix+'_SHA256'] == digest

def test_v03_uses_owned_executor_external_evidence_and_exact_host_test():
    source = SOURCE.read_text()
    for phrase in ["SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_NATIVE='1'", 'OwnedDiagnosticExecutor',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_BUILD',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_EVIDENCE_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_URL',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_TOKEN',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_ORIGINAL_EVIDENCE_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_SOURCE_MANIFEST_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_FRONTEND_INVENTORY_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_MODEL_MANIFEST_PATH',
                   'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_NATIVE_RECEIPT_PATH',
                   "value.add_argument('--v03-native-receipt')",
                   "value.add_argument('--v03-native-receipt-sha256')",
                   "value.add_argument('--v03-native-result')",
                   "value.add_argument('--v03-native-result-sha256')",
                   'validate_v03_native_receipt(args, source)',
                   "'v03NativeReceiptSha256': args.v03_native_receipt_sha256",
                   "'v03NativeResultSha256': args.v03_native_result_sha256",
                   "PG_SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_{name}_RUNTIME_URL",
                   "require('./tests/postgres/secureshopV03ActualContract').validateV03ActualReceipt",
                   "run_node(label,[args.node,'--test','--test-reporter=tap','--test-concurrency=1',V03_OPTIMIZE_TEST],1200)"]:
        assert phrase in source
    for forbidden in ['SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_PRODUCT_URL',
                      'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_IMAGE_URL',
                      'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_TARGET_ID']:
        assert forbidden not in source
    assert 'SECURESHOP_V03_OPTIMIZE_NATIVE' not in source
    assert "run_node(native_label" not in source

def test_v03_host_assembles_the_real_listings_application_before_role_selection():
    source = HOST.read_text()
    for phrase in [
        "getListingsApplication: () => v03Listings?.ready === true",
        "createListingsProduction({ runtime: reset.listingsRuntime",
        "readChatSetup: input => composition.roleAssistants.merchant.runtime.readListingsSetup(input)",
        "systemDiagnosticClient: v03DiagnosticClient",
        "assert.equal(v03Listings.ready, true)",
        "assert.ok(v03Listings.application)",
        "composition = Object.freeze({ ...composition, listings: v03Listings })",
        "SECURESHOP_LISTINGS_TEST_MANAGER_DOCKER_AUTHORITY_SHA256",
        "secureshopListingsManagedConfiguration').validate",
    ]:
        assert phrase in source
    assert source.count("() => v03Listings?.close?.()") == 2

def test_v03_launcher_owns_current_source_listings_manager_and_cleanup():
    source=SOURCE.read_text()
    for phrase in [
      "manifest_program = \"const p=require('./scripts/install/secureshop-owned-listings').sourceManifest(process.cwd())",
      "created=raw_docker_command(args,clean,['run','--detach'",
      "if created.returncode:",
      "Disposable V03 Listings manager create failed",
      "get('Ports',{}).get('8095/tcp')",
      "Disposable V03 Listings manager loopback binding required",
      "readiness=wait_v03_listings_manager",
      "v03-listings-readiness.json",
      "SECURESHOP_LISTINGS_TEST_MANAGER_DOCKER_AUTHORITY_SHA256=authority",
      "cleanup['listings'] = listings_owned.cleanup",
    ]: assert phrase in source
    wrapper=WRAPPER.read_text()
    for phrase in [
      "package.qualify(launcher,package_args,source,after_package=child",
      "'--listings-image-id',admission['imageId']",
      "additional_drivers=(SELF,)",
      "if len(value.encode())>8*1024*1024",
      "os.chmod(path,0o600)",
      "start_new_session=True",
      "os.killpg(process.pid,signal.SIGTERM)",
      "process.communicate(timeout=grace)",
      "os.killpg(process.pid,signal.SIGKILL)",
      "'--listings-runtime-digest',admission['runtimeDigest']",
      "Closed V03 package callback admission required",
    ]: assert phrase in wrapper
    for phrase in [
      "validate_v03_listings_image(row,args.listings_image_id,manifest['sha256'],args.listings_runtime_digest)",
      "'dvaia.listings.runtime':args.listings_runtime_digest",
      "wait_v03_listings_manager(manager_origin,manager_token,args.listings_runtime_digest)",
      "SECURESHOP_LISTINGS_TEST_MANAGER_RUNTIME_DIGEST=args.listings_runtime_digest",
    ]: assert phrase in source
    for phrase in [
      "v03_listings_cleanup = dict.fromkeys(",
      "'containerAbsent', 'volumeAbsent', 'networkAbsent', 'profileAbsent'",
      "'listings': cleanup.get('listings')",
      "v03_python_cleanup['listings'] == v03_listings_cleanup",
    ]: assert phrase in source

def test_v03_manager_readiness_is_authenticated_closed_and_bounded():
    launcher=load_launcher('v03_manager_readiness')
    runtime='a'*64;token='b'*64
    class Response:
        status=200
        def __enter__(self): return self
        def __exit__(self,*_): return False
        def read(self,_): return json.dumps({'version':1,'ready':True,
          'capability':'owned-listings-manager.v1','runtimeDigest':runtime,
          'limits':{'maxPersistedTargets':200,'maxResidentTargets':32,
            'maxConcurrentExecutions':4,'maxQueuedExecutions':16}}).encode()
    class Opener:
        request=None
        def open(self,request,timeout): self.request=request;assert timeout==2;return Response()
    opener=Opener()
    with patch.object(launcher.urllib.request,'build_opener',return_value=opener):
        receipt=launcher.wait_v03_listings_manager('http://127.0.0.1:18095',token,runtime,timeout=1)
    assert receipt['ready'] is True and receipt['runtimeDigest']==runtime
    assert opener.request.full_url=='http://127.0.0.1:18095/manager/health'
    assert opener.request.headers['Authorization']=='Bearer '+token
    with patch.object(launcher.urllib.request,'build_opener',return_value=opener):
        try: launcher.wait_v03_listings_manager('http://localhost:18095',token,runtime,timeout=1)
        except RuntimeError as error: assert str(error)=='Canonical V03 Listings readiness input required'
        else: raise AssertionError('non-loopback manager admitted')
    class WrongRuntime(Response):
        def read(self,_): return json.dumps({'version':1,'ready':True,
          'capability':'owned-listings-manager.v1','runtimeDigest':'c'*64,
          'limits':{'maxPersistedTargets':200,'maxResidentTargets':32,
            'maxConcurrentExecutions':4,'maxQueuedExecutions':16}}).encode()
    class WrongOpener(Opener):
        def open(self,request,timeout): return WrongRuntime()
    with patch.object(launcher.urllib.request,'build_opener',return_value=WrongOpener()):
        try: launcher.wait_v03_listings_manager('http://127.0.0.1:18095',token,runtime,timeout=.01)
        except RuntimeError as error: assert str(error)=='V03 Listings manager readiness identity mismatch'
        else: raise AssertionError('wrong manager runtime admitted')


def test_v03_manager_environment_is_exactly_bound_before_container_admission():
    launcher=load_launcher('v03_manager_environment')
    value=('LISTINGS_MANAGER_ENABLED=true\n'
      'LISTINGS_PROFILE=dvaia-owned-listings-0123456789ab\n'
      'LISTINGS_PUBLIC_ORIGIN=http://127.0.0.1:18095\n'
      'LISTINGS_CONTROL_TOKEN='+'a'*64+'\n')
    expected=__import__('hashlib').sha256('\n'.join(sorted(value.splitlines())).encode()).hexdigest()
    assert launcher.v03_listings_environment_sha256(value)==expected
    for changed in (value.replace('LISTINGS_PROFILE=', 'OTHER_PROFILE=', 1),
                    value+'LISTINGS_EXTRA=denied\n', value.rstrip('\n')):
        try: launcher.v03_listings_environment_sha256(changed)
        except RuntimeError as error:
            assert str(error)=='Closed V03 Listings manager environment required'
        else: raise AssertionError('open V03 Listings manager environment admitted')
    source=SOURCE.read_text()
    assignment="listings_resources['environmentSha256']=v03_listings_environment_sha256(manager_environment)"
    assert source.index(assignment) < source.index("created=raw_docker_command(args,clean,['run','--detach'")


def test_v03_package_image_identity_accepts_absent_or_exact_runtime_label_only():
    launcher=load_launcher('v03_image_identity')
    image='sha256:'+'1'*64;source='2'*64;runtime='3'*64
    def row(runtime_label_marker):
        labels={'dvaia.listings.source':source}
        if runtime_label_marker is not None: labels['dvaia.listings.runtime']=runtime_label_marker
        return {'Id':image,'Architecture':'arm64','Os':'linux','Config':{'Labels':labels}}
    assert launcher.validate_v03_listings_image(row(None),image,source,runtime)=={'dvaia.listings.source':source}
    assert launcher.validate_v03_listings_image(row(runtime),image,source,runtime)['dvaia.listings.runtime']==runtime
    try: launcher.validate_v03_listings_image(row('4'*64),image,source,runtime)
    except RuntimeError as error: assert str(error)=='Qualified V03 Listings image identity mismatch'
    else: raise AssertionError('wrong package runtime label admitted')

def test_v03_wrapper_gracefully_interrupts_child_before_hard_stop():
    wrapper=load_wrapper('v03_wrapper_timeout')
    class Process:
        pid=8123;returncode=1;calls=0
        def communicate(self,timeout):
            self.calls+=1
            if self.calls==1: raise subprocess.TimeoutExpired(['child'],timeout)
            assert timeout==300
            return ('preserved stdout','preserved stderr')
    process=Process();signals=[]
    with patch.object(wrapper.subprocess,'Popen',return_value=process) as popen, \
         patch.object(wrapper.os,'killpg',side_effect=lambda pid,sig:signals.append((pid,sig))):
        result=wrapper.run_child(['child'],Path('/tmp'),timeout=1,grace=300)
    assert result==(1,'preserved stdout','preserved stderr',True)
    assert signals==[(8123,signal.SIGTERM)]
    assert popen.call_args.kwargs['start_new_session'] is True

def test_v03_validator_is_closed_and_digest_joined():
    source = SOURCE.read_text()
    start = source.index('def v03_optimize_browser_receipt')
    end = source.index('\ndef ', start + 4)
    body = source[start:end]
    for phrase in ["set(receipt) != required", "path.stat().st_nlink != 1",
                   "type(receipt.get('actorCorrectiveSpans')) is not int",
                   "receipt['actorProviderSpans'] != 18 + receipt['actorCorrectiveSpans']",
                   "type(receipt.get('actorWireAttempts')) is not int",
                   "receipt['actorWireAttempts'] + receipt['judgeProviderSpans'] <= receipt['actorWireCeiling'] == 27",
                   'digest(original_path)',
                   "row['hostname'] != 'system-diag-' + row['targetId'].replace('-', '')"]:
        assert phrase in body

def test_unrelated_live_cohorts_are_preserved():
    value = constants()
    source = SOURCE.read_text()
    assert 'LIVE_BROWSER_COHORTS = (V03_OPTIMIZE_BROWSER,) + LIVE_BROWSER_COHORTS' in source
    assert value['V01_AUDIT_BROWSER'] == 'customer-checkout-audit-v01-browser'
    # Preserve the pre-V03 MAIN contract; V01 source freshness is checked by its
    # own launcher tests, not by this unrelated-cohort preservation assertion.
    assert value['V01_AUDIT_TEST_SHA256'] == 'a166f9cb63705a110236082a660edcc442a8362c4a37b0f31aede130a6f744c9'
    assert value['V06_UPLOAD_BROWSER'] == 'customer-avatar-upload-v06-browser'
    v06_calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'validate_v06_upload_pins']
    assert len(v06_calls) == 2
    assert all(len(call.args) == 2 and not call.keywords
               and all(isinstance(arg, ast.Name) and arg.id == name
                       for arg, name in zip(call.args, ('source', 'digest')))
               for call in v06_calls)
    for phrase in ["'containerNameAbsent': cleanup.get('containerNameAbsent')",
                   "'containerIdAbsent': cleanup.get('containerIdAbsent')",
                   "'browserProfilesAbsent': cleanup.get('browserProfilesAbsent')",
                   "'browserProcessesAbsent': cleanup.get('browserProcessesAbsent')",
                   "'ownedDiagnosticExecutor': cleanup.get('ownedSystemDiagnosticExecutor')",
                   "all(v03_python_cleanup[key] is True for key in (",
                   "v03_python_cleanup['listings'] == v03_listings_cleanup",
                   '**v03_result_fields(v03_optimize_result,v03_receipt_path,v03_original_path,',
                   'v03_native_result_path,v03_python_cleanup)']:
        assert phrase in source
    for phrase in ['V03 native receipt options are exclusive to the V03 browser cohort',
                   "V03_OPTIMIZE_NATIVE_RESULT_SHA256 = 'c6133d5e",
                   "V03_OPTIMIZE_NATIVE_TAP_SHA256 = '06bd8a06",
                   "V03_OPTIMIZE_NATIVE_HISTORICAL_FIXTURE_SHA256 = '326c4464",
                   "Private single-link pinned V03 native {label} required",
                   "counts != {'tests':2,'pass':2,'fail':0,'skipped':0,'cancelled':0}",
                   "digest(source / name) != expected",
                   "result.get('sourceHashes') != result.get('sourceHashesAfter')",
                   "historical.get(name) != expected",
                   "'v03NativeResultSha256': present_digest(native_result_path)"]:
        assert phrase in source


def test_v03_source_snapshot_closes_executor_runtime_and_browser_dependencies():
    launcher=load_launcher('v03_launcher_closure')
    with patch.object(launcher,'dependency_inventory',return_value={'closed':'inventory'}):
        snapshot=launcher.source_snapshot(SOURCE.parents[2],'/unused-node',launcher.V03_OPTIMIZE_BROWSER,browser_root=SOURCE.parents[2])
    required={
      'tests/fixtures/secureshopV03CandidateCatalog.js',
      'tests/postgres/secureshopMailActualTransport.js',
      'tests/postgres/system_diagnostic_owned_executor.py',
      'tests/postgres/test_system_diagnostic_owned_executor_build.py',
      'tests/postgres/run-csrf-email-composed-isolated.py',
      'tests/postgres/test_secureshop_v03_optimize_browser_launcher.py',
      'sidecars/sandbox-runner/owned-system/diagnostic-wire.js'}
    assert not required-set(snapshot['sourcePins'])
    assert snapshot['clientDependencyInventory']=={'closed':'inventory'}
    assert snapshot['browserInventory']=={'closed':'inventory'}


def test_v03_failure_projection_keeps_primary_result_path_writable():
    launcher=load_launcher('v03_launcher_failure')
    cleanup={'containerNameAbsent':True,'ownedDiagnosticExecutor':True}
    assert launcher.v03_result_fields(None,None,None,None,cleanup)=={
      'v03OptimizeBrowserReceipt':None,
      'v03OptimizeBrowserReceiptSha256':None,
      'v03OriginalEvidenceSha256':None,
      'v03NativeResultSha256':None,
      'v03PythonCleanup':cleanup}
    source=SOURCE.read_text()
    for phrase in ['v03_optimize_result = None','v03_receipt_path = None',
      'v03_original_path = None','v03_native_result_path = None']:
        assert phrase in source


def test_v03_failure_diagnostic_is_bounded_redacted_and_stage_specific():
    launcher=load_launcher('v03_launcher_error_detail')
    try:
        raise RuntimeError('postgresql://owner:private@127.0.0.1/db token=private-value\nsecond line')
    except RuntimeError as error:
        detail=launcher.bounded_error_diagnostic(error)
    assert detail['message']=='[REDACTED_DATABASE_URL] token=[REDACTED] second line'
    assert 1 <= len(detail['frames']) <= 12
    assert set(detail['frames'][-1])=={'file','line','function'}
    assert 'private-value' not in json.dumps(detail)
    source=SOURCE.read_text()
    for stage in [
      "stage = 'owned-system-diagnostic-browser-cleanup-import'",
      "stage = 'environment-configuration'",
      "stage = 'v03-listings-manifest'",
      "stage = 'v03-listings-image-admission'",
      "stage = 'v03-listings-workspace-authority'",
      "stage = 'v03-listings-resource-admission'",
    ]: assert stage in source
    assert '**bounded_error_diagnostic(error)' in source


def test_v03_runtime_digest_is_closed_and_cohort_exclusive():
    launcher=load_launcher('v03_runtime_digest_admission')
    base=['--main-workspace',str(SOURCE.parents[2]),'--node','/node','--docker','/docker',
      '--docker-sha256','a'*64,'--docker-host','unix:///owned','--docker-daemon','d',
      '--cohort',launcher.V03_OPTIMIZE_BROWSER,'--listings-runtime-digest','not-a-digest']
    try: launcher.validate_static(launcher.parse(base))
    except RuntimeError as error: assert str(error)=='Exact V03 Listings runtime digest required'
    else: raise AssertionError('invalid runtime digest admitted')
    other=launcher.parse(['--main-workspace',str(SOURCE.parents[2]),'--node','/node','--docker','/docker',
      '--docker-sha256','a'*64,'--docker-host','unix:///owned','--docker-daemon','d',
      '--cohort','transport','--listings-runtime-digest','b'*64])
    try: launcher.validate_static(other)
    except RuntimeError as error: assert str(error)=='V03 Listings runtime digest is cohort exclusive'
    else: raise AssertionError('cross-cohort runtime digest admitted')

def test_v03_static_admission_checks_exact_sources_before_resources():
    launcher=load_launcher('v03_static_source_admission')
    source=SOURCE.read_text()
    tree=ast.parse(source)
    function=next(node for node in tree.body
      if isinstance(node,ast.FunctionDef) and node.name=='validate_static')
    static='\n'.join(source.splitlines()[function.lineno-1:function.end_lineno])
    assert static.index('validate_v03_source_pins(source)') < static.index('validate_v03_native_receipt(args, source)')
    calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
      and isinstance(node.func,ast.Name) and node.func.id=='validate_v03_source_pins']
    assert len(calls)==2
    exact=dict((name,value) for name,value in [
      (launcher.V03_OPTIMIZE_ASSESSMENT_DIAGNOSTIC,launcher.V03_OPTIMIZE_ASSESSMENT_DIAGNOSTIC_SHA256),
      (launcher.V03_OPTIMIZE_ASSESSMENT_DIAGNOSTIC_CONTROL,launcher.V03_OPTIMIZE_ASSESSMENT_DIAGNOSTIC_CONTROL_SHA256)])
    assert exact=={
      'tests/fixtures/secureshopV03AssessmentDiagnostic.js':'b55efbc7fdde2df6514e9ba515c355e097683b62260ac1ee7020fc4e7d6dcb1b',
      'tests/secureshopV03AssessmentDiagnostic.test.js':'9ce5179a5b057c91ef4953d8b3eba583e605a433e93958afc4a7ec8c9e64aaa0'}

def test_scene_tap_parser_accepts_nested_passes_and_rejects_nested_failures():
    launcher=load_launcher('scene_nested_tap_parser')
    names=list(launcher.SCENE_ASSERTIONS)
    nested='\n'.join(f'    # Subtest: {name}\n    ok {index} - {name}'
      for index,name in enumerate(names[1:],1))
    valid=(f'TAP version 13\n{nested}\n# Subtest: {names[0]}\n'
      f'ok 1 - {names[0]}\n1..1\n# tests 6\n# suites 0\n# pass 6\n'
      '# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n')
    assert launcher.complete_tap_counts(valid,'scene',names)=={
      'tests':6,'pass':6,'fail':0,'skipped':0,'cancelled':0}
    for invalid in (
      valid.replace(f'    ok 1 - {names[1]}',f'    not ok 1 - {names[1]}'),
      valid.replace('# skipped 0','# skipped 1'),
      valid.replace(f'    # Subtest: {names[1]}',f'    # Subtest: missing {names[1]}')):
        try: launcher.complete_tap_counts(invalid,'scene',names)
        except RuntimeError as error: assert str(error)=='scene native effect assertion missing or skipped'
        else: raise AssertionError('invalid nested scene TAP admitted')

def test_v03_finalizer_shape_is_accepted_by_actual_outer_receipt_consumer(tmp_path):
    launcher = load_launcher('v03_final_receipt_outer_consumer')
    original = tmp_path / 'original.json'
    original.write_text('{"version":1}\n')
    original.chmod(0o600)
    digest = __import__('hashlib').sha256(original.read_bytes()).hexdigest()
    hashes = {
        'sourceManifestSha256': 'a' * 64,
        'frontendInventorySha256': 'b' * 64,
        'browserSha256': 'c' * 64,
        'modelManifestSha256': 'd' * 64,
        'nativeReceiptSha256': 'e' * 64,
        'originalEvidenceSha256': digest,
    }
    ids = ['00000000-0000-4000-8000-000000000001',
           '00000000-0000-4000-8000-000000000002',
           '00000000-0000-4000-8000-000000000003']
    receipt = {
        **{flag: True for flag in launcher.V03_OPTIMIZE_FLAGS},
        'scope': launcher.V03_OPTIMIZE_SCOPE,
        'model': launcher.OLLAMA_MODEL,
        'targets': {phase: {'targetId': target_id,
            'hostname': 'system-diag-' + target_id.replace('-', '')}
            for phase, target_id in zip(('vulnerable', 'benign', 'fixed'), ids)},
        'errors': [],
        'logicalActorTurns': 9,
        'actorProviderSpans': 19,
        'actorCorrectiveSpans': 1,
        'actorWireAttempts': 19,
        'actorWireCeiling': 27,
        'qualifiedSelections': 6,
        'logicalJudgeCalls': 1,
        'judgeProviderSpans': 1,
        'diagnosticDispatches': 2,
        'genuineCredit': 1,
        **hashes,
    }
    target = tmp_path / 'receipt.json'
    target.write_text(json.dumps(receipt))
    target.chmod(0o600)
    assert launcher.v03_optimize_browser_receipt(target, original, hashes) == receipt
    receipt['fixtureLocalCandidateAdmission'] = False
    target.write_text(json.dumps(receipt))
    assert launcher.v03_optimize_browser_receipt(target, original, hashes) == receipt
    for invalid in ({**receipt, 'fixtureLocalCandidateAdmission': 'false'},
                    {key: value for key, value in receipt.items() if key != 'fixtureLocalCandidateAdmission'},
                    {**receipt, 'canonicalJudgeCredit': False}):
        target.write_text(json.dumps(invalid))
        try:
            launcher.v03_optimize_browser_receipt(target, original, hashes)
        except RuntimeError:
            pass
        else:
            raise AssertionError('outer consumer admitted invalid candidate or acceptance flags')
    receipt['scope'] += ' drift'
    target.write_text(json.dumps(receipt))
    target.chmod(0o600)
    try:
        launcher.v03_optimize_browser_receipt(target, original, hashes)
    except RuntimeError as error:
        assert str(error) == 'Complete V03 actual browser/Judge assertion required'
    else:
        raise AssertionError('outer consumer admitted a different V03 scope')
