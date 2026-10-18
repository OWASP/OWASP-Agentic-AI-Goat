"""Resource-free controls for the V03 actual browser launcher."""
import ast
import importlib.util
import json
import signal
import subprocess
import sys
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
    assert value['V01_AUDIT_TEST_SHA256'] == '86b869c86f2ab7cd06c7508ae113f2888ddff49a2d2b7f64832381781d2c7262'
    assert value['V06_UPLOAD_BROWSER'] == 'customer-avatar-upload-v06-browser'
    assert source.count('validate_v06_upload_pins(source, digest)') == 1
    assert source.count('validate_v06_upload_pins(source,digest)') == 1
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
