#!/usr/bin/env python3
"""Original V27 policy output with scoped browser admission only."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'standalone-ssrf-rendered-browser'
TEST = 'tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
LIFECYCLE = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
ADMISSION = 'tests/fixtures/secureshopPolicyOutputBrowserAdmission.js'
CONTRACT = 'tests/secureshopPolicyOutputBrowserAdmission.test.js'
CONTRACT_MODULE = 'tests/postgres/secureshop_standalone_ssrf_launcher_contract.py'
CALLER = 'tests/secureshopStandaloneSsrfRenderedCaller.test.js'
PINS = {
    'tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js': 'c91c4f989e9c9c2d19208e91250ef99b55a7598ed669c4a06931e37734528d81',
    'tests/postgres/run-secureshop-agent-host-transport-main.py': 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    'tests/postgres/run-secureshop-idor-lesson-browser.py': 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    'tests/postgres/run-secureshop-audit-collection-browser.py': '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    'tests/fixtures/secureshopPolicyOutputBrowserAdmission.js': 'b1d305776f691ab6d36381f92e4acf861a10f5f7a968b585553f9378744a520b',
    'tests/secureshopPolicyOutputBrowserAdmission.test.js': '37371f54e42dbbc8672c5229e171f03fd0b8e0d04a97b4fbf394c3304f05fbec',
    'tests/postgres/secureshop_standalone_ssrf_launcher_contract.py': '72fb7f659ab9c56e092e0db46c665004330f87e0927c8889b2230f95cd2aaac9',
    'tests/secureshopStandaloneSsrfRenderedCaller.test.js': 'b3b7d31885facce6f9c30c0992be19c4f34b61bbaaa88a3c7138a475844e4c41',
}
CONTROL_SOURCES = (
    'tests/postgres/run-secureshop-policy-output-browser.py',
    'tests/postgres/run_policy_output_with_inspector.py',
    'tests/postgres/test_secureshop_policy_output_browser_admission.py',
    'tests/postgres/test_secureshop_standalone_ssrf_launcher_contract.py',
    'tests/postgres/test_secureshop_standalone_ssrf_shared_launcher_contract.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_chrome_singleton_owner.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tests/fixtures/secureshopAnalyticsBrowserOwner.js',
    'tests/fixtures/browserProcessOwnership.js',
    'tasks/run-in-repository.sh',
)
RECORD, ACK = 'policy-output-browser.json', 'policy-output-browser-ack.json'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def inventory():
    return {name: digest(ROOT / name) for name in (*PINS, *CONTROL_SOURCES)}


def validate_pins():
    for name, pin in PINS.items():
        value = ROOT / name
        if value.is_symlink() or value.resolve() != value or digest(value) != pin:
            raise RuntimeError(f'Policy output frozen source mismatch: {name}')


def arguments(argv):
    values = list(argv)
    if values.count('--policy-output-test-no-sandbox') != 1 \
            or values.count('--policy-output-browser') != 1 or values.count('--cohort') != 1:
        raise RuntimeError('Explicit original combined policy output selection required')
    values.remove('--policy-output-test-no-sandbox')
    index = values.index('--cohort')
    if index + 1 == len(values) or values[index + 1] != COHORT:
        raise RuntimeError('Only original full policy output cohort admitted')
    return values


def owned_environment(environment, parsed):
    env = dict(environment)
    if env.get('SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE') != '1' \
            or env.get('SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE') != '1':
        raise RuntimeError('Combined policy output native environment required')
    receipt = Path(env['SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH'])
    evidence = receipt.parent
    if evidence.name != 'standalone-ssrf-rendered' or evidence.parent.parent != ROOT / 'tasks/qualification' \
            or not evidence.parent.name.startswith('run-') or receipt.name != 'result.json' \
            or env.get('SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE') != '1':
        raise RuntimeError('Exact owned policy output receipt required')
    env.update(SECURESHOP_POLICY_OUTPUT_TEST_NO_SANDBOX='1',
        SECURESHOP_POLICY_OUTPUT_BROWSER_RECORD_PATH=str(evidence / RECORD),
        SECURESHOP_POLICY_OUTPUT_BROWSER_ACK_PATH=str(evidence / ACK),
        SECURESHOP_POLICY_OUTPUT_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()))
    return env, evidence


def lifecycle():
    watcher = load(LIFECYCLE, 'policy_owned_browser_watcher')
    watcher.TEST, watcher.RECORD, watcher.ACK = TEST, RECORD, ACK
    watcher.KIND = 'policy_output_browser'
    watcher.owned_environment = owned_environment
    ownership = load(OWNERSHIP, 'policy_owned_browser_capture')
    ownership.capture_live_v36 = lambda record, birth, runtime, **kwargs: capture_live_policy(
        record, birth, runtime, ownership=ownership, **kwargs)
    singleton = load('tests/postgres/secureshop_chrome_singleton_owner.py', 'policy_singleton_owner')
    original_capture, original_retire = ownership.capture_live_v36, ownership.retire_live_v36
    def capture(record, birth, runtime, **kwargs):
        value = original_capture(record, birth, runtime, **kwargs)
        value.singleton = singleton.capture(value.profile, Path(runtime).parent.parent / 'runtime/tmp')
        return value
    def capture_with_deadline(record, birth, runtime, *, deadline, stop, **kwargs):
        value, proof = singleton.capture_until(Path(runtime) / 'browser-profile',
            Path(runtime).parent.parent / 'runtime/tmp',
            lambda: original_capture(record, birth, runtime, **kwargs), deadline, stop)
        value.singleton = proof
        return value
    def retire(value, **kwargs):
        if not hasattr(value, 'singleton'):
            raise RuntimeError('Policy browser singleton live capture missing')
        result = original_retire(value, **kwargs)
        singleton.retire(value.singleton, value.record, kwargs['api'])
        return result
    ownership.capture_live_v36, ownership.retire_live_v36 = capture, retire
    ownership.capture_live_v36_with_deadline = capture_with_deadline
    return watcher, ownership


def capture_live_policy(record, parent_birth, runtime, *, api, ownership, getsid=os.getsid):
    """Exact same-group V27 capture; never grants a detached-group kill authority."""
    _, zombie, _, _, _ = ownership._browser_modules()
    if record['pgid'] != record['parentPid'] or record['sessionId'] != record['parentPid']:
        raise RuntimeError('Policy browser must remain in the direct Node group')
    def parent():
        value = api.identity(record['parentPid'])
        if value is None or (value.start_sec, value.start_usec) != parent_birth \
                or value.uid != os.getuid() or value.ruid != os.getuid() \
                or value.pgid != record['parentPid'] or value.status == zombie:
            raise RuntimeError('Policy direct Node birth unavailable')
    fields = lambda value: (value.pid, value.ppid, value.uid, value.ruid,
                           value.pgid, value.start_sec, value.start_usec)
    expected = (record['pid'], record['parentPid'], os.getuid(), os.getuid(),
                record['pgid'], *record['birth'])
    parent()
    first = api.identity(record['pid'])
    if first is None or fields(first) != expected or first.status == zombie \
            or getsid(first.pid) != record['sessionId']:
        raise RuntimeError('Policy browser live birth mismatch')
    argv = api.arguments(first.pid)
    profiles = [item.split('=', 1)[1] for item in argv if item.startswith('--user-data-dir=')]
    profile = str(Path(runtime) / 'browser-profile')
    if not argv or argv[0] != record['executablePath'] or profiles != [profile]:
        raise RuntimeError('Policy browser executable or exact profile mismatch')
    second = api.identity(first.pid)
    parent()
    if second is None or fields(second) != expected or second.status == zombie:
        raise RuntimeError('Policy browser changed during capture')
    return ownership.CapturedV36(record, profile, ownership._CAPTURE_KEY)


def verify_retirement(owner, ownership):
    profile = Path(owner.captured.profile)
    if profile != owner.evidence / 'runtime/browser-profile':
        raise RuntimeError('Policy output captured profile ownership mismatch')
    _, _, _, _, absent = ownership._browser_modules()
    owner.retired = absent([owner.captured.record])
    if profile.exists() or profile.is_symlink():
        raise RuntimeError('Policy output owned browser profile remains')


def run(shared, argv, parsed, before):
    watcher, ownership = lifecycle()
    original = shared.subprocess.Popen
    owner = watcher.BrowserOwner(original, parsed, ownership)
    shared.subprocess.Popen = owner
    output, primary, result = io.StringIO(), None, None
    try:
        with contextlib.redirect_stdout(output):
            code = shared.main(argv)
        result = json.loads([line for line in output.getvalue().splitlines() if line.strip()][-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('Original policy output qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('Policy output live browser capture incomplete') from owner.error
        verify_retirement(owner, ownership)
        # The original policy-output branch checks these before execution; retain
        # explicit after checks too, independent of source inventory coverage.
        if digest(parsed.browser) != parsed.browser_sha256 \
                or not shared.node_pin_matches(parsed.node, shared.effective_node_sha256(parsed)):
            raise RuntimeError('Pinned policy output browser or Node changed')
        if inventory() != before:
            raise RuntimeError('Policy output source changed')
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        shared.subprocess.Popen = original
        retirement_error = None
        profile_absent = None
        if owner.captured is not None:
            try:
                verify_retirement(owner, ownership)
                profile_absent = True
            except BaseException as error:
                retirement_error = error
                profile_absent = False
        try:
            after = inventory()
            report = {'version': 1, 'cohort': COHORT, 'policyOutput': True,
                'adapterPassed': primary is None and retirement_error is None,
                'sourceBefore': before, 'sourceAfter': after,
                'sourceUnchanged': before == after,
                'mainOutputSha256': hashlib.sha256(output.getvalue().encode()).hexdigest(),
                'browserCaptured': owner.captured is not None, 'browserRetirement': owner.retired,
                'capturedProfileAbsent': profile_absent,
                'retirementCheckFailure': None if retirement_error is None else str(retirement_error)[:1000],
                'failure': None if primary is None else str(primary)[:1000],
                'captureFailure': None if owner.error is None else str(owner.error)[:1000]}
            if owner.evidence is not None:
                target = owner.evidence.parent / 'result.json'
                if target.is_file() and not target.is_symlink():
                    report['mainResult'] = json.loads(target.read_text())
                    report['mainResultSha256'] = digest(target)
                with (owner.evidence / 'policy-output-adapter-report.json').open('x', encoding='utf-8') as handle:
                    os.chmod(handle.name, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('Policy output source changed')
            if primary is None and retirement_error is not None:
                raise retirement_error
            if primary is None:
                print(json.dumps(result))
        except BaseException:
            if primary is None:
                raise


def main(argv=None):
    validate_pins()
    before = inventory()
    values = arguments(sys.argv[1:] if argv is None else argv)
    shared = load(MAIN, 'policy_original_launcher')
    shared.ssrf_owned = load(CONTRACT_MODULE, 'policy_independent_original_contract')
    if shared.ssrf_owned.TEST != TEST:
        raise RuntimeError('Original policy output source selection changed')
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256 or not parsed.policy_output_browser:
        raise RuntimeError('Pinned original current-main policy browser required')
    shared.ssrf_owned.TEST_SHA256 = PINS[TEST]
    shared.ssrf_owned.CALLER_TEST_SHA256 = PINS[CALLER]
    shared.ssrf_owned.POLICY_PINNED = (*shared.ssrf_owned.POLICY_PINNED, ADMISSION)
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': COHORT, 'policyOutput': True, 'test': TEST,
            'nativeStarted': False, 'sourceCopy': False, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('Policy output live capture requires Darwin')
    return run(shared, values, parsed, before)


if __name__ == '__main__':
    raise SystemExit(main())

