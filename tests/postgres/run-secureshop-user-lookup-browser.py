#!/usr/bin/env python3
"""Original V21/V22 combined disclosure with scoped browser admission only."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'admin-user-chat-browser'
TEST = 'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
LIFECYCLE = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
ADMISSION = 'tests/fixtures/secureshopUserLookupBrowserAdmission.js'
CONTRACT = 'tests/secureshopUserLookupBrowserAdmission.test.js'
PINS = {
    TEST: '450d9c441d4b387a0f374faf227bc450803b2bfc67dfc57c9975e57e0e8fc11e',
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    LIFECYCLE: 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    ADMISSION: '8c5c7b61f9f0ef0593582de8141b13c214a4d8a1961262ac69122558a19185fd',
    CONTRACT: 'f4c45473c5a1654cfd183db185e9c24a598eef62b01ef5d0aa1d8cb8cba9fcd5',
    'tests/fixtures/secureshopEnabledUsersBrowser.js': '9825ace48e8948389abac251d9a29275280247460efa6bcb287973a342216f0e',
    'tests/postgres/secureshopAdminReadReceiptContract.test.js': '3e51a2b99c6143f091773976e45c94ff258d616cedffb324aed73ef44176a674',
    'tests/secureshopUserLookupRenderedIntegrationAdmission.test.js': '91febccd088abbebfb8f7d5349af29f9b85c756c70e3ec93c869f2d8374c1159',
}
CONTROL_SOURCES = (
    'tests/postgres/run-secureshop-user-lookup-browser.py',
    'tests/postgres/run_user_lookup_with_inspector.py',
    'tests/postgres/test_secureshop_user_lookup_browser_admission.py',
    'tests/postgres/test_secureshop_role_choices_launcher.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tasks/run-in-repository.sh',
    'tests/fixtures/secureshopUserLookupBenignCapture.js',
    'tests/secureshopUserLookupBenignCapture.test.js',
)
RECORD, ACK = 'user-lookup-browser.json', 'user-lookup-browser-ack.json'


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
            raise RuntimeError(f'User lookup frozen source mismatch: {name}')


def arguments(argv):
    values = list(argv)
    if values.count('--user-lookup-benign-capture') > 1:
        raise RuntimeError('Duplicate benign capture selection')
    if values.count('--user-lookup-test-no-sandbox') != 1 \
            or values.count('--user-lookup-disclosure') != 1 or values.count('--cohort') != 1:
        raise RuntimeError('Explicit original combined user lookup selection required')
    values.remove('--user-lookup-test-no-sandbox')
    index = values.index('--cohort')
    if index + 1 == len(values) or values[index + 1] != COHORT:
        raise RuntimeError('Only original administrator user lookup cohort admitted')
    return values


def owned_environment(environment, parsed):
    env = dict(environment)
    if env.get('SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE') != '1' \
            or env.get('SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE') != '1':
        raise RuntimeError('Combined user lookup native environment required')
    receipt = Path(env['SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH'])
    evidence = receipt.parent
    benign = getattr(parsed, 'user_lookup_benign_capture', False)
    if env.get('SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE', '0') != ('1' if benign else '0'):
        raise RuntimeError('Benign capture environment must match explicit selection')
    if evidence.parent != ROOT / 'tasks/qualification' or not evidence.name.startswith('run-') \
            or receipt.name != ('user-lookup-benign-browser.json' if benign else 'user-lookup-disclosure-browser.json'):
        raise RuntimeError('Exact owned user lookup receipt required')
    env.update(SECURESHOP_USER_LOOKUP_TEST_NO_SANDBOX='1',
        SECURESHOP_USER_LOOKUP_BROWSER_RECORD_PATH=str(evidence / RECORD),
        SECURESHOP_USER_LOOKUP_BROWSER_ACK_PATH=str(evidence / ACK),
        SECURESHOP_USER_LOOKUP_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()))
    return env, evidence


def lifecycle():
    watcher = load(LIFECYCLE, 'lookup_owned_browser_watcher')
    watcher.TEST, watcher.RECORD, watcher.ACK = TEST, RECORD, ACK
    watcher.KIND = 'user_lookup_disclosure_browser'
    watcher.owned_environment = owned_environment
    ownership = load(OWNERSHIP, 'lookup_owned_browser_capture')
    ownership.PROFILE_PREFIX = 'dvaia-user-lookup-browser-'
    return watcher, ownership


def verify_retirement(owner, ownership):
    profile = Path(owner.captured.profile)
    if profile.parent != owner.evidence / 'runtime/tmp' \
            or not profile.name.startswith('dvaia-user-lookup-browser-'):
        raise RuntimeError('User lookup captured profile ownership mismatch')
    _, _, _, _, absent = ownership._browser_modules()
    owner.retired = absent([owner.captured.record])
    if profile.exists() or profile.is_symlink():
        raise RuntimeError('User lookup owned browser profile remains')


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
            raise RuntimeError('Original user lookup qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('User lookup live browser capture incomplete') from owner.error
        verify_retirement(owner, ownership)
        # The original user-lookup branch checks these before execution; retain
        # explicit after checks too, independent of source inventory coverage.
        if digest(parsed.browser) != parsed.browser_sha256 \
                or not shared.node_pin_matches(parsed.node, shared.effective_node_sha256(parsed)):
            raise RuntimeError('Pinned user lookup browser or Node changed')
        if inventory() != before:
            raise RuntimeError('User lookup source changed')
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
            report = {'version': 1, 'cohort': COHORT, 'userLookupDisclosure': True,
                'actorNegativeCapture': getattr(parsed, 'user_lookup_benign_capture', False),
                'independentJudgeCalibration': False,
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
                target = owner.evidence / 'result.json'
                if target.is_file() and not target.is_symlink():
                    report['mainResult'] = json.loads(target.read_text())
                    report['mainResultSha256'] = digest(target)
                with (owner.evidence / 'user-lookup-adapter-report.json').open('x', encoding='utf-8') as handle:
                    os.chmod(handle.name, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('User lookup source changed')
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
    shared = load(MAIN, 'lookup_original_launcher')
    if shared.ADMIN_USER_CHAT_TEST != TEST:
        raise RuntimeError('Original user lookup source selection changed')
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256 or not parsed.user_lookup_disclosure:
        raise RuntimeError('Pinned original current-main lookup browser required')
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': COHORT, 'userLookupDisclosure': True, 'test': TEST,
            'actorNegativeCapture': getattr(parsed, 'user_lookup_benign_capture', False),
            'independentJudgeCalibration': False,
            'nativeStarted': False, 'sourceCopy': False, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('User lookup live capture requires Darwin')
    return run(shared, values, parsed, before)


if __name__ == '__main__':
    raise SystemExit(main())
