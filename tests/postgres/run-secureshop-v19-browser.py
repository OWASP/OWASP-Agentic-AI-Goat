#!/usr/bin/env python3
"""Full original V19 only; test-scoped browser exception and owned cleanup."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'customer-file-summary-v19-browser'
TEST = 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
LIFECYCLE = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
ADMISSION = 'tests/fixtures/secureshopV19BrowserAdmission.js'
CONTRACT = 'tests/secureshopV19BrowserAdmission.test.js'
INTEGRATION_CONTRACT = 'tests/secureshopV19BrowserIntegration.test.js'
TRANSPORT = 'tests/postgres/secureshopMailActualTransport.js'
TRANSPORT_TEST = 'tests/secureshopMailActualTransportV19Budget.test.js'
LAUNCHER_TEST = 'tests/postgres/test_secureshop_v19_file_summary_browser_launcher.py'
COHORT_HELPER = 'tests/fixtures/secureshopV19RenderedCohort.js'
PATH_HELPER = 'tests/fixtures/secureshopV19RepositoryPaths.js'
PATH_CONTRACT = 'tests/secureshopV19RepositoryPaths.test.js'
CAPTURE_HELPER = 'tests/fixtures/secureshopFileSummaryRenderedQualification.js'
CAPTURE_CONTRACT = 'tests/secureshopFileSummaryRenderedQualification.test.js'
PINS = {
    CAPTURE_HELPER: 'b1a45ec065b2167945f1f43fbe202a767d1008a910e38d4fd1ce4187a5a7709f',
    CAPTURE_CONTRACT: 'a2c2a1896df56e54fbada451ba6296e2947584b7004f2239e217af0e7979d4f0',
    COHORT_HELPER: '60a85901e7ece9178cbedbc638b7e703c2c9c90edf170f49c307302833dd0b01',
    PATH_HELPER: '56777ce872ce5c51196e61783744c2a58cfeadf9652f8cb411071bef9bc2ff4c',
    PATH_CONTRACT: 'bbb412e58bf28b3a2f6436ea567894fb5b95842b0aa3b56fe65368d6ef21346f',
    TEST: '879f06e727c5ec59b80bf75339f2afd814694e91fd6f0331689e42eea3b72c52',
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    LIFECYCLE: 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    ADMISSION: '588b595548d5c4da3bbca3ab063b716f955e61890a0e08713f9ae9ff98a2f8fd',
    CONTRACT: 'da814897335805283f6a49dd6dcbf00100d6d51a186750a0324cf8a46e21c7e7',
    INTEGRATION_CONTRACT: 'ea8d4ecd0fbbfcf91b4e45fae6d0eb484850d52c3957be1b4f8aba51b02c3cbe',
    TRANSPORT: 'ee032d973c55be5474227f5cdf6ec712e015d8ff10aa7fdaaf89c7a998dd8ce4',
    TRANSPORT_TEST: '6a14c2b484b5f9dff93576745eecf7d15448541dc40f66769d71682b6e06577a',
    LAUNCHER_TEST: '6f0bd6ee35120443d11377d4af4f87355ba37c469a8a1db7613e9de6c5b4f97f',
}
CONTROL_SOURCES = (
    'tests/postgres/run-secureshop-v19-browser.py',
    'tests/postgres/run_v19_with_inspector.py',
    'tests/postgres/test_secureshop_v19_browser_admission.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tasks/run-in-repository.sh',
)
RECORD, ACK = 'v19-browser.json', 'v19-browser-ack.json'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def inventory():
    return {name: digest(ROOT / name) for name in (*PINS, *CONTROL_SOURCES)}


def validate_pins():
    for name, pin in PINS.items():
        value = ROOT / name
        if value.is_symlink() or value.resolve() != value or digest(value) != pin:
            raise RuntimeError(f'V19 frozen source mismatch: {name}')


def arguments(argv):
    values = list(argv)
    if values.count('--v19-test-no-sandbox') != 1 or any(
            value.startswith('--v19-graph-diagnostic') for value in values):
        raise RuntimeError('Explicit full V19 browser exception; diagnostic denied')
    values.remove('--v19-test-no-sandbox')
    if values.count('--cohort') != 1:
        raise RuntimeError('Exact full V19 cohort required')
    index = values.index('--cohort')
    if index + 1 == len(values) or values[index + 1] != COHORT:
        raise RuntimeError('Only original full V19 cohort admitted')
    return values


def owned_environment(environment, parsed):
    env = dict(environment)
    if env.get('SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE') != '1' \
            or env.get('SECURESHOP_V19_FILE_SUMMARY_DIAGNOSTIC_NATIVE') not in (None, '0'):
        raise RuntimeError('Full V19 environment required')
    evidence = Path(env['SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH']).parent
    if evidence.parent != ROOT / 'tasks/qualification' or not evidence.name.startswith('run-'):
        raise RuntimeError('V19 owned evidence required')
    env.update(SECURESHOP_V19_TEST_NO_SANDBOX='1',
        SECURESHOP_V19_BROWSER_RECORD_PATH=str(evidence / RECORD),
        SECURESHOP_V19_BROWSER_ACK_PATH=str(evidence / ACK),
        SECURESHOP_V19_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()))
    return env, evidence


def lifecycle():
    # Separate instances: neither original V12 nor V36 selection is modified.
    watcher = load(LIFECYCLE, 'v19_owned_browser_watcher')
    watcher.TEST, watcher.RECORD, watcher.ACK = TEST, RECORD, ACK
    watcher.KIND = 'v19_file_summary_browser'
    watcher.owned_environment = owned_environment
    ownership = load(OWNERSHIP, 'v19_owned_browser_capture')
    ownership.PROFILE_PREFIX = 'dvaia-v19-browser-'
    return watcher, ownership


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
            raise RuntimeError('Original V19 qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('V19 live capture incomplete') from owner.error
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
        if inventory() != before:
            raise RuntimeError('V19 source changed')
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        shared.subprocess.Popen = original
        try:
            after = inventory()
            report = {'version': 1, 'cohort': COHORT, 'adapterPassed': primary is None,
                'sourceBefore': before, 'sourceAfter': after, 'sourceUnchanged': before == after,
                'mainOutputSha256': hashlib.sha256(output.getvalue().encode()).hexdigest(),
                'browserCaptured': owner.captured is not None, 'browserRetirement': owner.retired,
                'failure': None if primary is None else str(primary)[:1000],
                'captureFailure': None if owner.error is None else str(owner.error)[:1000]}
            if owner.evidence is not None:
                target = owner.evidence / 'result.json'
                if target.is_file() and not target.is_symlink():
                    report['mainResult'] = json.loads(target.read_text())
                    report['mainResultSha256'] = digest(target)
                with (owner.evidence / 'v19-adapter-report.json').open('x', encoding='utf-8') as handle:
                    os.chmod(handle.name, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('V19 source changed')
            if primary is None:
                print(json.dumps(result))
        except BaseException:
            if primary is None:
                raise


def configure_shared(shared):
    if shared.V19_SUMMARY_BROWSER != COHORT or shared.V19_SUMMARY_TEST != TEST \
            or shared.V19_SUMMARY_LIMITS != {'cases': 5, 'maximumActorCalls': 10,
                'canonicalAssessmentInvocations': 4, 'maximumJudgeCalls': 16,
                'maximumModelCalls': 26, 'fixedJudgeCalls': 0, 'postRetries': 0}:
        raise RuntimeError('Original V19 scope or limits changed')
    # Only these reviewed source pins differ from original admission.
    shared.V19_SUMMARY_PINS = dict(shared.V19_SUMMARY_PINS)
    for name in (TEST, TRANSPORT, TRANSPORT_TEST, LAUNCHER_TEST, COHORT_HELPER,
                 CAPTURE_HELPER, CAPTURE_CONTRACT):
        if name not in shared.V19_SUMMARY_PINS:
            raise RuntimeError('Original V19 source inventory changed')
        shared.V19_SUMMARY_PINS[name] = PINS[name]
    return shared


def main(argv=None):
    validate_pins()
    before = inventory()
    values = arguments(sys.argv[1:] if argv is None else argv)
    shared = configure_shared(load(MAIN, 'v19_original_launcher'))
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256 or parsed.v19_graph_diagnostic:
        raise RuntimeError('V19 pinned full current-main browser admission required')
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': COHORT, 'test': TEST, 'nativeStarted': False,
            'sourceCopy': False, 'fullFiveCases': True, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('V19 live capture requires Darwin')
    return run(shared, values, parsed, before)


if __name__ == '__main__':
    raise SystemExit(main())
