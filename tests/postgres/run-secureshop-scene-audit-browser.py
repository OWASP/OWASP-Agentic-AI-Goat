#!/usr/bin/env python3
"""Closed V15 admission; original scene Audit provisioning and semantics."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'scene-audit-v15-browser'
TEST = 'tests/postgres/secureshopAdminAuditJobsRendered.integration.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
LIFECYCLE = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
HELPER = 'tests/fixtures/secureshopSceneAuditRenderedQualification.js'
CONTRACT = 'tests/secureshopSceneAuditRenderedQualification.test.js'
ADMISSION = 'tests/fixtures/secureshopSceneAuditBrowserAdmission.js'
ADMISSION_TEST = 'tests/secureshopSceneAuditBrowserAdmission.test.js'
PINS = {
    TEST: 'dd1fe9491021fe751e390183227e4ae29aa6a435b5ac8ffb8377f64f28c549c1',
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    LIFECYCLE: 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    HELPER: '97f7f071385fd97de02003a8263f48bc7a68413d24ea6ac96321ee4b9b06c2d8',
    CONTRACT: '5fd0cd9bbb75eeea722918d1d1b13501c372b1fc7c75f45f9528a603978336b7',
    ADMISSION: '68f07b7a2c88e1222eac5e891f23fb913fc59657ddb1493016540c09a000e2e8',
    ADMISSION_TEST: '709d5900baaba870a58134354083d1ffa9321ee7106e1ddd53763edc5d9d1abe',
}
CONTROL_SOURCES = (
    'tests/postgres/run-secureshop-scene-audit-browser.py',
    'tests/postgres/run_scene_audit_with_inspector.py',
    'tests/postgres/test_secureshop_scene_audit_browser_admission.py',
    'tests/postgres/run_idor_lesson_with_inspector.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tasks/run-in-repository.sh',
)
RECORD = 'scene-audit-v15-browser-birth.json'
ACK = 'scene-audit-v15-browser-ack.json'
PROFILE = 'dvaia-scene-audit-v15-'


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
            raise RuntimeError(f'V15 frozen source mismatch: {name}')
    for name in CONTROL_SOURCES:
        value = ROOT / name
        if value.is_symlink() or not value.is_file() or value.resolve() != value:
            raise RuntimeError(f'V15 control source unavailable: {name}')


def arguments(argv):
    values = list(argv)
    if values.count('--v15-test-no-sandbox') != 1:
        raise RuntimeError('Exactly one V15 browser exception required')
    values.remove('--v15-test-no-sandbox')
    if values.count('--cohort') != 1:
        raise RuntimeError('Exact V15 cohort required')
    index = values.index('--cohort')
    if index + 1 == len(values) or values[index + 1] != COHORT:
        raise RuntimeError('Only original V15 scene Audit cohort is admitted')
    return values


def owned_environment(environment, parsed):
    env = dict(environment)
    if env.get('SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE') != '1' \
            or any(env.get(key) not in (None, '0') for key in (
                'SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE',
                'SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE',
                'SECURESHOP_AUDIT_TIMING_BROWSER_NATIVE')):
        raise RuntimeError('Original isolated V15 environment required')
    evidence = Path(env['SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH']).parent
    if evidence.parent != ROOT / 'tasks/qualification' or not evidence.name.startswith('run-'):
        raise RuntimeError('V15 owned evidence required')
    env.update(
        SECURESHOP_SCENE_AUDIT_TEST_NO_SANDBOX='1',
        SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH=str(evidence / RECORD),
        SECURESHOP_SCENE_AUDIT_BROWSER_ACK_PATH=str(evidence / ACK),
        SECURESHOP_SCENE_AUDIT_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()),
    )
    return env, evidence


def lifecycle():
    # Independent imported instances: V12/V36 defaults remain unchanged.
    module = load(LIFECYCLE, 'v15_owned_browser_watcher')
    module.TEST, module.RECORD, module.ACK = TEST, RECORD, ACK
    module.KIND = 'scene_audit_v15_browser'
    module.owned_environment = owned_environment
    ownership = load(OWNERSHIP, 'v15_owned_browser_capture')
    ownership.PROFILE_PREFIX = PROFILE
    return module, ownership


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
            raise RuntimeError('Original V15 qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('V15 live browser capture incomplete') from owner.error
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
        if inventory() != before:
            raise RuntimeError('V15 source changed')
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
                original_result = owner.evidence / 'result.json'
                if original_result.is_file() and not original_result.is_symlink():
                    report['mainResult'] = json.loads(original_result.read_text())
                    report['mainResultSha256'] = digest(original_result)
                with (owner.evidence / 'v15-adapter-report.json').open('x', encoding='utf-8') as handle:
                    os.chmod(handle.name, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('V15 source changed')
            if primary is None:
                print(json.dumps(result))
        except BaseException:
            if primary is None:
                raise


def main(argv=None):
    validate_pins()
    before = inventory()
    values = arguments(sys.argv[1:] if argv is None else argv)
    shared = load(MAIN, 'v15_original_scene_audit_launcher')
    if shared.SCENE_AUDIT_BROWSER != COHORT or shared.ADMIN_AUDIT_JOBS_TEST != TEST:
        raise RuntimeError('V15 original shared selection changed')
    # No default shared admission or another cohort's source pins are changed.
    shared.SCENE_AUDIT_TEST_SHA256 = PINS[TEST]
    shared.SCENE_AUDIT_HELPER_SHA256 = PINS[HELPER]
    shared.SCENE_AUDIT_CONTRACT_SHA256 = PINS[CONTRACT]
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256:
        raise RuntimeError('V15 pinned current-main browser profile required')
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': COHORT, 'test': TEST, 'nativeStarted': False,
                          'sourceCopy': False, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('V15 live capture requires Darwin')
    return run(shared, values, parsed, before)


if __name__ == '__main__':
    raise SystemExit(main())
