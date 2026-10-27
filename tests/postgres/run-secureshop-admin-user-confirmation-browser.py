#!/usr/bin/env python3
"""Closed actual-model admin-user-confirmation admission; no new scenario or production policy."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys

import admin_q05_current_host as safety
import run_admin_user_confirmation_with_inspector as outer
from trusted_process_inspector import consume_environment

ROOT = Path(__file__).resolve().parents[2]
COHORT = outer.COHORT
TEST = 'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopAdminUserConfirmationBrowserAdmission.js'
CONTRACT = 'tests/secureshopAdminUserConfirmationBrowserAdmission.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
REUSE = 'tests/postgres/run-secureshop-standalone-commerce-browser.py'
OWNER = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
RECORD = 'admin-user-confirmation-browser-birth.json'
ACK = 'admin-user-confirmation-browser-ack.json'
KIND = 'admin_user_confirmation_browser'
PROFILE = 'dvaia-role-admin-user-'
PREFIX = 'SECURESHOP_ADMIN_USER_CONFIRMATION_'
EVIDENCE_ENV = 'SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH'
NATIVE_ENV = 'SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE'
FD_ENV = PREFIX + 'ADMISSION_FD'
RECEIPT = 'admin-user-chat-browser.json'
OUTER = 'tests/postgres/run_admin_user_confirmation_with_inspector.py'
TITLE = 'standalone administrator changes and bans a selected registered user through real local llama3.1:8b and trusted confirmation'
LIMITS = dict(fixtureSeconds=600, launcherSeconds=600, providerSeconds=60,
              maximumPhysicalActorCalls=20, roleTurns=4, judgeCalls=0,
              databaseCount=4, roleCount=8)
# Exact independently reviewed/frozen source, including the original validator.
PINS = {
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    REUSE: '3d389725e04539e85b6e17bd0c285e1255a7074d93ddd2f471a408169f5e0090',
    OWNER: 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    'tests/postgres/admin_q05_current_host.py': '30775a6b28f3834216bd8d7e3c42b82bb78d55e3e0afd5ee79f2323fa2174e88',
}
RENDERED_PINS = {
    TEST: '450d9c441d4b387a0f374faf227bc450803b2bfc67dfc57c9975e57e0e8fc11e',
    HELPER: '81fe3006df68ab3d9decee540a436ae9741e7a7aef2f501dba7bff29d5ad2995',
    CONTRACT: '167d1e5bc34705387de033f72188ea600bf829319cd687a1f4b053f07e658093',
    'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
    'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629',
}
CONTROL_SOURCES = (
    outer.ADAPTER, OUTER,
    'tests/postgres/test_secureshop_admin_user_confirmation_browser_admission.py',
    'tests/postgres/run_standalone_commerce_with_inspector.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/admin_q05_current_host.py',
    'tests/postgres/admin_browser_current_main_admission.py',
    'tests/postgres/secureshop_current_host_admission.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tests/fixtures/inheritedFifoGrant.js',
    'tests/postgres/adminQ05RenderedScenario.js',
    'tasks/run-in-repository.sh', 'tasks/repository-only.sb',
    'tasks/q05-current-build-receipt.json',
)


def digest(path):
    return safety.sha(path)


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_pins():
    if not PINS or not {MAIN, REUSE, OWNER, OWNERSHIP} <= PINS.keys() \
            or not RENDERED_PINS or not {TEST, HELPER, CONTRACT} <= RENDERED_PINS.keys():
        raise RuntimeError('Administrator confirmation admission not independently reviewed/pinned')
    for name, expected in {**PINS, **RENDERED_PINS}.items():
        path = ROOT / name
        if path.is_symlink() or path.resolve() != path or digest(path) != expected:
            raise RuntimeError('Frozen admin-user-confirmation source mismatch: ' + name)


def arguments(argv):
    values = list(argv)
    outer.validate_arguments(values if '--plan' in values else ['--run', *values],
                             planning='--plan' in values)
    if '--expected-snapshot-sha256' in values:
        index = values.index('--expected-snapshot-sha256')
        del values[index:index + 2]
    return [value for value in values if value != outer.OPT_IN]


def owned_environment(environment, parsed, before):
    env = dict(environment)
    evidence = Path(env.get(EVIDENCE_ENV, ''))
    run = evidence.parent
    if env.get(NATIVE_ENV) != '1' or env.get('LIVE_OLLAMA_TEST') != '1' \
            or env.get('PG_TEST_DISPOSABLE') != 'yes' or env.get('NODE_ENV') != 'test' \
            or env.get('LAB_MODE') != 'vuln' \
            or evidence.name != RECEIPT or run.parent != ROOT / 'tasks/qualification' \
            or not run.name.startswith('run-') or env.get('TMPDIR') != str(run / 'runtime/tmp') \
            or env.get('DVAIA_CURRENT_MAIN_WORKSPACE') != str(ROOT) \
            or env.get('OLLAMA_BASE_URL') != 'http://127.0.0.1:11434' \
            or env.get('OLLAMA_MODEL') != 'llama3.1:8b' \
            or env.get('PUPPETEER_EXECUTABLE_PATH') != parsed.browser \
            or env.get('SECURESHOP_ADMIN_USER_CHAT_BROWSER_BUILD') != str(ROOT / 'client/build'):
        raise RuntimeError('Exact owned admin-user-confirmation environment required')
    if any(key != NATIVE_ENV and key.startswith('SECURESHOP_') and key.endswith('_NATIVE')
           and value == '1' for key, value in env.items()):
        raise RuntimeError('Administrator confirmation cannot admit another native cohort')
    env.update({
        PREFIX + 'TEST_NO_SANDBOX': '1',
        PREFIX + 'BROWSER_RECORD_PATH': str(run / RECORD),
        PREFIX + 'BROWSER_ACK_PATH': str(run / ACK),
        PREFIX + 'BROWSER_SHA256': parsed.browser_sha256,
        PREFIX + 'SNAPSHOT_SHA256': safety.encoded(before),
        PREFIX + 'BUILD_SHA256': safety.encoded(before['build']),
        'MAC_CHROMIUM_TMPDIR': str(run / 'runtime/tmp'),
        'SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT': str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        'SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON': str(Path(sys.executable).resolve()),
    })
    if env.get('SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE') not in (None, '0'):
        raise RuntimeError('User lookup capture is not administrator confirmation')
    return env, run


def admission_grant(parsed, before, env, pid):
    return dict(version=1, cohort=COHORT, launcherPid=os.getpid(), workerPid=pid,
        nonce=secrets.token_hex(32), workspace=str(ROOT), evidencePath=env[EVIDENCE_ENV],
        buildSha256=safety.encoded(before['build']), snapshotSha256=safety.encoded(before),
        outerSandbox='repository-only', chromium=parsed.browser,
        chromiumSha256=parsed.browser_sha256)


def lifecycle_helpers():
    """Private literal rebinding of tested helpers, never commerce main/run/report."""
    helpers = load(REUSE, 'admin_user_confirmation_private_lifecycle_helpers')
    bindings = dict(COHORT=COHORT, TEST=TEST, HELPER=HELPER, CONTRACT=CONTRACT,
        MAIN=MAIN, OWNER=OWNER, OWNERSHIP=OWNERSHIP, RECORD=RECORD, ACK=ACK,
        KIND=KIND, PROFILE=PROFILE, FD_ENV=FD_ENV, PINS=dict(PINS or {}),
        RENDERED_PINS=dict(RENDERED_PINS or {}), CONTROL_SOURCES=CONTROL_SOURCES,
        owned_environment=owned_environment, admission_grant=admission_grant)
    for name, value in bindings.items():
        setattr(helpers, name, value)
    return helpers


def verify_outer_boundary(argv, client, *, api=None, denied=safety.sandbox_write_denied):
    api = api or safety.LibProc()
    parent = os.getppid()
    row = api.identity(parent)
    if client is None or client.parent != parent or row is None \
            or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Same-user direct admin-user-confirmation coordinator required')
    birth = row.start_sec, row.start_usec
    observed = api.arguments(parent)
    if len(observed) < 4 or observed[0] != str(safety.physical_python(api)) \
            or list(observed[1:3]) != ['-B', str(ROOT / OUTER)] \
            or outer.validate_arguments(list(observed[3:])) != list(argv):
        raise RuntimeError('Exact fixed admin-user-confirmation coordinator invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != birth \
            or after.uid != os.getuid() or after.ruid != os.getuid() \
            or not denied('/private/tmp') or denied(ROOT / 'tasks/qualification'):
        raise RuntimeError('Administrator confirmation parent birth or repository sandbox changed')


def validate_result(shared, result, evidence):
    if (not isinstance(result, dict) or set(result) != {'evidence', 'passed', 'cleanup'}
            or result['evidence'] != str(evidence) or result['passed'] is not True
            or evidence.parent != ROOT / 'tasks/qualification' or not evidence.name.startswith('run-')):
        raise RuntimeError('Exact administrator confirmation terminal required')
    cleanup = result['cleanup']
    if (not isinstance(cleanup, dict) or cleanup.get('errors') != []
            or any(cleanup.get(key) is not True for key in ('containerNameAbsent',
                'containerIdAbsent', 'browserProcessesAbsent', 'browserProfilesAbsent'))):
        raise RuntimeError('Complete administrator confirmation cleanup required')
    receipt_path = evidence / RECEIPT
    receipt = shared.admin_user_chat_receipt(receipt_path)
    path = evidence / 'result.json'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 65536):
            raise RuntimeError('Private bounded administrator result required')
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
        named = os.stat(path, follow_symlinks=False)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if len(raw) != info.st_size or identity(after) != identity(info) or identity(named) != identity(info):
        raise RuntimeError('Stable complete administrator result required')
    durable = json.loads(raw)
    if (durable.get('passed') is not True or durable.get('cohort') != shared.ADMIN_USER_CHAT_COHORT
            or durable.get('sourceCopy') is not False or 'primaryError' not in durable
            or durable['primaryError'] is not None or durable.get('cleanup') != cleanup
            or durable.get('testExitCodes') != {COHORT: 0}
            or type(durable['testExitCodes'][COHORT]) is not int):
        raise RuntimeError('Exact durable administrator confirmation result required')
    if (json.dumps(durable.get('adminUserChatReceipt'), sort_keys=True, allow_nan=False)
            != json.dumps(receipt, sort_keys=True, allow_nan=False)
            or durable.get('adminUserChatReceiptSha256') != digest(receipt_path)):
        raise RuntimeError('Administrator confirmation receipt join required')
    if durable.get('modelPin') != dict(baseURL=shared.OLLAMA_BASE_URL,
            model=shared.OLLAMA_MODEL, sha256=outer.MODEL_SHA256):
        raise RuntimeError('Exact original model pin required')
    return receipt


def run(shared, values, parsed, ownership, before, helpers):
    original = shared.subprocess.Popen
    owner = helpers.browser_owner(original, parsed, ownership, before)
    output = io.StringIO()
    result = None
    primary = None
    receipt = None
    shared.subprocess.Popen = owner
    try:
        with contextlib.redirect_stdout(output):
            code = shared.main(values)
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        result = json.loads(lines[-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('Selected administrator user-confirmation facet did not complete')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('Independent admin-user-confirmation browser capture incomplete') from owner.error
        receipt = validate_result(shared, result, owner.evidence)
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = helpers.exact_profile_retirement(owner.captured.record,
            absent([owner.captured.record]))
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        shared.subprocess.Popen = original
        after = None
        inventory_error = None
        try:
            after = helpers.inventory(shared, parsed)
        except BaseException as error:
            inventory_error = str(error)[:1000]
        report = dict(version=1, cohort=COHORT,
            adapterPassed=primary is None and after == before,
            actualModelCalls=None if receipt is None else receipt['actorCalls'],
            judgeCalls=None if receipt is None else receipt['judgeCalls'],
            roleTurns=None if receipt is None else receipt['roleTurns'],
            limits=LIMITS, canonicalCredit=False, fullQ05Qualification=False,
            fullQ08Qualification=False, sourceBefore=before, sourceAfter=after,
            sourceUnchanged=before == after, inventoryError=inventory_error,
            mainOutputSha256=hashlib.sha256(output.getvalue().encode()).hexdigest(),
            browserCaptured=owner.captured is not None, browserRetirement=owner.retired,
            failure=None if primary is None else str(primary)[:1000],
            captureFailure=None if owner.error is None else str(owner.error)[:1000])
        try:
            if owner.evidence is not None:
                main_result = owner.evidence / 'result.json'
                if main_result.is_file() and not main_result.is_symlink():
                    report.update(mainResultPath=str(main_result),
                                  mainResultSha256=digest(main_result))
                safety.private_json(owner.evidence / 'admin-user-confirmation-adapter-report.json', report)
        except BaseException as error:
            if primary is None:
                raise
            print('Administrator confirmation failure report unavailable: ' + type(error).__name__, file=sys.stderr)
        if primary is None:
            if before != after:
                raise RuntimeError('Administrator confirmation source/build postflight unproved')
            print(json.dumps(result))


def main(argv=None):
    validate_pins()
    supplied = list(sys.argv[1:] if argv is None else argv)
    values = arguments(supplied)
    shared = load(MAIN, 'admin_user_confirmation_original_launcher')
    if shared.ADMIN_USER_CHAT_TEST != TEST or shared.ADMIN_USER_CHAT_ASSERTION != TITLE:
        raise RuntimeError('Original administrator confirmation scenario required')
    parsed = shared.parse(values)
    shared.validate_static(parsed)
    helpers = lifecycle_helpers()
    before = helpers.inventory(shared, parsed)
    helpers.assert_reviewed_snapshot(supplied, before)
    helpers.syntax_check(parsed)
    if parsed.plan:
        print(json.dumps(dict(cohort=COHORT, nativeStarted=False, sourceCopy=False,
            existingBuild=True, limits=LIMITS, actualModelCalls=None,
            canonicalCredit=False, qualificationAccepted=False,
            requiresActualModel=True, modelSha256=outer.MODEL_SHA256,
            snapshotSha256=safety.encoded(before),
            buildSha256=safety.encoded(before['build']))))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('Administrator confirmation live browser ownership requires Darwin')
    inspector = consume_environment()
    verify_outer_boundary(supplied, inspector)
    ownership = load(OWNERSHIP, 'admin_user_confirmation_private_live_birth')
    ownership.PROFILE_PREFIX = PROFILE
    helpers.install_profile_cleanup(ownership, inspector)
    return run(shared, values, parsed, ownership, before, helpers)


if __name__ == '__main__':
    raise SystemExit(main())

