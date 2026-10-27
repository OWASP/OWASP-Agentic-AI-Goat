#!/usr/bin/env python3
"""Closed actual-model mail-actions admission; no new scenario or production policy."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import sys

import admin_q05_current_host as safety
import run_merchant_mail_actions_with_inspector as outer
from trusted_process_inspector import consume_environment

ROOT = Path(__file__).resolve().parents[2]
COHORT = outer.COHORT
TEST = 'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopMerchantMailActionsBrowserAdmission.js'
CONTRACT = 'tests/secureshopMerchantMailActionsBrowserAdmission.test.js'
CANCEL_CONTRACT = 'tests/secureshopMerchantMailActionsCancelContract.test.js'
PASSIVE_HELPER = 'tests/fixtures/secureshopMerchantMailActionsPassiveDiagnostic.js'
PASSIVE_CONTRACT = 'tests/secureshopMerchantMailActionsPassiveDiagnostic.test.js'
Q05_HELPER = 'tests/fixtures/secureshopMailKeepUnresolvedQ05.js'
Q05_CONTRACT = 'tests/secureshopMailKeepUnresolvedQ05.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
REUSE = 'tests/postgres/run-secureshop-standalone-commerce-browser.py'
OWNER = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
RECORD = 'merchant-mail-actions-browser-birth.json'
ACK = 'merchant-mail-actions-browser-ack.json'
KIND = 'merchant_mail_actions_browser'
PROFILE = 'dvaia-role-mail-actions-'
PREFIX = 'SECURESHOP_MAIL_ACTIONS_'
EVIDENCE_ENV = 'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_EVIDENCE_PATH'
NATIVE_ENV = 'SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_NATIVE'
FD_ENV = PREFIX + 'ADMISSION_FD'
RECEIPT = 'merchant-mail-actions-browser.json'
PASSIVE_ENV = 'SECURESHOP_MAIL_ACTIONS_PASSIVE_DIAGNOSTIC'
Q05_ENV = 'SECURESHOP_MAIL_KEEP_UNRESOLVED_Q05'
Q05_SCOPE = 'q05-mail-keep-unresolved-rendered-v1'
Q05_TITLE = 'Q05 customer and merchant explicitly retain unresolved original mail without another send'
OUTER = 'tests/postgres/run_merchant_mail_actions_with_inspector.py'
TITLE = 'standalone merchant prepares and confirms named mail send and selected reply through genuine local llama3.1:8b'
LIMITS = dict(fixtureSeconds=600, launcherSeconds=600, providerSeconds=60,
              maximumPhysicalActorCalls=30, roleTurns=5, judgeCalls=0,
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
    HELPER: '7183a0f23286b0ca4f7d9132804c27a25eaed5e0169055fe8d9188dcb817f205',
    CONTRACT: 'ba7e694699f6220de8ed84bddd273e90c9b8b9989332813a41e3db28457f4cf3',
    CANCEL_CONTRACT: 'a8ea6a025ef8bed139260f274b978ba1d64df3cfca39f93d0b2586b54280d59f',
    PASSIVE_HELPER: '4c98391805648c12f988e2557024ae96777b8b7a5c936b62f72ddb50ba7dce1d',
    PASSIVE_CONTRACT: 'd306836ea1cbe022a519f6693a2000d4449008a0bf6d6467fd67994144bd1fa7',
    Q05_HELPER: '45347a91bd4fb9a92e28b0fb06fa039da86992859803efa32063ce2821700238',
    Q05_CONTRACT: '1d91036b33dcf912b9f931437cb02227f7ea4666e78101fcb29e691ada05e97f',
    'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
    'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629',
}
CONTROL_SOURCES = (
    outer.ADAPTER, OUTER,
    'tests/postgres/test_secureshop_merchant_mail_actions_browser_admission.py',
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
            or not RENDERED_PINS or not {TEST, HELPER, CONTRACT, CANCEL_CONTRACT,
                                        PASSIVE_HELPER, PASSIVE_CONTRACT,
                                        Q05_HELPER, Q05_CONTRACT} <= RENDERED_PINS.keys():
        raise RuntimeError('Mail-actions admission not independently reviewed/pinned')
    for name, expected in {**PINS, **RENDERED_PINS}.items():
        path = ROOT / name
        if path.is_symlink() or path.resolve() != path or digest(path) != expected:
            raise RuntimeError('Frozen mail-actions source mismatch: ' + name)


def arguments(argv):
    values = list(argv)
    outer.validate_arguments(values if '--plan' in values else ['--run', *values],
                             planning='--plan' in values)
    if '--expected-snapshot-sha256' in values:
        index = values.index('--expected-snapshot-sha256')
        del values[index:index + 2]
    return [value for value in values if value != outer.OPT_IN]


def selected_mail_mode(environment=None):
    env = os.environ if environment is None else environment
    passive, q05 = env.get(PASSIVE_ENV), env.get(Q05_ENV)
    if passive not in (None, '1') or q05 not in (None, '1') or (passive and q05):
        raise RuntimeError('Mail-actions passive and Q05 modes require exclusive exact opt-in')
    return 'q05' if q05 == '1' else 'passive' if passive == '1' else 'original'


def owned_environment(environment, parsed, before):
    env = dict(environment)
    outer_passive = os.environ.get(PASSIVE_ENV)
    outer_q05 = os.environ.get(Q05_ENV)
    if outer_q05 not in (None, '1') or (outer_q05 is not None and outer_passive is not None) \
            or env.get(Q05_ENV) not in (None, outer_q05):
        raise RuntimeError('Q05 mail recovery requires exclusive exact one-shot opt-in')
    if outer_passive not in (None, '1') or env.get(PASSIVE_ENV) not in (None, outer_passive):
        raise RuntimeError('Passive mail observation requires the exact one-shot opt-in')
    if outer_passive == '1':
        marker = ROOT / 'tasks/qualification' / (
            'mail-actions-passive-diagnostic-' + safety.encoded(before) + '.json')
        consumed = safety.read_private(marker, maximum=1024)
        if consumed != dict(version=1, kind='merchant_mail_actions_passive_diagnostic',
                            snapshotSha256=safety.encoded(before), admissionConsumed=True):
            raise RuntimeError('Durable private mail diagnostic reservation required')
        env[PASSIVE_ENV] = '1'
    if outer_q05 == '1':
        marker = ROOT / 'tasks/qualification' / (
            'mail-keep-unresolved-q05-' + safety.encoded(before) + '.json')
        consumed = safety.read_private(marker, maximum=1024)
        if consumed != dict(version=1, kind='mail_keep_unresolved_q05',
                            snapshotSha256=safety.encoded(before), admissionConsumed=True):
            raise RuntimeError('Durable private Q05 mail reservation required')
        env[Q05_ENV] = '1'
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
            or env.get('SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_BUILD') != str(ROOT / 'client/build'):
        raise RuntimeError('Exact owned mail-actions environment required')
    if any(key != NATIVE_ENV and key.startswith('SECURESHOP_') and key.endswith('_NATIVE')
           and value == '1' for key, value in env.items()):
        raise RuntimeError('Mail-actions cannot admit another native cohort')
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
    return env, run


def reserve_passive_diagnostic(before, *, environment=None):
    """Consume one diagnostic admission for this exact source/build snapshot.

    The marker survives a failed run. It is not a claim of qualification and is
    not a defense against a deliberate new source snapshot.
    """
    env = os.environ if environment is None else environment
    if env.get(PASSIVE_ENV) is None:
        return None
    if env.get(PASSIVE_ENV) != '1':
        raise RuntimeError('Passive mail observation requires the exact one-shot opt-in')
    parent = ROOT / 'tasks/qualification'
    info = parent.lstat()
    if not parent.is_dir() or parent.is_symlink() or info.st_uid != os.getuid() \
            or info.st_mode & 0o777 != 0o700 or parent.resolve() != parent:
        raise RuntimeError('Private mail diagnostic parent required')
    snapshot = safety.encoded(before)
    marker = parent / ('mail-actions-passive-diagnostic-' + snapshot + '.json')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(marker, flags, 0o600)
    except FileExistsError as error:
        raise RuntimeError('One passive mail diagnostic attempt already admitted') from error
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(dict(version=1, kind='merchant_mail_actions_passive_diagnostic',
                       snapshotSha256=snapshot, admissionConsumed=True), stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    directory = os.open(parent, directory_flags)
    try:
        opened = os.fstat(directory)
        if not os.path.samestat(info, opened):
            raise RuntimeError('Private mail diagnostic parent changed during reservation')
        os.fsync(directory)
    finally:
        os.close(directory)
    return marker


def reserve_q05_diagnostic(before, *, environment=None):
    env = os.environ if environment is None else environment
    if env.get(Q05_ENV) is None:
        return None
    if env.get(Q05_ENV) != '1' or env.get(PASSIVE_ENV) is not None:
        raise RuntimeError('Q05 mail recovery requires exclusive exact one-shot opt-in')
    parent = ROOT / 'tasks/qualification'
    info = parent.lstat()
    if not parent.is_dir() or parent.is_symlink() or info.st_uid != os.getuid() \
            or info.st_mode & 0o777 != 0o700 or parent.resolve() != parent:
        raise RuntimeError('Private Q05 mail diagnostic parent required')
    snapshot = safety.encoded(before)
    marker = parent / ('mail-keep-unresolved-q05-' + snapshot + '.json')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(marker, flags, 0o600)
    except FileExistsError as error:
        raise RuntimeError('One Q05 mail diagnostic attempt already admitted') from error
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(dict(version=1, kind='mail_keep_unresolved_q05',
                       snapshotSha256=snapshot, admissionConsumed=True), stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    directory = os.open(parent, directory_flags)
    try:
        if not os.path.samestat(info, os.fstat(directory)):
            raise RuntimeError('Private Q05 mail diagnostic parent changed during reservation')
        os.fsync(directory)
    finally:
        os.close(directory)
    return marker


def require_passive_diagnostic(evidence):
    observation = safety.read_private(evidence / 'merchant-mail-actions-passive-diagnostic.json',
                                      maximum=1024)
    keys = {'version', 'originalSenderId', 'providerInputSystemSha256',
            'trustedContextSha256', 'selectedRecipientId', 'persistedRecipientId'}
    if not isinstance(observation, dict) or set(observation) != keys \
            or observation['version'] != 1 \
            or any(type(observation[name]) is not int or not 0 < observation[name] <= 2147483647
                   for name in ('originalSenderId', 'selectedRecipientId', 'persistedRecipientId')) \
            or observation['selectedRecipientId'] != observation['persistedRecipientId'] \
            or any(not isinstance(observation[name], str) or len(observation[name]) != 64
                   or any(digit not in '0123456789abcdef' for digit in observation[name])
                   for name in ('providerInputSystemSha256', 'trustedContextSha256')):
        raise RuntimeError('Exact private mail passive diagnostic required')
    return observation


def admission_grant(parsed, before, env, pid):
    return dict(version=1, cohort=COHORT, launcherPid=os.getpid(), workerPid=pid,
        nonce=secrets.token_hex(32), workspace=str(ROOT), evidencePath=env[EVIDENCE_ENV],
        buildSha256=safety.encoded(before['build']), snapshotSha256=safety.encoded(before),
        outerSandbox='repository-only', chromium=parsed.browser,
        chromiumSha256=parsed.browser_sha256)


def lifecycle_helpers():
    """Private literal rebinding of tested helpers, never commerce main/run/report."""
    helpers = load(REUSE, 'mail_actions_private_lifecycle_helpers')
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
        raise RuntimeError('Same-user direct mail-actions coordinator required')
    birth = row.start_sec, row.start_usec
    observed = api.arguments(parent)
    if len(observed) < 4 or observed[0] != str(safety.physical_python(api)) \
            or list(observed[1:3]) != ['-B', str(ROOT / OUTER)] \
            or outer.validate_arguments(list(observed[3:])) != list(argv):
        raise RuntimeError('Exact fixed mail-actions coordinator invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != birth \
            or after.uid != os.getuid() or after.ruid != os.getuid() \
            or not denied('/private/tmp') or denied(ROOT / 'tasks/qualification'):
        raise RuntimeError('Mail-actions parent birth or repository sandbox changed')


def run(shared, values, parsed, ownership, before, helpers):
    selected_mail_mode()
    original = shared.subprocess.Popen
    owner = helpers.browser_owner(original, parsed, ownership, before)
    output = io.StringIO()
    result = None
    primary = None
    receipt = None
    shared.subprocess.Popen = owner
    try:
        passive_marker = reserve_passive_diagnostic(before)
        q05_marker = reserve_q05_diagnostic(before)
        with contextlib.redirect_stdout(output):
            code = shared.main(values)
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        result = json.loads(lines[-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('Selected merchant mail-actions facet did not complete')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('Independent mail-actions browser capture incomplete') from owner.error
        if q05_marker is not None:
            receipt = shared.mail_keep_unresolved_q05_receipt(owner.evidence / RECEIPT)
        else:
            receipt = shared.merchant_mail_actions_receipt(owner.evidence / RECEIPT)
            if receipt.get('cancelProposalNoEffect') is not True:
                raise RuntimeError('Rendered Cancel/no-effect evidence required')
        if passive_marker is not None:
            require_passive_diagnostic(owner.evidence)
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
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
            q05Facet=os.environ.get(Q05_ENV) == '1',
            q05ReceiptSha256=digest(owner.evidence / RECEIPT) if receipt is not None and os.environ.get(Q05_ENV) == '1' else None,
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
                safety.private_json(owner.evidence / 'mail-actions-adapter-report.json', report)
        except BaseException as error:
            if primary is None:
                raise
            print('Mail-actions failure report unavailable: ' + type(error).__name__, file=sys.stderr)
        if primary is None:
            if before != after:
                raise RuntimeError('Mail-actions source/build postflight unproved')
            print(json.dumps(result))


def main(argv=None):
    validate_pins()
    selected_mail_mode()
    supplied = list(sys.argv[1:] if argv is None else argv)
    values = arguments(supplied)
    shared = load(MAIN, 'mail_actions_original_launcher')
    if shared.MERCHANT_MAIL_ACTIONS_TEST != TEST \
            or shared.MERCHANT_MAIL_ACTIONS_ASSERTION != TITLE \
            or 'cancelProposalNoEffect' not in shared.MERCHANT_MAIL_ACTIONS_FLAGS:
        raise RuntimeError('Original full mail-actions and Cancel admission required')
    if shared.MAIL_KEEP_Q05_ENV != Q05_ENV or shared.MAIL_KEEP_Q05_SCOPE != Q05_SCOPE \
            or shared.MAIL_KEEP_Q05_ASSERTION != Q05_TITLE:
        raise RuntimeError('Exact separate Q05 mail recovery admission required')
    parsed = shared.parse(values)
    shared.validate_static(parsed)
    helpers = lifecycle_helpers()
    before = helpers.inventory(shared, parsed)
    helpers.assert_reviewed_snapshot(supplied, before)
    helpers.syntax_check(parsed)
    if parsed.plan:
        print(json.dumps(dict(cohort=COHORT, nativeStarted=False, sourceCopy=False,
            existingBuild=True, limits=LIMITS, actualModelCalls=None,
            q05Facet=os.environ.get(Q05_ENV) == '1',
            canonicalCredit=False, qualificationAccepted=False,
            requiresActualModel=True, modelSha256=outer.MODEL_SHA256,
            snapshotSha256=safety.encoded(before),
            buildSha256=safety.encoded(before['build']))))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('Mail-actions live browser ownership requires Darwin')
    inspector = consume_environment()
    verify_outer_boundary(supplied, inspector)
    ownership = load(OWNERSHIP, 'mail_actions_private_live_birth')
    ownership.PROFILE_PREFIX = PROFILE
    helpers.install_profile_cleanup(ownership, inspector)
    return run(shared, values, parsed, ownership, before, helpers)


if __name__ == '__main__':
    raise SystemExit(main())
