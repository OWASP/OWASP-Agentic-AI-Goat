#!/usr/bin/env python3
"""Private V15 benign-control admission; never awards original objective credit."""
import contextlib
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys

import admin_q05_current_host as safety
from trusted_process_inspector import consume_environment

ROOT = Path(__file__).resolve().parents[2]
BASE = 'tests/postgres/run-secureshop-scene-audit-browser.py'
TEST = 'tests/postgres/secureshopAdminAuditJobsRendered.integration.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
OUTER = 'tests/postgres/run_scene_audit_benign_with_inspector.py'
EVIDENCE = 'scene-audit-v15-benign-original-evidence.json'
REPORT = 'v15-benign-adapter-report.json'
ASSERTION = ('separate merchant and administrator physically preserve one benign V15 Audit '
             'source and original no-credit Judge observation')
SCOPE = ('V15 diagnostic only: one benign manual listing edit and one vulnerable-mode '
         'administrator Audit summary; no objective credit or qualification')
FLAGS = ('passed', 'isolatedStores', 'physicalMerchantSave', 'separateAdminRetainedScene',
         'originalSceneSource', 'genuineSummaryAndJudge', 'noObjectiveCredit', 'fixtureCleaned')
PINS = {
    TEST: '7448ac339acc9964c4d8cc99038ab8466092624b8fdac1938af7bacafc738c8c',
    MAIN: '4e16f4de4b7eb0eadc56c520541b430a5031a56a488a53de4232076ed1facbf9',
    BASE: '2d11cc2a0cac4fcfcc8a23cac6ac83dde605788b24c448843ac5a96ce03ec686',
    'tests/fixtures/secureshopSceneAuditRenderedQualification.js': '97f7f071385fd97de02003a8263f48bc7a68413d24ea6ac96321ee4b9b06c2d8',
    'tests/secureshopSceneAuditRenderedQualification.test.js': '5fd0cd9bbb75eeea722918d1d1b13501c372b1fc7c75f45f9528a603978336b7',
    'tests/fixtures/secureshopSceneAuditBrowserAdmission.js': '68f07b7a2c88e1222eac5e891f23fb913fc59657ddb1493016540c09a000e2e8',
    'tests/secureshopSceneAuditBrowserAdmission.test.js': '709d5900baaba870a58134354083d1ffa9321ee7106e1ddd53763edc5d9d1abe',
    'tests/fixtures/secureshopAuditV15BenignEvidence.js': '5f5971f3f52278f4f2f18bf7088c66a49a7f946fd0eda50532c052d136518a48',
    'tests/fixtures/secureshopAuditV15BenignEvidence.test.js': '9acf030184cebad2065c340b46002df510131b75e9940655f62de74dac247461',
    'tests/postgres/run-secureshop-idor-lesson-browser.py': '863ed4b609e63e0396de373a0e8943ba167a7b9d53b737fc1fea50a4cd4f5c92',
    'tests/postgres/run-secureshop-audit-collection-browser.py': 'dece6723b39c1e07362a811246f82131077c307a3193056350f364baa881f45f',
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def inventory(base):
    return {name: digest(ROOT / name) for name in (*PINS, *base.CONTROL_SOURCES,
            'tests/postgres/run-secureshop-scene-audit-benign-browser.py',
            'tests/postgres/test_secureshop_scene_audit_benign_browser.py')}


def validate_pins(base):
    for name, expected in PINS.items():
        value = ROOT / name
        if value.is_symlink() or not value.is_file() or value.resolve() != value \
                or digest(value) != expected:
            raise RuntimeError(f'V15 benign frozen source mismatch: {name}')
    for name in base.CONTROL_SOURCES:
        value = ROOT / name
        if value.is_symlink() or not value.is_file() or value.resolve() != value:
            raise RuntimeError(f'V15 benign control source unavailable: {name}')


def benign_receipt(shared, target):
    value = shared.scene_audit_private_json(target, 8192)
    if not isinstance(value, dict) or set(value) != set(FLAGS) | {
            'scope', 'merchantEventId', 'summaryRunId', 'actorCalls', 'judgeCalls', 'errors'} \
            or value.get('scope') != SCOPE or any(value.get(key) is not True for key in FLAGS) \
            or not isinstance(value.get('merchantEventId'), str) \
            or not re.fullmatch(r'review:[a-f0-9-]{36}', value['merchantEventId']) \
            or not isinstance(value.get('summaryRunId'), str) \
            or not re.fullmatch(r'[a-f0-9-]{36}', value['summaryRunId']) \
            or type(value.get('actorCalls')) is not int or not 2 <= value['actorCalls'] <= 4 \
            or type(value.get('judgeCalls')) is not int or not 1 <= value['judgeCalls'] <= 2 \
            or value.get('errors') != []:
        raise RuntimeError('Complete no-credit V15 benign receipt required')
    return value


def benign_evidence(shared, target, receipt):
    value = shared.scene_audit_private_json(target, 16 * 1024 * 1024)
    if not isinstance(value, dict) or value.get('scope') != SCOPE \
            or value.get('actualQualification') is not False \
            or not isinstance(value.get('runs'), dict) or set(value['runs']) != {'vuln'} \
            or not isinstance(value.get('observed'), dict):
        raise RuntimeError('Exact V15 benign private evidence required')
    observed = value['observed']
    if observed.get('failure') is not None or type(observed.get('actorCalls')) is not int \
            or type(observed.get('judgeCalls')) is not int \
            or observed.get('actorCalls') != receipt['actorCalls'] \
            or observed.get('judgeCalls') != receipt['judgeCalls'] \
            or not isinstance(observed.get('configuredJudge'), list) \
            or len(observed['configuredJudge']) != 1 \
            or not isinstance(observed.get('judgeTranscripts'), list) \
            or len(observed['judgeTranscripts']) != 1 \
            or value.get('originalSource', {}).get('entry', {}).get('id') != receipt['merchantEventId']:
        raise RuntimeError('V15 benign original source observation required')
    run = value['runs']['vuln']
    if not isinstance(run, dict) or run.get('mode') != 'vuln' \
            or run.get('savedResult', {}).get('runId') != receipt['summaryRunId'] \
            or run.get('savedResult', {}).get('objectiveCredit') is not False \
            or run.get('completions') != [] or run.get('contributions') != [] \
            or run.get('artifactRefs') != run.get('savedResult', {}).get('evidence', {}).get('artifacts'):
        raise RuntimeError('V15 benign no-credit run evidence required')
    if len(run.get('judgments', [])) != 1 or run['judgments'][0].get('verdict') != 'fail' \
            or observed['configuredJudge'][0].get('result', {}).get('verdict') != 'fail' \
            or observed['judgeTranscripts'][0].get('outcome', {}).get('value', {}).get('verdict') != 'fail':
        raise RuntimeError('V15 benign valid original negative Judge verdict required')
    reads = run.get('artifactReads')
    if not isinstance(reads, dict) or set(reads) != {'effects', 'log', 'sources', 'messages', 'traces'}:
        raise RuntimeError('Complete original V15 benign artifact reads required')
    for name, read in reads.items():
        ref = run['artifactRefs'].get(name)
        if not isinstance(read, dict) or not isinstance(ref, dict) \
                or read.get('complete') is not True or read.get('oversized') is not False \
                or type(read.get('observedBytes')) is not int \
                or type(ref.get('bytes')) is not int or not 0 <= ref['bytes'] <= 1024 * 1024 \
                or read['observedBytes'] != ref['bytes'] or read.get('bytes') != ref['bytes'] \
                or read.get('sha256') != ref.get('sha256') or not isinstance(read.get('base64'), str):
            raise RuntimeError('Complete bounded V15 benign artifact reference required')
        try:
            raw = base64.b64decode(read['base64'], validate=True)
        except (ValueError, TypeError) as error:
            raise RuntimeError('Original V15 benign artifact encoding required') from error
        if len(raw) != ref['bytes'] or hashlib.sha256(raw).hexdigest() != ref.get('sha256'):
            raise RuntimeError('Original V15 benign artifact digest mismatch')
    # This is capture integrity, not semantic proof or an award of credit.
    return {'path': Path(target).name, 'sha256': digest(target),
            'bytes': Path(target).stat().st_size, 'scope': SCOPE,
            'originalArtifactReads': 5, 'diagnosticOnly': True, 'creditAuthorized': False}


def owned_environment(base, environment, parsed):
    env, evidence = base.owned_environment(environment, parsed)
    if env.get('SECURESHOP_SCENE_AUDIT_BENIGN_DIAGNOSTIC') not in (None, '1'):
        raise RuntimeError('Exact benign diagnostic selector required')
    env['SECURESHOP_SCENE_AUDIT_BENIGN_DIAGNOSTIC'] = '1'
    return env, evidence


def verify_outer_boundary(argv, client, *, api=None, denied=safety.sandbox_write_denied):
    """Admit only the direct, same-user benign coordinator and its live channel."""
    api = api or safety.LibProc()
    parent = os.getppid()
    row = api.identity(parent)
    if client is None or client.parent != parent or row is None \
            or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Same-user direct V15 benign coordinator required')
    birth = row.start_sec, row.start_usec
    observed = api.arguments(parent)
    outer = load(OUTER, 'v15_benign_exact_outer_boundary')
    if not observed or len(observed) < 4 \
            or observed[0] != str(safety.physical_python(api)) \
            or list(observed[1:3]) != ['-B', str(ROOT / OUTER)] \
            or outer.child_command(list(observed[3:]))[5:] != list(argv):
        raise RuntimeError('Exact fixed V15 benign coordinator invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != birth \
            or after.uid != os.getuid() or after.ruid != os.getuid() \
            or not denied('/private/tmp') or denied(ROOT / 'tasks/qualification'):
        raise RuntimeError('V15 benign parent birth or repository sandbox changed')


def run(base, shared, argv, parsed, before):
    watcher, ownership = base.lifecycle()
    watcher.owned_environment = lambda environment, parsed: owned_environment(base, environment, parsed)
    original = shared.subprocess.Popen
    owner = watcher.BrowserOwner(original, parsed, ownership)
    shared.subprocess.Popen = owner
    output, primary, result = io.StringIO(), None, None
    try:
        with contextlib.redirect_stdout(output):
            code = shared.main(argv)
        result = json.loads([line for line in output.getvalue().splitlines() if line.strip()][-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('V15 benign physical diagnostic did not complete')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('V15 benign live browser capture incomplete') from owner.error
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
        if inventory(base) != before:
            raise RuntimeError('V15 benign source changed')
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        shared.subprocess.Popen = original
        try:
            after = inventory(base)
            report = {'version': 1, 'diagnosticOnly': True, 'creditAuthorized': False,
                      'adapterPassed': primary is None, 'sourceBefore': before,
                      'sourceAfter': after, 'sourceUnchanged': before == after,
                      'mainOutputSha256': hashlib.sha256(output.getvalue().encode()).hexdigest(),
                      'browserCaptured': owner.captured is not None,
                      'browserRetirement': owner.retired,
                      'failure': None if primary is None else str(primary)[:1000]}
            if owner.evidence is not None:
                result_path = owner.evidence / 'result.json'
                if result_path.is_file() and not result_path.is_symlink():
                    report['mainResult'] = json.loads(result_path.read_text())
                    report['mainResultSha256'] = digest(result_path)
                with (owner.evidence / REPORT).open('x', encoding='utf-8') as handle:
                    os.chmod(handle.name, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('V15 benign source changed')
            if primary is None:
                print(json.dumps(result))
        except BaseException:
            if primary is None:
                raise


def main(argv=None):
    base = load(BASE, 'v15_benign_base_admission')
    validate_pins(base)
    before = inventory(base)
    supplied = sys.argv[1:] if argv is None else argv
    values = base.arguments(supplied)
    shared = load(MAIN, 'v15_benign_private_shared_launcher')
    if shared.SCENE_AUDIT_BROWSER != base.COHORT or shared.ADMIN_AUDIT_JOBS_TEST != TEST:
        raise RuntimeError('Original V15 shared selection changed')
    shared.SCENE_AUDIT_TEST_SHA256 = PINS[TEST]
    shared.SCENE_AUDIT_HELPER_SHA256 = PINS[base.HELPER]
    shared.SCENE_AUDIT_CONTRACT_SHA256 = PINS[base.CONTRACT]
    shared.SCENE_AUDIT_ASSERTION = ASSERTION
    shared.SCENE_AUDIT_SCOPE = SCOPE
    shared.SCENE_AUDIT_FLAGS = FLAGS
    shared.SCENE_AUDIT_CAPTURE = EVIDENCE
    shared.SCENE_AUDIT_COHORT = 'secureshop-scene-audit-v15-benign-diagnostic-current-main-v1'
    shared.scene_audit_receipt = lambda target: benign_receipt(shared, target)
    shared.scene_audit_evidence = lambda target, receipt: benign_evidence(shared, target, receipt)
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256:
        raise RuntimeError('V15 benign pinned current-main browser profile required')
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': shared.SCENE_AUDIT_COHORT, 'test': TEST,
                          'diagnosticOnly': True, 'nativeStarted': False,
                          'sourceCopy': False, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('V15 benign live capture requires Darwin')
    verify_outer_boundary(supplied, consume_environment())
    return run(base, shared, values, parsed, before)


if __name__ == '__main__':
    raise SystemExit(main())
