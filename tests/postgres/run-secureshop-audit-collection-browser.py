#!/usr/bin/env python3
"""V36 browser adapter over the reviewed four-store/audit-cluster launcher.

The shared launcher remains unchanged. This adapter selects its existing owned
provisioning and cleanup path, then adds only the V36 collection environment to
the selected rendered test process.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MAIN_PATH = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
COHORT = 'secureshop-admin-audit-collection-browser-current-main-v1'
MAIN_COHORT = 'admin-audit-jobs-browser'
TEST = 'tests/postgres/secureshopAdminAuditJobsRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopAuditCollectionQualification.js'
CONTRACT = 'tests/secureshopAuditCollectionQualification.test.js'
TEST_SHA256 = '0f12b4b017e877e16d1b53a70ca3923dbcb7b17a58792218a1b8772fc4022e5d'
HELPER_SHA256 = '7671d0135516f1b4ae099bd01c925e8bd3fc7ff320d90f26be6989599a531fe8'
CONTRACT_SHA256 = '99985b4c9c29cfec03818302eacf3724457ae4094b2bce5b8eaf0c392c23fc57'
MODEL = 'llama3.1:8b'
CONTEXT = '32768'
SCOPE = 'V36 focused current-build Audit button; complete oversized original observation, owned witness, actual Ollama and canonical Judge; same-ID POST replay, fixed count rejection, committed reset and populated sibling'
ASSERTION = 'V36 physical unbounded Audit observes over 100 owned rows and 131072 bytes with genuine model witness, canonical Judge credit and fixed replay reset sibling fences'
FLAGS = ('passed','isolatedStores','genuineAdminUiSession','physicalUnboundedRun',
         'fullOwnedObservation','originalWitness','canonicalCredit','sameIdPostReplay',
         'fixedCountDenied','foreignSessionDenied','committedReset','siblingPreserved',
         'fixtureCleaned')
REQUIRED_RECEIPT_KEYS = set(FLAGS) | {'scope','summaryRunId','rowCount','sourceBytes',
                                      'actorCalls','judgeCalls','promptEvalCount','errors'}
ORIGINAL_EVIDENCE = 'audit-collection-v36-original-evidence.json'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_main():
    spec = importlib.util.spec_from_file_location('secureshop_main_launcher_v36_adapter', MAIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_frozen_sources():
    expected = {TEST: TEST_SHA256, HELPER: HELPER_SHA256, CONTRACT: CONTRACT_SHA256}
    for relative, pin in expected.items():
        if digest(ROOT / relative) != pin:
            raise RuntimeError(f'Frozen V36 source pin mismatch: {relative}')

    validate_context_contract((ROOT / TEST).read_text(), (ROOT / HELPER).read_text())


def validate_context_contract(fixture_source, helper_source):
    fixture = re.findall(r"if \(collection\) assert\.equal\(process\.env\.OLLAMA_CONTEXT_WINDOW, '([0-9]+)'\);", fixture_source)
    helper = re.findall(r'^const CONTEXT_WINDOW = ([0-9]+);$', helper_source, re.MULTILINE)
    if fixture != [CONTEXT] or helper != [CONTEXT]:
        raise RuntimeError('V36 fixture/helper context disagrees with wrapper before provisioning')


def frozen_source_digests():
    return {relative: digest(ROOT / relative) for relative in (TEST, HELPER, CONTRACT)}


def _safe_int(value, *, minimum=None, maximum=None):
    if type(value) is not int or value < 0:
        return False
    return (minimum is None or value >= minimum) and (maximum is None or value <= maximum)


def assert_closed_receipt(value):
    """Mirror the JS helper's closed receipt contract at the adapter boundary."""
    if not isinstance(value, dict) or set(value) != REQUIRED_RECEIPT_KEYS:
        raise RuntimeError('V36 receipt keys are not closed')
    if value.get('scope') != SCOPE or any(value.get(flag) is not True for flag in FLAGS):
        raise RuntimeError('V36 receipt flags or scope are incomplete')
    if not isinstance(value.get('summaryRunId'), str) or not re.fullmatch(r'[a-f0-9-]{36}', value['summaryRunId']):
        raise RuntimeError('V36 receipt run identity is invalid')
    bounds = {
        'rowCount': (101, 5000), 'sourceBytes': (131073, 4 * 1024 * 1024),
        'actorCalls': (2, 28), 'judgeCalls': (1, 12), 'promptEvalCount': (1, 32768 - 256 - 1),
    }
    for key, (minimum, maximum) in bounds.items():
        if not _safe_int(value.get(key), minimum=minimum, maximum=maximum):
            raise RuntimeError(f'V36 receipt counter {key} is outside its bound')
    if value.get('errors') != []:
        raise RuntimeError('V36 receipt contains errors')
    return value


def _private_json(path, maximum):
    path = Path(path)
    info = path.lstat()
    parent = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 \
            or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 \
            or info.st_size <= 0 or info.st_size > maximum:
        raise RuntimeError(f'Private bounded V36 evidence required: {path}')
    raw = path.read_bytes()
    after = path.lstat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != \
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError('V36 original evidence changed during validation')
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError('V36 original evidence is not JSON') from error
    if not isinstance(value, dict):
        raise RuntimeError('V36 original evidence must be an object')
    return raw, value


def validate_original_evidence(path, receipt):
    """Require raw HTTP/wire/Judge joins, rather than trusting receipt flags."""
    raw, evidence = _private_json(path, 32 * 1024 * 1024)
    if evidence.get('scope') != SCOPE or evidence.get('failure') is not None:
        raise RuntimeError('V36 original evidence scope or failure is incomplete')
    physical = evidence.get('physical')
    if not isinstance(physical, list) or len(physical) != 2:
        raise RuntimeError('V36 physical original and fixed observations are required')
    original = [row for row in physical if isinstance(row, dict) and row.get('status') == 200
                and isinstance(row.get('body'), dict) and row['body'].get('replayed') is False]
    fixed = [row for row in physical if isinstance(row, dict) and row.get('status') == 400]
    if len(original) != 1 or len(fixed) != 1:
        raise RuntimeError('V36 original/fixed physical observations are incomplete')
    request = original[0].get('request')
    if not isinstance(request, dict) or request.get('limit') != 5000 or not isinstance(request.get('request_id'), str):
        raise RuntimeError('V36 original POST request is not the bounded unbounded-summary request')
    fixed_request = fixed[0].get('request')
    if not isinstance(fixed_request, dict) or fixed_request.get('limit') != 5000 \
            or not isinstance(fixed_request.get('request_id'), str) \
            or fixed_request.get('request_id') == request['request_id']:
        raise RuntimeError('V36 fixed-count request identity is missing or reused')
    if fixed[0].get('body') != {'error': 'Fixed audit summaries accept at most 100 events'}:
        raise RuntimeError('V36 fixed-count denial projection changed')
    replay = evidence.get('replay')
    if not isinstance(replay, dict) or replay.get('status') != 200 \
            or not isinstance(replay.get('body'), dict) or replay['body'].get('replayed') is not True \
            or replay['body'].get('summary') != original[0]['body'].get('summary'):
        raise RuntimeError('V36 same-ID replay does not join the original request/result')
    http = evidence.get('http')
    if not isinstance(http, list) or sum(row.get('path') == '/admin/audit/unbounded-summary'
                                         and row.get('status') == 200
                                         and row.get('request') == request for row in http if isinstance(row, dict)) < 1:
        raise RuntimeError('V36 captured HTTP POST does not join the original request')
    errors = evidence.get('errors')
    if errors != [{'requestId': request['request_id'], 'code': 'CONVERSATION_UNAVAILABLE'},
                  {'requestId': fixed_request['request_id'], 'code': 'AUDIT_FIXED_COUNT_LIMIT'}]:
        raise RuntimeError('V36 foreign-session error capture is incomplete')
    wires = evidence.get('wires')
    if not isinstance(wires, list):
        raise RuntimeError('V36 raw actor wire capture is missing')
    artifacts = evidence.get('artifacts', {})
    original_messages = artifacts.get('messages')
    if not isinstance(original_messages, list):
        raise RuntimeError('V36 original messages are required')
    observations = [row.get('content') for row in original_messages
                    if isinstance(row, dict) and row.get('role') == 'tool']
    if len(observations) != 1 or not isinstance(observations[0], str):
        raise RuntimeError('V36 exact original tool observation is required')
    suffix = '(tool result):\n' + observations[0]
    matching = [wire for wire in wires if isinstance(wire, dict)
                and isinstance(wire.get('request'), dict)
                and isinstance(wire['request'].get('messages'), list)
                and any(isinstance(message, dict) and message.get('role') == 'user'
                        and isinstance(message.get('content'), str)
                        and message['content'].startswith('Tool observation for completed call ')
                        and message['content'].endswith(suffix)
                        for message in wire['request']['messages'])]
    if len(matching) not in (1, 2):
        raise RuntimeError('V36 original final plus at most one repair required')
    remaining = 256
    previous_messages = None
    previous_raw = None
    repair = 'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.'
    for index, wire in enumerate(matching):
        req = wire['request']
        if wire.get('path') != '/api/chat' or wire.get('status') != 200 or wire.get('complete') is not True \
                or req.get('model') != MODEL or req.get('options', {}).get('num_ctx') != int(CONTEXT) \
                or type(req.get('options', {}).get('num_predict')) is not int \
                or req['options']['num_predict'] != remaining:
            raise RuntimeError('V36 final attempt transport or remaining budget is invalid')
        if index and req['messages'] != previous_messages + [
                {'role': 'assistant', 'content': previous_raw}, {'role': 'user', 'content': repair}]:
            raise RuntimeError('V36 repair does not extend the exact original transcript')
        try:
            frames = [json.loads(line) for line in wire['responseText'].strip().splitlines()]
        except (KeyError, AttributeError, json.JSONDecodeError) as error:
            raise RuntimeError('V36 final stream is invalid') from error
        if not frames or any(not isinstance(frame, dict) or frame.get('model') != MODEL
                or frame.get('done') is not (position == len(frames) - 1)
                or 'error' in frame or not isinstance(frame.get('message'), dict)
                or frame['message'].get('role') != 'assistant'
                or not isinstance(frame['message'].get('content'), str)
                for position, frame in enumerate(frames)):
            raise RuntimeError('V36 final stream framing is invalid')
        terminal = frames[-1]
        if terminal.get('done_reason') != 'stop' \
                or not _safe_int(terminal.get('prompt_eval_count'), minimum=1, maximum=int(CONTEXT)-remaining-1) \
                or not _safe_int(terminal.get('eval_count'), minimum=1, maximum=remaining):
            raise RuntimeError('V36 final token telemetry, headroom or stop reason is invalid')
        raw_answer = ''.join(frame['message']['content'] for frame in frames)
        try:
            decoded = json.loads(raw_answer)
        except json.JSONDecodeError:
            decoded = None
        valid = isinstance(decoded, dict) and set(decoded) == {'answer'} \
            and isinstance(decoded['answer'], str) and bool(decoded['answer'].strip())
        if index == len(matching)-1:
            if not valid or decoded['answer'] != original[0]['body'].get('summary') \
                    or terminal['prompt_eval_count'] != receipt['promptEvalCount']:
                raise RuntimeError('V36 final response or receipt telemetry does not match')
        elif valid:
            raise RuntimeError('V36 cannot repair an already valid final answer')
        remaining -= terminal['eval_count']
        if index < len(matching)-1 and remaining <= 0:
            raise RuntimeError('V36 repair exceeded total output allowance')
        previous_messages, previous_raw = req['messages'], raw_answer
    judge_results = evidence.get('judgeResults')
    transcripts = evidence.get('judgeTranscripts')
    run_id = receipt['summaryRunId']
    if not isinstance(judge_results, list) or not any(isinstance(row, dict)
                                                      and isinstance(row.get('result'), dict)
                                                      and row['result'].get('runId') == run_id
                                                      for row in judge_results):
        raise RuntimeError('V36 canonical Judge result is not joined to the original run')
    if not isinstance(transcripts, list) or not any(isinstance(row, dict)
                                                    and row.get('complete') is True
                                                    and isinstance(row.get('header'), dict)
                                                    and row['header'].get('runId') == run_id
                                                    for row in transcripts):
        raise RuntimeError('V36 canonical Judge transcript is not joined to the original run')
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'scope': SCOPE, 'summaryRunId': run_id, 'validated': True}


def rewrite_args(argv):
    rewritten = list(argv)
    for index, value in enumerate(rewritten[:-1]):
        if value == '--cohort' and rewritten[index + 1] == COHORT:
            rewritten[index + 1] = MAIN_COHORT
            break
    else:
        raise RuntimeError(f'--cohort {COHORT} is required')
    return rewritten


def plan(main, parsed):
    main.validate_static(parsed)
    print(json.dumps({
        'cohort': COHORT,
        'sharedProvisioningCohort': MAIN_COHORT,
        'test': TEST,
        'helper': HELPER,
        'contract': CONTRACT,
        'scope': SCOPE,
        'assertion': ASSERTION,
        'model': MODEL,
        'contextWindow': int(CONTEXT),
        'stores': ['identity', 'secureshop_agents', 'secureshop_review', 'secureshop'],
        'separateAuditSqlCluster': True,
        'nativeStarted': False,
        'sourceCopy': False,
    }, indent=2))
    return 0


def run(main, rewritten, source_before):
    original_popen = main.subprocess.Popen
    original_counts = main.complete_tap_counts
    original_receipt = main.admin_audit_jobs_receipt
    evidence_path = None

    def collection_popen(command, *args, **kwargs):
        nonlocal evidence_path
        if TEST in {str(item) for item in command}:
            child_env = dict(kwargs.get('env') or os.environ)
            child_env.update(
                SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE='1',
                OLLAMA_CONTEXT_WINDOW=CONTEXT,
                SS_AUDIT_SUMMARY_ENABLED='true',
                SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE='0',
                SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE='0',
            )
            configured_path = child_env.get('SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH')
            if configured_path:
                # The shared launcher passes the receipt filename, while the
                # adapter report belongs beside it in the private directory.
                evidence_path = Path(configured_path).parent
            kwargs['env'] = child_env
        return original_popen(command, *args, **kwargs)

    def collection_counts(content, label, expected_assertions):
        if expected_assertions == [main.ADMIN_AUDIT_JOBS_ASSERTION]:
            return original_counts(content, label, [ASSERTION])
        return original_counts(content, label, expected_assertions)

    def collection_receipt(path):
        value = json.loads(Path(path).read_text())
        return assert_closed_receipt(value)

    main.subprocess.Popen = collection_popen
    main.complete_tap_counts = collection_counts
    main.admin_audit_jobs_receipt = collection_receipt
    output = io.StringIO()
    try:
        try:
            with contextlib.redirect_stdout(output):
                code = main.main(rewritten)
        except Exception as error:
            if evidence_path is not None:
                # Diagnostics are best-effort: never mask the qualification
                # exception with a report, hash, or source-check failure.
                try:
                    source_after = frozen_source_digests()
                    failure_report = {
                        'version': 1, 'cohort': COHORT, 'scope': SCOPE, 'assertion': ASSERTION,
                        'adapterPassed': False, 'failure': {'type': type(error).__name__,
                        'message': str(error)[:1000]}, 'sourceBefore': source_before,
                        'sourceAfter': source_after, 'sourceUnchanged': source_after == source_before,
                        'modelVerification': {'status': 'unverified',
                                              'reason': 'shared launcher raised before post-run model snapshot'},
                        'mainOutputSha256': hashlib.sha256(output.getvalue().encode()).hexdigest(),
                        'mainOutputBytes': len(output.getvalue().encode()),
                    }
                    result_path = evidence_path / 'result.json'
                    if result_path.is_file() and not result_path.is_symlink():
                        try:
                            failure_report['mainResult'] = json.loads(result_path.read_text())
                            failure_report['mainResultSha256'] = digest(result_path)
                        except (OSError, json.JSONDecodeError):
                            failure_report['mainResultUnavailable'] = True
                    report_path = evidence_path / 'v36-adapter-report.json'
                    if evidence_path.is_dir() and not report_path.exists():
                        with report_path.open('x', encoding='utf-8') as handle:
                            os.chmod(report_path, 0o600)
                            json.dump(failure_report, handle, sort_keys=True, separators=(',', ':'))
                            handle.write('\n')
                except Exception:
                    pass
            raise
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        if not lines:
            raise RuntimeError('Shared launcher did not emit its final JSON result')
        try:
            launcher_result = json.loads(lines[-1])
        except json.JSONDecodeError as error:
            raise RuntimeError('Shared launcher final result is not JSON') from error
        if not isinstance(launcher_result, dict) or not isinstance(launcher_result.get('evidence'), str):
            raise RuntimeError('Shared launcher final result lacks evidence path')
        evidence = Path(launcher_result['evidence'])
        result_path = evidence / 'result.json'
        receipt_path = evidence / 'admin-audit-jobs-browser.json'
        original_path = evidence / ORIGINAL_EVIDENCE
        if not result_path.is_file() or not receipt_path.is_file():
            raise RuntimeError('V36 shared evidence result or receipt is missing')
        main_result = json.loads(result_path.read_text())
        receipt = assert_closed_receipt(json.loads(receipt_path.read_text()))
        original = validate_original_evidence(original_path, receipt)
        source_after = frozen_source_digests()
        if source_after != source_before:
            raise RuntimeError('V36 frozen fixture/helper/contract changed during qualification')
        report = {
            'version': 1,
            'cohort': COHORT,
            'scope': SCOPE,
            'assertion': ASSERTION,
            'mainResult': main_result,
            'mainResultSha256': digest(result_path),
            'mainReceiptSha256': digest(receipt_path),
            'originalEvidence': original,
            'sourceBefore': source_before,
            'sourceAfter': source_after,
            'sourceUnchanged': True,
            'adapterPassed': True,
        }
        report_path = evidence / 'v36-adapter-report.json'
        with report_path.open('x', encoding='utf-8') as handle:
            os.chmod(report_path, 0o600)
            json.dump(report, handle, sort_keys=True, separators=(',', ':'))
            handle.write('\n')
        print(json.dumps({'evidence': str(evidence), 'passed': True,
                          'cleanup': launcher_result.get('cleanup'),
                          'v36AdapterReport': str(report_path)}))
        return code
    finally:
        main.subprocess.Popen = original_popen
        main.complete_tap_counts = original_counts
        main.admin_audit_jobs_receipt = original_receipt


def main(argv=None):
    validate_frozen_sources()
    source_before = frozen_source_digests()
    main_module = load_main()
    raw = list(sys.argv[1:] if argv is None else argv)
    rewritten = rewrite_args(raw)
    parsed = main_module.parse(rewritten)
    if parsed.plan:
        return plan(main_module, parsed)
    primary = None
    try:
        return run(main_module, rewritten, source_before)
    except Exception as error:
        primary = error
        raise
    finally:
        try:
            drifted = frozen_source_digests() != source_before
        except Exception:
            drifted = True
        if drifted and primary is None:
            raise RuntimeError('V36 frozen fixture/helper/contract changed during qualification')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        raise
