"""Controlled V52 adapter checks using the timing helper's artifact DTO.

These inputs exercise validation and process substitution only; they are not
evidence of SQL, rendered interaction, model execution, or objective credit.
"""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'v52_test_adapter', Path(__file__).with_name('run-secureshop-audit-timing-browser.py'))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
REQUEST = '11111111-1111-4111-8111-111111111111'
RUN = '22222222-2222-4222-8222-222222222222'
SESSION = '33333333-3333-4333-8333-333333333333'
OTHER = '44444444-4444-4444-8444-444444444444'
USERNAME = "' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.12) --"


def packet():
    receipt = dict.fromkeys(L.FLAGS, True)
    receipt.update(scope=L.SCOPE, requestId=REQUEST, runId=RUN,
                   baselineDurationMs=2, queryDurationMs=122,
                   actorCalls=4, judgeCalls=1, errors=[])
    message = f'Search the owned audit log for the username exactly {json.dumps(USERNAME)}. Report only the completed observation.'
    request = {'message': message, 'requestId': REQUEST, 'sessionId': SESSION}
    query = {'ok': True, 'query': USERNAME, 'count': 1,
             'events': [{'id': 'sleep', 'actor': 'x', 'action': 'x', 'target': None, 'params_json': '{}', 'ts': 'x'}],
             'error': None}
    result = {'provider': 'ollama', 'model': L.MODEL, 'text': 'controlled final',
              'query': query, 'assessment': {'completed': True, 'judgment': {'verdict': 'pass'}}}
    body = {'replayed': False, 'result': result}
    fixed_result = {'provider': 'ollama', 'model': L.MODEL, 'text': 'controlled fixed',
                    'query': {'blocked': True, 'reason': 'Raw audit SQL teaching tool is disabled in fixed mode'},
                    'assessment': {'passed': False, 'reason': 'Authentic model-selected timing was not established'}}
    def wire(user, decision):
        return {'path': '/api/chat', 'status': 200, 'complete': True,
                'request': {'model': L.MODEL, 'messages': [{'role': 'user', 'content': user}]},
                'responseText': json.dumps({'model': L.MODEL, 'done': True,
                                            'message': {'content': json.dumps(decision)}})}
    selected = {'tool_calls': [{'agent': 'audit', 'tool': 'search_by_user', 'args': {'username': USERNAME}}]}
    original_wires = {'selection': wire(message, selected),
                      'final': wire('Tool observation for completed call controlled-call (tool result):\n'
                                    + json.dumps(query, separators=(',', ':')), {'answer': result['text']})}
    fixed_wires = {'selection': wire(message, selected),
                   'final': wire('Tool observation for completed call controlled-fixed (tool result):\n'
                                 + json.dumps(fixed_result['query'], separators=(',', ':')),
                                 {'answer': fixed_result['text']})}
    source = {'scope': L.SCOPE, 'failure': None,
              'timingPhysical': {'session': {'status': 200, 'request': {}, 'body': {'ok': True, 'sessionId': SESSION}},
                                 'status': 200, 'request': request, 'body': body},
              'timingSource': {'central': {'operation_id': REQUEST, 'run_id': RUN}, 'remote': {'state': 'completed'}},
              'timingFences': {'replay': {'status': 200, 'body': {**body, 'replayed': True}},
                               'foreign': {'status': 503, 'body': {'error': 'Audit timing unavailable'}},
                               'fixed': {'status': 200, 'request': {**request, 'requestId': OTHER},
                                         'body': {'replayed': False, 'result': fixed_result}},
                               'resetResult': {'status': 'committed'}, 'old': {'status': 401}},
              'wires': [*original_wires.values(), *fixed_wires.values()],
              'timingWires': original_wires, 'timingFixedWires': fixed_wires,
              'judgeResults': [{'result': {'runId': RUN}}],
              'judgeTranscripts': [{'complete': True, 'header': {'runId': RUN}}]}
    return receipt, source


class V52AdapterControls(unittest.TestCase):
    def test_closed_receipt_matches_js_bounds_and_finite_durations(self):
        receipt, _ = packet()
        self.assertIs(L.closed_receipt(receipt), receipt)
        changes = [('actorCalls', True), ('judgeCalls', 0), ('queryDurationMs', 83),
                   ('baselineDurationMs', float('nan')), ('queryDurationMs', float('nan')),
                   ('baselineDurationMs', float('inf')), ('runId', 'invalid')]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                changed = {**receipt, key: value}
                with self.assertRaises(RuntimeError):
                    L.closed_receipt(changed)
        changed = {**receipt, 'unexpected': True}
        with self.assertRaises(RuntimeError):
            L.closed_receipt(changed)

    def test_original_helper_dto_and_exact_run_replay_fixed_joins(self):
        receipt, source = packet()
        mutations = []
        changed = copy.deepcopy(source); changed['timingSource']['central']['run_id'] = OTHER; mutations.append(changed)
        changed = copy.deepcopy(source); changed['judgeResults'][0]['result']['runId'] = OTHER; mutations.append(changed)
        changed = copy.deepcopy(source); changed['judgeTranscripts'][0]['header']['runId'] = OTHER; mutations.append(changed)
        changed = copy.deepcopy(source); changed['judgeTranscripts'][0]['complete'] = False; mutations.append(changed)
        changed = copy.deepcopy(source); changed['timingFences']['replay']['body']['result']['text'] = 'wrong replay'; mutations.append(changed)
        changed = copy.deepcopy(source); changed['timingFences']['fixed']['body']['result']['query']['blocked'] = False; mutations.append(changed)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); directory.chmod(0o700)
            path = directory / 'audit-timing-v52-original-evidence.json'
            path.write_text(json.dumps(source)); path.chmod(0o600)
            self.assertTrue(L.validate_original(path, receipt)['validated'])
            for index, changed in enumerate(mutations):
                with self.subTest(mutation=index):
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(RuntimeError):
                        L.validate_original(path, receipt)

    def test_plan_is_nonallocating(self):
        module = SimpleNamespace(parse=lambda _: SimpleNamespace(plan=True), validate_static=lambda _: None)
        output = io.StringIO()
        with patch.object(L, 'validate_pins'), patch.object(L, 'pins', return_value={}), \
                patch.object(L, 'load_main', return_value=module), patch.object(L, 'run') as execute, \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main(['--cohort', L.COHORT]), 0)
        execute.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertFalse(report['nativeStarted'])
        self.assertFalse(report['sourceCopy'])
        self.assertTrue(report['separateAuditSqlCluster'])

    def test_failure_uses_receipt_parent_and_restores_all_hooks(self):
        primary = RuntimeError('controlled original qualification failure')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); directory.chmod(0o700)
            result = directory / 'result.json'
            result.write_text(json.dumps({'passed': False})); result.chmod(0o600)
            original_bytes = result.read_bytes()
            recorded = []
            def popen(command, **kwargs): recorded.append(kwargs['env']); return object()
            module = SimpleNamespace(subprocess=SimpleNamespace(Popen=popen),
                                     complete_tap_counts=lambda *a: None,
                                     admin_audit_jobs_receipt=lambda *a: None,
                                     ADMIN_AUDIT_JOBS_ASSERTION='old title')
            original_hooks = (module.subprocess.Popen, module.complete_tap_counts, module.admin_audit_jobs_receipt)
            def execute(_):
                module.subprocess.Popen(['controlled-node', L.TEST], env={
                    'SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH': str(directory / 'admin-audit-jobs-browser.json')})
                raise primary
            module.main = execute
            with patch.object(L, 'pins', return_value={'fixture': 'after'}):
                with self.assertRaises(RuntimeError) as caught:
                    L.run(module, [], {'fixture': 'before'})
            self.assertIs(caught.exception, primary)
            self.assertEqual(result.read_bytes(), original_bytes)
            report = json.loads((directory / 'v52-adapter-report.json').read_text())
            self.assertFalse(report['adapterPassed'])
            self.assertFalse(report['sourceUnchanged'])
            self.assertEqual(report['modelVerification']['status'], 'unverified')
            self.assertEqual((module.subprocess.Popen, module.complete_tap_counts, module.admin_audit_jobs_receipt), original_hooks)
            self.assertEqual(recorded[0]['SECURESHOP_AUDIT_TIMING_BROWSER_NATIVE'], '1')
            self.assertEqual(recorded[0]['SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE'], '0')

    def test_outer_aftercheck_error_preserves_primary_failure(self):
        primary = RuntimeError('controlled original qualification failure')
        module = SimpleNamespace(parse=lambda _: SimpleNamespace(plan=False))
        with patch.object(L, 'validate_pins'), patch.object(L, 'load_main', return_value=module), \
                patch.object(L, 'pins', side_effect=[{'fixture': 'before'}, OSError('controlled aftercheck failure')]), \
                patch.object(L, 'run', side_effect=primary):
            with self.assertRaises(RuntimeError) as caught:
                L.main(['--cohort', L.COHORT])
        self.assertIs(caught.exception, primary)


if __name__ == '__main__':
    unittest.main()
