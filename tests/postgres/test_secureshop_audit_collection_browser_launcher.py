"""Offline contract checks for the bounded V36 browser adapter."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('v36_launcher', HERE / 'run-secureshop-audit-collection-browser.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class V36LauncherContract(unittest.TestCase):
    def test_browser_opt_in_and_direct_node_command_are_exact(self):
        argv = ['--cohort', L.COHORT, '--v36-test-no-sandbox']
        self.assertEqual(L.extract_browser_opt_in(argv), (['--cohort', L.COHORT], True))
        self.assertEqual(L.extract_browser_opt_in(['--cohort', L.COHORT]),
                         (['--cohort', L.COHORT], False))
        with self.assertRaises(RuntimeError):
            L.extract_browser_opt_in(argv + ['--v36-test-no-sandbox'])
        parsed = SimpleNamespace(node='/owned/node')
        expected = [parsed.node, '--test', '--test-reporter=tap', '--test-concurrency=1', L.TEST]
        self.assertEqual(L.direct_v36_command(expected, parsed),
                         [parsed.node, '--test-reporter=tap', L.TEST])
        for changed in (expected[:-1], [parsed.node, '--test', L.TEST],
                        [parsed.node, '--test', '--test-reporter=tap', '--test-concurrency=2', L.TEST],
                        expected + ['another.test.js']):
            with self.assertRaises(RuntimeError):
                L.direct_v36_command(changed, parsed)

    def test_browser_signal_requires_opaque_independent_live_capture(self):
        parent_pid, browser_pid = 4321, 5678
        parent = SimpleNamespace(pid=parent_pid, ppid=os.getpid(), uid=os.getuid(),
            ruid=os.getuid(), pgid=parent_pid, start_sec=10, start_usec=20, status=0)
        browser = SimpleNamespace(pid=browser_pid, ppid=parent_pid, uid=os.getuid(),
            ruid=os.getuid(), pgid=browser_pid, start_sec=30, start_usec=40, status=0)
        profile = '/owned/run/runtime/tmp/owasp-ai-goat-admin-audit-jobs-controlled'
        class Api:
            def identity(self, pid):
                return {parent_pid: parent, browser_pid: browser}.get(pid)
            def arguments(self, pid):
                return ['/owned/browser', f'--user-data-dir={profile}']
        record = {'pid': browser_pid, 'parentPid': parent_pid, 'uid': os.getuid(),
            'pgid': browser_pid, 'sessionId': browser_pid, 'birth': [30, 40],
            'executablePath': '/owned/browser'}
        sent = []
        with self.assertRaisesRegex(RuntimeError, 'journal-only'):
            L.retire_live_v36(record, api=Api(), killpg=lambda *args: sent.append(args))
        self.assertEqual(sent, [])
        captured = L.capture_live_v36(record, (10, 20), Path('/owned/run/runtime'),
                                      api=Api(), getsid=lambda _: browser_pid)
        self.assertIsInstance(captured, L.CapturedV36)
        self.assertEqual(captured.profile, profile)
        with self.assertRaises(RuntimeError):
            L.capture_live_v36(record, (10, 21), Path('/owned/run/runtime'),
                               api=Api(), getsid=lambda _: browser_pid)
        with self.assertRaises(RuntimeError):
            L.capture_live_v36(record, (10, 20), Path('/owned/other/runtime'),
                               api=Api(), getsid=lambda _: browser_pid)
    def test_frozen_sources_and_closed_scope(self):
        self.assertEqual(L.digest(ROOT / L.TEST), L.TEST_SHA256)
        self.assertEqual(L.digest(ROOT / L.HELPER), L.HELPER_SHA256)
        self.assertEqual(L.digest(ROOT / L.CONTRACT), L.CONTRACT_SHA256)
        self.assertEqual(L.CONTEXT, '32768')
        self.assertIn('canonical Judge', L.SCOPE)

    def test_changed_shared_fixture_is_rejected_before_resource_import(self):
        original_digest = L.digest
        with patch.object(L, 'digest', side_effect=lambda path:
                '0' * 64 if Path(path) == ROOT / L.TEST else original_digest(path)), \
                patch.object(L, 'load_main', side_effect=AssertionError('resource import must not occur')):
            with self.assertRaisesRegex(RuntimeError, 'Frozen V36 source pin mismatch'):
                L.main(['--cohort', L.COHORT, '--plan'])

    def test_collection_caps_remain_original_after_v15_only_browser_branch(self):
        fixture = (ROOT / L.TEST).read_text()
        helper = (ROOT / L.HELPER).read_text()
        worker = (ROOT / 'server/agent-runtime/workers/secureshopAuditWorker.js').read_text()
        L.validate_context_contract(fixture, helper)
        self.assertIn('capture.seedIds=await append(c,scope,principal.user,128);', helper)
        self.assertIn('const graphSignal = AbortSignal.timeout(taskRequestVersion===2?graphTimeoutMs:90000);', worker)
        self.assertIn("createSecureShopAuditTiming({profile:'unbounded'})", fixture)
        self.assertIn('timeout: actorWireTimeoutMs(collectionTiming)', fixture)
        self.assertIn('timeout:COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS', helper)
        self.assertIn("const sceneAdmission = v15 ? require('../fixtures/secureshopSceneAuditBrowserAdmission') : null;", fixture)
        self.assertIn(": collection ? collectionBrowserArgs(process.env, { workspace, evidencePath, profile, origin })", fixture)
        self.assertIn("if (collection && process.env.SECURESHOP_AUDIT_COLLECTION_TEST_NO_SANDBOX === '1')", fixture)

    def test_control_plane_snapshot_includes_adapter_outer_route_and_ownership_helpers(self):
        before = L.frozen_source_digests()
        required = {L.TEST, L.HELPER, L.CONTRACT,
                    'tests/postgres/run-secureshop-audit-collection-browser.py',
                    'tests/postgres/run_audit_collection_with_inspector.py',
                    'tests/postgres/secureshop_bound_browser_ownership.py',
                    'tests/postgres/darwin_process_inventory.py',
                    'tests/fixtures/secureshopDarwinBrowserBirth.js',
                    'tasks/run-in-repository.sh'}
        self.assertTrue(required.issubset(before))
        control = ROOT / 'tests/postgres/secureshop_bound_browser_ownership.py'
        original_digest = L.digest
        with patch.object(L, 'digest', side_effect=lambda path:
                '0' * 64 if Path(path) == control else original_digest(path)):
            after = L.frozen_source_digests()
        self.assertNotEqual(before, after)
        self.assertEqual({key for key in before if before[key] != after[key]},
                         {'tests/postgres/secureshop_bound_browser_ownership.py'})

    def test_context_mismatch_rejected_before_shared_resource_import(self):
        fixture = (ROOT / L.TEST).read_text()
        helper = (ROOT / L.HELPER).read_text()
        L.validate_context_contract(fixture, helper)
        for bad_fixture, bad_helper in ((fixture.replace("OLLAMA_CONTEXT_WINDOW, '32768'", "OLLAMA_CONTEXT_WINDOW, '65536'"), helper),
                                         (fixture, helper.replace('const CONTEXT_WINDOW = 32768;', 'const CONTEXT_WINDOW = 65536;')),
                                         ('', helper), (fixture, '')):
            with self.assertRaisesRegex(RuntimeError, 'before provisioning'):
                L.validate_context_contract(bad_fixture, bad_helper)
        for bad_fixture, bad_helper in ((fixture.replace("createSecureShopAuditTiming({profile:'unbounded'})", 'createSecureShopAuditTiming()'), helper),
                                         (fixture.replace('collectionTiming ? 180000 : 120000', 'collectionTiming ? 120000 : 120000'), helper),
                                         (fixture, helper.replace('const COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS = 320000;', 'const COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS = 240000;'))):
            with self.assertRaisesRegex(RuntimeError, 'before provisioning'):
                L.validate_context_contract(bad_fixture, bad_helper)
        expected = {ROOT / L.TEST: L.TEST_SHA256, ROOT / L.HELPER: L.HELPER_SHA256, ROOT / L.CONTRACT: L.CONTRACT_SHA256}
        with patch.object(L, 'digest', side_effect=lambda path: expected[path]), \
                patch.object(Path, 'read_text', side_effect=[fixture.replace("OLLAMA_CONTEXT_WINDOW, '32768'", "OLLAMA_CONTEXT_WINDOW, '65536'"), helper]), \
                patch.object(L, 'load_main', side_effect=AssertionError('resource import must not occur')):
            with self.assertRaisesRegex(RuntimeError, 'before provisioning'):
                L.main(['--cohort', L.COHORT, '--plan'])

    def test_plan_is_nonallocating_and_selects_collection(self):
        main = L.load_main()
        argv = ['--cohort', L.COHORT, '--main-workspace', str(ROOT), '--node', '/pinned/node',
                '--docker', '/pinned/docker', '--docker-sha256', 'a' * 64,
                '--docker-host', main.EXPECTED_DOCKER_HOST, '--docker-daemon', 'owned',
                '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(L, 'load_main', return_value=main), patch.object(main, 'validate_static'), patch.object(main, 'subprocess') as subprocess_mock, contextlib.redirect_stdout(output):
            self.assertEqual(L.main(argv), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['cohort'], L.COHORT)
        self.assertEqual(value['sharedProvisioningCohort'], L.MAIN_COHORT)
        self.assertEqual(value['contextWindow'], 32768)
        self.assertTrue(value['separateAuditSqlCluster'])
        self.assertFalse(value['nativeStarted'])
        subprocess_mock.Popen.assert_not_called()

    def _receipt(self):
        value = {flag: True for flag in L.FLAGS}
        value.update(scope=L.SCOPE, summaryRunId='01234567-89ab-cdef-0123-456789abcdef',
                     rowCount=128, sourceBytes=131073, actorCalls=2, judgeCalls=1,
                     promptEvalCount=1, errors=[])
        return value

    def test_closed_receipt_validator_rejects_tampering(self):
        valid = self._receipt()
        self.assertIs(L.assert_closed_receipt(valid), valid)
        mutations = []
        extra = copy.deepcopy(valid); extra['unexpected'] = True; mutations.append(extra)
        for flag in L.FLAGS:
            changed = copy.deepcopy(valid); changed[flag] = False; mutations.append(changed)
        for key, value in (('scope', 'wrong'), ('summaryRunId', 'not-a-uuid'),
                           ('rowCount', 100), ('sourceBytes', 131072), ('actorCalls', 29),
                           ('judgeCalls', 0), ('promptEvalCount', 32768), ('errors', ['leak'])):
            changed = copy.deepcopy(valid); changed[key] = value; mutations.append(changed)
        for candidate in mutations:
            with self.assertRaises(RuntimeError):
                L.assert_closed_receipt(candidate)

    def test_original_evidence_validator_requires_wire_and_judge_joins(self):
        receipt = self._receipt()
        request = {'limit': 5000, 'request_id': 'req-1', 'session_id': 'session-1'}
        fixed_request = {'limit': 5000, 'request_id': 'req-fixed', 'session_id': 'session-1'}
        response = {'summary': 'owned summary', 'replayed': False}
        replay = {'summary': 'owned summary', 'replayed': True}
        wire = {'path': '/api/chat', 'status': 200, 'complete': True,
                'request': {'model': L.MODEL, 'options': {'num_ctx': 32768, 'num_predict': 256},
                            'messages': [{'role': 'user', 'content': 'Tool observation for completed call x (tool result):\nowned observation'}]},
                'responseText': json.dumps({'model': L.MODEL, 'message': {'role': 'assistant', 'content': '{"answer":"owned summary"}'},
                                            'done': True, 'done_reason': 'stop', 'prompt_eval_count': 1, 'eval_count': 32})}
        value = {'scope': L.SCOPE, 'artifacts': {'messages': [{'role':'tool','content':'owned observation'}]}, 'physical': [
            {'status': 200, 'request': request, 'body': response},
            {'status': 400, 'request': fixed_request, 'body': {'error': 'Fixed audit summaries accept at most 100 events'}}],
            'http': [{'path': '/admin/audit/unbounded-summary', 'request': request, 'status': 200},
                     {'path': '/admin/audit/unbounded-summary', 'request': request, 'status': 200}],
            'replay': {'status': 200, 'body': replay},
            'wires': [wire], 'errors': [{'requestId': 'req-1', 'code': 'CONVERSATION_UNAVAILABLE'},
                                       {'requestId': 'req-fixed', 'code': 'AUDIT_FIXED_COUNT_LIMIT'}], 'failure': None,
            'judgeResults': [{'result': {'runId': receipt['summaryRunId']}}],
            'judgeTranscripts': [{'complete': True, 'header': {'runId': receipt['summaryRunId']}}]}
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary); private.chmod(0o700)
            path = private / L.ORIGINAL_EVIDENCE
            path.write_text(json.dumps(value)); path.chmod(0o600)
            self.assertTrue(L.validate_original_evidence(path, receipt)['validated'])
            oversized_context = copy.deepcopy(value)
            oversized_context['wires'][0]['request']['options']['num_ctx'] = 65536
            path.unlink(); path.write_text(json.dumps(oversized_context)); path.chmod(0o600)
            with self.assertRaises(RuntimeError):
                L.validate_original_evidence(path, receipt)
            for field, bad in (('done_reason','length'),('prompt_eval_count',32512),('eval_count',257),('eval_count',None),('prompt_eval_count',None)):
                broken = copy.deepcopy(value)
                terminal = json.loads(broken['wires'][0]['responseText']); terminal[field] = bad
                broken['wires'][0]['responseText'] = json.dumps(terminal)
                path.unlink(); path.write_text(json.dumps(broken)); path.chmod(0o600)
                with self.subTest(field=field,bad=bad), self.assertRaises(RuntimeError):
                    L.validate_original_evidence(path, receipt)
            repaired = copy.deepcopy(value)
            first = repaired['wires'][0]
            terminal = json.loads(first['responseText']); terminal['message']['content'] = 'invalid json'
            first['responseText'] = json.dumps(terminal)
            second = copy.deepcopy(wire); second['request']['options']['num_predict'] = 224
            second['request']['messages'] += [
                {'role':'assistant','content':'invalid json'},
                {'role':'user','content':'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.'}]
            repaired['wires'].append(second)
            path.unlink(); path.write_text(json.dumps(repaired)); path.chmod(0o600)
            self.assertTrue(L.validate_original_evidence(path, receipt)['validated'])
            for attempt,field,bad in ((0,'eval_count',300),(0,'eval_count',None),(0,'done_reason','length'),(1,'eval_count',225)):
                broken=copy.deepcopy(repaired); terminal=json.loads(broken['wires'][attempt]['responseText']);terminal[field]=bad
                broken['wires'][attempt]['responseText']=json.dumps(terminal)
                path.unlink();path.write_text(json.dumps(broken));path.chmod(0o600)
                with self.subTest(attempt=attempt,field=field,bad=bad),self.assertRaises(RuntimeError):L.validate_original_evidence(path,receipt)
            broken=copy.deepcopy(repaired);broken['wires'][1]['request']['options']['num_predict']=256
            path.unlink();path.write_text(json.dumps(broken));path.chmod(0o600)
            with self.assertRaises(RuntimeError):L.validate_original_evidence(path,receipt)
            for field in ('wires', 'judgeResults', 'failure'):
                broken = copy.deepcopy(value)
                broken[field] = [] if field != 'failure' else {'stage': 'bad'}
                path.unlink(); path.write_text(json.dumps(broken)); path.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    L.validate_original_evidence(path, receipt)

if __name__ == '__main__':
    unittest.main()
