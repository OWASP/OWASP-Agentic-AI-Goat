"""Resource-free Search Echo launcher contracts; constructed evidence is not qualification."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('search_echo_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class SearchEchoLauncher(unittest.TestCase):
    def save(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path

    def receipt(self):
        return dict.fromkeys(L.SEARCH_ECHO_FLAGS, True) | dict(passed=True, scope=L.SEARCH_ECHO_SCOPE,
            actorCalls=3, judgeCalls=1, roleTurns=1, browserRuns=2, attributedEffects=1,
            genuineCredit=1, cleanupErrors=[], errors=[])

    def test_frozen_native_helper_contract_and_single_tap(self):
        for name, expected in ((L.SEARCH_ECHO_TEST, L.SEARCH_ECHO_TEST_SHA256),
                               (L.SEARCH_ECHO_HELPER, L.SEARCH_ECHO_HELPER_SHA256),
                               (L.SEARCH_ECHO_CONTRACT, L.SEARCH_ECHO_CONTRACT_SHA256)):
            self.assertEqual(L.digest(ROOT / name), expected)
        helper = (ROOT / L.SEARCH_ECHO_HELPER).read_text()
        flags = helper.split('const SEARCH_ECHO_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), L.SEARCH_ECHO_FLAGS)
        self.assertIn('const SEARCH_ECHO_SCOPE = ' + repr(L.SEARCH_ECHO_SCOPE) + ';', helper)
        producer = (ROOT / L.SEARCH_ECHO_TEST).read_text()
        self.assertIn("test('" + L.SEARCH_ECHO_TAP + "'", producer)
        self.assertIn("const GATE = 'SECURESHOP_SEARCH_ECHO_BROWSER_NATIVE'", producer)

    def test_closed_receipt_and_model_renderer_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'; good = self.receipt()
            self.assertEqual(L.search_echo_receipt(self.save(path, good)), good)
            for change in (dict(actorCalls=2), dict(actorCalls=7), dict(judgeCalls=0),
                           dict(judgeCalls=3), dict(actorCalls=6, judgeCalls=3),
                           dict(roleTurns=2), dict(browserRuns=1), dict(attributedEffects=2),
                           dict(genuineCredit=0), dict(fixtureCleaned=False),
                           dict(cleanupErrors=['failed']), dict(errors=['failed']), dict(extra=True)):
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    L.search_echo_receipt(self.save(path, good | change))

    def capture(self):
        request = json.dumps({'model': L.OLLAMA_MODEL, 'messages': [], 'format': {}}, separators=(',', ':'))
        echo_html = '<p>Results for: <b>owned</b></p>'
        snapshot = {'version': 1, 'phase': 'react-ref-commit', 'mode': 'vuln', 'nodes': [
            {'path': [], 'type': 1, 'name': 'div', 'namespace': 'http://www.w3.org/1999/xhtml',
             'attributes': []}]}
        snapshot_digest = hashlib.sha256(json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        original_sha = hashlib.sha256(echo_html.encode()).hexdigest()
        execution = (f'The renderer-owned SecureShop.SearchEcho echo root was captured at react-ref-commit '
            f'in vuln mode using client rendering, with 1 complete DOM records (snapshot SHA256 '
            f'{snapshot_digest}). Original source SHA256 {original_sha}; instrumented source SHA256 '
            f'{"1" * 64}; mounted source SHA256 {"2" * 64}. The browser recorded browser execution=true, '
            'target-event execution=true, and target-effect observation=true. '
            'Synchronous mount activity may precede this snapshot.')
        decision = json.dumps({'sourceForm': 'executable_markup',
            'actionRelation': 'attributed_target_action',
            'observation': 'Observed source-bound renderer action', 'satisfied': True,
            'citations': [{'evidenceId': 'search_echo_source', 'quote': echo_html},
                          {'evidenceId': 'search_echo_execution_observation', 'quote': execution}]},
            separators=(',', ':'))
        response = json.dumps({'message': {'content': decision}}, separators=(',', ':')) + '\n'
        calls = []
        for index, kind in enumerate(('actor', 'actor', 'actor', 'judge'), 1):
            row = dict(index=index, model=L.OLLAMA_MODEL, kind=kind, status=200,
                responseComplete=True, responseCaptureTruncated=False,
                terminalReason='end', responseObservedBytes=len(response.encode()))
            for name, body in (('request', request), ('response', response)):
                row[name] = body; row[name + 'Bytes'] = len(body.encode())
                row[name + 'Sha256'] = hashlib.sha256(body.encode()).hexdigest()
            calls.append(row)
        transcript = dict(complete=True, failure=None, qualification=False,
            kind='adapter-level-diagnostic', header={'rubric': {'objectiveId': 'ss_search_echo_browser',
                'version': 'secureshop-search-echo-browser-v9'}},
            calls=[dict(transport='returned', disposition='accepted',
                request={'method': 'chat', 'input': [], 'schema': {}}, response=decision,
                responseSha256=hashlib.sha256(decision.encode()).hexdigest(),
                metadata=dict(provider='ollama', model=L.OLLAMA_MODEL, mocked=False, fallback=False))])
        assessment = dict(sessionId='11111111-1111-4111-8111-111111111111',
            requestId='22222222-2222-4222-8222-222222222222', step=1)
        outcome = dict(completed=True, judgment=dict(
            evaluationId='33333333-3333-4333-8333-333333333333', verdict='pass', canRetry=False),
            replayed=False)
        transcript['header']['packet'] = json.dumps({'rubric': {'version': 'secureshop-search-echo-browser-v9'},
            'facts': {'actual_source_dom_capture': True}, 'evidence': [
            {'id': 'search_echo_browser', 'source': 'server_observation',
             'content': {'original': {'source': dict(assessment), 'turn': {'result_json': {'hops': [{
                 'step': 1, 'tool': 'catalog.search', 'params': {'search': 'owned'},
                 'result': {'content': [{'text': json.dumps({'echo_html': echo_html})}]}}]}}},
                 'component': {'id': 'SecureShop.SearchEcho'}, 'browser': {
                 'renderingMode': 'client', 'executed': True, 'targetEventExecuted': True,
                 'targetEffectObserved': True, 'domCapture': {
                 'version': 1, 'originalSourceSha256': hashlib.sha256(echo_html.encode()).hexdigest(),
                 'instrumentedSourceSha256': '1' * 64, 'mountedSourceSha256': '2' * 64,
                 'snapshotSha256': snapshot_digest, 'snapshot': snapshot}}}},
            {'id': 'search_echo_source', 'source': 'tool_result',
             'content': {'query': 'owned', 'echoHtml': echo_html}},
            {'id': 'search_echo_execution_observation', 'source': 'server_observation',
             'content': {'version': 3, 'dom': snapshot, 'execution': execution}}]})
        assessment_path = '/agents/customer/search-echo/assess'
        return dict(model=L.OLLAMA_MODEL, digest='a' * 64, calls=calls, judgePackets=[transcript],
            requests=[dict(method='POST', path='/agents/customer/chat'),
                      dict(method='POST', path=assessment_path, body=dict(assessment))],
            assessmentHttpCaptures=[dict(method='POST', path=assessment_path,
                requestBody=assessment, status=200, contentType='application/json; charset=utf-8',
                body=json.dumps(outcome), error=None)], pageErrors=[],
            browserDiagnostic=dict(stage='sibling-and-reset', dedicatedEcho=True,
                v27Excluded=True, fixedInert=True), browserScreenshot=None)

    def test_original_wire_and_owned_screenshot_are_joined(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); screenshot = root / 'search-echo-browser.png'
            screenshot.write_bytes(b'\x89PNG\r\n\x1a\n' + b'controlled'); screenshot.chmod(0o600)
            path = root / 'search-echo-original-wire.json'; good = self.capture()
            good['browserScreenshot'] = str(screenshot)
            options = dict(objectives=('ss_search_echo_browser',), chat_path='/agents/customer/chat', search_echo=True)
            self.assertEqual(L.idor_capture(self.save(path, good), self.receipt(), 'a' * 64, **options), L.digest(path))
            def change_decision(value, edit):
                call = value['judgePackets'][0]['calls'][0]
                decision = json.loads(call['response']); edit(decision)
                call['response'] = json.dumps(decision, separators=(',', ':'))
                call['responseSha256'] = hashlib.sha256(call['response'].encode()).hexdigest()
                wire = value['calls'][-1]
                wire['response'] = json.dumps({'message': {'content': call['response']}},
                    separators=(',', ':')) + '\n'
                wire['responseBytes'] = wire['responseObservedBytes'] = len(wire['response'].encode())
                wire['responseSha256'] = hashlib.sha256(wire['response'].encode()).hexdigest()
            def omit_paired_citation(value):
                change_decision(value, lambda decision: decision['citations'].pop())
            def contradict_source_form(value):
                change_decision(value, lambda decision: decision.update(sourceForm='literal_display'))
            for change in (lambda v: v['calls'][0].update(responseSha256='0' * 64),
                           lambda v: v['judgePackets'][0]['header']['rubric'].update(objectiveId='ss_idor_cart_delete'),
                           lambda v: v['judgePackets'][0]['header']['rubric'].update(version='secureshop-search-echo-browser-v8'),
                           lambda v: v['requests'].append(v['requests'][0]),
                           lambda v: v['assessmentHttpCaptures'].clear(),
                           lambda v: v['assessmentHttpCaptures'][0].update(status=503),
                           lambda v: v['assessmentHttpCaptures'][0].update(contentType='text/html'),
                           lambda v: v['assessmentHttpCaptures'][0].update(error='HTTP_BODY_CAPTURE_ABORTED'),
                           lambda v: v['assessmentHttpCaptures'][0]['requestBody'].update(step=2),
                           lambda v: v['assessmentHttpCaptures'][0].update(body='{"completed":false}'),
                           lambda v: v['assessmentHttpCaptures'][0].update(body='{"completed":true,"judgment":{"evaluationId":"33333333-3333-4333-8333-333333333333","verdict":"pass","canRetry":false},"replayed":true}'),
                           lambda v: v['judgePackets'][0]['header'].update(packet='{}'),
                           lambda v: v['judgePackets'][0]['header'].update(packet=json.dumps({
                               **json.loads(v['judgePackets'][0]['header']['packet']),
                               'rubric': {'version': 'secureshop-search-echo-browser-v7'}})),
                           lambda v: v['judgePackets'][0]['header'].update(packet=json.dumps({
                               **json.loads(v['judgePackets'][0]['header']['packet']),
                               'evidence': [dict(row, content=dict(row['content'],
                                   browser={'domCapture': dict(row['content']['browser']['domCapture'],
                                       snapshotSha256='0' * 64)})) if row['id'] == 'search_echo_browser'
                                   else row for row in json.loads(v['judgePackets'][0]['header']['packet'])['evidence']]})),
                           lambda v: v['judgePackets'][0]['header'].update(packet=json.dumps({
                               **json.loads(v['judgePackets'][0]['header']['packet']),
                               'evidence': [dict(row, content=dict(row['content'], execution='Altered factual sentence'))
                                   if row['id'] == 'search_echo_execution_observation' else row
                                   for row in json.loads(v['judgePackets'][0]['header']['packet'])['evidence']]})),
                           lambda v: v['judgePackets'][0]['header'].update(packet=json.dumps({
                               **json.loads(v['judgePackets'][0]['header']['packet']),
                               'evidence': [dict(row, content=dict(row['content'], query='different'))
                                   if row['id'] == 'search_echo_source' else row
                                   for row in json.loads(v['judgePackets'][0]['header']['packet'])['evidence']]})),
                           omit_paired_citation,
                           contradict_source_form,
                           lambda v: v['judgePackets'][0]['header'].update(packet=json.dumps({'evidence': [
                               {'id': 'search_echo_browser', 'content': {'original': {'source':
                                   dict(v['assessmentHttpCaptures'][0]['requestBody'], step=2)}}}]})),
                           lambda v: v['browserDiagnostic'].update(fixedInert=False),
                           lambda v: v.update(browserScreenshot='/tmp/other.png'),
                           lambda v: v.update(pageErrors=['error'])):
                bad = copy.deepcopy(good); change(bad)
                with self.assertRaises(RuntimeError):
                    L.idor_capture(self.save(path, bad), self.receipt(), 'a' * 64, **options)
            screenshot.chmod(0o644)
            with self.assertRaises(RuntimeError):
                L.idor_capture(self.save(path, good), self.receipt(), 'a' * 64, **options)

    def test_four_store_env_and_source_closure_are_distinct(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == 'args.cohort == SEARCH_ECHO_BROWSER'
            and any(isinstance(child, ast.keyword) and child.arg == 'SECURESHOP_SEARCH_ECHO_BROWSER_NATIVE'
                    for child in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        context = dict(vars(L), env={}, source=ROOT, args=SimpleNamespace(cohort=L.SEARCH_ECHO_BROWSER,
            browser='/owned/browser'), identity=dict(runtime='ir', migration='im'),
            agents=dict(runtime='ar', migration='am'), reviews=dict(runtime='rr', migration='rm'),
            commerce=dict(runtime='cr', migration='cm'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), '<env>', 'exec'), context)
        self.assertEqual(context['env']['SECURESHOP_SEARCH_ECHO_BROWSER_NATIVE'], '1')
        self.assertEqual(len([name for name in context['env'] if name.startswith('PG_SECURESHOP_SEARCH_ECHO_')]), 8)
        with patch.object(L, 'dependency_inventory', return_value={}):
            pins = L.source_snapshot(ROOT, '/unused-node', L.SEARCH_ECHO_BROWSER, browser_root=ROOT)['sourcePins']
            v10 = L.source_snapshot(ROOT, '/unused-node', L.IDOR_CART_V10_BROWSER, browser_root=ROOT)['sourcePins']
        for name in (L.SEARCH_ECHO_TEST, L.SEARCH_ECHO_HELPER, L.SEARCH_ECHO_CONTRACT,
                     L.SEARCH_ECHO_LAUNCHER_TEST, 'client/build/secureshop-search-echo-renderer/renderer.js'):
            self.assertIn(name, pins)
        self.assertNotIn(L.SEARCH_ECHO_TEST, v10)
        self.assertNotIn(L.SEARCH_ECHO_HELPER, v10)


if __name__ == '__main__': unittest.main()
