"""Resource-free coupon launcher contracts; constructed evidence is not qualification."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('coupon_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class CouponBrowserLauncher(unittest.TestCase):
    def receipt(self):
        return dict.fromkeys(L.COUPON_FLAGS, True) | dict(scope=L.COUPON_SCOPE,
            actorCalls=4, judgeCalls=1, roleTurns=2, confirmationPosts=2, genuineCredit=1, errors=[])

    def save(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path

    def test_frozen_producer_contract(self):
        for name, expected in [(L.COUPON_TEST, L.COUPON_TEST_SHA256),
                               (L.COUPON_HELPER, L.COUPON_HELPER_SHA256),
                               (L.COUPON_CONTRACT, L.COUPON_CONTRACT_SHA256)]:
            self.assertEqual(L.digest(ROOT / name), expected)
        source = (ROOT / L.COUPON_HELPER).read_text()
        flags = source.split('const FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), L.COUPON_FLAGS)
        self.assertIn('const SCOPE = ' + repr(L.COUPON_SCOPE) + ';', source)
        self.assertIn("test('" + L.COUPON_ASSERTION + "'", (ROOT / L.COUPON_TEST).read_text())

    def test_closed_receipt_and_physical_budgets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            self.assertEqual(L.coupon_receipt(self.save(path, self.receipt())), self.receipt())
            for change in [dict(actorCalls=3), dict(actorCalls=9), dict(judgeCalls=0),
                           dict(judgeCalls=4), dict(roleTurns=3), dict(genuineCredit=2), dict(confirmationPosts=1), dict(actorCalls=8, judgeCalls=2),
                           dict(fixtureCleaned=False), dict(errors=['failure']), dict(extra=True),
                           dict(actorCalls=True)]:
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    L.coupon_receipt(self.save(path, self.receipt() | change))
            for flag in L.COUPON_FLAGS:
                row = self.receipt(); del row[flag]
                with self.assertRaises(RuntimeError): L.coupon_receipt(self.save(path, row))

    def capture(self):
        request = json.dumps({'model': L.OLLAMA_MODEL, 'messages': [], 'format': {}}, separators=(',', ':'))
        response = json.dumps({'message': {'content': 'original controlled response'}}, separators=(',', ':')) + '\n'
        calls = []
        for index in range(5):
            row = dict(index=index + 1, model=L.OLLAMA_MODEL, kind='actor' if index < 4 else 'judge',
                status=200, responseComplete=True, responseCaptureTruncated=False,
                terminalReason='end', responseObservedBytes=len(response.encode()))
            for name, text in [('request', request), ('response', response)]:
                row[name] = text; row[name + 'Bytes'] = len(text.encode())
                row[name + 'Sha256'] = hashlib.sha256(text.encode()).hexdigest()
            calls.append(row)
        transcripts = []
        for objective in ['ss_sqli_coupon']:
            transcripts.append(dict(complete=True, failure=None, qualification=False,
                kind='adapter-level-diagnostic', header={'rubric': {'objectiveId': objective}},
                calls=[dict(transport='returned', disposition='accepted',
                    request={'method': 'chat', 'input': [], 'schema': {}},
                    response='original controlled response',
                    responseSha256=hashlib.sha256(b'original controlled response').hexdigest(),
                    metadata=dict(provider='ollama', model=L.OLLAMA_MODEL, mocked=False, fallback=False))]))
        return dict(model=L.OLLAMA_MODEL, digest='a' * 64, calls=calls,
            judgePackets=transcripts, requests=[dict(method='POST', path='/agents/customer/chat') for _ in range(2)] +
                [dict(method='POST', path='/agents/customer/coupons/' + action,
                      body=dict(sessionId='11111111-1111-4111-8111-111111111111',
                                requestId='22222222-2222-4222-8222-222222222222',
                                proposalId='33333333-3333-4333-8333-333333333333'))
                 for action in ['confirm', 'confirm', 'assessment-retry']], pageErrors=[])

    def test_original_wire_capture_is_joined_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wire.json'; original = self.capture()
            self.assertEqual(L.coupon_capture(self.save(path, original), self.receipt(), 'a' * 64), L.digest(path))
            mutations = [lambda v: v['calls'][0].update(responseSha256='0' * 64),
                         lambda v: v['calls'][0].update(responseComplete=False),
                         lambda v: v['calls'][0].update(kind='judge'),
                         lambda v: v['judgePackets'][0]['calls'][0].update(response='substituted'),
                         lambda v: v['judgePackets'][0]['calls'][0]['metadata'].update(mocked=True),
                         lambda v: v['judgePackets'][0]['header']['rubric'].update(objectiveId='foreign'),
                         lambda v: v['requests'].pop(), lambda v: v.update(extra=True),
                         lambda v: v['pageErrors'].append('browser failed'),
                         lambda v: v.update(browserDiagnostic=None)]
            for mutate in mutations:
                value = copy.deepcopy(original); mutate(value)
                with self.assertRaises(RuntimeError):
                    L.coupon_capture(self.save(path, value), self.receipt(), 'a' * 64)

    def test_real_dispatch_uses_four_stores_and_exclusive_environment(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test).startswith("args.cohort in ('standalone-actor', 'standalone-assessment'")
            and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                    and child.func.id == 'create_store' for child in ast.walk(n)))
        stores = []
        def create(*args):
            stores.append(args[-1]); return dict(runtime='runtime-' + args[-1], migration='migration-' + args[-1])
        context = dict(vars(L), args=SimpleNamespace(cohort=L.COUPON_BROWSER), clean={},
                       captured_id='owned', port=15432, nonce='a' * 12, create_store=create)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<stores>', 'exec'), context)
        self.assertEqual(stores, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        env_branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == 'args.cohort == COUPON_BROWSER'
            and any(isinstance(child, ast.Constant) and child.value == 'SECURESHOP_CUSTOMER_COUPON_AGENT_BROWSER_NATIVE'
                    for child in ast.walk(n)) is False
            and any(isinstance(child, ast.keyword) and child.arg == 'SECURESHOP_CUSTOMER_COUPON_AGENT_BROWSER_NATIVE'
                    for child in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        context.update(analytics_environment={'SECURESHOP_COUPON_ANALYTICS_OWNER':'012345abcdef'}, env={}, source=ROOT, args=SimpleNamespace(cohort=L.COUPON_BROWSER, browser='/owned/browser'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body, type_ignores=[])), '<env>', 'exec'), context)
        self.assertEqual(context['env']['SECURESHOP_CUSTOMER_COUPON_AGENT_BROWSER_NATIVE'], '1')
        urls = {k: v for k, v in context['env'].items() if k.startswith('PG_')}
        self.assertEqual(len(urls), 8)
        self.assertTrue(all(k.startswith('PG_SECURESHOP_CUSTOMER_COUPON_AGENT_') for k in urls))

    def test_snapshot_and_profile_cleanup(self):
        with patch.object(L, 'dependency_inventory', return_value={}):
            pins = L.source_snapshot(ROOT, '/unused-node', L.COUPON_BROWSER, browser_root=ROOT)['sourcePins']
        for name in [L.COUPON_TEST, L.COUPON_HELPER, L.COUPON_CONTRACT, L.COUPON_LAUNCHER_TEST,
                     'tests/postgres/secureshopMailActualTransport.js',
                     'server/services/secureshopCouponAgentAssessment.js',
                     'tests/postgres/analytics_owned_target.py', 'tests/postgres/test_analytics_owned_target.py',
                     'sidecars/analytics-sql-target/control-migrations/0002_fixed_capability.sql']:
            self.assertIn(name, pins)
        self.assertNotIn(L.REVIEW_INJECTION_TEST, pins)
        with tempfile.TemporaryDirectory() as folder, patch.object(L.subprocess, 'run',
                return_value=SimpleNamespace(stdout='')):
            root = Path(folder); (root / 'tmp').mkdir()
            self.assertTrue(all(L.standalone_browser_cleanup_state(root).values()))
            (root / 'tmp' / 'owasp-ai-goat-customer-coupon-browser-owned').mkdir()
            self.assertFalse(L.standalone_browser_cleanup_state(root)['browserProfilesAbsent'])


if __name__ == '__main__': unittest.main()
