"""Resource-free IDOR launcher contracts; constructed evidence is not qualification."""
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
SPEC = importlib.util.spec_from_file_location('idor_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class IdorBrowserLauncher(unittest.TestCase):
    def receipt(self):
        return dict.fromkeys(L.IDOR_FLAGS, True) | dict(scope=L.IDOR_SCOPE,
            actorCalls=8, judgeCalls=2, roleTurns=4, genuineCredit=2, errors=[])

    def cart_v10_receipt(self):
        return dict.fromkeys(L.IDOR_CART_V10_FLAGS, True) | dict(scope=L.IDOR_CART_V10_SCOPE,
            actorCalls=4, judgeCalls=1, roleTurns=2, genuineCredit=1, errors=[])

    def save(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path

    def test_frozen_producer_contract(self):
        for name, expected in [(L.IDOR_TEST, L.IDOR_TEST_SHA256),
                               (L.IDOR_HELPER, L.IDOR_HELPER_SHA256),
                               (L.IDOR_CONTRACT, L.IDOR_CONTRACT_SHA256)]:
            self.assertEqual(L.digest(ROOT / name), expected)
        source = (ROOT / L.IDOR_HELPER).read_text()
        flags = source.split('const FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), L.IDOR_FLAGS)
        self.assertIn('const SCOPE = ' + repr(L.IDOR_SCOPE) + ';', source)
        producer = (ROOT / L.IDOR_TEST).read_text()
        self.assertIn("test(TEST_TITLE,", producer)
        self.assertIn(": '" + L.IDOR_ASSERTION + "'", producer)
        cart_flags = producer.split('const V10_BROWSER_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + cart_flags + ']')), L.IDOR_CART_V10_FLAGS)
        self.assertIn('const V10_BROWSER_SCOPE = ' + repr(L.IDOR_CART_V10_SCOPE) + ';', producer)
        self.assertIn("? '" + L.IDOR_CART_V10_ASSERTION + "'", producer)
        self.assertIn("const V10_ONLY_FLAG = 'SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY'", producer)
        self.assertEqual(L.digest(ROOT / L.IDOR_CART_V10_CONTRACT), L.IDOR_CART_V10_CONTRACT_SHA256)

    def test_closed_receipt_and_physical_budgets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            self.assertEqual(L.idor_receipt(self.save(path, self.receipt())), self.receipt())
            for change in [dict(actorCalls=7), dict(actorCalls=11), dict(judgeCalls=1),
                           dict(judgeCalls=5), dict(roleTurns=3), dict(genuineCredit=1),
                           dict(fixtureCleaned=False), dict(errors=['failure']), dict(extra=True),
                           dict(actorCalls=True)]:
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    L.idor_receipt(self.save(path, self.receipt() | change))
            for flag in L.IDOR_FLAGS:
                row = self.receipt(); del row[flag]
                with self.assertRaises(RuntimeError): L.idor_receipt(self.save(path, row))
            cart = self.cart_v10_receipt()
            self.assertEqual(L.idor_receipt(self.save(path, cart), cart_v10_only=True), cart)
            with self.assertRaises(RuntimeError): L.idor_receipt(self.save(path, cart))
            with self.assertRaises(RuntimeError): L.idor_receipt(self.save(path, self.receipt()), cart_v10_only=True)
            for change in [dict(actorCalls=3), dict(actorCalls=6), dict(judgeCalls=0),
                           dict(judgeCalls=3), dict(roleTurns=4), dict(genuineCredit=2),
                           dict(fixtureCleaned=False), dict(errors=['failure']), dict(extra=True)]:
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    L.idor_receipt(self.save(path, cart | change), cart_v10_only=True)

    def capture(self):
        request = json.dumps({'model': L.OLLAMA_MODEL, 'messages': [], 'format': {}}, separators=(',', ':'))
        response = json.dumps({'message': {'content': 'original controlled response'}}, separators=(',', ':')) + '\n'
        calls = []
        for index in range(10):
            row = dict(index=index + 1, model=L.OLLAMA_MODEL, kind='actor' if index < 8 else 'judge',
                status=200, responseComplete=True, responseCaptureTruncated=False,
                terminalReason='end', responseObservedBytes=len(response.encode()))
            for name, text in [('request', request), ('response', response)]:
                row[name] = text; row[name + 'Bytes'] = len(text.encode())
                row[name + 'Sha256'] = hashlib.sha256(text.encode()).hexdigest()
            calls.append(row)
        transcripts = []
        for objective in ['ss_idor_cart_delete', 'ss_idor_order_status_disclosure']:
            transcripts.append(dict(complete=True, failure=None, qualification=False,
                kind='adapter-level-diagnostic', header={'rubric': {'objectiveId': objective}},
                calls=[dict(transport='returned', disposition='accepted',
                    request={'method': 'chat', 'input': [], 'schema': {}},
                    response='original controlled response',
                    responseSha256=hashlib.sha256(b'original controlled response').hexdigest(),
                    metadata=dict(provider='ollama', model=L.OLLAMA_MODEL, mocked=False, fallback=False))]))
        return dict(model=L.OLLAMA_MODEL, digest='a' * 64, calls=calls,
            judgePackets=transcripts, requests=[dict(method='POST', path='/agents/customer/idor/chat') for _ in range(4)],
            pageErrors=[], browserDiagnostic=None, browserScreenshot=None)

    def test_original_wire_capture_is_joined_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wire.json'; original = self.capture()
            self.assertEqual(L.idor_capture(self.save(path, original), self.receipt(), 'a' * 64), L.digest(path))
            mutations = [lambda v: v['calls'][0].update(responseSha256='0' * 64),
                         lambda v: v['calls'][0].update(responseComplete=False),
                         lambda v: v['calls'][0].update(kind='judge'),
                         lambda v: v['judgePackets'][0]['calls'][0].update(response='substituted'),
                         lambda v: v['judgePackets'][0]['calls'][0]['metadata'].update(mocked=True),
                         lambda v: v['judgePackets'].reverse(),
                         lambda v: v['requests'].pop(), lambda v: v.update(extra=True),
                         lambda v: v.update(browserScreenshot='/tmp/forged.png'),
                         lambda v: v.update(browserDiagnostic={'stage':'failed'})]
            for mutate in mutations:
                value = copy.deepcopy(original); mutate(value)
                with self.assertRaises(RuntimeError):
                    L.idor_capture(self.save(path, value), self.receipt(), 'a' * 64)

    def test_v10_original_capture_has_one_cart_judge_packet_and_two_turns(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wire.json'
            original = self.capture()
            original['calls'] = [*original['calls'][:4], original['calls'][8]]
            for index, call in enumerate(original['calls'], 1): call['index'] = index
            original['judgePackets'] = original['judgePackets'][:1]
            original['requests'] = original['requests'][:2]
            cart = self.cart_v10_receipt()
            self.assertEqual(L.idor_capture(self.save(path, original), cart, 'a' * 64,
                objectives=('ss_idor_cart_delete',)), L.digest(path))
            for mutate in (lambda v: v['judgePackets'].append(copy.deepcopy(v['judgePackets'][0])),
                           lambda v: v['requests'].append(copy.deepcopy(v['requests'][0])),
                           lambda v: v['calls'][0].update(kind='judge')):
                value = copy.deepcopy(original); mutate(value)
                with self.assertRaises(RuntimeError):
                    L.idor_capture(self.save(path, value), cart, 'a' * 64,
                        objectives=('ss_idor_cart_delete',))

    def test_real_dispatch_uses_four_stores_and_exclusive_environment(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test).startswith("args.cohort in ('standalone-actor', 'standalone-assessment'")
            and any(isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                    and child.func.id == 'create_store' for child in ast.walk(n)))
        stores = []
        def create(*args):
            stores.append(args[-1]); return dict(runtime='runtime-' + args[-1], migration='migration-' + args[-1])
        context = dict(vars(L), args=SimpleNamespace(cohort=L.IDOR_BROWSER), clean={},
                       captured_id='owned', port=15432, nonce='a' * 12, create_store=create)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<stores>', 'exec'), context)
        self.assertEqual(stores, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        stores.clear(); context['args'] = SimpleNamespace(cohort=L.IDOR_CART_V10_BROWSER)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<stores>', 'exec'), context)
        self.assertEqual(stores, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        env_branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == 'args.cohort in IDOR_BROWSER_COHORTS'
            and any(isinstance(child, ast.Constant) and child.value == 'SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE'
                    for child in ast.walk(n)) is False
            and any(isinstance(child, ast.keyword) and child.arg == 'SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE'
                    for child in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        context.update(env={'SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY':'1'}, source=ROOT,
            args=SimpleNamespace(cohort=L.IDOR_BROWSER, browser='/owned/browser'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body, type_ignores=[])), '<env>', 'exec'), context)
        self.assertEqual(context['env']['SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE'], '1')
        self.assertNotIn('SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY', context['env'])
        urls = {k: v for k, v in context['env'].items() if k.startswith('PG_')}
        self.assertEqual(len(urls), 8)
        self.assertTrue(all(k.startswith('PG_SECURESHOP_CUSTOMER_IDOR_LESSON_') for k in urls))
        context.update(env={}, args=SimpleNamespace(cohort=L.IDOR_CART_V10_BROWSER, browser='/owned/browser'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body, type_ignores=[])), '<env>', 'exec'), context)
        self.assertEqual(context['env']['SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY'], '1')
        self.assertEqual(len([k for k in context['env'] if k.startswith('PG_')]), 8)

    def test_snapshot_and_profile_cleanup(self):
        with patch.object(L, 'dependency_inventory', return_value={}):
            pins = L.source_snapshot(ROOT, '/unused-node', L.IDOR_BROWSER, browser_root=ROOT)['sourcePins']
            cart_pins = L.source_snapshot(ROOT, '/unused-node', L.IDOR_CART_V10_BROWSER, browser_root=ROOT)['sourcePins']
        for name in [L.IDOR_TEST, L.IDOR_HELPER, L.IDOR_CONTRACT, L.IDOR_LAUNCHER_TEST,
                     'tests/postgres/secureshopMailActualTransport.js',
                     'server/services/secureshopBoundIdorLessonChat.js']:
            self.assertIn(name, pins)
            self.assertIn(name, cart_pins)
        self.assertNotIn(L.IDOR_CART_V10_CONTRACT, pins)
        self.assertIn(L.IDOR_CART_V10_CONTRACT, cart_pins)
        self.assertNotIn(L.REVIEW_INJECTION_TEST, pins)
        with tempfile.TemporaryDirectory() as folder, patch.object(L.subprocess, 'run',
                return_value=SimpleNamespace(stdout='')):
            root = Path(folder); (root / 'tmp').mkdir()
            self.assertTrue(all(L.standalone_browser_cleanup_state(root).values()))
            (root / 'tmp' / 'owasp-ai-goat-customer-idor-browser-owned').mkdir()
            self.assertFalse(L.standalone_browser_cleanup_state(root)['browserProfilesAbsent'])


if __name__ == '__main__': unittest.main()
