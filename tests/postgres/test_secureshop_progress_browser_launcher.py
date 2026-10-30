"""Controlled launcher contracts only; no rendered/native qualification."""
import ast
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
SPEC = importlib.util.spec_from_file_location('progress_browser_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(L)

class ProgressBrowserLauncher(unittest.TestCase):
    def test_reviewed_producer_and_zero_model_receipt(self):
        for name, expected in [(L.PROGRESS_BROWSER_TEST, L.PROGRESS_BROWSER_TEST_SHA256),
                               (L.PROGRESS_BROWSER_HELPER, L.PROGRESS_BROWSER_HELPER_SHA256),
                               (L.PROGRESS_BROWSER_CONTRACT, L.PROGRESS_BROWSER_CONTRACT_SHA256)]:
            self.assertEqual(L.digest(ROOT / name), expected)
        source = (ROOT / L.PROGRESS_BROWSER_HELPER).read_text()
        raw = source.split('const PROGRESS_RENDERED_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + raw + ']')), L.PROGRESS_BROWSER_FLAGS)
        self.assertIn("test('" + L.PROGRESS_BROWSER_ASSERTION + "'", (ROOT / L.PROGRESS_BROWSER_TEST).read_text())
        row = dict.fromkeys(L.PROGRESS_BROWSER_FLAGS, True) | dict(scope=L.PROGRESS_BROWSER_SCOPE, actorCalls=0, judgeCalls=0, errors=[])
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'receipt.json'
            def check(value):
                target.write_text(json.dumps(value)); target.chmod(0o600)
                return L.progress_browser_receipt(target)
            self.assertEqual(check(row), row)
            for change in [dict(actorCalls=1), dict(judgeCalls=1), dict(actorCalls=False), dict(scope='wrong'),
                           dict(errors=['error']), dict(extra=True)]:
                with self.assertRaises(RuntimeError): check(row | change)
            for flag in L.PROGRESS_BROWSER_FLAGS:
                with self.assertRaises(RuntimeError): check(row | {flag: False})

    def test_actual_four_store_and_non_model_environment_branch(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test).startswith("args.cohort in ('standalone-actor', 'standalone-assessment'")
            and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == 'create_store' for c in ast.walk(n)))
        stores = []
        def create(*args):
            stores.append(args[-1]); return dict(runtime='runtime-' + args[-1], migration='migration-' + args[-1])
        context = dict(vars(L), args=SimpleNamespace(cohort=L.PROGRESS_BROWSER), clean={}, captured_id='owned',
                       port=15432, nonce='a' * 12, create_store=create)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<stores>', 'exec'), context)
        self.assertEqual(stores, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and ast.unparse(n.test) == 'args.cohort == PROGRESS_BROWSER'
            and any(isinstance(c, ast.keyword) and c.arg == 'SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_NATIVE'
                    for c in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        context.update(env={}, source=ROOT, args=SimpleNamespace(cohort=L.PROGRESS_BROWSER, browser='/owned/browser'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), '<env>', 'exec'), context)
        env = context['env']
        self.assertEqual(env['SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_NATIVE'], '1')
        self.assertEqual(len([name for name in env if name.startswith('PG_SECURESHOP_ASSESSMENT_PROGRESS_RENDERED_')]), 8)
        self.assertNotIn('LIVE_OLLAMA_TEST', env)
        self.assertNotIn(L.PROGRESS_BROWSER, L.LIVE_BROWSER_COHORTS)
        self.assertIn(L.PROGRESS_BROWSER, L.STANDALONE_BROWSER_COHORTS)
        self.assertTrue(L.plan_requires_browser(L.PROGRESS_BROWSER))

    def test_current_sources_and_profile_absence(self):
        with patch.object(L, 'dependency_inventory', return_value={}):
            pins = L.source_snapshot(ROOT, '/unused-node', L.PROGRESS_BROWSER, browser_root=ROOT)['sourcePins']
        for name in [L.PROGRESS_BROWSER_TEST, L.PROGRESS_BROWSER_HELPER, L.PROGRESS_BROWSER_CONTRACT,
                     L.PROGRESS_BROWSER_LAUNCHER_TEST, 'db/postgres/seeds/secureshop.json',
                     'server/services/secureshopAssessmentProgress.js', 'client/build/index.html']:
            self.assertIn(name, pins)
        self.assertNotIn(L.COUPON_TEST, pins)
        with tempfile.TemporaryDirectory() as folder, patch.object(L.subprocess, 'run', return_value=SimpleNamespace(stdout='')):
            root = Path(folder); (root / 'tmp').mkdir()
            self.assertTrue(all(L.standalone_browser_cleanup_state(root).values()))
            (root / 'tmp' / 'owasp-ai-goat-progress-rendered-owned').mkdir()
            self.assertFalse(L.standalone_browser_cleanup_state(root)['browserProfilesAbsent'])

if __name__ == '__main__': unittest.main()
