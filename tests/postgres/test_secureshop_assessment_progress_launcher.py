"""Resource-free dispatch/TAP/source checks, not native progress qualification."""
import ast
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('progress_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class AssessmentProgressLauncher(unittest.TestCase):
    def test_exact_one_tap_requires_success_without_skip(self):
        name = L.ASSESSMENT_PROGRESS_ASSERTION
        tap = f'TAP version 13\n# Subtest: {name}\nok 1 - {name}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(L.assessment_progress_tap_counts(tap)['tests'], 1)
        for bad in [tap.replace(name, 'wrong'), tap.replace('ok 1', 'not ok 1'),
                    tap.replace('# skipped 0', '# skipped 1'),
                    tap.replace('# tests 1', '# tests 2').replace('# pass 1', '# pass 2')]:
            with self.assertRaises(RuntimeError): L.assessment_progress_tap_counts(bad)
        self.assertIn("test('" + name + "'", (ROOT / L.ASSESSMENT_PROGRESS_TEST).read_text())
        self.assertIn('no model, Judge or browser qualification', L.ASSESSMENT_PROGRESS_SCOPE)

    def test_actual_allocation_branch_only_creates_identity_with_distinct_roles(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "args.cohort in ('product-admission', 'registered-admin-reset', 'assessment-progress')"
            and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == 'create_store'
                    for c in ast.walk(n)))
        sql = []
        with patch.object(L, 'docker_command', side_effect=lambda *args, **kwargs: sql.append(args[-1])):
            context = dict(vars(L), args=SimpleNamespace(cohort='assessment-progress'), clean={},
                           captured_id='owned', port=15432, nonce='a' * 12)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), '<allocation>', 'exec'), context)
        self.assertEqual(len(sql), 5)
        self.assertIn('CREATE DATABASE dvaia_test_agent_host_aaaaaaaaaaaa_identity OWNER dvaia_identity_migration', sql)
        pair = context['identity']
        self.assertEqual(pair['runtime'], 'postgresql://dvaia_identity_runtime@127.0.0.1:15432/dvaia_test_agent_host_aaaaaaaaaaaa_identity')
        self.assertEqual(pair['migration'], pair['runtime'].replace('_runtime@', '_migration@'))
        env_branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "args.cohort == 'assessment-progress'"
            and any(isinstance(c, ast.keyword) and c.arg == 'SECURESHOP_ASSESSMENT_PROGRESS_NATIVE'
                    for c in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        context.update(env={'PG_TEST_DISPOSABLE': 'yes'}, source=ROOT)
        exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body, type_ignores=[])), '<environment>', 'exec'), context)
        self.assertEqual(context['env'], {
            'PG_TEST_DISPOSABLE': 'yes', 'SECURESHOP_ASSESSMENT_PROGRESS_NATIVE': '1',
            'DVAIA_CURRENT_MAIN_WORKSPACE': str(ROOT),
            'PG_SECURESHOP_ASSESSMENT_PROGRESS_RUNTIME_URL': pair['runtime'],
            'PG_SECURESHOP_ASSESSMENT_PROGRESS_MIGRATION_URL': pair['migration']})
        self.assertFalse(L.plan_requires_browser('assessment-progress'))
        self.assertNotIn('assessment-progress', L.LIVE_BROWSER_COHORTS)

    def test_bounded_child_executes_only_selected_fixture(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and ast.unparse(n.test) == "args.cohort == 'assessment-progress'"
            and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == 'run_node'
                    for c in ast.walk(ast.Module(body=n.body, type_ignores=[]))))
        call = next(c for c in ast.walk(ast.Module(body=branch.body, type_ignores=[]))
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == 'run_node')
        calls = []
        eval(compile(ast.Expression(call), '<child>', 'eval'), dict(vars(L),
            args=SimpleNamespace(node='/owned/node'), label='assessment-progress',
            run_node=lambda *args: calls.append(args)))
        self.assertEqual(calls, [('assessment-progress', ['/owned/node', '--test', '--test-reporter=tap',
            '--test-concurrency=1', L.ASSESSMENT_PROGRESS_TEST], 240)])

    def test_source_closure_requires_identity_sql_and_executed_production_sources(self):
        with patch.object(L, 'dependency_inventory', return_value={}):
            pins = L.source_snapshot(ROOT, '/unused-node', 'assessment-progress')['sourcePins']
        for name in [L.ASSESSMENT_PROGRESS_TEST, L.ASSESSMENT_PROGRESS_LAUNCHER_TEST,
                     'db/postgres/migrate.js',
                     'server/database/postgres/secureshopAssessmentProgressRepository.js',
                     'server/database/postgres/secureshopRealmProgressCleanupCheckpointRepository.js',
                     'server/services/secureshopStandaloneAuth.js', 'server/services/sessionLifetimeConfiguration.js',
                     'server/services/secureshopAssessmentCatalog.js', 'server/config/secureshopCurriculum.js']:
            self.assertIn(name, pins)
        self.assertTrue(any(name.startswith('db/postgres/identity-migrations/') for name in pins))
        self.assertFalse(any(name.startswith('db/postgres/workshop-migrations/') for name in pins))
        self.assertFalse(any(name.startswith('client/') for name in pins))
        self.assertNotIn(L.COUPON_TEST, pins)


if __name__ == '__main__': unittest.main()
