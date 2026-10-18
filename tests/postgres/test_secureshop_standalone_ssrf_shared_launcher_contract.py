"""Resource-free admission checks for the shared C32 browser launcher branch."""

import ast
import copy
import json
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import importlib.util
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_ssrf_shared_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class StandaloneSsrfSharedLauncherContract(unittest.TestCase):
    def test_exact_selector_current_caller_and_one_tap(self):
        cohort = LAUNCHER.C32_COHORT
        self.assertEqual(cohort, LAUNCHER.ssrf_owned.COHORT)
        self.assertIn(cohort, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertIn(cohort, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(cohort, LAUNCHER.STANDALONE_BROWSER_COHORTS)
        self.assertTrue(LAUNCHER.plan_requires_browser(cohort))
        self.assertEqual(LAUNCHER.digest(ROOT / LAUNCHER.ssrf_owned.TEST),
                         LAUNCHER.ssrf_owned.TEST_SHA256)
        self.assertEqual(LAUNCHER.digest(ROOT / LAUNCHER.ssrf_owned.CALLER_TEST),
                         LAUNCHER.ssrf_owned.CALLER_TEST_SHA256)
        title = LAUNCHER.ssrf_owned.TITLE
        tap = (f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n'
               '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(tap, cohort, [title])['tests'], 1)
        for bad in (tap.replace('# skipped 0', '# skipped 1'),
                    tap.replace('ok 1 -', 'not ok 1 -'),
                    tap.replace(title, 'other test')):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                LAUNCHER.complete_tap_counts(bad, cohort, [title])

    def test_policy_output_native_closed_selection_and_receipt(self):
        required = ['--main-workspace', str(ROOT), '--node', '/unused/node', '--docker', '/unused/docker',
            '--docker-sha256', 'a' * 64, '--docker-host', 'unix:///unused', '--docker-daemon', 'owned']
        args = LAUNCHER.parse(required + ['--cohort', 'standalone-assessment', '--policy-output-native'])
        self.assertTrue(args.policy_output_native)
        self.assertFalse(LAUNCHER.parse(required).policy_output_native)
        self.assertFalse(LAUNCHER.plan_requires_browser(args.cohort))
        for cohort in ('transport', LAUNCHER.C32_COHORT):
            with self.assertRaisesRegex(RuntimeError, 'exclusive'):
                LAUNCHER.validate_static(LAUNCHER.parse(required + ['--cohort', cohort, '--policy-output-native']))
        self.assertEqual(LAUNCHER.digest(ROOT / LAUNCHER.POLICY_OUTPUT_NATIVE_TEST), LAUNCHER.POLICY_OUTPUT_NATIVE_SHA256)
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "args.cohort == 'standalone-assessment'"
            and any(isinstance(child, ast.JoinedStr) and 'PG_SECURESHOP_SSRF_' in ast.unparse(child)
                    for child in ast.walk(ast.Module(body=node.body, type_ignores=[]))))
        pairs = {'runtime': 'owned-runtime', 'migration': 'owned-migration'}
        context = dict(vars(LAUNCHER), args=args, source=ROOT, env={'PG_TEST_DISPOSABLE': 'yes'}, identity=pairs, agents=pairs)
        exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), '<native-env>', 'exec'), context)
        self.assertEqual(set(context['env']), {'PG_TEST_DISPOSABLE', 'DVAIA_ISOLATED_TEST_WORKSPACE',
            'DVAIA_CURRENT_MAIN_WORKSPACE', 'PG_SECURESHOP_SSRF_IDENTITY_RUNTIME_URL',
            'PG_SECURESHOP_SSRF_IDENTITY_MIGRATION_URL', 'PG_SECURESHOP_SSRF_AGENTS_RUNTIME_URL',
            'PG_SECURESHOP_SSRF_AGENTS_MIGRATION_URL'})
        value = {key: True for key in LAUNCHER.POLICY_OUTPUT_NATIVE_FLAGS}
        value.update(scope=LAUNCHER.POLICY_OUTPUT_NATIVE_SCOPE, actualModel=False, genuineCredit=False,
            recordedHtmlInvocations=1, controlledMcpInvocations=3, historicalMigrationInvocations=2)
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory).resolve() / 'native.json'
            def validate(row):
                receipt.write_text(json.dumps(row)); receipt.chmod(0o600)
                return LAUNCHER.policy_output_native_receipt(receipt)
            self.assertEqual(validate(value), value)
            for key, wrong in [('actualModel', True), ('genuineCredit', True), ('recordedHtmlInvocations', True),
                    ('controlledMcpInvocations', 4), ('migrationNoop', False), ('scope', 'other'), ('extra', True)]:
                bad = copy.deepcopy(value); bad[key] = wrong
                with self.subTest(key=key), self.assertRaises(RuntimeError): validate(bad)
            bad = dict(value); del bad['htmlRequestImmutable']
            with self.assertRaises(RuntimeError): validate(bad)
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}):
            pins = LAUNCHER.source_snapshot(ROOT, '/unused', 'standalone-assessment', policy_output_native=True)['sourcePins']
        self.assertEqual(pins[LAUNCHER.POLICY_OUTPUT_NATIVE_TEST], LAUNCHER.POLICY_OUTPUT_NATIVE_SHA256)
        self.assertTrue(any(key.endswith('0110_policy_final_html.sql') for key in pins))

    def test_policy_output_browser_is_closed_and_cohort_exclusive(self):
        required = ['--main-workspace', str(ROOT), '--node', '/unused/node', '--docker', '/unused/docker',
            '--docker-sha256', 'a' * 64, '--docker-host', 'unix:///unused', '--docker-daemon', 'owned']
        self.assertFalse(LAUNCHER.parse(required).policy_output_browser)
        args = LAUNCHER.parse(required + ['--cohort', LAUNCHER.C32_COHORT, '--policy-output-browser'])
        self.assertTrue(args.policy_output_browser)
        for cohort in ('standalone-assessment', 'transport'):
            with self.assertRaisesRegex(RuntimeError, 'exclusive'):
                LAUNCHER.validate_static(LAUNCHER.parse(required + ['--cohort', cohort, '--policy-output-browser']))
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}):
            pins = LAUNCHER.source_snapshot(ROOT, '/unused', LAUNCHER.C32_COHORT,
                browser_root=ROOT / 'client/node_modules', policy_output_browser=True)['sourcePins']
        for name in LAUNCHER.ssrf_owned.POLICY_PINNED:
            self.assertEqual(pins[name], LAUNCHER.digest(ROOT / name))

    def test_current_main_source_and_dependency_closure(self):
        snapshot = LAUNCHER.source_snapshot(
            ROOT, '/usr/bin/false', LAUNCHER.C32_COHORT,
            browser_root=ROOT / 'client/node_modules')
        self.assertEqual(set(snapshot), {
            'sourcePins', 'dependencyInventory', 'clientDependencyInventory',
            'browserInventory'})
        pins = snapshot['sourcePins']
        imported = set(LAUNCHER.ssrf_owned.source_files()) | {
            LAUNCHER.C32_LAUNCHER_TEST}
        for directory in ('sidecars/sandbox-runner', 'sidecars/analytics-sql-target',
                          'agent-host/agents/summarizer', 'agent-host/shared'):
            imported.update(path.relative_to(ROOT).as_posix()
                            for path in (ROOT / directory).rglob('*')
                            if path.is_file() and path.suffix in {'.js', '.json', '.sql'})
        for relative in sorted(imported):
            with self.subTest(relative=relative):
                self.assertEqual(pins[relative], LAUNCHER.digest(ROOT / relative))


if __name__ == '__main__':
    unittest.main()
