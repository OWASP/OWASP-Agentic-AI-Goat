"""Nonallocating admission and cleanup-authority checks for the IDOR draft launcher."""

import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tests/postgres/run-secureshop-owned-idor-native.py'
spec = importlib.util.spec_from_file_location('owned_idor_native_launcher', LAUNCHER)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class OwnedIdorNativeLauncherContract(unittest.TestCase):
    def argv(self, *extra):
        return [sys.executable, str(LAUNCHER), '--plan', *extra]

    def test_plan_is_nonallocating_and_pins_promoted_migration(self):
        completed = subprocess.run(self.argv(), cwd=ROOT, text=True, capture_output=True,
                                   timeout=15, check=True)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan['status'], 'plan')
        self.assertEqual(plan['migrationSha256'], launcher.DRAFT_SHA256)
        self.assertEqual(plan['modelCalls'], 0)
        self.assertEqual(set(plan['stores']), {'IDENTITY', 'AGENTS', 'COMMERCE', 'REVIEW', 'FRESH'})
        self.assertEqual(plan['nodeSha256'], launcher.NODE_SHA256)
        self.assertEqual(plan['dockerSha256'], launcher.DOCKER_SHA256)
        self.assertGreater(plan['sourceCount'], 1000)
        self.assertEqual(launcher.sha(ROOT / launcher.DRAFT), launcher.DRAFT_SHA256)
        active = ROOT / 'db/postgres/workshop-migrations/secureshop_review' / Path(launcher.DRAFT).name
        self.assertEqual(launcher.sha(active), launcher.DRAFT_SHA256)

    def test_purpose_plan_selects_exact_two_store_fixture(self):
        completed = subprocess.run(self.argv('--purpose-only'), cwd=ROOT, text=True,
                                   capture_output=True, timeout=15, check=True)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan['case'], launcher.PURPOSE_CASE)
        self.assertEqual(plan['migrationSha256'], launcher.PURPOSE_SHA256)
        self.assertEqual(plan['stores'], {'FRESH': 'secureshop_agents',
                                         'POPULATED': 'secureshop_agents'})
        self.assertEqual(plan['modelCalls'], 0)
        pins = launcher.inventory(True)
        for name in [launcher.PURPOSE_CASE, launcher.PURPOSE_DRAFT,
                     'tests/helpers/secureshopAgentsMigrationView.js',
                     launcher.selected_cohort(True)['active']]:
            self.assertEqual(pins[name], launcher.sha(ROOT / name))
        with patch.object(launcher, 'PURPOSE_CASE_SHA256', '0' * 64), \
                patch.object(sys, 'argv', [str(LAUNCHER), '--plan', '--purpose-only']):
            with self.assertRaisesRegex(SystemExit, 'fixture hash mismatch'):
                launcher.main()

    def test_actual_provisioning_loop_matches_both_native_url_contracts(self):
        # Execute the unchanged production provisioning block with a recording
        # command boundary; no PostgreSQL or Docker process is started.
        tree = ast.parse(LAUNCHER.read_text())
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef)
                    and item.name == 'main')
        body = next(item for item in main.body if isinstance(item, ast.Try)).body
        first = next(i for i, item in enumerate(body) if isinstance(item, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'url_env' for t in item.targets))
        last = next(i for i in range(first, len(body)) if isinstance(body[i], ast.If))
        block = compile(ast.fix_missing_locations(ast.Module(body=body[first:last],
                                                             type_ignores=[])), '<provisioning>', 'exec')
        for purpose in (False, True):
            cohort = launcher.selected_cohort(purpose)
            calls = []
            values = {'cohort': cohort, 'owner': 'abcdef012345', 'port': 15432,
                      'psql': ['owned-psql'], 'BASE_ENV': {},
                      'command': lambda argv, **kwargs: calls.append(argv)}
            exec(block, values)
            self.assertEqual(len(calls), 1 + 2 * len(cohort['families']))
            for store, family in cohort['families'].items():
                database = cohort['databasePrefix'] + 'abcdef012345_' + store.lower()
                self.assertTrue(any('CREATE DATABASE ' + database + ' OWNER' in call[-1]
                                    for call in calls))
                for role in ('RUNTIME', 'MIGRATION'):
                    self.assertEqual(values['url_env'][cohort['prefix'] + store + '_' + role + '_URL'],
                        f'postgresql://dvaia_{family}_{role.lower()}@127.0.0.1:15432/{database}')
            self.assertEqual(len(values['url_env']), 2 * len(cohort['families']))
            self.assertEqual(cohort['gate'], 'SECURESHOP_IDOR_PURPOSE_MIGRATION_NATIVE'
                             if purpose else 'OWNED_IDOR_LESSON_NATIVE')

    def test_purpose_tap_rejects_default_and_skipped_fixture(self):
        tap = ('# Subtest: ' + launcher.PURPOSE_TEST_NAME + '\n'
               'ok 1 - ' + launcher.PURPOSE_TEST_NAME + '\n'
               '1..1\n# tests 1\n# pass 1\n# fail 0\n'
               '# cancelled 0\n# skipped 0\n# todo 0\n')
        self.assertTrue(launcher.tap_passed(tap, launcher.PURPOSE_TEST_NAME))
        self.assertFalse(launcher.tap_passed(tap))
        self.assertFalse(launcher.tap_passed(tap.replace('# skipped 0', '# skipped 1'),
                                           launcher.PURPOSE_TEST_NAME))

    def test_executable_and_extra_options_refused_before_allocation(self):
        completed = subprocess.run(self.argv('--docker-host', 'unix:///tmp/foreign.sock'),
                                   cwd=ROOT, text=True, capture_output=True, timeout=15)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, '')
        with patch.object(launcher, 'NODE_SHA256', '0' * 64), \
                patch.object(sys, 'argv', [str(LAUNCHER), '--plan']):
            with self.assertRaisesRegex(SystemExit, 'executable hash mismatch'):
                launcher.main()
        self.assertTrue(launcher.executables_match())
        with patch.object(launcher, 'DOCKER_SHA256', '0' * 64):
            self.assertFalse(launcher.executables_match())

    def test_tap_requires_one_named_real_pass_and_zero_skips(self):
        accepted = ('# Subtest: ' + launcher.TEST_NAME + '\n'
                    'ok 1 - ' + launcher.TEST_NAME + '\n'
                    '1..1\n# tests 1\n# pass 1\n# fail 0\n'
                    '# cancelled 0\n# skipped 0\n# todo 0\n')
        self.assertTrue(launcher.tap_passed(accepted))
        self.assertFalse(launcher.tap_passed(accepted.replace('# pass 1', '# pass 0')
                                             .replace('# skipped 0', '# skipped 1')))
        self.assertFalse(launcher.tap_passed(accepted.replace('ok 1 - ', 'not ok 1 - ')))
        self.assertFalse(launcher.tap_passed(accepted + 'ok 2 - unexpected\n'))

    def test_process_group_cleanup_requires_absence(self):
        with patch.object(launcher, 'owned_group_members', side_effect=[[101], []]), \
                patch.object(launcher.os, 'killpg') as kill:
            self.assertTrue(launcher.stop_owned_group(101))
            kill.assert_called_once_with(101, launcher.signal.SIGTERM)
        with patch.object(launcher, 'owned_group_members', return_value=[101]), \
                patch.object(launcher.os, 'killpg'):
            with patch.object(launcher.time, 'monotonic', side_effect=[0, 4, 5, 9]):
                self.assertFalse(launcher.stop_owned_group(101))

    def test_signed_unrelated_uid_and_foreign_matching_group(self):
        own = launcher.os.getuid()
        rows = f'2 2 -2\n101 101 {own}\n'
        with patch.object(launcher, 'command', return_value=SimpleNamespace(stdout=rows)):
            self.assertEqual(launcher.owned_group_members(8013), [])
            self.assertEqual(launcher.owned_group_members(101), [101])
        with patch.object(launcher, 'command', return_value=SimpleNamespace(stdout='2 8013 -2\n')):
            with self.assertRaisesRegex(RuntimeError, 'Foreign member'):
                launcher.owned_group_members(8013)
        with patch.object(launcher, 'command', return_value=SimpleNamespace(stdout='2 8013 unknown\n')):
            with self.assertRaisesRegex(RuntimeError, 'Cannot establish'):
                launcher.owned_group_members(8013)

    def test_captured_id_rename_does_not_count_as_cleanup(self):
        docker = ['docker', '--host', launcher.DOCKER_HOST]
        with patch.object(launcher, 'verify_daemon'), \
                patch.object(launcher, 'inspect_owned', return_value=None), \
                patch.object(launcher, 'inspect_captured_id', return_value={'Id': 'captured'}), \
                patch.object(launcher, 'docker_call') as remove:
            with self.assertRaisesRegex(RuntimeError, 'renamed'):
                launcher.cleanup_owned_container(docker, 'name', 'owner', 'captured')
            remove.assert_not_called()

    def test_dependency_inventory_has_runtime_modules(self):
        dependencies = launcher.dependency_inventory()
        self.assertIn('pg/package.json', dependencies)
        self.assertEqual(dependencies, launcher.dependency_inventory())

    def test_cleanup_inspection_distinguishes_absent_foreign_and_unknown(self):
        docker = ['docker', '--host', launcher.DOCKER_HOST]
        missing = subprocess.CompletedProcess(docker, 1, '', 'Error: No such object: owned')
        with patch.object(launcher.subprocess, 'run', return_value=missing):
            self.assertIsNone(launcher.inspect_owned(docker, 'owned', 'owner'))
        uncertain = subprocess.CompletedProcess(docker, 1, '', 'Cannot connect to Docker daemon')
        with patch.object(launcher.subprocess, 'run', return_value=uncertain):
            with self.assertRaisesRegex(RuntimeError, 'Unable to inspect'):
                launcher.inspect_owned(docker, 'owned', 'owner')
        foreign = {'Name': '/owned', 'Id': 'foreign-id',
                   'Config': {'Labels': {'dvaia.test.owner': 'foreign'}}}
        observed = subprocess.CompletedProcess(docker, 0, json.dumps([foreign]), '')
        with patch.object(launcher.subprocess, 'run', return_value=observed):
            with self.assertRaisesRegex(RuntimeError, 'different run'):
                launcher.inspect_owned(docker, 'owned', 'owner')


if __name__ == '__main__':
    unittest.main()
