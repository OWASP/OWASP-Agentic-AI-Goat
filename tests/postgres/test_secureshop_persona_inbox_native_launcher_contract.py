#!/usr/bin/env python3
"""Offline contract for the no-copy persona-inbox native cohort."""

import importlib.util
import ast
import contextlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class PersonaInboxNativeLauncherContract(unittest.TestCase):
    def test_native_source_closure_without_browser_registry_or_process(self):
        source = HERE.parent.parent
        # Exercise actual closure selection/hashing; only dependency traversal is
        # stubbed. No Node, database, model, browser or child process is allowed.
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}) as inventory, \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('No native closure subprocess')):
            snapshot = LAUNCHER.source_snapshot(source, '/not-executed/node', 'persona-inbox-native')
        inventory.assert_called_once_with(source / 'node_modules')
        self.assertEqual(set(snapshot), {'sourcePins', 'dependencyInventory'})
        required = {
            LAUNCHER.PERSONA_INBOX_NATIVE_TEST,
            'tests/postgres/test_secureshop_persona_inbox_native_launcher_contract.py',
            'docs/modernization/drafts/secureshop-persona-inbox-identity.sql',
            'docs/modernization/drafts/secureshop-persona-inbox-agents.sql',
            'db/postgres/initialize-application.js',
            'db/postgres/migrate.js',
            'server/services/secureshopPersonaInboxPriorAdvisoryReader.js',
            'server/services/secureshopObjectiveCompletionService.js',
            'server/database/postgres/secureshopAssessmentStore.js',
            'server/database/postgres/secureshopPersonaInboxRepository.js',
            'server/database/postgres/secureshopReviewDb.js',
            'server/database/postgres/secureshopSeed.js',
            'server/database/postgres/secureshopSceneRepository.js',
            'server/database/postgres/secureshopMailSceneRepository.js',
            'server/database/postgres/secureshopBoundProductRepository.js',
            'server/services/secureshopScenes.js',
            'server/services/secureshopMailScenes.js',
            'server/services/secureshopBoundCatalog.js',
            'db/postgres/seeds/secureshop.json',
            'server/agent-runtime/objectiveJudge.js',
        }
        for directory in ('db/postgres/identity-migrations', 'db/postgres/workshop-migrations/secureshop_agents',
                          'db/postgres/workshop-migrations/secureshop_review',
                          'db/postgres/workshop-migrations/secureshop'):
            required.update(path.relative_to(source).as_posix() for path in (source / directory).glob('*.sql'))
        self.assertTrue(required <= set(snapshot['sourcePins']))
        for relative in required:
            self.assertEqual(snapshot['sourcePins'][relative], LAUNCHER.digest(source / relative))

    def test_exact_no_copy_selector_and_fixture(self):
        self.assertIn('persona-inbox-native',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotIn('persona-inbox-native', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertEqual(LAUNCHER.PERSONA_INBOX_NATIVE_COHORT,
                         'secureshop-persona-inbox-native-current-main-v1')
        self.assertEqual(LAUNCHER.PERSONA_INBOX_NATIVE_TEST,
                         'tests/postgres/secureshopPersonaInbox.integration.test.js')
        self.assertEqual(LAUNCHER.PERSONA_INBOX_NATIVE_ASSERTION,
                         'native persona inbox persists scoped ACL effects, cleanup proofs, and canonical advisory contribution')
        fixture = (HERE.parent.parent / LAUNCHER.PERSONA_INBOX_NATIVE_TEST).read_text()
        for store in ('IDENTITY', 'AGENTS', 'REVIEW', 'COMMERCE'):
            for role in ('MIGRATION', 'RUNTIME'):
                self.assertIn(f'{store}_{role}_URL', fixture)
        launcher = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn("for name, pair in [('IDENTITY', identity), ('AGENTS', agents), ('REVIEW', reviews), ('COMMERCE', commerce)]:\n"
                      "                env[f'PG_SECURESHOP_PERSONA_INBOX_{name}_RUNTIME_URL']", launcher)

    def test_plan_requires_four_owned_stores_without_allocation(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'persona-inbox-native', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], False)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)

    def test_actual_allocation_and_env_branches_supply_four_pairs(self):
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        main = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        nodes = list(ast.walk(main))
        allocation = next(node for node in nodes if isinstance(node, ast.If)
                          and ast.get_source_segment(source, node.test).startswith(
                              "args.cohort in ('product-admission', 'registered-admin-reset')")
                          and 'provision-secureshop-agents' in ast.get_source_segment(source, node))
        environment = next(node for node in nodes if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == 'env'
                                   for target in node.targets)
                           and 'PG_TEST_DISPOSABLE' in ast.get_source_segment(source, node))
        persona = next(node for node in nodes if isinstance(node, ast.If)
                       and ast.get_source_segment(source, node.test) ==
                       "args.cohort == 'persona-inbox-native'"
                       and 'PG_SECURESHOP_PERSONA_INBOX_' in ast.get_source_segment(source, node))
        allocated = []
        def fake_store(_args, _clean, _captured_id, _port, _nonce, store):
            allocated.append(store)
            return {'runtime': store + '-runtime', 'migration': store + '-migration'}
        scope = {'args': SimpleNamespace(cohort='persona-inbox-native'),
                 'clean': {}, 'captured_id': 'controlled', 'port': 1,
                 'nonce': 'controlled', 'create_store': fake_store,
                 'STANDALONE_BROWSER_COHORTS': LAUNCHER.STANDALONE_BROWSER_COHORTS,
                 'C31_COHORT': LAUNCHER.C31_COHORT,
                 'runtime': Path('/controlled/runtime'), 'source': HERE.parent.parent}
        # Execute only the three exact launcher branches. No resource function
        # beyond fake_store is in scope, so unexpected allocation fails closed.
        branch = ast.fix_missing_locations(ast.Module(body=[allocation, environment, persona], type_ignores=[]))
        exec(compile(branch, '<actual launcher provision/env branches>', 'exec'), scope)
        self.assertEqual(allocated, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(scope['env']['SECURESHOP_PERSONA_INBOX_NATIVE'], '1')
        self.assertEqual(scope['env']['SS_ENABLE_REAL_LLM_TESTS'], 'false')
        for label, store in (('IDENTITY', 'identity'), ('AGENTS', 'secureshop_agents'),
                             ('COMMERCE', 'secureshop'), ('REVIEW', 'secureshop_review')):
            self.assertEqual(scope['env'][f'PG_SECURESHOP_PERSONA_INBOX_{label}_RUNTIME_URL'],
                             store + '-runtime')
            self.assertEqual(scope['env'][f'PG_SECURESHOP_PERSONA_INBOX_{label}_MIGRATION_URL'],
                             store + '-migration')

    def test_exact_unskipped_tap_required(self):
        label = 'persona-inbox-native'
        title = LAUNCHER.PERSONA_INBOX_NATIVE_ASSERTION
        valid = (f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n'
                 '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(valid, label, [title])['tests'], 1)
        for invalid in (valid.replace(title, 'unrelated assertion'),
                        valid.replace('# skipped 0', '# skipped 1'),
                        valid.replace('# fail 0', '# fail 1')):
            with self.subTest(invalid=invalid[-60:]):
                with self.assertRaises(RuntimeError):
                    LAUNCHER.complete_tap_counts(invalid, label, [title])


if __name__ == '__main__':
    unittest.main()
