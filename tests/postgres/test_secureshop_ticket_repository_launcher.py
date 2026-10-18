#!/usr/bin/env python3
"""Offline contract for the storage-only support-ticket repository cohort."""

import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_ticket_repository_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class TicketRepositoryLauncherContract(unittest.TestCase):
    def test_closed_selector_four_store_plan_and_fixture_pin(self):
        self.assertIn('ticket-repository-native',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotIn('ticket-repository-native', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertNotIn('ticket-repository-native', LAUNCHER.STANDALONE_BROWSER_COHORTS)
        fixture = ROOT / LAUNCHER.TICKET_REPOSITORY_TEST
        self.assertEqual(LAUNCHER.digest(fixture), LAUNCHER.TICKET_REPOSITORY_TEST_SHA256)
        source = fixture.read_text()
        self.assertIn('SECURESHOP_TICKET_REPOSITORY_NATIVE', source)
        for store in ('REVIEW_FRESH', 'REVIEW_POPULATED', 'AGENTS_FRESH', 'AGENTS_POPULATED'):
            self.assertIn(store, source)
        self.assertIn('`${PREFIX}${key}_URL`', source)

        argv = ['--cohort', 'ticket-repository-native', '--main-workspace', str(ROOT),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--image-id', 'sha256:' + 'b' * 64,
                '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=ROOT), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.TICKET_REPOSITORY_COHORT)
        self.assertEqual(plan['stores'], [
            'ticket_repository_review_fresh', 'ticket_repository_review_populated',
            'ticket_repository_agents_fresh', 'ticket_repository_agents_populated'])
        self.assertEqual(plan['tests'], 1)
        self.assertFalse(plan['browser'])
        self.assertEqual(plan['modelCalls'], 0)
        self.assertFalse(plan['nativeStarted'])
        self.assertFalse(plan['sourceCopy'])

    def test_allocation_and_environment_use_exact_four_ticket_pairs(self):
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        main = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        allocation = next(node for node in ast.walk(main)
                           if isinstance(node, ast.If)
                           and ast.unparse(node.test) == "args.cohort == 'ticket-repository-native'"
                           and 'create_ticket_store' in ast.get_source_segment(source, node))
        environment = next(node for node in ast.walk(main)
                           if isinstance(node, ast.If)
                           and ast.unparse(node.test) == "args.cohort == 'ticket-repository-native'"
                           and 'PG_SECURESHOP_TICKET_REPOSITORY_' in ast.get_source_segment(source, node))
        allocated = []

        def fake_store(_args, _clean, _container, _port, owner, store, role_families):
            allocated.append((owner, store))
            role_families.add(store.split('_')[0].lower())
            return {'runtime': f'{store}-runtime', 'migration': f'{store}-migration'}

        scope = {
            'args': SimpleNamespace(cohort='ticket-repository-native'),
            'clean': {}, 'captured_id': 'controlled', 'port': 15432, 'nonce': 'a' * 12,
            'ticket_stores': {}, 'ticket_role_families': set(),
            'create_ticket_store': fake_store, 'env': {}, 'source': ROOT,
        }
        exec(compile(ast.fix_missing_locations(ast.Module(body=allocation.body, type_ignores=[])),
                     '<ticket allocation>', 'exec'), scope)
        self.assertEqual(allocated, [('a' * 12, 'REVIEW_FRESH'), ('a' * 12, 'REVIEW_POPULATED'),
                                     ('a' * 12, 'AGENTS_FRESH'), ('a' * 12, 'AGENTS_POPULATED')])
        exec(compile(ast.fix_missing_locations(ast.Module(body=environment.body, type_ignores=[])),
                     '<ticket environment>', 'exec'), scope)
        self.assertEqual(scope['env']['SECURESHOP_TICKET_REPOSITORY_NATIVE'], '1')
        self.assertEqual(scope['env']['PG_SECURESHOP_TICKET_REPOSITORY_OWNER'], 'a' * 12)
        self.assertEqual(len([key for key in scope['env'] if key.endswith('_RUNTIME_URL')]), 4)
        self.assertEqual(len([key for key in scope['env'] if key.endswith('_MIGRATION_URL')]), 4)
        self.assertEqual(scope['env']['PG_SECURESHOP_TICKET_REPOSITORY_REVIEW_FRESH_RUNTIME_URL'],
                         'REVIEW_FRESH-runtime')

    def test_exact_unskipped_tap_and_source_closure(self):
        title = LAUNCHER.TICKET_REPOSITORY_ASSERTION
        valid = (f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n'
                 '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(valid, 'ticket-repository-native', [title])['tests'], 1)
        for bad in (valid.replace(title, 'wrong assertion'), valid.replace('# skipped 0', '# skipped 1'),
                    valid.replace('# pass 1', '# pass 0').replace('# fail 0', '# fail 1')):
            with self.assertRaises(RuntimeError):
                LAUNCHER.complete_tap_counts(bad, 'ticket-repository-native', [title])

        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}):
            snapshot = LAUNCHER.source_snapshot(ROOT, '/unused/node', 'ticket-repository-native')
        required = {
            LAUNCHER.TICKET_REPOSITORY_TEST, LAUNCHER.TICKET_REPOSITORY_LAUNCHER_TEST,
            'db/postgres/migrate.js',
            'tests/helpers/secureshopAgentsMigrationView.js',
            'server/database/postgres/secureshopTicketRepository.js',
            'server/database/postgres/secureshopBoundProductRepository.js',
            'server/database/postgres/secureshopBoundToolPolicyReadiness.js',
            'server/services/secureshopTicketContract.js',
            'server/services/secureshopSceneBinding.js',
        }
        self.assertTrue(required <= set(snapshot['sourcePins']))
        for directory in ('db/postgres/workshop-migrations/secureshop_review',
                          'db/postgres/workshop-migrations/secureshop_agents'):
            self.assertTrue(any(name.startswith(directory + '/') for name in snapshot['sourcePins']))


if __name__ == '__main__':
    unittest.main()
