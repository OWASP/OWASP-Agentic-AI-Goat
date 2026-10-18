#!/usr/bin/env python3
"""Offline admission and receipt controls for the Q07 terminal authority matrix."""

import contextlib
import copy
import ast
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('terminal_authority_launcher',
    HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)
from test_secureshop_customer_pre_admission_receipt import receipt as customer_pre_admission_receipt


def diagnostic():
    family_ids = {family: {phase: f'{index:08x}-0000-4000-8000-{phase:012x}'
                           for phase in (1, 2, 3)}
                  for index, family in enumerate(LAUNCHER.TERMINAL_AUTHORITY_MATRIX_FAMILIES, 1)}
    tables = {'customer-ticket': 'product_target_support_ticket_receipts',
              'merchant-listing': 'owned_merchant_listing_create_receipts',
              'merchant-inventory': 'owned_inventory_operations',
              'admin-policy': 'bound_prompt_policy_operations',
              'admin-acl': 'bound_tool_policy_operations'}
    positives = [{'family': family, 'requestId': family_ids[family][1],
                  'proposalId': family_ids[family][1], 'status': 200,
                  'receiptTable': tables[family], 'beforeSha256': 'a' * 64, 'afterSha256': 'b' * 64}
                 for family in LAUNCHER.TERMINAL_AUTHORITY_MATRIX_FAMILIES]
    phase = {'revoked_persona_session': 2, 'stale_generation': 3}
    denials = [{'family': family, 'denial': denial,
                'requestId': family_ids[family][phase.get(denial, 1)],
                'status': 503 if (family, denial) == ('customer-ticket', 'foreign_tenant') else 403,
                'code': None, 'beforeSha256': 'c' * 64, 'afterSha256': 'c' * 64}
               for family in LAUNCHER.TERMINAL_AUTHORITY_MATRIX_FAMILIES
               for denial in LAUNCHER.TERMINAL_AUTHORITY_MATRIX_DENIALS]
    provider = lambda turns, count: {'provider': 'ollama', 'model': 'llama3.1:8b',
                                     'transport': 'unmodified-production-adapter',
                                     'supervisorInvocations': count, 'traceSha256': 'd' * 64,
                                     turns[0]: turns[1]}
    return {'version': 1, 'scope': 'focused-production-http', 'positives': positives,
            'denials': denials, 'objectiveCredit': False, 'judgeCalls': 0,
            'ticketProvider': provider(('preparedTurns', 3), 8),
            'inventoryProvider': provider(('confirmedTurns', 1), 3),
            'roleProvider': {'provider': 'mock', 'model': 'q07-controlled-no-credit', 'calls': 20},
            'customerPreAdmission': customer_pre_admission_receipt(),
            'reset': {'resetId': '99999999-9999-4999-8999-999999999999',
                      'status': 'committed', 'cleanupComplete': True}}


class TerminalAuthorityMatrixLauncherContract(unittest.TestCase):
    def test_failed_native_receipt_survives_absent_post_run_model_artifact(self):
        # Execute the launcher's actual Q07 final-receipt branch without starting
        # the disposable database, model, or native test process.
        syntax = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        receipt_branches = [node for node in ast.walk(syntax)
                            if isinstance(node, ast.If)
                            and ast.unparse(node.test) == "args.cohort == 'terminal-authority-matrix-native'"
                            and any('receipt.update(' in ast.unparse(item) for item in node.body)]
        self.assertEqual(len(receipt_branches), 1)
        branch = compile(ast.fix_missing_locations(ast.Module(body=receipt_branches, type_ignores=[])),
                         '<q07-final-receipt>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            primary = {'type': 'RuntimeError', 'stage': 'node-terminal-authority-matrix-native-retire',
                       'exitCode': None}
            cleanup = {'containerNameAbsent': True, 'containerIdAbsent': True, 'errors': []}
            receipt = {'passed': False, 'primaryError': primary, 'cleanup': cleanup,
                       'testExitCodes': {'terminal-authority-matrix-native': 1}}
            values = dict(vars(LAUNCHER), args=type('Args', (), {'cohort': 'terminal-authority-matrix-native'})(),
                          receipt=receipt, evidence=evidence, effect_counts={}, model_pin={'sha256': 'a' * 64},
                          terminal_authority_result=None, terminal_authority_model_after=None,
                          digest=lambda _path: self.fail('Absent model-after artifact must not be read'))
            exec(branch, values)
            LAUNCHER.atomic_json(evidence / 'result.json', receipt)
            saved = json.loads((evidence / 'result.json').read_text())
            self.assertFalse(saved['passed'])
            self.assertEqual(saved['primaryError'], primary)
            self.assertEqual(saved['cleanup'], cleanup)
            self.assertEqual(saved['testExitCodes'], {'terminal-authority-matrix-native': 1})
            self.assertIsNone(saved['terminalAuthorityModelAfter'])
            self.assertIsNone(saved['terminalAuthorityModelAfterSha256'])
            self.assertFalse((evidence / 'local-model-after.json').exists())

            # A claimed post-run model identity still requires its real artifact.
            values['terminal_authority_model_after'] = {'sha256': 'a' * 64}
            values['digest'] = LAUNCHER.digest
            with self.assertRaises(FileNotFoundError):
                exec(branch, values)

    def test_frozen_fixture_model_pin_and_no_browser_selector(self):
        self.assertIn('terminal-authority-matrix-native',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotIn('terminal-authority-matrix-native', LAUNCHER.STANDALONE_BROWSER_COHORTS)
        self.assertFalse(LAUNCHER.plan_requires_browser('terminal-authority-matrix-native'))
        for name, expected in ((LAUNCHER.TERMINAL_AUTHORITY_MATRIX_TEST,
                                LAUNCHER.TERMINAL_AUTHORITY_MATRIX_TEST_SHA256),
                               (LAUNCHER.TERMINAL_AUTHORITY_MATRIX_CONTRACT,
                                LAUNCHER.TERMINAL_AUTHORITY_MATRIX_CONTRACT_SHA256)):
            self.assertEqual(LAUNCHER.digest(ROOT / name), expected)
        self.assertEqual(LAUNCHER.TERMINAL_AUTHORITY_MATRIX_MODEL_SHA256,
                         '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e')
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('no child')):
            snapshot = LAUNCHER.source_snapshot(ROOT, '/unused/node', 'terminal-authority-matrix-native')
        pins = snapshot['sourcePins']
        self.assertIn(LAUNCHER.TERMINAL_AUTHORITY_MATRIX_TEST, pins)
        self.assertIn(LAUNCHER.TERMINAL_AUTHORITY_MATRIX_CONTRACT, pins)
        self.assertIn('server/services/secureshopBoundReviewComposition.js', pins)
        self.assertIn('server/agent-runtime/secureshopSupervisorGraph.js', pins)
        self.assertIn('server/middleware/secureshopBoundDispatch.js', pins)
        for directory in ('identity-migrations', 'workshop-migrations/secureshop_agents',
                          'workshop-migrations/secureshop_review', 'workshop-migrations/secureshop'):
            for path in (ROOT / 'db/postgres' / directory).glob('*.sql'):
                self.assertIn(path.relative_to(ROOT).as_posix(), pins)
        self.assertNotIn('client/build/index.html', pins)

    def test_nonallocating_four_store_plan_with_honest_model_bounds(self):
        argv = ['--cohort', 'terminal-authority-matrix-native', '--main-workspace', str(ROOT),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--image-id', 'sha256:' + 'b' * 64,
                '--ollama-model-sha256', LAUNCHER.TERMINAL_AUTHORITY_MATRIX_MODEL_SHA256, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=ROOT), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.TERMINAL_AUTHORITY_MATRIX_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertFalse(plan['browser'])
        self.assertFalse(plan['sourceCopy'])
        self.assertFalse(plan['nativeStarted'])
        self.assertIsNone(plan['modelCalls'])
        self.assertEqual((plan['ticketTurns'], plan['inventoryTurns']), (3, 1))
        self.assertEqual((plan['maximumSupervisorInvocations'], plan['maximumTransportCalls']), (17, 34))
        self.assertEqual((plan['positiveEffects'], plan['coreDenials'], plan['platformTokenDenials']), (5, 25, 5))
        self.assertEqual((plan['browserCalls'], plan['judgeCalls']), (0, 0))

    def test_exact_tap_and_diagnostic_disallow_fabricated_counts_or_credit(self):
        title = LAUNCHER.TERMINAL_AUTHORITY_MATRIX_ASSERTION
        value = diagnostic()
        content = ('TAP version 13\n# Subtest: ' + title + '\nok 1 - ' + title + '\n1..1\n'
                   '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
                   '# Q07_AUTHORITY_MATRIX ' + json.dumps(value) + '\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(content, 'q07', [title])['pass'], 1)
        self.assertEqual(LAUNCHER.terminal_authority_matrix_diagnostic(content), value)
        for mutate in (
            lambda row: row.update(objectiveCredit=True),
            lambda row: row.update(judgeCalls=1),
            lambda row: row['positives'].pop(),
            lambda row: row['denials'].pop(),
            lambda row: row['denials'][0].update(afterSha256='f' * 64),
            lambda row: row['denials'][0].update(status=200),
            lambda row: next(item for item in row['denials'] if item['family'] == 'customer-ticket'
                             and item['denial'] == 'revoked_persona_session').update(
                                 requestId=row['positives'][0]['requestId']),
            lambda row: next(item for item in row['denials'] if item['family'] == 'merchant-listing'
                             and item['denial'] == 'stale_generation').update(
                                 requestId=next(item for item in row['denials']
                                                if item['family'] == 'customer-ticket'
                                                and item['denial'] == 'stale_generation')['requestId']),
            lambda row: row['ticketProvider'].update(supervisorInvocations=13),
            lambda row: row['inventoryProvider'].update(supervisorInvocations=6),
            lambda row: row['roleProvider'].update(provider='ollama'),
            lambda row: row.pop('customerPreAdmission'),
            lambda row: row['customerPreAdmission']['denials'].pop(),
            lambda row: row['customerPreAdmission']['denials'][0].update(providerCalls=19),
            lambda row: row['customerPreAdmission']['compatibility'][0].update(savedStatus='pending'),
            lambda row: row['customerPreAdmission']['refund'].update(dispatch='invoked'),
            lambda row: row['customerPreAdmission'].update(extra=True),
            lambda row: row['reset'].update(cleanupComplete=False),
        ):
            bad = copy.deepcopy(value); mutate(bad)
            with self.assertRaises(RuntimeError):
                LAUNCHER.terminal_authority_matrix_diagnostic('# Q07_AUTHORITY_MATRIX ' + json.dumps(bad))
        with self.assertRaises(RuntimeError):
            LAUNCHER.terminal_authority_matrix_diagnostic(content + '# Q07_AUTHORITY_MATRIX ' + json.dumps(value))

    def test_post_run_model_identity_requires_exact_pinned_artifact(self):
        expected = LAUNCHER.TERMINAL_AUTHORITY_MATRIX_MODEL_SHA256
        identity = {'baseURL': LAUNCHER.OLLAMA_BASE_URL, 'model': LAUNCHER.OLLAMA_MODEL,
                    'sha256': expected}
        self.assertEqual(LAUNCHER.terminal_authority_matrix_model_identity(identity, expected), identity)
        for mutate in (
            lambda row: row.update(sha256='a' * 64),
            lambda row: row.update(model='llama3.1:70b'),
            lambda row: row.update(baseURL='http://127.0.0.1:11435'),
            lambda row: row.update(extra=True),
        ):
            bad = dict(identity)
            mutate(bad)
            with self.assertRaises(RuntimeError):
                LAUNCHER.terminal_authority_matrix_model_identity(bad, expected)


if __name__ == '__main__':
    unittest.main()
