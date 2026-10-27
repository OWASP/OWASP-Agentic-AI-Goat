"""Closed, controlled Q05 Account session-revoke admission; no native work."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


outer = load('q05_session_outer', 'run_standalone_commerce_with_inspector.py')
main = load('q05_session_main', 'run-secureshop-agent-host-transport-main.py')
adapter = load('q05_session_adapter', 'run-secureshop-standalone-commerce-browser.py')


def complete():
    return {'version': 1, 'scope': 'standalone-account-session-revoke-rendered-v1',
            'passed': True,
            'physical': {'cancelPosts': 0, 'preConfirmPosts': 0, 'confirmedPosts': 1, 'foreignDeniedPosts': 1,
                         'confirmedStatus': 200, 'selectedDialogExact': True,
                         'browserAckLost': True, 'serverReplySha256': 'a' * 64},
            'state': {'twoSameLaunchSessions': True, 'selectedRevoked': True,
                      'currentRetained': True, 'selectedTokenDenied': True,
                      'currentTokenAccepted': True, 'auditBound': True},
            'authority': {'capturedBrowserBearer': True, 'sameLaunchOwnerSession': True,
                          'foreignSessionDenied': True, 'foreignHttpDenied': True},
            'recovery': {'operationIdAvailable': False, 'explicitSessionsGet': True,
                         'noSecondPost': True},
            'sibling': {'preexistingNonempty': True, 'unchanged': True},
            'calls': {'model': 0, 'judge': 0, 'credit': 0}}


def current_complete():
    return {'version': 2, 'scope': 'standalone-account-current-session-revoke-rendered-v2',
            'passed': True,
            'physical': {'cancelPosts': 0, 'preConfirmPosts': 0, 'confirmedPosts': 1,
                         'foreignDeniedPosts': 1, 'confirmedStatus': 200,
                         'selectedDialogExact': True},
            'state': {'originalCurrentRevoked': True, 'originalTokenDenied': True,
                      'freshAuthAccepted': True, 'freshSessionDistinct': True,
                      'auditBound': True},
            'authority': {'capturedBrowserBearer': True, 'exactCurrentSession': True,
                          'sameOriginalLaunchOwnerSession': True,
                          'foreignSessionDenied': True, 'foreignHttpDenied': True},
            'recovery': {'operationIdAvailable': False, 'browserConfirmedReply': True,
                         'noSecondPost': True},
            'sibling': {'preexistingNonempty': True, 'unchanged': True},
            'calls': {'model': 0, 'judge': 0, 'credit': 0}}


class AccountSessionRevokeLauncherTests(unittest.TestCase):
    def test_actual_emitted_session_environment_matches_imported_panel_policies(self):
        environment = {'PLATFORM_DATABASE_ENGINE': 'postgres',
                       'WORKSHOP_DATABASE_ENGINE': 'postgres'}
        emitted = main.session_revoke_application_environment(environment)
        self.assertIs(emitted, environment)
        self.assertEqual({key: emitted[key] for key in (
            'SS_PERSONA_INBOX_READY', 'SS_MCP_TRUST_READY', 'SS_CONTROLLED_SSRF_READY')},
            {'SS_PERSONA_INBOX_READY': 'false', 'SS_MCP_TRUST_READY': 'false',
             'SS_CONTROLLED_SSRF_READY': 'false'})
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        source = """const a=require('./server/services/secureshopPersonaInboxActivationPolicy');
const b=require('./server/services/secureshopMcpTrustActivationPolicy');
const c=require('./server/services/secureshopSsrfProduction');
process.stdout.write(JSON.stringify([a.activationPolicy().requested,
  b.activationPolicy().requested,c.activationPolicy().requested]));"""
        actual = subprocess.run([str(node), '-e', source], cwd=ROOT, env=emitted,
                                capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(actual.stdout), [False, False, False])
        default = subprocess.run([str(node), '-e', source], cwd=ROOT,
                                 env={'PLATFORM_DATABASE_ENGINE': 'postgres',
                                      'WORKSHOP_DATABASE_ENGINE': 'postgres'},
                                 capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(default.stdout), [True, False, False])

    def test_closed_cohort_is_distinct_from_original_whole_commerce(self):
        self.assertEqual(outer.COHORT, 'standalone-commerce-browser')
        self.assertEqual(outer.SESSION_REVOKE_COHORT, 'account-session-revoke-browser')
        self.assertIn(main.SESSION_REVOKE_BROWSER, main.STANDALONE_BROWSER_COHORTS)
        self.assertEqual(main.STANDALONE_COMMERCE_TEST,
                         'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js')
        self.assertNotEqual(main.SESSION_REVOKE_TEST, main.STANDALONE_COMMERCE_TEST)
        self.assertEqual(main.SESSION_REVOKE_ASSERTION,
                         'registered shopper physically confirms current-session revoke and signs in afresh')
        args = main.parse(['--cohort', main.SESSION_REVOKE_BROWSER, '--plan',
                           '--main-workspace', str(ROOT), '--node', '/controlled/node',
                           '--docker', '/controlled/docker', '--docker-sha256', 'a'*64,
                           '--docker-host', 'unix:///controlled.sock', '--docker-daemon', 'b'*64])
        self.assertEqual(args.cohort, main.SESSION_REVOKE_BROWSER)

    def test_adapter_specializes_existing_browser_owner_without_running_old_journey(self):
        self.assertEqual(adapter.TEST, main.STANDALONE_COMMERCE_TEST)
        self.assertEqual(adapter.COHORT, outer.COHORT)
        adapter.select_cohort(['--cohort', outer.SESSION_REVOKE_COHORT])
        adapter.validate_pins()
        self.assertEqual(adapter.TEST, main.SESSION_REVOKE_TEST)
        self.assertEqual(adapter.COHORT, outer.SESSION_REVOKE_COHORT)
        self.assertEqual(adapter.KIND, 'account_session_revoke_browser')
        self.assertEqual(adapter.RECORD, 'account-session-revoke-browser-birth.json')
        self.assertEqual(adapter.ACK, 'account-session-revoke-browser-ack.json')
        self.assertEqual(adapter.EVIDENCE_ENV, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH')
        self.assertEqual(adapter.SELECTOR_ENV, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE')
        self.assertEqual(adapter.SESSION_REVOKE_RECEIPT,
                         'account-current-session-revoke-browser-v2.json')
        parsed = type('Parsed', (), {'node': '/controlled/node'})()
        old = [parsed.node, '--test', '--test-reporter=tap', '--test-concurrency=1',
               main.STANDALONE_COMMERCE_TEST]
        focused = [parsed.node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                   main.SESSION_REVOKE_TEST]
        self.assertEqual(adapter.direct_command(focused, parsed),
                         [parsed.node, '--test-reporter=tap', main.SESSION_REVOKE_TEST])
        with self.assertRaises(RuntimeError):
            adapter.direct_command(old, parsed)

    def test_outer_accepts_only_explicit_distinct_current_host_selection(self):
        for cohort in (outer.COHORT, outer.SESSION_REVOKE_COHORT):
            values = ['--plan', '--commerce-test-no-sandbox']
            for key in sorted(outer.REQUIRED):
                values.extend([key, cohort if key == '--cohort' else
                               str(ROOT) if key == '--main-workspace' else
                               str(ROOT / 'tasks/qualification') if key == '--evidence-parent' else
                               'a'*64 if key.endswith('sha256') else 'controlled'])
            self.assertEqual(outer.validate_arguments(values, planning=True), values)
            for wrong in ('other', 'account-session-revoke', 'standalone-commerce'):
                tampered = list(values)
                tampered[tampered.index('--cohort') + 1] = wrong
                with self.assertRaises(RuntimeError):
                    outer.validate_arguments(tampered, planning=True)
            with self.assertRaises(RuntimeError):
                outer.validate_arguments(values + ['--cohort', cohort], planning=True)

    def test_exact_private_receipt_rejects_false_credit_retry_and_types(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/qualification') as folder:
            target = Path(folder) / 'account-session-revoke-browser.json'
            target.write_text(json.dumps(complete()))
            target.chmod(0o600)
            self.assertEqual(main.session_revoke_receipt(target), complete())
            for section, field, value in (
                    ('physical', 'confirmedPosts', 2), ('physical', 'confirmedPosts', True),
                    ('physical', 'foreignDeniedPosts', 0), ('physical', 'foreignDeniedPosts', True),
                    ('physical', 'serverReplySha256', 'short'),
                    ('physical', 'browserAckLost', False),
                    ('authority', 'foreignHttpDenied', False),
                    ('recovery', 'noSecondPost', False),
                    ('recovery', 'operationIdAvailable', True),
                    ('state', 'selectedRevoked', False),
                    ('sibling', 'unchanged', False),
                    ('calls', 'credit', 1), ('calls', 'model', 1), ('calls', 'judge', True)):
                value_row = copy.deepcopy(complete())
                value_row[section][field] = value
                target.write_text(json.dumps(value_row))
                with self.subTest(section=section, field=field, value=value), self.assertRaises(RuntimeError):
                    main.session_revoke_receipt(target)
            value_row = complete(); value_row['unproved'] = True
            target.write_text(json.dumps(value_row))
            with self.assertRaises(RuntimeError):
                main.session_revoke_receipt(target)

    def test_current_receipt_is_distinct_and_type_exact_without_v1_promotion(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/qualification') as folder:
            target = Path(folder) / 'account-current-session-revoke-browser-v2.json'
            target.write_text(json.dumps(current_complete()))
            target.chmod(0o600)
            self.assertEqual(main.session_current_revoke_receipt(target), current_complete())
            with self.assertRaises(RuntimeError):
                main.session_revoke_receipt(target)
            for section, field, value in (
                    ('physical', 'confirmedPosts', 2), ('physical', 'confirmedPosts', True),
                    ('physical', 'foreignDeniedPosts', 0), ('physical', 'confirmedStatus', 200.0),
                    ('physical', 'selectedDialogExact', 1),
                    ('state', 'originalCurrentRevoked', False),
                    ('state', 'freshSessionDistinct', 1),
                    ('authority', 'exactCurrentSession', False),
                    ('recovery', 'browserConfirmedReply', False),
                    ('recovery', 'noSecondPost', 1),
                    ('sibling', 'unchanged', False),
                    ('calls', 'credit', 1), ('calls', 'judge', True)):
                row = copy.deepcopy(current_complete())
                row[section][field] = value
                target.write_text(json.dumps(row))
                with self.subTest(section=section, field=field, value=value), self.assertRaises(RuntimeError):
                    main.session_current_revoke_receipt(target)
            for row in (complete(), {**current_complete(), 'unproved': True}):
                target.write_text(json.dumps(row))
                with self.assertRaises(RuntimeError):
                    main.session_current_revoke_receipt(target)


if __name__ == '__main__':
    unittest.main()
