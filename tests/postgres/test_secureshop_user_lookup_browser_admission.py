"""Combined original lookup admission controls; no native resources."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


L = load('run-secureshop-user-lookup-browser.py')
C = load('run_user_lookup_with_inspector.py')


class Admission(unittest.TestCase):
    def test_exact_combined_selection(self):
        args = ['--cohort', L.COHORT, '--user-lookup-test-no-sandbox', '--user-lookup-disclosure']
        self.assertEqual(L.arguments(args), args[:2] + args[3:])
        for values in (args[:-1], args + [args[-1]], args[:2],
                       ['--cohort', 'customer-checkout-browser', *args[2:]]):
            with self.assertRaises(RuntimeError):
                L.arguments(values)

    def test_benign_selection_is_explicit_and_environment_bound(self):
        args = ['--cohort', L.COHORT, '--user-lookup-test-no-sandbox', '--user-lookup-disclosure', '--user-lookup-benign-capture']
        self.assertIn('--user-lookup-benign-capture', L.arguments(args))
        with self.assertRaises(RuntimeError):
            L.arguments(args + ['--user-lookup-benign-capture'])
        parsed = SimpleNamespace(browser_sha256='a' * 64, user_lookup_benign_capture=True)
        env = {'SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE':'1',
               'SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE':'1',
               'SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE':'1',
               'SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH':str(L.ROOT / 'tasks/qualification/run-controlled/user-lookup-benign-browser.json')}
        self.assertEqual(L.owned_environment(env, parsed)[0]['SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE'], '1')
        for changed in ({**env, 'SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE':'0'},
                        {**env, 'SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH':str(L.ROOT / 'tasks/qualification/run-controlled/user-lookup-disclosure-browser.json')}):
            with self.assertRaises(RuntimeError):
                L.owned_environment(changed, parsed)
        with self.assertRaises(RuntimeError):
            L.owned_environment(env, SimpleNamespace(browser_sha256='a' * 64))

    def test_benign_physical_budget_and_judge_gate_precede_dispatch(self):
        source = (L.ROOT / L.TEST).read_text()
        self.assertIn('maxHttpCalls: USER_LOOKUP_BENIGN ? 4 : USER_LOOKUP_BROWSER ? 8', source)
        self.assertIn('maximumPhysicalCalls: USER_LOOKUP_BENIGN ? 4 : USER_LOOKUP_BROWSER ? 8', source)
        self.assertIn("systemJudge = async input => {\n        assert.equal(USER_LOOKUP_BENIGN, false, 'Benign actor-negative capture cannot dispatch a configured Judge');\n        judgeCalls++;", source)

    def test_environment_preserves_original_roles_and_context(self):
        parsed = SimpleNamespace(browser_sha256='a' * 64)
        env = {'SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE': '1',
               'SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE': '1',
               'SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH':
                   str(L.ROOT / 'tasks/qualification/run-controlled/user-lookup-disclosure-browser.json'),
               'OLLAMA_CONTEXT_WINDOW': 'original', 'DATABASE_RUNTIME': 'runtime', 'DATABASE_MIGRATION': 'migration'}
        actual, evidence = L.owned_environment(env, parsed)
        for key, value in env.items():
            self.assertEqual(actual[key], value)
        self.assertEqual(actual['SECURESHOP_USER_LOOKUP_BROWSER_RECORD_PATH'], str(evidence / L.RECORD))
        for key in ('SECURESHOP_USER_LOOKUP_DISCLOSURE_BROWSER_NATIVE', 'SECURESHOP_ADMIN_USER_CHAT_BROWSER_NATIVE'):
            with self.assertRaises(RuntimeError):
                L.owned_environment({**env, key: '0'}, parsed)
        with self.assertRaises(RuntimeError):
            L.owned_environment({**env, 'SECURESHOP_ADMIN_USER_CHAT_BROWSER_EVIDENCE_PATH': '/foreign/receipt.json'}, parsed)

    def test_independent_lifecycle_and_exact_direct_node(self):
        watcher, ownership = L.lifecycle()
        parsed = SimpleNamespace(node='controlled-node')
        self.assertEqual(watcher.direct_command([parsed.node, '--test', '--test-reporter=tap',
            '--test-concurrency=1', L.TEST], parsed), [parsed.node, '--test-reporter=tap', L.TEST])
        self.assertEqual(watcher.KIND, 'user_lookup_disclosure_browser')
        self.assertEqual(ownership.PROFILE_PREFIX, 'owasp-ai-goat-user-lookup-browser-')
        original = L.load(L.LIFECYCLE, 'lookup_v12_unmodified_control')
        self.assertEqual(original.KIND, 'idor_lesson_browser')
        self.assertNotEqual(original.TEST, watcher.TEST)
        with self.assertRaises(RuntimeError):
            watcher.direct_command([parsed.node, '--test', 'foreign.js'], parsed)

    def test_exact_profile_and_independent_absence(self):
        evidence = L.ROOT / 'tasks/qualification/run-controlled'
        owner = SimpleNamespace(evidence=evidence, captured=SimpleNamespace(
            profile=str(evidence / 'runtime/tmp/owasp-ai-goat-user-lookup-browser-controlled'), record={'pid': 123}))
        absent = Mock(return_value={'absent': True})
        ownership = SimpleNamespace(_browser_modules=lambda: (None, None, None, None, absent))
        with patch.object(Path, 'exists', return_value=False), patch.object(Path, 'is_symlink', return_value=False):
            L.verify_retirement(owner, ownership)
        absent.assert_called_once_with([owner.captured.record])
        with patch.object(Path, 'exists', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'profile remains'):
                L.verify_retirement(owner, ownership)
        owner.captured.profile = str(evidence / 'runtime/tmp/owasp-ai-goat-v19-browser-foreign')
        with self.assertRaisesRegex(RuntimeError, 'ownership mismatch'):
            L.verify_retirement(owner, ownership)
        owner.captured.profile = str(evidence / 'runtime/tmp/owasp-ai-goat-user-lookup-browser-controlled')
        absent.side_effect = RuntimeError('still live')
        with self.assertRaisesRegex(RuntimeError, 'still live'):
            L.verify_retirement(owner, ownership)

    def test_closed_outer(self):
        args = []
        for key in sorted(C.REQUIRED):
            args += [key, str(C.ROOT) if key == '--main-workspace' else C.COHORT if key == '--cohort' else 'controlled']
        args += ['--run', '--user-lookup-test-no-sandbox', '--user-lookup-disclosure']
        command = C.child_command(args)
        self.assertEqual(command[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertNotIn('--run', command)
        self.assertIn('--user-lookup-benign-capture', C.child_command(args + ['--user-lookup-benign-capture']))
        with self.assertRaises(RuntimeError):
            C.child_command(args + ['--user-lookup-benign-capture'] * 2)
        for extra in (['--plan'], ['--shell', 'sh'], ['--run'], ['--v19-graph-diagnostic']):
            with self.assertRaises(RuntimeError):
                C.child_command(args + extra)

    def test_original_failure_survives_reporting_failure(self):
        primary = RuntimeError('original lookup failure')
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=lambda *a, **k: None),
                                 main=lambda argv: (_ for _ in ()).throw(primary))
        original = shared.subprocess.Popen
        with patch.object(L, 'inventory', side_effect=OSError('aftercheck failed')):
            with self.assertRaises(RuntimeError) as raised:
                L.run(shared, [], SimpleNamespace(), {})
        self.assertIs(raised.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)

    def test_frozen_inventory(self):
        L.validate_pins()
        self.assertTrue(set(L.PINS) <= L.inventory().keys())

    def test_failure_checks_captured_profile_without_replacing_primary(self):
        primary = RuntimeError('original receipt failure')
        owner = SimpleNamespace(captured=object(), evidence=None, error=None, retired=None)
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=object()),
                                 main=lambda argv: (_ for _ in ()).throw(primary))
        watcher = SimpleNamespace(BrowserOwner=lambda *args: owner)
        for retirement_failure in (None, RuntimeError('owned profile remains')):
            with patch.object(L, 'lifecycle', return_value=(watcher, object())), \
                    patch.object(L, 'inventory', return_value={}), \
                    patch.object(L, 'verify_retirement', side_effect=retirement_failure) as check:
                with self.assertRaises(RuntimeError) as raised:
                    L.run(shared, [], SimpleNamespace(), {})
                self.assertIs(raised.exception, primary)
                check.assert_called_once()

    def test_success_rechecks_profile_and_fails_closed_on_late_failure(self):
        owner = SimpleNamespace(captured=object(), evidence=None, error=None, retired=None)
        def main(argv):
            print('{"passed":true}')
            return 0
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=object()), main=main,
            effective_node_sha256=lambda args: 'nodehash', node_pin_matches=lambda *args: True)
        watcher = SimpleNamespace(BrowserOwner=lambda *args: owner)
        parsed = SimpleNamespace(browser='controlled', browser_sha256='hash', node='node')
        for late in (None, RuntimeError('profile reappeared')):
            with patch.object(L, 'lifecycle', return_value=(watcher, object())), \
                    patch.object(L, 'inventory', return_value={}), \
                    patch.object(L, 'digest', return_value='hash'), \
                    patch.object(L, 'verify_retirement', side_effect=[None, late]) as check:
                if late is None:
                    self.assertEqual(L.run(shared, [], parsed, {}), 0)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'profile reappeared'):
                        L.run(shared, [], parsed, {})
                self.assertEqual(check.call_count, 2)


if __name__ == '__main__':
    unittest.main()
