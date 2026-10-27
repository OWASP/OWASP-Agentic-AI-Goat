"""Full V19 scoped adapter controls; no native resources."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import sys
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


L = load('run-secureshop-v19-browser.py')
C = load('run_v19_with_inspector.py')


class Admission(unittest.TestCase):
    def test_only_full_cohort(self):
        args = ['--cohort', L.COHORT, '--v19-test-no-sandbox']
        self.assertEqual(L.arguments(args), args[:2])
        for values in (args + ['--v19-graph-diagnostic'], args + ['--v19-graph-diagnostic=true'],
                       args + ['--v19-test-no-sandbox'], args[:2],
                       ['--cohort', 'customer-checkout-browser', '--v19-test-no-sandbox']):
            with self.assertRaises(RuntimeError):
                L.arguments(values)

    def test_exact_environment_preserves_original_context_and_roles(self):
        parsed = SimpleNamespace(browser_sha256='a' * 64)
        env = {'SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE': '1',
               'SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH':
                   str(L.ROOT / 'tasks/qualification/run-controlled/customer-file-summary-v19-browser.json'),
               'OLLAMA_CONTEXT_WINDOW': 'original', 'DATABASE_RUNTIME': 'runtime', 'DATABASE_MIGRATION': 'migration'}
        actual, evidence = L.owned_environment(env, parsed)
        for key, value in env.items():
            self.assertEqual(actual[key], value)
        self.assertEqual(actual['SECURESHOP_V19_BROWSER_RECORD_PATH'], str(evidence / L.RECORD))
        with self.assertRaises(RuntimeError):
            L.owned_environment({**env, 'SECURESHOP_V19_FILE_SUMMARY_DIAGNOSTIC_NATIVE': '1'}, parsed)

    def test_lifecycle_independent_and_exact_direct_node(self):
        watcher, ownership = L.lifecycle()
        parsed = SimpleNamespace(node='controlled-node')
        self.assertEqual(watcher.direct_command([parsed.node, '--test', '--test-reporter=tap',
            '--test-concurrency=1', L.TEST], parsed), [parsed.node, '--test-reporter=tap', L.TEST])
        self.assertEqual(watcher.KIND, 'v19_file_summary_browser')
        self.assertEqual(ownership.PROFILE_PREFIX, 'dvaia-v19-browser-')
        original = L.load(L.LIFECYCLE, 'v12_unmodified_control')
        self.assertNotEqual(original.TEST, watcher.TEST)
        self.assertEqual(original.KIND, 'idor_lesson_browser')
        with self.assertRaises(RuntimeError):
            watcher.direct_command([parsed.node, '--test', 'foreign.js'], parsed)

    def test_closed_outer_no_diagnostic_or_arbitrary_command(self):
        args = []
        for key in sorted(C.REQUIRED):
            args += [key, str(C.ROOT) if key == '--main-workspace' else C.COHORT if key == '--cohort' else 'controlled']
        args += ['--run', '--v19-test-no-sandbox']
        command = C.child_command(args)
        self.assertEqual(command[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertNotIn('--run', command)
        for extra in (['--v19-graph-diagnostic'], ['--shell', 'sh'], ['--run']):
            with self.assertRaises(RuntimeError):
                C.child_command(args + extra)

    def test_original_failure_not_replaced_by_supplement(self):
        primary = RuntimeError('original V19 failure')
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=lambda *a, **k: None),
                                 main=lambda argv: (_ for _ in ()).throw(primary))
        original = shared.subprocess.Popen
        with patch.object(L, 'inventory', side_effect=OSError('aftercheck failed')):
            with self.assertRaises(RuntimeError) as raised:
                L.run(shared, [], SimpleNamespace(), {})
        self.assertIs(raised.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)

    def test_only_reviewed_pin_overrides_with_original_limits(self):
        with patch.object(sys, 'path', [str(Path(__file__).parent.resolve()), *sys.path]):
            shared = L.load(L.MAIN, 'v19_original_control')
        before = dict(shared.V19_SUMMARY_PINS)
        L.configure_shared(shared)
        self.assertEqual(shared.V19_SUMMARY_PINS, before)
        for name, pin in before.items():
            self.assertEqual(L.digest(L.ROOT / name), pin)
            with self.subTest(path=name), self.assertRaisesRegex(RuntimeError, 'Pinned V19 source changed'):
                shared.validate_v19_summary_pins(L.ROOT, lambda path, selected=name:
                    '0' * 64 if path == L.ROOT / selected else L.digest(path))
        shared.V19_SUMMARY_LIMITS = {**shared.V19_SUMMARY_LIMITS, 'postRetries': 1}
        with self.assertRaises(RuntimeError):
            L.configure_shared(shared)

    def test_frozen_inventory(self):
        L.validate_pins()
        self.assertTrue(set(L.PINS) <= L.inventory().keys())


if __name__ == '__main__':
    unittest.main()
