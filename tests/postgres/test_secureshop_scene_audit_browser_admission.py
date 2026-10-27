"""Controlled V15 admission, source pin and ownership checks; no native work."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


L = load('run-secureshop-scene-audit-browser.py', 'v15_admission_control')
C = load('run_scene_audit_with_inspector.py', 'v15_outer_control')


class Admission(unittest.TestCase):
    def test_exact_selection_and_closed_outer_command(self):
        args = ['--cohort', L.COHORT, '--v15-test-no-sandbox']
        self.assertEqual(L.arguments(args), args[:2])
        for changed in (args[:-1], args + [args[-1]],
                        ['--cohort', 'admin-audit-jobs-browser', args[-1]],
                        ['--cohort', L.COHORT, '--cohort', L.COHORT, args[-1]]):
            with self.assertRaises(RuntimeError):
                L.arguments(changed)
        outside = []
        for key in sorted(C.REQUIRED):
            outside += [key, str(C.ROOT) if key == '--main-workspace'
                        else C.COHORT if key == '--cohort' else 'controlled']
        outside += ['--run', '--v15-test-no-sandbox']
        child = C.child_command(outside)
        self.assertEqual(child[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertIn(str(C.ROOT / 'tests/postgres/run-secureshop-scene-audit-browser.py'), child)
        self.assertNotIn('--run', child)
        for extra in (['--plan'], ['--run'], ['--v15-test-no-sandbox'], ['--shell', 'sh']):
            with self.assertRaises(RuntimeError):
                C.child_command(outside + extra)

    def test_environment_keeps_original_v15_without_mixing_other_modes(self):
        parsed = SimpleNamespace(browser_sha256='a' * 64)
        evidence = L.ROOT / 'tasks/qualification/run-controlled'
        env = {'SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE': '1',
               'SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH':
                   str(evidence / 'scene-audit-v15-browser.json'),
               'OLLAMA_CONTEXT_WINDOW': 'original',
               'PG_TEST_DISPOSABLE': 'yes', 'LIVE_OLLAMA_TEST': '1'}
        actual, owner = L.owned_environment(env, parsed)
        self.assertEqual(owner, evidence)
        for key, value in env.items():
            self.assertEqual(actual[key], value)
        self.assertEqual(actual['SECURESHOP_SCENE_AUDIT_TEST_NO_SANDBOX'], '1')
        self.assertEqual(actual['SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH'], str(evidence / L.RECORD))
        self.assertNotEqual(actual['SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH'],
                            env['SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH'])
        self.assertEqual(L.RECORD, 'scene-audit-v15-browser-birth.json')
        for changed in ({'SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE': '0'},
                        {'SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE': '1'},
                        {'SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE': '1'},
                        {'SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH': '/foreign/evidence.json'}):
            with self.assertRaises(RuntimeError):
                L.owned_environment({**env, **changed}, parsed)

    def test_lifecycle_is_independent_and_current_source_pins_are_exact(self):
        watcher, ownership = L.lifecycle()
        self.assertEqual(watcher.TEST, L.TEST)
        self.assertEqual(watcher.RECORD, L.RECORD)
        self.assertEqual(watcher.KIND, 'scene_audit_v15_browser')
        self.assertEqual(ownership.PROFILE_PREFIX, L.PROFILE)
        original = L.load(L.LIFECYCLE, 'v15_unmodified_lifecycle_control')
        self.assertNotEqual(original.TEST, watcher.TEST)
        self.assertNotEqual(original.KIND, watcher.KIND)
        L.validate_pins()
        self.assertEqual(set(L.PINS) | set(L.CONTROL_SOURCES), set(L.inventory()))
        for name in L.PINS:
            self.assertEqual(L.PINS[name], L.digest(L.ROOT / name))
        wrong = {**L.PINS, L.TEST: '0' * 64}
        with patch.object(L, 'PINS', wrong):
            with self.assertRaisesRegex(RuntimeError, 'frozen source mismatch'):
                L.validate_pins()

    def test_plan_checks_original_selection_without_running_native(self):
        parsed = SimpleNamespace(main_workspace=str(L.ROOT), current_host_profile='controlled',
                                 browser='controlled-browser', browser_sha256='a' * 64, plan=True)
        shared = SimpleNamespace(SCENE_AUDIT_BROWSER=L.COHORT, ADMIN_AUDIT_JOBS_TEST=L.TEST,
                                 parse=Mock(return_value=parsed), validate_static=Mock())
        with patch.object(L, 'load', return_value=shared), patch.object(L, 'run') as native:
            self.assertEqual(L.main(['--cohort', L.COHORT,
                                     '--v15-test-no-sandbox', '--plan']), 0)
        shared.validate_static.assert_called_once_with(parsed)
        native.assert_not_called()

    def test_adapter_specializes_original_static_guard_only_for_closed_v15_plan(self):
        shared = L.load(L.MAIN, 'v15_real_static_guard_control')
        argv = ['--cohort', L.COHORT, '--main-workspace', str(L.ROOT),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', shared.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'a' * 16, '--image-id', 'sha256:' + 'b' * 64,
                '--ollama-model-sha256', 'c' * 64,
                '--current-host-profile', 'controlled', '--browser', str(L.ROOT / L.TEST),
                '--browser-sha256', L.PINS[L.TEST], '--browser-root', str(L.ROOT), '--plan']
        parsed = shared.parse(argv)
        with patch.object(shared.subprocess, 'Popen', side_effect=AssertionError('external effect forbidden')) as spawn:
            with self.assertRaisesRegex(RuntimeError, '^Explicit dedicated qualification profile required$'):
                shared.validate_static(parsed)
            spawn.assert_not_called()
        output = io.StringIO()
        with patch.object(L, 'load', return_value=shared), \
                patch.object(shared, 'validate_current_host', return_value=None), \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main([*argv, '--v15-test-no-sandbox']), 0)
        value = json.loads(output.getvalue())
        self.assertFalse(value['nativeStarted'])
        self.assertEqual(value['sourceInventory'][L.TEST], L.PINS[L.TEST])
        self.assertEqual(shared.SCENE_AUDIT_TEST_SHA256, L.PINS[L.TEST])
        self.assertEqual(shared.SCENE_AUDIT_HELPER_SHA256, L.PINS[L.HELPER])
        self.assertEqual(shared.SCENE_AUDIT_CONTRACT_SHA256, L.PINS[L.CONTRACT])

    def test_original_failure_survives_report_or_retirement_failure(self):
        primary = RuntimeError('original V15 qualification failed')
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=object()),
                                 main=lambda argv: (_ for _ in ()).throw(primary))
        original = shared.subprocess.Popen
        owner = SimpleNamespace(captured=None, evidence=None, error=None, retired=None)
        watcher = SimpleNamespace(BrowserOwner=lambda *args: owner)
        with patch.object(L, 'lifecycle', return_value=(watcher, object())), \
                patch.object(L, 'inventory', side_effect=OSError('report unavailable')):
            with self.assertRaises(RuntimeError) as raised:
                L.run(shared, [], SimpleNamespace(), {})
        self.assertIs(raised.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)

    def test_success_requires_capture_retirement_and_unchanged_sources(self):
        def successful(argv):
            print('{"passed":true}')
            return 0
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=object()), main=successful)
        original = shared.subprocess.Popen
        owner = SimpleNamespace(captured=None, evidence=None, error=None, retired=None)
        watcher = SimpleNamespace(BrowserOwner=lambda *args: owner)
        with patch.object(L, 'lifecycle', return_value=(watcher, object())), \
                patch.object(L, 'inventory', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'capture incomplete'):
                L.run(shared, [], SimpleNamespace(), {})
        self.assertIs(shared.subprocess.Popen, original)
        owner.captured = SimpleNamespace(record={'pid': 1})
        absent = Mock(side_effect=RuntimeError('browser still live'))
        ownership = SimpleNamespace(_browser_modules=lambda: (None, None, None, None, absent))
        with patch.object(L, 'lifecycle', return_value=(watcher, ownership)), \
                patch.object(L, 'inventory', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'browser still live'):
                L.run(shared, [], SimpleNamespace(), {})
        absent.assert_called_once_with([owner.captured.record])
        self.assertIs(shared.subprocess.Popen, original)


if __name__ == '__main__':
    unittest.main()
