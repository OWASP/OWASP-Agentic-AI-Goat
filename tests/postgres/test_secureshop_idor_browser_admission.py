"""Controlled V12 admission/ownership contracts; no native/model/browser run."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


L = module('run-secureshop-idor-lesson-browser.py', 'v12_controlled')
C = module('run_idor_lesson_with_inspector.py', 'v12_outer_controlled')


class Admission(unittest.TestCase):
    def setUp(self):
        self.parsed = SimpleNamespace(node='/controlled/node', browser='/controlled/chrome',
                                      browser_sha256='a' * 64)
        self.command = [self.parsed.node, '--test', '--test-reporter=tap',
                        '--test-concurrency=1', L.TEST]

    def test_closed_cohort_and_direct_command(self):
        self.assertEqual(L.arguments(['--cohort', L.COHORT, '--v12-test-no-sandbox']),
                         ['--cohort', L.COHORT])
        for values in (['--cohort', L.COHORT],
                       ['--cohort', 'customer-idor-cart-v10-browser', '--v12-test-no-sandbox'],
                       ['--cohort', L.COHORT, '--v12-test-no-sandbox', '--v12-test-no-sandbox']):
            with self.assertRaises(RuntimeError):
                L.arguments(values)
        self.assertEqual(L.direct_command(self.command, self.parsed),
                         [self.parsed.node, '--test-reporter=tap', L.TEST])
        for command in (self.command + ['--extra'], [self.parsed.node, L.TEST]):
            with self.assertRaises(RuntimeError):
                L.direct_command(command, self.parsed)

    def test_environment_preserves_original_roles_and_caps(self):
        env = {'SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE': '1',
               'SECURESHOP_CUSTOMER_IDOR_LESSON_EVIDENCE_PATH':
                   str(L.ROOT / 'tasks/qualification/run-controlled/customer-idor-lesson-browser.json'),
               'PG_SECURESHOP_CUSTOMER_IDOR_LESSON_COMMERCE_RUNTIME_URL': 'controlled-runtime',
               'PG_SECURESHOP_CUSTOMER_IDOR_LESSON_COMMERCE_MIGRATION_URL': 'controlled-migration',
               'OLLAMA_CONTEXT_WINDOW': 'original'}
        actual, evidence = L.owned_environment(env, self.parsed)
        for key, value in env.items():
            self.assertEqual(actual[key], value)
        self.assertEqual(actual['SECURESHOP_IDOR_LESSON_TEST_NO_SANDBOX'], '1')
        self.assertEqual(actual['SECURESHOP_IDOR_LESSON_BROWSER_RECORD_PATH'], str(evidence / L.RECORD))
        for patch_value in ({'SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY': '1'},
                            {'SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE': '0'},
                            {'SECURESHOP_CUSTOMER_IDOR_LESSON_EVIDENCE_PATH': '/foreign/receipt.json'}):
            with self.assertRaises(RuntimeError):
                L.owned_environment({**env, **patch_value}, self.parsed)

    def test_outer_closed_command(self):
        arguments = []
        for key in sorted(C.REQUIRED):
            value = str(C.ROOT) if key == '--main-workspace' else C.COHORT if key == '--cohort' else 'controlled'
            arguments += [key, value]
        arguments += ['--run', '--v12-test-no-sandbox']
        command = C.child_command(arguments)
        self.assertEqual(command[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertIn(str(C.ROOT / 'tests/postgres/run-secureshop-idor-lesson-browser.py'), command)
        self.assertNotIn('--run', command)
        for extra in (['--shell', 'sh'], ['--run'], ['--v36-test-no-sandbox']):
            with self.assertRaises(RuntimeError):
                C.child_command(arguments + extra)

    def test_unrelated_command_unmodified(self):
        calls = []
        sentinel = object()
        owner = L.BrowserOwner(lambda command, **kwargs: calls.append((command, kwargs)) or sentinel,
                               self.parsed, None)
        command, env = ['controlled-other'], {'unchanged': 'yes'}
        self.assertIs(owner(command, env=env), sentinel)
        self.assertEqual(calls, [(command, {'env': env})])

    def test_postspawn_error_returns_child_before_raise(self):
        primary = RuntimeError('live identity unavailable')
        child = SimpleNamespace(pid=123, wait=lambda **kwargs: 0)
        ownership = SimpleNamespace(_browser_modules=lambda: (_ for _ in ()).throw(primary))
        owner = L.BrowserOwner(lambda *args, **kwargs: child, self.parsed, ownership)
        with patch.object(L, 'owned_environment', return_value=({}, L.ROOT / 'tasks/tmp')):
            self.assertIs(owner(self.command, env={}), child)
        with self.assertRaises(RuntimeError) as raised:
            child.wait(timeout=1)
        self.assertIs(raised.exception, primary)
        self.assertEqual(child.wait(timeout=1), 0)

    def _watcher_case(self, *, wait_error=None, setup_error=False, capture_error=False):
        temporary = tempfile.TemporaryDirectory(dir=L.ROOT / 'tasks/tmp')
        self.addCleanup(temporary.cleanup)
        evidence = Path(temporary.name)
        (evidence / L.RECORD).write_text('{}')
        parent = SimpleNamespace(ppid=os.getpid(), uid=os.getuid(), ruid=os.getuid(),
                                 pgid=123, status=1, start_sec=2, start_usec=3)
        captured = SimpleNamespace(record={'pid': 456, 'pgid': 456}, profile='owned-profile')
        events = []
        def capture(*args, **kwargs):
            events.append('capture')
            if capture_error:
                raise RuntimeError('forged live record')
            return captured
        ownership = SimpleNamespace(
            _browser_modules=lambda: (lambda: SimpleNamespace(identity=lambda pid: parent),
                5, None, lambda *args, **kwargs: [{'pid': 456}], None),
            capture_live_v36=capture,
            retire_live_v36=lambda *args, **kwargs: events.append('retire') or {'absent': True})
        def wait(**kwargs):
            if wait_error:
                raise wait_error
            return 0
        child = SimpleNamespace(pid=123, wait=wait)
        class Thread:
            def __init__(self, *, target, **kwargs):
                self.target = target
            def start(self):
                if setup_error:
                    raise RuntimeError('thread setup failed')
                self.target()
            def join(self, **kwargs):
                events.append('join')
            def is_alive(self):
                return False
        owner = L.BrowserOwner(lambda *args, **kwargs: child, self.parsed, ownership)
        with patch.object(L, 'owned_environment', return_value=({}, evidence)), \
                patch.object(L.os, 'getsid', return_value=123), \
                patch.object(L.threading, 'Thread', Thread):
            self.assertIs(owner(self.command), child)
        return owner, child, events, evidence

    def test_live_capture_ack_and_retirement(self):
        owner, child, events, evidence = self._watcher_case()
        ack = json.loads((evidence / L.ACK).read_text())
        self.assertEqual(ack['recordSha256'], L.digest(evidence / L.RECORD))
        self.assertEqual((ack['parentPid'], ack['browserPid'], ack['profile']), (123, 456, 'owned-profile'))
        self.assertEqual((evidence / L.ACK).stat().st_mode & 0o777, 0o600)
        self.assertEqual(child.wait(timeout=1), 0)
        self.assertEqual(events, ['capture', 'join', 'retire'])
        self.assertEqual(owner.retired, {'absent': True})

    def test_timeout_preserved_and_captured_browser_retired(self):
        primary = subprocess.TimeoutExpired('controlled', 1)
        owner, child, events, _ = self._watcher_case(wait_error=primary)
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            child.wait(timeout=1)
        self.assertIs(raised.exception, primary)
        self.assertEqual(events[-1], 'retire')

    def test_forged_capture_never_acknowledged_or_signaled(self):
        owner, child, events, evidence = self._watcher_case(capture_error=True)
        self.assertFalse((evidence / L.ACK).exists())
        child.wait(timeout=1)
        self.assertIsNotNone(owner.error)
        self.assertNotIn('retire', events)

    def test_thread_setup_failure_returns_owned_child(self):
        owner, child, _, _ = self._watcher_case(setup_error=True)
        with self.assertRaisesRegex(RuntimeError, 'thread setup failed'):
            child.wait(timeout=1)
        self.assertEqual(child.wait(timeout=1), 0)

    def test_original_error_survives_inventory_and_report_failures(self):
        primary = RuntimeError('original fixture failure')
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=lambda *args, **kwargs: None),
                                 main=lambda argv: (_ for _ in ()).throw(primary))
        original = shared.subprocess.Popen
        with patch.object(L, 'inventory', side_effect=OSError('supplement failed')):
            with self.assertRaises(RuntimeError) as raised:
                L.run(shared, [], self.parsed, None, {})
        self.assertIs(raised.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)

    def test_current_pins_and_inventory(self):
        L.validate_pins()
        self.assertTrue(set(L.PINS) <= L.inventory().keys())
        self.assertIn('tests/postgres/run_audit_collection_with_inspector.py', L.inventory())


if __name__ == '__main__':
    unittest.main()
