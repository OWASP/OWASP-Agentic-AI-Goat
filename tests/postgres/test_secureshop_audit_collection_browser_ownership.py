"""Controlled V36 process-ownership and wait/watcher tests; no live child/browser."""
import importlib.util
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('v36_owned_adapter', HERE / 'run-secureshop-audit-collection-browser.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class OwnedBrowserWait(unittest.TestCase):
    def _run_control(self, *, wait_error=None, capture_error=None, ack_error=False,
                     postspawn_error=None, thread_error=None, start_error=None,
                     retire_error=None, successful_main=False):
        primary = wait_error or RuntimeError('controlled Node failure')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            record_path = root / L.BROWSER_RECORD
            record_path.write_text('{}')
            record_path.chmod(0o600)
            ack_path = root / L.BROWSER_ACK
            record = {'pid': 5678, 'parentPid': 4321, 'pgid': 5678,
                      'sessionId': 5678, 'birth': [30, 40], 'executablePath': '/pinned/browser'}
            node = SimpleNamespace(pid=4321, ppid=os.getpid(), uid=os.getuid(),
                                   ruid=os.getuid(), pgid=4321, start_sec=10,
                                   start_usec=20, status=0)
            captured = L.CapturedV36(record, str(root / 'runtime/tmp/dvaia-admin-audit-jobs-controlled'), L._CAPTURE_KEY)
            observations = {'commands': [], 'retired': [], 'read': 0,
                            'ackAttempted': threading.Event(), 'captureAttempted': threading.Event()}

            class Api:
                def identity(self, pid):
                    if postspawn_error:
                        raise postspawn_error
                    return node if pid == 4321 else None

            class Child:
                pid = 4321
                def wait(self, **kwargs):
                    until = time.monotonic() + 2
                    while time.monotonic() < until:
                        if ack_path.exists() or observations['ackAttempted'].is_set() \
                                or observations['captureAttempted'].is_set() or postspawn_error is not None:
                            break
                        time.sleep(0.005)
                    if successful_main:
                        return 0
                    raise primary

            def popen(command, *args, **kwargs):
                observations['commands'].append((command, kwargs))
                return Child()

            def read_record(*args, **kwargs):
                observations['read'] += 1
                return [record]

            def capture(*args, **kwargs):
                if capture_error is not None:
                    observations['captureAttempted'].set()
                    raise capture_error
                return captured

            def retire(value, **kwargs):
                self.assertIs(value, captured)
                if retire_error is not None:
                    raise retire_error
                observations['retired'].append(value)
                return [{'pid': 5678, 'absent': True}]

            def replace(source, target):
                observations['ackAttempted'].set()
                if ack_error:
                    raise OSError('controlled ACK failure')
                return original_replace(source, target)

            class Main:
                subprocess = SimpleNamespace(Popen=popen)
                complete_tap_counts = staticmethod(lambda *args: None)
                admin_audit_jobs_receipt = staticmethod(lambda *args: None)
                ADMIN_AUDIT_JOBS_ASSERTION = 'original assertion'
                def main(self, argv):
                    command = ['/pinned/node', '--test', '--test-reporter=tap', '--test-concurrency=1', L.TEST]
                    child = self.subprocess.Popen(command, env={
                        'SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH': str(root / 'admin-audit-jobs-browser.json')})
                    result = child.wait(timeout=1)
                    if successful_main:
                        print(json.dumps({'evidence': str(root)}))
                    return result

            original_replace = os.replace
            browser_modules = (lambda: (Api, 99, None, read_record, lambda *args, **kwargs: []))
            parsed = SimpleNamespace(node='/pinned/node', browser='/pinned/browser',
                                     browser_sha256='a' * 64)
            thread_patch = patch.object(L.threading, 'Thread', side_effect=thread_error) \
                if thread_error is not None else contextlib.nullcontext()
            start_patch = patch.object(L.threading.Thread, 'start', side_effect=start_error) \
                if start_error is not None else contextlib.nullcontext()
            with patch.object(L, '_browser_modules', browser_modules), \
                 patch.object(L, 'capture_live_v36', capture), \
                 patch.object(L, 'retire_live_v36', retire), \
                 patch.object(L.os, 'getsid', lambda pid: pid), \
                 patch.object(L.os, 'replace', replace), thread_patch, start_patch:
                expected_error = RuntimeError if successful_main else type(
                    postspawn_error or thread_error or start_error or primary)
                with self.assertRaises(expected_error) as raised:
                    L.run(Main(), [], {'fixture': 'before'}, parsed, browser_opt_in=True)
            if successful_main:
                self.assertIn('capture incomplete', str(raised.exception))
            else:
                self.assertIs(raised.exception, postspawn_error or thread_error or start_error or primary)
            report = json.loads((root / 'v36-adapter-report.json').read_text())
            self.assertFalse(report['adapterPassed'])
            self.assertEqual(observations['commands'][0][0],
                             ['/pinned/node', '--test-reporter=tap', L.TEST])
            if postspawn_error is not None or thread_error is not None or start_error is not None:
                self.assertEqual(report['browserCapture']['captureError'],
                                 type(postspawn_error or thread_error or start_error).__name__)
                self.assertEqual(observations['retired'], [])
            elif capture_error is not None:
                self.assertEqual(report['browserCapture']['captureError'], type(capture_error).__name__)
                self.assertEqual(observations['retired'], [])
                self.assertFalse(report['browserCapture']['ackPresent'])
            elif ack_error:
                self.assertEqual(report['browserCapture']['captureError'], 'OSError')
                self.assertEqual(len(observations['retired']), 1)
                self.assertFalse(report['browserCapture']['ackPresent'])
            elif retire_error is not None:
                self.assertEqual(report['browserCapture']['captureError'], type(retire_error).__name__)
                self.assertEqual(observations['retired'], [])
                self.assertTrue(report['browserCapture']['liveCaptured'])
            else:
                self.assertEqual(len(observations['retired']), 1)
                self.assertTrue(report['browserCapture']['ackPresent'])
                self.assertTrue(report['browserCapture']['liveCaptured'])
            return observations

    def test_timeout_wait_retires_only_captured_browser_and_keeps_original_error(self):
        error = subprocess.TimeoutExpired('/pinned/node', 1)
        self._run_control(wait_error=error)

    def test_interrupt_wait_keeps_primary_and_captured_cleanup(self):
        self._run_control(wait_error=KeyboardInterrupt('controlled interrupt'))

    def test_capture_or_ack_failure_has_no_false_success(self):
        self._run_control(capture_error=RuntimeError('changed birth'))
        self._run_control(ack_error=True)

    def test_watcher_interrupt_is_reported_without_masking_primary(self):
        self._run_control(capture_error=KeyboardInterrupt('controlled watcher interruption'))

    def test_post_spawn_inspector_failure_returns_child_before_raising(self):
        self._run_control(postspawn_error=RuntimeError('inspector unavailable'))

    def test_post_spawn_thread_constructor_failure_returns_child_before_raising(self):
        self._run_control(thread_error=RuntimeError('thread constructor unavailable'))

    def test_post_spawn_watcher_start_failure_returns_child_before_raising(self):
        self._run_control(start_error=RuntimeError('watcher start unavailable'))

    def test_retirement_failure_keeps_original_timeout_and_is_reported(self):
        self._run_control(wait_error=subprocess.TimeoutExpired('/pinned/node', 1),
                          retire_error=RuntimeError('retirement denied'))

    def test_main_success_with_failed_birth_capture_still_writes_failure_report(self):
        self._run_control(capture_error=RuntimeError('birth mismatch'), successful_main=True)


class OwnedBrowserRetirement(unittest.TestCase):
    def _handle(self):
        record = {'pid': 5678, 'parentPid': 4321, 'uid': os.getuid(),
                  'pgid': 5678, 'sessionId': 5678, 'birth': [30, 40],
                  'executablePath': '/pinned/browser'}
        return L.CapturedV36(record, '/owned/run/runtime/tmp/dvaia-admin-audit-jobs-controlled',
                             L._CAPTURE_KEY)

    def test_term_then_kill_is_bounded_and_birth_checked(self):
        handle = self._handle()
        clock = [0.0]
        signals = []
        alive = [True]
        leader = SimpleNamespace(pid=5678, uid=os.getuid(), ruid=os.getuid(), pgid=5678,
                                 start_sec=30, start_usec=40)
        class Api:
            def identity(self, pid):
                return leader if alive[0] else None
        def members(*args, **kwargs):
            return [5678] if alive[0] else []
        def kill(group, sig):
            signals.append((group, sig))
            if sig == signal.SIGKILL:
                alive[0] = False
        with patch.object(L, '_browser_modules', return_value=(None, None, members, None,
                lambda rows, api: [{'pid': 5678, 'absent': True}])):
            result = L.retire_live_v36(handle, api=Api(), getsid=lambda _: 5678,
                killpg=kill, monotonic=lambda: clock[0], sleep=lambda n: clock.__setitem__(0, clock[0] + n))
        self.assertEqual(signals, [(5678, signal.SIGTERM), (5678, signal.SIGKILL)])
        self.assertEqual(result, [{'pid': 5678, 'absent': True}])
        self.assertLessEqual(clock[0], 5.2)

    def test_reused_leader_and_foreign_group_never_signal(self):
        handle = self._handle()
        signals = []
        changed = SimpleNamespace(pid=5678, uid=os.getuid(), ruid=os.getuid(), pgid=5678,
                                  start_sec=31, start_usec=40)
        class Api:
            def identity(self, pid):
                return changed
        for members in (lambda *args, **kwargs: [5678],
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('foreign group'))):
            with patch.object(L, '_browser_modules', return_value=(None, None, members, None,
                    lambda rows, api: [])):
                with self.assertRaises(RuntimeError):
                    L.retire_live_v36(handle, api=Api(), getsid=lambda _: 5678,
                                      killpg=lambda *args: signals.append(args))
        self.assertEqual(signals, [])


if __name__ == '__main__':
    unittest.main()
