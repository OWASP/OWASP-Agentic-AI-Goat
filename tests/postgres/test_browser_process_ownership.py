import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from browser_process_ownership import (
    cleanup_browser_profile, process_rows, validate_browser_postflight,
)


class BrowserOwnership(unittest.TestCase):
    def fixture(self, directory, *, inner=False, role="rendered"):
        prefix = "browser" if role == "rendered" else "assessment-browser"
        runtime = Path(directory).resolve() / 'runtime'
        runtime.mkdir(mode=0o700)
        profile = runtime / (prefix + '-profile')
        profile.mkdir(mode=0o700)
        (profile / 'owned').write_text('owned')
        qualification = dict(name='qualification', pid=4100, pgid=4100,
                             sessionId=4100, status='cleanup_verified')
        browser = dict(pid=4101, pgid=4100, sessionId=4100, uid=os.getuid(),
                       qualificationPid=4100, qualificationPgid=4100,
                       qualificationSessionId=4100, workerPid=4102, profile=str(profile),
                       executableSha256='a' * 64)
        journal = runtime / (prefix + '-process.json')
        journal.write_text(json.dumps(browser));journal.chmod(0o600)
        if inner:
            receipt = runtime / (prefix + '-cleanup.json')
            receipt.write_text(json.dumps(dict(browserPid=4101, pidAbsent=True,
                                               profileAbsent=True, closed=True)))
            receipt.chmod(0o600)
            profile.rmdir() if not any(profile.iterdir()) else (profile / 'owned').unlink()
            if profile.exists(): profile.rmdir()
        return runtime, qualification, browser

    def test_failed_run_removes_only_bound_profile_without_claiming_close(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory)
            receipt = cleanup_browser_profile(runtime, qualification, rows=[], successful=False)
            self.assertFalse(receipt['innerCloseVerified'])
            self.assertFalse(receipt['browserClosedClaimed'])
            self.assertFalse((runtime / 'browser-profile').exists())
            self.assertTrue(validate_browser_postflight(runtime, qualification, receipt,
                                                         successful=False, rows=[]))

    def test_assessment_cleanup_preserves_rendered_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory, role='assessment')
            sibling = runtime / 'browser-profile'
            sibling.mkdir(mode=0o700)
            (sibling / 'sentinel').write_text('preserve')
            receipt = cleanup_browser_profile(runtime, qualification, rows=[], role='assessment')
            self.assertFalse((runtime / 'assessment-browser-profile').exists())
            self.assertEqual((sibling / 'sentinel').read_text(), 'preserve')
            self.assertTrue(validate_browser_postflight(runtime, qualification, receipt,
                            successful=False, rows=[], role='assessment'))
            with self.assertRaises(FileNotFoundError):
                validate_browser_postflight(runtime, qualification, receipt, successful=False, rows=[])

    def test_assessment_success_requires_its_own_close_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory, inner=True, role='assessment')
            receipt = cleanup_browser_profile(runtime, qualification, rows=[], successful=True, role='assessment')
            self.assertTrue(receipt['innerCloseVerified'])
            (runtime / 'assessment-browser-cleanup.json').rename(runtime / 'browser-cleanup.json')
            with self.assertRaisesRegex(RuntimeError, 'graceful browser close'):
                validate_browser_postflight(runtime, qualification, receipt,
                                            successful=True, rows=[], role='assessment')

    def test_unknown_role_cannot_select_arbitrary_cleanup_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory)
            for role in ['../browser', '', 'backend', None]:
                with self.assertRaisesRegex(RuntimeError, 'Unknown owned browser role'):
                    cleanup_browser_profile(runtime, qualification, rows=[], role=role)
            self.assertTrue((runtime / 'browser-profile/owned').exists())

    def test_dangling_inner_receipt_is_not_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory)
            (runtime / 'browser-cleanup.json').symlink_to(runtime / 'missing-receipt')
            with self.assertRaises(RuntimeError):
                cleanup_browser_profile(runtime, qualification, rows=[], successful=False)
            self.assertTrue((runtime / 'browser-profile/owned').is_file())

    def test_success_requires_exact_inner_graceful_close(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory)
            with self.assertRaisesRegex(RuntimeError, 'graceful browser close'):
                cleanup_browser_profile(runtime, qualification, rows=[], successful=True)
        with tempfile.TemporaryDirectory() as directory:
            runtime, qualification, _ = self.fixture(directory, inner=True)
            receipt = cleanup_browser_profile(runtime, qualification, rows=[], successful=True)
            self.assertTrue(receipt['innerCloseVerified'])
            self.assertTrue(receipt['browserClosedClaimed'])
            self.assertTrue(validate_browser_postflight(runtime, qualification, receipt,
                                                         successful=True, rows=[]))

    def test_live_or_mismatched_identity_preserves_profile(self):
        cases = [
            ('live PID', lambda q, b: [(b['pid'], 99, 98, os.getuid())]),
            ('live group', lambda q, b: [(99, b['pgid'], 98, os.getuid())]),
            ('live session', lambda q, b: [(99, 98, b['sessionId'], os.getuid())]),
            ('foreign UID', lambda q, b: [(b['pid'], b['pgid'], b['sessionId'], os.getuid() + 1)]),
        ]
        for label, rows in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                runtime, qualification, browser = self.fixture(directory)
                with self.assertRaises(RuntimeError):
                    cleanup_browser_profile(runtime, qualification,
                                            rows=rows(qualification, browser), successful=False)
                self.assertTrue((runtime / 'browser-profile/owned').is_file())
        for field, value in [('qualificationPid', 999), ('pgid', 999), ('sessionId', 999),
                             ('uid', os.getuid() + 1), ('profile', '/tmp/foreign')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                runtime, qualification, browser = self.fixture(directory)
                browser[field] = value
                path = runtime / 'browser-process.json'
                path.write_text(json.dumps(browser));path.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    cleanup_browser_profile(runtime, qualification, rows=[], successful=False)
                self.assertTrue((runtime / 'browser-profile/owned').is_file())

    def test_real_owned_process_group_must_be_gone_before_cleanup(self):
        script = ('import subprocess,sys,time; '
                  'c=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                  'print(c.pid,flush=True); time.sleep(30)')
        owner = subprocess.Popen([sys.executable, '-c', script], start_new_session=True,
                                 stdout=subprocess.PIPE, text=True)
        browser_pid = int(owner.stdout.readline().strip())
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                rows = process_rows()
                match = next((row for row in rows if row[0] == browser_pid), None)
                if match: break
                time.sleep(0.02)
            self.assertIsNotNone(match)
            self.assertEqual(match[1:3], (owner.pid, owner.pid))
            with self.assertRaisesRegex(RuntimeError, 'remains'):
                # Directly exercise the live roster binding without trusting it for a signal.
                from browser_process_ownership import _assert_absent
                _assert_absent(dict(pid=browser_pid, pgid=owner.pid, session_id=owner.pid), rows)
        finally:
            try: os.killpg(owner.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            owner.wait(timeout=3)
            owner.stdout.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            rows = process_rows()
            if not any(row[0] == browser_pid or row[1] == owner.pid or row[2] == owner.pid for row in rows):
                break
            time.sleep(0.02)
        self.assertFalse(any(row[0] == browser_pid or row[1] == owner.pid or row[2] == owner.pid
                             for row in rows))


if __name__ == '__main__':
    unittest.main()
