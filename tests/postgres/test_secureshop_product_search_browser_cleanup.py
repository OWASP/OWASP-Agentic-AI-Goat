"""Resource-free V53 browser profile absence regression."""

import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import os
import signal
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'product_search_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class ProductSearchBrowserCleanup(unittest.TestCase):
    def setUp(self):
        # These fixtures explicitly exercise the retained ps parser.
        platform = patch.object(LAUNCHER.sys, 'platform', 'linux')
        platform.start()
        self.addCleanup(platform.stop)

    def test_residual_owned_profile_fails_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            temporary = runtime / 'tmp'
            temporary.mkdir()
            with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(stdout='')):
                self.assertEqual(LAUNCHER.standalone_browser_cleanup_state(runtime),
                                 {'browserProfilesAbsent': True, 'browserProcessesAbsent': True})
                residual = temporary / 'dvaia-product-search-browser-residual'
                residual.mkdir()
                self.assertEqual(LAUNCHER.standalone_browser_cleanup_state(runtime),
                                 {'browserProfilesAbsent': False, 'browserProcessesAbsent': True})

    def test_exited_leader_retires_only_its_owned_session_group(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        roster = f'73122 73121 {os.getuid()}\n'
        run = [SimpleNamespace(returncode=0, stdout=roster),
               SimpleNamespace(returncode=0, stdout='')]
        with patch.object(LAUNCHER.subprocess, 'run', side_effect=run), \
                patch.object(LAUNCHER.os, 'getsid', return_value=child.pid), \
                patch.object(LAUNCHER.os, 'killpg') as kill, \
                patch.object(LAUNCHER.time, 'sleep'):
            LAUNCHER.stop_process_group(child)
        kill.assert_called_once_with(child.pid, signal.SIGTERM)

    def test_exited_leader_rejects_foreign_session_before_signal(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        roster = f'73122 73121 {os.getuid()}\n'
        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=roster)), \
                patch.object(LAUNCHER.os, 'getsid', return_value=child.pid + 1), \
                patch.object(LAUNCHER.os, 'killpg') as kill:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                LAUNCHER.stop_process_group(child)
        kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
