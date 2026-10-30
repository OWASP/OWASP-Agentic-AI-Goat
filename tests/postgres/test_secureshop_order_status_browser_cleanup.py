"""Inert V50 browser-profile cleanup regression."""

import importlib.util
import ast
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'order_status_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class OrderStatusBrowserCleanup(unittest.TestCase):
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
                (temporary / 'owasp-ai-goat-order-status-browser-residual').mkdir()
                self.assertEqual(LAUNCHER.standalone_browser_cleanup_state(runtime),
                                 {'browserProfilesAbsent': False, 'browserProcessesAbsent': True})

    def test_exited_leader_ignores_only_verified_owned_zombie(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        zombie = f'73122 73121 {os.getuid()} Z\n'
        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=zombie)), \
                patch.object(LAUNCHER.os, 'getsid', return_value=child.pid), \
                patch.object(LAUNCHER.os, 'killpg') as kill:
            LAUNCHER.stop_process_group(child)
        kill.assert_not_called()

    def test_zombie_with_foreign_session_still_fails_closed(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        zombie = f'73122 73121 {os.getuid()} Z\n'
        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=zombie)), \
                patch.object(LAUNCHER.os, 'getsid', return_value=child.pid + 1), \
                patch.object(LAUNCHER.os, 'killpg') as kill:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                LAUNCHER.stop_process_group(child)
        kill.assert_not_called()

    def test_unrelated_negative_uid_does_not_block_owned_inventory(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        unrelated = '701 701 -2 S\n'
        owned_zombie = f'73122 {child.pid} {os.getuid()} Z\n'
        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=unrelated + owned_zombie)), \
                patch.object(LAUNCHER.os, 'getsid', return_value=child.pid), \
                patch.object(LAUNCHER.os, 'killpg') as kill:
            LAUNCHER.stop_process_group(child)
        kill.assert_not_called()

    def test_owned_negative_uid_still_fails_closed(self):
        child = SimpleNamespace(pid=73121, poll=lambda: 0)
        owned = f'73122 {child.pid} -2 S\n'
        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=owned)), \
                patch.object(LAUNCHER.os, 'killpg') as kill:
            with self.assertRaisesRegex(RuntimeError, 'inventory malformed'):
                LAUNCHER.stop_process_group(child)
        kill.assert_not_called()

    def test_retirement_reason_is_a_bounded_category(self):
        self.assertEqual(LAUNCHER.process_retire_category(
            RuntimeError('Owned test process group remains')), 'group-remains')
        self.assertEqual(LAUNCHER.process_retire_category(
            RuntimeError('unexpected private detail')), 'other')

    def test_nonzero_node_result_is_not_classified_as_retirement(self):
        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        run_node = next(node for parent in ast.walk(tree)
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
            for node in parent.body if isinstance(node, ast.FunctionDef) and node.name == 'run_node')
        statements = [ast.unparse(node) for node in run_node.body]
        retire = statements.index("stage = f'node-{label}-retire'")
        result = statements.index("stage = f'node-{label}-result'")
        # The ordinary nonzero-result guard may be an elif after an explicitly
        # selected diagnostic failure. Check its AST position, not indentation.
        failure_guards = [(index, child) for index, statement in enumerate(run_node.body)
            for child in ast.walk(statement) if isinstance(child, ast.If)
            and ast.unparse(child.test) == 'code != 0']
        self.assertEqual(len(failure_guards), 1)
        failed, guard = failure_guards[0]
        self.assertTrue(any(isinstance(node, ast.Raise) for node in guard.body))
        self.assertLess(retire, result)
        self.assertLess(result, failed)


if __name__ == '__main__':
    unittest.main()
