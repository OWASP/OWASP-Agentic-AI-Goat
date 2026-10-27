"""Actual-source regression for owned Chrome temporary entries; no browser launch."""
import ast
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
SOURCE = MAIN.read_text()


def cleanup_state():
    function = next(node for node in ast.parse(SOURCE).body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'standalone_browser_cleanup_state')
    namespace = {'Path': Path, 'sys': types.SimpleNamespace(platform='darwin'),
                 'time': time, 're': re, 'subprocess': subprocess}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(MAIN), 'exec'), namespace)
    return namespace['standalone_browser_cleanup_state']


class ChromeTempCleanupState(unittest.TestCase):
    def test_owned_singleton_entries_block_absence(self):
        check = cleanup_state()
        inspector = types.SimpleNamespace(current_client=lambda: types.SimpleNamespace(absent=lambda *a, **kw: True))
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as area, \
                patch.dict(sys.modules, {'trusted_process_inspector': inspector}):
            runtime = Path(area) / 'runtime'
            temporary = runtime / 'tmp'
            temporary.mkdir(parents=True)
            self.assertEqual(check(runtime), {'browserProfilesAbsent': True, 'browserProcessesAbsent': True})
            chrome = temporary / 'com.google.Chrome.cnizo8'
            chrome.mkdir()
            (chrome / 'SingletonSocket').touch()
            (chrome / 'SingletonCookie').symlink_to('owned-cookie')
            self.assertFalse(check(runtime)['browserProfilesAbsent'])
            (chrome / 'SingletonSocket').unlink()
            (chrome / 'SingletonCookie').unlink()
            chrome.rmdir()
            self.assertTrue(check(runtime)['browserProfilesAbsent'])

    def test_symlink_entry_detected_without_following(self):
        check = cleanup_state()
        inspector = types.SimpleNamespace(current_client=lambda: types.SimpleNamespace(absent=lambda *a, **kw: True))
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as area, \
                patch.dict(sys.modules, {'trusted_process_inspector': inspector}):
            runtime = Path(area) / 'runtime'
            temporary = runtime / 'tmp'
            temporary.mkdir(parents=True)
            sibling = Path(area) / 'outside'
            sibling.mkdir()
            self.assertTrue(check(runtime)['browserProfilesAbsent'])
            (temporary / 'com.google.Chrome.alias').symlink_to(sibling, target_is_directory=True)
            self.assertFalse(check(runtime)['browserProfilesAbsent'])
            self.assertTrue(sibling.is_dir())


if __name__ == '__main__':
    unittest.main()
