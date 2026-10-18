"""Resource-free controls for the V04 storage adapter's real dispatch contract."""
import sys
sys.dont_write_bytecode = True
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('run-secureshop-restart-full-receipt-isolated.py')
SPEC = importlib.util.spec_from_file_location('restart_full_receipt_launcher_tested', PATH)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class RestartFullReceiptLauncher(unittest.TestCase):
    def test_plan_has_only_two_disposable_review_stores_and_no_resources(self):
        output = io.StringIO()
        with patch.object(launcher, 'validate_sources'), patch.object(launcher.importlib.util, 'spec_from_file_location',
                          side_effect=AssertionError('plan must not load resource launcher')):
            with contextlib.redirect_stdout(output):
                self.assertEqual(launcher.main(['--plan']), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['stores'], [['FRESH', 'secureshop_review'], ['POPULATED', 'secureshop_review']])
        self.assertEqual(value['expectedTests'], 2)
        self.assertIs(value['allocationStarted'], False)
        self.assertIs(value['actualModel'], False)
        self.assertIs(value['sourceCopies'], False)

    def test_actual_shared_dispatch_and_inventory_are_closed(self):
        spec = importlib.util.spec_from_file_location('restart_full_receipt_real_shared_contract', launcher.SHARED)
        shared = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shared)  # Import does not load the resource lifecycle.
        original_main = shared.main
        original_suites = dict(shared.SUITES)
        seen = []
        shared.source_inventory = lambda paths: seen.extend(paths) or {'controlled': True}
        configured = launcher.configure(shared, run=True)
        self.assertIs(configured.main, original_main)
        self.assertEqual(configured.SUITES,
            {'restart-full-receipt': (launcher.FIXTURE, launcher.PREFIX, launcher.STORES, 2)})
        self.assertGreater(len(original_suites), 1)
        self.assertTrue(configured.arguments().run)
        self.assertEqual(configured.arguments().suite, 'restart-full-receipt')
        self.assertEqual(configured.source_inventory([]), {'controlled': True})
        self.assertIn(PATH.resolve(), seen)
        self.assertIn(Path(__file__).resolve(), seen)
        for relative in launcher.PINS:
            self.assertIn(launcher.ROOT / relative, seen)
        self.assertIn(launcher.ROOT / 'sidecars/sandbox-runner/owned-system/restart-contract.js', seen)

    def test_real_run_path_delegates_original_main_once(self):
        selected = []
        shared = SimpleNamespace(source_inventory=lambda extra: {},
            main=lambda: selected.append(shared.arguments().suite) or 0)
        loader = SimpleNamespace(exec_module=lambda value: None)
        with patch.object(launcher, 'validate_sources'), patch.object(launcher.importlib.util, 'spec_from_file_location',
                          return_value=SimpleNamespace(loader=loader)), \
             patch.object(launcher.importlib.util, 'module_from_spec', return_value=shared):
            self.assertEqual(launcher.main(['--run']), 0)
        self.assertEqual(selected, ['restart-full-receipt'])

    def test_all_exact_source_pins_checked_before_dispatch(self):
        expected = {launcher.ROOT / launcher.FIXTURE: launcher.FIXTURE_SHA256,
                    launcher.SHARED: launcher.SHARED_SHA256,
                    **{launcher.ROOT / path: digest for path, digest in launcher.PINS.items()}}
        with patch.object(launcher, 'sha', side_effect=lambda path: expected[Path(path)]) as digest:
            launcher.validate_sources()
        self.assertEqual(digest.call_count, len(expected))
        self.assertEqual(len(launcher.PINS), 3)

    def test_source_pin_mismatch_prevents_dispatch(self):
        with patch.object(launcher, 'sha', return_value='0' * 64), \
             patch.object(launcher.importlib.util, 'spec_from_file_location',
                          side_effect=AssertionError('must reject before resource import')):
            with self.assertRaisesRegex(RuntimeError, 'source pin mismatch'):
                launcher.main(['--run'])


if __name__ == '__main__':
    unittest.main()
