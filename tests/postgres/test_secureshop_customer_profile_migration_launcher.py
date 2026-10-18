#!/usr/bin/env python3
"""Closed disposable review-store admission for customer profile migration."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
PATH = HERE / 'run-persona-transition-main-isolated.py'
SPEC = importlib.util.spec_from_file_location('persona_profile_launcher', PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class CustomerProfileMigrationLauncherContract(unittest.TestCase):
    def test_closed_disposable_review_pairs_and_one_tap(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['customer-profile-migration']
        self.assertEqual(fixture, 'tests/postgres/secureshopCustomerProfileMigration.integration.test.js')
        self.assertEqual(prefix, 'PG_SECURESHOP_PROFILE_')
        self.assertEqual(stores, (('FRESH', 'secureshop_review'),
                                  ('POPULATED', 'secureshop_review')))
        self.assertEqual(count, 1)
        self.assertTrue((LAUNCHER.ROOT / fixture).is_file())

    def test_plan_does_not_allocate_or_use_installed_stores(self):
        result = subprocess.run([sys.executable, '-B', str(PATH), '--suite',
                                 'customer-profile-migration', '--plan'],
                                capture_output=True, text=True, check=True)
        self.assertIn('"plan": true', result.stdout)
        self.assertIn('"sourceCopies": false', result.stdout)
        self.assertIn('"actualModel": false', result.stdout)
        self.assertNotIn('postgresql://', result.stdout)


if __name__ == '__main__':
    unittest.main()
