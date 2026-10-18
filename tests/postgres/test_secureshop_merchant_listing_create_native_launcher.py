#!/usr/bin/env python3
"""Closed selector checks for controlled merchant listing creation."""

import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class MerchantListingCreateNativeLauncherContract(unittest.TestCase):
    def test_exact_selector_fixture_and_title(self):
        self.assertIn('merchant-listing-create', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotIn('merchant-listing-create', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertEqual(LAUNCHER.MERCHANT_LISTING_CREATE_TEST,
                         'tests/postgres/secureshopMerchantListingCreate.integration.test.js')
        self.assertEqual(LAUNCHER.MERCHANT_LISTING_CREATE_ASSERTION,
                         'merchant listing create preserves populated history, previews without effects, commits one owned listing, and fences replay conflicts or retired authority')

    def test_one_exact_tap_required(self):
        label = 'merchant-listing-create'
        title = LAUNCHER.MERCHANT_LISTING_CREATE_ASSERTION
        valid = f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(LAUNCHER.complete_tap_counts(valid, label, [title])['tests'], 1)
        for invalid in (valid.replace(title, 'unrelated assertion'),
                        valid.replace('# skipped 0', '# skipped 1'),
                        valid.replace('# fail 0', '# fail 1')):
            with self.subTest(invalid=invalid[-60:]):
                with self.assertRaises(RuntimeError):
                    LAUNCHER.complete_tap_counts(invalid, label, [title])


if __name__ == '__main__':
    unittest.main()
