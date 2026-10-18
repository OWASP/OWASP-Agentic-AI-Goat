#!/usr/bin/env python3
"""Closed current-main customer profile browser admission contract."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('secureshop_transport_profile',
                                              HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class CustomerProfileBrowserLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_PROFILE_FLAGS}
        value.update(scope=LAUNCHER.CUSTOMER_PROFILE_SCOPE, actualModelCalls=4,
                     chatTurns=2, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_fixture_and_exact_receipt(self):
        self.assertIn('customer-profile-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-profile-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_PROFILE_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_PROFILE_ASSERTION,
                            LAUNCHER.CUSTOMER_ADDRESS_SETUP_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_profile_receipt(path), expected)
            self.assertEqual(LAUNCHER.customer_profile_receipt(path) if path.exists() else None,
                             expected)

    def test_rejects_partial_extra_unbounded_or_nonprivate_receipt(self):
        variants = ({'renderedNoEffectProposal': False}, {'accountProfileParity': None},
                    {'chatTurns': 1}, {'chatTurns': 3}, {'actualModelCalls': 1},
                    {'actualModelCalls': 11}, {'judgeCalls': 1},
                    {'cleanupErrors': ['browser-remains']}, {'scope': 'other'},
                    {'unexpected': True})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError): LAUNCHER.customer_profile_receipt(path)
            value = self.receipt(path)
            del value['siblingProfilePrivate']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): LAUNCHER.customer_profile_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError): LAUNCHER.customer_profile_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError): LAUNCHER.customer_profile_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError): LAUNCHER.customer_profile_receipt(path)


if __name__ == '__main__':
    unittest.main()
