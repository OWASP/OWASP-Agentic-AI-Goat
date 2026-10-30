#!/usr/bin/env python3
"""Closed launcher receipt checks for the merchant listing edit browser cohort."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class MerchantListingEditLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_LISTING_EDIT_BROWSER_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_LISTING_EDIT_BROWSER_SCOPE,
                     actorCalls=6, roleTurns=2, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_selector_title_and_bounds(self):
        self.assertIn('merchant-listing-edit-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-listing-edit-browser', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.MERCHANT_LISTING_EDIT_BROWSER_TEST, LAUNCHER.ROLE_CHOICES_TEST)
        self.assertEqual(LAUNCHER.MERCHANT_LISTING_EDIT_BROWSER_ASSERTION,
                         'standalone merchant confirms one named listing edit through real local llama3.1:8b and recovers its saved receipt')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.merchant_listing_edit_browser_receipt(path), expected)
            for calls in (2, 10):
                self.receipt(path, actorCalls=calls)
                LAUNCHER.merchant_listing_edit_browser_receipt(path)

    def test_rejects_partial_false_extra_and_wrong_counters(self):
        variants = [
            {'namedOwnedChoice': False}, {'preparedWithoutEffect': None},
            {'oneOwnedListingEdit': 1}, {'exactGetRecoveryNoReplay': False},
            {'actorCalls': 1}, {'actorCalls': 11}, {'actorCalls': True},
            {'roleTurns': 1}, {'roleTurns': True}, {'judgeCalls': 1},
            {'judgeCalls': False}, {'errors': ['unexpected']},
            {'scope': 'other'}, {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_listing_edit_browser_receipt(path)
            partial = self.receipt(path)
            del partial['resetFenced']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_listing_edit_browser_receipt(path)

    def test_private_receipt_and_owned_profile_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_listing_edit_browser_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_listing_edit_browser_receipt(link)
            runtime = Path(directory)
            temporary = runtime / 'tmp'
            temporary.mkdir()
            (temporary / 'owasp-ai-goat-role-listing-edit-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


if __name__ == '__main__':
    unittest.main()
