#!/usr/bin/env python3
"""Controlled contract checks for the separate merchant Pricing chat cohort."""

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


class MerchantPricingChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_PRICING_CHAT_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_PRICING_CHAT_SCOPE,
                     actorCalls=6, pricingOperations=2, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_separate_live_browser_cohort_and_bounds(self):
        self.assertIn('merchant-pricing-chat-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-pricing-chat-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.MERCHANT_PRICING_CHAT_TEST, LAUNCHER.STANDALONE_PRICING_TEST)
        self.assertNotEqual(LAUNCHER.MERCHANT_PRICING_CHAT_ASSERTION,
                            LAUNCHER.STANDALONE_PRICING_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.merchant_pricing_chat_receipt(path), expected)
            self.receipt(path, actorCalls=36, judgeCalls=2)
            LAUNCHER.merchant_pricing_chat_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipt(self):
        variants = (
            {'namedOwnedChoice': False}, {'experimentConfirmedOneReceipt': None},
            {'fixtureCleaned': 1}, {'actorCalls': 5}, {'actorCalls': 37},
            {'actorCalls': True}, {'pricingOperations': 1}, {'pricingOperations': True},
            {'judgeCalls': 3}, {'judgeCalls': False}, {'errors': ['cleanup']},
            {'scope': 'other'}, {'unexpected': True},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_pricing_chat_receipt(path)
            missing = self.receipt(path)
            del missing['noPriceApply']
            path.write_text(json.dumps(missing))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_pricing_chat_receipt(path)

    def test_private_owned_receipt_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_pricing_chat_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_pricing_chat_receipt(link)

    def test_fixed_comparison_denial_and_reset_have_a_separate_closed_receipt(self):
        cohort = 'merchant-pricing-compare-fixed-reset-browser'
        self.assertIn(cohort, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(cohort, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotEqual(LAUNCHER.MERCHANT_PRICING_COMPARE_FIXED_RESET_COHORT,
                            LAUNCHER.MERCHANT_PRICING_COMPARE_CHAT_COHORT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            receipt = {flag: True for flag in LAUNCHER.MERCHANT_PRICING_COMPARE_FIXED_RESET_FLAGS}
            receipt.update(scope=LAUNCHER.MERCHANT_PRICING_COMPARE_FIXED_RESET_SCOPE,
                           actorCalls=4, roleTurns=2, pricingOperations=1, judgeCalls=0, errors=[])
            path.write_text(json.dumps(receipt))
            os.chmod(path, 0o600)
            self.assertEqual(LAUNCHER.merchant_pricing_compare_fixed_reset_receipt(path), receipt)
            for change in ({'privateUrlPolicyDenied': False}, {'zeroProtectedListenerHits': False},
                           {'terminalBlockedVisible': False}, {'exactBlockedGetNoReplay': False},
                           {'modelTraceBound': False}, {'resetFenced': False}, {'actorCalls': 13}, {'roleTurns': 3},
                           {'pricingOperations': 2}, {'judgeCalls': 1}, {'unexpected': True}):
                candidate = dict(receipt, **change)
                path.write_text(json.dumps(candidate))
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    LAUNCHER.merchant_pricing_compare_fixed_reset_receipt(path)


if __name__ == '__main__':
    unittest.main()
