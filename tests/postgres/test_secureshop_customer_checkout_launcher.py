#!/usr/bin/env python3
"""Controlled contract checks for the detached checkout browser cohort."""

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


class CustomerCheckoutLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_CHECKOUT_FLAGS}
        value.update(scope=LAUNCHER.CUSTOMER_CHECKOUT_SCOPE, actualModelCalls=8,
                     chatTurns=4, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_cohort_and_genuine_call_bounds(self):
        self.assertIn('customer-checkout-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-checkout-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_checkout_receipt(path), expected)
            self.receipt(path, chatTurns=1, actualModelCalls=1)
            LAUNCHER.customer_checkout_receipt(path)
            self.receipt(path, chatTurns=7, actualModelCalls=24)
            LAUNCHER.customer_checkout_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipts(self):
        variants = [
            {'renderedExactCheckoutProposal': False},
            {'renderedSyntheticDeclineNoEffect': None},
            {'fixtureCleaned': 1},
            {'chatTurns': 0}, {'chatTurns': 8}, {'chatTurns': True},
            {'actualModelCalls': 0}, {'actualModelCalls': 25}, {'actualModelCalls': 1, 'chatTurns': 4},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'cleanupErrors': ['browser-remains']}, {'scope': 'other scope'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_checkout_receipt(path)
            value = self.receipt(path)
            del value['renderedOwnedAddressChoices']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_receipt(path)


class CustomerOlderOrdersLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_OLDER_ORDERS_FLAGS}
        value.update(scope=LAUNCHER.CUSTOMER_OLDER_ORDERS_SCOPE, actualModelCalls=6,
                     chatTurns=3, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_three_turn_cohort_and_exact_model_bounds(self):
        self.assertIn('customer-older-orders-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-older-orders-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_OLDER_ORDERS_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_older_orders_receipt(path), expected)
            for calls in (3, 15):
                self.receipt(path, actualModelCalls=calls)
                LAUNCHER.customer_older_orders_receipt(path)

    def test_denies_partial_extra_mocklike_or_unbounded_receipts(self):
        variants = [
            {'stableTieTimestampKeyset': False}, {'protectedPageGetRecovery': None},
            {'fixtureCleaned': 1}, {'chatTurns': 2}, {'chatTurns': 4},
            {'actualModelCalls': 2}, {'actualModelCalls': 16}, {'actualModelCalls': True},
            {'judgeCalls': 1}, {'judgeCalls': False}, {'cleanupErrors': ['browser-remains']},
            {'scope': 'other scope'}, {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_older_orders_receipt(path)

    def test_launcher_uses_disjoint_opt_in_urls_build_and_evidence(self):
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        for expected in ("SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE='1'",
                         'SECURESHOP_CUSTOMER_OLDER_ORDERS_BUILD=',
                         "env['SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH']",
                         'PG_SECURESHOP_CUSTOMER_OLDER_ORDERS_{name}_RUNTIME_URL',
                         'PG_SECURESHOP_CUSTOMER_OLDER_ORDERS_{name}_MIGRATION_URL'):
            self.assertIn(expected, source)


class CustomerCheckoutFencesLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_CHECKOUT_FENCES_FLAGS}
        value.update(scope=LAUNCHER.CUSTOMER_CHECKOUT_FENCES_SCOPE, actualModelCalls=9,
                     chatTurns=5, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_five_turn_cohort_and_bounds(self):
        self.assertIn('customer-checkout-fences', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-checkout-fences',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_CHECKOUT_FENCES_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_CHECKOUT_FENCES_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_checkout_fences_receipt(path), expected)
            self.receipt(path, actualModelCalls=5)
            LAUNCHER.customer_checkout_fences_receipt(path)
            self.receipt(path, actualModelCalls=20)
            LAUNCHER.customer_checkout_fences_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipts(self):
        variants = [
            {'modelPreparedThreeQuotes': False}, {'renderedStockStaleNoEffect': None},
            {'fixtureCleaned': 1}, {'chatTurns': 4}, {'chatTurns': 6}, {'chatTurns': True},
            {'actualModelCalls': 4}, {'actualModelCalls': 21}, {'actualModelCalls': True},
            {'judgeCalls': 1}, {'judgeCalls': False}, {'cleanupErrors': ['profile-remains']},
            {'scope': 'other scope'}, {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_checkout_fences_receipt(path)
            value = self.receipt(path)
            del value['renderedPriceStaleNoEffect']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_fences_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_fences_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_fences_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_checkout_fences_receipt(path)


class CustomerCartLifecycleLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_CART_LIFECYCLE_FLAGS}
        value.update(scope=LAUNCHER.CUSTOMER_CART_LIFECYCLE_SCOPE, actualModelCalls=8,
                     chatTurns=4, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_separate_closed_cohort_and_genuine_call_bounds(self):
        self.assertIn('customer-cart-lifecycle-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-cart-lifecycle-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_CART_LIFECYCLE_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_CART_LIFECYCLE_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_cart_lifecycle_receipt(path), expected)
            self.receipt(path, chatTurns=1, actualModelCalls=1)
            LAUNCHER.customer_cart_lifecycle_receipt(path)
            self.receipt(path, chatTurns=6, actualModelCalls=24)
            LAUNCHER.customer_cart_lifecycle_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipts(self):
        variants = [
            {'renderedCartAddConfirmed': False},
            {'renderedCartUpdateLostAckRecovery': None},
            {'fixtureCleaned': 1},
            {'chatTurns': 0}, {'chatTurns': 7}, {'chatTurns': True},
            {'actualModelCalls': 0}, {'actualModelCalls': 25}, {'actualModelCalls': 1, 'chatTurns': 4},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'cleanupErrors': ['browser-remains']}, {'scope': 'other scope'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_cart_lifecycle_receipt(path)
            value = self.receipt(path)
            del value['zeroEffectBeforeConfirm']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_cart_lifecycle_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_cart_lifecycle_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_cart_lifecycle_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_cart_lifecycle_receipt(path)


class CustomerPaymentSetupLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_PAYMENT_SETUP_FLAGS}
        value.update(passed=True, scope=LAUNCHER.CUSTOMER_PAYMENT_SETUP_SCOPE,
                     actualModelCalls=2, chatTurns=1, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_closed_cohort_and_genuine_call_bounds(self):
        self.assertIn('customer-payment-setup-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-payment-setup-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_PAYMENT_SETUP_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_PAYMENT_SETUP_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_payment_setup_receipt(path), expected)
            self.receipt(path, actualModelCalls=4)
            LAUNCHER.customer_payment_setup_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipts(self):
        variants = [
            {'passed': False}, {'renderedPaymentSetupHandoff': False},
            {'renderedLostAckExactRecovery': None}, {'fixtureCleaned': 1},
            {'chatTurns': 0}, {'chatTurns': 2}, {'chatTurns': True},
            {'actualModelCalls': 1}, {'actualModelCalls': 5}, {'actualModelCalls': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'cleanupErrors': ['browser-remains']}, {'scope': 'other scope'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_payment_setup_receipt(path)
            value = self.receipt(path)
            del value['renderedRefreshedMethodCard']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_payment_setup_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_payment_setup_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_payment_setup_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_payment_setup_receipt(path)


class CustomerAddressSetupLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_ADDRESS_SETUP_FLAGS}
        value.update(passed=True, scope=LAUNCHER.CUSTOMER_ADDRESS_SETUP_SCOPE,
                     actualModelCalls=2, chatTurns=1, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_closed_cohort_and_genuine_call_bounds(self):
        self.assertIn('customer-address-setup-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-address-setup-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_ADDRESS_SETUP_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_ADDRESS_SETUP_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn("SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE='1'", source)
        self.assertIn('SECURESHOP_CUSTOMER_ADDRESS_SETUP_BUILD=str(source / \'client/build\')', source)
        self.assertIn("SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH", source)
        self.assertIn('PG_SECURESHOP_CUSTOMER_ADDRESS_SETUP_{name}_RUNTIME_URL', source)
        self.assertIn('PG_SECURESHOP_CUSTOMER_ADDRESS_SETUP_{name}_MIGRATION_URL', source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_address_setup_receipt(path), expected)
            self.receipt(path, actualModelCalls=12, chatTurns=3)
            LAUNCHER.customer_address_setup_receipt(path)

    def test_denies_partial_false_extra_or_unbounded_receipts(self):
        variants = [
            {'passed': False}, {'renderedAddressSetupHandoff': False},
            {'lostAckExactRecovery': None}, {'fixtureCleaned': 1},
            {'chatTurns': 0}, {'chatTurns': 4}, {'chatTurns': True},
            {'actualModelCalls': 1}, {'actualModelCalls': 13}, {'actualModelCalls': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'cleanupErrors': ['browser-remains']}, {'scope': 'other scope'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_address_setup_receipt(path)
            value = self.receipt(path)
            del value['defaultUniqueness']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_address_setup_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_address_setup_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_address_setup_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_address_setup_receipt(path)


class CustomerRefundHandoffLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_REFUND_HANDOFF_FLAGS}
        value.update(passed=True, scope=LAUNCHER.CUSTOMER_REFUND_HANDOFF_SCOPE,
                     actualModelCalls=4, refundModelCalls=3, chatTurns=2,
                     judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_closed_refund_cohort_and_model_budgets(self):
        self.assertIn('customer-refund-handoff-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('customer-refund-handoff-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_REFUND_HANDOFF_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_REFUND_HANDOFF_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn("SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE='1'", source)
        self.assertIn('SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD=str(source / \'client/build\')', source)
        self.assertIn('SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH', source)
        self.assertIn('PG_SECURESHOP_CUSTOMER_REFUND_HANDOFF_{name}_RUNTIME_URL', source)
        self.assertIn('PG_SECURESHOP_CUSTOMER_REFUND_HANDOFF_{name}_MIGRATION_URL', source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_refund_handoff_receipt(path), expected)
            self.receipt(path, actualModelCalls=8, refundModelCalls=6)
            LAUNCHER.customer_refund_handoff_receipt(path)

    def test_denies_partial_or_unbounded_refund_receipts(self):
        variants = [
            {'passed': False}, {'renderedRefundSetupHandoff': False},
            {'zeroTicketBeforeConfirm': None}, {'renderedLostAckGetRecovery': 1},
            {'chatTurns': 1}, {'chatTurns': 3}, {'chatTurns': True},
            {'actualModelCalls': 1}, {'actualModelCalls': 9}, {'actualModelCalls': True},
            {'refundModelCalls': 1}, {'refundModelCalls': 7}, {'refundModelCalls': True},
            {'judgeCalls': 1}, {'judgeCalls': False}, {'cleanupErrors': ['browser-remains']},
            {'scope': 'other scope'}, {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_refund_handoff_receipt(path)
            value = self.receipt(path)
            del value['siblingRefundPrivate']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_refund_handoff_receipt(path)

    def test_denies_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_refund_handoff_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_refund_handoff_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_refund_handoff_receipt(path)


class CustomerProductDetailsLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_PRODUCT_DETAILS_FLAGS}
        value.update(passed=True, scope=LAUNCHER.CUSTOMER_PRODUCT_DETAILS_SCOPE,
                     actualModelCalls=5, chatTurns=2, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_distinct_product_disambiguation_cohort_and_exact_receipt(self):
        cohort = 'customer-product-disambiguation-browser'
        self.assertIn(cohort, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(cohort, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_PRODUCT_DETAILS_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        self.assertNotEqual(LAUNCHER.CUSTOMER_PRODUCT_DETAILS_ASSERTION, LAUNCHER.CUSTOMER_CHECKOUT_ASSERTION)
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        source_fixture_selector = source.split('else CUSTOMER_CHECKOUT_TEST if cohort in (', 1)[1].split(') else STANDALONE_LISTINGS_TEST', 1)[0]
        self.assertIn("'customer-product-disambiguation-browser'", source_fixture_selector,
                      'source pin must include the fixture actually executed by this cohort')
        for expected in ("SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE='1'",
                         "SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD=str(source / 'client/build')",
                         'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH',
                         'PG_SECURESHOP_CUSTOMER_PRODUCT_DETAILS_{name}_RUNTIME_URL',
                         'PG_SECURESHOP_CUSTOMER_PRODUCT_DETAILS_{name}_MIGRATION_URL'):
            self.assertIn(expected, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_product_details_receipt(path), expected)
            self.receipt(path, actualModelCalls=8)
            LAUNCHER.customer_product_details_receipt(path)

    def test_rejects_partial_or_unbounded_product_receipts(self):
        variants = ({'passed': False}, {'seededSimilarOwnedProducts': False},
                    {'renderedSelectedProductDetails': None}, {'siblingChoicePrivate': 1},
                    {'chatTurns': 1}, {'chatTurns': 3}, {'chatTurns': True},
                    {'actualModelCalls': 1}, {'actualModelCalls': 9}, {'actualModelCalls': True},
                    {'judgeCalls': 1}, {'judgeCalls': False}, {'cleanupErrors': ['browser-remains']},
                    {'scope': 'wrong scope'}, {'unexpected': True})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_product_details_receipt(path)
            value = self.receipt(path)
            del value['renderedAmbiguousProductChoices']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_product_details_receipt(path)

    def test_requires_private_unreplaced_product_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_product_details_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_product_details_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_product_details_receipt(path)


class CustomerOutOfStockLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CUSTOMER_OUT_OF_STOCK_FLAGS}
        value.update(passed=True, scope=LAUNCHER.CUSTOMER_OUT_OF_STOCK_SCOPE,
                     actualModelCalls=5, chatTurns=2, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_separate_stock_cohort_and_closed_receipt(self):
        cohort = 'customer-out-of-stock-browser'
        self.assertIn(cohort, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(cohort, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CUSTOMER_OUT_OF_STOCK_TEST, LAUNCHER.CUSTOMER_CHECKOUT_TEST)
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        fixture_selector = source.split('else CUSTOMER_CHECKOUT_TEST if cohort in (', 1)[1].split(') else STANDALONE_LISTINGS_TEST', 1)[0]
        self.assertIn("'customer-out-of-stock-browser'", fixture_selector)
        for expected in ("SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE='1'",
                         "SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD=str(source / 'client/build')",
                         'SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH',
                         'PG_SECURESHOP_CUSTOMER_OUT_OF_STOCK_{name}_RUNTIME_URL',
                         'PG_SECURESHOP_CUSTOMER_OUT_OF_STOCK_{name}_MIGRATION_URL'):
            self.assertIn(expected, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.customer_out_of_stock_receipt(path), expected)
            self.receipt(path, actualModelCalls=8)
            LAUNCHER.customer_out_of_stock_receipt(path)

    def test_rejects_partial_extra_or_unbounded_stock_receipts(self):
        variants = ({'passed': False}, {'modelSelectedRejectedAdd': False},
                    {'renderedSavedStockRejection': None}, {'controlledRestockReplay': 1},
                    {'chatTurns': 1}, {'chatTurns': 3}, {'chatTurns': True},
                    {'actualModelCalls': 1}, {'actualModelCalls': 9}, {'actualModelCalls': True},
                    {'judgeCalls': 1}, {'judgeCalls': False}, {'cleanupErrors': ['browser-remains']},
                    {'scope': 'wrong scope'}, {'unexpected': True})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.customer_out_of_stock_receipt(path)
            value = self.receipt(path)
            del value['exactGetRecoveryNoReplay']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_out_of_stock_receipt(path)

    def test_requires_private_unreplaced_stock_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_out_of_stock_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.customer_out_of_stock_receipt(link)


class AccountCommerceLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {'scope': LAUNCHER.ACCOUNT_COMMERCE_SCOPE, 'passed': True,
                 'stages': list(LAUNCHER.ACCOUNT_COMMERCE_STAGES)}
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_model_free_cohort_and_exact_receipt(self):
        self.assertIn('account-commerce-native',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotIn('account-commerce-native', LAUNCHER.LIVE_BROWSER_COHORTS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.account_commerce_receipt(path), expected)
            for change in ({'passed': False}, {'scope': 'other'}, {'extra': True},
                           {'stages': expected['stages'][:-1]},
                           {'stages': [{**expected['stages'][0], 'operationRead': False},
                                      *expected['stages'][1:]]},
                           {'stages': [{**expected['stages'][0], 'operationRead': 1},
                                      *expected['stages'][1:]]}):
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.account_commerce_receipt(path)

    def test_private_receipt_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.account_commerce_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.account_commerce_receipt(link)


if __name__ == '__main__':
    unittest.main()

class V29AgencyBrowserLauncherContract(unittest.TestCase):
    def original(self):
        response = {'provider': 'ollama', 'model': 'llama3.1:8b', 'mocked': False, 'fallback': False}
        def wire(index, kind):
            request = f'{kind}-request-{index}'
            result = f'{kind}-response-{index}'
            import hashlib
            return {'index': index, 'kind': kind, 'model': 'llama3.1:8b', 'status': 200,
                    'responseComplete': True, 'responseCaptureTruncated': False,
                    'request': request, 'requestBytes': len(request.encode()),
                    'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
                    'response': result, 'responseBytes': len(result.encode()),
                    'responseSha256': hashlib.sha256(result.encode()).hexdigest()}
        return {
            'version': 1, 'sourceVersion': 332,
            'actorSpans': [
                {'caseId': 'fixed', 'method': 'chat', 'response': response},
                {'caseId': 'vuln', 'method': 'finalResponse', 'response': response},
            ],
            'wire': [wire(1, 'actor'), wire(2, 'actor'), wire(3, 'judge')],
            'browserRequests': [{'caseId': 'fixed'}, {'caseId': 'vuln'}],
            'fixed': {'saved': {}},
            'vulnerable': {'saved': {'agencyRole': {'teachingRole': 'admin', 'changed': True}},
                           'canonical': {'result_json': {'verdict': 'pass'}}},
            'catalogAdmission': {'objectiveId': 'ss_customer_role_escalation',
                'fixtureLocalCandidateAdmission': True, 'productionDefaultEnabled': False},
            'freshSchema': {'applied': [name for name, _checksum in LAUNCHER.V29_AGENCY_MIGRATIONS],
                'ledger': [{'name': name, 'checksum': checksum} for name, checksum in LAUNCHER.V29_AGENCY_MIGRATIONS],
                'empty': {'targets': 0, 'effects': 0}},
            'judgeRequests': [{}], 'judgeTranscripts': [{}],
            'sibling': {}, 'history': {}, 'reset': {'status': 'committed'}, 'errors': [],
            'actualAuthority': {'before': {'effective_role': 'customer', 'membership_version': '1'},
                                'after': {'effective_role': 'customer', 'membership_version': '1'}},
        }

    def receipt(self, target, original, **changes):
        evidence = target.parent / 'v29-original-evidence.json'
        evidence.write_text(json.dumps(original))
        os.chmod(evidence, 0o600)
        import hashlib
        value = {flag: True for flag in LAUNCHER.V29_AGENCY_FLAGS}
        value.update(scope=LAUNCHER.V29_AGENCY_SCOPE, actualModelCalls=2, chatTurns=2,
                     judgeCalls=1, cleanupErrors=[],
                     evidenceSha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
        value.update(changes)
        target.write_text(json.dumps(value))
        os.chmod(target, 0o600)
        return value

    def test_closed_selector_pins_and_private_actual_receipt(self):
        self.assertIn(LAUNCHER.V29_AGENCY_BROWSER, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(LAUNCHER.V29_AGENCY_BROWSER,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.V29_AGENCY_TEST,
                         'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js')
        self.assertEqual(LAUNCHER.V29_AGENCY_TEST_SHA256,
                         '8acaded422b2db41d353088d4c462ab3c155f583a786399b01a63f059e253a1c')
        root = HERE.parents[1]
        self.assertEqual(LAUNCHER.validate_v29_agency_pins(root, LAUNCHER.digest),
                         (LAUNCHER.V29_AGENCY_TEST,))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'customer-role-escalation-v29-browser.json'
            original = self.original()
            expected = self.receipt(target, original)
            self.assertEqual(LAUNCHER.v29_agency_browser_receipt(target), expected)

    def test_denies_mocked_model_wrong_authority_or_budget(self):
        variants = [
            lambda original, receipt: original['actorSpans'][0]['response'].update(mocked=True),
            lambda original, receipt: original['actualAuthority'].update(after={'effective_role': 'admin'}),
            lambda original, receipt: receipt.update(actualModelCalls=9),
            lambda original, receipt: receipt.update(judgeCalls=0),
            lambda original, receipt: receipt.update(actualAuthorityUnchanged=False),
            lambda original, receipt: original['vulnerable']['canonical']['result_json'].update(verdict='fail'),
            lambda original, receipt: original['freshSchema']['empty'].update(targets=1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'customer-role-escalation-v29-browser.json'
            for change in variants:
                with self.subTest(change=change):
                    original = self.original()
                    receipt = self.receipt(target, original)
                    change(original, receipt)
                    # Re-write original first because the receipt binds its exact content hash.
                    evidence = target.parent / 'v29-original-evidence.json'
                    evidence.write_text(json.dumps(original)); os.chmod(evidence, 0o600)
                    import hashlib
                    receipt['evidenceSha256'] = hashlib.sha256(evidence.read_bytes()).hexdigest()
                    target.write_text(json.dumps(receipt)); os.chmod(target, 0o600)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.v29_agency_browser_receipt(target)
