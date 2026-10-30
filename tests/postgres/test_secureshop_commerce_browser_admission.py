"""Controlled whole-commerce admission; no browser, DB, model or network."""
import contextlib
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


L = module('run-secureshop-standalone-commerce-browser.py', 'commerce_controlled')
C = module('run_standalone_commerce_with_inspector.py', 'commerce_outer_controlled')
B = module('secureshop_bound_browser_ownership.py', 'commerce_browser_ownership_controlled')
ACTUAL_RETIREMENT = object()


def arguments(mode='--plan', cohort=None):
    cohort = C.COHORT if cohort is None else cohort
    values = {key: 'controlled' for key in C.REQUIRED}
    values.update({'--main-workspace': str(C.ROOT), '--cohort': cohort,
                   '--evidence-parent': str(C.ROOT / 'tasks/qualification'),
                   '--build-report': str(C.ROOT / 'tasks/qualification/frontend-build-controlled/report.json'),
                   '--build-report-sha256': '1' * 64,
                   '--build-input-sha256': '2' * 64,
                   '--build-output-sha256': '3' * 64,
                   '--build-recorder-sha256': '4' * 64})
    if cohort in (C.CHECKOUT_COHORT, C.PROFILE_COHORT, C.CART_COHORT, C.PAYMENT_COHORT, C.STOCK_COHORT, C.PRODUCT_COHORT, C.REFUND_COHORT, C.ADDRESS_COHORT,
                  C.OLDER_ORDERS_COHORT, C.CHECKOUT_FENCES_COHORT):
        values[C.CHECKOUT_MODEL_PIN] = 'f' * 64
    if mode == '--run':
        values['--expected-snapshot-sha256'] = 'a' * 64
    return [mode, '--commerce-test-no-sandbox',
            *(item for key, value in sorted(values.items()) for item in (key, value))]


def parsed():
    return SimpleNamespace(node='/controlled/node', browser='/controlled/chrome',
                           browser_sha256='a' * 64, ollama_model_sha256='f' * 64,
                           policy_renderer_admission=None)


def environment():
    run = L.ROOT / 'tasks/qualification/run-controlled'
    return {
        'SECURESHOP_STANDALONE_COMMERCE_NATIVE': '1',
        'SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH': str(run / 'standalone-commerce-browser.json'),
        'TMPDIR': str(run / 'runtime/tmp'),
        'PG_SECURESHOP_STANDALONE_COMMERCE_IDENTITY_RUNTIME_URL': 'original-runtime',
        'PG_TEST_DISPOSABLE': 'yes',
    }


class Admission(unittest.TestCase):
    def test_original_parser_requires_qualified_build_fields_for_commerce(self):
        shared = L.load(L.MAIN, 'commerce_build_parse_contract')
        parsed = shared.parse(L.arguments(arguments()))
        self.assertEqual(parsed.build_report_sha256, '1' * 64)
        self.assertEqual(parsed.build_output_sha256, '3' * 64)
        for field in ('build_report', 'build_report_sha256', 'build_input_sha256',
                      'build_output_sha256', 'build_recorder_sha256'):
            missing = SimpleNamespace(**vars(parsed))
            setattr(missing, field, None)
            with self.subTest(missing=field), self.assertRaisesRegex(RuntimeError,
                    'Exact qualified browser build provenance required'):
                shared.validate_static(missing)

    def check_customer_current_host_requires_exact_build_and_model_pins(self, cohort):
        shared = L.load(L.MAIN, 'commerce_checkout_build_parse_contract')
        checkout = arguments(cohort=cohort)
        selected = shared.parse(L.arguments(checkout))
        self.assertEqual((selected.cohort, selected.ollama_model_sha256),
            (cohort, 'f' * 64))
        selected.image_id = 'sha256:' + 'a' * 64
        selected.docker_daemon = 'a' * 32
        selected.browser = str(C.ROOT / L.MAIN)
        selected.browser_root = str(C.ROOT)
        selected.browser_sha256 = shared.digest(selected.browser)
        with patch.object(shared, 'validate_current_host') as host:
            self.assertEqual(shared.validate_static(selected), C.ROOT)
        host.assert_called_once()
        for field in ('build_report', 'build_report_sha256', 'build_input_sha256',
                      'build_output_sha256', 'build_recorder_sha256'):
            missing = SimpleNamespace(**vars(selected))
            setattr(missing, field, None)
            with self.subTest(missing=field), self.assertRaisesRegex(RuntimeError,
                    'Exact qualified browser build provenance required'):
                shared.validate_static(missing)
        for field in ('build_report_sha256', 'build_input_sha256',
                      'build_output_sha256', 'build_recorder_sha256'):
            malformed = SimpleNamespace(**vars(selected))
            setattr(malformed, field, 'not-a-sha')
            with self.subTest(malformed=field), self.assertRaisesRegex(RuntimeError,
                    'Exact qualified browser build provenance required'):
                shared.validate_static(malformed)
        for value in (None, 'not-a-sha'):
            malformed = SimpleNamespace(**vars(selected))
            malformed.ollama_model_sha256 = value
            with self.subTest(model=value), self.assertRaisesRegex(RuntimeError,
                    'Exact local llama3.1:8b model digest required'):
                with patch.object(shared, 'validate_current_host'):
                    shared.validate_static(malformed)
        unrelated = SimpleNamespace(**vars(selected))
        unrelated.cohort = 'merchant-order-browser'
        with self.assertRaisesRegex(RuntimeError, 'Qualified commerce build options are cohort exclusive'):
            shared.validate_static(unrelated)
        external = SimpleNamespace(**vars(selected))
        external.current_host_profile = None
        with self.assertRaisesRegex(RuntimeError, 'Qualified commerce build options are cohort exclusive'):
            shared.validate_static(external)

    def test_main_checkout_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.CHECKOUT_COHORT)

    def test_main_profile_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.PROFILE_COHORT)

    def test_main_cart_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.CART_COHORT)

    def test_main_payment_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.PAYMENT_COHORT)

    def test_main_older_orders_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.OLDER_ORDERS_COHORT)

    def test_main_checkout_fences_current_host_requires_exact_build_and_model_pins(self):
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.CHECKOUT_FENCES_COHORT)

    def check_customer_source_closure(self, cohort):
        shared = L.load(L.MAIN, 'commerce_checkout_source_closure_contract')
        node = C.ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        with patch.object(shared, 'dependency_inventory', return_value={}):
            selected = shared.source_snapshot(C.ROOT, str(node), cohort,
                browser_root=C.ROOT)['sourcePins']
        for member in (L.CHECKOUT_TEST, L.HELPER, L.CONTRACT,
                       C.ADAPTER, 'tests/postgres/run_standalone_commerce_with_inspector.py',
                       'tests/postgres/test_secureshop_commerce_browser_admission.py'):
            with self.subTest(member=member):
                self.assertIn(member, selected)
                self.assertEqual(selected[member], L.digest(C.ROOT / member))

    def test_main_checkout_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.CHECKOUT_COHORT)

    def test_main_profile_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.PROFILE_COHORT)

    def test_main_cart_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.CART_COHORT)

    def test_main_payment_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.PAYMENT_COHORT)

    def test_main_older_orders_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.OLDER_ORDERS_COHORT)

    def test_main_checkout_fences_source_closure_contains_exact_owned_browser_chain(self):
        self.check_customer_source_closure(C.CHECKOUT_FENCES_COHORT)

    def test_direct_manual_checkout_has_distinct_zero_model_closed_admission(self):
        manual = arguments(cohort=C.MANUAL_CHECKOUT_COHORT)
        self.assertNotIn(C.CHECKOUT_MODEL_PIN, manual)
        self.assertEqual(C.validate_arguments(manual, planning=True), manual)
        with self.assertRaises(RuntimeError):
            C.validate_arguments([*manual, C.CHECKOUT_MODEL_PIN, 'f' * 64], planning=True)
        shared = L.load(L.MAIN, 'commerce_manual_checkout_static_contract')
        selected = shared.parse(L.arguments(manual))
        self.assertEqual(selected.cohort, C.MANUAL_CHECKOUT_COHORT)
        self.assertIsNone(selected.ollama_model_sha256)
        selected.image_id = 'sha256:' + 'a' * 64
        selected.docker_daemon = 'a' * 32
        selected.browser = str(C.ROOT / L.MAIN)
        selected.browser_root = str(C.ROOT)
        selected.browser_sha256 = shared.digest(selected.browser)
        with patch.object(shared, 'validate_current_host') as host:
            self.assertEqual(shared.validate_static(selected), C.ROOT)
        host.assert_called_once()
        scoped = ('COHORT', 'TEST', 'RECORD', 'ACK', 'KIND', 'PROFILE',
                  'EVIDENCE_ENV', 'SELECTOR_ENV', 'RENDERED_PINS')
        with patch.multiple(L, **{name: getattr(L, name) for name in scoped}):
            L.select_cohort(manual)
            self.assertEqual((L.COHORT, L.TEST, L.KIND, L.PROFILE),
                (C.MANUAL_CHECKOUT_COHORT, L.CHECKOUT_TEST,
                 'customer_manual_checkout_browser', 'owasp-ai-goat-customer-manual-checkout-'))
            self.assertEqual((L.RECORD, L.ACK),
                ('customer-manual-checkout-browser-birth.json',
                 'customer-manual-checkout-browser-ack.json'))
            env = environment()
            env.pop('SECURESHOP_STANDALONE_COMMERCE_NATIVE')
            env.pop('SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH')
            env[L.SELECTOR_ENV] = '1'
            env[L.EVIDENCE_ENV] = str(L.ROOT / 'tasks/qualification/run-controlled' / L.MANUAL_CHECKOUT_RECEIPT)
            owned, evidence = L.owned_environment(env, parsed(), {'build': {'index.html': 'b' * 64}})
            self.assertEqual(evidence, L.ROOT / 'tasks/qualification/run-controlled')
            self.assertEqual(owned['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'], str(evidence / L.RECORD))
            for other in ('SECURESHOP_CUSTOMER_CHECKOUT_NATIVE', 'SECURESHOP_CUSTOMER_PROFILE_NATIVE',
                          'SECURESHOP_ACCOUNT_AVATAR_NATIVE', 'SECURESHOP_STANDALONE_COMMERCE_NATIVE'):
                with self.subTest(other=other), self.assertRaisesRegex(RuntimeError, 'Exclusive'):
                    L.owned_environment({**env, other: '1'}, parsed(), {'build': {'index.html': 'b' * 64}})
            self.check_customer_source_closure(C.MANUAL_CHECKOUT_COHORT)
            controlled = SimpleNamespace(
                STANDALONE_COMMERCE_TEST='tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js',
                STANDALONE_COMMERCE_TEST_SHA256=L.ORIGINAL_TEST_SHA256,
                CUSTOMER_MANUAL_CHECKOUT_TEST=L.CHECKOUT_TEST,
                CUSTOMER_MANUAL_CHECKOUT_ASSERTION='standalone direct customer checkout physically prepares one quote, explicitly confirms one order, and recovers a lost acknowledgement by exact GET only',
                parse=Mock(return_value=SimpleNamespace(plan=True, policy_renderer_admission=None)), validate_static=Mock())
            with patch.object(L, 'validate_pins'), patch.object(L, 'inventory', return_value={'build': {'index.html': 'b' * 64}}), \
                    patch.object(L, 'load', return_value=controlled), patch.object(L, 'syntax_check'), \
                    patch.object(L, 'assert_reviewed_snapshot'), patch.object(L, 'consume_environment') as inspector, \
                    patch.object(L, 'run') as run_native, contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(L.main(manual), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual((plan['cohort'], plan['fixtureSeconds'], plan['workSeconds'], plan['launcherSeconds']),
                (C.MANUAL_CHECKOUT_COHORT, 600, 600, 600))
            self.assertEqual((plan['actualModelCalls'], plan['databaseCount'], plan['roleCount']), (0, 4, 8))
            self.assertFalse(plan['nativeStarted'])
            inspector.assert_not_called()
            run_native.assert_not_called()

    def test_direct_manual_checkout_receipt_rejects_count_type_and_journal_spoofing(self):
        shared = L.load(L.MAIN, 'commerce_manual_checkout_receipt_contract')
        operation_id = '123e4567-e89b-42d3-a456-426614174000'
        receipt = {name: True for name in shared.CUSTOMER_MANUAL_CHECKOUT_FLAGS}
        receipt.update(scope=shared.CUSTOMER_MANUAL_CHECKOUT_SCOPE,
            actualModelCalls=0, chatTurns=0, judgeCalls=0,
            canonicalCredit=False, qualificationAccepted=False, cleanupErrors=[],
            operationId=operation_id, quoteSha256='a' * 64, scopeKey='b' * 64, orderId=7,
            physical=dict(preparePosts=1, confirmPosts=1, failedGets=1, recoveredGets=1,
                prepareStatus=200, committedConfirmStatus=200, browserConfirmAckDelivered=False),
            journal=dict(operationId=operation_id, targetId='123e4567-e89b-42d3-a456-426614174001',
                shopUserId=3, kind='checkout', preparedState='prepared', completedState='completed',
                contextSha256='b' * 64, intentSha256='d' * 64, proposalSha256='a' * 64,
                resultSha256='e' * 64, orderId=7))
        with tempfile.TemporaryDirectory(prefix='run-manual-checkout-contract-', dir=L.ROOT / 'tasks/qualification') as directory:
            path = Path(directory) / L.MANUAL_CHECKOUT_RECEIPT
            for label, changed in (
                ('valid', receipt),
                ('bool-count', {**receipt, 'physical': {**receipt['physical'], 'failedGets': True}}),
                ('extra-post', {**receipt, 'physical': {**receipt['physical'], 'confirmPosts': 2}}),
                ('ack-delivered', {**receipt, 'physical': {**receipt['physical'], 'browserConfirmAckDelivered': True}}),
                ('wrong-proposal', {**receipt, 'journal': {**receipt['journal'], 'proposalSha256': 'f' * 64}}),
                ('wrong-scope', {**receipt, 'journal': {**receipt['journal'], 'contextSha256': 'f' * 64}}),
                ('wrong-order', {**receipt, 'journal': {**receipt['journal'], 'orderId': 8}}),
                ('wrong-kind', {**receipt, 'journal': {**receipt['journal'], 'kind': 'chat'}}),
                ('credit', {**receipt, 'canonicalCredit': True}),
                ('judge', {**receipt, 'judgeCalls': 1})):
                with self.subTest(label=label):
                    if path.exists():
                        path.unlink()
                    ParentAndFailure.private_json(path, changed)
                    if label == 'valid':
                        self.assertEqual(shared.customer_manual_checkout_receipt(path), receipt)
                    else:
                        with self.assertRaises(RuntimeError):
                            shared.customer_manual_checkout_receipt(path)

    def test_existing_full_checkout_profile_cart_and_revoke_pins_are_exact(self):
        scoped = ('COHORT', 'TEST', 'RECORD', 'ACK', 'KIND', 'PROFILE',
                  'EVIDENCE_ENV', 'SELECTOR_ENV', 'RENDERED_PINS')
        for cohort in (C.COHORT, C.SESSION_REVOKE_COHORT, C.CHECKOUT_COHORT,
                       C.PROFILE_COHORT, C.CART_COHORT, C.PAYMENT_COHORT, C.STOCK_COHORT, C.PRODUCT_COHORT, C.REFUND_COHORT, C.ADDRESS_COHORT,
                       C.OLDER_ORDERS_COHORT, C.CHECKOUT_FENCES_COHORT):
            with self.subTest(cohort=cohort), patch.multiple(L,
                    **{name: getattr(L, name) for name in scoped}):
                L.select_cohort(arguments(cohort=cohort))
                L.validate_pins()

    def test_closed_full_cohort_no_model_or_optional_executor_authority(self):
        plan = arguments()
        actual = L.arguments(plan)
        self.assertNotIn('--commerce-test-no-sandbox', actual)
        self.assertIn('--plan', actual)
        self.assertNotIn('--run', C.validate_arguments(arguments('--run')))
        for extra in (['--run'], ['--ollama-model-sha256', 'a' * 64],
                      ['--policy-renderer-admission', '/foreign'],
                      ['--embedding-cache', '/foreign'], ['--shell', '/bin/sh']):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                C.validate_arguments(arguments('--run') + extra)
        for key, value in (('--cohort', 'unadmitted-checkout-browser'),
                           ('--evidence-parent', '/foreign'), ('--main-workspace', '/foreign'),
                           ('--build-report-sha256', 'not-a-sha')):
            bad = arguments('--run')
            bad[bad.index(key) + 1] = value
            with self.assertRaises(RuntimeError):
                C.validate_arguments(bad)
        for field in ('--build-report', '--build-report-sha256', '--build-input-sha256',
                      '--build-output-sha256', '--build-recorder-sha256'):
            missing = arguments('--run')
            offset = missing.index(field)
            del missing[offset:offset + 2]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                C.validate_arguments(missing)

    def check_closed_customer_owner_chain(self, profile=False, cart=False, payment=False, older=False, fences=False, address=False, refund=False, product=False, stock=False):
        cohort = C.STOCK_COHORT if stock else C.PRODUCT_COHORT if product else C.REFUND_COHORT if refund else C.ADDRESS_COHORT if address else C.OLDER_ORDERS_COHORT if older else C.CHECKOUT_FENCES_COHORT if fences else C.PAYMENT_COHORT if payment else C.CART_COHORT if cart else C.PROFILE_COHORT if profile else C.CHECKOUT_COHORT
        stem = 'customer-out-of-stock' if stock else 'customer-product-details' if product else 'customer-refund-handoff' if refund else 'customer-address-setup' if address else 'customer-older-orders' if older else 'customer-checkout-fences' if fences else 'customer-payment-setup' if payment else 'customer-cart-lifecycle' if cart else 'customer-profile' if profile else 'customer-checkout'
        selector = 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE' if stock else 'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE' if product else 'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE' if refund else 'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE' if address else 'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE' if older else 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE' if fences else 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE' if payment else 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE' if cart else 'SECURESHOP_CUSTOMER_PROFILE_NATIVE' if profile else 'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE'
        evidence_key = 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH' if stock else 'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH' if product else 'SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH' if refund else 'SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH' if address else 'SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH' if older else 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH' if fences else 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH' if payment else 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH' if cart else 'SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH' if profile else 'SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH'
        checkout = arguments(cohort=cohort)
        self.assertEqual(C.validate_arguments(checkout, planning=True), checkout)
        for value in (None, 'not-a-sha'):
            malformed = list(checkout)
            if value is None:
                index = malformed.index(C.CHECKOUT_MODEL_PIN)
                del malformed[index:index + 2]
            else:
                malformed[malformed.index(C.CHECKOUT_MODEL_PIN) + 1] = value
            with self.subTest(model=value), self.assertRaises(RuntimeError):
                C.validate_arguments(malformed, planning=True)
        wrong_cohort = list(checkout)
        wrong_cohort[wrong_cohort.index('--cohort') + 1] = C.COHORT
        with self.assertRaises(RuntimeError):
            C.validate_arguments(wrong_cohort, planning=True)
        scoped = ('COHORT', 'TEST', 'RECORD', 'ACK', 'KIND', 'PROFILE',
                  'EVIDENCE_ENV', 'SELECTOR_ENV', 'RENDERED_PINS')
        with patch.multiple(L, **{name: getattr(L, name) for name in scoped}):
            L.select_cohort(checkout)
            self.assertEqual((L.COHORT, L.TEST, L.KIND),
                (cohort, L.CHECKOUT_TEST, stem.replace('-', '_') + '_browser'))
            self.assertEqual((L.RECORD, L.ACK),
                (stem + '-browser-birth.json', stem + '-browser-ack.json'))
            self.assertEqual(L.PROFILE, 'owasp-ai-goat-' + stem + '-')
            self.assertEqual(L.direct_command([parsed().node, '--test', '--test-reporter=tap',
                '--test-concurrency=1', L.TEST], parsed()),
                [parsed().node, '--test-reporter=tap', L.TEST])
            original = environment()
            run = L.ROOT / 'tasks/qualification/run-controlled'
            original.pop('SECURESHOP_STANDALONE_COMMERCE_NATIVE')
            original.pop('SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH')
            original.update({selector: '1', evidence_key: str(run / (L.STOCK_RECEIPT if stock else L.PRODUCT_RECEIPT if product else L.CHECKOUT_FENCES_RECEIPT if fences else stem + '-browser.json'))})
            before = {'build': {'index.html': 'b' * 64}}
            env, evidence = L.owned_environment(original, parsed(), before)
            self.assertEqual(evidence, run)
            self.assertEqual(env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'], str(run / L.RECORD))
            self.assertEqual(env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'], str(run / L.ACK))
            grant = L.admission_grant(parsed(), before, env, 123)
            self.assertEqual(grant['cohort'], cohort)
            self.assertEqual(grant['evidencePath'], original[evidence_key])
            for mutation in ({selector: '0'},
                             {evidence_key: str(run / 'foreign.json')},
                             {'TMPDIR': '/private/tmp'}):
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    L.owned_environment({**original, **mutation}, parsed(), before)
            if profile or cart or payment or older or fences or product or stock:
                for other in ('SECURESHOP_STANDALONE_COMMERCE_NATIVE',
                              'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE',
                              'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE',
                              'SECURESHOP_CUSTOMER_PROFILE_NATIVE',
                              'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE',
                              'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE',
                              'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE',
                              'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE',
                              'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE',
                              'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE',
                              'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE',
                              'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE'):
                    if other == selector:
                        continue
                    with self.subTest(other=other), self.assertRaisesRegex(RuntimeError, 'Exclusive'):
                        L.owned_environment({**original, other: '1'}, parsed(), before)
                with self.assertRaises(RuntimeError):
                    L.owned_environment({**original, evidence_key: str(run / L.CHECKOUT_RECEIPT)}, parsed(), before)
            shared = SimpleNamespace(STANDALONE_COMMERCE_TEST='tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js',
                STANDALONE_COMMERCE_TEST_SHA256=L.ORIGINAL_TEST_SHA256,
                CUSTOMER_CHECKOUT_TEST=L.CHECKOUT_TEST,
                CUSTOMER_CHECKOUT_ASSERTION='standalone customer checkout and owned order chat require real model, trusted confirmation, and exact recovery',
                CUSTOMER_PROFILE_TEST=L.CHECKOUT_TEST,
                CUSTOMER_PROFILE_ASSERTION='standalone customer chat prepares and confirms an owned profile update with exact recovery',
                CUSTOMER_CART_LIFECYCLE_TEST=L.CHECKOUT_TEST,
                CUSTOMER_CART_LIFECYCLE_ASSERTION='standalone customer chat prepares, confirms, and exactly recovers bound cart mutations',
                CUSTOMER_PAYMENT_SETUP_TEST=L.CHECKOUT_TEST,
                CUSTOMER_PAYMENT_SETUP_ASSERTION='standalone customer chat opens trusted practice payment setup and exactly recovers one method',
                CUSTOMER_OUT_OF_STOCK_TEST=L.CHECKOUT_TEST,
                CUSTOMER_OUT_OF_STOCK_ASSERTION='standalone customer chat durably rejects an explicit zero-stock add and recovers the exact saved outcome',
                CUSTOMER_PRODUCT_DETAILS_TEST=L.CHECKOUT_TEST,
                CUSTOMER_PRODUCT_DETAILS_ASSERTION='standalone customer chat disambiguates similar owned products and reads the physically selected detail',
                CUSTOMER_REFUND_HANDOFF_TEST=L.CHECKOUT_TEST,
                CUSTOMER_REFUND_HANDOFF_ASSERTION='standalone customer chat opens trusted refund review and exactly recovers one owned ticket',
                CUSTOMER_ADDRESS_SETUP_TEST=L.CHECKOUT_TEST,
                CUSTOMER_ADDRESS_SETUP_ASSERTION='standalone customer chat opens trusted address setup and exactly recovers owned address create and edit',
                CUSTOMER_OLDER_ORDERS_TEST=L.CHECKOUT_TEST,
                CUSTOMER_OLDER_ORDERS_ASSERTION='standalone customer chat paginates owned older orders and reads the physically selected detail',
                CUSTOMER_CHECKOUT_FENCES_TEST=L.CHECKOUT_TEST,
                CUSTOMER_CHECKOUT_FENCES_ASSERTION='standalone customer checkout invalidates changed stock and price and recovers one confirmation across two tabs',
                parse=Mock(return_value=SimpleNamespace(plan=True, policy_renderer_admission=None)), validate_static=Mock())
            with patch.object(L, 'validate_pins'), patch.object(L, 'inventory', return_value=before), \
                    patch.object(L, 'load', return_value=shared), patch.object(L, 'syntax_check'), \
                    patch.object(L, 'consume_environment') as inspector, patch.object(L, 'run') as run_native, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(L.main(checkout), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual((plan['fixtureSeconds'], plan['workSeconds'], plan['launcherSeconds']),
                (600, 600, 600))
            self.assertFalse(plan['fullOriginalCohort'])
            self.assertEqual((plan['cohort'], plan['databaseCount'], plan['roleCount']), (cohort, 4, 8))
            self.assertFalse(plan['nativeStarted'])
            inspector.assert_not_called()
            run_native.assert_not_called()

    def test_closed_original_customer_checkout_uses_same_owner_chain_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain()

    def test_stock_closed_owner_chain(self):
        self.check_closed_customer_owner_chain(stock=True)

    def test_product_closed_owner_chain(self):
        self.check_closed_customer_owner_chain(product=True)

    def test_refund_closed_owner_chain(self):
        self.check_closed_customer_owner_chain(refund=True)

    def test_address_closed_owner_chain(self):
        self.check_closed_customer_owner_chain(address=True)
        self.check_customer_current_host_requires_exact_build_and_model_pins(C.ADDRESS_COHORT)
        self.check_customer_source_closure(C.ADDRESS_COHORT)

    def test_closed_original_customer_profile_uses_distinct_owner_grant_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain(profile=True)

    def test_closed_original_customer_cart_uses_distinct_owner_grant_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain(cart=True)

    def test_closed_original_customer_payment_uses_distinct_owner_grant_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain(payment=True)

    def test_closed_original_customer_older_orders_uses_distinct_owner_grant_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain(older=True)

    def test_closed_original_customer_checkout_fences_uses_distinct_owner_grant_and_600_second_fixture(self):
        self.check_closed_customer_owner_chain(fences=True)

    def test_exact_original_test_command_only(self):
        original = [parsed().node, '--test', '--test-reporter=tap',
                    '--test-concurrency=1', L.TEST]
        self.assertEqual(L.direct_command(original, parsed()),
                         [parsed().node, '--test-reporter=tap', L.TEST])
        for command in (original + ['--test-name-pattern', 'subset'],
                        original[:-1] + ['other.test.js']):
            with self.assertRaises(RuntimeError):
                L.direct_command(command, parsed())

    def test_outer_command_uses_fixed_wrapper_and_adapter_without_run_flag(self):
        command = C.child_command(arguments('--run'))
        self.assertEqual(command[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertIn(str(C.ROOT / C.ADAPTER), command)
        self.assertNotIn('--run', command)

    def test_pending_pins_fail_closed(self):
        with patch.object(L, 'RENDERED_PINS', None):
            with self.assertRaisesRegex(RuntimeError, 'not reviewed/pinned'):
                L.validate_pins()

    def test_environment_keeps_original_stores_and_enforces_owned_paths(self):
        before = {'build': {'index.html': 'b' * 64}}
        original = environment()
        env, run = L.owned_environment(original, parsed(), before)
        for key, value in original.items():
            self.assertEqual(env[key], value)
        self.assertEqual(env['MAC_CHROMIUM_TMPDIR'], env['TMPDIR'])
        self.assertEqual(env['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'], str(run / L.RECORD))
        self.assertEqual(env['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'], str(run / L.ACK))
        self.assertEqual(env['SECURESHOP_COMMERCE_SNAPSHOT_SHA256'], L.safety.encoded(before))
        for change in ({'TMPDIR': '/private/tmp'},
                       {'SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH': '/foreign/standalone-commerce-browser.json'},
                       {'SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH': str(run / 'substitution.json')},
                       {'SECURESHOP_STANDALONE_COMMERCE_NATIVE': '0'},
                       {'SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION': '/foreign'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                L.owned_environment({**original, **change}, parsed(), before)

    def test_grant_is_exact_worker_build_source_and_executable_bound(self):
        before = {'build': {'index.html': 'b' * 64}}
        first = L.admission_grant(parsed(), before, environment(), 123)
        second = L.admission_grant(parsed(), before, environment(), 123)
        self.assertEqual(set(first), {'version', 'cohort', 'launcherPid', 'workerPid',
            'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256',
            'outerSandbox', 'chromium', 'chromiumSha256'})
        self.assertEqual(first['workerPid'], 123)
        self.assertEqual(first['launcherPid'], os.getpid())
        self.assertEqual(first['cohort'], L.COHORT)
        self.assertEqual(first['snapshotSha256'], L.safety.encoded(before))
        self.assertEqual(first['buildSha256'], L.safety.encoded(before['build']))
        self.assertNotEqual(first['nonce'], second['nonce'])
        self.assertLess(len(json.dumps(first).encode()), 8192)

    def test_reuses_existing_live_birth_class_in_private_instance(self):
        before = {'build': {}}
        owner = L.browser_owner(Mock(), parsed(), Mock(), before)
        globals_ = owner.__call__.__func__.__globals__
        self.assertEqual(globals_['TEST'], L.TEST)
        self.assertEqual(globals_['KIND'], L.KIND)
        self.assertEqual(globals_['RECORD'], L.RECORD)
        self.assertEqual(globals_['ACK'], L.ACK)
        original = L.load(L.OWNER, 'commerce_original_v12_unmodified')
        self.assertEqual(original.COHORT, 'customer-idor-lesson-browser')
        self.assertNotEqual(original.TEST, L.TEST)

    def test_plan_never_calls_coordinator_inspector_or_runtime(self):
        shared = SimpleNamespace(STANDALONE_COMMERCE_TEST=L.TEST,
            STANDALONE_COMMERCE_TEST_SHA256=L.ORIGINAL_TEST_SHA256,
            parse=Mock(return_value=SimpleNamespace(plan=True, policy_renderer_admission=None)), validate_static=Mock())
        before = {'build': {'index.html': 'b' * 64}}
        with patch.object(L, 'validate_pins'), \
                patch.object(L, 'RENDERED_PINS', {L.TEST: 'c' * 64}), \
                patch.object(L, 'inventory', return_value=before), \
                patch.object(L, 'load', return_value=shared), \
                patch.object(L, 'syntax_check') as syntax, \
                patch.object(L, 'consume_environment') as inspector, \
                patch.object(L, 'run') as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(L.main(arguments()), 0)
        result = json.loads(output.getvalue())
        self.assertFalse(result['nativeStarted'])
        self.assertTrue(result['fullOriginalCohort'])
        self.assertEqual((result['fixtureSeconds'], result['workSeconds'], result['launcherSeconds']),
                         (330, 280, 360))
        self.assertEqual((result['databaseCount'], result['roleCount']), (4, 8))
        self.assertFalse(result['policyRendererIncluded'])
        inspector.assert_not_called()
        run.assert_not_called()
        syntax.assert_called_once()

    def test_reviewed_snapshot_is_required_only_on_run_and_stripped_from_main(self):
        run = C.validate_arguments(arguments('--run'))
        self.assertNotIn('--expected-snapshot-sha256', L.arguments(run))
        before = {'build': {}}
        with self.assertRaisesRegex(RuntimeError, 'reviewed plan'):
            L.assert_reviewed_snapshot(run, before)
        run[run.index('--expected-snapshot-sha256') + 1] = L.safety.encoded(before)
        L.assert_reviewed_snapshot(run, before)
        L.assert_reviewed_snapshot(arguments(), before)
        with self.assertRaises(RuntimeError):
            C.validate_arguments(arguments() + ['--expected-snapshot-sha256', 'a' * 64],
                                 planning=True)
        bad = arguments('--run')
        bad[bad.index('--expected-snapshot-sha256') + 1] = 'invalid'
        with self.assertRaises(RuntimeError):
            C.validate_arguments(bad)

    def test_mismatched_plan_fails_before_original_main_and_provisioning(self):
        shared = SimpleNamespace(STANDALONE_COMMERCE_TEST=L.TEST,
            STANDALONE_COMMERCE_TEST_SHA256=L.ORIGINAL_TEST_SHA256,
            parse=Mock(return_value=SimpleNamespace(plan=False)), validate_static=Mock())
        with patch.object(L, 'validate_pins'), \
                patch.object(L, 'inventory', return_value={'build': {}}), \
                patch.object(L, 'load', return_value=shared), patch.object(L, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'reviewed plan'):
                L.main(C.validate_arguments(arguments('--run')))
        run.assert_not_called()

    def test_full_original_source_dependency_browser_inventory_is_bound(self):
        shared = SimpleNamespace(source_snapshot=Mock(return_value={
            'files': {'server/authority.js': 'a' * 64}, 'dependencies': {'pg': 'b' * 64}}))
        options = parsed()
        options.browser_root = '/controlled/browser-root'
        with patch.object(L.safety, 'files', return_value={'index.html': 'c' * 64}), \
                patch.object(L.safety, 'validate_modern_build_receipt',
                             return_value={'qualified': True}) as provenance, \
                patch.object(L.safety, 'physical_python', return_value=Path('/controlled/python')), \
                patch.object(L, 'digest', return_value='d' * 64):
            before = L.inventory(shared, options)
            shared.source_snapshot.assert_called_once_with(L.ROOT, options.node, L.COHORT,
            browser_root=Path(options.browser_root), policy_renderer=False)
            shared.source_snapshot.return_value = {
                'files': {'server/authority.js': 'e' * 64}, 'dependencies': {'pg': 'b' * 64}}
            after = L.inventory(shared, options)
        provenance.assert_called_with(L.ROOT, options)
        self.assertIn('originalSource', before)
        self.assertEqual(before['executionArguments']['browser_root'], options.browser_root)
        self.assertNotEqual(L.safety.encoded(before), L.safety.encoded(after))

    def test_full_fixture_syntax_is_checked_without_import_or_setup(self):
        with patch.object(L.subprocess, 'run') as check:
            L.syntax_check(parsed())
        self.assertEqual(check.call_args.args[0],
                         [parsed().node, '--check', str(L.ROOT / L.TEST)])
        self.assertEqual(check.call_args.kwargs['timeout'], 30)
        self.assertTrue(check.call_args.kwargs['check'])


class GrantLifecycle(unittest.TestCase):
    def setUp(self):
        self.before = {'build': {'index.html': 'a' * 64}}
        self.child = SimpleNamespace(pid=111, wait=Mock(return_value=0))
        self.api = Mock()
        self.api.identity.return_value = SimpleNamespace(pid=111, ppid=os.getpid(), pgid=111,
            uid=os.getuid(), ruid=os.getuid(), start_sec=10, start_usec=20)
        self.inherited = None

    def tearDown(self):
        if self.inherited is not None:
            os.close(self.inherited)

    def spawn(self, command, **options):
        self.inherited = os.dup(options['pass_fds'][0])
        self.options = options
        return self.child

    def test_real_fifo_delivers_one_grant_and_no_other_inherited_descriptor(self):
        spawner = L.GrantSpawner(self.spawn, parsed(), self.before, api=self.api)
        with patch.object(L.os, 'getsid', return_value=111):
            child = spawner([parsed().node, '--test-reporter=tap', L.TEST],
                env=environment(), start_new_session=True)
        self.assertIs(child, self.child)
        self.assertEqual(len(self.options['pass_fds']), 1)
        self.assertTrue(self.options['close_fds'])
        grant = json.loads(os.read(self.inherited, 8192))
        self.assertEqual(grant['workerPid'], 111)
        self.assertEqual(os.read(self.inherited, 1), b'')
        with self.assertRaises(OSError):
            os.fstat(self.options['pass_fds'][0])

    def test_foreign_child_gets_no_grant_and_remains_registered_for_original_cleanup(self):
        self.api.identity.return_value.ppid = 99999
        spawner = L.GrantSpawner(self.spawn, parsed(), self.before, api=self.api)
        child = spawner([parsed().node, '--test-reporter=tap', L.TEST],
            env=environment(), start_new_session=True)
        self.assertEqual(os.read(self.inherited, 8192), b'')
        with self.assertRaisesRegex(RuntimeError, 'live birth'):
            child.wait()
        self.assertEqual(child.wait(), 0)

    def test_profile_real_fifo_grant_is_bound_to_distinct_profile_evidence(self):
        scoped = ('COHORT', 'TEST', 'RECORD', 'ACK', 'KIND', 'PROFILE',
                  'EVIDENCE_ENV', 'SELECTOR_ENV', 'RENDERED_PINS')
        with patch.multiple(L, **{name: getattr(L, name) for name in scoped}):
            L.select_cohort(arguments(cohort=C.PROFILE_COHORT))
            run = L.ROOT / 'tasks/qualification/run-controlled'
            env, _ = L.owned_environment({L.SELECTOR_ENV: '1',
                L.EVIDENCE_ENV: str(run / L.PROFILE_RECEIPT),
                'TMPDIR': str(run / 'runtime/tmp')}, parsed(), self.before)
            spawner = L.GrantSpawner(self.spawn, parsed(), self.before, api=self.api)
            with patch.object(L.os, 'getsid', return_value=111):
                self.assertIs(spawner([parsed().node, '--test-reporter=tap', L.TEST],
                    env=env, start_new_session=True), self.child)
            grant = json.loads(os.read(self.inherited, 8192))
            self.assertEqual(grant['cohort'], C.PROFILE_COHORT)
            self.assertEqual(grant['evidencePath'], str(run / L.PROFILE_RECEIPT))
            self.assertEqual(grant['snapshotSha256'], L.safety.encoded(self.before))
            self.assertEqual(os.read(self.inherited, 1), b'')
            with self.assertRaises(OSError):
                os.fstat(self.options['pass_fds'][0])

    def test_unrelated_commands_are_not_given_grant_and_nesting_denied_before_spawn(self):
        original = Mock()
        spawner = L.GrantSpawner(original, parsed(), self.before, api=self.api)
        spawner(['/controlled/docker', 'inspect'])
        original.assert_called_once_with(['/controlled/docker', 'inspect'])
        original.reset_mock()
        with self.assertRaisesRegex(RuntimeError, 'Exclusive'):
            spawner([parsed().node, '--test-reporter=tap', L.TEST],
                env=environment(), start_new_session=True, pass_fds=(99,))
        original.assert_not_called()


class ParentAndFailure(unittest.TestCase):
    @staticmethod
    def actual_main_terminal(evidence, cleanup):
        # Execute the real MAIN print expression; stdout is intentionally only a
        # three-field terminal summary, not its durable result.json receipt.
        tree = ast.parse((L.ROOT / L.MAIN).read_text())
        matches = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'print'
            and len(node.args) == 1 and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Attribute)
            and node.args[0].func.attr == 'dumps'
            and len(node.args[0].args) == 1
            and isinstance(node.args[0].args[0], ast.Dict)
            and all(isinstance(key, ast.Constant) for key in node.args[0].args[0].keys)
            and [key.value for key in node.args[0].args[0].keys] ==
                ['evidence', 'passed', 'cleanup']]
        if len(matches) != 1:
            raise AssertionError('MAIN terminal print contract changed')
        statement = ast.Module(body=[ast.Expr(value=matches[0])], type_ignores=[])
        ast.fix_missing_locations(statement)
        code = compile(statement, str(L.ROOT / L.MAIN), 'exec')
        def emit(_values):
            exec(code, {'print': print, 'json': json, 'str': str},
                 {'evidence': evidence, 'qualified': True, 'cleanup': cleanup})
            return 0
        return emit

    @staticmethod
    def private_json(path, value):
        body = json.dumps(value).encode()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
        return hashlib.sha256(body).hexdigest()

    def checkout_case(self, count=3, mutate=None, terminal_evidence=None,
                      terminal_cleanup=None, profile=False, cart=False, payment=False,
                      older=False, fences=False, refund=False, product=False, stock=False, address=False, manual=False, retired=ACTUAL_RETIREMENT):
        shared = L.load(L.MAIN, 'commerce_checkout_durable_contract')
        with tempfile.TemporaryDirectory(prefix='run-commerce-count-',
                dir=L.ROOT / 'tasks/qualification') as directory:
            evidence = Path(directory)
            cleanup = dict(containerNameAbsent=True, containerIdAbsent=True,
                browserProcessesAbsent=True, browserProfilesAbsent=True, errors=[])
            receipt = {name: True for name in (shared.CUSTOMER_MANUAL_CHECKOUT_FLAGS if manual else shared.CUSTOMER_OUT_OF_STOCK_FLAGS if stock else shared.CUSTOMER_PRODUCT_DETAILS_FLAGS if product else shared.CUSTOMER_REFUND_HANDOFF_FLAGS if refund else shared.CUSTOMER_ADDRESS_SETUP_FLAGS if address else shared.CUSTOMER_OLDER_ORDERS_FLAGS if older
                else shared.CUSTOMER_CHECKOUT_FENCES_FLAGS if fences
                else shared.CUSTOMER_PAYMENT_SETUP_FLAGS if payment
                else shared.CUSTOMER_CART_LIFECYCLE_FLAGS if cart
                else shared.CUSTOMER_PROFILE_FLAGS if profile else shared.CUSTOMER_CHECKOUT_FLAGS)}
            receipt.update(scope=shared.CUSTOMER_OUT_OF_STOCK_SCOPE if stock else shared.CUSTOMER_PRODUCT_DETAILS_SCOPE if product else shared.CUSTOMER_REFUND_HANDOFF_SCOPE if refund else shared.CUSTOMER_ADDRESS_SETUP_SCOPE if address else shared.CUSTOMER_OLDER_ORDERS_SCOPE if older else shared.CUSTOMER_CHECKOUT_FENCES_SCOPE if fences else shared.CUSTOMER_PAYMENT_SETUP_SCOPE if payment else shared.CUSTOMER_CART_LIFECYCLE_SCOPE if cart else shared.CUSTOMER_PROFILE_SCOPE if profile else shared.CUSTOMER_CHECKOUT_SCOPE, actualModelCalls=count,
                           chatTurns=3 if older else 5 if fences else 1 if payment else 2, judgeCalls=0, cleanupErrors=[])
            if payment or older or fences or address or refund or product or stock:
                receipt['passed'] = True
            if refund:
                receipt['refundModelCalls'] = 2
            if manual:
                operation_id = '123e4567-e89b-42d3-a456-426614174000'
                receipt.update(scope=shared.CUSTOMER_MANUAL_CHECKOUT_SCOPE,
                    actualModelCalls=0, chatTurns=0, judgeCalls=0,
                    canonicalCredit=False, qualificationAccepted=False,
                    operationId=operation_id, quoteSha256='a' * 64,
                    scopeKey='b' * 64, orderId=7,
                    physical=dict(preparePosts=1, confirmPosts=1, failedGets=1,
                        recoveredGets=1, prepareStatus=200, committedConfirmStatus=200,
                        browserConfirmAckDelivered=False),
                    journal=dict(operationId=operation_id,
                        targetId='123e4567-e89b-42d3-a456-426614174001',
                        shopUserId=3, kind='checkout', preparedState='prepared',
                        completedState='completed', contextSha256='b' * 64,
                        intentSha256='d' * 64, proposalSha256='a' * 64,
                        resultSha256='e' * 64, orderId=7))
            receipt_path = evidence / (L.MANUAL_CHECKOUT_RECEIPT if manual else L.STOCK_RECEIPT if stock else L.PRODUCT_RECEIPT if product else L.REFUND_RECEIPT if refund else L.ADDRESS_RECEIPT if address else L.OLDER_ORDERS_RECEIPT if older else L.CHECKOUT_FENCES_RECEIPT if fences else L.PAYMENT_RECEIPT if payment else L.CART_RECEIPT if cart else L.PROFILE_RECEIPT if profile else L.CHECKOUT_RECEIPT)
            receipt_hash = self.private_json(receipt_path, receipt)
            durable = dict(cohort=shared.CUSTOMER_CHECKOUT_COHORT, passed=True,
                primaryError=None, sourceCopy=False,
                testExitCodes={'customer-checkout-browser': 0}, cleanup=cleanup,
                customerCheckoutReceipt=receipt,
                customerCheckoutReceiptSha256=receipt_hash)
            if manual:
                durable.update(cohort=shared.CUSTOMER_MANUAL_CHECKOUT_COHORT,
                    testExitCodes={C.MANUAL_CHECKOUT_COHORT: 0},
                    customerManualCheckoutReceipt=durable.pop('customerCheckoutReceipt'),
                    customerManualCheckoutReceiptSha256=durable.pop('customerCheckoutReceiptSha256'))
            if profile:
                durable.update(cohort=shared.CUSTOMER_PROFILE_COHORT,
                    testExitCodes={C.PROFILE_COHORT: 0},
                    customerProfileReceipt=durable.pop('customerCheckoutReceipt'),
                    customerProfileReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if cart:
                durable.update(cohort=shared.CUSTOMER_CART_LIFECYCLE_COHORT,
                    testExitCodes={C.CART_COHORT: 0},
                    customerCartLifecycleReceipt=durable.pop('customerCheckoutReceipt'),
                    customerCartLifecycleReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if payment:
                durable.update(cohort=shared.CUSTOMER_PAYMENT_SETUP_COHORT,
                    testExitCodes={C.PAYMENT_COHORT: 0},
                    customerPaymentSetupReceipt=durable.pop('customerCheckoutReceipt'),
                    customerPaymentSetupReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if address:
                durable.update(cohort=shared.CUSTOMER_ADDRESS_SETUP_COHORT, testExitCodes={C.ADDRESS_COHORT: 0},
                    customerAddressSetupReceipt=durable.pop('customerCheckoutReceipt'),
                    customerAddressSetupReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if product:
                durable.update(cohort=shared.CUSTOMER_PRODUCT_DETAILS_COHORT, testExitCodes={C.PRODUCT_COHORT: 0},
                    customerProductDetailsReceipt=durable.pop('customerCheckoutReceipt'),
                    customerProductDetailsReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if stock:
                durable.update(cohort=shared.CUSTOMER_OUT_OF_STOCK_COHORT, testExitCodes={C.STOCK_COHORT: 0},
                    customerOutOfStockReceipt=durable.pop('customerCheckoutReceipt'),
                    customerOutOfStockReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if refund:
                durable.update(cohort=shared.CUSTOMER_REFUND_HANDOFF_COHORT, testExitCodes={C.REFUND_COHORT: 0},
                    customerRefundHandoffReceipt=durable.pop('customerCheckoutReceipt'),
                    customerRefundHandoffReceiptSha256=durable.pop('customerCheckoutReceiptSha256'),
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
            if older or fences:
                durable.update(cohort=shared.CUSTOMER_OLDER_ORDERS_COHORT if older else shared.CUSTOMER_CHECKOUT_FENCES_COHORT,
                    testExitCodes={C.OLDER_ORDERS_COHORT if older else C.CHECKOUT_FENCES_COHORT: 0},
                    modelPin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                              'sha256': parsed().ollama_model_sha256})
                durable['customerOlderOrdersReceipt' if older else 'customerCheckoutFencesReceipt'] = durable.pop('customerCheckoutReceipt')
                durable['customerOlderOrdersReceiptSha256' if older else 'customerCheckoutFencesReceiptSha256'] = durable.pop('customerCheckoutReceiptSha256')
            if mutate:
                mutate(evidence, cleanup, receipt, durable)
            result_path = evidence / 'result.json'
            if not result_path.exists() and not result_path.is_symlink():
                self.private_json(result_path, durable)
            record = {'kind': 'customer_manual_checkout_browser' if manual else 'customer_out_of_stock_browser' if stock else 'customer_product_details_browser' if product else 'customer_refund_handoff_browser' if refund else 'customer_address_setup_browser' if address else 'customer_older_orders_browser' if older else 'customer_checkout_fences_browser' if fences else 'customer_payment_setup_browser' if payment else 'customer_cart_lifecycle_browser' if cart else 'customer_profile_browser' if profile else 'customer_checkout_browser',
                      'pid': 54321, 'birth': [100, 200]}
            owner = SimpleNamespace(evidence=evidence, captured=SimpleNamespace(record=record),
                                    retired=None, error=None)
            def absent(records):
                if retired is ACTUAL_RETIREMENT:
                    identity = Mock(return_value=None)
                    result = B.prove_record_absent(records,
                        api=SimpleNamespace(identity=identity))
                    identity.assert_called_once_with(record['pid'])
                    return result
                return retired(records) if callable(retired) else retired
            ownership = SimpleNamespace(_browser_modules=Mock(return_value=(None, None,
                None, None, absent)))
            original = Mock()
            # This fixture executes only MAIN's terminal expression. Keep its
            # fake process namespace private so adjacent real controls still
            # use the actual subprocess module.
            shared.subprocess = SimpleNamespace(Popen=original)
            shared.main = self.actual_main_terminal(
                terminal_evidence or evidence, terminal_cleanup or cleanup)
            reports = []
            with patch.object(L, 'COHORT', L.MANUAL_CHECKOUT_COHORT if manual else L.STOCK_COHORT if stock else L.PRODUCT_COHORT if product else L.REFUND_COHORT if refund else L.ADDRESS_COHORT if address else L.OLDER_ORDERS_COHORT if older else L.CHECKOUT_FENCES_COHORT if fences else L.PAYMENT_COHORT if payment else L.CART_COHORT if cart else L.PROFILE_COHORT if profile else L.CHECKOUT_COHORT), \
                    patch.object(L, 'browser_owner', return_value=owner), \
                    patch.object(L, 'inventory', return_value={}), \
                    patch.object(L.safety, 'private_json',
                        side_effect=lambda _p, body: reports.append(body)), \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    outcome = L.run(shared, [], parsed(), ownership, {})
                    failure = None
                except Exception as error:
                    outcome, failure = None, error
            self.assertIs(shared.subprocess.Popen, original)
            return outcome, failure, reports[-1]

    def test_checkout_report_uses_only_main_validated_physical_model_count(self):
        outcome, failure, report = self.checkout_case()
        self.assertIsNone(failure)
        self.assertEqual(outcome, 0)
        self.assertEqual(report['actualModelCalls'], 3)
        self.assertTrue(report['adapterPassed'])

    def test_manual_checkout_durable_zero_actor_receipt_and_negative_effect_counts(self):
        outcome, failure, report = self.checkout_case(count=0, manual=True)
        self.assertIsNone(failure)
        self.assertEqual(outcome, 0)
        self.assertEqual(report['actualModelCalls'], 0)
        self.assertTrue(report['adapterPassed'])
        def extra_confirm(evidence, cleanup, receipt, durable):
            receipt['physical']['confirmPosts'] = 2
            path = evidence / L.MANUAL_CHECKOUT_RECEIPT
            path.unlink()
            durable['customerManualCheckoutReceiptSha256'] = self.private_json(path, receipt)
            durable['customerManualCheckoutReceipt'] = receipt
        _, failure, report = self.checkout_case(count=0, manual=True, mutate=extra_confirm)
        self.assertIsInstance(failure, RuntimeError)
        self.assertFalse(report['adapterPassed'])
        _, failure, report = self.checkout_case(count=0, manual=True,
            mutate=lambda _e, _c, _r, durable: durable.update(modelPin={'sha256': 'f' * 64}))
        self.assertIsInstance(failure, RuntimeError)
        self.assertFalse(report['adapterPassed'])
        for count in (True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_profile_uses_actual_main_receipt_and_model_pin_join(self):
        for count in (2, 10):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, profile=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertFalse(report['fullOriginalCohort'])
                self.assertFalse(report['fullQ05Qualification'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_profile_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 11, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, profile=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_cart_uses_actual_main_receipt_and_model_pin_join(self):
        for count in (2, 24):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, cart=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_cart_lifecycle_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 25, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, cart=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_cart_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'checkout-exit': lambda e, c, r, d: d.update(testExitCodes={C.CHECKOUT_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'receipt-alias': lambda e, c, r, d: d['customerCartLifecycleReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerCartLifecycleReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(cart=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_cart_actual_validator_rejects_missing_criteria_and_changed_budget(self):
        shared = L.load(L.MAIN, 'cart_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_CART_LIFECYCLE_FLAGS), 13)
        mutations = {key: False for key in shared.CUSTOMER_CART_LIFECYCLE_FLAGS}
        mutations.update(scope='foreign', chatTurns=7, judgeCalls=1,
                         cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.CART_RECEIPT
                path.unlink()
                durable['customerCartLifecycleReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(cart=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])
        valid = {'kind': 'customer_cart_lifecycle_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_profile_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(cart=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_payment_uses_original_main_validator_and_exact_model_pin(self):
        for count in (2, 4):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, payment=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_payment_setup_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 5, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, payment=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_payment_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'cart-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.PAYMENT_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'receipt-alias': lambda e, c, r, d: d['customerPaymentSetupReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerPaymentSetupReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(payment=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
        valid = {'kind': 'customer_payment_setup_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_cart_lifecycle_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(payment=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_payment_validator_preserves_all_original_flags_one_turn_and_zero_judge(self):
        shared = L.load(L.MAIN, 'payment_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_PAYMENT_SETUP_FLAGS), 11)
        mutations = {key: False for key in shared.CUSTOMER_PAYMENT_SETUP_FLAGS}
        mutations.update(passed=False, scope='foreign', chatTurns=2,
                         judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.PAYMENT_RECEIPT
                path.unlink()
                durable['customerPaymentSetupReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(payment=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_address_uses_original_main_validator_and_exact_model_pin(self):
        for count in (2, 12):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, address=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_address_setup_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 13, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, address=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_address_exact_receipt_shape_and_all_original_turn_boundaries(self):
        for turns in (1, 2, 3, 0, 4, True, '1'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt['chatTurns'] = turns
                path = evidence / L.ADDRESS_RECEIPT
                path.unlink()
                durable['customerAddressSetupReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(address=True, mutate=mutate)
            valid = type(turns) is int and 1 <= turns <= 3
            self.assertEqual(failure is None, valid)
            self.assertEqual(report['adapterPassed'], valid)
        for key in ('passed', 'isolatedStores', 'lostAckExactRecovery'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt.pop(key)
                path = evidence / L.ADDRESS_RECEIPT
                path.unlink()
                durable['customerAddressSetupReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(address=True, mutate=mutate)
            self.assertIsNotNone(failure)
            self.assertFalse(report['adapterPassed'])

    def test_address_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'cart-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.ADDRESS_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'receipt-alias': lambda e, c, r, d: d['customerAddressSetupReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerAddressSetupReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(address=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
        valid = {'kind': 'customer_address_setup_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_cart_lifecycle_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(address=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_address_validator_preserves_all_original_flags_turn_bounds_and_zero_judge(self):
        shared = L.load(L.MAIN, 'address_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_ADDRESS_SETUP_FLAGS), 12)
        mutations = {key: False for key in shared.CUSTOMER_ADDRESS_SETUP_FLAGS}
        mutations.update(passed=False, scope='foreign', chatTurns=4, extra='unadmitted',
                         judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.ADDRESS_RECEIPT
                path.unlink()
                durable['customerAddressSetupReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(address=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_product_uses_original_main_validator_and_exact_model_pin(self):
        for count in (2, 8):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, product=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_product_details_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 9, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, product=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_product_exact_receipt_shape_and_all_original_turn_boundaries(self):
        for turns in (1, 2, 3, 0, 4, True, '1'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt['chatTurns'] = turns
                path = evidence / L.PRODUCT_RECEIPT
                path.unlink()
                durable['customerProductDetailsReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(product=True, mutate=mutate)
            valid = type(turns) is int and turns == 2
            self.assertEqual(failure is None, valid)
            self.assertEqual(report['adapterPassed'], valid)
        for key in ('passed', 'isolatedStores', 'renderedSelectedProductDetails'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt.pop(key)
                path = evidence / L.PRODUCT_RECEIPT
                path.unlink()
                durable['customerProductDetailsReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(product=True, mutate=mutate)
            self.assertIsNotNone(failure)
            self.assertFalse(report['adapterPassed'])

    def test_product_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'missing-count': lambda e, c, r, d: d['customerProductDetailsReceipt'].pop('actualModelCalls'),
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'cart-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.PRODUCT_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'receipt-alias': lambda e, c, r, d: d['customerProductDetailsReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerProductDetailsReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(product=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
        valid = {'kind': 'customer_product_details_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_cart_lifecycle_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(product=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_product_validator_preserves_all_original_flags_turn_bounds_and_zero_judge(self):
        shared = L.load(L.MAIN, 'product_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_PRODUCT_DETAILS_FLAGS), 7)
        mutations = {key: False for key in shared.CUSTOMER_PRODUCT_DETAILS_FLAGS}
        mutations.update(passed=False, scope='foreign', chatTurns=4, extra='unadmitted',
                         judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.PRODUCT_RECEIPT
                path.unlink()
                durable['customerProductDetailsReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(product=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_stock_uses_original_main_validator_and_exact_model_pin(self):
        for count in (2, 8):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, stock=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_out_of_stock_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 9, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, stock=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_stock_exact_receipt_shape_and_all_original_turn_boundaries(self):
        for turns in (1, 2, 3, 0, 4, True, '1'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt['chatTurns'] = turns
                path = evidence / L.STOCK_RECEIPT
                path.unlink()
                durable['customerOutOfStockReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(stock=True, mutate=mutate)
            valid = type(turns) is int and turns == 2
            self.assertEqual(failure is None, valid)
            self.assertEqual(report['adapterPassed'], valid)
        for key in ('passed', 'isolatedStores', 'exactGetRecoveryNoReplay'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt.pop(key)
                path = evidence / L.STOCK_RECEIPT
                path.unlink()
                durable['customerOutOfStockReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(stock=True, mutate=mutate)
            self.assertIsNotNone(failure)
            self.assertFalse(report['adapterPassed'])

    def test_stock_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'missing-count': lambda e, c, r, d: d['customerOutOfStockReceipt'].pop('actualModelCalls'),
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'cart-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.STOCK_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'receipt-alias': lambda e, c, r, d: d['customerOutOfStockReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerOutOfStockReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(stock=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
        valid = {'kind': 'customer_out_of_stock_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_cart_lifecycle_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(stock=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_stock_validator_preserves_all_original_flags_turn_bounds_and_zero_judge(self):
        shared = L.load(L.MAIN, 'stock_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_OUT_OF_STOCK_FLAGS), 10)
        mutations = {key: False for key in shared.CUSTOMER_OUT_OF_STOCK_FLAGS}
        mutations.update(passed=False, scope='foreign', chatTurns=4, extra='unadmitted',
                         judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.STOCK_RECEIPT
                path.unlink()
                durable['customerOutOfStockReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(stock=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_refund_separate_counter_exact_bounds_and_no_swap(self):
        for actual, refund_count in ((2, 2), (8, 6), (8, 8), (6, 8), (2, 1), (2, 7), (2, True), (2, '2'), (2, None)):
            def mutate(evidence, cleanup, receipt, durable):
                if refund_count is None:
                    receipt.pop('refundModelCalls')
                else:
                    receipt['refundModelCalls'] = refund_count
                path = evidence / L.REFUND_RECEIPT
                path.unlink()
                durable['customerRefundHandoffReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(actual, refund=True, mutate=mutate)
            valid = type(refund_count) is int and 2 <= refund_count <= 6
            self.assertEqual(failure is None, valid)
            self.assertEqual(report['adapterPassed'], valid)
            self.assertEqual(report['refundModelCalls'], refund_count if valid else None)

    def test_refund_uses_original_main_validator_and_exact_model_pin(self):
        for count in (2, 8):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, refund=True)
                self.assertIsNone(failure)
                self.assertEqual(outcome, 0)
                self.assertEqual(report['actualModelCalls'], count)
                self.assertTrue(report['adapterPassed'])
                self.assertEqual(report['browserRetirement'], [{
                    'kind': 'customer_refund_handoff_browser', 'pid': 54321,
                    'birth': [100, 200], 'absent': True}])
        for count in (1, 9, True, '3'):
            with self.subTest(count=count):
                outcome, failure, report = self.checkout_case(count, refund=True)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])

    def test_refund_exact_receipt_shape_and_all_original_turn_boundaries(self):
        for turns in (1, 2, 3, 0, 4, True, '1'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt['chatTurns'] = turns
                path = evidence / L.REFUND_RECEIPT
                path.unlink()
                durable['customerRefundHandoffReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(refund=True, mutate=mutate)
            valid = type(turns) is int and turns == 2
            self.assertEqual(failure is None, valid)
            self.assertEqual(report['adapterPassed'], valid)
        for key in ('passed', 'isolatedStores', 'renderedLostAckGetRecovery'):
            def mutate(evidence, cleanup, receipt, durable):
                receipt.pop(key)
                path = evidence / L.REFUND_RECEIPT
                path.unlink()
                durable['customerRefundHandoffReceiptSha256'] = self.private_json(path, receipt)
            outcome, failure, report = self.checkout_case(refund=True, mutate=mutate)
            self.assertIsNotNone(failure)
            self.assertFalse(report['adapterPassed'])

    def test_refund_rejects_cross_cohort_model_receipt_and_retirement_aliases(self):
        variants = {
            'missing-actual-count': lambda e, c, r, d: d['customerRefundHandoffReceipt'].pop('actualModelCalls'),
            'swapped-durable-counters': lambda e, c, r, d: d.update(customerRefundHandoffReceipt={**r,
                'actualModelCalls': 2, 'refundModelCalls': r['actualModelCalls']}),
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'cart-exit': lambda e, c, r, d: d.update(testExitCodes={C.CART_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.REFUND_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'receipt-alias': lambda e, c, r, d: d['customerRefundHandoffReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerRefundHandoffReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(refund=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
        valid = {'kind': 'customer_refund_handoff_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        for retired in ([], True, [{**valid, 'kind': 'customer_cart_lifecycle_browser'}],
                        [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
            with self.subTest(retired=retired):
                outcome, failure, report = self.checkout_case(refund=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])

    def test_refund_validator_preserves_all_original_flags_turn_bounds_and_zero_judge(self):
        shared = L.load(L.MAIN, 'refund_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_REFUND_HANDOFF_FLAGS), 11)
        mutations = {key: False for key in shared.CUSTOMER_REFUND_HANDOFF_FLAGS}
        mutations.update(passed=False, scope='foreign', chatTurns=4, extra='unadmitted',
                         judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.REFUND_RECEIPT
                path.unlink()
                durable['customerRefundHandoffReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(refund=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_older_orders_and_checkout_fences_use_separate_original_validators(self):
        shared = L.load(L.MAIN, 'older_and_fences_original_receipt_contract')
        for options, flags, expected_count, lower, upper, receipt_name, receipt_key, kind in (
                ({'older': True}, shared.CUSTOMER_OLDER_ORDERS_FLAGS, 3, 3, 15,
                 L.OLDER_ORDERS_RECEIPT, 'customerOlderOrdersReceipt', 'customer_older_orders_browser'),
                ({'fences': True}, shared.CUSTOMER_CHECKOUT_FENCES_FLAGS, 5, 5, 20,
                 L.CHECKOUT_FENCES_RECEIPT, 'customerCheckoutFencesReceipt', 'customer_checkout_fences_browser')):
            with self.subTest(cohort=options):
                self.assertEqual(len(flags), 14 if options.get('older') else 12)
                for count in (lower, upper):
                    outcome, failure, report = self.checkout_case(count, **options)
                    self.assertIsNone(failure)
                    self.assertEqual(outcome, 0)
                    self.assertEqual(report['actualModelCalls'], count)
                    self.assertEqual(report['browserRetirement'], [{
                        'kind': kind, 'pid': 54321, 'birth': [100, 200], 'absent': True}])
                for count in (lower - 1, upper + 1, True, str(expected_count)):
                    outcome, failure, report = self.checkout_case(count, **options)
                    self.assertIsNone(outcome)
                    self.assertIsNotNone(failure)
                    self.assertFalse(report['adapterPassed'])
                    self.assertIsNone(report['actualModelCalls'])
                for field in flags:
                    def changed(evidence, cleanup, receipt, durable):
                        receipt[field] = False
                        path = evidence / receipt_name
                        path.unlink()
                        durable[receipt_key + 'Sha256'] = self.private_json(path, receipt)
                    with self.subTest(field=field):
                        outcome, failure, report = self.checkout_case(expected_count, mutate=changed, **options)
                        self.assertIsNone(outcome)
                        self.assertIsNotNone(failure)
                        self.assertFalse(report['adapterPassed'])
                for field, value in (('scope', 'foreign'), ('chatTurns', expected_count + 1),
                                     ('judgeCalls', 1), ('cleanupErrors', ['debt'])):
                    def changed(evidence, cleanup, receipt, durable):
                        receipt[field] = value
                        path = evidence / receipt_name
                        path.unlink()
                        durable[receipt_key + 'Sha256'] = self.private_json(path, receipt)
                    with self.subTest(field=field):
                        outcome, failure, report = self.checkout_case(expected_count, mutate=changed, **options)
                        self.assertIsNone(outcome)
                        self.assertIsNotNone(failure)
                        self.assertFalse(report['adapterPassed'])

    def test_older_orders_and_fences_reject_cross_cohort_receipt_model_and_retirement(self):
        for options, key, other, kind in (
                ({'older': True}, 'customerOlderOrdersReceipt', C.CHECKOUT_FENCES_COHORT,
                 'customer_older_orders_browser'),
                ({'fences': True}, 'customerCheckoutFencesReceipt', C.OLDER_ORDERS_COHORT,
                 'customer_checkout_fences_browser')):
            count = 3 if options.get('older') else 5
            selected = C.OLDER_ORDERS_COHORT if options.get('older') else C.CHECKOUT_FENCES_COHORT
            mutations = {
                'foreign-cohort': lambda e, c, r, d: d.update(cohort=other),
                'foreign-exit': lambda e, c, r, d: d.update(testExitCodes={other: 0}),
                'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={selected: False}),
                'missing-model': lambda e, c, r, d: d.pop('modelPin'),
                'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
                'wrong-receipt-hash': lambda e, c, r, d: d.update({key + 'Sha256': '0' * 64}),
                'receipt-alias': lambda e, c, r, d: d[key].update(judgeCalls=False),
            }
            for label, mutation in mutations.items():
                with self.subTest(cohort=options, mutation=label):
                    outcome, failure, report = self.checkout_case(count, mutate=mutation, **options)
                    self.assertIsNone(outcome)
                    self.assertIsNotNone(failure)
                    self.assertFalse(report['adapterPassed'])
            valid = {'kind': kind, 'pid': 54321, 'birth': [100, 200], 'absent': True}
            for retired in ([], True, [{**valid, 'kind': 'customer_checkout_browser'}],
                            [{**valid, 'pid': 54322}], [{**valid, 'absent': False}]):
                with self.subTest(cohort=options, retired=retired):
                    outcome, failure, report = self.checkout_case(count, retired=retired, **options)
                    self.assertIsNone(outcome)
                    self.assertIsNotNone(failure)
                    self.assertFalse(report['adapterPassed'])

    def test_profile_retirement_requires_exact_captured_browser_receipt(self):
        valid = {'kind': 'customer_profile_browser', 'pid': 54321,
                 'birth': [100, 200], 'absent': True}
        variants = {
            'empty': [], 'duplicate': [valid, valid], 'boolean': True,
            'missing': [{key: value for key, value in valid.items() if key != 'birth'}],
            'extra': [{**valid, 'extra': True}],
            'wrong-kind': [{**valid, 'kind': 'customer_checkout_browser'}],
            'wrong-pid': [{**valid, 'pid': 54322}],
            'boolean-pid': [{**valid, 'pid': True}],
            'wrong-birth': [{**valid, 'birth': [100, 201]}],
            'boolean-birth': [{**valid, 'birth': [True, 200]}],
            'not-absent': [{**valid, 'absent': False}],
            'boolean-alias': [{**valid, 'absent': 1}],
        }
        for label, retired in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(profile=True, retired=retired)
                self.assertIsNone(outcome)
                self.assertRegex(str(failure), 'profile browser retirement unproved')
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])
                self.assertEqual(report['browserRetirement'], retired)
        def still_alive(records):
            return B.prove_record_absent(records, api=SimpleNamespace(identity=lambda pid:
                SimpleNamespace(start_sec=100, start_usec=200)))
        outcome, failure, report = self.checkout_case(profile=True, retired=still_alive)
        self.assertIsNone(outcome)
        self.assertRegex(str(failure), 'Owned browser birth remains')
        self.assertFalse(report['adapterPassed'])

    def test_profile_actual_validator_rejects_every_missing_criterion_and_changed_budget(self):
        shared = L.load(L.MAIN, 'profile_original_receipt_contract')
        self.assertEqual(len(shared.CUSTOMER_PROFILE_FLAGS), 14)
        mutations = {key: False for key in shared.CUSTOMER_PROFILE_FLAGS}
        mutations.update(scope='foreign', chatTurns=3, judgeCalls=1, cleanupErrors=['debt'])
        for key, value in mutations.items():
            def mutate(evidence, cleanup, receipt, durable):
                receipt[key] = value
                path = evidence / L.PROFILE_RECEIPT
                path.unlink()
                durable['customerProfileReceiptSha256'] = self.private_json(path, receipt)
            with self.subTest(key=key):
                outcome, failure, report = self.checkout_case(profile=True, mutate=mutate)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_profile_durable_cross_cohort_and_model_cleanup_or_identity_mismatches_fail_closed(self):
        variants = {
            'checkout-cohort': lambda e, c, r, d: d.update(cohort='secureshop-customer-checkout-browser-current-main-v1'),
            'checkout-exit': lambda e, c, r, d: d.update(testExitCodes={C.CHECKOUT_COHORT: 0}),
            'boolean-exit': lambda e, c, r, d: d.update(testExitCodes={C.PROFILE_COHORT: False}),
            'missing-model': lambda e, c, r, d: d.pop('modelPin'),
            'wrong-model': lambda e, c, r, d: d['modelPin'].update(sha256='0' * 64),
            'wrong-endpoint': lambda e, c, r, d: d['modelPin'].update(baseURL='http://foreign'),
            'model-extra': lambda e, c, r, d: d['modelPin'].update(extra=True),
            'receipt-alias': lambda e, c, r, d: d['customerProfileReceipt'].update(judgeCalls=False),
            'wrong-receipt-hash': lambda e, c, r, d: d.update(customerProfileReceiptSha256='0' * 64),
            'cleanup-alias': lambda e, c, r, d: d.update(cleanup={**c, 'containerIdAbsent': 1}),
            'failed-main': lambda e, c, r, d: d.update(passed=False),
            'primary-failure': lambda e, c, r, d: d.update(primaryError='preserved failure'),
            'world-readable': lambda e, c, r, d: self.private_json(e / 'result.json', d) and (e / 'result.json').chmod(0o644),
            'symlink': lambda e, c, r, d: (e / 'result.json').symlink_to(e / L.PROFILE_RECEIPT),
            'hardlink': lambda e, c, r, d: self.private_json(e / 'result.json', d) and os.link(e / 'result.json', e / 'other.json'),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(profile=True, mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])
        for options in ({'retired': False}, {'retired': None},
                        {'terminal_evidence': L.ROOT / 'tasks/qualification/run-foreign'},
                        {'terminal_cleanup': {'errors': ['debt']}}):
            with self.subTest(options=options):
                outcome, failure, report = self.checkout_case(profile=True, **options)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertFalse(report['adapterPassed'])
                self.assertIsNone(report['actualModelCalls'])

    def test_checkout_terminal_and_durable_result_must_match(self):
        variants = {
            'wrong-cohort': lambda e, c, r, d: d.update(cohort='foreign'),
            'wrong-cleanup': lambda e, c, r, d: d.update(cleanup={'errors': []}),
            'failed-durable': lambda e, c, r, d: d.update(passed=False),
            'missing-primary': lambda e, c, r, d: d.pop('primaryError'),
            'boolean-exit': lambda e, c, r, d: d.update(
                testExitCodes={'customer-checkout-browser': False}),
            'wrong-receipt': lambda e, c, r, d: d.update(customerCheckoutReceipt={}),
            'boolean-judge-alias': lambda e, c, r, d: d['customerCheckoutReceipt'].update(
                judgeCalls=False),
            'boolean-cleanup-alias': lambda e, c, r, d: d.update(cleanup={
                **c, 'containerIdAbsent': 1}),
            'wrong-sha': lambda e, c, r, d: d.update(customerCheckoutReceiptSha256='0' * 64),
            'wrong-count': lambda e, c, r, d: d['customerCheckoutReceipt'].update(actualModelCalls=4),
            'symlink': lambda e, c, r, d: (e / 'result.json').symlink_to(e / L.CHECKOUT_RECEIPT),
            'world-readable': lambda e, c, r, d: self.private_json(e / 'result.json', d) and
                (e / 'result.json').chmod(0o644),
            'hardlink': lambda e, c, r, d: self.private_json(e / 'result.json', d) and
                os.link(e / 'result.json', e / 'other-result.json'),
            'malformed-json': lambda e, c, r, d: self.private_json(e / 'result.json', d) and
                (e / 'result.json').write_bytes(b'{'),
            'oversize': lambda e, c, r, d: self.private_json(e / 'result.json', d) and
                (e / 'result.json').write_bytes(b' ' * 65537),
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(mutate=mutation)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])
                self.assertFalse(report['adapterPassed'])
        for label, options in {
            'terminal-path': {'terminal_evidence': L.ROOT / 'tasks/qualification/run-foreign'},
            'terminal-cleanup': {'terminal_cleanup': {'errors': ['retirement-debt']}},
        }.items():
            with self.subTest(label=label):
                outcome, failure, report = self.checkout_case(**options)
                self.assertIsNone(outcome)
                self.assertIsNotNone(failure)
                self.assertIsNone(report['actualModelCalls'])

    def test_checkout_failure_before_receipt_reports_unknown_not_zero(self):
        primary = RuntimeError('controlled failure before checkout receipt')
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-mocked',
                                captured=None, retired=None, error=None)
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=Mock()),
                                 main=Mock(side_effect=primary))
        reports = []
        with patch.object(L, 'COHORT', L.CHECKOUT_COHORT), \
                patch.object(L, 'browser_owner', return_value=owner), \
                patch.object(L, 'inventory', return_value={}), \
                patch.object(L.safety, 'private_json', side_effect=lambda _p, body: reports.append(body)):
            with self.assertRaises(RuntimeError) as error:
                L.run(shared, [], parsed(), Mock(), {})
        self.assertIs(error.exception, primary)
        self.assertIsNone(reports[-1]['actualModelCalls'])
        self.assertFalse(reports[-1]['adapterPassed'])

    def test_fixed_parent_birth_args_and_sandbox_required(self):
        api = Mock()
        parent = os.getppid()
        api.identity.return_value = SimpleNamespace(uid=os.getuid(), ruid=os.getuid(),
                                                    start_sec=100, start_usec=20)
        original = arguments('--run')
        argv = C.validate_arguments(original)
        api.arguments.return_value = ['/physical/python', '-B',
            str(L.ROOT / 'tests/postgres/run_standalone_commerce_with_inspector.py'), *original]
        denied = lambda path: str(path) == '/private/tmp'
        with patch.object(L.safety, 'physical_python', return_value=Path('/physical/python')):
            L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=denied)
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent + 1), api=api, denied=denied)
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=lambda _: False)
            api.arguments.return_value[2] = '/arbitrary/script.py'
            with self.assertRaises(RuntimeError):
                L.verify_outer_boundary(argv, SimpleNamespace(parent=parent), api=api, denied=denied)

    def test_original_failure_restores_popen_and_is_not_replaced_by_inventory_error(self):
        primary = RuntimeError('original commerce failure')
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original),
                                 main=Mock(side_effect=primary))
        owner = SimpleNamespace(evidence=None, captured=None, retired=None, error=None)
        with patch.object(L, 'browser_owner', return_value=owner), \
                patch.object(L, 'inventory', side_effect=OSError('postflight unavailable')):
            with self.assertRaises(RuntimeError) as error:
                L.run(shared, [], parsed(), Mock(), {})
        self.assertIs(error.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)

    def test_failed_report_write_keeps_original_failure(self):
        primary = RuntimeError('original failure')
        original = Mock()
        shared = SimpleNamespace(subprocess=SimpleNamespace(Popen=original),
                                 main=Mock(side_effect=primary))
        owner = SimpleNamespace(evidence=L.ROOT / 'tasks/qualification/run-mocked',
                                captured=None, retired=None, error=None)
        with patch.object(L, 'browser_owner', return_value=owner), \
                patch.object(L, 'inventory', return_value={}), \
                patch.object(L.safety, 'private_json', side_effect=OSError('controlled write failure')), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError) as error:
                L.run(shared, [], parsed(), Mock(), {})
        self.assertIs(error.exception, primary)
        self.assertIs(shared.subprocess.Popen, original)


class ProfileCleanup(unittest.TestCase):
    def test_main_profile_directory_is_not_reported_absent_until_removed(self):
        shared = L.load(L.MAIN, 'customer_profile_cleanup_contract')
        with tempfile.TemporaryDirectory(prefix='run-profile-cleanup-',
                dir=L.ROOT / 'tasks/qualification') as directory:
            runtime = Path(directory) / 'runtime'
            profile = runtime / 'tmp/owasp-ai-goat-customer-profile-controlled'
            profile.mkdir(parents=True, mode=0o700)
            # Exercise the actual directory scan without any host process probe.
            with patch.object(shared.sys, 'platform', 'linux'), \
                    patch.object(shared.subprocess, 'run', return_value=SimpleNamespace(stdout='')):
                self.assertEqual(shared.standalone_browser_cleanup_state(runtime),
                    {'browserProfilesAbsent': False, 'browserProcessesAbsent': True})
                profile.rmdir()
                self.assertEqual(shared.standalone_browser_cleanup_state(runtime),
                    {'browserProfilesAbsent': True, 'browserProcessesAbsent': True})

    def test_profile_specific_owned_retirement_and_debt_controls(self):
        with patch.object(L, 'PROFILE', 'owasp-ai-goat-customer-profile-'):
            self.test_retirement_and_complete_profile_absence_precede_exact_removal()
            self.test_failed_retirement_or_inspection_and_replaced_profile_preserve_files()

    def test_retirement_and_complete_profile_absence_precede_exact_removal(self):
        with tempfile.TemporaryDirectory(prefix='run-commerce-control-',
                dir=L.ROOT / 'tasks/qualification') as directory:
            runtime = Path(directory) / 'runtime'
            profile = runtime / 'tmp' / (L.PROFILE + 'controlled')
            profile.mkdir(parents=True, mode=0o700)
            captured = SimpleNamespace(profile=str(profile))
            calls = []
            ownership = SimpleNamespace(
                capture_live_v36=Mock(return_value=captured),
                retire_live_v36=Mock(side_effect=lambda *_a, **_kw: calls.append('retire') or ['absent']))
            inspector = SimpleNamespace(absent=Mock(side_effect=lambda *_a:
                calls.append('inspect') or True))
            L.install_profile_cleanup(ownership, inspector)
            ownership.capture_live_v36({}, (10, 20), runtime, api=Mock())
            remove = L.shutil.rmtree
            with patch.object(L.shutil, 'rmtree', side_effect=lambda target:
                    calls.append('remove') or remove(target)):
                self.assertEqual(ownership.retire_live_v36(captured, api=Mock()), ['absent'])
                self.assertEqual(calls, ['retire', 'inspect', 'remove'])
                ownership.retire_live_v36(captured, api=Mock())
                self.assertEqual(calls.count('remove'), 1)
            self.assertFalse(profile.exists())

    def test_failed_retirement_or_inspection_and_replaced_profile_preserve_files(self):
        for failure in ('retire', 'inspect', 'replace'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(
                    prefix='run-commerce-control-', dir=L.ROOT / 'tasks/qualification') as directory:
                runtime = Path(directory) / 'runtime'
                profile = runtime / 'tmp' / (L.PROFILE + 'controlled')
                profile.mkdir(parents=True, mode=0o700)
                captured = SimpleNamespace(profile=str(profile))
                ownership = SimpleNamespace(capture_live_v36=Mock(return_value=captured),
                    retire_live_v36=Mock(side_effect=RuntimeError('retirement failed')
                        if failure == 'retire' else None, return_value=['absent']))
                inspector = SimpleNamespace(absent=Mock(return_value=failure != 'inspect'))
                L.install_profile_cleanup(ownership, inspector)
                ownership.capture_live_v36({}, (10, 20), runtime, api=Mock())
                if failure == 'replace':
                    captured.commerce_profile_identity = (-1, -1)
                with patch.object(L.shutil, 'rmtree') as remove:
                    with self.assertRaises(RuntimeError):
                        ownership.retire_live_v36(captured, api=Mock())
                    remove.assert_not_called()
                self.assertTrue(profile.is_dir())


if __name__ == '__main__':
    unittest.main()
