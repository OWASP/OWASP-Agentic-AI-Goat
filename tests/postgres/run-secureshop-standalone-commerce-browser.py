#!/usr/bin/env python3
"""Owned, whole-cohort commerce adapter; original main and criteria unchanged."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys

import admin_q05_current_host as safety
import run_standalone_commerce_with_inspector as outer
from trusted_process_inspector import consume_environment

ROOT = Path(__file__).resolve().parents[2]
COHORT = outer.COHORT
SESSION_REVOKE_COHORT = outer.SESSION_REVOKE_COHORT
SESSION_REVOKE_OTHER_COHORT = outer.SESSION_REVOKE_OTHER_COHORT
ACCOUNT_AVATAR_COHORT = outer.ACCOUNT_AVATAR_COHORT
CHECKOUT_COHORT = outer.CHECKOUT_COHORT
MANUAL_CHECKOUT_COHORT = outer.MANUAL_CHECKOUT_COHORT
PROFILE_COHORT = outer.PROFILE_COHORT
CART_COHORT = outer.CART_COHORT
STOCK_COHORT = outer.STOCK_COHORT
PRODUCT_COHORT = outer.PRODUCT_COHORT
REFUND_COHORT = outer.REFUND_COHORT
ADDRESS_COHORT = outer.ADDRESS_COHORT
PAYMENT_COHORT = outer.PAYMENT_COHORT
OLDER_ORDERS_COHORT = outer.OLDER_ORDERS_COHORT
CHECKOUT_FENCES_COHORT = outer.CHECKOUT_FENCES_COHORT
TEST = 'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopCommerceBrowserAdmission.js'
CONTRACT = 'tests/secureshopCommerceBrowserAdmission.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
OWNER = 'tests/postgres/run-secureshop-idor-lesson-browser.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
ORIGINAL_TEST_SHA256 = '27ce5db7b3c6613215c11e8ab2fc8b9fb72beaf3e2d0651003cc5a91eea1c638'
PINS = {
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    OWNER: 'cee47b00174cebe77b12719144f458f5ca662b494791824f36d69d2bc88dea41',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
    'tests/postgres/admin_q05_current_host.py': '30775a6b28f3834216bd8d7e3c42b82bb78d55e3e0afd5ee79f2323fa2174e88',
}
# Only reviewed/frozen fixture and shared admission changes may open this path.
RENDERED_PINS = {
    TEST: '27ce5db7b3c6613215c11e8ab2fc8b9fb72beaf3e2d0651003cc5a91eea1c638',
    HELPER: '207862207336fa97f60af3035ef444f1924fca1c846174cc4503d081ed42c033',
    CONTRACT: '3cd9b44ad097f288cbef2b9526505282d07bb644bffca7af4c4de3219e8865ec',
    'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
    'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629',
}
CONTROL_SOURCES = (
    outer.ADAPTER, 'tests/postgres/run_standalone_commerce_with_inspector.py',
    'tests/postgres/test_secureshop_commerce_browser_admission.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tasks/run-in-repository.sh', 'tasks/repository-only.sb',
    'tasks/q05-current-build-receipt.json',
)
RECORD = 'standalone-commerce-browser-birth.json'
ACK = 'standalone-commerce-browser-ack.json'
KIND = 'standalone_commerce_browser'
PROFILE = 'owasp-ai-goat-standalone-commerce-'
FD_ENV = 'SECURESHOP_COMMERCE_ADMISSION_FD'
SESSION_REVOKE_TEST = 'tests/postgres/secureshopStandaloneAccountSessionRevokeRendered.integration.test.js'
SESSION_REVOKE_CASES = 'tests/fixtures/secureshopAccountSessionRevokeRenderedCases.js'
SESSION_REVOKE_CONTRACT = 'tests/secureshopAccountSessionRevokeRendered.test.js'
SESSION_REVOKE_RECEIPT = 'account-current-session-revoke-browser-v2.json'
SESSION_REVOKE_OTHER_RECEIPT = 'account-other-session-revoke-browser-v1.json'
ACCOUNT_AVATAR_RECEIPT = 'account-avatar-browser-v1.json'
CHECKOUT_TEST = 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js'
CHECKOUT_RECEIPT = 'customer-checkout-browser.json'
MANUAL_CHECKOUT_RECEIPT = 'customer-manual-checkout-browser.json'
PROFILE_RECEIPT = 'customer-profile-browser.json'
CART_RECEIPT = 'customer-cart-lifecycle-browser.json'
STOCK_RECEIPT = 'customer-out-of-stock-browser.json'
PRODUCT_RECEIPT = 'customer-product-disambiguation-browser.json'
REFUND_RECEIPT = 'customer-refund-handoff-browser.json'
ADDRESS_RECEIPT = 'customer-address-setup-browser.json'
PAYMENT_RECEIPT = 'customer-payment-setup-browser.json'
OLDER_ORDERS_RECEIPT = 'customer-older-orders-browser.json'
CHECKOUT_FENCES_RECEIPT = 'customer-checkout-fences.json'
EVIDENCE_ENV = 'SECURESHOP_STANDALONE_COMMERCE_EVIDENCE_PATH'
SELECTOR_ENV = 'SECURESHOP_STANDALONE_COMMERCE_NATIVE'


def select_cohort(values):
    global COHORT, TEST, RECORD, ACK, KIND, PROFILE, EVIDENCE_ENV, SELECTOR_ENV, RENDERED_PINS
    if values[values.index('--cohort') + 1] == outer.COHORT:
        return
    if values[values.index('--cohort') + 1] in (CHECKOUT_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT):
        COHORT = values[values.index('--cohort') + 1]
        TEST = CHECKOUT_TEST
        profile = COHORT == PROFILE_COHORT
        cart = COHORT == CART_COHORT
        payment = COHORT == PAYMENT_COHORT
        older = COHORT == OLDER_ORDERS_COHORT
        stock = COHORT == STOCK_COHORT
        product = COHORT == PRODUCT_COHORT
        refund = COHORT == REFUND_COHORT
        address = COHORT == ADDRESS_COHORT
        fences = COHORT == CHECKOUT_FENCES_COHORT
        manual = COHORT == MANUAL_CHECKOUT_COHORT
        stem = 'customer-manual-checkout' if manual else 'customer-out-of-stock' if stock else 'customer-product-details' if product else 'customer-refund-handoff' if refund else 'customer-address-setup' if address else 'customer-older-orders' if older else 'customer-checkout-fences' if fences else 'customer-payment-setup' if payment else 'customer-cart-lifecycle' if cart else 'customer-profile' if profile else 'customer-checkout'
        RECORD = stem + '-browser-birth.json'
        ACK = stem + '-browser-ack.json'
        KIND = stem.replace('-', '_') + '_browser'
        PROFILE = 'owasp-ai-goat-' + stem + '-'
        EVIDENCE_ENV = 'SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_EVIDENCE_PATH' if manual else 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH' if stock else 'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH' if product else 'SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH' if refund else 'SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH' if address else 'SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH' if older else 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH' if fences else 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH' if payment else 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH' if cart else 'SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH' if profile else 'SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH'
        SELECTOR_ENV = 'SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE' if manual else 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE' if stock else 'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE' if product else 'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE' if refund else 'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE' if address else 'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE' if older else 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE' if fences else 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE' if payment else 'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE' if cart else 'SECURESHOP_CUSTOMER_PROFILE_NATIVE' if profile else 'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE'
        RENDERED_PINS = {TEST: '879f06e727c5ec59b80bf75339f2afd814694e91fd6f0331689e42eea3b72c52',
            'tests/fixtures/secureshopManualCheckoutReceiptWitness.js': '8cffb2a31311684b3613a484db0de31f39d6a612ded0003279c7e1d26ef886e1',
            HELPER: '207862207336fa97f60af3035ef444f1924fca1c846174cc4503d081ed42c033',
            CONTRACT: '3cd9b44ad097f288cbef2b9526505282d07bb644bffca7af4c4de3219e8865ec',
            'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
            'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629'}
        return
    if values[values.index('--cohort') + 1] == ACCOUNT_AVATAR_COHORT:
        COHORT = ACCOUNT_AVATAR_COHORT
        TEST = SESSION_REVOKE_TEST
        RECORD = 'account-avatar-browser-birth.json'
        ACK = 'account-avatar-browser-ack.json'
        KIND = 'account_avatar_browser'
        PROFILE = 'owasp-ai-goat-account-avatar-'
        EVIDENCE_ENV = 'SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH'
        SELECTOR_ENV = 'SECURESHOP_ACCOUNT_AVATAR_NATIVE'
        RENDERED_PINS = {TEST: '5301a9d92d67ba1bc9225601a44869679d086dcd82d6d210ad242568891fce65',
            HELPER: '207862207336fa97f60af3035ef444f1924fca1c846174cc4503d081ed42c033',
            CONTRACT: '3cd9b44ad097f288cbef2b9526505282d07bb644bffca7af4c4de3219e8865ec',
            'tests/secureshopAccountAvatarRendered.test.js': '72dddf61498ba44cb9c246a1df29e0b2a59ce724094f72cf6db11c68d7096674',
            SESSION_REVOKE_CASES: 'cc8d8280608a4d8e1a55468e948a1289af92299a419c7fa10a0933df39ce6c08',
            SESSION_REVOKE_CONTRACT: '25be869f8ce41a0f0a44974a9d8dc3419ce626c26644f07d995378b2b64280b6',
            'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
            'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629',
            'tests/postgres/test_secureshop_account_avatar_launcher.py': '4380305a8c1da7dc625baba5caa17bc7782e30339163f9bfea92779d77aefda2'}
        return
    if values[values.index('--cohort') + 1] == SESSION_REVOKE_OTHER_COHORT:
        COHORT = SESSION_REVOKE_OTHER_COHORT
        TEST = SESSION_REVOKE_TEST
        RECORD = 'account-session-revoke-other-browser-birth.json'
        ACK = 'account-session-revoke-other-browser-ack.json'
        KIND = 'account_session_revoke_other_browser'
        PROFILE = 'owasp-ai-goat-standalone-commerce-'
        EVIDENCE_ENV = 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH'
        SELECTOR_ENV = 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE'
        RENDERED_PINS = {TEST: '5301a9d92d67ba1bc9225601a44869679d086dcd82d6d210ad242568891fce65',
            HELPER: '207862207336fa97f60af3035ef444f1924fca1c846174cc4503d081ed42c033',
            CONTRACT: '3cd9b44ad097f288cbef2b9526505282d07bb644bffca7af4c4de3219e8865ec',
            SESSION_REVOKE_CASES: 'cc8d8280608a4d8e1a55468e948a1289af92299a419c7fa10a0933df39ce6c08',
            SESSION_REVOKE_CONTRACT: '25be869f8ce41a0f0a44974a9d8dc3419ce626c26644f07d995378b2b64280b6',
            'tests/secureshopAccountSessionRevokeOtherPhysical.test.js': '4e5636305e79e31bcee9790a87716ee3a3c2df6d46aa3aba36c8540e456dd3ce',
            'tests/postgres/test_q05_other_session_launcher.py': '93c9fdcb32dee945f5e8148b6e2b6c7d9810e08b2837ba42456e4ff3ca576947',
            'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
            'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629'}
        return
    if values[values.index('--cohort') + 1] != SESSION_REVOKE_COHORT:
        raise RuntimeError('Unadmitted commerce browser cohort')
    COHORT = SESSION_REVOKE_COHORT
    TEST = SESSION_REVOKE_TEST
    RECORD = 'account-session-revoke-browser-birth.json'
    ACK = 'account-session-revoke-browser-ack.json'
    KIND = 'account_session_revoke_browser'
    PROFILE = 'owasp-ai-goat-standalone-commerce-'
    EVIDENCE_ENV = 'SECURESHOP_ACCOUNT_SESSION_REVOKE_EVIDENCE_PATH'
    SELECTOR_ENV = 'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE'
    RENDERED_PINS = {TEST: '5301a9d92d67ba1bc9225601a44869679d086dcd82d6d210ad242568891fce65',
        HELPER: '207862207336fa97f60af3035ef444f1924fca1c846174cc4503d081ed42c033',
        CONTRACT: '3cd9b44ad097f288cbef2b9526505282d07bb644bffca7af4c4de3219e8865ec',
        SESSION_REVOKE_CASES: 'cc8d8280608a4d8e1a55468e948a1289af92299a419c7fa10a0933df39ce6c08',
        SESSION_REVOKE_CONTRACT: '25be869f8ce41a0f0a44974a9d8dc3419ce626c26644f07d995378b2b64280b6',
        'tests/fixtures/inheritedFifoGrant.js': '2f5d9bc1b8ec3253404399ddc74e44bddc41c9360c3fc3ed74270fd7e351e4fe',
        'tests/postgres/adminQ05RenderedScenario.js': '215b987ff1410d6987861c762a9f8dfa359f1c9260e969967648e3bddd4cf629'}


def digest(path):
    return safety.sha(path)


def checkout_durable_model_count(shared, owner, terminal):
    return _customer_durable_model_count(shared, owner, terminal, profile=False)


def profile_durable_model_count(shared, owner, terminal, parsed):
    return _customer_durable_model_count(shared, owner, terminal, profile=True,
        model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                   'sha256': parsed.ollama_model_sha256})


def cart_durable_model_count(shared, owner, terminal, parsed):
    return _customer_durable_model_count(shared, owner, terminal, profile=False, cart=True,
        model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                   'sha256': parsed.ollama_model_sha256})


def payment_durable_model_count(shared, owner, terminal, parsed):
    return _customer_durable_model_count(shared, owner, terminal, profile=False, payment=True,
        model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                   'sha256': parsed.ollama_model_sha256})


def older_orders_durable_model_count(shared, owner, terminal, parsed):
    return _customer_durable_model_count(shared, owner, terminal, profile=False, older=True,
        model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                   'sha256': parsed.ollama_model_sha256})


def checkout_fences_durable_model_count(shared, owner, terminal, parsed):
    return _customer_durable_model_count(shared, owner, terminal, profile=False, fences=True,
        model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL,
                   'sha256': parsed.ollama_model_sha256})


def _customer_durable_model_count(shared, owner, terminal, *, profile, cart=False, payment=False, older=False, fences=False, address=False, refund=False, product=False, stock=False, manual=False, model_pin=None):
    # Closed selection only; original MAIN validators own all lesson criteria.
    cohort = shared.CUSTOMER_MANUAL_CHECKOUT_COHORT if manual else shared.CUSTOMER_OUT_OF_STOCK_COHORT if stock else shared.CUSTOMER_PRODUCT_DETAILS_COHORT if product else shared.CUSTOMER_REFUND_HANDOFF_COHORT if refund else shared.CUSTOMER_ADDRESS_SETUP_COHORT if address else shared.CUSTOMER_OLDER_ORDERS_COHORT if older else shared.CUSTOMER_CHECKOUT_FENCES_COHORT if fences else shared.CUSTOMER_PAYMENT_SETUP_COHORT if payment else shared.CUSTOMER_CART_LIFECYCLE_COHORT if cart else shared.CUSTOMER_PROFILE_COHORT if profile else shared.CUSTOMER_CHECKOUT_COHORT
    key = MANUAL_CHECKOUT_COHORT if manual else STOCK_COHORT if stock else PRODUCT_COHORT if product else REFUND_COHORT if refund else ADDRESS_COHORT if address else OLDER_ORDERS_COHORT if older else CHECKOUT_FENCES_COHORT if fences else PAYMENT_COHORT if payment else CART_COHORT if cart else PROFILE_COHORT if profile else CHECKOUT_COHORT
    receipt_key = 'customerManualCheckoutReceipt' if manual else 'customerOutOfStockReceipt' if stock else 'customerProductDetailsReceipt' if product else 'customerRefundHandoffReceipt' if refund else 'customerAddressSetupReceipt' if address else 'customerOlderOrdersReceipt' if older else 'customerCheckoutFencesReceipt' if fences else 'customerPaymentSetupReceipt' if payment else 'customerCartLifecycleReceipt' if cart else 'customerProfileReceipt' if profile else 'customerCheckoutReceipt'
    def exact_json(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)

    evidence = Path(owner.evidence) if owner.evidence is not None else None
    if (evidence is None or not evidence.is_absolute() or evidence.is_symlink()
            or evidence.resolve() != evidence
            or evidence.parent != ROOT / 'tasks/qualification'
            or not evidence.name.startswith('run-')
            or not isinstance(terminal, dict)
            or set(terminal) != {'evidence', 'passed', 'cleanup'}
            or terminal['evidence'] != str(evidence) or terminal['passed'] is not True):
        raise RuntimeError('Exact customer checkout terminal and captured evidence required')
    cleanup = terminal['cleanup']
    if (not isinstance(cleanup, dict)
            or cleanup.get('errors') != []
            or any(cleanup.get(key) is not True for key in (
                'containerNameAbsent', 'containerIdAbsent',
                'browserProcessesAbsent', 'browserProfilesAbsent'))):
        raise RuntimeError('Complete customer checkout cleanup required')
    path = evidence / 'result.json'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 65536):
            raise RuntimeError('Private bounded customer checkout result required')
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
        named = os.stat(path, follow_symlinks=False)
    if (len(raw) != info.st_size or (after.st_dev, after.st_ino, after.st_size) !=
            (info.st_dev, info.st_ino, info.st_size) or
            (named.st_dev, named.st_ino, named.st_size) !=
            (info.st_dev, info.st_ino, info.st_size)):
        raise RuntimeError('Complete customer checkout result bytes required')
    durable = json.loads(raw)
    if (not isinstance(durable, dict)
            or durable.get('cohort') != cohort
            or durable.get('passed') is not True or 'primaryError' not in durable
            or durable['primaryError'] is not None
            or durable.get('sourceCopy') is not False
            or not isinstance(durable.get('testExitCodes'), dict)
            or set(durable['testExitCodes']) != {key}
            or type(durable['testExitCodes'][key]) is not int
            or durable['testExitCodes'][key] != 0
            or exact_json(durable.get('cleanup')) != exact_json(cleanup)):
        raise RuntimeError('Customer checkout terminal and durable result disagree')
    if manual and 'modelPin' in durable:
        raise RuntimeError('Direct manual checkout must not claim model provenance')
    if (profile or cart or payment or older or fences or address or refund or product or stock) and exact_json(durable.get('modelPin')) != exact_json(model_pin):
        raise RuntimeError('Customer model pin disagrees with admitted model')
    receipt_path = evidence / (MANUAL_CHECKOUT_RECEIPT if manual else STOCK_RECEIPT if stock else PRODUCT_RECEIPT if product else REFUND_RECEIPT if refund else ADDRESS_RECEIPT if address else OLDER_ORDERS_RECEIPT if older else CHECKOUT_FENCES_RECEIPT if fences else PAYMENT_RECEIPT if payment else CART_RECEIPT if cart else PROFILE_RECEIPT if profile else CHECKOUT_RECEIPT)
    validator = shared.customer_manual_checkout_receipt if manual else shared.customer_out_of_stock_receipt if stock else shared.customer_product_details_receipt if product else shared.customer_refund_handoff_receipt if refund else shared.customer_address_setup_receipt if address else shared.customer_older_orders_receipt if older else shared.customer_checkout_fences_receipt if fences else shared.customer_payment_setup_receipt if payment else shared.customer_cart_lifecycle_receipt if cart else shared.customer_profile_receipt if profile else shared.customer_checkout_receipt
    validated = validator(receipt_path)
    count = validated.get('actualModelCalls') if isinstance(validated, dict) else None
    lower = 0 if manual else validated['chatTurns'] if (older or fences or cart) else 2 if (payment or profile or address or refund or product or stock) else 1
    upper = 0 if manual else 8 if (stock or product or refund) else 12 if address else 15 if older else 20 if fences else 4 if payment else 10 if profile else 24
    if (type(count) is not int or not lower <= count <= upper
            or exact_json(durable.get(receipt_key)) != exact_json(validated)
            or durable.get(receipt_key + 'Sha256') != digest(receipt_path)):
        raise RuntimeError('Validated customer checkout model count unavailable')
    if refund:
        refund_count = validated.get('refundModelCalls')
        if type(refund_count) is not int or not 2 <= refund_count <= 6:
            raise RuntimeError('Validated separate refund model count unavailable')
        return count, refund_count
    return count


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_pins():
    if not RENDERED_PINS or not {TEST, HELPER, CONTRACT} <= RENDERED_PINS.keys():
        raise RuntimeError('Whole-commerce rendered sources not reviewed/pinned')
    for name, expected in {**PINS, **RENDERED_PINS}.items():
        path = ROOT / name
        if path.is_symlink() or path.resolve() != path or digest(path) != expected:
            raise RuntimeError('Frozen commerce source mismatch: ' + name)


def inventory(shared, parsed):
    build = safety.files(ROOT / 'client/build')
    return dict(files={name: digest(ROOT / name) for name in (
        *PINS, *(RENDERED_PINS or {}), *CONTROL_SOURCES)},
        build=build, buildProvenance=safety.validate_modern_build_receipt(ROOT, parsed),
        originalSource=shared.source_snapshot(ROOT, parsed.node, COHORT,
            browser_root=Path(parsed.browser_root), policy_renderer=parsed.policy_renderer_admission is not None),
        **({"policyRendererAdmission": shared.policy_renderer_admission(parsed, ROOT)} if parsed.policy_renderer_admission is not None else {}),
        executionArguments={key: value for key, value in vars(parsed).items() if key != 'plan'},
        python={'path': str(Path(sys.executable).resolve()), 'sha256': digest(sys.executable),
                'physicalPath': str(safety.physical_python()),
                'physicalSha256': digest(safety.physical_python())})


def arguments(argv):
    values = list(argv)
    if '--plan' in values:
        outer.validate_arguments(values, planning=True)
    else:
        # The fixed coordinator removes --run; retain every other exact byte.
        outer.validate_arguments(['--run', *values])
    if '--expected-snapshot-sha256' in values:
        index = values.index('--expected-snapshot-sha256')
        del values[index:index + 2]
    return [value for value in values if value != '--commerce-test-no-sandbox']


def assert_reviewed_snapshot(argv, before):
    if '--plan' not in argv:
        expected = argv[argv.index('--expected-snapshot-sha256') + 1]
        if safety.encoded(before) != expected:
            raise RuntimeError('Commerce source does not match the reviewed plan')


def syntax_check(parsed):
    subprocess.run([parsed.node, '--check', str(ROOT / TEST)], cwd=ROOT,
        env={'PATH': str(Path(parsed.node).parent)}, check=True,
        capture_output=True, timeout=30)


def install_profile_cleanup(ownership, inspector):
    """Reuse live capture/retirement; remove its exact profile only after absence."""
    capture, retire = ownership.capture_live_v36, ownership.retire_live_v36

    def identity(profile, runtime):
        if runtime.parent.parent != ROOT / 'tasks/qualification' \
                or not runtime.parent.name.startswith('run-') \
                or runtime.name != 'runtime' or profile.parent != runtime / 'tmp' \
                or not profile.name.startswith(PROFILE) or profile.resolve() != profile:
            raise RuntimeError('Exact captured commerce profile required')
        info = profile.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() \
                or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('Private captured commerce profile required')
        return info.st_dev, info.st_ino

    def captured(record, parent_birth, runtime, **kwargs):
        value = capture(record, parent_birth, runtime, **kwargs)
        value.commerce_runtime = Path(runtime)
        value.commerce_profile_identity = identity(Path(value.profile), Path(runtime))
        value.commerce_profile_removed = False
        return value

    def retired(value, **kwargs):
        result = retire(value, **kwargs)
        runtime, profile = value.commerce_runtime, Path(value.profile)
        if inspector.absent(runtime, 'temporary-profiles') is not True:
            raise RuntimeError('Commerce profile process absence unproved')
        if value.commerce_profile_removed:
            if profile.exists() or profile.is_symlink():
                raise RuntimeError('Commerce removed profile reappeared')
            return result
        if identity(profile, runtime) != value.commerce_profile_identity:
            raise RuntimeError('Commerce captured profile was replaced')
        shutil.rmtree(profile)
        if profile.exists() or profile.is_symlink():
            raise RuntimeError('Commerce captured profile removal incomplete')
        value.commerce_profile_removed = True
        return result

    ownership.capture_live_v36, ownership.retire_live_v36 = captured, retired


def direct_command(command, parsed):
    if list(command) != [parsed.node, '--test', '--test-reporter=tap',
                         '--test-concurrency=1', TEST]:
        raise RuntimeError('Closed commerce command changed')
    return [parsed.node, '--test-reporter=tap', TEST]


def owned_environment(environment, parsed, before):
    env = dict(environment)
    evidence = Path(env.get(EVIDENCE_ENV, ''))
    run = evidence.parent
    if env.get(SELECTOR_ENV) != '1' \
            or evidence.name != (SESSION_REVOKE_OTHER_RECEIPT if COHORT == SESSION_REVOKE_OTHER_COHORT
                else SESSION_REVOKE_RECEIPT if COHORT == SESSION_REVOKE_COHORT
                else ACCOUNT_AVATAR_RECEIPT if COHORT == ACCOUNT_AVATAR_COHORT
                else STOCK_RECEIPT if COHORT == STOCK_COHORT
                else PRODUCT_RECEIPT if COHORT == PRODUCT_COHORT
                else REFUND_RECEIPT if COHORT == REFUND_COHORT
                else ADDRESS_RECEIPT if COHORT == ADDRESS_COHORT
                else OLDER_ORDERS_RECEIPT if COHORT == OLDER_ORDERS_COHORT
                else CHECKOUT_FENCES_RECEIPT if COHORT == CHECKOUT_FENCES_COHORT
                else MANUAL_CHECKOUT_RECEIPT if COHORT == MANUAL_CHECKOUT_COHORT
                else PAYMENT_RECEIPT if COHORT == PAYMENT_COHORT
                else CART_RECEIPT if COHORT == CART_COHORT
                else PROFILE_RECEIPT if COHORT == PROFILE_COHORT
                else CHECKOUT_RECEIPT if COHORT == CHECKOUT_COHORT else 'standalone-commerce-browser.json') \
            or run.parent != ROOT / 'tasks/qualification' \
            or not run.name.startswith('run-') \
            or env.get('SECURESHOP_STANDALONE_COMMERCE_POLICY_RENDERER_ADMISSION') != parsed.policy_renderer_admission or (parsed.policy_renderer_admission is not None and COHORT != outer.COHORT):
        raise RuntimeError('Exact whole-commerce owned evidence required; policy renderer not admitted')
    if COHORT in (SESSION_REVOKE_OTHER_COHORT, ACCOUNT_AVATAR_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) and any(
            env.get(key) == '1' for key in (
                'SECURESHOP_STANDALONE_COMMERCE_NATIVE', 'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE',
                'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE',
                'SECURESHOP_ACCOUNT_AVATAR_NATIVE',
                'SECURESHOP_CUSTOMER_CHECKOUT_NATIVE', 'SECURESHOP_CUSTOMER_MANUAL_CHECKOUT_NATIVE', 'SECURESHOP_CUSTOMER_PROFILE_NATIVE',
                'SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE', 'SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE',
                'SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE',
                'SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE', 'SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE',
                'SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE', 'SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE', 'SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE')
            if key != SELECTOR_ENV):
        raise RuntimeError('Exclusive customer browser selector required')
    if env.get('TMPDIR') != str(run / 'runtime/tmp'):
        raise RuntimeError('Exact owned commerce temporary directory required')
    env.update(SECURESHOP_COMMERCE_TEST_NO_SANDBOX='1',
        SECURESHOP_COMMERCE_BROWSER_RECORD_PATH=str(run / RECORD),
        SECURESHOP_COMMERCE_BROWSER_ACK_PATH=str(run / ACK),
        SECURESHOP_COMMERCE_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_COMMERCE_SNAPSHOT_SHA256=safety.encoded(before),
        SECURESHOP_COMMERCE_BUILD_SHA256=safety.encoded(before['build']),
        MAC_CHROMIUM_TMPDIR=str(run / 'runtime/tmp'),
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()))
    return env, run


def verify_outer_boundary(argv, client, *, api=None, denied=safety.sandbox_write_denied):
    api = api or safety.LibProc()
    parent = os.getppid()
    row = api.identity(parent)
    if client is None or client.parent != parent or row is None \
            or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Same-user direct commerce coordinator required')
    original = (row.start_sec, row.start_usec)
    observed = api.arguments(parent)
    if len(observed) < 4 or observed[0] != str(safety.physical_python(api)) \
            or list(observed[1:3]) != ['-B', str(ROOT / 'tests/postgres/run_standalone_commerce_with_inspector.py')] \
            or outer.validate_arguments(list(observed[3:])) != list(argv):
        raise RuntimeError('Exact fixed commerce coordinator invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != original \
            or after.uid != os.getuid() or after.ruid != os.getuid() \
            or not denied('/private/tmp') or denied(ROOT / 'tasks/qualification'):
        raise RuntimeError('Commerce coordinator birth or repository sandbox changed')


def admission_grant(parsed, before, env, pid):
    return dict(version=1, cohort=COHORT, launcherPid=os.getpid(), workerPid=pid,
        nonce=secrets.token_hex(32), workspace=str(ROOT),
        evidencePath=env[EVIDENCE_ENV],
        buildSha256=safety.encoded(before['build']), snapshotSha256=safety.encoded(before),
        outerSandbox='repository-only', chromium=parsed.browser,
        chromiumSha256=parsed.browser_sha256)


class GrantSpawner:
    """One FIFO capability, scoped to the exact direct test process."""
    def __init__(self, original, parsed, before, api=None):
        self.original, self.parsed, self.before = original, parsed, before
        self.api = api

    def __call__(self, command, *args, **kwargs):
        if TEST not in {str(value) for value in command}:
            return self.original(command, *args, **kwargs)
        if list(command) != [self.parsed.node, '--test-reporter=tap', TEST] \
                or kwargs.get('pass_fds') or kwargs.get('start_new_session') is not True:
            raise RuntimeError('Exclusive direct commerce child required')
        read, write = os.pipe()
        child = None
        try:
            env = dict(kwargs['env'])
            if FD_ENV in env:
                raise RuntimeError('Nested commerce grant forbidden')
            env[FD_ENV] = str(read)
            child = self.original(command, *args,
                **{**kwargs, 'env': env, 'close_fds': True, 'pass_fds': (read,)})
            os.close(read)
            read = None
            api = self.api or safety.LibProc()
            row = api.identity(child.pid)
            if row is None or row.ppid != os.getpid() or row.uid != os.getuid() \
                    or row.ruid != os.getuid() or row.pgid != child.pid \
                    or os.getsid(child.pid) != child.pid:
                raise RuntimeError('Commerce child live birth unavailable before grant')
            data = json.dumps(admission_grant(self.parsed, self.before, env, child.pid),
                              separators=(',', ':')).encode()
            if len(data) > 8192 or os.write(write, data) != len(data):
                raise RuntimeError('Complete bounded commerce FIFO required')
            return child
        except BaseException as error:
            if child is None:
                raise
            # Shared main must register the spawned child before cleanup. Do
            # not throw it away after Popen, even if grant delivery failed.
            original_wait = child.wait
            def fail_first_wait(*_args, _error=error, **_kwargs):
                child.wait = original_wait
                raise _error
            child.wait = fail_first_wait
            return child
        finally:
            for descriptor in (read, write):
                if descriptor is not None:
                    os.close(descriptor)


def browser_owner(original, parsed, ownership, before):
    # A private module instance specializes existing tested lifecycle code,
    # not V12's public launcher or its qualification criteria.
    module = load(OWNER, 'commerce_reused_browser_lifecycle')
    module.TEST, module.RECORD, module.ACK, module.KIND = TEST, RECORD, ACK, KIND
    module.direct_command = direct_command
    module.owned_environment = lambda env, options: owned_environment(env, options, before)
    return module.BrowserOwner(GrantSpawner(original, parsed, before), parsed, ownership)


def exact_profile_retirement(record, receipts):
    if type(record) is not dict or type(receipts) is not list or len(receipts) != 1:
        raise RuntimeError('Independent customer profile browser retirement unproved')
    receipt = receipts[0]
    if type(receipt) is not dict or set(receipt) != {'kind', 'pid', 'birth', 'absent'} \
            or receipt['absent'] is not True \
            or type(record.get('kind')) is not str or type(receipt['kind']) is not str \
            or type(record.get('pid')) is not int or type(receipt['pid']) is not int \
            or type(record.get('birth')) is not list or type(receipt['birth']) is not list \
            or len(record['birth']) != 2 or len(receipt['birth']) != 2 \
            or any(type(value) is not int for value in record['birth'] + receipt['birth']) \
            or any(receipt[key] != record[key] for key in ('kind', 'pid', 'birth')):
        raise RuntimeError('Independent customer profile browser retirement unproved')
    return receipts


def run(shared, values, parsed, ownership, before):
    original = shared.subprocess.Popen
    owner = browser_owner(original, parsed, ownership, before)
    output = io.StringIO()
    result = None
    primary = None
    checkout_model_calls = None
    refund_model_calls = None
    shared.subprocess.Popen = owner
    try:
        with contextlib.redirect_stdout(output):
            code = shared.main(values)
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        result = json.loads(lines[-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('Original whole-commerce qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('Independent commerce browser capture incomplete') from owner.error
        if COHORT == CHECKOUT_COHORT:
            checkout_model_calls = checkout_durable_model_count(shared, owner, result)
        elif COHORT == MANUAL_CHECKOUT_COHORT:
            checkout_model_calls = _customer_durable_model_count(shared, owner, result, profile=False, manual=True)
        elif COHORT == PROFILE_COHORT:
            checkout_model_calls = profile_durable_model_count(shared, owner, result, parsed)
        elif COHORT == CART_COHORT:
            checkout_model_calls = cart_durable_model_count(shared, owner, result, parsed)
        elif COHORT == PAYMENT_COHORT:
            checkout_model_calls = payment_durable_model_count(shared, owner, result, parsed)
        elif COHORT == OLDER_ORDERS_COHORT:
            checkout_model_calls = older_orders_durable_model_count(shared, owner, result, parsed)
        elif COHORT == STOCK_COHORT:
            checkout_model_calls = _customer_durable_model_count(shared, owner, result,
                profile=False, stock=True, model_pin={'baseURL': shared.OLLAMA_BASE_URL,
                    'model': shared.OLLAMA_MODEL, 'sha256': parsed.ollama_model_sha256})
        elif COHORT == PRODUCT_COHORT:
            checkout_model_calls = _customer_durable_model_count(shared, owner, result,
                profile=False, product=True, model_pin={'baseURL': shared.OLLAMA_BASE_URL,
                    'model': shared.OLLAMA_MODEL, 'sha256': parsed.ollama_model_sha256})
        elif COHORT == REFUND_COHORT:
            checkout_model_calls, refund_model_calls = _customer_durable_model_count(shared, owner, result,
                profile=False, refund=True, model_pin={'baseURL': shared.OLLAMA_BASE_URL,
                    'model': shared.OLLAMA_MODEL, 'sha256': parsed.ollama_model_sha256})
        elif COHORT == ADDRESS_COHORT:
            checkout_model_calls = _customer_durable_model_count(shared, owner, result, profile=False, address=True,
                model_pin={'baseURL': shared.OLLAMA_BASE_URL, 'model': shared.OLLAMA_MODEL, 'sha256': parsed.ollama_model_sha256})
        elif COHORT == CHECKOUT_FENCES_COHORT:
            checkout_model_calls = checkout_fences_durable_model_count(shared, owner, result, parsed)
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
        if COHORT in (SESSION_REVOKE_OTHER_COHORT, ACCOUNT_AVATAR_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT):
            exact_profile_retirement(owner.captured.record, owner.retired)
        if inventory(shared, parsed) != before:
            raise RuntimeError('Commerce source/build changed')
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        shared.subprocess.Popen = original
        after = None
        inventory_error = None
        try:
            after = inventory(shared, parsed)
        except BaseException as error:
            inventory_error = str(error)[:1000]
        report = dict(version=1, cohort=COHORT, fullOriginalCohort=COHORT == outer.COHORT,
            adapterPassed=primary is None and after == before,
            actualModelCalls=(checkout_model_calls if primary is None and after == before else None)
                if COHORT in (CHECKOUT_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) else 0,
            **({'refundModelCalls': refund_model_calls if primary is None and after == before else None}
               if COHORT == REFUND_COHORT else {}),
            policyRendererIncluded=parsed.policy_renderer_admission is not None, fullQ05Qualification=False, fullQ08Qualification=False,
            sourceBefore=before, sourceAfter=after, sourceUnchanged=after == before,
            inventoryError=inventory_error,
            mainOutputSha256=hashlib.sha256(output.getvalue().encode()).hexdigest(),
            browserCaptured=owner.captured is not None, browserRetirement=owner.retired,
            failure=None if primary is None else str(primary)[:1000],
            captureFailure=None if owner.error is None else str(owner.error)[:1000])
        try:
            if owner.evidence is not None:
                main_result = owner.evidence / 'result.json'
                if main_result.is_file() and not main_result.is_symlink():
                    report['mainResultPath'] = str(main_result)
                    report['mainResultSha256'] = digest(main_result)
                safety.private_json(owner.evidence / 'commerce-adapter-report.json', report)
        except BaseException as error:
            if primary is None:
                raise
            print('Commerce failure report unavailable: ' + type(error).__name__, file=sys.stderr)
        if primary is None:
            if after != before:
                raise RuntimeError('Commerce source/build postflight unproved')
            print(json.dumps(result))


def main(argv=None):
    supplied = list(sys.argv[1:] if argv is None else argv)
    select_cohort(supplied)
    validate_pins()
    values = arguments(supplied)
    shared = load(MAIN, 'commerce_original_launcher')
    if shared.STANDALONE_COMMERCE_TEST != 'tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js' \
            or shared.STANDALONE_COMMERCE_TEST_SHA256 != ORIGINAL_TEST_SHA256:
        raise RuntimeError('Original commerce admission changed')
    if COHORT == outer.COHORT:
        shared.STANDALONE_COMMERCE_TEST_SHA256 = RENDERED_PINS[TEST]
    elif COHORT == SESSION_REVOKE_OTHER_COHORT:
        if shared.SESSION_REVOKE_OTHER_BROWSER != COHORT or shared.SESSION_REVOKE_TEST != TEST \
                or shared.SESSION_REVOKE_TEST_SHA256 != RENDERED_PINS[TEST] \
                or shared.SESSION_REVOKE_OTHER_ASSERTION != 'registered shopper physically revokes OTHER owned session with GET-only recovery':
            raise RuntimeError('Focused OTHER-session revoke admission changed')
    elif COHORT == SESSION_REVOKE_COHORT:
        if shared.SESSION_REVOKE_TEST != TEST or shared.SESSION_REVOKE_TEST_SHA256 != RENDERED_PINS[TEST]:
            raise RuntimeError('Focused account session revoke admission changed')
    elif COHORT == ACCOUNT_AVATAR_COHORT:
        if shared.ACCOUNT_AVATAR_TEST != TEST or shared.ACCOUNT_AVATAR_TEST_SHA256 != RENDERED_PINS[TEST]:
            raise RuntimeError('Focused Account avatar admission changed')
    elif COHORT == MANUAL_CHECKOUT_COHORT:
        if shared.CUSTOMER_MANUAL_CHECKOUT_TEST != TEST or shared.CUSTOMER_MANUAL_CHECKOUT_ASSERTION != 'standalone direct customer checkout physically prepares one quote, explicitly confirms one order, and recovers a lost acknowledgement by exact GET only':
            raise RuntimeError('Manual customer checkout admission changed')
    elif COHORT == PROFILE_COHORT:
        if shared.CUSTOMER_PROFILE_TEST != TEST \
                or shared.CUSTOMER_PROFILE_ASSERTION != 'standalone customer chat prepares and confirms an owned profile update with exact recovery':
            raise RuntimeError('Original customer profile admission changed')
    elif COHORT == CART_COHORT:
        if shared.CUSTOMER_CART_LIFECYCLE_TEST != TEST \
                or shared.CUSTOMER_CART_LIFECYCLE_ASSERTION != 'standalone customer chat prepares, confirms, and exactly recovers bound cart mutations':
            raise RuntimeError('Original customer cart lifecycle admission changed')
    elif COHORT == PAYMENT_COHORT:
        if shared.CUSTOMER_PAYMENT_SETUP_TEST != TEST \
                or shared.CUSTOMER_PAYMENT_SETUP_ASSERTION != 'standalone customer chat opens trusted practice payment setup and exactly recovers one method':
            raise RuntimeError('Original customer payment setup admission changed')
    elif COHORT == STOCK_COHORT:
        if shared.CUSTOMER_OUT_OF_STOCK_TEST != TEST \
                or shared.CUSTOMER_OUT_OF_STOCK_ASSERTION != 'standalone customer chat durably rejects an explicit zero-stock add and recovers the exact saved outcome':
            raise RuntimeError('Original customer stock rejection admission changed')
    elif COHORT == PRODUCT_COHORT:
        if shared.CUSTOMER_PRODUCT_DETAILS_TEST != TEST \
                or shared.CUSTOMER_PRODUCT_DETAILS_ASSERTION != 'standalone customer chat disambiguates similar owned products and reads the physically selected detail':
            raise RuntimeError('Original customer product details admission changed')
    elif COHORT == REFUND_COHORT:
        if shared.CUSTOMER_REFUND_HANDOFF_TEST != TEST \
                or shared.CUSTOMER_REFUND_HANDOFF_ASSERTION != 'standalone customer chat opens trusted refund review and exactly recovers one owned ticket':
            raise RuntimeError('Original customer refund handoff admission changed')
    elif COHORT == ADDRESS_COHORT:
        if shared.CUSTOMER_ADDRESS_SETUP_TEST != TEST \
                or shared.CUSTOMER_ADDRESS_SETUP_ASSERTION != 'standalone customer chat opens trusted address setup and exactly recovers owned address create and edit':
            raise RuntimeError('Original customer address setup admission changed')
    elif COHORT == OLDER_ORDERS_COHORT:
        if shared.CUSTOMER_OLDER_ORDERS_TEST != TEST \
                or shared.CUSTOMER_OLDER_ORDERS_ASSERTION != 'standalone customer chat paginates owned older orders and reads the physically selected detail':
            raise RuntimeError('Original customer older-orders admission changed')
    elif COHORT == CHECKOUT_FENCES_COHORT:
        if shared.CUSTOMER_CHECKOUT_FENCES_TEST != TEST \
                or shared.CUSTOMER_CHECKOUT_FENCES_ASSERTION != 'standalone customer checkout invalidates changed stock and price and recovers one confirmation across two tabs':
            raise RuntimeError('Original customer checkout fences admission changed')
    elif shared.CUSTOMER_CHECKOUT_TEST != TEST \
            or shared.CUSTOMER_CHECKOUT_ASSERTION != 'standalone customer checkout and owned order chat require real model, trusted confirmation, and exact recovery':
        raise RuntimeError('Original customer checkout admission changed')
    parsed = shared.parse(values)
    shared.validate_static(parsed)
    before = inventory(shared, parsed)
    assert_reviewed_snapshot(supplied, before)
    syntax_check(parsed)
    if parsed.plan:
        print(json.dumps(dict(cohort=COHORT, nativeStarted=False, sourceCopy=False,
            existingBuild=True, fullOriginalCohort=COHORT == outer.COHORT, actualModelCalls=0,
            databaseCount=4, roleCount=8, policyRendererIncluded=parsed.policy_renderer_admission is not None,
            fixtureSeconds=150 if COHORT == SESSION_REVOKE_OTHER_COHORT else 300 if COHORT == ACCOUNT_AVATAR_COHORT else 150 if COHORT == SESSION_REVOKE_COHORT else 600 if COHORT in (CHECKOUT_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) else 330,
            workSeconds=150 if COHORT == SESSION_REVOKE_OTHER_COHORT else 300 if COHORT == ACCOUNT_AVATAR_COHORT else 150 if COHORT == SESSION_REVOKE_COHORT else 600 if COHORT in (CHECKOUT_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) else 280,
            launcherSeconds=180 if COHORT == SESSION_REVOKE_OTHER_COHORT else 330 if COHORT == ACCOUNT_AVATAR_COHORT else 180 if COHORT == SESSION_REVOKE_COHORT else 600 if COHORT in (CHECKOUT_COHORT, MANUAL_CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) else 360,
            snapshotSha256=safety.encoded(before),
            buildSha256=safety.encoded(before['build']))))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('Commerce live browser capture requires Darwin')
    inspector = consume_environment()
    verify_outer_boundary(supplied, inspector)
    ownership = load(OWNERSHIP, 'commerce_reused_live_birth')
    ownership.PROFILE_PREFIX = PROFILE
    install_profile_cleanup(ownership, inspector)
    return run(shared, values, parsed, ownership, before)


if __name__ == '__main__':
    raise SystemExit(main())
