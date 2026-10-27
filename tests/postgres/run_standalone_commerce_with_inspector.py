#!/usr/bin/env python3
"""Closed whole-commerce selection over the existing read-only inspector loop."""
import importlib.util
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'standalone-commerce-browser'
SESSION_REVOKE_COHORT = 'account-session-revoke-browser'
SESSION_REVOKE_OTHER_COHORT = 'account-session-revoke-other-browser'
ACCOUNT_AVATAR_COHORT = 'account-avatar-browser'
CHECKOUT_COHORT = 'customer-checkout-browser'
PROFILE_COHORT = 'customer-profile-browser'
CART_COHORT = 'customer-cart-lifecycle-browser'
STOCK_COHORT = 'customer-out-of-stock-browser'
PRODUCT_COHORT = 'customer-product-disambiguation-browser'
REFUND_COHORT = 'customer-refund-handoff-browser'
ADDRESS_COHORT = 'customer-address-setup-browser'
PAYMENT_COHORT = 'customer-payment-setup-browser'
OLDER_ORDERS_COHORT = 'customer-older-orders-browser'
CHECKOUT_FENCES_COHORT = 'customer-checkout-fences'
MANUAL_CHECKOUT_COHORT = 'customer-manual-checkout-browser'
POLICY_FLAGS = {'--policy-renderer-admission', '--policy-renderer-admission-sha256'}
REQUIRED = frozenset(('--main-workspace', '--node', '--node-sha256', '--docker',
    '--docker-sha256', '--docker-host', '--docker-daemon', '--image-id',
    '--current-host-profile', '--cohort', '--browser', '--browser-sha256',
    '--browser-root', '--evidence-parent', '--build-report',
    '--build-report-sha256', '--build-input-sha256', '--build-output-sha256',
    '--build-recorder-sha256'))
CHECKOUT_MODEL_PIN = '--ollama-model-sha256'
ADAPTER = 'tests/postgres/run-secureshop-standalone-commerce-browser.py'


def validate_arguments(arguments, *, planning=False):
    values, flags = {}, set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--plan', '--commerce-test-no-sandbox'):
            if key in flags:
                raise RuntimeError('Duplicate commerce flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED | POLICY_FLAGS | {CHECKOUT_MODEL_PIN, '--expected-snapshot-sha256'}:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing commerce argument')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only closed whole-commerce arguments permitted')
    expected = {'--plan' if planning else '--run', '--commerce-test-no-sandbox'}
    required = REQUIRED | ({CHECKOUT_MODEL_PIN} if values.get('--cohort') in (CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) else set())
    if set(values) & POLICY_FLAGS:
        if not POLICY_FLAGS <= set(values) or values.get('--cohort') != COHORT:
            raise RuntimeError('Policy renderer exclusive to whole commerce')
        if values['--policy-renderer-admission'] != str(ROOT / 'tasks/qualification/commerce-policy-renderer/admission.json') or not re.fullmatch(r'[a-f0-9]{64}', values['--policy-renderer-admission-sha256']):
            raise RuntimeError('Exact repository policy renderer admission required')
        required = required | POLICY_FLAGS
    if not planning:
        required = required | {'--expected-snapshot-sha256'}
    if flags != expected or set(values) != required or values['--cohort'] not in (COHORT, SESSION_REVOKE_COHORT, SESSION_REVOKE_OTHER_COHORT, ACCOUNT_AVATAR_COHORT, CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT, MANUAL_CHECKOUT_COHORT) \
            or values['--main-workspace'] != str(ROOT) \
            or values['--evidence-parent'] != str(ROOT / 'tasks/qualification'):
        raise RuntimeError('Exact current-source whole-commerce selection required')
    if not planning and not re.fullmatch(r'[a-f0-9]{64}', values['--expected-snapshot-sha256']):
        raise RuntimeError('Exact reviewed commerce snapshot digest required')
    for key in ('--build-report-sha256', '--build-input-sha256',
                '--build-output-sha256', '--build-recorder-sha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', values[key]):
            raise RuntimeError('Exact qualified commerce build provenance pins required')
    if values['--cohort'] in (CHECKOUT_COHORT, PROFILE_COHORT, CART_COHORT, PAYMENT_COHORT, STOCK_COHORT, PRODUCT_COHORT, REFUND_COHORT, ADDRESS_COHORT, OLDER_ORDERS_COHORT, CHECKOUT_FENCES_COHORT) and not re.fullmatch(r'[a-f0-9]{64}', values[CHECKOUT_MODEL_PIN]):
        raise RuntimeError('Exact checkout model provenance pin required')
    return [value for value in arguments if value != '--run']


def child_command(arguments):
    forwarded = validate_arguments(arguments)
    wrapper, adapter = ROOT / 'tasks/run-in-repository.sh', ROOT / ADAPTER
    for path in (wrapper, adapter):
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Fixed commerce entrypoint unavailable')
    return ['/bin/bash', str(wrapper), sys.executable, '-B', str(adapter), *forwarded]


def coordinate(arguments):
    path = ROOT / 'tests/postgres/run_audit_collection_with_inspector.py'
    spec = importlib.util.spec_from_file_location('commerce_fixed_inspector_loop', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.child_command = child_command
    return module.coordinate(arguments)


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
