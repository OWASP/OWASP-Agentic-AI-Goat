"""Controlled receipt mutations only; these tests provide no native evidence."""

import copy
import unittest

from secureshop_customer_pre_admission_receipt import (
    DENIALS, FAMILIES, validate_customer_pre_admission,
)


def receipt():
    return {'version': 1, 'scope': 'current-customer-http-before-provider-or-effect',
            'compatibility': [
                {'family': family, 'operationId': f'{index:08x}-0000-4000-8000-000000000001',
                 'confirmedStatus': 'declined' if family == 'checkout' else 'completed',
                 'savedStatus': 'completed', 'replayStatus': 200}
                for index, family in enumerate(FAMILIES[:-1], 1)],
            'denials': [
                {'family': family, 'denial': denial,
                 'status': 403 if denial == 'wrong_role' else
                    (200 if family == 'refund' else 503)
                    if denial in ('foreign_tenant', 'stale_generation') else 401,
                 'beforeSha256': 'a' * 64, 'afterSha256': 'a' * 64, 'providerCalls': 20}
                for family in FAMILIES for denial in DENIALS],
            'refund': {'sessionPrepared': True, 'dispatch': 'not-invoked'}}


class CustomerPreAdmissionReceiptTests(unittest.TestCase):
    def validate(self, value):
        return validate_customer_pre_admission(value, expected_provider_calls=20)

    def test_exact_receipt_is_unchanged_and_order_independent(self):
        value = receipt()
        before = copy.deepcopy(value)
        self.assertEqual(self.validate(value), before)
        self.assertEqual(value, before)
        value['compatibility'].reverse()
        value['denials'].reverse()
        self.validate(value)

    def test_every_record_is_closed_and_required(self):
        for path in ((), ('compatibility', 0), ('denials', 0), ('refund',)):
            original = receipt()
            node = original
            for key in path:
                node = node[key]
            for key in tuple(node) + ('injected',):
                with self.subTest(path=path, key=key):
                    value = copy.deepcopy(original)
                    target = value
                    for part in path:
                        target = target[part]
                    if key == 'injected':
                        target[key] = True
                    else:
                        del target[key]
                    with self.assertRaises(RuntimeError):
                        self.validate(value)

    def test_counts_pairs_and_families_are_exact(self):
        for collection in ('compatibility', 'denials'):
            for mutation in ('missing', 'duplicate', 'extra', 'foreign'):
                with self.subTest(collection=collection, mutation=mutation):
                    value = receipt()
                    rows = value[collection]
                    if mutation == 'missing': rows.pop()
                    elif mutation == 'extra': rows.append(copy.deepcopy(rows[0]))
                    elif mutation == 'duplicate': rows[-1] = copy.deepcopy(rows[0])
                    else: rows[0]['family'] = 'not-a-terminal'
                    with self.assertRaises(RuntimeError): self.validate(value)

    def test_compatibility_requires_exact_operation_and_terminal_status(self):
        changes = [('operationId', 'x' * 36), ('operationId', '00000000-0000-0000-0000-000000000000'),
                   ('confirmedStatus', 'prepared'), ('savedStatus', 'unconfirmed'),
                   ('replayStatus', True), ('replayStatus', 202)]
        for key, invalid in changes:
            value = receipt(); value['compatibility'][0][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(RuntimeError): self.validate(value)
        value = receipt(); value['compatibility'][1]['operationId'] = value['compatibility'][0]['operationId']
        with self.assertRaises(RuntimeError): self.validate(value)
        value = receipt(); value['compatibility'][3]['confirmedStatus'] = 'approved'
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_each_denial_requires_its_exact_status(self):
        for index in range(30):
            value = receipt(); value['denials'][index]['status'] = 404
            with self.subTest(index=index), self.assertRaises(RuntimeError): self.validate(value)
        value = receipt(); value['denials'][-4]['status'] = 503  # refund's foreign SSE is 200
        with self.assertRaises(RuntimeError): self.validate(value)
        for family in FAMILIES:
            value = receipt()
            stale = next(row for row in value['denials']
                         if row['family'] == family and row['denial'] == 'stale_generation')
            stale['status'] = 401
            with self.subTest(family=family, denial='stale_generation'), self.assertRaises(RuntimeError):
                self.validate(value)

    def test_snapshot_provider_and_identity_mutations_fail(self):
        for key, invalid in [('beforeSha256', 'A' * 64), ('afterSha256', 'b' * 64),
                             ('providerCalls', 19), ('providerCalls', 21), ('providerCalls', True),
                             ('denial', 'platform_token_substitution'), ('family', []), ('status', True)]:
            value = receipt(); value['denials'][0][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(RuntimeError): self.validate(value)

    def test_scope_and_refund_cannot_claim_extra_execution(self):
        for key, invalid in [('version', True), ('version', 2), ('scope', 'full-Q07')]:
            value = receipt(); value[key] = invalid
            with self.assertRaises(RuntimeError): self.validate(value)
        for key, invalid in [('sessionPrepared', 1), ('sessionPrepared', False), ('dispatch', 'completed')]:
            value = receipt(); value['refund'][key] = invalid
            with self.assertRaises(RuntimeError): self.validate(value)

    def test_parent_provider_count_is_typed_and_bounded(self):
        for calls in (True, 0, -1, 101, '20', None):
            with self.subTest(calls=calls), self.assertRaises(RuntimeError):
                validate_customer_pre_admission(receipt(), expected_provider_calls=calls)


if __name__ == '__main__':
    unittest.main()
