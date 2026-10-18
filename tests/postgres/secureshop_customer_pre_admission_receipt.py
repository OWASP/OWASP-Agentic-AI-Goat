"""Closed additive Q07 customer HTTP receipt; no resource or model execution."""

import re


FAMILIES = ('cart', 'address', 'payment', 'checkout', 'profile', 'refund')
DENIALS = ('wrong_role', 'foreign_tenant', 'revoked_persona_session',
           'stale_generation', 'platform_launch_substitution')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
_SHA = re.compile(r'[0-9a-f]{64}')


def _exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def validate_customer_pre_admission(value, *, expected_provider_calls):
    """Validate the parsed subreceipt after the launcher's bounded TAP parse.

    The enclosing validator must still verify its original five positives,
    thirty denials, model provenance, zero credit and authenticated reset.
    Provider counts are cumulative; they equal the already-validated final
    controlled role count because this added slice never dispatches a provider.
    """
    if (type(expected_provider_calls) is not int or not 1 <= expected_provider_calls <= 100
            or not _exact(value, ('version', 'scope', 'compatibility', 'denials', 'refund'))
            or type(value['version']) is not int or value['version'] != 1
            or value['scope'] != 'current-customer-http-before-provider-or-effect'):
        raise RuntimeError('Exact customer pre-admission scope required')
    rows = value['compatibility']
    if type(rows) is not list or len(rows) != 5:
        raise RuntimeError('Five current customer owner compatibility receipts required')
    families, operations = set(), set()
    for row in rows:
        if (not _exact(row, ('family', 'operationId', 'confirmedStatus', 'savedStatus', 'replayStatus'))
                or type(row['family']) is not str or row['family'] not in FAMILIES[:-1]
                or row['family'] in families or not _matches(_UUID, row['operationId'])
                or row['operationId'] in operations
                or row['confirmedStatus'] != ('declined' if row['family'] == 'checkout' else 'completed')
                or row['savedStatus'] != 'completed'
                or type(row['replayStatus']) is not int or row['replayStatus'] != 200):
            raise RuntimeError('Exact owner confirmation, saved receipt and replay required')
        families.add(row['family'])
        operations.add(row['operationId'])
    if families != set(FAMILIES[:-1]):
        raise RuntimeError('All five customer compatibility families required')
    rows = value['denials']
    if type(rows) is not list or len(rows) != 30:
        raise RuntimeError('Thirty customer pre-admission denials required')
    pairs = set()
    for row in rows:
        if (not _exact(row, ('family', 'denial', 'status', 'beforeSha256', 'afterSha256', 'providerCalls'))
                or type(row['family']) is not str or row['family'] not in FAMILIES
                or type(row['denial']) is not str or row['denial'] not in DENIALS):
            raise RuntimeError('Exact customer denial identity required')
        pair = (row['family'], row['denial'])
        expected_status = (403 if row['denial'] == 'wrong_role' else
                           (200 if row['family'] == 'refund' else 503)
                           if row['denial'] in ('foreign_tenant', 'stale_generation') else 401)
        if (pair in pairs or type(row['status']) is not int or row['status'] != expected_status
                or not _matches(_SHA, row['beforeSha256'])
                or row['afterSha256'] != row['beforeSha256']
                or type(row['providerCalls']) is not int
                or row['providerCalls'] != expected_provider_calls):
            raise RuntimeError('Exact no-effect, no-provider customer denial required')
        pairs.add(pair)
    if pairs != {(family, denial) for family in FAMILIES for denial in DENIALS}:
        raise RuntimeError('Complete customer pre-admission denial cross-product required')
    refund = value['refund']
    if (not _exact(refund, ('sessionPrepared', 'dispatch'))
            or refund['sessionPrepared'] is not True or refund['dispatch'] != 'not-invoked'):
        raise RuntimeError('Refund scope must remain session-only without dispatch')
    return value
