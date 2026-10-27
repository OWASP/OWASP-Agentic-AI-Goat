"""Pricing private-topology consumer. Public admission remains closed.

Reuses the original four-store producer, canonical cohort script and replay;
does not pretend a private daemon container exists on the shared daemon.
"""
import importlib.util
import json
import hashlib
import os
import stat
from pathlib import Path
import time

LIVE_ENABLED = False
ROOT = Path(__file__).resolve().parents[2]


def original():
    path = ROOT / 'tests/postgres/run-secureshop-customer-pricing-current-host.py'
    spec = importlib.util.spec_from_file_location('pricing_original_cohort_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*_args, **_kwargs):
    raise RuntimeError('PRICING_PRIVATE_COHORT_NOT_ADMITTED')


def private_store_class(producer, private):
    class PrivateStores(producer.CurrentHostRuntime):
        def verify_executor_identity(self):
            if private.descriptor is None or any(private.descriptor.get(key) != value
                    for key, value in self.identity.items()) or private.verify_current() is not True:
                raise RuntimeError('PRICING_PRIVATE_IDENTITY_CHANGED')
    return PrivateStores


def _consume(private, run_directory, image_id, nonce, journal, deadline, snapshot, *, clock=time.monotonic, retirement_budget=None, source_variant='original'):
    """Internal lifecycle body; doubles exercise ordering, never live admission.

    The outside authenticated owner must retain its builder until this method's
    positive retirement receipt. A thrown error carries all observed debt.
    """
    if source_variant not in ('original', 'owned-deal-name-verification-directive-v1'):
        raise RuntimeError('V33_SOURCE_VARIANT_DENIED')
    producer = original()
    run_directory = Path(run_directory)
    if (not run_directory.is_relative_to(ROOT/'tasks/qualification')
            or run_directory.resolve() != run_directory
            or run_directory.is_symlink()
            or stat.S_IMODE(run_directory.stat().st_mode) != 0o700
            or run_directory.stat().st_uid != os.getuid()
            or producer.full_snapshot() != snapshot):
        raise RuntimeError('PRICING_PRIVATE_COHORT_SOURCE')
    if not 0 < deadline-clock() <= 600:
        raise RuntimeError('PRICING_ORIGINAL_COHORT_BUDGET')
    result = dict(version=1, target='original-v33-pricing-private-consumer-v1',
                  passed=False, nativeQualificationAccepted=False,
                  builderReleaseAllowed=False, cleanupErrors=[])
    pg = child = stores = None
    primary = None

    def current():
        if clock() >= deadline:
            raise RuntimeError('PRICING_ORIGINAL_COHORT_EXPIRED')

    try:
        current()
        descriptor = private.open(image_id)
        # Original capability handshake is also performed by private.open.
        # The Node producer still validates the exact private descriptor bytes.
        expected = {key: descriptor[key] for key in producer.IDENTITY_KEYS}
        producer.validate_descriptor(descriptor, expected)
        raw = (json.dumps(descriptor, sort_keys=True)+'\n').encode()
        if len(raw) > 65536:
            raise RuntimeError('PRICING_DESCRIPTOR_SIZE')
        descriptor_path = run_directory/'private-executor.json'
        fd = os.open(descriptor_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        try:
            at = 0
            while at < len(raw):
                count = os.write(fd, raw[at:])
                if count <= 0:
                    raise RuntimeError('PRICING_DESCRIPTOR_WRITE')
                at += count
            os.fsync(fd)
        finally:
            os.close(fd)
        stores = private_store_class(producer, private)(run_directory, descriptor_path,
            hashlib.sha256(raw).hexdigest(), expected, deadline, snapshot=snapshot)
        stores.source_variant = source_variant
        stores.assert_executor_ready(descriptor)
        current()
        pg = stores.open_postgres(nonce)
        pairs = {}
        for store in producer.STORES:
            current()
            pair = producer.database_pair(nonce, store, pg['port'])
            if stores.create_store(pg, nonce, store) != pair:
                raise RuntimeError('PRICING_ORIGINAL_STORE_RESULT')
            pairs[store] = pair
        current()
        child = stores.start_child(pairs, descriptor, producer.LIMITS.copy())
        receipt = stores.wait_child(child, deadline)
        stores.verify_receipt(receipt)
        current()
        result['passed'] = True
    except BaseException as error:
        primary = error
        result['errorType'] = type(error).__name__
    finally:
        budget_ready = True
        if retirement_budget is not None:
            try:
                cleanup_deadline = retirement_budget.begin_retirement()
                private.set_cleanup_deadline(cleanup_deadline)
                if stores is not None:
                    stores.set_cleanup_deadline(cleanup_deadline)
            except BaseException as error:
                budget_ready = False
                result['passed'] = False
                result['cleanupErrors'].append('cleanup-budget')
                if primary is None:
                    primary = error
        child_retired = stores is None
        try:
            if not budget_ready:
                raise RuntimeError('PRICING_CLEANUP_BUDGET_UNPROVEN')
            if stores is not None:
                child_retired = stores.close_child(child) is True
            if not child_retired:
                raise RuntimeError('PRICING_CHILD_RETIREMENT_UNPROVEN')
        except BaseException:
            child_retired = False
            result['cleanupErrors'].append('child')
        if child_retired:
            try:
                if stores is not None and stores.close_postgres(pg) is not True:
                    raise RuntimeError('PRICING_POSTGRES_RETIREMENT_UNPROVEN')
            except BaseException:
                result['cleanupErrors'].append('postgres')
            try:
                retired = private.close()
                if retired.get('builderReleaseAllowed') is not True:
                    raise RuntimeError('PRICING_RUNTIME_RETIREMENT_UNPROVEN')
                result['builderReleaseAllowed'] = True
                if retired.get('bridge', {}).get('failures'):
                    raise RuntimeError('PRICING_PRIVATE_TRANSPORT_FAILED')
            except BaseException:
                result['cleanupErrors'].append('private-runtime')
        else:
            result['cleanupErrors'].extend(['postgres:retained', 'private-runtime:retained'])
        result['passed'] = result['passed'] and not result['cleanupErrors']
        def interrupted():
            nonlocal primary
            if stores is not None and stores.cleanup_interrupted():
                result['passed'] = False
                result['cleanupInterrupted'] = True
                if primary is None:
                    primary = RuntimeError('PRICING_CLEANUP_INTERRUPTED')
                return True
            return False
        try:
            interrupted()
            journal(json.loads(json.dumps(result)))
            if interrupted():
                journal(json.loads(json.dumps(result)))
        except BaseException as error:
            result['passed'] = False
            result['cleanupErrors'].append('journal')
            if primary is None:
                primary = error
        finally:
            try:
                if stores is not None:
                    stores.finalize_cleanup()
            except BaseException as error:
                result['passed'] = False
                result['cleanupErrors'].append('signal-restoration')
                if primary is None:
                    primary = error
            try:
                if interrupted() or 'signal-restoration' in result['cleanupErrors']:
                    journal(json.loads(json.dumps(result)))
            except BaseException as error:
                result['passed'] = False
                if primary is None:
                    primary = error
                else:
                    primary.terminalJournalError = type(error).__name__
    if primary is not None or result['cleanupErrors']:
        error = primary or RuntimeError('PRICING_PRIVATE_COHORT_CLEANUP')
        error.result = result
        raise error
    return result
