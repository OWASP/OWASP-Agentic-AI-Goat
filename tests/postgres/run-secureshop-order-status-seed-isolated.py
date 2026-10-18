#!/usr/bin/env python3
"""V50 database-only seed qualification over the existing owned PG18 lifecycle.

No application configuration or supplied database URL is accepted. The shared
launcher stays byte-for-byte unchanged; only this invocation's suite table is
restricted to two fresh, independently owned identity stores.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'tests/postgres/run-persona-transition-main-isolated.py'
SHARED_SHA256 = 'f7a32c72699cad35f9d92afd4a55fbf1d3f84a7397f88143c4060ccfb00554e7'
FIXTURE = 'tests/postgres/secureshopOrderStatusAssessmentSeed.integration.test.js'
FIXTURE_SHA256 = '1095e48270e01c3d2bb16b4bb07ec58388d5343b45f6f52cf5cb6ff4e7ae3608'
SEED = 'server/database/postgres/secureshopAssessmentSeed.js'
SEED_SHA256 = 'c6cdc7646b1e3e9ae99e3225f8e463bc3578d8fb6aa340cfef234ed602711639'
SUITE = 'order-status-seed'
PREFIX = 'PG_SECURESHOP_ORDER_STATUS_SEED_'
STORES = (('FRESH', 'identity'), ('POPULATED', 'identity'))
SCOPE = ('V50 exact pending order-status checked-in seed predecessor to native-model; fresh disabled default, '
         'populated enabled/catalog/label/timestamp and two-tenant configuration/history preservation, '
         'instructor/unknown digest/altered document/other mechanism nonmatches, actual administrator '
         'pending denial then qualification-based enable, and exact no-op; no model, Judge or credit')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_sources():
    for relative, expected in ((FIXTURE, FIXTURE_SHA256), (SEED, SEED_SHA256),
                               (str(SHARED.relative_to(ROOT)), SHARED_SHA256)):
        if sha(ROOT / relative) != expected:
            raise RuntimeError('V50 seed qualification source pin mismatch: ' + relative)


def configure(shared, *, run):
    """Reuse the original resource implementation, never a replacement provisioner."""
    shared.SUITES = {SUITE: (FIXTURE, PREFIX, STORES, 2)}
    shared.arguments = lambda: SimpleNamespace(suite=SUITE, fresh_cohort=None, run=run, plan=not run)
    original_inventory = shared.source_inventory

    def inventory(extra):
        return original_inventory([*extra, Path(__file__).resolve(),
            ROOT / 'tests/postgres/test_secureshop_order_status_seed_launcher.py',
            ROOT / 'tests/secureshopOrderStatusAssessmentSeedTransition.test.js'])
    shared.source_inventory = inventory
    return shared


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true')
    modes.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    validate_sources()
    if not args.run:
        print(json.dumps({'plan': True, 'suite': SUITE, 'fixture': FIXTURE,
            'fixtureSha256': FIXTURE_SHA256, 'seedSha256': SEED_SHA256,
            'sharedLauncherSha256': SHARED_SHA256, 'stores': STORES,
            'expectedTests': 2, 'sourceCopies': False, 'actualModel': False,
            'qualificationScope': SCOPE, 'allocationStarted': False}))
        return 0
    spec = importlib.util.spec_from_file_location('order_status_seed_owned_persona_launcher', SHARED)
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    return configure(shared, run=True).main()


if __name__ == '__main__':
    sys.exit(main())
