#!/usr/bin/env python3
"""V04 database-only full-receipt qualification over the existing owned PG18 lifecycle.

No application configuration or supplied database URL is accepted. The shared
launcher stays byte-for-byte unchanged; only this invocation's suite table is
restricted to two fresh, independently owned review stores.
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
FIXTURE = 'tests/postgres/secureshopSystemRestartFullReceipt.integration.test.js'
FIXTURE_SHA256 = '4700c43b182575162299e35051ec02b6d7cad475cd5ac24fe44be72aa5d7a319'
PINS = {
    'db/postgres/workshop-migrations/secureshop_review/0051_bound_system_restart_full_receipts.sql': '2d142026ea64fb62bbb9b59d7d206478c39769313be1b31d00dfba2ca021a512',
    'server/database/postgres/secureshopSystemRestartRepository.js': '856261d6fa96c05e71f3251f1bc9def558b47e72adbb040a316957f0124623f5',
    'sidecars/sandbox-runner/owned-system/restart-wire.js': '90cdf49371051228e344b62327a7116910115d158fdd647222f0c9d8e1daa0cc',
}
SUITE = 'restart-full-receipt'
PREFIX = 'PG_SECURESHOP_RESTART_FULL_'
STORES = (('FRESH', 'secureshop_review'), ('POPULATED', 'secureshop_review'))
SCOPE = ('review0051 fresh/populated0050/second-run no-op; exact original full v3 receipt TEXT/SHA '
         'and separate streams, atomic completion rollback, SELECT-only runtime child privileges, '
         'immutability, canonical owner-deletion child cascade and sibling preservation; '
         'legacy v2 rows unchanged with no witness backfill; synthetic storage data only, '
         'no command executor, model, Judge, browser or objective-credit proof')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_sources():
    for relative, expected in ((FIXTURE, FIXTURE_SHA256),
                               (str(SHARED.relative_to(ROOT)), SHARED_SHA256), *PINS.items()):
        if sha(ROOT / relative) != expected:
            raise RuntimeError('V04 full-receipt qualification source pin mismatch: ' + relative)


def configure(shared, *, run):
    """Reuse the original resource implementation, never a replacement provisioner."""
    shared.SUITES = {SUITE: (FIXTURE, PREFIX, STORES, 2)}
    shared.arguments = lambda: SimpleNamespace(suite=SUITE, fresh_cohort=None, run=run, plan=not run)
    original_inventory = shared.source_inventory

    def inventory(extra):
        return original_inventory([*extra, Path(__file__).resolve(),
            ROOT / 'tests/postgres/test_secureshop_restart_full_receipt_launcher.py',
            ROOT / 'tests/secureshopSystemRestartFullReceipt.test.js',
            ROOT / 'sidecars/sandbox-runner/owned-system/restart-contract.js',
            *(ROOT / relative for relative in PINS)])
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
            'fixtureSha256': FIXTURE_SHA256, 'runtimePins': PINS,
            'sharedLauncherSha256': SHARED_SHA256, 'stores': STORES,
            'expectedTests': 2, 'sourceCopies': False, 'actualModel': False,
            'qualificationScope': SCOPE, 'allocationStarted': False}))
        return 0
    spec = importlib.util.spec_from_file_location('restart_full_receipt_owned_persona_launcher', SHARED)
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    return configure(shared, run=True).main()


if __name__ == '__main__':
    sys.exit(main())
