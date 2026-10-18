#!/usr/bin/env python3
"""Resource-free receipt and selector checks for focused A11 qualification."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_route_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


def valid_receipt():
    return {'scope': LAUNCHER.ROUTE_AVAILABILITY_SCOPE,
            **{name: True for name in LAUNCHER.ROUTE_AVAILABILITY_FLAGS},
            'legacyFallbackHits': 0, 'browserCloseVerified': True,
            'profileRemoved': True, 'profilePreserved': False}


class RouteAvailabilityLauncherContract(unittest.TestCase):
    def test_exact_selector_fixture_and_browser_plan(self):
        self.assertIn(LAUNCHER.ROUTE_AVAILABILITY_COHORT,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertIn(LAUNCHER.ROUTE_AVAILABILITY_COHORT,
                      LAUNCHER.STANDALONE_BROWSER_COHORTS)
        self.assertNotIn(LAUNCHER.ROUTE_AVAILABILITY_COHORT,
                         LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertTrue(LAUNCHER.plan_requires_browser(LAUNCHER.ROUTE_AVAILABILITY_COHORT))
        self.assertEqual(LAUNCHER.digest(HERE.parent.parent / LAUNCHER.ROUTE_AVAILABILITY_TEST),
                         LAUNCHER.ROUTE_AVAILABILITY_TEST_SHA256)

    def test_all_controlled_and_rendered_taps_required(self):
        names = [LAUNCHER.ROUTE_AVAILABILITY_CLEANUP_ASSERTION,
                 LAUNCHER.ROUTE_AVAILABILITY_BODY_ASSERTION,
                 LAUNCHER.ROUTE_AVAILABILITY_IDENTITY_ASSERTION,
                 LAUNCHER.ROUTE_AVAILABILITY_ASSERTION]
        content = ('TAP version 13\n'
                   + ''.join(f'# Subtest: {name}\nok {index} - {name}\n'
                             for index, name in enumerate(names, 1))
                   + '# tests 4\n# pass 4\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(content, 'route', names)['tests'], 4)
        for changed in (content.replace('# skipped 0', '# skipped 1'),
                        content.replace(f'ok 2 - {names[1]}', 'not ok 2 - missing'),
                        content.replace(names[1], 'wrong name')):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                LAUNCHER.complete_tap_counts(changed, 'route', names)

    def test_private_closed_success_and_negative_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'receipt.json'

            def check(value):
                target.write_text(json.dumps(value))
                os.chmod(target, 0o600)
                return LAUNCHER.route_availability_receipt(target)

            good = valid_receipt()
            self.assertEqual(check(good), good)
            changes = [lambda row: row.update(ownerRendered=False),
                       lambda row: row.update(disabledListings503=1),
                       lambda row: row.update(legacyFallbackHits=True),
                       lambda row: row.update(browserCloseVerified=False),
                       lambda row: row.update(profileRemoved=False),
                       lambda row: row.update(profilePreserved=True),
                       lambda row: row.update(failure={'name': 'Error', 'code': None}),
                       lambda row: row.update(scope='other')]
            for index, change in enumerate(changes):
                receipt = valid_receipt()
                change(receipt)
                with self.subTest(index=index), self.assertRaises(RuntimeError):
                    check(receipt)
            check(good)
            os.chmod(target, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.route_availability_receipt(target)


if __name__ == '__main__':
    unittest.main()
