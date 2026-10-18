#!/usr/bin/env python3
"""Closed selector and receipt checks for D16's current-main launcher cohort."""

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
    'secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class McpTrustStandaloneLauncherContract(unittest.TestCase):
    def write_private_json(self, target, value):
        target.write_text(json.dumps(value))
        os.chmod(target, 0o600)

    def test_exact_selector_fixture_and_frozen_digest(self):
        self.assertIn(LAUNCHER.D16_COHORT,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertIn(LAUNCHER.D16_COHORT, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(LAUNCHER.D16_COHORT, LAUNCHER.STANDALONE_BROWSER_COHORTS)
        self.assertEqual(LAUNCHER.D16_TEST,
                         'tests/postgres/secureshopOwnedMcpRegistryRendered.native.js')
        self.assertEqual(LAUNCHER.digest(HERE.parent.parent / LAUNCHER.D16_TEST),
                         LAUNCHER.D16_TEST_SHA256)

    def test_plan_requires_browser_for_d16(self):
        self.assertTrue(LAUNCHER.plan_requires_browser(LAUNCHER.D16_COHORT))
        self.assertTrue(LAUNCHER.plan_requires_browser('standalone-commerce-browser'))
        self.assertFalse(LAUNCHER.plan_requires_browser('transport'))

    def test_d16_requires_one_exact_tap_and_terminal_actual_wire(self):
        title = LAUNCHER.D16_ASSERTION
        valid = f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(LAUNCHER.complete_tap_counts(valid, LAUNCHER.D16_COHORT, [title])['tests'], 1)
        with self.assertRaises(RuntimeError):
            LAUNCHER.complete_tap_counts(valid.replace('# skipped 0', '# skipped 1'),
                                         LAUNCHER.D16_COHORT, [title])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            status = root / 'mcp-trust-standalone-rendered.json'
            wire_dir = root / 'mcp-trust-wire'
            wire_dir.mkdir(mode=0o700)
            wire = wire_dir / 'wire.json'
            self.write_private_json(status, {
                'status': 'passed', 'scope': 'D16-standalone',
                **{name: True for name in LAUNCHER.D16_STATUS_FLAGS},
                'cleanupErrors': [], 'actorCalls': 3, 'judgeCalls': 2,
            })
            self.write_private_json(wire, {
                'version': 'mcp-trust-actual-wire-v1', 'closed': True,
                'failed': False, 'physicalPending': 0,
                'externalAttempts': 6, 'counts': {'tags': 1, 'actor': 3, 'judge': 2},
                'calls': [{'role': 'tags', 'status': 'returned'},
                          *[{'role': 'actor', 'status': 'returned'} for _ in range(3)],
                          *[{'role': 'judge', 'status': 'returned'} for _ in range(2)]],
            })
            self.assertEqual(LAUNCHER.d16_receipt(status, wire)['status'], 'passed')


if __name__ == '__main__':
    unittest.main()
