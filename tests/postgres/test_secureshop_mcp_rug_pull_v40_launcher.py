#!/usr/bin/env python3
"""Resource-free V40 launcher admission checks; no actual qualification claim."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_v40_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class McpRugPullFixedLauncherContract(unittest.TestCase):
    def write_private(self, path, value):
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)

    def test_distinct_opt_in_reuses_exact_d16_fixture_and_pins_v40_sources(self):
        self.assertIn(LAUNCHER.D16_V40_COHORT,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertTrue(LAUNCHER.plan_requires_browser(LAUNCHER.D16_V40_COHORT))
        self.assertEqual(LAUNCHER.digest(HERE.parent.parent / LAUNCHER.D16_TEST),
                         LAUNCHER.D16_TEST_SHA256)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                LAUNCHER, 'dependency_inventory', return_value={}):
            files = LAUNCHER.source_snapshot(HERE.parent.parent, sys.executable,
                                             LAUNCHER.D16_V40_COHORT,
                                             browser_root=Path(directory))['sourcePins']
            prior = LAUNCHER.source_snapshot(HERE.parent.parent, sys.executable,
                                              LAUNCHER.D16_COHORT,
                                              browser_root=Path(directory))['sourcePins']
        for name in ('tests/fixtures/secureshopMcpTrustStandaloneQualification.js',
                     'tests/fixtures/secureshopMcpRugPullV40Qualification.js',
                     'tests/secureshopMcpRugPullV40Qualification.test.js',
                     'tests/postgres/test_secureshop_mcp_rug_pull_v40_launcher.py'):
            self.assertIn(name, files)
        self.assertNotIn('tests/fixtures/secureshopMcpRugPullV40Qualification.js',
                         prior)

    def test_closed_physical_fixed_denial_requires_same_positive_and_zero_effect(self):
        ident = 'secureshop-weather-lab'
        first, changed = '1' * 64, '2' * 64
        request = '30000000-0000-4000-8000-000000000001'
        summary = {'scope': 'V40-fixed-contrast', 'physicalMode': True,
                   'physicalChangedRunDenied': True, 'noInvocation': True,
                   'noEffect': True, 'noJudgeCredit': True, 'sameIdentity': True}
        positive = {'beforeReset': summary,
                    'summary': {'qualified': True, 'genuineCredit': 2,
                                'replay': True, 'siblingDenied': True,
                                'siblingPreserved': True, 'reset': True,
                                'immutablePreserved': True, 'ownedTargetsRetired': True},
                    'turns': [{'phase': 'rogue'},
                              {'phase': 'baseline', 'response': {
                                  'serverIdentity': ident, 'schemaVersion': 1,
                                  'schemaSha256': first}},
                              {'phase': 'changed', 'response': {
                                  'serverIdentity': ident, 'schemaVersion': 2,
                                  'schemaSha256': changed}}],
                    'controls': [{}, {}, {}, {}, {'path': '/rotate'}, {'path': '/run'}]}
        state = {'invocations': [], 'turns': [], 'effects': [], 'judgments': []}
        wire = {'externalAttempts': 6, 'counts': {'tags': 1, 'actor': 3, 'judge': 2},
                'failed': False}
        fixed = {'scope': 'V40-fixed-contrast',
                 'sameIdentity': {'serverIdentity': ident,
                                  'baselineSha256': first, 'changedSha256': changed},
                 'fixed': True, 'denied': True, 'mode': {'mode': 'fixed', 'revision': '2'},
                 'requestId': request,
                 'response': {'status': 503, 'body': {
                     'error': 'MCP trust exercise unavailable'}},
                 'originalDenial': {'requestId': request,
                                    'code': 'BOUND_MCP_UNAVAILABLE',
                                    'message': 'Changed MCP schema blocked by fixed policy'},
                 'before': state, 'after': state.copy(),
                 'wireBefore': wire, 'wireAfter': wire.copy()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            positive_file, fixed_file = root / 'positive.json', root / 'fixed.json'
            self.write_private(positive_file, positive)
            self.write_private(fixed_file, fixed)
            self.assertEqual(LAUNCHER.v40_receipt(fixed_file, positive_file)['noEffect'], True)
            for change in (
                lambda value: value['sameIdentity'].__setitem__('changedSha256', first),
                lambda value: value['originalDenial'].__setitem__('code', 'MODEL_UNAVAILABLE'),
                lambda value: value['after']['effects'].append({'effect': 'forbidden'}),
                lambda value: value['wireAfter'].__setitem__('externalAttempts', 7),
                lambda value: value.__setitem__('unexpected', True),
            ):
                subject = json.loads(json.dumps(fixed))
                change(subject)
                self.write_private(fixed_file, subject)
                with self.assertRaises(RuntimeError):
                    LAUNCHER.v40_receipt(fixed_file, positive_file)
            self.write_private(fixed_file, fixed)
            positive['summary']['reset'] = False
            self.write_private(positive_file, positive)
            with self.assertRaises(RuntimeError):
                LAUNCHER.v40_receipt(fixed_file, positive_file)


if __name__ == '__main__':
    unittest.main()
