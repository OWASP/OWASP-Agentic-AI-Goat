#!/usr/bin/env python3
"""No-resource contract for the separate physical M16 Pricing cohort."""

import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class MerchantPricingExperimentLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_PRICING_EXPERIMENT_FLAGS}
        value.update({flag: True for flag in LAUNCHER.MERCHANT_PRICING_EXPERIMENT_HISTORY_FLAGS})
        value.update(scope=LAUNCHER.MERCHANT_PRICING_EXPERIMENT_SCOPE,
                     actorCalls=2, pricingOperations=1, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_fixture_contract_and_closed_receipt(self):
        fixture = (HERE.parent.parent / LAUNCHER.MERCHANT_PRICING_EXPERIMENT_TEST).read_text()
        self.assertIn("const EXPERIMENT_ASSERTION='" + LAUNCHER.MERCHANT_PRICING_EXPERIMENT_ASSERTION + "';", fixture)
        self.assertIn("const EXPERIMENT_SCOPE='" + LAUNCHER.MERCHANT_PRICING_EXPERIMENT_SCOPE + "';", fixture)
        flags = fixture.split('const EXPERIMENT_FLAGS=[', 1)[1].split('];', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')),
                         LAUNCHER.MERCHANT_PRICING_EXPERIMENT_FLAGS)
        self.assertIn('merchant-pricing-experiment-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-pricing-experiment-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'experiment.json'
            for count in (2, 4, 6):
                expected = self.receipt(path, actorCalls=count)
                self.assertEqual(LAUNCHER.merchant_pricing_experiment_receipt(path), expected)
            for mutation in ({'actorCalls': 1}, {'actorCalls': 7}, {'actorCalls': True},
                             {'pricingOperations': 2}, {'pricingOperations': True},
                             {'judgeCalls': 1}, {'judgeCalls': False}, {'errors': ['failed']},
                             {'scope': 'other'}, {'extra': True}):
                self.receipt(path, **mutation)
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    LAUNCHER.merchant_pricing_experiment_receipt(path)
            for flag in LAUNCHER.MERCHANT_PRICING_EXPERIMENT_FLAGS:
                self.receipt(path, **{flag: False})
                with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                    LAUNCHER.merchant_pricing_experiment_receipt(path)
            for flag in LAUNCHER.MERCHANT_PRICING_EXPERIMENT_HISTORY_FLAGS:
                self.receipt(path, **{flag: False})
                with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                    LAUNCHER.merchant_pricing_experiment_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_pricing_experiment_receipt(path)

    def test_plan_reuses_four_owned_stores_without_allocation(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'merchant-pricing-experiment-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'validate_ssh', return_value=None), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.MERCHANT_PRICING_EXPERIMENT_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['actualJudgeRequired'], False)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)


if __name__ == '__main__':
    unittest.main()
