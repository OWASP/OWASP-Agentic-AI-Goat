#!/usr/bin/env python3
"""No-resource contract for the three-role Stop watching browser cohort."""

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


class ChatStopWatchingLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CHAT_STOP_WATCHING_FLAGS}
        value.update(scope=LAUNCHER.CHAT_STOP_WATCHING_SCOPE, actorCalls=9,
                     roleTurns=3, chatPosts=3, recoveryGets=3, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_fixture_contract_and_exact_real_model_bounds(self):
        self.assertIn('chat-stop-watching-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('chat-stop-watching-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CHAT_STOP_WATCHING_TEST, LAUNCHER.ROLE_CHOICES_TEST)
        fixture = (HERE.parent.parent / LAUNCHER.CHAT_STOP_WATCHING_TEST).read_text()
        self.assertIn("const CHAT_STOP_WATCHING_ASSERTION = '" + LAUNCHER.CHAT_STOP_WATCHING_ASSERTION + "';", fixture)
        self.assertIn("const CHAT_STOP_WATCHING_SCOPE = '" + LAUNCHER.CHAT_STOP_WATCHING_SCOPE + "';", fixture)
        flags = fixture.split('const CHAT_STOP_WATCHING_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.CHAT_STOP_WATCHING_FLAGS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for count in (6, 9, 18):
                expected = self.receipt(path, actorCalls=count)
                self.assertEqual(LAUNCHER.chat_stop_watching_receipt(path), expected)

    def test_rejects_missing_false_extra_and_malformed_receipts(self):
        variants = [{flag: False} for flag in LAUNCHER.CHAT_STOP_WATCHING_FLAGS] + [
            {'actorCalls': 5}, {'actorCalls': 19}, {'actorCalls': True},
            {'roleTurns': 2}, {'roleTurns': True}, {'chatPosts': 4},
            {'recoveryGets': 2}, {'recoveryGets': True}, {'judgeCalls': 1},
            {'judgeCalls': False}, {'scope': 'other'}, {'errors': ['failure']},
            {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.chat_stop_watching_receipt(path)
            value = self.receipt(path)
            value.pop('customerPhysicalStop')
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_stop_watching_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_stop_watching_receipt(path)

    def test_reload_proof_is_distinct_from_prior_same_frame_receipt(self):
        self.assertEqual(
            {name for name in LAUNCHER.CHAT_STOP_WATCHING_FLAGS if name.endswith('ReloadedRecovery')},
            {'customerReloadedRecovery', 'merchantReloadedRecovery', 'adminReloadedRecovery'})
        self.assertIn('customer automatic and merchant/admin explicit exact saved GET',
                      LAUNCHER.CHAT_STOP_WATCHING_SCOPE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'prior-receipt.json'
            old = self.receipt(path)
            for name in ('customerReloadedRecovery', 'merchantReloadedRecovery', 'adminReloadedRecovery'):
                old.pop(name)
            old['scope'] = ('current-main three-role local Stop watching after durable ACK; '
                'real completed model/tool turns and explicit exact saved GET without repeated execution, '
                'no agent-cancellation claim')
            path.write_text(json.dumps(old))
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_stop_watching_receipt(path)

    def test_plan_is_four_store_browser_without_allocation_or_judge(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'chat-stop-watching-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'validate_ssh', side_effect=AssertionError('SSH')), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.CHAT_STOP_WATCHING_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['actualJudgeRequired'], False)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)


if __name__ == '__main__':
    unittest.main()
