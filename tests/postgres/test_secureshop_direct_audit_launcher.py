#!/usr/bin/env python3
"""Closed opt-in launcher contract for direct rendered Audit Search/Summarize."""

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
SPEC = importlib.util.spec_from_file_location('secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class DirectAuditLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_DIRECT_AUDIT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_DIRECT_AUDIT_SCOPE,
                     searchOperationId='11111111-1111-4111-8111-111111111111',
                     summaryRunId='22222222-2222-4222-8222-222222222222',
                     actorCalls=2, judgeCalls=1, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_fixture_and_source_closure(self):
        self.assertIn('admin-direct-audit-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-direct-audit-browser', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.ADMIN_DIRECT_AUDIT_TEST, LAUNCHER.ADMIN_AUDIT_JOBS_TEST)
        fixture = (HERE.parent.parent / LAUNCHER.ADMIN_DIRECT_AUDIT_TEST).read_text()
        helper = (HERE.parent.parent / LAUNCHER.ADMIN_DIRECT_AUDIT_HELPER).read_text()
        self.assertIn("const DIRECT_ASSERTION = '" + LAUNCHER.ADMIN_DIRECT_AUDIT_ASSERTION + "';", fixture)
        self.assertIn("const SCOPE = '" + LAUNCHER.ADMIN_DIRECT_AUDIT_SCOPE + "';", helper)
        self.assertIn('SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE', fixture)
        self.assertIn('qualifyDirectAudit({ page, frame, origin', fixture)
        launcher = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        # The selected test imports the helper even when Q61 runs, so both
        # source snapshots must pin it without copying sources.
        self.assertIn('files.update((ADMIN_AUDIT_JOBS_CONTRACT_TEST, ADMIN_DIRECT_AUDIT_HELPER))', launcher)
        self.assertIn('files.update((ADMIN_DIRECT_AUDIT_HELPER, ADMIN_DIRECT_AUDIT_CONTRACT_TEST,', launcher)
        self.assertIn('ADMIN_DIRECT_AUDIT_LAUNCHER_TEST))', launcher)

    def test_closed_private_receipt_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for actors, judges in ((2, 1), (12, 12)):
                expected = self.receipt(path, actorCalls=actors, judgeCalls=judges)
                self.assertEqual(LAUNCHER.admin_direct_audit_receipt(path), expected)
            variants = [{flag: False} for flag in LAUNCHER.ADMIN_DIRECT_AUDIT_FLAGS] + [
                {'actorCalls': 1}, {'actorCalls': 13}, {'actorCalls': True},
                {'judgeCalls': 0}, {'judgeCalls': 13}, {'judgeCalls': True},
                {'scope': 'other'}, {'searchOperationId': 'not-a-uuid'},
                {'summaryRunId': 'not-a-uuid'}, {'errors': [{'stage': 'search'}]},
                {'extra': True},
            ]
            for change in variants:
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_direct_audit_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_direct_audit_receipt(path)
            os.chmod(path, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_direct_audit_receipt(alias)

    def test_plan_is_allocation_free_and_requires_real_judge(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'admin-direct-audit-browser', '--main-workspace', str(source),
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
        self.assertEqual(plan['cohort'], LAUNCHER.ADMIN_DIRECT_AUDIT_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)


if __name__ == '__main__':
    unittest.main()
