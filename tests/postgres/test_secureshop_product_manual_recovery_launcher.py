#!/usr/bin/env python3
"""Closed, offline Q05 physical manual-upload recovery launcher contract."""

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
SOURCE = HERE.parent.parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class ProductManualRecoveryLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.PRODUCT_MANUAL_RECOVERY_FLAGS}
        value.update(scope=LAUNCHER.PRODUCT_MANUAL_RECOVERY_SCOPE,
                     profile='merchant-product-manual-recovery-v1', actorCalls=4,
                     uploadPosts=2, actualActorCalls=4, ownerUploadPosts=1,
                     allUploadPosts=2, receiptGets=2, judgeCalls=0,
                     canonicalCredit=False, diagnosticOnly=True, cleanupErrors=[],
                     evidence={
                         'operationId': '123e4567-e89b-42d3-a456-426614174000',
                         'responseSha256': 'a' * 64, 'responseBytes': 123,
                         'manualSha256': 'b' * 64,
                         'browserLoadingFailed': True,
                         'browserLoadingFinished': False,
                         'recoveryScopeKeySha256': 'c' * 64,
                         'ownerSequence': [
                             {'method':'GET','path':'/api/secureshop/uploads/product-manual/receipt','status':200,'state':'not_found'},
                             {'method':'POST','path':'/api/secureshop/uploads','status':200,'state':'indexed'},
                             {'method':'GET','path':'/api/secureshop/uploads/product-manual/receipt','status':200,'state':'indexed'},
                         ], 'siblingReceiptStatus': 401})
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_plan_does_not_allocate_or_call_external_services(self):
        selector = LAUNCHER.PRODUCT_MANUAL_RECOVERY_BROWSER
        self.assertIn(selector, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(selector, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        argv = ['--cohort', selector, '--main-workspace', str(SOURCE),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64,
                '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon',
                '--ollama-model-sha256', 'b' * 64,
                '--listings-image-id', 'sha256:' + 'c' * 64, '--plan']
        out = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=SOURCE), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(out):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(out.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.PRODUCT_MANUAL_RECOVERY_COHORT)
        self.assertEqual(plan['stores'], ['identity','secureshop_agents','secureshop','secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['actualJudgeRequired'], False)
        self.assertEqual(plan['selectedFixtures'], [LAUNCHER.STANDALONE_LISTINGS_TEST])
        self.assertEqual(plan['profile'], 'merchant-product-manual-recovery-v1')
        self.assertEqual(plan['maximumActorCalls'], 12)
        self.assertEqual(plan['maximumJudgeCalls'], 0)
        self.assertEqual(plan['ownerUploadPosts'], 1)
        self.assertEqual(plan['allUploadPosts'], 2)
        self.assertEqual(plan['receiptGets'], 2)
        self.assertIs(plan['canonicalCredit'], False)
        self.assertIs(plan['diagnosticOnly'], True)
        self.assertNotIn('browserBirthAckRequired', plan)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)

    def test_receipt_requires_exact_private_one_post_loss_and_get_recovery(self):
        qualification = SOURCE / 'tasks/qualification'
        with tempfile.TemporaryDirectory(prefix='run-', dir=qualification) as directory:
            target = Path(directory) / 'merchant-product-manual-recovery-v1.json'
            accepted = self.receipt(target)
            self.assertEqual(LAUNCHER.product_manual_recovery_receipt(target), accepted)
            for change in ({'uploadPosts': 3}, {'ownerUploadPosts': 2},
                           {'allUploadPosts': 1}, {'receiptGets': 1},
                           {'actorCalls': True}, {'actualActorCalls': 5},
                           {'judgeCalls': 1}, {'canonicalCredit': True},
                           {'diagnosticOnly': False}, {'cleanupErrors': ['failure']},
                           {'physicalOwnedManualUpload': False},
                           {'profile': 'merchant-manual-ingest-browser'},
                           {'scope': LAUNCHER.PRODUCT_MANUAL_SCOPE},
                           {'evidence': dict(accepted['evidence'], browserLoadingFinished=True)},
                           {'evidence': dict(accepted['evidence'], siblingReceiptStatus=200)},
                           {'evidence': dict(accepted['evidence'], ownerSequence=accepted['evidence']['ownerSequence'][:2])},
                           {'extra': True}):
                with self.subTest(change=change):
                    self.receipt(target, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.product_manual_recovery_receipt(target)
            self.receipt(target)
            os.chmod(target, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.product_manual_recovery_receipt(target)
            os.chmod(target, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(target)
            with self.assertRaises(RuntimeError):
                LAUNCHER.product_manual_recovery_receipt(alias)
            target.write_text(target.read_text()[:-1] + ',"judgeCalls":0}')
            with self.assertRaises(RuntimeError):
                LAUNCHER.product_manual_recovery_receipt(target)

    def test_reviewed_source_closure_rejects_mutated_helper(self):
        node = SOURCE / 'tasks/runtime/node/node_modules/node/bin/node'
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={'controlled':True}), \
                patch.object(LAUNCHER, 'embedding_inventory', return_value={'controlled':True}), \
                patch.object(LAUNCHER, 'embedding_runtime', return_value={'fingerprint':'controlled'}):
            snapshot = LAUNCHER.source_snapshot(SOURCE, node, LAUNCHER.PRODUCT_MANUAL_RECOVERY_BROWSER,
                browser_root=SOURCE / 'tasks/runtime', embedding_cache=SOURCE / 'tasks/runtime')
            self.assertEqual({key:snapshot['sourcePins'][key] for key in LAUNCHER.PRODUCT_MANUAL_RECOVERY_PINS},
                             LAUNCHER.PRODUCT_MANUAL_RECOVERY_PINS)
            original = LAUNCHER.digest
            member = 'tests/fixtures/secureshopProductManualRenderedRecovery.js'
            with patch.object(LAUNCHER, 'digest', side_effect=lambda path:
                              '0'*64 if Path(path) == SOURCE / member else original(path)):
                with self.assertRaisesRegex(RuntimeError, 'Reviewed physical manual recovery source'):
                    LAUNCHER.source_snapshot(SOURCE, node, LAUNCHER.PRODUCT_MANUAL_RECOVERY_BROWSER,
                        browser_root=SOURCE / 'tasks/runtime', embedding_cache=SOURCE / 'tasks/runtime')


if __name__ == '__main__':
    unittest.main()
