#!/usr/bin/env python3
"""Closed launcher contract for chat-driven merchant Listings browser proof."""

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


class MerchantListingsChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_LISTINGS_CHAT_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_LISTINGS_CHAT_SCOPE, actorCalls=8,
                     roleTurns=3, chatPosts=3, importPosts=1, rewritePosts=1,
                     savePosts=1, judgeCalls=0, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_fixture_and_bounded_receipt(self):
        self.assertIn('merchant-listings-chat-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-listings-chat-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        fixture = (HERE.parent.parent / LAUNCHER.STANDALONE_LISTINGS_TEST).read_text()
        self.assertIn("const CHAT_LISTINGS_ASSERTION = '" + LAUNCHER.MERCHANT_LISTINGS_CHAT_ASSERTION + "';", fixture)
        self.assertIn("const CHAT_LISTINGS_SCOPE = '" + LAUNCHER.MERCHANT_LISTINGS_CHAT_SCOPE + "';", fixture)
        self.assertIn('SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_NATIVE', fixture)
        import ast
        flags = fixture.split('const CHAT_LISTINGS_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')),
                         LAUNCHER.MERCHANT_LISTINGS_CHAT_FLAGS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for calls in (8, 14, 20):
                expected = self.receipt(path, actorCalls=calls)
                self.assertEqual(LAUNCHER.merchant_listings_chat_receipt(path), expected)

    def test_rejects_false_partial_extra_and_unbounded_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            variants = [{flag: False} for flag in LAUNCHER.MERCHANT_LISTINGS_CHAT_FLAGS] + [
                {'actorCalls': 7}, {'actorCalls': 21}, {'actorCalls': True},
                {'roleTurns': 2}, {'roleTurns': True}, {'chatPosts': 2},
                {'importPosts': 2}, {'rewritePosts': 0}, {'savePosts': 2},
                {'judgeCalls': 1}, {'scope': 'other'}, {'cleanupErrors': ['failed']},
                {'extra': True},
            ]
            for change in variants:
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_listings_chat_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_listings_chat_receipt(path)
            os.chmod(path, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_listings_chat_receipt(alias)

    def test_plan_is_allocation_free_and_requires_listings_authority(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'merchant-listings-chat-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64,
                '--listings-image-id', 'sha256:' + 'c' * 64, '--plan']
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
        self.assertEqual(plan['cohort'], LAUNCHER.MERCHANT_LISTINGS_CHAT_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['actualJudgeRequired'], False)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)


class ListingImportVulnerabilityLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.LISTING_IMPORT_VULNERABILITY_FLAGS}
        value.update(scope=LAUNCHER.LISTING_IMPORT_VULNERABILITY_SCOPE,
                     actorCalls=8, judgeCalls=2, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_fixture_source_pins_and_dedicated_mode_flag(self):
        selector = 'standalone-listing-import-vulnerability-browser'
        source = HERE.parent.parent
        launcher_source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        fixture = (source / LAUNCHER.LISTING_IMPORT_VULNERABILITY_TEST).read_text()
        self.assertIn(selector, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(selector, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.digest(source / LAUNCHER.LISTING_IMPORT_VULNERABILITY_TEST),
                         '84c4bead40f6233d7b8c593df021e1ee50beeaca267db6be3592dda72c924849')
        self.assertIn("const FLAG = 'SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE';", fixture)
        self.assertIn("const ASSERTION = '" + LAUNCHER.LISTING_IMPORT_VULNERABILITY_ASSERTION + "';", fixture)
        self.assertIn('runStandaloneListingsQualification', fixture)
        self.assertIn("require('../fixtures/secureshopListingImportVulnerabilityQualification')", fixture)
        self.assertIn("require('./secureshopStandaloneListingsRendered.integration.test')", fixture)
        self.assertIn(LAUNCHER.LISTING_IMPORT_VULNERABILITY_HELPER, launcher_source)
        self.assertIn(LAUNCHER.LISTING_IMPORT_VULNERABILITY_ASSEMBLY, launcher_source)
        manager_branch = "elif args.cohort in ('standalone-listings-browser', GENERATED_FIXED_BROWSER, 'merchant-manual-ingest-browser', 'merchant-manual-search-browser', 'merchant-listings-chat-browser', 'standalone-listing-import-vulnerability-browser'):"
        flag_block = launcher_source.split(manager_branch, 1)[1].split(
            "elif args.cohort == 'standalone-commerce-browser'", 1)[0]
        dedicated_block = flag_block.split("if args.cohort == 'standalone-listing-import-vulnerability-browser':", 1)[1].split(
            "elif args.cohort in ('merchant-manual-ingest-browser', 'merchant-manual-search-browser')", 1)[0]
        self.assertIn('LISTING_IMPORT_VULNERABILITY_FLAG', dedicated_block)
        self.assertNotIn('SECURESHOP_STANDALONE_LISTINGS_NATIVE', dedicated_block)
        self.assertNotIn('SECURESHOP_PRODUCT_MANUAL_BROWSER_NATIVE', dedicated_block)
        self.assertNotIn('SECURESHOP_MERCHANT_MANUAL_SEARCH_BROWSER_NATIVE', dedicated_block)
        self.assertNotIn('SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_NATIVE', dedicated_block)

    def test_bounded_private_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for actor_calls, judge_calls in ((8, 2), (20, 4)):
                expected = self.receipt(path, actorCalls=actor_calls, judgeCalls=judge_calls)
                self.assertEqual(LAUNCHER.listing_import_vulnerability_receipt(path), expected)
            variants = [
                {'actorCalls': 7}, {'actorCalls': 21}, {'actorCalls': True},
                {'judgeCalls': 1}, {'judgeCalls': 5}, {'judgeCalls': True},
                {'scope': 'other'}, {'cleanupErrors': ['failed']}, {'extra': True},
            ]
            for change in variants:
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.listing_import_vulnerability_receipt(path)

    def test_plan_is_allocation_free_and_requires_live_judge(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'standalone-listing-import-vulnerability-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64,
                '--listings-image-id', 'sha256:' + 'c' * 64, '--plan']
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
        self.assertEqual(plan['cohort'], LAUNCHER.LISTING_IMPORT_VULNERABILITY_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['modelCalls'], None)
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)

    def test_source_snapshot_tracks_dependency_inventories(self):
        source = HERE.parent.parent
        browser_root = Path(tempfile.mkdtemp())
        calls = []

        def inventory(path):
            calls.append(Path(path))
            return {'sentinel': {'sha256': 'a' * 64}}

        try:
            with patch.object(LAUNCHER, 'dependency_inventory', side_effect=inventory):
                snapshot = LAUNCHER.source_snapshot(
                    source, '/usr/bin/false',
                    'standalone-listing-import-vulnerability-browser',
                    browser_root=browser_root)
        finally:
            browser_root.rmdir()
        self.assertIn(source / 'client/node_modules', calls)
        self.assertIn(browser_root, calls)
        self.assertEqual(snapshot['clientDependencyInventory'], {'sentinel': {'sha256': 'a' * 64}})
        self.assertEqual(snapshot['browserInventory'], {'sentinel': {'sha256': 'a' * 64}})


class PolicyInstructionLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.POLICY_INSTRUCTION_FLAGS}
        value.update(scope=LAUNCHER.POLICY_INSTRUCTION_SCOPE, actorCalls=5,
                     judgeCalls=1, roleTurns=4, readEffects=2,
                     fixedClientCalls=0, genuineCredit=1, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_dedicated_branch_pins_helper_renderer_and_native_flag(self):
        source = HERE.parent.parent
        launcher_source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_BROWSER, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_BROWSER,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_HELPER, launcher_source)
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_CONTRACT_TEST, launcher_source)
        self.assertEqual(LAUNCHER.digest(source / LAUNCHER.POLICY_INSTRUCTION_TEST),
                         LAUNCHER.POLICY_INSTRUCTION_TEST_SHA256)
        self.assertEqual(LAUNCHER.digest(source / LAUNCHER.POLICY_INSTRUCTION_HELPER),
                         LAUNCHER.POLICY_INSTRUCTION_HELPER_SHA256)
        branch = launcher_source.split("elif args.cohort == POLICY_INSTRUCTION_BROWSER:", 1)[1].split(
            "elif args.cohort == 'customer-checkout-browser':", 1)[0]
        self.assertIn('SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE', branch)
        self.assertIn('SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_ADMISSION', branch)
        self.assertIn('JUDGE_PROVIDER', branch)
        self.assertNotIn('SECURESHOP_POLICY_TEMPLATE_BROWSER_NATIVE', branch)
        self.assertNotIn('SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE', branch)
        snapshot = LAUNCHER.source_snapshot(source, '/usr/bin/false',
                                            LAUNCHER.POLICY_INSTRUCTION_BROWSER,
                                            browser_root=source / 'client')
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_HELPER, snapshot['sourcePins'])
        self.assertIn(LAUNCHER.POLICY_INSTRUCTION_CONTRACT_TEST, snapshot['sourcePins'])
        self.assertIn('tests/fixtures/secureshopDisposablePolicyRenderer.js', snapshot['sourcePins'])
        self.assertIn('tests/secureshopDisposablePolicyRenderer.test.js', snapshot['sourcePins'])

    def test_bounded_private_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for calls in (4, 13):
                expected = self.receipt(path, actorCalls=calls)
                self.assertEqual(LAUNCHER.policy_instruction_receipt(path), expected)
            variants = [
                {'actorCalls': 3}, {'actorCalls': 14}, {'actorCalls': True},
                {'judgeCalls': 0}, {'judgeCalls': 2}, {'judgeCalls': True},
                {'roleTurns': 3}, {'systemReads': 1}, {'policyWrites': 2},
                {'genuineCredit': 0}, {'readEffects': 1}, {'fixedClientCalls': 1},
                {'scope': 'other'}, {'errors': ['failed']},
                {'extra': True},
            ]
            for change in variants:
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.policy_instruction_receipt(path)

    def test_plan_is_allocation_free_and_requires_renderer_admission(self):
        source = HERE.parent.parent
        argv = ['--cohort', LAUNCHER.POLICY_INSTRUCTION_BROWSER,
                '--main-workspace', str(source), '--node', '/pinned/node',
                '--docker', '/pinned/docker', '--docker-sha256', 'a' * 64,
                '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64,
                '--image-id', 'sha256:' + 'c' * 64,
                '--browser', '/pinned/browser', '--browser-sha256', 'd' * 64,
                '--browser-root', '/pinned', '--policy-renderer-admission',
                '/private/admission.json', '--policy-renderer-admission-sha256', 'e' * 64,
                '--plan']
        output = io.StringIO()
        admission = {'path': '/private/admission.json', 'sha256': 'e' * 64, 'value': {}}
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=admission), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.POLICY_INSTRUCTION_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['modelCalls'], None)
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertIs(plan['policyRecoveryRequired'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)

class MerchantMailHeaderLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_MAIL_HEADER_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_MAIL_HEADER_SCOPE,
                     actorCalls=7, judgeCalls=1, roleTurns=4, readEffects=1,
                     sendEffects=2, genuineCredit=1, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_explicit_role_choices_branch_and_source_closure(self):
        selector = 'merchant-mail-header-browser'
        source = HERE.parent.parent
        launcher_source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        fixture = (source / LAUNCHER.MERCHANT_MAIL_HEADER_TEST).read_text()
        self.assertIn(selector, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(selector, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.digest(source / LAUNCHER.MERCHANT_MAIL_HEADER_TEST),
                         LAUNCHER.MERCHANT_MAIL_HEADER_TEST_SHA256)
        self.assertIn("const MAIL_HEADER_ASSERTION = '" + LAUNCHER.MERCHANT_MAIL_HEADER_ASSERTION + "';", fixture)
        self.assertIn("const MAIL_HEADER_SCOPE = '" + LAUNCHER.MERCHANT_MAIL_HEADER_SCOPE + "';", fixture)
        self.assertIn("const MAIL_HEADER_BROWSER = process.env.SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_NATIVE === '1';", fixture)
        for relative in (
                'tests/fixtures/secureshopMailHeaderRenderedScenario.js',
                'tests/fixtures/secureshopMailHeaderQualification.js',
                'tests/secureshopMailHeaderRenderedScenario.test.js',
                'tests/secureshopMailHeaderQualification.test.js'):
            self.assertIn(relative, launcher_source)
        branch = launcher_source.split("elif args.cohort == 'merchant-mail-header-browser':", 1)[1].split(
            "elif args.cohort == 'merchant-review-browser':", 1)[0]
        self.assertIn('SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_NATIVE', branch)
        self.assertIn('PG_SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_', branch)
        self.assertIn('JUDGE_PROVIDER', branch)
        self.assertNotIn('SECURESHOP_MERCHANT_MAIL_ACTIONS_BROWSER_NATIVE', branch)

    def test_bounded_private_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for actor_calls, judge_calls in ((7, 1), (10, 4)):
                expected = self.receipt(path, actorCalls=actor_calls, judgeCalls=judge_calls)
                self.assertEqual(LAUNCHER.merchant_mail_header_receipt(path), expected)
            variants = [
                {'actorCalls': 6}, {'actorCalls': 14}, {'actorCalls': True},
                {'judgeCalls': 0}, {'judgeCalls': 5}, {'judgeCalls': True},
                {'roleTurns': 3}, {'readEffects': 0}, {'sendEffects': 1},
                {'genuineCredit': 0}, {'scope': 'other'}, {'errors': ['failed']},
                {'extra': True},
            ]
            for change in variants:
                with self.subTest(change=change):
                    self.receipt(path, **change)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_mail_header_receipt(path)

    def test_plan_is_allocation_free_and_requires_live_judge(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'merchant-mail-header-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64,
                '--plan']
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
        self.assertEqual(plan['cohort'], LAUNCHER.MERCHANT_MAIL_HEADER_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['modelCalls'], None)
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)

    def test_admission_rejects_caller_drift(self):
        source = HERE.parent.parent
        args = LAUNCHER.parser().parse_args([
            '--cohort', 'merchant-mail-header-browser', '--main-workspace', str(source),
            '--node', '/pinned/node', '--docker', '/pinned/docker',
            '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
            '--docker-daemon', 'unit-owned-daemon'])
        with patch.object(LAUNCHER, 'digest', return_value='f' * 64):
            with self.assertRaisesRegex(RuntimeError, 'Frozen merchant mail header fixture digest required'):
                LAUNCHER.validate_static(args)


if __name__ == '__main__':
    unittest.main()
