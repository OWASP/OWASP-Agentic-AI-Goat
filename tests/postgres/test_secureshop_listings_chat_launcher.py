#!/usr/bin/env python3
"""Closed launcher contract for chat-driven merchant Listings browser proof."""

import contextlib
import ast
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
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


class MerchantListingsPrivateProducerAdmissionContract(unittest.TestCase):
    """The original chat fixture may use the owned manager, never a weaker test."""

    def args(self, cohort='merchant-listings-chat-browser', **changes):
        value = dict(cohort=cohort, listings_private_run_id='a' * 32,
                     listings_private_plan_sha256='b' * 64,
                     listings_private_plan='/repository/tasks/private-plan.json',
                     listings_image_id=None)
        value.update(changes)
        return SimpleNamespace(**value)

    def plan(self, source):
        return {
            'target': 'listings-package',
            'spec': {'root': str(source), 'runId': 'a' * 32},
            'listingsConsumer': {'mode': 'manager'},
            'sharedImageLoadAllowed': False,
            'limits': {'consumerWorkMs': 600000, 'consumerRetirementMs': 1080000},
            'listingsLease': dict(profile='listings-manager-browser',
                                  target='original-listings-manager-total-lease-v1',
                                  totalMs=6680000, startupMs=60000, browserMs=540000,
                                  retirementMs=1080000, cleanupMs=2520000),
            'helperHashes': {
                'tests/postgres/ownedMcpOriginalBuildAdapter.js':
                    LAUNCHER.digest(source / 'tests/postgres/ownedMcpOriginalBuildAdapter.js')},
            'buildSources': {
                'tests/postgres/ownedMcpBoundedBuild.js':
                    LAUNCHER.digest(source / 'tests/postgres/ownedMcpBoundedBuild.js')},
        }

    def test_exact_private_selector_and_owned_pg_gate(self):
        for cohort in ('standalone-listings-browser', 'merchant-listings-chat-browser',
                       'merchant-manual-ingest-browser'):
            self.assertTrue(LAUNCHER.listings_private_selected(self.args(cohort)))
            self.assertTrue(LAUNCHER.owned_pg_network_selected(cohort, private_listings=True))
            self.assertFalse(LAUNCHER.owned_pg_network_selected(cohort, private_listings=False))
        for cohort in ('merchant-manual-search-browser', LAUNCHER.PRODUCT_MANUAL_RECOVERY_BROWSER,
                       'standalone-listing-import-vulnerability-browser',
                       'merchant-pricing-chat-browser', 'merchant-mail-actions-browser'):
            with self.subTest(cohort=cohort), self.assertRaises(RuntimeError):
                LAUNCHER.listings_private_selected(self.args(cohort))
            self.assertFalse(LAUNCHER.owned_pg_network_selected(cohort, private_listings=True))
        for changes in ({'listings_private_run_id': None},
                        {'listings_private_plan_sha256': None},
                        {'listings_private_plan': None},
                        {'listings_image_id': 'sha256:' + 'c' * 64}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                LAUNCHER.listings_private_selected(self.args(**changes))
        self.assertFalse(LAUNCHER.listings_private_selected(self.args(
            listings_private_run_id=None, listings_private_plan_sha256=None,
            listings_private_plan=None, listings_image_id='sha256:' + 'c' * 64)))

    def test_private_plan_packet_lease_and_retirement_are_exact(self):
        source = HERE.parent.parent
        plan = self.plan(source)
        self.assertEqual(LAUNCHER.listings_private_browser_budget(plan, 'a' * 32), 600000)
        with tempfile.TemporaryDirectory(dir=source / 'tasks/tmp') as directory:
            target = Path(directory) / 'private-plan.json'
            compact = json.dumps(plan, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            import hashlib
            digest = hashlib.sha256(compact.encode()).hexdigest()
            target.write_text(json.dumps({'version': 1, 'runId': 'a' * 32,
                                          'planSha256': digest, 'plan': plan}))
            os.chmod(target, 0o600)
            args = self.args(listings_private_plan=str(target),
                             listings_private_plan_sha256=digest)
            self.assertEqual(LAUNCHER.listings_private_packet(args, source)['plan'], plan)
            with self.assertRaises(RuntimeError):
                LAUNCHER.listings_private_packet(self.args(
                    cohort='merchant-manual-search-browser',
                    listings_private_plan=str(target), listings_private_plan_sha256=digest), source)
        for invalid in ({'sharedImageLoadAllowed': True},
                        {'limits': {'consumerWorkMs': 120000, 'consumerRetirementMs': 1080000}},
                        {'listingsConsumer': {'mode': 'fixture'}}):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                LAUNCHER.listings_private_browser_budget({**plan, **invalid}, 'a' * 32)
        self.assertFalse(LAUNCHER.listings_private_may_retire_pg(
            SimpleNamespace(closed=False), {'listingsPrivate': {'cleanupVerified': True}}))
        self.assertFalse(LAUNCHER.listings_private_may_retire_pg(
            SimpleNamespace(closed=True), {'listingsPrivate': {'cleanupVerified': False}}))
        self.assertTrue(LAUNCHER.listings_private_may_retire_pg(
            SimpleNamespace(closed=True), {'listingsPrivate': {'cleanupVerified': True}}))

    def test_private_source_union_and_original_worker_binding(self):
        source = HERE.parent.parent
        plan = self.plan(source)
        packet = {'runId': 'a' * 32, 'planSha256': 'b' * 64, 'plan': plan}
        original_run = subprocess.run

        def run(command, *args, **kwargs):
            if len(command) >= 3 and command[1] == '-e' and 'originalBuildPlan(process.cwd()' in command[2]:
                return SimpleNamespace(stdout=json.dumps(['tests/postgres/ownedMcpOriginalBuildAdapter.js']))
            return original_run(command, *args, **kwargs)

        with patch.object(LAUNCHER.subprocess, 'run', side_effect=run):
            snapshot = LAUNCHER.source_snapshot(
                source, str(source / 'tasks/runtime/node/node_modules/node/bin/node'),
                'merchant-listings-chat-browser', browser_root=Path('/Applications/Google Chrome.app'),
                listings_private=packet)
        pins = snapshot['sourcePins']
        for name, digest in {**plan['helperHashes'], **plan['buildSources']}.items():
            self.assertEqual(pins[name], digest)
        for name in ('tests/postgres/listings_integrated_executor_owner.py',
                     'tests/postgres/listings_phase_client.py',
                     'tests/postgres/test_secureshop_owned_pg_network.py',
                     'tests/postgres/secureshopStandaloneListingsRendered.integration.test.js'):
            self.assertEqual(pins[name], LAUNCHER.digest(source / name))
        worker = ast.parse(inspect.getsource(LAUNCHER.main))
        guards = [node for node in ast.walk(worker) if isinstance(node, ast.If)
                  and ast.unparse(node.test) ==
                  "listings_private_producer is not None and label in ('standalone-listings-browser', 'merchant-listings-chat-browser', 'merchant-manual-ingest-browser')"]
        self.assertEqual(len(guards), 2)
        bodies = [ast.unparse(node) for node in guards]
        self.assertTrue(any('work_deadline' in body for body in bodies))
        self.assertTrue(any('attach_browser(child)' in body for body in bodies))
        fixture = source / LAUNCHER.STANDALONE_LISTINGS_TEST
        self.assertEqual(LAUNCHER.digest(fixture), pins[LAUNCHER.STANDALONE_LISTINGS_TEST])
        fixture_source = fixture.read_text()
        for required in ('SECURESHOP_LISTINGS_PRIVATE_MANAGER_RUN_ID',
                         'merchantPrivateReceipt', 'merchant-listings-chat-browser.json',
                         'privateListingsReceipt', 'publishStandaloneReceipt(root, receiptPath, finalPacket, privateReceiptName)',
                         'receiptPath: merchantPrivateReceipt ? receiptPath : null'):
            self.assertIn(required, fixture_source)

    def test_original_run_node_reserves_and_attaches_merchant_worker(self):
        """Execute the actual nested worker body with a fake process, not a string match."""
        source = HERE.parent.parent
        main = next(node for node in ast.parse(inspect.getsource(LAUNCHER.main)).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        worker = next(node for node in main.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'run_node')
        wrapper = ast.FunctionDef(name='make_worker', args=ast.arguments(posonlyargs=[], args=[],
            vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
            body=[ast.Assign(targets=[ast.Tuple(elts=[ast.Name(id=name, ctx=ast.Store())
                for name in ('child', 'stage', 'c31_child_pgid', 'c32_child_pgid',
                             'v30_worker_fd', 'v30_worker_pid', 'v23_child_quiescent')], ctx=ast.Store())],
                value=ast.Tuple(elts=[ast.Constant(value=None)] * 7, ctx=ast.Load())),
                worker, ast.Return(value=ast.Name(id='run_node', ctx=ast.Load()))],
            decorator_list=[])
        program = ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[]))
        class FakeChild:
            pid = 90210
            def wait(self, timeout):
                observed['waitTimeout'] = timeout
                return 0
        class FakeProducer:
            work_deadline = 1600
            def attach_browser(self, child):
                observed['attached'] = child
        observed = {}
        producer = FakeProducer()
        with tempfile.TemporaryDirectory(dir=source / 'tasks/tmp') as directory:
            namespace = dict(args=SimpleNamespace(cohort='merchant-listings-chat-browser'),
                source=source, env={}, evidence=Path(directory), tap_paths={}, exit_codes={},
                listings_private_producer=producer, time=SimpleNamespace(monotonic=lambda: 1000),
                os=os, subprocess=SimpleNamespace(Popen=lambda *a, **kw: FakeChild(),
                    STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired),
                stop_process_group=lambda child: observed.setdefault('retired', child),
                STANDALONE_BROWSER_COHORTS={'merchant-listings-chat-browser'},
                V23_ORIGINAL='registered-admin-reset', V03_OPTIMIZE_BROWSER='v03',
                C31_COHORT='c31', C32_COHORT='c32', v03_private_facade=None, v30_v2=False,
                v23_judge_lease=None, Q05_REVIEW_BROWSER='q05-review-moderation-browser')
            exec(compile(program, '<original-run-node>', 'exec'), namespace)
            run_node = namespace['make_worker']()
            run_node('merchant-listings-chat-browser', ['node', '--test'], 540)
            self.assertEqual(observed['waitTimeout'], 540)
            self.assertIs(observed['attached'], observed['retired'])
            self.assertEqual(namespace['exit_codes']['merchant-listings-chat-browser'], 0)
            self.assertTrue((Path(directory) / 'merchant-listings-chat-browser.tap').exists())
            producer.work_deadline = 1539
            with self.assertRaisesRegex(RuntimeError, 'full540s reserve'):
                run_node('merchant-listings-chat-browser', ['node', '--test'], 540)

    def test_actual_private_merchant_receipt_path_and_exclusive_publication(self):
        source = HERE.parent.parent
        node = source / 'tasks/runtime/node/node_modules/node/bin/node'
        script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const root = process.cwd();
const source = require('node:fs').readFileSync(process.argv[1], 'utf8');
const helpers = source.slice(source.indexOf('async function assertStandaloneReceiptPath('),
  source.indexOf('\nconst READINESS_CODES'));
assert.ok(helpers.startsWith('async function assertStandaloneReceiptPath('));
const { assertStandaloneReceiptPath, publishStandaloneReceipt } =
  new Function('fs', 'path', 'assert', 'process', `${helpers}\nreturn { assertStandaloneReceiptPath, publishStandaloneReceipt };`)(fs, path, assert, process);
const predicate = source.match(/const merchantPrivateReceipt = ([\s\S]*?);/);
assert.ok(predicate, 'actual private merchant admission expression required');
const admitted = (flags = {}) => new Function('exercise', 'CHAT_LISTINGS_ENABLED',
  'MANUAL_ENABLED', 'GENERATED_FIXED_ENABLED', 'process', `return (${predicate[1]});`)(
  flags.exercise || false, flags.chat !== false, flags.manual || false,
  flags.generated || false, { env: { SECURESHOP_STANDALONE_LISTINGS_NATIVE: flags.standalone || '0',
    SECURESHOP_LISTING_IMPORT_VULNERABILITY_BROWSER_NATIVE: flags.import || '0',
    SECURESHOP_LISTINGS_PRIVATE_MANAGER_RUN_ID: flags.runId === undefined ? 'a'.repeat(32) : flags.runId } });
assert.equal(admitted(), true);
for (const flags of [{ chat: false }, { manual: true }, { generated: true },
  { standalone: '1' }, { import: '1' }, { exercise: true }, { runId: '' },
  { runId: 'not-a-valid-run-id' }]) assert.equal(admitted(flags), false, JSON.stringify(flags));
(async () => {
  const directory = path.join(root, 'tasks', 'qualification', `run-${randomBytes(8).toString('hex')}`);
  await fs.mkdir(directory, { mode: 0o700 });
  const merchant = path.join(directory, 'merchant-listings-chat-browser.json');
  const standalone = path.join(directory, 'standalone-listings-browser.json');
  const manual = path.join(directory, 'merchant-manual-ingest-browser.json');
  try {
    assert.equal(await assertStandaloneReceiptPath(root, merchant, 'merchant-listings-chat-browser.json'), directory);
    await assert.rejects(assertStandaloneReceiptPath(root, merchant, 'standalone-listings-browser.json'));
    await assert.rejects(assertStandaloneReceiptPath(root, standalone, 'merchant-listings-chat-browser.json'));
    await assert.rejects(assertStandaloneReceiptPath(root, merchant, 'another-cohort.json'));
    assert.equal(await assertStandaloneReceiptPath(root, manual, 'merchant-manual-ingest-browser.json'), directory);
    await assert.rejects(assertStandaloneReceiptPath(root, manual, 'merchant-listings-chat-browser.json'));
    await publishStandaloneReceipt(root, manual, { passed: true }, 'merchant-manual-ingest-browser.json');
    assert.equal((await fs.stat(manual)).mode & 0o777, 0o600);
    await assert.rejects(publishStandaloneReceipt(root, manual, { passed: false }, 'merchant-manual-ingest-browser.json'));
    await publishStandaloneReceipt(root, merchant, { passed: true }, 'merchant-listings-chat-browser.json');
    assert.deepEqual(JSON.parse(await fs.readFile(merchant, 'utf8')), { passed: true });
    assert.equal((await fs.stat(merchant)).mode & 0o777, 0o600);
    await assert.rejects(publishStandaloneReceipt(root, merchant, { passed: false }, 'merchant-listings-chat-browser.json'));
    await assert.rejects(publishStandaloneReceipt(root, standalone, { passed: false }, 'merchant-listings-chat-browser.json'));
  } finally { await fs.rm(directory, { recursive: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run([str(node), '-e', script, str(source /
            LAUNCHER.STANDALONE_LISTINGS_TEST)], cwd=source, capture_output=True,
            text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


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
        manager_branch = "elif args.cohort in ('standalone-listings-browser', GENERATED_FIXED_BROWSER, 'merchant-manual-ingest-browser', 'merchant-manual-search-browser', PRODUCT_MANUAL_RECOVERY_BROWSER, 'merchant-listings-chat-browser', 'standalone-listing-import-vulnerability-browser'):"
        flag_block = launcher_source.split(manager_branch, 1)[1].split(
            "elif args.cohort == 'standalone-commerce-browser'", 1)[0]
        dedicated_block = flag_block.split("if args.cohort == 'standalone-listing-import-vulnerability-browser':", 1)[1].split(
            "elif args.cohort in ('merchant-manual-ingest-browser', 'merchant-manual-search-browser', PRODUCT_MANUAL_RECOVERY_BROWSER)", 1)[0]
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
        branches = [node for node in ast.walk(ast.parse(launcher_source))
                    if isinstance(node, ast.If)
                    and ast.unparse(node.test) == 'args.cohort == POLICY_INSTRUCTION_BROWSER'
                    and any(isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Name) and child.func.id == 'run_node'
                            for statement in node.body for child in ast.walk(statement))]
        self.assertEqual(len(branches), 1)
        branch = '\n'.join(ast.unparse(statement) for statement in branches[0].body)
        self.assertIn('V24_OWNER', branch)
        self.assertIn('--owned-main-input', branch)
        self.assertIn('v24_owner_terminal', branch)
        owner_source = (source / LAUNCHER.V24_OWNER).read_text()
        self.assertEqual(LAUNCHER.digest(source / LAUNCHER.V24_OWNER), LAUNCHER.V24_OWNER_CORE_PINS[LAUNCHER.V24_OWNER])
        start = owner_source.index('const p=locations(options),env=')
        stop = owner_source.index(' for(const [role,store]', start)
        environment = owner_source[start:stop]
        self.assertIn("SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE:'1'", environment)
        self.assertIn("SECURESHOP_POLICY_INSTRUCTION_BROWSER_RENDERER_TRANSPORT:'owned-pair-v1'", environment)
        self.assertIn('SECURESHOP_POLICY_INSTRUCTION_BROWSER_POLICY_RENDERER_URL:endpoint.policy.baseURL', environment)
        self.assertIn('JUDGE_PROVIDER', environment)
        self.assertNotIn('SECURESHOP_POLICY_TEMPLATE_BROWSER_NATIVE', environment)
        self.assertNotIn('SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE', environment)
        snapshot = LAUNCHER.source_snapshot(source, str(source / 'tasks/runtime/node/node_modules/node/bin/node'),
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
