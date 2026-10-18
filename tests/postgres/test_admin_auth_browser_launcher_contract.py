#!/usr/bin/env python3
"""No-native contract tests for the strict admin/auth/browser/analytics launcher."""

import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


LAUNCHER_PATH = Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
BROWSER_TEST_PATH = Path(__file__).with_name('adminProductionAuthBrowser.integration.test.js')
SPEC = importlib.util.spec_from_file_location('admin_auth_browser_launcher', LAUNCHER_PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


def make_package(base):
    package = Path(base) / 'package'
    source = package / 'source'
    required = [suite['test'] for suite in LAUNCHER.SUITES]
    required.append('tests/postgres/run-admin-auth-browser-cohort-isolated.py')
    dependencies = [
        'node_modules/pg/package.json',
        'node_modules/puppeteer/package.json',
        'client/node_modules/vite/package.json',
    ]
    for relative in required + dependencies:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(relative + '\n')
    linked_package = source / 'node_modules/linked-package'
    linked_package.symlink_to('pg', target_is_directory=True)
    for path in sorted(source.rglob('*'), key=lambda item: len(item.parts), reverse=True):
        if not path.is_symlink():
            os.chmod(path, 0o444 if path.is_file() else 0o555)
    os.chmod(source, 0o555)
    observed = LAUNCHER.package_inventory(package)
    manifest = {
        'stage': LAUNCHER.STAGE,
        'scope': LAUNCHER.SCOPE,
        'qualification': 'native-source-candidate',
        'semanticEffectsQualified': [],
        'mutableSourcePaths': [],
        'suites': [{key: suite[key] for key in (
            'name', 'test', 'databaseStem', 'migrationVariable', 'runtimeVariable',
            'gate', 'timeoutSeconds')} for suite in LAUNCHER.SUITES],
        **observed,
        **{field + 'Sha256': LAUNCHER.json_digest(value) for field, value in observed.items()},
    }
    manifest_path = package / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    os.chmod(manifest_path, 0o444)
    return package, manifest_path


class LauncherContract(unittest.TestCase):
    def test_browser_fixture_declares_mcp_recon_projection_and_visibility_parity(self):
        source = BROWSER_TEST_PATH.read_text()
        self.assertIn('Projection-only fixture', source)
        self.assertIn('createPostgresWorkshopRouter', source)
        self.assertIn("app.use('/api/workshop', createPostgresWorkshopRouter", source)
        self.assertIn("await progress.syncObjectiveComplete(firstStudent.id, 'mcp_workshop', 'mcp_recon')", source)
        for objective_id in (
            'mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning',
            'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
            'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server',
        ):
            self.assertIn(f"'{objective_id}'", source)
        for endpoint in (
            '/api/workshop/challenges', '/api/workshop/progress',
            '/api/workshop/student/stats', '/api/workshop/time/summary',
            '/api/admin/workshops/mcp_workshop/objectives',
            '/api/admin/mcp-workshop/solutions',
            '/api/admin/student-workshop-view/',
        ):
            self.assertIn(endpoint, source)
        self.assertIn("['/workshop-dashboard', '/workshop/challenges', '/workshop/progress']", source)
        self.assertIn("workshopKey: 'mcp_workshop'", source)
        self.assertIn('heartbeatStart + 37_000', source)
        self.assertIn('learnerMcpProjection(1, 11, 37)', source)
        self.assertIn('learnerMcpProjection(0, 10, 37)', source)
        self.assertIn('adminMcpProjection(secondStudent.id, 0, 11, 0)', source)
        self.assertIn('hiding an objective must retain canonical workshop time', source)
        self.assertIn('title.parentElement?.parentElement?.parentElement', source)
        self.assertIn('(^|[^0-9])', source)
        self.assertIn("page.goto(`${base}/admin/solutions`", source)
        self.assertIn("location.pathname === '/admin/exercises'", source)
        self.assertIn('mcpAdminModalMatches', source)
        self.assertIn('mcpObjectiveHelpControlsMatch', source)
        self.assertIn('mcpObjectiveStylesMatch', source)
        self.assertIn('assertConditionalBrowserRead', source)
        self.assertIn("[expectedTime]", source)
        self.assertIn("'the rendered solution toggle must not change objective visibility'", source)
        self.assertIn("'the rendered solution toggle must restore the independent baseline'", source)
        self.assertIn("'the rendered hint toggle must not change objective visibility'", source)
        self.assertIn("'the rendered hint toggle must not change the independent solution gate'", source)
        self.assertIn("'hint restoration must preserve the sibling learner count, time and completion projection'", source)
        self.assertIn("'the restored global hint gate must also reach the sibling projection'", source)
        self.assertIn("body: { enabled: false }", source)
        self.assertIn("body: { enabled: true }", source)
        self.assertIn('hiding an objective must retain its canonical completion', source)
        self.assertIn('objective visibility must not mutate the independent solution gate', source)

    def test_mcp_rendered_dom_helpers_reject_cross_card_counts_and_bind_real_controls(self):
        script = r'''
const assert = require('node:assert/strict');
const { JSDOM } = require('./client/node_modules/jsdom');
const helpers = require('./tests/postgres/adminProductionAuthBrowser.integration.test.js');
const browserResponse = (status, method = 'GET') => ({
  status: () => status,
  request: () => ({ method: () => method }),
});
assert.doesNotThrow(() => helpers.assertConditionalBrowserRead(browserResponse(200), 'fresh'));
assert.doesNotThrow(() => helpers.assertConditionalBrowserRead(browserResponse(304), 'cached'));
assert.throws(() => helpers.assertConditionalBrowserRead(browserResponse(401), 'auth failure'));
assert.throws(() => helpers.assertConditionalBrowserRead(browserResponse(200, 'POST'), 'mutation'));
const ids = [
  'mcp_recon', 'mcp_cmd_injection', 'mcp_ssrf', 'mcp_tool_poisoning',
  'mcp_indirect_injection', 'mcp_confused_deputy', 'mcp_broken_authz',
  'mcp_secret_exposure', 'mcp_supply_chain', 'mcp_audit_gap', 'mcp_shadow_server',
];
const recon = 'Recon: ask the assistant in plain English what tools it can use';
const incomplete = 'Command injection: escape the "safe command" allowlist to read a restricted file';
const dom = new JSDOM(`<body>
  <div id="mcp-card"><div><div><span>MCP Server Lab</span></div></div>
    <span id="count">1/11 objectives</span><span>37s</span>
    <div id="done" style="color:rgb(45, 106, 79)"><svg style="color:rgb(40, 167, 69)"></svg><div><span>${recon}</span><button>Hint</button><button>Solution</button></div></div>
    <div style="color:rgb(74, 85, 104)"><svg style="color:rgb(160, 174, 192)"></svg><div><span>${incomplete}</span></div></div>
  </div><div>11/110 objectives</div>
  <div id="admin-card"><div><div><h3>MCP Server Lab</h3></div></div><button>Manage Objectives</button></div>
  <div id="modal"><div><h3>Objectives — MCP Server Lab</h3></div>
    ${ids.map((id) => `<div><div><div>${id}</div></div><div><div style="background-color:rgb(72, 187, 120)"></div></div><div><div style="background-color:rgb(72, 187, 120)"></div></div><div><div style="background-color:rgb(203, 213, 224)"></div></div><div></div></div>`).join('')}
  </div>
</body>`);
const document = dom.window.document;
assert.equal(helpers.mcpCardMatches(1, 11, ['37s'], [], document), true);
document.querySelector('#count').textContent = '11/110 objectives';
assert.equal(helpers.mcpCardMatches(1, 11, ['37s'], [], document), false);
document.querySelector('#count').textContent = '1/11 objectives';
assert.equal(helpers.mcpCardMatches(1, 11, ['37s'], [recon], document), false);
assert.equal(helpers.mcpObjectiveStylesMatch(recon, incomplete, true, document), true);
assert.equal(helpers.mcpObjectiveHelpControlsMatch(recon, true, true, document), true);
assert.equal(helpers.mcpAdminModalMatches(ids, true, false, document), true);
const reconRow = [...document.querySelectorAll('#modal *')]
  .find(node => node.children.length === 0 && node.textContent === 'mcp_recon').parentElement.parentElement;
reconRow.children[1].firstElementChild.style.backgroundColor = 'rgb(203, 213, 224)';
assert.equal(helpers.mcpAdminModalMatches(ids, true, false, document), false);
reconRow.children[1].firstElementChild.style.backgroundColor = 'rgb(72, 187, 120)';
reconRow.children[2].firstElementChild.style.backgroundColor = 'rgb(203, 213, 224)';
assert.equal(helpers.mcpAdminModalMatches(ids, true, false, document), false);
assert.equal(helpers.mcpAdminModalMatches(ids, false, false, document), true);
let hintClicks = 0;
reconRow.children[2].firstElementChild.addEventListener('click', () => { hintClicks += 1; });
assert.equal(helpers.clickMcpReconHint(document), true);
assert.equal(hintClicks, 1);
reconRow.children[2].firstElementChild.style.backgroundColor = 'rgb(72, 187, 120)';
const secondId = [...document.querySelectorAll('#modal *')]
  .find(node => node.children.length === 0 && node.textContent === 'mcp_cmd_injection');
secondId.textContent = 'mcp_wrong_order';
assert.equal(helpers.mcpAdminModalMatches(ids, true, false, document), false);
secondId.textContent = 'mcp_cmd_injection';
reconRow.children[3].firstElementChild.style.backgroundColor = 'rgb(72, 187, 120)';
assert.equal(helpers.mcpAdminModalMatches(ids, true, true, document), true);
let solutionClicks = 0;
reconRow.children[3].firstElementChild.addEventListener('click', () => { solutionClicks += 1; });
assert.equal(helpers.clickMcpReconSolution(document), true);
assert.equal(solutionClicks, 1);
document.querySelector('#done button').remove();
assert.equal(helpers.mcpObjectiveHelpControlsMatch(recon, true, true, document), false);
assert.equal(helpers.mcpObjectiveHelpControlsMatch(recon, false, true, document), true);
let manageClicks = 0;
document.querySelector('#admin-card button').addEventListener('click', () => { manageClicks += 1; });
assert.equal(helpers.clickMcpManageObjectives(document), true);
assert.equal(manageClicks, 1);
document.querySelector('#done').remove();
assert.equal(helpers.mcpObjectiveStylesMatch(recon, incomplete, false, document), true);
console.log('MCP_DOM_HELPERS_OK');
'''
        environment = {name: os.environ[name] for name in ('PATH', 'TMPDIR', 'TMP', 'TEMP')
                       if name in os.environ}
        environment['NODE_ENV'] = 'test'
        result = subprocess.run(['node', '-e', script], cwd=LAUNCHER_PATH.parents[2],
                                env=environment, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MCP_DOM_HELPERS_OK', result.stdout)

    @unittest.skipUnless(os.environ.get('ADMIN_AUTH_BROWSER_PACKAGE_ROOT'),
                         'frozen package root not supplied')
    def test_declared_frozen_package_has_exact_manifest(self):
        package = Path(os.environ['ADMIN_AUTH_BROWSER_PACKAGE_ROOT']).resolve()
        verified = LAUNCHER.verify_manifest(package, package / 'manifest.json')
        self.assertEqual(verified['qualification'], 'native-source-candidate')

    def test_exact_four_suite_and_database_plan(self):
        self.assertEqual([suite['name'] for suite in LAUNCHER.SUITES],
            ['authHttp', 'adminHttp', 'adminProgressAnalytics', 'adminProductionAuthBrowser'])
        plan = LAUNCHER.database_plan('a1b2c3d4e5f6')
        self.assertEqual(plan, {
            'authHttp': 'dvaia_test_auth_http_a1b2c3d4e5f6',
            'adminHttp': 'dvaia_test_admin_http_a1b2c3d4e5f6',
            'adminProgressAnalytics': 'dvaia_test_admin_analytics_a1b2c3d4e5f6',
            'adminProductionAuthBrowser': 'dvaia_test_admin_browser_a1b2c3d4e5f6',
        })
        analytics = LAUNCHER.SUITES[2]
        self.assertEqual(analytics['migrationVariable'],
            'PG_ADMIN_ANALYTICS_TEST_MIGRATION_URL')
        self.assertEqual(analytics['runtimeVariable'],
            'PG_ADMIN_ANALYTICS_TEST_RUNTIME_URL')
        self.assertIsNone(analytics['gate'])
        self.assertEqual(LAUNCHER.POSTGRES_IMAGE_ID,
            'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280')
        self.assertEqual(LAUNCHER.DOCKER_HOST,
            'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock')

    def test_manifest_accepts_only_exact_readonly_source_and_dependency_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            package, manifest = make_package(directory)
            verified = LAUNCHER.verify_manifest(package, manifest)
            self.assertEqual(verified['semanticEffectsQualified'], [])
            unexpected = package / 'source/unexpected.js'
            source = package / 'source'
            os.chmod(source, 0o755)
            unexpected.write_text('drift')
            os.chmod(unexpected, 0o444)
            os.chmod(source, 0o555)
            with self.assertRaisesRegex(RuntimeError, 'inventory mismatch'):
                LAUNCHER.verify_manifest(package, manifest)
            os.chmod(source, 0o755)
            unexpected.unlink()
            os.chmod(source, 0o555)
            target = package / 'source/tests/postgres/authHttp.integration.test.js'
            os.chmod(target, 0o644)
            with self.assertRaisesRegex(RuntimeError, 'writable frozen file'):
                LAUNCHER.verify_manifest(package, manifest)

    def test_postflight_pins_original_manifest_and_managed_runtime_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            package, manifest_path = make_package(directory)
            manifest = json.loads(manifest_path.read_text())
            node = Path(directory) / 'node'
            chromium = Path(directory) / 'chromium'
            node.write_text('node-v26')
            chromium.write_text('chromium')
            arguments = (package, manifest_path, manifest, LAUNCHER.sha256(manifest_path),
                         node, LAUNCHER.sha256(node), chromium, LAUNCHER.sha256(chromium))
            LAUNCHER.verify_postflight_identity(*arguments)
            chromium.write_text('replacement')
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                LAUNCHER.verify_postflight_identity(*arguments)

    def test_tap_contract_rejects_skips_and_requires_one_real_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'suite.tap'
            log.write_text('# pass 1\n# fail 0\n# skipped 0\n')
            self.assertRegex(LAUNCHER.verify_tap(log), r'^[0-9a-f]{64}$')
            log.write_text('# pass 0\n# fail 0\n# skipped 1\n')
            with self.assertRaisesRegex(RuntimeError, 'exactly one pass'):
                LAUNCHER.verify_tap(log)

    def test_browser_journal_binds_paths_loopback_and_completed_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / 'admin-browser-runtime'
            journal = root / 'admin-browser-resources.json'
            value = {
                'version': 1,
                'status': 'cleanup_complete',
                'testBody': 'passed',
                'tempRootAbsent': True,
                'externalCleanupAuthority': 'launcher-owned-test-process-group-and-database',
                'resources': {
                    'tempRoot': str(runtime),
                    'buildDirectory': str(runtime / 'build'),
                    'profileDirectory': str(runtime / 'chromium-profile'),
                    'build': {'pid': 2147483001, 'pgid': 2147483001},
                    'browser': {'pid': 2147483002},
                    'server': {'address': '127.0.0.1', 'port': 49152},
                },
                'cleanup': [{'name': 'browser-close', 'ok': True}],
            }
            journal.write_text(json.dumps(value))
            os.chmod(journal, 0o600)
            self.assertEqual(LAUNCHER.load_browser_resource_journal(
                journal, runtime, require_terminal=True), value)
            value['resources']['server']['address'] = '0.0.0.0'
            journal.write_text(json.dumps(value))
            with self.assertRaisesRegex(RuntimeError, 'cleanup was not proven'):
                LAUNCHER.load_browser_resource_journal(journal, runtime, require_terminal=True)

    def test_uncertain_container_create_removes_only_exact_labeled_identity(self):
        container_id = 'a' * 64
        name = 'dvaia-admin-auth-browser-' + 'b' * 12
        labels = {
            'dvaia.owner': '/root', 'dvaia.grant': 'grant',
            'dvaia.scope': LAUNCHER.SCOPE, 'dvaia.nonce': 'b' * 12,
        }
        calls = []
        original = LAUNCHER.run
        def fake_run(command, **_kwargs):
            calls.append(command)
            if command[-2:] == ['inspect', name]:
                body = [{'Id': container_id, 'Name': '/' + name, 'Config': {'Labels': labels}}]
                return subprocess.CompletedProcess(command, 0, json.dumps(body), '')
            if command[-3:] == ['rm', '--force', container_id]:
                return subprocess.CompletedProcess(command, 0, '', '')
            raise AssertionError(command)
        LAUNCHER.run = fake_run
        try:
            self.assertEqual(LAUNCHER.remove_owned_container(['docker'], name, None, labels),
                container_id)
        finally:
            LAUNCHER.run = original
        self.assertEqual(calls[-1][-1], container_id)

        wrong = dict(labels, **{'dvaia.owner': '/other'})
        LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(command, 0,
            json.dumps([{'Id': container_id, 'Name': '/' + name,
                         'Config': {'Labels': wrong}}]), '')
        try:
            with self.assertRaisesRegex(RuntimeError, 'unowned container'):
                LAUNCHER.remove_owned_container(['docker'], name, None, labels)
        finally:
            LAUNCHER.run = original

    def test_paths_and_docker_absence_are_bound_to_exact_requested_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / 'real'
            real.mkdir()
            linked = root / 'linked'
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlink ancestry forbidden'):
                LAUNCHER.resolve_without_symlinks(linked / 'future', 'fixture', must_exist=False)

        original = LAUNCHER.run
        try:
            LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, '', 'Error: No such object: another-container')
            with self.assertRaisesRegex(RuntimeError, 'absence could not be verified'):
                LAUNCHER.docker_object_absent(['docker'], 'owned-container')
            LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, '', 'Error: No such object: owned-container-extra')
            with self.assertRaisesRegex(RuntimeError, 'absence could not be verified'):
                LAUNCHER.docker_object_absent(['docker'], 'owned-container')
            LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, '', 'Error: No such object: owned-container')
            self.assertTrue(LAUNCHER.docker_object_absent(['docker'], 'owned-container'))
            LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, '', 'Error: No such container: another-container')
            with self.assertRaisesRegex(RuntimeError, 'inspection failed'):
                LAUNCHER.remove_owned_container(['docker'], 'owned-container', None, {})
            LAUNCHER.run = lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 1, '', 'Error: No such container: owned-container-extra')
            with self.assertRaisesRegex(RuntimeError, 'inspection failed'):
                LAUNCHER.remove_owned_container(['docker'], 'owned-container', None, {})
        finally:
            LAUNCHER.run = original

    def test_import_is_inert_and_chromium_wrapper_records_before_exec(self):
        source = LAUNCHER_PATH.read_text()
        self.assertIn("if __name__ == '__main__':", source)
        self.assertIn('os.fsync(output.fileno())', LAUNCHER.CHROMIUM_WRAPPER_SOURCE)
        self.assertIn('os.execv(actual', LAUNCHER.CHROMIUM_WRAPPER_SOURCE)
        self.assertNotIn('docker run', LAUNCHER.CHROMIUM_WRAPPER_SOURCE)
        self.assertIn("wrapper_resources['pgid'] != wrapper_resources['pid']", source)


if __name__ == '__main__':
    unittest.main()
