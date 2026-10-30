"""Nonallocating controls for the deliberately blocked deletion plan."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import admin_student_deletion_current_host as admission


ROOT = Path(__file__).resolve().parents[2]


class StudentDeletionPlanTests(unittest.TestCase):
    def test_store_names_and_variable_prefixes_match_production_manifest(self):
        source = (ROOT / 'db/postgres/initialize-application.js').read_text()
        rows = tuple(re.findall(r"\['([a-z_]+)',\s*'([A-Z_]+)',", source))
        self.assertEqual(rows, admission.STORES)
        self.assertEqual(len(rows), 16)

    def test_canonical_sixteen_database_names_and_role_variables(self):
        rows = admission.database_plan('a' * 12)
        self.assertEqual(len(rows), 16)
        self.assertEqual(len({r['database'] for r in rows}), 16)
        self.assertEqual(rows[0], {
            'schema': 'identity',
            'database': 'owasp_ai_goat_test_student_deletion_aaaaaaaaaaaa_identity',
            'runtimeVariable': 'IDENTITY_DATABASE_URL',
            'migrationVariable': 'IDENTITY_MIGRATION_DATABASE_URL',
        })
        self.assertTrue(all(len(r['database'].encode()) <= 63 for r in rows))
        self.assertEqual(rows[-1]['schema'], 'secureshop_review')

    def test_nonce_and_identifier_limit_fail_closed(self):
        for nonce in ('', 'A' * 12, '../etc/passwd', 'a' * 13, None):
            with self.subTest(nonce=nonce), self.assertRaises(RuntimeError):
                admission.database_plan(nonce)
        with patch.object(admission, 'STORES', (('x' * 40, 'X'),) * 16):
            with self.assertRaises(RuntimeError):
                admission.database_plan('a' * 12)

    def test_limit_envelope_is_closed_and_counted(self):
        self.assertEqual(admission.LIMITS, {
            'containers': 1, 'stores': 16, 'baseStoreRoles': 32,
            'dedicatedCtfDeliveryRoles': 1, 'totalLoginRoles': 33,
            'provisioningAdminExcludedFromRoleCount': True,
            'memoryBytes': 2 * 1024 ** 3, 'memorySwapBytes': 2 * 1024 ** 3,
            'cpus': 2, 'pids': 256,
            'postgresTmpfsBytes': 1024 ** 3, 'maxConnections': 96,
            'aggregatePoolBudget': 78, 'migrationOrder': 'sequential',
            'migrationPoolsDrainedBeforeRendered': True, 'actualModelCalls': 0,
        })

    def test_dedicated_ctf_delivery_role_is_outside_base_manifest(self):
        production = (ROOT / 'server/services/ctfAuthorityProduction.js').read_text()
        pool = (ROOT / 'server/database/postgres/ctfDeliveryPool.js').read_text()
        migration = (ROOT / 'db/postgres/workshop-migrations/ctf/0011_delivery_activation.sql').read_text()
        self.assertIn('createCtfDeliveryPool({env:config.env,activation}', production)
        self.assertIn("env.CTF_DELIVERY_DATABASE_URL", pool)
        self.assertIn("'dvaia_ctf_delivery'", pool)
        self.assertIn("session_user='dvaia_ctf_delivery'", migration)
        self.assertNotIn('CTF_DELIVERY_DATABASE_URL', {row['runtimeVariable']
            for row in admission.database_plan('a' * 12)})

    def test_store_plan_digest_matches_node_grant_serialization(self):
        nonce = 'b' * 12
        rows = [{'database': row['database'], 'schema': row['schema']}
                for row in admission.database_plan(nonce)]
        expected = hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(admission.store_plan_sha256(nonce), expected)
        self.assertIn('JSON.stringify(rows.map(({ database, schema }) => ({ database, schema })))',
                      (ROOT / 'tests/postgres/adminStudentDeletionRendered.integration.test.js').read_text())

    def test_deletion_snapshot_includes_actual_transitive_agent_and_sidecar_sources(self):
        from full_backend_auth_contract import student_deletion_source_closure
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        closure = student_deletion_source_closure(ROOT, node)
        snapshot = admission.deletion_source_files(ROOT)
        self.assertTrue(closure <= set(snapshot))
        self.assertIn('agent-host/shared/vectorStore.js', snapshot)
        self.assertIn('sidecars/sandbox-runner/owned-mcp-registry/http-handler.js', snapshot)

    def test_private_one_worker_grant_has_exact_profile_and_rejects_aliases(self):
        nonce = 'b' * 12
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/qualification') as temporary:
            parent = Path(temporary)
            run = parent / ('run-admin-student-deletion-' + nonce)
            runtime = run / 'runtime'
            tmp = runtime / 'tmp'
            tmp.mkdir(parents=True, mode=0o700)
            run.chmod(0o700)
            runtime.chmod(0o700)
            tmp.chmod(0o700)
            profile = tmp / ('owasp-ai-goat-student-deletion-browser-' + nonce)
            args = SimpleNamespace(build_sha256='a'*64, snapshot_sha256='b'*64,
                chromium=str(ROOT / 'tests/postgres/adminStudentDeletionRenderedSupport.js'))
            with patch.object(admission, 'evidence_parent', return_value=parent):
                grant = admission.admission_grant(ROOT, run, nonce, args, 321, profile)
                self.assertEqual(grant['storePlanSha256'], admission.store_plan_sha256(nonce))
                self.assertEqual(grant['workerPid'], 321)
                self.assertEqual(grant['profile'], str(profile))
                self.assertEqual(grant['outerSandbox'], 'repository-only')
                for bad in (profile.parent / 'wrong', profile.parent.parent / profile.name):
                    with self.assertRaisesRegex(RuntimeError, 'profile'):
                        admission.admission_grant(ROOT, run, nonce, args, 321, bad)
                with self.assertRaisesRegex(RuntimeError, 'worker PID'):
                    admission.admission_grant(ROOT, run, nonce, args, True, profile)
                tmp.chmod(0o755)
                with self.assertRaisesRegex(RuntimeError, 'private student-deletion runtime'):
                    admission.admission_grant(ROOT, run, nonce, args, 321, profile)

    def test_run_syntax_requires_exact_reviewed_snapshot_and_keeps_proof_gate(self):
        values = {name: 'test' for name in (
            'node', 'node-sha256', 'docker', 'docker-sha256', 'docker-host',
            'daemon-id', 'image-id', 'current-host-profile', 'chromium',
            'chromium-sha256', 'browser-root', 'python-sha256', 'build-sha256',
            'build-report', 'build-report-sha256', 'build-input-sha256',
            'build-output-sha256', 'build-recorder-sha256', 'source-sha256')}
        arguments = ['--run', '--nonce', 'a'*12]
        for name, value in values.items():
            arguments.extend(('--' + name, value))
        with self.assertRaisesRegex(RuntimeError, 'snapshot'):
            admission.parse(arguments)
        parsed = admission.parse([*arguments, '--snapshot-sha256', 'a'*64])
        self.assertIs(parsed.run, True)
        self.assertIs(parsed.plan, False)
        self.assertEqual(admission.blockers(ROOT), ())

    def test_duplicate_flags_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            admission.parse(['--plan', '--plan'])

    def test_reviewed_support_hashes_are_exact(self):
        admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionRenderedSupport.js',
                                admission.SUPPORT_SHA256)
        admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionSeedSupport.js',
                                admission.SEED_SUPPORT_SHA256)
        admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionArtifactSupport.js',
                                admission.ARTIFACT_SUPPORT_SHA256)
        admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionNetworkGuard.js',
                                admission.NETWORK_GUARD_SHA256)
        admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionSecureShopSupport.js',
                                admission.SECURESHOP_SUPPORT_SHA256)
        admission.reviewed_file(ROOT, 'tests/fixtures/studentDeletionSourceClosure.js',
                                admission.AST_HELPER_SHA256)
        with self.assertRaisesRegex(RuntimeError, 'pin mismatch'):
            admission.reviewed_file(ROOT, 'tests/postgres/adminStudentDeletionRenderedSupport.js', '0' * 64)

    def test_only_actual_missing_source_or_unresolved_closure_blocks_plan(self):
        self.assertEqual(admission.blockers(ROOT), ())
        self.assertIn('canonical-deletion-source-closure-unresolved', admission.blockers(ROOT, 'unresolved'))

    def test_plan_is_eligible_but_nonexecuting_with_pinned_inputs(self):
        source = {'server/services/studentDeletionApplication.js': 'a' * 64}
        build = {'index.html': 'b' * 64}
        browser = ROOT / 'tests/postgres/adminStudentDeletionRenderedSupport.js'
        args = argparse.Namespace(nonce='a' * 12, source_sha256=admission.encoded(source),
            build_sha256=admission.encoded(build), chromium=str(browser),
            browser_root=str(browser.parent), chromium_sha256=admission.sha(browser),
            python_sha256=admission.sha(Path(sys.executable).resolve()),
            current_host_profile='goat-q', docker_host='unix:///owned/socket',
            node='node', node_sha256='n' * 64, docker='docker', docker_sha256='d' * 64,
            daemon_id='owned', image_id='sha256:' + 'a' * 64)
        with patch.object(admission, 'deletion_source_files', return_value=source), \
             patch.object(admission, 'files', return_value=build), \
             patch.object(admission, 'inventory', return_value={'chrome': 'c' * 64}), \
             patch.object(admission, 'student_deletion_source_closure',
                          return_value=frozenset(source)) as closure:
            result = admission.plan(args, repo=ROOT,
                host_validator=lambda **kwargs: {'profile': kwargs['profile']},
                build_validator=lambda *_args: {'qualified': True})
        self.assertIs(result['eligible'], True)
        self.assertIs(result['actualExecution'], False)
        self.assertIs(result['sourceCopy'], False)
        self.assertEqual(result['limits']['stores'], 16)
        self.assertEqual(result['sourceClosureFiles'], 1)
        closure.assert_called_once_with(ROOT, 'node')
        self.assertEqual(result['blockers'], ())

    def test_wrong_source_snapshot_blocks_before_host_or_build_checks(self):
        args = argparse.Namespace(nonce='a' * 12, source_sha256='0' * 64)
        with patch.object(admission, 'deletion_source_files', return_value={'x': 'y'}):
            with self.assertRaisesRegex(RuntimeError, 'source snapshot'):
                admission.plan(args, repo=ROOT, host_validator=lambda **_: self.fail('host called'),
                               build_validator=lambda *_: self.fail('build called'))

    def test_snapshot_binds_source_build_both_dependency_trees_and_physical_python(self):
        source = {'tests/postgres/adminStudentDeletionInitialize.js': 'a'*64}
        build = {'index.html': 'b'*64}
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        docker = ROOT / 'tasks/runtime/container/bin/docker'
        args = argparse.Namespace(source_sha256=admission.encoded(source),
            build_sha256=admission.encoded(build),
            python_sha256=admission.sha(Path(sys.executable).resolve()),
            node=str(node), node_sha256=admission.sha(node),
            docker=str(docker), docker_sha256=admission.sha(docker),
            browser_root=str(ROOT / 'tests/postgres'),
            current_host_profile='owned', docker_host='unix:///owned/socket',
            daemon_id='owned', image_id='sha256:'+'a'*64,
            chromium=str(ROOT / 'tests/postgres/adminStudentDeletionRenderedSupport.js'),
            chromium_sha256='c'*64, nonce='a'*12)
        observed = []
        def inventory(directory):
            observed.append(str(directory))
            return {'reviewed': 'd'*64}
        with patch.object(admission, 'deletion_source_files', return_value=source), \
             patch.object(admission, 'files', return_value=build), \
             patch.object(admission, 'inventory', side_effect=inventory), \
             patch.object(admission, 'physical_python', return_value=str(Path(sys.executable).resolve())):
            snap = admission.snapshot(ROOT, args, {'sourceSha256': args.source_sha256,
                'buildProvenance': {'qualified': True}})
            self.assertEqual(snap['source'], source)
            self.assertEqual(snap['build'], build)
            self.assertEqual(snap['dependencies']['root'], {'reviewed': 'd'*64})
            self.assertEqual(snap['dependencies']['client'], {'reviewed': 'd'*64})
            self.assertIn(str(ROOT / 'node_modules'), observed)
            self.assertIn(str(ROOT / 'client/node_modules'), observed)
            self.assertEqual(snap['executionPins']['storePlanSha256'],
                admission.store_plan_sha256('a'*12))

    def test_outside_inspector_parent_and_repository_boundary_are_exact(self):
        parent = 321
        argv = ['--run', '--nonce', 'a'*12]
        fixed = str(ROOT / 'tests/postgres/run_admin_student_deletion_with_inspector.py')
        class API:
            def identity(self, pid):
                return SimpleNamespace(uid=99, ruid=99, start_sec=12, start_usec=34) \
                    if pid == parent else None
            def arguments(self, pid):
                return ['/owned/python', '-B', fixed, *argv] if pid == parent else []
        api = API()
        inspector = SimpleNamespace(parent=parent)
        denied = lambda path: str(path) == '/private/tmp'
        with patch.object(admission.os, 'getppid', return_value=parent), \
             patch.object(admission.os, 'getuid', return_value=99), \
             patch.object(admission, 'physical_python', return_value='/owned/python'):
            admission.verify_outer_boundary(ROOT, argv, inspector, api=api, denied=denied)
            with self.assertRaisesRegex(RuntimeError, 'Repository-only'):
                admission.verify_outer_boundary(ROOT, argv, inspector, api=api,
                    denied=lambda _path: False)
            with self.assertRaisesRegex(RuntimeError, 'Inspector is not current direct parent'):
                admission.verify_outer_boundary(ROOT, argv,
                    SimpleNamespace(parent=parent+1), api=api, denied=denied)
            with self.assertRaisesRegex(RuntimeError, 'invocation'):
                admission.verify_outer_boundary(ROOT, [*argv, '--extra'], inspector,
                    api=api, denied=denied)

    def test_installed_build_dependency_provenance_precedes_ast_execution(self):
        source = {'server/services/studentDeletionApplication.js': 'a'*64}
        build = {'index.html': 'b'*64}
        browser = ROOT / 'tests/postgres/adminStudentDeletionRenderedSupport.js'
        args = argparse.Namespace(nonce='a'*12, source_sha256=admission.encoded(source),
            build_sha256=admission.encoded(build), chromium=str(browser),
            browser_root=str(browser.parent), chromium_sha256=admission.sha(browser),
            python_sha256=admission.sha(Path(sys.executable).resolve()),
            current_host_profile='goat-q', docker_host='unix:///owned/socket',
            node='node', node_sha256='n'*64, docker='docker', docker_sha256='d'*64,
            daemon_id='owned', image_id='sha256:'+'a'*64)
        with patch.object(admission, 'deletion_source_files', return_value=source), \
             patch.object(admission, 'files', return_value=build), \
             patch.object(admission, 'student_deletion_source_closure') as scanner:
            with self.assertRaisesRegex(RuntimeError, 'installed dependencies changed'):
                admission.plan(args, repo=ROOT,
                    host_validator=lambda **_: {'owned': True},
                    build_validator=lambda *_: (_ for _ in ()).throw(RuntimeError('installed dependencies changed')))
            scanner.assert_not_called()

    def test_checkout_cannot_be_substituted(self):
        with self.assertRaisesRegex(RuntimeError, 'existing checkout'):
            admission.plan(argparse.Namespace(), repo=ROOT / 'tests')


if __name__ == '__main__':
    unittest.main()
