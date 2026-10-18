import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_PATH = Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
ADMISSION_PATH = Path(__file__).with_name('admin_browser_current_main_admission.py')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load('admin_browser_current_main_launcher', LAUNCHER_PATH)
admission = load('admin_browser_current_main_admission_test', ADMISSION_PATH)


def write(path, value='fixture\n'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def fixture(root):
    root = Path(root).resolve()
    for relative in admission.REQUIRED_SOURCE:
        write(root / relative, relative + '\n')
    write(root / 'db/postgres/identity-migrations/0001_fixture.sql', 'SELECT 1;\n')
    write(root / 'node_modules/pg/package.json', '{}\n')
    write(root / 'node_modules/puppeteer/package.json', '{}\n')
    write(root / 'client/node_modules/vite/package.json', '{}\n')
    node = root.parent / 'runtime/node'
    browser_root = root.parent / 'runtime/browser'
    chromium = browser_root / 'Chromium'
    write(node, 'managed node\n')
    write(chromium, 'managed browser\n')
    return root, node, chromium, browser_root


class Selector(unittest.TestCase):
    def tearDown(self):
        launcher.configure_cohort('full')

    def test_closed_selector_reuses_only_existing_browser_suite(self):
        launcher.configure_cohort('admin-browser-current-main')
        self.assertEqual([row['name'] for row in launcher.SUITES],
                         ['adminProductionAuthBrowser'])
        self.assertIs(launcher.SUITES[0], launcher.FULL_SUITES[3])
        self.assertEqual(launcher.SCOPE, admission.SCOPE)
        self.assertEqual(launcher.NODE_VERSION, admission.NODE_VERSION)
        self.assertEqual(launcher.database_plan('abcdef123456'), {
            'adminProductionAuthBrowser': 'dvaia_test_admin_browser_abcdef123456',
        })
        env = launcher.suite_environment({}, launcher.SUITES[0],
            launcher.database_plan('abcdef123456'), 55432)
        self.assertEqual(env['RUN_ADMIN_PRODUCTION_BROWSER'], '1')
        self.assertIn('dvaia_identity_migration@127.0.0.1:55432',
                      env['PG_ADMIN_BROWSER_TEST_MIGRATION_URL'])
        self.assertIn('dvaia_identity_runtime@127.0.0.1:55432',
                      env['PG_ADMIN_BROWSER_TEST_RUNTIME_URL'])
        self.assertEqual(launcher.cohort_resource_args('admin-browser-current-main'),
                         ['--memory', '1g', '--cpus', '1', '--pids-limit', '128'])

    def test_default_immutable_cohort_is_unchanged(self):
        launcher.configure_cohort('full')
        self.assertEqual(launcher.SUITES, launcher.FULL_SUITES)
        self.assertEqual(launcher.SCOPE, launcher.FULL_SCOPE)
        self.assertEqual(launcher.NODE_VERSION, launcher.FULL_NODE_VERSION)

    def test_parser_exposes_only_explicit_current_main_admission_fields(self):
        required = ('package-root', 'manifest', 'managed-node', 'chromium', 'docker-host',
            'postgres-image-id', 'container-nonce', 'evidence-root', 'grant-file',
            'grant-id', 'owner', 'owner-handle-file', 'canonical-workspace', 'scope')
        argv = [item for name in required for item in ('--' + name, '/fixture')]
        args = launcher.parse_args(argv + ['--cohort', 'admin-browser-current-main',
            '--main-workspace', '--manifest-sha256', 'a' * 64, '--browser-root', '/browser',
            '--python-sha256', 'b' * 64, '--await-grant',
            '--launcher-pid-file', '/launcher-pid'])
        self.assertTrue(args.main_workspace)
        self.assertEqual(args.cohort, 'admin-browser-current-main')
        self.assertEqual(args.manifest_sha256, 'a' * 64)
        self.assertEqual(args.browser_root, '/browser')
        self.assertEqual(args.python_sha256, 'b' * 64)
        self.assertTrue(args.await_grant)
        self.assertEqual(args.launcher_pid_file, '/launcher-pid')


class Admission(unittest.TestCase):
    def test_live_launch_handshake_publishes_pid_and_accepts_fresh_session_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'main'
            boundary = source / admission.PRIVATE_EVIDENCE_RELATIVE
            boundary.mkdir(parents=True)
            for path in (source / 'backups', source / 'backups/private-recovery', boundary):
                os.chmod(path, 0o700)
            nonce = 'abcdef123456'
            pid_path = boundary / f'launcher-pid-{nonce}.txt'
            grant_path = boundary / f'grant-{nonce}.json'
            handle_path = boundary / f'owner-handle-{nonce}.txt'
            admission.publish_launcher_pid(source, pid_path, nonce)
            self.assertEqual(pid_path.read_text(), f'{os.getpid()}\n')
            self.assertEqual(pid_path.stat().st_mode & 0o777, 0o600)
            handle_path.write_text('54321\n'); os.chmod(handle_path, 0o600)
            grant_path.write_text(json.dumps({'status': 'granted',
                'expectedLauncherPid': os.getpid(), 'expectedOwnerHandle': 54321,
                'ownerHandle': None}) + '\n'); os.chmod(grant_path, 0o600)
            self.assertEqual(admission.wait_for_launch_authorization(
                source, grant_path, handle_path, nonce, timeout_seconds=.01,
                poll_seconds=.001), 54321)
            with self.assertRaises(FileExistsError):
                admission.publish_launcher_pid(source, pid_path, nonce)

    def test_live_launch_handshake_rejects_stale_or_mismatched_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'main'
            boundary = source / admission.PRIVATE_EVIDENCE_RELATIVE
            boundary.mkdir(parents=True)
            for path in (source / 'backups', source / 'backups/private-recovery', boundary):
                os.chmod(path, 0o700)
            nonce = 'abcdef123456'
            grant_path = boundary / f'grant-{nonce}.json'
            handle_path = boundary / f'owner-handle-{nonce}.txt'
            handle_path.write_text('99606\n'); os.chmod(handle_path, 0o600)
            grant_path.write_text(json.dumps({'status': 'granted',
                'expectedLauncherPid': os.getpid() + 1, 'expectedOwnerHandle': 99606,
                'ownerHandle': None}) + '\n'); os.chmod(grant_path, 0o600)
            with self.assertRaisesRegex(RuntimeError, 'created by the live session'):
                admission.require_fresh_launch_authorization(
                    source, grant_path, handle_path, nonce)
            with self.assertRaisesRegex(RuntimeError, 'binding invalid'):
                admission.wait_for_launch_authorization(source, grant_path, handle_path,
                    nonce, timeout_seconds=.01, poll_seconds=.001)

    def test_current_main_evidence_accepts_only_fresh_nonce_bound_private_child(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'main'
            boundary = source / admission.PRIVATE_EVIDENCE_RELATIVE
            boundary.mkdir(parents=True)
            os.chmod(source / 'backups', 0o700)
            os.chmod(source / 'backups/private-recovery', 0o700)
            os.chmod(boundary, 0o700)
            evidence = boundary / 'run-abcdef123456'
            self.assertEqual(admission.validate_evidence_path(
                source, evidence, 'abcdef123456'), evidence)
            with self.assertRaisesRegex(RuntimeError, 'exact private checkout path'):
                admission.validate_evidence_path(
                    source, Path(directory).resolve() / 'outside', 'abcdef123456')
            with self.assertRaisesRegex(RuntimeError, 'exact private checkout path'):
                admission.validate_evidence_path(source, boundary, 'abcdef123456')
            evidence.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'fresh'):
                admission.validate_evidence_path(source, evidence, 'abcdef123456')

    def test_current_main_evidence_rejects_symlink_ancestry_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'main'
            private = root / 'private'
            private.mkdir()
            os.chmod(private, 0o700)
            (source / 'backups').mkdir(parents=True)
            os.chmod(source / 'backups', 0o700)
            (source / 'backups/private-recovery').symlink_to(private, target_is_directory=True)
            evidence = source / admission.PRIVATE_EVIDENCE_RELATIVE / 'run-abcdef123456'
            with self.assertRaisesRegex(RuntimeError, 'ancestry'):
                admission.validate_evidence_path(source, evidence, 'abcdef123456')

            (source / 'backups/private-recovery').unlink()
            boundary = source / admission.PRIVATE_EVIDENCE_RELATIVE
            boundary.mkdir(parents=True)
            os.chmod(source / 'backups/private-recovery', 0o700)
            os.chmod(boundary, 0o755)
            with self.assertRaisesRegex(RuntimeError, 'owned and private'):
                admission.validate_evidence_path(source, evidence, 'abcdef123456')

            os.chmod(boundary, 0o700)
            evidence.symlink_to(root / 'private-run', target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlink forbidden'):
                admission.validate_evidence_path(source, evidence, 'abcdef123456')

    def test_exact_source_dependency_browser_and_runtime_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            source, node, chromium, browser_root = fixture(Path(directory) / 'main')
            manifest = admission.capture(source, node, chromium, browser_root)
            manifest_path = Path(directory) / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
            os.chmod(manifest_path, 0o600)
            manifest_sha = admission.digest(manifest_path)
            with patch.object(admission, 'NODE_SHA256', admission.digest(node)):
                self.assertEqual(admission.validate(source, manifest_path, manifest_sha,
                    admission.digest(Path(sys.executable).resolve()), node, chromium, browser_root), manifest)
                self.assertTrue(admission.verify_postflight(source, manifest_path,
                    manifest_sha, admission.digest(Path(sys.executable).resolve()), manifest,
                    node, chromium, browser_root))

                write(source / 'server/routes/adminExercises.js', 'drift\n')
                with self.assertRaisesRegex(RuntimeError, 'sourcePins'):
                    admission.validate(source, manifest_path, manifest_sha,
                        admission.digest(Path(sys.executable).resolve()), node, chromium, browser_root)

    def test_installed_dependency_and_browser_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, node, chromium, browser_root = fixture(Path(directory) / 'main')
            manifest = admission.capture(source, node, chromium, browser_root)
            manifest_path = Path(directory) / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
            os.chmod(manifest_path, 0o600)
            manifest_sha = admission.digest(manifest_path)
            with patch.object(admission, 'NODE_SHA256', admission.digest(node)):
                write(source / 'node_modules/pg/package.json', '{"changed":true}\n')
                with self.assertRaisesRegex(RuntimeError, 'dependencyInventory'):
                    admission.validate(source, manifest_path, manifest_sha,
                        admission.digest(Path(sys.executable).resolve()), node, chromium, browser_root)
                write(source / 'node_modules/pg/package.json', '{}\n')
                write(chromium, 'replacement browser\n')
                with self.assertRaisesRegex(RuntimeError, 'runtimePins'):
                    admission.validate(source, manifest_path, manifest_sha,
                        admission.digest(Path(sys.executable).resolve()), node, chromium, browser_root)

    def test_manifest_boundary_and_required_closure_are_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            source, node, chromium, browser_root = fixture(Path(directory) / 'main')
            manifest = admission.capture(source, node, chromium, browser_root)
            manifest['mode'] = 'actual-model'
            manifest_path = Path(directory) / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
            os.chmod(manifest_path, 0o600)
            with patch.object(admission, 'NODE_SHA256', admission.digest(node)), \
                    self.assertRaisesRegex(RuntimeError, 'boundary'):
                admission.validate(source, manifest_path, admission.digest(manifest_path),
                    admission.digest(Path(sys.executable).resolve()), node, chromium, browser_root)

    def test_grant_binds_candidate_to_main_checkout_in_new_selector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            handle = root / 'owner.txt'
            handle.write_text('123\n')
            args = types.SimpleNamespace(package_root=str(root), canonical_workspace=str(root),
                owner_handle_file=str(handle), container_nonce='abcdef123456', grant_id='grant',
                managed_node='/runtime/node', chromium='/runtime/chromium', evidence_root='/private/evidence',
                cohort='admin-browser-current-main', python_sha256='python')
            launcher.configure_cohort('admin-browser-current-main')
            manifest = {'sourceFilesSha256': 'source', 'dependencyFilesSha256': 'deps',
                        'dependencySymlinksSha256': 'links'}
            grant = launcher.expected_grant(args, manifest, 123, 'node', 'browser', 'manifest')
            self.assertEqual(grant['candidateSourceRoot'], str(root))
            self.assertEqual(grant['runningPythonSha256'], 'python')
            self.assertEqual(grant['databasePlan'], {
                'adminProductionAuthBrowser': 'dvaia_test_admin_browser_abcdef123456',
            })


if __name__ == '__main__':
    unittest.main()
