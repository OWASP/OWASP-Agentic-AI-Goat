"""Controlled launcher contracts only; never starts PostgreSQL or a container."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
launcher = Path(__file__).with_name('run-application-maintenance-fence-isolated.py')
spec = importlib.util.spec_from_file_location('maintenance_v5_launcher_contract', launcher)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MaintenanceV5Launcher(unittest.TestCase):
    def arguments(self):
        return sum((["--" + key, 'owned'] for key in ('package', 'manifest', 'manifest-sha256', 'node', 'node-sha256', 'docker', 'docker-sha256', 'docker-host', 'docker-daemon', 'image-id')), [])

    def test_closed_selector_and_prior_cohorts_preserved(self):
        selected = module.selection(v5=True)
        self.assertEqual(selected['cases'], ('fresh', 'populated', 'concurrency'))
        self.assertEqual(selected['fixture'], 'tests/postgres/applicationMaintenanceV5.integration.test.js')
        self.assertEqual(selected['gate'], 'APPLICATION_MAINTENANCE_V5_ISOLATED')
        self.assertEqual(selected['evidence'], 'MAINTENANCE_V5_EVIDENCE')
        self.assertEqual(module.selection()['cases'], module.CASES)
        self.assertEqual(module.selection(v2=True)['cases'], module.V2_CASES)
        self.assertEqual(module.selection(v3=True)['cases'], ('fresh', 'populated', 'rollback'))
        self.assertEqual(module.selection(v4=True)['fixture'], 'tests/postgres/applicationMaintenanceV4.integration.test.js')
        for flags in ({'v2': True, 'v5': True}, {'v3': True, 'v5': True}, {'v4': True, 'v5': True}, {'v5': 'true'}):
            with self.assertRaises(ValueError):
                module.selection(**flags)

    def test_exact_six_owned_loopback_url_pairs(self):
        environment = module.database_environment('abcdef012345', 54321, v5=True)
        expected = {f'PG_MAINTENANCE_V5_{case.upper()}_{role}_URL' for case in ('fresh', 'populated', 'concurrency') for role in ('RUNTIME', 'MIGRATION')}
        self.assertEqual(set(environment), expected)
        self.assertEqual(len({value.rsplit('/', 1)[1] for value in environment.values()}), 3)
        for value in environment.values():
            self.assertIn('@127.0.0.1:54321/dvaia_test_maintenance_v5_abcdef012345_', value)
            self.assertLessEqual(len(value.rsplit('/', 1)[1].encode()), 63)
        for owner, port in (('learner', 5432), ('abcdef012345', 0), ('abcdef012345', 65536), ('abcdef012345', 'application')):
            with self.assertRaises(ValueError):
                module.database_environment(owner, port, v5=True)

    def test_v5_cli_is_exclusive(self):
        parsed = module.argument_parser().parse_args(self.arguments() + ['--application-maintenance-v5', '--main-workspace'])
        self.assertTrue(parsed.application_maintenance_v5)
        self.assertTrue(parsed.main_workspace)
        for other in ('fence', 'v2', 'v3', 'v4'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.argument_parser().parse_args(self.arguments() + ['--application-maintenance-v5', '--application-maintenance-' + other])

    def test_v5_without_main_is_denied_before_any_native_resource_or_copy(self):
        with patch.object(sys, 'argv', [str(launcher), *self.arguments(), '--application-maintenance-v5']), patch.object(module.signal, 'signal'), patch.object(module.signal, 'alarm'), patch.object(module.subprocess, 'run') as command, patch.object(module.shutil, 'copytree') as copy:
            with self.assertRaisesRegex(RuntimeError, 'Main v5 workspace'):
                module.main()
            command.assert_not_called()
            copy.assert_not_called()

    def create_main(self, root):
        files = ('tests/postgres/applicationMaintenanceV5.integration.test.js', 'tests/postgres/run-application-maintenance-fence-isolated.py', 'server/database/postgres/applicationMaintenanceControl.js', 'server/services/applicationMaintenanceLease.js', 'db/postgres/maintenance-migrations/0001.sql', 'db/postgres/maintenance-migrations/0005_windows_owner_records.sql')
        for name in files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('controlled source')
        (root / 'node_modules').mkdir()
        executable = root / 'node'
        executable.write_text('controlled executable')
        manifest = root / 'manifest.json'
        document = {'cohort': 'application-maintenance-v5-main', 'workspace': str(root), 'sourcePins': {name: module.digest(root / name) for name in files}, 'dependencyInventory': module.inventory(root / 'node_modules')}
        manifest.write_text(json.dumps(document))
        args = SimpleNamespace(main_workspace=True, application_maintenance_v5=True, application_maintenance_v4=False, package=str(root), manifest=str(manifest), manifest_sha256=module.digest(manifest), node=str(executable), node_sha256=module.digest(executable), docker=str(executable), docker_sha256=module.digest(executable))
        return args, document, files

    def test_main_source_sql_dependency_and_executable_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            args, document, files = self.create_main(root)
            with patch.object(module, '__file__', str(root / 'tests/postgres/run-application-maintenance-fence-isolated.py')):
                self.assertEqual(module.validate(args), root)
                sql = root / 'db/postgres/maintenance-migrations/0005_windows_owner_records.sql'
                sql.write_text('drift')
                with self.assertRaisesRegex(RuntimeError, 'source pin'):
                    module.validate(args)
                sql.write_text('controlled source')
                (root / 'node_modules/drift').write_text('changed dependencies')
                with self.assertRaisesRegex(RuntimeError, 'dependencies'):
                    module.validate(args)
                (root / 'node_modules/drift').unlink()
                (root / 'node').write_text('different executable')
                with self.assertRaisesRegex(RuntimeError, 'Executable pin'):
                    module.validate(args)

    def test_v4_manifest_missing_v5_pin_and_other_workspace_are_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            args, document, _ = self.create_main(root)
            with patch.object(module, '__file__', str(root / 'tests/postgres/run-application-maintenance-fence-isolated.py')):
                for change, error in ((lambda: document.update(cohort='application-maintenance-v4-main'), 'Wrong main cohort'), (lambda: (document.update(cohort='application-maintenance-v5-main'), document['sourcePins'].pop('db/postgres/maintenance-migrations/0005_windows_owner_records.sql')), 'Incomplete main source pins')):
                    change()
                    Path(args.manifest).write_text(json.dumps(document))
                    args.manifest_sha256 = module.digest(args.manifest)
                    with self.assertRaisesRegex(RuntimeError, error):
                        module.validate(args)
            with patch.object(module, '__file__', str(root / 'other/tests/postgres/run-application-maintenance-fence-isolated.py')):
                with self.assertRaisesRegex(RuntimeError, 'Main v5 workspace'):
                    module.validate(args)

    def test_v5_evidence_is_separate_private_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'tasks').mkdir()
            evidence = module.main_evidence(root, v5=True)
            self.assertEqual(evidence.parent, root / 'tasks/maintenance-v5-native-evidence')
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'tasks').mkdir()
            (root / 'tasks/maintenance-v5-native-evidence').symlink_to(root)
            with self.assertRaisesRegex(RuntimeError, 'escape'):
                module.main_evidence(root, v5=True)

    def test_owned_pg18_and_shared_bounded_cleanup_are_reused(self):
        source = launcher.read_text()
        self.assertIn('deadline=time.monotonic()+420', source)
        self.assertIn('signal.alarm(420)', source)
        self.assertIn('deadline=time.monotonic()+120', source)
        self.assertIn('args.application_maintenance_v4 or args.application_maintenance_v5', source)
        self.assertIn('APPLICATION_MAINTENANCE_V5_MAIN_WORKSPACE', source)
        self.assertIn('Owned cluster is not empty', source)
        self.assertIn('180000<=int(version.stdout.strip())<190000', source)
        self.assertIn('verify_daemon(docker,args.docker_daemon);verify_image(docker,args.image_id)', source)
        self.assertIn('cleanup_phase_container(docker,args,name,labels,captured)', source)
        self.assertIn('processes.cleanup', source)
        self.assertIn('validate(args)==package', source)


if __name__ == '__main__':
    unittest.main()
