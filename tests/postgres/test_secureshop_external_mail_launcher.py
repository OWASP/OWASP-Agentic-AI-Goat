"""Non-allocating controls for the closed external-mail identity qualification."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('external_mail_repository_launcher',
    HERE / 'run-secureshop-external-mail-repository.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class ExternalMailLauncherContract(unittest.TestCase):
    def test_exact_cli_and_closed_scope(self):
        self.assertTrue(LAUNCHER.arguments(['--plan']).plan)
        self.assertTrue(LAUNCHER.arguments(['--run', '--expected-snapshot-sha256', 'f' * 64]).run)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(['--run', '--plan'])
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(['--run', '--smtp'])
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(['--run'])
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(['--plan', '--expected-snapshot-sha256', 'f' * 64])
        self.assertEqual(LAUNCHER.TEST,
            'tests/postgres/secureshopExternalMailRepository.integration.test.js')
        self.assertIn('db/postgres/identity-migrations/0153_secureshop_external_test_mail.sql',
            LAUNCHER.source_snapshot()[0])
        self.assertIn('server/services/secureshopExternalMail.js', LAUNCHER.source_snapshot()[0])
        self.assertEqual(LAUNCHER.IMAGE,
            'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336')

    def test_plan_and_unpinned_run_do_not_allocate(self):
        with mock.patch.object(LAUNCHER, 'source_snapshot', return_value=({}, 'f' * 64)), \
                mock.patch.object(LAUNCHER, 'settings', return_value={'dockerSha256': 'a' * 64,
                    'nodeSha256': 'b' * 64}), \
                mock.patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('external I/O')), \
                mock.patch.object(LAUNCHER.tempfile, 'mkdtemp',
                    side_effect=AssertionError('allocation')):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(LAUNCHER.main(['--plan']), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value['databaseCount'], 2)
            self.assertFalse(value['nativeStarted'])
            self.assertFalse(value['sourceCopies'])
            self.assertFalse(value['actualSmtp'])
            with self.assertRaisesRegex(RuntimeError, 'Reviewed external-mail source pin required'):
                LAUNCHER.main(['--run', '--expected-snapshot-sha256', 'e' * 64])

    def test_exact_tap_rejects_skip_and_wrong_name(self):
        root = LAUNCHER.ROOT / 'tasks/tmp'
        with tempfile.TemporaryDirectory(prefix='external-mail-control-', dir=root) as folder:
            target = Path(folder) / 'result.tap'
            title = 'identity0153 fresh and populated migration preserve history, runtime grants and retained mail claims'
            target.write_text(f'# Subtest: {title}\nok 1 - {title}\n'
                '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
            self.assertEqual(len(LAUNCHER.validate_tap(target, 0)), 64)
            with self.assertRaisesRegex(RuntimeError, 'failed'):
                LAUNCHER.validate_tap(target, 1)
            target.write_text(target.read_text().replace('# skipped 0', '# skipped 1'))
            with self.assertRaisesRegex(RuntimeError, 'Exact non-skipped'):
                LAUNCHER.validate_tap(target, 0)
            target.write_text(target.read_text().replace(title, 'different title')
                .replace('# skipped 1', '# skipped 0'))
            with self.assertRaisesRegex(RuntimeError, 'Original external-mail assertion missing'):
                LAUNCHER.validate_tap(target, 0)
            target.write_text('# tests 0\n# pass 0\n# fail 0\n# skipped 0\n# cancelled 0\n')
            with self.assertRaisesRegex(RuntimeError, 'Exact non-skipped'):
                LAUNCHER.validate_tap(target, 0)

    def test_runtime_pin_and_dependency_symlink_fail_closed(self):
        with mock.patch.object(LAUNCHER, 'digest', return_value='0' * 64):
            with self.assertRaisesRegex(RuntimeError, 'runtime executable mismatch'):
                LAUNCHER.settings()
        with tempfile.TemporaryDirectory(prefix='external-mail-deps-',
                                         dir=LAUNCHER.ROOT / 'tasks/tmp') as folder:
            root = Path(folder)
            for name in ('pg', 'bcryptjs'):
                package = root / 'node_modules' / name
                package.mkdir(parents=True)
                (package / 'package.json').write_text(json.dumps({'name': name, 'dependencies': {}}))
            (root / 'node_modules/pg/link').symlink_to(root / 'node_modules/pg/package.json')
            with mock.patch.object(LAUNCHER, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'symlink rejected'):
                    LAUNCHER.dependency_snapshot()

    def test_cleanup_and_postflight_are_required_for_pass(self):
        complete = {'passed': True, 'cleanupErrors': [], 'sourceUnchanged': True,
            'runtimeUnchanged': True, 'containerCleanup': {'status': 'removed_absence_verified'},
            'tapSha256': 'a' * 64}
        self.assertTrue(LAUNCHER.accepted(complete))
        for key, changed in [('cleanupErrors', ['container']), ('sourceUnchanged', False),
                             ('runtimeUnchanged', False), ('containerCleanup', {'status': 'absent'}),
                             ('tapSha256', None)]:
            with self.subTest(key=key):
                self.assertFalse(LAUNCHER.accepted({**complete, key: changed}))

    def test_signal_handler_installed_before_first_docker_call(self):
        with tempfile.TemporaryDirectory(prefix='external-mail-admission-',
                                         dir=LAUNCHER.ROOT / 'tasks/qualification') as folder:
            root = Path(folder)
            installed = []
            class Processes:
                def install(self): installed.append('installed')
                def mask_cleanup_signals(self): pass
                def cleanup(self): pass
                def restore(self): pass
            def denied(_command, _daemon):
                self.assertEqual(installed, ['installed'])
                raise RuntimeError('controlled preallocation denial')
            source = ({}, 'f' * 64)
            runtime = {'dockerSha256': 'a' * 64, 'nodeSha256': 'b' * 64,
                'dependencySha256': 'c' * 64}
            pin = LAUNCHER.snapshot_sha(source[1], runtime)
            def owned_dir(*, prefix, dir):
                self.assertEqual(dir, LAUNCHER.ROOT / 'tasks/qualification')
                self.assertEqual(prefix, 'run-external-mail-')
                return str(root)
            with mock.patch.object(LAUNCHER, 'source_snapshot', return_value=source), \
                    mock.patch.object(LAUNCHER, 'settings', return_value=runtime), \
                    mock.patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=owned_dir), \
                    mock.patch.object(LAUNCHER.process_ownership, 'OwnedProcesses', return_value=Processes()), \
                    mock.patch.object(LAUNCHER.docker_ownership, 'verify_daemon', side_effect=denied), \
                    mock.patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('Docker launched')):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(LAUNCHER.main(['--run', '--expected-snapshot-sha256', pin]), 1)
            self.assertEqual(installed, ['installed'])
            evidence = json.loads((root / 'result.json').read_text())
            self.assertFalse(evidence['passed'])
            self.assertFalse(evidence['nativeStarted'])


if __name__ == '__main__':
    unittest.main()
