"""Nonallocating controls for the four-store external-mail authority launcher."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('external_mail_authority_launcher',
    HERE / 'run-secureshop-external-mail-authority.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class ExternalMailAuthorityLauncherContract(unittest.TestCase):
    def test_exact_cli_scope_and_source_closure(self):
        self.assertTrue(LAUNCHER.arguments(['--plan']).plan)
        self.assertTrue(LAUNCHER.arguments(['--run', '--expected-snapshot-sha256', 'f' * 64]).run)
        with contextlib.redirect_stderr(io.StringIO()):
            for args in (['--run'], ['--plan', '--run'], ['--run', '--smtp'],
                         ['--plan', '--expected-snapshot-sha256', 'f' * 64]):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    LAUNCHER.arguments(args)
        self.assertEqual(LAUNCHER.TEST,
            'tests/postgres/secureshopExternalMailAuthority.integration.test.js')
        source = LAUNCHER.source_snapshot()[0]
        for name in ('server/services/secureshopExternalMail.js',
                     'db/postgres/identity-migrations/0153_secureshop_external_test_mail.sql',
                     'tests/postgres/secureshopManualRagNativeSetup.js',
                     'tests/postgres/sql_nosql_process_ownership.py'):
            self.assertIn(name, source)
        self.assertEqual(LAUNCHER.IMAGE,
            'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336')

    def test_four_database_identifiers_are_exact_and_below_postgres_limit(self):
        nonce = 'abcdef123456'
        names = [LAUNCHER.database_name(nonce, store) for store in LAUNCHER.STORES.values()]
        self.assertEqual(len(set(names)), 4)
        for store, name in zip(LAUNCHER.STORES.values(), names):
            self.assertEqual(name, f'dvaia_test_extmail_auth_{nonce}_{store}')
            self.assertLessEqual(len(name.encode('utf-8')), 63)
        for bad_nonce, bad_store in [('x' * 12, 'secureshop_agents'),
                                     (nonce, 'secureshop_agents_extended_to_overrun_pg_identifier')]:
            with self.assertRaisesRegex(RuntimeError, 'Closed disposable store'):
                LAUNCHER.database_name(bad_nonce, bad_store)
        with mock.patch.object(LAUNCHER, 'DATABASE_PREFIX', 'dvaia_test_external_mail_authority_'):
            with self.assertRaisesRegex(RuntimeError, 'exceeds 63 bytes'):
                LAUNCHER.database_name(nonce, 'secureshop_agents')

    def test_fixture_owned_urls_accept_only_exact_short_launcher_names(self):
        nonce = 'abcdef123456'
        env = {'PATH': str(LAUNCHER.NODE.parent) + ':/usr/bin:/bin', 'NODE_ENV': 'test'}
        for store, physical in LAUNCHER.STORES.items():
            name = LAUNCHER.database_name(nonce, physical)
            for role in ('RUNTIME', 'MIGRATION'):
                env[f'PG_EXTERNAL_MAIL_{store}_{role}_URL'] = (
                    f'postgresql://dvaia_{physical}_{role.lower()}@127.0.0.1:5432/{name}')
        script = ("const u=require('./tests/postgres/secureshopExternalMailAuthority.integration.test.js')"
                  ".ownedUrls(process.env);process.stdout.write(String(Object.keys(u).length));")
        accepted = subprocess.run([str(LAUNCHER.NODE), '-e', script], cwd=LAUNCHER.ROOT,
            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual((accepted.returncode, accepted.stdout), (0, '8'), accepted.stderr)
        wrong = dict(env)
        wrong['PG_EXTERNAL_MAIL_AGENTS_RUNTIME_URL'] = wrong[
            'PG_EXTERNAL_MAIL_AGENTS_RUNTIME_URL'].replace(
                LAUNCHER.DATABASE_PREFIX, 'dvaia_test_external_mail_authority_')
        denied = subprocess.run([str(LAUNCHER.NODE), '-e', script], cwd=LAUNCHER.ROOT,
            env=wrong, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(denied.returncode, 0)

    def test_plan_and_mismatched_pin_do_not_allocate(self):
        source = ({}, 'f' * 64)
        runtime = {'dockerSha256': 'a' * 64, 'nodeSha256': 'b' * 64,
                   'dependencySha256': 'c' * 64}
        with mock.patch.object(LAUNCHER, 'source_snapshot', return_value=source), \
                mock.patch.object(LAUNCHER, 'settings', return_value=runtime), \
                mock.patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('I/O')), \
                mock.patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(LAUNCHER.main(['--plan']), 0)
            value = json.loads(output.getvalue())
            self.assertEqual((value['databaseCount'], value['roleCount']), (4, 8))
            self.assertFalse(value['nativeStarted'])
            self.assertFalse(value['actualSmtp'])
            with self.assertRaisesRegex(RuntimeError, 'source pin required'):
                LAUNCHER.main(['--run', '--expected-snapshot-sha256', 'e' * 64])

    def test_tap_requires_exact_original_non_skipped_test(self):
        with tempfile.TemporaryDirectory(prefix='mail-authority-control-',
                dir=LAUNCHER.ROOT / 'tasks/tmp') as folder:
            target = Path(folder) / 'result.tap'
            title = LAUNCHER.TITLE
            valid = (f'# Subtest: {title}\nok 1 - {title}\n'
                     '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
            target.write_text(valid)
            self.assertEqual(len(LAUNCHER.validate_tap(target, 0)), 64)
            for changed, code in ((valid, 1),
                                  (valid.replace('# skipped 0', '# skipped 1'), 0),
                                  (valid.replace(title, 'wrong test'), 0),
                                  ('# tests 0\n# pass 0\n# fail 0\n# skipped 0\n# cancelled 0\n', 0)):
                target.write_text(changed)
                with self.subTest(code=code, changed=changed[:30]), self.assertRaises(RuntimeError):
                    LAUNCHER.validate_tap(target, code)

    def test_runtime_pin_and_dependency_symlink_fail_closed(self):
        with mock.patch.object(LAUNCHER, 'digest', return_value='0' * 64):
            with self.assertRaisesRegex(RuntimeError, 'runtime executable mismatch'):
                LAUNCHER.settings()
        with tempfile.TemporaryDirectory(prefix='mail-authority-deps-',
                dir=LAUNCHER.ROOT / 'tasks/tmp') as folder:
            root = Path(folder)
            for name in ('pg', 'express', 'bcryptjs'):
                package = root / 'node_modules' / name
                package.mkdir(parents=True)
                (package / 'package.json').write_text(json.dumps({'name': name, 'dependencies': {}}))
            (root / 'node_modules/express/link').symlink_to(root / 'node_modules/express/package.json')
            with mock.patch.object(LAUNCHER, 'ROOT', root), \
                    mock.patch.object(LAUNCHER, 'source_snapshot', return_value=({}, 'f' * 64)):
                with self.assertRaisesRegex(RuntimeError, 'symlink rejected'):
                    LAUNCHER.dependency_snapshot()

    def test_clean_child_environment_is_closed_and_bounded(self):
        with tempfile.TemporaryDirectory(prefix='mail-authority-env-',
                dir=LAUNCHER.ROOT / 'tasks/tmp') as folder:
            env = LAUNCHER.clean_environment(Path(folder))
            self.assertEqual(env['PG_EXTERNAL_MAIL_AUTHORITY_NATIVE'], 'yes')
            self.assertEqual(env['DVAIA_CURRENT_MAIN_WORKSPACE'], str(LAUNCHER.ROOT))
            self.assertEqual(env['DOCKER_HOST'], 'unix://' + str(LAUNCHER.SOCKET))
            self.assertEqual(Path(env['PG_EXTERNAL_MAIL_AUTHORITY_EVIDENCE_PATH']).name,
                'external-mail-authority-evidence.json')
            self.assertFalse(any(key.startswith(('SMTP_', 'OLLAMA_', 'OPENAI_')) for key in env))
            self.assertEqual(env['AI_PROVIDER'], 'mock')

    def test_acceptance_requires_replay_and_verified_cleanup(self):
        complete = {'passed': True, 'cleanupErrors': [], 'sourceUnchanged': True,
            'runtimeUnchanged': True, 'containerCleanup': {'status': 'removed_absence_verified'},
            'tapSha256': 'a' * 64, 'evidenceSha256': 'b' * 64}
        self.assertTrue(LAUNCHER.accepted(complete))
        for key, changed in [('cleanupErrors', ['container']), ('sourceUnchanged', False),
                             ('runtimeUnchanged', False), ('containerCleanup', {'status': 'absent'}),
                             ('tapSha256', None), ('evidenceSha256', None)]:
            with self.subTest(key=key):
                self.assertFalse(LAUNCHER.accepted({**complete, key: changed}))

    def test_signal_handler_installed_before_first_docker_call(self):
        with tempfile.TemporaryDirectory(prefix='mail-authority-admission-',
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
                self.assertEqual(prefix, 'run-external-mail-authority-')
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
