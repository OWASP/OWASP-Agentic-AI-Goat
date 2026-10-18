import importlib.util
import json
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name('run-ipi-email-rendered-isolated.py')
SPEC = importlib.util.spec_from_file_location('run_ipi_email_rendered_isolated', MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeChild:
    def __init__(self, returncode=None, pgid=9001, name='fake'):
        self.returncode = returncode
        self.pid = pgid
        self._owned_pgid = pgid
        self._owned_name = name
        self.poll_calls = 0
        self.wait_calls = []

    def poll(self):
        self.poll_calls += 1
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired('fake', timeout)
        return self.returncode


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, amount):
        self.now += amount


class FakeLog:
    def __init__(self, failure=None):
        self.failure = failure
        self.closed = False

    def close(self):
        self.closed = True
        if self.failure:
            raise self.failure


class RunnerLifecycleTests(unittest.TestCase):
    def test_module_is_import_safe_and_plan_gate_requires_no_files(self):
        self.assertTrue(callable(runner.main))
        with mock.patch('builtins.print') as output:
            self.assertEqual(runner.main([
                '--docker-host', 'unused', '--node', '/missing', '--node-sha256', '0' * 64,
                '--browser', '/missing', '--browser-sha256', '0' * 64,
            ]), 0)
        output.assert_called_once_with('plan: no workspace, container, database, browser, or model mutation')

    def test_stop_group_terminates_descendants_after_leader_already_exited(self):
        child = FakeChild(returncode=0)
        states = iter([True, True, False, False, False])
        kills = []
        clock = Clock()
        result = runner.stop_group(
            child,
            group_exists=lambda _pgid, env=None: next(states),
            killpg=lambda pgid, sig: kills.append((pgid, sig)),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        self.assertEqual(result, 0)
        self.assertEqual(kills, [(9001, signal.SIGTERM)])
        self.assertGreaterEqual(child.poll_calls, 2)

    def test_stop_group_escalates_to_kill_and_proves_absence(self):
        child = FakeChild(returncode=None)
        present = {'value': True}
        kills = []
        clock = Clock()

        def killpg(pgid, sig):
            kills.append((pgid, sig))
            if sig == signal.SIGKILL:
                present['value'] = False
                child.returncode = -signal.SIGKILL

        result = runner.stop_group(
            child,
            group_exists=lambda _pgid, env=None: present['value'],
            killpg=killpg,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            term_seconds=0.2,
            kill_seconds=0.2,
        )
        self.assertEqual(result, -signal.SIGKILL)
        self.assertEqual(kills, [(9001, signal.SIGTERM), (9001, signal.SIGKILL)])

    def test_stop_group_rejects_surviving_group(self):
        child = FakeChild(returncode=1)
        clock = Clock()
        with self.assertRaisesRegex(RuntimeError, 'process group remains'):
            runner.stop_group(
                child,
                group_exists=lambda _pgid, env=None: True,
                killpg=lambda _pgid, _sig: None,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
                term_seconds=0.1,
                kill_seconds=0.1,
            )

    def test_cleanup_attempts_every_container_and_retains_each_failure(self):
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            operation = 'rm' if 'rm' in command else 'ps'
            name = command[-1] if operation == 'rm' else command[command.index('--filter') + 1]
            if operation == 'rm' and name == 'second':
                return SimpleNamespace(returncode=2, stdout='')
            if operation == 'ps' and 'first' in name:
                return SimpleNamespace(returncode=0, stdout='first\n')
            return SimpleNamespace(returncode=0, stdout='')

        errors = runner.cleanup_containers(['first', 'second'], ['docker', '--host', 'owned'], {}, runner=fake_run)
        self.assertEqual(len(calls), 4)
        self.assertEqual(len(errors), 2)
        self.assertIn('second', str(errors[0]))
        self.assertIn('first', str(errors[1]))

    def test_postgres_command_uses_coherent_small_wal_configuration(self):
        command = runner.postgres_container_command(['docker', '--host', 'owned'], 'qualified-pg')
        self.assertIn('POSTGRES_INITDB_ARGS=--wal-segsize=1', command)
        self.assertEqual(command[command.index('max_wal_size=16MB') - 1], '-c')
        self.assertEqual(command[command.index('min_wal_size=4MB') - 1], '-c')
        self.assertIn('/var/lib/postgresql:rw,size=536870912', command)
        self.assertEqual(command.count('sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'), 1)

    def test_failure_log_capture_attempts_all_containers_and_is_private(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            kwargs['stdout'].write(f"diagnostic:{command[-1]}\n".encode())
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = runner.capture_container_logs(
                ['first', 'second'], ['docker', '--host', 'owned'], {}, root, runner=fake_run,
            )
            self.assertEqual(errors, [])
            self.assertEqual(len(calls), 2)
            for name in ('first', 'second'):
                path = root / f'{name}.container.log'
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertIn(f'diagnostic:{name}', path.read_text())

    def test_primary_error_is_preserved_with_cleanup_details(self):
        primary = ValueError('primary qualification failure')
        runner.add_cleanup_errors(primary, [RuntimeError('group survived'), RuntimeError('container survived')])
        self.assertEqual(str(primary), 'primary qualification failure')
        self.assertEqual(len(primary.__notes__), 1)
        self.assertIn('group survived', primary.__notes__[0])
        self.assertIn('container survived', primary.__notes__[0])

    def test_finalizer_attempts_every_child_log_and_container_after_errors(self):
        first = FakeChild(returncode=0, pgid=101, name='first')
        second = FakeChild(returncode=0, pgid=102, name='second')
        good_log, bad_log = FakeLog(), FakeLog(RuntimeError('log close failed'))
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(runner, 'stop_group', side_effect=[RuntimeError('child stop failed'), 0]) as stop, \
             mock.patch.object(runner, 'cleanup_containers', return_value=[RuntimeError('container failed')]) as cleanup:
            receipt = Path(directory) / 'cleanup.json'
            errors = runner.finalize_owned([first, second], [good_log, bad_log], ['one'], ['docker'], {}, receipt)
            result = json.loads(receipt.read_text())
        self.assertEqual(stop.call_count, 2)
        self.assertTrue(good_log.closed)
        self.assertTrue(bad_log.closed)
        cleanup.assert_called_once()
        self.assertEqual([str(error) for error in errors], [
            'child stop failed', 'log close failed', 'container failed',
        ])
        self.assertEqual(result, {
            'schemaVersion': 1,
            'processes': [
                {'cleanup': 'absent_verified', 'name': 'first', 'pgid': 101, 'pid': first.pid, 'returncode': 0},
                {'cleanup': 'failed', 'error': 'RuntimeError: child stop failed', 'name': 'second', 'pgid': 102, 'pid': second.pid, 'returncode': 0},
            ],
        })

    def test_child_intent_receipt_is_private_and_contains_only_owned_identity(self):
        children = [
            FakeChild(returncode=None, pgid=201, name='fixture'),
            FakeChild(returncode=None, pgid=202, name='browser_test'),
        ]
        children[0].pid = 1201
        children[1].pid = 1202
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'intent.json'
            runner.write_child_intent(path, children)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), {
                'schemaVersion': 1,
                'processes': [
                    {'name': 'fixture', 'pid': 1201, 'pgid': 201},
                    {'name': 'browser_test', 'pid': 1202, 'pgid': 202},
                ],
            })

    def test_completion_requires_exit_zero_and_exact_final_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'readiness.json'
            digest = runner.EXPECTED_MODEL_DIGEST
            ready.write_text(json.dumps({'modelDigestBefore': digest}))
            Path(f'{ready}.final').write_text(json.dumps({
                'counters': {'modelCalls': 2},
                'modelDigestBefore': digest,
                'modelDigestAfter': digest,
            }))
            final = runner.validate_fixture_completion(FakeChild(returncode=0), ready)
            self.assertEqual(final['modelDigestAfter'], digest)

            with self.assertRaisesRegex(RuntimeError, 'shutdown failed'):
                runner.validate_fixture_completion(FakeChild(returncode=1), ready)

            Path(f'{ready}.final').write_text(json.dumps({
                'modelDigestBefore': digest,
                'modelDigestAfter': 'f' * 64,
            }))
            with self.assertRaisesRegex(RuntimeError, 'final model digest mismatch'):
                runner.validate_fixture_completion(FakeChild(returncode=0), ready)

    def test_completion_rejects_missing_and_oversized_final_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'readiness.json'
            ready.write_text(json.dumps({'modelDigestBefore': runner.EXPECTED_MODEL_DIGEST}))
            child = FakeChild(returncode=0)
            with self.assertRaisesRegex(RuntimeError, 'final evidence missing'):
                runner.validate_fixture_completion(child, ready)
            Path(f'{ready}.final').write_bytes(b'x' * (runner.MAX_EVIDENCE_BYTES + 1))
            with self.assertRaisesRegex(RuntimeError, 'final evidence size invalid'):
                runner.validate_fixture_completion(child, ready)


if __name__ == '__main__':
    unittest.main()
