"""Pure command/identity controls; never launch Docker, Node, or a browser."""

import argparse
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import admin_student_deletion_execution as execution
import admin_q05_current_host as admin_q05


ROOT = Path(__file__).resolve().parents[2]
NONCE = 'a' * 12


class DeletionExecutionControls(unittest.TestCase):
    def test_exact_sixteen_store_thirty_three_role_provisioning(self):
        statements = execution.provision_statements(NONCE)
        self.assertEqual(len(statements), 81)
        self.assertEqual(sum(row.startswith('CREATE ROLE ') for row in statements), 33)
        self.assertEqual(sum(row.startswith('CREATE DATABASE ') for row in statements), 16)
        self.assertEqual(sum(row.startswith('REVOKE CONNECT ') for row in statements), 16)
        self.assertEqual(sum(row.startswith('GRANT CONNECT ') for row in statements), 16)
        self.assertEqual(sum('dvaia_ctf_delivery' in row for row in statements), 2)
        self.assertIn('GRANT CONNECT ON DATABASE dvaia_test_student_deletion_aaaaaaaaaaaa_ctf '
                      'TO dvaia_ctf_migration,dvaia_ctf_runtime,dvaia_ctf_delivery', statements)
        self.assertTrue(all(' IF NOT EXISTS ' not in row for row in statements))

    def test_exact_url_scope_and_delivery_role(self):
        urls = execution.store_urls(NONCE, 54321)
        self.assertEqual(len(urls), 33)
        self.assertEqual(urls['IDENTITY_DATABASE_URL'],
                         'postgresql://dvaia_identity_runtime@127.0.0.1:54321/'
                         'dvaia_test_student_deletion_aaaaaaaaaaaa_identity')
        self.assertEqual(urls['CTF_DELIVERY_DATABASE_URL'],
                         'postgresql://dvaia_ctf_delivery@127.0.0.1:54321/'
                         'dvaia_test_student_deletion_aaaaaaaaaaaa_ctf')
        for bad in (None, True, 0, 65536, '54321'):
            with self.assertRaises(RuntimeError): execution.store_urls(NONCE, bad)

    def test_owned_existing_image_command_has_closed_resource_envelope(self):
        image = 'sha256:' + 'b' * 64
        command = execution.container_command('/owned/docker', 'unix:///owned/docker.sock',
            'dvaia-student-deletion-' + NONCE, image, 'c' * 32)
        self.assertIn('--pull', command)
        self.assertEqual(command[command.index('--pull') + 1], 'never')
        self.assertEqual(command[command.index('--memory') + 1], str(2 * 1024 ** 3))
        self.assertEqual(command[command.index('--memory-swap') + 1], str(2 * 1024 ** 3))
        self.assertEqual(command[command.index('--cpus') + 1], '2')
        self.assertEqual(command[command.index('--pids-limit') + 1], '256')
        self.assertEqual(command[-1], 'max_connections=96')
        self.assertIn('127.0.0.1::5432', command)
        host = {'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3,
                'NanoCpus': 2 * 10**9, 'PidsLimit': 256,
                'Tmpfs': {'/var/lib/postgresql': 'rw,size=' + str(1024**3)}}
        self.assertIs(execution.resource_envelope_matches(host), True)
        for wrong in (0, 512 * 1024**2, True, 3 * 1024**3):
            self.assertIs(execution.resource_envelope_matches(
                {**host, 'MemorySwap': wrong}), False)
        for bad in ('latest', 'sha256:'+'a'*63):
            with self.assertRaises(RuntimeError):
                execution.container_command('/owned/docker', 'unix:///owned/docker.sock',
                    'dvaia-student-deletion-' + NONCE, bad, 'c'*32)

    def test_private_worker_environment_and_direct_node_commands(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/qualification') as parent:
            # The exact run name is deliberate; tests do not start services.
            expected = ROOT / 'tasks/qualification' / ('run-admin-student-deletion-' + NONCE)
            with patch.object(execution, 'database_plan', wraps=execution.database_plan):
                # Avoid reusing an existing qualification run name.
                self.assertTrue(parent)
            if expected.exists():
                self.skipTest('Exact synthetic run name already exists')
            expected.mkdir(mode=0o700)
            try:
                runtime = expected / 'runtime'
                runtime.mkdir(mode=0o700)
                args = argparse.Namespace(node=str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
                    chromium=str(ROOT/'tests/postgres/adminStudentDeletionRenderedSupport.js'),
                    build_sha256='b'*64)
                env = execution.worker_environment(ROOT, runtime, NONCE, 54321, args,
                    'c'*64, 'privateSyntheticSigningSecret1234567890')
                self.assertEqual(env['PG_POOL_BUDGET'], '78')
                self.assertEqual(env['DVAIA_APP_DATA_ROOT'], str(runtime))
                self.assertEqual(env['STUDENT_DELETION_RESOURCE_JOURNAL'],
                    str(runtime/'tmp/student-deletion-resources.json'))
                self.assertEqual(env['ADMIN_STUDENT_DELETION_STORE_PLAN_SHA256'],
                    execution.store_plan_sha256(NONCE))
                self.assertEqual(len([key for key in env if key.endswith('_DATABASE_URL')]) +
                                 len([key for key in env if key.endswith('_MIGRATION_DATABASE_URL') and
                                     not key.endswith('_DATABASE_URL')]), 33)
                self.assertEqual(execution.initializer_command(args.node, ROOT)[-1],
                                 str(ROOT/'tests/postgres/adminStudentDeletionInitialize.js'))
                self.assertEqual(execution.worker_command(args.node, ROOT)[1:3],
                                 ('--test', '--test-isolation=none'))
                with self.assertRaisesRegex(RuntimeError, 'signing secret'):
                    execution.worker_environment(ROOT, runtime, NONCE, 54321, args, 'c'*64, 'short')
            finally:
                runtime.rmdir()
                expected.rmdir()

    def test_initializer_requires_joined_original_child(self):
        class Child:
            pid = 123
            returncode = 0
            def poll(self): return 0
        class Owned:
            def __init__(self):
                self.registered = []
                self.api = self
            def register_child(self, pid): self.registered.append(pid)
            def identity(self, _pid): return None
        owned = Owned()
        retained = []
        with tempfile.TemporaryFile(mode='w+') as log, \
             patch.object(execution.subprocess, 'Popen', return_value=Child()) as popen:
            result = execution.run_initializer('/owned/node', ROOT, {'NODE_ENV':'test'},
                log, owned, deadline=10**12, on_spawn=retained.append)
        self.assertEqual(owned.registered, [123])
        self.assertEqual(len(retained), 1)
        self.assertEqual(result['stores'], 16)
        self.assertEqual(popen.call_args.kwargs['start_new_session'], True)
        self.assertEqual(popen.call_args.args[0][-1],
                         str(ROOT/'tests/postgres/adminStudentDeletionInitialize.js'))

    def test_initializer_registration_failure_keeps_spawn_handle_for_cleanup(self):
        class Child:
            pid = 123
        class Owned:
            def register_child(self, _pid):
                raise RuntimeError('birth capture unavailable')
        retained = []
        with tempfile.TemporaryFile(mode='w+') as log, \
             patch.object(execution.subprocess, 'Popen', return_value=Child()):
            with self.assertRaisesRegex(RuntimeError, 'birth capture unavailable'):
                execution.run_initializer('/owned/node', ROOT, {'NODE_ENV': 'test'},
                    log, Owned(), deadline=10**12, on_spawn=retained.append)
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].pid, 123)

    def test_resource_journal_browser_identity_is_bounded(self):
        marker = Path('/owned/private/journal.json')
        self.assertIsNone(execution.parse_resource_browser_pid(marker,
            lambda _: {'resources': {}}))
        self.assertEqual(execution.parse_resource_browser_pid(marker,
            lambda _: {'resources': {'browser': {'pid': 123,
                'profile': '/owned/profile', 'executable': '/owned/chrome'}}}), 123)
        self.assertIsNone(execution.parse_resource_browser_pid(marker,
            lambda _: {'resources': {'browser': {'pid': None,
                'profile': '/owned/profile', 'executable': '/owned/chrome'}}}))
        for bad in (True, '123', 0):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected browser resource'):
                execution.parse_resource_browser_pid(marker,
                    lambda _: {'resources': {'browser': {'pid': bad,
                        'profile': '/owned/profile', 'executable': '/owned/chrome'}}})
        with self.assertRaisesRegex(RuntimeError, 'Unexpected browser resource'):
            execution.parse_resource_browser_pid(marker,
                lambda _: {'resources': {'browser': {'pid': 123, 'foreign': True}}})
        with self.assertRaisesRegex(RuntimeError, 'Unexpected browser resource'):
            execution.parse_resource_browser_pid(marker,
                lambda _: {'resources': {'browser': {'pid': 123,
                    'profileDirectory': '/owned/profile', 'executablePath': '/owned/chrome'}}})

    def test_postgres_failure_diagnostic_keeps_only_fixed_categories(self):
        row = {'State': {'Running': True, 'OOMKilled': False, 'ExitCode': 0,
                         'Error': 'private database URL and secret'}}
        logs = 'private SQL and token\nserver process 123 terminated by signal 9: Killed\n'
        result = execution.postgres_failure_diagnostic(row, logs)
        self.assertEqual(result, dict(containerRunning=True, containerOOMKilled=False,
            containerExitCode=0, backendSignalNine=True,
            outOfMemoryReported=False, connectionTerminatedReported=False))
        self.assertNotIn('private', repr(result))
        with self.assertRaisesRegex(RuntimeError, 'Bounded PostgreSQL'):
            execution.postgres_failure_diagnostic(row, 'x' * 65537)
        with self.assertRaisesRegex(RuntimeError, 'Bounded PostgreSQL'):
            execution.postgres_failure_diagnostic({'State': {'Running': 1,
                'OOMKilled': False, 'ExitCode': 0}}, '')

    def test_execute_rejects_missing_strict_verifier_before_allocation(self):
        with patch.object(execution, 'provision_statements') as ddl:
            with self.assertRaisesRegex(RuntimeError, 'Complete reviewed execution admission'):
                execution.execute(argparse.Namespace(), repo=ROOT, inspector=None,
                    before={}, verify_fixture=None, verify_tap=None, snapshot_after=None)
            ddl.assert_not_called()

    def test_execute_failure_still_removes_exact_owned_container_and_keeps_failure(self):
        image = 'sha256:' + 'b' * 64
        container = 'c' * 64
        name = 'dvaia-student-deletion-' + NONCE
        args = argparse.Namespace(nonce=NONCE, docker='/owned/docker',
            docker_host='unix:///owned/docker.sock', daemon_id='owned-daemon',
            image_id=image, current_host_profile='owned', node='/owned/node',
            node_sha256='a'*64, docker_sha256='a'*64,
            chromium='/owned/chrome', snapshot_sha256='d'*64,
            build_sha256='e'*64)
        events = []
        state = {'container': False}
        class FakeOwned:
            records = []
            def stop(self, deadline, child, **_kwargs):
                events.append(('stop', child))
                return True
        class FakeInspector:
            def absent(self, _path, category):
                self_category = category
                events.append(('absent', self_category))
                return True
        def result(out='', err='', code=0):
            return SimpleNamespace(stdout=out, stderr=err, returncode=code)
        def docker_run(parts, **_kwargs):
            command = tuple(parts)
            if 'info' in command: return result('owned-daemon\n')
            if command[-3:-1] == ('image', 'inspect'):
                return result(json.dumps([{'Id': image}]))
            if 'container' in command and 'inspect' in command:
                if not state['container'] or command[-1] == container and state.get('removed'):
                    return result(err=f'Error: No such object: {command[-1]}', code=1)
                return result(json.dumps([{'Id': container,
                    'Config': {'Labels': {'dvaia.test.owner': state['owner']}},
                    'State': {'Running': True, 'OOMKilled': False, 'ExitCode': 0},
                    'HostConfig': {'Memory': 2 * 1024**3, 'MemorySwap': 2 * 1024**3,
                        'NanoCpus': 2*10**9,
                        'PidsLimit': 256, 'Tmpfs': {'/var/lib/postgresql':
                            'rw,size=' + str(1024**3)}},
                    'NetworkSettings': {'Ports': {'5432/tcp':
                        [{'HostIp': '127.0.0.1', 'HostPort': '54321'}]}}}]))
            if 'run' in command:
                state['container'] = True
                state['owner'] = command[command.index('--label')+1].split('=',1)[1]
                return result(container)
            if 'pg_isready' in command: return result()
            if 'psql' in command: raise TimeoutError('simulated work deadline')
            if 'logs' in command:
                return result('server process 123 terminated by signal 9: Killed\n')
            if 'rm' in command:
                events.append(('remove', command[-1]))
                state['container'] = False
                state['removed'] = True
                return result(container)
            raise AssertionError(command)
        original_private_json = admin_q05.private_json
        def one_failed_intermediate_journal(path, payload):
            if payload.get('cleanup', {}).get('processes') is True and \
                    'containerAbsent' not in payload['cleanup'] and \
                    not state.get('journal_failed'):
                state['journal_failed'] = True
                raise OSError('simulated private journal failure')
            return original_private_json(path, payload)
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as parent:
            with patch('admin_q05_current_host.Owned', FakeOwned), \
                 patch('admin_q05_current_host.private_json', one_failed_intermediate_journal), \
                 patch.object(execution, 'validate_current_host', create=True), \
                 patch('secureshop_current_host_admission.validate_current_host',
                       return_value={'owned': True}), \
                 patch('secureshop_current_host_admission.evidence_parent',
                       return_value=Path(parent)), \
                 patch.object(execution.subprocess, 'run', side_effect=docker_run):
                outcome = execution.execute(args, repo=ROOT, inspector=FakeInspector(),
                    before={'source': 'same'}, verify_fixture=lambda *_: {'passed': True},
                    verify_tap=lambda *_: None,
                    snapshot_after=lambda: {'source': 'same'})
            receipt = json.loads(Path(outcome['evidence']).read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertIs(receipt['eligible'], False)
            self.assertEqual(receipt['error']['type'], 'TimeoutError')
            self.assertEqual(receipt['cleanup']['containerAbsent'], True)
            self.assertEqual(receipt['cleanup']['runtimeAbsent'], True)
            self.assertEqual(receipt['cleanup']['intermediateJournalErrorType'], 'OSError')
            self.assertEqual(receipt['postgresFailureDiagnostic']['backendSignalNine'], True)
            self.assertIn(('remove', container), events)


if __name__ == '__main__': unittest.main()
