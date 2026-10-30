"""Offline executable fault-path checks for the SecureShop review launcher."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

LAUNCHER = Path(__file__).with_name('run-secureshop-review-db-isolated.py')
SPEC = importlib.util.spec_from_file_location('review_launcher', LAUNCHER)
LAUNCHER_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER_MODULE)


class LauncherContract(unittest.TestCase):
    def test_compiles_and_has_review_specific_bindings(self):
        source = LAUNCHER.read_text()
        compile(source, str(LAUNCHER), 'exec')
        for token in ("'grant-file'", "'grant-id'", "'owner-handle-file'", "'package-root'",
                      "'manifest'", "'managed-node'", "'postgres-image-id'", "'container-nonce'",
                      "'run', '--detach', '--pull', 'never'", "'127.0.0.1::5432'", 'owasp-ai-goat.owner',
                      'WAITING_OWNER_HANDLE', 'canonicalWorkspaceRoot', 'candidateSourceRoot',
                      'sourceFilesSha256', 'terminal_pass_cleaned', 'unowned container cleanup refused',
                      'grant already consumed', "NODE_VERSION = 'v26.8.2'",
                      "POSTGRES_IMAGE = 'postgres:18'", 'DOCKER_DAEMON_ID', 'process_group_absent',
                      'docker_object_absent', 'containerCreateAttempt', 'terminalGrantRecorded',
                      'dockerCliPath', 'dockerCliSha256', 'validate_container_id', 'secureshopReviewDb'):
            self.assertIn(token, source)
        self.assertNotIn('fcntl', source)
        self.assertNotIn('activeSlotPath', source)
        self.assertNotIn('legacyAiHistory', source)
        self.assertNotIn("os.environ['PATH']", source)

    def test_rejects_wrong_owner_before_docker_or_filesystem_resources(self):
        package = Path(__file__).parents[2]
        args = [sys.executable, str(LAUNCHER), '--grant-file', str(package / 'package.json'), '--grant-id', 'g',
                '--owner', '/not-root', '--owner-handle-file', str(package / 'package.json'),
                '--docker-host', 'unix:///invalid', '--container-nonce', 'a' * 12,
                '--evidence-root', '/missing/evidence', '--docker-cli', '/bin/echo',
                '--docker-cli-sha256', '0' * 64,
                '--canonical-workspace', '/', '--package-root', str(package),
                '--manifest', str(package / 'package.json'), '--managed-node', '/bin/sh',
                '--postgres-image-id', 'sha256:' + '0' * 64, '--scope', 'secureshop_review_db']
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('root launcher binding invalid', result.stderr)

    def test_cleanup_rejects_unowned_replacement_and_image_mismatch(self):
        good_id = 'a' * 64
        calls = []
        original = LAUNCHER_MODULE.run

        def fake_run(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout=json.dumps([{
                'Id': good_id, 'Name': '/review', 'Image': 'sha256:' + 'b' * 64,
                'Config': {'Labels': {'owasp-ai-goat.owner': '/root'}}}]), stderr='')

        LAUNCHER_MODULE.run = fake_run
        try:
            with self.assertRaisesRegex(RuntimeError, 'unowned container cleanup refused'):
                LAUNCHER_MODULE.remove_owned_container(
                    ['docker'], 'review', good_id, {'owasp-ai-goat.owner': '/root'},
                    expected_image='sha256:' + 'c' * 64)
        finally:
            LAUNCHER_MODULE.run = original
        self.assertEqual(len(calls), 1)

    def test_cleanup_refuses_inspect_error_and_rm_failure(self):
        original = LAUNCHER_MODULE.run
        try:
            LAUNCHER_MODULE.run = lambda command, **kwargs: SimpleNamespace(
                returncode=2, stdout='', stderr='daemon unavailable')
            with self.assertRaisesRegex(RuntimeError, 'inspection failed'):
                LAUNCHER_MODULE.remove_owned_container(['docker'], 'review', 'a' * 64, {})

            def rm_failure(command, **kwargs):
                if command[1] == 'inspect':
                    return SimpleNamespace(returncode=0, stdout=json.dumps([{
                        'Id': 'a' * 64, 'Name': '/review', 'Image': 'sha256:' + 'b' * 64,
                        'Config': {'Labels': {}}}]), stderr='')
                return SimpleNamespace(returncode=1, stdout='', stderr='rm failed')

            LAUNCHER_MODULE.run = rm_failure
            with self.assertRaisesRegex(RuntimeError, 'removal failed'):
                LAUNCHER_MODULE.remove_owned_container(['docker'], 'review', 'a' * 64, {},
                                                        expected_image='sha256:' + 'b' * 64)
        finally:
            LAUNCHER_MODULE.run = original

    def test_interrupted_create_cleans_by_name_and_malformed_id_stops(self):
        original = LAUNCHER_MODULE.run
        original_sleep = LAUNCHER_MODULE.time.sleep
        try:
            responses = [SimpleNamespace(returncode=1, stdout='', stderr='No such object: review\n'),
                         SimpleNamespace(returncode=1, stdout='', stderr='No such object: review\n'),
                         SimpleNamespace(returncode=0, stdout=json.dumps([{
                    'Id': 'a' * 64, 'Name': '/review', 'Image': 'sha256:' + 'b' * 64,
                    'Config': {'Labels': {}}}]), stderr=''),
                         SimpleNamespace(returncode=0, stdout='', stderr='')]
            calls = []
            LAUNCHER_MODULE.run = lambda command, **kwargs: (calls.append(command) or responses.pop(0))
            LAUNCHER_MODULE.time.sleep = lambda _: None
            self.assertEqual(LAUNCHER_MODULE.remove_owned_container(
                ['docker'], 'review', None, {}, expected_image='sha256:' + 'b' * 64), 'a' * 64)
            self.assertEqual(len(calls), 4)
        finally:
            LAUNCHER_MODULE.run = original
            LAUNCHER_MODULE.time.sleep = original_sleep
        try:
            calls = []
            LAUNCHER_MODULE.run = lambda command, **kwargs: (
                calls.append(command) or SimpleNamespace(
                    returncode=1, stdout='', stderr='No such object: review\n'))
            LAUNCHER_MODULE.time.sleep = lambda _: None
            with self.assertRaisesRegex(RuntimeError, 'outcome unresolved'):
                LAUNCHER_MODULE.remove_owned_container(
                    ['docker'], 'review', None, {}, expected_image='sha256:' + 'b' * 64,
                    require_seen=True)
            self.assertEqual(len(calls), LAUNCHER_MODULE.CLEANUP_RECONCILE_ATTEMPTS)
        finally:
            LAUNCHER_MODULE.run = original
            LAUNCHER_MODULE.time.sleep = original_sleep
        with self.assertRaisesRegex(RuntimeError, 'invalid owned container id'):
            LAUNCHER_MODULE.validate_container_id('container-name-output')

    def test_malformed_docker_absence_is_not_treated_as_clean(self):
        original = LAUNCHER_MODULE.run
        LAUNCHER_MODULE.run = lambda command, **kwargs: SimpleNamespace(
            returncode=1, stdout='not found', stderr='')
        try:
            with self.assertRaisesRegex(RuntimeError, 'absence could not be verified'):
                LAUNCHER_MODULE.docker_object_absent(['docker'], 'review')
        finally:
            LAUNCHER_MODULE.run = original

    def test_grant_consumption_registration_and_terminal_state_faults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'grant.json'
            expected = {'grantId': 'g', 'containerName': 'review'}
            path.write_text(json.dumps({**expected, 'status': 'granted'}))
            consumed = LAUNCHER_MODULE.consume_grant(path, expected, Path(directory) / 'evidence')
            self.assertEqual(consumed['status'], 'consumed')
            with self.assertRaisesRegex(RuntimeError, 'already consumed'):
                LAUNCHER_MODULE.consume_grant(path, expected, Path(directory) / 'evidence')

            path.write_text(json.dumps({'grantId': 'changed', 'containerName': 'review',
                                        'status': 'granted'}))
            with self.assertRaisesRegex(RuntimeError, 'binding mismatch'):
                LAUNCHER_MODULE.consume_grant(path, expected, Path(directory) / 'evidence')

            path.write_text(json.dumps({**expected, 'status': 'consumed', 'ownerHandle': 7,
                                        'consumerPid': 123}))
            with self.assertRaisesRegex(RuntimeError, 'owner handle mismatch'):
                LAUNCHER_MODULE.wait_for_owner_handle(path, 8, timeout=.1)
            with self.assertRaisesRegex(RuntimeError, 'registration timeout'):
                LAUNCHER_MODULE.wait_for_owner_handle(path, 7, timeout=0)
            with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                LAUNCHER_MODULE.record_terminal_grant(
                    path, 'wrong', 7, 'terminal_fail', Path(directory), {}, process_id=123)

            path.write_text(json.dumps({**expected, 'status': 'consumed', 'ownerHandle': 7,
                                        'consumerPid': 123}))
            result = LAUNCHER_MODULE.record_terminal_grant(
                path, 'g', 7, 'terminal_fail', Path(directory), {}, process_id=123)
            self.assertEqual(result['runStatus'], 'terminal_fail')
            original_save = LAUNCHER_MODULE.save_json
            LAUNCHER_MODULE.save_json = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError('terminal persistence failed'))
            try:
                with self.assertRaisesRegex(OSError, 'terminal persistence failed'):
                    LAUNCHER_MODULE.record_terminal_grant(
                        path, 'g', 7, 'terminal_fail', Path(directory), {}, process_id=123)
            finally:
                LAUNCHER_MODULE.save_json = original_save

    def test_process_group_fault_and_tap_validation_are_bounded(self):
        self.assertTrue(LAUNCHER_MODULE.process_group_absent(999999999))
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'bad.tap'
            log.write_text('# pass 1\n# fail 1\n# skipped 0\n')
            with self.assertRaisesRegex(RuntimeError, 'did not prove'):
                LAUNCHER_MODULE.verify_tap(log)


if __name__ == '__main__':
    unittest.main()
