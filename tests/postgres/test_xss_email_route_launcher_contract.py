"""Offline launcher boundary checks; never imports the executing launcher."""
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from xss_launcher_cleanup import cleanup_owned_containers


LAUNCHER = Path(__file__).with_name('run-xss-email-route-isolated.py')


class XssLauncherContract(unittest.TestCase):
    def test_cleanup_continues_after_identity_mismatch_and_remove_failure(self):
        inspected = {'second': {'id': 'id-second'}, 'first': RuntimeError('foreign')}
        removed = []
        def inspect(name):
            value = inspected[name]
            if isinstance(value, Exception): raise value
            return value
        def remove(name, _identity):
            removed.append(name)
            if name == 'second': raise TimeoutError('timeout')
        results, failures = cleanup_owned_containers(('first', 'second'), inspect, remove, lambda *_: True)
        self.assertEqual(removed, ['second'])
        self.assertEqual(results, [])
        self.assertEqual(failures, ['second:remove:TimeoutError', 'first:identity:RuntimeError'])

    def test_cleanup_never_removes_exactly_absent_or_mismatched_resources(self):
        removed = []
        def inspect(name):
            if name == 'absent': return None
            raise ValueError('captured identity mismatch')
        results, failures = cleanup_owned_containers(('absent', 'mismatch'), inspect,
            lambda name, identity: removed.append((name, identity)), lambda *_: True)
        self.assertEqual(removed, [])
        self.assertEqual(results, [{'name': 'absent', 'status': 'absent'}])
        self.assertEqual(failures, ['mismatch:identity:ValueError'])

    def test_cleanup_records_absence_failure_and_continues(self):
        removed = []
        results, failures = cleanup_owned_containers(('first', 'second'),
            lambda name: {'id': f'id-{name}'},
            lambda name, identity: removed.append((name, identity)),
            lambda name, _identity: name == 'first')
        self.assertEqual(removed, [('second', 'id-second'), ('first', 'id-first')])
        self.assertEqual(results, [{'name': 'first', 'status': 'removed_absence_verified', 'containerId': 'id-first'}])
        self.assertEqual(failures, ['container still exists: second'])

    def test_rejects_non_owned_docker_socket_before_resources(self):
        result = subprocess.run(
            ['python3', str(LAUNCHER), '--docker-host', 'tcp://remote.invalid:2375',
             '--package', '/tmp/missing', '--manifest', '/tmp/missing', '--manifest-sha256', '0' * 64],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Exact owned Colima verification Docker host is required', result.stderr)

    def test_source_requires_pinned_runtime_and_container_identity(self):
        source = LAUNCHER.read_text()
        for marker in (
            "EXPECTED_DOCKER_DAEMON_ID",
            "NODE_SHA256",
            "PUPPETEER_EXECUTABLE_SHA256",
            "verify_container(name, image_id, expected_id=None)",
            "container_ids.get(name)",
            "is_relative_to(Path(allowed_root).resolve())",
            "owasp-ai-goat.run-nonce",
            "validate_package(package, manifest_path, args.manifest_sha256)",
            "verify_copy(workspace, manifest)",
            "manifestSha256",
            "cleanup_owned_containers(started, inspect, remove, absent)",
        ):
            self.assertIn(marker, source)


if __name__ == '__main__':
    unittest.main()
