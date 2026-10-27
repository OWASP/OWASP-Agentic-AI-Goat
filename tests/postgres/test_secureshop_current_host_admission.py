"""Offline admission checks; no Docker or PostgreSQL is started."""

import hashlib
import importlib.util
import contextlib
import io
import json
import inspect
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from secureshop_current_host_admission import evidence_parent, validate_current_host


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGE = 'sha256:' + 'b' * 64
DAEMON = 'a' * 32


class CurrentHostAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.q-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        profile = self.workspace / '.qualification' / 'goat-q'
        profile.mkdir(parents=True)
        self.socket_path = profile / 'docker.sock'
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(self.socket_path))
        self.addCleanup(listener.close)
        self.node = self.workspace / 'node'
        self.docker = self.workspace / 'docker'
        self.node.write_bytes(b'owned node executable')
        self.docker.write_bytes(b'owned docker executable')
        self.node.chmod(0o700)
        self.docker.chmod(0o700)
        self.kwargs = dict(
            workspace=self.workspace, profile='goat-q', docker_host='unix://' + str(self.socket_path),
            node=str(self.node), node_sha256=hashlib.sha256(self.node.read_bytes()).hexdigest(),
            docker=str(self.docker), docker_sha256=hashlib.sha256(self.docker.read_bytes()).hexdigest(),
            daemon_id=DAEMON, image_id=IMAGE, uid=os.getuid(),
            version_runner=lambda *args, **kwargs: SimpleNamespace(stdout='v26.10.0\n'))

    def test_accepts_exact_owned_dedicated_socket_and_pins(self):
        admitted = validate_current_host(**self.kwargs)
        self.assertEqual(admitted['dockerHost'], self.kwargs['docker_host'])
        self.assertEqual(admitted['postgresImageId'], IMAGE)
        self.assertEqual(admitted['daemonId'], DAEMON)

    def test_rejects_default_or_foreign_socket(self):
        for update in (
            {'profile': 'default'},
            {'profile': 'colima-default'},
            {'docker_host': 'unix:///var/run/docker.sock'},
            {'docker_host': 'unix://' + str(self.workspace / '.qualification' / 'other' / 'docker.sock')},
        ):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                validate_current_host(**{**self.kwargs, **update})

    def test_rejects_missing_and_linked_socket(self):
        self.socket_path.unlink()
        with self.assertRaisesRegex(RuntimeError, 'socket'):
            validate_current_host(**self.kwargs)
        target = self.workspace / 'target.sock'
        other = socket.socket(socket.AF_UNIX)
        self.addCleanup(other.close)
        other.bind(str(target))
        self.socket_path.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'socket'):
            validate_current_host(**self.kwargs)

    def test_rejects_changed_binary_hash_or_link(self):
        with self.assertRaisesRegex(RuntimeError, 'node digest mismatch'):
            validate_current_host(**{**self.kwargs, 'node_sha256': 'f' * 64})
        link = self.workspace / 'linked-node'
        link.symlink_to(self.node)
        with self.assertRaisesRegex(RuntimeError, 'Canonical node'):
            validate_current_host(**{**self.kwargs, 'node': str(link)})
        with self.assertRaisesRegex(RuntimeError, 'docker digest mismatch'):
            validate_current_host(**{**self.kwargs, 'docker_sha256': 'f' * 64})

    def test_rejects_malformed_identity_and_wrong_node_version(self):
        for update in ({'daemon_id': 'short'}, {'image_id': 'postgres:18'}, {'node_sha256': 'bad'}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                validate_current_host(**{**self.kwargs, **update})
        with self.assertRaisesRegex(RuntimeError, 'Node 26.10'):
            validate_current_host(**{**self.kwargs, 'version_runner':
                lambda *args, **kwargs: SimpleNamespace(stdout='v25.0.0')})

    def test_launcher_requires_explicit_profile_for_node_override(self):
        spec = importlib.util.spec_from_file_location('secureshop_transport_current_host',
                                                   HERE / 'run-secureshop-agent-host-transport-main.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        base = ['--main-workspace', str(HERE.parents[1]), '--node', str(self.node),
                '--docker', str(self.docker), '--docker-sha256', self.kwargs['docker_sha256'],
                '--docker-host', self.kwargs['docker_host'], '--docker-daemon', DAEMON,
                '--image-id', IMAGE]
        args = launcher.parse(base + ['--node-sha256', self.kwargs['node_sha256']])
        with self.assertRaisesRegex(RuntimeError, 'requires explicit current-host profile'):
            launcher.validate_static(args)
        args = launcher.parse(base + ['--current-host-profile', 'goat-q',
                                      '--node-sha256', self.kwargs['node_sha256']])
        with patch.object(launcher, 'validate_current_host', return_value={} ) as admission:
            self.assertEqual(launcher.validate_static(args), HERE.parents[1])
            self.assertEqual(admission.call_args.kwargs['profile'], 'goat-q')

    def test_evidence_parent_is_exact_checkout_destination_before_creation(self):
        tasks = self.workspace / 'tasks'
        tasks.mkdir()
        destination = tasks / 'qualification'
        self.assertEqual(evidence_parent(self.workspace), destination)
        self.assertFalse(destination.exists())
        self.assertEqual(evidence_parent(self.workspace, str(destination)), destination)
        for requested in ('/tmp/outside', str(tasks / '..' / 'tasks' / 'qualification'),
                          str(destination / 'nested'), 'tasks/qualification'):
            with self.subTest(requested=requested), self.assertRaises(RuntimeError):
                evidence_parent(self.workspace, requested)
        destination.symlink_to(self.workspace)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            evidence_parent(self.workspace)

    def test_launcher_plan_rejects_foreign_evidence_before_any_creation(self):
        spec = importlib.util.spec_from_file_location('secureshop_transport_evidence',
                                                   HERE / 'run-secureshop-agent-host-transport-main.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        argv = ['--main-workspace', str(ROOT), '--node', str(self.node),
                '--docker', str(self.docker), '--docker-sha256', self.kwargs['docker_sha256'],
                '--docker-host', self.kwargs['docker_host'], '--docker-daemon', DAEMON,
                '--image-id', IMAGE, '--current-host-profile', 'goat-q',
                '--node-sha256', self.kwargs['node_sha256'], '--cohort', 'transport', '--plan',
                '--evidence-parent', '/tmp/foreign']
        with patch.object(launcher, 'validate_static', return_value=ROOT):
            with self.assertRaisesRegex(RuntimeError, 'tasks/qualification'):
                launcher.main(argv)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(launcher.main(argv[:-2]), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual(plan['workspace'], str(ROOT))
            self.assertIs(plan['sourceCopy'], False)
            self.assertIs(plan['nativeStarted'], False)

    def test_current_host_selection_never_queries_legacy_temp_directory(self):
        spec = importlib.util.spec_from_file_location('secureshop_transport_temp',
                                                   HERE / 'run-secureshop-agent-host-transport-main.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        args = SimpleNamespace(current_host_profile='goat-q', evidence_parent=None, cohort='scene')
        with patch.object(launcher.tempfile, 'gettempdir', side_effect=AssertionError('external temp probed')):
            self.assertEqual(launcher.select_evidence_parent(args, ROOT, 'legacy'),
                             ROOT / 'tasks' / 'qualification')

    def test_changed_current_host_node_pin_drives_later_integrity_checks(self):
        spec = importlib.util.spec_from_file_location('secureshop_transport_node',
                                                   HERE / 'run-secureshop-agent-host-transport-main.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        selected = SimpleNamespace(current_host_profile='goat-q', node_sha256=self.kwargs['node_sha256'])
        admitted = launcher.effective_node_sha256(selected)
        self.assertNotEqual(admitted, launcher.NODE_SHA256)
        self.assertTrue(launcher.node_pin_matches(self.node, admitted))
        self.assertFalse(launcher.node_pin_matches(self.node, launcher.NODE_SHA256))
        self.node.write_bytes(b'changed after admission')
        self.assertFalse(launcher.node_pin_matches(self.node, admitted))
        legacy = SimpleNamespace(current_host_profile=None, node_sha256=None)
        self.assertEqual(launcher.effective_node_sha256(legacy), launcher.NODE_SHA256)
        main_source = inspect.getsource(launcher.main)
        self.assertNotIn('digest(args.node)', main_source)
        self.assertIn("'nodeSha256': admitted_node_sha256", main_source)

    def test_current_host_child_environment_has_no_home_override(self):
        spec = importlib.util.spec_from_file_location('secureshop_transport_environment',
                                                   HERE / 'run-secureshop-agent-host-transport-main.py')
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        args = SimpleNamespace(current_host_profile='goat-q', node=str(self.node),
                               docker=str(self.docker), docker_host=self.kwargs['docker_host'])
        runtime = self.workspace / 'tasks' / 'qualification' / 'run-test' / 'runtime'
        current = launcher.runtime_environment(args, runtime)
        self.assertNotIn('HOME', current)
        for key in ('TMPDIR', 'MAC_CHROMIUM_TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'DOCKER_CONFIG', 'npm_config_cache'):
            self.assertTrue(Path(current[key]).is_relative_to(runtime), key)
        self.assertEqual(current['MAC_CHROMIUM_TMPDIR'], current['TMPDIR'])
        args.current_host_profile = None
        legacy = launcher.runtime_environment(args, runtime)
        self.assertEqual(legacy['HOME'], str(runtime / 'home'))


if __name__ == '__main__':
    unittest.main()
