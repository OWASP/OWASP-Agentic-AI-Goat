"""Controlled current-host Listings package admission; no build or native run."""
import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import listings_package_candidate as package
import listings_package_goat_current as current


ROOT = Path(__file__).resolve().parents[2]
DAEMON = '945f6fce-3aaf-4d8f-a483-170464fb2416'


def probe_row(**change):
    buildx = {'path': current.GUEST_BUILDX, 'realpath': current.GUEST_BUILDX,
        'uid': 0, 'mode': 0o755, 'nlink': 1, 'regular': True,
        'sha256': current.GUEST_BUILDX_SHA256}
    docker = {'path': current.GUEST_DOCKER, 'realpath': current.GUEST_DOCKER,
        'uid': 0, 'mode': 0o755, 'nlink': 1, 'regular': True,
        'sha256': current.GUEST_DOCKER_SHA256}
    socket = {'path': current.GUEST_SOCKET, 'realpath': current.GUEST_SOCKET,
        'uid': 0, 'mode': 0o660, 'socket': True}
    row = {'buildx': buildx, 'docker': docker, 'socket': socket, 'daemonId': DAEMON}
    row.update(change)
    return row


class Admission(unittest.TestCase):
    def test_private_lifetime_never_mints_shared_image_or_network_authority(self):
        plan = current.private_lifetime_plan('a' * 32, 'b' * 64, 'c' * 64)
        self.assertEqual(plan['storageCapBytes'], 6 * 1024**3)
        self.assertEqual(plan['privateDockerHost'],
                         'unix:///var/tmp/owasp-ai-goat-v23-build-' + 'a' * 32 + '/fs/docker.sock')
        self.assertFalse(plan['sharedImageLoadAllowed'])
        self.assertFalse(plan['sharedNetworkAttachmentAllowed'])
        self.assertFalse(plan['executionApproved'])
        self.assertFalse(plan['consumerIntegrationComplete'])
        self.assertLess(plan['retirementOrder'].index('consumer'),
                        plan['retirementOrder'].index('private-daemon'))
        self.assertIn('consumer-private-endpoint', plan['requiredProofs'])
        for args in [('../escape', 'b' * 64, 'c' * 64),
                     ('a' * 32, '', 'c' * 64), ('a' * 32, 'b' * 64, 'invalid')]:
            with self.assertRaises(RuntimeError): current.private_lifetime_plan(*args)

    def authority(self, row=None):
        runner = lambda argv, **kwargs: SimpleNamespace(stdout=json.dumps(row or probe_row()))
        return current.CurrentHost(ROOT, DAEMON, runner=runner)

    def test_repository_vm_and_pinned_guest_tool_are_separate_from_historical_pin(self):
        authority = self.authority()
        self.assertEqual(authority.ssh['config'], str(ROOT / 'tasks/l/colima-goat-q/ssh.config'))
        proof = authority.guest_identity()
        self.assertEqual(proof['sha256'], current.GUEST_BUILDX_SHA256)
        self.assertNotEqual(proof['sha256'], package.BUILDX_SHA256)
        self.assertEqual(proof['daemonId'], DAEMON)

    def test_guest_owner_mode_symlink_hash_and_daemon_drift_reject_before_build(self):
        for field, value in (('uid', 501), ('mode', 0o777), ('realpath', '/tmp/redirect'),
                             ('sha256', 'a' * 64), ('nlink', 2)):
            with self.subTest(field=field):
                row = probe_row(); row['buildx'][field] = value
                with self.assertRaises(RuntimeError):
                    self.authority(row).guest_identity()
        for part, field, value in (('docker', 'sha256', 'a' * 64),
                                   ('socket', 'realpath', '/tmp/redirect'),
                                   ('socket', 'socket', False)):
            row = probe_row(); row[part][field] = value
            with self.assertRaises(RuntimeError): self.authority(row).guest_identity()
        with self.assertRaises(RuntimeError):
            self.authority(probe_row(daemonId='a' * 36)).guest_identity()

    def test_fixed_build_argv_streams_to_vm_buildx_without_host_plugin_fallback(self):
        authority = self.authority()
        with self.assertRaisesRegex(RuntimeError, 'nonce-owned'):
            authority.build_argv(['build', '--platform', 'linux/arm64', '--pull=false', '-'])
        builder = 'owasp-ai-goat-listings-builder-123456789abc'
        argv = authority.build_argv(['build', '--platform', 'linux/arm64', '--pull=false', '-'], builder=builder)
        self.assertEqual(argv[:4], ['/usr/bin/ssh', '-F', authority.ssh['config'], current.SSH_HOST])
        self.assertIn('/usr/libexec/docker/cli-plugins/docker-buildx build --builder '+builder+' --load --no-cache', argv[4])
        self.assertIn('env -i PATH=/usr/bin:/bin HOME=/nonexistent DOCKER_CONFIG=/nonexistent DOCKER_HOST=unix:///run/docker.sock', argv[4])
        self.assertTrue(argv[4].endswith(" --platform linux/arm64 --pull=false -"))
        for bad in ([], ['image', 'rm', 'foreign'], ['buildx', 'prune']):
            with self.assertRaises(RuntimeError): authority.build_argv(bad, builder=builder)
        with self.assertRaises(RuntimeError): authority.build_argv(['build', '-'], builder='default')

    def test_conflicting_host_context_and_plugin_environment_cannot_reach_guest(self):
        commands = []
        def runner(argv, **kwargs):
            commands.append((argv, kwargs))
            return SimpleNamespace(stdout=json.dumps(probe_row()))
        with patch.dict(os.environ, {'DOCKER_CONTEXT': 'foreign', 'DOCKER_HOST': 'tcp://foreign:2375',
                                      'DOCKER_CONFIG': '/tmp/foreign',
                                      'DOCKER_CLI_PLUGIN_EXTRA_DIRS': '/tmp/foreign-plugin'}):
            authority = current.CurrentHost(ROOT, DAEMON, runner=runner)
            authority.guest_identity()
            build = authority.build_argv(['build', '-'], builder='owasp-ai-goat-listings-builder-123456789abc')
        probe, options = commands[0]
        self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin'})
        self.assertNotIn('foreign', repr(probe) + repr(build))
        self.assertIn('DOCKER_HOST=unix:///run/docker.sock', repr(build))
        self.assertIn('DOCKER_CONFIG=/nonexistent', repr(build))
        self.assertIn('DOCKER_HOST=unix:///run/docker.sock', repr(probe))

    def test_profile_comes_from_original_template_with_only_fresh_nonce(self):
        authority = self.authority()
        value = authority.profile_plan('123456789abc')
        self.assertEqual(value['name'], 'owasp-ai-goat-owned-listings-123456789abc')
        self.assertEqual(value['platform'], 'darwin')
        self.assertEqual(value['sshHost'], current.SSH_HOST)
        self.assertEqual(value['sshConfig'], authority.ssh['config'])
        with self.assertRaises(RuntimeError): authority.profile_plan('../invalid')

    def test_current_mode_plan_is_inert_and_historical_plan_remains_distinct(self):
        args = SimpleNamespace(plan=True)
        api = SimpleNamespace()
        for mode, expected in ((None, 'listings-package'), (self.authority(), 'listings-package-goat-current-v1')):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(package.qualify(api, args, ROOT, current_host=mode), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value['cohort'], expected)
            self.assertFalse(value['nativeStarted'])
            self.assertFalse(value['sourceCopy'])

    def test_current_mode_live_gate_rejects_before_allocating_evidence(self):
        args = SimpleNamespace(plan=False, current_host_profile='goat-q', docker_daemon=DAEMON,
            docker_host='unix://' + str(ROOT / '.qualification/goat-q/docker.sock'), evidence_parent=None)
        with self.assertRaisesRegex(RuntimeError, 'remains closed'):
            package.qualify(SimpleNamespace(), args, ROOT, current_host=self.authority())

    def test_ssh_config_denies_extra_command_or_redirected_identity(self):
        config = ROOT / 'tasks/l/colima-goat-q/ssh.config'
        original = config.read_text()
        with patch.object(Path, 'read_text', autospec=True, side_effect=lambda path, *a, **kw:
                          original + '\n  ProxyCommand echo unsafe\n' if path == config else original):
            with self.assertRaises(RuntimeError): current.ssh_configuration(ROOT)


if __name__ == '__main__':
    unittest.main()
