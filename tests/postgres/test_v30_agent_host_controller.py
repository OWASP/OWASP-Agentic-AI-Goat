"""Controlled only: no host, Docker, VM, network or model launch."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import v30_agent_host_controller as C

SPEC = importlib.util.spec_from_file_location('v30_outside_coordinator', Path(__file__).with_name('run_v30_with_host_controller.py'))
COORDINATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COORDINATOR)
PROBE_SPEC = importlib.util.spec_from_file_location('v30_boundary_probe', Path(__file__).with_name('run_v30_controller_boundary_probe.py'))
PROBE = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_SPEC.loader.exec_module(PROBE)


class FakeDriver:
    def __init__(self):
        self.calls = []; self.pid = None; self.code = None; self.fail_stop = False; self.fail_probe = False
    def launcher(self): self.calls.append('launcher')
    def bind_worker(self, pid, grant): self.calls.append(('bind', pid))
    def worker(self): self.calls.append('worker')
    def verify_pg(self, grant): self.calls.append('verify-pg')
    def probe(self, grant, profile):
        self.calls.append('probe')
        if self.fail_probe: raise RuntimeError('controlled probe failure')
        return {'version': 1, 'policySha256': C.sha(profile), 'probePid': 102,
                'probeTerminal': {'exitCode': 0, 'signalCode': None},
                'postgresAllowed': True, 'modelDenied': True, 'externalDenied': True,
                'loopbackBound': True, 'loopbackInboundVerified': True}
    def start(self, grant, profile, instance_id):
        self.calls.append('start'); self.pid = 103; return 103, [1234, 56]
    def host_identity(self): return (None, None) if self.pid is None else (self.pid, [1234, 56])
    def terminal(self): return self.code
    def signal(self, name): self.calls.append(('signal', name))
    def stop(self, grant):
        self.calls.append('stop')
        if self.fail_stop: raise RuntimeError('controlled unresolved process')
        if self.pid: self.code = {'exitCode': 0, 'signalCode': None}
        return self.code


class Contracts(unittest.TestCase):
    def setUp(self):
        # The wrapper supplies an owned repository TMPDIR. Do not create test
        # artifacts in an implicit host /tmp directory.
        repository = Path(__file__).resolve().parents[2]
        temporary = Path(os.environ['TMPDIR']).resolve()
        self.assertTrue(temporary.is_relative_to(repository))
        self.temp = tempfile.TemporaryDirectory(prefix='v30-controller-', dir=temporary)
        self.repo = Path(self.temp.name).resolve()
        self.run = self.repo / 'tasks/qualification/run-controlled'
        for directory in (self.run.parent, self.run, self.run / 'runtime', self.run / 'runtime/tmp'):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700); directory.chmod(0o700)
        node = self.repo / C.NODE_RELATIVE
        node.parent.mkdir(parents=True); node.write_bytes(b'controlled node'); node.chmod(0o700)
        self.node_digest = C.sha(node)
        rows = {}
        for name in ('agent-host/index.js', C.FIXTURE, 'server/services/secureshop/agentHostSupervisor.js'):
            target = self.repo / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(name)
            rows[name] = C.sha(target)
        self.manifest = self.run / 'source-before.json'
        self.manifest.write_bytes(C.encoded({'cohort': C.COHORT, 'sourcePins': rows, 'dependencyInventory': {}}))
        self.manifest.chmod(0o600)
        self.grant = {'run': str(self.run), 'nodePath': str(node), 'nodeSha256': self.node_digest,
            'sourceManifestSha256': C.sha(self.manifest), 'pgNonce': '1' * 12, 'pgPort': 40101, 'hostPort': 40102,
            'commerceUrl': 'postgresql://dvaia_secureshop_runtime@127.0.0.1:40101/owasp_ai_goat_test_agent_host_' + '1' * 12 + '_secureshop',
            'agentsUrl': 'postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:40101/owasp_ai_goat_test_agent_host_' + '1' * 12 + '_secureshop_agents',
            'containerId': '2' * 64, 'owner': '11111111-2222-4333-8444-555555555555'}
        self.nonce = 'a' * 64
        self.driver = FakeDriver()
        self.pin = mock.patch.object(C, 'NODE_SHA256', self.node_digest); self.pin.start()
        def validate(repo, grant): return C.validate_grant(repo, grant, check_dependencies=False)
        self.controller = C.Controller(self.repo, 101, self.nonce, self.driver, validator=validate)
        self.seq = {'launcher': 0, 'worker': 0}

    def tearDown(self):
        if self.controller.archive: self.controller.archive.close()
        self.pin.stop(); self.temp.cleanup()

    def request(self, side, op, value):
        self.seq[side] += 1
        return {'version': 1, 'sequence': self.seq[side], 'nonce': self.nonce,
                'pid': 101 if side == 'launcher' else 102, 'op': op, 'payload': value}

    def call(self, side, op, value):
        return self.controller.handle(side, self.request(side, op, value))

    def admitted(self):
        result = self.call('launcher', 'grant', self.grant)
        self.assertEqual(result['hostPort'], 40102)
        self.call('launcher', 'bind-worker', {'pid': 102})
        return self.call('worker', 'hello', {})

    def test_live_gate_denies_before_any_resource_or_probe(self):
        args = ['--run', '--cohort', 'v30-original-disclosure', '--v30-original-profile', C.PROFILE]
        with mock.patch.object(COORDINATOR.socket, 'socketpair') as pair, mock.patch.object(COORDINATOR.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'UNQUALIFIED'):
                COORDINATOR.coordinate(self.repo, args)
            pair.assert_not_called(); spawn.assert_not_called()
        driver = C.DarwinDriver(self.repo, 101, api=mock.Mock())
        with mock.patch.object(C.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'UNQUALIFIED'):
                driver._capture(['/not/a/capability'], {})
            spawn.assert_not_called()

    def test_distinct_v3_profile_binds_launcher_argv_before_worker(self):
        self.assertTrue(C.FULL_LIVE_ENABLED)
        self.assertFalse(C.LIVE_ENABLED)
        v3 = ['--run', '--cohort', 'v30-original-disclosure',
              '--v30-original-profile', C.FULL_PROFILE]
        self.assertEqual(COORDINATOR.validate_arguments(v3), C.FULL_PROFILE)
        with mock.patch.object(C, 'FULL_LIVE_ENABLED', False), \
                mock.patch.object(COORDINATOR.socket, 'socketpair') as pair, \
                mock.patch.object(COORDINATOR.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'UNQUALIFIED'):
                COORDINATOR.coordinate(self.repo, v3)
            pair.assert_not_called(); spawn.assert_not_called()
        driver_closed = C.DarwinDriver(self.repo, 101, api=mock.Mock(),
                                       expected_profile=C.FULL_PROFILE)
        with mock.patch.object(C, 'FULL_LIVE_ENABLED', False), \
                mock.patch.object(C.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'UNQUALIFIED'):
                driver_closed._capture(['/not/a/capability'], {})
            spawn.assert_not_called()
        self.assertEqual(COORDINATOR.validate_arguments(
            ['--run', '--cohort', 'v30-original-disclosure',
             '--v30-original-profile', C.PROFILE]), C.PROFILE)
        for bad in ('unsupported-v4', '', None):
            with self.subTest(bad=bad), self.assertRaisesRegex(RuntimeError, 'ARGUMENTS'):
                COORDINATOR.validate_arguments(v3[:-1] + ([bad] if bad is not None else []))
        for bad in (v3[1:] + ['--run'], v3 + ['--run'], v3 + ['--plan']):
            with self.subTest(bad=bad), self.assertRaisesRegex(RuntimeError, 'ARGUMENTS'):
                COORDINATOR.validate_arguments(bad)
        def row():
            return mock.Mock(pid=101, ppid=os.getpid(), uid=os.getuid(),
                             ruid=os.getuid(), pgid=101, start_sec=10, start_usec=20)
        api = mock.Mock()
        api.identity.side_effect = lambda _: row()
        api.arguments.return_value = ('python3', 'tests/postgres/run-secureshop-agent-host-transport-main.py',
                                      '--cohort', 'v30-original-disclosure',
                                      '--v30-original-profile', C.FULL_PROFILE)
        C.DarwinDriver(self.repo, 101, api=api, expected_profile=C.FULL_PROFILE).launcher()
        with self.assertRaisesRegex(RuntimeError, 'LAUNCHER'):
            C.DarwinDriver(self.repo, 101, api=api, expected_profile=C.PROFILE).launcher()
        with self.assertRaisesRegex(RuntimeError, 'PROFILE'):
            C.DarwinDriver(self.repo, 101, api=api, expected_profile='unreviewed-v4')

    def test_grant_exact_urls_ports_roles_source_and_dependency_bytes(self):
        C.validate_grant(self.repo, self.grant, check_dependencies=False)
        for key, value in [('pgPort', True), ('hostPort', 11434), ('hostPort', 40101),
            ('nodeSha256', 'f' * 64), ('sourceManifestSha256', 'f' * 64),
            ('commerceUrl', self.grant['commerceUrl'].replace('_runtime@', '_migration@')),
            ('agentsUrl', self.grant['commerceUrl']), ('containerId', '../escape'), ('owner', 'owner')]:
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                C.validate_grant(self.repo, {**self.grant, key: value}, check_dependencies=False)
        with self.assertRaises(RuntimeError):
            C.validate_grant(self.repo, {**self.grant, 'env': {'NODE_OPTIONS': '-e evil'}}, check_dependencies=False)
        with mock.patch.object(C, 'dependency_inventory', return_value={'changed': True}), self.assertRaisesRegex(RuntimeError, 'DEPENDENCIES'):
            C.validate_grant(self.repo, self.grant)
        (self.repo / 'agent-host/index.js').write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'SOURCE'):
            C.validate_grant(self.repo, self.grant, check_dependencies=False)

    def test_private_paths_and_manifest_replacement_reject_before_archive(self):
        self.manifest.chmod(0o644)
        with self.assertRaises(RuntimeError): self.call('launcher', 'grant', self.grant)
        self.assertIsNone(self.controller.archive)
        self.manifest.chmod(0o600)
        body = json.loads(self.manifest.read_bytes()); body['sourcePins']['../outside'] = 'f' * 64
        self.manifest.write_bytes(C.encoded(body)); self.grant['sourceManifestSha256'] = C.sha(self.manifest)
        with self.assertRaises(RuntimeError): self.call('launcher', 'grant', self.grant)

    def test_combined_policy_and_host_environment_are_fixed_and_no_provider(self):
        policy = C.combined_policy(self.repo, 40101, 40102)
        for text in ('(deny file-write*)', '(deny network*)',
                     '(allow network-outbound (remote tcp "localhost:40101"))',
                     '(allow network-bind (local tcp "localhost:40102"))',
                     '(allow network-inbound (local tcp "localhost:40102"))'):
            self.assertIn(text, policy)
        self.assertNotIn('*:40102', policy)
        self.assertNotIn('127.0.0.1:', policy)
        env = C.host_environment(self.grant, self.grant['owner'])
        self.assertEqual(env['SS_AGENT_HOST_BIND_HOST'], '127.0.0.1')
        self.assertEqual({key: env[key] for key in C.POOL_LIMITS}, C.POOL_LIMITS)
        self.assertFalse(any('MIGRATION_DATABASE' in key or 'OLLAMA' in key or key in ('NODE_OPTIONS', 'HOME') for key in env))
        self.assertEqual(env['SECURESHOP_DATABASE_URL'], self.grant['commerceUrl'])

    def test_nonce_sequence_schema_and_channel_identity_fail_closed(self):
        self.admitted()
        request = self.request('worker', 'start', {'instanceId': self.grant['owner']})
        for changed in ({**request, 'nonce': 'b' * 64}, {**request, 'pid': 999},
                        {**request, 'sequence': True}, {**request, 'command': 'anything'}):
            with self.assertRaises(RuntimeError): self.controller.handle('worker', changed)
        self.assertNotIn('start', self.driver.calls)
        # A consumed invalid owner frame cannot be replayed at the same sequence.
        with self.assertRaises(RuntimeError): self.controller.handle('worker', request)

    def test_one_host_actual_terminal_and_cleanup_receipt(self):
        self.assertEqual(self.admitted()['phase'], 'bound')
        running = self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.assertEqual((running['pid'], running['birth']), (103, [1234, 56]))
        self.assertIsNone(running['terminal']); self.assertFalse(running['cleanupVerified'])
        self.call('worker', 'signal', {'signal': 'SIGTERM'})
        self.assertIsNone(self.call('worker', 'status', {})['terminal'])
        terminal = self.call('launcher', 'stop', {})
        self.assertTrue(terminal['cleanupVerified'])
        self.assertEqual(terminal['terminal'], {'exitCode': 0, 'signalCode': None})
        receipt = self.run / 'v30-host-controller.json'
        self.assertEqual(C.sha(receipt), terminal['receiptSha256'])
        self.assertEqual(json.loads(receipt.read_bytes())['state'], {k: v for k, v in terminal.items() if k != 'receiptSha256'})
        with self.assertRaises(RuntimeError): self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.assertEqual(self.driver.calls.count('start'), 1)

    def test_probe_failure_consumes_start_without_host_or_retry(self):
        self.admitted(); self.driver.fail_probe = True
        with self.assertRaises(RuntimeError): self.call('worker', 'start', {'instanceId': self.grant['owner']})
        with self.assertRaises(RuntimeError): self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.assertNotIn('start', self.driver.calls)
        result = self.controller.stop()
        self.assertIsNone(result['pid']); self.assertIsNone(result['terminal']); self.assertTrue(result['cleanupVerified'])
        self.assertIsNone(result['birth']); self.assertIsNone(result['instanceId'])
        journal = [json.loads(line) for line in (self.run / 'v30-host-controller.jsonl').read_bytes().splitlines()]
        attempt = next(row for row in journal if row['event'] == 'start-attempted')
        self.assertEqual(attempt['state']['instanceId'], self.grant['owner'])

    def test_spawn_error_keeps_real_child_identity_until_cleanup_proven(self):
        self.admitted()
        def failed_start(*_):
            self.driver.pid = 103
            raise RuntimeError('controlled failure after actual spawn')
        self.driver.start = failed_start
        with self.assertRaises(RuntimeError):
            self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.driver.fail_stop = True
        with self.assertRaises(RuntimeError): self.controller.stop()
        self.assertEqual(self.controller.state['pid'], 103)
        self.assertEqual(self.controller.state['birth'], [1234, 56])
        self.assertEqual(self.controller.state['instanceId'], self.grant['owner'])
        self.assertFalse(self.controller.state['cleanupVerified'])
        self.driver.fail_stop = False
        result = self.controller.stop()
        self.assertEqual(result['pid'], 103); self.assertTrue(result['cleanupVerified'])

    def test_worker_loss_owner_closes_and_uncertain_stop_never_emits_clean(self):
        self.admitted(); self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.driver.fail_stop = True
        with self.assertRaises(RuntimeError): self.controller.stop()
        state = self.controller.status()
        self.assertFalse(state['cleanupVerified']); self.assertEqual(state['phase'], 'failed')
        self.assertIsNone(state['terminal']); self.assertEqual(state['pid'], 103)
        self.driver.fail_stop = False
        self.assertTrue(self.controller.stop()['cleanupVerified'])

    def test_source_or_policy_drift_before_start_prevents_effect(self):
        self.admitted()
        (self.run / 'v30-agent-host-combined.sb').write_text('(allow default)')
        with self.assertRaisesRegex(RuntimeError, 'POLICY'):
            self.call('worker', 'start', {'instanceId': self.grant['owner']})
        self.assertNotIn('probe', self.driver.calls); self.assertNotIn('start', self.driver.calls)

    def test_framing_rejects_duplicate_keys_nonfinite_and_oversized_header(self):
        for raw in (b'{"op":1,"op":2}', b'{"x":NaN}'):
            with self.assertRaises(RuntimeError): C.unique_json(raw)
        stream = mock.Mock(); stream.recv.return_value = (C.MAX_FRAME + 1).to_bytes(4, 'big')
        with self.assertRaises(RuntimeError): C.receive(stream)
        self.assertEqual(stream.recv.call_count, 1)

    def test_full_frame_deadline_bounds_slow_header_and_body_for_both_channels(self):
        for reader in (C.receive, COORDINATOR.inspector_receive):
            for header_slow in (True, False):
                with self.subTest(reader=reader.__name__, header_slow=header_slow):
                    clock = [0.0]; stream = mock.Mock()
                    raw = bytearray((8).to_bytes(4, 'big') + b'{"x":12}')
                    calls = [0]
                    def drip(size):
                        calls[0] += 1
                        count = 1 if header_slow or calls[0] > 1 else 4
                        clock[0] += .7
                        part = bytes(raw[:count]); del raw[:count]
                        return part
                    stream.recv.side_effect = drip
                    with mock.patch.object(C.time, 'monotonic', side_effect=lambda: clock[0]):
                        with self.assertRaisesRegex(TimeoutError, 'FRAME_TIMEOUT'):
                            reader(stream, timeout=2)
                    self.assertEqual(calls[0], 3)
                    self.assertLess(stream.settimeout.call_args.args[0], .61)
        stream = mock.Mock()
        stream.recv.return_value = (COORDINATOR.INSPECTOR_MAX_FRAME + 1).to_bytes(4, 'big')
        with self.assertRaises(RuntimeError): COORDINATOR.inspector_receive(stream)
        stream.sendall.side_effect = TimeoutError('controlled total send deadline')
        with self.assertRaises(TimeoutError): C.send(stream, {}, timeout=.25)
        stream.settimeout.assert_called_with(.25)

    def test_probe_requires_both_outside_connection_and_inside_acceptance(self):
        driver = C.DarwinDriver(self.repo, 101, api=mock.Mock())
        profile = self.run / 'controlled.sb'; profile.write_text('controlled profile')
        result = {'pid': 701, 'postgres': 'CONNECTED', 'model': 'EPERM', 'external': 'EACCES',
                  'loopbackBound': True, 'loopbackInboundVerified': True}
        def capture(*args, **kwargs):
            kwargs['after_spawn']()
            return 701, 0, C.encoded(result), b''
        endpoint = mock.Mock(); endpoint.connect_ex.return_value = 0
        with mock.patch.object(driver, '_capture', side_effect=capture), \
                mock.patch.object(C.socket, 'socket') as socket_factory:
            socket_factory.return_value.__enter__.return_value = endpoint
            self.assertTrue(driver.probe(self.grant, profile)['loopbackInboundVerified'])
            endpoint.connect_ex.assert_called_with(('127.0.0.1', 40102))
            result['loopbackInboundVerified'] = False
            with self.assertRaisesRegex(RuntimeError, 'PROBE'): driver.probe(self.grant, profile)
            result['loopbackInboundVerified'] = True; endpoint.connect_ex.return_value = 13
            with self.assertRaisesRegex(RuntimeError, 'PROBE_INBOUND'): driver.probe(self.grant, profile)

    def test_child_identity_binding_requires_exact_fixture_and_same_birth(self):
        def row(pid, ppid, birth=9):
            return mock.Mock(pid=pid, ppid=ppid, uid=os.getuid(), ruid=os.getuid(), pgid=pid, start_sec=birth, start_usec=1)
        api = mock.Mock()
        api.identity.side_effect = lambda pid: row(pid, os.getpid() if pid == 101 else 101)
        api.arguments.side_effect = lambda pid: (('python3', 'tests/postgres/run-secureshop-agent-host-transport-main.py', '--cohort', 'v30-original-disclosure', '--v30-original-profile', C.PROFILE)
            if pid == 101 else (self.grant['nodePath'], '--test', '--test-isolation=none', '--test-reporter=tap', str(self.repo / C.FIXTURE)))
        driver = C.DarwinDriver(self.repo, 101, api=api)
        original_arguments = api.arguments.side_effect
        expected = original_arguments(102)
        for bad in (tuple(x for x in expected if x != '--test-reporter=tap'),
                    tuple('--test-reporter=spec' if x == '--test-reporter=tap' else x for x in expected),
                    (*expected[:-1], '--test-reporter=tap', expected[-1])):
            api.arguments.side_effect = lambda pid, bad=bad: original_arguments(pid) if pid == 101 else bad
            rejected = C.DarwinDriver(self.repo, 101, api=api)
            with self.assertRaisesRegex(RuntimeError, 'V30_CONTROLLER_WORKER'):
                rejected.bind_worker(102, self.grant)
        api.arguments.side_effect = original_arguments
        driver.bind_worker(102, self.grant); driver.worker()
        api.identity.side_effect = lambda pid: row(pid, os.getpid() if pid == 101 else 101, birth=10 if pid == 102 else 9)
        with self.assertRaises(RuntimeError): driver.worker()

    def test_real_driver_capture_retains_child_before_selector_allocation(self):
        driver = C.DarwinDriver(self.repo, 101, api=mock.Mock())
        child = mock.Mock(pid=701)
        child.poll.return_value = None; child.wait.return_value = 0
        with mock.patch.object(C, 'LIVE_ENABLED', True), \
                mock.patch.object(C.subprocess, 'Popen', return_value=child), \
                mock.patch.object(C.selectors, 'DefaultSelector', side_effect=RuntimeError('selector allocation')):
            with self.assertRaisesRegex(RuntimeError, 'selector allocation'):
                driver._capture(['fixed-controlled-command'], {})
        child.kill.assert_called_once(); child.wait.assert_called_once_with(timeout=2)
        child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()
        self.assertEqual(driver.pending, [])

    def test_real_driver_capture_cleanup_failure_attempts_each_resource_and_retains_debt(self):
        driver = C.DarwinDriver(self.repo, 101, api=mock.Mock())
        child = mock.Mock(pid=701)
        child.poll.return_value = None; child.wait.return_value = 0
        child.kill.side_effect = OSError('controlled kill failure')
        child.stdout.close.side_effect = OSError('controlled pipe close failure')
        with mock.patch.object(C, 'LIVE_ENABLED', True), \
                mock.patch.object(C.subprocess, 'Popen', return_value=child), \
                mock.patch.object(C.selectors, 'DefaultSelector', side_effect=RuntimeError('selector allocation')):
            with self.assertRaisesRegex(RuntimeError, 'COMMAND_CLEANUP'):
                driver._capture(['fixed-controlled-command'], {})
        child.wait.assert_called_once_with(timeout=2)
        child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()
        self.assertEqual(driver.pending, [child])
        child.kill.side_effect = None; child.poll.return_value = 0
        # A real reaped process is not enough while an owned pipe still fails
        # close. Retry all retained resources, keep the debt until each joins.
        with self.assertRaisesRegex(RuntimeError, 'CLEANUP_INCOMPLETE'): driver.stop(None)
        self.assertEqual(driver.pending, [child])
        child.stdout.close.side_effect = None
        self.assertIsNone(driver.stop(None))
        self.assertEqual(driver.pending, []); self.assertEqual(driver.pending_resources, {})
        self.assertEqual(child.stderr.close.call_count, 3)

    def test_real_driver_stop_does_not_skip_host_when_auxiliary_cleanup_fails(self):
        driver = C.DarwinDriver(self.repo, 101, api=mock.Mock())
        pending = mock.Mock(pid=701)
        pending.poll.return_value = None; pending.wait.return_value = 0
        pending.kill.side_effect = OSError('controlled auxiliary failure')
        driver.pending = [pending]
        child = mock.Mock(pid=702); child.poll.return_value = 0; child.wait.return_value = 0
        driver.child = child; driver.births[702] = (123, 4)
        endpoint = mock.Mock(); endpoint.connect_ex.return_value = 61
        with mock.patch.object(driver, 'signal') as signal_child, \
                mock.patch.object(C, 'owned_group_members', return_value=[]), \
                mock.patch.object(C.socket, 'socket') as socket_factory:
            socket_factory.return_value.__enter__.return_value = endpoint
            with self.assertRaisesRegex(RuntimeError, 'CLEANUP_INCOMPLETE'):
                driver.stop(self.grant)
        pending.wait.assert_called_once(); signal_child.assert_called_once_with('SIGTERM')
        child.wait.assert_called_once(); endpoint.connect_ex.assert_called_once_with(('127.0.0.1', 40102))
        self.assertEqual(driver.pending, [pending])

    def test_real_driver_missing_birth_never_signals_group_and_requires_proven_empty_group(self):
        for group in ([], [703]):
            with self.subTest(group=group):
                api = mock.Mock(); api.group_pids.return_value = group
                driver = C.DarwinDriver(self.repo, 101, api=api)
                child = mock.Mock(pid=702); child.poll.return_value = 0; child.wait.return_value = 0
                driver.child = child
                endpoint = mock.Mock(); endpoint.connect_ex.return_value = 61
                with mock.patch.object(C.os, 'killpg') as kill_group, \
                        mock.patch.object(C.socket, 'socket') as socket_factory:
                    socket_factory.return_value.__enter__.return_value = endpoint
                    if group:
                        with self.assertRaisesRegex(RuntimeError, 'CLEANUP_INCOMPLETE'):
                            driver.stop(self.grant)
                    else:
                        self.assertEqual(driver.stop(self.grant), {'exitCode': 0, 'signalCode': None})
                kill_group.assert_not_called(); child.send_signal.assert_called_once_with(C.signal.SIGTERM)
                api.group_pids.assert_called_once_with(702)

    def test_coordinator_interrupt_deadline_and_error_keep_cleanup_rpc_serviced(self):
        for trigger in ('interrupt', 'deadline', 'error', 'drain-limit'):
            with self.subTest(trigger=trigger):
                channels = [mock.MagicMock() for _ in range(6)]
                for index, channel in enumerate(channels): channel.fileno.return_value = 100 + index
                inspector_parent, _, launch_parent, _, _, _ = channels
                child = mock.Mock(pid=801, returncode=None)
                child.poll.side_effect = lambda: child.returncode
                driver = mock.Mock(host_started=None)
                controller = mock.Mock(worker_pid=None)
                inspector = mock.Mock()
                handlers = {}; clock = [0]; phase = [0]; events = []
                controller.stop.side_effect = lambda: events.append('host-stop')
                child.send_signal.side_effect = lambda number: events.append('launcher-interrupt')
                def install(number, handler):
                    previous = handlers.get(number, 'previous')
                    handlers[number] = handler
                    return previous
                def selected(*_):
                    phase[0] += 1
                    if phase[0] == 1:
                        if trigger in ('interrupt', 'drain-limit'): handlers[C.signal.SIGINT]()
                        elif trigger == 'deadline': clock[0] = 1201
                        else: raise RuntimeError('controlled service failure')
                        return [], [], []
                    inspector_parent.close.assert_not_called()
                    launch_parent.close.assert_not_called()
                    if phase[0] == 2:
                        if trigger == 'drain-limit': clock[0] = 119.75
                        return [inspector_parent], [], []
                    if phase[0] == 3: return [launch_parent], [], []
                    raise AssertionError('cleanup did not terminate')
                def reply(*_, **__):
                    events.append('cleanup-reply'); child.returncode = 0
                def inspector_frame(*_, **kwargs):
                    if trigger == 'drain-limit':
                        self.assertEqual(kwargs['timeout'], .25)
                        clock[0] = 120.01
                        raise TimeoutError('controlled drip across drain deadline')
                    return {'op': 'inspect'}
                request = {'version': 1, 'sequence': 1, 'nonce': 'a' * 64,
                           'pid': 801, 'op': 'stop', 'payload': {}}
                with mock.patch.object(C, 'LIVE_ENABLED', True), \
                        mock.patch.object(COORDINATOR.sys, 'platform', 'darwin'), \
                        mock.patch.object(C, 'canonical_file', return_value=self.repo / 'tasks/run-native-current.sh'), \
                        mock.patch.object(COORDINATOR.socket, 'socketpair', side_effect=[tuple(channels[i:i+2]) for i in (0, 2, 4)]), \
                        mock.patch.object(COORDINATOR.subprocess, 'Popen', return_value=child), \
                        mock.patch.object(C, 'DarwinDriver', return_value=driver), \
                        mock.patch.object(C, 'Controller', return_value=controller), \
                        mock.patch.object(COORDINATOR, 'Inspector', return_value=inspector), \
                        mock.patch.object(COORDINATOR.signal, 'signal', side_effect=install), \
                        mock.patch.object(COORDINATOR.time, 'monotonic', side_effect=lambda: clock[0]), \
                        mock.patch.object(COORDINATOR.select, 'select', side_effect=selected), \
                        mock.patch.object(COORDINATOR, 'inspector_receive', side_effect=inspector_frame), \
                        mock.patch.object(COORDINATOR, 'inspector_send') as inspector_reply, \
                        mock.patch.object(C, 'receive', return_value=request), \
                        mock.patch.object(C, 'send', side_effect=reply):
                    arguments = ['--run', '--cohort', 'v30-original-disclosure',
                                 '--v30-original-profile', C.PROFILE]
                    if trigger in ('error', 'drain-limit'):
                        expected = 'controlled service failure' if trigger == 'error' else 'LAUNCHER_CLEANUP_TIMEOUT'
                        with self.assertRaisesRegex(RuntimeError, expected):
                            COORDINATOR.coordinate(self.repo, arguments)
                    else: self.assertEqual(COORDINATOR.coordinate(self.repo, arguments), 0)
                    actual = COORDINATOR.subprocess.Popen.call_args.args[0]
                    self.assertEqual(actual, ['/bin/bash', str(self.repo / 'tasks/run-native-current.sh'),
                                              *arguments[1:]])
                    self.assertNotIn('--run', actual)
                if trigger == 'drain-limit':
                    self.assertEqual(events, ['host-stop', 'launcher-interrupt'])
                    inspector.handle.assert_not_called(); inspector_reply.assert_not_called()
                    controller.response.assert_not_called(); child.wait.assert_not_called()
                    self.assertIsNone(child.returncode)  # No fabricated launcher reap.
                    controller.close.assert_called_once()
                    for channel in channels: self.assertTrue(channel.close.called)
                    continue
                self.assertEqual(events[:3], ['host-stop', 'launcher-interrupt', 'cleanup-reply'])
                inspector.handle.assert_called_once(); inspector_reply.assert_called_once()
                controller.response.assert_called_once_with('launcher', request)
                child.wait.assert_not_called(); controller.close.assert_called_once()
                for channel in channels: self.assertTrue(channel.close.called)

    def test_boundary_probe_is_separately_closed_and_cannot_start_original_host(self):
        with mock.patch.object(PROBE, 'PROBE_LIVE_ENABLED', False), \
             mock.patch.object(PROBE, 'admit') as admission, mock.patch.object(PROBE, 'Archive') as archive:
            with self.assertRaisesRegex(RuntimeError, 'PROBE_UNQUALIFIED'):
                PROBE.run(self.repo, self.run / PROBE.GRANT_NAME, 'a' * 64)
        admission.assert_not_called(); archive.assert_not_called()
        driver = PROBE.ProbeDriver(self.repo, os.getpid(), api=mock.Mock())
        with mock.patch.object(PROBE, 'PROBE_LIVE_ENABLED', True), mock.patch.object(C.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'ORIGINAL_HOST_STILL_CLOSED'):
                driver.start(self.grant, None, self.grant['owner'])
        spawn.assert_not_called(); self.assertFalse(C.LIVE_ENABLED)

    def test_failed_probe_launch_retains_only_bounded_sanitized_stderr(self):
        read_fd, write_fd = os.pipe()
        raw=b'sandbox_apply: Operation not permitted postgresql://user:secret@127.0.0.1/store\n'
        try:
            os.write(write_fd,raw)
        finally:
            os.close(write_fd)
        with os.fdopen(read_fd,'rb',buffering=0) as stderr:
            child=mock.Mock(stderr=stderr)
            child.poll.return_value=65
            fact=PROBE.bounded_launch_failure(child)
        self.assertEqual(fact['exitCode'],65)
        self.assertIsNone(fact['signalCode'])
        self.assertEqual(fact['stderrCapturedBytes'],len(raw))
        self.assertEqual(fact['stderrPrefixSha256'],hashlib.sha256(raw).hexdigest())
        self.assertIn('sandbox_apply: Operation not permitted',fact['stderrSanitized'])
        self.assertNotIn('secret',fact['stderrSanitized'])

    def test_boundary_probe_admission_binds_its_own_source_and_exact_private_grant(self):
        snapshot = json.loads(self.manifest.read_bytes())
        for name in (PROBE.PROBE_RELATIVE, 'tests/postgres/v30_agent_host_controller.py',
                     'tests/postgres/test_v30_agent_host_controller.py'):
            file = self.repo / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(name)
            snapshot['sourcePins'][name] = C.sha(file)
        self.manifest.write_bytes(C.encoded(snapshot)); self.grant['sourceManifestSha256'] = C.sha(self.manifest)
        grant_file = self.run / PROBE.GRANT_NAME
        grant_file.write_bytes(C.encoded(self.grant)); grant_file.chmod(0o600)
        with mock.patch.object(C, 'dependency_inventory', return_value={}):
            self.assertEqual(PROBE.admit(self.repo, grant_file, C.sha(grant_file)), self.grant)
            with self.assertRaises(RuntimeError): PROBE.admit(self.repo, grant_file, '0' * 64)
            (self.repo / PROBE.PROBE_RELATIVE).write_text('changed')
            with self.assertRaises(RuntimeError): PROBE.admit(self.repo, grant_file, C.sha(grant_file))

    def test_boundary_probe_ready_requires_real_runtime_identity_and_denial_not_timeout(self):
        value = {'version': 1, 'pid': 701, 'phase': 'ready',
                 'commerce': {'database': 'owasp_ai_goat_test_agent_host_'+'1'*12+'_secureshop', 'role': 'dvaia_secureshop_runtime'},
                 'agents': {'database': 'owasp_ai_goat_test_agent_host_'+'1'*12+'_secureshop_agents', 'role': 'dvaia_secureshop_agents_runtime'},
                 'model': 'EPERM', 'external': 'EACCES', 'outsideWriteOpenDenied': True, 'loopbackBound': True}
        PROBE.checked_ready(value, self.grant, 701)
        for mutation in ({'model': 'TIMEOUT'}, {'external': 'CONNECTED'}, {'outsideWriteOpenDenied': 1},
                         {'pid': 702}, {'loopbackBound': False}, {'version': True},
                         {'commerce': {**value['commerce'], 'role': 'dvaia_secureshop_migration'}}):
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                PROBE.checked_ready({**value, **mutation}, self.grant, 701)
        self.assertIn("fs.openSync('/dev/zero',fs.constants.O_WRONLY)", PROBE.PROGRAM)
        self.assertNotIn('O_TRUNC', PROBE.PROGRAM); self.assertNotIn('O_CREAT', PROBE.PROGRAM)
        self.assertNotIn('agent-host/index.js', PROBE.PROGRAM)

    def test_boundary_probe_archive_only_retires_exact_owned_inode(self):
        archive = PROBE.Archive(self.run, 'fixed controlled policy')
        try:
            target = self.run / PROBE.WRITE_NAME
            target.unlink(); target.write_bytes(b'unowned replacement'); target.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, 'ARTIFACT_CHANGED'): archive.retire_write()
            self.assertEqual(target.read_bytes(), b'unowned replacement')
        finally: archive.close()

    def test_boundary_probe_preserves_partial_child_failure_and_always_attempts_cleanup(self):
        driver = FakeDriver()
        def partial(*_):
            driver.pid = 103
            raise RuntimeError('controlled failed birth after spawn')
        driver.launch_probe = partial
        with mock.patch.object(PROBE, 'PROBE_LIVE_ENABLED', True), \
                mock.patch.object(PROBE.sys, 'platform', 'darwin'), \
                mock.patch.object(PROBE, 'admit', return_value=self.grant), \
                mock.patch.object(PROBE, 'ProbeDriver', return_value=driver), \
                mock.patch.object(PROBE, 'observe') as observe:
            with self.assertRaisesRegex(RuntimeError, 'BOUNDARY_PROBE_FAILED'):
                PROBE.run(self.repo, self.run / PROBE.GRANT_NAME, 'a' * 64)
        observe.assert_not_called(); self.assertIn('stop', driver.calls)
        self.assertFalse((self.run / PROBE.WRITE_NAME).exists())
        report = json.loads((self.run / PROBE.REPORT_NAME).read_bytes())
        self.assertFalse(report['passed']); self.assertFalse(report['originalV30Qualified'])
        self.assertEqual(report['pid'], 103); self.assertEqual(report['modelCalls'], 0)
        self.assertTrue(report['cleanupVerified']); self.assertEqual(report['error'], 'RuntimeError')

    def test_boundary_probe_capture_joins_ready_inbound_and_real_terminal_in_order(self):
        archive = PROBE.Archive(self.run, 'fixed controlled policy')
        try:
            (self.run / PROBE.WRITE_NAME).write_bytes(PROBE.WRITE_BYTES)
            ready = {'version': 1, 'pid': 701, 'phase': 'ready',
                'commerce': {'database': 'owasp_ai_goat_test_agent_host_'+'1'*12+'_secureshop', 'role': 'dvaia_secureshop_runtime'},
                'agents': {'database': 'owasp_ai_goat_test_agent_host_'+'1'*12+'_secureshop_agents', 'role': 'dvaia_secureshop_agents_runtime'},
                'model': 'EPERM', 'external': 'EACCES', 'outsideWriteOpenDenied': True, 'loopbackBound': True}
            inbound = {'version': 1, 'pid': 701, 'phase': 'inbound'}
            stopped = {'version': 1, 'pid': 701, 'phase': 'stopped', 'ready': True, 'inbound': True, 'exitCode': 0}
            for rows, valid in (([ready, inbound, stopped], True), ([ready, stopped, inbound], False),
                                ([ready, inbound, {**stopped, 'inbound': False}], False)):
                with self.subTest(valid=valid, order=[row['phase'] for row in rows]):
                    raw = b''.join(C.encoded(row)+b'\n' for row in rows)
                    child = mock.Mock(pid=701); child.wait.return_value = 0
                    driver = mock.Mock(child=child)
                    selector = mock.Mock(); selector.get_map.side_effect = [True, False]
                    key = mock.Mock(fileobj=child.stdout, data=0)
                    selector.select.return_value = [(key, 1)]
                    with mock.patch.object(PROBE.selectors, 'DefaultSelector', return_value=selector), \
                            mock.patch.object(PROBE.os, 'set_blocking'), \
                            mock.patch.object(PROBE.os, 'read', return_value=raw), \
                            mock.patch.object(PROBE.socket, 'socket') as socket_factory:
                        if valid:
                            result = PROBE.observe(driver, self.grant, archive, C.time.monotonic()+5)
                            self.assertEqual(result['phases'], ['ready', 'inbound', 'stopped'])
                            self.assertEqual(result['stdoutSha256'], hashlib.sha256(raw).hexdigest())
                            driver.signal.assert_called_once_with('SIGTERM'); child.wait.assert_called_once()
                        else:
                            with self.assertRaises(RuntimeError):
                                PROBE.observe(driver, self.grant, archive, C.time.monotonic()+5)
                        socket_factory.return_value.__enter__.return_value.connect.assert_called_once_with(('127.0.0.1', 40102))
                    selector.close.assert_called_once(); child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()
        finally: archive.close()

    def test_probe_final_report_retains_checkpoint_close_and_partial_pipe_failures(self):
        real_checkpoint, real_close = PROBE.Archive.checkpoint, PROBE.Archive.close
        for fault in ('checkpoint', 'archive-close', 'partial-pipe'):
            with self.subTest(fault=fault):
                run = self.run / fault; run.mkdir(mode=0o700)
                grant = {**self.grant, 'run': str(run)}
                driver = FakeDriver(); driver.child = mock.Mock()
                def launch(*_):
                    driver.pid = 103
                    if fault == 'partial-pipe': raise ValueError('original birth capture failure')
                driver.launch_probe = launch
                if fault == 'partial-pipe': driver.child.stdout.close.side_effect = OSError('controlled pipe close')
                def checkpoint(archive, event, **fields):
                    if fault == 'checkpoint' and event == 'retired': raise OSError('controlled checkpoint storage')
                    return real_checkpoint(archive, event, **fields)
                def close(archive):
                    real_close(archive)
                    if fault == 'archive-close': raise OSError('controlled archive close')
                with mock.patch.object(PROBE, 'PROBE_LIVE_ENABLED', True), \
                        mock.patch.object(PROBE.sys, 'platform', 'darwin'), \
                        mock.patch.object(PROBE, 'admit', return_value=grant), \
                        mock.patch.object(PROBE, 'ProbeDriver', return_value=driver), \
                        mock.patch.object(PROBE, 'observe', return_value={'controlled': True}), \
                        mock.patch.object(PROBE.Archive, 'checkpoint', checkpoint), \
                        mock.patch.object(PROBE.Archive, 'close', close):
                    with self.assertRaisesRegex(RuntimeError, 'BOUNDARY_PROBE_FAILED'):
                        PROBE.run(self.repo, run / PROBE.GRANT_NAME, 'a' * 64)
                report = json.loads((run / PROBE.REPORT_NAME).read_bytes())
                self.assertFalse(report['passed']); self.assertFalse(report['cleanupVerified'])
                prefix = {'checkpoint': 'terminal-checkpoint:', 'archive-close': 'archive-close:',
                          'partial-pipe': 'stdout:'}[fault]
                self.assertTrue(any(item.startswith(prefix) for item in report['cleanupErrors']))
                driver.child.stdout.close.assert_called_once(); driver.child.stderr.close.assert_called_once()
                self.assertFalse((run / PROBE.WRITE_NAME).exists())
                self.assertEqual(report['pid'], 103)
                if fault == 'partial-pipe': self.assertEqual(report['error'], 'ValueError')

    def test_probe_report_publication_failure_never_retains_optimistic_success(self):
        archive = PROBE.Archive(self.run, 'controlled policy'); archive.close()
        report = {'passed': True, 'cleanupVerified': True, 'cleanupErrors': []}
        baseline = (self.run / PROBE.REPORT_NAME).read_bytes()
        real_close, real_write = PROBE.os.close, PROBE.os.write
        closed = [False]; writes = [0]
        def failed_close(fd):
            # Candidate bytes have already been fsynced, but its close fails.
            self.assertTrue(json.loads((self.run / PROBE.REPORT_CANDIDATE_NAME).read_bytes())['passed'])
            real_close(fd); closed[0] = True
            raise OSError('controlled candidate close failure')
        def unavailable_corrective_write(fd, raw):
            writes[0] += 1
            if closed[0]: raise OSError('all corrective storage writes unavailable')
            return real_write(fd, raw)
        with mock.patch.object(PROBE.os, 'close', side_effect=failed_close), \
                mock.patch.object(PROBE.os, 'write', side_effect=unavailable_corrective_write), \
                mock.patch.object(PROBE.os, 'replace') as replace:
            with self.assertRaisesRegex(RuntimeError, 'REPORT_PUBLICATION_FAILED'):
                archive.publish_report(report)
        replace.assert_not_called()
        self.assertEqual((self.run / PROBE.REPORT_NAME).read_bytes(), baseline)
        retained = json.loads((self.run / PROBE.REPORT_NAME).read_bytes())
        self.assertFalse(retained['passed']); self.assertFalse(retained['cleanupVerified'])
        self.assertEqual(retained['cleanupErrors'], ['report-publication-not-committed'])
        self.assertEqual(report['cleanupErrors'], ['report-publication:OSError'])
        self.assertEqual(writes[0], 1); self.assertEqual(archive.fds, {})
        self.assertFalse((self.run / PROBE.REPORT_CANDIDATE_NAME).exists())

    def test_probe_report_publication_commits_only_after_candidate_and_directory_close(self):
        archive = PROBE.Archive(self.run, 'controlled policy'); archive.close()
        report = {'passed': True, 'cleanupVerified': True, 'cleanupErrors': []}
        old_identity = archive.identities[PROBE.REPORT_NAME]
        real_replace, real_close = PROBE.os.replace, PROBE.os.close
        closes = []
        def close(fd): real_close(fd); closes.append(fd)
        def commit(source, destination):
            self.assertEqual(len(closes), 2)
            self.assertFalse(json.loads(destination.read_bytes())['passed'])
            self.assertEqual(json.loads(source.read_bytes()), report)
            real_replace(source, destination)
        with mock.patch.object(PROBE.os, 'close', side_effect=close), \
                mock.patch.object(PROBE.os, 'replace', side_effect=commit) as replace:
            archive.publish_report(report)
        replace.assert_called_once()
        self.assertEqual(json.loads((self.run / PROBE.REPORT_NAME).read_bytes()), report)
        self.assertNotEqual(archive.identities[PROBE.REPORT_NAME], old_identity)
        archive.check(PROBE.REPORT_NAME)
        self.assertEqual(archive.fds, {})

    def test_probe_report_publication_rejects_replaced_placeholder(self):
        archive = PROBE.Archive(self.run, 'controlled policy'); archive.close()
        report = {'passed': True, 'cleanupVerified': True, 'cleanupErrors': []}
        real_check = archive.check
        checks = [0]
        def check(name):
            if name == PROBE.REPORT_NAME:
                checks[0] += 1
                if checks[0] == 2:
                    (self.run / name).rename(self.run / 'original-placeholder')
                    replacement = self.run / name
                    replacement.write_bytes(b'foreign replacement'); replacement.chmod(0o600)
            return real_check(name)
        with mock.patch.object(archive, 'check', side_effect=check), \
                mock.patch.object(PROBE.os, 'replace') as replace:
            with self.assertRaisesRegex(RuntimeError, 'REPORT_PUBLICATION_FAILED'):
                archive.publish_report(report)
        replace.assert_not_called()
        self.assertEqual((self.run / PROBE.REPORT_NAME).read_bytes(), b'foreign replacement')
        self.assertFalse((self.run / PROBE.REPORT_CANDIDATE_NAME).exists())


if __name__ == '__main__': unittest.main()
