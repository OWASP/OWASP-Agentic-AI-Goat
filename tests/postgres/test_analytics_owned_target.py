"""Controlled command responses only; no Docker/PostgreSQL qualification."""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analytics_owned_target import OwnedAnalyticsTarget


class Commands:
    def __init__(self):
        self.calls, self.rows = [], {}
        self.image = 'sha256:' + 'a' * 64
        self.identifier = 'b' * 64
        self.daemon = 'owned-daemon'
        self.bad_ack = False
        self.bad_cluster = False
        self.not_ready = False

    def result(self, stdout='', code=0, stderr=''):
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == 'info': return self.result(self.daemon)
        if args[:2] == ['image', 'inspect']: return self.result(self.image)
        if args[0] == 'inspect':
            row = self.rows.get(args[-1])
            return self.result(json.dumps([row])) if row else self.result(code=1, stderr='Error: No such container: ' + args[-1])
        if args[0] == 'run':
            name = args[args.index('--name') + 1]
            labels = dict(args[i + 1].split('=', 1) for i, value in enumerate(args) if value == '--label')
            row = {'Id': self.identifier, 'Name': '/' + name, 'Image': self.image,
                   'Config': {'Labels': labels}, 'Mounts': [],
                   'HostConfig': {'Tmpfs': {'/var/lib/postgresql': 'rw,size=268435456'},
                                  'Memory': 536870912, 'NanoCpus': 2000000000, 'PidsLimit': 256},
                   'NetworkSettings': {'Ports': {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '45678'}]}}}
            self.rows[name] = row; self.rows[self.identifier] = row
            return self.result('uncertain' if self.bad_ack else self.identifier)
        if args[0] == 'exec':
            if args[2] == 'pg_isready': return self.result(code=2 if self.not_ready else 0)
            sql = args[-1]
            if 'count(*)' in sql: return self.result('0')
            if 'json_build_object' in sql:
                return self.result(json.dumps({'systemIdentifier': '123456789',
                    'cluster': 'foreign' if self.bad_cluster else 'dvaia-owned-analytics-012345abcdef'}))
            return self.result()
        if args[0] == 'logs':
            return self.result(stderr='FATAL: "min_wal_size" must be at least twice "wal_segment_size"\npassword=private-value postgres://private:secret@host/db')
        if args[0] == 'rm':
            row = self.rows.pop(args[-1]); self.rows.pop(row['Name'][1:], None)
            return self.result()
        raise AssertionError(args)

    def absent(self, name): return name not in self.rows


class AnalyticsOwnedTargetTest(unittest.TestCase):
    def fixture(self):
        command = Commands(); persisted = []
        target = OwnedAnalyticsTarget(command=command, absent=command.absent,
            daemon_id=command.daemon, image=command.image, owner='run-owner',
            nonce='012345abcdef', cohort='customer-coupon-agent-browser',
            persist=lambda state: persisted.append(copy.deepcopy(state)), pause=lambda _: None)
        return command, target, persisted

    def test_real_admission_coordinates_and_exact_cleanup(self):
        command, target, persisted = self.fixture()
        self.assertEqual(target.start(), {
            'SECURESHOP_COUPON_ANALYTICS_OWNER': '012345abcdef',
            'SECURESHOP_COUPON_ANALYTICS_PORT': '45678',
            'SECURESHOP_COUPON_ANALYTICS_DATABASE': 'dvaia_analytics_control_012345abcdef',
            'SECURESHOP_COUPON_ANALYTICS_CLUSTER': 'dvaia-owned-analytics-012345abcdef',
            'SECURESHOP_COUPON_ANALYTICS_SYSTEM_IDENTIFIER': '123456789'})
        self.assertTrue(persisted[0]['attempted']); self.assertIsNone(persisted[0]['containerId'])
        create = next(args for args in command.calls if args[0] == 'run')
        self.assertIn('--pull', create); self.assertIn('never', create)
        self.assertNotIn('--volume', create)
        self.assertEqual(target.close(), {'containerNameAbsent': True, 'containerIdAbsent': True})
        self.assertEqual([args[-1] for args in command.calls if args[0] == 'rm'], [command.identifier])
        with self.assertRaises(RuntimeError): target.environment()

    def test_foreign_collision_never_creates_or_removes(self):
        command, target, _ = self.fixture()
        command.rows[target.name] = {'Id': 'c' * 64}
        with self.assertRaises(RuntimeError): target.start()
        self.assertFalse(target.close()['containerNameAbsent'])
        self.assertFalse(any(args[0] in ('run', 'rm') for args in command.calls))

    def test_small_wal_limits_use_matching_fresh_cluster_segment_size(self):
        command, target, _ = self.fixture()
        target.start()
        create = next(args for args in command.calls if args[0] == 'run')
        environment = dict(create[i + 1].split('=', 1)
                           for i, value in enumerate(create) if value == '-e')
        settings = dict(create[i + 1].split('=', 1)
                        for i, value in enumerate(create) if value == '-c')
        # PostgreSQL's default 16 MiB WAL segments are incompatible with the
        # deliberately small limits on this fresh, bounded tmpfs cluster.
        self.assertEqual(environment['POSTGRES_INITDB_ARGS'], '--wal-segsize=1')
        segment_mb = int(environment['POSTGRES_INITDB_ARGS'].split('=')[1])
        self.assertEqual(settings['max_wal_size'], '16MB')
        self.assertEqual(settings['min_wal_size'], '4MB')
        for key in ('min_wal_size', 'max_wal_size'):
            self.assertGreaterEqual(int(settings[key][:-2]), 2 * segment_mb)
        self.assertTrue(all(target.close().values()))

    def test_lost_create_ack_recovers_only_exact_owned_resource(self):
        command, target, _ = self.fixture(); command.bad_ack = True
        with self.assertRaises(RuntimeError): target.start()
        self.assertIsNone(target.state['containerId'])
        self.assertTrue(all(target.close().values()))
        self.assertEqual(target.state['containerId'], command.identifier)

    def test_foreign_replacement_is_never_removed(self):
        command, target, _ = self.fixture(); target.start()
        command.rows[target.name] = copy.deepcopy(command.rows[target.name])
        command.rows[target.name]['Id'] = 'c' * 64
        with self.assertRaises(RuntimeError): target.close()
        self.assertFalse(any(args[0] == 'rm' for args in command.calls))

    def test_renamed_captured_id_is_not_reported_absent(self):
        command, target, _ = self.fixture(); target.start()
        del command.rows[target.name]
        with self.assertRaisesRegex(RuntimeError, 'renamed'): target.close()
        self.assertFalse(any(args[0] == 'rm' for args in command.calls))

    def test_daemon_change_blocks_cleanup(self):
        command, target, _ = self.fixture(); target.start(); command.daemon = 'foreign'
        with self.assertRaises(RuntimeError): target.close()
        self.assertFalse(any(args[0] == 'rm' for args in command.calls))

    def test_wrong_postgres_identity_fails_and_owned_resource_is_cleaned(self):
        command, target, _ = self.fixture(); command.bad_cluster = True
        with self.assertRaisesRegex(RuntimeError, 'identity mismatch'): target.start()
        with self.assertRaises(RuntimeError): target.environment()
        self.assertTrue(all(target.close().values()))

    def test_readiness_failure_records_only_safe_bounded_diagnostic_then_cleans(self):
        command, target, persisted = self.fixture(); command.not_ready = True
        with self.assertRaisesRegex(RuntimeError, 'readiness timeout'):
            target.start()
        diagnostic = target.state['startupDiagnostic']
        self.assertEqual(diagnostic['readinessExitCode'], 2)
        self.assertEqual(diagnostic['reasons'], ['"min_wal_size" must be at least twice "wal_segment_size"'])
        self.assertTrue(diagnostic['logTailRead'])
        self.assertEqual([args for args in command.calls if args[0] == 'logs'],
                         [['logs', '--tail', '20', command.identifier]])
        self.assertNotIn('private', json.dumps(persisted))
        self.assertNotIn('secret', json.dumps(persisted))
        self.assertTrue(all(target.close().values()))


if __name__ == '__main__': unittest.main()
