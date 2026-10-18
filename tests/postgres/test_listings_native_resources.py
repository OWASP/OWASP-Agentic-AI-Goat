"""Controlled commands only: no Docker, profile, model or network operations."""
import copy
import hashlib
import json
from types import SimpleNamespace
import unittest

import listings_native_resources as resource


class Docker:
    def __init__(self):
        self.calls = []
        self.fail_remove = False
        self.unknown_absence = False
        self.daemon = 'daemon'
        self.state = {'container': 'dvaia-standalone-listings-' + 'a' * 12,
                      'network': 'network', 'volume': 'volume', 'image': 'sha256:' + 'b' * 64,
                      'daemon': self.daemon, 'profile': {'name': 'dvaia-owned-listings-' + 'a' * 12},
                      'labels': {'dvaia.owner': 'owner', 'dvaia.cohort': 'listings'},
                      'port': '18095', 'attempted': ['profile', 'network', 'volume', 'container']}
        self.network = {'Name': 'network', 'Id': 'c' * 64, 'Labels': self.state['labels'].copy(),
                        'Driver': 'bridge', 'Internal': False, 'Options': {}, 'Containers': {'d' * 64: {}}}
        self.volume = {'Name': 'volume', 'Labels': self.state['labels'].copy(), 'Driver': 'local',
                       'Scope': 'local', 'Options': None, 'Mountpoint': '/var/lib/docker/volumes/volume/_data'}
        self.container = {'Name': '/' + self.state['container'], 'Id': 'd' * 64,
            'Image': self.state['image'], 'Config': {'Labels': self.state['labels'].copy(), 'User': '10001:10001'},
            'AppArmorProfile': self.state['profile']['name'], 'State': {'Running': True},
            'Mounts': [{'Type': 'volume', 'Name': 'volume', 'Destination': '/journal', 'RW': True}],
            'NetworkSettings': {'Networks': {'network': {'NetworkID': 'c' * 64}}},
            'HostConfig': {'NetworkMode': 'network', 'ReadonlyRootfs': True, 'Privileged': False,
                'Memory': 536870912, 'NanoCpus': 1000000000, 'PidsLimit': 128,
                'CapDrop': ['ALL'], 'CapAdd': None,
                'SecurityOpt': ['apparmor=' + self.state['profile']['name'], 'seccomp=unconfined'],
                'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'},
                'PortBindings': {'8095/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18095'}]}}}
        self.foreign = []
        environment = ['LISTINGS_MANAGER_ENABLED=true', 'LISTINGS_PROFILE=' + self.state['profile']['name'],
                       'LISTINGS_PUBLIC_ORIGIN=http://127.0.0.1:18095', 'LISTINGS_CONTROL_TOKEN=private-token']
        self.state['environmentSha256'] = hashlib.sha256('\n'.join(sorted(environment)).encode()).hexdigest()
        self.container['Config']['Env'] = environment
        self.container['Mounts'][0]['Source'] = self.volume['Mountpoint']

    def __call__(self, args):
        self.calls.append(args)
        def result(code=0, stdout='', stderr=''):
            return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        if args[0] == 'info':
            return result(stdout=self.daemon)
        if args[0] == 'ps':
            return result(stdout='\n'.join(row['Id'] for row in [self.container, *self.foreign] if row))
        if args[0] == 'inspect':
            kind, name = 'container', args[-1]
            row = next((r for r in [self.container, *self.foreign] if r and name in (r['Id'], r['Name'][1:])), None)
        elif len(args) > 1 and args[1] == 'inspect':
            kind, name = args[0], args[-1]
            row = self.network if kind == 'network' else self.volume
            if row and name not in (row['Name'], row.get('Id')): row = None
        elif args[0] == 'rm' or args[1] == 'rm':
            if not self.fail_remove:
                if args[0] == 'rm':
                    self.container = None
                    if self.network: self.network['Containers'] = {}
                elif args[0] == 'network': self.network = None
                else: self.volume = None
            # Simulate a lost acknowledgement even when the mutation committed.
            return result(1, stderr='response lost')
        else:
            raise AssertionError(args)
        if row: return result(stdout=json.dumps([row]))
        missing = {'container': f'Error: No such container: {name}',
                   'network': f'Error response from daemon: network {name} not found',
                   'volume': f'Error response from daemon: get {name}: no such volume'}
        return result(1, stderr='permission denied' if self.unknown_absence else missing[kind])

    def mutations(self):
        return [args for args in self.calls if args[0] == 'rm' or len(args) > 1 and args[1] == 'rm']


class Controls(unittest.TestCase):
    def test_packaged_fixture_cleanup_uses_none_network_and_exact_entrypoint(self):
        d = Docker(); d.state.update(packaged=True, network='none', attempted=['profile','volume','container'])
        d.network = None
        d.container['HostConfig'].update(NetworkMode='none', PortBindings={})
        d.container['NetworkSettings'] = {'Networks': {'none': {}}, 'Ports': {}}
        env = 'LISTINGS_PROFILE=' + d.state['profile']['name']
        d.state['environmentSha256'] = hashlib.sha256(env.encode()).hexdigest()
        d.container['Config'].update(Env=[env], Entrypoint=['node'],
            Cmd=['/app/tests/fixtures/secureshopOwnedListingsPackaged.native.cjs'])
        result = resource.cleanup(d, d.state, lambda p: None)
        self.assertEqual(result, dict(containerAbsent=True,volumeAbsent=True,profileAbsent=True))
        self.assertFalse(any(a[0]=='network' for a in d.calls))

    def test_lost_create_and_remove_ack_recovered_by_exact_identity_and_absence(self):
        d = Docker(); removed = []
        result = resource.cleanup(d, d.state, lambda profile: removed.append(profile))
        self.assertEqual(d.state['containerId'], 'd' * 64)
        self.assertEqual(result, dict(containerAbsent=True, volumeAbsent=True, networkAbsent=True, profileAbsent=True))
        self.assertEqual(d.mutations()[0], ['rm', '--force', 'd' * 64])
        self.assertEqual(len(removed), 1)

    def test_partial_creation_cleans_only_attempted_owned_resources(self):
        d = Docker(); d.container = None; d.volume = None; d.network['Containers'] = {}
        d.state['attempted'] = ['profile', 'network']; removed = []
        result = resource.cleanup(d, d.state, lambda p: removed.append(p))
        self.assertEqual(result, dict(networkAbsent=True, profileAbsent=True))
        self.assertEqual(d.mutations(), [['network', 'rm', 'c' * 64]])

    def assert_retained(self, change):
        d = Docker(); change(d); removed = []
        with self.assertRaises(RuntimeError): resource.cleanup(d, d.state, lambda p: removed.append(p))
        self.assertEqual(d.mutations(), []); self.assertEqual(removed, [])

    def test_foreign_container_label_retains_every_resource(self):
        self.assert_retained(lambda d: d.container['Config']['Labels'].update({'dvaia.owner': 'foreign'}))

    def test_container_image_drift_retains_every_resource(self):
        self.assert_retained(lambda d: d.container.update(Image='sha256:' + 'e' * 64))

    def test_daemon_drift_retains_every_resource(self):
        self.assert_retained(lambda d: setattr(d, 'daemon', 'other'))

    def test_captured_network_id_drift_retains_every_resource(self):
        self.assert_retained(lambda d: d.state.update(networkId='f' * 64))

    def test_foreign_network_endpoint_retains_every_resource(self):
        self.assert_retained(lambda d: d.network['Containers'].update({'e' * 64: {}}))

    def test_renamed_container_retains_every_resource(self):
        def change(d):
            d.state['containerId'] = d.container['Id']; d.container['Name'] = '/renamed'
        self.assert_retained(change)

    def test_foreign_volume_user_retains_every_resource(self):
        def change(d):
            row = copy.deepcopy(d.container); row['Id'] = 'e' * 64; row['Name'] = '/foreign'
            row['NetworkSettings']['Networks'] = {}; row['AppArmorProfile'] = 'other'; d.foreign.append(row)
        self.assert_retained(change)

    def test_foreign_running_profile_user_retains_every_resource(self):
        def change(d):
            row = copy.deepcopy(d.container); row['Id'] = 'e' * 64; row['Name'] = '/foreign'
            row['NetworkSettings']['Networks'] = {}; row['Mounts'] = []; d.foreign.append(row)
        self.assert_retained(change)

    def test_foreign_stopped_configured_profile_user_retains_every_resource(self):
        def change(d):
            row = copy.deepcopy(d.container); row['Id'] = 'e' * 64; row['Name'] = '/foreign'
            row['NetworkSettings']['Networks'] = {}; row['Mounts'] = []
            row['State']['Running'] = False; row['AppArmorProfile'] = ''
            d.foreign.append(row)
        self.assert_retained(change)

    def test_failed_removal_cannot_unload_profile(self):
        d = Docker(); d.fail_remove = True; removed = []
        with self.assertRaises(RuntimeError): resource.cleanup(d, d.state, lambda p: removed.append(p))
        self.assertEqual(len(d.mutations()), 1); self.assertEqual(removed, [])

    def test_unknown_absence_denies(self):
        d = Docker(); d.container = None; d.unknown_absence = True
        with self.assertRaises(RuntimeError): resource.cleanup(d, d.state, lambda _: self.fail('profile removed'))
        self.assertEqual(d.mutations(), [])

    def test_resource_or_environment_drift_retains_every_resource(self):
        for change in (
            lambda d: d.volume['Labels'].update({'dvaia.owner': 'foreign'}),
            lambda d: d.network['Labels'].update({'dvaia.owner': 'foreign'}),
            lambda d: d.container['HostConfig'].update(Privileged=True),
            lambda d: d.container['Config']['Env'].append('LISTINGS_CONTROL_TOKEN=other'),
            lambda d: d.container['Mounts'][0].update(Source='/foreign'),
        ):
            with self.subTest(change=change): self.assert_retained(change)

    def test_profile_cleanup_retry_after_all_docker_resources_removed(self):
        d = Docker()
        def interrupted(_): raise RuntimeError('profile cleanup interrupted')
        with self.assertRaises(RuntimeError): resource.cleanup(d, d.state, interrupted)
        count = len(d.mutations()); removed = []
        result = resource.cleanup(d, d.state, lambda p: removed.append(p))
        self.assertEqual(len(d.mutations()), count)
        self.assertTrue(result['profileAbsent']); self.assertEqual(len(removed), 1)


if __name__ == '__main__':
    unittest.main()
