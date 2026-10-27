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


class PrivateBridgeContract(unittest.TestCase):
    def handoff(self):
        return dict(runId='a'*32, root='/var/tmp/dvaia-v23-build-'+'a'*32+'/fs',
                    filesystemDevice=1792, filesystemInode=2, namespaceInode=1234,
                    holderPid=200, holderStart=300, containerPid=400, containerStart=500,
                    containerId='b'*64, imageId='sha256:'+'c'*64, sourceSha256='d'*64,
                    runtimeSha256='e'*64, environmentSha256='f'*64, publicOrigin='http://127.0.0.1:1234',
                    workspaceId='a'*12,profileName='dvaia-owned-listings-'+'a'*12,
                    profileSha256='f'*64,containerName='dvaia-owned-listings-'+'a'*12,
                    privateDockerHost='unix:///var/tmp/dvaia-v23-build-'+'a'*32+'/fs/docker.sock',daemonId='d'*36)

    def test_closed_handoff_copies_and_rejects_ambiguous_authority(self):
        value = self.handoff(); captured = resource.private_handoff(value)
        value['holderPid'] = 999
        self.assertEqual(captured['holderPid'], 200)
        for key, value in [('root', '/run'), ('runId', 'bad'), ('holderPid', True),
                           ('containerStart', 0), ('imageId', 'tag:latest'), ('environmentSha256', None),
                           ('workspaceId','b'*12),('profileName','foreign'),('containerName','foreign'),
                           ('privateDockerHost','unix:///run/docker.sock'),('daemonId','unknown'),('profileSha256',None)]:
            row = self.handoff(); row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): resource.private_handoff(row)
        row = self.handoff(); row['token'] = 'not-allowed'
        with self.assertRaises(ValueError): resource.private_handoff(row)

    def test_actual_channel_compiles_and_rejects_before_effect(self):
        source = resource.private_channel_program(self.handoff(), '1'*32, 10)
        compile(source, '<actual-listings-channel>', 'exec')
        # Execute actual emitted code with euid denied; no filesystem/socket/process effects.
        from unittest.mock import patch
        with patch('os.geteuid', return_value=501), self.assertRaisesRegex(RuntimeError, 'CHANNEL_DENIED'):
            exec(compile(source, '<actual-listings-channel>', 'exec'), {})
        for seconds in [0, 121, True, 1.5]:
            with self.assertRaises(ValueError): resource.private_channel_program(self.handoff(), '1'*32, seconds)
        with self.assertRaises(ValueError): resource.private_channel_program(self.handoff(), '../bad', 10)

    def test_bridge_actual_transport_construction_and_local_retirement(self):
        import pathlib, time, threading
        from unittest.mock import patch
        root = pathlib.Path(__file__).resolve().parents[2]
        bridge = resource.PrivateListingsBridge(root, self.handoff(), time.monotonic()+30)
        class Client:
            def close(self): pass
        client = Client()
        calls = []
        def relay_stub(*args, before_spawn):
            before_spawn();calls.append(args)
        with patch.object(bridge.mux, 'admit_existing_mux', return_value={'bound': True}), \
             patch.object(bridge.mux, 'mux_command', side_effect=lambda authority, command: ['ssh', command]), \
             patch.object(bridge.mux, 'relay_connection', side_effect=relay_stub):
            bridge._connection(client)
        self.assertEqual(len(calls), 1)
        import shlex
        remote = shlex.split(calls[0][1][1])
        self.assertEqual(remote[:5], ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2'])
        self.assertEqual(remote[6:11], ['/usr/bin/python3', '-I', '-S', '-B', '-c'])
        compile(remote[11], '<actual-channel-command>', 'exec')
        receipt = bridge.close(time.monotonic()+1)
        self.assertTrue(receipt['localChannelsRetired'])
        self.assertFalse(receipt['remoteChannelsVerified'])
        self.assertEqual(len(receipt['channelIds']), 1)
        self.assertEqual(receipt['channelStates'][0]['state'], 'spawn_attempted')
        bridge.children.add(object())
        with self.assertRaisesRegex(RuntimeError, 'RETIREMENT_UNPROVEN'): bridge.close(time.monotonic()+1)

    def test_actual_emitted_container_authority_checks(self):
        h = self.handoff()
        profile='dvaia-owned-listings-'+h['runId'][:12]; volume='dvaia-listings-journal-'+h['runId']
        environment = ['LISTINGS_MANAGER_ENABLED=true', 'LISTINGS_PROFILE='+profile,
                       'LISTINGS_PUBLIC_ORIGIN=http://127.0.0.1:1234', 'LISTINGS_CONTROL_TOKEN=controlled']
        h['environmentSha256'] = hashlib.sha256('\n'.join(sorted(environment)).encode()).hexdigest()
        row = dict(Name='/'+h['containerName'],Id=h['containerId'], Image=h['imageId'], State=dict(Running=True, Pid=h['containerPid']),
                   AppArmorProfile=profile,
                   Mounts=[dict(Type='volume',Name=volume,Source=h['root']+'/data/volumes/'+volume+'/_data',Destination='/journal',Driver='local',Mode='',RW=True,Propagation='')],
                   Config=dict(User='10001:10001', Env=environment, Entrypoint=['node'],Cmd=['/app/sidecars/sandbox-runner/owned-listings/manager-entry.js'], Labels={
                       'dvaia.test.owner': h['runId'], 'dvaia.listings.source': h['sourceSha256'],
                       'dvaia.listings.runtime': h['runtimeSha256']}),
                   HostConfig=dict(NetworkMode='host', ReadonlyRootfs=True, Privileged=False,
                       Memory=536870912,NanoCpus=1000000000,PidsLimit=128,CapDrop=['ALL'],
                       SecurityOpt=['apparmor='+profile,'seccomp=unconfined'],
                       Tmpfs={'/tmp':'rw,nosuid,nodev,noexec,size=16m'},
                       LogConfig={'Type':'local','Config':{'max-size':'1m','max-file':'1','compress':'false'}}))
        source = resource.private_channel_program(h, '1'*32, 10)
        # The exact emitted post-inspect guard runs against controlled Docker observations.
        body = source[source.index('rows=json.loads(buffers[child.stdout])'):source.index('import fcntl')]
        marker = object()
        def check(value):
            def need(ok):
                if not ok: raise RuntimeError('denied')
            exec(compile(body, '<actual-post-inspect-guard>', 'exec'), dict(
                json=json, hashlib=hashlib, H=h, need=need, identity=lambda: None, root=__import__('pathlib').Path(h['root']),
                child=SimpleNamespace(stdout=marker), buffers={marker: json.dumps([value]).encode()}))
        check(row)
        # Sanitized mount from listings-f538 partial-result.json: only run/root
        # identities are replaced; retain the observed keys and Mode='z'.
        retained_mount = {
            'Destination': '/journal', 'Driver': 'local', 'Mode': 'z',
            'Name': volume, 'Propagation': '', 'RW': True,
            'Source': h['root']+'/data/volumes/'+volume+'/_data', 'Type': 'volume',
        }
        row['Mounts'] = [retained_mount]
        check(row)
        for mounts in (None, {}, 'volume', [], [None], [[]], [True],
                       [retained_mount, copy.deepcopy(retained_mount)]):
            changed = copy.deepcopy(row); changed['Mounts'] = mounts
            with self.subTest(mounts=mounts), self.assertRaises(RuntimeError): check(changed)
        for key in retained_mount:
            changed = copy.deepcopy(row); del changed['Mounts'][0][key]
            with self.subTest(missing=key), self.assertRaises(RuntimeError): check(changed)
        changed = copy.deepcopy(row); changed['Mounts'][0]['Unexpected'] = True
        with self.assertRaises(RuntimeError): check(changed)
        for key, value in [
            ('Type', 'bind'), ('Name', 'foreign'),
            ('Source', '/foreign/_data'),
            ('Source', h['root']+'/data/volumes/foreign/_data'),
            ('Source', h['root']+'/data/volumes/'+volume+'/../'+volume+'/_data'),
            ('Destination', '/other'), ('Driver', 'foreign'),
            ('Propagation', 'rshared'), ('RW', False), ('RW', 1), ('RW', 'true'),
        ]:
            changed = copy.deepcopy(row); changed['Mounts'][0][key] = value
            with self.subTest(field=key, value=value), self.assertRaises(RuntimeError): check(changed)
        for mode in (None, True, 0, [], {}, 'Z', 'rw', 'ro', 'z,rw', 'rw,z', ' ', 'z ', 'unknown'):
            changed = copy.deepcopy(row); changed['Mounts'][0]['Mode'] = mode
            with self.subTest(mode=mode), self.assertRaises(RuntimeError): check(changed)
        # Repeat all existing container authority denials with the observed z base.
        for path, value in [(('Id',), '0'*64), (('Image',), 'sha256:'+'0'*64),
                            (('State', 'Pid'), 999), (('State', 'Running'), False),
                            (('Config', 'Labels', 'dvaia.test.owner'), 'foreign'),
                            (('HostConfig', 'NetworkMode'), 'bridge'),
                            (('Config', 'Cmd'), ['/unapproved.js']),
                            (('Config', 'Entrypoint'), ['sh']),
                            (('HostConfig', 'Memory'), 0), (('HostConfig', 'PidsLimit'), 0),
                            (('HostConfig', 'SecurityOpt'), ['seccomp=unconfined']),
                            (('Mounts',), []),
                            (('Config', 'Env'), environment+['LISTINGS_CONTROL_TOKEN=duplicate'])]:
            changed=copy.deepcopy(row); target=changed
            for key in path[:-1]: target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path), self.assertRaises(RuntimeError): check(changed)

    def test_bridge_reservation_is_inert_until_bound_and_activation_once(self):
        import pathlib, time
        from unittest.mock import patch, MagicMock
        bridge=resource.PrivateListingsBridge(pathlib.Path(__file__).resolve().parents[2], None, time.monotonic()+30)
        listener=MagicMock(); listener.getsockname.return_value=('127.0.0.1',1234)
        with patch('socket.socket', return_value=listener), \
             patch.object(bridge.mux, 'admit_existing_mux', return_value={'bound':True}), \
             patch('threading.Thread') as thread:
            self.assertEqual(bridge.open(), 'http://127.0.0.1:1234')
            thread.assert_not_called()
            wrong=self.handoff(); wrong['publicOrigin']='http://127.0.0.1:1235'
            with self.assertRaisesRegex(RuntimeError, 'IDENTITY_CHANGED'): bridge.activate(wrong)
            bridge.activate(self.handoff())
            thread.return_value.start.assert_called_once()
            with self.assertRaises(RuntimeError): bridge.activate(self.handoff())

    def test_actual_emitted_inspection_stream_caps_cancellation_and_join(self):
        import pathlib, subprocess
        source=resource.private_channel_program(self.handoff(),'1'*32,10)
        body=source[source.index('child=subprocess.Popen'):source.index('rows=json.loads(buffers[child.stdout])')]
        class Stream:
            def __init__(self,number): self.number=number; self.closed=False
            def fileno(self): return self.number
            def close(self): self.closed=True
        def exercise(mode):
            calls=[]; clock=[0]; amounts={1:0,2:0}
            class Child:
                stdout=Stream(1); stderr=Stream(2); code=None
                def poll(self): return self.code
                def terminate(self): calls.append('term')
                def kill(self): calls.append('kill')
                def wait(self,timeout):
                    calls.append('wait')
                    if mode=='unjoinable' or mode=='termignored' and 'kill' not in calls:
                        raise subprocess.TimeoutExpired('controlled',timeout)
                    self.code=1 if mode=='nonzero' else 0; return self.code
            child=Child()
            def monotonic():
                clock[0]+=.2 if mode in ('hang','termignored','unjoinable') else .0001
                return clock[0]
            def read(fd,count):
                if mode=='stdout' and fd==1 or mode=='stderr' and fd==2:
                    amounts[fd]+=count; return b'x'*count
                return b''
            def need(ok):
                if not ok: raise RuntimeError('denied')
            env=dict(H=self.handoff(), root=pathlib.Path(self.handoff()['root']),need=need,
                subprocess=SimpleNamespace(Popen=lambda *a,**k:child, PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired),
                os=SimpleNamespace(set_blocking=lambda *a:None,read=read),time=SimpleNamespace(monotonic=monotonic),
                select=SimpleNamespace(select=lambda pending,*a:([] if mode in ('hang','termignored','unjoinable') else pending,[],[])))
            failure=None
            try:exec(compile(body,'<actual-inspection-loop>','exec'),env)
            except BaseException as error:failure=error
            self.assertTrue(child.stdout.closed and child.stderr.closed)
            return failure,calls
        self.assertIsNone(exercise('success')[0])
        for mode in ('stdout','stderr','hang','nonzero','termignored','unjoinable'):
            error,calls=exercise(mode)
            with self.subTest(mode=mode): self.assertIsNotNone(error)
            if mode in ('stdout','stderr','hang','termignored','unjoinable'): self.assertIn('term',calls)
            if mode in ('termignored','unjoinable'): self.assertIn('kill',calls)

    def test_actual_remote_journal_retirement_requires_terminal_and_pid_absence(self):
        import pathlib,tempfile,os,stat,io,contextlib
        from unittest.mock import patch
        h=self.handoff(); channel='1'*32
        source=resource.private_channels_retirement_program(h,[channel])
        compile(source,'<actual-remote-retirement>','exec')
        body=source[source.index('import fcntl'):]
        with tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).resolve().parents[2]/'tasks/tmp') as directory:
            root=pathlib.Path(directory); file=root/('listings-channel-'+channel+'.jsonl')
            first=dict(version=1,runId=h['runId'],channelId=channel,pid=99999999,startTicks=123,namespaceInode=h['namespaceInode'],stage='started')
            last=dict(version=1,runId=h['runId'],channelId=channel,stage='terminal',complete=True,sentBytes=5,receivedBytes=7)
            actual_fstat=os.fstat
            actual_open=os.open
            def fstat(fd):
                row=actual_fstat(fd)
                return SimpleNamespace(**{key:getattr(row,key) for key in ('st_mode','st_nlink','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')},st_uid=0)
            def run(rows,live=False):
                file.write_text(''.join(json.dumps(r)+'\n' for r in rows)); file.chmod(0o600)
                def need(ok):
                    if not ok:raise RuntimeError('denied')
                class ProcessPath:
                    def __init__(self,value):self.value=value
                    def exists(self):return live
                output=io.StringIO()
                opened=[]
                def opening(*args,**kwargs):
                    fd=actual_open(*args,**kwargs);opened.append(fd);return fd
                try:
                    with patch('os.fstat',side_effect=fstat),patch('os.open',side_effect=opening),contextlib.redirect_stdout(output):
                        exec(compile(body,'<actual-remote-journals>','exec'),dict(root=root,H=h,CHANNELS=[channel],
                            need=need,identity=lambda:None,Path=ProcessPath,os=os,stat=stat,json=json,hashlib=hashlib))
                        self.assertEqual((root/'listings-channel-admission-closed').read_text(),h['runId'])
                        admission=resource.private_channel_program(h,'2'*32,10)
                        admission=admission[admission.index('import fcntl'):admission.index('sock=None;complete=False')]
                        with self.assertRaises(RuntimeError):
                            exec(compile(admission,'<actual-late-admission>','exec'),dict(root=root,need=need,os=os,stat=stat,
                                time=__import__('time'),end=__import__('time').monotonic()+1))
                        self.assertFalse((root/('listings-channel-'+'2'*32+'.jsonl')).exists())
                finally:
                    for fd in opened:
                        try:os.close(fd)
                        except OSError:pass
                    fence=root/'listings-channel-admission-closed'
                    if fence.exists():fence.unlink()
                return json.loads(output.getvalue())
            self.assertTrue(run([first,last])['remoteChannelsAbsent'])
            for rows,live in [([first],False),([first,last],True),([first,dict(last,channelId='2'*32)],False),
                              ([first,dict(last,sentBytes=8388609)],False)]:
                with self.assertRaises(RuntimeError):run(rows,live)
            (root/'listings-channel-unowned.jsonl').write_text('foreign')
            with self.assertRaises(RuntimeError):run([first,last])


if __name__ == '__main__':
    unittest.main()
