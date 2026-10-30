"""Controlled contracts only; no Docker, SSH, sockets, models or guest writes."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pricing_owned_provisioning', Path(__file__).with_name('pricing_owned_provisioning.py'))
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class PricingPrivateProvisioning(unittest.TestCase):
    def test_slow_mux_preparation_cannot_launch_after_deadline_or_consume_remote_reserve(self):
        for after in (131,130,129):
            clock=[100]
            def command(authority,remote):
                clock[0]=after
                return ['fixed-ssh',remote]
            mux=SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py'),admit_existing_mux=Mock(return_value={}),mux_command=Mock(side_effect=command))
            processes=Mock()
            with patch('time.monotonic',side_effect=lambda:clock[0]):
                runtime=m.PrivateRuntimeComponents(self.spec,mux,processes,{},200,'t'*43)
                runtime.set_cleanup_deadline(130)
                with self.assertRaisesRegex(ValueError,'DEADLINE'):runtime._dispatch('stop',cleanup=True)
                self.assertEqual(runtime._cleanup_deadline,130)
            mux.mux_command.assert_called_once()
            processes.launch.assert_not_called()

    def test_shared_cleanup_deadline_bounds_real_dispatch_without_renewal(self):
        mux=SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py'),admit_existing_mux=Mock(return_value={}),mux_command=Mock(side_effect=lambda a,r:['fixed-ssh',r]))
        processes=Mock();child=SimpleNamespace(stdout=Mock(),stderr=Mock());processes.launch.return_value=child
        with patch('time.monotonic',return_value=100):
            runtime=m.PrivateRuntimeComponents(self.spec,mux,processes,{},200,'t'*43)
            runtime.set_cleanup_deadline(130)
            with self.assertRaisesRegex(ValueError,'NONRENEWAL'):runtime.set_cleanup_deadline(140)
            with patch('selectors.DefaultSelector',side_effect=RuntimeError('selector')):
                with self.assertRaisesRegex(RuntimeError,'selector'):runtime._dispatch('stop',cleanup=True)
            self.assertIn('--kill-after=2 25 ',processes.launch.call_args.args[0][1])
            self.assertIn('deadline=time.monotonic()+20',processes.launch.call_args.args[0][1])
        processes.launch.reset_mock()
        with patch('time.monotonic',return_value=131):
            with self.assertRaisesRegex(ValueError,'DEADLINE'):runtime._dispatch('stop',cleanup=True)
        processes.launch.assert_not_called()

    def test_private_current_inspection_uses_actual_dispatch_exact_descriptor(self):
        runtime=object.__new__(m.PrivateRuntimeComponents)
        runtime.attempted=True;runtime.closed=False
        runtime.descriptor={'containerId':'a'*64,'imageId':'sha256:'+'b'*64}
        row=dict(containerId='a'*64,imageId='sha256:'+'b'*64,running=True)
        runtime._dispatch=Mock(return_value=row)
        self.assertIs(runtime.verify_current(),True)
        runtime._dispatch.assert_called_once_with('inspect')
        for changed in [dict(row,containerId='c'*64),dict(row,running=False),dict(row,extra=True)]:
            runtime._dispatch=Mock(return_value=changed)
            with self.assertRaisesRegex(ValueError,'IDENTITY_CHANGED'):runtime.verify_current()

    def test_pricing_lease_holder_actual_program_and_legacy_separation(self):
        from dataclasses import replace
        leased = replace(self.spec, holder_contract='pricing-total-lease-v1')
        old = m.guest_runtime_program(self.spec, self.package, 'inspect')
        new = m.guest_runtime_program(leased, self.package, 'inspect')
        self.assertIn("b'/usr/bin/sleep\\x00900\\x00'", old)
        self.assertNotIn("b'/usr/bin/sleep\\x00900\\x00'", new)
        self.assertIn("pricing_holder(root.parent,B['runId'])", new)
        self.assertIn('pricing_holder(root.parent,RUN)', m.namespace_channel_program(leased, 'f'*32))
        compile(new, '<controlled-pricing-guest>', 'exec')
        compile(m.namespace_channel_program(leased, 'f'*32), '<controlled-pricing-channel>', 'exec')

    def test_lease_holder_rejects_renewed_wrong_duration_and_wrong_owner(self):
        import stat
        run = self.spec.run_id
        lease = dict(version=1,target='original-v33-pricing-total-lease-v1',runId=run,clock='linux-monotonic-ms',startedAtMs=1000,expiresAtMs=2617000)
        def invoke(record, seconds='2615.999', owner=run, now=2000, source=m.PRICING_HOLDER):
            namespace = {'need': lambda ok: self.assertTrue(ok)}
            exec(source, namespace)
            contents = [owner.encode(), json.dumps(record).encode(), seconds.encode()]
            index = [-1]
            def opened(*_args): index[0] += 1; return index[0]+100
            def info(_fd): return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=len(contents[index[0]]))
            with patch('os.open',side_effect=opened), patch('os.fstat',side_effect=info), patch('os.read',side_effect=lambda *_:contents[index[0]]), patch('os.close'), patch('time.monotonic_ns',return_value=now*1000000):
                return namespace['pricing_holder'](Path('/exact-owned'),run)
        self.assertEqual(invoke(lease), b'/usr/bin/sleep\x002615.999\x00')
        for record in [dict(lease,expiresAtMs=2617001),dict(lease,startedAtMs=3000,expiresAtMs=2619000),dict(lease,runId='b'*32),dict(lease,version=True)]:
            with self.assertRaises(AssertionError): invoke(record)
        for seconds in ['900','2616.001','NaN','2615.999\n']:
            with self.assertRaises(AssertionError): invoke(lease,seconds)
        with self.assertRaises(AssertionError): invoke(lease,now=2617000)
        with self.assertRaises(AssertionError): invoke(lease,owner='b'*32)
        from dataclasses import replace
        spec = replace(self.spec, holder_contract='pricing-v34-total-lease-v1')
        source = m.pricing_holder_source(spec)
        v34 = dict(lease, target='original-v34-pricing-total-lease-v1', expiresAtMs=3017000)
        self.assertEqual(invoke(v34, '3015.999', source=source), b'/usr/bin/sleep\x003015.999\x00')
        with self.assertRaises(AssertionError): invoke(lease, source=source)
        with self.assertRaises(AssertionError): invoke(v34)
        for record in [dict(v34,expiresAtMs=3017001),dict(v34,version=True)]:
            with self.assertRaises(AssertionError): invoke(record,'3015.999',source=source)
        with self.assertRaises(AssertionError): invoke(v34,'3015.999',now=3017000,source=source)
        v25spec=replace(self.spec,holder_contract='pricing-v25-total-lease-v1')
        v25source=m.pricing_holder_source(v25spec)
        v25=dict(lease,target='original-v25-pricing-total-lease-v1',expiresAtMs=2857000)
        self.assertEqual(invoke(v25,'2855.999',source=v25source),b'/usr/bin/sleep\x002855.999\x00')
        for record in (lease,v34,dict(v25,version=True),dict(v25,expiresAtMs=2857001)):
            with self.assertRaises(AssertionError):invoke(record,'2855.999',source=v25source)
        with self.assertRaises(AssertionError):invoke(v25,'2855.999',now=2857000,source=v25source)
        self.assertEqual(v25spec.runtime_seconds,840)
        for program in (m.guest_runtime_program(v25spec,self.package,'inspect'),m.namespace_channel_program(v25spec,'f'*32)):
            compile(program,'<actual-v25-guard>','exec')
            self.assertIn('original-v25-pricing-total-lease-v1',program)
            self.assertNotIn('original-v34-pricing-total-lease-v1',program)
        for program in [m.guest_runtime_program(spec,self.package,'inspect'),m.namespace_channel_program(spec,'f'*32)]:
            compile(program,'<actual-v34-guard>','exec')
            self.assertIn('original-v34-pricing-total-lease-v1',program)
            self.assertNotIn('original-v33-pricing-total-lease-v1',program)

    def test_v34_runtime_deadline_is_one_shared_original_child_window(self):
        from dataclasses import replace
        spec=replace(self.spec,holder_contract='pricing-v34-total-lease-v1')
        mux=SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py'),admit_existing_mux=Mock(return_value={}))
        processes=Mock()
        with patch('time.monotonic',return_value=100):
            runtime=m.PrivateRuntimeComponents(spec,mux,processes,{},1100,'t'*43)
            self.assertEqual(spec.runtime_seconds,1000)
            self.assertEqual(self.spec.runtime_seconds,600)
            for item,deadline in [(self.spec,1100),(spec,1101),(spec,100)]:
                with self.assertRaisesRegex(ValueError,'DEADLINE'):
                    m.PrivateRuntimeComponents(item,mux,processes,{},deadline,'t'*43)
            runtime.set_cleanup_deadline(700)
            with self.assertRaisesRegex(ValueError,'NONRENEWAL'):runtime.set_cleanup_deadline(699)
        with patch('time.monotonic',return_value=1100):
            with self.assertRaisesRegex(ValueError,'DEADLINE'):runtime._dispatch('inspect')
        processes.launch.assert_not_called()

    def setUp(self):
        self.spec = m.PricingSpec(str(ROOT), 'a' * 32, '10000000-0000-4000-8000-000000000001',
                                  'b' * 12, 'c' * 12, '945f6fce-3aaf-4d8f-a483-170464fb2416')
        self.package = m.capture_package(ROOT)

    def diagnostic(self):
        return dict(version=1,containerId='a'*64,imageId='sha256:'+'b'*64,running=False,exitCode=1,oomKilled=False,errorPresent=False,
                    startedAt='2026-10-21T01:00:00Z',finishedAt='2026-10-21T01:00:01Z',logBytes=24,unexpectedLines=0,
                    markers={'PRICING_LISTENER_READY':0,'PRICING_LISTENER_FAILED':1,'PRICING_LISTENER_CLOSED':0},startup=None)

    def test_actual_guest_diagnostic_projects_only_closed_state_and_marker_counts(self):
        namespace={'__name__':'controlled_guest'}
        exec(m.guest_runtime_program(self.spec,self.package,'diagnose'),namespace)
        image='sha256:'+'b'*64;cid='a'*64
        namespace['guard']=lambda:{'imageId':image}
        namespace['captured_container']=lambda h:cid
        state=dict(Running=False,ExitCode=1,OOMKilled=False,Error='private secret text',StartedAt='2026-10-21T01:00:00Z',FinishedAt='2026-10-21T01:00:01Z')
        namespace['inspect']=lambda *args:{'State':state}
        logs='PRICING_LISTENER_FAILED\nprivate bearer text\nPRICING_LISTENER_READY forged\n'
        namespace['docker']=Mock(return_value=logs)
        result=namespace['run']();m.validate_runtime_diagnostic(result)
        self.assertEqual(result['markers']['PRICING_LISTENER_FAILED'],1)
        self.assertEqual(result['unexpectedLines'],2);self.assertTrue(result['errorPresent'])
        self.assertNotIn('private',json.dumps(result));self.assertNotIn('forged',json.dumps(result))
        namespace['docker'].assert_called_once_with('logs','--tail','64',cid,output_cap=65536)
        for raw in ('x'*65537,'\n'*65):
            namespace['docker']=Mock(return_value=raw)
            with self.assertRaisesRegex(RuntimeError,'PRICING_GUEST_ADMISSION_OR_RETIREMENT'):namespace['run']()
        namespace['inspect']=Mock(side_effect=RuntimeError('wrong identity'));namespace['docker']=Mock()
        with self.assertRaisesRegex(RuntimeError,'wrong identity'):namespace['run']()
        namespace['docker'].assert_not_called()

    def test_guest_closed_startup_projection_and_malformed_or_duplicate_rejection(self):
        namespace={'__name__':'controlled_guest'};exec(m.guest_runtime_program(self.spec,self.package,'diagnose'),namespace)
        namespace['guard']=lambda:{'imageId':'sha256:'+'b'*64};namespace['captured_container']=lambda h:'a'*64
        namespace['inspect']=lambda *a:{'State':dict(Running=False,ExitCode=1,OOMKilled=False,Error='',StartedAt='2026-10-21T01:00:00Z',FinishedAt='2026-10-21T01:00:01Z')}
        valid={'version':1,'code':'HTTP_CHILD_FAILED','childExit':70};prefix='PRICING_STARTUP_DIAGNOSTIC_V1:'
        namespace['docker']=Mock(return_value=prefix+json.dumps(valid)+'\nPRICING_LISTENER_FAILED\n')
        result=namespace['run']();m.validate_runtime_diagnostic(result);self.assertEqual(result['startup'],valid)
        for item in [dict(valid,code='secret'),dict(valid,raw='secret'),dict(valid,childExit=True),dict(valid,childExit=256),dict(valid,version=True)]:
            namespace['docker']=Mock(return_value=prefix+json.dumps(item))
            with self.assertRaises(RuntimeError):namespace['run']()
        namespace['docker']=Mock(return_value=(prefix+json.dumps(valid)+'\n')*2)
        with self.assertRaises(RuntimeError):namespace['run']()

    def test_proven_no_container_diagnostic_does_not_block_exact_absence_cleanup(self):
        namespace={'__name__':'controlled_guest'};exec(m.guest_runtime_program(self.spec,self.package,'diagnose'),namespace)
        namespace['guard']=lambda:{};namespace['captured_container']=lambda h:None;namespace['docker']=Mock()
        absent=namespace['run']();self.assertEqual(absent,{'version':1,'containerAbsent':True,'readiness':'not-observed'});m.validate_runtime_diagnostic(absent)
        namespace['docker'].assert_not_called()
        namespace['captured_container']=Mock(side_effect=RuntimeError('uncertain'))
        with self.assertRaisesRegex(RuntimeError,'uncertain'):namespace['run']()
        runtime=m.PrivateRuntimeComponents(self.spec,SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py')),Mock(),{},time.monotonic()+30,'t'*43)
        runtime.attempted=True;runtime._record_runtime=Mock();runtime.bridge.close=Mock(return_value=dict(listenerClosed=True,localChannelsRetired=True,failures=[]))
        runtime._dispatch=Mock(side_effect=[absent,dict(containerId=None,containerAbsent=True,profileAbsent=True,daemonRetained=True,remoteChannelsAbsent=True)])
        self.assertTrue(runtime.close()['builderReleaseAllowed']);runtime._record_runtime.assert_called_once_with('diagnostic',absent)

    def test_diagnostic_schema_rejects_malformed_oversized_or_secret_fields(self):
        for key,value in [('running',1),('exitCode',True),('exitCode',256),('logBytes',65537),('unexpectedLines',65),('startedAt','secret text'),('containerId','foreign'),('imageId','foreign'),('raw','secret')]:
            row=self.diagnostic();row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_runtime_diagnostic(row)
        row=self.diagnostic();row['markers']['unknown']='secret'
        with self.assertRaises(ValueError):m.validate_runtime_diagnostic(row)

    def test_running_to_exited_is_retained_without_opening_bridge_and_cleanup_preserves_primary(self):
        mux=SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py'))
        for persistence_failure in (False,True):
            runtime=m.PrivateRuntimeComponents(self.spec,mux,Mock(),{},time.monotonic()+30,'t'*43)
            events=[];start=dict(containerId='a'*64,imageId='sha256:'+'b'*64,running=True)
            def dispatch(operation,**kwargs):
                events.append(operation)
                if operation=='start':return start
                if operation=='inspect':return dict(start,running=False)
                if operation=='diagnose':return self.diagnostic()
                return dict(containerId=start['containerId'],containerAbsent=True,profileAbsent=True,daemonRetained=True,remoteChannelsAbsent=True)
            saved=[]
            def save(kind,value):
                if persistence_failure and kind=='diagnostic':raise OSError('fsync')
                saved.append((kind,value))
            runtime._dispatch=dispatch;runtime._record_runtime=save
            runtime.bridge.open=Mock();runtime.bridge.close=Mock(return_value=dict(listenerClosed=True,localChannelsRetired=True,failures=[]))
            consumer=Mock()
            with self.assertRaisesRegex(ValueError,'PRICING_INSPECT_IDENTITY_CHANGED') as raised:runtime.consume(start['imageId'],consumer)
            runtime.bridge.open.assert_not_called();consumer.assert_not_called()
            self.assertEqual(events,['start','inspect','diagnose','stop'])
            self.assertEqual(saved[:2],[('start',start),('inspect',dict(start,running=False))])
            if persistence_failure:self.assertTrue(raised.exception.pricingRetirementUnproven)
            else:self.assertEqual(saved[-1],('diagnostic',self.diagnostic()))

    def test_actual_private_diagnostic_file_is_exclusive_and_persistence_failure_rejects(self):
        import uuid,os,shutil
        from dataclasses import replace
        for failure in (None,'fsync','write'):
            spec=replace(self.spec,run_id=uuid.uuid4().hex)
            directory=ROOT/'tasks/qualification'/('pricing-private-'+spec.run_id);directory.mkdir(mode=0o700)
            runtime=object.__new__(m.PrivateRuntimeComponents);runtime.spec=spec
            try:
                if failure:
                    with patch.object(m.os,failure,side_effect=OSError('injected')):
                        with self.assertRaises(OSError):runtime._record_runtime('diagnostic',self.diagnostic())
                else:
                    runtime._record_runtime('diagnostic',self.diagnostic())
                    target=directory/'runtime-diagnostic.json';self.assertEqual(target.stat().st_mode&0o777,0o600)
                    self.assertEqual(json.loads(target.read_text())['value'],self.diagnostic())
                    with self.assertRaises(FileExistsError):runtime._record_runtime('diagnostic',self.diagnostic())
            finally:shutil.rmtree(directory)

    def fixture(self):
        captured = dict(daemonId='20000000-0000-4000-8000-000000000002', namespaceInode=12345, sharedNamespaceInode=67890,
                        initNamespaceInode=67890, imageId='sha256:' + 'f' * 64,
                        containerId='1' * 64, origin='http://127.0.0.1:18093')
        spec = self.spec
        witness = dict(version='pricing-private-runtime-v1', target=m.TARGET, ownerId=spec.owner_id,
            runId=spec.run_id, workspaceId=spec.workspace_id, qualificationNonce=spec.qualification_nonce,
            packageSha256=self.package['sha256'],
            privateDaemon=dict(id=captured['daemonId'], root=spec.guest_mount + '/data',
                socket=spec.guest_mount + '/docker.sock', namespaceInode=12345, capBytes=m.DISK_BYTES,
                loopbackOnly=True, acquisitionRelayRetired=True, sharedStateUnchanged=True),
            container=dict(id=captured['containerId'], imageId=captured['imageId'], name=spec.name,
                architecture='arm64', profile=spec.profile, profileEnforcing=True, namespaceInode=12345,
                user='10001:10001', memoryBytes=512 * 1024 ** 2, nanoCpus=1000000000, pidsLimit=128,
                readonlyRootfs=True, privileged=False, capDrop=['ALL'], capAdd=[], seccomp='unconfined',
                networkMode='host', binds=[], volumes=[], portBindings={},
                tmpfs={'/tmp': 'rw,nosuid,nodev,size=134217728'}, logDriver='none',
                entrypoint=['node', 'sidecars/sandbox-runner/owned-pricing-http/http-listener.js']),
            bridge=dict(contract='private-netns-existing-mux-stdio-v1', origin=captured['origin'],
                namespaceInode=12345, existingMuxVerified=True, ownedChildVerified=True, sharedMasterForward=False),
            readiness={'ready': True})
        return captured, witness

    def test_fixed_guest_runtime_program_is_closed_and_compiles_without_effects(self):
        for action in ('start', 'inspect', 'stop'):
            source = m.guest_runtime_program(self.spec, self.package, action)
            compile(source, '<pricing-guest>', 'exec')
            self.assertIn("'--network','host'", source)
            self.assertIn("'--pull','never'", source)
            self.assertIn("'127.0.0.1'", source)
            self.assertNotIn('docker.sock:/', source)
        with self.assertRaisesRegex(ValueError, 'PRICING_OPERATION'):
            m.guest_runtime_program(self.spec, self.package, 'build')

    def test_actual_guest_stop_orders_identity_check_before_exact_container_retirement(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'stop'), namespace)
        cid = 'a' * 64
        events = []
        namespace['guard'] = lambda: {'imageId': 'sha256:' + 'b' * 64}
        namespace['private'] = lambda name: {'ownerId': self.spec.owner_id, 'containerId': cid}
        namespace['profile_stop'] = lambda: events.append('profile-stop')
        def inspect(handoff, selected):
            self.assertEqual(selected, cid)
            events.append('inspect')
            return {'State': {'Running': events.count('inspect') <= 2}}
        def docker(*args):
            events.append(args)
            return ''
        namespace['inspect'] = inspect
        namespace['docker'] = docker
        self.assertTrue(namespace['run']()['containerAbsent'])
        self.assertEqual(events, ['inspect', 'inspect', ('stop', '--time', '5', cid), 'inspect',
                                  ('rm', cid), ('ps', '-aq', '--filter', 'id=' + cid), 'profile-stop'])
        events.clear()
        namespace['inspect'] = Mock(side_effect=RuntimeError('identity-changed'))
        with self.assertRaisesRegex(RuntimeError, 'identity-changed'):
            namespace['run']()
        self.assertEqual(events, [])

    def test_guest_stop_never_removes_running_or_unproven_container(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'stop'), namespace)
        namespace['guard'] = lambda: {}
        namespace['private'] = lambda name: {'ownerId': self.spec.owner_id, 'containerId': 'a' * 64}
        namespace['inspect'] = lambda *args: {'State': {'Running': True}}
        docker = Mock(return_value=''); namespace['docker'] = docker
        with self.assertRaisesRegex(RuntimeError, 'ADMISSION_OR_RETIREMENT'):
            namespace['run']()
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(docker.call_args.args[0], 'stop')

    def test_guest_create_pipeline_journals_before_effect_and_never_exposes_token_in_argv(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'start'), namespace)
        events = []; cid = 'a' * 64; image = 'sha256:' + 'b' * 64
        namespace['guard'] = lambda: {'imageId': image}
        namespace['private'] = lambda name: {'token': 't' * 43}
        namespace['profile_start'] = lambda: events.append('profile')
        namespace['processes_current'] = lambda h: events.append('process-identity')
        namespace['save'] = lambda name, value: events.append(('save', name))
        namespace['inspect'] = lambda *args: {'State': {'Running': True}}
        def docker(*args, **kwargs):
            events.append(args)
            self.assertNotIn('t' * 43, repr(args))
            if args[0] == 'create':
                self.assertEqual(kwargs, {'token': 't' * 43})
                self.assertIn('--pull', args); self.assertIn('never', args)
                self.assertEqual(events[-2], 'process-identity')
                self.assertIn(('save', 'pricing-create-intent.json'), events)
                return cid
            return ''
        namespace['docker'] = docker
        self.assertEqual(namespace['run'](), {'containerId': cid, 'imageId': image, 'running': True})
        self.assertLess(events.index(('save', 'pricing-created.json')), events.index(('start', cid)))

    def test_ambiguous_create_resolves_only_exact_owned_container(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'stop'), namespace)
        image = 'sha256:' + 'b' * 64; cid = 'a' * 64
        def private(name):
            if name == 'pricing-created.json': raise FileNotFoundError()
            self.assertEqual(name, 'pricing-create-intent.json')
            return {'runId': self.spec.run_id, 'ownerId': self.spec.owner_id, 'imageId': image, 'name': self.spec.name}
        namespace['private'] = private
        namespace['docker'] = Mock(return_value=cid)
        namespace['inspect'] = Mock()
        self.assertEqual(namespace['captured_container']({'imageId': image}), cid)
        namespace['inspect'].assert_called_once_with({'imageId': image}, cid)
        namespace['docker'].assert_called_once_with('ps', '-aq', '--no-trunc', '--filter', 'name=^/' + self.spec.name + '$')
        namespace['inspect'] = Mock(side_effect=RuntimeError('foreign-label'))
        with self.assertRaisesRegex(RuntimeError, 'foreign-label'):
            namespace['captured_container']({'imageId': image})
        namespace['docker'].return_value = cid + '\n' + 'c' * 64
        with self.assertRaisesRegex(RuntimeError, 'ADMISSION_OR_RETIREMENT'):
            namespace['captured_container']({'imageId': image})

    def test_namespace_channel_is_fixed_and_profile_uses_exact_original_template(self):
        source = m.namespace_channel_program(self.spec, 'd'*32)
        compile(source, '<namespace-channel>', 'exec')
        self.assertIn("sock.connect(('127.0.0.1',8093))", source)
        self.assertIn("os.fstat(fd).st_ino==h['namespaceInode']", source)
        self.assertLess(source.index('os.setuid(account.pw_uid)'), source.index('sock.connect'))
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'inspect'), namespace)
        template = (ROOT / m.PREFIX / 'http-profile.apparmor.in').read_text()
        self.assertEqual(namespace['B']['profileText'], template.replace('@@SUPERVISOR_PROFILE@@', self.spec.profile))

    def test_channel_uses_existing_mux_exec_not_master_forward(self):
        mux = Mock()
        mux.mux_command.side_effect = lambda authority, remote: ['existing-mux', remote]
        command = m.channel_command(self.spec, {'controlled': True}, mux, 'd'*32)
        self.assertEqual(command[0], 'existing-mux')
        self.assertIn('sudo -n timeout', command[1])
        self.assertIn('/usr/bin/python3 -I -S -B -c', command[1])
        self.assertNotIn(' -L ', command[1]); self.assertNotIn(' -R ', command[1])

    def test_original_client_readiness_exact_result_and_retirement_on_setup_failure(self):
        captured, _ = self.fixture()
        descriptor = dict(version=1, ownerId=self.spec.owner_id, workspaceId=self.spec.workspace_id,
            qualificationNonce=self.spec.qualification_nonce, containerId=captured['containerId'],
            imageId=captured['imageId'], packageSha256=self.package['sha256'], profile=self.spec.profile,
            origin=captured['origin'], token='t' * 43)
        class Selector:
            def __init__(self): self.keys = {}
            def register(self, stream, event, buffer): self.keys[stream.fileno()] = SimpleNamespace(fileobj=stream, data=buffer)
            def get_map(self): return self.keys
            def select(self, _timeout): return [(key, 1) for key in list(self.keys.values())]
            def unregister(self, stream): del self.keys[stream.fileno()]
            def close(self): pass
        for failure in (None, 'selector', 'wrong-output'):
            child = SimpleNamespace(stdin=Mock(), stdout=Mock(), stderr=Mock(), wait=Mock(), returncode=0)
            child.stdout.fileno.return_value = 10; child.stderr.fileno.return_value = 11
            processes = Mock(); processes.launch.return_value = child
            chunks = {10: [b'WRONG' if failure == 'wrong-output' else b'PRICING_READY\n', b''], 11: [b'']}
            with patch('selectors.DefaultSelector', side_effect=RuntimeError('selector') if failure == 'selector' else Selector), \
                    patch.object(m, 'capture_package', return_value=self.package), \
                    patch('os.set_blocking'), patch('os.read', side_effect=lambda fd, _: chunks[fd].pop(0)):
                if failure:
                    with self.assertRaises((RuntimeError, ValueError)):
                        m.check_original_client(self.spec, descriptor, processes, {}, time.monotonic()+20)
                else:
                    self.assertEqual(m.check_original_client(self.spec, descriptor, processes, {}, time.monotonic()+20), {'ready': True})
            processes.finish.assert_called_once_with(child)
            self.assertNotIn(descriptor['token'], repr(processes.launch.call_args))
            child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()

    def test_owner_environment_open_uses_real_client_preflight_without_transport_mutation(self):
        class Selector:
            def __init__(self): self.keys={}
            def register(self,stream,event,buffer): self.keys[stream.fileno()]=SimpleNamespace(fileobj=stream,data=buffer)
            def get_map(self): return self.keys
            def select(self,_): return [(key,1) for key in list(self.keys.values())]
            def unregister(self,stream): del self.keys[stream.fileno()]
            def close(self): pass
        for invalid in (False,True):
            environment={'PATH':str(ROOT/'tasks/runtime/node/node_modules/node/bin')+':/usr/bin:/bin',
                'LANG':'C','PYTHONDONTWRITEBYTECODE':'1','HOME':str(ROOT/'tasks/qualification/controlled/home'),
                'TMPDIR':'/tmp/outside' if invalid else str(ROOT/'tasks/qualification/controlled/tmp')}
            original=dict(environment);processes=Mock()
            child=SimpleNamespace(stdin=Mock(),stdout=Mock(),stderr=Mock(),wait=Mock(),returncode=0)
            child.stdout.fileno.return_value=100010;child.stderr.fileno.return_value=100011;processes.launch.return_value=child
            chunks={100010:[b'PRICING_READY\n',b''],100011:[b'']}
            real_read=m.os.read
            mux=SimpleNamespace(__file__=str(ROOT/'tests/postgres/owned_mcp_mux_relay.py'))
            runtime=m.PrivateRuntimeComponents(self.spec,mux,processes,environment,time.monotonic()+30,'t'*43)
            runtime._record_runtime=Mock()
            runtime._dispatch=Mock(return_value=dict(containerId='a'*64,imageId='sha256:'+'b'*64,running=True))
            runtime.bridge.open=Mock(return_value='http://127.0.0.1:18093')
            with patch('selectors.DefaultSelector',Selector),patch('os.set_blocking'),patch('os.read',side_effect=lambda fd,size:chunks[fd].pop(0) if fd in chunks else real_read(fd,size)):
                if invalid:
                    with self.assertRaisesRegex(ValueError,'PRICING_CLIENT_ENV'):runtime.open('sha256:'+'b'*64)
                    processes.launch.assert_not_called()
                else:
                    result=runtime.open('sha256:'+'b'*64)
                    self.assertEqual(result['containerId'],'a'*64)
                    launched=processes.launch.call_args.kwargs
                    self.assertEqual(launched['env'],{k:environment[k] for k in ('PATH','TMPDIR')})
                    self.assertEqual(processes.launch.call_args.args[0][2],m.READINESS_SOURCE)
                    processes.finish.assert_called_once_with(child)
            self.assertIs(runtime.environment,environment);self.assertEqual(environment,original)
            self.assertEqual([c.args[0] for c in runtime._dispatch.call_args_list],['start','inspect'])

    def test_bridge_cleanup_requires_all_owned_pumps_and_children_absent(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        bridge = m.PrivateLoopbackBridge(self.spec, mux, time.monotonic()+30)
        bridge.listener = Mock(); bridge.acceptor = Mock(ident=123)
        bridge.acceptor.is_alive.return_value = False
        bridge.threads = [Mock()]; bridge.threads[0].is_alive.return_value = False
        result = bridge.close()
        self.assertTrue(result['localChannelsRetired'])
        self.assertFalse(result['remoteChannelsVerified'])
        bridge = m.PrivateLoopbackBridge(self.spec, mux, time.monotonic()+30)
        bridge.children.add(object())
        with self.assertRaisesRegex(ValueError, 'RETIREMENT_UNPROVEN'): bridge.close()
        self.assertFalse(bridge.retired)

    def test_bridge_close_fault_does_not_skip_other_owned_retirement(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        bridge = m.PrivateLoopbackBridge(self.spec, mux, time.monotonic()+30)
        bridge.listener = Mock(); bridge.listener.close.side_effect = OSError('close')
        bridge.acceptor = Mock(ident=123); bridge.acceptor.is_alive.return_value = False
        thread = Mock(); thread.is_alive.return_value = False; bridge.threads = [thread]
        with self.assertRaisesRegex(ValueError, 'RETIREMENT_UNPROVEN'): bridge.close()
        bridge.acceptor.join.assert_called_once(); thread.join.assert_called_once()
        self.assertFalse(bridge.retired)

    def test_runtime_pipeline_joins_partial_start_readiness_and_consumer_failures(self):
        image = 'sha256:' + 'b' * 64; cid = 'a' * 64
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        for failure in (None, 'start', 'inspect', 'readiness', 'consumer', 'bridge-retirement', 'guest-retirement'):
            events = []
            runtime = m.PrivateRuntimeComponents(self.spec, mux, Mock(), {}, time.monotonic()+30, 't'*43)
            runtime._record_runtime=Mock()
            def dispatch(operation, **kwargs):
                events.append(operation)
                if failure == operation or (failure == 'guest-retirement' and operation == 'stop'):
                    raise RuntimeError('controlled-'+operation)
                if operation == 'stop':
                    return dict(containerId=cid, containerAbsent=True, profileAbsent=True, daemonRetained=True, remoteChannelsAbsent=True)
                if operation == 'diagnose':return self.diagnostic()
                return dict(containerId=cid, imageId=image, running=True)
            runtime._dispatch = dispatch
            runtime.bridge.open = lambda: events.append('bridge-open') or 'http://127.0.0.1:18093'
            def close():
                events.append('bridge-close')
                if failure == 'bridge-retirement': raise RuntimeError('bridge-debt')
                return dict(listenerClosed=True, localChannelsRetired=True, remoteChannelsVerified=False, failures=[])
            runtime.bridge.close = close
            def ready(*args):
                events.append('readiness')
                if failure == 'readiness': raise RuntimeError('readiness')
                return {'ready': True}
            def consume(descriptor):
                events.append('consumer'); self.assertEqual(descriptor['imageId'], image)
                if failure == 'consumer': raise RuntimeError('consumer')
                return 'observed'
            with patch.object(m, 'check_original_client', side_effect=ready):
                if failure:
                    with self.assertRaises(RuntimeError): runtime.consume(image, consume)
                else: self.assertEqual(runtime.consume(image, consume), 'observed')
            self.assertIn('bridge-close', events)
            if failure == 'bridge-retirement':
                self.assertNotIn('stop', events); self.assertFalse(runtime.closed)
            else:
                self.assertLess(events.index('bridge-close'), events.index('stop'))
            if failure is None:
                self.assertEqual(events, ['start', 'inspect', 'bridge-open', 'readiness', 'consumer', 'bridge-close', 'diagnose', 'stop'])

    def test_runtime_partial_start_keeps_primary_and_records_cleanup_debt(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        runtime = m.PrivateRuntimeComponents(self.spec, mux, Mock(), {}, time.monotonic()+30, 't'*43)
        primary = RuntimeError('lost-create-ack')
        runtime._dispatch = Mock(side_effect=primary)
        runtime.bridge.close = Mock(side_effect=RuntimeError('unresolved-channel'))
        with self.assertRaises(RuntimeError) as raised:
            runtime.consume('sha256:'+'b'*64, Mock())
        self.assertIs(raised.exception, primary)
        self.assertTrue(primary.pricingRetirementUnproven)
        self.assertTrue(runtime.attempted); self.assertFalse(runtime.closed)
        runtime._dispatch.assert_called_once_with('start')

    def test_inspect_identity_drift_stops_before_bridge_readiness_or_consumer(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        original = dict(containerId='a'*64, imageId='sha256:'+'b'*64, running=True)
        for key, value in [('containerId','c'*64), ('imageId','sha256:'+'d'*64),
                           ('running',False), ('extra',True)]:
            runtime = m.PrivateRuntimeComponents(self.spec, mux, Mock(), {}, time.monotonic()+30, 't'*43)
            runtime._record_runtime=Mock()
            altered = dict(original); altered[key] = value
            runtime._dispatch = Mock(side_effect=[original, altered])
            runtime.bridge.open = Mock(side_effect=AssertionError('bridge must not open'))
            with patch.object(m, 'check_original_client', side_effect=AssertionError('client must not run')) as ready:
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'INSPECT_IDENTITY_CHANGED|SCHEMA'):
                    runtime.open(original['imageId'])
                runtime.bridge.open.assert_not_called(); ready.assert_not_called()

    def test_transport_failure_never_disappears_after_positive_cleanup(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'))
        receipt = dict(builderReleaseAllowed=True, bridge={'failures':['RuntimeError']})
        for primary in (None, RuntimeError('consumer-failed')):
            runtime = m.PrivateRuntimeComponents(self.spec, mux, Mock(), {}, time.monotonic()+30, 't'*43)
            runtime.open = Mock(return_value={}); runtime.close = Mock(return_value=receipt)
            consumer = Mock(side_effect=primary) if primary else Mock(return_value='passed')
            with self.assertRaises(RuntimeError) as raised:
                runtime.consume('sha256:'+'b'*64, consumer)
            if primary: self.assertIs(raised.exception, primary)
            else: self.assertEqual(str(raised.exception), 'PRICING_TRANSPORT_FAILED')
            self.assertEqual(raised.exception.pricingTransportFailures, ['RuntimeError'])
            self.assertIs(raised.exception.pricingCleanupReceipt, receipt)
            self.assertFalse(getattr(raised.exception, 'pricingRetirementUnproven', False))

    def test_fixed_guest_dispatch_joins_child_on_selector_failure(self):
        mux = SimpleNamespace(__file__=str(ROOT / 'tests/postgres/owned_mcp_mux_relay.py'),
            admit_existing_mux=Mock(return_value={'owned': True}),
            mux_command=Mock(side_effect=lambda authority, remote: ['fixed-ssh', remote]))
        child = SimpleNamespace(stdout=Mock(), stderr=Mock())
        processes = Mock(); processes.launch.return_value = child
        runtime = m.PrivateRuntimeComponents(self.spec, mux, processes, {}, time.monotonic()+30, 't'*43)
        with patch('selectors.DefaultSelector', side_effect=RuntimeError('selector')):
            with self.assertRaisesRegex(RuntimeError, 'selector'): runtime._dispatch('inspect')
        processes.finish.assert_called_once_with(child)
        child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()
        args = processes.launch.call_args.args[0]
        self.assertEqual(args[0], 'fixed-ssh')
        self.assertIn('sudo -n timeout --signal=TERM --kill-after=2 65', args[1])
        self.assertNotIn('t'*43, repr(args))

    def test_actual_guest_inspect_rejects_original_runtime_contract_drift(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'inspect'), namespace)
        cid = 'a'*64; image = 'sha256:'+'b'*64
        row = dict(Id=cid, Image=image, Name='/'+self.spec.name, Mounts=[],
            Config=dict(User='10001:10001', Entrypoint=['node', 'sidecars/sandbox-runner/owned-pricing-http/http-listener.js'],
                Labels={'owasp-ai-goat.pricing.owner':self.spec.owner_id,'owasp-ai-goat.pricing.workspace':self.spec.workspace_id,
                        'owasp-ai-goat.pricing.package':self.package['sha256']}),
            AppArmorProfile=self.spec.profile, State={'Running':False,'Pid':0},
            HostConfig=dict(NetworkMode='host', PortBindings={}, Binds=[], ReadonlyRootfs=True,
                Privileged=False, CapDrop=['ALL'], CapAdd=[], Memory=536870912, NanoCpus=1000000000,
                PidsLimit=128, Tmpfs={'/tmp':'rw,nosuid,nodev,size=134217728'}, LogConfig={'Type':'local','Config':{'max-size':'64k','max-file':'1','compress':'false'}},
                SecurityOpt=['seccomp=unconfined','apparmor='+self.spec.profile]))
        namespace['docker'] = lambda *args: json.dumps([row])
        self.assertEqual(namespace['inspect']({'imageId':image}, cid), row)
        for section, key, value in [('Config','Entrypoint',['sh']), ('Config','User','0'),
                ('HostConfig','Tmpfs',{}), ('HostConfig','LogConfig',{'Type':'json-file'}),
                ('HostConfig','SecurityOpt',['apparmor=unconfined']), ('HostConfig','NetworkMode','bridge')]:
            original = row[section][key]; row[section][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'ADMISSION_OR_RETIREMENT'):
                namespace['inspect']({'imageId':image}, cid)
            row[section][key] = original

    def test_daemon_and_holder_identity_are_checked_before_create_and_start(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'start'), namespace)
        namespace['guard'] = lambda: {'imageId':'sha256:'+'b'*64}
        namespace['private'] = lambda name: {'token':'t'*43}
        namespace['profile_start'] = Mock(); namespace['save'] = Mock()
        namespace['inspect'] = Mock(return_value={'State':{'Running':True}})
        for failed_check in (1, 2):
            calls = []
            namespace['docker'] = lambda *args, **kwargs: calls.append(args) or ('a'*64 if args[0]=='create' else '')
            checks = Mock(side_effect=[RuntimeError('namespace-drift')] if failed_check==1
                          else [None, RuntimeError('namespace-drift')])
            namespace['processes_current'] = checks
            with self.assertRaisesRegex(RuntimeError, 'namespace-drift'): namespace['run']()
            self.assertFalse(any(args[0]=='start' for args in calls))
            self.assertEqual(any(args[0]=='create' for args in calls), failed_check==2)

    def test_remote_channel_terminal_and_process_absence_are_both_required(self):
        channel = 'd'*32; filename = 'pricing-channel-'+channel+'.jsonl'
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'stop', [channel]), namespace)
        born = dict(version=1, runId=self.spec.run_id, channelId=channel, pid=12345, startTicks='123')
        terminal = dict(terminal=True, channelId=channel)
        for mutation in ('absent', 'still-live', 'missing-terminal', 'foreign-run', 'extra-journal'):
            first = dict(born)
            if mutation=='foreign-run': first['runId']='f'*32
            rows = [first] if mutation=='missing-terminal' else [first,terminal]
            raw = b''.join(json.dumps(row).encode()+b'\n' for row in rows)
            files = [Path(filename)] + ([Path('pricing-channel-'+'e'*32+'.jsonl')] if mutation=='extra-journal' else [])
            fake_stat = SimpleNamespace(st_mode=0o100600, st_uid=0, st_nlink=1, st_size=len(raw))
            # Actual /proc field indexing, with a live matching birth or an
            # explicit ENOENT. No time delay is treated as absence.
            proc = '12345 (python) '+' '.join(['0']*19+['123'])
            with patch.object(Path, 'glob', return_value=files), patch('os.open', return_value=42), \
                    patch('os.fstat', return_value=fake_stat), patch('os.read', return_value=raw), patch('os.close'), \
                    patch.object(Path, 'read_text', side_effect=FileNotFoundError() if mutation=='absent' else None,
                                 return_value=proc):
                if mutation=='absent': namespace['channels_absent']()
                else:
                    with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, 'ADMISSION_OR_RETIREMENT'):
                        namespace['channels_absent']()

    def test_unverified_remote_channel_blocks_container_stop_and_builder_release(self):
        namespace = {'__name__': 'controlled_guest'}
        exec(m.guest_runtime_program(self.spec, self.package, 'stop'), namespace)
        namespace['guard'] = lambda: {}
        namespace['channels_absent'] = Mock(side_effect=RuntimeError('remote-channel-debt'))
        namespace['captured_container'] = Mock(side_effect=AssertionError('no container teardown'))
        with self.assertRaisesRegex(RuntimeError, 'remote-channel-debt'): namespace['run']()
        namespace['captured_container'].assert_not_called()

    def test_real_source_capture_parity_and_no_dependency_substitution(self):
        manifest = json.loads((ROOT / m.PREFIX / 'local-package-manifest.json').read_text())
        self.assertEqual(len(self.package['files']), 14)
        # Historical installation qualification is not authority for this
        # prospective diagnostic package. All other original recipe bytes stay
        # equal; fresh private capture must bind the changed listener itself.
        listener=m.PREFIX+'http-listener.js'
        self.assertEqual(set(self.package['files']),set(manifest['files']))
        self.assertEqual({k:v for k,v in self.package['files'].items() if k!=listener},
                         {k:v for k,v in manifest['files'].items() if k!=listener})
        self.assertEqual(self.package['files'][listener],m.hashlib.sha256((ROOT/listener).read_bytes()).hexdigest())
        self.assertNotEqual(self.package['files'][listener],manifest['files'][listener])
        self.assertNotEqual(self.package['sha256'],manifest['sha256'])
        source = (ROOT / m.PREFIX / 'Dockerfile.local').read_text()
        self.assertEqual(source.count('FROM ' + m.BASE), 2)
        self.assertIn('gcc libc6-dev libseccomp-dev', source)
        self.assertIn('bubblewrap libseccomp2', source)
        self.assertNotIn('npm ', source)

    def test_plan_is_non_allocating_and_honestly_closed(self):
        with patch('os.mkdir', side_effect=AssertionError('write')), patch('os.system', side_effect=AssertionError('exec')):
            result = m.plan(self.spec)
        self.assertIs(result['eligible'], False)
        self.assertIs(result['storage']['enforced'], False)
        self.assertIs(result['qualificationComplete'], False)
        self.assertEqual(result['requestedPackages'], list(m.PACKAGES))
        self.assertEqual(result['blockers'], list(m.BLOCKERS))

    def test_closed_gate_ignores_injected_runner_or_flipped_constant(self):
        runner = Mock(side_effect=AssertionError('must not dispatch'))
        with patch.object(m, 'LIVE_ENABLED', True):
            with self.assertRaisesRegex(RuntimeError, 'UNQUALIFIED'):
                m.start(self.spec, runner=runner, approved=True)
        runner.assert_not_called()

    def test_engine_id_is_exact_opaque_identity_not_image_digest(self):
        captured, witness = self.fixture()
        self.assertTrue(m.validate_runtime_witness(self.spec, self.package, witness, captured))
        for value in ('', True, 'x' * 129, 'engine\nother', '/run/docker.sock', ' engine'):
            bad = dict(captured); bad['daemonId'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.validate_runtime_witness(self.spec, self.package, witness, bad)
        bad = copy.deepcopy(witness)
        bad['privateDaemon']['id'] = '30000000-0000-4000-8000-000000000003'
        with self.assertRaisesRegex(ValueError, 'PRIVATE_DAEMON'):
            m.validate_runtime_witness(self.spec, self.package, bad, captured)

    def test_exact_controlled_witness_is_consistent_not_live_proof(self):
        captured, witness = self.fixture()
        self.assertTrue(m.validate_runtime_witness(self.spec, self.package, witness, captured))
        witness['container'] = dict(reversed(list(witness['container'].items())))
        self.assertTrue(m.validate_runtime_witness(self.spec, self.package, witness, captured))

    def test_private_store_namespace_identity_and_no_egress_tampering(self):
        captured, witness = self.fixture()
        cases = [('privateDaemon', 'id', self.spec.shared_daemon_id),
                 ('privateDaemon', 'root', '/var/lib/docker'),
                 ('privateDaemon', 'socket', '/run/docker.sock'),
                 ('privateDaemon', 'capBytes', m.DISK_BYTES + 1),
                 ('privateDaemon', 'loopbackOnly', 1),
                 ('privateDaemon', 'acquisitionRelayRetired', False),
                 ('container', 'namespaceInode', 99), ('container', 'privileged', True),
                 ('container', 'pidsLimit', 128.0), ('container', 'profileEnforcing', 1),
                 ('container', 'imageId', 'sha256:' + '0' * 64),
                 ('container', 'binds', ['/var/run/docker.sock:/run/docker.sock']),
                 ('container', 'entrypoint', ['node', 'substitute.js']),
                 ('bridge', 'sharedMasterForward', True), ('bridge', 'origin', 'http://localhost:18093'),
                 ('readiness', 'ready', 1)]
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                bad = copy.deepcopy(witness); bad[section][key] = value
                with self.assertRaises(ValueError):
                    m.validate_runtime_witness(self.spec, self.package, bad, captured)

    def test_wrong_owner_target_package_extra_fields_and_uncaptured_identity(self):
        captured, witness = self.fixture()
        for key, value in [('ownerId', 'foreign'), ('target', 'v23-registry'),
                           ('packageSha256', '0' * 64), ('secret', 'not-admitted')]:
            bad = copy.deepcopy(witness); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_runtime_witness(self.spec, self.package, bad, captured)
        for key, value in [('daemonId', self.spec.shared_daemon_id), ('namespaceInode', True),
                           ('sharedNamespaceInode', 12345), ('initNamespaceInode', 12345),
                           ('containerId', 'short'), ('origin', 'http://127.0.0.1:80')]:
            bad = dict(captured); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.validate_runtime_witness(self.spec, self.package, witness, bad)

    def test_source_omission_and_dockerfile_mutation_rejected(self):
        with patch.object(m, '_read_source', return_value=b'FROM different'):
            with self.assertRaisesRegex(ValueError, 'DOCKERFILE_REVIEW'):
                m.capture_package(ROOT)
        bad = copy.deepcopy(self.package); bad['files'].pop(m.FILES[0])
        captured, witness = self.fixture()
        with self.assertRaisesRegex(ValueError, 'PACKAGE'):
            m.validate_runtime_witness(self.spec, bad, witness, captured)


if __name__ == '__main__':
    unittest.main()
