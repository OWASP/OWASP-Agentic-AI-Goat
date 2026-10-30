import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('system_channel', Path(__file__).with_name('owned_system_private_http_channel.py'))
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)


def binding():
    return {'version':1,'target':'original-v24-system','runId':'a'*32,
            'imageId':'sha256:'+'b'*64,'inputSha256':'c'*64,'daemonId':'d'*36,
            'physical':{'privateDockerHost':'unix:///var/tmp/owasp-ai-goat-v23-build-'+'a'*32+'/fs/docker.sock',
                        'namespaceInode':'net:[12345]','filesystemIdentity':{'device':1,'inode':2},
                        'daemonProcess':{'pid':101,'startTicks':'100','exe':'/usr/bin/dockerd'},
                        'namespaceHolder':{'pid':102,'startTicks':'101','exe':'/usr/bin/sleep'}}}


class ControlledRuntime(channel.GuestRuntime):
    def __init__(self):
        super().__init__(binding(),time.monotonic()+10)
        self.events, self.files, self.profiles, self.row = [], {}, set(), None
    def guard(self): self.events.append('guard')
    def lease(self, runtime_deadline=None): self.events.append('lease')
    def commands_absent(self): self.events.append('command-absence')
    def write_new(self,name,raw):
        if name in self.files: raise RuntimeError('collision')
        self.events.append('write:'+name);self.files[name]=raw
    def private_read(self,name,limit=8192):
        if name not in self.files: raise FileNotFoundError(name)
        return self.files[name]
    def profile_names(self): return self.profiles
    def channels_absent(self,ids): self.events.append('remote-absence');return []
    def docker(self,*args):
        self.events.append(args[0])
        if args[0]=='ps': return b'a' if self.row else b''
        if args[0]=='create':
            self.row={'Id':'f'*64,'Image':self.binding['imageId'],'Name':'/'+self.name,
                'Config':{'Labels':{'owasp-ai-goat.system.runtime':self.binding['runId']},'User':'10001:10001',
                          'Entrypoint':['/usr/local/bin/node','/qualification/owned-system/http-listener.js']},
                'HostConfig':{'NetworkMode':'host','PortBindings':{},'ReadonlyRootfs':True,'Memory':536870912,
                              'NanoCpus':1000000000,'PidsLimit':128,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=128m'},
                              'SecurityOpt':['seccomp=unconfined','apparmor='+self.profile]},
                'Mounts':[],'State':{'Running':False,'Pid':201}}
            return b'f'*64
        if args[0]=='container': return json.dumps([self.row]).encode()
        if args[0]=='start':self.row['State']['Running']=True;return b''
        if args[0]=='rm':self.row=None;return b''
        raise AssertionError(args)
    def command(self,args,*unused,**kwargs):
        if args[0] == '/usr/bin/nsenter':
            self.events.append('startup-connect'); return b''
        self.events.append(args[1])
        self.profiles={self.profile,self.profile+'//bwrap'} if args[1]=='-a' else set()
        return b''


class ChannelTests(unittest.TestCase):
    def pairs(self):
        pairs = [socket.socketpair() for _ in range(3)]
        for pair in pairs:
            for sock in pair:
                self.addCleanup(sock.close)
        return pairs

    def test_literal_http_transparent_and_half_close(self):
        (local, incoming), (outgoing, reader), (upstream, server) = self.pairs()
        request = bytes([71,69,84,32,47,32,72,84,84,80,47,49,46,49,13,10,13,10])
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        observed, errors = [], []
        def peer():
            try:
                server.settimeout(2)
                data = b''
                while True:
                    part = server.recv(64)
                    if not part:
                        break
                    data += part
                observed.append(data)
                server.sendall(response)
                server.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=peer)
        worker.start()
        try:
            local.sendall(request)
            local.shutdown(socket.SHUT_WR)
            receipt = channel.pump(incoming.fileno(), outgoing.fileno(), upstream,
                                   deadline=time.monotonic()+2, stopped=lambda: False)
            reader.settimeout(2)
            self.assertEqual(reader.recv(1024), response)
        finally:
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observed, [request])
        self.assertEqual(receipt, {'sentBytes': len(request), 'receivedBytes': len(response)})
        self.assertTrue(os.get_blocking(incoming.fileno()))

    def test_stalled_peer_deadline_is_independent(self):
        (_, incoming), (outgoing, _), (upstream, _) = self.pairs()
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'DEADLINE'):
            channel.pump(incoming.fileno(), outgoing.fileno(), upstream,
                         deadline=start+.05, stopped=lambda: False)
        self.assertLess(time.monotonic()-start, .5)

    def test_cancel_and_bad_deadline_before_reads(self):
        for value in (float('nan'), float('inf'), time.monotonic()-1, time.monotonic()+121):
            with self.assertRaisesRegex(RuntimeError, 'DEADLINE'):
                channel.pump(-1, -2, None, deadline=value, stopped=lambda: False)
        with self.assertRaisesRegex(RuntimeError, 'CANCELLED'):
            channel.pump(-1, -2, None, deadline=time.monotonic()+1, stopped=lambda: True)

    def test_byte_overflow_not_forwarded(self):
        (local, incoming), (outgoing, _), (upstream, server) = self.pairs()
        local.sendall(b'12345')
        with patch.object(channel, 'MAX_BYTES', 4):
            with self.assertRaisesRegex(RuntimeError, 'BYTES'):
                channel.pump(incoming.fileno(), outgoing.fileno(), upstream,
                             deadline=time.monotonic()+1, stopped=lambda: False)
        server.setblocking(False)
        with self.assertRaises(BlockingIOError):
            server.recv(1)

    def test_journal_is_append_only_and_bounded(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            name = Path(directory)/'channel.jsonl'
            fd = os.open(name, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW, 0o600)
            try:
                channel.journal(fd, {'stage': 'started'})
                channel.journal(fd, {'stage': 'terminal'})
                with self.assertRaisesRegex(RuntimeError, 'LIMIT'):
                    channel.journal(fd, {'data': 'x'*16384})
            finally:
                os.close(fd)
            self.assertEqual([json.loads(line) for line in name.read_text().splitlines()],
                             [{'stage':'started'}, {'stage':'terminal'}])
            fd = os.open(name, os.O_WRONLY|os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(RuntimeError, 'JOURNAL'):
                    channel.journal(fd, {'stage':'overwrite'})
            finally:
                os.close(fd)

    def test_public_gate_is_closed(self):
        self.assertFalse(channel.LIVE_ENABLED)

    def test_fixed_lifecycle_intent_before_effect_and_remote_before_teardown(self):
        runtime=ControlledRuntime()
        profile=Path(__file__).parents[2].joinpath('sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').read_bytes()
        with patch.object(channel,'bounded_command',runtime.command), patch.object(channel.os,'stat',return_value=SimpleNamespace(st_ino=12345)), \
             patch.object(runtime,'docker',wraps=runtime.docker) as docker:
            result=runtime.start('x'*43,profile,time.monotonic()+20)
            create=next(call.args for call in docker.call_args_list if call.args[0]=='create')
            self.assertEqual(create[create.index('--log-driver')+1],'local')
            self.assertEqual([create[i+1] for i,arg in enumerate(create) if arg=='--log-opt'],
                             ['max-size=1m','max-file=1','compress=false'])
            self.assertTrue(result['running'])
            self.assertLess(runtime.events.index('write:system-runtime-intent.json'),runtime.events.index('-a'))
            self.assertLess(runtime.events.index('-a'),runtime.events.index('create'))
            self.assertIn('system-runtime.deadline',runtime.files)
            cleanup=runtime.stop([])
            self.assertFalse(cleanup['builderReleaseAllowed'])
            self.assertTrue(cleanup['remoteChannelsAbsent'])
            self.assertLess(runtime.events.index('remote-absence'),runtime.events.index('rm'))

    def test_inspect_wrong_image_resources_or_shared_publish_rejected(self):
        runtime=ControlledRuntime();runtime.docker('create')
        original=json.dumps(runtime.row)
        for change in (lambda r:r.update(Image='sha256:'+'0'*64),
                       lambda r:r['HostConfig'].update(NetworkMode='bridge'),
                       lambda r:r['HostConfig'].update(PortBindings={'8090/tcp':[]}),
                       lambda r:r['HostConfig'].update(Memory=1),
                       lambda r:r['Config'].update(User='0'),
                       lambda r:r.update(Mounts=[{}])):
            runtime.row=json.loads(original);change(runtime.row)
            with self.assertRaisesRegex(RuntimeError,'SYSTEM_CONTAINER'):
                runtime.inspect(False)

    def test_unproven_remote_channels_prevent_container_removal(self):
        runtime=ControlledRuntime();runtime.docker('create')
        with patch.object(runtime,'channels_absent',side_effect=RuntimeError('live-channel')):
            with self.assertRaisesRegex(RuntimeError,'live-channel'):runtime.stop(['a'*32])
        self.assertNotIn('rm',runtime.events)

    def test_channel_program_syntax_and_fixed_destination(self):
        source=channel.channel_program(binding(),'e'*32)
        compile(source,'controlled-channel','exec')
        self.assertIn("connect_ex(('127.0.0.1', PORT))",source)
        self.assertIn("system-runtime.deadline",source)
        self.assertNotIn('ControlMaster=yes',source)

    def test_lost_create_ack_absence_retains_owned_runtime(self):
        runtime=ControlledRuntime()
        runtime.files['system-runtime-intent.json']=json.dumps({'version':1,'binding':runtime.binding,
            'name':runtime.name,'profile':runtime.profile}).encode()
        runtime.files['system-runtime-create-attempt.json']=b'{"attempted":true}'
        with self.assertRaisesRegex(RuntimeError,'SYSTEM_CREATE_OUTCOME_UNCERTAIN'):
            runtime.stop([])
        self.assertNotIn('rm',runtime.events)
        self.assertNotIn('-R',runtime.events)

    def test_known_container_mismatch_never_removes_replacement(self):
        runtime=ControlledRuntime();runtime.docker('create')
        runtime.files['system-runtime-intent.json']=json.dumps({'version':1,'binding':runtime.binding,
            'name':runtime.name,'profile':runtime.profile}).encode()
        runtime.files['system-runtime-create-attempt.json']=b'{"attempted":true}'
        runtime.files['system-runtime-created-id']=b'e'*64
        with self.assertRaisesRegex(RuntimeError,'SYSTEM_CLEANUP_CONTAINER_CHANGED'):runtime.stop([])
        self.assertNotIn('rm',runtime.events)

    def test_remote_terminal_requires_exact_birth_absence_not_local_ssh_eof(self):
        runtime=channel.GuestRuntime(binding(),time.monotonic()+10)
        cid='e'*32
        first={'version':1,'runId':runtime.binding['runId'],'channelId':cid,'pid':9999,
               'startTicks':'100','namespaceInode':12345,'stage':'started'}
        last=dict(first,stage='terminal',outcome='failed',sentBytes=0,receivedBytes=0)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            runtime.root=Path(directory)
            path=runtime.root/('system-channel-'+cid+'.jsonl')
            path.touch()
            with patch.object(runtime,'private_read',return_value=b'\n'.join(json.dumps(row).encode() for row in (first,last))):
                with patch.object(channel,'birth',return_value='100'):
                    with self.assertRaisesRegex(RuntimeError,'STILL_LIVE'):runtime.channels_absent([cid])
                with patch.object(channel,'birth',side_effect=FileNotFoundError):
                    self.assertEqual(runtime.channels_absent([cid]),[cid])
            with patch.object(runtime,'private_read',return_value=json.dumps(first).encode()):
                with self.assertRaisesRegex(RuntimeError,'TERMINAL'):runtime.channels_absent([cid])
            with self.assertRaisesRegex(RuntimeError,'INVENTORY'):runtime.channels_absent([])

    def test_selector_allocation_and_kill_reap_faults_retain_primary_and_debt(self):
        class Stream:
            def close(self): raise OSError('close')
        class Child:
            pid=7777
            stdout=Stream();stdin=Stream();stderr=Stream()
            def poll(self):return None
            def kill(self):raise OSError('kill')
            def wait(self,timeout):raise subprocess.TimeoutExpired('controlled',timeout)
        with patch.object(channel.subprocess,'Popen',return_value=Child()), \
             patch.object(channel.selectors,'DefaultSelector',side_effect=ValueError('selector')), \
             patch.object(channel.os,'killpg',side_effect=ProcessLookupError):
            with self.assertRaisesRegex(ValueError,'selector') as caught:
                channel.bounded_command(['/unused'],time.monotonic()+1)
        self.assertEqual(caught.exception.cleanupDebt,{'pid':7777,'items':['kill','reap','descriptor','descriptor']})

    def test_mux_cancellation_after_admission_never_spawns(self):
        bridge=channel.PrivateBridge('/controlled',{},binding(),time.monotonic()+2,-1)
        local,client=socket.socketpair();self.addCleanup(local.close)
        bridge.clients.add(client)
        fake=SimpleNamespace(admit_existing_mux=lambda *a,**k:bridge.stop_event.set())
        with patch.dict(sys.modules,{'owned_mcp_mux_relay':fake}), patch.object(channel.subprocess,'Popen') as spawn:
            bridge.work(client,'e'*32)
            spawn.assert_not_called()
        self.assertTrue(bridge.stop_event.is_set())
        self.assertTrue(bridge.failures)
        self.assertFalse(bridge.close()['remoteRetired'])

    def test_actual_local_child_bridge_preserves_bytes_and_reaps_without_remote_claim(self):
        bridge=channel.PrivateBridge('/controlled',{},binding(),time.monotonic()+3,-1)
        local,client=socket.socketpair();self.addCleanup(local.close)
        bridge.clients.add(client)
        request=b'GET /secureshop/system/health HTTP/1.1\r\nConnection: close\r\n\r\n'
        response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        original_popen=subprocess.Popen
        seen=[]
        def spawn(argv,**kwargs):
            self.assertEqual(argv[0],'controlled-existing-mux')
            self.assertIn('/usr/bin/python3',argv[1]);self.assertNotIn(' -W ',argv[1])
            seen.append(argv)
            code='import sys; data=sys.stdin.buffer.read(); assert data=='+repr(request)+'; sys.stdout.buffer.write('+repr(response)+'); sys.stdout.buffer.flush()'
            return original_popen([sys.executable,'-I','-S','-B','-c',code],**kwargs)
        fake=SimpleNamespace(admit_existing_mux=lambda *a,**k:None,mux_command=lambda authority,remote:['controlled-existing-mux',remote])
        with patch.dict(sys.modules,{'owned_mcp_mux_relay':fake}), patch.object(channel.subprocess,'Popen',side_effect=spawn):
            worker=threading.Thread(target=bridge.work,args=(client,'e'*32));bridge.threads.append(worker)
            worker.start()
            try:
                local.sendall(request);local.shutdown(socket.SHUT_WR);local.settimeout(3)
                received=b''
                while True:
                    part=local.recv(1024)
                    if not part:break
                    received+=part
            finally:
                worker.join(3)
        self.assertFalse(worker.is_alive());self.assertEqual(received,response)
        self.assertEqual(len(seen),1);self.assertEqual(bridge.failures,[])
        receipt=bridge.close()
        self.assertTrue(receipt['localRetired']);self.assertFalse(receipt['remoteRetired'])
        self.assertFalse(receipt['builderReleaseAllowed'])

    def test_runtime_budget_matches_original_outer_but_each_channel_remains_bounded(self):
        channel.check_runtime_deadline(time.monotonic()+899)
        with self.assertRaisesRegex(RuntimeError,'RUNTIME_DEADLINE'):
            channel.check_runtime_deadline(time.monotonic()+901)
        with self.assertRaisesRegex(RuntimeError,'CHANNEL_DEADLINE'):
            channel.check_deadline(time.monotonic()+121)
        producer=Path(__file__).with_name('ownedSystemImageProducer.js').read_text()
        self.assertTrue('const cohortEnd=performance.now()+900000' in producer)

    def test_owned_mux_probe_streams_and_journals_local_retirement(self):
        with tempfile.TemporaryDirectory() as folder:
            fd=os.open(Path(folder)/'probe.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_APPEND,0o600)
            try:
                bridge=channel.PrivateBridge('/controlled',{},binding(),time.monotonic()+10,fd)
                api=SimpleNamespace(LibProc=lambda:SimpleNamespace(identity=lambda pid:
                    SimpleNamespace(uid=os.getuid(),start_sec=1,start_usec=2)))
                with patch.dict(sys.modules,{'darwin_process_inventory':api}):
                    result=bridge.probe([sys.executable,'-I','-S','-B','-c',
                        "import sys; print('out'); print('err',file=sys.stderr)"],
                        capture_output=True,text=True,timeout=5,check=True)
                rows=[json.loads(x) for x in (Path(folder)/'probe.jsonl').read_text().splitlines()]
                self.assertEqual([r['stage'] for r in rows],['intent','spawned','terminal'])
                self.assertEqual(rows[2]['cleanupDebt'],[])
                self.assertEqual(result.stdout,'out\n');self.assertEqual(result.stderr,'err\n')
                self.assertNotIn('out',json.dumps(rows));self.assertNotIn('err\n',json.dumps(rows))
            finally: os.close(fd)

    def test_command_obligation_persists_and_unresolved_debt_vetoes_cleanup(self):
        runtime=ControlledRuntime()
        with tempfile.TemporaryDirectory() as folder:
            runtime.root=Path(folder)
            runtime.private_read=lambda name,limit=8192:(runtime.root/name).read_bytes()
            rows=[{'stage':'intent','runId':binding()['runId']},
                  {'stage':'spawned','runId':binding()['runId'],'pid':765432,'birth':'1'},
                  {'stage':'terminal','runId':binding()['runId'],'pid':765432,'cleanupDebt':[]}]
            file=runtime.root/('system-command-'+'e'*32+'.jsonl')
            def save(): file.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            save()
            with patch.object(channel,'birth',side_effect=FileNotFoundError),patch.object(channel.os,'killpg',side_effect=ProcessLookupError):
                channel.GuestRuntime.commands_absent(runtime)
                rows[2]['cleanupDebt']=['reap'];save()
                with self.assertRaisesRegex(RuntimeError,'RETIREMENT_UNPROVEN'):
                    channel.GuestRuntime.commands_absent(runtime)
                rows.pop();save()
                with self.assertRaisesRegex(RuntimeError,'RETIREMENT_UNPROVEN'):
                    channel.GuestRuntime.commands_absent(runtime)

    def test_startup_refusal_is_polled_before_http_and_other_errors_not_retried(self):
        runtime=ControlledRuntime();program=[]
        runtime.command=lambda args:program.append(args)
        runtime.wait_listener()
        self.assertEqual(program[0][0],'/usr/bin/nsenter')
        source=program[0][-1]
        attempts=[]
        class Socket:
            def settimeout(self,x): pass
            def connect(self,address):
                attempts.append(address)
                if len(attempts)<3: raise ConnectionRefusedError(channel.errno.ECONNREFUSED,'refused')
            def close(self): pass
        with patch.object(socket,'socket',Socket),patch.object(time,'sleep'),patch.object(os,'stat',return_value=SimpleNamespace(st_ino=12345)):
            exec(compile(source,'<fixed-startup>','exec'),{})
        self.assertEqual(attempts,[('127.0.0.1',8090)]*3)
        attempts.clear()
        class Wrong(Socket):
            def connect(self,address):
                attempts.append(address);raise OSError(channel.errno.EACCES,'denied')
        with patch.object(socket,'socket',Wrong),patch.object(os,'stat',return_value=SimpleNamespace(st_ino=12345)),self.assertRaises(OSError):
            exec(compile(source,'<fixed-startup>','exec'),{})
        self.assertEqual(len(attempts),1)
        with patch.object(socket,'socket') as create,patch.object(os,'stat',return_value=SimpleNamespace(st_ino=999)):
            with self.assertRaisesRegex(RuntimeError,'STARTUP_NAMESPACE'):
                exec(compile(source,'<fixed-startup>','exec'),{})
            create.assert_not_called()

    def test_mux_probe_cleanup_debt_cannot_become_local_retirement(self):
        bridge=channel.PrivateBridge('/controlled',{},binding(),time.monotonic()+10,-1)
        error=RuntimeError('failed');error.cleanupDebt={'pid':123,'items':['reap']}
        with patch.object(channel,'bounded_command',side_effect=error):
            with self.assertRaisesRegex(RuntimeError,'failed'):
                bridge.probe(['/unused'],capture_output=True,text=True,timeout=5,check=True)
        receipt=bridge.close()
        self.assertFalse(receipt['localRetired']);self.assertTrue(receipt['retirementUnproven'])

    def test_guest_absolute_lease_and_reserved_retirement_bound(self):
        runtime=channel.GuestRuntime(binding(),time.monotonic()+10)
        now=time.monotonic_ns()//1000000
        row={'version':1,'target':'original-v24-system-total-lease-v1','runId':binding()['runId'],
             'clock':'linux-monotonic-ms','startedAtMs':now-1000,'expiresAtMs':now-1000+3636000}
        with tempfile.TemporaryDirectory() as folder:
            runtime.root=Path(folder)/'fs'
            file=Path(folder)/'system-lease.json'
            original=os.fstat
            def root_owned(fd):
                info=original(fd)
                return SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_nlink=info.st_nlink,st_size=info.st_size)
            def save():
                file.write_text(json.dumps(row));file.chmod(0o600)
            save()
            with patch.object(channel.os,'fstat',side_effect=root_owned):
                runtime.lease(time.monotonic()+899)
                with self.assertRaisesRegex(RuntimeError,'RESERVE'):
                    runtime.lease(row['expiresAtMs']/1000)
                row['runId']='f'*32;save()
                with self.assertRaisesRegex(RuntimeError,'LEASE'):runtime.lease()
                row['runId']=binding()['runId'];row['startedAtMs']=now-4000000
                row['expiresAtMs']=row['startedAtMs']+3636000;save()
                with self.assertRaisesRegex(RuntimeError,'LEASE'):runtime.lease()

    def test_mux_postflight_has_one_cleanup_deadline_and_owned_runner(self):
        bridge=channel.PrivateBridge('/controlled',{'expected':'same'},binding(),time.monotonic()+10,-1)
        bridge.stop_event.set();seen=[]
        def admit(root,expected,run):
            self.assertEqual(expected,bridge.authority)
            run(['first'],capture_output=True,text=True,timeout=5,check=True)
            run(['second'],capture_output=True,text=True,timeout=5,check=True)
        def probe(argv,options,deadline,stopped):
            self.assertFalse(stopped());seen.append(deadline)
        with patch.dict(sys.modules,{'owned_mcp_mux_relay':SimpleNamespace(admit_existing_mux=admit)}),patch.object(bridge,'_probe',side_effect=probe):
            bridge.postflight()
        self.assertEqual(len(seen),2);self.assertEqual(seen[0],seen[1])
        self.assertLessEqual(seen[0]-time.monotonic(),5)


class PolicyRuntimeTests(unittest.TestCase):
    def fixture(self):
        # Execute the serialized guest module, not a second implementation.
        namespace={'__name__':'controlled_serialized_guest','__file__':str(Path(channel.__file__))}
        exec(compile(Path(channel.__file__).read_text().split("\nif __name__ == '__main__':")[0],'<actual guest>','exec'),namespace)
        base=namespace['GuestRuntime']
        class Policy(base, ControlledRuntime):
            def __init__(self):
                b=binding();b['target']='original-v24-policy'
                base.__init__(self,b,time.monotonic()+10)
                self.events,self.files,self.profiles,self.row=[],{},set(),None
                self.argv=[]
            guard=ControlledRuntime.guard
            lease=ControlledRuntime.lease
            commands_absent=ControlledRuntime.commands_absent
            profile_names=ControlledRuntime.profile_names
            channels_absent=ControlledRuntime.channels_absent
            command=ControlledRuntime.command
            def write_new(self,name,raw):return ControlledRuntime.write_new(self,self.filename(name),raw)
            def private_read(self,name,limit=8192):return ControlledRuntime.private_read(self,self.filename(name),limit)
            def docker(self,*args):
                self.argv.append(args)
                result=ControlledRuntime.docker(self,*args)
                if args[0]=='create':
                    self.row['Config'].update(Labels={'owasp-ai-goat.policy.runtime':self.binding['runId']},Entrypoint=self.entrypoint,
                        Env=['SECURESHOP_POLICY_RENDER_ENABLED=true','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1'])
                    self.row['HostConfig'].update(NetworkMode='none',CapDrop=['ALL'],CapAdd=[],Privileged=False,
                        Tmpfs={'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'})
                    self.row['NetworkSettings']={'Networks':{'none':{}},'Ports':{'8090/tcp':None}}
                return result
        return Policy(),namespace

    def start(self,runtime,ns,namespace=23456):
        end=time.monotonic()+20
        # Existing System deadline is a real private file; only root UID/proc
        # facts are controlled, no real Docker/namespace or platform mutation.
        folder=tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'));self.addCleanup(folder.cleanup)
        runtime.root=Path(folder.name)
        deadline=runtime.root/'system-runtime.deadline';deadline.write_text(str(end));deadline.chmod(0o600)
        original_fstat=os.fstat
        def fstat(fd):
            row=original_fstat(fd)
            return SimpleNamespace(st_mode=row.st_mode,st_uid=0,st_nlink=row.st_nlink,st_size=row.st_size)
        def stat_(name,*args,**kwargs):
            return SimpleNamespace(st_ino=namespace if str(name)=='/proc/201/ns/net' else 100)
        with patch.object(ns['os'],'stat',side_effect=stat_),patch.object(ns['os'],'fstat',side_effect=fstat),\
             patch.object(ns['os'],'readlink',return_value='/usr/local/bin/node'),patch.dict(ns,{'birth':lambda pid:'900'}):
            result=runtime.start(None,Path(channel.__file__).parents[2].joinpath('sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').read_bytes(),end)
        return result

    def test_actual_serialized_policy_start_private_namespace_and_original_argv(self):
        runtime,ns=self.fixture();row=self.start(runtime,ns)
        self.assertEqual(row['target'],'original-v24-policy');self.assertEqual(row['namespaceInode'],23456)
        create=next(a for a in runtime.argv if a[0]=='create')
        self.assertEqual(create[create.index('--log-driver')+1],'local')
        self.assertEqual([create[i+1] for i,arg in enumerate(create) if arg=='--log-opt'],
                         ['max-size=1m','max-file=1','compress=false'])
        self.assertEqual(create[create.index('--network')+1],'none')
        self.assertNotIn('--publish',create);self.assertNotIn('-p',create)
        self.assertEqual(create[create.index('--cap-drop')+1],'ALL')
        self.assertEqual(create[-1],runtime.binding['imageId'])
        self.assertEqual(runtime.files['policy-runtime.env'],b'SECURESHOP_POLICY_RENDER_ENABLED=true\nSECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1\n')
        self.assertTrue(all(n.startswith('policy-') for n in runtime.files))
        capture=json.loads(runtime.files['policy-runtime-process.json'])
        self.assertEqual(capture['process'],{'pid':201,'startTicks':'900','exe':'/usr/local/bin/node'})

    def test_policy_namespace_excludes_builder_and_shared_and_capture_swap(self):
        for forbidden in (12345,100):
            runtime,ns=self.fixture()
            with self.assertRaisesRegex(RuntimeError,'POLICY_RUNTIME_NAMESPACE'):self.start(runtime,ns,forbidden)
            self.assertNotIn('policy-runtime-process.json',runtime.files)
        runtime,ns=self.fixture();self.start(runtime,ns)
        with patch.object(ns['os'],'stat',return_value=SimpleNamespace(st_ino=100)),patch.dict(ns,{'process_current':lambda *_:None}):
            runtime.row['State']['Pid']=202
            with self.assertRaisesRegex(RuntimeError,'POLICY_RUNTIME_CHANGED'):runtime.inspect(True)

    def test_policy_rejects_pid_reuse_wrong_executable_and_namespace(self):
        runtime,ns=self.fixture();self.start(runtime,ns)
        for ticks,exe,inode in [('901','/usr/local/bin/node',23456),('900','/bin/sh',23456),('900','/usr/local/bin/node',12345)]:
            with patch.dict(ns,{'birth':lambda pid:ticks}),patch.object(ns['os'],'readlink',return_value=exe),\
                 patch.object(ns['os'],'stat',side_effect=lambda name:SimpleNamespace(st_ino=inode if str(name)=='/proc/201/ns/net' else 100)):
                with self.assertRaisesRegex(RuntimeError,'PROCESS_CHANGED'):runtime.inspect(True)

    def test_second_policy_failure_does_not_touch_system_files_and_retains_unknown_create(self):
        runtime,ns=self.fixture();self.start(runtime,ns)
        runtime.files['system-runtime-intent.json']=b'original system untouched'
        runtime.files.pop('policy-runtime-created-id');runtime.row=None
        with self.assertRaisesRegex(RuntimeError,'SYSTEM_CREATE_OUTCOME_UNCERTAIN'):runtime.stop([])
        self.assertEqual(runtime.files['system-runtime-intent.json'],b'original system untouched')
        self.assertNotIn('rm',runtime.events)

    def test_pending_policy_channel_blocks_removal_and_positive_cleanup_is_target_bound(self):
        runtime,ns=self.fixture();self.start(runtime,ns)
        runtime.channels_absent=lambda ids:(_ for _ in ()).throw(RuntimeError('channel still live'))
        with self.assertRaisesRegex(RuntimeError,'channel still live'):runtime.stop(['e'*32])
        self.assertNotIn('rm',runtime.events)
        runtime.channels_absent=lambda ids:[]
        terminal=runtime.stop([])
        self.assertEqual(terminal['target'],'original-v24-policy');self.assertTrue(terminal['containerAbsent'])
        self.assertEqual(runtime.stop([]),terminal)

    def test_policy_container_rejects_published_host_privileged_or_changed_original_settings(self):
        runtime,ns=self.fixture();runtime.docker('create');original=json.dumps(runtime.row)
        for mutate in [lambda r:r['HostConfig'].update(NetworkMode='host'),lambda r:r['HostConfig'].update(CapDrop=[]),
            lambda r:r['HostConfig'].update(PortBindings={'8090/tcp':[{}]}),lambda r:r['HostConfig'].update(Privileged=True),
            lambda r:r['NetworkSettings'].update(Networks={'none':{},'bridge':{}}),
            lambda r:r['NetworkSettings'].update(Ports={'8090/tcp':[{'HostPort':'8090'}]}),
            lambda r:r['Config'].update(Entrypoint=['/bin/sh']),lambda r:r['Config'].update(Env=['SECURESHOP_POLICY_RENDER_ENABLED=false'])]:
            runtime.row=json.loads(original);mutate(runtime.row)
            with self.assertRaises(RuntimeError):runtime.inspect(False)

    def test_policy_channel_emission_uses_captured_process_and_open_namespace_fd(self):
        b=binding();b['target']='original-v24-policy'
        emitted=channel.channel_program(b,'e'*32)
        compile(emitted,'<actual policy channel>','exec')
        self.assertIn('holder, NAMESPACE = runtime.runtime_capture()',emitted)
        self.assertIn('namespace_fd = os.open',emitted)
        self.assertIn('process_current(holder, NAMESPACE)',emitted)
        self.assertIn("ROOT/(SLOT+'-channel-'",emitted)
        self.assertIn('os.fstat(namespace_fd).st_ino == NAMESPACE',emitted)

    def test_executed_channel_suffix_opens_exact_fd_and_rejects_namespace_fd_swap(self):
        import pwd
        for swapped in (False,True):
            runtime,ns=self.fixture();self.start(runtime,ns)
            (runtime.root/'policy-runtime.deadline').write_bytes(runtime.files['policy-runtime.deadline'])
            (runtime.root/'policy-runtime.deadline').chmod(0o600)
            inode_file=runtime.root/'controlled-namespace';inode_file.write_bytes(b'owned descriptor')
            original_open,original_fstat=os.open,os.fstat
            namespace_fds=set();seen=[]
            def open_(name,flags,*args,**kwargs):
                if str(name)=='/proc/201/ns/net':
                    fd=original_open(inode_file,flags);namespace_fds.add(fd);return fd
                return original_open(name,flags,*args,**kwargs)
            def fstat(fd):
                row=original_fstat(fd)
                return SimpleNamespace(st_mode=row.st_mode,st_uid=0,st_nlink=row.st_nlink,st_size=row.st_size,
                    st_ino=(99999 if swapped else 23456) if fd in namespace_fds else row.st_ino)
            def serve(**kw):
                seen.append(kw);self.assertEqual(kw['namespace_inode'],23456)
                self.assertIn(kw['namespace_fd'],namespace_fds)
                self.assertLessEqual(kw['deadline']-time.monotonic(),120)
                self.assertEqual(kw['run_id'],runtime.binding['runId'])
            source=channel.channel_program(runtime.binding,'e'*32)
            suffix=source[source.rindex('\nimport signal\nBINDING ='):]
            with patch.dict(ns,{'GuestRuntime':lambda *a:runtime,'fixed_binding':lambda b:(runtime.root,12345),
                    'serve_inherited':serve,'birth':lambda pid:'900'}),\
                 patch.object(ns['os'],'open',side_effect=open_),patch.object(ns['os'],'fstat',side_effect=fstat),\
                 patch.object(ns['os'],'stat',side_effect=lambda name:SimpleNamespace(st_ino=23456 if str(name)=='/proc/201/ns/net' else 100)),\
                 patch.object(ns['os'],'readlink',return_value='/usr/local/bin/node'),\
                 patch.object(pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=501,pw_gid=20)):
                if swapped:
                    with self.assertRaisesRegex(RuntimeError,'SYSTEM_CHANNEL_NAMESPACE'):exec(compile(suffix,'<exact channel suffix>','exec'),ns)
                else:exec(compile(suffix,'<exact channel suffix>','exec'),ns)
            self.assertEqual(len(seen),0 if swapped else 1)
            for fd in namespace_fds:
                with self.assertRaises(OSError):original_fstat(fd)

    def test_actual_renderer_channel_journal_rejects_unjoined_birth_before_delete(self):
        runtime,ns=self.fixture();self.start(runtime,ns)
        cid='e'*32
        first={'version':1,'runId':runtime.binding['runId'],'channelId':cid,'pid':303,
               'startTicks':'999','namespaceInode':23456,'stage':'started'}
        last=dict(first,stage='terminal',outcome='complete',sentBytes=0,receivedBytes=0)
        raw=(json.dumps(first)+'\n'+json.dumps(last)+'\n').encode()
        name='policy-channel-'+cid+'.jsonl'
        (runtime.root/name).write_bytes(raw);runtime.files[name]=raw
        runtime.channels_absent=lambda ids:ns['GuestRuntime'].channels_absent(runtime,ids)
        with patch.object(ns['os'],'stat',return_value=SimpleNamespace(st_ino=100)),patch.dict(ns,{'birth':lambda pid:'999'}):
            with self.assertRaisesRegex(RuntimeError,'SYSTEM_CHANNEL_STILL_LIVE'):runtime.stop([cid])
        self.assertNotIn('rm',runtime.events)

    def test_renderer_deadline_cannot_renew_after_first_start(self):
        runtime,ns=self.fixture();self.start(runtime,ns)
        original_fstat=os.fstat
        def fstat(fd):
            row=original_fstat(fd)
            return SimpleNamespace(st_mode=row.st_mode,st_uid=0,st_nlink=row.st_nlink,st_size=row.st_size)
        before=len(runtime.argv)
        with patch.object(ns['os'],'fstat',side_effect=fstat):
            with self.assertRaisesRegex(RuntimeError,'POLICY_COHORT_CHANGED'):
                runtime.start(None,Path(channel.__file__).parents[2].joinpath('sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').read_bytes(),time.monotonic()+21)
        self.assertEqual(len(runtime.argv),before)

    def test_expired_or_invalid_renderer_deadline_has_zero_effect(self):
        profile=Path(channel.__file__).parents[2].joinpath('sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in').read_bytes()
        for end in [float('nan'),float('inf'),time.monotonic()-1,time.monotonic()+901]:
            runtime,ns=self.fixture()
            with self.assertRaisesRegex(RuntimeError,'RUNTIME_DEADLINE'):runtime.start(None,profile,end)
            self.assertEqual(runtime.events,[]);self.assertEqual(runtime.files,{})


if __name__ == '__main__':
    unittest.main()
