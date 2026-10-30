import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from unittest.mock import MagicMock, patch

PATH = Path(__file__).with_name('run_owned_mcp_relay_lifecycle.py')
spec = importlib.util.spec_from_file_location('lifecycle', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
client_spec = importlib.util.spec_from_file_location('transport_client', PATH.with_name('ownedMcpPrivateTransportClient.py'))
client = importlib.util.module_from_spec(client_spec)
client_spec.loader.exec_module(client)


def plan():
    return {'version': 1, 'kind': 'private-relay-lifecycle-only', 'runId': 'b'*32,
        'guest': '/var/tmp/owasp-ai-goat-v23-build-'+'b'*32, 'storageCapBytes': 16777216,
        'acquisitionApproved': False, 'executionApproved': False,
        'admission': {'account': 'lima', 'uid': 501, 'gid': 1000},
        'relaySourceSha256': 'a'*64, 'lifecycleSourceSha256': 'b'*64,
        'mux': {'masterPid': 123, 'masterBirth': [1, 2]},
        'commands': {key: key for key in m.OPERATIONS}}


def evidence(terminal=False):
    value = plan()
    files = {'namespace.inode': 'net:[2]', 'shared.inode': 'net:[1]'}
    for mode in ('connector', 'adapter'):
        lines = [{'kind': 'relay-ready', 'mode': mode, 'port': 12345 if mode == 'adapter' else None}]
        if terminal:
            lines.append({'kind': 'relay-terminal', 'connections': 0, 'bytes': 0,
                'hostBytes': {host: 0 for host in ('registry-1.docker.io', 'auth.docker.io', 'deb.debian.org')},
                'records': [], 'unjoinedWorkers': 0, 'unresolvedResolverCleanup': 0, 'cleanupVerified': True})
        files['relay.'+mode+'.log'] = '\n'.join(json.dumps(row) for row in lines)+'\n'
        files['relay.'+mode+'.err'] = ''
    return {'version': 1, 'runId': value['runId'], 'lifecycleOnly': True,
        'sourceSha256': value['relaySourceSha256'], 'admission': value['admission'],
        'storage': {'capBytes': 16777216, 'usedBytes': 65536}, 'files': files}


INVENTORY = ('"945f6fce-3aaf-4d8f-a483-170464fb2416"\n'
    'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 postgres:18\n'
    'CONTAINERS\n\nVOLUMES\n\nNETWORK\n'+json.dumps({'version': 1, 'bridge': {'id': 'owned'}, 'links': [{'ifname': 'docker0'}]}))


class Mux:
    def __init__(self, events):
        self.events = events
    def admit_existing_mux(self, root, expected=None, run=None):
        self.events.append('mux')
        assert expected == {'masterPid': 123, 'masterBirth': (1, 2)}
        return expected
    def mux_command(self, authority, *args):
        return ['CONTROLLED', *args]


class Runner:
    def __init__(self, events, terminal=False, failure=None, bad_terminal=False, changed_inventory=False):
        self.events = events
        self.terminal = terminal
        self.failure = failure
        self.bad_terminal = bad_terminal
        self.changed_inventory = changed_inventory
        self.children = []
        self.observed = 0
        self.calls = []
    def __call__(self, argv, **kw):
        operation = kw['input']
        self.events.append(operation)
        self.calls.append((argv, kw))
        if operation == self.failure:
            raise RuntimeError('controlled')
        if operation == 'inventory':
            output = INVENTORY + (' ' if self.changed_inventory else '')
        elif operation == 'authority':
            output = '12345\n'
        elif operation == 'evidence':
            value = evidence(self.terminal)
            if self.bad_terminal:
                value['files']['relay.adapter.log'] = value['files']['relay.adapter.log'].replace('"connections": 0', '"connections": 1')
            output = json.dumps(value)
        elif operation == 'cleanup':
            output = 'absent\n'
        else:
            output = ''
        return subprocess.CompletedProcess(argv, 0, output, '')


def audit(mode, stage, sequence, trigger='checkpoint'):
    counts = dict(dnsSubprocesses=0, externalConnectAttempts=0, unixConnectAttempts=0, peerChecks=0, peerDenied=0)
    if stage in ('denials', 'positive') and mode == 'connector':
        counts.update(peerChecks=1, peerDenied=1)
    if stage == 'positive':
        counts.update(dict(peerChecks=4,dnsSubprocesses=3,externalConnectAttempts=3)
            if mode == 'connector' else dict(peerChecks=3,unixConnectAttempts=3))
    return {'kind':'transport-audit','variant':'connect-audit-v1','runId':'b'*32,'mode':mode,
        'sequence':sequence,'trigger':trigger,'counts':counts,'activeWorkers':0}


def transport_evidence(terminal=False):
    value = evidence(False)
    value['lifecycleOnly'] = False
    if terminal:
        for mode in ('connector','adapter'):
            lines = [json.loads(value['files']['relay.'+mode+'.log'])]
            lines += [audit(mode,stage,seq) for seq,stage in enumerate(('baseline','denials','positive'),1)]
            lines += [{'kind':'relay-terminal','connections':4,'bytes':300,
                'hostBytes':{host:100 for host,_,_ in m.TRANSPORT_CASES.values()},
                'records':[{'host':None,'status':'denied'}]+[{'host':host,'status':'closed'} for host,_,_ in m.TRANSPORT_CASES.values()],
                'unjoinedWorkers':0,'unresolvedResolverCleanup':0,'cleanupVerified':True},
                audit(mode,'positive',4,trigger='terminal')]
            value['files']['relay.'+mode+'.log'] = '\n'.join(json.dumps(row) for row in lines)+'\n'
    return value


def client_result(case):
    if case in ('deny-peer','deny-host'):
        row = {'case':case,'denied':True,'effectiveUid':0 if case=='deny-peer' else 501,'responseBytes':0}
    else:
        host,path,status = m.TRANSPORT_CASES[case]
        row = {'case':case,'host':host,'path':path,'status':status,'bodyBytes':10,'bodySha256':'a'*64,
            'certificateSha256':'b'*64,'tlsVerified':True,'tlsVersion':'TLSv1.3','effectiveUid':501}
    return {'version':1,'ok':True,'closed':True,'result':row}


class TransportRunner(Runner):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw)
        self.sequence=0
    def __call__(self,argv,**kw):
        operation = kw['input']
        if operation in ('checkpoint','evidence') or operation.startswith('client-'):
            self.events.append(operation)
            if operation=='checkpoint':
                self.sequence+=1
                stage=('baseline','denials','positive')[self.sequence-1]
                value={'version':1,'runId':'b'*32,'variant':'connect-audit-v1',
                    'rows':{mode:audit(mode,stage,self.sequence) for mode in ('connector','adapter')}}
            elif operation=='evidence': value=transport_evidence(self.terminal)
            else: value=client_result(operation.removeprefix('client-'))
            return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
        return super().__call__(argv,**kw)


class LifecycleTests(unittest.TestCase):
    def test_guest_client_compiles_with_syntax_warnings_as_errors(self):
        source = PATH.with_name('ownedMcpPrivateTransportClient.py')
        with warnings.catch_warnings():
            warnings.simplefilter('error', SyntaxWarning)
            compile(source.read_bytes(), str(source), 'exec')

    def flow(self, directory, *, failure=None, bad_terminal=False, capture_failure=False, uncertain=False, changed_inventory=False):
        events = []
        work = Runner(events, failure=failure)
        cleanup = Runner(events, terminal=True, failure='evidence' if capture_failure else None,
                         bad_terminal=bad_terminal, changed_inventory=changed_inventory)
        if uncertain:
            work.children.append({'pid': 42, 'reaped': False, 'groupAbsent': False})
        with patch.object(m, 'verify_sources'):
            result = m.run_lifecycle(plan(), {}, directory, None, Mux(events), work, cleanup,
                pause=lambda delay: events.append(('settle', delay)))
        return result, events, work, cleanup

    def temp(self):
        return tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))

    def test_actual_local_plan_has_closed_sources_and_no_vm_command(self):
        probe = m.load_probe()
        runner = probe.BoundedRunner(time.monotonic()+30)
        value, sources = m.make_plan('b'*32, runner)
        self.assertEqual(value['admission']['gid'], 1000)
        self.assertEqual(set(value['commands']), m.OPERATIONS)
        self.assertGreater(len(sources), 10)
        self.assertTrue(all(row['reaped'] and row['groupAbsent'] for row in runner.children))
        self.assertEqual(len(runner.children), 1, 'only the local Node plan generator ran')

    def test_complete_flow_captures_journals_before_retirement_and_joins_witnesses(self):
        with self.temp() as tmp:
            result, events, work, cleanup = self.flow(Path(tmp))
            self.assertTrue(result['passed'])
            self.assertEqual(events, ['mux', 'inventory', 'preflight', 'prepare', 'namespace',
                'start', 'authority', 'evidence', 'stop', 'evidence', 'cleanup', 'inventory', 'mux'])
            self.assertTrue((Path(tmp)/'startup.json').exists())
            self.assertTrue((Path(tmp)/'terminal.json').exists())
            self.assertFalse(result['acquisitionApproved'])
            self.assertFalse(result['buildApproved'])
            for argv, kw in work.calls+cleanup.calls:
                self.assertEqual(argv[1:8], ['sudo','-n','timeout','--signal=TERM','--kill-after=2','15','/bin/sh'])
                self.assertLessEqual(kw['timeout'], 20)

    def test_failed_start_retains_partial_terminal_then_cleanup_and_failure(self):
        with self.temp() as tmp:
            result, events, _, _ = self.flow(Path(tmp), failure='start')
            self.assertFalse(result['passed'])
            self.assertTrue(result['guestAbsent'])
            self.assertIn(('settle', 17), events)
            self.assertLess(events.index('evidence'), events.index('cleanup'))

    def test_terminal_capture_failure_withholds_disk_retirement(self):
        with self.temp() as tmp:
            result, events, _, _ = self.flow(Path(tmp), capture_failure=True)
            self.assertFalse(result['passed'])
            self.assertNotIn('cleanup', events)
            self.assertIn('GUEST_RETAINED_FOR_INSPECTION', result['cleanupErrors'])
            self.assertIn('inventory', events[events.index('stop'):])

    def test_saved_terminal_criterion_failure_does_not_prevent_safe_cleanup(self):
        with self.temp() as tmp:
            result, events, _, _ = self.flow(Path(tmp), bad_terminal=True)
            self.assertFalse(result['passed'])
            self.assertIn('TERMINAL_CRITERIA_FAILED', result['cleanupErrors'])
            self.assertIn('cleanup', events)
            self.assertTrue((Path(tmp)/'terminal.json').exists())

    def test_host_uncertainty_withholds_all_guest_retirement(self):
        with self.temp() as tmp:
            result, events, _, _ = self.flow(Path(tmp), uncertain=True)
            self.assertFalse(result['passed'])
            self.assertNotIn('stop', events)
            self.assertNotIn('cleanup', events)
            self.assertIn('HOST_QUIESCENCE_UNVERIFIED', result['cleanupErrors'])

    def test_shared_postflight_drift_rejects_after_cleanup(self):
        with self.temp() as tmp:
            result, events, _, _ = self.flow(Path(tmp), changed_inventory=True)
            self.assertFalse(result['passed'])
            self.assertTrue(result['guestAbsent'])
            self.assertIn('SHARED_POSTFLIGHT_FAILED', result['cleanupErrors'])

    def test_evidence_rejects_nonprivate_namespace_wrong_binding_and_egress(self):
        mutations = [lambda v: v.update(runId='c'*32),
            lambda v: v['files'].update({'namespace.inode': 'net:[1]'}),
            lambda v: v['files'].update({'namespace.inode': ''}),
            lambda v: v['storage'].update(usedBytes=16777217),
            lambda v: v['files'].update({'relay.adapter.log': v['files']['relay.adapter.log'].replace('"bytes": 0', '"bytes": 1')}),
            lambda v: v['files'].update({'relay.adapter.err': 'failure'})]
        for mutate in mutations:
            value = evidence(True)
            mutate(value)
            with self.assertRaises(RuntimeError):
                m.verify_evidence(value, plan(), terminal=True)

    def test_retained_namespace_newlines_compare_canonically_without_mutating_evidence(self):
        retained_path = m.ROOT/'tasks/qualification/relay-lifecycle-72f0ca8b1a694a909e03bd2898434f2e/terminal.json'
        retained = json.loads(retained_path.read_text())
        self.assertIsNone(retained['files']['relay.intent'])
        value = evidence(True)
        for key in ('namespace.inode', 'shared.inode'):
            value['files'][key] = retained['files'][key]
        before = copy.deepcopy(value)
        m.verify_evidence(value, plan(), terminal=True)
        self.assertEqual(value, before)
        for bad in ('net:[2]\n\n','net:[2]\r\n',' net:[2]\n','net:[2] '):
            value['files']['namespace.inode'] = bad
            with self.assertRaisesRegex(RuntimeError, 'NAMESPACE'):
                m.verify_evidence(value, plan(), terminal=True)
        value['files']['namespace.inode'] = value['files']['shared.inode'].removesuffix('\n')
        with self.assertRaisesRegex(RuntimeError, 'NOT_PRIVATE'):
            m.verify_evidence(value, plan(), terminal=True)

    def test_failed_operation_safe_exit_code_is_retained_not_arbitrary_error_text(self):
        for message, expected in [('COMMAND_EXIT_1','COMMAND_EXIT_1'),('COMMAND_DEADLINE','COMMAND_DEADLINE'),
                                  ('private content','COMMAND_FAILED')]:
            with self.temp() as tmp:
                events = []
                work, cleanup = Runner(events), Runner(events, terminal=True)
                original = work.__call__
                def called(argv, **kw):
                    if kw['input'] == 'start':
                        raise RuntimeError(message)
                    return original(argv, **kw)
                with patch.object(m, 'verify_sources'), patch.object(Runner, '__call__', autospec=True) as callback:
                    callback.side_effect = lambda obj, argv, **kw: called(argv, **kw) if obj is work else original_cleanup(argv, **kw)
                    # Keep the original bound method before installing the mock.
                    original_cleanup = lambda argv, **kw: original.__func__(cleanup, argv, **kw)
                    result = m.run_lifecycle(plan(), {}, Path(tmp), None, Mux(events), work, cleanup, pause=lambda _: None)
                self.assertEqual(result['commandFailures'][0], {'operation':'start','code':expected})
                self.assertFalse(result['passed'])
                self.assertNotIn('private content', json.dumps(result))

    def test_output_requires_new_canonical_repository_directory(self):
        with self.temp() as tmp:
            root = Path(tmp).resolve()
            base = root/'tasks/qualification'
            base.mkdir(parents=True)
            with patch.object(m, 'ROOT', root):
                directory = m.private_directory(str(base/'owned'))
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                m.persist(directory, 'result.json', {'safe': True})
                self.assertEqual((directory/'result.json').stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    m.private_directory(str(directory))
                (base/'alias').symlink_to(directory, target_is_directory=True)
                with self.assertRaises(RuntimeError):
                    m.private_directory(str(base/'alias/new'))

    def test_plan_default_never_loads_mux_or_creates_output(self):
        probe = m.load_probe()
        with patch.object(sys, 'argv', [str(PATH)]), patch.object(m, 'load_probe', return_value=probe), \
                patch.object(probe, 'load_mux') as mux, patch.object(m, 'private_directory') as mkdir, \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(m.main(), 0)
        mux.assert_not_called()
        mkdir.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['acquisitionApproved'])

    def test_transport_plan_is_distinct_and_pins_client_and_actual_lifecycle_prerequisite(self):
        probe=m.load_probe()
        value,sources=m.make_plan('b'*32,probe.BoundedRunner(time.monotonic()+30),'transport')
        self.assertEqual(value['kind'],'private-relay-real-transport')
        self.assertEqual(set(value['commands']),m.TRANSPORT_OPERATIONS)
        self.assertIn('tests/postgres/ownedMcpPrivateTransportClient.py',sources)
        self.assertIn(value['prerequisite']['path'],sources)
        self.assertNotIn('LIFECYCLE_ONLY_NO_ACQUISITION',value['commands']['start'])
        self.assertFalse(value['acquisitionApproved'])

    def test_transport_orders_real_negatives_zero_audit_before_positive_clients(self):
        value=plan();value.update(kind='private-relay-real-transport',variant='connect-audit-v1',
            commands={name:name for name in m.TRANSPORT_OPERATIONS})
        with self.temp() as tmp, patch.object(m,'verify_sources'):
            events=[]
            result=m.run_lifecycle(value,{},Path(tmp),None,Mux(events),TransportRunner(events),
                TransportRunner(events,terminal=True),pause=lambda _:None)
            self.assertTrue(result['passed'])
            self.assertTrue(result['realTransportVerified'])
            self.assertLess(events.index('client-deny-host'),events.index('client-registry'))
            self.assertEqual(events.count('checkpoint'),3)
            self.assertTrue((Path(tmp)/'checkpoint-denials.json').exists())
            self.assertFalse(result['acquisitionApproved'])

    def test_transport_negatives_fail_on_actual_dns_connect_or_peer_acceptance_counters(self):
        value=plan();value['kind']='private-relay-real-transport'
        for mode,key in [('connector','dnsSubprocesses'),('connector','externalConnectAttempts'),
                         ('connector','peerDenied'),('adapter','unixConnectAttempts')]:
            row=audit(mode,'denials',2)
            row['counts'][key]=0 if key=='peerDenied' else 1
            with self.assertRaisesRegex(RuntimeError,'AUDIT'):
                m.verify_audit(row,value,mode,'denials',2)
        for field,changed in [('runId','c'*32),('sequence',1),('activeWorkers',1),('variant','lifecycle-only')]:
            row=audit('connector','denials',2);row[field]=changed
            with self.assertRaisesRegex(RuntimeError,'AUDIT'):
                m.verify_audit(row,value,'connector','denials',2)

    def test_transport_positive_fails_wrong_status_tls_hash_or_raw_body_fields(self):
        for field,changed in [('status',302),('tlsVerified',False),('bodySha256','bad'),
                              ('bodyBytes',65537),('token','must never retain')]:
            value=client_result('auth');value['result'][field]=changed
            with self.assertRaisesRegex(RuntimeError,'POSITIVE'):
                m.verify_client(value,'auth')

    def test_client_packet_is_closed_and_numeric_proofs_reject_bool_and_float(self):
        for case in ('deny-peer','deny-host','registry','auth','debian'):
            m.verify_client(client_result(case),case)
            for field in ('token','authorization','rawBody'):
                value=client_result(case);value[field]='must not retain'
                with self.subTest(case=case,field=field), self.assertRaisesRegex(RuntimeError,'CLIENT'):
                    m.verify_client(value,case)
            for version in (True,1.0):
                value=client_result(case);value['version']=version
                with self.assertRaisesRegex(RuntimeError,'CLIENT'): m.verify_client(value,case)
        for case,field,invalid in [('deny-peer','denied',1),('deny-peer','effectiveUid',False),
                ('deny-host','effectiveUid',501.0),('deny-peer','responseBytes',False),
                ('deny-host','responseBytes',0.0),('auth','status',200.0),
                ('auth','effectiveUid',501.0),('auth','bodyBytes',True),('auth','bodyBytes',10.0)]:
            value=client_result(case);value['result'][field]=invalid
            with self.subTest(case=case,field=field), self.assertRaises(RuntimeError): m.verify_client(value,case)

    def test_audit_and_checkpoint_proof_types_are_strict(self):
        for field in ('sequence','activeWorkers'):
            for invalid in ((True,1.0) if field=='sequence' else (False,0.0)):
                row=audit('connector','baseline',1);row[field]=invalid
                with self.assertRaisesRegex(RuntimeError,'AUDIT'): m.verify_audit(row,plan(),'connector','baseline',1)
        for field in audit('connector','denials',2)['counts']:
            for convert in (bool,float):
                row=audit('connector','denials',2);row['counts'][field]=convert(row['counts'][field])
                with self.subTest(field=field,convert=convert), self.assertRaisesRegex(RuntimeError,'AUDIT'):
                    m.verify_audit(row,plan(),'connector','denials',2)
        for version in (True,1.0):
            packet={'version':version,'runId':'b'*32,'variant':'connect-audit-v1',
                'rows':{mode:audit(mode,'baseline',1) for mode in ('connector','adapter')}}
            with self.assertRaisesRegex(RuntimeError,'BINDING'): m.verify_checkpoint(packet,plan(),'baseline',1)

    def test_success_exit_with_extra_client_secret_is_sanitized_and_stops_cohort(self):
        value=plan();value.update(kind='private-relay-real-transport',variant='connect-audit-v1',
            commands={name:name for name in m.TRANSPORT_OPERATIONS})
        class Extra(TransportRunner):
            def __call__(self,argv,**kw):
                response=super().__call__(argv,**kw)
                if kw['input']=='client-registry':
                    packet=json.loads(response.stdout);packet['token']='sensitive-sentinel'
                    response.stdout=json.dumps(packet)
                return response
        with self.temp() as tmp, patch.object(m,'verify_sources'):
            events=[]
            result=m.run_lifecycle(value,{},Path(tmp),None,Mux(events),Extra(events),
                TransportRunner(events,terminal=True),pause=lambda _:None)
            self.assertFalse(result['passed'])
            record=(Path(tmp)/'client-registry.json').read_text()
            self.assertNotIn('sensitive-sentinel',record)
            self.assertEqual(json.loads(record),{'version':1,'ok':False,'case':'registry','error':'CLIENT_RECEIPT_INVALID'})
            self.assertNotIn('client-auth',events)

    def test_transport_client_failure_retains_only_safe_error_and_exit_not_token_fields(self):
        value=plan();value.update(kind='private-relay-real-transport',variant='connect-audit-v1',
            commands={name:name for name in m.TRANSPORT_OPERATIONS})
        class Failed(TransportRunner):
            def __call__(self,argv,**kw):
                if kw['input']=='client-registry':
                    self.events.append(kw['input'])
                    assert kw['check'] is False
                    return subprocess.CompletedProcess(argv,1,json.dumps({'version':1,'ok':False,
                        'error':'TRANSPORT_FAILED','token':'must not be retained'}),'')
                return super().__call__(argv,**kw)
        with self.temp() as tmp, patch.object(m,'verify_sources'):
            events=[]
            result=m.run_lifecycle(value,{},Path(tmp),None,Mux(events),Failed(events),
                TransportRunner(events,terminal=True),pause=lambda _:None)
            self.assertFalse(result['passed'])
            record=(Path(tmp)/'client-registry.json').read_text()
            self.assertNotIn('token',record)
            self.assertEqual(json.loads(record)['error'],'TRANSPORT_FAILED')
            self.assertIn({'operation':'client-registry','code':'COMMAND_EXIT_1'},result['commandFailures'])
            self.assertNotIn('client-auth',events)

    def test_guest_client_hashes_body_with_strict_framing_and_cap(self):
        count,digest=client.body_digest(io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n'),{'transfer-encoding':'chunked'})
        self.assertEqual(count,5)
        self.assertEqual(digest, __import__('hashlib').sha256(b'hello').hexdigest())
        for data,fields in [(b'x'*65537,{}),(b'a',{'content-length':'2'}),
                (b'',{'content-length':'0','transfer-encoding':'chunked'})]:
            with self.assertRaises(RuntimeError): client.body_digest(io.BytesIO(data),fields)

    def test_guest_tls_client_only_connects_loopback_and_retains_no_anonymous_token(self):
        token=b'{"token":"anonymous-test-value"}'
        raw,secure,context=MagicMock(),MagicMock(),MagicMock()
        raw.recv.side_effect=[bytes([byte]) for byte in b'HTTP/1.1 200 Connection Established\r\n\r\n']
        secure.getpeercert.return_value=b'controlled cert';secure.version.return_value='TLSv1.3'
        secure.makefile.return_value=io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(token)).encode()+b'\r\n\r\n'+token)
        context.wrap_socket.return_value=secure
        with patch.object(client.os,'readlink',return_value='net:[2]'),patch.object(client.os,'geteuid',return_value=501), \
                patch.object(client.os,'getegid',return_value=1000),patch.object(client.os,'getgroups',return_value=[]), \
                patch.object(client.socket,'socket',return_value=raw) as allocation, \
                patch.object(client.ssl,'create_default_context',return_value=context) as tls:
            value=client.execute('auth',12345,'/var/tmp/owasp-ai-goat-v23-relay-'+'b'*32,'net:[2]',time.monotonic()+30)
        allocation.assert_called_once_with(client.socket.AF_INET,client.socket.SOCK_STREAM)
        raw.connect.assert_called_once_with(('127.0.0.1',12345))
        context.wrap_socket.assert_called_once_with(raw,server_hostname='auth.docker.io')
        tls.assert_called_once_with()
        self.assertEqual(value['bodyBytes'],len(token))
        self.assertNotIn('anonymous-test-value',json.dumps(value))
        raw.close.assert_called_once();secure.close.assert_called_once()

    def test_guest_wrong_uid_negative_opens_unchanged_unix_socket_and_requires_eof(self):
        raw=MagicMock();raw.recv.return_value=b''
        with patch.object(client.os,'readlink',return_value='net:[2]'),patch.object(client.os,'geteuid',return_value=0), \
                patch.object(client.socket,'socket',return_value=raw),patch.object(client.os,'chmod') as chmod:
            value=client.execute('deny-peer',12345,'/var/tmp/owasp-ai-goat-v23-relay-'+'b'*32,'net:[2]',time.monotonic()+30)
        raw.connect.assert_called_once_with('/var/tmp/owasp-ai-goat-v23-relay-'+'b'*32+'/connector.sock')
        raw.sendall.assert_not_called();chmod.assert_not_called()
        self.assertTrue(value['denied'])


if __name__ == '__main__':
    unittest.main()
