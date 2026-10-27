"""Offline facade controls with injected socket/process observations; no effects."""
import json
import hashlib
import fcntl
import stat
import sys
import os
import types
import unittest
from unittest.mock import patch
from v03_private_executors import V03PrivateExecutors, ENV_KEYS, _verify_source

class SourceCloseControls(unittest.TestCase):
    def test_only_fixed_node_path_accepts_two_stable_links(self):
        import v03_private_executors as module
        node=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(module.__file__))))+'/tasks/runtime/node/node_modules/node/bin/node'
        row=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=2,st_size=0,st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        with patch.object(os,'open',return_value=1001),patch.object(os,'fstat',return_value=row),patch.object(os,'read',return_value=b''),patch.object(os,'close'):
            _verify_source(node,hashlib.sha256(b'').hexdigest())
            with self.assertRaisesRegex(ValueError,'SOURCE_FILE'):_verify_source('/synthetic',hashlib.sha256(b'').hexdigest())
            row.st_nlink=3
            with self.assertRaisesRegex(ValueError,'SOURCE_FILE'):_verify_source(node,hashlib.sha256(b'').hexdigest())
            row.st_nlink=2;row.st_size=256*1024**2+1
            with self.assertRaisesRegex(ValueError,'SOURCE_FILE'):_verify_source(node,hashlib.sha256(b'').hexdigest())

    def test_source_primary_survives_close_failure_with_explicit_debt(self):
        primary=ValueError('read failure')
        with patch.object(os,'open',return_value=1001),patch.object(os,'fstat',side_effect=primary),patch.object(os,'close',side_effect=OSError('close')):
            with self.assertRaises(ValueError) as raised:_verify_source('/synthetic','a'*64)
        self.assertIs(raised.exception,primary)
        self.assertTrue(primary.cleanupDebt)
        self.assertTrue(primary.sourceCloseUnproven)

    def test_successful_source_read_cannot_hide_close_failure(self):
        row=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=0,st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        with patch.object(os,'open',return_value=1001),patch.object(os,'fstat',return_value=row),patch.object(os,'read',return_value=b''),patch.object(os,'close',side_effect=OSError('close')):
            with self.assertRaises(OSError) as raised:_verify_source('/synthetic',hashlib.sha256(b'').hexdigest())
        self.assertTrue(raised.exception.cleanupDebt)
        self.assertTrue(raised.exception.sourceCloseUnproven)

class Wire:
    def __init__(self): self.raw=b'';self.sent=[];self.closed=False
    def settimeout(self,value):
        if value<=0:raise ValueError('timeout')
    def sendall(self,raw):self.sent.append(json.loads(raw))
    def recv(self,n):part,self.raw=self.raw[:n],self.raw[n:];return part
    def close(self):self.closed=True

def facade():
    f=V03PrivateExecutors.__new__(V03PrivateExecutors)
    f.channel=Wire();f.run_id='a'*32;f.plan_sha256='b'*64;f.sequence=0
    f.now=lambda:100.;f.deadline=11196.;f.cohort_deadline=None;f.activation_deadline=None;f.state='new';f.debt=False
    f.browser=f.browser_identity=f.receipt=None
    f.work_deadline=1900.;f.pg_intent=f.pg_binding=None
    f._parent=lambda:None
    return f

def response(f,op,result):
    if op=='claim-cohort':result.setdefault('clockUncertaintyMs',0)
    if op=='start' and result.get('ready') is True:result.setdefault('workRemainingMsAtAdmission',1800000)
    f.channel.raw=(json.dumps(dict(version=1,runId=f.run_id,planSha256=f.plan_sha256,
        sequence=f.sequence,op=op,result=result))+'\n').encode()

def environment():
    value={k:'c'*64 for k in ENV_KEYS}
    for k in value:
        if k.endswith('ORIGIN') or k.endswith('SYSTEM_URL'):value[k]='http://127.0.0.1:23456'
        if k.endswith('TOKEN'):value[k]='T'*48
    value['SECURESHOP_LISTINGS_TEST_MANAGER_IMAGE_ID']='sha256:'+'d'*64
    value['SECURESHOP_LISTINGS_TEST_DOCKER_HOST']='unix:///var/tmp/dvaia-v23-build-'+hashlib.sha256(('a'*32+':v03-listings').encode()).hexdigest()[:32]+'/fs/docker.sock'
    value['SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID']='f'*32
    return value

class Controls(unittest.TestCase):
    def test_source_bound_fd_admission_has_fixed_parent_entry_and_no_wire_selected_pins(self):
        # Files/FD observations are injected; no process, socket or VM is opened.
        root='/synthetic/repository';names=['tests/postgres/ownedV03PrivateExecutors.js',
            'tests/postgres/v03_private_executors.py','tests/postgres/run-secureshop-agent-host-transport-main.py',
            'tests/postgres/darwin_process_inventory.py','tasks/runtime/node/node_modules/node/bin/node']
        pins={n:hashlib.sha256(b'source').hexdigest() for n in names}
        packet=dict(version=1,target='original-v03-private-main-admission-v1',root=root,runId='a'*32,
            planSha256='b'*64,sourcePins=pins,parentIdentity={'pid':123},mainArgv=sys.argv)
        def metadata(size):return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=os.getuid(),st_nlink=1,
            st_size=size,st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        for bad in (False,True):
            value=dict(packet,sourcePins={} if bad else pins);raw=json.dumps(value).encode();reads=[]
            with patch.object(os.path,'realpath',side_effect=lambda p:p),patch.object(os,'fstat',side_effect=lambda fd:metadata(len(raw) if fd==4 else 6)), \
                 patch.object(fcntl,'fcntl',return_value=os.O_RDONLY),patch.object(os,'pread',return_value=raw), \
                 patch.object(os,'open',return_value=1001),patch.object(os,'close'), \
                 patch.object(os,'read',side_effect=lambda fd,n:reads.pop(0)), \
                 patch.object(V03PrivateExecutors,'from_inherited_fd',return_value='admitted') as admitted:
                reads.extend([b'source',b'']*len(names))
                if bad:
                    with self.assertRaises(ValueError):V03PrivateExecutors.from_admission_fds(root=root,run_id='a'*32,plan_sha256='b'*64,source_pins=pins)
                    admitted.assert_not_called()
                else:
                    self.assertEqual(V03PrivateExecutors.from_admission_fds(root=root,run_id='a'*32,plan_sha256='b'*64,source_pins=pins),'admitted')
                    self.assertEqual(admitted.call_args.kwargs['parent_argv'],[root+'/'+names[-1],root+'/'+names[0],'--v03-main-parent','a'*32,'b'*64])
    def test_clock_uncertainty_consumes_activation_not_original_child(self):
        f=facade();f.state='ready'
        response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,
            infrastructureMsAtClaim=1210000,clockUncertaintyMs=2000,environment=environment()))
        self.assertEqual(f.claim_cohort(),1308.)
        f.now=lambda:107.999
        self.assertEqual(f.assert_spawn_ready(),1200)
        f.now=lambda:108.
        with self.assertRaises(RuntimeError):f.assert_spawn_ready()
    def test_foreign_private_daemon_and_invalid_ports_are_not_endpoints(self):
        for key,value in [('SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN','http://127.0.0.1:99999'),
                          ('SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_URL','http://127.0.0.1:1000'),
                          ('SECURESHOP_LISTINGS_TEST_DOCKER_HOST','unix:///var/tmp/dvaia-v23-build-'+'e'*32+'/fs/docker.sock')]:
            f=facade();env=environment();env[key]=value
            with self.assertRaises(ValueError):f._validate_environment(env)
            self.assertTrue(f.debt)
    def test_expired_or_invalid_window_never_sends(self):
        for limit in (0, -1, float('nan'), float('inf'), True, None, '1'):
            f=facade()
            with self.assertRaises(TimeoutError):f._exchange('start',{},limit)
            self.assertEqual(f.channel.sent,[])
        f=facade();f.deadline=100.
        with self.assertRaises(TimeoutError):f._exchange('start',{},1)
        self.assertEqual(f.channel.sent,[])
        f=facade()
        def inspect_parent():f.now=lambda:102.
        f._parent=inspect_parent
        with self.assertRaises(TimeoutError):f._exchange('start',{},1)
        self.assertEqual(f.channel.sent,[])
    def test_start_claim_once_and_no_token_receipt(self):
        f=facade();response(f,'start',dict(ready=True,parentRemainingMsAtAdmission=9000000))
        self.assertIsNone(f.start())
        self.assertEqual(f.deadline,9100.)
        response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,infrastructureMsAtClaim=1210000,environment=environment()))
        self.assertEqual(f.claim_cohort(),1310.)
        self.assertEqual(f.assert_spawn_ready(),1200)
        self.assertEqual(f.fixture_environment(),environment())
        with self.assertRaises(RuntimeError):f.claim_cohort()
    def test_missing_parent_rejected_before_fd(self):
        with self.assertRaises(ValueError):V03PrivateExecutors.from_inherited_fd(5,run_id='a'*32,
            plan_sha256='b'*64,parent_identity={'pid':-1},parent_argv=[])
    def test_short_or_stale_cohort_claim_is_not_full_reserve(self):
        for remaining in (1,1189999,1200001,True):
            f=facade();f.state='ready'
            response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,infrastructureMsAtClaim=remaining,environment=environment()))
            with self.assertRaises(ValueError):f.claim_cohort()
            self.assertTrue(f.debt)
    def test_activation_deadline_does_not_clip_original_child_timeout(self):
        f=facade();f.state='ready'
        response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,infrastructureMsAtClaim=1210000,environment=environment()))
        f.claim_cohort();f.now=lambda:109.999
        self.assertEqual(f.assert_spawn_ready(),1200)
        f.now=lambda:110.
        with self.assertRaises(RuntimeError):f.assert_spawn_ready()
        self.assertIsNone(f.browser)
    def test_slow_spawn_retains_proved_child_for_cleanup_without_dispatch(self):
        f=facade();f.state='claimed';f.activation_deadline=110.;f.cohort_deadline=1310.;f.now=lambda:111.
        row=types.SimpleNamespace(pid=555,ppid=os.getpid(),pgid=555,uid=os.getuid(),start_sec=1,start_usec=2)
        birth=dict(pid=555,ppid=os.getpid(),pgid=555,uid=os.getuid(),birth=[1,2])
        f.api=types.SimpleNamespace(identity=lambda pid:row,group_pids=lambda pid:[])
        child=types.SimpleNamespace(pid=555,poll=lambda:None,wait=lambda timeout:0)
        with self.assertRaises(RuntimeError):f.attach_browser(child,birth)
        self.assertEqual(f.channel.sent,[]);self.assertEqual(f.browser_identity,birth)
        with patch('os.killpg') as kill:
            receipt=f.close();kill.assert_called_once()
        self.assertTrue(receipt['browserAbsent']);self.assertFalse(receipt['cleanupVerified'])
    def test_start_and_transit_charge_admission_work_only_once(self):
        f=facade()
        # Parent preparation precedes MAIN. Admission sample is3ms after send;
        # the bounded current-parent proofs consume30s exactly once.
        response(f,'start',dict(ready=True,parentRemainingMsAtAdmission=11095997))
        read=f.channel.recv
        def delayed_read(n):f.now=lambda:130.;return read(n)
        f.channel.recv=delayed_read;f.start()
        self.assertAlmostEqual(f.deadline,11195.997)
        self.assertGreaterEqual(f.deadline-f.now(),6636)
        self.assertEqual(f.work_deadline,1900.)
        with self.assertRaises(RuntimeError):f.start()
    def test_slow_claim_charged_once_with_full_original_wait(self):
        f=facade();f.state='ready'
        response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,infrastructureMsAtClaim=1210000,environment=environment()))
        read=f.channel.recv
        def delayed_read(n):f.now=lambda:106.;return read(n)
        f.channel.recv=delayed_read;f.claim_cohort()
        self.assertEqual(f.cohort_deadline,1310.)
        self.assertEqual(f.cohort_deadline-f.now(),1204.)
        self.assertEqual(f.assert_spawn_ready(),1200)
    def test_wrong_sequence_poisoned(self):
        f=facade();response(f,'start',{})
        f.channel.raw=f.channel.raw.replace(b'"sequence": 0',b'"sequence": 1')
        with self.assertRaises(ValueError):f.start()
        self.assertTrue(f.debt)
        self.assertFalse(f.close()['cleanupVerified']);self.assertFalse(f.may_retire_pg())
    def test_wrong_loopback_denied(self):
        f=facade();f.state='ready';env=environment();env['SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN']='http://example.com'
        response(f,'claim-cohort',dict(originalChildMs=1200000,activationMsAtClaim=10000,infrastructureMsAtClaim=1210000,environment=env))
        with self.assertRaises(ValueError):f.claim_cohort()
        self.assertTrue(f.debt)
    def test_eof_never_becomes_cleanup(self):
        f=facade()
        with self.assertRaises(EOFError):f.start()
        self.assertFalse(f.close()['cleanupVerified']);self.assertFalse(f.may_retire_pg())
    def test_unknown_browser_birth_retained_and_not_signalled(self):
        f=facade();f.state='claimed';f.cohort_deadline=1310.;f.activation_deadline=110.;f.api=types.SimpleNamespace(identity=lambda p:None)
        child=types.SimpleNamespace(pid=555,poll=lambda:None)
        with self.assertRaises(ValueError):f.attach_browser(child,None)
        self.assertIs(f.browser,child)
        with patch('os.killpg',side_effect=AssertionError('must not signal')):
            self.assertFalse(f.close()['cleanupVerified'])
    def test_work_handoff_is_pending_and_never_authorizes_main_pg_cleanup(self):
        f=facade();response(f,'finish-work',dict(accepted=True,cleanupPending=True,qualificationComplete=False))
        result=f.close(primary=RuntimeError('primary'))
        self.assertFalse(result['cleanupVerified']);self.assertTrue(result['primaryFailed']);self.assertTrue(result['handoffAccepted'])
        self.assertFalse(f.may_retire_pg());self.assertIs(f.close(),result)
        self.assertEqual(f.channel.sent[0]['op'],'finish-work')
        self.assertNotIn('TOKEN',json.dumps(result))
    def test_remote_error_and_frame_cap_fail_closed(self):
        f=facade();response(f,'finish-work',dict(closed=True,cleanupVerified=False,diagnosticAbsent=False,listingsAbsent=True,errors=['debt']))
        self.assertFalse(f.close()['cleanupVerified'])
        f=facade();f.channel.raw=b'x'*16385
        with self.assertRaises(ValueError):f.start()
        self.assertTrue(f.debt)

if __name__=='__main__':unittest.main()
