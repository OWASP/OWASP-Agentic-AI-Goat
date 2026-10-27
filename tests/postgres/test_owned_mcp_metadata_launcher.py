import copy
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import time
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run_owned_mcp_metadata_isolated.py')
spec=importlib.util.spec_from_file_location('metadata_launcher',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
l=m.load_lifecycle()
INVENTORY=('"945f6fce-3aaf-4d8f-a483-170464fb2416"\n'
 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 postgres:18\n'
 'CONTAINERS\n\nVOLUMES\n\nNETWORK\n'+json.dumps({'version':1,'bridge':{'id':'owned'},'links':[{'ifname':'docker0'}]}))


def plan():
    return {'kind':'private-v23-registry-metadata','variant':'metadata-idle-barrier-v4','runId':'b'*32,'guest':'/var/tmp/dvaia-v23-build-'+'b'*32,
        'binding':{'runId':'b'*32,'target':'v23-registry','base':m.BASE},'guestSourceSha256':'a'*64,
        'relaySourceSha256':'c'*64,'admission':{'uid':501},'mux':{'masterPid':123,'masterBirth':[1,2],
            'config':'controlled','configSha256':'d'*64,'limaConfigSha256':'e'*64,
            'socket':'controlled-socket','socketDevice':1,'socketInode':2},
        'commands':{key:key for key in m.OPERATIONS}}


def terminal():
    value=plan();files={}
    for mode in ('connector','adapter'):
        rows=[{'kind':'relay-ready','mode':mode},
            {'kind':'relay-terminal','connections':4,'bytes':40,
             'hostBytes':{host:10 for host in m.HOST_LIMITS},
             'records':[{'host':host,'status':'closed'} for host in m.HOST_LIMITS],
             'cleanupVerified':True,'unjoinedWorkers':0,'unresolvedResolverCleanup':0},
            {'kind':'transport-audit','runId':value['runId'],'variant':'metadata-idle-barrier-v4','mode':mode,
             'trigger':'terminal','sequence':3,'activeWorkers':0,
             'deniedAuthorities':{'hosts':{},'unclassified':0,'overflow':0},
             'admission':{'workerLimitRejected':0,'connectionLimitRejected':0,'saturated':False},
             'counts':{'dnsSubprocesses':4 if mode=='connector' else 0,'externalConnectAttempts':4 if mode=='connector' else 0,
                       'unixConnectAttempts':4 if mode=='adapter' else 0,'peerChecks':4,'peerDenied':0}}]
        checkpoint=copy.deepcopy(rows[-1]);checkpoint.update(trigger='checkpoint',sequence=1)
        rows.insert(1,checkpoint)
        checkpoint=copy.deepcopy(rows[-1]);checkpoint.update(trigger='checkpoint',sequence=2)
        rows.insert(2,checkpoint)
        files['relay.'+mode+'.log']='\n'.join(map(json.dumps,rows))+'\n'
        files['relay.'+mode+'.process']=json.dumps({'pid':100 if mode=='connector' else 101,'start':9,'net':'net:[2]','deadline':'1300.000000'})
    files['relay.ready']=json.dumps({'deadline':'1300.000000'})
    files['relay.idle.intent']=json.dumps({'version':1,'runId':value['runId'],'deadline':'1300.000000','started':1000.0,'end':1016.0,
        'processes':{mode:{key:json.loads(files['relay.'+mode+'.process'])[key] for key in ('pid','start','net')} for mode in ('connector','adapter')}})
    files['relay.idle.result']=json.dumps({'version':1,'runId':value['runId'],'quiescent':True,'attempts':31,
        'observations':{'connector':0,'adapter':0},'checkpointSequences':{'connector':2,'adapter':2},'completedAt':1015.5})
    return {'version':1,'runId':value['runId'],'sourceSha256':value['relaySourceSha256'],'lifecycleOnly':False,
            'admission':value['admission'],'files':files,
            'storage':{'capBytes':6442450944,'logicalBytes':6442450944,'allocatedBytes':1024**2,'usedBytes':512*1024}}


class Mux:
    def admit_existing_mux(self,root,expected,run):
        exact=dict(plan()['mux']);exact['masterBirth']=tuple(exact['masterBirth'])
        assert expected==exact
        return expected
    def mux_command(self,authority,*args):return ['EXISTING_MUX',*args]


class Runner:
    def __init__(self,events,fail=None,uncertain=False,changed=False):
        self.children=[];self.events=events;self.fail=fail;self.uncertain=uncertain;self.changed=changed;self.calls=[]
    def __call__(self,argv,**kw):
        op=kw['input'];self.events.append(op);self.calls.append((argv,kw))
        self.children.append({'pid':100+len(self.children),'reaped':True,'groupAbsent':not self.uncertain})
        if op==self.fail:raise RuntimeError('COMMAND_DEADLINE')
        if op=='inventory':value=INVENTORY+(' ' if self.changed else '')
        elif op=='acquire':value=json.dumps({'version':3,'ok':True})
        elif op=='inspect':value=json.dumps({'ID':'private','Driver':'overlay2','Architecture':'aarch64','DockerRootDir':plan()['guest']+'/fs/data'})
        elif op=='evidence':value=json.dumps(terminal())
        elif op=='cleanup':value='absent\n'
        else:value=''
        return subprocess.CompletedProcess(argv,0,value,'')


class MetadataTests(unittest.TestCase):
    def test_retained_archive_requires_exact_ustar_record_padding(self):
        boundary=None
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root=Path(tmp)
            for size in range(1,10241,512):
                payload=b'x'*size;digest=hashlib.sha256(payload).hexdigest()
                manifest={'objects':[{'file':'objects/'+digest,'sha256':digest,'bytes':size}]}
                envelope={'candidate':{'retainedMetadata':manifest}}
                stream=io.BytesIO()
                with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
                    for name,body in [('manifest.json',json.dumps(manifest).encode()),
                                      ('result.json',json.dumps(envelope).encode()),('objects/'+digest,payload)]:
                        member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o444
                        archive.addfile(member,io.BytesIO(body))
                    offset=archive.offset
                raw=stream.getvalue();self.assertEqual(len(raw)-offset,1024+(-(offset+1024))%10240)
                path=root/f'valid-{size}.tar';path.write_bytes(raw);path.chmod(0o600)
                result=m.verify_retained_archive(path,envelope)
                self.assertEqual(result['sha256'],hashlib.sha256(raw).hexdigest())
                if len(raw)-offset==10752:boundary=(raw,offset,envelope)
            self.assertIsNotNone(boundary)
            raw,offset,envelope=boundary
            for index,broken in enumerate((raw[:-1],raw+b'\0'*10240,
                                             raw[:offset]+b'X'+raw[offset+1:],raw[:offset]+b'\0'*1024)):
                path=root/f'bad-padding-{index}.tar';path.write_bytes(broken);path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError,'METADATA_ARCHIVE_TRAILER'):
                    m.verify_retained_archive(path,envelope)

    def test_retained_archive_streamed_hashes_and_closed_members(self):
        raw=b'original upstream compressed bytes\x00\xff';digest=hashlib.sha256(raw).hexdigest()
        manifest={'objects':[{'file':'objects/'+digest,'sha256':digest,'bytes':len(raw)}]}
        envelope={'version':3,'candidate':{'retainedMetadata':manifest},'ok':True}
        for scenario in ('success','tamper','missing','extra','duplicate','path','symlink','pax','mode','join','bool-join','trailer'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
                path=Path(tmp)/'archive';rows=[('manifest.json',json.dumps(manifest).encode()),('result.json',json.dumps(envelope).encode()),('objects/'+digest,raw)]
                if scenario=='tamper':rows[-1]=(rows[-1][0],raw+b'x')
                if scenario=='missing':rows.pop()
                if scenario=='extra':rows.append(('unknown',b'x'))
                if scenario=='duplicate':rows.append(rows[-1])
                if scenario=='path':rows[-1]=('../'+rows[-1][0],raw)
                if scenario in ('join','bool-join'):
                    altered=copy.deepcopy(envelope);altered['ok']=False if scenario=='join' else 1
                    rows[1]=('result.json',json.dumps(altered).encode())
                with tarfile.open(path,'w',format=tarfile.PAX_FORMAT if scenario=='pax' else tarfile.USTAR_FORMAT) as archive:
                    for name,body in rows:
                        member=tarfile.TarInfo(name);member.size=len(body);member.mode=0o444
                        if name.startswith('objects/'):
                            if scenario=='symlink':member.type=tarfile.SYMTYPE;member.linkname='/etc/shadow';member.size=0
                            if scenario=='mode':member.mode=0o644
                            if scenario=='pax':member.pax_headers={'comment':'unadmitted'}
                        archive.addfile(member,io.BytesIO(body) if member.isfile() else None)
                path.chmod(0o600)
                if scenario=='trailer':
                    with path.open('ab') as stream:stream.write(b'not admitted')
                if scenario=='success':
                    result=m.verify_retained_archive(path,envelope)
                    self.assertEqual(result['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertTrue(result['candidateOnly']);self.assertFalse(result['authenticatedReplayComplete'])
                else:
                    with self.assertRaises((RuntimeError,tarfile.TarError)):m.verify_retained_archive(path,envelope)

    def test_export_failure_retains_partial_without_false_complete_and_still_cleans(self):
        result,events,files,_,_,pauses=self.flow(cleanup_args={'fail':'retainedExport'})
        self.assertFalse(result['passed']);self.assertTrue(result['guestAbsent'])
        self.assertIn('METADATA_EXPORT_UNVERIFIED',result['cleanupErrors'])
        self.assertIn('metadata-retained.tar.partial',files);self.assertNotIn('metadata-retained.tar',files)
        self.assertEqual(events.count('retainedExport'),1);self.assertEqual(pauses,[72])

    def test_interrupted_export_grace_retains_guest_and_partial_without_later_guest_operations(self):
        for interrupt in (KeyboardInterrupt(),SystemExit(2),None):
            with self.subTest(interrupt=type(interrupt).__name__):
                events=[];work=Runner(events);cleanup=Runner(events,fail='retainedExport')
                def pause(seconds):
                    if interrupt is not None:raise interrupt
                    # No clock advance means remote quiescence is still unknown.
                with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp,patch.object(l,'verify_sources'),\
                        patch.object(m.time,'monotonic',return_value=1000):
                    def invoke():return m.run_metadata(plan(),{},Path(tmp),l,None,Mux(),work,cleanup,
                        lambda raw:{'version':3,'ok':True,'candidate':{'candidateOnly':True}},pause=pause)
                    if interrupt is not None:
                        with self.assertRaises(type(interrupt)):invoke()
                    else:invoke()
                    result=json.loads((Path(tmp)/'result.json').read_text())
                    self.assertTrue((Path(tmp)/'metadata-retained.tar.partial').exists())
                    self.assertFalse((Path(tmp)/'metadata-retained.tar').exists())
                self.assertEqual(events[-1],'retainedExport');self.assertNotIn('cleanup',events)
                self.assertEqual(events.count('inventory'),1);self.assertFalse(result['passed'])
                self.assertFalse(result['remoteQuiescenceVerified']);self.assertIsNone(result['candidate'])
                self.assertEqual(result['pendingRemote'],{'operation':'retainedExport','notBeforeHostMonotonic':1072})
                self.assertIn('METADATA_GUEST_RETAINED',result['cleanupErrors'])

    def test_idle_proof_rejects_restarted_deadline_missing_identity_unknown_or_late_observations(self):
        for scenario in ('deadline-reset','end-reset','late','bool','active','interrupted','pid-reused','missing','wrong-sequence'):
            with self.subTest(scenario=scenario):
                snapshot=terminal();files=snapshot['files'];intent=json.loads(files['relay.idle.intent']);result=json.loads(files['relay.idle.result'])
                if scenario=='deadline-reset':intent['deadline']='1600.000000'
                elif scenario=='end-reset':intent['end']=1316.0
                elif scenario=='late':result['completedAt']=intent['end']
                elif scenario=='bool':result['observations']['adapter']=False
                elif scenario=='active':result['observations']['adapter']=1
                elif scenario=='interrupted':result['quiescent']=False
                elif scenario=='pid-reused':intent['processes']['adapter']['start']+=1
                elif scenario=='wrong-sequence':result['checkpointSequences']['adapter']=1
                files['relay.idle.intent']=json.dumps(intent);files['relay.idle.result']=json.dumps(result)
                if scenario=='missing':del files['relay.idle.result']
                with self.assertRaises((RuntimeError,KeyError)):m.verify_terminal(snapshot,plan())

    def test_admission_checkpoint_retains_saturation_without_inventing_causality_or_terminal_idle(self):
        snapshot=terminal();rows=[json.loads(line) for line in snapshot['files']['relay.adapter.log'].splitlines()]
        rows[1]['activeWorkers']=4
        rows[-1]['admission']['workerLimitRejected']=1
        snapshot['files']['relay.adapter.log']='\n'.join(map(json.dumps,rows))+'\n'
        m.verify_terminal(snapshot,plan())
        diagnostic=m.relay_diagnostics(snapshot,plan())['adapter']
        self.assertEqual(diagnostic['checkpoint']['activeWorkers'],4)
        self.assertEqual(diagnostic['terminal']['activeWorkers'],0)
        self.assertEqual(diagnostic['terminal']['admission']['workerLimitRejected'],1)
        for change in ('bool','float','overflow','false-saturation','regression','missing-checkpoint','wrong-order'):
            with self.subTest(change=change):
                bad=copy.deepcopy(rows)
                if change=='bool':bad[-1]['admission']['workerLimitRejected']=True
                elif change=='float':bad[-1]['admission']['connectionLimitRejected']=0.0
                elif change=='overflow':bad[-1]['admission']['workerLimitRejected']=65536
                elif change=='false-saturation':bad[-1]['admission']['saturated']=True
                elif change=='regression':bad[1]['admission']['workerLimitRejected']=2
                elif change=='missing-checkpoint':del bad[1]
                else:bad[1],bad[-1]=bad[-1],bad[1]
                altered=copy.deepcopy(snapshot);altered['files']['relay.adapter.log']='\n'.join(map(json.dumps,bad))+'\n'
                with self.assertRaisesRegex(RuntimeError,'METADATA_'):m.verify_terminal(altered,plan())
        # Before pull completion, a failed run can truthfully have no checkpoint.
        before=copy.deepcopy(snapshot);del rows[1:3];rows[-1]['sequence']=1
        before['files']['relay.adapter.log']='\n'.join(map(json.dumps,rows))+'\n'
        self.assertIsNone(m.relay_diagnostics(before,plan())['adapter']['checkpoint'])

    def test_blob_host_receipt_requires_exact_new_host_and_preserves_old_aggregate_caps(self):
        blob='production.cloudfront.docker.com'
        self.assertEqual(m.HOST_LIMITS,{'registry-1.docker.io':128*1024**2,'auth.docker.io':1024**2,
                                     'deb.debian.org':132*1024**2,blob:128*1024**2})
        m.verify_terminal(terminal(),plan())
        for scenario in ('missing-host','alternate-host','host-cap','total-cap','connections','old-variant'):
            with self.subTest(scenario=scenario):
                snapshot=terminal();rows=[json.loads(line) for line in snapshot['files']['relay.connector.log'].splitlines()]
                last=rows[-2]
                if scenario=='missing-host':del last['hostBytes'][blob]
                elif scenario=='alternate-host':last['hostBytes']['other.cloudfront.docker.com']=last['hostBytes'].pop(blob)
                elif scenario=='host-cap':last['hostBytes'][blob]=128*1024**2+1;last['bytes']=sum(last['hostBytes'].values())
                elif scenario=='total-cap':
                    last['hostBytes']={'registry-1.docker.io':128*1024**2,'auth.docker.io':1024**2,
                                       'deb.debian.org':4*1024**2+1,blob:128*1024**2}
                    last['bytes']=sum(last['hostBytes'].values())
                elif scenario=='connections':last['connections']=33
                else:rows[-1]['variant']='metadata-authority-audit-v1'
                snapshot['files']['relay.connector.log']='\n'.join(map(json.dumps,rows))+'\n'
                with self.assertRaisesRegex(RuntimeError,'METADATA_'):m.verify_terminal(snapshot,plan())

    def test_stage_error_is_closed_projection_not_raw_stderr_or_causal_claim(self):
        raw='DVAIA_METADATA_STAGE=base-pull\nproxyconnect tcp: unexpected EOF https://blob.invalid/path?token=SECRET\nAuthorization: Bearer PRIVATE\n'
        projected=m.stage_error(raw,'base-pull',1)
        self.assertEqual(projected,{'version':1,'stage':'base-pull','exitCode':1,
            'stderrSignals':['proxy-connect','unexpected-eof'],'interpretation':'observed-substrings-not-root-cause'})
        for secret in ('SECRET','PRIVATE','blob.invalid','https','Authorization'):
            self.assertNotIn(secret,json.dumps(projected))
        self.assertIsNone(m.stage_error(raw,'base-pull',0))
        self.assertIsNone(m.stage_error('', 'unreviewed-stage',None)['stage'])
        self.assertIsNone(m.stage_error('',None,True)['exitCode'])
        with self.assertRaisesRegex(RuntimeError,'METADATA_STREAM_LIMIT'):m.stage_error('x'*(1024**2+1),None,1)

    def test_denied_authority_projection_rejects_secrets_types_and_out_of_bound_packets(self):
        snapshot=terminal()
        rows=[json.loads(line) for line in snapshot['files']['relay.adapter.log'].splitlines()]
        audit=rows[-1]
        audit['deniedAuthorities']['hosts']={'blob.invalid':2}
        rows[-2]['records'][:2]=[{'host':None,'status':'denied'}]*2
        snapshot['files']['relay.adapter.log']='\n'.join(map(json.dumps,rows))+'\n'
        m.verify_terminal(snapshot,plan())
        projected=m.relay_diagnostics(snapshot,plan())
        self.assertEqual(projected['adapter']['terminal']['deniedAuthorities']['hosts'],{'blob.invalid':2})
        negatives=[{'hosts':{'https://blob.invalid/?token=SECRET':1},'unclassified':0,'overflow':0},
            {'hosts':{'127.0.0.1':1},'unclassified':0,'overflow':0},
            {'hosts':{'deb.debian.org':1},'unclassified':0,'overflow':0},
            {'hosts':{'blob.invalid':True},'unclassified':0,'overflow':0},
            {'hosts':{'blob.invalid':1.0},'unclassified':0,'overflow':0},
            {'hosts':{},'unclassified':True,'overflow':0},
            {'hosts':{},'unclassified':0,'overflow':0.0},
            {'hosts':{'blob.invalid':32},'unclassified':1,'overflow':0},
            {'hosts':{str(i)+'.invalid':1 for i in range(9)},'unclassified':0,'overflow':0},
            {'hosts':{},'unclassified':0,'overflow':0,'rawBody':'SECRET'}]
        for denied in negatives:
            with self.subTest(denied=denied):
                bad=copy.deepcopy(audit);bad['deniedAuthorities']=denied
                with self.assertRaisesRegex(RuntimeError,'METADATA_DENIED_AUTHORITIES'):m.verify_audit(bad,plan(),'adapter')
        for key,value in [('token','SECRET'),('variant','connect-audit-v1'),('sequence',True)]:
            bad=copy.deepcopy(audit);bad[key]=value
            with self.assertRaisesRegex(RuntimeError,'METADATA_AUDIT'):m.verify_audit(bad,plan(),'adapter')

    def test_failed_pull_retains_sanitized_stage_error_and_denied_hostname_without_promotion(self):
        events=[]
        class Failed(Runner):
            def __call__(self,argv,**kw):
                response=super().__call__(argv,**kw)
                if kw['input']=='acquire':
                    response.returncode=1;response.stdout=''
                    response.stderr='DVAIA_METADATA_STAGE=base-pull\nproxyconnect tcp: unexpected EOF https://blob.invalid/?token=SECRET\n'
                return response
        class Cleanup(Runner):
            def __call__(self,argv,**kw):
                response=super().__call__(argv,**kw)
                if kw['input']=='evidence':
                    snapshot=terminal();rows=[json.loads(line) for line in snapshot['files']['relay.adapter.log'].splitlines()]
                    rows[-1]['deniedAuthorities']['hosts']={'blob.invalid':2}
                    rows[-2]['records'][:2]=[{'host':None,'status':'denied'}]*2
                    snapshot['files']['relay.adapter.log']='\n'.join(map(json.dumps,rows))+'\n'
                    response.stdout=json.dumps(snapshot)
                return response
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp,patch.object(l,'verify_sources'):
            result=m.run_metadata(plan(),{},Path(tmp),l,None,Mux(),Failed(events),Cleanup(events),
                                  lambda raw:self.fail('failed pull must not validate candidate'))
            retained='\n'.join(p.read_text() for p in Path(tmp).iterdir())
            receipt=json.loads((Path(tmp)/'2-acquire-command.json').read_text())
        self.assertFalse(result['passed']);self.assertIsNone(result['candidate']);self.assertTrue(result['guestAbsent'])
        self.assertEqual(events.count('acquire'),1);self.assertNotIn('SECRET',retained)
        self.assertEqual(receipt['stageError']['stderrSignals'],['proxy-connect','unexpected-eof'])
        self.assertEqual(result['relayDiagnostics']['adapter']['terminal']['deniedAuthorities']['hosts'],{'blob.invalid':2})

    def flow(self,work_args=None,cleanup_args=None,semantic_failure=False):
        events=[];work=Runner(events,**(work_args or {}));cleanup=Runner(events,**(cleanup_args or {}));pauses=[];clock=[1000.0]
        def pause(seconds):pauses.append(seconds);clock[0]+=seconds
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp,patch.object(l,'verify_sources'),\
                patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),\
                patch.object(m,'verify_retained_archive',return_value={'version':1,'candidateOnly':True,'authenticatedReplayComplete':False}):
            result=m.run_metadata(plan(),{},Path(tmp),l,None,Mux(),work,cleanup,
                lambda raw:{'version':3,'ok':not semantic_failure,'candidate':None if semantic_failure else {'candidateOnly':True}},pause=pause)
            files={p.name:p.read_text() for p in Path(tmp).iterdir()}
        return result,events,files,work,cleanup,pauses

    def test_success_is_metadata_only_and_retains_before_exact_cleanup(self):
        result,events,files,work,cleanup,_=self.flow()
        self.assertTrue(result['passed']);self.assertTrue(result['guestAbsent'])
        self.assertFalse(result['buildApproved']);self.assertFalse(result['executionApproved'])
        self.assertTrue(result['candidateOnly'])
        self.assertLess(events.index('stop'),events.index('evidence'));self.assertLess(events.index('evidence'),events.index('cleanup'))
        self.assertLess(events.index('evidence'),events.index('retainedExport'));self.assertLess(events.index('retainedExport'),events.index('cleanup'))
        self.assertIn('metadata-retained.tar',files)
        self.assertIn('acquisition-output.json',files);self.assertIn('terminal.json',files)
        acquire=next(call for call in work.calls if call[1]['input']=='acquire')
        self.assertEqual(acquire[1]['timeout'],315);self.assertIn('300',acquire[0])
        self.assertTrue(all(call[0][0]=='EXISTING_MUX' for call in work.calls+cleanup.calls))

    def test_semantic_failure_retains_envelope_and_never_candidate(self):
        result,_,files,_,_,_=self.flow(semantic_failure=True)
        self.assertFalse(result['passed']);self.assertIsNone(result['candidate']);self.assertTrue(result['guestAbsent'])
        self.assertFalse(json.loads(files['validated-envelope.json'])['ok'])

    def test_lost_acquisition_waits_original_bound_then_cleans_without_retry(self):
        result,events,files,_,_,pauses=self.flow({'fail':'acquire'})
        self.assertFalse(result['passed']);self.assertEqual(events.count('acquire'),1)
        self.assertTrue(result['guestAbsent']);self.assertIn('terminal.json',files)
        self.assertEqual(len(pauses),1);self.assertGreater(pauses[0],300);self.assertLessEqual(pauses[0],312)

    def test_stop_or_evidence_failure_retains_guest(self):
        for op in ('stop','evidence'):
            with self.subTest(op=op):
                result,events,files,_,_,_=self.flow(cleanup_args={'fail':op})
                self.assertFalse(result['passed']);self.assertNotIn('cleanup',events)
                self.assertIn('METADATA_GUEST_RETAINED',result['cleanupErrors']);self.assertIn('result.json',files)

    def test_unretired_host_child_prevents_guest_cleanup(self):
        result,events,_,_,_,_=self.flow({'uncertain':True})
        self.assertFalse(result['passed']);self.assertNotIn('stop',events);self.assertNotIn('cleanup',events)
        self.assertIn('HOST_QUIESCENCE_UNVERIFIED',result['cleanupErrors'])

    def test_shared_inventory_change_prevents_qualification(self):
        result,_,_,_,_,_=self.flow(cleanup_args={'changed':True})
        self.assertFalse(result['passed']);self.assertIn('SHARED_POSTFLIGHT_FAILED',result['cleanupErrors'])

    def test_transport_loss_waits_remaining_original_bound_before_every_guest_cleanup_operation(self):
        for status in (255,-15,None,'statusless-cap','unknown-status-cap','confirmed-zero-cap',1):
            with self.subTest(status=status):
                clock=[1000.0];pauses=[];events=[];observed=[]
                uncertain=status not in ('confirmed-zero-cap',1)
                class Failed(Runner):
                    def __call__(self,argv,**kw):
                        response=super().__call__(argv,**kw)
                        if kw['input']=='acquire':
                            clock[0]+=7
                            if status=='statusless-cap':raise RuntimeError('OUTPUT_LIMIT')
                            response.returncode=0 if status=='confirmed-zero-cap' else None if status=='unknown-status-cap' else status
                            if status in ('confirmed-zero-cap','unknown-status-cap'):response.stdout='x'*(1024**2+1)
                        return response
                class Cleanup(Runner):
                    def __call__(self,argv,**kw):
                        observed.append((kw['input'],clock[0]))
                        if uncertain:assert clock[0]>=1312,kw['input']
                        return super().__call__(argv,**kw)
                def pause(seconds):pauses.append(seconds);clock[0]+=seconds
                with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp,\
                        patch.object(l,'verify_sources'),patch.object(m.time,'monotonic',side_effect=lambda:clock[0]):
                    result=m.run_metadata(plan(),{},Path(tmp),l,None,Mux(),Failed(events),Cleanup(events),
                        lambda raw: (_ for _ in ()).throw(AssertionError('must not validate lost/failed acquisition')),pause=pause)
                self.assertFalse(result['passed']);self.assertTrue(result['guestAbsent'])
                self.assertEqual(events.count('acquire'),1)
                self.assertEqual(pauses,[305] if uncertain else [])
                self.assertEqual([op for op,_ in observed[:3]],['stop','evidence','cleanup'])
                self.assertTrue(all(at==1312 if uncertain else at==1007 for _,at in observed))

    def test_interrupted_or_unverified_grace_retains_guest_and_reraises_interrupt(self):
        for operation in ('acquire','stop'):
            for interrupt in (KeyboardInterrupt(),SystemExit(3),None):
                with self.subTest(operation=operation,interrupt=type(interrupt).__name__):
                    events=[];work=Runner(events,fail=operation if operation=='acquire' else None)
                    cleanup=Runner(events,fail=operation if operation=='stop' else None)
                    def pause(seconds):
                        if interrupt is not None:raise interrupt
                        # Deliberately returns early; no elapsed-time proof.
                    with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp,\
                            patch.object(l,'verify_sources'),patch.object(m.time,'monotonic',return_value=1000):
                        def invoke():return m.run_metadata(plan(),{},Path(tmp),l,None,Mux(),work,cleanup,
                            lambda raw:{'version':3,'ok':True,'candidate':{'candidateOnly':True}},pause=pause)
                        if interrupt is not None:
                            with self.assertRaises(type(interrupt)) as caught:invoke()
                            self.assertIs(caught.exception,interrupt)
                        else:invoke()
                        result=json.loads((Path(tmp)/'result.json').read_text())
                        self.assertTrue((Path(tmp)/'intent.json').exists())
                    self.assertFalse(result['passed']);self.assertFalse(result['remoteQuiescenceVerified'])
                    self.assertEqual(result['pendingRemote'],{'operation':operation,'notBeforeHostMonotonic':1312 if operation=='acquire' else 1072})
                    self.assertEqual(events[-1],operation)
                    self.assertEqual(events.count('inventory'),1)
                    self.assertNotIn('evidence',events);self.assertNotIn('cleanup',events)
                    self.assertIn('REMOTE_QUIESCENCE_UNVERIFIED',result['cleanupErrors'])
                    self.assertIsNone(result['candidate'])

    def test_terminal_caps_and_worker_debt_fail_closed(self):
        m.verify_terminal(terminal(),plan())
        for field,value in [('unjoinedWorkers',1),('unresolvedResolverCleanup',1),('connections',True),('bytes',261*1024**2+1),('cleanupVerified',1)]:
            snapshot=terminal();rows=[json.loads(line) for line in snapshot['files']['relay.connector.log'].splitlines()]
            rows[1][field]=value;snapshot['files']['relay.connector.log']='\n'.join(map(json.dumps,rows))
            with self.subTest(field=field),self.assertRaises(RuntimeError):m.verify_terminal(snapshot,plan())
        snapshot=terminal();snapshot['storage']['allocatedBytes']=6442450945
        with self.assertRaisesRegex(RuntimeError,'STORAGE'):m.verify_terminal(snapshot,plan())

    def test_plan_is_local_and_pins_target_source_and_actual_transport_receipt(self):
        probe=l.load_probe();value,sources=m.make_plan('b'*32,l,probe.BoundedRunner(time.monotonic()+30))
        self.assertEqual(set(value['commands']),m.OPERATIONS);self.assertFalse(value['executionApproved'])
        for name in ('tests/postgres/ownedPolicySystemMetadata.js','tests/postgres/ownedPolicySystemBuild.js',value['transportProof']['path']):
            self.assertIn(name,sources)
        self.assertEqual(value['binding']['base'],m.BASE)

    def test_system_metadata_source_pins_match_frozen_inputs_and_reject_drift(self):
        inputs={'tests/postgres/ownedPolicySystemMetadata.js':m.METADATA_SHA,
                'tests/postgres/ownedPolicySystemBuild.js':m.TARGET_SHA}
        self.assertEqual(inputs,{
            'tests/postgres/ownedPolicySystemMetadata.js':'e2c4cf076f8cfdc03f2595b2413559a65e1b4ab75ef184998403906435c11678',
            'tests/postgres/ownedPolicySystemBuild.js':'7c1c7d05f520fde31902ea8f0992517dbd0648c985d7750d461a917524850870'})
        for name,digest in inputs.items():
            self.assertEqual(hashlib.sha256((m.ROOT/name).read_bytes()).hexdigest(),digest)
        probe=l.load_probe()
        value,sources=m.make_plan('b'*32,l,probe.BoundedRunner(time.monotonic()+30),'v24-system')
        self.assertEqual(value['binding']['base'],m.SYSTEM_BASE)
        for name,digest in inputs.items():self.assertEqual(sources[name],digest)
        with patch.object(m,'TARGET_SHA','0'*64),self.assertRaises(RuntimeError):
            m.make_plan('b'*32,l,probe.BoundedRunner(time.monotonic()+30),'v24-system')

    def test_cli_default_plan_never_imports_mux_or_allocates_output(self):
        with patch.object(m,'make_plan',return_value=(plan(),{})),patch.object(m.sys,'argv',['metadata']),\
                patch.object(l,'private_directory') as mkdir,patch.object(m,'load_lifecycle',return_value=l),\
                patch.object(m.sys,'stdout',new_callable=io.StringIO) as out:
            self.assertEqual(m.main(),0);mkdir.assert_not_called()
            self.assertEqual(json.loads(out.getvalue())['kind'],'private-v23-registry-metadata')

    def test_system_plan_is_closed_distinct_and_not_build_authority(self):
        probe=l.load_probe()
        value,_=m.make_plan('b'*32,l,probe.BoundedRunner(time.monotonic()+30),'v24-system')
        self.assertEqual(value['binding'],{'runId':'b'*32,'target':'v24-system','base':m.SYSTEM_BASE})
        self.assertEqual(value['kind'],'private-v24-system-metadata')
        self.assertEqual(value['metadataRetention']['mode'],'v24-system-metadata-retention-v1')
        self.assertFalse(value['buildApproved']);self.assertFalse(value['executionApproved'])
        with self.assertRaisesRegex(RuntimeError,'METADATA_TARGET'):
            m.make_plan('b'*32,l,lambda *a,**kw:self.fail('must reject before execution'),'v24-policy')
        def wrong(*args,**kwargs):
            response=probe.BoundedRunner(time.monotonic()+30)(*args,**kwargs)
            packet=json.loads(response.stdout);packet['plan']['binding']['target']='v23-registry'
            return subprocess.CompletedProcess(args,0,json.dumps(packet),'')
        with self.assertRaisesRegex(RuntimeError,'METADATA_PLAN_SHAPE'):
            m.make_plan('b'*32,l,wrong,'v24-system')


if __name__=='__main__':unittest.main()
