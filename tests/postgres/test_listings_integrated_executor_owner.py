"""Enabled public composition with controlled authority; no live build."""
import ast,hashlib,json,pathlib,time,unittest,types
from unittest.mock import patch
from listings_integrated_executor_owner import PrivateExecutorOwner

ROOT=pathlib.Path(__file__).resolve().parents[2]
RUN='a'*32

class Phase:
    run_id=RUN
    plan_sha256='b'*64
    def __init__(self,events,fail=None):self.events=events;self.fail=fail;self.input=None
    def run_phase(self,name,value):
        self.events.append(name)
        if name==self.fail:raise RuntimeError('controlled phase failure')
        if name=='listingsManagerCreate':self.input=value
        if name=='listingsManagerStart':
            workspace_id=hashlib.sha256(str(ROOT.resolve()).encode()).hexdigest()[:12]
            profile='owasp-ai-goat-owned-listings-'+workspace_id
            policy=(ROOT/'sidecars/sandbox-runner/owned-listings/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',profile)
            env=['LISTINGS_MANAGER_ENABLED=true','LISTINGS_PROFILE='+profile,'LISTINGS_PUBLIC_ORIGIN='+self.input['origin'],'LISTINGS_CONTROL_TOKEN='+self.input['token']]
            return json.dumps(dict(runId=RUN,root='/var/tmp/owasp-ai-goat-v23-build-'+RUN+'/fs',filesystemDevice=1792,filesystemInode=2,
                namespaceInode=123,holderPid=200,holderStart=300,containerPid=400,containerStart=500,containerId='c'*64,
                imageId='sha256:'+'d'*64,sourceSha256='e'*64,runtimeSha256='f'*64,
                environmentSha256=hashlib.sha256('\n'.join(sorted(env)).encode()).hexdigest(),publicOrigin=self.input['origin'],
                workspaceId=workspace_id,profileName=profile,profileSha256=hashlib.sha256(policy.encode()).hexdigest(),containerName=profile,
                privateDockerHost='unix:///var/tmp/owasp-ai-goat-v23-build-'+RUN+'/fs/docker.sock',daemonId='d'*36))
        if name=='listingsManagerChannels':return json.dumps(dict(runId=RUN,remoteChannelsAbsent=True,channels=[]))
        return 'absent'
    def confirm_retired(self):self.events.append('confirm')
    def begin_retirement(self,deadline):self.events.append('retirement-grant')

class OwnerTests(unittest.TestCase):
    def setup_owner(self,fail=None,browser_fail=False):
        events=[];phase=Phase(events,fail)
        class Browser:
            def close(self,cleanup_deadline):
                events.append('browser-close')
                if browser_fail:raise RuntimeError('browser debt')
        class Bridge:
            def __init__(self,*args):pass
            def open(self):events.append('reserve');return 'http://127.0.0.1:1234'
            def activate(self,h):events.append('activate')
            def close(self,deadline):events.append('bridge-close');return dict(listenerClosed=True,localChannelsRetired=True,channelIds=(),channelStates=())
        owner=PrivateExecutorOwner(ROOT,RUN,'b'*64,phase,Browser(),time.monotonic()+30)
        return owner,events,Bridge

    def test_public_entry_switch_can_close_before_effect(self):
        owner,events,bridge=self.setup_owner()
        with patch('listings_integrated_executor_owner.PRIVATE_MANAGER_LIVE',False),self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):owner.start()
        self.assertEqual(events,[])

    def test_actual_component_orders_browser_bridge_remote_manager_and_release(self):
        owner,events,bridge=self.setup_owner()
        with patch('listings_native_resources.PrivateListingsBridge',bridge):
            env=owner.start()
        self.assertEqual(env['LISTINGS_MANAGER_ORIGIN'],'http://127.0.0.1:1234')
        result=owner.close(time.monotonic()+10)
        self.assertTrue(result['builderReleaseAllowed'])
        self.assertEqual(events[-6:],['browser-close','bridge-close','listingsManagerChannels','listingsManagerRetire','listingsProfileRetire','confirm'])

    def test_exact_channel_intent_written_before_phase_and_writer_failure_blocks_it(self):
        channel='a'*32
        states=({'channelId':channel,'state':'spawn_attempted'},
                {'channelId':'b'*32,'state':'never_attempted'})
        for fail_writer in (False,True):
            owner,events,bridge=self.setup_owner()
            def bridge_close(self,deadline):
                events.append('bridge-close')
                return dict(listenerClosed=True,localChannelsRetired=True,
                            channelIds=(channel,),channelStates=states)
            bridge.close=bridge_close
            captured=[]
            def write(value):
                events.append('intent-write');captured.append(value)
                if fail_writer:raise OSError('controlled writer failure')
            owner.channel_intent_writer=write
            original=owner.phase_owner.run_phase
            def phase(name,value):
                if name=='listingsManagerChannels':
                    self.assertEqual(captured[0]['expectedChannelIds'],value['channelIds'])
                    events.append('intent-checked')
                    return json.dumps(dict(runId=RUN,remoteChannelsAbsent=True,
                                           channels=[dict(channelId=channel)]))
                return original(name,value)
            owner.phase_owner.run_phase=phase
            with patch('listings_native_resources.PrivateListingsBridge',bridge):owner.start()
            if fail_writer:
                with self.assertRaisesRegex(OSError,'writer failure'):owner.close(time.monotonic()+10)
                self.assertNotIn('listingsManagerChannels',events)
                self.assertNotIn('confirm',events)
            else:
                self.assertTrue(owner.close(time.monotonic()+10)['builderReleaseAllowed'])
                self.assertEqual(captured[0]['channelStates'],list(states))
                self.assertLess(events.index('intent-write'),events.index('intent-checked'))

    def test_browser_and_remote_debt_never_release_builder(self):
        for fail,browser_fail in [(None,True),('listingsManagerChannels',False),('listingsManagerStart',False),('bridge',False)]:
            owner,events,bridge=self.setup_owner(fail,browser_fail)
            if fail=='bridge':
                def bridge_debt(self,deadline):raise RuntimeError('controlled local bridge debt')
                bridge.close=bridge_debt
            with patch('listings_native_resources.PrivateListingsBridge',bridge):
                try:owner.start()
                except RuntimeError:pass
            with self.assertRaises(RuntimeError):owner.close(time.monotonic()+10)
            self.assertNotIn('listingsManagerRetire',events);self.assertNotIn('confirm',events)
            if browser_fail:self.assertNotIn('bridge-close',events)

    def test_cleanup_clock_cannot_renew_and_wrong_plan_rejects(self):
        owner,events,bridge=self.setup_owner(browser_fail=True)
        end=time.monotonic()+10
        with self.assertRaises(RuntimeError):owner.close(end)
        with self.assertRaisesRegex(RuntimeError,'RENEWAL'):owner.close(end+1)
        with self.assertRaises(ValueError):PrivateExecutorOwner(ROOT,RUN,'c'*64,owner.phase_owner,owner.browser_owner,time.monotonic()+30)

    def test_late_browser_and_final_phase_cannot_release_builder(self):
        for delayed in ('browser','phase','confirm'):
            owner,events,bridge=self.setup_owner()
            with patch('listings_native_resources.PrivateListingsBridge',bridge):owner.start()
            clock=[100.0]
            if delayed=='browser':
                def late_close(cleanup_deadline):clock[0]=102
                owner.browser_owner.close=late_close
            elif delayed=='phase':
                original=owner.phase_owner.run_phase
                def late_phase(name,value):
                    result=original(name,value)
                    if name=='listingsProfileRetire':clock[0]=102
                    return result
                owner.phase_owner.run_phase=late_phase
            else:
                def late_confirm():clock[0]=102
                owner.phase_owner.confirm_retired=late_confirm
            with patch('listings_integrated_executor_owner.time.monotonic',side_effect=lambda:clock[0]),self.assertRaisesRegex(RuntimeError,'DEADLINE'):
                owner.close(101)
            self.assertFalse(owner.closed)
            if delayed!='confirm':self.assertNotIn('confirm',events)

class MainBrowserBoundaryTests(unittest.TestCase):
    def test_actual_plan_cli_bytes_join_original_main_packet_and_sources(self):
        import os,re,stat,subprocess,tempfile
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        names={'listings_private_selected','listings_private_packet','listings_private_sources','listings_private_browser_budget'}
        nodes=[n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name in names]
        ns=dict(Path=pathlib.Path,os=os,stat=stat,json=json,re=re,hashlib=hashlib,
                digest=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest())
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),ns)
        result=subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
            str(ROOT/'tests/postgres/ownedMcpOriginalBuildAdapter.js'),'--listings-manager-plan',RUN],
            cwd=ROOT,stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=True)
        self.assertEqual(result.stderr,b'');packet=json.loads(result.stdout)
        with tempfile.TemporaryDirectory(prefix='listings-plan-control-',dir=ROOT/'tasks/tmp') as directory:
            file=pathlib.Path(directory)/'plan.json';file.write_bytes(result.stdout);file.chmod(0o600)
            args=types.SimpleNamespace(cohort='standalone-listings-browser',listings_private_run_id=RUN,
                listings_private_plan_sha256=packet['planSha256'],listings_private_plan=str(file),listings_image_id=None)
            self.assertEqual(ns['listings_private_packet'](args,ROOT),packet)
            for changes in ({'cohort':'standalone-commerce-browser'}, {'listings_private_run_id':'bad'},
                            {'listings_private_plan_sha256':None}, {'listings_private_plan':None}):
                invalid=types.SimpleNamespace(**{**vars(args),**changes})
                with self.assertRaisesRegex(RuntimeError,'Exclusive'):ns['listings_private_selected'](invalid)
            self.assertFalse(ns['listings_private_selected'](types.SimpleNamespace(cohort='standalone-listings-browser')))
            args.listings_image_id='sha256:'+'a'*64
            with self.assertRaisesRegex(RuntimeError,'Exclusive'):ns['listings_private_packet'](args,ROOT)
            args.listings_image_id=None;args.listings_private_plan_sha256='0'*64
            with self.assertRaisesRegex(RuntimeError,'mismatch'):ns['listings_private_packet'](args,ROOT)
            args.listings_private_plan_sha256=packet['planSha256'];file.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,'identity'):ns['listings_private_packet'](args,ROOT)
            file.chmod(0o600)
            mutated=json.loads(result.stdout);key=next(iter(mutated['plan']['helperHashes']))
            mutated['plan']['helperHashes'][key]='0'*64
            mutated['planSha256']=hashlib.sha256(json.dumps(mutated['plan'],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
            file.write_text(json.dumps(mutated));args.listings_private_plan_sha256=mutated['planSha256']
            with self.assertRaisesRegex(RuntimeError,'source changed'):ns['listings_private_packet'](args,ROOT)

    def test_original_browser_budget_cannot_be_shortened_to_fixture_budget(self):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='listings_private_browser_budget')
        ns={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
        plan=dict(target='listings-package',spec=dict(runId=RUN),listingsConsumer=dict(mode='manager'),
                  sharedImageLoadAllowed=False,limits=dict(consumerWorkMs=120000,consumerRetirementMs=1080000))
        for value in (120000,539999,600001,True,'600000'):
            plan['limits']['consumerWorkMs']=value
            with self.assertRaisesRegex(RuntimeError,'incompatible'):ns['listings_private_browser_budget'](plan,RUN)
        plan['limits']['consumerWorkMs']=600000
        with self.assertRaisesRegex(RuntimeError,'lease incompatible'):ns['listings_private_browser_budget'](plan,RUN)
        plan['listingsLease']=dict(profile='listings-manager-browser',target='original-listings-manager-total-lease-v1',
            totalMs=6680000,startupMs=60000,browserMs=540000,retirementMs=1080000,cleanupMs=2520000)
        self.assertEqual(ns['listings_private_browser_budget'](plan,RUN),600000)
        original=dict(plan['listingsLease'])
        for key,value in [('profile','q05-registered-pair'),('browserMs',120000),('totalMs',7400000),('cleanupMs',0),('extra',1)]:
            plan['listingsLease']={**original,key:value}
            with self.assertRaisesRegex(RuntimeError,'lease incompatible'):ns['listings_private_browser_budget'](plan,RUN)
        plan['listingsLease']=original
        with self.assertRaisesRegex(RuntimeError,'contract'):ns['listings_private_browser_budget'](plan,'b'*32)

    def test_actual_main_group_probe_receives_only_remaining_budget(self):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='owned_test_group_members')
        calls=[]
        def run(argv,**kwargs):calls.append(kwargs);return types.SimpleNamespace(returncode=0,stdout='')
        ns=dict(sys=types.SimpleNamespace(platform='linux'),time=types.SimpleNamespace(monotonic=lambda:10),
                subprocess=types.SimpleNamespace(run=run))
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
        self.assertEqual(ns['owned_test_group_members'](object(),deadline=10.25),[])
        self.assertEqual(calls[0]['timeout'],.25)
        with self.assertRaisesRegex(RuntimeError,'deadline'):ns['owned_test_group_members'](object(),deadline=9)
        self.assertEqual(len(calls),1)

    def test_actual_main_factory_requires_authority_and_retains_emergency_switch(self):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='listings_private_owner')
        ns={'LISTINGS_PRIVATE_CALLER_ENABLED':False}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
        with self.assertRaisesRegex(RuntimeError,'not admitted'):
            ns['listings_private_owner'](None,None,None,None,None,None,None)
        gate=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id=='LISTINGS_PRIVATE_CALLER_ENABLED' for t in n.targets))
        exec(compile(ast.Module(body=[gate],type_ignores=[]),str(source),'exec'),ns)
        self.assertIs(ns['LISTINGS_PRIVATE_CALLER_ENABLED'],True)
        def require_plan(plan,run):raise RuntimeError('controlled valid producer authority required')
        ns['listings_private_browser_budget']=require_plan
        with self.assertRaisesRegex(RuntimeError,'controlled valid producer authority required'):
            ns['listings_private_owner'](None,None,None,None,None,None,None)

    def test_actual_main_stop_does_not_signal_after_deadline(self):
        import subprocess
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='stop_process_group')
        clock=[10.0];signals=[];waits=[]
        class Child:
            pid=123
            def poll(self):return None
            def wait(self,timeout):
                waits.append(timeout);clock[0]+=timeout
                raise subprocess.TimeoutExpired('controlled',timeout)
        ns=dict(time=types.SimpleNamespace(monotonic=lambda:clock[0]),subprocess=subprocess,
                os=types.SimpleNamespace(killpg=lambda *args:signals.append(args)),
                signal=types.SimpleNamespace(SIGTERM=15,SIGKILL=9),owned_test_group_members=lambda child:[])
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
        with self.assertRaisesRegex(RuntimeError,'deadline'):ns['stop_process_group'](Child(),cleanup_deadline=12)
        self.assertEqual(waits,[2]);self.assertEqual(signals,[(123,15)])

    def boundary(self, state=None, delay=0):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.ClassDef) and n.name=='ListingsPrivateBrowserOwner')
        clock=[10.0];calls=[]
        def stop(child,**kwargs):calls.append((child,kwargs))
        def inspect(runtime, *, deadline):
            self.assertEqual(deadline,50)
            clock[0]+=delay
            return state if state is not None else dict(browserProfilesAbsent=True,browserProcessesAbsent=True)
        ns=dict(Path=pathlib.Path,time=types.SimpleNamespace(monotonic=lambda:clock[0]),stop_process_group=stop,standalone_browser_cleanup_state=inspect)
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
        child=object();return ns['ListingsPrivateBrowserOwner'](ROOT,child),clock,calls,child

    def test_actual_main_owner_passes_exact_child_and_immutable_deadline(self):
        owner,clock,calls,child=self.boundary()
        self.assertTrue(owner.close(cleanup_deadline=50)['browserProcessesAbsent'])
        self.assertEqual(calls,[(child,{'cleanup_deadline':50})])
        with self.assertRaises(RuntimeError):owner.close(cleanup_deadline=60)

    def test_actual_main_owner_preserves_profile_debt_and_rejects_renewal(self):
        owner,clock,calls,child=self.boundary(dict(browserProfilesAbsent=False,browserProcessesAbsent=True))
        with self.assertRaisesRegex(RuntimeError,'unproven'):owner.close(cleanup_deadline=50)
        self.assertFalse(owner.closed)
        with self.assertRaisesRegex(RuntimeError,'renewal'):owner.close(cleanup_deadline=60)
        self.assertEqual(len(calls),1)

    def test_actual_main_owner_inspection_cannot_extend_cleanup(self):
        owner,clock,calls,child=self.boundary(delay=50)
        with self.assertRaisesRegex(RuntimeError,'unproven'):owner.close(cleanup_deadline=50)
        self.assertFalse(owner.closed)
        owner,clock,calls,child=self.boundary()
        with self.assertRaisesRegex(RuntimeError,'budget'):owner.close(cleanup_deadline=20)
        self.assertFalse(owner.closed)

class MainProducerChildTests(unittest.TestCase):
    """Actual inherited socket/Node child, with guest effects and browser controlled."""
    def boundary(self, mode):
        import os,re,stat,socket,subprocess,tempfile,uuid,shutil
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        selected={'ListingsPrivateProducer','ListingsPrivateBrowserOwner','listings_private_browser_budget',
                  'listings_private_may_retire_pg'}
        nodes=[n for n in ast.parse(source.read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in selected]
        nodes += [n for n in ast.parse(source.read_text()).body if isinstance(n,ast.Assign)
                  and any(isinstance(t,ast.Name) and t.id=='LISTINGS_PRIVATE_CALLER_ENABLED' for t in n.targets)]
        evidence=pathlib.Path(tempfile.mkdtemp(prefix='listings-caller-control-',dir=ROOT/'tasks/tmp'))
        run=uuid.uuid4().hex;artifact=ROOT/'tasks/tmp'/('v23-build-'+run)
        self.assertFalse(artifact.exists())
        self.addCleanup(lambda:shutil.rmtree(artifact) if artifact.exists() else None)
        self.addCleanup(shutil.rmtree,evidence)
        packet=dict(runId=run,planSha256='b'*64,plan=dict(target='listings-package',spec=dict(runId=run),
            listingsConsumer=dict(mode='manager'),sharedImageLoadAllowed=False,
            limits=dict(consumerWorkMs=600000,consumerRetirementMs=1080000),
            listingsLease=dict(profile='listings-manager-browser',target='original-listings-manager-total-lease-v1',
                totalMs=6680000,startupMs=60000,browserMs=540000,retirementMs=1080000,cleanupMs=2520000)))
        script=r'''
const net=require('node:net'),fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const [fd,runId,planSha256,artifact,mode]=process.argv.slice(1);
if(mode==='eof')process.exit(2);
if(mode==='prehello-clean-failure'){
 fs.mkdirSync(artifact,{mode:0o700});
 fs.writeFileSync(path.join(artifact,'result.json'),JSON.stringify({version:1,runId,planSha256,controlled:false,
  buildCompleted:false,qualificationComplete:false,cleanupVerified:true,cleanupErrors:[],
  error:'ORIGINAL_BUILD_PHASE_INVENTORY',interruptions:[],consumerJournal:{sealed:true,pendingOperations:0}}),{flag:'wx',mode:0o600});
 process.exit(1);
}
const {serveListingsPhases}=require('./tests/postgres/listingsPhaseEndpoint');
const adapter=require('./tests/postgres/ownedMcpOriginalBuildAdapter');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const workspaceId=hash(fs.realpathSync(process.cwd())).slice(0,12),profile='owasp-ai-goat-owned-listings-'+workspaceId;
const profileSha256=hash(fs.readFileSync('sidecars/sandbox-runner/owned-listings/profile.apparmor.in','utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile));
let create,confirmed=false;
const base={assertOpen(){},assertActive(){},assertRetirementAdmission(){},joinPhase:fn=>fn(),confirmRetired(){confirmed=true;},expireWork(){},
 signal:new AbortController().signal,retirementSignal:new AbortController().signal};
const lifetime=adapter._internals.listingsLifetime(base,{spec:{runId},listingsConsumer:{mode:'manager',name:profile}},async(name,options)=>{
 if(name==='listingsManagerCreate'){let s='';for await(const c of options.input)s+=c;create=JSON.parse(s);}
 if(name==='listingsManagerStart'){
  if(mode==='start-failure')throw Error('controlled guest start failure');
  const env=['LISTINGS_MANAGER_ENABLED=true','LISTINGS_PROFILE='+profile,'LISTINGS_PUBLIC_ORIGIN='+create.origin,'LISTINGS_CONTROL_TOKEN='+create.token];
  return JSON.stringify({runId,root:'/var/tmp/owasp-ai-goat-v23-build-'+runId+'/fs',filesystemDevice:1792,filesystemInode:2,
   namespaceInode:123,holderPid:200,holderStart:300,containerPid:400,containerStart:500,containerId:'c'.repeat(64),
   imageId:'sha256:'+'d'.repeat(64),sourceSha256:'e'.repeat(64),runtimeSha256:'f'.repeat(64),environmentSha256:hash(env.sort().join('\n')),
   publicOrigin:create.origin,workspaceId,profileName:profile,profileSha256,containerName:profile,
   privateDockerHost:'unix:///var/tmp/owasp-ai-goat-v23-build-'+runId+'/fs/docker.sock',daemonId:'d'.repeat(36)});
 }
 return name==='listingsManagerChannels'?JSON.stringify({version:1,runId,remoteChannelsAbsent:true,channels:[]}):name.includes('Retire')?'absent':'controlled';
});
serveListingsPhases(new net.Socket({fd:Number(fd),readable:true,writable:true}),{runId,planSha256},lifetime)
 .then(()=>finish(null),error=>finish(error));
function finish(error){
 fs.mkdirSync(artifact,{mode:0o700});
 // Synthetic controlled result used only to exercise the parent's strict join.
 fs.writeFileSync(path.join(artifact,'result.json'),JSON.stringify({version:1,runId,planSha256,controlled:false,
 qualificationComplete:false,cleanupVerified:confirmed,cleanupErrors:confirmed?[]:['controlled-retirement-debt'],
 error:error?'controlled-failure':null,interruptions:[],consumerJournal:{sealed:confirmed,pendingOperations:0}}),{flag:'wx',mode:0o600});
 process.exitCode=error?1:0;
}
'''
        children=[];records=[]
        node=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
        def spawn(argv,**kwargs):
            self.assertEqual(argv[:3],[str(node),str(ROOT/'tests/postgres/ownedMcpOriginalBuildAdapter.js'),'--listings-manager-run'])
            self.assertEqual(argv[3:5],[run,'b'*64]);self.assertEqual(kwargs['pass_fds'],(int(argv[5]),))
            self.assertTrue(kwargs['start_new_session']);self.assertEqual(kwargs['stdin'],subprocess.DEVNULL)
            if mode=='spawn-failure':raise OSError('controlled spawn failure')
            child=subprocess.Popen([str(node),'-e',script,argv[5],run,'b'*64,str(artifact),mode],**kwargs)
            children.append(child);return child
        def members(child,*,deadline):
            self.assertGreater(deadline,time.monotonic())
            try:pgid=os.getpgid(child.pid)
            except ProcessLookupError:return []
            self.assertEqual(pgid,child.pid)
            return [child.pid] if child.poll() is None else []
        def stop(child,*,cleanup_deadline):
            if child is None:return
            if child.poll() is None:
                child.terminate();child.wait(timeout=min(2,cleanup_deadline-time.monotonic()))
        def persist(path,value):
            self.assertTrue(path.is_relative_to(evidence));records.append(value)
        ns=dict(Path=pathlib.Path,time=time,json=json,hashlib=hashlib,os=os,stat=stat,socket=socket,
                subprocess=types.SimpleNamespace(Popen=spawn,DEVNULL=subprocess.DEVNULL),
                listings_private_sources=lambda *args:None,node_pin_matches=lambda *args:True,
                owned_test_group_members=members,stop_process_group=stop,atomic_json=persist,
                standalone_browser_cleanup_state=lambda *args,**kwargs:dict(browserProfilesAbsent=True,browserProcessesAbsent=True),
                )
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),ns)
        instance=ns['ListingsPrivateProducer'](ROOT,node,'e'*64,packet,evidence,evidence)
        class Bridge:
            def __init__(self,*args):pass
            def open(self):return 'http://127.0.0.1:1234'
            def activate(self,handoff):self.handoff=handoff
            def close(self,end):return dict(listenerClosed=True,localChannelsRetired=True,channelIds=[],channelStates=[])
        def finish():
            if instance.channel is not None:instance.channel.close()
            for child in children:
                if child.poll() is None:child.kill();child.wait(timeout=2)
        self.addCleanup(finish)
        return instance,ns,records,children,Bridge

    def test_actual_inherited_fd_and_result_join_normal_and_failed_start(self):
        for mode in ('normal','start-failure','eof','spawn-failure'):
            with self.subTest(mode=mode):
                owner,ns,records,children,bridge=self.boundary(mode)
                self.assertFalse(owner.started)
                self.assertIs(ns['LISTINGS_PRIVATE_CALLER_ENABLED'],True)
                with patch('listings_native_resources.PrivateListingsBridge',bridge):
                    if mode=='normal':
                        environment=owner.start()
                        self.assertIn('SECURESHOP_LISTINGS_PRIVATE_MANAGER_RUN_ID',environment)
                        result=owner.close();self.assertTrue(result['cleanupVerified']);self.assertTrue(owner.closed)
                        self.assertTrue(any(record.get('expectedChannelIds')==[] and record.get('channelStates')==[]
                                            for record in records))
                        self.assertTrue(ns['listings_private_may_retire_pg'](owner,{'listingsPrivate':result}))
                    else:
                        with self.assertRaises(Exception):owner.start()
                        with self.assertRaisesRegex(RuntimeError,'cleanup unproven'):owner.close()
                        self.assertFalse(owner.closed)
                        self.assertFalse(ns['listings_private_may_retire_pg'](owner,{'listingsPrivate':{'cleanupVerified':True}}))
                self.assertEqual(owner.channel.fileno(),-1)
                self.assertTrue(all(c.poll() is not None for c in children))
                self.assertEqual(records[-1]['cleanupVerified'],mode=='normal')

    def test_actual_main_finally_guards_pg_and_always_closes_attempted_producer(self):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        tree=ast.parse(source.read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        cleanup_try=next(n for n in ast.walk(main) if isinstance(n,ast.Try) and any(
            isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr=='close'
            and isinstance(c.func.value,ast.Name) and c.func.value.id=='listings_private_producer'
            for f in n.finalbody for c in ast.walk(f)))
        self.assertTrue(cleanup_try.finalbody)
        guarded=next(n for n in ast.walk(main) if isinstance(n,ast.If) and isinstance(n.test,ast.BoolOp)
            and isinstance(n.test.values[0],ast.Name) and n.test.values[0].id=='creation_attempted'
            and 'listings_private_may_retire_pg' in ast.unparse(n.test))
        calls=[]
        ns={'creation_attempted':True,'listings_private_producer':object(),'cleanup':{},
            'listings_private_may_retire_pg':lambda *args:False,
            'pg_observer_may_retire':lambda *args:calls.append('must not reach')}
        self.assertFalse(eval(compile(ast.Expression(guarded.test),str(source),'eval'),ns));self.assertEqual(calls,[])
        network=next(n for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
            and isinstance(n.func.value,ast.Name) and n.func.value.id=='pg_network' and n.func.attr=='close')
        condition=next(k.value for k in network.keywords if k.arg=='owner_quiescent')
        self.assertFalse(eval(compile(ast.Expression(condition),str(source),'eval'),ns));self.assertEqual(calls,[])

    def test_actual_prehello_failed_work_can_retire_without_becoming_success(self):
        owner,ns,records,children,bridge=self.boundary('prehello-clean-failure')
        with self.assertRaises(Exception) as primary:owner.start()
        self.assertIsNone(owner.owner)
        result=owner.close()
        self.assertTrue(owner.closed);self.assertTrue(result['cleanupVerified'])
        self.assertFalse(result['workSucceeded']);self.assertFalse(result['qualificationComplete'])
        self.assertEqual(result['producerExitCode'],1)
        self.assertEqual(result['producerReceipt']['error'],'ORIGINAL_BUILD_PHASE_INVENTORY')
        self.assertTrue(ns['listings_private_may_retire_pg'](owner,{'listingsPrivate':result}))
        self.assertIsNotNone(primary.exception)
        self.assertEqual(owner.channel.fileno(),-1)
        self.assertTrue(all(child.poll()==1 for child in children))

    def test_failed_work_retirement_still_rejects_receipt_identity_source_and_group_debt(self):
        for fault in ('cleanup','errors','unsealed','pending','pending-bool','run','plan','version',
                      'controlled','interruptions','source','node','group','deadline','mode','outcome'):
            with self.subTest(fault=fault):
                owner,ns,records,children,bridge=self.boundary('prehello-clean-failure')
                with self.assertRaises(Exception):owner.start()
                children[0].wait(timeout=3)
                file=owner.artifact/'result.json';receipt=json.loads(file.read_text())
                if fault=='cleanup':receipt['cleanupVerified']=False
                elif fault=='errors':receipt['cleanupErrors']=['debt']
                elif fault=='unsealed':receipt['consumerJournal']['sealed']=False
                elif fault=='pending':receipt['consumerJournal']['pendingOperations']=1
                elif fault=='pending-bool':receipt['consumerJournal']['pendingOperations']=False
                elif fault=='run':receipt['runId']='0'*32
                elif fault=='plan':receipt['planSha256']='0'*64
                elif fault=='version':receipt['version']=True
                elif fault=='controlled':receipt['controlled']=True
                elif fault=='interruptions':receipt['interruptions']=['SIGTERM']
                elif fault=='outcome':receipt['error']=None
                elif fault=='source':
                    def changed(*args):raise RuntimeError('source changed')
                    ns['listings_private_sources']=changed
                elif fault=='node':ns['node_pin_matches']=lambda *args:False
                elif fault=='group':ns['owned_test_group_members']=lambda *args,**kwargs:[children[0].pid]
                elif fault=='deadline':owner.deadline=time.monotonic()-1
                file.write_text(json.dumps(receipt))
                if fault=='mode':file.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError,'cleanup unproven|deadline expired'):owner.close()
                self.assertFalse(owner.closed)
                self.assertFalse(ns['listings_private_may_retire_pg'](owner,{'listingsPrivate':{'cleanupVerified':True}}))

    def test_actual_main_records_terminal_failure_without_blocking_verified_cleanup(self):
        source=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
        tree=ast.parse(source.read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        branch=next(n for n in ast.walk(main) if isinstance(n,ast.If)
                    and ast.unparse(n.test)=='listings_private_producer is not None'
                    and any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='close'
                            for x in ast.walk(n)))
        result=dict(cleanupVerified=True,workSucceeded=False,producerExitCode=1,qualificationComplete=False)
        for prior in (None,{'type':'OriginalStartFailure'}):
            ns=dict(listings_private_producer=types.SimpleNamespace(close=lambda:result),cleanup={},
                    primary_error=prior,cleanup_errors=[])
            exec(compile(ast.Module(body=[branch],type_ignores=[]),str(source),'exec'),ns)
            self.assertEqual(ns['cleanup']['listingsPrivate'],result);self.assertEqual(ns['cleanup_errors'],[])
            if prior is not None:self.assertIs(ns['primary_error'],prior)
            else:self.assertEqual(ns['primary_error']['type'],'ListingsProducerFailure')

    def test_late_final_publication_cannot_release_parent_pg(self):
        owner,ns,records,children,bridge=self.boundary('normal')
        with patch('listings_native_resources.PrivateListingsBridge',bridge):
            owner.start()
            original=ns['atomic_json']
            def delayed(path,value):
                original(path,value);owner.deadline=time.monotonic()-1
            ns['atomic_json']=delayed
            with self.assertRaisesRegex(RuntimeError,'deadline expired'):owner.close()
        self.assertFalse(owner.closed)
        self.assertFalse(ns['listings_private_may_retire_pg'](owner,{'listingsPrivate':records[-1]}))
        self.assertFalse(records[-1]['publicationSealed'])

if __name__=='__main__':unittest.main()
