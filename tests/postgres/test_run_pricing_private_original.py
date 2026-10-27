"""Plan/clock controls only; no native resources."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import uuid
import shutil
import json
import os
import subprocess
import io
import sys
import time
import contextlib
import stat

spec=importlib.util.spec_from_file_location('pricing_owner',Path(__file__).with_name('run_pricing_private_original.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class PricingOwner(unittest.TestCase):
    def test_v25_profile_is_inert_exact_source_bound_and_deadline_nonrenewing(self):
        admitted=m.plan('b'*32,'v25-manual')
        self.assertEqual((admitted['totalSeconds'],admitted['cohortSeconds'],admitted['helperSeconds'],admitted['retirementSeconds']),(2856,840,780,600))
        self.assertEqual((admitted['actor'],admitted['judge'],admitted['totalCalls']),(20,12,32))
        self.assertTrue(m.V25_LIVE_ENABLED)
        self.assertTrue(admitted['eligible']);self.assertTrue(admitted['liveEnabled']);self.assertFalse(admitted['qualificationComplete'])
        self.assertEqual(admitted['blockers'],[])
        self.assertEqual(admitted['stores'],{'identity':'identity','fresh':'secureshop_agents','commerce':'secureshop','aclfresh':'secureshop_agents','review':'secureshop_review'})
        for name in m.V25_SOURCES:self.assertEqual(admitted['sources'][name],m._file_digest(m.ROOT/name))
        command=[admitted['manual']['node'],'-e',"const a=require('./tests/postgres/ownedPricingBuildAdapter');process.stdout.write(JSON.stringify(a.pricingBuildInputs(process.cwd(),process.argv[1],'v25-manual').sources));",admitted['runId']]
        captured=subprocess.run(command,cwd=m.ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(captured.returncode,0,captured.stderr)
        self.assertEqual(json.loads(captured.stdout),{k:v for k,v in admitted['sources'].items() if k!='tests/postgres/owned_mcp_mux_relay.py'})
        with patch.object(m,'V25_LIVE_ENABLED',False):
            closed=m.plan('b'*32,'v25-manual')
            self.assertFalse(closed['liveEnabled']);self.assertFalse(closed['eligible'])
            self.assertFalse(closed['qualificationComplete']);self.assertEqual(len(closed['blockers']),1)
        with patch.object(m,'V25_LIVE_ENABLED',False),patch.object(m,'BuilderChannel') as builder,patch.object(m,'plan') as read:
            with self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):m.with_manual_session(admitted,lambda _:None)
            with self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):m._execute_owned(admitted,'v25-manual',lambda _:None)
            builder.assert_not_called();read.assert_not_called()
        with patch.object(m,'plan',return_value=admitted),patch.object(m,'BuilderChannel') as builder,patch.object(Path,'mkdir') as allocate:
            for forged in (dict(admitted,sources={}),dict(admitted,consumerProfile='v33'),dict(admitted,cohortSeconds=900)):
                with self.assertRaisesRegex(RuntimeError,'OWNER_SOURCE'):m.with_manual_session(forged,lambda _:None)
            with self.assertRaisesRegex(RuntimeError,'MANUAL_CONSUMER'):m.with_manual_session(admitted,None)
            builder.assert_not_called();allocate.assert_not_called()
        clock=[0];budget=m.RetirementBudget(profile='v25-manual',clock=lambda:clock[0])
        clock[0]=1416;self.assertEqual(budget.cohort_deadline(),2256)
        clock[0]=1430
        with self.assertRaisesRegex(RuntimeError,'NONRENEWAL'):budget.cohort_deadline()
        clock[0]=2256;self.assertEqual(budget.begin_retirement(),2856)
        clock[0]=2300;self.assertEqual(budget.begin_retirement(),2856)
        clock[0]=2856
        with self.assertRaisesRegex(RuntimeError,'EXPIRED'):budget.remaining(1)
        self.assertEqual(m.builder_argv('v25-manual'),m.builder_argv()+['--v25-manual-session'])

    def test_v25_failed_terminal_retirement_never_confers_qualification(self):
        admitted=m.plan('b'*32,'v25-manual')
        owner_sha=m.hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        directory=m.ROOT/'tasks/qualification'/('manual-terminal-control-'+uuid.uuid4().hex);directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree,directory);path=directory/'result.json'
        outcome=dict(version=2,passed=False,cleanupVerified=True,ownerPlanSha256=owner_sha,nodePlanSha256='a'*64,
            cleanupErrors=[],sourceMatched=True,consumerProfile='v25-manual',qualificationComplete=False,errorType='AssertionError')
        identity=m.exclusive_record(path,{'passed':False});sha=m.publish_result(path,identity,outcome)
        result=dict(outcome,terminalJoin=dict(version=1,candidateSha256=sha,withinOriginalDeadline=True,
            ownerPlanSha256=owner_sha,nodePlanSha256='a'*64))
        self.assertTrue(m.verify_retirement(admitted,result,path,lambda:None))
        with self.assertRaises(RuntimeError):m.verify_terminal(admitted,result,path,lambda:None)
        for delta in ({'consumerProfile':'v34-browser'},{'qualificationComplete':True},{'cleanupErrors':['debt']},
                      {'cleanupVerified':False},{'sourceMatched':False},{'passed':1},{'version':True}):
            with self.assertRaises(RuntimeError):m.verify_retirement(admitted,dict(result,**delta),path,lambda:None)
        with self.assertRaises(RuntimeError):m.verify_retirement(admitted,outcome,path,lambda:None)

    def test_v25_real_issuer_pipes_birth_bound_grant_and_failure_retirement(self):
        base=m.plan('a'*32,'v25-manual');ownership=m.load('sql_nosql_process_ownership.py')
        for fault in ('none','delay','wrong-command','executable-override','wrong-store','wrong-selector','source','descriptor',
                      'output-swap','uid','birth','argv','ready-invalid','ready-eof','ready-stalled',
                      'ready-expired','duplicate','close','child-failed'):
            run_id=uuid.uuid4().hex;admitted=dict(base,runId=run_id,sources=dict(base['sources']))
            directory=m.ROOT/'tasks/qualification'/('pricing-private-'+run_id);directory.mkdir(mode=0o700)
            cohort=directory/'cohort';cohort.mkdir(mode=0o700);clock=[0];events=[];held=[];timers=[]
            budget=m.RetirementBudget(profile='v25-manual',clock=lambda:clock[0]);budget.cohort_deadline()
            child=SimpleNamespace(pid=43210,returncode=None,stdin=None,stdout=io.BytesIO(),stderr=io.BytesIO())
            child.poll=lambda:child.returncode;child.wait=lambda timeout=None:events.append(('wait',timeout)) or child.returncode
            ledger={'attempts':0,'registered':[]}
            def record(row):
                if row['status']=='registered':ledger['registered'].append(child)
            def stop(*_):
                events.append('child-group-joined');child.returncode=1 if fault=='child-failed' else 0
                child.wait(timeout=1)
            processes=ownership.OwnedProcesses(stop,record)
            identity=SimpleNamespace(pid=43210,ppid=os.getpid(),uid=os.getuid(),ruid=os.getuid(),pgid=43210,start_sec=10,start_usec=1,status=0)
            identity_calls=[]
            def inspect(_):
                identity_calls.append(True)
                if fault=='birth' and len(identity_calls)>1:identity.start_usec=2
                if fault=='uid':identity.uid=os.getuid()+1
                return identity
            api=SimpleNamespace(identity=inspect,arguments=lambda _:tuple(spawner.argv()+(['extra'] if fault=='argv' else [])))
            owner=SimpleNamespace(set_cleanup_deadline=lambda _:None,inventory=SimpleNamespace(LibProc=lambda:api))
            descriptor=dict(version=1,ownerId='11111111-1111-4111-8111-111111111111',workspaceId=m.canonical_workspace_id(m.ROOT),
                qualificationNonce='0123456789ab',containerId='a'*64,imageId='sha256:'+'b'*64,packageSha256='c'*64,
                profile='dvaia-owned-pricing-http-0123456789ab',origin='http://127.0.0.1:12345',token='t'*43)
            private=SimpleNamespace(spec=SimpleNamespace(owner_id=descriptor['ownerId'],run_id=run_id),open=lambda _:descriptor,
                set_cleanup_deadline=lambda _:None,close=lambda:events.append('private-release') or dict(builderReleaseAllowed=True,bridge={'failures':[]}))
            session=m._RetainedRuntime(private,processes,owner,budget,cohort,ledger);session.open(descriptor['imageId'])
            spawner=m._V25ManualOwner(session,admitted);session.manual_owner=spawner
            env=dict(PERSONA_PRICING_NATIVE='1',PERSONA_PRICING_ACTUAL='1',PERSONA_PRICING_MANUAL_ONLY='1',
                PERSONA_PRICING_ACTUAL_REMAINING='0',PERSONA_PRICING_COHORT='baseline',PERSONA_PRICING_CANONICAL='1',PG_TEST_DISPOSABLE='yes')
            for store,family in admitted['stores'].items():
                for role in ('runtime','migration'):env['PERSONA_'+store.upper()+'_'+role.upper()+'_URL']=f'postgresql://dvaia_{family}_{role}@127.0.0.1:12345/dvaia_test_persona_0123456789ab_{store}'
            command=spawner.argv()
            child_options=dict(cwd=m.ROOT,start_new_session=True,umask=0o077,env=env)
            if fault=='executable-override':child_options['executable']='/bin/sh'
            if fault=='wrong-command':command=command+['--extra']
            if fault=='wrong-store':env['PERSONA_ACLFRESH_RUNTIME_URL']=env['PERSONA_FRESH_RUNTIME_URL']
            if fault=='wrong-selector':env['PERSONA_PRICING_ACTUAL_REMAINING']='1'
            if fault=='source':admitted['sources'][m.V25_TEST]='0'*64
            if fault=='descriptor':session.descriptor_sha256='0'*64
            if fault=='output-swap':spawner.output.rename(spawner.output.with_name('old-output'));spawner.output.mkdir(mode=0o700)
            def factory(*_args,**kwargs):
                self.assertEqual(kwargs['env']['SECURESHOP_PRICING_V25_ADMISSION_FD'],str(kwargs['pass_fds'][0]))
                held.append(os.dup(kwargs['pass_fds'][0]));ready=os.dup(kwargs['pass_fds'][1])
                try:
                    if fault not in ('ready-eof','ready-stalled'):os.write(ready,b'XX' if fault=='ready-invalid' else b'R')
                    if fault=='ready-stalled':
                        held.append(os.dup(ready));timer=m.threading.Timer(.02,lambda:clock.__setitem__(0,11));timers.append(timer);timer.start()
                finally:os.close(ready)
                if fault=='delay':clock[0]=17
                if fault=='ready-expired':clock[0]=840
                return child
            launch=processes.launch
            def registered(*args,**kwargs):ledger['attempts']+=1;return launch(*args,**kwargs,factory=factory)
            processes.launch=registered
            close=os.close;failed_close=[]
            # _close_fd removes ownership before close to avoid an unsafe retry.
            def owned_close(fd):
                close(fd)
                if fault=='close' and not failed_close:
                    failed_close.append(True);raise OSError('controlled-close')
            try:
                with patch.object(m.os,'getsid',side_effect=lambda pid:pid):
                    if fault=='close':
                        # Fail only the descriptor-validation close, after its
                        # actual close; real issuer must nevertheless retain debt.
                        with patch.object(m.os,'close',side_effect=owned_close):
                            with self.assertRaises(OSError):spawner(command,cwd=m.ROOT,start_new_session=True,umask=0o077,env=env)
                    elif fault in ('none','delay','duplicate','child-failed'):
                        returned=spawner(command,cwd=m.ROOT,start_new_session=True,umask=0o077,env=env)
                        self.assertIs(returned,child);self.assertTrue(spawner.granted)
                        raw=os.read(held[0],4097);grant=json.loads(raw)
                        self.assertLessEqual(len(raw),4096);self.assertNotIn(descriptor['token'],raw.decode())
                        self.assertEqual(grant['workerPid'],child.pid);self.assertEqual(grant['launcherPid'],os.getpid())
                        self.assertEqual(grant['outputIdentity'],spawner._directory(spawner.output))
                        self.assertEqual(grant['executorIdentity'],session.expected)
                        self.assertEqual(grant['descriptorSha256'],m.hashlib.sha256(session.descriptor_path.read_bytes()).hexdigest())
                        self.assertEqual(grant['remainingMs'],823000 if fault=='delay' else 840000)
                        if fault=='duplicate':
                            with self.assertRaisesRegex(RuntimeError,'FIXED_CHILD'):spawner(command,cwd=m.ROOT,start_new_session=True,umask=0o077,env=env)
                    else:
                        with self.assertRaises((RuntimeError,ValueError)):spawner(command,**child_options)
                    for timer in timers:timer.join()
                    # Readiness failure is not runtime absence; actual existing
                    # registrar/child join must precede private service release.
                    if fault in ('close','ready-expired'):
                        with self.assertRaisesRegex(RuntimeError,'FD_UNJOINED' if fault=='close' else 'CHILD_UNJOINED'):session.close()
                        self.assertNotIn('private-release',events)
                    else:
                        session.close();self.assertIn('private-release',events)
                        if ledger['attempts']:self.assertLess(events.index('child-group-joined'),events.index('private-release'))
                    self.assertEqual(spawner.fds,set())
            finally:
                for timer in timers:timer.join()
                for fd in held:close(fd)
                for stream in (child.stdout,child.stderr):stream.close()
                shutil.rmtree(directory)

    def test_v25_actual_issuer_to_preloaded_controlled_node_child(self):
        # Only the final fixed test target is substituted. The real issuer,
        # owned-process registrar, Darwin birth checks, FIFO ready/grant,
        # preload, receiver and no-isolation module cache all execute. The
        # existing receiver test child mocks fetch and stops before any store
        # access; this is not an original Journal/native qualification run.
        target='tests/secureshopPricingV25OwnerPreload.test.js'
        admitted=m.plan(uuid.uuid4().hex,'v25-manual')
        sources=tuple(target if name==m.V25_TEST else name for name in m.V25_SOURCES)
        admitted['manual']=dict(admitted['manual'],fixture=target)
        admitted['sources'][target]=m._file_digest(m.ROOT/target)
        directory=m.ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId']);directory.mkdir(mode=0o700)
        cohort=directory/'cohort';cohort.mkdir(mode=0o700)
        producer=m.load('run-secureshop-customer-pricing-current-host.py')
        ownership=m.load('sql_nosql_process_ownership.py')
        owner=object.__new__(producer.CurrentHostRuntime)
        owner.run=directory;owner.births={};owner.inventory=producer.load_support('darwin_process_inventory.py')
        ledger={'attempts':0,'registered':[]};events=[]
        def record(value):
            if value['status']=='registered':
                ledger['registered'].append(next(child for _,child in processes.children if child.pid==value['pid']))
            owner._record_child(value)
        processes=ownership.OwnedProcesses(owner._stop_child,record)
        original_launch=processes.launch
        def launch(*args,**kwargs):ledger['attempts']+=1;return original_launch(*args,**kwargs)
        processes.launch=launch
        budget=m.RetirementBudget(profile='v25-manual');budget.cohort_deadline()
        nonce='0123456789ab'
        descriptor=dict(version=1,ownerId='11111111-1111-4111-8111-111111111111',workspaceId=m.canonical_workspace_id(m.ROOT),
            qualificationNonce=nonce,containerId='a'*64,imageId='sha256:'+'b'*64,packageSha256='c'*64,
            profile='dvaia-owned-pricing-http-'+nonce,origin='http://127.0.0.1:12345',token='t'*43)
        private=SimpleNamespace(spec=SimpleNamespace(owner_id=descriptor['ownerId'],run_id=admitted['runId']),
            open=lambda _:descriptor,set_cleanup_deadline=lambda _:None,
            close=lambda:events.append('private-release') or dict(builderReleaseAllowed=True,bridge={'failures':[]}))
        session=m._RetainedRuntime(private,processes,owner,budget,cohort,ledger)
        child=None
        try:
            with patch.object(m,'V25_TEST',target),patch.object(m,'V25_SOURCES',sources):
                session.open(descriptor['imageId']);spawner=m._V25ManualOwner(session,admitted);session.manual_owner=spawner
                env=dict(PATH=str(producer.NODE.parent)+':/usr/bin:/bin',LANG='C',PYTHONDONTWRITEBYTECODE='1',
                    PERSONA_PRICING_NATIVE='1',PERSONA_PRICING_ACTUAL='1',PERSONA_PRICING_MANUAL_ONLY='1',
                    PERSONA_PRICING_ACTUAL_REMAINING='0',PERSONA_PRICING_COHORT='baseline',PERSONA_PRICING_CANONICAL='1',
                    PG_TEST_DISPOSABLE='yes',V25_PRELOAD_CONTROL_CHILD='1')
                for key in ('HOME','TMPDIR'):
                    folder=directory/key.lower();folder.mkdir(mode=0o700);env[key]=str(folder)
                for store,family in admitted['stores'].items():
                    for role in ('runtime','migration'):
                        env['PERSONA_'+store.upper()+'_'+role.upper()+'_URL']=f'postgresql://dvaia_{family}_{role}@127.0.0.1:12345/dvaia_test_persona_{nonce}_{store}'
                child=spawner(spawner.argv(),cwd=m.ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,start_new_session=True,umask=0o077)
                stdout,stderr=child.communicate(timeout=20)
                self.assertEqual(child.returncode,0,stderr[-2000:].decode(errors='replace'))
                self.assertLess(len(stdout)+len(stderr),65536)
                self.assertIn(b'# pass 1',stdout);self.assertTrue(spawner.granted)
                self.assertTrue((spawner.output/'pricing-actual-result.json').is_file())
                session.close()
                self.assertEqual(events,['private-release']);self.assertEqual(processes.children,[])
                self.assertFalse(owner.inventory.owned_group_members(child.pid,births=owner.births))
                self.assertEqual(admitted['sources'][target],m._file_digest(m.ROOT/target))
        finally:
            if session.manual_owner is not None:session.manual_owner.begin_retirement()
            owner.set_cleanup_deadline(budget.begin_retirement())
            processes.cleanup()
            if child is not None:
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream is not None:stream.close()
            shutil.rmtree(directory)

    def controlled_browser(self, mode=0o775):
        directory=m.ROOT/'tasks/qualification'/('pricing-browser-file-control-'+uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree,directory)
        root=directory/'Google Chrome.app';binary=root/'Contents/MacOS/Google Chrome'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'controlled browser bytes; never executed\n');binary.chmod(mode)
        inventory=m.load('admin_browser_current_main_admission.py').inventory(root)
        return binary,root,inventory

    def test_browser_only_modes_are_inventory_bound_and_generic_source_policy_unchanged(self):
        for mode in (0o755,0o775):
            binary,root,inventory=self.controlled_browser(mode)
            expected=m.hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual(m._browser_digest(binary,root,inventory),expected)
            if mode==0o775:
                with self.assertRaisesRegex(RuntimeError,'SOURCE_FILE'):m._file_digest(binary)
            else:self.assertEqual(m._file_digest(binary),expected)
            for bad in (None,{}, {'Contents/MacOS/Google Chrome':{'mode':mode,'sha256':'0'*64}},
                        {'Contents/MacOS/Google Chrome':{'mode':True,'sha256':expected}},
                        {'Contents/MacOS/Google Chrome':{'mode':mode,'sha256':expected,'extra':True}}):
                with self.assertRaises(RuntimeError):m._browser_digest(binary,root,bad)
            with self.assertRaisesRegex(RuntimeError,'PATH'):m._browser_digest(binary,root.parent,inventory)
            sibling=binary.with_name('other');sibling.write_bytes(binary.read_bytes());sibling.chmod(mode)
            with self.assertRaisesRegex(RuntimeError,'PATH'):m._browser_digest(sibling,root,inventory)
            for invalid_mode in (0o777,0o644):
                binary.chmod(invalid_mode)
                self.assertEqual(stat.S_IMODE(binary.stat().st_mode),invalid_mode)
                with self.assertRaises(RuntimeError):m._browser_digest(binary,root,inventory)
                changed=m.load('admin_browser_current_main_admission.py').inventory(root)
                with self.assertRaises(RuntimeError):m._browser_digest(binary,root,changed)
            binary.chmod(mode)
            peer=binary.with_name('hardlink');os.link(binary,peer)
            self.assertEqual(binary.stat().st_nlink,2)
            self.assertEqual(m._browser_digest(binary,root,inventory),expected)
            peer.unlink()
            binary.unlink();binary.symlink_to(sibling)
            with self.assertRaisesRegex(RuntimeError,'PATH'):m._browser_digest(binary,root,inventory)

    def test_browser_validator_owner_group_size_and_mode_drift_are_rejected(self):
        binary,root,inventory=self.controlled_browser()
        actual_fstat=os.fstat
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
        for field,value in (('st_uid',os.getuid()+1),('st_gid',max(os.getgroups()+[os.getgid(),os.getegid()])+10000),
                            ('st_size',0),('st_size',512*1024*1024+1),('st_nlink',0),
                            ('st_mode',stat.S_IFIFO|0o775),('st_mode',stat.S_IFREG|0o4775),
                            ('st_mode',stat.S_IFREG|0o2775),('st_mode',stat.S_IFREG|0o1775)):
            def fault(fd):
                first=actual_fstat(fd);row={key:getattr(first,key) for key in fields};row[field]=value
                return SimpleNamespace(**row)
            with patch.object(m.os,'fstat',side_effect=fault):
                with self.assertRaisesRegex(RuntimeError,'FILE'):m._browser_digest(binary,root,inventory)
        with patch.object(m.os,'geteuid',return_value=os.getuid()+1):
            with self.assertRaisesRegex(RuntimeError,'FILE'):m._browser_digest(binary,root,inventory)
        for field in ('st_uid','st_gid','st_nlink','st_ino','st_mode'):
            calls=[]
            def drift(fd):
                first=actual_fstat(fd);calls.append(True)
                if len(calls)==1:return first
                row={key:getattr(first,key) for key in fields};row[field]+=1
                return SimpleNamespace(**row)
            with patch.object(m.os,'fstat',side_effect=drift):
                with self.assertRaisesRegex(RuntimeError,'CHANGED'):m._browser_digest(binary,root,inventory)

    def test_browser_validator_actual_rename_mutation_open_flags_and_close_failure(self):
        for fault in ('rename','mutation','close','read-and-close'):
            binary,root,inventory=self.controlled_browser()
            actual_read=os.read;actual_open=os.open;actual_close=os.close;fds=[];reads=[];closed=[]
            def opened(path,flags,*args):
                self.assertEqual(Path(path),binary)
                self.assertTrue(flags&os.O_NOFOLLOW);self.assertTrue(flags&os.O_NONBLOCK)
                fd=actual_open(path,flags,*args);fds.append(fd);return fd
            def read(fd,size):
                if fault=='read-and-close':raise RuntimeError('CONTROLLED_READ_PRIMARY')
                raw=actual_read(fd,size)
                if raw and not reads:
                    reads.append(True)
                    if fault=='rename':
                        binary.rename(binary.with_name('original'))
                        binary.write_bytes(raw);binary.chmod(0o775)
                    elif fault=='mutation':binary.write_bytes(b'changed browser bytes\n')
                return raw
            def close(fd):
                closed.append(fd);actual_close(fd)
                if fault in ('close','read-and-close'):raise OSError('CONTROLLED_CLOSE_FAILURE')
            with patch.object(m.os,'open',side_effect=opened),patch.object(m.os,'read',side_effect=read),patch.object(m.os,'close',side_effect=close):
                if fault=='close':
                    with self.assertRaisesRegex(OSError,'CLOSE_FAILURE'):m._browser_digest(binary,root,inventory)
                else:
                    with self.assertRaisesRegex(RuntimeError,'READ_PRIMARY' if fault=='read-and-close' else 'CHANGED'):
                        m._browser_digest(binary,root,inventory)
            self.assertEqual(closed,fds)
            for fd in fds:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_v34_browser_plan_recomputes_actual_main_closure_and_preserves_v33(self):
        binary,root,inventory=self.controlled_browser()
        inputs=dict(node=str(m.ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
            browser=str(binary),browserRoot=str(root),embeddingCache=str(m.ROOT/'tasks'))
        calls=[];original_load=m.load
        main=SimpleNamespace(PRICING_V34_BROWSER='original-v34-controlled-selector',
            source_snapshot=lambda *args,**kwargs:calls.append((args,kwargs)) or {'sourcePins':{'controlled':'a'*64},'browserInventory':inventory})
        with patch.object(m,'load',side_effect=lambda name:main if name=='run-secureshop-agent-host-transport-main.py' else original_load(name)):
            browser=m.capture_v34_browser(inputs)
            self.assertEqual(calls[0][0],(m.ROOT,inputs['node'],main.PRICING_V34_BROWSER))
            self.assertEqual(calls[0][1],dict(browser_root=root,embedding_cache=m.ROOT/'tasks'))
            self.assertEqual(browser['value']['browserSha256'],inventory['Contents/MacOS/Google Chrome']['sha256'])
            self.assertEqual(browser['value']['ownerSources'][m.V34_TEST],m._file_digest(m.ROOT/m.V34_TEST))
            admitted=m.plan('a'*32,'v34-browser',browser_inputs=inputs)
            self.assertEqual(admitted['browser'],browser)
            self.assertFalse(admitted['browserAdmission']);self.assertFalse(admitted['eligible'])
            with patch.object(m,'BuilderChannel') as launch:
                admitted['browser']['sha256']='0'*64
                with self.assertRaisesRegex(RuntimeError,'SOURCE'):m._execute_owned(admitted,'v34-browser',lambda _:None)
                launch.assert_not_called()
            for bad in ({},dict(inputs,extra='x'),dict(inputs,node='/tmp/node'),dict(inputs,browserRoot='/tmp')):
                with self.assertRaises(RuntimeError):m.capture_v34_browser(bad)
        v33=m.plan('a'*32);self.assertNotIn('browser',v33)
        with self.assertRaisesRegex(RuntimeError,'PROFILE'):m.plan('a'*32,browser_inputs=inputs)

    def test_fixed_v34_browser_owner_actual_capture_ack_and_retirement_precede_private_release(self):
        # Execute the actual owner, registrar, V36 birth/group primitives and
        # retained close. Only OS identities/signals and Popen are controlled.
        for fault in ('none','node-failed','wrong-command','browser-changed','browser-mode','browser-close','no-birth','wrong-profile','changed-birth','profile-swap','pending-watcher','expiry','duplicate','ready-delay','ready-expired','ready-invalid','ready-eof','ready-stalled'):
            run_id=uuid.uuid4().hex;directory=m.ROOT/'tasks/qualification'/('pricing-private-'+run_id)
            directory.mkdir(mode=0o700);cohort=directory/'cohort';cohort.mkdir(mode=0o700)
            events=[];clock=[0];budget=m.RetirementBudget(profile='v34-browser',clock=lambda:clock[0]);budget.cohort_deadline()
            ledger={'attempts':0,'registered':[]};ownership=m.load('sql_nosql_process_ownership.py')
            child=SimpleNamespace(pid=43210,returncode=None,stdin=None,stdout=None,stderr=None)
            child.poll=lambda:child.returncode
            child.wait=lambda timeout=None:events.append(('wait',timeout)) or 0
            def record(row):
                if row['status']=='registered':ledger['registered'].append(child)
            def stop(*_):child.returncode=1 if fault=='node-failed' else 0;events.append('node-joined')
            processes=ownership.OwnedProcesses(stop,record)
            owner=SimpleNamespace(set_cleanup_deadline=lambda _:None)
            descriptor=dict(version=1,ownerId='11111111-1111-4111-8111-111111111111',workspaceId=m.canonical_workspace_id(m.ROOT),
                qualificationNonce='0123456789ab',containerId='a'*64,imageId='sha256:'+'b'*64,packageSha256='c'*64,
                profile='dvaia-owned-pricing-http-0123456789ab',origin='http://127.0.0.1:12345',token='t'*43)
            private=SimpleNamespace(open=lambda _:descriptor,set_cleanup_deadline=lambda _:None,
                close=lambda:events.append('private-release') or dict(builderReleaseAllowed=True,bridge={'failures':[]}))
            session=m._RetainedRuntime(private,processes,owner,budget,cohort,ledger);session.open(descriptor['imageId'])
            binary,app_root,inventory=self.controlled_browser()
            browser=str(binary);node=str(m.ROOT/'tasks/runtime/node/node_modules/node/bin/node');python=str(Path(sys.executable).resolve())
            admitted=dict(runId=run_id,browser=dict(sha256='d'*64,value=dict(inputs=dict(node=node,browser=browser,browserRoot=str(app_root)),
                snapshot={'browserInventory':inventory},nodeSha256=m._file_digest(node),
                browserSha256=m._browser_digest(binary,app_root,inventory),python=python,pythonSha256=m._file_digest(python))))
            state={'gone':False,'changed':False};read_fds=[];timers=[];actual_load=m.load;module=actual_load('run-secureshop-audit-collection-browser.py')
            node_identity=SimpleNamespace(pid=43210,ppid=os.getpid(),uid=os.getuid(),ruid=os.getuid(),pgid=43210,start_sec=10,start_usec=2,status=0)
            def identity(pid):
                if pid==43210:
                    if fault=='ready-expired':clock[0]=1000
                    if fault=='ready-stalled':
                        timer=m.threading.Timer(.02,lambda:clock.__setitem__(0,1000));timers.append(timer);timer.start()
                    return node_identity
                if state['gone']:return None
                return SimpleNamespace(pid=43211,ppid=43210,uid=os.getuid(),ruid=os.getuid(),pgid=43211,
                    start_sec=21 if state['changed'] else 20,start_usec=3,status=0)
            api=SimpleNamespace(identity=identity,arguments=lambda _:[browser,'--user-data-dir='+str(spawner.profile)],
                group_pids=lambda _:[] if state['gone'] else [43211])
            original_modules=module._browser_modules();modules=(lambda:api,*original_modules[1:])
            def kill(*_):events.append('browser-retire');state['gone']=True
            def factory(*args,**kwargs):
                read_fds.append(os.dup(kwargs['pass_fds'][0]))
                ready=os.dup(kwargs['pass_fds'][1])
                try:
                    if fault not in ('ready-eof','ready-stalled'):os.write(ready,b'XX' if fault=='ready-invalid' else b'R')
                    if fault=='ready-stalled':read_fds.append(os.dup(ready))
                finally:os.close(ready)
                if fault=='ready-delay':clock[0]=17
                spawner.profile.mkdir(mode=0o700)
                if fault=='wrong-profile':api.arguments=lambda _:[browser,'--user-data-dir='+str(spawner.profile.parent/'dvaia-pricing-chat-sibling')]
                if fault!='no-birth':
                    m.exclusive_record(spawner.directory/'browser-birth.json',dict(schemaVersion=2,processes=[dict(kind='pricing_v34_browser',
                        pid=43211,parentPid=43210,uid=os.getuid(),pgid=43211,sessionId=43211,birth=[20,3],
                        executablePath=browser,executableSha256=admitted['browser']['value']['browserSha256'])]))
                return child
            launch=processes.launch
            def recorded(*args,**kwargs):ledger['attempts']+=1;return launch(*args,**kwargs,factory=factory)
            processes.launch=recorded
            try:
                with patch.object(m,'load',side_effect=lambda name:module if name=='run-secureshop-audit-collection-browser.py' else actual_load(name)), \
                        patch.object(module,'_browser_modules',return_value=modules),patch.object(m.os,'getsid',side_effect=lambda pid:pid),patch.object(m.os,'killpg',side_effect=kill):
                    # Existing primitive defaults hold their original getsid;
                    # pass controlled identity lookup explicitly, not fake capture.
                    capture=module.capture_live_v36;retire=module.retire_live_v36
                    module.capture_live_v36=lambda *args,**kwargs:capture(*args,**kwargs,getsid=lambda pid:pid)
                    module.retire_live_v36=lambda *args,**kwargs:retire(*args,**kwargs,getsid=lambda pid:pid)
                    spawner=m._V34BrowserOwner(session,admitted);session.browser_owner=spawner
                    command=[node,'--test','--test-isolation=none','--test-reporter=tap','--test-concurrency=1',m.V34_TEST]
                    kwargs=dict(cwd=m.ROOT,start_new_session=True,pass_fds=(),umask=0o077,
                        env={'SECURESHOP_PRICING_V34_MANUAL_EXPERIMENT_NATIVE':'1','PUPPETEER_EXECUTABLE_PATH':browser})
                    if fault=='wrong-command':
                        with self.assertRaisesRegex(RuntimeError,'FIXED_CHILD'):spawner(command+['--extra'],**kwargs)
                        self.assertEqual(ledger['attempts'],0);session.close();self.assertIn('private-release',events);continue
                    if fault in ('browser-changed','browser-mode','browser-close'):
                        if fault=='browser-changed':binary.write_bytes(b'replaced executable\n')
                        if fault=='browser-mode':binary.chmod(0o755)
                        opened=[];actual_open=os.open;actual_close=os.close
                        def open_browser(path,*args):
                            fd=actual_open(path,*args)
                            if Path(path)==binary:opened.append(fd)
                            return fd
                        def close_browser(fd):
                            actual_close(fd)
                            if fd in opened:raise OSError('CONTROLLED_BROWSER_CLOSE')
                        with patch.object(m.os,'open',side_effect=open_browser),patch.object(m.os,'close',side_effect=close_browser if fault=='browser-close' else actual_close):
                            with self.assertRaises((RuntimeError,OSError)):spawner(command,**kwargs)
                        self.assertEqual(ledger['attempts'],0);self.assertFalse(spawner.attempted);self.assertFalse(spawner.fds)
                        session.close();self.assertIn('private-release',events);continue
                    if fault in ('ready-expired','ready-invalid','ready-eof','ready-stalled'):
                        with self.assertRaises(RuntimeError):spawner(command,**kwargs)
                        self.assertIs(session.child,child);self.assertFalse(spawner.fds)
                        self.assertEqual(os.read(read_fds[0],4097),b'')
                        with self.assertRaisesRegex(RuntimeError,'BIRTH_UNPROVEN'):session.close()
                        self.assertNotIn('private-release',events);continue
                    self.assertIs(spawner(command,**kwargs),child)
                    raw=os.read(read_fds[0],4097);self.assertEqual(json.loads(raw)['remainingMs'],983000 if fault=='ready-delay' else 1000000)
                    clock[0]=17;child.wait(timeout=1000);self.assertIn(('wait',983),events)
                    if fault=='duplicate':
                        with self.assertRaisesRegex(RuntimeError,'FIXED_CHILD'):spawner(command,**kwargs)
                        self.assertEqual(ledger['attempts'],1)
                    if fault not in ('no-birth',):
                        end=time.monotonic()+2
                        while not spawner.acknowledged and spawner.error is None and time.monotonic()<end:time.sleep(.01)
                    if fault=='changed-birth':state['changed']=True
                    if fault=='profile-swap':
                        spawner.profile.rename(spawner.profile.with_name('saved-sibling'));spawner.profile.mkdir(mode=0o700)
                    if fault=='pending-watcher':
                        spawner.watcher.join(timeout=2)
                        spawner.watcher=SimpleNamespace(join=lambda **_:None,is_alive=lambda:True)
                    if fault=='expiry':clock[0]=3017
                    if fault in ('no-birth','wrong-profile','changed-birth','profile-swap','pending-watcher','expiry'):
                        with self.assertRaises(RuntimeError):session.close()
                        self.assertNotIn('private-release',events)
                    else:
                        session.close();self.assertTrue(spawner.retired);self.assertFalse(spawner.profile.exists())
                        self.assertLess(events.index('node-joined'),events.index('browser-retire'))
                        self.assertLess(events.index('browser-retire'),events.index('private-release'))
            finally:
                if 'spawner' in locals():
                    spawner.stopped.set()
                    if isinstance(spawner.watcher,m.threading.Thread):spawner.watcher.join(timeout=2)
                for fd in read_fds:os.close(fd)
                for timer in timers:timer.join(timeout=1)
                shutil.rmtree(directory)

    def test_v34_failed_lesson_retirement_requires_actual_terminal_join(self):
        directory=m.ROOT/'tasks/qualification'/('pricing-terminal-control-'+uuid.uuid4().hex);directory.mkdir(mode=0o700)
        admitted=m.plan('b'*32,'v34-browser');owner_sha=m.hashlib.sha256(m.json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        outcome=dict(version=2,passed=False,cleanupVerified=True,ownerPlanSha256=owner_sha,nodePlanSha256='a'*64,
            cleanupErrors=[],sourceMatched=True,consumerProfile='v34-browser',qualificationComplete=False,errorType='AssertionError')
        path=directory/'result.json'
        try:
            identity=m.exclusive_record(path,{'passed':False});digest=m.publish_result(path,identity,outcome)
            result=dict(outcome,terminalJoin=dict(version=1,candidateSha256=digest,withinOriginalDeadline=True,
                ownerPlanSha256=owner_sha,nodePlanSha256='a'*64))
            self.assertTrue(m.verify_retirement(admitted,result,path,lambda:None))
            with self.assertRaises(RuntimeError):m.verify_terminal(admitted,result,path,lambda:None)
            for key,value in [('cleanupVerified',False),('sourceMatched',False),('qualificationComplete',True),('passed',1),('extra',True)]:
                with self.assertRaises(RuntimeError):m.verify_retirement(admitted,dict(result,**{key:value}),path,lambda:None)
            with self.assertRaises(RuntimeError):m.verify_retirement(admitted,outcome,path,lambda:None)
        finally:shutil.rmtree(directory)

    def test_v34_plan_and_deadline_are_closed_and_nonrenewing_before_startup(self):
        self.assertTrue(m.V34_LIVE_ENABLED)
        admitted=m.plan('b'*32,'v34-browser')
        self.assertEqual((admitted['totalSeconds'],admitted['cohortSeconds'],admitted['retirementSeconds']),(3016,1000,600))
        self.assertFalse(admitted['eligible']);self.assertFalse(admitted['browserAdmission'])
        with patch.object(m,'V34_LIVE_ENABLED',False),patch.object(m,'_execute_owned') as execute:
            with self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):m.with_retained_session(admitted,lambda _:None)
            execute.assert_not_called()
        with patch.object(m,'_execute_owned') as execute:
            for malformed in (None,{},admitted):
                with self.assertRaisesRegex(RuntimeError,'BROWSER_PLAN_REQUIRED'):m.with_retained_session(malformed,lambda _:None)
            execute.assert_not_called()
        self.assertEqual(m.builder_argv('v34-browser'),m.builder_argv()+['--v34-retained-session'])
        for profile in (None,{},'v34',3016):
            with self.assertRaises(RuntimeError):m.plan('b'*32,profile)
        clock=[0];budget=m.RetirementBudget(profile='v34-browser',clock=lambda:clock[0])
        clock[0]=1416;end=budget.cohort_deadline();self.assertEqual(end,2416)
        clock[0]=1450
        with self.assertRaisesRegex(RuntimeError,'NONRENEWAL'):budget.cohort_deadline()
        self.assertEqual(budget.child_until,end)
        clock[0]=2416;self.assertEqual(budget.begin_retirement(),3016)
        clock[0]=2500;self.assertEqual(budget.begin_retirement(),3016)
        clock[0]=3016
        with self.assertRaisesRegex(RuntimeError,'EXPIRED'):budget.remaining(1)

    def test_retained_runtime_actual_registrar_distinguishes_no_launch_and_pending_child(self):
        # Execute the real registrar/session; doubles replace only OS effects.
        ownership=m.load('sql_nosql_process_ownership.py')
        for fault in ('none','real-child','no-launch','attempt-only','unbound','duplicate','stop','pipe','expiry','startup'):
            directory=m.ROOT/'tasks/qualification'/('pricing-session-control-'+uuid.uuid4().hex)
            directory.mkdir(mode=0o700);events=[];clock=[0]
            budget=m.RetirementBudget(profile='v34-browser',clock=lambda:clock[0]);budget.cohort_deadline()
            ledger={'attempts':0,'registered':[]}
            def record(value):
                if value['status']=='registered':ledger['registered'].append(next(child for _,child in processes.children if child.pid==value['pid']))
            def stop(child,*_):
                events.append('child-group-join')
                if fault=='stop':raise RuntimeError('unjoined')
                if fault=='real-child':
                    child.wait(timeout=5)
                    with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
                    return
                child.returncode=0
            processes=ownership.OwnedProcesses(stop,record)
            owner=SimpleNamespace(set_cleanup_deadline=lambda until:events.append(('deadline',until)))
            descriptor=dict(version=1,ownerId='11111111-1111-4111-8111-111111111111',workspaceId=m.canonical_workspace_id(m.ROOT),
                qualificationNonce='0123456789ab',containerId='a'*64,imageId='sha256:'+'b'*64,packageSha256='c'*64,
                profile='dvaia-owned-pricing-http-0123456789ab',origin='http://127.0.0.1:12345',token='t'*43)
            def opened(_):
                events.append('start')
                self.assertEqual(budget.child_until,1000)
                if fault=='startup':raise RuntimeError('lost-start-ack')
                return descriptor
            private=SimpleNamespace(open=opened,set_cleanup_deadline=lambda until:events.append(('private-deadline',until)),
                close=lambda:events.append('private-close') or dict(builderReleaseAllowed=True,bridge={'failures':[]}))
            session=m._RetainedRuntime(private,processes,owner,budget,directory,ledger)
            child=None
            try:
                if fault=='startup':
                    with self.assertRaisesRegex(RuntimeError,'lost-start'):session.open(descriptor['imageId'])
                    session.close();self.assertIn('private-close',events);continue
                session.open(descriptor['imageId'])
                self.assertEqual(session.deadline,1000)
                self.assertEqual(session.descriptor_sha256,m.hashlib.sha256(session.descriptor_path.read_bytes()).hexdigest())
                if fault=='no-launch':
                    session.close();self.assertIn('private-close',events);continue
                if fault=='attempt-only':
                    ledger['attempts']+=1
                    with self.assertRaisesRegex(RuntimeError,'UNJOINED'):session.close()
                    self.assertNotIn('private-close',events);continue
                ledger['attempts']+=1
                if fault=='real-child':
                    child=processes.launch([sys.executable,'-B','-c','print("controlled child only")'],name='v34-browser',
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,cwd=m.ROOT)
                else:
                    child=SimpleNamespace(pid=43210,returncode=None,stdin=io.BytesIO(),stdout=io.BytesIO(),stderr=io.BytesIO())
                    child.poll=lambda:child.returncode
                    processes.launch(['controlled-only'],name='v34-browser',factory=lambda *_a,**_k:child,start_new_session=True)
                if fault!='unbound':session.bind_child(child)
                if fault=='duplicate':
                    with self.assertRaisesRegex(RuntimeError,'OWNERSHIP'):session.bind_child(child)
                    self.assertIs(session.child,child)
                if fault=='pipe':
                    class Broken(io.BytesIO):
                        def close(self):raise OSError('pipe-close')
                    child.stdin=Broken()
                if fault=='expiry':clock[0]=3017
                if fault in ('unbound','stop','pipe','expiry'):
                    with self.assertRaises(RuntimeError):session.close()
                    self.assertNotIn('private-close',events)
                    if fault=='pipe':self.assertTrue(child.stdout.closed and child.stderr.closed)
                else:
                    session.close();self.assertTrue(session.joined)
                    self.assertTrue(all(stream.closed for stream in (child.stdin,child.stdout,child.stderr)))
                    self.assertLess(events.index('child-group-join'),events.index('private-close'))
            finally:
                if child is not None:
                    for stream in (child.stdin,child.stdout,child.stderr):
                        try:
                            if isinstance(stream,io.BytesIO):io.BytesIO.close(stream)
                            else:stream.close()
                        except OSError:pass
                shutil.rmtree(directory)

    def test_retained_shared_owner_protocol_joins_runtime_before_builder_without_v33_cohort(self):
        ownership=m.load('sql_nosql_process_ownership.py')
        original=m.load('run-secureshop-customer-pricing-current-host.py')
        common=(None,'before-spawn','lost-publish','startup','startup-unjoined','registration-error','unbound','pending','cross-profile','builder-debt')
        cases=[('v34-browser',fault) for fault in common+('browser-success','browser-failed','browser-debt')]+[('v25-manual',fault) for fault in common+('lesson-failed','manual-debt')]
        for profile,fault in cases:
            run_id=uuid.uuid4().hex;admitted=m.plan(run_id,profile)
            browser_case=bool(fault and fault.startswith('browser-'))
            browser_packet=dict(value={'inputs':{'controlled':True}},sha256='c'*64)
            if browser_case:admitted['browser']=browser_packet
            directory=m.ROOT/'tasks/qualification'/('pricing-private-'+run_id);events=[]
            class Owner:
                def _record_child(self,value):
                    events.append(value['status'])
                    if fault=='registration-error' and value['status']=='registered':raise RuntimeError('REGISTRATION_IO')
                def _stop_child(self,child,*_):events.append('join-child');child.returncode=0
                def set_cleanup_deadline(self,value):events.append('retirement-clock')
            producer=SimpleNamespace(CurrentHostRuntime=Owner,NODE=original.NODE,DAEMON=original.DAEMON,
                IDENTITY_KEYS=original.IDENTITY_KEYS,validate_descriptor=original.validate_descriptor,
                load_support=lambda name:ownership if name=='sql_nosql_process_ownership.py' else object())
            class Private:
                def __init__(self,spec,mux,processes,env,until,token):
                    self.spec=spec;self.token=token;self.until=until;self.processes=processes
                    self.outer=spec.root
                def open(self,image_id):
                    events.append('runtime-start')
                    if fault=='startup':raise RuntimeError('STARTUP_ACK_LOST')
                    if fault=='startup-unjoined':
                        child=SimpleNamespace(pid=43211,returncode=None,stdin=None,stdout=io.BytesIO(),stderr=io.BytesIO())
                        child.poll=lambda:child.returncode;children.append(child)
                        self.processes.launch(['controlled-only'],name='partial-start',factory=lambda *_a,**_k:child,start_new_session=True)
                        raise RuntimeError('STARTUP_ACK_LOST')
                    return dict(version=1,ownerId=self.spec.owner_id,workspaceId=self.spec.workspace_id,
                        qualificationNonce=self.spec.qualification_nonce,containerId='a'*64,imageId=image_id,packageSha256='c'*64,
                        profile='dvaia-owned-pricing-http-'+self.spec.qualification_nonce,origin='http://127.0.0.1:12345',token=self.token)
                def set_cleanup_deadline(self,value):events.append('runtime-deadline')
                def close(self):events.append('runtime-close');return dict(builderReleaseAllowed=True,bridge={'failures':[]})
            def spec(root,run,owner,workspace,nonce,daemon,holder_contract):
                self.assertEqual(holder_contract,m.profile_values(profile)[2])
                return SimpleNamespace(root=root,owner_id=owner,workspace_id=workspace,qualification_nonce=nonce)
            modules={'run-secureshop-customer-pricing-current-host.py':producer,
                'pricing_private_cohort.py':SimpleNamespace(_consume=lambda *_a,**_k:self.fail('V33 cohort must not run')),
                'pricing_owned_provisioning.py':SimpleNamespace(PricingSpec=spec,PrivateRuntimeComponents=Private),
                'owned_mcp_mux_relay.py':object()}
            class Channel:
                def __init__(self,*_):
                    self.stage=0;self.child=SimpleNamespace(wait=lambda **_:events.append('builder-wait'),returncode=0)
                def send(self,value,deadline):
                    events.append(value['verb'])
                    if value['verb']=='admit':
                        self.binding={k:value[k] for k in ('version','runId','ownerPlanSha256','consumerProfile')}
                        self.binding['nodePlanSha256']='a'*64
                        self_test.assertEqual(value['consumerProfile'],profile)
                def receive(self,deadline):
                    self.stage+=1
                    if self.stage==1:
                        value=dict(self.binding,verb='ready',sources={k:v for k,v in admitted['sources'].items() if k!='tests/postgres/owned_mcp_mux_relay.py'},packageSha256=admitted['originalPackage']['sha256'])
                        if fault=='cross-profile':value['consumerProfile']='v33'
                        return value
                    if self.stage==2:return dict(self.binding,verb='image',observed={'runId':run_id,'packageDigest':admitted['originalPackage']['sha256'],'sharedDaemonId':original.DAEMON,'imageId':'sha256:'+'b'*64})
                    if self.stage==3:
                        if fault=='lost-publish':raise RuntimeError('PUBLISH_ACK_LOST')
                        return dict(self.binding,verb='published')
                    if self.stage==4:return dict(self.binding,verb='retirement-ready')
                    return dict(self.binding,verb='terminal',result=dict(version=1,target='original-v33-pricing',controlled=True,buildCompleted=True,cleanupVerified=fault!='builder-debt',qualificationComplete=False,runtimeAvailable=False,failure=None,cleanupErrors=[]))
                def close(self):events.append('channel-close')
            self_test=self
            children=[]
            class Browser:
                error=None;acknowledged=True
                def __init__(self,*_):pass
                def close(self):
                    events.append('browser-close')
                    if fault=='browser-debt':raise RuntimeError('BROWSER_UNJOINED')
            class Manual:
                granted=True
                def __init__(self,*_):pass
                def begin_retirement(self):events.append('manual-retirement')
                def close(self):
                    events.append('manual-closed')
                    if fault=='manual-debt':raise RuntimeError('MANUAL_FD_UNJOINED')
            def consumer(session):
                self.assertIsNotNone(session.budget.child_until)
                self.assertEqual(session.deadline,session.private.until)
                with self.assertRaisesRegex(RuntimeError,'NONRENEWAL'):session.budget.cohort_deadline()
                if fault=='before-spawn':raise RuntimeError('BEFORE_SPAWN')
                child=SimpleNamespace(pid=43210,returncode=None,stdin=io.BytesIO(),stdout=io.BytesIO(),stderr=io.BytesIO())
                child.poll=lambda:child.returncode;children.append(child)
                session.processes.launch(['controlled-only'],name='v34-browser',factory=lambda *_a,**_k:child,start_new_session=True)
                if fault!='unbound':session.bind_child(child)
                if browser_case:child.returncode=1 if fault=='browser-failed' else 0
                if profile=='v25-manual':child.returncode=0
                if fault=='pending':return object()
                if fault=='lesson-failed':raise RuntimeError('ORIGINAL_MANUAL_SEMANTIC_FAILURE')
            try:
                with patch.object(m,'load',side_effect=lambda name:modules[name]),patch.object(m,'BuilderChannel',Channel), \
                        patch.object(m,'capture_v34_browser',return_value=browser_packet),patch.object(m,'_V34BrowserOwner',Browser), \
                        patch.object(m,'_V25ManualOwner',Manual):
                    if fault and fault!='browser-success':
                        with self.assertRaises(RuntimeError) as raised:m._execute_owned(admitted,profile,consumer)
                        result=raised.exception.result;self.assertFalse(result['passed'])
                        if fault=='lesson-failed':self.assertEqual(str(raised.exception),'ORIGINAL_MANUAL_SEMANTIC_FAILURE')
                    else:result=m._execute_owned(admitted,profile,consumer);self.assertTrue(result['passed'])
                self.assertFalse(result['qualificationComplete'])
                if fault in (None,'before-spawn','startup','browser-success','browser-failed','lesson-failed'):
                    self.assertTrue(result['cleanupVerified']);self.assertLess(events.index('runtime-close'),events.index('consumer-retired'))
                    if fault is None:self.assertLess(events.index('join-child'),events.index('runtime-close'))
                    if browser_case:
                        self.assertLess(events.index('browser-close'),events.index('runtime-close'))
                        self.assertEqual(result['passed'],fault=='browser-success')
                else:self.assertFalse(result['cleanupVerified'])
                if fault in ('unbound','pending','lost-publish','cross-profile','startup-unjoined','registration-error','browser-debt','manual-debt'):
                    self.assertNotIn('consumer-retired',events)
                    self.assertNotIn('runtime-close',events)
                self.assertIn('channel-close',events)
            finally:
                for child in children:
                    for stream in (child.stdin,child.stdout,child.stderr):
                        if stream is not None:stream.close()
                if directory.exists():shutil.rmtree(directory)

    def test_canonical_workspace_passes_real_descriptor_executor_boundary(self):
        workspace=m.canonical_workspace_id(m.ROOT)
        script=r"""const fs=require('fs'),path=require('path'),crypto=require('crypto');
const fixture=require('./tests/postgres/secureshopCustomerPricingActual.integration.test');
const root=process.cwd(),workspace=process.argv[1];
require('assert/strict').equal(workspace,require('./scripts/application-data-root').workspaceId(root));
const dir=fs.mkdtempSync(path.join(root,'tasks/qualification/workspace-control-'));
(async()=>{let calls=0;const old=global.fetch;
try{for(const invalid of [false,true]){
 const d={version:1,ownerId:'11111111-1111-4111-8111-111111111111',workspaceId:invalid?'000000000000':workspace,qualificationNonce:'0123456789ab',containerId:'a'.repeat(64),imageId:'sha256:'+'b'.repeat(64),packageSha256:'c'.repeat(64),profile:'dvaia-owned-pricing-http-0123456789ab',origin:'http://127.0.0.1:12345',token:'t'.repeat(43)};
 const file=path.join(dir,invalid?'bad.json':'good.json'),bytes=JSON.stringify(d);fs.writeFileSync(file,bytes,{mode:0o600,flag:'wx'});
 const {version,token,...expected}=d;
 global.fetch=async()=>{calls++;return new Response(JSON.stringify({version:require('./sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}),{status:200});};
 const open=()=>fixture.openAdmittedPricingExecutor({descriptorPath:file,descriptorSha256:crypto.createHash('sha256').update(bytes).digest('hex'),expected,signal:new AbortController().signal});
 if(invalid)await require('assert/strict').rejects(open,{code:'ERR_ASSERTION'});
 else{const executor=await open();await executor.close();require('assert/strict').equal(executor.retirement().localClientClosed,true);}
}require('assert/strict').equal(calls,1);process.stdout.write('boundary-ok');
}finally{global.fetch=old;fs.rmSync(dir,{recursive:true});}})().catch(e=>{process.stderr.write(String(e.stack));process.exitCode=1;});"""
        result=subprocess.run([str(m.ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',script,workspace],cwd=m.ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'boundary-ok')

    def setUp(self):
        value={'controlledOriginalClosure':True}
        self.snapshot=dict(value=value,sha256=m.hashlib.sha256(m.json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        capture=patch.object(m,'capture_snapshot',return_value=self.snapshot)
        capture.start();self.addCleanup(capture.stop)

    def test_actual_node_plan_source_map_equals_owner_admission_except_mux(self):
        run_id='b'*32
        child=subprocess.run([str(m.ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',
            "require('./tests/postgres/ownedPricingBuildAdapter').pricingBuildPlan(process.cwd(),process.argv[1]).then(p=>process.stdout.write(JSON.stringify(p.inputs.sources))).catch(()=>process.exit(1))",run_id],
            cwd=m.ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
        self.assertLess(len(child.stdout),65536)
        actual=json.loads(child.stdout)
        admitted=m.plan(run_id)['sources']
        expected={k:v for k,v in admitted.items() if k!='tests/postgres/owned_mcp_mux_relay.py'}
        self.assertEqual(actual,expected)
        policy='tests/postgres/ownedPricingEgressPolicy.js'
        self.assertEqual(actual[policy],m.hashlib.sha256((m.ROOT/policy).read_bytes()).hexdigest())
        for change in ('missing','wrong','extra'):
            tampered=dict(expected)
            if change=='missing':tampered.pop(policy)
            elif change=='wrong':tampered[policy]='0'*64
            else:tampered['unowned.js']='0'*64
            self.assertNotEqual(actual,tampered)

    def test_publication_failure_never_replaces_failed_placeholder(self):
        for failure in ('fsync','close','identity','expiry',None):
            directory=m.ROOT/'tasks/qualification'/('pricing-publication-control-'+uuid.uuid4().hex)
            directory.mkdir(mode=0o700);path=directory/'result.json'
            try:
                identity=m.exclusive_record(path,{'passed':False})
                if failure=='identity':identity=(identity[0],identity[1]+1)
                if failure in ('fsync','close'):
                    original=getattr(os,failure)
                    def injected(fd):
                        if failure=='close':original(fd)
                        raise OSError('injected')
                    with patch.object(m.os,failure,side_effect=injected):
                        with self.assertRaises(OSError):m.publish_result(path,identity,{'passed':True})
                elif failure=='expiry':
                    checks=[]
                    def check():
                        checks.append(True)
                        if len(checks)==2:raise RuntimeError('EXPIRED')
                    with self.assertRaisesRegex(RuntimeError,'EXPIRED'):m.publish_result(path,identity,{'passed':True},check)
                elif failure:
                    with self.assertRaisesRegex(RuntimeError,'IDENTITY'):m.publish_result(path,identity,{'passed':True})
                else:m.publish_result(path,identity,{'passed':True})
                packet=json.loads(path.read_text());self.assertIs(packet['passed'],False)
                if failure is None:self.assertIs(packet['sealed'],False);self.assertIs(packet['candidateOutcome']['passed'],True)
            finally:shutil.rmtree(directory)

    def test_delayed_publication_never_leaves_standalone_success(self):
        for operation in ('replace','fsync'):
            directory=m.ROOT/'tasks/qualification'/('pricing-publication-control-'+uuid.uuid4().hex)
            directory.mkdir(mode=0o700);path=directory/'result.json';clock=[0]
            try:
                identity=m.exclusive_record(path,{'passed':False})
                original=getattr(m.os,operation)
                def delayed(*args):
                    value=original(*args);clock[0]=11;return value
                def check():
                    if clock[0]>=10:raise RuntimeError('EXPIRED')
                with patch.object(m.os,operation,side_effect=delayed):
                    with self.assertRaisesRegex(RuntimeError,'EXPIRED'):m.publish_result(path,identity,{'passed':True},check)
                packet=json.loads(path.read_text());self.assertIs(packet['passed'],False)
                if 'candidateOutcome' in packet:self.assertIs(packet['sealed'],False)
            finally:shutil.rmtree(directory)

    def test_actual_owner_orchestration_binds_both_plans_and_requires_retirement(self):
        for failure in (None,'consumer-debt','builder-debt','empty-sources','extra-ready','terminal-debt'):
            run_id=uuid.uuid4().hex;admitted=m.plan(run_id);directory=m.ROOT/'tasks/qualification'/('pricing-private-'+run_id);events=[]
            class Runtime:
                def _stop_child(self,*a):pass
                def _record_child(self,*a):pass
                def set_cleanup_deadline(self,value):events.append('deadline')
            processes=SimpleNamespace(install=lambda:None,cleanup=lambda:events.append('process-cleanup'),restore=lambda:events.append('restore'))
            ownership=SimpleNamespace(OwnedProcesses=lambda *a:processes)
            producer=SimpleNamespace(CurrentHostRuntime=Runtime,NODE=m.ROOT/'tasks/runtime/node/node_modules/node/bin/node',DAEMON='shared',load_support=lambda name:ownership if name=='sql_nosql_process_ownership.py' else object(),full_snapshot=lambda:{'original':True},private_json=lambda file,value:None)
            def consume(*args,**kw):
                events.append('consume');kw['retirement_budget'].begin_retirement()
                return {'passed':True,'builderReleaseAllowed':failure!='consumer-debt','cleanupErrors':[]}
            cohort=SimpleNamespace(_consume=consume)
            provision=SimpleNamespace(PricingSpec=lambda *a,**kw:object(),PrivateRuntimeComponents=lambda *a:object())
            modules={'run-secureshop-customer-pricing-current-host.py':producer,'pricing_private_cohort.py':cohort,'pricing_owned_provisioning.py':provision,'owned_mcp_mux_relay.py':object()}
            class Channel:
                def __init__(self,*a):self.stage=0;self.child=SimpleNamespace(wait=lambda **kw:events.append('wait'),returncode=0)
                def send(self,value,deadline):
                    events.append(value['verb'])
                    if value['verb']=='admit':self.admission=value;self.binding={key:value[key] for key in ('version','runId','ownerPlanSha256')};self.binding['nodePlanSha256']='a'*64
                    if value['verb']=='retire':assert value['retired'] is True and 0<value['remainingMs']<=600000
                def receive(self,deadline):
                    self.stage+=1
                    if self.stage==1:
                        value=dict(self.binding,verb='ready',sources={k:v for k,v in admitted['sources'].items() if k!='tests/postgres/owned_mcp_mux_relay.py'},packageSha256=admitted['originalPackage']['sha256'])
                        if failure=='empty-sources':value['sources']={}
                        if failure=='extra-ready':value['extra']=True
                        return value
                    if self.stage==2:return dict(self.binding,verb='image',observed={'runId':run_id,'packageDigest':admitted['originalPackage']['sha256'],'sharedDaemonId':'shared','imageId':'sha256:'+'b'*64})
                    if self.stage==3:return dict(self.binding,verb='published')
                    if self.stage==4:return dict(self.binding,verb='retirement-ready')
                    return dict(self.binding,verb='terminal',result=dict(version=1,target='original-v33-pricing',controlled=True,buildCompleted=True,cleanupVerified=failure!='builder-debt',qualificationComplete=False,runtimeAvailable=False,failure=None,cleanupErrors=['debt'] if failure=='terminal-debt' else []))
                def close(self):events.append('channel-close')
            try:
                with patch.object(m,'load',side_effect=lambda name:modules[name]),patch.object(m,'BuilderChannel',Channel):
                    if failure:
                        with self.assertRaises(RuntimeError) as raised:m._execute(admitted)
                        self.assertFalse(raised.exception.result['passed'])
                    else:
                        result=m._execute(admitted);self.assertTrue(result['passed']);self.assertTrue(result['cleanupVerified']);self.assertEqual(result['nodePlanSha256'],'a'*64)
                if failure in ('consumer-debt','empty-sources','extra-ready'):self.assertNotIn('retire',events)
                else:self.assertLess(events.index('consume'),events.index('retire'))
                self.assertIn('channel-close',events);self.assertIn('restore',events)
                self.assertEqual(json.loads((directory/'launch-intent.json').read_text())['runId'],run_id)
                packet=json.loads((directory/'result.json').read_text());self.assertIs(packet['passed'],False);self.assertIs(packet['sealed'],False)
                self.assertEqual(packet['candidateOutcome']['passed'],failure is None)
                if failure is None:
                    self.assertEqual(result['terminalJoin']['candidateSha256'],m.hashlib.sha256((directory/'result.json').read_bytes()).hexdigest())
                    self.assertTrue(m.verify_terminal(admitted,result,directory/'result.json',lambda:None))
                    for changed in ('hash','plan','extra','passed','candidate'):
                        tampered=json.loads(json.dumps(result))
                        if changed=='hash':tampered['terminalJoin']['candidateSha256']='0'*64
                        if changed=='plan':tampered['terminalJoin']['ownerPlanSha256']='0'*64
                        if changed=='extra':tampered['extra']=True
                        if changed=='passed':tampered['passed']=1
                        if changed=='candidate':tampered=packet['candidateOutcome']
                        with self.assertRaises(RuntimeError):m.verify_terminal(admitted,tampered,directory/'result.json',lambda:None)
            finally:
                if directory.exists():shutil.rmtree(directory)

    def test_initial_snapshot_and_run_admission_are_bound_before_execution(self):
        admitted=m.plan('a'*32)
        self.assertEqual(admitted['originalSnapshot'],self.snapshot)
        digest=m.hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        with patch.object(m,'LIVE_ENABLED',True),patch.object(m,'_execute') as execute,patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError,'ADMISSION'):m.main(['--run','--run-id','a'*32,'--expected-plan-sha256','0'*64])
            execute.assert_not_called()
            execute.return_value={'controlled':True}
            m.main(['--run','--run-id','a'*32,'--expected-plan-sha256',digest])
            execute.assert_called_once_with(admitted)
        changed=dict(self.snapshot,sha256='0'*64)
        with patch.object(m,'capture_snapshot',return_value=changed),patch.object(m,'BuilderChannel') as launch:
            with self.assertRaisesRegex(RuntimeError,'SOURCE'):m._execute(admitted)
            launch.assert_not_called()

    def test_original_snapshot_capture_checks_original_digest(self):
        # Exercise the real wrapper, not the setUp controlled replacement.
        value={'actualWrapperControl':True}
        digest=m.hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        # Load a fresh module to retain the production capture implementation.
        fresh_spec=importlib.util.spec_from_file_location('pricing_capture_control',Path(m.__file__))
        fresh=importlib.util.module_from_spec(fresh_spec);fresh_spec.loader.exec_module(fresh)
        with patch.object(fresh,'load',return_value=SimpleNamespace(full_snapshot=lambda:(value,digest))):
            self.assertEqual(fresh.capture_snapshot(),dict(value=value,sha256=digest))
        with patch.object(fresh,'load',return_value=SimpleNamespace(full_snapshot=lambda:(value,'0'*64))):
            with self.assertRaisesRegex(RuntimeError,'DIGEST'):fresh.capture_snapshot()

    def test_plan_binds_original_and_helper_sources_with_live_gate_closed(self):
        p=m.plan('a'*32)
        self.assertTrue(p['liveEnabled']);self.assertTrue(p['eligible'])
        self.assertEqual(len(p['originalPackage']['files']),14)
        self.assertIn('tests/postgres/pricing_private_cohort.py',p['sources'])
        self.assertEqual((p['actor'],p['judge']),(4,2))
        with self.assertRaises(ValueError):m.plan('../x')
        with patch.object(m,'LIVE_ENABLED',False),patch.object(m,'_execute') as execute:
            with self.assertRaisesRegex(RuntimeError,'NOT_ADMITTED'):m.main(['--run','--run-id','a'*32])
            execute.assert_not_called()
        with patch.object(m,'plan') as capture:
            with self.assertRaisesRegex(RuntimeError,'ADMISSION'):m.main(['--run','--run-id','a'*32,'--expected-plan-sha256','bad'])
            capture.assert_not_called()

    def test_single_cleanup_window_cannot_renew(self):
        clock=[0.0];b=m.RetirementBudget(clock=lambda:clock[0])
        clock[0]=1000;self.assertEqual(b.cohort_deadline(),1600)
        clock[0]=1600;self.assertEqual(b.begin_retirement(),2200)
        clock[0]=2100;self.assertEqual(b.begin_retirement(),2200)
        self.assertEqual(b.remaining(200),100)
        clock[0]=2200
        with self.assertRaisesRegex(RuntimeError,'EXPIRED'):b.begin_retirement()
        with self.assertRaisesRegex(RuntimeError,'EXPIRED'):b.remaining(10)

    def test_reserve_clock_regression_and_nonfinite_fail_before_dispatch(self):
        clock=[0.0];b=m.RetirementBudget(clock=lambda:clock[0]);clock[0]=1417
        with self.assertRaisesRegex(RuntimeError,'RESERVE'):b.cohort_deadline()
        clock[0]=2017
        with self.assertRaisesRegex(RuntimeError,'RESERVE'):b.begin_retirement()
        clock[0]=0
        with self.assertRaisesRegex(RuntimeError,'CLOCK'):b.current()
        with self.assertRaisesRegex(RuntimeError,'CLOCK'):m.RetirementBudget(clock=lambda:float('nan'))


if __name__=='__main__':unittest.main()
