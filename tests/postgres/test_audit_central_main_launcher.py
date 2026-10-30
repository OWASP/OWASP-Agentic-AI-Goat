import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

RUNNER = pathlib.Path(__file__).with_name('run-secureshop-audit-central-isolated.py')

class AuditCentralMainLauncher(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('audit_central_main', RUNNER)
        self.module = importlib.util.module_from_spec(spec)
        with mock.patch('subprocess.run', side_effect=AssertionError('import must not launch')), mock.patch('subprocess.Popen', side_effect=AssertionError('import must not launch')):
            spec.loader.exec_module(self.module)

    def test_plan_does_not_allocate_or_qualify(self):
        with mock.patch.object(self.module, 'qualify', side_effect=AssertionError('plan allocated')):
            self.assertEqual(self.module.main([]), 0)

    def test_journal_selector_binds_all_four_isolated_pairs_without_live_model(self):
        env={f'PG_AUDIT_{store}_{role}_URL':f'owned-{store}-{role}'
             for store in ('AGENTS','REVIEW','COMMERCE') for role in ('RUNTIME','MIGRATION')}
        env.update({f'PG_HTTP_{role}_URL':f'owned-IDENTITY-{role}' for role in ('RUNTIME','MIGRATION')})
        original=dict(env)
        self.assertEqual(self.module.selected_fixture('audit-journal',env),
                         'tests/postgres/secureshopBoundAudit.integration.test.js')
        for store in ('IDENTITY','AGENTS','REVIEW','COMMERCE'):
            for role in ('RUNTIME','MIGRATION'):
                self.assertEqual(env[f'PG_SECURESHOP_BOUND_AUDIT_{store}_{role}_URL'],f'owned-{store}-{role}')
        self.assertNotIn('SS_AUDIT_GRAPH_LIVE_MODEL',env)
        with self.assertRaises(KeyError):self.module.selected_fixture('audit-journal',{})
        self.assertEqual(self.module.selected_fixture('admin-reads',original),
                         'tests/postgres/secureshopAuditQueryCentral.integration.test.js')
        self.assertFalse(any(key.startswith('PG_SECURESHOP_BOUND_AUDIT_') for key in original))

    def test_composition_selector_uses_owned_store_pairs_without_model_flags(self):
        env={f'PG_AUDIT_{store}_{role}_URL':f'owned-{store}-{role}'
             for store in ('AGENTS','REVIEW','COMMERCE') for role in ('RUNTIME','MIGRATION')}
        env.update({f'PG_HTTP_{role}_URL':f'owned-IDENTITY-{role}' for role in ('RUNTIME','MIGRATION')})
        self.assertEqual(self.module.selected_fixture('composition',env),
                         'tests/postgres/secureshopBoundReviewComposition.integration.test.js')
        for store in ('IDENTITY','AGENTS','REVIEW','COMMERCE'):
            for role in ('RUNTIME','MIGRATION'):
                self.assertEqual(env[f'PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_{store}_{role}_URL'],f'owned-{store}-{role}')
                canonical={'IDENTITY':'IDENTITY','AGENTS':'SECURESHOP_AGENTS',
                           'REVIEW':'SECURESHOP_REVIEW','COMMERCE':'SECURESHOP'}[store]
                suffix='DATABASE_URL' if role=='RUNTIME' else 'MIGRATION_DATABASE_URL'
                self.assertEqual(env[f'{canonical}_{suffix}'],f'owned-{store}-{role}')
        self.assertEqual(env['PLATFORM_DATABASE_ENGINE'],'postgres')
        self.assertEqual(env['WORKSHOP_DATABASE_ENGINE'],'postgres')
        self.assertEqual(len(env['JWT_SECRET']),64)
        self.assertFalse(any('MODEL' in key for key in env))
        with self.assertRaises(KeyError):self.module.selected_fixture('composition',{})

    def test_unique_private_evidence_preserves_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            a = self.module.create_evidence(pathlib.Path(directory))
            (a/'result.json').write_text('retained')
            b = self.module.create_evidence(pathlib.Path(directory))
            self.assertNotEqual(a, b)
            self.assertEqual((a/'result.json').read_text(), 'retained')
            self.assertEqual(a.stat().st_mode & 0o777, 0o700)

    def test_cleanup_attempts_each_group_and_all_containers_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(self.module.helpers, 'stop_group', side_effect=[RuntimeError('one'), 0]) as stop, mock.patch.object(self.module.helpers, 'cleanup_containers', return_value=([{'name':'first','cleanup':'absent_verified'}, {'name':'second','cleanup':'absent_verified'}], [])) as containers:
                errors = self.module.cleanup_owned(['a','b'], [{'name':'first'},{'name':'second'}], ['docker'], pathlib.Path(directory))
                self.assertEqual(stop.call_count, 2)
                self.assertEqual(len(containers.call_args.args[0]), 2)
                self.assertEqual(errors, ['one'])

    def test_timeout_child_is_registered_with_private_receipt_before_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=pathlib.Path(directory); children=[]
            child=mock.Mock(pid=8765)
            def wait(**kwargs):
                self.assertEqual(children, [child])
                self.assertTrue((evidence/'child-intent.json').is_file())
                self.assertEqual(kwargs['timeout'],600)
                raise subprocess.TimeoutExpired('owned',600)
            child.wait.side_effect=wait
            with mock.patch.object(self.module.subprocess,'Popen',return_value=child) as launch:
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.module.run_owned_child(['node'],cwd=directory,env={},evidence=evidence,children=children)
                self.assertTrue(launch.call_args.kwargs['start_new_session'])
                self.assertEqual(child._owned_pgid,8765)

    def test_owned_environment_excludes_credentials_and_removes_only_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=pathlib.Path(directory)
            (evidence/'result.json').write_text('keep')
            with mock.patch.dict('os.environ',{'HOME':'/host/home','TMPDIR':'/host/tmp','DATABASE_URL':'secret','OPENAI_API_KEY':'secret','AI_PROVIDER':'openai','NODE_OPTIONS':'host-option'}):
                env=self.module.owned_environment(evidence,'/owned/node/bin/node')
            for key in ('DATABASE_URL','OPENAI_API_KEY','AI_PROVIDER','NODE_OPTIONS'):self.assertNotIn(key,env)
            for key in ('HOME','TMPDIR','TMP','TEMP','XDG_CACHE_HOME','HF_HOME','npm_config_cache'):
                owned=pathlib.Path(env[key]);self.assertTrue(owned.is_relative_to(evidence/'runtime'));self.assertEqual(owned.stat().st_mode & 0o777,0o700)
            with mock.patch.object(self.module.helpers,'cleanup_containers',return_value=([],[])):
                self.assertEqual(self.module.cleanup_owned([],[],['docker'],evidence),[])
            self.assertFalse((evidence/'runtime').exists())
            self.assertEqual((evidence/'result.json').read_text(),'keep')

    def test_live_group_cleanup_failure_retains_owned_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=pathlib.Path(directory);self.module.owned_environment(evidence,'/owned/node')
            with mock.patch.object(self.module.helpers,'stop_group',side_effect=RuntimeError('still live')),mock.patch.object(self.module.helpers,'cleanup_containers',return_value=([],[])):
                self.assertEqual(self.module.cleanup_owned(['child'],[],['docker'],evidence),['still live'])
            self.assertTrue((evidence/'runtime').is_dir())

    def test_container_cleanup_precedes_runtime_removal_and_failure_preserves_recovery(self):
        for outcome in ('success', 'reported-failure', 'exception'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                evidence=pathlib.Path(directory)
                self.module.owned_environment(evidence,'/owned/node')
                recovery=evidence/'runtime'/'home'/'ownership.json'
                recovery.write_text('owned recovery fixture')
                def cleanup(*_args):
                    self.assertEqual(recovery.read_text(),'owned recovery fixture')
                    if outcome=='exception':raise RuntimeError('daemon unavailable')
                    return [], ['container remains'] if outcome=='reported-failure' else []
                with mock.patch.object(self.module.helpers,'cleanup_containers',side_effect=cleanup):
                    errors=self.module.cleanup_owned([],[],['docker'],evidence)
                self.assertEqual(bool(errors),outcome!='success')
                self.assertEqual(recovery.exists(),outcome!='success')
                self.assertTrue((evidence/'cleanup.json').is_file())

    def test_signal_runs_finally_and_restores_handlers(self):
        import signal
        prior={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
        def qualify(_args):
            try:signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
            finally:self.cleaned=True
        self.cleaned=False
        with mock.patch.object(self.module,'qualify',side_effect=qualify):
            with self.assertRaises(SystemExit):self.module.main(['--run','--node',str(RUNNER)])
        self.assertTrue(self.cleaned)
        self.assertEqual({sig:signal.getsignal(sig) for sig in prior},prior)

    def test_activation_cleanup_validates_both_resources_before_deletion(self):
        import json
        intent={'id':'a'*12,'name':'owasp-ai-goat-audit-sql-'+'a'*12,
                'volume':'owasp-ai-goat-audit-sql-'+'a'*12+'-data','image':'sha256:'+'b'*64}
        cid='c'*64
        labels={'owasp-ai-goat.workspace':intent['id'],'owasp-ai-goat.purpose':'owned-audit-sql'}
        for fault in (None,'absent','foreign-container','foreign-volume','image','binding','daemon','inspect','remaining','invalid-intent'):
            with self.subTest(fault=fault):
                calls=[]; deleted=set()
                def run(argv, **kwargs):
                    args=argv[1:];calls.append(args)
                    if fault=='daemon':raise OSError('daemon unavailable')
                    if args[0]=='ps':out=cid if fault!='absent' and ('container' not in deleted or fault=='remaining') else ''
                    elif args[:2]==['volume','ls']:out=intent['volume'] if fault!='absent' and 'volume' not in deleted else ''
                    elif args[0]=='inspect':
                        if fault=='inspect':raise subprocess.CalledProcessError(1,argv)
                        out=json.dumps([{'Id':cid,'Name':'/'+intent['name'],'Image':'sha256:'+'d'*64 if fault=='image' else intent['image'],
                          'Config':{'Labels':{} if fault=='foreign-container' else labels},
                          'HostConfig':{'PortBindings':{'5432/tcp':[{'HostIp':'0.0.0.0' if fault=='binding' else '127.0.0.1'}]}},
                          'Mounts':[{'Type':'volume','Name':intent['volume'],'Destination':'/var/lib/postgresql'}]}])
                    elif args[:2]==['volume','inspect']:out=json.dumps([{'Name':intent['volume'],'Labels':{} if fault=='foreign-volume' else labels}])
                    elif args[0]=='rm':self.assertEqual(args,['rm','-f',cid]);deleted.add('container');out=''
                    elif args[:2]==['volume','rm']:self.assertEqual(args[2],intent['volume']);deleted.add('volume');out=''
                    else:raise AssertionError(args)
                    return subprocess.CompletedProcess(argv,0,stdout=out,stderr='')
                value=dict(intent)
                if fault=='invalid-intent':value['name']='foreign'
                errors=self.module.cleanup_activation_resources(value,['docker'],runner=run)
                self.assertEqual(bool(errors),fault not in (None,'absent'))
                if fault not in (None,'remaining'):self.assertEqual(deleted,set())
                if fault is None:
                    self.assertEqual(deleted,{'container','volume'})
                    self.assertLess(calls.index(['volume','inspect',intent['volume']]),calls.index(['rm','-f',cid]))

    def test_activation_admission_and_receipt_are_closed(self):
        import json, hashlib
        for occupied in (False,True):
            with tempfile.TemporaryDirectory() as folder:
                evidence=pathlib.Path(folder).resolve();env=self.module.owned_environment(evidence,'/owned/node')
                calls=[]
                def run(argv,**kwargs):
                    calls.append(argv)
                    if argv[0]=='/owned/node':
                        root,home,host=argv[-3:];wid=hashlib.sha256(root.encode()).hexdigest()[:12];name='owasp-ai-goat-audit-sql-'+wid
                        out=json.dumps(dict(root=root,id=wid,name=name,volume=name+'-data',database='owasp_ai_goat_audit_control_'+wid,dockerHost=host,port=8095,file=str(pathlib.Path(home)/'.owasp-ai-goat'/wid/'audit-sql-target.json')))
                    else:out='occupied' if occupied else ''
                    return subprocess.CompletedProcess(argv,0,stdout=out,stderr='')
                if occupied:
                    with self.assertRaisesRegex(RuntimeError,'not absent'):self.module.prepare_activation(pathlib.Path.cwd(),evidence,'/owned/node',['docker','--host','unix:///owned'],env,'sha256:'+'b'*64,runner=run)
                    self.assertNotIn('AUDIT_SQL_ACTIVATION_INTENT',env)
                else:
                    intent=self.module.prepare_activation(pathlib.Path.cwd(),evidence,'/owned/node',['docker','--host','unix:///owned'],env,'sha256:'+'b'*64,runner=run)
                    self.assertEqual(json.loads(pathlib.Path(env['AUDIT_SQL_ACTIVATION_INTENT']).read_text()),intent)
                    self.assertFalse(any('run' in argv or 'rm' in argv for argv in calls))
        keys=('freshActivation','actualApplicationLedgerAndPrivileges','realPrivateDaemon','failedPrerequisitePreservedConfig','repeatByteStable','existingDisabledPreserved','stoppedOwnedContainerRestarted')
        payload={key:True for key in keys}
        def output(p):return 'AUDIT_SQL_FRESH_ACTIVATION_NATIVE_PASSED '+json.dumps(p)+'\nAUDIT_CENTRAL_NATIVE_ACTUAL_SQL_TRANSPORT_PASSED'
        self.module.validate_activation_receipt(output(payload))
        for key in keys:
            with self.assertRaises(RuntimeError):self.module.validate_activation_receipt(output({**payload,key:False}))
        with mock.patch.object(self.module,'qualify',return_value=0) as qualify:
            self.module.main(['--mode','activation','--run'])
            self.assertEqual(qualify.call_args.args[0].mode,'activation')

    def test_activation_cleanup_waits_for_child_and_preserves_uncertain_config(self):
        for live,error in ((False,[]),(False,['uncertain']),(True,[])):
            with tempfile.TemporaryDirectory() as folder:
                evidence=pathlib.Path(folder);self.module.owned_environment(evidence,'/owned/node')
                with mock.patch.object(self.module.helpers,'stop_group',side_effect=RuntimeError('live') if live else None),mock.patch.object(self.module.helpers,'cleanup_containers',return_value=([],[])),mock.patch.object(self.module,'cleanup_activation_resources',return_value=error) as activation:
                    result=self.module.cleanup_owned(['child'],[],['docker'],evidence,{'owned':'intent'})
                    self.assertEqual(activation.call_count,0 if live else 1)
                    self.assertEqual((evidence/'runtime').exists(),bool(live or error))
                    self.assertEqual(bool(result),bool(live or error))

    def test_browser_ancestry_identity_and_fallback_retirement(self):
        import os
        state={'executable':'/owned/Chrome','profile':'/owned/profile','members':{}}
        row={'pid':2345,'ppid':1234,'pgid':2345,'uid':os.getuid(),'command':'/owned/Chrome --user-data-dir=/owned/profile --flag'}
        run=mock.Mock(return_value=subprocess.CompletedProcess([],0,stdout='start identity',stderr=''))
        self.module.observe_browsers(state,1234,[row],runner=run)
        self.assertEqual(state['members'][2345]['start'],'start identity')
        with self.assertRaisesRegex(RuntimeError,'ancestry'):
            self.module.observe_browsers({'executable':'/owned/Chrome','profile':'/owned/profile','members':{}},999,[row],runner=run)
        kill=mock.Mock()
        with mock.patch.object(self.module,'browser_rows',side_effect=[[{**row,'ppid':1}],[]]):
            self.assertEqual(self.module.retire_browsers(state,runner=run,killpg=kill),[])
        kill.assert_called_once_with(2345,self.module.signal.SIGKILL)
        kill.reset_mock()
        with mock.patch.object(self.module,'browser_rows',return_value=[{**row,'uid':os.getuid()+1}]):
            self.assertTrue(self.module.retire_browsers(state,runner=run,killpg=kill))
        kill.assert_not_called()
        with mock.patch.object(self.module,'browser_rows',side_effect=OSError('inventory denied')):
            self.assertTrue(self.module.retire_browsers(state,runner=run,killpg=kill))
        kill.assert_not_called()

    def test_rendered_digest_and_receipts_reject_tamper(self):
        import hashlib,json
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'index.html').write_text('owned');
            rows=[['index.html',hashlib.sha256(b'owned').hexdigest()]]
            self.assertEqual(self.module.build_digest(root),hashlib.sha256(json.dumps(rows,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())
            (root/'linked').symlink_to(root/'index.html')
            with self.assertRaisesRegex(RuntimeError,'symlink'):self.module.build_digest(root)
            (root/'linked').unlink()
            file=root/'audit-rendered-result-2026-09-19.json';file.write_text(json.dumps({'actualModel':False,'canonicalCredit':False,'errors':[]}))
            self.module.validate_rendered_receipt('rendered',root)
            file.write_text(json.dumps({'actualModel':True,'canonicalCredit':False,'errors':[]}))
            with self.assertRaises(RuntimeError):self.module.validate_rendered_receipt('rendered',root)

    def test_rendered_failed_cleanup_preserves_external_owned_runtime(self):
        for error in ([],['browser remains']):
            with tempfile.TemporaryDirectory() as folder,tempfile.TemporaryDirectory() as outer:
                evidence=pathlib.Path(folder);runtime=pathlib.Path(outer)/'owned';runtime.mkdir();
                browser={'runtimeRoot':str(runtime)}
                with mock.patch.object(self.module.helpers,'cleanup_containers',return_value=([],[])),mock.patch.object(self.module,'retire_browsers',return_value=error):
                    result=self.module.cleanup_owned([],[],['docker'],evidence,browser=browser)
                    self.assertEqual(runtime.exists(),bool(error));self.assertEqual(result,error)

    def test_rendered_build_uses_owned_external_siblings_and_boundary(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            evidence=pathlib.Path(folder).resolve();env=self.module.owned_environment(evidence,'/owned/node');state={};children=[]
            chrome=evidence/'Chrome';chrome.write_text('synthetic');chrome.chmod(0o700)
            def plan(argv,**kwargs):
                self.assertIn('buildBoundary',argv[2]);self.assertIn('discoverSecrets',argv[2]);self.assertIn('--configLoader',argv[2])
                return subprocess.CompletedProcess(argv,0,stdout=json.dumps({'boundary':{'command':'sandbox-exec','args':['-p','owned'],'cwd':str(evidence)},'env':{'controlled':'yes'}}),stderr='')
            def build(command,**kwargs):
                self.assertEqual(command[0],'sandbox-exec');self.assertEqual(kwargs['timeout'],120)
                base=pathlib.Path(state['runtimeRoot'])/'tmp'/'workspace'/'build'
                for name in ('index.html','secureshop-frame.html'):(base/name).write_text('synthetic')
                children.append(mock.Mock());return mock.Mock(returncode=0)
            try:
                with mock.patch.object(self.module.subprocess,'run',side_effect=plan),mock.patch.object(self.module,'run_owned_child',side_effect=build),mock.patch.object(self.module.helpers,'stop_group'):
                    self.module.prepare_rendered(evidence,evidence,'/owned/node',env,children,str(chrome),state)
                build_path=pathlib.Path(env['AUDIT_SQL_BUILD_ROOT']);profile=pathlib.Path(env['AUDIT_SQL_BROWSER_PROFILE'])
                self.assertEqual(build_path.parent,profile.parent);self.assertNotEqual(build_path,profile)
                self.assertFalse(build_path.is_relative_to(evidence));self.assertEqual(build_path.stat().st_mode&0o777,0o700)
                self.assertEqual(env['AUDIT_SQL_BUILD_SHA256'],self.module.build_digest(build_path))
                self.assertNotIn('AUDIT_SQL_ACTUAL_MODEL',env)
            finally:
                if state.get('runtimeRoot'):self.module.shutil.rmtree(state['runtimeRoot'])

    def test_actual_modes_require_opt_in_loopback_and_private_intent(self):
        from types import SimpleNamespace
        for mode in ('actual-model','rendered-actual'):
            for opt,url in ((False,'http://127.0.0.1:11434'),(True,None),(True,'http://example.com:11434'),(True,'http://user:pass@127.0.0.1:11434'),(True,'http://127.0.0.1:11434/path'),(True,'http://127.0.0.1:11434?x=y')):
                with self.assertRaises(ValueError):self.module.actual_model_url(SimpleNamespace(mode=mode,allow_actual_model=opt,ollama_base_url=url))
        with self.assertRaises(ValueError):self.module.actual_model_url(SimpleNamespace(mode='parity',allow_actual_model=True,ollama_base_url='http://127.0.0.1:11434'))
        with mock.patch.object(self.module,'qualify',side_effect=AssertionError('must reject before dispatch')):
            with self.assertRaises(ValueError):self.module.main(['--mode','actual-model','--run'])
        with tempfile.TemporaryDirectory() as folder:
            import json
            evidence=pathlib.Path(folder).resolve();env={}
            args=SimpleNamespace(mode='actual-model',allow_actual_model=True,ollama_base_url='http://127.0.0.1:11434/')
            value=self.module.bind_actual_intent(args,evidence,env)
            self.assertEqual(value['baseUrl'],'http://127.0.0.1:11434');self.assertEqual(env['AUDIT_SQL_ACTUAL_MODEL'],'yes')
            file=pathlib.Path(env['AUDIT_SQL_ACTUAL_INTENT']);self.assertEqual(file.stat().st_mode&0o777,0o600);self.assertEqual(json.loads(file.read_text()),value)
            cases=[{'name':name,'replayed':True,'canonicalCredit':name=='extraction','verdict':'pass' if name=='extraction' else 'no_credit','provider':'ollama','model':'llama3.1:8b','queryCalls':0 if name=='fixed' else 1} for name in ('extraction','benign','fixed')]
            payload={'canonicalCredit':True,'mounted':True,'cases':cases}
            self.module.validate_actual_receipt('AUDIT_SQL_ACTUAL_MODEL_QUALIFICATION '+json.dumps(payload))
            cases[1]['canonicalCredit']=True
            with self.assertRaises(RuntimeError):self.module.validate_actual_receipt('AUDIT_SQL_ACTUAL_MODEL_QUALIFICATION '+json.dumps(payload))

if __name__ == '__main__':unittest.main()
