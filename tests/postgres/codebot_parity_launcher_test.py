import importlib.util
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('setup_codebot',HERE/'run-setup-database-phase-isolated.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)

class Controls(unittest.TestCase):
    def test_closed_store_roles_and_urls(self):
        urls={}
        for store in ('identity','supply_chain'):
            sql,pairs=launcher.codebot_store_configuration(store,54321,'abcdef012345')
            self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',sql)
            self.assertIn('REVOKE CONNECT ON DATABASE',sql)
            self.assertEqual(len(pairs),2);urls.update(pairs)
            for value in pairs.values():self.assertTrue(value.endswith('/dvaia_test_codebot_parity_abcdef012345_'+store))
        self.assertEqual(len(urls),4)
        for args in [('postgres',54321,'abcdef012345'),('identity',True,'abcdef012345'),('identity',1,'../../bad')]:
            with self.assertRaises(ValueError):launcher.codebot_store_configuration(*args)

    def test_history_profile_closed_three_stores_without_changing_codebot(self):
        args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='workshop-history')
        self.assertEqual(launcher.browser_profile(args),'workshop-history')
        self.assertEqual(launcher.browser_stores('workshop-history'),('identity','aria','nova'))
        urls={}
        for store in launcher.browser_stores('workshop-history'):
            sql,pairs=launcher.codebot_store_configuration(store,54321,'abcdef012345','workshop-history');urls.update(pairs)
            self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',sql)
            for value in pairs.values():self.assertTrue(value.endswith('/dvaia_test_codebot_parity_abcdef012345_'+store))
        self.assertEqual(set(urls),{p+s for p in ['IDENTITY','SQL_WORKSHOP','NOSQL_WORKSHOP'] for s in ['_DATABASE_URL','_MIGRATION_DATABASE_URL']})
        with self.assertRaises(ValueError):launcher.codebot_store_configuration('supply_chain',54321,'abcdef012345','workshop-history')
        with self.assertRaises(ValueError):launcher.codebot_store_configuration('aria',54321,'abcdef012345')
        for profile,scenario in [('other','codebot-rendered-parity'),('workshop-history','finflow-0055')]:
            with self.assertRaises(ValueError):launcher.browser_profile(SimpleNamespace(browser_profile=profile,scenario=scenario))
        self.assertEqual(launcher.browser_profile(SimpleNamespace()),'codebot')

    def test_profile_manifest_wrong_cohort_or_actual_model_mode_denied(self):
        args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='workshop-history')
        valid={'cohort':'workshop-history','profile':'workshop-history','mode':'model-free'}
        self.assertEqual(launcher.validate_browser_profile_manifest(args,valid),'workshop-history')
        for patch in [{'cohort':'codebot-rendered-parity'},{'profile':'codebot'},{'mode':'actual'}]:
            with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**valid,**patch})
        args.browser_profile=None
        self.assertEqual(launcher.validate_browser_profile_manifest(args,{'cohort':'codebot-rendered-parity'}),'codebot')
        with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,valid)

    def test_history_clean_environment_requires_exact_six_urls(self):
        args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='workshop-history',node='/p/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
        urls={}
        for store in launcher.browser_stores('workshop-history'):urls.update(launcher.codebot_store_configuration(store,54321,'abcdef012345','workshop-history')[1])
        with patch.object(pathlib.Path,'mkdir'):
            env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
            for changed in [{},dict(urls,PG_ADMIN_DATABASE_URL='forbidden'),dict(urls,SUPPLY_CHAIN_WORKSHOP_DATABASE_URL='forbidden')]:
                with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',changed)
        self.assertEqual(env['CODEBOT_PARITY_PROFILE'],'workshop-history');self.assertEqual(env['AI_PROVIDER'],'mock')
        self.assertNotIn('PG_ADMIN_DATABASE_URL',env);self.assertEqual(env['LOGS_DIR'],'/e/runtime/logs')

    def test_history_receipt_requires_both_families_and_all_checks_without_model_credit(self):
        import copy
        flags=['persistenceReload','siblingIsolation','resetLateResponse','ownerSwitchLateResponse','actualRenderedResults','escapedHtml','siblingHistoryPreserved']
        value={'status':'passed','profile':'workshop-history','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'cases':[{'id':id,'source':'fixture','rowCount':4,'responseSha256':'a'*64,'resultLayout':layout,**dict.fromkeys(flags,True)} for id,layout in [('sql','json-blocks'),('nosql','table')]],'requests':{'api':30,'chats':6,'resets':2,'historyRequests':8},'controlledProviderCalls':6,'cleanup':[{'name':name,'status':'fulfilled'} for name in ['browser','routes','server','runs','pools']]}
        value['migrationProbe']={'migration':'0124_graph_presentation_snapshot.sql','populatedUpgrade':True,'priorLedgerChecksumsPreserved':True,'priorTracePreserved':True,'runtimeGrants':True,'publicExecuteDenied':True,'sqlNullDenied':True,'accepted':7,'rejected':31,'noOp':True,'supported128PrefixFourBlocks':True,'worstUnicodeEnvelope':True,'legacyMetadataBoundPreserved':True,'freshInitialization':False}
        value['migrationProbe']['gradePacketProbe']={'migration':'0125_dpi_policy_packet_budget.sql','populatedUpgrade':True,'priorPacketPreserved':True,'predecessorExpandedDenied':True,'legacy24000Preserved':True,'compactActorAccepted':True,'compactDecoderAccepted':True,'sqlNullAccepted':True,'runtimeGrants':True,'publicExecuteDenied':True,'accepted':4,'rejected':21,'freshInitialization':False,'noOp':True}
        launcher.verify_workshop_history_result(value)
        for mutate in [lambda x:x.update(actualModelProof=True),lambda x:x.update(genuineCredit=1),lambda x:x.update(modelCalls=False),lambda x:x.update(cleanupFailures=['error']),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(id='nosql'),lambda x:x['requests'].update(chats=5),lambda x:x['requests'].update(resets=1),lambda x:x['requests'].update(api=1501),lambda x:x['requests'].update(historyRequests=7),lambda x:x.update(controlledProviderCalls=0),lambda x:x['cleanup'].pop(),lambda x:x['cases'][0].update(source='model'),lambda x:x['cases'][0].update(rowCount=3),lambda x:x['cases'][0].update(resultLayout='table'),lambda x:x['cases'][0].update(responseSha256='invalid')]+[lambda x,flag=flag:x['cases'][0].pop(flag) for flag in flags]:
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(RuntimeError):launcher.verify_workshop_history_result(changed)

    def test_migration_probe_rejects_missing_wrong_and_untyped_fields(self):
        import copy
        # Capture the complete accepted child receipt used by the existing terminal control.
        receipts=[]
        original=launcher.verify_workshop_history_result
        def capture(value):
            original(value)
            receipts.append(copy.deepcopy(value))
        with patch.object(launcher,'verify_workshop_history_result',side_effect=capture):
            self.test_history_receipt_requires_both_families_and_all_checks_without_model_credit()
        value=receipts[0]
        for key,expected in value['migrationProbe']['gradePacketProbe'].items():
            for replacement in [None,1 if type(expected)is bool else True,'wrong']:
                changed=copy.deepcopy(value);changed['migrationProbe']['gradePacketProbe'][key]=replacement
                with self.assertRaises(RuntimeError):original(changed)
            changed=copy.deepcopy(value);del changed['migrationProbe']['gradePacketProbe'][key]
            with self.assertRaises(RuntimeError):original(changed)
        changed=copy.deepcopy(value);changed['migrationProbe']['gradePacketProbe']['extra']=True
        with self.assertRaises(RuntimeError):original(changed)
        for key,expected in value['migrationProbe'].items():
            for replacement in [None,1 if type(expected)is bool else True,'wrong']:
                changed=copy.deepcopy(value);changed['migrationProbe'][key]=replacement
                with self.assertRaises(RuntimeError):original(changed)
            changed=copy.deepcopy(value);del changed['migrationProbe'][key]
            with self.assertRaises(RuntimeError):original(changed)
        for probe in [None,{},dict(value['migrationProbe'],extra=True)]:
            changed=copy.deepcopy(value);changed['migrationProbe']=probe
            with self.assertRaises(RuntimeError):original(changed)

    def test_history_predecessor_links_are_exact_pinned_and_profile_scoped(self):
        import tempfile,os,hashlib
        source=HERE.parents[1];migration=source/'db/postgres/identity-migrations'
        names=sorted(p.name for p in migration.glob('*.sql') if p.name<='0123_ctf_canonical_admin_policy.sql')
        pins={str((migration/name).relative_to(source)):hashlib.sha256((migration/name).read_bytes()).hexdigest() for name in names}
        with tempfile.TemporaryDirectory() as directory:
            evidence=pathlib.Path(directory).resolve();evidence.chmod(0o700)
            runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
            view=runtime/'presentation-predecessor-view';view.mkdir(mode=0o700)
            for name in names:os.symlink(migration/name,view/name)
            self.assertEqual(launcher.check_history_logs(evidence,source,pins,True),0)
            with self.assertRaisesRegex(RuntimeError,'Owned evidence link'):launcher.check_native_logs(evidence,'codebot-rendered-parity')
            first=view/names[0];first.unlink();os.symlink(migration/names[1],first)
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,pins)
            first.unlink();os.symlink(migration/names[0],first)
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,{**pins,str((migration/names[0]).relative_to(source)):'0'*64})
            extra=view/'9999_extra.sql';os.symlink(migration/names[0],extra)
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,pins)
            extra.unlink();outside=runtime/'extra-link';os.symlink(migration/names[0],outside)
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,pins)
            outside.unlink();(view/names[-1]).unlink()
            self.assertEqual(launcher.check_history_logs(evidence,source,pins),0)
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,pins,True)
            (view/names[0]).unlink()
            with self.assertRaises(RuntimeError):launcher.check_history_logs(evidence,source,pins)

    def test_stdin_release_only_after_durable_publication(self):
        events=[]
        pipe=SimpleNamespace(write=lambda data:events.append(('write',data)),flush=lambda:events.append('flush'),close=lambda:events.append('close'))
        state={}
        launcher.publish_child_start(SimpleNamespace(pid=42,stdin=pipe),state,lambda:events.append(('record',dict(state))),'codebot-rendered-parity')
        self.assertEqual(events,[('record',{'nativeStarted':True,'nativePid':42}),('write',b'1'),'flush','close'])
        events.clear()
        with self.assertRaises(RuntimeError):
            launcher.publish_child_start(SimpleNamespace(pid=42,stdin=pipe),{},lambda:(_ for _ in ()).throw(RuntimeError('publish failed')),'codebot-rendered-parity')
        self.assertEqual(events,[])

    def test_bounds_direct_entry_and_other_scenarios_preserved(self):
        self.assertEqual(launcher.scenario_bounds('codebot-rendered-parity'),(780,600,120))
        args=SimpleNamespace(scenario='codebot-rendered-parity',node='/node',package='/main')
        self.assertEqual(launcher.scenario_command(args),['/node','/main/tests/postgres/codeBotRenderedParityMainV1.js'])
        args.scenario='restored-populated-upgrade'
        self.assertEqual(launcher.scenario_command(args),['/node','tests/release-inputs/populated16-rehearsal.cjs'])

    def test_private_environment_never_inherits_admin_url_or_source_sentinel(self):
        args=SimpleNamespace(node='/p/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
        with patch.object(pathlib.Path,'mkdir'):
            env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',{'IDENTITY_DATABASE_URL':'controlled'})
        self.assertNotIn('PG_ADMIN_DATABASE_URL',env)
        self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE',env)
        self.assertEqual(env['HOME'],'/e/runtime/home')
        self.assertEqual(env['CODEBOT_PARITY_SOURCE_ROOT'],'/main')

    def test_wrong_main_denied_before_manifest_or_helper(self):
        with patch.object(launcher,'codebot_browser_helper',side_effect=AssertionError('must not import')):
            with self.assertRaises(RuntimeError):launcher.validate_codebot_main(SimpleNamespace(package='/foreign',main_workspace=True))


    def test_mcp_content_closed_profile_and_exact_stores(self):
        args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='mcp-audit-content')
        self.assertEqual(launcher.validate_browser_profile_manifest(args,{'cohort':'mcp-audit-content','profile':'mcp-audit-content','mode':'model-free'}),'mcp-audit-content')
        self.assertEqual(launcher.browser_stores('mcp-audit-content'),('identity','mcp'))
        sql,urls=launcher.codebot_store_configuration('mcp',54321,'abcdef012345','mcp-audit-content')
        self.assertEqual(set(urls),{'MCP_WORKSHOP_DATABASE_URL','MCP_WORKSHOP_MIGRATION_DATABASE_URL'})
        self.assertIn('NOSUPERUSER',sql)
        with self.assertRaises(ValueError):launcher.codebot_store_configuration('supply_chain',54321,'abcdef012345','mcp-audit-content')
        with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{'cohort':'mcp-audit-content','profile':'mcp-audit-content','mode':'actual-model'})

    def test_mcp_content_terminal_rejects_missing_proof_credit_and_bounds(self):
        import copy
        good={'status':'passed','profile':'mcp-audit-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],
          **{k:True for k in ('freshThreeFields','seedUpgrade','customFullSeedPreserved','nullFullSeedPreserved','masterGates','objectiveGates','learnerContent','adminPreview','siblingPreserved','contentRestored')},
          'requests':{'browser':100,'api':20},'cleanup':[{'name':n,'status':'fulfilled'} for n in ('browser','routes','server','pools')]}
        good['seedReceipt']={'version':'mcp-audit-seed-v1',**{k:True for k in ('freshDefaults','managedPriorThreeFields','instructorThreeFieldsPreserved','nullableContentPreserved','labelNullRejected','secondRunNoop','siblingCatalogPreserved','customProbeRolledBack','independentEffectiveGates','nullContentDenied')}}
        launcher.verify_mcp_audit_content_result(good)
        for key in good:
            bad=copy.deepcopy(good);del bad[key]
            with self.assertRaises(RuntimeError):launcher.verify_mcp_audit_content_result(bad)
        for key in ('actualModelProof','genuineCredit','modelCalls'):
            bad=copy.deepcopy(good);bad[key]=True if key=='actualModelProof' else 1
            with self.assertRaises(RuntimeError):launcher.verify_mcp_audit_content_result(bad)
        for key,limit in [('browser',400),('api',40)]:
            bad=copy.deepcopy(good);bad['requests'][key]=limit+1
            with self.assertRaises(RuntimeError):launcher.verify_mcp_audit_content_result(bad)


class ObjectiveContent(unittest.TestCase):
    def test_closed_profile_receipt_and_bounds(self):
        args=SimpleNamespace(browser_profile='objective-solution-content',scenario='codebot-rendered-parity')
        self.assertEqual(launcher.browser_stores(launcher.browser_profile(args)),('identity','supply_chain'))
        self.assertEqual(launcher.scenario_bounds('codebot-rendered-parity'),(780,600,120))
        launcher.validate_browser_profile_manifest(args,{'cohort':'objective-solution-content','profile':'objective-solution-content','mode':'model-free'})
        value={'status':'passed','profile':'objective-solution-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'siblingPreserved':True,'gatesPreserved':True,'contentRestored':True,'requests':{'browser':400,'api':40},'cleanup':[{'name':n,'status':'fulfilled'} for n in ('browser','routes','server','pools')],'cases':[{'id':id,'workshopKey':key,**{f:True for f in ('typedSave','readback','learnerProjection','reseedPreserved','restored')}} for id,key in [('xss_r1','xss_workshop'),('csrf_g1','csrf_workshop')]]}
        launcher.verify_objective_solution_content_result(value)
        import copy
        for mutate in [lambda x:x['requests'].update(browser=401),lambda x:x.update(modelCalls=True),lambda x:x.update(siblingPreserved=False),lambda x:x['cases'][1].update(id='other'),lambda x:x['cases'][0].update(reseedPreserved=False),lambda x:x.update(cleanup=[])]:
            bad=copy.deepcopy(value);mutate(bad)
            with self.assertRaises(RuntimeError):launcher.verify_objective_solution_content_result(bad)

class GenericContent(unittest.TestCase):
    def test_exact_generic_case_keeps_default_denial_and_bounds(self):
        import copy
        profile='generic-solution-content'
        args=SimpleNamespace(browser_profile=profile,scenario='codebot-rendered-parity')
        self.assertEqual(launcher.browser_stores(launcher.browser_profile(args)),('identity','supply_chain'))
        self.assertEqual(launcher.scenario_bounds(args.scenario),(780,600,120))
        launcher.validate_browser_profile_manifest(args,{'cohort':profile,'profile':profile,'mode':'model-free'})
        value={'status':'passed','profile':profile,'actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'siblingPreserved':True,'gatesPreserved':True,'contentRestored':True,'requests':{'browser':400,'api':40},'cleanup':[{'name':n,'status':'fulfilled'} for n in ('browser','routes','server','pools')],'cases':[{'id':'path_traversal','workshopKey':'legacy_sensitive_file_ssi',**{f:True for f in ('typedSave','readback','learnerProjection','reseedPreserved','restored')}}]}
        launcher.verify_objective_solution_content_result(value,profile)
        with self.assertRaises(RuntimeError):launcher.verify_objective_solution_content_result(value)
        for mutate in [lambda x:x['cases'].append(copy.deepcopy(x['cases'][0])),lambda x:x['cases'][0].update(workshopKey='other'),lambda x:x['cases'][0].update(restored=False),lambda x:x.update(modelCalls=1),lambda x:x['requests'].update(api=41),lambda x:x.update(cleanup=[])]:
            bad=copy.deepcopy(value);mutate(bad)
            with self.assertRaises(RuntimeError):launcher.verify_objective_solution_content_result(bad,profile)

class XssStoredSix(unittest.TestCase):
 def test_closed_stores_and_full_receipt(self):
  import copy
  profile='xss-stored-six-content-inert'
  self.assertEqual(launcher.browser_stores(profile),('identity','xss'))
  sql,urls=launcher.codebot_store_configuration('xss',2222,'0123456789ab',profile)
  self.assertEqual(set(urls),{'XSS_WORKSHOP_DATABASE_URL','XSS_WORKSHOP_MIGRATION_DATABASE_URL'})
  with self.assertRaises(ValueError):launcher.codebot_store_configuration('ctf',2222,'0123456789ab',profile)
  good=dict(status='passed',profile=profile,actualModelProof=False,modelCalls=0,genuineCredit=0,installedWrites=False,pendingControlledCalls=0,cleanupFailures=[],controlledCalls=20,requests={'browser':800,'api':80},cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for id in ['xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3']],cleanup=[dict(name=name,status='fulfilled') for name in ['runs','restore','browser','xss-route','routes','server','pools']])
  for name in ['dashboardParity','configurationRestored','siblingPreserved','projectionRestored','inertRendering','noWrite','copiedOriginDenied','missingProofNoCredit','sessionDenied','resetRetired','immutableEvidencePreserved']:good[name]=True
  launcher.verify_xss_stored_six_result(good)
  for change in [lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(learnerContent=1),lambda x:x['requests'].update(browser=801),lambda x:x['requests'].update(api=81),lambda x:x.update(genuineCredit=1),lambda x:x.update(sessionDenied=False),lambda x:x.update(pendingControlledCalls=1),lambda x:x['cleanup'][0].update(status='rejected')]:
   bad=copy.deepcopy(good);change(bad)
   with self.assertRaises(RuntimeError):launcher.verify_xss_stored_six_result(bad)

class XssReflectedActual(unittest.TestCase):
 def test_closed_actual_admission_and_prior_profiles(self):
  profile='xss-reflected-three-actual'
  args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
  manifest=dict(cohort=profile,profile=profile,mode='actual-model',model=launcher.POLICY_MODEL,modelDigest=launcher.POLICY_DIGEST,actualExecution=True,inputSha256=launcher.XSS_REFLECTED_INPUT_SHA256,cases=[x['id'] for x in launcher.XSS_REFLECTED_CASES],wireBudget=launcher.XSS_REFLECTED_WIRE_BUDGET.copy())
  self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),profile)
  self.assertEqual(launcher.browser_stores(profile),('identity','xss'))
  for changed in [dict(mode='model-free'),dict(model='other'),dict(modelDigest='0'*64),dict(profile='codebot'),dict(cohort='codebot-rendered-parity')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,**changed})
  with self.assertRaises(ValueError):launcher.codebot_store_configuration('mcp',2222,'0123456789ab',profile)
  args.browser_profile='xss-stored-six-content-inert'
  with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,'cohort':args.browser_profile,'profile':args.browser_profile})
 def test_exact_actual_environment_and_foreign_url_denial(self):
  profile='xss-reflected-three-actual'
  args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile,node='/p/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
  urls={}
  for store in launcher.browser_stores(profile):urls.update(launcher.codebot_store_configuration(store,2222,'0123456789ab',profile)[1])
  with patch.object(pathlib.Path,'mkdir'):
   env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
   for wrong in [{},dict(urls,PG_ADMIN_DATABASE_URL='forbidden'),dict(urls,MCP_WORKSHOP_DATABASE_URL='forbidden')]:
    with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',wrong)
  self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['OLLAMA_MODEL'],launcher.POLICY_MODEL);self.assertEqual(env['OLLAMA_BASE_URL'],'http://127.0.0.1:11434')
  self.assertNotIn('OPENAI_API_KEY',env)
 def reflected_fixture(self):
  import json,hashlib,copy
  enc=lambda x:json.dumps(x,separators=(',',':'));sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  value=dict(status='passed',profile='xss-reflected-three-actual',actualModelProof=True,genuineCredit=3,installedWrites=False,cleanupFailures=[],modelCalls=8,requests={'browser':800,'api':80},cases=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for id in ['xss_r1','xss_r2','xss_r3']],cleanup=[dict(name=n,status='fulfilled') for n in ['runs','restore','browser','xss-route','routes','server','transport','pools']])
  for k in ('inertNoCredit','actualExecution','wireBinding','dashboardParity','configurationRestored','siblingPreserved','projectionRestored','sessionDenied','resetRetired','immutableHistoryPreserved','immutableEvidencePreserved'):value[k]=True
  calls=[];captures=[];completed=[]
  def call(kind,case,request,response):
   row=dict(index=len(calls),kind=kind,caseId=case,request=request,requestSha256=sha(request),response=response,responseSha256=sha(response),responseBytes=len(response.encode()),terminal='returned',status=200,responseComplete=True,responseCaptureTruncated=False);calls.append(row);return row['index']
  call('tags',None,'','{}')
  for number,spec in enumerate(launcher.XSS_REFLECTED_CASES):
   messages=[dict(role='user',content=spec['message'])];actor=call('chat',spec['id'],enc(dict(model=launcher.POLICY_MODEL,messages=messages,options={'num_predict':512,'temperature':.7})),enc({'message':{'content':'answer'},'done':True}));judge=call('chat',spec['id'],enc(dict(model=launcher.POLICY_MODEL,messages=messages,options={'num_predict':900,'temperature':0,'num_ctx':32768})),enc({'message':{'content':'judge'},'done':True}));run='run-'+str(number);evaluation='eval-'+str(number);owner=enc(['XSS','7']);packet={'rubric':{'objectiveId':spec['objective']}};result={'attempts':1,'verdict':'pass' if spec['completed'] else 'fail'}
   record=dict(user_id=7,run_id=run,owner_key=owner,owner_generation='0',evaluation_id=evaluation,objective_id=spec['objective'],workshop_key='xss_workshop',packet=enc(packet),result_json=enc(result),verdict=result['verdict'],disposition='awarded' if spec['completed'] else 'not_pass')
   if spec['completed']:completed.append(dict(user_id=7,workshop_key='xss_workshop',objective_id=spec['completed']))
   captures.append(dict(capture=dict(caseId=spec['id'],actors=[dict(messages=messages,result=dict(response='answer',provider='ollama',model=launcher.POLICY_MODEL))],grades=[dict(execution=dict(runId=run,ownerKey=owner,durableGeneration='0'),input=dict(message=spec['message'],objectiveId=spec['objective'],userId=7,response='answer'))]),body=dict(response='answer',completedObjectiveId=spec['completed']),records=[record],run=dict(run_id=run,owner_key=owner,generation='0',status='completed'),completions=copy.deepcopy(completed),binding=dict(caseId=spec['id'],status='verified',objectiveId=spec['objective'],runId=run,evaluationId=evaluation,actorIndexes=[actor],judgeIndexes=[judge],selectedActorIndex=actor,packetSha256=sha(enc(packet)))))
  wire=dict(profile=value['profile'],version='xss-reflected-three-actual-wire-v1',model=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST,closed=True,physicalPending=0,failures=[],counts=dict(incoming=8,external=9,chat=8,generate=0,metadata=1,tags=1,version=0),calls=calls)
  value['resetGeneration']={'before':0,'after':1}
  return value,wire,captures
 def test_actual_terminal_bijection_and_rejections(self):
  import copy
  value,wire,captures=self.reflected_fixture()
  launcher.verify_xss_reflected_result(value,wire,captures)
  mutations=[lambda v,w,c:w['counts'].update(incoming=9),lambda v,w,c:v['resetGeneration'].update(after=0),lambda v,w,c:v['resetGeneration'].update(before=False),lambda v,w,c:v.update(actualExecution=False),lambda v,w,c:v.update(modelCalls=True),lambda v,w,c:v['requests'].update(browser=801),lambda v,w,c:v['cleanup'].pop(),lambda v,w,c:w.update(closed=False),lambda v,w,c:w.update(physicalPending=1),lambda v,w,c:w['counts'].update(tags=29),lambda v,w,c:w['calls'][1].update(responseComplete=False),lambda v,w,c:w['calls'][1].update(response='changed'),lambda v,w,c:c.pop(),lambda v,w,c:c[0]['binding'].update(actorIndexes=[2]),lambda v,w,c:c[0]['records'][0].update(owner_generation='1'),lambda v,w,c:c[2]['records'][0].update(verdict='pass'),lambda v,w,c:c[-1]['completions'][0].update(user_id=8),lambda v,w,c:c[1]['capture']['grades'][0]['input'].update(message='retuned')]
  for mutate in mutations:
   v,w,c=copy.deepcopy((value,wire,captures));mutate(v,w,c)
   with self.assertRaises(RuntimeError):launcher.verify_xss_reflected_result(v,w,c)

 def test_r3_admission_is_closed_and_keeps_full_profile(self):
  import copy
  profile='xss-reflected-r3-actual'
  cases,input_sha,budget=launcher.reflected_contract(profile)
  self.assertEqual(cases,launcher.XSS_REFLECTED_CASES[2:])
  self.assertEqual(budget,dict(actor=4,judge=4,chat=8,tags=16,version=1,metadata=17,external=25,generate=0))
  args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
  manifest=dict(cohort=profile,profile=profile,mode='actual-model',model=launcher.POLICY_MODEL,modelDigest=launcher.POLICY_DIGEST,actualExecution=True,inputSha256=input_sha,cases=[x['id'] for x in cases],wireBudget=budget.copy())
  self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),profile)
  self.assertEqual(launcher.browser_stores(profile),('identity','xss'))
  for fields in [dict(inputSha256=launcher.XSS_REFLECTED_INPUT_SHA256),dict(cases=[x['id'] for x in launcher.XSS_REFLECTED_CASES]),dict(wireBudget=launcher.XSS_REFLECTED_WIRE_BUDGET),dict(actualExecution=False),dict(model='other')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,**fields})
  self.assertEqual(launcher.reflected_contract('xss-reflected-three-actual')[2]['external'],45)

 def test_r3_terminal_preserves_controlled_prerequisites_without_credit(self):
  import copy
  value,wire,full=self.reflected_fixture()
  prerequisites=dict(version='xss-reflected-prerequisites-v1',ownerId=7,completions=copy.deepcopy(full[1]['completions']),progress=[dict(user_key='7',objective_id=id,completed=1,completed_at='2026-09-29T00:00:00.000Z') for id in ['xss_r1','xss_r2']],judgments=[],packets=[])
  captures=copy.deepcopy(full[2:]);value.update(profile='xss-reflected-r3-actual',genuineCredit=1,controlledPrerequisiteCount=2,actualObjectiveIds=['xss_r3'],prerequisiteProjection=True,prerequisiteEvidenceEmpty=True,modelCalls=4)
  wire.update(profile=value['profile'],version=value['profile']+'-wire-v1');wire['calls']=[wire['calls'][0]]+wire['calls'][5:]
  for index,row in enumerate(wire['calls']):row['index']=index
  for capture in captures:
   capture['progress']=copy.deepcopy(prerequisites['progress'])
   if capture['capture']['caseId']=='reflected-execute':capture['progress'].append(dict(user_key='7',objective_id='xss_r3',completed=1,completed_at='2026-09-29T00:00:01.000Z'))
   binding=capture['binding']
   for key in ['actorIndexes','judgeIndexes']:binding[key]=[x-4 for x in binding[key]]
   binding['selectedActorIndex']-=4
  wire['counts'].update(incoming=4,external=5,chat=4)
  launcher.verify_xss_reflected_result(value,wire,captures,prerequisites)
  mutations=[lambda v,w,c,p:v.update(genuineCredit=3),lambda v,w,c,p:v.update(controlledPrerequisiteCount=True),lambda v,w,c,p:v.update(actualObjectiveIds=['xss_r1','xss_r3']),lambda v,w,c,p:p['judgments'].append({}),lambda v,w,c,p:p['packets'].append({}),lambda v,w,c,p:p.update(ownerId=8),lambda v,w,c,p:p['completions'].pop(),lambda v,w,c,p:p['progress'].pop(),lambda v,w,c,p:p['progress'][0].update(user_key='8'),lambda v,w,c,p:c[0]['progress'][0].update(completed_at='changed'),lambda v,w,c,p:c[0]['completions'][0].update(created_at='changed'),lambda v,w,c,p:c[0]['completions'].append(dict(user_id=7,workshop_key='xss_workshop',objective_id='xss_r3')),lambda v,w,c,p:w['counts'].update(tags=17),lambda v,w,c,p:c.pop()]
  for mutation in mutations:
   v,w,c,p=copy.deepcopy((value,wire,captures,prerequisites));mutation(v,w,c,p)
   with self.assertRaises(RuntimeError):launcher.verify_xss_reflected_result(v,w,c,p)
  with self.assertRaises(RuntimeError):launcher.verify_xss_reflected_result(value,wire,captures)

class ReflectedReceiptCleanupOwnership(unittest.TestCase):
 def test_actual_success_and_failed_receipt_paths_keep_owned_container_name(self):
  import ast,json
  source=(HERE/'run-setup-database-phase-isolated.py').read_text()
  tree=ast.parse(source)
  main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
  receipt=next(n for n in ast.walk(main) if isinstance(n,ast.If) and 'XSS_REFLECTED_PROFILES' in ast.unparse(n.test) and any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='documents' for t in x.targets) for x in n.body))
  cleanup=next(n for n in ast.walk(main) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Subscript) and ast.unparse(t)=="state['containerCleanup']" for t in n.targets))
  module=ast.fix_missing_locations(ast.Module(body=[ast.Try(body=receipt.body,handlers=[],orelse=[],finalbody=[cleanup])],type_ignores=[]))
  compiled=compile(module,'actual-parent-receipt-and-cleanup','exec')
  for profile in launcher.XSS_REFLECTED_PROFILES:
   for fail in (False,True):
    with self.subTest(profile=profile,failedReceipt=fail):
     original='dvaia-setup-phase-0123456789ab';identifier='a'*64;image='sha256:'+'b'*64;labels={'dvaia.test.owner':'owned'};commands=[];alive=[True];validated=[]
     class Proof:
      def __init__(self,name):self.name=name
      def lstat(self):
       if fail:raise OSError('controlled receipt failure')
       return SimpleNamespace(st_nlink=1,st_uid=launcher.os.getuid(),st_mode=0o100600,st_size=2)
      def is_symlink(self):return False
      def is_file(self):return True
      def read_text(self):return '{}'
     class Evidence:
      def __truediv__(self,name):return Proof(name)
     def docker(argv,timeout=None):
      commands.append(argv)
      if argv==['info','--format','{{.ID}}']:return SimpleNamespace(returncode=0,stdout='daemon',stderr='')
      if argv[:3]==['inspect','--type','container']:
       target=argv[3]
       if target!=original or not alive[0]:return SimpleNamespace(returncode=1,stdout='',stderr='Error: No such object: '+target)
       return SimpleNamespace(returncode=0,stdout=json.dumps([dict(Id=identifier,Name='/'+original,Image=image,Config={'Labels':labels})]),stderr='')
      if argv==['rm','--force','--volumes',identifier]:alive[0]=False;return SimpleNamespace(returncode=0,stdout='',stderr='')
      raise AssertionError('unexpected command')
     ns=dict(launcher.__dict__,args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile,docker_daemon='daemon',image_id=image),evidence=Evidence(),result={},name=original,labels=labels,captured=identifier,docker=docker,deadline=123,state={},within_cleanup=lambda deadline,action,*rest:action(),verify_xss_reflected_result=lambda *args:validated.append(args))
     if fail:
      with self.assertRaises(OSError):exec(compiled,ns)
     else:exec(compiled,ns)
     self.assertEqual(ns['name'],original)
     self.assertFalse(alive[0],'actual captured container must be retired')
     self.assertEqual(ns['state']['containerCleanup'],dict(status='removed_absence_verified',containerId=identifier))
     self.assertEqual([a[3] for a in commands if a[:3]==['inspect','--type','container']],[original,original])
     self.assertEqual(len(validated),0 if fail else 1)


class XssEmailContent(unittest.TestCase):
 def test_closed_model_free_admission_and_environment(self):
  profile='xss-email-three-content';args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile,node='/node',package='/main',manifest='/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
  manifest=dict(cohort=profile,profile=profile,mode='model-free')
  self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),profile)
  self.assertEqual(launcher.browser_stores(profile),('identity','xss'))
  for fields in [dict(mode='actual-model'),dict(profile='xss-stored-six-content-inert'),dict(cohort='other')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,**fields})
  urls={}
  for store in launcher.browser_stores(profile):urls.update(launcher.codebot_store_configuration(store,2222,'0123456789ab',profile)[1])
  with patch.object(pathlib.Path,'mkdir'):
   env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',urls)
   with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',{**urls,'MCP_WORKSHOP_DATABASE_URL':'foreign'})
  self.assertEqual(env['AI_PROVIDER'],'mock');self.assertNotIn('OLLAMA_BASE_URL',env);self.assertNotIn('JUDGE_PROVIDER',env)
 def test_seed_content_projection_and_cleanup_are_required(self):
  import copy
  value=dict(status='passed',profile='xss-email-three-content',actualModelProof=False,modelCalls=0,genuineCredit=0,installedWrites=False,controlledCalls=0,pendingControlledCalls=0,controlledProjectionCount=3,cleanupFailures=[],requests=dict(browser=800,api=80))
  for key in ['dashboardParity','configurationRestored','siblingPreserved','projectionRestored','immutableEvidencePreserved','resetRetired','emailSetup','emailBrowserTarget','emailBrowserInertDenied','mailProviderClosed','emailBrowserRetired']:value[key]=True
  value['emailBrowserCases']=['active-target','comment-target','textarea-target']
  value['cases']=[dict(id=id,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for id in ['xss_e1','xss_e2','xss_e3']]
  value['seedReceipt']=dict(version='xss-email-hint-seed-v1',**dict.fromkeys(['freshDefaults','managedPriorHints','instructorHintsPreserved','nullHintsPreserved','secondRunNoop','siblingCatalogPreserved','rollbackExact'],True))
  value['cleanup']=[dict(name=n,status='fulfilled') for n in ['runs','restore','browser','xss-route','routes','server','pools']]
  launcher.verify_xss_email_three_result(value)
  mutations=[lambda v:v.update(modelCalls=1),lambda v:v.update(genuineCredit=1),lambda v:v.update(actualModelProof=True),lambda v:v.update(controlledProjectionCount=True),lambda v:v.update(controlledCalls=1),lambda v:v.update(emailSetup=False),lambda v:v.update(emailBrowserTarget=False),lambda v:v.update(emailBrowserInertDenied=False),lambda v:v.update(mailProviderClosed=False),lambda v:v.update(emailBrowserRetired=False),lambda v:v['emailBrowserCases'].pop(),lambda v:v['cases'].pop(),lambda v:v['cases'][0].update(id='xss_r1'),lambda v:v['cases'][0].update(independentGates=1),lambda v:v['requests'].update(browser=801),lambda v:v['cleanup'].pop(),lambda v:v['seedReceipt'].update(unknown=True)]
  for field in ['freshDefaults','managedPriorHints','instructorHintsPreserved','nullHintsPreserved','secondRunNoop','siblingCatalogPreserved','rollbackExact']:
   bad=copy.deepcopy(value);bad['seedReceipt'][field]=False
   with self.assertRaises(RuntimeError):launcher.verify_xss_email_three_result(bad)
  for mutation in mutations:
   bad=copy.deepcopy(value);mutation(bad)
   with self.assertRaises(RuntimeError):launcher.verify_xss_email_three_result(bad)

class CsrfTwelveContent(unittest.TestCase):
 profile='csrf-twelve-content'
 def test_closed_model_free_store_and_environment_admission(self):
  profile=self.profile;args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile,node='/node',package='/main',manifest='/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
  manifest=dict(cohort=profile,profile=profile,mode='model-free')
  self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),profile)
  self.assertEqual(launcher.browser_stores(profile),('identity','csrf'))
  self.assertEqual(launcher.scenario_bounds('codebot-rendered-parity'),(780,600,120))
  for fields in [dict(mode='actual-model'),dict(profile='xss-email-three-content'),dict(cohort='other')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,**fields})
  urls={}
  for store in launcher.browser_stores(profile):
   sql,part=launcher.codebot_store_configuration(store,2222,'0123456789ab',profile);urls.update(part)
   self.assertIn('dvaia_test_codebot_parity_0123456789ab_'+store,sql)
  with patch.object(pathlib.Path,'mkdir'):
   env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',urls)
   for bad in [{**urls,'XSS_WORKSHOP_DATABASE_URL':'foreign'},{k:v for k,v in urls.items() if k!='CSRF_WORKSHOP_MIGRATION_DATABASE_URL'}]:
    with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',bad)
  self.assertEqual(env['AI_PROVIDER'],'mock');self.assertNotIn('OLLAMA_BASE_URL',env);self.assertNotIn('JUDGE_PROVIDER',env)

 def test_all_twelve_scoped_receipts_and_retirement_required(self):
  import copy
  value=dict(status='passed',profile=self.profile,actualModelProof=False,modelCalls=0,genuineCredit=0,installedWrites=False,controlledCalls=0,pendingControlledCalls=0,controlledProjectionCount=12,cleanupFailures=[],requests=dict(browser=1600,api=120),immutableEvidenceScope='empty controlled owner; retained genuine evidence reviewed separately')
  required=['dashboardParity','configurationRestored','siblingPreserved','projectionRestored','immutableEvidencePreserved','resetRetired','emailSetup','sessionDenied','sessionReload']
  for key in required:value[key]=True
  value['cases']=[dict(id='csrf_'+family+str(n),learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for family in ['g','p','x','i'] for n in [1,2,3]]
  value['cleanup']=[dict(name=n,status='fulfilled') for n in ['runs','restore','browser','csrf-route','teaching','mail','routes','server','pools']]
  value['masterGateObjectiveIds']=[c['id'] for c in value['cases']]
  if self.profile=='csrf-rag-content-lifecycle':value['cases']=value['cases'][-3:]
  value['contentObjectiveIds']=[c['id'] for c in value['cases']]
  launcher.verify_csrf_twelve_result(value,self.profile)
  for key in required:
   bad=copy.deepcopy(value);bad[key]=False
   with self.assertRaises(RuntimeError):launcher.verify_csrf_twelve_result(bad,self.profile)
  mutations=[lambda v:v.update(modelCalls=1),lambda v:v.update(genuineCredit=1),lambda v:v.update(actualModelProof=True),lambda v:v.update(controlledProjectionCount=True),lambda v:v.update(controlledCalls=1),lambda v:v.update(pendingControlledCalls=1),lambda v:v.update(immutableEvidenceScope='genuine evidence preserved'),lambda v:v['cases'].pop(),lambda v:v['cases'].reverse(),lambda v:v['cases'][0].update(id='xss_e1'),lambda v:v['cases'][0].update(independentGates=1),lambda v:v['requests'].update(browser=1601),lambda v:v['requests'].update(api=121),lambda v:v['requests'].update(api=True),lambda v:v['cleanup'].pop(),lambda v:v['cleanup'][3].update(status='rejected')]
  if self.profile=='csrf-rag-content-lifecycle':mutations.extend([lambda v:v.pop('contentObjectiveIds'),lambda v:v['masterGateObjectiveIds'].pop(),lambda v:v['contentObjectiveIds'].reverse(),lambda v:v.update(controlledProjectionCount=3)])
  for mutation in mutations:
   bad=copy.deepcopy(value);mutation(bad)
   with self.assertRaises(RuntimeError):launcher.verify_csrf_twelve_result(bad,self.profile)

class CsrfRagContinuation(CsrfTwelveContent):
 profile='csrf-rag-content-lifecycle'
 def test_scope_cannot_be_substituted(self):
  with self.assertRaises(RuntimeError):launcher.verify_csrf_twelve_result({},'csrf-other')
  import inspect
  entry=pathlib.Path('tests/postgres/codeBotRenderedParityMainV1.js').read_text()
  self.assertIn("['csrf-twelve-content','csrf-rag-content-lifecycle'].includes(process.env.CODEBOT_PARITY_PROFILE)",entry)
  self.assertIn('source:SOURCE,profile:process.env.CODEBOT_PARITY_PROFILE',entry)

class McpIndirectSupplyContent(unittest.TestCase):
 def test_closed_scope_store_and_model_free(self):
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='mcp-indirect-supply-content')
  manifest={'cohort':a.browser_profile,'profile':a.browser_profile,'mode':'model-free'}
  self.assertEqual(launcher.validate_browser_profile_manifest(a,manifest),a.browser_profile)
  self.assertEqual(launcher.browser_stores(a.browser_profile),('identity','mcp'))
  self.assertEqual(launcher.scenario_bounds(a.scenario),(780,600,120))
  for key,val in [('mode','actual-model'),('profile','mcp-audit-content'),('cohort','mcp-audit-content')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,{**manifest,key:val})
  a.scenario='mcp-mounted-http'
  with self.assertRaises(ValueError):launcher.browser_profile(a)
 def test_exact_current_content_and_controlled_projection(self):
  import copy
  v={'status':'passed','profile':'mcp-indirect-supply-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':1,'completionScope':'Controlled supply completion projection only; no earned credit','requests':{'browser':400,'api':40},'cleanup':[{'name':n,'status':'fulfilled'} for n in ['browser','routes','server','pools']]}
  flags=['freshDefaults','secondRunNoop','supplyDone','countParity','contentRestored','siblingPreserved']
  v.update(dict.fromkeys(flags,True));v['cases']=[dict(id=i,label=True,hint=True,solution=True,adminPreview=True) for i in ['mcp_indirect_injection','mcp_supply_chain']]
  launcher.verify_mcp_indirect_supply_content_result(v)
  zero=copy.deepcopy(v);zero['requests']['api']=0
  launcher.verify_mcp_indirect_supply_content_result(zero)
  mutations=[lambda x:x.update(modelCalls=1),lambda x:x.update(genuineCredit=1),lambda x:x.update(controlledProjectionCount=True),lambda x:x.update(completionScope='earned'),lambda x:x['cases'].reverse(),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(hint=1),lambda x:x['requests'].update(browser=401),lambda x:x['requests'].update(api=41),lambda x:x['requests'].update(api=-1),lambda x:x['requests'].update(api=True),lambda x:x['cleanup'].pop()]
  for flag in flags:
   bad=copy.deepcopy(v);bad[flag]=False
   with self.assertRaises(RuntimeError):launcher.verify_mcp_indirect_supply_content_result(bad)
  for mutate in mutations:
   bad=copy.deepcopy(v);mutate(bad)
   with self.assertRaises(RuntimeError):launcher.verify_mcp_indirect_supply_content_result(bad)

class McpRemainingNineContent(unittest.TestCase):
 def test_closed_scope_store_and_model_free(self):
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='mcp-remaining-nine-content')
  manifest={'cohort':a.browser_profile,'profile':a.browser_profile,'mode':'model-free'}
  self.assertEqual(launcher.validate_browser_profile_manifest(a,manifest),a.browser_profile)
  self.assertEqual(launcher.browser_stores(a.browser_profile),('identity','mcp'))
  self.assertEqual(launcher.scenario_bounds(a.scenario),(780,600,120))
  for key,val in [('mode','actual-model'),('profile','mcp-audit-content'),('cohort','mcp-audit-content')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,{**manifest,key:val})
  a.scenario='mcp-mounted-http'
  with self.assertRaises(ValueError):launcher.browser_profile(a)
 def test_exact_current_content_and_controlled_projection(self):
  import copy
  v={'status':'passed','profile':'mcp-remaining-nine-content','actualModelProof':False,'modelCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':9,'completionScope':'Controlled remaining-nine completion projections only; no earned credit','requests':{'browser':1000,'api':40},'cleanup':[{'name':n,'status':'fulfilled'} for n in ['browser','routes','server','pools']]}
  flags=['freshDefaults','secondRunNoop','allDone','countParity','contentRestored','siblingPreserved','timeParity','instructorTimeParity','timeRestored','immutableEvidencePreserved']
  v.update(dict.fromkeys(flags,True));v['cases']=[dict(id=i,label=True,hint=True,solution=True,adminPreview=True,done=True) for i in ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_audit_gap','mcp_shadow_server']]
  v['controlledTimeSeconds']=165
  v['timeProof']={'ownerId':1,'siblingId':2,'controlledSeconds':165,'siblingSeconds':23,'instructorSeconds':165,'learnerRoutes':[{'route':r,'seconds':165} for r in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']],'before':[{'id':'7','user_id':'2','workshop_key':'mcp_workshop','session_start':'2026-09-30T00:00:00.000Z','last_heartbeat':'2026-09-30T00:00:23.000Z','duration_seconds':23}],'after':[{'id':'7','user_id':'2','workshop_key':'mcp_workshop','session_start':'2026-09-30T00:00:00.000Z','last_heartbeat':'2026-09-30T00:00:23.000Z','duration_seconds':23}]}
  launcher.verify_mcp_remaining_nine_content_result(v)
  zero=copy.deepcopy(v);zero['requests']['api']=0
  launcher.verify_mcp_remaining_nine_content_result(zero)
  mutations=[lambda x:x.update(modelCalls=1),lambda x:x.update(genuineCredit=1),lambda x:x.update(controlledProjectionCount=True),lambda x:x.update(completionScope='earned'),lambda x:x['cases'].reverse(),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(hint=1),lambda x:x['cases'][0].update(done=False),lambda x:x.update(controlledProjectionCount=8),lambda x:x['requests'].update(browser=1001),lambda x:x['requests'].update(api=41),lambda x:x['requests'].update(api=-1),lambda x:x['requests'].update(api=True),lambda x:x['cleanup'].pop()]
  mutations.extend([lambda x:x['timeProof'].update(ownerId=2),lambda x:x['timeProof'].update(siblingId=True),lambda x:[x['timeProof'][k][0].update(user_id='1') for k in ['before','after']],lambda x:[x['timeProof'][k][0].update(duration_seconds=0) for k in ['before','after']],lambda x:[x['timeProof'][k][0].update(workshop_key='other') for k in ['before','after']],lambda x:[x['timeProof'][k][0].pop('last_heartbeat') for k in ['before','after']],lambda x:x.pop('timeProof'),lambda x:x.update(controlledTimeSeconds=0),lambda x:x.update(controlledTimeSeconds=True),lambda x:x['timeProof'].update(controlledSeconds=0),lambda x:x['timeProof'].update(siblingSeconds=0),lambda x:x['timeProof'].update(instructorSeconds=0),lambda x:x['timeProof']['learnerRoutes'][0].update(seconds=0),lambda x:x['timeProof']['learnerRoutes'].reverse(),lambda x:x['timeProof']['learnerRoutes'].pop(),lambda x:x['timeProof'].update(before=[],after=[]),lambda x:x['timeProof']['after'][0].update(duration_seconds=24)])
  for flag in flags:
   bad=copy.deepcopy(v);bad[flag]=False
   with self.assertRaises(RuntimeError):launcher.verify_mcp_remaining_nine_content_result(bad)
  for mutate in mutations:
   bad=copy.deepcopy(v);mutate(bad)
   with self.assertRaises(RuntimeError):launcher.verify_mcp_remaining_nine_content_result(bad)


class IpiEmailFiveContent(unittest.TestCase):
 def test_closed_identity_scope_and_existing_bounds(self):
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='ipi-email-five-content')
  m={'cohort':a.browser_profile,'profile':a.browser_profile,'mode':'model-free'}
  self.assertEqual(launcher.validate_browser_profile_manifest(a,m),a.browser_profile)
  self.assertEqual(launcher.browser_stores(a.browser_profile),('identity',))
  self.assertEqual(launcher.scenario_bounds(a.scenario),(780,600,120))
  self.assertEqual(launcher.browser_stores('codebot'),('identity','supply_chain'))
  for key,value in [('mode','actual-model'),('profile','codebot'),('cohort','codebot')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,{**m,key:value})
  with self.assertRaises(ValueError):launcher.codebot_environment(a,None,None,None,{'IDENTITY_DATABASE_URL':'unused'})
  a.scenario='mcp-mounted-http'
  with self.assertRaises(ValueError):launcher.browser_profile(a)
 def test_capture_requires_exact_fixture_and_identity_migrations(self):
  path=HERE.parents[1]/'tests/release-inputs/capture-codebot-parity-main.py'
  spec=importlib.util.spec_from_file_location('ipi_capture',path);capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
  required,dirs=capture.profile_requirements('ipi-email-five-content')
  self.assertIn('tests/postgres/ipiEmailRenderedFixture.js',required)
  self.assertIn('tests/ipiEmailRenderedQualificationContract.test.js',required)
  self.assertEqual(dirs,['db/postgres/identity-migrations'])

 def test_exact_receipt_and_denials(self):
  import copy
  v={'status':'passed','profile':'ipi-email-five-content','actualModelProof':False,'modelCalls':0,'mailCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':5,'controlledJudgeCalls':2,'controlledSessionOwners':2,'completionScope':'Controlled five email completion projections only; no earned credit','requests':{'browser':1000,'api':80},'cleanup':[{'name':n,'status':'fulfilled'} for n in ['restore','browser','mail','rag','routes','server','pools']]}
  flags=['dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved','sessionPreEffectDenied','sessionJudgeCommitDenied','sessionPostCommitPublicationDenied','sessionPriorCommitPreserved','sessionSiblingPreserved'];v.update(dict.fromkeys(flags,True))
  v['cases']=[dict(id=i,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for i in ['email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense']]
  launcher.verify_ipi_email_five_content_result(v)
  zero=copy.deepcopy(v);zero['requests']['api']=0;launcher.verify_ipi_email_five_content_result(zero)
  mutations=[lambda x:x.update(controlledJudgeCalls=True),lambda x:x.update(controlledJudgeCalls=1),lambda x:x.update(controlledSessionOwners=3),lambda x:x.pop('sessionPreEffectDenied'),lambda x:x.update(sessionJudgeCommitDenied=1),lambda x:x.update(modelCalls=1),lambda x:x.update(mailCalls=1),lambda x:x.update(genuineCredit=1),lambda x:x.update(controlledProjectionCount=True),lambda x:x.update(completionScope='earned'),lambda x:x['cases'].reverse(),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(learnerContent=1),lambda x:x['requests'].update(browser=1001),lambda x:x['requests'].update(api=81),lambda x:x['requests'].update(api=-1),lambda x:x['requests'].update(api=True),lambda x:x['cleanup'].reverse()]
  for flag in flags:
   bad=copy.deepcopy(v);bad[flag]=False
   with self.assertRaises(RuntimeError):launcher.verify_ipi_email_five_content_result(bad)
  for mutate in mutations:
   bad=copy.deepcopy(v);mutate(bad)
   with self.assertRaises(RuntimeError):launcher.verify_ipi_email_five_content_result(bad)


class XssBuilderReset(unittest.TestCase):
 def test_closed_profiles_and_exact_model_free_stores(self):
  for profile in launcher.XSS_BUILDER_RESET_PROFILES:
   args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile,node='/node',package='/main',manifest='/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64)
   manifest=dict(cohort=profile,profile=profile,mode='model-free')
   self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),profile)
   self.assertEqual(launcher.browser_stores(profile),('identity','xss'))
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,'mode':'actual-model'})
   urls={}
   for store in launcher.browser_stores(profile):urls.update(launcher.codebot_store_configuration(store,2222,'0123456789ab',profile)[1])
   with patch.object(pathlib.Path,'mkdir'):
    env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',urls)
    with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/r'),'owner',{**urls,'MCP_WORKSHOP_DATABASE_URL':'foreign'})
   self.assertEqual(env['AI_PROVIDER'],'mock');self.assertNotIn('OLLAMA_BASE_URL',env);self.assertNotIn('JUDGE_PROVIDER',env)
 def test_every_qualification_and_cleanup_flag_required(self):
  import copy
  for profile in launcher.XSS_BUILDER_RESET_PROFILES:
   fresh=profile==launcher.XSS_BUILDER_RESET_PROFILES[0]
   value=dict(status='passed',profile=profile,mode='fresh' if fresh else 'upgrade',actualModelProof=False,modelCalls=0,judgeCalls=0,genuineCredit=0,installedWrites=False,cleanupFailures=[],requests=dict(browser=0,api=0),cleanup=[dict(name='pools',status='fulfilled')])
   value['migration']=dict(fresh=fresh,populatedUpgrade=not fresh,**dict.fromkeys(['exactNewMigrations','priorChecksumsPreserved','secondRunNoop','runtimeGrants','publicExecuteDenied'],True))
   value['seed']=dict.fromkeys(['fourDefaults','instructorContentPreserved','nullContentPreserved','noHistoricalCredit','secondRunNoop'],True)
   value['reset']=dict.fromkeys(['pendingBlocks','implicitRecovery','terminalReplay','newRunUncancelled','exactReceipt','siblingPreserved','immutablePreserved','profilePreserved','builderOnly','ownerDeletionReceiptsRetired','lateWriteDenied'],True)
   launcher.verify_xss_builder_reset_result(value,profile)
   for group in ['migration','seed','reset']:
    for key in value[group]:
     for badvalue in [not value[group][key],1,None]:
      bad=copy.deepcopy(value);bad[group][key]=badvalue
      with self.assertRaises(RuntimeError):launcher.verify_xss_builder_reset_result(bad,profile)
   for key,badvalue in [('modelCalls',1),('judgeCalls',1),('genuineCredit',1),('installedWrites',True),('cleanup',[]),('requests',dict(browser=1,api=0)),('requests',dict(browser=False,api=False)),('cleanupFailures',['failed'])]:
    bad=copy.deepcopy(value);bad[key]=badvalue
    with self.assertRaises(RuntimeError):launcher.verify_xss_builder_reset_result(bad,profile)


class XssBuilderNoBrowserCleanup(unittest.TestCase):
 def test_sql_only_profiles_require_absent_journal_and_retired_group(self):
  for profile in launcher.XSS_BUILDER_RESET_PROFILES:
   args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
   state=dict(nativeStarted=True,nativePid=123,exitCode=0)
   with patch.object(pathlib.Path,'exists',return_value=False):
    self.assertEqual(launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),state,[]),dict(started=False,expectedNoBrowser=True,groupAbsent=True,profileRetained=False))
    for rows in [[(123,123,501)],[(456,123,501)]]:
     with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),state,rows)
    with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),{**state,'nativePid':None},[])
   with patch.object(pathlib.Path,'exists',return_value=True):
    with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),state,[])
 def test_dangling_browser_artifacts_are_not_absence(self):
  args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=launcher.XSS_BUILDER_RESET_PROFILES[0])
  with patch.object(pathlib.Path,'exists',return_value=False),patch.object(pathlib.Path,'is_symlink',return_value=True):
   with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),dict(nativeStarted=True,nativePid=123),[])
 def test_browser_profiles_keep_original_browser_evidence_requirement(self):
  args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='xss-email-three-content')
  with patch.object(launcher,'codebot_browser_helper') as helper:
   helper.return_value.verify_browser_absence.side_effect=RuntimeError('Missing browser ownership evidence')
   with self.assertRaisesRegex(RuntimeError,'Missing browser'):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),dict(exitCode=0),[])

class XssBuilderActual(unittest.TestCase):
 def manifest(self):
  p=launcher.XSS_BUILDER_ACTUAL_PROFILE
  return dict(cohort=p,profile=p,mode='actual-model',model=launcher.POLICY_MODEL,modelDigest=launcher.POLICY_DIGEST,actualExecution=True,inputSha256=launcher.XSS_BUILDER_ACTUAL_INPUT_SHA256,cases=[x['id'] for x in launcher.XSS_BUILDER_ACTUAL_CASES],wireBudget=launcher.XSS_BUILDER_ACTUAL_WIRE_BUDGET.copy())
 def test_frozen_admission_and_no_reset_browser_exemption(self):
  import copy
  p=launcher.XSS_BUILDER_ACTUAL_PROFILE;args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=p);m=self.manifest()
  self.assertEqual(launcher.validate_browser_profile_manifest(args,m),p);self.assertEqual(launcher.browser_stores(p),('identity','xss'))
  self.assertEqual(m['wireBudget'],dict(actor=25,judge=10,generate=25,chat=10,tags=4,version=1,metadata=5,external=40))
  for key in m:
   changed=copy.deepcopy(m);changed[key]=None
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,changed)
  for key in m['wireBudget']:
   for wrong in [True,m['wireBudget'][key]+1]:
    changed=copy.deepcopy(m);changed['wireBudget'][key]=wrong
    with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,changed)
  self.assertEqual(launcher.XSS_BUILDER_RESET_PROFILES,('xss-email-builder-fresh-reset','xss-email-builder-upgrade-reset'))
  with patch.object(launcher,'codebot_browser_helper') as helper:
   helper.return_value.verify_browser_absence.side_effect=RuntimeError('Missing browser ownership evidence')
   with self.assertRaisesRegex(RuntimeError,'Missing browser'):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),dict(exitCode=0),[])
 def test_actual_clean_environment_is_exact_and_prior_profile_remains_mock(self):
  p=launcher.XSS_BUILDER_ACTUAL_PROFILE;args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=p,node='/p/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64);urls={}
  for store in launcher.browser_stores(p):urls.update(launcher.codebot_store_configuration(store,2222,'0123456789ab',p)[1])
  with patch.object(pathlib.Path,'mkdir'):
   env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
   for wrong in [{},dict(urls,PG_ADMIN_DATABASE_URL='forbidden')]:
    with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',wrong)
   args.browser_profile='xss-email-builder-fresh-reset';old=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
  self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['JUDGE_PROVIDER'],'ollama');self.assertEqual(old['AI_PROVIDER'],'mock');self.assertNotIn('JUDGE_PROVIDER',old)
 def fixture(self):
  # Synthetic receipt validator fixture only: no browser, database or model runs.
  import json,hashlib,copy
  enc=lambda x:json.dumps(x,separators=(',',':'),ensure_ascii=False);sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  p=launcher.XSS_BUILDER_ACTUAL_PROFILE;calls=[];captures=[];cases=[];prior=[]
  def wire(kind,case,request,response):
   request='' if request is None else enc(request);response=enc(response);row=dict(profile=p,index=len(calls),kind=kind,caseId=case,method='GET' if kind in ['tags','version'] else 'POST',path='/api/'+kind,request=request,requestBytes=len(request.encode()),requestSha256=sha(request),response=response,responseBytes=len(response.encode()),responseSha256=sha(response),terminal='returned',status=200,responseComplete=True,responseCaptureTruncated=False);calls.append(row);return row
  wire('tags',None,None,{'models':[{'name':launcher.POLICY_MODEL,'digest':launcher.POLICY_DIGEST}]})
  for number,frozen in enumerate(launcher.XSS_BUILDER_ACTUAL_CASES):
   spec=copy.deepcopy(frozen);positive=spec['positive'];level=spec['level'];owner=7 if positive else 8;run='run-'+str(number);evaluation='eval-'+str(number);ownerkey=enc(['XSS_EMAIL',str(owner)]);execution=dict(runId=run,ownerKey=ownerkey,durableGeneration='0');actors=[]
   for tool in ['read_profile','generate_template',None]:
    decision=tool is not None;opts={'temperature':0,'num_predict':300,'num_ctx':8192} if decision else {'temperature':.7,'num_predict':1000};options={**opts,'max_tokens':opts['num_predict']};prompt='You are an email template builder.' if decision else 'You are a professional email template generator.';response=enc({'tool':tool}) if decision else '<html>synthetic controlled validator fixture</html>';request=dict(model=launcher.POLICY_MODEL,stream=True,prompt=prompt,options=opts)
    if decision:
     request['format']={'type':'object','additionalProperties':False,'required':['tool'],'properties':{'tool':{'type':'string','enum':['read_profile','finish'] if tool=='read_profile' else ['generate_template','finish']}}};options['format']=copy.deepcopy(request['format'])
    wire('generate',spec['id'],request,dict(model=launcher.POLICY_MODEL,response=response,done=True,done_reason='stop'));actors.append(dict(prompt=prompt,options=options,result=dict(provider='ollama',model=launcher.POLICY_MODEL,response=response)))
   html=actors[-1]['result']['response'];profile=dict(spec['profile'],id=owner,user_id=owner);spec['profileSnapshot']=profile
   browsers=[dict(method='qualify',html=html,options={},result={'syntheticCookieOnly':True}),dict(method='qualifyDocument' if level==1 else 'qualify',html=html,options=({'scriptSource':profile['full_name']} if level==1 else {'eventSource':profile['signature_html' if level==2 else 'company_name']} if level<4 else {'eventSources':['onerror="alert(44)"']}),result={'syntheticCookieOnly':True,'scriptExecuted' if level==1 else 'targetEventExecuted':positive,**({'targetEffectObserved':True} if level!=1 else {})})]
   facts=dict(all_required_proofs=positive,actual_model_generation=True,durable_template_effect=True);rubric=dict(objectiveId=spec['objectiveId'],requiredFacts=list(facts));evidence=[dict(id='generation_receipt',content=dict(templateId=number+1,authenticatedOwnerId=str(owner),actualModel=True))];packet=dict(rubric=rubric,evidence=evidence,facts=facts);verdict='pass' if positive else 'fail';result=dict(verdict=verdict,attempts=1)
   messages=[dict(role='system',content='Policy\nAUTHORITATIVE RUBRIC:\n'+enc(rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+enc(facts)+'\nEnd'),dict(role='user',content=enc(evidence))]
   wire('chat',spec['id'],dict(model=launcher.POLICY_MODEL,stream=True,options={'temperature':0,'num_predict':900,'num_ctx':32768},messages=messages,format={'type':'object'}),dict(model=launcher.POLICY_MODEL,message={'content':enc(result)},done=True,done_reason='stop'))
   record=dict(user_id=owner,run_id=run,owner_key=ownerkey,owner_generation='0',generation=0,evaluation_id=evaluation,objective_id=spec['objectiveId'],workshop_key='xss_email_builder',packet=enc(packet),evidence_digest=sha(enc(packet)),result_json=result,verdict=verdict,disposition='awarded' if positive else 'not_pass')
   template=dict(id=number+1,user_id=owner,html_content=html);effects=[dict(effect_key=run+':'+name,run_id=run,owner_key=ownerkey,generation='0',status='completed') for name in ['read_profile','persist_template']]
   if positive:prior.append(dict(user_id=owner,workshop_key='xss_email_builder',objective_id=spec['objectiveId']))
   captures.append(dict(spec=spec,actualRequest=copy.deepcopy(spec['request']),ownerId=owner,error=None,run=dict(run_id=run,owner_key=ownerkey,generation='0',status='completed'),effects=effects,records=[record],template=template,reply=dict(status=200,body=dict(template=dict(id=number+1,html=html),completedLevels=[level] if positive else [])),capture=dict(caseId=spec['id'],execution=execution,actors=actors,browsers=browsers,graderInput=dict(persistedHtml=html,rawModelResponse=actors[-1]['result'],profile=profile,prompt=spec['request']['prompt'],includeSignature=spec['request']['includeSignature'],requestedLevel=level),grades=[dict(execution=execution,input=dict(rubric=rubric,evidence=evidence,facts=facts,attempt={'generation':0}),output={'completed':positive})]),snapshot={'completions':[{'row':x} for x in copy.deepcopy(prior)] if positive else []},**({'preview':{'sandbox':'allow-scripts allow-modals','csp':'sandbox allow-scripts allow-modals','html':'Content-Security-Policy'}} if positive else {})))
   cases.append(dict(caseId=spec['id'],objectiveId=spec['objectiveId'],status='verified',positive=positive,runId=run,evaluationId=evaluation,actorCalls=3,judgeCalls=1,**(dict(learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) if positive else {})))
  value=dict(profile=p,status='passed',actualModelProof=True,genuineCredit=4,controlledProjectionCount=0,installedWrites=False,cleanupFailures=[],requests={'browser':300,'api':30},modelCalls=15,judgeCalls=5,cases=cases,cleanup=[dict(name=n,status='fulfilled') for n in ['restore','qualification-browser','browser','routes','server','transport','pools']])
  value.update(dict.fromkeys(['wireBinding','masterGates','dashboardParity','adminProgress','sessionDenied','foreignDenied','resetRetired','resetReplay','immutableEvidencePreserved','profilePreserved','siblingPreserved','configurationRestored'],True))
  actual=dict(profile=p,version=p+'-wire-v1',model=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST,closed=True,physicalPending=0,failures=[],counts=dict(incoming=20,external=21,generate=15,chat=5,tags=1,version=0,metadata=1),calls=calls)
  lifecycle={'progress':[dict(route=route,challenge=dict(workshopKey='xss_email_builder',completedObjectiveCount=4,objectiveCount=4)) for route in ['/workshop/progress','/workshop/challenges','/workshop-dashboard']]}
  return value,actual,captures,lifecycle
 def test_terminal_wire_evidence_progress_bijection_and_mutations(self):
  import copy
  original=self.fixture();self.assertTrue(launcher.verify_xss_builder_actual_result(*original))
  mutations=[lambda v,w,c,l:v.update(actualModelProof=False),lambda v,w,c,l:v.update(modelCalls=True),lambda v,w,c,l:v.update(controlledProjectionCount=1),lambda v,w,c,l:v['cleanup'].pop(),lambda v,w,c,l:w.update(closed=False),lambda v,w,c,l:w['counts'].update(incoming=21),lambda v,w,c,l:w['counts'].update(generate=26),lambda v,w,c,l:w['calls'][1].update(response='changed'),lambda v,w,c,l:w['calls'][1].update(responseComplete=False),lambda v,w,c,l:w['calls'][1].update(profile='other'),lambda v,w,c,l:c.pop(),lambda v,w,c,l:c[0]['spec']['request'].update(prompt='retuned'),lambda v,w,c,l:c[0]['effects'].pop(0),lambda v,w,c,l:c[0]['records'][0].update(owner_generation='1'),lambda v,w,c,l:c[0]['capture']['actors'][0]['result'].update(mocked=True),lambda v,w,c,l:c[0]['capture']['browsers'][1]['options'].update(scriptSource='other source'),lambda v,w,c,l:c[0]['capture']['browsers'][1]['result'].update(scriptExecuted=False),lambda v,w,c,l:c[0]['snapshot']['completions'][0]['row'].update(user_id=8),lambda v,w,c,l:c[4]['records'][0].update(verdict='pass'),lambda v,w,c,l:c[4]['snapshot']['completions'].append({'row':dict(user_id=8,objective_id='xss_email_level_1',workshop_key='xss_email_builder')}),lambda v,w,c,l:l['progress'].pop()]
  for mutation in mutations:
   args=copy.deepcopy(original);mutation(*args)
   with self.assertRaises(RuntimeError):launcher.verify_xss_builder_actual_result(*args)

 def test_decision_repair_preserves_semantically_rejected_rows(self):
  import copy,json,hashlib
  def insert(args,position,tool):
   value,wire,captures,_=args;case=captures[0];actor=copy.deepcopy(case['capture']['actors'][0]);row=copy.deepcopy(wire['calls'][1]);actor['result']['response']=json.dumps({'tool':tool},separators=(',',':'));frame=json.loads(row['response']);frame['response']=actor['result']['response'];row['response']=json.dumps(frame,separators=(',',':'));row['responseBytes']=len(row['response'].encode());row['responseSha256']=hashlib.sha256(row['response'].encode()).hexdigest()
   profile_read=False
   for previous in case['capture']['actors'][:position]:
    if json.loads(previous['result']['response']).get('tool')=='read_profile':profile_read=True
   request=json.loads(row['request']);request['format']['properties']['tool']['enum']=['generate_template','finish'] if profile_read else ['read_profile','finish'];actor['options']['format']=copy.deepcopy(request['format']);row['request']=json.dumps(request,separators=(',',':'));row['requestBytes']=len(row['request'].encode());row['requestSha256']=hashlib.sha256(row['request'].encode()).hexdigest()
   wire['calls'].insert(1+position,row);case['capture']['actors'].insert(position,actor)
   for index,entry in enumerate(wire['calls']):entry['index']=index
   for key in ['incoming','external','generate']:wire['counts'][key]+=1
   value['modelCalls']+=1;value['cases'][0]['actorCalls']+=1
  for rejected,position in [('generate_template',0),('read_profile',1)]:
   args=self.fixture();insert(args,position,rejected);self.assertTrue(launcher.verify_xss_builder_actual_result(*args))
   self.assertEqual(len(args[1]['calls']),22);self.assertEqual(len(args[2][0]['capture']['actors']),4)
  # Each phase can consume its single runtime repair, while retaining all five actor calls.
  args=self.fixture();insert(args,0,'generate_template');insert(args,2,'read_profile');self.assertTrue(launcher.verify_xss_builder_actual_result(*args))
  # Two consecutive rejected decisions exhaust the runtime; a terminal finish cannot resume.
  for tools in [('generate_template','generate_template'),('finish',)]:
   args=self.fixture()
   for position,tool in enumerate(tools):insert(args,position,tool)
   with self.assertRaises(RuntimeError):launcher.verify_xss_builder_actual_result(*args)

 def test_state_schema_and_exact_intercepted_request_are_required(self):
  import copy,json,hashlib
  original=self.fixture()
  for request in [None,{},dict(original[2][0]['actualRequest'],prompt='different'),dict(original[2][0]['actualRequest'],includeSignature=0),dict(original[2][0]['actualRequest'],challengeLevel=True)]:
   args=copy.deepcopy(original);args[2][0]['actualRequest']=request
   with self.assertRaisesRegex(RuntimeError,'exact captured request'):launcher.verify_xss_builder_actual_result(*args)
  for index,choices in [(1,['read_profile','generate_template','finish']),(1,['generate_template','finish']),(2,['read_profile','finish'])]:
   args=copy.deepcopy(original);row=args[1]['calls'][index];request=json.loads(row['request']);request['format']['properties']['tool']['enum']=choices;row['request']=json.dumps(request,separators=(',',':'));row['requestBytes']=len(row['request'].encode());row['requestSha256']=hashlib.sha256(row['request'].encode()).hexdigest();args[2][0]['capture']['actors'][index-1]['options']['format']=copy.deepcopy(request['format'])
   with self.assertRaisesRegex(RuntimeError,'decision contract|state-specific decision schema'):launcher.verify_xss_builder_actual_result(*args)

class XssBuilderContent(unittest.TestCase):
 def fixture(self):
  value=dict(profile=launcher.XSS_BUILDER_CONTENT_PROFILE,status='passed',actualModelProof=False,modelCalls=0,judgeCalls=0,genuineCredit=0,deniedModelCalls=0,controlledProjectionCount=4,controlledTimeSeconds=60,installedWrites=False,immutableEvidencePreserved=False,immutableEvidenceScope='Not qualified here; separate native reset proof required',cleanupFailures=[],requests={'browser':300,'api':30},cases=[dict(caseId='builder-level-'+str(n),objectiveId='xss_email_level_'+str(n),positive=True,status='controlled',learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True) for n in range(1,5)],cleanup=[dict(name=n,status='fulfilled') for n in ['restore','qualification-browser','browser','routes','server','transport','pools']])
  value.update(dict.fromkeys(['masterGates','dashboardParity','adminProgress','sessionDenied','foreignDenied','resetRetired','resetReplay','profilePreserved','siblingPreserved','configurationRestored','emptyImmutableTablesUnchanged'],True));return value
 def test_closed_content_admission_environment_and_real_browser_requirement(self):
  p=launcher.XSS_BUILDER_CONTENT_PROFILE;args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=p,node='/p/node',package='/main',manifest='/main/manifest',manifest_sha256='a'*64,browser='/browser',browser_sha256='b'*64);manifest=dict(cohort=p,profile=p,mode='model-free',actualExecution=False)
  self.assertEqual(launcher.validate_browser_profile_manifest(args,manifest),p);self.assertEqual(launcher.browser_stores(p),('identity','xss'));self.assertNotIn(p,launcher.XSS_BUILDER_RESET_PROFILES)
  for change in [dict(mode='actual-model'),dict(actualExecution=True),dict(actualExecution=0),dict(cohort='xss-email-three-content')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,{**manifest,**change})
  urls={}
  for store in launcher.browser_stores(p):urls.update(launcher.codebot_store_configuration(store,2222,'0123456789ab',p)[1])
  with patch.object(pathlib.Path,'mkdir'):
   env=launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',urls)
   for wrong in [{},dict(urls,PG_ADMIN_DATABASE_URL='forbidden')]:
    with self.assertRaises(ValueError):launcher.codebot_environment(args,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'owner',wrong)
  self.assertEqual(env['AI_PROVIDER'],'mock');self.assertNotIn('JUDGE_PROVIDER',env);self.assertNotIn('OLLAMA_BASE_URL',env)
  with patch.object(launcher,'codebot_browser_helper') as helper:
   helper.return_value.verify_browser_absence.side_effect=RuntimeError('Missing browser ownership evidence')
   with self.assertRaisesRegex(RuntimeError,'Missing browser'):launcher.verify_codebot_browser_cleanup(args,pathlib.Path('/runtime'),dict(exitCode=0),[])
 def test_content_receipt_cannot_claim_model_credit_or_nonempty_immutable_evidence(self):
  import copy
  original=self.fixture();self.assertTrue(launcher.verify_xss_builder_content_result(original))
  for key in ['modelCalls','judgeCalls','genuineCredit','deniedModelCalls']:
   for wrong in [1,False,None]:
    value=copy.deepcopy(original);value[key]=wrong
    with self.assertRaises(RuntimeError):launcher.verify_xss_builder_content_result(value)
  for key in ['masterGates','dashboardParity','adminProgress','sessionDenied','foreignDenied','resetRetired','resetReplay','profilePreserved','siblingPreserved','configurationRestored','emptyImmutableTablesUnchanged']:
   for wrong in [False,1,None]:
    value=copy.deepcopy(original);value[key]=wrong
    with self.assertRaises(RuntimeError):launcher.verify_xss_builder_content_result(value)
  mutations=[lambda x:x.update(actualModelProof=True),lambda x:x.update(immutableEvidencePreserved=True),lambda x:x.update(immutableEvidenceScope=''),lambda x:x.update(controlledProjectionCount=3),lambda x:x.update(controlledTimeSeconds=0),lambda x:x['cases'].pop(),lambda x:x['cases'][0].update(status='verified'),lambda x:x['cases'][0].update(independentGates=False),lambda x:x['requests'].update(browser=0),lambda x:x['cleanup'].pop()]
  for mutation in mutations:
   value=copy.deepcopy(original);mutation(value)
   with self.assertRaises(RuntimeError):launcher.verify_xss_builder_content_result(value)

class IpiRagQueryContent(unittest.TestCase):
 def test_closed_identity_scope(self):
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='ipi-rag-query-content')
  launcher.validate_browser_profile_manifest(a,{'cohort':a.browser_profile,'profile':a.browser_profile,'mode':'model-free'})
  self.assertEqual(launcher.browser_stores(a.browser_profile),('identity',))
  self.assertEqual(launcher.scenario_bounds(a.scenario),(780,600,120))
  with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,{'cohort':a.browser_profile,'profile':a.browser_profile,'mode':'actual-model'})
 def test_exact_controlled_receipt(self):
  import copy
  v={'status':'passed','profile':'ipi-rag-query-content','actualModelProof':False,'modelCalls':0,'mailCalls':0,'genuineCredit':0,'installedWrites':False,'cleanupFailures':[],'controlledProjectionCount':1,'controlledActorCalls':2,'controlledJudgeCalls':5,'controlledEmbeddingCalls':3,'completionScope':'Controlled one RAG query completion projection; no earned credit','requests':{'browser':100,'api':12},'cleanup':[{'name':n,'status':'fulfilled'} for n in ['restore','browser','mail','rag','routes','server','pools']],'cases':[dict(id='rag_query',learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)]}
  for key in ('uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'):v[key]=True
  launcher.verify_ipi_rag_query_content_result(v)
  for key,wrong in [('genuineCredit',1),('modelCalls',1),('controlledActorCalls',3),('controlledEmbeddingCalls',0),('resetReplayExact',False),('nonemptySiblingPreserved',False),('timePreserved',False),('profile','ipi-email-five-content')]:
   bad=copy.deepcopy(v);bad[key]=wrong
   with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_query_content_result(bad)

class RagActualControls(unittest.TestCase):
 def test_private_input_permissions_and_installed_cache_are_admitted_before_allocation(self):
  import tempfile,os,json,hashlib
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory).resolve();file=root/'input.json';file.write_text('{}');file.chmod(0o644)
   with self.assertRaises(RuntimeError):launcher.read_rag_private_json(file)
   file.chmod(0o400);self.assertEqual(launcher.read_rag_private_json(file)[1],{})
   link=root/'link';link.symlink_to(file)
   with self.assertRaises(RuntimeError):launcher.read_rag_private_json(link)
   assets=[]
   for name in ['config.json','onnx/model_quantized.onnx','tokenizer.json','tokenizer_config.json']:
    asset=root/'Xenova/all-MiniLM-L6-v2'/name;asset.parent.mkdir(parents=True,exist_ok=True);asset.write_bytes(b'synthetic');assets.append(dict(path=name,bytes=9,sha256=hashlib.sha256(b'synthetic').hexdigest()))
   description=dict(schemaVersion=2,model='Xenova/all-MiniLM-L6-v2',dimension=384,dtype='q8',pooling='mean',normalization='l2',backend='onnxruntime-node:cpu',transformersVersion='1.0.0',tokenizersVersion='1.0.0',onnxVersion='1.0.0',platform='darwin',architecture='arm64',assets=assets)
   cache=dict(directory=str(root),description=description,fingerprint=hashlib.sha256(json.dumps(description,separators=(',',':')).encode()).hexdigest());self.assertEqual(launcher.validate_rag_embedding_cache(cache),cache)
   (root/'Xenova/all-MiniLM-L6-v2/config.json').write_bytes(b'changed')
   with self.assertRaises(RuntimeError):launcher.validate_rag_embedding_cache(cache)
 def test_actual_profile_scope_is_closed_and_browser_exemption_is_exact(self):
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile='ipi-rag-query-actual');self.assertEqual(launcher.browser_stores(launcher.browser_profile(a)),('identity',))
  manifest=dict(cohort=a.browser_profile,profile=a.browser_profile,mode='actual-model',model=launcher.POLICY_MODEL,modelDigest=launcher.POLICY_DIGEST,actualExecution=True,inputSha256=launcher.IPI_RAG_INPUT_SHA256,cases=['owner-upload','owner-query'],wireBudget=dict(launcher.IPI_RAG_WIRE_BUDGET),embeddingCache={})
  with patch.object(launcher,'validate_rag_embedding_cache',return_value={}):
   self.assertEqual(launcher.validate_browser_profile_manifest(a,manifest),a.browser_profile)
   for key,value in [('inputSha256','0'*64),('mode','model-free'),('actualExecution',False),('cases',['owner-query'])]:
    bad=dict(manifest);bad[key]=value
    with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,bad)
  source=(HERE/'run-setup-database-phase-isolated.py').read_text();self.assertIn("browser_profile(args) not in (IPI_RAG_ACTUAL_PROFILE,IPI_EMAIL_ACTUAL_PROFILE)",source)
 def fixture(self):
  import json,hashlib,copy
  compact=lambda x:json.dumps(x,separators=(',',':'));sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  frozen=json.loads((HERE.parent/'fixtures/ipiRagQueryActualInput.json').read_text());owner=7;owner_key='["RAG","7"]';answer='17 days';criteria=[dict(id='grounded',satisfied=True,evidenceRefs=['raw_response'])]
  receipt=dict(ownerId=owner,runId='run',documentId='doc',runtimeFingerprint='a'*64,sourceSha256=sha(frozen['document']),graphGeneration='0')
  packet=dict(rubric=dict(objectiveId='rag_query',version='ipi-rag-evidence-bound-v2',requiredFacts=['real']),facts=dict(real=True),evidence=[dict(id='question',content=frozen['question']),dict(id='raw_response',content=answer),dict(id='context',content=frozen['document']),dict(id='retrieval_receipts',content=[receipt])]);packet_text=compact(packet)
  j=dict(objective_id='rag_query',evaluation_id='evaluation',run_id='run',user_id=owner,generation=0,verdict='pass',disposition='awarded',evidence_digest=sha(packet_text),result_json=dict(criteria=criteria))
  body=dict(presentation_source='model',completedObjectiveIds=['rag_query'],raw_model_answer=answer,retrieved_chunks=[dict(text=frozen['document'])],judgments=[dict(objectiveId='rag_query',evaluationId='evaluation',verdict='pass',criteria=criteria)])
  c=dict(input=frozen,ownerId=owner,query=dict(status=200,body=body),upload=dict(body=dict(session_id='doc')),judgments=[j],packets=[dict(packet=packet_text,evaluation_id='evaluation',owner_key=owner_key,user_id=owner,owner_generation=0)],runs=[dict(run_id='run',owner_key=owner_key,generation=0,status='completed')],events=[dict(run_id='run',node='rag_search',event_type='tool')],effects=[dict(effect_key='run:rag_search:0:'+sha(compact(dict(query=frozen['question'],topK=1))),run_id='run',owner_key=owner_key,generation=0,status='completed')],embeddingFingerprint=dict(fingerprint='a'*64,description={}),modelCalls=[])
  calls=[]
  def wire(kind,request,response,role=None,case=None):
   row=dict(index=len(calls),kind=kind,caseId=case,role=role,terminal='returned',status=200,responseComplete=True,responseCaptureTruncated=False,request=request,response=response)
   for field in ['request','response']:row[field+'Sha256']=sha(row[field]);row[field+'Bytes']=len(row[field].encode())
   calls.append(row)
  wire('tags','',compact(dict(models=[dict(name=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST)])))
  outputs=[('actor',dict(action='search_document',query=frozen['question'],topK=1)),('actor',dict(action='answer',answer=answer)),('judge',dict(verdict='pass',criteria=criteria))]
  for role,out in outputs:
   messages=[dict(role='system',content='AUTHORITATIVE RUBRIC:\n'+compact(packet['rubric'])+'\nAUTHORITATIVE SERVER FACTS:\n'+compact(packet['facts'])+'\n'),dict(role='user',content=compact(packet['evidence']))];options=dict(temperature=0,num_predict=1200 if role=='actor' else 900);format=dict(type='object');raw=compact(out)
   c['modelCalls'].append(dict(role=role,caseId='owner-query',error=None,messages=messages,options=dict(**options,format=format),result=dict(response=raw,provider='ollama',model=launcher.POLICY_MODEL)))
   wire('chat',compact(dict(model=launcher.POLICY_MODEL,messages=messages,options=options,format=format)),compact(dict(model=launcher.POLICY_MODEL,done=True,done_reason='stop',message=dict(content=raw))),role,'owner-query')
  counts=dict(external=4,incoming=3,metadata=1,tags=1,version=0,generate=0,chat=3);w=dict(profile=launcher.IPI_RAG_ACTUAL_PROFILE,version=launcher.IPI_RAG_ACTUAL_PROFILE+'-wire-v1',model=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST,closed=True,physicalPending=0,failures=[],calls=calls,counts=counts)
  life=dict(wireBefore=counts,wireAfter=counts,reset=dict(status=200,body=dict(success=True)),ownerBefore=[dict(row=dict(document_id='doc',owner_id=owner))],ownerAfter=[dict(row=dict(document_id='doc',owner_id=owner,retired_at='time'))],completionsBefore=[dict(user_id=owner,workshop_key='indirect_prompt_injection',objective_id='rag_query')],immutableBefore=dict(judgments=[j]),immutableAfter=dict(judgments=[j]),siblingBefore=[dict(document_id='sibling')],siblingAfter=[dict(document_id='sibling')])
  for name,status in [('foreign-document',404),('revoked-session',401),('retired-document',404)]:life[name]=dict(before=counts,after=counts,response=dict(status=status))
  c['lifecycle']=life
  v=dict(profile=launcher.IPI_RAG_ACTUAL_PROFILE,status='passed',installedWrites=False,actualModelProof=True,controlledProjectionCount=0,genuineCredit=1,caseIds=['owner-upload','owner-query'],cleanupFailures=[],cleanup=[dict(name=n,status='fulfilled')for n in ['routes','server','embedding','transport','pools']],embeddingFingerprint=c['embeddingFingerprint'],actorCalls=2,judgeCalls=1,modelCalls=3)
  for key in ['foreignDocumentDenied','sessionDenied','resetRetired','noCallNegatives','immutableEvidencePreserved','siblingPreserved']:v[key]=True
  return v,w,c,dict(embeddingCache=c['embeddingFingerprint'])
 def test_actual_receipt_joins_raw_model_effect_judge_owner_and_lifecycle(self):
  import copy
  values=self.fixture();launcher.verify_ipi_rag_actual_result(*values)
  mutations=[lambda v,w,c,m:c.update(ownerId=8),lambda v,w,c,m:c.update(effects=[]),lambda v,w,c,m:c['effects'][0].update(effect_key=c['effects'][0]['effect_key'].removeprefix('run:')),lambda v,w,c,m:c['effects'][0].update(effect_key='foreign:'+c['effects'][0]['effect_key'].removeprefix('run:')),lambda v,w,c,m:c['runs'][0].update(status='failed'),lambda v,w,c,m:c['lifecycle'].update(completionsBefore=[]),lambda v,w,c,m:c['lifecycle']['ownerAfter'][0]['row'].update(document_id='foreign'),lambda v,w,c,m:c['modelCalls'][0].update(error={'code':'failed'}),lambda v,w,c,m:w['calls'][1].update(responseComplete=False),lambda v,w,c,m:c['lifecycle']['foreign-document'].update(after={}),lambda v,w,c,m:v.update(genuineCredit=2)]
  for mutate in mutations:
   bad=copy.deepcopy(values);mutate(*bad)
   with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_actual_result(*bad)

class RagUploadCleanControls(unittest.TestCase):
 def test_two_card_profile_requires_browser_identity_store_and_exact_controlled_receipt(self):
  import copy
  profile='ipi-rag-upload-clean-content';args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
  self.assertEqual(launcher.browser_profile(args),profile);self.assertEqual(launcher.browser_stores(profile),('identity',))
  self.assertEqual(launcher.validate_browser_profile_manifest(args,dict(cohort=profile,profile=profile,mode='model-free')),profile)
  with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,dict(cohort=profile,profile=profile,mode='actual-model'))
  v=dict(status='passed',profile=profile,actualModelProof=False,modelCalls=0,mailCalls=0,genuineCredit=0,installedWrites=False,cleanupFailures=[],controlledProjectionCount=2,controlledActorCalls=2,controlledJudgeCalls=5,controlledEmbeddingCalls=3,completionScope='Controlled RAG upload and clean document completion projections; no earned credit',requests=dict(browser=100,api=12),cleanup=[dict(name=n,status='fulfilled')for n in ['restore','browser','mail','rag','routes','server','pools']],cases=[dict(id=n,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for n in ['rag_upload','rag_clean_doc']])
  for key in ('uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'):v[key]=True
  launcher.verify_ipi_rag_query_content_result(v,profile)
  for key,value in [('controlledProjectionCount',1),('genuineCredit',1),('modelCalls',1),('controlledActorCalls',3),('profile','ipi-rag-query-content'),('cases',v['cases'][:1]),('requests',dict(browser=0,api=12)),('resetReplayExact',False)]:
   bad=copy.deepcopy(v);bad[key]=value
   with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_query_content_result(bad,profile)
  with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_query_content_result(v)

class EmailActualOwnerControls(unittest.TestCase):
 def test_exact_manifest_budget_and_input(self):
  import copy
  profile=launcher.IPI_EMAIL_ACTUAL_PROFILE;a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
  m=dict(cohort=profile,profile=profile,mode='actual-model',actualExecution=True,model=launcher.POLICY_MODEL,modelDigest=launcher.POLICY_DIGEST,inputSha256=launcher.IPI_EMAIL_INPUT_SHA256,cases=['setup','clean-control','attack'],wireBudget=dict(launcher.IPI_EMAIL_WIRE_BUDGET),mailpitImage=launcher.IPI_EMAIL_MAILPIT_IMAGE)
  self.assertEqual(launcher.validate_browser_profile_manifest(a,m),profile);self.assertEqual(launcher.browser_stores(profile),('identity',))
  for change in [dict(mode='model-free'),dict(actualExecution=1),dict(inputSha256='0'*64),dict(cases=['attack']),dict(mailpitImage='latest')]:
   with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,{**m,**change})
  bad=copy.deepcopy(m);bad['wireBudget']['actor']=17
  with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(a,bad)
  with self.assertRaises(ValueError):launcher.codebot_store_configuration('supply_chain',54321,'abcdef012345',profile)
 def test_owned_mailpit_layout_and_no_browser_retirement(self):
  import copy
  row={'Mounts':[],'HostConfig':{'Memory':268435456,'NanoCpus':1000000000,'PidsLimit':64,'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Tmpfs':{'/tmp':'rw,noexec,nosuid,size=67108864'}},'NetworkSettings':{'Ports':{'8025/tcp':[{'HostIp':'127.0.0.1','HostPort':'45001'}],'1025/tcp':[{'HostIp':'127.0.0.1','HostPort':'45002'}]}}}
  self.assertEqual(launcher.validate_email_mailpit_layout(row),dict(apiUrl='http://127.0.0.1:45001',smtpHost='127.0.0.1',smtpPort=45002))
  realistic=copy.deepcopy(row);realistic['NetworkSettings']['Ports']['1110/tcp']=None
  self.assertEqual(launcher.validate_email_mailpit_layout(realistic),launcher.validate_email_mailpit_layout(row))
  for binding in [[],[{'HostIp':'127.0.0.1','HostPort':'45003'}],[{'HostIp':'0.0.0.0','HostPort':'45003'}]]:
   invalid=copy.deepcopy(realistic);invalid['NetworkSettings']['Ports']['1110/tcp']=binding
   with self.assertRaises(RuntimeError):launcher.validate_email_mailpit_layout(invalid)
  unknown=copy.deepcopy(realistic);unknown['NetworkSettings']['Ports']['9999/tcp']=None
  with self.assertRaises(RuntimeError):launcher.validate_email_mailpit_layout(unknown)
  for mutate in [lambda r:r.update(Mounts=[{}]),lambda r:r['HostConfig'].update(ReadonlyRootfs=False),lambda r:r['NetworkSettings']['Ports']['8025/tcp'][0].update(HostIp='0.0.0.0'),lambda r:r['NetworkSettings']['Ports']['1025/tcp'][0].update(HostPort='45001')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):launcher.validate_email_mailpit_layout(bad)
  a=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=launcher.IPI_EMAIL_ACTUAL_PROFILE)
  with patch.object(pathlib.Path,'exists',return_value=False),patch.object(pathlib.Path,'is_symlink',return_value=False):
   self.assertTrue(launcher.verify_codebot_browser_cleanup(a,pathlib.Path('/owned'),dict(nativeStarted=True,nativePid=42),[])['groupAbsent'])
   with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(a,pathlib.Path('/owned'),dict(nativeStarted=True,nativePid=42),[(42,42,1)])
  with patch.object(pathlib.Path,'exists',return_value=True):
   with self.assertRaises(RuntimeError):launcher.verify_codebot_browser_cleanup(a,pathlib.Path('/owned'),{},[])

class EmailMailpitOwnershipControls(unittest.TestCase):
 def test_captured_identity_cleanup_and_failure_cleanup(self):
  from unittest.mock import Mock
  command=Mock(return_value=SimpleNamespace(returncode=0,stdout='b'*64,stderr=''));record=Mock();owner='a'*32
  with patch.object(launcher,'verify_daemon'),patch.object(launcher,'verify_image'),patch.object(launcher,'inspect_owned',side_effect=[None,{}]),patch.object(launcher,'validate_email_mailpit_layout',return_value=dict(apiUrl='http://127.0.0.1:45001',smtpHost='127.0.0.1',smtpPort=45002)),patch.object(launcher,'cleanup_owned')as cleanup:
   resource=launcher.OwnedEmailMailpit(command,'daemon',owner,record);result=resource.start();self.assertEqual(result['containerId'],'b'*64)
   argv=command.call_args[0][0];self.assertIn('--read-only',argv);self.assertIn('127.0.0.1::8025',argv);self.assertEqual(argv[-1],launcher.IPI_EMAIL_MAILPIT_IMAGE)
   resource.cleanup();self.assertEqual(cleanup.call_args.kwargs['captured_id'],'b'*64);self.assertEqual(record.call_args[0][0]['cleanup'],{'status':'removed_absence_verified'})
  with patch.object(launcher,'verify_daemon'),patch.object(launcher,'verify_image'),patch.object(launcher,'inspect_owned',return_value=None),patch.object(launcher,'cleanup_owned')as cleanup:
   command.return_value=SimpleNamespace(returncode=1,stdout='',stderr='failure');resource=launcher.OwnedEmailMailpit(command,'daemon',owner,record)
   with self.assertRaises(RuntimeError):resource.start()
   resource.cleanup();self.assertIsNone(cleanup.call_args.kwargs['captured_id']);self.assertEqual(cleanup.call_args.kwargs['labels']['dvaia.owner'],owner)

class EmailActualReceiptControls(unittest.TestCase):
 def fixture(self):
  import json,hashlib
  compact=lambda x:json.dumps(x,separators=(',',':'));sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  frozen=json.loads((HERE.parent/'fixtures/ipiEmailTriggerActualInput.json').read_text());profile=launcher.IPI_EMAIL_ACTUAL_PROFILE
  c=dict(input=frozen,ownerId=1,siblingId=2,modelCalls=[],evaluations=[],judgments=[],packets=[],runs=[],cases=[])
  def wire_row(kind,case,request,response,role=None):
   row=dict(index=len(calls),kind=kind,caseId=case,terminal='returned',status=200,responseComplete=True,responseCaptureTruncated=False,request=request,response=response)
   if role:row['role']=role
   for field in ['request','response']:row[field+'Sha256']=sha(row[field]);row[field+'Bytes']=len(row[field].encode())
   calls.append(row)
  calls=[];wire_row('tags',None,'',compact({'models':[dict(name=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST)]}))
  for case in ['clean-control','attack']:
   positive=case=='attack';run='run-'+case;eid='eval-'+case;verdict='pass'if positive else'fail';criteria=[dict(id='followed',satisfied=positive,evidenceRefs=[])]
   for role in ['actor']*6+['judge']:
    messages=[dict(role='system',content='controlled'),dict(role='user',content='controlled')];fmt={'type':'object'}
    requested=dict(temperature=0,num_predict=900,num_ctx=32768)if role=='judge'else dict(temperature=0,max_tokens=900)
    effective=dict(temperature=0,num_predict=900,num_ctx=32768 if role=='judge'else 8192)
    result=dict(provider='ollama',model=launcher.POLICY_MODEL,response='controlled');c['modelCalls'].append(dict(role=role,caseId=case,messages=messages,options={**requested,'format':fmt},result=result,error=None))
    wire_row('chat',case,compact(dict(model=launcher.POLICY_MODEL,messages=messages,options=effective,format=fmt)),compact(dict(model=launcher.POLICY_MODEL,message=dict(content='controlled'),done=True,done_reason='stop')),role)
   packet=dict(rubric=dict(objectiveId='email_trigger_injection'),evidence=[],facts={});raw=compact(packet);digest=sha(raw)
   c['runs'].append(dict(run_id=run,owner_key='["IndirectEmail","1"]',generation=0,status='completed'))
   row=dict(run_id=run,evaluation_id=eid,objective_id='email_trigger_injection',user_id=1,evidence_digest=digest,verdict=verdict,disposition='awarded'if positive else'not_pass',result_json=dict(criteria=criteria));c['judgments'].append(row)
   c['packets'].append(dict(evaluation_id=eid,packet=raw,owner_key='["IndirectEmail","1"]',owner_generation=0))
   c['evaluations'].append(dict(runId=run,packet=packet,result=dict(verdict=verdict,criteria=criteria),callIndexes=[len(c['modelCalls'])-1],caseId=case))
   artifact=dict(artifactId='artifact-'+case,body='controlled',modelBody='controlled',bodySha256=sha('controlled'),modelBodySha256=sha('controlled'))
   c['cases'].append(dict(id=case,request=dict(artifactId=artifact['artifactId']),artifact=artifact,response=dict(status=200,body=dict(judgments=[dict(objectiveId='email_trigger_injection',evaluationId=eid,verdict=verdict,criteria=criteria,evidenceDigest=digest)])),completions=[dict(user_id=1,objective_id='email_trigger_injection')]if positive else[]))
  counts=dict(external=15,incoming=14,chat=14,tags=1,metadata=1,generate=0,version=0)
  wire=dict(profile=profile,version=profile+'-wire-v1',model=launcher.POLICY_MODEL,digest=launcher.POLICY_DIGEST,closed=True,physicalPending=0,failures=[],calls=calls,counts=counts)
  before=[dict(artifact_id='a'),dict(artifact_id='b')];after=[dict(artifact_id='a',retired_at='now'),dict(artifact_id='b',retired_at='now')]
  lifecycle=dict(generationBefore='0',generationAfter='1',wireBefore=counts,wireAfter=counts,immutableBefore=dict(judgments=c['judgments']),immutableAfter=dict(judgments=c['judgments']),siblingBefore=dict(artifacts=[{'artifact_id':'s'}]),siblingAfter=dict(artifacts=[{'artifact_id':'s'}]),ownerBefore=before,ownerAfter=after,completionsAfter=[],reset=dict(status=200,body=dict(success=True)))
  for name,status in [('foreign-artifact',409),('revoked-session',401),('retired-artifact',409),('forged-body',400)]:lifecycle[name]=dict(before=counts,after=counts,response=dict(status=status))
  c['lifecycle']=lifecycle
  value=dict(profile=profile,status='passed',installedWrites=False,browserStarted=False,actualModelProof=True,controlledProjectionCount=0,genuineCredit=1,caseIds=['setup','clean-control','attack'],cleanupFailures=[],cleanup=[dict(name=n,status='fulfilled')for n in ['routes','server','mail','transport','pools']],actorCalls=12,judgeCalls=2,modelCalls=14)
  for key in ['foreignArtifactDenied','sessionDenied','resetRetired','noCallNegatives','immutableEvidencePreserved','siblingPreserved']:value[key]=True
  return value,wire,c,dict(inputSha256=launcher.IPI_EMAIL_INPUT_SHA256)
 def test_raw_receipt_and_negative_mutations(self):
  import copy
  values=self.fixture();launcher.verify_ipi_email_actual_result(*values)
  changes=[lambda v:v[0].update(genuineCredit=2),lambda v:v[1].update(closed=False),lambda v:v[1]['calls'][1].update(requestSha256='0'*64),lambda v:v[2]['modelCalls'][0]['result'].update(fallback=True),lambda v:v[2]['evaluations'][0]['callIndexes'].append(6),lambda v:v[2]['packets'][0].update(owner_generation=1),lambda v:v[2]['cases'][0]['completions'].append(dict(user_id=1,objective_id='email_trigger_injection')),lambda v:v[2]['lifecycle']['ownerAfter'][0].update(retired_at=None),lambda v:v[2]['lifecycle']['siblingAfter'].update(artifacts=[]),lambda v:v[2]['lifecycle']['foreign-artifact']['response'].update(status=200)]
  for mutate in changes:
   bad=copy.deepcopy(values);mutate(bad)
   with self.assertRaises(RuntimeError):launcher.verify_ipi_email_actual_result(*bad)
 def test_actor_effective_default_and_explicit_judge_context_are_distinct(self):
  import copy,hashlib,json
  compact=lambda x:json.dumps(x,separators=(',',':'));sha=lambda x:hashlib.sha256(x.encode()).hexdigest()
  values=self.fixture();launcher.verify_ipi_email_actual_result(*values)
  actor=copy.deepcopy(values);row=next(x for x in actor[1]['calls']if x.get('role')=='actor');request=json.loads(row['request']);request['options']['num_ctx']=4096;row['request']=compact(request);row['requestSha256']=sha(row['request']);row['requestBytes']=len(row['request'].encode())
  with self.assertRaises(RuntimeError):launcher.verify_ipi_email_actual_result(*actor)
  judge=copy.deepcopy(values);call=next(x for x in judge[2]['modelCalls']if x['role']=='judge');call['options']['num_ctx']=8192;row=next(x for x in judge[1]['calls']if x.get('role')=='judge');request=json.loads(row['request']);request['options']['num_ctx']=8192;row['request']=compact(request);row['requestSha256']=sha(row['request']);row['requestBytes']=len(row['request'].encode())
  with self.assertRaises(RuntimeError):launcher.verify_ipi_email_actual_result(*judge)

class RagInjectionTwoControls(unittest.TestCase):
 def test_closed_two_card_seed_receipt(self):
  import copy
  profile='ipi-rag-injection-two-content';args=SimpleNamespace(scenario='codebot-rendered-parity',browser_profile=profile)
  self.assertEqual(launcher.browser_stores(profile),('identity',))
  self.assertEqual(launcher.validate_browser_profile_manifest(args,dict(cohort=profile,profile=profile,mode='model-free')),profile)
  with self.assertRaises(RuntimeError):launcher.validate_browser_profile_manifest(args,dict(cohort=profile,profile=profile,mode='actual-model'))
  proof=dict(version='ipi-rag-two-seed-v1',scope='Catalog/provenance before learner fixtures; later lifecycle proof covers nonempty learner preservation',ids=['rag_injected_doc','rag_query_injection'],predecessorSha256='d8b36f19c987a00038a475c17ef285c5d375ee92c93df05c259894378b31205d')
  for key in ('freshDefaults','managedUpgrade','customPreserved','nullPreserved','secondRunNoop','unrelatedPreserved','restored'):proof[key]=True
  v=dict(status='passed',profile=profile,actualModelProof=False,modelCalls=0,mailCalls=0,genuineCredit=0,installedWrites=False,cleanupFailures=[],controlledProjectionCount=2,controlledActorCalls=2,controlledJudgeCalls=5,controlledEmbeddingCalls=3,completionScope='Controlled RAG defense and injection completion projections; no earned credit',requests=dict(browser=100,api=12),cleanup=[dict(name=n,status='fulfilled')for n in ['restore','browser','mail','rag','routes','server','pools']],cases=[dict(id=n,learnerContent=True,adminPreview=True,independentGates=True,completedProjection=True)for n in proof['ids']],seedProof=proof)
  for key in ('uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'):v[key]=True
  launcher.verify_ipi_rag_query_content_result(v,profile)
  for key in proof:
   bad=copy.deepcopy(v);bad['seedProof'].pop(key)
   with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_query_content_result(bad,profile)
  for key,value in [('cases',v['cases'][::-1]),('genuineCredit',1),('actualModelProof',True),('modelCalls',1),('sessionDenied',False),('resetReplayExact',False),('controlledProjectionCount',1)]:
   bad=copy.deepcopy(v);bad[key]=value
   with self.assertRaises(RuntimeError):launcher.verify_ipi_rag_query_content_result(bad,profile)

if __name__=='__main__':unittest.main()
