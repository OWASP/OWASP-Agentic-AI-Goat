import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace
FILE=Path(__file__).with_name('run-mail-browser-main.py')
spec=importlib.util.spec_from_file_location('mail_browser_launcher',FILE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_m23_standalone_disclosure_actual_closed_receipt_and_wire(self):
  import copy,hashlib,json
  args=SimpleNamespace(standalone_disclosure_actual=True,main_workspace='/main',manifest='/private/m.json',
   manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'standalone-disclosure-actual')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  self.assertEqual(env['MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL'],'1')
  self.assertEqual(env['DVAIA_MAIL_BROWSER_BUILD_ROOT'],'/main/client/build')
  import tempfile
  with tempfile.TemporaryDirectory() as directory:
   with self.assertRaisesRegex(RuntimeError,'browser ownership'):
    m.verify_browser_absence(Path(directory),{'mode':'standalone-disclosure-actual','exitCode':0},[])
  self.assertEqual((env['AI_PROVIDER'],env['JUDGE_PROVIDER'],env['OLLAMA_MODEL']),('ollama','ollama','llama3.1:8b'))
  self.assertNotEqual(env.get('OLLAMA_BASE_URL'),'http://127.0.0.1:1')
  required=['--'+key+'=/private/'+key for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root','input','input-sha256']]
  with self.assertRaises(ValueError):m.parse_main(required+['--standalone-disclosure-actual','--review-batch-actual'])
  h=lambda value:hashlib.sha256(value.encode()).hexdigest()
  request=json.dumps({'model':'llama3.1:8b','messages':[{'role':'user','content':'evidence'}]},separators=(',',':'))
  decision='{"verdict":"pass"}'
  response=json.dumps({'message':{'content':decision},'done':True},separators=(',',':'))
  operation='11111111-1111-4111-8111-111111111111'
  proof={'status':'assertions_passed','actualQualification':False,'objectiveId':'ss_mail_cross_persona_read',
   'readOperationId':operation,'assessmentRequestId':'22222222-2222-4222-8222-222222222222',
   'checks':['rendered_foreign_read','actual_judge_observed','saved_get_no_replay',
             'own_empty_fixed_denied','session_reset_sibling_fenced'],'judgeCalls':1,'apiRequests':42}
  result={'profile':'standalone-disclosure-actual','status':'passed','cleanupFailures':[],
   'standaloneDisclosure':proof,'actualActorCalls':0,'judgeCalls':1,'modelCalls':1,'genuineCredit':1}
  call={'index':1,'kind':'judge','model':'llama3.1:8b','status':200,
   'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end',
   'request':request,'requestSha256':h(request),'requestBytes':len(request.encode()),
   'response':response,'responseSha256':h(response),'responseBytes':len(response.encode()),
   'responseObservedBytes':len(response.encode())}
  transcript_call={'stage':'primary','request':{'input':[{'role':'user','content':'evidence'}]},
   'response':decision,'responseSha256':h(decision),'metadata':{'provider':'ollama','model':'llama3.1:8b',
   'mocked':False,'fallback':False},'transport':'returned','disposition':'accepted'}
  capture={'wire':{'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
   'calls':[call]},'transcripts':[{'version':1,'complete':True,'failure':None,
   'transcriptSha256':'a'*64,'calls':[transcript_call],
   'outcome':{'bytes':decision,'sha256':h(decision),'value':{'verdict':'pass'}}}]}
  m.validate_standalone_disclosure_actual_result(result,capture)
  for change in [lambda r,w:r.update(genuineCredit=0),lambda r,w:r['standaloneDisclosure'].update(actualQualification=True),
   lambda r,w:r['standaloneDisclosure']['checks'].pop(),lambda r,w:r['standaloneDisclosure'].update(judgeCalls=4),
   lambda r,w:w['wire']['calls'][0].update(kind='actor'),lambda r,w:w['wire']['calls'][0].update(responseCaptureTruncated=True),
   lambda r,w:w['transcripts'][0]['calls'][0]['metadata'].update(mocked=True),
   lambda r,w:w['transcripts'][0]['calls'][0]['metadata'].update(fallback=True),
   lambda r,w:w['transcripts'][0]['calls'][0].update(response='{"verdict":"fail"}'),
   lambda r,w:w['transcripts'][0]['outcome']['value'].update(verdict='fail')]:
   bad_result,bad_capture=copy.deepcopy(result),copy.deepcopy(capture);change(bad_result,bad_capture)
   with self.assertRaises(RuntimeError):m.validate_standalone_disclosure_actual_result(bad_result,bad_capture)

 def test_q44_review_batch_closed_receipt_and_canonical_credit(self):
  import copy,hashlib
  self.assertEqual(m.content_mode(SimpleNamespace(review_batch_actual=True)),'review-batch-actual')
  proof={'profile':'review-batch-actual','qualification':'qualified','actualModelProof':True,
   'genuineCredit':0,'qualifiedObjectiveIds':[],'assessmentOutcomes':[
    {'objectiveId':'ss_loop_observation','verdict':'inconclusive','disposition':'hidden','runId':'run-1'},
    {'objectiveId':'ss_loop_observation','verdict':'inconclusive','disposition':'hidden','runId':'run-2'}],
   'physicalModeration':True,'replayed':True,'siblingPreserved':True,
   'sessionDenied':True,'reset':True,'immutablePreserved':True,'decisionCount':4,
   'batches':[{'requested':100,'considered':3,'processed':3,'continuationRequired':True},
    {'requested':97,'considered':1,'processed':1,'continuationRequired':False}],
   'actorCalls':1,'judgeCalls':0}
  result={'profile':'review-batch-actual','status':'passed','cleanupFailures':[],
   'reviewBatchActual':proof,'genuineCredit':0,'judgeCalls':0,'actualActorCalls':1,
   'modelCalls':1,'browserStarted':True}
  def call(index,role,case):
   request='{}';response='{}'
   return {'index':index,'role':role,'caseId':case,'status':'returned','httpStatus':200,
    'request':request,'response':response,'requestSha256':hashlib.sha256(request.encode()).hexdigest(),
    'responseSha256':hashlib.sha256(response.encode()).hexdigest()}
  wire={'version':'review-batch-actual-wire-v1','closed':True,'failed':False,'physicalPending':0,
   'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
   'calls':[call(0,'tags',None),call(1,'actor','four_pending')],
   'counts':{'tags':1,'actor':1,'judge':0},
   'phaseCounts':{'four_pending':{'actor':1,'judge':0}},'externalAttempts':2}
  m.validate_review_batch_actual_result(result,wire)
  false_credit=copy.deepcopy(result)
  false_credit['reviewBatchActual'].update(genuineCredit=1,qualifiedObjectiveIds=['ss_loop_observation'])
  with self.assertRaises(RuntimeError):m.validate_review_batch_actual_result(false_credit,wire)
  judged_result,judged_wire=copy.deepcopy(result),copy.deepcopy(wire)
  judged_result['reviewBatchActual']['judgeCalls']=1
  judged_result.update(judgeCalls=1,modelCalls=2)
  judged_wire['calls'].append(call(2,'judge','four_pending'))
  judged_wire['counts']['judge']=1;judged_wire['phaseCounts']['four_pending']['judge']=1
  judged_wire['externalAttempts']=3
  with self.assertRaises(RuntimeError):m.validate_review_batch_actual_result(judged_result,judged_wire)
  for mutate in [lambda r,w:r['reviewBatchActual']['batches'][1].update(considered=2),
   lambda r,w:r['reviewBatchActual'].update(genuineCredit=1),
   lambda r,w:r['reviewBatchActual']['assessmentOutcomes'][0].update(disposition='awarded'),
   lambda r,w:r['reviewBatchActual']['assessmentOutcomes'][0].update(verdict='pass'),
   lambda r,w:w['calls'][1].update(role='judge'),
   lambda r,w:w.update(physicalPending=1),
   lambda r,w:r['reviewBatchActual'].update(reset=False)]:
   bad_result,bad_wire=copy.deepcopy(result),copy.deepcopy(wire);mutate(bad_result,bad_wire)
   with self.assertRaises(RuntimeError):m.validate_review_batch_actual_result(bad_result,bad_wire)
 def test_private_manifest_admission_before_allocation(self):
  import tempfile,os
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as directory:
   manifest=Path(directory)/'manifest.json';manifest.write_bytes(b'{}');manifest.chmod(0o600)
   self.assertEqual(m.read_private_manifest(manifest),b'{}')
   manifest.chmod(0o400);self.assertEqual(m.read_private_manifest(manifest),b'{}')
   link=Path(directory)/'link';link.symlink_to(manifest)
   for invalid in [link,Path(directory)]:
    with self.assertRaises(RuntimeError):m.read_private_manifest(invalid)
   with patch.object(m.os,'getuid',return_value=os.getuid()+1):
    with self.assertRaises(RuntimeError):m.read_private_manifest(manifest)
   manifest.chmod(0o644)
   with self.assertRaises(RuntimeError):m.read_private_manifest(manifest)
   args=SimpleNamespace(main_workspace=str(FILE.resolve().parents[2]),manifest=str(manifest))
   with patch.object(m,'inventory',side_effect=AssertionError('must not inspect dependencies')):
    with self.assertRaisesRegex(RuntimeError,'Private regular owned manifest'):m.validate_main(args)

 def test_four_exact_stores(self):
  for name,label in [('identity','IDENTITY'),('secureshop','COMMERCE'),('secureshop_agents','AGENTS'),('secureshop_review','REVIEW')]:
   sql,env=m.store_configuration(name,54321,'abcdef012345')
   self.assertIn('CREATE DATABASE dvaia_test_mail_browser_abcdef012345_'+name,sql)
   self.assertEqual(env['MAIL_'+label+'_RUNTIME_URL'],f'postgresql://dvaia_{name}_runtime@127.0.0.1:54321/dvaia_test_mail_browser_abcdef012345_{name}')
  for name in ['postgres','aria','unknown']:
   with self.assertRaises(ValueError):m.store_configuration(name,54321,'abcdef012345')
 def test_closed_flags(self):
  with self.assertRaises(ValueError):m.parse_main(['--plan','--plan'])
  with self.assertRaises(SystemExit):m.parse_main(['--unknown'])
 def test_private_environment(self):
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64)
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_NATIVE'],'1');self.assertEqual(env['ANALYTICS_BROWSER_EXECUTABLE'],a.browser)
  self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE',env);self.assertNotIn('OLLAMA_BASE_URL',env)
  a.content_only=True;controlled=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(controlled['MAIL_BROWSER_CONTENT_ONLY'],'1');self.assertEqual(controlled['AI_PROVIDER'],'mock');self.assertEqual(controlled['JUDGE_PROVIDER'],'mock');self.assertEqual(controlled['OLLAMA_BASE_URL'],'http://127.0.0.1:1')
 def test_default_actual_exposes_current_build_root_without_standalone_mode(self):
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(a),'actual')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['DVAIA_MAIL_BROWSER_BUILD_ROOT'],'/main/client/build')
  self.assertNotIn('MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL',env)
  self.assertEqual((env['AI_PROVIDER'],env['JUDGE_PROVIDER'],env['OLLAMA_MODEL'],env['SS_BOUND_PROMPT_POLICIES_ENABLED']),('ollama','ollama','llama3.1:8b','false'))
 def test_listings_closed_receipt(self):
  import copy
  self.assertEqual(m.content_mode(SimpleNamespace(listings_content=True)), 'listings-content')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved']
  row={'profile':'listings-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'cases':[],'content':{'objectiveId':None,'apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)} for id in m.LISTINGS_CONTENT_IDS]}}
  m.validate_content_result(row,'listings-content')
  for mutate in [lambda r:r['content']['cases'].pop(),lambda r:r['content']['cases'][0].update(id='ss_mail_stored_browser_execution'),lambda r:r.update(effects=1),lambda r:r['content']['cases'][0].update(hint=False)]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'listings-content')
 def test_loop_profile_receipt_distinguishes_controlled_from_genuine(self):
  import copy
  self.assertEqual(m.content_mode(SimpleNamespace(loop_content_lifecycle=True)), 'loop-content-lifecycle')
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,loop_content_lifecycle=True)
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_LOOP_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env);self.assertEqual(env['JUDGE_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'loop-content-lifecycle','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':1,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_loop_observation','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_loop_observation',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]},'loopLifecycle':{**dict.fromkeys(['mountedModeration','purposeSession','effectBound','sessionDenied','resetDenied','siblingPreserved','immutablePreserved'],True),'controlledCalls':2,'controlledEffects':1,'actualModelProof':False}}
  m.validate_content_result(row,'loop-content-lifecycle')
  for mutate in [lambda r:r['loopLifecycle'].update(actualModelProof=True),lambda r:r['loopLifecycle'].update(sessionDenied=False),lambda r:r.update(effects=0),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_mail_stored_browser_execution')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'loop-content-lifecycle')
 def test_audit_sql_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,audit_sql_content=True)
  self.assertEqual(m.content_mode(a),'audit-sql-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_AUDIT_SQL_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'audit-sql-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_audit_sql_extraction','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_audit_sql_extraction',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  m.validate_content_result(row,'audit-sql-content')
  for mutate in [lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'audit-sql-content')

 def test_audit_instruction_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,audit_instruction_content=True)
  self.assertEqual(m.content_mode(a),'audit-instruction-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_AUDIT_INSTRUCTION_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'audit-instruction-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_audit_instruction_followed','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_audit_instruction_followed',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  row=self.controlled_reset_fixture('ss_audit_instruction_followed');row['profile']='audit-instruction-content';row['content']['auditControlledReset']=row['content'].pop('analyticsLifecycle')
  m.validate_content_result(row,'audit-instruction-content')
  for mutate in [lambda r:r['content']['projectionRoutes'][0].update(done=0),lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'audit-instruction-content')
 def test_audit_controlled_tail_requires_reset_and_sibling_receipts(self):
  import copy
  row=self.controlled_reset_fixture('ss_audit_instruction_followed');row['profile']='audit-instruction-content';row['content']['auditControlledReset']=row['content'].pop('analyticsLifecycle')
  for mutate in [lambda r:r['content'].pop('auditControlledReset'),lambda r:r['content']['auditControlledReset'].update(actualModelProof=True),lambda r:r.update(modelCalls=1),lambda r:r.update(judgeCalls=1),lambda r:r['content']['auditControlledReset']['after']['siblingCompletions'].clear(),lambda r:r['content']['auditControlledReset']['canonicalAfter'].update(completedObjectiveCount=1),lambda r:r['content']['auditControlledReset'].update(immutableAfter={}),lambda r:r['content']['auditControlledReset']['cleanupHistory'].update(retired_time_seconds='0'),lambda r:r['content']['auditControlledReset']['before']['ownerCompletions'][0].update(objective_id='ss_analytics_sensitive_disclosure'),lambda r:r['content']['auditControlledReset'].update(staleLaunchDenied=False),lambda r:r['content']['auditControlledReset']['replay']['body'].update(resetId='wrong')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'audit-instruction-content')

 def test_ssrf_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,ssrf_content=True)
  self.assertEqual(m.content_mode(a),'ssrf-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_SSRF_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'ssrf-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_controlled_ssrf','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_controlled_ssrf',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  row['content']['projectionRoutes']=[{'requested':p,'total':1,'done':1,'time':75} for p in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']]
  m.validate_content_result(row,'ssrf-content')
  for mutate in [lambda r:r['content']['projectionRoutes'][0].update(done=0),lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'ssrf-content')
 def test_review_persist_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,review_persist_content=True)
  self.assertEqual(m.content_mode(a),'review-persist-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_REVIEW_PERSIST_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'review-persist-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_content_persist','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_content_persist',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  m.validate_content_result(row,'review-persist-content')
  for mutate in [lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'review-persist-content')
 def controlled_reset_fixture(self,objective='ss_analytics_sensitive_disclosure'):
  import copy
  workshop='secureshop_agent_security'
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  completion=lambda uid:[{'user_id':uid,'workshop_key':workshop,'objective_id':objective}]
  times=lambda uid,seconds:[{'id':uid,'user_id':uid,'workshop_key':workshop,'duration_seconds':seconds,'platform_launch_id':'22222222-2222-4222-8222-222222222222','platform_launch_generation':0,'workshop_generation':0}]
  reset={'status':200,'body':{'resetId':'11111111-1111-4111-8111-111111111111','cleanupComplete':True,'launch':{'generation':1}}}
  proof=dict.fromkeys(['controlledProjectionReset','resetReplayExact','staleLaunchDenied','seededTimeRetired','siblingPreserved','immutablePreserved'],True)
  proof.update(objectiveId=objective,actualModelProof=False,staleStatus=409,ownerId=1,siblingId=2,beforeGeneration=0,afterGeneration=1,seededTimeId=1,reset=reset,replay=copy.deepcopy(reset),before={'ownerCompletions':completion(1),'ownerTime':times(1,75),'siblingCompletions':completion(2),'siblingTime':times(2,23)},after={'ownerCompletions':[],'ownerTime':times(1,75),'siblingCompletions':completion(2),'siblingTime':times(2,23)},immutableBefore={'judgments':[],'packets':[],'effects':[]},immutableAfter={'judgments':[],'packets':[],'effects':[]})
  proof.update(rawTimePreserved=True,launchId='22222222-2222-4222-8222-222222222222',cleanupHistory={'reset_id':reset['body']['resetId'],'launch_id':'22222222-2222-4222-8222-222222222222','original_platform_owner_id':1,'workshop_key':workshop,'from_launch_generation':0,'workshop_generation':0,'retired_time_entry_count':1,'retired_time_seconds':'75','projected_time_seconds':'0'},canonicalAfter={'workshopKey':workshop,'completedObjectiveCount':0,'timeSpentSeconds':0})
  proof['siblingLaunch']={'ownerId':2,'launchId':'33333333-3333-4333-8333-333333333333','scenarioId':'44444444-4444-4444-8444-444444444444','generation':1,'workshopGeneration':0}
  for side in ['before','after']:proof[side]['siblingTime'][0].update(platform_launch_id=proof['siblingLaunch']['launchId'],platform_scenario_id=proof['siblingLaunch']['scenarioId'],platform_launch_generation=1)
  row={'profile':'analytics-disclosure-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':objective,'apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':objective,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}],'projectionRoutes':[{'requested':r,'total':1,'done':1,'time':75} for r in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']],'analyticsLifecycle':proof,'instructorProjection':{'total':1,'done':1,'time':75}}}
  return row

 def test_analytics_content_exact_profile_and_lifecycle(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,analytics_disclosure_content=True)
  self.assertEqual(m.content_mode(a),'analytics-disclosure-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_ANALYTICS_DISCLOSURE_CONTENT'],'1');self.assertEqual(env['AI_PROVIDER'],'mock')
  row=self.controlled_reset_fixture()
  m.validate_content_result(row,'analytics-disclosure-content')
  for mutate in [lambda r:r['content']['analyticsLifecycle']['siblingLaunch'].update(ownerId=1),lambda r:r['content']['analyticsLifecycle']['siblingLaunch'].update(generation=2),lambda r:r['content']['analyticsLifecycle']['siblingLaunch'].update(scenarioId='44444444-4444-4444-8444-555555555555'),lambda r:r['content']['analyticsLifecycle']['cleanupHistory'].update(reset_id='wrong'),lambda r:r['content']['analyticsLifecycle']['cleanupHistory'].update(retired_time_seconds='74'),lambda r:r['content']['analyticsLifecycle']['cleanupHistory'].update(workshop_generation=9),lambda r:r['content']['analyticsLifecycle']['canonicalAfter'].update(timeSpentSeconds=75),lambda r:r['content'].update(instructorProjection={}),lambda r:r.update(genuineCredit=1),lambda r:r.update(effects=1),lambda r:r.update(controlledProjectionCount=2),lambda r:r['content']['projectionRoutes'].reverse(),lambda r:r['content']['projectionRoutes'][0].update(time=0),lambda r:r['content']['cases'][0].update(id='wrong'),lambda r:r['content']['analyticsLifecycle'].update(actualModelProof=True),lambda r:r['content']['analyticsLifecycle'].update(afterGeneration=2),lambda r:r['content']['analyticsLifecycle'].update(seededTimeId=9),lambda r:r['content']['analyticsLifecycle']['after'].update(ownerTime=[]),lambda r:r['content']['analyticsLifecycle']['before'].update(siblingTime=[]),lambda r:r['content']['analyticsLifecycle'].update(immutableAfter={}),lambda r:r['content']['analyticsLifecycle']['replay']['body'].update(resetId='different')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'analytics-disclosure-content')

 def test_review_followed_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,review_followed_content=True)
  self.assertEqual(m.content_mode(a),'review-followed-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_REVIEW_FOLLOWED_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'review-followed-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_content_followed','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_content_followed',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  row['content']['projectionRoutes']=[{'requested':route,'total':1,'done':1,'time':75} for route in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']]
  m.validate_content_result(row,'review-followed-content')
  for mutate in [lambda r:r['content'].update(projectionRoutes=[]),lambda r:r['content']['projectionRoutes'][0].update(time=0),lambda r:r['content'].update(objectiveId='ss_content_persist'),lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'review-followed-content')
 def test_pricing_disclosure_profile_no_execution_and_exact_projection(self):
  import copy
  a=SimpleNamespace(main_workspace='/main',manifest='/private/m.json',manifest_sha256='a'*64,input='/private/i.json',input_sha256='b'*64,browser='/native/chrome',browser_sha256='c'*64,pricing_disclosure_content=True)
  self.assertEqual(m.content_mode(a),'pricing-disclosure-content')
  env=m.child_environment({'HOME':'/private/home'},Path('/evidence'),Path('/evidence/runtime'),'owner',a)
  self.assertEqual(env['MAIL_BROWSER_PRICING_DISCLOSURE_CONTENT'],'1');self.assertNotIn('MAIL_BROWSER_LOOP_CONTENT',env);self.assertEqual(env['AI_PROVIDER'],'mock')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'pricing-disclosure-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'content':{'objectiveId':'ss_pricing_competitor_disclosure','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_pricing_competitor_disclosure',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  m.validate_content_result(row,'pricing-disclosure-content')
  for mutate in [lambda r:r.update(effects=1),lambda r:r.update(controlledProviderCalls=1),lambda r:r.update(loopLifecycle={}),lambda r:r.update(genuineCredit=1),lambda r:r['content'].update(projectionRestored=False),lambda r:r['content']['cases'][0].update(id='ss_loop_observation')]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'pricing-disclosure-content')
 def test_inputs_are_exact(self):
  source=FILE.resolve().parents[2];self.assertEqual(m.digest(source/m.ACTUAL_INPUT),m.ACTUAL_INPUT_SHA256)
  args=SimpleNamespace(input=str(source/m.ACTUAL_INPUT),input_sha256=m.ACTUAL_INPUT_SHA256)
  m.validate_actual_input(args,source,{'sourcePins':{m.ACTUAL_INPUT:m.ACTUAL_INPUT_SHA256}})
  with self.assertRaises(RuntimeError):m.validate_actual_input(args,source,{'sourcePins':{}})
 def test_content_receipt_is_closed_and_zero_inference(self):
  import copy
  row={'profile':'content-only','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'cases':[],'content':{'objectiveId':'ss_mail_stored_browser_execution','apiRequests':30,**dict.fromkeys(['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved'],True)}}
  m.validate_content_result(row)
  self.assertEqual(m.CONTENT_API_REQUEST_LIMIT,1024)
  for count in [1,1024]:
   bounded=copy.deepcopy(row);bounded['content']['apiRequests']=count;m.validate_content_result(bounded)
  for count in [0,1025,True,1.5]:
   bounded=copy.deepcopy(row);bounded['content']['apiRequests']=count
   with self.assertRaises(RuntimeError):m.validate_content_result(bounded)
  for key,value in [('modelCalls',1),('judgeCalls',True),('genuineCredit',1),('transport',{}),('profile','actual')]:
   bad=copy.deepcopy(row);bad[key]=value
   with self.assertRaises(RuntimeError):m.validate_content_result(bad)
  for key in ['hint','solution','configurationRestored','siblingPreserved']:
   bad=copy.deepcopy(row);bad['content'][key]=False
   with self.assertRaises(RuntimeError):m.validate_content_result(bad)
 def test_stored_browser_closed_lifecycle_and_aggregate_budget(self):
  import copy
  a=SimpleNamespace(stored_browser_content_lifecycle=True)
  self.assertEqual(m.content_mode(a),'stored-browser-content-lifecycle')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  proof=dict.fromkeys(['mountedProduct','realBrowserEffect','controlledNonaward','heldReset','stalePublicationDenied','seededProjectionRetired','immutableHistoryPreserved','siblingPreserved','contextsClosed'],True)
  proof.update(actualModelProof=False,controlledJudgeCalls=1,seededAcceptedContributions=1,browserCalls=2,browserExecutions=2,confirmedCompletedEffectCount=1,runId="run",effectKey="effect",completedEffectReceipt={"version":1,"status":"completed","runId":"run","effectKey":"effect","ownerKey":"owner","generation":"1"},requests=40)
  row={'profile':'stored-browser-content-lifecycle','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':1,'browserExecutions':2,'controlledProviderCalls':0,'controlledProjectionCount':1,'cases':[],'storedBrowserLifecycle':proof,'content':{'objectiveId':'ss_stored_browser_execution','apiRequests':100,**dict.fromkeys(flags,True),'cases':[{'id':'ss_stored_browser_execution',**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)}]}}
  m.validate_content_result(row,'stored-browser-content-lifecycle')
  for field,value in [('heldReset',False),('actualModelProof',True),('controlledJudgeCalls',2),('seededAcceptedContributions',0),('requests',925),('confirmedCompletedEffectCount',2),('browserExecutions',1),('completedEffectReceipt',{})]:
   bad=copy.deepcopy(row);bad['storedBrowserLifecycle'][field]=value
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'stored-browser-content-lifecycle')

 def test_inbox_three_closed_projection(self):
  import copy
  args=SimpleNamespace(inbox_content=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/browser',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'inbox-content')
  env=m.child_environment({'HOME':'/owned'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  self.assertEqual(env['MAIL_BROWSER_INBOX_CONTENT'],'1');self.assertEqual(env['AI_PROVIDER'],'mock');self.assertEqual(env['OLLAMA_BASE_URL'],'http://127.0.0.1:1')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'inbox-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':3,'cases':[],'content':{'objectiveId':None,'apiRequests':400,**dict.fromkeys(flags,True),'cases':[{'id':id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)} for id in m.INBOX_CONTENT_IDS],'projectionRoutes':[{'requested':path,'total':3,'done':3,'time':75} for path in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']]}}
  m.validate_content_result(row,'inbox-content')
  for field,value in [('effects',1),('controlledProviderCalls',1),('controlledProjectionCount',1),('genuineCredit',3),('judgeCalls',1),('loopLifecycle',{})]:
   bad=copy.deepcopy(row);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'inbox-content')
  for change in ['case','count','time','restored']:
   bad=copy.deepcopy(row)
   if change=='case':bad['content']['cases'][2]['id']='ss_audit_sql_extraction'
   elif change=='count':bad['content']['projectionRoutes'][0]['done']=1
   elif change=='time':bad['content']['projectionRoutes'][0]['time']=0
   else:bad['content']['projectionRestored']=False
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'inbox-content')

 def test_mcp_trust_two_closed_projection(self):
  import copy
  args=SimpleNamespace(mcp_trust_content=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/browser',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'mcp-trust-content')
  env=m.child_environment({'HOME':'/owned'},Path('/evidence'),Path('/evidence/runtime'),'owner',args)
  self.assertEqual(env['MAIL_BROWSER_MCP_TRUST_CONTENT'],'1');self.assertEqual(env['AI_PROVIDER'],'mock');self.assertEqual(env['OLLAMA_BASE_URL'],'http://127.0.0.1:1')
  flags=['label','hint','solution','objectiveGates','masterGates','adminParity','configurationRestored','immutableEvidencePreserved','siblingPreserved','controlledProjection','completedStyling','threeRouteParity','instructorCompletion','projectionRestored']
  row={'profile':'mcp-trust-content','status':'passed','cleanupFailures':[],'modelCalls':0,'judgeCalls':0,'genuineCredit':0,'actualActorCalls':0,'effects':0,'controlledProviderCalls':0,'controlledProjectionCount':2,'cases':[],'content':{'objectiveId':None,'apiRequests':400,**dict.fromkeys(flags,True),'cases':[{'id':id,**dict.fromkeys(['label','hint','solution','objectiveGates','adminParity'],True)} for id in m.MCP_TRUST_CONTENT_IDS],'projectionRoutes':[{'requested':path,'total':2,'done':2,'time':75} for path in ['/workshop-dashboard','/workshop/challenges','/workshop/progress']]}}
  m.validate_content_result(row,'mcp-trust-content')
  for field,value in [('effects',1),('controlledProviderCalls',1),('controlledProjectionCount',1),('genuineCredit',3),('judgeCalls',1),('loopLifecycle',{})]:
   bad=copy.deepcopy(row);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'mcp-trust-content')
  for change in ['case','count','time','restored']:
   bad=copy.deepcopy(row)
   if change=='case':bad['content']['cases'][1]['id']='ss_audit_sql_extraction'
   elif change=='count':bad['content']['projectionRoutes'][0]['done']=1
   elif change=='time':bad['content']['projectionRoutes'][0]['time']=0
   else:bad['content']['projectionRestored']=False
   with self.assertRaises(RuntimeError):m.validate_content_result(bad,'mcp-trust-content')

 def test_inbox_actual_closed_wire_and_no_browser(self):
  import copy,hashlib
  args=SimpleNamespace(inbox_actual=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/b',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'inbox-actual');env=m.child_environment({},Path('/e'),Path('/r'),'o',args);self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['MAIL_BROWSER_INBOX_ACTUAL'],'1');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env)
  calls=[]
  for case,role in [(None,'tags'),('advisory','actor'),('advisory','judge'),('enforced','actor'),('enforced','judge')]:
   calls.append({'index':len(calls),'caseId':case,'role':role,'httpStatus':200,'status':'returned','request':'{}','response':'{}','requestSha256':hashlib.sha256(b'{}').hexdigest(),'responseSha256':hashlib.sha256(b'{}').hexdigest()})
  wire={'version':'inbox-actual-wire-v1','closed':True,'failed':False,'physicalPending':0,'calls':calls,'counts':{'actor':2,'judge':2,'tags':1},'phaseCounts':{id:{'actor':1,'judge':1} for id in ['advisory','enforced']}}
  result={'profile':'inbox-actual','status':'passed','cleanupFailures':[],'inboxActual':{'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':m.INBOX_CONTENT_IDS,'genuineCredit':3,'cases':[{'id':id,'replay':True} for id in ['advisory','enforced']],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved'],True),'actorCalls':2,'judgeCalls':2}}
  m.validate_inbox_actual_result(result,wire)
  for field,value in [('closed',False),('failed',True),('physicalPending',1)]:
   bad=copy.deepcopy(wire);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_inbox_actual_result(result,bad)
  bad=copy.deepcopy(wire);bad['calls'][1]['response']='tamper'
  with self.assertRaises(RuntimeError):m.validate_inbox_actual_result(result,bad)
  bad=copy.deepcopy(result);bad['inboxActual']['genuineCredit']=2
  with self.assertRaises(RuntimeError):m.validate_inbox_actual_result(bad,wire)

 def test_mcp_trust_actual_closed_wire_and_no_browser(self):
  import copy,hashlib
  args=SimpleNamespace(mcp_trust_actual=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/b',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'mcp-trust-actual');env=m.child_environment({},Path('/e'),Path('/r'),'o',args);self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['MAIL_BROWSER_MCP_TRUST_ACTUAL'],'1');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env)
  calls=[]
  for case,role in [(None,'tags'),('rogue','actor'),('rogue','judge'),('baseline','actor'),('changed','actor'),('changed','judge')]:
   calls.append({'index':len(calls),'caseId':case,'role':role,'httpStatus':200,'status':'returned','request':'{}','response':'{}','requestSha256':hashlib.sha256(b'{}').hexdigest(),'responseSha256':hashlib.sha256(b'{}').hexdigest()})
  wire={'version':'mcp-trust-actual-wire-v1','closed':True,'failed':False,'physicalPending':0,'calls':calls,'counts':{'actor':3,'judge':2,'tags':1},'phaseCounts':{id:{'actor':1,'judge':0 if id=='baseline' else 1} for id in ['rogue','baseline','changed']}}
  result={'profile':'mcp-trust-actual','status':'passed','cleanupFailures':[],'mcpTrustActual':{'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':m.MCP_TRUST_CONTENT_IDS,'genuineCredit':2,'cases':[{'id':id,'replay':True} for id in ['rogue','baseline','changed']],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved','ownedTargetsRetired'],True),'policyScope':{'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False},'actorCalls':3,'judgeCalls':2}}
  m.validate_mcp_trust_actual_result(result,wire)
  for field,value in [('closed',False),('failed',True),('physicalPending',1)]:
   bad=copy.deepcopy(wire);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_mcp_trust_actual_result(result,bad)
  bad=copy.deepcopy(wire);bad['calls'][1]['response']='tamper'
  with self.assertRaises(RuntimeError):m.validate_mcp_trust_actual_result(result,bad)
  bad=copy.deepcopy(result);bad['mcpTrustActual']['genuineCredit']=1
  with self.assertRaises(RuntimeError):m.validate_mcp_trust_actual_result(bad,wire)

 def test_ssrf_actual_closed_wire_and_no_browser(self):
  import copy,hashlib
  args=SimpleNamespace(ssrf_actual=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/b',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'ssrf-actual');env=m.child_environment({},Path('/e'),Path('/r'),'o',args);self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['MAIL_BROWSER_SSRF_ACTUAL'],'1');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env)
  calls=[]
  for case,role in [(None,'tags'),('baseline','actor'),('private','actor'),('private','judge')]:
   calls.append({'index':len(calls),'caseId':case,'role':role,'httpStatus':200,'status':'returned','request':'{}','response':'{}','requestSha256':hashlib.sha256(b'{}').hexdigest(),'responseSha256':hashlib.sha256(b'{}').hexdigest()})
  wire={'version':'ssrf-actual-wire-v1','closed':True,'failed':False,'physicalPending':0,'calls':calls,'counts':{'actor':2,'judge':1,'tags':1},'phaseCounts':{id:{'actor':1,'judge':0 if id=='baseline' else 1} for id in ['baseline','private']}}
  result={'profile':'ssrf-actual','status':'passed','cleanupFailures':[],'ssrfActual':{'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':['ss_controlled_ssrf'],'genuineCredit':1,'cases':[{'id':id,'replay':True} for id in ['baseline','private']],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved','ownedTargetsRetired','sdkRetired'],True),'policyScope':{'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False},'actorCalls':2,'judgeCalls':1}}
  m.validate_ssrf_actual_result(result,wire)
  for field,value in [('closed',False),('failed',True),('physicalPending',1)]:
   bad=copy.deepcopy(wire);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_ssrf_actual_result(result,bad)
  bad=copy.deepcopy(wire);bad['calls'][1]['response']='tamper'
  with self.assertRaises(RuntimeError):m.validate_ssrf_actual_result(result,bad)
  bad=copy.deepcopy(result);bad['ssrfActual']['genuineCredit']=0
  with self.assertRaises(RuntimeError):m.validate_ssrf_actual_result(bad,wire)
 def test_audit_instruction_actual_closed_wire_and_no_browser(self):
  import copy,hashlib,tempfile
  args=SimpleNamespace(audit_instruction_actual=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/b',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'audit-instruction-actual');env=m.child_environment({},Path('/e'),Path('/r'),'o',args);self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertEqual(env['MAIL_BROWSER_AUDIT_INSTRUCTION_ACTUAL'],'1');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env)
  calls=[]
  for case,role in [(None,'tags'),('benign','actor'),('benign','judge'),('injected','actor'),('injected','judge')]:
   calls.append({'index':len(calls),'caseId':case,'role':role,'httpStatus':200,'status':'returned','request':'{}','response':'{}','requestSha256':hashlib.sha256(b'{}').hexdigest(),'responseSha256':hashlib.sha256(b'{}').hexdigest()})
  wire={'version':'audit-instruction-actual-wire-v1','model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e','closed':True,'failed':False,'physicalPending':0,'calls':calls,'counts':{'actor':2,'judge':2,'tags':1},'phaseCounts':{id:{'actor':1,'judge':1} for id in ['benign','injected']}}
  result={'profile':'audit-instruction-actual','status':'passed','cleanupFailures':[],'auditInstructionActual':{'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':['ss_audit_instruction_followed'],'genuineCredit':1,'cases':[{'id':id,'replay':True} for id in ['benign','injected']],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved','workerRetired'],True),'policyScope':{'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False},'actorCalls':2,'judgeCalls':2}}
  m.validate_audit_instruction_actual_result(result,wire)
  args.audit_70b=True;env=m.child_environment({},Path('/e'),Path('/r'),'o',args)
  self.assertEqual(env['OLLAMA_MODEL'],'llama3.3:70b');self.assertEqual(env['SS_AUDIT_RUN_TIMEOUT_MS'],'290000');self.assertEqual(env['SS_AUDIT_JUDGE_TIMEOUT_MS'],'240000')
  actual70=copy.deepcopy(wire);actual70.update(model='llama3.3:70b',digest='a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa')
  with self.assertRaisesRegex(RuntimeError,'rendered scope'):m.validate_audit_instruction_actual_result(result,actual70,audit70b=True)
  rendered={'version':'audit-earned-rendered-v1','objectiveId':'ss_audit_instruction_followed','ownerId':7,'launchId':'owned-launch','generation':0,'timeFabricated':False,**dict.fromkeys(['earnedCompletion','completedStyling','learnerInstructorParity','threeRouteParity','authenticatedApiRunInspectable','resetIncomplete'],True)}
  result['auditInstructionActual']['rendered']=rendered
  m.validate_audit_instruction_actual_result(result,actual70,audit70b=True)
  with self.assertRaisesRegex(RuntimeError,'model identity'):m.validate_audit_instruction_actual_result(result,wire,audit70b=True)
  for key in ['earnedCompletion','completedStyling','learnerInstructorParity','threeRouteParity','authenticatedApiRunInspectable','resetIncomplete']:
   bad=copy.deepcopy(result);bad['auditInstructionActual']['rendered'][key]=False
   with self.assertRaisesRegex(RuntimeError,'rendered checkpoint'):m.validate_audit_instruction_actual_result(bad,actual70,audit70b=True)
  bad=copy.deepcopy(result);bad['auditInstructionActual']['rendered']['timeFabricated']=True
  with self.assertRaisesRegex(RuntimeError,'fabricated'):m.validate_audit_instruction_actual_result(bad,actual70,audit70b=True)
  with tempfile.TemporaryDirectory() as directory:
   with self.assertRaisesRegex(RuntimeError,'browser ownership'):m.verify_browser_absence(Path(directory),{'mode':'audit-instruction-actual','audit70b':True,'exitCode':0},[])
   self.assertFalse(m.verify_browser_absence(Path(directory),{'mode':'audit-instruction-actual','audit70b':False,'exitCode':0},[])['started'])

  required=['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root','input','input-sha256']
  flags=[piece for key in required for piece in ('--'+key,'x')]
  with self.assertRaisesRegex(ValueError,'requires Audit actual'):m.parse_main([*flags,'--audit-70b'])
  for field,value in [('closed',False),('failed',True),('physicalPending',1)]:
   bad=copy.deepcopy(wire);bad[field]=value
   with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(result,bad)
  bad=copy.deepcopy(wire);bad['calls'][1]['response']='tamper'
  with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(result,bad)
  bad=copy.deepcopy(result);bad['auditInstructionActual']['genuineCredit']=0
  with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(bad,wire)

class ReviewFollowedControls(unittest.TestCase):
 def fixture(self):
  import hashlib,json
  ids=['authentic_advertising_approve_exploit','advertising_violation_without_instruction'];model='llama3.1:8b';digest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';calls=[]
  for case,role in [(None,'tags')]+[(id,role) for id in ids for role in ['actor','judge']]:
   request='' if role=='tags' else json.dumps({'model':model,'stream':True,'messages':[{'role':'system','content':'controlled'}],'format':{},'options':{'temperature':0,'num_predict':900,'num_ctx':32768}})
   response=json.dumps({'models':[{'name':model,'digest':digest}]}) if role=='tags' else json.dumps({'model':model,'done':True,'done_reason':'stop','message':{'content':'{}'}})
   calls.append({'index':len(calls),'caseId':case,'role':role,'path':'/api/tags' if role=='tags' else '/api/chat','httpStatus':200,'status':'returned','request':request,'response':response,'requestSha256':hashlib.sha256(request.encode()).hexdigest(),'responseSha256':hashlib.sha256(response.encode()).hexdigest()})
  wire={'model':model,'digest':digest,'version':'review-followed-actual-wire-v1','closed':True,'failed':False,'physicalPending':0,'externalAttempts':5,'calls':calls,'counts':{'actor':2,'judge':2,'tags':1},'phaseCounts':{id:{'actor':1,'judge':1} for id in ids}}
  proof={'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':['ss_content_followed'],'genuineCredit':1,'cases':[{'id':id,'replay':True,'accepted':True,'error':None} for id in ids],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved','positiveAccepted','negativeDenied'],True),'policyScope':{'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False},'actorCalls':2,'judgeCalls':2}
  return {'profile':'review-followed-actual','status':'passed','cleanupFailures':[],'browserStarted':False,'actualActorCalls':2,'judgeCalls':2,'modelCalls':4,'genuineCredit':1,'reviewFollowedActual':proof},wire
 def test_closed_admission_and_receipt(self):
  args=SimpleNamespace(review_followed_actual=True,main_workspace='/main',manifest='/m',manifest_sha256='a'*64,input='/i',input_sha256='b'*64,browser='/b',browser_sha256='c'*64)
  self.assertEqual(m.content_mode(args),'review-followed-actual');env=m.child_environment({},Path('/e'),Path('/r'),'o',args);self.assertEqual(env['MAIL_BROWSER_REVIEW_FOLLOWED_ACTUAL'],'1');self.assertEqual(env['AI_PROVIDER'],'ollama');self.assertNotIn('MAIL_BROWSER_CONTENT_ONLY',env)
  result,wire=self.fixture();m.validate_review_followed_actual_result(result,wire)
 def test_failed_unbound_or_tampered_receipts_rejected(self):
  import copy
  result,wire=self.fixture()
  for key,value in [('status','failed'),('genuineCredit',0),('browserStarted',True)]:
   bad=copy.deepcopy(result);bad[key]=value
   with self.assertRaises(RuntimeError):m.validate_review_followed_actual_result(bad,wire)
  for key,value in [('closed',False),('externalAttempts',33),('digest','0'*64)]:
   bad=copy.deepcopy(wire);bad[key]=value
   with self.assertRaises(RuntimeError):m.validate_review_followed_actual_result(result,bad)
  bad=copy.deepcopy(wire);bad['calls'][1]['response']='tamper'
  with self.assertRaises(RuntimeError):m.validate_review_followed_actual_result(result,bad)
  bad=copy.deepcopy(result);bad['reviewFollowedActual']['cases'].reverse()
  with self.assertRaises(RuntimeError):m.validate_review_followed_actual_result(bad,wire)

 def test_rehashed_truncation_and_negative_positive_only_options_rejected(self):
  import copy,json,hashlib
  result,wire=self.fixture()
  for index,key,mutate in [(1,'response',lambda value:value.update(done_reason='length')),(4,'request',lambda value:value['options'].update(num_predict=1040))]:
   bad=copy.deepcopy(wire);value=json.loads(bad['calls'][index][key]);mutate(value);raw=json.dumps(value);bad['calls'][index][key]=raw;bad['calls'][index][key+'Sha256']=hashlib.sha256(raw.encode()).hexdigest()
   with self.assertRaises(RuntimeError):m.validate_review_followed_actual_result(result,bad)


class AuditContinuationControls(unittest.TestCase):
 def fixture(self):
  import copy,hashlib,json
  sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
  encode=lambda x:json.dumps(x,ensure_ascii=False,separators=(',',':'))
  parent='11111111-1111-4111-8111-111111111111';child='22222222-2222-4222-8222-222222222222';run='33333333-3333-4333-8333-333333333333';retry='44444444-4444-4444-8444-444444444444';objective='ss_audit_instruction_followed'
  calls=[]
  for case,role in [(None,'tags'),('benign','actor'),('benign','judge'),('injected','actor'),('injected','judge'),('injected','judge'),('injected','judge'),('recovery','judge')]:
   request=encode({'messages':[{'role':'user','content':'saved request'}],'format':{'type':'object'},'options':{'temperature':0,'num_predict':500,'num_ctx':32768}});response=encode({'message':{'content':'accepted stage'}})
   row={'index':len(calls),'role':role,'caseId':case,'status':'returned','httpStatus':200,'request':request,'requestSha256':sha(request),'response':response,'responseSha256':sha(response)}
   if len(calls)==6:row.update(status='incomplete',partialResponse='',partialResponseSha256=sha(''),judgeAbortReason='TimeoutError');row.pop('response');row.pop('responseSha256')
   calls.append(row)
  checkpoints=[]
  for stage in ['source','effect']:
   canonical={'messages':[{'role':'user','content':'saved request'}],'format':{'type':'object'},'maxOutput':500,'temperature':0,'numCtx':32768}
   checkpoints.append({'evaluation_id':parent,'stage':stage,'user_id':7,'run_id':run,'provider':'ollama','model':'llama3.3:70b','raw_response':'accepted stage','response_sha256':sha('accepted stage'),'actual_request_sha256':sha(encode(canonical)),'checkpoint_sha256':sha(stage),'source_checkpoint_sha256':None if stage=='source' else sha('source')})
  judgment={'evaluation_id':parent,'user_id':7,'run_id':run,'objective_id':objective,'verdict':'unavailable','result_json':{'errorCode':'JUDGE_TIMEOUT'}}
  before={'judgments':[judgment],'packets':[{'evaluation_id':parent,'user_id':7,'packet':'retained packet'}],'checkpoints':checkpoints,'contributions':[],'completions':[]}
  after=copy.deepcopy(before);after['packets'][0]['child_evaluation_id']=child
  after['judgments'].append({'evaluation_id':child,'user_id':7,'run_id':run,'objective_id':objective,'verdict':'pass','disposition':'awarded','result_json':{'comparisonStages':[{'stage':stage,'attempts':attempt} for stage,attempt in [('source',0),('effect',0),('support',1)]],'auditContinuation':{'checkpoints':[{'stage':stage,'checkpointSha256':sha(stage)} for stage in ['source','effect']]}}})
  after['contributions']=[{'evaluation_id':child,'user_id':7,'objective_id':objective}];after['completions']=[{'user_id':7,'objective_id':objective,'workshop_key':'secureshop_agent_security'}]
  captures={'scope':{'ownerId':7,'launchId':'launch','generation':0},'cases':[{'name':'injected','snapshot':before,'response':{'body':{'objectiveCredit':False}},'verified':{'runId':run}}],'recovery':{'parentEvaluationId':parent,'parentVerdict':'unavailable','parentErrorCode':'JUDGE_TIMEOUT','sourceCheckpointSha256':sha('source'),'effectCheckpointSha256':sha('effect'),'originalObjectiveCredit':False,'retry':{'status':200,'body':{'completed':True,'replayed':False,'judgment':{'evaluationId':child},'retryRunId':retry}},'after':after}}
  rendered={'version':'audit-earned-rendered-v1','objectiveId':objective,'ownerId':7,'launchId':'launch','generation':0,'timeFabricated':False,**dict.fromkeys(['earnedCompletion','completedStyling','learnerInstructorParity','threeRouteParity','authenticatedApiRunInspectable','resetIncomplete'],True)}
  proof={'qualification':'qualified','actualModelProof':True,'qualifiedObjectiveIds':[objective],'genuineCredit':1,'cases':[{'id':id,'replay':True} for id in ['benign','injected']],**dict.fromkeys(['sessionDenied','reset','immutablePreserved','siblingPreserved','workerRetired'],True),'policyScope':{'toolPolicy':'canonical','promptPolicyFeatureEnabled':False,'rendererActivated':False},'actorCalls':2,'judgeCalls':5,'rendered':rendered,'recovery':{'parentEvaluationId':parent,'childEvaluationId':child,'oneChild':True,'actorReplay':False,'reusedStages':['source','effect'],'newStages':['support']}}
  wire={'version':'audit-instruction-actual-wire-v1','model':'llama3.3:70b','digest':'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa','closed':True,'failed':False,'physicalPending':0,'calls':calls,'counts':{'tags':1,'actor':2,'judge':5},'phaseCounts':{'benign':{'actor':1,'judge':1},'injected':{'actor':1,'judge':3},'recovery':{'actor':0,'judge':1}},'originalFailure':{'index':6,'status':'incomplete','judgeAbortReason':'TimeoutError'},'recoveryAdmission':{'evaluationId':parent,'parentErrorCode':'JUDGE_TIMEOUT','sourceCheckpointSha256':sha('source'),'effectCheckpointSha256':sha('effect')}}
  wire['externalAttempts']=len(calls)
  result={'profile':'audit-instruction-actual','status':'passed','cleanupFailures':[],'auditInstructionActual':proof,'actualActorCalls':2,'judgeCalls':5,'modelCalls':7,'genuineCredit':1}
  return result,wire,captures
 def source_only_fixture(self):
  import copy
  result,wire,captures=self.fixture();proof=result['auditInstructionActual'];proof['recovery'].update(reusedStages=['source'],newStages=['effect','support'])
  wire['calls'].pop(5);wire['calls'].append(copy.deepcopy(wire['calls'][-1]))
  for index,row in enumerate(wire['calls']):row['index']=index
  wire['originalFailure']['index']=5;wire['phaseCounts']['injected']['judge']=2;wire['phaseCounts']['recovery']['judge']=2
  wire['recoveryAdmission']['effectCheckpointSha256']=None;captures['recovery']['effectCheckpointSha256']=None
  for snapshot in [captures['cases'][0]['snapshot'],captures['recovery']['after']]:snapshot['checkpoints']=[x for x in snapshot['checkpoints'] if x['stage']=='source']
  child=captures['recovery']['after']['judgments'][1]['result_json'];child['comparisonStages'][1]['attempts']=1;child['auditContinuation']['checkpoints']=child['auditContinuation']['checkpoints'][:1]
  return result,wire,captures
 def test_source_only_resumes_exact_effect_and_support(self):
  result,wire,captures=self.source_only_fixture();m.validate_audit_instruction_actual_result(result,wire,audit70b=True,audit_continuation=True,captures=captures)
  import copy
  for mutate in [lambda r,w,c:r['auditInstructionActual']['recovery'].update(newStages=['support']),lambda r,w,c:w['calls'].pop(),lambda r,w,c:c['recovery'].update(effectCheckpointSha256='0'*64),lambda r,w,c:c['recovery']['after']['judgments'][1]['result_json']['comparisonStages'][1].update(attempts=0),lambda r,w,c:c['recovery']['after']['checkpoints'].append(dict(c['recovery']['after']['checkpoints'][0],evaluation_id=r['auditInstructionActual']['recovery']['childEvaluationId']))]:
   r,w,c=self.source_only_fixture();mutate(r,w,c)
   with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(r,w,audit70b=True,audit_continuation=True,captures=c)

 def test_closed_opt_in_deadlines_and_manifest(self):
  args=SimpleNamespace(audit_continuation=False,audit_70b=False,audit_instruction_actual=True)
  self.assertEqual(m.audit_time_limits(args),(780,600));args.audit_70b=True;self.assertEqual(m.audit_time_limits(args),(990,850));args.audit_continuation=True;self.assertEqual(m.audit_time_limits(args),(1350,1200))
  m.validate_audit_continuation_manifest(args,{'auditContinuation':True})
  for value in [False,1,'true',None]:
   with self.assertRaises(RuntimeError):m.validate_audit_continuation_manifest(args,{'auditContinuation':value})
  args.audit_70b=False
  with self.assertRaises(RuntimeError):m.validate_audit_continuation_manifest(args,{'auditContinuation':True})
  required=['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id','browser','browser-sha256','browser-root','input','input-sha256']
  flags=[piece for key in required for piece in ('--'+key,'x')]
  with self.assertRaisesRegex(ValueError,'continuation requires'):m.parse_main([*flags,'--audit-instruction-actual','--audit-continuation'])
  parsed=m.parse_main([*flags,'--audit-instruction-actual','--audit-70b','--audit-continuation']);self.assertTrue(parsed.audit_continuation)
  env=m.child_environment({},Path('/e'),Path('/r'),'o',parsed);self.assertEqual(env['MAIL_BROWSER_AUDIT_CONTINUATION'],'1');self.assertEqual(env['SS_AUDIT_RUN_TIMEOUT_MS'],'290000');self.assertEqual(env['SS_AUDIT_JUDGE_TIMEOUT_MS'],'240000')
 def test_terminal_joins_accepted_stages_and_genuine_child(self):
  result,wire,captures=self.fixture();m.validate_audit_instruction_actual_result(result,wire,audit70b=True,audit_continuation=True,captures=captures)
  with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(result,wire,audit70b=True)
  with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(result,wire,audit_continuation=True,captures=captures)
 def test_rejects_replayed_actor_forged_stages_and_mutated_authority(self):
  import copy,hashlib
  mutations=[lambda r,w,c:r.update(modelCalls=6),lambda r,w,c:w.update(externalAttempts=7),lambda r,w,c:w['originalFailure'].update(judgeAbortReason='AbortError'),lambda r,w,c:w['calls'][7].update(role='actor'),lambda r,w,c:w['calls'][7].update(request='{}',requestSha256=hashlib.sha256(b'{}').hexdigest()),lambda r,w,c:c['recovery']['after']['judgments'][0].update(verdict='pass'),lambda r,w,c:c['recovery']['after']['judgments'][1].update(run_id='55555555-5555-4555-8555-555555555555'),lambda r,w,c:c['recovery']['after']['contributions'].append(copy.deepcopy(c['recovery']['after']['contributions'][0])),lambda r,w,c:c['cases'][0]['snapshot']['checkpoints'][0].update(actual_request_sha256='0'*64),lambda r,w,c:c['recovery']['after']['judgments'][1]['result_json']['comparisonStages'][0].update(attempts=1),lambda r,w,c:c['recovery'].update(originalObjectiveCredit=True),lambda r,w,c:c['recovery']['after']['completions'][0].update(user_id=8),lambda r,w,c:r['auditInstructionActual']['rendered'].update(resetIncomplete=False)]
  for mutate in mutations:
   with self.subTest(mutation=mutate):
    r,w,c=self.fixture();mutate(r,w,c)
    with self.assertRaises(RuntimeError):m.validate_audit_instruction_actual_result(r,w,audit70b=True,audit_continuation=True,captures=c)

if __name__=='__main__':unittest.main()
