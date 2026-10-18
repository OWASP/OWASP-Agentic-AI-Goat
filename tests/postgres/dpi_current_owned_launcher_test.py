import importlib.util,pathlib,sys,unittest,copy,json
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('dpi_parent',HERE/'run-setup-database-phase-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_manifest(self):
  v={'cohort':'dpi-current-owned','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST,'inputSha256':m.DPI_INPUT_SHA256,'budgets':m.DPI_BUDGETS.copy()};self.assertTrue(m.validate_dpi_manifest(v))
  for k in v:
   with self.assertRaises(RuntimeError):m.validate_dpi_manifest({**v,k:'wrong'})
  for k in m.DPI_BUDGETS:
   bad=copy.deepcopy(v);bad['budgets'][k]+=1
   with self.assertRaises(RuntimeError):m.validate_dpi_manifest(bad)
  retained={**v,'selector':m.DPI_RETAINED_SELECTOR,'inputSha256':m.DPI_RETAINED_INPUT_SHA256,'budgets':m.DPI_RETAINED_BUDGETS.copy()};self.assertTrue(m.validate_dpi_manifest(retained))
  self.assertEqual(len(m.dpi_cases(m.DPI_RETAINED_SELECTOR)),9)
  for selector,input_sha,budgets,ids in [(m.DPI_FIXED_SELECTOR,m.DPI_FIXED_INPUT_SHA256,m.DPI_FIXED_BUDGETS,['obfuscation:fixed']),(m.DPI_RETRY_SELECTOR,m.DPI_RETRY_INPUT_SHA256,m.DPI_RETRY_BUDGETS,['virtualization:candidate','side_stepping:candidate','side_stepping:negative','obfuscation:candidate','obfuscation:fixed']),(m.DPI_UX_SELECTOR,m.DPI_UX_INPUT_SHA256,m.DPI_UX_BUDGETS,['interact:fixed1','interact:fixed2','system_prompt:candidate'])]:
   selected={**v,'selector':selector,'inputSha256':input_sha,'budgets':budgets.copy()};self.assertTrue(m.validate_dpi_manifest(selected));self.assertEqual([id for id,_ in m.dpi_cases(selector)],ids)
   for bad in ({**selected,'inputSha256':v['inputSha256']},{**selected,'budgets':v['budgets']}):
    with self.assertRaises(RuntimeError):m.validate_dpi_manifest(bad)
  for bad in ({**retained,'selector':'unknown'},{**retained,'inputSha256':v['inputSha256']},{**retained,'budgets':v['budgets']},{**v,'selector':'all'}):
   with self.assertRaises(RuntimeError):m.validate_dpi_manifest(bad)
 def test_identity_environment(self):
  sql,urls=m.dpi_store_configuration(55432,'abcdef012345');self.assertEqual(sql.count('CREATE DATABASE'),1);self.assertEqual(sql.count('CREATE ROLE'),2)
  a=SimpleNamespace(node='/node',package='/main',manifest='/main/m',manifest_sha256='a'*64)
  manifest={'cohort':'dpi-current-owned','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST,'inputSha256':m.DPI_INPUT_SHA256,'budgets':m.DPI_BUDGETS.copy()}
  with patch.object(pathlib.Path,'mkdir'),patch.object(pathlib.Path,'read_text',return_value=json.dumps(manifest)):
   e=m.dpi_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'abcdef012345'+20*'a',urls)
   for bad in [{**urls,'PG_ADMIN_DATABASE_URL':'bad'},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('runtime','migration')},{**urls,'IDENTITY_MIGRATION_DATABASE_URL':urls['IDENTITY_MIGRATION_DATABASE_URL'].replace('55432','55433')},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('abcdef012345','000000000000')}]:
    with self.assertRaises(RuntimeError):m.dpi_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),'abcdef012345'+20*'a',bad)
  self.assertEqual({k for k in e if k.endswith('_URL')},set(urls));self.assertEqual(e['LOGS_DIR'],'/e/runtime/logs');self.assertEqual(e['DPI_CURRENT_SELECTOR'],'all');self.assertNotIn('OPENAI_API_KEY',e);self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE',e)
 def test_selector_and_barrier(self):
  a=SimpleNamespace(scenario='dpi-current-owned',policy_cohort=None,main_workspace=True,python_sha256='a'*64,browser=None,browser_root=None,browser_sha256=None,original_case=None,node='/node',package='/main');m.validate_original_case(a)
  for k,v in [('main_workspace',False),('policy_cohort','plain'),('browser','/browser'),('python_sha256',None)]:
   b=copy.copy(a);setattr(b,k,v)
   with self.assertRaises(ValueError):m.validate_original_case(b)
  self.assertEqual(m.scenario_bounds(a.scenario),(5340,5220,120));self.assertEqual(m.scenario_command(a),['/node','/main/tests/postgres/dpiCurrentOwnedMain.js'])
  events=[];state={'parentPid':1,'manifestSha256':'a'*64};pipe=SimpleNamespace(write=lambda b:events.append(b),flush=lambda:None,close=lambda:None);m.publish_child_start(SimpleNamespace(pid=2,stdin=pipe),state,lambda:events.append(dict(state)),a.scenario);self.assertEqual(events[0]['nativePid'],2);self.assertEqual(events[1],b'1')
 def receipt(self):
  turns=[{'id':i,'objective':o,'status':503,'qualified':False,'outputLimited':False,'actualActorCalls':0,'actualJudgeCalls':0}for i,o in m.dpi_cases()]
  q={'technicalPassed':True,'allObjectivesCreditQualified':False,'installedWrites':False,'resetHistorySiblingPreserved':True,'semanticQualified':False,'turns':turns}
  w={'version':'dpi-current-owned-wire-v1','model':m.POLICY_MODEL,'digest':m.POLICY_DIGEST,'closed':True,'physicalPending':0,'handlersPending':0,'failures':[],'counts':{'external':1,'actor':0,'judge':0,'tags':1},'calls':[{'index':0,'kind':'tags','caseId':None,'terminal':'returned','status':200,'responseComplete':True,'responseCaptureTruncated':False}]}
  return {'status':'passed','installedWrites':False,'actualModelProof':False,'cleanupFailures':[],'qualification':q},w
 def test_technical_completion_is_not_semantic_credit(self):
  v,w=self.receipt();self.assertTrue(m.verify_dpi_result(v,w))
  for k,val in [('technicalPassed',False),('allObjectivesCreditQualified',True),('semanticQualified',True),('resetHistorySiblingPreserved',False),('turns',v['qualification']['turns'][:-1])]:
   b=copy.deepcopy(v);b['qualification'][k]=val
   with self.assertRaises(RuntimeError):m.verify_dpi_result(b,w)
 def test_actual_model_proof_requires_bound_returned_actor_and_judge(self):
  v,w=self.receipt()
  with self.assertRaisesRegex(RuntimeError,'actual model proof'):m.verify_dpi_result({**v,'actualModelProof':True},w)
  turn=v['qualification']['turns'][0];turn.update(status=200,actualActorCalls=1,actualJudgeCalls=1,actorBinding={'actorCalls':1,'effects':0},judgeBinding={'judgeCalls':1,'transcriptSha256':'a'*64})
  for kind in ('actor','judge'):
   w['calls'].append({**w['calls'][0],'index':len(w['calls']),'kind':kind,'caseId':turn['id'],'doneReason':'stop'});w['counts'][kind]+=1;w['counts']['external']+=1
  v['actualModelProof']=True;self.assertTrue(m.verify_dpi_result(v,w))
  for key in ('actorBinding','judgeBinding'):
   bad=copy.deepcopy(v);bad['qualification']['turns'][0].pop(key)
   with self.assertRaisesRegex(RuntimeError,'actual model proof'):m.verify_dpi_result(bad,w)
 def test_physical_wire_and_turn_denials(self):
  v,w=self.receipt()
  for k,val in [('closed',False),('physicalPending',1),('handlersPending',1),('digest','bad'),('failures',[{}])]:
   with self.assertRaises(RuntimeError):m.verify_dpi_result(v,{**w,k:val})
  for mutate in [lambda x:x['counts'].update(external=120),lambda x:x['calls'][0].update(terminal='pending'),lambda x:x['calls'][0].update(caseId='unknown'),lambda x:x['calls'][0].update(responseCaptureTruncated=True)]:
   b=copy.deepcopy(w);mutate(b)
   with self.assertRaises(RuntimeError):m.verify_dpi_result(v,b)
  b=copy.deepcopy(v);b['qualification']['turns'][0]['actualActorCalls']=1
  with self.assertRaises(RuntimeError):m.verify_dpi_result(b,w)
 def test_manifest_hash_precedes_inventory(self):
  a=SimpleNamespace(package=str(HERE.parents[1]),main_workspace=True,manifest='/absent',manifest_sha256='a'*64)
  with patch.object(m,'digest',return_value='b'*64),patch.object(m,'inventory',side_effect=AssertionError('no scan')):
   with self.assertRaisesRegex(RuntimeError,'manifest hash'):m.validate_finflow0055_main(a)
 def test_mode_ux_receipt_requires_ordered_stamp_and_completion_preservation(self):
  v,w=self.receipt();v['qualification'].update(selector=m.DPI_UX_SELECTOR,actorAchievement='unreviewed',modeTransitions=[
   {'from':'vuln','to':'fixed','generationBefore':'0','generationAfter':'0','modeStampBefore':'default','modeStampAfter':'fixed-stamp','revisionBefore':'0','revisionAfter':'1','staleGradeDenied':True,'completedObjectiveIds':[]},
   {'from':'fixed','to':'vuln','generationBefore':'0','generationAfter':'0','modeStampBefore':'fixed-stamp','modeStampAfter':'vuln-stamp','revisionBefore':'1','revisionAfter':'2','staleGradeDenied':True,'completedObjectiveIds':[]}]);
  v['qualification']['turns']=[{'id':i,'objective':o,'status':200,'qualified':False,'outputLimited':False,
    'actualActorCalls':1,'actualJudgeCalls':1,'actualReviewCalls':0,'actorProvenance':True,'effectProvenance':True,
    'actorBinding':{'actorCalls':1},'judgeBinding':{'judgeCalls':1,'transcriptSha256':'a'*64},
    'completedAfter':[],'actorOutcome':{'assessment':'unreviewed'}}for i,o in m.dpi_cases(m.DPI_UX_SELECTOR)]
  w['counts']['review']=0
  for turn in v['qualification']['turns']:
   for kind in ('actor','judge'):
    w['calls'].append({**w['calls'][0],'index':len(w['calls']),'kind':kind,'caseId':turn['id'],'doneReason':'stop'})
    w['counts'][kind]+=1;w['counts']['external']+=1
  v['actualModelProof']=True
  self.assertTrue(m.verify_dpi_result(v,w,m.DPI_UX_SELECTOR))
  for change in ['wrong-mode','lost-completion','generation-mutated','no-stamp','no-revision','stale-grade-not-denied']:
   bad=copy.deepcopy(v)
   if change=='wrong-mode':bad['qualification']['modeTransitions'][1]['to']='fixed'
   if change=='lost-completion':bad['qualification']['modeTransitions'][1]['completedObjectiveIds']=['interact']
   if change=='generation-mutated':bad['qualification']['modeTransitions'][0]['generationAfter']='1'
   if change=='no-stamp':bad['qualification']['modeTransitions'][0]['modeStampAfter']='default'
   if change=='no-revision':bad['qualification']['modeTransitions'][0]['revisionAfter']='0'
   if change=='stale-grade-not-denied':bad['qualification']['modeTransitions'][0]['staleGradeDenied']=False
   with self.assertRaises(RuntimeError):m.verify_dpi_result(bad,w,m.DPI_UX_SELECTOR)
if __name__=='__main__':
 import socket
 with patch('subprocess.run',side_effect=AssertionError('denied')),patch('subprocess.Popen',side_effect=AssertionError('denied')),patch.object(socket,'socket',side_effect=AssertionError('denied')):unittest.main()
