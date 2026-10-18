import importlib.util,pathlib,sys,unittest,copy,json
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('policy_parent',HERE/'run-setup-database-phase-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_closed_manifest_model(self):
  v={'cohort':'finflow-policy','policyCohort':'plain','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST};m.validate_policy_manifest(v,'plain')
  for k in v:
   with self.assertRaises(RuntimeError):m.validate_policy_manifest({**v,k:'wrong'},'plain')
  with self.assertRaises(RuntimeError):m.validate_policy_manifest(v,'adversarial')
 def test_exact_urls_clean_env(self):
  owner='abcdef012345-owned';urls={};sql=''
  for store in ('identity','finflow'):
   q,u=m.finflow_policy_store_configuration(store,55432,owner[:12]);sql+=q;urls.update(u)
  self.assertEqual(sql.count('CREATE DATABASE'),2);self.assertEqual(sql.count('CREATE ROLE'),4)
  a=SimpleNamespace(policy_cohort='plain',node='/node',package='/main',manifest='/main/m',manifest_sha256='a'*64)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.finflow_policy_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),owner,urls)
   for bad in [{**urls,'PG_ADMIN_DATABASE_URL':'postgresql://admin@127.0.0.1:55432/postgres'},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('55432','55433')},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('runtime','migration')}]:
    with self.assertRaises(RuntimeError):m.finflow_policy_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),owner,bad)
  self.assertEqual({k for k in env if k.endswith('_URL')},set(urls));self.assertNotIn('OPENAI_API_KEY',env);self.assertEqual(env['FINFLOW_TRAVERSAL_TARGET_ROOT'],'/e/runtime/appdata/finflow-traversal-targets');self.assertEqual(env['SENSITIVE_INFO_AGGREGATE_RESET_ENABLED'],'true')
 def test_limits_and_barrier(self):
  self.assertEqual(m.scenario_bounds('finflow-policy','plain'),(960,900,120));self.assertEqual(m.scenario_bounds('finflow-policy','adversarial'),(1200,1140,120))
  with self.assertRaises(ValueError):m.scenario_bounds('finflow-policy','unknown')
  events=[];pipe=SimpleNamespace(write=lambda b:events.append(b),flush=lambda:None,close=lambda:None);state={'parentPid':1,'manifestSha256':'a'*64}
  m.publish_child_start(SimpleNamespace(pid=2,stdin=pipe),state,lambda:events.append(dict(state)),'finflow-policy');self.assertEqual(events[0]['nativePid'],2);self.assertEqual(events[1],b'1')
 def receipt(self,cohort):
  phases=['normal']+(['ordinary_admin_request']if cohort=='adversarial'else[])+['plain_unauthorized_request'if cohort=='plain'else'adversarial_request','fixed_identical_input']
  q={'cohort':cohort,'controlsPassed':True,'qualification':'qualified','scenarios':[{'objectiveId':id,'calls':[{'phase':p}for p in phases],'controlsPassed':True,'positiveOutcome':'observed_bypass','qualification':'qualified',**({'ordinaryRequestDenied':True}if cohort=='adversarial'else{})}for id in ['admin_read_logs','admin_llm_logs']]}
  turns=6 if cohort=='plain'else 8;counts={'generate':turns,'chat':2,'tags':1,'version':0,'metadata':1,'external':turns+3,'incoming':turns+2};return {'status':'passed','cohort':cohort,'installedWrites':False,'actualModelProof':True,'cleanupFailures':[],'qualification':q,'counts':counts},{'version':'finflow-policy-wire-v1','model':m.POLICY_MODEL,'digest':m.POLICY_DIGEST,'closed':True,'physicalPending':0,'failures':[],'counts':counts,'calls':[{'kind':kind,'terminal':'returned'}for kind in ('generate','chat','tags','version')for _ in range(counts[kind])]}
 def test_technical_success_distinct_semantics(self):
  for cohort in ('plain','adversarial'):
   v,w=self.receipt(cohort);self.assertTrue(m.verify_finflow_policy_result(v,w,cohort));v['qualification']['qualification']='incomplete';r=v['qualification']['scenarios'][0];r['positiveOutcome']=r['qualification']='incomplete_refusal';self.assertTrue(m.verify_finflow_policy_result(v,w,cohort))
   for change in ['calls','controlsPassed','objectiveId','positiveOutcome']:
    bad=copy.deepcopy(v);bad['qualification']['scenarios'][0].pop(change)
    with self.assertRaises(RuntimeError):m.verify_finflow_policy_result(bad,w,cohort)
   bad=copy.deepcopy(v);bad['qualification']['qualification']='qualified'
   with self.assertRaises(RuntimeError):m.verify_finflow_policy_result(bad,w,cohort)
 def test_drain_model_and_budget_denials(self):
  v,w=self.receipt('plain')
  for k,val in [('closed',False),('physicalPending',1),('model','other'),('digest','0'*64),('failures',[{}])]:
   with self.assertRaises(RuntimeError):m.verify_finflow_policy_result(v,{**w,k:val},'plain')
  for k,val in [('installedWrites',True),('actualModelProof',False),('cleanupFailures',[{}])]:
   with self.assertRaises(RuntimeError):m.verify_finflow_policy_result({**v,k:val},w,'plain')
  bad=copy.deepcopy(v);bad['counts']['generate']=61;wire=copy.deepcopy(w);wire['counts']=bad['counts']
  with self.assertRaises(RuntimeError):m.verify_finflow_policy_result(bad,wire,'plain')
 def test_manifest_digest_denies_before_inventory(self):
  a=SimpleNamespace(package=str(HERE.parents[1]),main_workspace=True,manifest='/absent',manifest_sha256='a'*64)
  with patch.object(m,'digest',return_value='b'*64),patch.object(m,'inventory',side_effect=AssertionError('must not inventory')):
   with self.assertRaisesRegex(RuntimeError,'manifest hash'):m.validate_finflow0055_main(a)
if __name__=='__main__':
 import socket
 with patch('subprocess.run',side_effect=AssertionError('denied')),patch('subprocess.Popen',side_effect=AssertionError('denied')),patch.object(socket,'socket',side_effect=AssertionError('denied')):unittest.main()
