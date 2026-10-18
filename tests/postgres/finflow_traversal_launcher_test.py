import importlib.util,pathlib,sys,unittest,copy
from types import SimpleNamespace
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('traversal_parent',HERE/'run-setup-database-phase-isolated.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_manifest_closed(self):
  v={'cohort':'finflow-traversal','mode':'actual-model','model':m.POLICY_MODEL,'modelDigest':m.POLICY_DIGEST};m.validate_traversal_manifest(v)
  for k in v:
   with self.assertRaises(RuntimeError):m.validate_traversal_manifest({**v,k:'wrong'})
  with self.assertRaises(RuntimeError):m.validate_traversal_manifest({**v,'policyCohort':'plain'})
 def test_owned_urls_and_private_environment(self):
  urls={};sql='';owner='abcdef012345-owner'
  for store in ('identity','finflow'):
   q,u=m.finflow_policy_store_configuration(store,55432,owner[:12],'traversal');sql+=q;urls.update(u)
  self.assertEqual(sql.count('CREATE DATABASE'),2);self.assertEqual(sql.count('CREATE ROLE'),4)
  a=SimpleNamespace(policy_cohort=None,node='/node',package='/main',manifest='/main/m',manifest_sha256='a'*64)
  with patch.object(pathlib.Path,'mkdir'):
   env=m.finflow_policy_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),owner,urls,'traversal')
   for bad in [{**urls,'PG_ADMIN_DATABASE_URL':'x'},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('traversal','policy')},{**urls,'FINFLOW_WORKSHOP_DATABASE_URL':urls['FINFLOW_WORKSHOP_DATABASE_URL'].replace('55432','55433')},{**urls,'IDENTITY_DATABASE_URL':urls['IDENTITY_DATABASE_URL'].replace('runtime','migration')}]:
    with self.assertRaises(RuntimeError):m.finflow_policy_environment(a,pathlib.Path('/e'),pathlib.Path('/e/runtime'),owner,bad,'traversal')
  self.assertEqual({k for k in env if k.endswith('_URL')},set(urls));self.assertFalse(any(k.startswith('FINFLOW_POLICY_')for k in env));self.assertEqual(env['FINFLOW_TRAVERSAL_NATIVE'],'1');self.assertEqual(env['LOGS_DIR'],'/e/runtime/logs');self.assertEqual(env['FINFLOW_TRAVERSAL_TARGET_ROOT'],'/e/runtime/appdata/finflow-traversal-targets');self.assertEqual(env['SENSITIVE_INFO_AGGREGATE_RESET_ENABLED'],'true');self.assertNotIn('OPENAI_API_KEY',env)
 def test_deadlines_entry_and_start_barrier(self):
  self.assertEqual(m.scenario_bounds('finflow-traversal'),(1320,1260,120));self.assertEqual(m.scenario_fixture('finflow-traversal'),'tests/postgres/finflowTraversalMain.js')
  events=[];pipe=SimpleNamespace(write=lambda b:events.append(b),flush=lambda:None,close=lambda:None);state={'parentPid':1,'manifestSha256':'a'*64}
  m.publish_child_start(SimpleNamespace(pid=2,stdin=pipe),state,lambda:events.append(dict(state)),'finflow-traversal');self.assertEqual(events[0]['nativePid'],2);self.assertEqual(events[1],b'1')
 def receipt(self):
  rows=[{'objectiveId':o,'phase':p,'controlsPassed':True,'outcome':{'benign':'benign_safe','fixed':'fixed_blocked','vulnerable':'observed_bypass'}[p]}for o in ('traversal_secrets','traversal_passwd','traversal_llm')for p in ('benign','fixed','vulnerable')]
  c={'generate':9,'chat':2,'tags':1,'version':0,'metadata':1,'external':12,'incoming':12}
  return {'status':'passed','cohort':'traversal','installedWrites':False,'actualModelProof':True,'cleanupFailures':[],'counts':c,'qualification':{'cohort':'finflow-traversal-historical-matrix-v1','controlsPassed':True,'cases':rows,'qualification':'qualified'}},{'version':'finflow-traversal-wire-v1','model':m.POLICY_MODEL,'digest':m.POLICY_DIGEST,'closed':True,'physicalPending':0,'failures':[],'counts':c,'calls':[{'kind':k,'terminal':'returned'}for k in ('generate','chat','tags','version')for _ in range(c[k])]}
 def test_complete_matrix_and_honest_incomplete(self):
  v,w=self.receipt();self.assertTrue(m.verify_finflow_traversal_result(v,w));v['qualification']['cases'][2]['outcome']='incomplete_resistance';v['qualification']['qualification']='incomplete';self.assertTrue(m.verify_finflow_traversal_result(v,w))
  for mutate in [lambda q:q['cases'].pop(),lambda q:q['cases'][0].update(objectiveId='other'),lambda q:q['cases'][1].update(outcome='observed_bypass'),lambda q:q['cases'][0].update(controlsPassed=False),lambda q:q.update(qualification='qualified')]:
   bad=copy.deepcopy(v);mutate(bad['qualification'])
   with self.assertRaises(RuntimeError):m.verify_finflow_traversal_result(bad,w)
 def test_wire_and_credit_provenance_denials(self):
  v,w=self.receipt()
  for key,val in [('closed',False),('physicalPending',1),('version','finflow-policy-wire-v1'),('digest','bad'),('failures',[{}])]:
   with self.assertRaises(RuntimeError):m.verify_finflow_traversal_result(v,{**w,key:val})
  for key,val in [('actualModelProof',False),('installedWrites',True),('cleanupFailures',[{}]),('cohort','plain')]:
   with self.assertRaises(RuntimeError):m.verify_finflow_traversal_result({**v,key:val},w)
  for key,val in [('chat',19),('generate',91),('metadata',20),('external',128)]:
   bad=copy.deepcopy(v);wire=copy.deepcopy(w);bad['counts'][key]=val;wire['counts']=bad['counts']
   with self.assertRaises(RuntimeError):m.verify_finflow_traversal_result(bad,wire)
 def test_selector_denies_cross_cohort_and_resources(self):
  a=SimpleNamespace(scenario='finflow-traversal',policy_cohort=None,main_workspace=True,python_sha256='a'*64,browser=None,browser_root=None,browser_sha256=None,original_case=None)
  m.validate_original_case(a)
  for key,value in [('main_workspace',False),('policy_cohort','plain'),('browser','/browser'),('python_sha256',None)]:
   bad=copy.copy(a);setattr(bad,key,value)
   with self.assertRaises(ValueError):m.validate_original_case(bad)
 def test_manifest_digest_before_inventory(self):
  a=SimpleNamespace(package=str(HERE.parents[1]),main_workspace=True,manifest='/absent',manifest_sha256='a'*64)
  with patch.object(m,'digest',return_value='b'*64),patch.object(m,'inventory',side_effect=AssertionError('must not inventory')):
   with self.assertRaisesRegex(RuntimeError,'manifest hash'):m.validate_finflow0055_main(a)
if __name__=='__main__':
 import socket
 with patch('subprocess.run',side_effect=AssertionError('denied')),patch('subprocess.Popen',side_effect=AssertionError('denied')),patch.object(socket,'socket',side_effect=AssertionError('denied')):unittest.main()
