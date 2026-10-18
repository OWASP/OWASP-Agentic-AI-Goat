import hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

LAUNCHER=Path(__file__).with_name('run-finflow-backup-browser-main.py')
spec=importlib.util.spec_from_file_location('csrf_main_launcher',LAUNCHER)
m=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('No resources')),patch('subprocess.Popen',side_effect=AssertionError('No resources')),patch('tempfile.mkdtemp',side_effect=AssertionError('No allocation')):spec.loader.exec_module(m)

class ClosedCsrfMainProfile(unittest.TestCase):
 def args(self):return type('Args',(),{'profile':m.CSRF_PROFILE,'main_workspace':'/main','manifest':'/manifest','manifest_sha256':'a'*64,'input':'/fixed','input_sha256':m.CSRF_INDIRECT_INPUT_SHA256,'browser':'/browser','browser_sha256':'b'*64,'plan':True,'dpi_boot_preflight':False,'dpi_health_preflight':False,'dpi_tail_preflight':False})()
 def test_main_only_plan_is_sixteen_store_actual_with_fixed_18_call_cap(self):
  args=self.args()
  with patch.object(m,'parse_main',return_value=args),patch.object(m,'validate_main',return_value=(Path('/main'),{})),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):
   with patch('builtins.print')as emit:self.assertEqual(m.main_current([]),0)
  plan=json.loads(emit.call_args.args[0]);self.assertEqual(plan['cohort'],'csrf-indirect70b-main');self.assertEqual(plan['mode'],'actual');self.assertEqual(len(plan['stores']),16);self.assertEqual(plan['maxModelCalls'],18);self.assertEqual(plan['modelHttpTimeoutMs'],60000);self.assertFalse(plan['allocation'])
 def test_disposable_store_and_scrubbed_child_environment(self):
  args=self.args();sql,urls=m.store_configuration('csrf',54321,'a'*12,m.CSRF_PROFILE)
  self.assertEqual(set(urls),{'CSRF_WORKSHOP_DATABASE_URL','CSRF_WORKSHOP_MIGRATION_DATABASE_URL'});self.assertIn('/dvaia_test_csrf_browser_'+'a'*12+'_csrf',next(iter(urls.values())));self.assertIn('REVOKE CONNECT',sql)
  for label,_ in m.DPI_STORES:self.assertEqual(len(m.store_configuration(label,54321,'a'*12,m.CSRF_PROFILE)[1]),3 if label=='ctf' else 2)
  with patch.dict(os.environ,{'IDENTITY_DATABASE_URL':'installed','OPENAI_API_KEY':'private','NODE_OPTIONS':'unsafe'}):env=m.child_environment({'PATH':'/pinned'},Path('/evidence'),Path('/external/runtime'),'owner',args)
  self.assertEqual(env['CSRF_FULL_INDEX_MODE'],'actual-indirect-chain');self.assertEqual(env['CSRF_FULL_INDEX_70B'],'yes');self.assertEqual(env['CSRF_HTML_SUMMARY_TIMEOUT_MS'],'55000');self.assertEqual(env['CSRF_FULL_INDEX_SOURCE_ROOT'],'/main');self.assertEqual(env['CSRF_FULL_INDEX_RUNTIME_ROOT'],'/external/runtime');self.assertEqual(env['DVAIA_APP_DATA_ROOT'],'/external/runtime/appdata');self.assertEqual(env['OLLAMA_MODEL'],'llama3.3:70b')
  for key in ('IDENTITY_DATABASE_URL','OPENAI_API_KEY','NODE_OPTIONS'):self.assertNotIn(key,env)
 def test_api_only_cleanup_admission_rejects_browser_artifacts(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);state={'profile':m.CSRF_PROFILE,'evidenceRoot':str(root)}
   self.assertEqual(m.verify_browser_absence(root,state,[]),{'started':False,'browserScope':'API-only indirect chain','ownedChildGroupAbsent':True})
   (root/'browser-launch-intent.json').symlink_to(root/'missing')
   with self.assertRaisesRegex(RuntimeError,'Unexpected CSRF browser'):m.verify_browser_absence(root,state,[])
 def test_input_is_exact_existing_declared_cohort(self):
  args=self.args();root=Path('/main');args.input=str(root/m.CSRF_INDIRECT_INPUT)
  with patch.object(m.Path,'is_symlink',return_value=False),patch.object(m.Path,'resolve',return_value=root/m.CSRF_INDIRECT_INPUT),patch.object(m,'private_input_digest',return_value=m.CSRF_INDIRECT_INPUT_SHA256):
   m.validate_actual_input(args,root,{'sourcePins':{m.CSRF_INDIRECT_INPUT:m.CSRF_INDIRECT_INPUT_SHA256}})
   with self.assertRaises(RuntimeError):m.validate_actual_input(args,root,{'sourcePins':{}})
 def test_result_verifier_requires_fixed_six_cases_and_exact_complete_70b_wire(self):
  cases=['clean-Q1','off-topic','on-topic-first','same-query-replay','on-topic-second','defended-second-query']
  result={'mode':'actual-indirect-chain','controlledDisplayProjection':False,'actualModel':True,'actualHttpCalls':6,'indirect':{'status':'passed','technicalComplete':True,'acceptedObjectives':['csrf_i1','csrf_i2','csrf_i3'],'notAttemptedActorCases':[],'cases':[{'name':name}for name in cases]}}
  call={'model':'llama3.3:70b','status':200,'responseComplete':True,'responseCaptureTruncated':False,'endpoint':'/api/chat','request':'{"model":"llama3.3:70b"}','response':'{"done":true}'}
  for key in ('request','response'):call[key+'Sha256']=hashlib.sha256(call[key].encode()).hexdigest()
  wire={'modelDigest':m.CSRF_70B_MODEL_DIGEST,'calls':[call.copy()for _ in cases]}
  m.verify_csrf_actual_result(result,wire)
  for change in ({'modelDigest':'0'*64},{'calls':wire['calls'][:-1]}):
   with self.assertRaises(RuntimeError):m.verify_csrf_actual_result(result,{**wire,**change})
  for change in ({'responseComplete':False},{'model':'llama3.1:8b'},{'requestSha256':'0'*64},{'endpoint':'/api/version'}):
   with self.assertRaises(RuntimeError):m.verify_csrf_actual_result(result,{**wire,'calls':[{**call,**change},*wire['calls'][1:]]})
  with self.assertRaises(RuntimeError):m.verify_csrf_actual_result({**result,'indirect':{**result['indirect'],'cases':result['indirect']['cases'][:-1]}},wire)

if __name__=='__main__':unittest.main()
