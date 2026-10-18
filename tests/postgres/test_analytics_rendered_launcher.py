import importlib.util,unittest,subprocess,tempfile,os,ast,hashlib,json,sys,io,contextlib
from pathlib import Path
from unittest.mock import patch
p=Path(__file__).with_name('run-analytics-rendered-isolated.py')
spec=importlib.util.spec_from_file_location('analytics_launcher',p);m=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('import command')),patch('tempfile.mkdtemp',side_effect=AssertionError('import mutation')):spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_merchant_count_answer_accepts_observed_scalar_and_rejects_wrong_answers(self):
  node='/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node'
  helper=p.parents[1]/'fixtures/secureshopAnalyticsRenderedBrowser.js'
  script="""const assert=require('node:assert/strict');const {answersObservedCount}=require(process.argv[1]);
for(const answer of ['256',' 256 ','There are 256 products.'])assert.equal(answersObservedCount(answer,'256','products'),true);
for(const answer of ['257','2','There are 257 products.','There are 1256 products.','256 unrelated items.','Unavailable',null])assert.equal(answersObservedCount(answer,'256','products'),false);
assert.equal(answersObservedCount('2','2','orders'),true);assert.equal(answersObservedCount('256','2','orders'),false);
"""
  result=subprocess.run([node,'-e',script,str(helper)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5,
   env={'PATH':'/usr/bin:/bin'})
  self.assertEqual(result.returncode,0,result.stderr)
 def test_merchant_history_valid_plan_never_allocates_or_contacts_docker(self):
  launcher=p.with_name('run-analytics-actual8b-isolated.py');tree=ast.parse(launcher.read_text())
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();build=root/'client/build';build.mkdir(parents=True);(build/'index.html').write_text('controlled build')
   browser=root/'browser';browser.mkdir();binary=browser/'controlled-executable';binary.write_text('controlled executable');binary.chmod(0o700)
   pin=hashlib.sha256(binary.read_bytes()).hexdigest()
   digest=hashlib.sha256(json.dumps({'index.html':hashlib.sha256(b'controlled build').hexdigest()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
   for node in tree.body:
    if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='SOURCE' for target in node.targets):
     node.value=ast.Call(func=ast.Name(id='Path',ctx=ast.Load()),args=[ast.Constant(str(root))],keywords=[])
   ast.fix_missing_locations(tree)
   argv=[str(launcher),'--docker-host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock','--merchant-history-browser','--main-source','--plan',
    '--node',str(binary),'--node-sha256',pin,'--browser',str(binary),'--browser-sha256',pin,'--browser-root',str(browser),
    '--build',str(build),'--build-sha256',digest,'--ollama-model-sha256','46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e']
   output=io.StringIO()
   def command(args,**kwargs):
    self.assertEqual(args,[str(binary),'--version']);return subprocess.CompletedProcess(args,0,'v26.10.0\n','')
   with (patch.object(sys,'argv',argv),patch.object(sys,'path',[str(p.parent),*sys.path]),patch('subprocess.run',side_effect=command),
    patch('tempfile.mkdtemp',side_effect=AssertionError('plan allocated')),contextlib.redirect_stdout(output)):
    with self.assertRaises(SystemExit) as stopped:exec(compile(tree,str(launcher),'exec'),{'__file__':str(launcher),'__name__':'controlled_plan'})
   self.assertEqual(stopped.exception.code,0);plan=json.loads(output.getvalue());self.assertFalse(plan['allocationStarted']);self.assertFalse(plan['sourceCopy'])
   self.assertEqual(plan['actorBudget'],[4,12]);self.assertEqual(plan['queryPosts'],2)
 def test_merchant_history_missing_pins_denied_before_allocation(self):
  launcher=p.with_name('run-analytics-actual8b-isolated.py')
  result=subprocess.run([sys.executable,str(launcher),'--docker-host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock',
   '--merchant-history-browser','--main-source','--plan'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5,
   env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
  self.assertNotEqual(result.returncode,0);self.assertIn('Pinned executable required',result.stderr)
 def test_merchant_history_directory_pin_is_ordered_and_detects_byte_changes(self):
  source=p.with_name('run-analytics-actual8b-isolated.py').read_text();tree=ast.parse(source)
  functions=ast.Module(body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ['tree_inventory','tree_digest']],type_ignores=[])
  scope={'Path':Path,'hashlib':hashlib,'json':json};exec(compile(functions,'controlled-analytics-pin-functions','exec'),scope)
  with tempfile.TemporaryDirectory() as temporary:
   directory=Path(temporary).resolve();(directory/'b').write_text('two');(directory/'a').write_text('one')
   expected={name:hashlib.sha256(text.encode()).hexdigest() for name,text in [('a','one'),('b','two')]}
   self.assertEqual(scope['tree_inventory'](directory),expected)
   pin=scope['tree_digest'](directory);(directory/'a').write_text('changed');self.assertNotEqual(scope['tree_digest'](directory),pin)
   (directory/'link').symlink_to(directory/'a')
   with self.assertRaises(ValueError):scope['tree_inventory'](directory)
 def test_merchant_history_plan_precedes_mutation_and_retains_original_cohort(self):
  source=p.with_name('run-analytics-actual8b-isolated.py').read_text()
  self.assertLess(source.index("'allocationStarted':False"),source.index('owner=uuid.uuid4()'))
  self.assertIn("workspace=SOURCE if args.main_source else root/'source'",source)
  self.assertIn('if not args.main_source:',source)
  self.assertIn("'v26.10.0' if browser_cohort else 'v26.9.0'",source)
  fixture=p.with_name('secureshopAnalyticsActual8b.integration.test.js').read_text()
  self.assertIn("assert.equal(evidence.counters.queries,standaloneDisclosure?4:2)",fixture)
  self.assertIn("assert.equal(evidence.counters.posts,standaloneDisclosure?5:2)",fixture)
  self.assertIn("evidence.counters.actor>=(standaloneDisclosure?7:4)",fixture)
  self.assertIn("STANDALONE_DISCLOSURE_CONTRACT_SHA256",source)
  self.assertNotIn('setObjectiveVisibility',fixture)
  browser=(p.parents[1]/'fixtures/secureshopAnalyticsRenderedBrowser.js').read_text()
  self.assertIn("older history selection must only GET its saved result",browser)
  self.assertIn('executionCounts(readCounters()),executionCounts(beforeReload)',browser)
  self.assertIn("async function qualifyAnalyticsBrowser(",browser)
 def test_standalone_disclosure_receipt_enforces_fixed_contrast_and_exact_counts(self):
  source=p.with_name('run-analytics-actual8b-isolated.py').read_text();tree=ast.parse(source)
  function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='validate_standalone_disclosure_receipt')
  scope={};exec(compile(ast.Module(body=[function],type_ignores=[]),'controlled-v20-receipt','exec'),scope)
  good={'counters':{'actor':7,'judge':1,'queries':4,'successfulQueries':4,'posts':5},'browser':{
   'disclosure':{'physicalSubmit':True,'rendered':True,'savedGetCount':2,'replayed':True},
   'fixedDisclosure':{'physicalModeSwitch':True,'physicalSubmit':True,'rendered':True,'status':'denied','noProtectedDisclosure':True,'noCredit':True,
    'callbackProof':{'denial':{'code':'42501','source':'postgresql','backendAbsent':True},'priorJudgmentsUnchanged':True,'completionUnchanged':True,'activeCreditUnchanged':True,
     'fixedJudgment':{'evaluationId':'evaluation-1','runId':'run-1','evidenceDigest':'a'*64,'mode':'fixed','verdict':'fail','disposition':'not_pass','errorCode':'REQUIRED_FACTS_NOT_SATISFIED','provider':None,'model':None}}}}}
  self.assertIs(scope['validate_standalone_disclosure_receipt'](good),good)
  for bad in ({**good,'counters':{**good['counters'],'posts':4}},
              {**good,'counters':{**good['counters'],'actor':15}},
              {**good,'browser':{**good['browser'],'fixedDisclosure':{**good['browser']['fixedDisclosure'],'status':'completed'}}},
              {**good,'browser':{**good['browser'],'fixedDisclosure':{**good['browser']['fixedDisclosure'],'callbackProof':{**good['browser']['fixedDisclosure']['callbackProof'],'denial':{'code':'42501','source':'postgresql','backendAbsent':False}}}}},
              {**good,'browser':{**good['browser'],'fixedDisclosure':{**good['browser']['fixedDisclosure'],'callbackProof':{**good['browser']['fixedDisclosure']['callbackProof'],'priorJudgmentsUnchanged':False}}}},
              {**good,'browser':{**good['browser'],'fixedDisclosure':{**good['browser']['fixedDisclosure'],'callbackProof':{**good['browser']['fixedDisclosure']['callbackProof'],'fixedJudgment':{**good['browser']['fixedDisclosure']['callbackProof']['fixedJudgment'],'provider':'ollama'}}}}},
              {**good,'browser':{**good['browser'],'fixedDisclosure':{**good['browser']['fixedDisclosure'],'callbackProof':{key:value for key,value in good['browser']['fixedDisclosure']['callbackProof'].items() if key!='fixedJudgment'}}}}):
   with self.assertRaises(RuntimeError):scope['validate_standalone_disclosure_receipt'](bad)
 def test_exited_build_leader_still_drains_descendant_before_retiring(self):
  from types import SimpleNamespace
  child=SimpleNamespace(pid=123,exitCode=0);rows=[f'124 123 {os.getuid()}'];groups=m.OwnedGroups(lambda:'\n'.join(rows));groups.add(child)
  self.assertEqual(groups.all_members(),[124])
  def stop(c,members,budget):
   self.assertEqual(members(budget),[124]);rows.clear();return True
  with patch.object(m,'stop_directive_child',side_effect=stop) as cleanup:groups.stop(child,m.CleanupBudget(1));groups.cleanup(m.CleanupBudget(1));self.assertEqual(cleanup.call_count,1)
  self.assertEqual(groups.all_members(),[])
 def test_missing_pins_deny(self):
  with self.assertRaises(SystemExit):m.arguments([])
 def test_browser_pin_denies_before_docker_or_mutation(self):
  from types import SimpleNamespace
  a=SimpleNamespace(manifest='/manifest',manifest_sha256='0'*64,node_sha256='0'*64,browser_executable='/missing/browser',browser_sha256='0'*64)
  with patch.object(m,'validate_runtime',return_value=(Path('/node'),Path('/donor'),Path('/cache'))),patch.object(m,'validate_package'),patch.object(m,'validate_docker_cli',side_effect=AssertionError('Docker reached')),patch('tempfile.mkdtemp',side_effect=AssertionError('mutation')):
   with self.assertRaises(ValueError):m.validate(a,Path('/source'))
 def test_runtime_denial_precedes_package(self):
  with patch.object(m,'validate_runtime',side_effect=ValueError('pin')),patch.object(m,'validate_package',side_effect=AssertionError('package reached')):
   with self.assertRaises(ValueError):m.validate(object(),Path('/source'))
 def test_exact_absence_only(self):
  for text in ['permission denied','Cannot connect to daemon','Error: No such container: foreign']:
   with self.assertRaises(RuntimeError):m.absent_response('container','owned',subprocess.CompletedProcess([],1,'',text))
  self.assertTrue(m.absent_response('container','owned',subprocess.CompletedProcess([],1,'','Error: No such container: owned')))
 def test_both_builds_native_loader(self):
  rows=m.build_commands(Path('/node'),Path('/owned/source'));self.assertEqual(len(rows),2)
  for _,args in rows:self.assertEqual(args[-2:],['--configLoader','native'])
 def test_spent_cleanup_not_reused_after_error(self):
  now=[0];b=m.CleanupBudget(2,clock=lambda:now[0])
  def fail():now[0]=3;raise ValueError('first')
  with self.assertRaises(ValueError):b.run(fail)
  with self.assertRaises(TimeoutError):b.run(lambda:self.fail('late cleanup ran'))
 def test_owned_readonly_directory_preparation_preserves_file(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve();donor=root/'donor';donor.mkdir();e=root/'evidence';e.mkdir(mode=0o700);copy=e/'source';copy.mkdir();file=copy/'a';file.write_text('retained');file.chmod(0o444);copy.chmod(0o555)
   m.prepare_owned_runtime_directories(donor,copy,e);self.assertEqual(file.stat().st_mode&0o777,0o444);self.assertEqual(file.read_text(),'retained');self.assertTrue(copy.stat().st_mode&0o200)
if __name__=='__main__':unittest.main()
