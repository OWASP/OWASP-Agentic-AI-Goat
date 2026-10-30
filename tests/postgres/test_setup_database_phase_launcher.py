"""Resource-free rejection controls for the closed setup launcher."""
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
spec=importlib.util.spec_from_file_location('setup_phase_launcher',Path(__file__).with_name('run-setup-database-phase-isolated.py'))
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
class Admission(unittest.TestCase):
 def test_exact_plan_fixture_and_existing_scenarios(self):
  self.assertEqual(launcher.scenario_fixture('inspection-plan'),'tests/postgres/applicationMaintenanceInspectionPlan.integration.test.js')
  self.assertEqual(launcher.scenario_fixture('store-inspection'),'tests/postgres/applicationMaintenanceStoreInspection.integration.test.js')
  for scenario in ['fresh-success','additive-success']:self.assertEqual(launcher.scenario_fixture(scenario),'tests/postgres/setupDatabasePhase.integration.test.js')
  with self.assertRaises(KeyError):launcher.scenario_fixture('recovery')
 def test_only_success_cohorts_admitted(self):
  args=sum((["--"+key,"owned"] for key in ["package","manifest","manifest-sha256","node","node-sha256","docker","docker-sha256","docker-host","docker-daemon","image-id"]),[])
  for value in ["fresh-success","additive-success","store-inspection","inspection-plan"]:self.assertEqual(launcher.argument_parser().parse_args(args+["--scenario",value]).scenario,value)
  import contextlib,io
  for value in ["fresh","additive","signal","abrupt"]:
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):launcher.argument_parser().parse_args(args+["--scenario",value])
 def test_inventory_rejects_external_link(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)/'source';root.mkdir();(root/'escape').symlink_to(Path(directory))
   with self.assertRaisesRegex(RuntimeError,'escapes'):launcher.inventory(root)
 def test_reviewed_inventory_detects_source_mode_and_dependency_drift(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();package=root/'package';package.mkdir()
   for name in ['source','dependencies']:(package/name).mkdir();(package/name/'item').write_text('reviewed')
   node=root/'node';node.write_text('pinned');docker=root/'docker';docker.write_text('pinned-docker')
   manifest=root/'manifest.json';manifest.write_text(json.dumps({'cohort':'setup-database-phase','package':str(package),'inventories':{key:launcher.inventory(package/key) for key in ['source','dependencies']}}))
   args=SimpleNamespace(package=str(package),manifest=str(manifest),manifest_sha256=launcher.digest(manifest),node=str(node),node_sha256=launcher.digest(node),docker=str(docker),docker_sha256=launcher.digest(docker))
   self.assertEqual(launcher.validate(args),package)
   for name in ['source','dependencies']:
    target=package/name/'item';target.write_text('changed')
    with self.assertRaisesRegex(RuntimeError,'inventory'):launcher.validate(args)
    target.write_text('reviewed')
   target.chmod(0o700)
   with self.assertRaisesRegex(RuntimeError,'inventory'):launcher.validate(args)
 def test_pin_replacement_denied(self):
  # Hash comparison is exercised through the same admitted fixture above;
  # no executable or Docker invocation is needed to observe tampering.
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();package=root/'package';package.mkdir()
   for name in ['source','dependencies']:(package/name).mkdir()
   executable=root/'executable';executable.write_text('one');pin=launcher.digest(executable)
   manifest=root/'manifest';manifest.write_text(json.dumps({'cohort':'setup-database-phase','package':str(package),'inventories':{'source':{},'dependencies':{}}}))
   args=SimpleNamespace(package=str(package),manifest=str(manifest),manifest_sha256=launcher.digest(manifest),node=str(executable),node_sha256=pin,docker=str(executable),docker_sha256=pin)
   executable.write_text('two')
   with self.assertRaisesRegex(RuntimeError,'pin'):launcher.validate(args)
class CtfAdmission(unittest.TestCase):
 def test_closed_sequential_ctf_cases_and_bounds(self):
  for case in ('ctf-fresh','ctf-populated'):
   self.assertEqual(launcher.scenario_fixture(case),'tests/postgres/ctfSetupApplication.integration.test.js')
   self.assertEqual(launcher.scenario_bounds(case),(2100,1800,180) if case=='ctf-populated' else (1800,1680,120))
  self.assertEqual(launcher.scenario_bounds('fresh-success'),(780,780,120))
  with self.assertRaises(KeyError):launcher.scenario_bounds('ctf-all')
 def test_cleanup_timeout_cannot_leave_later_operation_unbounded(self):
  import time
  deadline=time.monotonic()+.04
  with self.assertRaises(TimeoutError):launcher.within_cleanup(deadline,lambda:time.sleep(1))
  called=[]
  with self.assertRaises(TimeoutError):launcher.within_cleanup(deadline,lambda:called.append(True))
  self.assertEqual(called,[])
 def test_hung_process_stage_preserves_time_for_container_cleanup(self):
  import time
  deadline=time.monotonic()+1
  with self.assertRaises(TimeoutError):launcher.within_cleanup(deadline,lambda:time.sleep(1),.01)
  self.assertEqual(launcher.within_cleanup(deadline,lambda:'exact container cleanup'),'exact container cleanup')
 def test_failure_does_not_disable_next_independent_cleanup(self):
  import time
  deadline=time.monotonic()+1
  with self.assertRaises(ValueError):launcher.within_cleanup(deadline,lambda:(_ for _ in ()).throw(ValueError('controlled')))
  self.assertEqual(launcher.within_cleanup(deadline,lambda:'done'),'done')

class CleanupContract(unittest.TestCase):
 def test_actual_cleanup_contract_checks_daemon_removes_exact_id_and_verifies_absence(self):
  identifier='a'*64;image='sha256:'+'b'*64;name='owned-setup-fixture';labels={'owner':'fixture'};calls=[];removed=False
  def command(argv):
   nonlocal removed
   calls.append(argv)
   if argv[0]=='info':return SimpleNamespace(returncode=0,stdout='reviewed-daemon\n',stderr='')
   if argv[0]=='inspect':
    if removed:return SimpleNamespace(returncode=1,stdout='',stderr=f'Error: No such object: {name}\n')
    return SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':identifier,'Name':'/'+name,'Image':image,'Config':{'Labels':labels}}]),stderr='')
   if argv[0]=='rm':
    self.assertEqual(argv[-1],identifier);removed=True;return SimpleNamespace(returncode=0,stdout='',stderr='')
   self.fail('Unexpected Docker operation')
  result=launcher.cleanup_phase_container(command,SimpleNamespace(docker_daemon='reviewed-daemon',image_id=image),name,labels,identifier)
  self.assertEqual(result,{'status':'removed_absence_verified','containerId':identifier})
  self.assertEqual(sum(row[0]=='inspect' for row in calls),2)
 def test_daemon_mismatch_never_inspects_or_removes(self):
  calls=[]
  def command(argv):calls.append(argv);return SimpleNamespace(returncode=0,stdout='foreign-daemon',stderr='')
  with self.assertRaisesRegex(RuntimeError,'daemon identity mismatch'):
   launcher.cleanup_phase_container(command,SimpleNamespace(docker_daemon='reviewed-daemon',image_id='sha256:'+'b'*64),'owned',{'owner':'fixture'},'a'*64)
  self.assertEqual(len(calls),1)
class JournalEntryAdmission(unittest.TestCase):
 def test_closed_entry_cases_and_bounds(self):
  self.assertEqual(launcher.scenario_fixture('journal-bound-entry'),'tests/postgres/applicationJournalBoundEntry.integration.test.js')
  self.assertEqual(launcher.scenario_bounds('journal-bound-entry'),(780,600,120))
  for case in ['success','v1','startup','interrupted']:
   launcher.validate_original_case(SimpleNamespace(scenario='journal-bound-entry',entry_case=case,original_case=None))
  for scenario,case in [('journal-bound-entry',None),('fresh-success','success'),('journal-bound-entry','unknown')]:
   with self.assertRaises(ValueError):launcher.validate_original_case(SimpleNamespace(scenario=scenario,entry_case=case,original_case=None))
class NestedBirthAdmission(unittest.TestCase):
 def test_unknown_or_reused_birth_is_never_admitted_for_signal(self):
  for code,text in [(1,''),(1,'same'),(0,''),(0,'   '),(0,'different')]:
   with self.assertRaisesRegex(RuntimeError,'no signal'):launcher.validate_nested_birth(SimpleNamespace(returncode=code,stdout=text),'same')
  launcher.validate_nested_birth(SimpleNamespace(returncode=0,stdout=' same\n'),'same')
class FreshInterruption(unittest.TestCase):
 def arguments(self,case='signal'):
  base=sum((["--"+key,"owned"] for key in ["package","manifest","manifest-sha256","node","node-sha256","docker","docker-sha256","docker-host","docker-daemon","image-id"]),[])
  return launcher.argument_parser().parse_args(base+['--scenario','fresh-interruption','--main-workspace','--interruption-case',case])
 def test_closed_cases(self):
  for case in ('runner-failure','signal','disconnect','abrupt'):
   args=self.arguments(case);launcher.validate_original_case(args)
   self.assertEqual(launcher.scenario_fixture(args.scenario),'tests/postgres/setupDatabasePhase.integration.test.js')
   self.assertEqual(launcher.scenario_bounds(args.scenario),(780,780,120))
  args=self.arguments();args.main_workspace=False
  with self.assertRaises(ValueError):launcher.validate_original_case(args)
  args=self.arguments();args.interruption_case=None
  with self.assertRaises(ValueError):launcher.validate_original_case(args)
  args=self.arguments();args.scenario='fresh-success';args.main_workspace=False
  with self.assertRaises(ValueError):launcher.validate_original_case(args)
 def test_exact_result(self):
  value={'passed':True,'actualModel':False,'privatePhaseDispatch':True,'sourceRoot':'/main','installationRoot':'/private/installation','controlledProcessBarriers':['signal'],'productionPhases':['fresh','populated-upgrade','no-op'],'cleanEntryBoundary':True,'cleanup':{'declaredGroupsAbsent':True,'ownedDirectChildrenAbsent':True,'databaseClientsClosed':True}}
  self.assertTrue(launcher.verify_interruption_result(value,'signal','/main','/private/installation'))
  for key,bad in [('controlledProcessBarriers',[]),('controlledProcessBarriers',['signal','abrupt']),('privatePhaseDispatch',False),('sourceRoot','/other'),('actualModel',True),('cleanup',{})]:
   with self.assertRaises(RuntimeError):launcher.verify_interruption_result({**value,key:bad},'signal','/main','/private/installation')
 def test_manifest_rejects_scope_case_missing_pin_and_never_reads_main_env(self):
  from unittest.mock import patch
  root=Path(__file__).resolve().parents[2];args=self.arguments();args.package=str(root)
  required={'package.json','package-lock.json','tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/setupDatabasePhase.integration.test.js','tests/fixtures/setupDatabasePhaseProcess.cjs','tests/fixtures/setupPrivatePhaseDispatch.js','tests/fixtures/setupPhaseInterruptionSelection.js','tests/fixtures/fullBackendBootControls.js','tests/fixtures/setupDatabasePhaseLeaseBarrier.js'}
  required.update(p.relative_to(root).as_posix() for directory in ('scripts','server','db') for p in (root/directory).rglob('*') if p.is_file() and p.suffix in ('.js','.cjs','.json','.sql'))
  required.update('tests/postgres/'+n for n in ('sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'))
  base={'cohort':'fresh-interruption','case':'signal','workspace':str(root),'actualModel':False,'sourcePins':dict.fromkeys(required,'pin'),'dependencyInventory':{}}
  touched=[]
  def digest(file):
   self.assertNotEqual(Path(file),root/'.env','main .env must never be read')
   touched.append(Path(file));return 'pin'
  with tempfile.TemporaryDirectory() as directory:
   manifest=Path(directory)/'manifest.json';args.manifest=str(manifest);args.manifest_sha256='pin'
   with patch.object(launcher,'digest',side_effect=digest),patch.object(launcher,'inventory',return_value={}):
    for change in ({'cohort':'other'},{'case':'abrupt'},{'sourcePins':{k:v for k,v in base['sourcePins'].items()if k!='package-lock.json'}},{'sourcePins':{**base['sourcePins'],'.env':'pin'}}):
     manifest.write_text(json.dumps({**base,**change}))
     with self.assertRaises(RuntimeError):launcher.validate_interruption_main(args)
  self.assertNotIn(root/'.env',touched)
 def test_external_evidence(self):
  import shutil
  root=Path(__file__).resolve().parents[2];evidence=launcher.prospective_evidence(root,'fresh-interruption')
  try:
   self.assertFalse(evidence.is_relative_to(root));self.assertTrue(evidence.name.startswith('owasp-ai-goat-setup-phase-'));self.assertEqual(evidence.stat().st_mode&0o777,0o700)
  finally:shutil.rmtree(evidence)
if __name__=='__main__':unittest.main()
