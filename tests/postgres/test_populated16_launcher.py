import importlib.util,os,json,tempfile,unittest,subprocess,socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('populated_launcher',Path(__file__).with_name('run-setup-database-phase-isolated.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ROOT=Path(__file__).resolve().parents[2]
class Populated(unittest.TestCase):
 def test_populated_source_closure_requires_loaded_network_guard(self):
  required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/applicationMaintenanceProspective.integration.test.js','tests/fixtures/applicationMaintenanceProspectiveProcess.cjs','server/services/applicationMaintenanceInprocessSources.json',
   'tests/postgres/sql_nosql_docker_ownership.py','tests/postgres/sql_nosql_process_ownership.py','tests/postgres/ctf_setup_sidecars.py',
   'tests/release-inputs/populated16-rehearsal.cjs','tests/release-inputs/populated16-upgrade-child.cjs','tests/release-inputs/populated16-network-guard.cjs'}
  required.update(json.loads((ROOT/'server/services/applicationMaintenanceInprocessSources.json').read_text())['files'])
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   p=Path(d)/'manifest.json';pins={name:'a'*64 for name in required}
   manifest={'cohort':'restored-populated-upgrade','workspace':str(ROOT),'sourcePins':pins,'dependencyInventory':{},'mainEnvSha256':'a'*64}
   args=SimpleNamespace(scenario='restored-populated-upgrade',package=str(ROOT),manifest=str(p),manifest_sha256='a'*64,auth_profile=None,node='/controlled/node',node_sha256='a'*64,docker='/controlled/docker',docker_sha256='a'*64)
   with patch.object(m,'digest',return_value='a'*64),patch.object(m,'inventory',return_value={}),patch.object(m,'admit_rehearsal_request'):
    p.write_text(json.dumps(manifest));self.assertEqual(m.validate_prospective_main(args),ROOT)
    del pins['tests/release-inputs/populated16-network-guard.cjs'];p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'source closure incomplete'):m.validate_prospective_main(args)
 def test_closed_selector_request_and_bounds(self):
  a=SimpleNamespace(scenario='restored-populated-upgrade',main_workspace=True,entry_case=None,original_case=None,rehearsal_request='/private/request',rehearsal_request_sha256='a'*64,node='/node')
  m.validate_original_case(a);self.assertEqual(m.scenario_bounds(a.scenario),(1800,1740,120));self.assertEqual(m.scenario_command(a),['/node','tests/release-inputs/populated16-rehearsal.cjs']);a.main_workspace=False
  with self.assertRaises(ValueError):m.validate_original_case(a)
 def test_private_request_exact_binding(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   p=Path(d)/'request';p.write_text('{}');p.chmod(0o600);a=SimpleNamespace(rehearsal_request=str(p),rehearsal_request_sha256=m.digest(p));manifest={'rehearsalRequest':{'path':str(p),'sha256':m.digest(p)}};self.assertEqual(m.admit_rehearsal_request(a,manifest),p);p.write_text('{"changed":true}')
   with self.assertRaises(RuntimeError):m.admit_rehearsal_request(a,manifest)
 def test_owned_home_and_no_disabled_features_override(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   root=Path(d);st=root.stat();row={'path':d,'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid};a=SimpleNamespace(rehearsal_request='/request',rehearsal_request_sha256='a'*64,docker='/pinned/docker',docker_host='unix:///owned/daemon')
   env=m.rehearsal_environment({'MCP_SIDECARS_AUTOSTART':'false','DVAIA_ISOLATED_TEST_WORKSPACE':'main','PG_TEST_DISPOSABLE':'yes'},row,a);self.assertEqual(env['DOCKER_HOST'],'unix:///owned/daemon');self.assertTrue(env['PATH'].startswith('/pinned:'));self.assertNotIn('MCP_SIDECARS_AUTOSTART',env);self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE',env);self.assertEqual(env['HOME'],str(root/'home'));self.assertEqual((root/'home').stat().st_mode&0o777,0o700)
 def test_success_requires_explicit_16store_result(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   p=Path(d)/'result.json';row={'status':'passed','restoredStores':16,'sourceRoot':str(ROOT),'installedWrites':False};p.write_text(json.dumps(row));p.chmod(0o600);m.verify_rehearsal_result(Path(d),ROOT)
   row['installedWrites']=True;p.write_text(json.dumps(row))
   with self.assertRaises(RuntimeError):m.verify_rehearsal_result(Path(d),ROOT)
 def test_retained_ownership_is_a_distinct_main_only_selector(self):
  a=SimpleNamespace(scenario='retained-ownership-migrations',main_workspace=True,entry_case=None,original_case=None,rehearsal_request='/private/request',rehearsal_request_sha256='a'*64,node='/node')
  m.validate_original_case(a)
  self.assertEqual(m.scenario_bounds(a.scenario),(1800,1740,120))
  self.assertEqual(m.scenario_command(a),['/node','tests/release-inputs/populated16-retained-ownership.cjs'])
  a.main_workspace=False
  with self.assertRaises(ValueError):m.validate_original_case(a)
  a.main_workspace=True;a.rehearsal_request=None
  with self.assertRaises(ValueError):m.validate_original_case(a)
 def test_retained_ownership_requires_its_child_and_active_admission_pin(self):
  required={'tests/postgres/run-setup-database-phase-isolated.py','tests/postgres/applicationMaintenanceProspective.integration.test.js','tests/fixtures/applicationMaintenanceProspectiveProcess.cjs','server/services/applicationMaintenanceInprocessSources.json','server/services/applicationMaintenanceInprocessSources-v88.json','tests/release-inputs/populated16-rehearsal.cjs','tests/release-inputs/populated16-upgrade-child.cjs','tests/release-inputs/populated16-network-guard.cjs','tests/release-inputs/populated16-retained-ownership.cjs','tests/release-inputs/populated16-retained-ownership-initialize-child.cjs'}
  required.update('tests/postgres/'+n for n in ['sql_nosql_docker_ownership.py','sql_nosql_process_ownership.py','ctf_setup_sidecars.py'])
  required.update(json.loads((ROOT/'server/services/applicationMaintenanceInprocessSources.json').read_text())['files'])
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   p=Path(d)/'manifest.json';pins={name:'a'*64 for name in required}
   manifest={'cohort':'retained-ownership-migrations','workspace':str(ROOT),'sourcePins':pins,'dependencyInventory':{},'mainEnvSha256':'a'*64}
   a=SimpleNamespace(scenario='retained-ownership-migrations',package=str(ROOT),manifest=str(p),manifest_sha256='a'*64,auth_profile=None,node='/controlled/node',node_sha256='a'*64,docker='/controlled/docker',docker_sha256='a'*64)
   with patch.object(m,'digest',return_value='a'*64),patch.object(m,'inventory',return_value={}),patch.object(m,'admit_rehearsal_request'),patch.object(m,'active_maintenance_recovery_manifest',return_value=('server/services/applicationMaintenanceInprocessSources-v88.json',{'files':{'server/services/applicationMaintenanceInprocessSources.json':'a'*64}})):
    p.write_text(json.dumps(manifest));self.assertEqual(m.validate_prospective_main(a),ROOT)
    del pins['tests/release-inputs/populated16-retained-ownership-initialize-child.cjs'];p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'source closure incomplete'):m.validate_prospective_main(a)
    pins['tests/release-inputs/populated16-retained-ownership-initialize-child.cjs']='a'*64
    del pins['tests/release-inputs/populated16-retained-ownership.cjs'];p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'source closure incomplete'):m.validate_prospective_main(a)
    pins['tests/release-inputs/populated16-retained-ownership.cjs']='a'*64;del pins['server/services/applicationMaintenanceInprocessSources-v88.json'];p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'source closure incomplete'):m.validate_prospective_main(a)
    pins['server/services/applicationMaintenanceInprocessSources-v88.json']='a'*64;manifest['cohort']='restored-populated-upgrade';p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'cohort'):m.validate_prospective_main(a)
    manifest['cohort']='retained-ownership-migrations';pins['server/services/applicationMaintenanceInprocessSources.json']='b'*64;p.write_text(json.dumps(manifest))
    with self.assertRaisesRegex(RuntimeError,'Active maintenance source closure incomplete'):m.validate_prospective_main(a)
 def test_retained_ownership_receipt_cannot_claim_full_setup(self):
  valid={'status':'passed','scope':'retained-ownership-migrations-v1','restoredStores':16,'canonicalLeaseRuns':2,'retainedPlatformTargets':1,'allStoresPreserved':True,'collisionChecksPassed':True,'noAutomaticLinking':True,'noPrivilegedSurrogate':True,'fullSetupProven':False,'installedWrites':False}
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   p=Path(d)/'result.json'
   def check(value):p.write_text(json.dumps(value));p.chmod(0o600);return m.verify_retained_ownership_result(Path(d))
   self.assertEqual(check(valid),valid)
   for altered in ({**valid,'fullSetupProven':True},{**valid,'retainedPlatformTargets':0},{**valid,'collisionChecksPassed':False},{**valid,'canonicalLeaseRuns':1},{**valid,'restoredStores':True},{**valid,'scope':'restored-populated-upgrade'},{**valid,'extraClaim':True}):
    with self.assertRaises(RuntimeError):check(altered)
if __name__=='__main__':
 with patch.object(subprocess,'Popen',side_effect=AssertionError('process denied')),patch.object(socket,'socket',side_effect=AssertionError('socket denied')):unittest.main()
