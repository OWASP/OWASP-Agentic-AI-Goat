import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location('fence_launcher',Path(__file__).with_name('run-application-maintenance-fence-isolated.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FenceLauncher(unittest.TestCase):
 def test_main_workspace_pins_and_scope(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();files=['tests/postgres/applicationMaintenanceV4.integration.test.js','tests/postgres/run-application-maintenance-fence-isolated.py','server/database/postgres/applicationMaintenanceControl.js','server/services/applicationMaintenanceLease.js','db/postgres/maintenance-migrations/0001.sql']
   for name in files:
    f=root/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('controlled')
   (root/'node_modules').mkdir();exe=root/'node';exe.write_text('executable pin');manifest=root/'manifest.json'
   document={'cohort':'application-maintenance-v4-main','workspace':str(root),'sourcePins':{n:m.digest(root/n) for n in files},'dependencyInventory':m.inventory(root/'node_modules')};manifest.write_text(json.dumps(document))
   a=SimpleNamespace(main_workspace=True,application_maintenance_v4=True,package=str(root),manifest=str(manifest),manifest_sha256=m.digest(manifest),node=str(exe),node_sha256=m.digest(exe),docker=str(exe),docker_sha256=m.digest(exe))
   with patch.object(m,'__file__',str(root/'tests/postgres/run-application-maintenance-fence-isolated.py')):
    self.assertEqual(m.validate(a),root)
    (root/files[0]).write_text('changed')
    with self.assertRaisesRegex(RuntimeError,'source pin'):m.validate(a)
    (root/files[0]).write_text('controlled');(root/'node_modules/new').write_text('drift')
    with self.assertRaisesRegex(RuntimeError,'dependencies'):m.validate(a)
    a.application_maintenance_v4=False
    with self.assertRaisesRegex(RuntimeError,'Main v4'):m.validate(a)
 def test_main_evidence_is_private_child_and_rejects_link(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();(root/'tasks').mkdir();e=m.main_evidence(root);self.assertEqual(e.parent,root/'tasks/maintenance-v4-native-evidence');self.assertEqual(e.stat().st_mode&0o777,0o700)
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();(root/'tasks').mkdir();(root/'tasks/maintenance-v4-native-evidence').symlink_to(root)
   with self.assertRaisesRegex(RuntimeError,'escape'):m.main_evidence(root)
 def test_closed_environment(self):
  env=m.database_environment('abcdef012345',54321)
  self.assertEqual(len(env),22)
  self.assertEqual(len({v.split('/')[-1] for v in env.values()}),11)
  self.assertTrue(all('@127.0.0.1:54321/dvaia_test_fence_' in v for v in env.values()))
  for owner,port in [('bad',5432),('abcdef012345',0),('abcdef012345','x')]:
   with self.assertRaises(ValueError):m.database_environment(owner,port)
 def test_inventory_rejects_external_link(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'escape').symlink_to('/tmp')
   with self.assertRaisesRegex(RuntimeError,'escapes'):m.inventory(p)
 def test_full_inventory_and_pins(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve();(p/'source').mkdir();(p/'dependencies').mkdir();f=p/'source'/'test.js';f.write_text('original');exe=p/'node';exe.write_text('pin')
   manifest=p/'manifest.json';manifest.write_text(json.dumps({'cohort':'application-maintenance-fence','package':str(p),'inventories':{k:m.inventory(p/k) for k in ['source','dependencies']}}))
   args=SimpleNamespace(package=str(p),manifest=str(manifest),manifest_sha256=m.digest(manifest),node=str(exe),node_sha256=m.digest(exe),docker=str(exe),docker_sha256=m.digest(exe))
   self.assertEqual(m.validate(args),p)
   f.write_text('changed')
   with self.assertRaisesRegex(RuntimeError,'inventory'):m.validate(args)
   f.write_text('original');exe.write_text('replacement')
   with self.assertRaisesRegex(RuntimeError,'pin'):m.validate(args)
 def test_v2_exact_four_databases_and_private_gates(self):
  env=m.database_environment('abcdef012345',54321,True)
  self.assertEqual(len(env),8)
  self.assertEqual(len({v.split('/')[-1] for v in env.values()}),4)
  self.assertTrue(all(k.startswith('PG_MAINTENANCE_V2_') for k in env))
  self.assertTrue(all('@127.0.0.1:54321/dvaia_test_maintenance_v2_' in v for v in env.values()))
  self.assertTrue(all(len(v.split('/')[-1].encode())<=63 for v in env.values()))
  self.assertEqual(m.selection(True)['gate'],'APPLICATION_MAINTENANCE_V2_ISOLATED')
  self.assertNotEqual(m.selection(True)['fixture'],m.selection(False)['fixture'])
  with self.assertRaises(ValueError):m.selection('true')
 def test_selectors_are_exclusive_before_resource_creation(self):
  import contextlib,io
  base=sum((["--"+k,'owned'] for k in ['package','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']),[])
  for extra in [[],['--application-maintenance-fence','--application-maintenance-v2']]:
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):m.argument_parser().parse_args(base+extra)
  a=m.argument_parser().parse_args(base+['--application-maintenance-v2']);self.assertTrue(a.application_maintenance_v2);self.assertFalse(a.application_maintenance_fence)
 def test_v2_manifest_cannot_launch_legacy_cohort(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve();(p/'source').mkdir();(p/'dependencies').mkdir();exe=p/'node';exe.write_text('pin')
   manifest=p/'manifest.json';manifest.write_text(json.dumps({'cohort':'application-maintenance-v2','package':str(p),'inventories':{k:m.inventory(p/k) for k in ['source','dependencies']}}))
   args=SimpleNamespace(package=str(p),manifest=str(manifest),manifest_sha256=m.digest(manifest),node=str(exe),node_sha256=m.digest(exe),docker=str(exe),docker_sha256=m.digest(exe),application_maintenance_v2=True)
   self.assertEqual(m.validate(args),p)
   args.application_maintenance_v2=False
   with self.assertRaisesRegex(RuntimeError,'cohort'):m.validate(args)
 def test_v3_closed_three_control_stores_and_unchanged_prior_modes(self):
  env=m.database_environment('abcdef012345',54321,False,True)
  self.assertEqual(len(env),6)
  self.assertTrue(all(k.startswith('PG_MAINTENANCE_V3_') for k in env))
  self.assertEqual(len({v.split('/')[-1] for v in env.values()}),3)
  self.assertEqual(m.selection(False,True)['fixture'],'tests/postgres/applicationMaintenanceV3.integration.test.js')
  self.assertEqual(m.selection(True)['cases'],m.V2_CASES)
  self.assertEqual(m.selection(False)['cases'],m.CASES)
  with self.assertRaises(ValueError):m.selection(True,True)
  with self.assertRaises(ValueError):m.selection(False,'true')
 def test_v3_cannot_combine_with_another_selector(self):
  import contextlib,io
  base=sum((["--"+k,'owned'] for k in ['package','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']),[])
  for other in ['--application-maintenance-fence','--application-maintenance-v2']:
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):m.argument_parser().parse_args(base+['--application-maintenance-v3',other])
  self.assertTrue(m.argument_parser().parse_args(base+['--application-maintenance-v3']).application_maintenance_v3)
 def test_v4_exact_three_and_exclusive_admission(self):
  import contextlib,io
  env=m.database_environment('abcdef012345',54321,False,False,True)
  self.assertEqual(len(env),6)
  self.assertEqual(m.selection(False,False,True)['cases'],('fresh','populated','concurrency'))
  self.assertTrue(all(k.startswith('PG_MAINTENANCE_V4_') and '@127.0.0.1:54321/dvaia_test_maintenance_v4_abcdef012345_' in v for k,v in env.items()))
  self.assertTrue(all(len(v.split('/')[-1])<=63 for v in env.values()))
  for args in [(True,False,True),(False,True,True),(False,False,'true')]:
   with self.assertRaises(ValueError):m.selection(*args)
  base=sum((["--"+k,'owned'] for k in ['package','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']),[])
  for other in ['--application-maintenance-fence','--application-maintenance-v2','--application-maintenance-v3']:
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):m.argument_parser().parse_args(base+['--application-maintenance-v4',other])
  self.assertTrue(m.argument_parser().parse_args(base+['--application-maintenance-v4']).application_maintenance_v4)
 def test_v4_manifest_does_not_admit_v3(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve();(p/'source').mkdir();(p/'dependencies').mkdir();exe=p/'node';exe.write_text('pin')
   manifest=p/'manifest.json';manifest.write_text(json.dumps({'cohort':'application-maintenance-v4','package':str(p),'inventories':{k:m.inventory(p/k) for k in ['source','dependencies']}}))
   args=SimpleNamespace(package=str(p),manifest=str(manifest),manifest_sha256=m.digest(manifest),node=str(exe),node_sha256=m.digest(exe),docker=str(exe),docker_sha256=m.digest(exe),application_maintenance_v4=True)
   self.assertEqual(m.validate(args),p)
   args.application_maintenance_v4=False;args.application_maintenance_v3=True
   with self.assertRaisesRegex(RuntimeError,'cohort'):m.validate(args)
 def test_v4_cleanup_deadline_is_not_renewed_after_caught_failure(self):
  from unittest.mock import patch
  clock=[1.0];called=[]
  def failing():
   called.append('physical');clock[0]=121.0;raise TimeoutError('physical')
  with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),patch.object(m.signal,'setitimer') as timer:
   with self.assertRaises(TimeoutError):m.bounded_cleanup_step(120.0,failing)
   with self.assertRaises(TimeoutError):m.bounded_cleanup_step(120.0,lambda:called.append('integrity'))
   self.assertEqual(called,['physical']);self.assertEqual(timer.call_args_list[0].args,(m.signal.ITIMER_REAL,119.0))
   self.assertEqual(timer.call_args_list[-1].args,(m.signal.ITIMER_REAL,0))
 def test_v4_cleanup_uses_remaining_budget_and_rejects_late_success(self):
  from unittest.mock import patch
  clock=[20.0]
  with patch.object(m.time,'monotonic',side_effect=lambda:clock[0]),patch.object(m.signal,'setitimer') as timer:
   self.assertEqual(m.bounded_cleanup_step(120.0,lambda:'done'),'done')
   clock[0]=110.0
   def late():clock[0]=121.0;return 'late'
   with self.assertRaises(TimeoutError):m.bounded_cleanup_step(120.0,late)
   self.assertEqual([c.args[1] for c in timer.call_args_list],[100.0,0,10.0,0])
if __name__=='__main__':unittest.main()
