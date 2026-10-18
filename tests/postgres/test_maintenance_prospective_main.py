import importlib.util
from pathlib import Path
import unittest
import tempfile
import os
from types import SimpleNamespace
from unittest.mock import patch
import json
path=Path(__file__).with_name('run-setup-database-phase-isolated.py')
spec=importlib.util.spec_from_file_location('setup_prospective_controls',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Prospective(unittest.TestCase):
 def test_recovery_manifest_is_derived_from_exact_pinned_active_admission(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);services=root/'server/services';services.mkdir(parents=True)
   admission=services/'applicationMaintenanceInprocessAdmission.js';admission.write_text("const CURRENT_MANIFEST=require('./applicationMaintenanceInprocessSources-v2.json');\n")
   selected=services/'applicationMaintenanceInprocessSources-v2.json';payload=root/'payload.js';payload.write_text('current')
   selected.write_text(json.dumps({'version':1,'profile':'canonical16-ctf-inprocess-v1','files':{'payload.js':module.digest(payload)},'recoveryFiles':['payload.js']}))
   pins={'server/services/applicationMaintenanceInprocessAdmission.js':module.digest(admission),'server/services/applicationMaintenanceInprocessSources-v2.json':module.digest(selected),'payload.js':module.digest(payload)}
   relative,value=module.active_maintenance_recovery_manifest(root,pins)
   self.assertEqual(relative,'server/services/applicationMaintenanceInprocessSources-v2.json');self.assertEqual(value['recoveryFiles'],['payload.js'])
   historical=services/'applicationMaintenanceInprocessSources-v1.json';historical.write_text(selected.read_text());pins['server/services/applicationMaintenanceInprocessSources-v1.json']=module.digest(historical)
   admission.write_text(admission.read_text()+"require('./applicationMaintenanceInprocessSources-v1.json');\n");pins['server/services/applicationMaintenanceInprocessAdmission.js']=module.digest(admission)
   with self.assertRaisesRegex(RuntimeError,'Exact active maintenance manifest required'):module.active_maintenance_recovery_manifest(root,pins)
   admission.write_text("const CURRENT_MANIFEST=require('./applicationMaintenanceInprocessSources-v2.json');\n");pins['server/services/applicationMaintenanceInprocessAdmission.js']=module.digest(admission)
   pins['payload.js']='0'*64
   with self.assertRaisesRegex(RuntimeError,'Recovery executable closure invalid'):module.active_maintenance_recovery_manifest(root,pins)
 def test_closed_main_selection_and_bounds(self):
  self.assertEqual(module.scenario_bounds('prospective-original'),(780,600,120))
  self.assertEqual(module.scenario_fixture('prospective-original'),'tests/postgres/applicationMaintenanceProspective.integration.test.js')
  self.assertEqual(module.scenario_bounds('prospective-recovery'),(900,780,120))
  self.assertEqual(module.scenario_fixture('prospective-recovery'),'tests/postgres/applicationMaintenanceRecovery.integration.test.js')
  for scenario in ('prospective-original','prospective-recovery'):
   for main in (False,True):
    args=SimpleNamespace(scenario=scenario,main_workspace=main,entry_case=None,original_case=None)
    if main:module.validate_original_case(args)
    else:
     with self.assertRaises(ValueError):module.validate_original_case(args)
 def test_legacy_cannot_use_main_selector(self):
  with self.assertRaises(ValueError):module.validate_original_case(SimpleNamespace(scenario='inprocess-original',main_workspace=True,entry_case=None,original_case='success'))
 def test_external_data_only_identity_and_cleanup(self):
  package=Path(__file__).resolve().parents[2]
  row=module.create_private_installation(package);root=Path(row['path'])
  try:
   self.assertNotIn(package,root.parents);self.assertEqual(list(root.iterdir()),[])
   self.assertEqual(root.stat().st_mode&0o777,0o700)
   (root/'private.json').write_text('synthetic')
   wrong={**row,'inode':row['inode']+1}
   with self.assertRaises(RuntimeError):module.remove_private_installation(wrong)
   self.assertTrue((root/'private.json').exists())
  finally:module.remove_private_installation(row)
  self.assertFalse(root.exists())
 def test_atomic_journal_keeps_prior_until_complete_replace(self):
  with tempfile.TemporaryDirectory() as directory:
   target=Path(directory)/'ownership.json'
   module.publish_ownership(target,{'owner':'first'})
   replace=module.os.replace;observed=[]
   def inspect(temporary,destination):
    observed.append(json.loads(target.read_text()))
    self.assertEqual(json.loads(Path(temporary).read_text()),{'owner':'second'})
    self.assertEqual(Path(temporary).stat().st_mode&0o777,0o600)
    replace(temporary,destination)
   with patch.object(module.os,'replace',side_effect=inspect):module.publish_ownership(target,{'owner':'second'})
   self.assertEqual(observed,[{'owner':'first'}]);self.assertEqual(json.loads(target.read_text()),{'owner':'second'})
   self.assertEqual(list(Path(directory).iterdir()),[target])
   with patch.object(module.os,'replace',side_effect=OSError('controlled')):
    with self.assertRaises(OSError):module.publish_ownership(target,{'owner':'third'})
   self.assertEqual(json.loads(target.read_text()),{'owner':'second'});self.assertEqual(list(Path(directory).iterdir()),[target])
 def test_reused_pid_birth_denies(self):
  with self.assertRaises(RuntimeError):module.validate_nested_birth(SimpleNamespace(returncode=0,stdout='different'), 'original')
if __name__=='__main__':unittest.main()
