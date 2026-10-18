import unittest
from application_capacity_contract import validate_capacity,BOUNDS
class CapacityAdmission(unittest.TestCase):
 def test_closed_combinations(self):
  for key in ('rendered','mcp','secureshop','model_digest'):
   with self.subTest(key=key),self.assertRaises(ValueError):validate_capacity(True,**{key:True})
 def test_existing_mode_is_untouched(self):self.assertIsNone(validate_capacity(False,rendered=True,mcp=True))
 def test_declared_limits_and_copy(self):
  value=validate_capacity(True);self.assertEqual(value['students'],200);self.assertEqual(value['postgresMiB'],512);self.assertEqual(value['maxConnections'],96)
  self.assertLess(value['childSeconds'],value['workSeconds']);self.assertEqual(value['cleanupSeconds'],120);value['students']=1;self.assertEqual(BOUNDS['students'],200)
 def test_real_launcher_rejects_before_package_or_resource_admission(self):
  import importlib.util,sys
  from pathlib import Path
  from unittest.mock import patch
  spec=importlib.util.spec_from_file_location('capacity_launcher',Path(__file__).with_name('run-full-backend-auth-isolated.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  args=['launcher','--capacity-200','--rendered']
  for key in ['docker-host','docker-daemon-id','postgres-image-id','package','manifest','manifest-sha256','node','node-sha256','evidence-root']:args.extend(['--'+key,'controlled'])
  with patch.object(sys,'argv',args),patch.object(module,'validate_package') as package,patch.object(module,'prepare_evidence_root') as evidence,patch.object(module.subprocess,'run') as child:
   with self.assertRaisesRegex(ValueError,'excludes'):module.main()
   package.assert_not_called();evidence.assert_not_called();child.assert_not_called()
