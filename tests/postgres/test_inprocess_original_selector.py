import unittest,importlib.util,sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location('original_launcher',Path(__file__).with_name('run-setup-database-phase-isolated.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Original(unittest.TestCase):
 def test_four_cases_and_closed_bounds(self):
  self.assertEqual(m.scenario_bounds('inprocess-original'),(780,600,120))
  self.assertEqual(m.scenario_fixture('inprocess-original'),'tests/postgres/applicationMaintenanceInprocessOriginal.integration.test.js')
  for case in ['success','begin-commit-loss','finish-commit-loss','interrupted-original']:m.validate_original_case(SimpleNamespace(scenario='inprocess-original',original_case=case))
 def test_cross_mode_rejected_before_resource_validation(self):
  for scenario,case in [('fresh-success','success'),('ctf-populated','success'),('inprocess-original',None)]:
   with self.assertRaises(ValueError):m.validate_original_case(SimpleNamespace(scenario=scenario,original_case=case))
  source=Path(m.__file__).read_text();self.assertLess(source.index('    validate_original_case(args)'),source.index('    package=validate(args)'))
 def test_prior_bounds_unchanged(self):
  self.assertEqual(m.scenario_bounds('fresh-success'),(780,780,120));self.assertEqual(m.scenario_bounds('ctf-populated'),(2100,1800,180))
if __name__=='__main__':unittest.main()
