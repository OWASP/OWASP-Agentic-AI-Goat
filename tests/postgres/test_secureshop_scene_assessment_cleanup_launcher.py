"""Resource-free controls for the V03 scene cleanup native launcher."""
import contextlib, importlib.util, io, json
from pathlib import Path
import unittest
from unittest import mock

PATH=Path(__file__).with_name('run-secureshop-scene-assessment-cleanup-isolated.py')
SPEC=importlib.util.spec_from_file_location('scene_cleanup_plan',PATH)
L=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(L)

class SceneCleanupLauncher(unittest.TestCase):
 def test_plan_is_pinned_and_nonallocating(self):
  output=io.StringIO()
  with mock.patch.object(L.importlib.util,'spec_from_file_location',side_effect=AssertionError('allocation import')),contextlib.redirect_stdout(output):
   self.assertEqual(L.main(['--plan']),0)
  plan=json.loads(output.getvalue());self.assertFalse(plan['allocationStarted']);self.assertEqual(plan['expectedTests'],1)
  self.assertEqual(plan['stores'],[['IDENTITY','identity']]);self.assertEqual(plan['sourcePins'],L.pins())
  self.assertFalse(plan['actualModel']);self.assertFalse(plan['browser']);self.assertFalse(plan['judge'])
 def test_changed_pin_denies_run_before_resource_import(self):
  with mock.patch.object(L,'installed',return_value={L.SHARED:True,L.FIXTURE:False,L.MIGRATION:True}),mock.patch.object(L.importlib.util,'spec_from_file_location',side_effect=AssertionError('allocation import')):
   with self.assertRaisesRegex(RuntimeError,'pin mismatch'):L.main(['--run'])
 def test_exact_environment_and_result_seams(self):
  source=(L.ROOT/L.SHARED).read_text();configured=L.configured_source(source)
  self.assertEqual(configured.count("SECURESHOP_SCENE_ASSESSMENT_NATIVE='1'"),1)
  self.assertEqual(configured.count("DVAIA_CURRENT_MAIN_WORKSPACE=str(ROOT)"),1)
  self.assertEqual(configured.count("'qualificationScope':SCENE_ASSESSMENT_SCOPE"),1)
 def test_fixture_assertion_and_current_pins(self):
  self.assertTrue(all(L.installed().values()))
  fixture=(L.ROOT/L.FIXTURE).read_text()
  self.assertIn("test('scene reset retires exact V03 scene contributions and preserves immutable evidence and unrelated progress'",fixture)

if __name__=='__main__':unittest.main()
