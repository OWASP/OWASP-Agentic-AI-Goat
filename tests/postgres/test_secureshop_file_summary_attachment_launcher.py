import importlib.util, pathlib, unittest
PATH=pathlib.Path(__file__).with_name('run-secureshop-file-summary-attachment-isolated.py')
SPEC=importlib.util.spec_from_file_location('v19_attachment_launcher',PATH);M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
class Launcher(unittest.TestCase):
 def test_plan_is_resource_free_and_exact(self):
  self.assertEqual(M.main(['--plan']),0);self.assertEqual(M.STORES,(('IDENTITY','identity'),('POPULATED','identity'),('UNKNOWN','identity'),('AGENTS','secureshop_agents'),('COMMERCE','secureshop'),('REVIEW','secureshop_review')))
  self.assertIn('no nested advisory-lock wait',M.SCOPE)
  self.assertIn('platform-owner debt remains fail-closed',M.SCOPE)
  self.assertIn('same-principal debt across sessions',M.SCOPE)
  self.assertIn('canonical reset isolation and fresh rebootstrap',M.SCOPE)
  self.assertIn('peer tenant merchant membership',M.SCOPE)
 def test_sources_are_current(self): self.assertEqual(M.validate_sources(),M.pins())
 def test_fixture_matches_shared_launcher_contract(self): self.assertTrue(M.validate_fixture_contract())
if __name__=='__main__':unittest.main()
