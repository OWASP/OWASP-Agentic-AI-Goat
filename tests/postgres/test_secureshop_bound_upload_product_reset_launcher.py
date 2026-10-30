"""Resource-free controls for the product-target upload reset launcher."""
import sys
sys.dont_write_bytecode=True
import contextlib,importlib.util,io,json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
PATH=Path(__file__).with_name('run-secureshop-bound-upload-product-reset-isolated.py')
SPEC=importlib.util.spec_from_file_location('upload_product_reset_launcher_tested',PATH)
launcher=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(launcher)
class UploadProductResetLauncher(unittest.TestCase):
 def test_fixture_database_guard_matches_owned_launcher_nonce(self):
  shared=launcher.SHARED.read_text();fixture=(launcher.ROOT/launcher.FIXTURE).read_text()
  self.assertIn("nonce=uuid.uuid4().hex; name='owasp-ai-goat-persona-transition-'+nonce[:12]",shared)
  self.assertIn("'owasp_ai_goat_test_persona_'+store.lower()+'_'+nonce[:12]",shared)
  self.assertIn("^\\/owasp_ai_goat_test_persona_(identity|agents|review)_[a-f0-9]{12}$",fixture)
 def test_plan_is_three_owned_stores_and_resource_free(self):
  output=io.StringIO()
  with patch.object(launcher,'validate_sources'),patch.object(launcher.importlib.util,'spec_from_file_location',side_effect=AssertionError('plan loaded resources')):
   with contextlib.redirect_stdout(output):self.assertEqual(launcher.main(['--plan']),0)
  value=json.loads(output.getvalue());self.assertEqual(value['stores'],[['IDENTITY','identity'],['AGENTS','secureshop_agents'],['REVIEW','secureshop_review']]);self.assertEqual(value['expectedTests'],1);self.assertIs(value['allocationStarted'],False);self.assertIs(value['actualModel'],False);self.assertIs(value['browser'],False);self.assertIs(value['sourceCopies'],False);self.assertIn('original-birth cleanup receipt',value['qualificationScope'])
 def test_shared_dispatch_and_inventory_are_closed(self):
  spec=importlib.util.spec_from_file_location('upload_product_reset_shared',launcher.SHARED);shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared);main=shared.main;old=dict(shared.SUITES);seen=[];shared.source_inventory=lambda paths:seen.extend(paths)or{'controlled':True};configured=launcher.configure(shared,run=True);self.assertIs(configured.main,main);self.assertEqual(configured.SUITES,{launcher.SUITE:(launcher.FIXTURE,launcher.PREFIX,launcher.STORES,1)});self.assertGreater(len(old),1);self.assertTrue(configured.arguments().run);self.assertEqual(configured.source_inventory([]),{'controlled':True});self.assertIn(PATH.resolve(),seen);self.assertIn(Path(__file__).resolve(),seen)
 def test_real_selected_inventory_contains_traversal_writer_and_sink_imports(self):
  spec=importlib.util.spec_from_file_location('upload_product_reset_inventory_actual',launcher.SHARED);shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
  pins=launcher.configure(shared,run=True).source_inventory([launcher.ROOT/launcher.FIXTURE])
  self.assertEqual(launcher.sha(launcher.ROOT/launcher.FIXTURE),launcher.FIXTURE_SHA256)
  for name in launcher.SELECTED_UPLOAD_SOURCES:self.assertEqual(pins[name],launcher.sha(launcher.ROOT/name))
  self.assertIn("require('../../agent-host/agents/uploads/tools')",(launcher.ROOT/launcher.SELECTED_UPLOAD_SOURCES[0]).read_text())
 def test_run_delegates_original_main_once(self):
  selected=[];shared=SimpleNamespace(source_inventory=lambda extra:{},main=lambda:selected.append(shared.arguments().suite)or 0);loader=SimpleNamespace(exec_module=lambda value:None)
  with patch.object(launcher,'validate_sources'),patch.object(launcher.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=loader)),patch.object(launcher.importlib.util,'module_from_spec',return_value=shared):self.assertEqual(launcher.main(['--run']),0)
  self.assertEqual(selected,[launcher.SUITE])
 def test_all_source_pins_fail_closed_before_resource_import(self):
  expected={launcher.ROOT/launcher.FIXTURE:launcher.FIXTURE_SHA256,launcher.ROOT/launcher.CLEANUP:launcher.CLEANUP_SHA256,launcher.ROOT/launcher.ADAPTER:launcher.ADAPTER_SHA256,launcher.SHARED:launcher.SHARED_SHA256}
  with patch.object(launcher,'sha',side_effect=lambda path:expected[Path(path)]) as digest:launcher.validate_sources()
  self.assertEqual(digest.call_count,4)
  for target in expected:
   with patch.object(launcher,'sha',side_effect=lambda path:'0'*64 if Path(path)==target else expected[Path(path)]):
    with self.assertRaisesRegex(RuntimeError,'source pin mismatch'):launcher.validate_sources()
  with patch.object(launcher,'sha',return_value='0'*64),patch.object(launcher.importlib.util,'spec_from_file_location',side_effect=AssertionError('must reject before import')):
   with self.assertRaisesRegex(RuntimeError,'source pin mismatch'):launcher.main(['--run'])
if __name__=='__main__':unittest.main()
