import importlib.util,pathlib,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
P=ROOT/'tests/release-inputs/capture-codebot-parity-main.py'
spec=importlib.util.spec_from_file_location('capture_codebot',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_missing_closure_denied_before_file_reads(self):
  with patch.object(m,'sha',side_effect=AssertionError('read')):
   with self.assertRaises(RuntimeError):m.verify_pins(ROOT,{})
 def test_all_migration_pins_required(self):
  pins={p:'digest' for p in m.REQUIRED}
  with patch.object(m,'sha',return_value='digest'):
   with self.assertRaisesRegex(RuntimeError,'Migration closure'):m.verify_pins(ROOT,pins)
 def test_changed_bytes_and_escape_denied(self):
  pins={p:'digest' for p in m.REQUIRED}
  with patch.object(m,'sha',return_value='different'):
   with self.assertRaisesRegex(RuntimeError,'Source changed'):m.verify_pins(ROOT,pins)
  pins['../foreign']='digest'
  with patch.object(m,'sha',return_value='digest'):
   with self.assertRaisesRegex(RuntimeError,'Source changed'):m.verify_pins(ROOT,pins)
 def test_history_requires_exact_new_helper_and_three_store_migrations(self):
  required,dirs=m.profile_requirements('workshop-history')
  self.assertIn('tests/fixtures/workshopHistoryBrowserQualification.js',required)
  self.assertEqual(dirs,['db/postgres/identity-migrations','db/postgres/workshop-migrations/aria','db/postgres/workshop-migrations/nova'])
  with self.assertRaises(ValueError):m.profile_requirements('all')
  pins={p:'digest' for p in required}
  with patch.object(m,'sha',return_value='digest'):
   with self.assertRaisesRegex(RuntimeError,'Migration closure'):m.verify_pins(ROOT,pins,'workshop-history')
 def test_mcp_content_exact_store_and_helpers(self):
  required,dirs=m.profile_requirements('mcp-audit-content')
  self.assertIn('tests/fixtures/mcpAuditContentBrowser.js',required)
  self.assertIn('tests/fixtures/mcpAuditSeedUpgrade.js',required)
  self.assertEqual(dirs,['db/postgres/identity-migrations','db/postgres/workshop-migrations/mcp'])
 def test_rag_content_requires_helpers_and_complete_identity_migrations(self):
  required,dirs=m.profile_requirements('ipi-rag-query-content')
  self.assertIn('tests/postgres/ipiEmailRenderedFixture.js',required)
  self.assertIn('tests/ipiEmailRenderedQualificationContract.test.js',required)
  self.assertEqual(dirs,['db/postgres/identity-migrations'])
  pins={p:'digest' for p in required}
  with patch.object(m,'sha',return_value='digest'):
   with self.assertRaisesRegex(RuntimeError,'Migration closure'):m.verify_pins(ROOT,pins,'ipi-rag-query-content')
  with patch.object(m,'sha',side_effect=AssertionError('must deny before read')):
   with self.assertRaises(RuntimeError):m.verify_pins(ROOT,{p:'digest' for p in m.REQUIRED},'ipi-rag-query-content')
 def test_upload_clean_profile_reuses_identity_closure(self):
  self.assertEqual(m.profile_requirements('ipi-rag-upload-clean-content'),m.profile_requirements('ipi-rag-query-content'))
  with patch.object(m,'sha',side_effect=AssertionError('must deny before read')):
   with self.assertRaises(RuntimeError):m.verify_pins(ROOT,{p:'digest' for p in m.REQUIRED},'ipi-rag-upload-clean-content')
 def test_scope_has_no_mail_renderer_or_model_input(self):
  self.assertFalse(any('Mail' in p or 'mail' in p or 'frozen-input' in p for p in m.REQUIRED))
  self.assertIn('tests/fixtures/browserProcessOwnership.js',m.REQUIRED)
class EmailCaptureControls(unittest.TestCase):
 def test_exact_email_profile_requires_frozen_input_wire_and_production_graph(self):
  required,roots=m.profile_requirements('ipi-email-trigger-actual')
  self.assertEqual(roots,['db/postgres/identity-migrations'])
  for name in ['tests/fixtures/ipiEmailTriggerActualInput.json','tests/postgres/finflowBackupBrowserActualTransport.js','server/agent-runtime/indirectEmailGraph.js','server/services/ipiEmailProvider.js']:self.assertIn(name,required)
  content,_=m.profile_requirements('ipi-email-five-content');self.assertNotIn('tests/fixtures/ipiEmailTriggerActualInput.json',content)
  with self.assertRaises(RuntimeError):m.verify_pins(ROOT,{p:'digest'for p in m.REQUIRED},'ipi-email-trigger-actual')
  with self.assertRaises(ValueError):m.profile_requirements('ipi-email-trigger-actual-other')
if __name__=='__main__':unittest.main()
