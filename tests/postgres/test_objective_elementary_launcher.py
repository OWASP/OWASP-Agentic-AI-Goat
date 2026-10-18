import unittest,importlib.util,pathlib,ast,hashlib
from unittest.mock import patch
ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('elementary_launcher',ROOT/'run-objective-elementary-isolated.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
import owned_diagnostic_process_cleanup as cleanup
class ElementaryLauncher(unittest.TestCase):
 def test_closed_required_selector(self):
  flags=['--elementary-72']+sum((['--'+x,'owned'] for x in module.REQUIRED),[])
  self.assertTrue(module.arguments(flags).elementary_72)
  for bad in [flags+['--whole-evidence-diagnostic'],flags[1:],['--elementary-72']]:
   with self.assertRaises(SystemExit):module.arguments(bad)
 def test_source_meaning_closed_mode(self):
  flags=['--source-meaning-18']+sum((['--'+x,'owned'] for x in module.REQUIRED),[])
  self.assertTrue(module.arguments(flags).source_meaning_18)
  with self.assertRaises(SystemExit):module.arguments(flags+['--elementary-72'])
  source=(ROOT/'run-objective-elementary-isolated.py').read_text()
  self.assertIn('(1200,1140) if source_only else (4560,4500)',source)
  self.assertLess(source.index('child.wait('),source.index("'tests/fixtures/sourceMeaningScoring.js'"))
  self.assertIn("'allHttp':19 if source_only else 73",source)
 def test_extraction_selector_is_closed_and_never_semantically_accepts(self):
  flags=['--source-extraction-18']+sum((['--'+x,'owned'] for x in module.REQUIRED),[])
  self.assertTrue(module.arguments(flags).source_extraction_18)
  for other in ['--source-meaning-18','--elementary-72']:
   with self.assertRaises(SystemExit):module.arguments(flags+[other])
  source=(ROOT/'run-objective-elementary-isolated.py').read_text()
  self.assertIn("state['semanticAccepted']=None",source)
  self.assertIn('mechanical-complete-semantic-review-pending',source)
  self.assertLess(source.index('child.wait('),source.index("'tests/fixtures/sourceExtractionMechanicalScoring.js'"))
 def test_cleanup_helper_matches_retained_original_function(self):
  new=next(n for n in ast.parse((ROOT/'owned_diagnostic_process_cleanup.py').read_text()).body if isinstance(n,ast.FunctionDef))
  self.assertEqual(hashlib.sha256(ast.dump(new,include_attributes=False).encode()).hexdigest(),'7ce94eab7f489ba942866d1dd6fa604a07d5308afd78eb0c2dc45716fce1d369')
 def test_old_launcher_imports_same_cleanup_without_other_function(self):
  tree=ast.parse((ROOT/'run-pricing-judge-replay-isolated.py').read_text())
  self.assertFalse(any(isinstance(n,ast.FunctionDef) and n.name=='stop_directive_child' for n in tree.body))
  self.assertTrue(any(isinstance(n,ast.ImportFrom) and n.module=='owned_diagnostic_process_cleanup' for n in tree.body))
 def test_cleanup_absence_and_unknown_are_distinct(self):
  class Budget:
   def remaining(self):return 1
  self.assertTrue(cleanup.stop_directive_child(None,lambda b:[],Budget()))
  with self.assertRaises(RuntimeError):cleanup.stop_directive_child(None,lambda b:(_ for _ in ()).throw(RuntimeError('unknown')),Budget())
class FactoredPhases(unittest.TestCase):
 def test_closed_phase_modes(self):
  base=sum((['--'+x,'owned'] for x in module.REQUIRED),[])
  for phase in ['simple6','remaining18']:
   self.assertEqual(module.arguments(['--factored-phase',phase]+base).factored_phase,phase)
  for flags in [['--factored-phase','all24'],['--factored-phase','simple6','--source-extraction-18']]:
   with self.assertRaises(SystemExit):module.arguments(flags+base)
 def test_unsealed_input_denies_before_resource_function(self):
  from types import SimpleNamespace
  args=SimpleNamespace(factored_phase='simple6',factored_input='/tmp/outside',factored_input_sha256='a'*64)
  with self.assertRaises(ValueError):module.factored_selection(args,ROOT)
 def test_gate_exact_shape_model_protocol_and_bindings_before_copy(self):
  gate=dict(version=1,phase='simple6',inputSha256='a'*64,resultSha256='b'*64,auditSha256='c'*64,modelDigest='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',protocol='factored-semantic-diagnostic.v1',semanticSha256='e'*64,decision='go',reviewType='independent-agent-provisional')
  module.validate_factored_gate(gate,'a'*64,'b'*64,'c'*64,'e'*64)
  for delta in [dict(semanticSha256='f'*64),dict(extra=True),dict(version=True),dict(modelDigest='0'*64),dict(protocol='other'),dict(decision='no-go'),dict(resultSha256='d'*64)]:
   with self.assertRaises(AssertionError):module.validate_factored_gate(gate|delta,'a'*64,'b'*64,'c'*64,'e'*64)
 def test_members_require_actual_session_before_any_signal(self):
  from types import SimpleNamespace
  c=SimpleNamespace(pid=200)
  with patch.object(module.os,'getuid',return_value=501),patch.object(module.os,'getsid',return_value=200):self.assertEqual(module.factored_members(c,['201 200 501']),[201])
  with patch.object(module.os,'getuid',return_value=501),patch.object(module.os,'getsid',return_value=999):
   with self.assertRaises(RuntimeError):module.factored_members(c,['201 200 501'])
  with patch.object(module.os,'getuid',return_value=501),patch.object(module.os,'getsid',side_effect=ProcessLookupError):
   with self.assertRaises(ProcessLookupError):module.factored_members(c,['201 200 501'])
 def test_phase_budgets_and_separate_cleanup_are_explicit(self):
  source=(ROOT/'run-objective-elementary-isolated.py').read_text()
  self.assertIn('dict(work=2400,child=2280,http=37',source)
  self.assertIn('dict(work=6720,child=6600,http=109',source)
  self.assertIn("owned=OwnedProcesses(stop,record)",source)
  self.assertIn('integrity=CleanupBudget(120)',source)
  self.assertIn("state['auditExitCode']=child_run",source)
if __name__=='__main__':unittest.main()
