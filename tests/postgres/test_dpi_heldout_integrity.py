import unittest,tempfile
from pathlib import Path
from unittest.mock import patch,Mock
from dpi_heldout_integrity import source_inventory,verify,cleanup
from owned_mcp_assembly_freeze import dependencies,digest
class Integrity(unittest.TestCase):
 def test_added_source_and_changed_dependency_deny(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/'tests').mkdir();(r/'node_modules').mkdir()
   for n in ['package.json','package-lock.json','tests/a.js','node_modules/a.js']:(r/n).write_text('original')
   source=source_inventory(r);deps=digest(dependencies(r));verify(r,source,deps)
   (r/'tests/extra.js').write_text('new')
   with self.assertRaisesRegex(RuntimeError,'source'):verify(r,source,deps)
   (r/'tests/extra.js').unlink();(r/'node_modules/a.js').write_text('changed')
   with self.assertRaisesRegex(RuntimeError,'Dependency'):verify(r,source,deps)
 def test_cleanup_ignores_repeated_signals_and_retains_ps_failure(self):
  with patch('dpi_heldout_integrity.signal.signal') as handler,patch('dpi_heldout_integrity.signal.alarm'),patch('dpi_heldout_integrity.subprocess.check_output',side_effect=TimeoutError('ps bound')):
   result=cleanup(Mock(),123);self.assertEqual(handler.call_count,2);self.assertFalse(result['wholeProcessGroupAbsent']);self.assertIn('ps bound',result['errors'][0])
 def test_wait_error_retained(self):
  child=Mock();child.wait.side_effect=TimeoutError('wait bound')
  with patch('dpi_heldout_integrity.signal.signal'),patch('dpi_heldout_integrity.signal.alarm'),patch('dpi_heldout_integrity.subprocess.check_output',return_value=''):
   self.assertIn('wait bound',cleanup(child,123)['errors'][0])
if __name__=='__main__':unittest.main()
