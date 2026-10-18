import importlib.util,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
p=Path(__file__).with_name('run-ollama-conformance-main.py');s=importlib.util.spec_from_file_location('owner',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_plan_no_allocation(self):
  with patch.object(m,'admit') as admit,patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')):
   self.assertEqual(m.main(['--manifest','/m','--manifest-sha256','h','--node','/n','--node-sha256','n','--python-sha256','p','--plan']),0);admit.assert_called_once()
 def test_required_entry_and_input_cannot_be_omitted(self):
  a=SimpleNamespace(manifest='/m',manifest_sha256='x',node='/n',node_sha256='x',python_sha256='x')
  with patch.object(m.base,'exact',side_effect=lambda p:Path(p)),patch.object(m.base,'digest',return_value='x'),patch.object(Path,'read_text',return_value=json.dumps({'root':str(m.ROOT),'node':{'path':'/n','sha256':'x'},'files':[]})):
   with self.assertRaisesRegex(ValueError,'Required closure'):m.admit(a)
if __name__=='__main__':unittest.main()
