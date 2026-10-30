import os,subprocess,sys,unittest
from pathlib import Path
SCRIPT=Path(__file__).with_name('run-rag-directive-judge-isolated.py')
class ClosedMode(unittest.TestCase):
 def invoke(self,*args):
  return subprocess.run([sys.executable,'-B',str(SCRIPT),*args],capture_output=True,text=True,timeout=10,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONDONTWRITEBYTECODE':'1'})
 def test_conflicting_modes_reject_at_parse(self):
  value=self.invoke('--rag-directive-groups','--synthetic-positive');self.assertEqual(value.returncode,2);self.assertIn('unrecognized arguments',value.stderr)
 def test_missing_pins_refuse_before_owned_root(self):
  value=self.invoke('--rag-directive-groups');self.assertNotEqual(value.returncode,0);self.assertIn('Explicit reviewed runtime',value.stderr);self.assertNotIn('owasp-ai-goat-rag-directive-judge-',value.stdout)
 def test_unknown_case_selector_cannot_subset_prospective_cases(self):
  value=self.invoke('--rag-directive-groups','--case','data_only');self.assertEqual(value.returncode,2);self.assertIn('unrecognized arguments',value.stderr)
class CleanupBehavior(unittest.TestCase):
 def namespace(self):
  import ast
  tree=ast.parse(SCRIPT.read_text());tree.body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
  ns={};exec(compile(tree,str(SCRIPT),'exec'),ns);return ns
 def test_exited_leader_does_not_hide_surviving_descendant(self):
  from unittest.mock import Mock,patch
  from types import SimpleNamespace
  ns=self.namespace();alive=[43211];signals=[];clock=[0]
  def kill(pid,sig):
   signals.append((pid,sig))
   if sig==ns['signal'].SIGKILL:alive.clear()
  def sleep(seconds):clock[0]+=seconds
  child=Mock(pid=43210);child.poll.return_value=0;child.wait.return_value=0
  with patch.object(ns['os'],'killpg',side_effect=kill),patch.object(ns['time'],'monotonic',side_effect=lambda:clock[0]),patch.object(ns['time'],'sleep',side_effect=sleep):
   self.assertTrue(ns['stop_directive_child'](child,lambda budget:list(alive),SimpleNamespace(remaining=lambda:120-clock[0])))
  self.assertEqual(signals,[(43210,ns['signal'].SIGTERM),(43210,ns['signal'].SIGKILL)])
  child.wait.assert_called_once()
 def test_post_child_result_failure_still_drains_and_checks_inventory(self):
  import tempfile,json,types
  from unittest.mock import Mock,patch
  ns=self.namespace();checks=[]
  class Budget:
   def __init__(self,*a):pass
   def remaining(self):return 120
   def run(self,fn):return fn()
  with tempfile.TemporaryDirectory() as directory:
   source=Path(directory)/'base';source.mkdir();owned=Path(directory)/'owned';owned.mkdir();node=Path('/owned/node')
   args=types.SimpleNamespace(**{k:'pin' for k in ['node_binary','node_sha256','node_version','dependency_root','dependency_hashes','dependency_byte_sha256','embedding_cache','embedding_manifest_sha256','manifest','manifest_sha256']})
   modules={'pricing_runtime_pins':types.SimpleNamespace(validate=lambda *a:(node,source,source/'tests/fixtures/fullBackendModelCache')),'full_backend_auth_contract':types.SimpleNamespace(validate_package=lambda *a:checks.append('inventory')),'owned_dependency_overlay':types.SimpleNamespace(prepare_owned_runtime_directories=lambda a,b,c:b.mkdir()),'mail_disclosure_cleanup_budget':types.SimpleNamespace(CleanupBudget=Budget)}
   child=Mock(pid=43210);child.wait.return_value=0
   with patch.dict(sys.modules,modules),patch.object(ns['tempfile'],'mkdtemp',return_value=str(owned)),patch.object(ns['subprocess'],'run',return_value=types.SimpleNamespace(stdout='')),patch.object(ns['subprocess'],'Popen',return_value=child),patch.dict(ns,{'stop_directive_child':Mock(return_value=True)}):
    with self.assertRaises(SystemExit):ns['run_directive_groups'](args,source)
    ns['stop_directive_child'].assert_called_once()
   state=json.loads((owned/'ownership.json').read_text());self.assertEqual(state['errorType'],'FileNotFoundError');self.assertTrue(state['cleanup']['processGroupAbsent']);self.assertTrue(state['postInventoryVerified']);self.assertEqual(checks,['inventory','inventory'])
if __name__=='__main__':unittest.main()

