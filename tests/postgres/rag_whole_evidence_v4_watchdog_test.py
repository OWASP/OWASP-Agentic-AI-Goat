import importlib.util,pathlib,unittest,sys
from types import SimpleNamespace
from unittest.mock import patch
P=pathlib.Path(__file__).with_name('run-rag-whole-evidence-v4-main.py')
spec=importlib.util.spec_from_file_location('watchdog',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Controls(unittest.TestCase):
 def test_release_follows_publication(self):
  events=[];state={};pipe=SimpleNamespace(write=lambda x:events.append(x),flush=lambda:None,close=lambda:events.append('closed'))
  m.release_child(SimpleNamespace(pid=99,stdin=pipe),state,lambda:events.append(dict(state)))
  self.assertEqual(events,[{'nativePid':99,'nativeStarted':True},b'1','closed'])
 def test_failed_publication_never_releases(self):
  pipe=SimpleNamespace(write=lambda _:self.fail('released'))
  with self.assertRaises(RuntimeError):m.release_child(SimpleNamespace(pid=99,stdin=pipe),{},lambda:(_ for _ in ()).throw(RuntimeError()))
 def test_plan_is_nonallocating_after_admission(self):
  with patch.object(m,'admit') as admit,patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')):
   args=sum((['--'+k,'controlled']for k in ['manifest','manifest-sha256','node','node-sha256','python-sha256','supervisor-sha256','helper-sha256']),[])+['--plan']
   self.assertEqual(m.main(args),0);admit.assert_called_once()
if __name__=='__main__':unittest.main()
