import unittest
from types import SimpleNamespace
from listings_integrated_executor_owner import inspected_absent, ExecutorOwner
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
class AbsenceTests(unittest.TestCase):
 def test_confirmed_missing(self):
  for kind,message in [('volume','Error response from daemon: get owned: no such volume'),('volume','Error response from daemon: get owned: no such volume: owned'),('network','Error response from daemon: network owned not found'),('image','Error response from daemon: No such image: owned')]:
   self.assertTrue(inspected_absent(SimpleNamespace(returncode=1,stderr=message),kind,'owned'))
   self.assertFalse(inspected_absent(SimpleNamespace(returncode=0,stderr=''),kind,'owned'))
 def test_unknown_is_not_absent(self):
  for kind in ['volume','network','image']:
   for message in ['permission denied','Cannot connect to the Docker daemon','context deadline exceeded','','Error response from daemon: No such image: other','Error response from daemon: get other: no such volume','Error response from daemon: get owned: no such volume: other','no such volume']:
    with self.subTest(kind=kind,message=message),self.assertRaises(RuntimeError):inspected_absent(SimpleNamespace(returncode=1,stderr=message),kind,'owned')
 def test_start_rejects_present_or_ambiguous_resource_before_create(self):
  # Exercise actual start ordering; every command/filesystem/build operation is controlled.
  for blocked_kind in ['volume','network']:
   for code,message in [(0,''),(1,'Docker context not found'),(1,'no such file or directory'),(1,'Error response from daemon: network other not found')]:
    with self.subTest(kind=blocked_kind,code=code,message=message):
     commands=[]
     owner=ExecutorOwner(Path('/synthetic-source'),Path('/synthetic-evidence'),['docker'],'fixture-owner',{}, {},lambda:None)
     def checked(args,**kwargs):
      commands.append(args)
      return 'sha256:controlled' if args[:3]==['docker','image','inspect'] else ''
     def run(args,**kwargs):
      commands.append(args)
      kind,name=args[1],args[3]
      if kind==blocked_kind:return SimpleNamespace(returncode=code,stderr=message)
      return SimpleNamespace(returncode=1,stderr='Error response from daemon: get '+name+': no such volume')
     owner.checked=checked;owner.run=run;owner.remote_run=lambda *a,**k:''
     child=MagicMock();child.wait.return_value=0;child.pid=123
     with patch('pathlib.Path.read_text',return_value='synthetic policy'),patch('pathlib.Path.write_text'),patch('pathlib.Path.chmod'),patch('pathlib.Path.open',mock_open()),patch('listings_integrated_executor_owner.subprocess.Popen',return_value=child):
      with self.assertRaises(RuntimeError):owner.start()
     self.assertIn(['docker',blocked_kind,'inspect',getattr(owner,blocked_kind)],commands)
     self.assertFalse(any(c[:3]==['docker',blocked_kind,'create'] for c in commands))
     self.assertFalse(any(c[:2]==['docker','run'] for c in commands))
if __name__=='__main__':unittest.main()
