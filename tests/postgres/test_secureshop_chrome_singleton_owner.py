import importlib.util
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('singleton_owner',Path(__file__).with_name('secureshop_chrome_singleton_owner.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

class Singleton(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]/'tasks/tmp')
  self.root=Path(self.temp.name).resolve();self.profile=self.root/'profile';self.tmp=self.root/'tmp'
  self.profile.mkdir(mode=0o700);self.tmp.mkdir(mode=0o700)
  self.target=self.tmp/'com.google.Chrome.test';self.target.mkdir(mode=0o700)
  self.sock=socket.socket(socket.AF_UNIX)
  self.addCleanup(self.temp.cleanup);self.addCleanup(self.sock.close)
  previous=os.getcwd()
  try:os.chdir(self.target);self.sock.bind('SingletonSocket')
  finally:os.chdir(previous)
  (self.target/'SingletonCookie').symlink_to('123456')
  (self.profile/'SingletonCookie').symlink_to('123456')
  (self.profile/'SingletonSocket').symlink_to(self.target/'SingletonSocket')
  self.record={'pid':111,'parentPid':112,'pgid':112}
  self.api=SimpleNamespace(identity=lambda _:None,group_pids=lambda _:[])
 def tearDown(self):self.sock.close();self.temp.cleanup()
 def capture(self):return M.capture(self.profile,self.tmp)
 def test_exact_live_topology_retired_and_sibling_preserved(self):
  sibling=self.tmp/'unrelated';sibling.write_text('keep')
  proof=self.capture();self.sock.close()
  self.assertTrue(M.retire(proof,self.record,self.api)['singletonTempAbsent'])
  self.assertFalse(self.target.exists());self.assertEqual(sibling.read_text(),'keep')
 def test_missing_profile_link_denied(self):
  (self.profile/'SingletonSocket').unlink()
  with self.assertRaises(FileNotFoundError):self.capture()
  self.assertTrue(self.target.exists())
 def test_foreign_socket_target_denied(self):
  (self.profile/'SingletonSocket').unlink();(self.profile/'SingletonSocket').symlink_to('/tmp/com.google.Chrome.foreign/SingletonSocket')
  with self.assertRaises(RuntimeError):self.capture()
 def test_cookie_mismatch_denied(self):
  (self.profile/'SingletonCookie').unlink();(self.profile/'SingletonCookie').symlink_to('other')
  with self.assertRaises(RuntimeError):self.capture()
 def test_live_process_denies_without_deletion(self):
  proof=self.capture();self.api.identity=lambda _:object()
  with self.assertRaises(RuntimeError):M.retire(proof,self.record,self.api)
  self.assertTrue((self.target/'SingletonSocket').exists())
 def test_live_group_denies_without_deletion(self):
  proof=self.capture();self.api.group_pids=lambda _:[123]
  with self.assertRaises(RuntimeError):M.retire(proof,self.record,self.api)
 def test_added_entry_denies_before_any_unlink(self):
  proof=self.capture();(self.target/'foreign').write_text('keep')
  with self.assertRaises(RuntimeError):M.retire(proof,self.record,self.api)
  self.assertTrue((self.target/'SingletonCookie').is_symlink())
 def test_replaced_cookie_denies_without_following(self):
  proof=self.capture();(self.target/'SingletonCookie').unlink();(self.target/'SingletonCookie').symlink_to('/etc/passwd')
  with self.assertRaises(RuntimeError):M.retire(proof,self.record,self.api)
 def test_directory_symlink_denied(self):
  proof=self.capture();renamed=self.tmp/'retained';self.target.rename(renamed);self.target.symlink_to(renamed,target_is_directory=True)
  with self.assertRaises(OSError):M.retire(proof,self.record,self.api)
  self.assertTrue((renamed/'SingletonSocket').exists())
 def test_naturally_absent_is_success(self):
  proof=self.capture();self.sock.close();(self.target/'SingletonSocket').unlink();(self.target/'SingletonCookie').unlink();self.target.rmdir()
  self.assertEqual(M.retire(proof,self.record,self.api)['removed'],[])
 def test_unlink_failure_propagates(self):
  proof=self.capture()
  with patch.object(M.os,'unlink',side_effect=OSError('controlled')):
   with self.assertRaises(OSError):M.retire(proof,self.record,self.api)
  self.assertTrue(self.target.exists())
 def test_wrong_directory_owner_denied(self):
  with patch.object(M.os,'getuid',return_value=os.getuid()+1):
   with self.assertRaises(RuntimeError):self.capture()
 def test_socket_replaced_with_regular_file_denied(self):
  proof=self.capture();self.sock.close();(self.target/'SingletonSocket').unlink();(self.target/'SingletonSocket').write_text('keep')
  with self.assertRaises(RuntimeError):M.retire(proof,self.record,self.api)
  self.assertEqual((self.target/'SingletonSocket').read_text(),'keep')
 def test_delayed_expected_link_uses_existing_deadline_and_rechecks_birth(self):
  (self.profile/'SingletonSocket').unlink();ticks=[0];verified=[]
  def wait(seconds):
   ticks[0]+=seconds;(self.profile/'SingletonSocket').symlink_to(self.target/'SingletonSocket')
  stop=SimpleNamespace(is_set=lambda:False,wait=wait)
  value,proof=M.capture_until(self.profile,self.tmp,lambda:verified.append(1) or 'live',1,stop,clock=lambda:ticks[0])
  self.assertEqual(value,'live');self.assertIsInstance(proof,M.CapturedSingleton);self.assertEqual(len(verified),3)
  self.assertLess(ticks[0],1)
 def test_missing_until_existing_deadline_denied(self):
  (self.profile/'SingletonSocket').unlink();ticks=[0]
  stop=SimpleNamespace(is_set=lambda:False,wait=lambda seconds:ticks.__setitem__(0,ticks[0]+seconds))
  with self.assertRaisesRegex(RuntimeError,'capture deadline'):
   M.capture_until(self.profile,self.tmp,lambda:'live',0.05,stop,clock=lambda:ticks[0])
  self.assertEqual(ticks[0],0.05);self.assertTrue(self.target.exists())
 def test_foreign_topology_never_retried(self):
  (self.profile/'SingletonSocket').unlink();(self.profile/'SingletonSocket').symlink_to('/tmp/com.google.Chrome.foreign/SingletonSocket')
  stop=SimpleNamespace(is_set=lambda:False,wait=lambda _:self.fail('must not retry foreign topology'))
  with self.assertRaisesRegex(RuntimeError,'outside owned temp'):
   M.capture_until(self.profile,self.tmp,lambda:'live',1,stop,clock=lambda:0)

class Integration(unittest.TestCase):
 def test_actual_adapter_forwards_existing_watcher_deadline_and_stop(self):
  spec=importlib.util.spec_from_file_location('policy_adapter_deadline',Path(__file__).with_name('run-secureshop-policy-output-browser.py'))
  adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
  stop=object();value=SimpleNamespace(profile='/owned/run/evidence/runtime/browser-profile',record={});seen=[]
  def capture_until(profile,temp,verify,deadline,event):
   self.assertEqual(deadline,123.25);self.assertIs(event,stop)
   self.assertIs(verify(),value);seen.append((str(profile),str(temp)));return value,'proof'
  ownership=SimpleNamespace(retire_live_v36=lambda *a,**k:[])
  with patch.object(adapter,'load',side_effect=[SimpleNamespace(),ownership,SimpleNamespace(capture_until=capture_until)]),patch.object(adapter,'capture_live_policy',return_value=value):
   _,owner=adapter.lifecycle()
   result=owner.capture_live_v36_with_deadline({},(1,2),Path('/owned/run/evidence/runtime'),api='api',deadline=123.25,stop=stop)
   self.assertIs(result,value);self.assertEqual(result.singleton,'proof')
  self.assertEqual(seen,[('/owned/run/evidence/runtime/browser-profile','/owned/run/runtime/tmp')])
 def test_actual_adapter_hooks_capture_and_retire_in_order(self):
  spec=importlib.util.spec_from_file_location('policy_adapter',Path(__file__).with_name('run-secureshop-policy-output-browser.py'))
  adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
  events=[];record={'pid':1};value=SimpleNamespace(profile='/owned/run/evidence/runtime/browser-profile',record=record)
  watcher=SimpleNamespace();ownership=SimpleNamespace(retire_live_v36=lambda *a,**k:events.append('browser-absence') or ['absent'])
  singleton=SimpleNamespace(capture=lambda p,t:events.append(('capture',p,str(t))) or 'proof',retire=lambda *a:events.append(('retire',a)))
  with patch.object(adapter,'load',side_effect=[watcher,ownership,singleton]),patch.object(adapter,'capture_live_policy',return_value=value):
   _,owner=adapter.lifecycle();captured=owner.capture_live_v36(record,(1,2),Path('/owned/run/evidence/runtime'),api='api')
   self.assertEqual(owner.retire_live_v36(captured,api='api'),['absent'])
  self.assertEqual(events[0],('capture',value.profile,'/owned/run/runtime/tmp'))
  self.assertEqual(events[1],'browser-absence');self.assertEqual(events[2],('retire',('proof',record,'api')))
 def test_actual_adapter_preserves_retirement_failure(self):
  spec=importlib.util.spec_from_file_location('policy_adapter_fault',Path(__file__).with_name('run-secureshop-policy-output-browser.py'))
  adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
  failure=RuntimeError('singleton debt');singleton=SimpleNamespace(retire=lambda *a:(_ for _ in ()).throw(failure))
  ownership=SimpleNamespace(retire_live_v36=lambda *a,**k:[])
  with patch.object(adapter,'load',side_effect=[SimpleNamespace(),ownership,singleton]):
   _,owner=adapter.lifecycle()
   with self.assertRaises(RuntimeError) as caught:owner.retire_live_v36(SimpleNamespace(singleton='proof',record={}),api='api')
   self.assertIs(caught.exception,failure)
 def test_actual_adapter_missing_capture_denies_before_retirement(self):
  spec=importlib.util.spec_from_file_location('policy_adapter_missing',Path(__file__).with_name('run-secureshop-policy-output-browser.py'))
  adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
  events=[];ownership=SimpleNamespace(retire_live_v36=lambda *a,**k:events.append('retire'))
  with patch.object(adapter,'load',side_effect=[SimpleNamespace(),ownership,SimpleNamespace()]):
   _,owner=adapter.lifecycle()
   with self.assertRaisesRegex(RuntimeError,'singleton live capture missing'):owner.retire_live_v36(SimpleNamespace(record={}),api='api')
  self.assertEqual(events,[])
if __name__=='__main__':unittest.main()
