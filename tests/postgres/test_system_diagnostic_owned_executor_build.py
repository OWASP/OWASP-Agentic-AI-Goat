"""Resource-free controls for bounded diagnostic executor build cleanup."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import system_diagnostic_owned_executor as module
from system_diagnostic_owned_executor import OwnedDiagnosticExecutor

class DiagnosticBuildCleanupTests(unittest.TestCase):
 def executor(self):
  root=Path(tempfile.mkdtemp())
  return OwnedDiagnosticExecutor(root,root,['docker'],{},'controlled-owner',lambda:None)
 def test_timeout_is_bounded_and_primary_exception_survives_cleanup_failure(self):
  executor=self.executor()
  timeout=subprocess.TimeoutExpired(['docker','build'],module.BUILD_TIMEOUT_SECONDS)
  executor.build=SimpleNamespace(wait=lambda **kwargs: (_ for _ in ()).throw(timeout),pid=321)
  executor.stop_build=lambda: (_ for _ in ()).throw(PermissionError('controlled cleanup failure'))
  with self.assertRaises(subprocess.TimeoutExpired) as raised:executor.wait_for_build()
  self.assertIs(raised.exception,timeout)
  self.assertEqual(executor.state['buildStopError'],'PermissionError')
  self.assertEqual(module.BUILD_TIMEOUT_SECONDS,420)
 def test_persist_failure_cannot_mask_primary_timeout(self):
  executor=self.executor()
  timeout=subprocess.TimeoutExpired(['docker','build'],module.BUILD_TIMEOUT_SECONDS)
  executor.build=SimpleNamespace(wait=lambda **kwargs: (_ for _ in ()).throw(timeout),pid=321)
  executor.stop_build=lambda: (_ for _ in ()).throw(PermissionError('controlled cleanup failure'))
  executor.persist=lambda: (_ for _ in ()).throw(OSError('controlled recording failure'))
  with self.assertRaises(subprocess.TimeoutExpired) as raised:executor.wait_for_build()
  self.assertIs(raised.exception,timeout)
  self.assertIn('Owned build cleanup recording failed: OSError',getattr(timeout,'__notes__',[]))
 def test_stop_build_signals_only_verified_members_without_killpg(self):
  executor=self.executor();executor.build=SimpleNamespace(pid=321,wait=lambda timeout:0)
  rosters=iter([[321,322],[],[]]);executor.groups=lambda:next(rosters,[]);executor.owned_build_member=lambda pid:True
  calls=[]
  with patch.object(module.os,'kill',side_effect=lambda pid,number:calls.append((pid,number))), \
       patch.object(module.os,'killpg',side_effect=AssertionError('killpg must not be used')):
   executor.stop_build()
  self.assertEqual(calls,[(321,module.signal.SIGTERM),(322,module.signal.SIGTERM)])
 def test_live_child_with_empty_group_cannot_report_stopped(self):
  executor=self.executor();executor.groups=lambda:[]
  executor.build=SimpleNamespace(pid=321,wait=lambda **kwargs:(_ for _ in ()).throw(subprocess.TimeoutExpired(['docker','build'],5)))
  with self.assertRaisesRegex(RuntimeError,'Build process remains'):executor.stop_build()
 def test_disappearing_member_is_tolerated(self):
  executor=self.executor();executor.groups=lambda:[321];executor.owned_build_member=lambda pid:True
  with patch.object(module.os,'kill',side_effect=ProcessLookupError):
   executor.signal_build_members(module.signal.SIGTERM)
 def test_immediate_identity_recheck_skips_disappeared_member_and_rejects_reused_pid(self):
  executor=self.executor();executor.build=SimpleNamespace(pid=321)
  gone=SimpleNamespace(stdout='',returncode=1)
  with patch.object(module.subprocess,'run',return_value=gone):self.assertFalse(executor.owned_build_member(322))
  reused=SimpleNamespace(stdout='999 502 S\n',returncode=0)
  with patch.object(module.subprocess,'run',return_value=reused),patch.object(module.os,'getuid',return_value=502):
   with self.assertRaisesRegex(RuntimeError,'identity changed'):executor.owned_build_member(322)
  failed=SimpleNamespace(stdout='',returncode=2)
  with patch.object(module.subprocess,'run',return_value=failed):
   with self.assertRaisesRegex(RuntimeError,'inspection failed'):executor.owned_build_member(322)
 def test_zombie_group_member_is_not_reported_as_live_work(self):
  executor=self.executor();executor.build=SimpleNamespace(pid=321)
  roster=SimpleNamespace(stdout='321 321 502 Z\n322 321 502 S\n')
  with patch.object(module.subprocess,'run',return_value=roster),patch.object(module.os,'getuid',return_value=502):
   self.assertEqual(executor.groups(),[322])
 def test_foreign_group_member_fails_before_any_signal(self):
  executor=self.executor();executor.build=SimpleNamespace(pid=321)
  roster=SimpleNamespace(stdout='321 321 999999 S\n')
  with patch.object(module.subprocess,'run',return_value=roster), \
       patch.object(module.os,'kill',side_effect=AssertionError('must not signal foreign member')):
   with self.assertRaisesRegex(RuntimeError,'Foreign build process group'):executor.signal_build_members(module.signal.SIGTERM)

if __name__=='__main__':unittest.main()
