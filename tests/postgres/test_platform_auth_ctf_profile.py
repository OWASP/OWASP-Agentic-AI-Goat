import unittest,importlib.util
from pathlib import Path
from unittest.mock import patch
import platform_auth_ctf_profile as p
class Profile(unittest.TestCase):
 def test_three_distinct_owned_databases(self):
  values=p.plan('a'*12);self.assertEqual(len(set(values.values())),3)
  self.assertTrue(values['fresh'].startswith('owasp_ai_goat_test_ctf_adminpolicy_'))
 def test_environment_does_not_inherit(self):
  with patch.dict('os.environ',{'IDENTITY_DATABASE_URL':'private','HOME':'unowned'}):
   e=p.environment('/owned',54321,p.plan('b'*12),'ctf')
  self.assertNotIn('IDENTITY_DATABASE_URL',e);self.assertEqual(e['HOME'],'/owned');self.assertEqual(e['CTF_CANONICAL_ADMIN_ISOLATED'],'1');self.assertNotIn('PG_HTTP_TEST_RUNTIME_URL',e)
 def test_closed_duplicate_selector_denies(self):
  with self.assertRaises(ValueError):p.arguments(['--cohort','platform-auth-ctf0123','--cohort','platform-auth-ctf0123'])
 def test_explicit_bounds(self):
  self.assertEqual([s[2] for s in p.SUITES],[300,180]);self.assertEqual(p.LIMIT,64*1024*1024)
 def test_historical_selector_unchanged_and_duplicate_denied(self):
  spec=importlib.util.spec_from_file_location('legacy',Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  self.assertIsNone(m.current_profile_arguments(['--cohort','full']));self.assertEqual(m.FULL_NODE_VERSION,'v26.9.0')
  with self.assertRaises(RuntimeError):m.current_profile_arguments(['--cohort','full','--cohort','platform-auth-ctf0123'])
class Cleanup(unittest.TestCase):
 def test_unproved_group_retains_cluster_and_failure_is_terminal(self):
  class Owned:
   def cleanup(self):raise RuntimeError('unknown group')
  class Budget:
   def run(self,fn):return fn()
  removed=[];r=p.cleanup_resources(Owned(),lambda:removed.append(True),lambda:{'Id':'owned'},Budget())
  self.assertFalse(r['processes']);self.assertFalse(r['container']);self.assertFalse(r['absence']);self.assertEqual(removed,[])
 def test_shared_exhausted_budget_prevents_later_mutation(self):
  class Owned:
   def cleanup(self):pass
  class Budget:
   def __init__(self):self.calls=0
   def run(self,fn):
    self.calls+=1
    if self.calls>1:raise TimeoutError('spent')
    return fn()
  removed=[];r=p.cleanup_resources(Owned(),lambda:removed.append(True),lambda:None,Budget())
  self.assertTrue(r['processes']);self.assertFalse(r['container']);self.assertFalse(r['absence']);self.assertEqual(removed,[])
 def test_success_requires_independent_absence_observation(self):
  class Owned:
   def cleanup(self):pass
  class Budget:
   def run(self,fn):return fn()
  r=p.cleanup_resources(Owned(),lambda:None,lambda:{'Id':'still there'},Budget());self.assertFalse(r['absence'])

class LogBudget(unittest.TestCase):
 def test_fast_exited_child_two_sublimit_logs_deny_before_read(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  a=Mock();a.stat.return_value.st_size=40*1024*1024
  b=Mock();b.stat.return_value.st_size=40*1024*1024
  root=Mock();root.glob.return_value=[a,b]
  with self.assertRaisesRegex(RuntimeError,'Log limit'):p.verify_exited_suite(SimpleNamespace(returncode=0),root,b)
  b.read_text.assert_not_called()
 def test_exact_aggregate_limit_accepts_valid_exited_tap(self):
  from types import SimpleNamespace
  from unittest.mock import Mock
  a=Mock();a.stat.return_value.st_size=p.LIMIT//2
  b=Mock();b.stat.return_value.st_size=p.LIMIT//2;b.read_text.return_value='# pass 1\n# fail 0\n# skipped 0\n'
  root=Mock();root.glob.return_value=[a,b]
  p.verify_exited_suite(SimpleNamespace(returncode=0),root,b)

if __name__=='__main__':unittest.main()
