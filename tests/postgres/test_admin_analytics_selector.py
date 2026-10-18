import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
s=importlib.util.spec_from_file_location('analytics_selector',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Selector(unittest.TestCase):
 def tearDown(self):m.configure_cohort('full')
 def test_only_analytics_has_separate_scope_and_pin(self):
  m.configure_cohort('analytics-only');self.assertEqual([s['name'] for s in m.SUITES],['adminProgressAnalytics']);self.assertEqual(m.SCOPE,'admin_progress_analytics_pg18');self.assertEqual(m.NODE_VERSION,'v26.10.0');self.assertEqual(len(m.database_plan('abcdef123456')),1);self.assertEqual(m.SUITES[0]['timeoutSeconds'],300);self.assertIsNone(m.SUITES[0]['gate'])
 def test_full_default_unchanged_and_unknown_rejected(self):
  m.configure_cohort('full');self.assertEqual(len(m.SUITES),4);self.assertEqual(m.SCOPE,m.FULL_SCOPE);self.assertEqual(m.NODE_VERSION,'v26.9.0');self.assertRaises(ValueError,m.configure_cohort,'browser-only')
