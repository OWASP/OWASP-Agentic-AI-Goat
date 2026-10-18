import unittest
from sql_nosql_route_contract import cohort_timeout_seconds
from sql_nosql_package_contract import REQUIRED
class Controls(unittest.TestCase):
 def test_opt_in_family_budget(self):
  for ids,extra in [(('sqli_5',),300),(('nosqli_8',),600),(('sqli_5','nosqli_8'),900)]:
   self.assertEqual(cohort_timeout_seconds(ids,observation_controls=True)-cohort_timeout_seconds(ids),extra)
 def test_required_helper(self):
  self.assertIn('tests/fixtures/sqlNoSqlObservationSequence.js',REQUIRED)
