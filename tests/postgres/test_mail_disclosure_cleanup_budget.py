import unittest,time
from mail_disclosure_cleanup_budget import CleanupBudget
class CleanupTests(unittest.TestCase):
 def test_failure_continues_with_remaining_budget(self):
  ticks=[0];budget=CleanupBudget(2,clock=lambda:ticks[0]);seen=[]
  def failed():ticks[0]=1;raise RuntimeError('owned cleanup failed')
  with self.assertRaises(RuntimeError):budget.run(failed)
  budget.run(lambda:seen.append('next exact resource'))
  self.assertEqual(seen,['next exact resource']);ticks[0]=2
  with self.assertRaises(TimeoutError):budget.run(lambda:seen.append('must not run'))
  self.assertEqual(len(seen),1)
 def test_real_timeout_cannot_restart_budget_after_catch(self):
  budget=CleanupBudget(.03);seen=[]
  with self.assertRaises(TimeoutError):budget.run(lambda:time.sleep(.2))
  with self.assertRaises(TimeoutError):budget.run(lambda:seen.append(True))
  self.assertEqual(seen,[])
if __name__=='__main__':unittest.main()
