import pathlib,signal,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from mcp_owned_runner_upgrade_safety import OwnedPauseSet,smoke_login_payload,validate_qualified_objectives,validate_recovery

class RunnerUpgradeSafetyTests(unittest.TestCase):
 def test_partial_pause_is_owned_and_resumed(self):
  calls=[];pause=OwnedPauseSet()
  pause.stop(11,lambda pid,sig:calls.append((pid,sig)))
  with self.assertRaises(OSError):pause.stop(22,lambda _pid,_sig:(_ for _ in ()).throw(OSError('denied')))
  self.assertEqual(pause.stopped,[11]);self.assertEqual(pause.resume_all(lambda pid,sig:calls.append((pid,sig))),[])
  self.assertEqual(calls,[(11,signal.SIGSTOP),(11,signal.SIGCONT)])
 def test_stale_health_cannot_prove_replacement(self):
  with self.assertRaises(RuntimeError):validate_recovery(prior_pid=31,candidate_pid=31,healthy=True,replacement_required=True)
  self.assertEqual(validate_recovery(prior_pid=31,candidate_pid=32,healthy=True,replacement_required=True),32)
 def test_no_replacement_path_requires_exact_resumed_process(self):
  self.assertEqual(validate_recovery(prior_pid=41,candidate_pid=41,healthy=True,replacement_required=False),41)
  with self.assertRaises(RuntimeError):validate_recovery(prior_pid=41,candidate_pid=42,healthy=True,replacement_required=False)
 def test_standard_generated_administrator_shape_is_projected_to_login(self):
  self.assertEqual(smoke_login_payload({'username':'admin','email':'admin@example.invalid','password':'private'}),
                   {'username':'admin','password':'private'})
  with self.assertRaises(RuntimeError):smoke_login_payload({'username':'admin','email':'x','password':'private','token':'bad'})
 def test_qualified_objectives_require_exact_ordered_five(self):
  expected=['mcp_cmd_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_audit_gap']
  self.assertEqual(validate_qualified_objectives(expected),5)
  with self.assertRaises(RuntimeError):validate_qualified_objectives(expected[:-1]+['mcp_tool_poisoning'])
if __name__=='__main__':unittest.main()
