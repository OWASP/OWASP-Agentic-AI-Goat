import unittest,tempfile
from pathlib import Path
from types import SimpleNamespace
from ctf_setup_sidecars import build_context,validate_sidecar_args,OwnedSidecars
class Controls(unittest.TestCase):
 def test_exact_copy_inventory_includes_nested_modes_and_rejects_links_ignore(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'Dockerfile').write_text('FROM pinned\nCOPY nested/a /app/a\n');(p/'nested').mkdir();(p/'nested/a').write_text('a');(p/'unrelated').write_text('not copied')
   a=build_context(p);self.assertIn('nested/a',a['entries']);self.assertTrue(a['entries']['nested']['directory']);self.assertNotIn('unrelated',a['entries'])
   (p/'nested/a').chmod(0o400);self.assertNotEqual(a,build_context(p))
   (p/'nested/link').symlink_to('a');(p/'Dockerfile').write_text('FROM pinned\nCOPY nested /app\n')
   with self.assertRaisesRegex(RuntimeError,'symlink'):build_context(p)
   (p/'nested/link').unlink();(p/'.dockerignore').write_text('nested')
   with self.assertRaisesRegex(RuntimeError,'ignore'):build_context(p)
 def test_closed_scenario_rejects_partial_or_cross_mode_before_resources(self):
  with self.assertRaises(RuntimeError):validate_sidecar_args(SimpleNamespace(scenario='ctf-populated'))
  with self.assertRaises(RuntimeError):validate_sidecar_args(SimpleNamespace(scenario='ctf-fresh',sandbox_image_id='unexpected'))
  validate_sidecar_args(SimpleNamespace(scenario='ctf-fresh'))
 def test_cleanup_continues_both_containers_but_retains_profile_after_failure(self):
  s=OwnedSidecars(SimpleNamespace(docker_daemon='owned'),'.','.', 'a'*32,lambda _:None,lambda _:None)
  s.rows.extend([{'name':'one','image':'image','id':'1'},{'name':'two','image':'image','id':'2'}]);s.remote_owned=True;s.profile_attempted=True
  calls=[]
  def bounded(action):calls.append(1);raise TimeoutError('controlled')
  s.remote_command=lambda _:self.fail('must not unload profile while container absence is unknown')
  with self.assertRaisesRegex(RuntimeError,'incomplete'):s.cleanup(bounded)
  self.assertEqual(len(calls),2);self.assertFalse(s.state['cleanupComplete'])
if __name__=='__main__':unittest.main()
