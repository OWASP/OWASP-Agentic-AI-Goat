import ast,pathlib,unittest
SOURCE=pathlib.Path(__file__).with_name('run-listings-integrated-isolated.py')
class SeedMode(unittest.TestCase):
 def test_closed_mode_rejects_rendered_combination_before_resources(self):
  import subprocess,sys
  p=subprocess.run([sys.executable,'-B',str(SOURCE),'--docker-host','unused','--mail-reply-seed-only','--mail-reply-rendered'],capture_output=True,text=True)
  self.assertNotEqual(p.returncode,0);self.assertIn('Seed-only and rendered reply modes are exclusive',p.stderr)
 def test_valid_seed_mode_uses_dependency_admission_before_resources(self):
  import subprocess,sys
  p=subprocess.run([sys.executable,'-B',str(SOURCE),'--docker-host','unused','--mail-reply-seed-only'],capture_output=True,text=True)
  self.assertNotEqual(p.returncode,0);self.assertIn('reviewed full dependency byte digest',p.stderr)
 def test_seed_rejects_production_assembly_with_other_required_flags(self):
  import subprocess,sys
  p=subprocess.run([sys.executable,'-B',str(SOURCE),'--docker-host','unused','--mail-reply-seed-only','--production-assembly','--mail-reply-dependency-byte-sha256','a'*64,'--node-binary','/dummy/node','--node-sha256','b'*64,'--node-version','v26.10.0','--dependency-hashes','{}'],capture_output=True,text=True)
  self.assertNotEqual(p.returncode,0);self.assertIn('Seed-only cannot use production assembly',p.stderr)
 def test_skip_paths_and_target_are_closed(self):
  tree=ast.parse(SOURCE.read_text());text=ast.unparse(tree)
  self.assertIn("'tests/postgres/secureshopMailReplySeed.native.js' if args.mail_reply_seed_only",text)
  self.assertIn('and (not args.mail_reply_seed_only)',text)
  self.assertIn('not (args.dpi_rendered or args.csrf_full_app or args.mail_reply_seed_only)',text)
  self.assertIn('timeout=480 if args.mail_reply_seed_only',text)
