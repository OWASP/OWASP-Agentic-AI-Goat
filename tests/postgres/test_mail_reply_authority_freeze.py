import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import mail_reply_authority_freeze as f
ROOT=Path(__file__).resolve().parents[2]
class Integrity(unittest.TestCase):
 def fixture(self,root):
  (root/'scripts/lib').mkdir(parents=True);(root/'scripts/lib/isolated-source-copy.js').write_bytes((ROOT/'scripts/lib/isolated-source-copy.js').read_bytes())
  (root/'server/config').mkdir(parents=True);(root/f.CURRICULUM).write_text(f.NEEDLE+'\n')
  (root/'node_modules/pkg').mkdir(parents=True);(root/'node_modules/pkg/index.js').write_text('dependency bytes')
  (root/'node_modules/.package-lock.json').write_text('{}')
  (root/'package-lock.json').write_text('{}');(root/'package.json').write_text('{}')
  (root/'__pycache__').mkdir();(root/'__pycache__/noise.pyc').write_bytes(b'ignored')
 def test_full_bytes_and_exact_candidate_delta(self):
  with tempfile.TemporaryDirectory() as tmp:
   source=Path(tmp)/'source';source.mkdir();self.fixture(source)
   rows=f.inventory(source);deps=f.dependencies(source);sd=f.digest(rows);dd=f.digest(deps)
   for p in source.rglob('*'):
    if p.is_file():p.chmod(0o400)
   dest=Path(tmp)/'copy';f.copy(source,dest);(dest/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
   self.assertFalse((dest/'__pycache__').exists());f.verify(dest,sd,dd)
   expected,data=f.stage_expected(rows,source);target=dest/f.CURRICULUM;target.chmod(0o600);target.write_bytes(data);target.chmod(0o400)
   f.verify(dest,f.digest(expected),dd);f.verify(source,sd,dd)
   target.chmod(0o600);target.write_bytes(data+b'\n')
   with self.assertRaisesRegex(RuntimeError,'source byte'):f.verify(dest,f.digest(expected),dd)
 def test_dependency_drift_missing_and_symlink_target(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.fixture(root);(root/'node_modules/link').symlink_to('pkg/index.js')
   sd=f.digest(f.inventory(root));dd=f.digest(f.dependencies(root));file=root/'node_modules/pkg/index.js';file.write_text('changed')
   with self.assertRaisesRegex(RuntimeError,'dependency byte'):f.verify(root,sd,dd)
   file.write_text('dependency bytes');(root/'node_modules/link').unlink();(root/'node_modules/link').symlink_to('pkg/other.js')
   with self.assertRaisesRegex(RuntimeError,'dependency byte'):f.verify(root,sd,dd)
   (root/'node_modules/link').unlink();file.unlink()
   with self.assertRaisesRegex(RuntimeError,'dependency byte'):f.verify(root,sd,dd)
 def test_missing_reviewed_digest_rejects_before_docker_or_temp_root(self):
  result=subprocess.run(['python3','-B',str(ROOT/'tests/postgres/run-bound-mail-isolated.py'),'--mode','reply-authority','--docker-host','unused'],capture_output=True,text=True)
  self.assertEqual(result.returncode,2);self.assertIn('requires explicit reviewed',result.stderr)
 def test_pin_mismatch_closed(self):
  with patch.object(f,'sha',side_effect=[f.NODE_SHA,f.DOCKER_SHA]):f.check_pins('node','docker',f.DAEMON_ID)
  for values,daemon in [(['bad',f.DOCKER_SHA],f.DAEMON_ID),([f.NODE_SHA,'bad'],f.DAEMON_ID),([f.NODE_SHA,f.DOCKER_SHA],'other')]:
   with patch.object(f,'sha',side_effect=values),self.assertRaisesRegex(RuntimeError,'identity mismatch'):f.check_pins('node','docker',daemon)
 def test_staging_requires_exact_unique_original(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);self.fixture(root);(root/f.CURRICULUM).write_text(f.NEEDLE*2)
   with self.assertRaisesRegex(RuntimeError,'staging'):f.stage_expected(f.inventory(root),root)
if __name__=='__main__':unittest.main()
