"""Resource-free owned-copy permissions regression; no Docker or database."""
import ast
import os
from pathlib import Path
import shutil
import tempfile
import unittest

LAUNCHER=Path(__file__).with_name('run-policy-lineage-isolated.py')
tree=ast.parse(LAUNCHER.read_text())
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='prepare_owned_copy')
scope={'os':os,'Path':Path}
exec(compile(ast.Module(body=[function],type_ignores=[]),str(LAUNCHER),'exec'),scope)
prepare=scope['prepare_owned_copy']

class Preparation(unittest.TestCase):
 def test_readonly_copy_writable_without_touching_source_or_links(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp); frozen=root/'frozen'; frozen.mkdir(); nested=frozen/'migrations';nested.mkdir()
   for i in range(1,28):(nested/f'{i:04d}_test.sql').write_text(str(i))
   for p in nested.iterdir():p.chmod(0o444)
   nested.chmod(0o555);frozen.chmod(0o555)
   owned=root/'owned';owned.mkdir(mode=0o700);workspace=owned/'source';shutil.copytree(frozen,workspace)
   external=root/'external';external.mkdir();external.chmod(0o555)
   workspace.chmod(0o755);(workspace/'external').symlink_to(external,target_is_directory=True);workspace.chmod(0o555)
   prepare(owned,workspace)
   (workspace/'node_modules').symlink_to(external,target_is_directory=True)
   prior=workspace/'prior';shutil.copytree(workspace/'migrations',prior);prior.chmod(0o700)
   for p in prior.iterdir():
    if int(p.name[:4])>18:p.unlink()
   self.assertEqual(len(list(prior.iterdir())),18)
   self.assertEqual(external.stat().st_mode&0o777,0o555)
   self.assertEqual(frozen.stat().st_mode&0o777,0o555)
   self.assertEqual(nested.stat().st_mode&0o777,0o555)
   self.assertEqual((workspace/'migrations/0001_test.sql').stat().st_mode&0o777,0o444)
   frozen.chmod(0o755);nested.chmod(0o755);external.chmod(0o755)
 def test_rejects_external_or_symlink_workspace(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);owned=root/'owned';owned.mkdir();other=root/'other';other.mkdir()
   with self.assertRaises(RuntimeError):prepare(owned,other)
   link=owned/'source';link.symlink_to(other,target_is_directory=True)
   with self.assertRaises(RuntimeError):prepare(owned,link)
 def test_launcher_prepares_before_symlink_and_migration_deletion(self):
  source=LAUNCHER.read_text()
  self.assertLess(source.index(' prepare_owned_copy(root,workspace)'),source.index(" (workspace/'node_modules').symlink_to"))
  self.assertLess(source.index(' prior_dir.chmod(0o700)'),source.index('item.unlink()'))

if __name__=='__main__':unittest.main()
