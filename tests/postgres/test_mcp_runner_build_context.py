"""Generated fixtures only; no repository labfs contents read or builds run."""
import json
from pathlib import Path
import tempfile
import unittest
from mcp_runner_build_context import FILES,prepare_context,sha

class Context(unittest.TestCase):
 def fixture(self,root):
  source=root/'source';source.mkdir();hashes={}
  for name in FILES:
   p=source/name;p.parent.mkdir(parents=True,exist_ok=True);data=('owned synthetic '+name).encode();p.write_bytes(data);hashes[name]=sha(data)
  return source,hashes
 def thaw(self,path):
  if path.exists():
   path.chmod(0o700)
   for p in path.rglob('*'):
    if p.is_dir():p.chmod(0o700)
 def test_deterministic_detached_exact_context(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();source,hashes=self.fixture(root)
   (source/'private.env').write_text('must never copy')
   outputs=[]
   try:
    for name in ['one','two']:
     target=root/name;target.mkdir(mode=0o700);outputs.append(prepare_context(source,target,hashes))
    self.assertEqual(outputs[0]['contextSha256'],outputs[1]['contextSha256'])
    for result in outputs:
     context=Path(result['context']);manifest=json.loads(Path(result['manifest']).read_text())
     self.assertEqual({p.relative_to(context).as_posix() for p in context.rglob('*') if p.is_file()},FILES)
     for name in FILES:
      p=context/name;self.assertEqual(p.stat().st_nlink,1);self.assertNotEqual(p.stat().st_ino,(source/name).stat().st_ino)
      self.assertEqual(p.stat().st_mtime,0);self.assertEqual(p.stat().st_mode&0o777,manifest['files'][name]['mode'])
   finally:
    self.thaw(root/'one');self.thaw(root/'two')
 def test_missing_hash_changed_bytes_and_symlinks_reject_before_copy(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();source,hashes=self.fixture(root);target=root/'target';target.mkdir()
   with self.assertRaises(RuntimeError):prepare_context(source,target,{})
   p=source/'index.js';original=p.read_bytes();p.write_bytes(b'changed')
   with self.assertRaises(RuntimeError):prepare_context(source,target,hashes)
   p.unlink();outside=root/'external';outside.write_bytes(original);p.symlink_to(outside)
   with self.assertRaises(RuntimeError):prepare_context(source,target,hashes)
   self.assertEqual(list(target.iterdir()),[])
 def test_public_destination_modes_and_parent_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();source,hashes=self.fixture(root);target=root/'target';target.mkdir(mode=0o700)
   for mode in [0o755,0o777]:
    target.chmod(mode)
    with self.assertRaises(RuntimeError):prepare_context(source,target,hashes)
   target.chmod(0o700)
   parent=source/'labfs/etc';moved=root/'moved';parent.rename(moved);parent.symlink_to(moved,target_is_directory=True)
   with self.assertRaises(RuntimeError):prepare_context(source,target,hashes)
   self.assertEqual(list(target.iterdir()),[])
 def test_private_or_extra_inputs_cannot_be_added_to_reviewed_manifest(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary).resolve();source,hashes=self.fixture(root);target=root/'target';target.mkdir()
   with self.assertRaises(RuntimeError):prepare_context(source,target,{**hashes,'.env':'a'*64})
if __name__=='__main__':unittest.main()
