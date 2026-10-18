import importlib.util,pathlib,tempfile,unittest,os,json
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('archive',ROOT/'scripts/lib/archive-installed-history.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Archive(unittest.TestCase):
 def test_stream_roundtrip_symlink_not_followed_and_tamper(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   root=pathlib.Path(d)/'source';root.mkdir();(root/'file').write_bytes(b'original');os.chmod(root/'file',0o644);(root/'link').symlink_to('/nonexistent-private-target-never-read');archive=pathlib.Path(d)/'history.tar'
   result=m.capture(str(root),str(archive));self.assertTrue(result['verified']);self.assertEqual(archive.stat().st_mode&0o777,0o600)
   rows=[json.loads(x)for x in pathlib.Path(str(archive)+'.inventory.jsonl').read_text().splitlines()];self.assertTrue(any(x.get('link')=='/nonexistent-private-target-never-read'for x in rows));self.assertTrue(any(x['mode']==0o644 for x in rows))
   (root/'file').write_bytes(b'changed');self.assertRaises(ValueError,m.verify,str(root),str(archive),str(archive)+'.inventory.jsonl')
 def test_new_membership_and_replaced_directory_and_hardlink_rejected(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   root=pathlib.Path(d)/'source';root.mkdir();(root/'sub').mkdir();(root/'sub/file').write_bytes(b'original');target=str(pathlib.Path(d)/'history.tar');m.capture(str(root),target)
   (root/'added').write_text('late');self.assertRaisesRegex(ValueError,'MEMBERSHIP',m.verify,str(root),target,target+'.inventory.jsonl');(root/'added').unlink()
   (root/'sub').rename(root/'old');(root/'sub').mkdir();(root/'sub/file').write_bytes(b'original');self.assertRaisesRegex(ValueError,'SOURCE_CHANGED',m.verify,str(root),target,target+'.inventory.jsonl')
   os.link(root/'sub/file',root/'hardlink');self.assertRaisesRegex(ValueError,'HARDLINK',m.entry,str(root),'hardlink')
 def test_bound_and_existing_output_refuse(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'backups/private-recovery') as d:
   root=pathlib.Path(d)/'source';root.mkdir();(root/'file').write_bytes(b'abc');target=str(pathlib.Path(d)/'history.tar');self.assertRaises(ValueError,m.capture,str(root),target,1);self.assertRaises(FileExistsError,m.capture,str(root),target)
if __name__=='__main__':unittest.main()
