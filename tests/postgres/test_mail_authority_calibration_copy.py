import hashlib,tempfile,unittest
from pathlib import Path
from mail_authority_calibration_copy import verify_files,verify_retained
class CalibrationCopyTests(unittest.TestCase):
 def test_exact_closed_inventory_and_content(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'server').mkdir();p=root/'server/a.js';p.write_bytes(b'approved')
   rows={'server/a.js':{'kind':'file','bytes':8,'sha256':hashlib.sha256(b'approved').hexdigest()}}
   self.assertEqual(verify_files(root,rows),rows)
   p.write_bytes(b'changed!')
   with self.assertRaises(RuntimeError):verify_files(root,rows)
 def test_omitted_private_and_generated_paths_cannot_sneak_into_copy(self):
  for name in ['server/platform_secrets.json','server/__pycache__/extra.pyc']:
   with self.subTest(name=name),tempfile.TemporaryDirectory() as d:
    root=Path(d);p=root/name;p.parent.mkdir(parents=True);p.write_bytes(b'unreviewed')
    with self.assertRaisesRegex(RuntimeError,'absent from reviewed'):verify_files(root,{})
 def test_retained_input_identity_is_not_redefined_by_post_copy_hash(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'retained.json';p.write_bytes(b'original');expected=hashlib.sha256(b'original').hexdigest();verify_retained(p,expected);p.write_bytes(b'drift')
   with self.assertRaises(RuntimeError):verify_retained(p,expected)
 def test_unexpected_symlink_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'unexpected').symlink_to('/tmp',target_is_directory=True)
   with self.assertRaises(RuntimeError):verify_files(root,{})
if __name__=='__main__':unittest.main()
