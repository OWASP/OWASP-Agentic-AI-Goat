import copy,unittest
import full_backend_auth_contract as c
class Admission(unittest.TestCase):
 def manifest(self):
  files={k:'0'*64 for k in c.REQUIRED|c.REVIEWED_MIGRATIONS};files.update(c.EMBEDDING_ASSETS);files.update(c.QUALIFIED_ADDITIONAL_MIGRATIONS)
  return dict(version=1,scope='full_backend_auth',files=files,symlinks={},directories=[])
 def test_exact_qualified_additions(self):
  self.assertEqual(len(c.QUALIFIED_ADDITIONAL_MIGRATIONS),4);c.validate_manifest(self.manifest())
 def test_each_wrong_or_missing_checksum_denies(self):
  for name in c.QUALIFIED_ADDITIONAL_MIGRATIONS:
   with self.subTest(name=name):
    m=self.manifest();m['files'][name]='f'*64
    with self.assertRaisesRegex(RuntimeError,'checksum'):c.validate_manifest(m)
    del m['files'][name]
    with self.assertRaises(RuntimeError):c.validate_manifest(m)
 def test_historical_qualified_pins_remain_exact(self):
  expected={
   'db/postgres/maintenance-migrations/0002_local_recovery.sql':'c2ae8481c0375ed278b5c872d8f9b442239fb31868d8feb9021d9fbf71f0a673',
   'db/postgres/maintenance-migrations/0003_canonical_inprocess_recovery.sql':'49b9a13f24727e729604a37264de247e962f7f1ad2c30f021c7045791f5b29b7',
   'db/postgres/workshop-migrations/secureshop_review/0027_policy_embedding_lineage.sql':'99d92c1bddc2bf40f8d480e9eecc860ce5a08794f442e34fdb0c2a66c68cd0d0',
  }
  self.assertEqual({k:c.QUALIFIED_ADDITIONAL_MIGRATIONS[k] for k in expected},expected)
 def test_ctf0123_exact_reviewed_checksum(self):
  self.assertEqual(c.QUALIFIED_ADDITIONAL_MIGRATIONS['db/postgres/identity-migrations/0123_ctf_canonical_admin_policy.sql'],'e0ceab31af4c5bb1aa9d31f56743cd70875b23669bf29ec277937f5d9d94c235')
 def test_unknown_and_unqualified0004_deny(self):
  for name in ['db/postgres/maintenance-migrations/0004_executable_recovery_admission.sql','db/postgres/workshop-migrations/secureshop_review/9999_unknown.sql']:
   m=self.manifest();m['files'][name]='a'*64
   with self.assertRaisesRegex(RuntimeError,'exact reviewed migration'):c.validate_manifest(m)
if __name__=='__main__':unittest.main()
