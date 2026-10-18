"""Rendered client admission remains closed; no browser or process is started."""
import unittest
from unittest.mock import patch
import full_backend_auth_contract as contract


class RenderedInventory(unittest.TestCase):
 def manifest(self):
  return {'files': {p: '0' * 64 for p in contract.RENDERED_REQUIRED | contract.RENDERED_SOURCE_FILES}}

 def validate(self, manifest):
  with patch.object(contract.Path, 'is_absolute', return_value=True), \
       patch.object(contract.Path, 'is_file', return_value=True), \
       patch.object(contract.Path, 'is_symlink', return_value=False), \
       patch.object(contract.Path, 'resolve', return_value=contract.Path('/controlled/browser')), \
       patch.object(contract.os, 'access', return_value=True), \
       patch.object(contract, 'digest', return_value=contract.BROWSER_SHA256):
   contract.validate_rendered(manifest, True, '/controlled/browser', contract.BROWSER_SHA256)

 def test_complete_retained_client_inventory_is_admitted(self):
  self.assertEqual(len([p for p in contract.RENDERED_SOURCE_FILES if p.startswith(('client/src/', 'client/public/'))]), 329)
  self.validate(self.manifest())

 def test_missing_inherited_client_file_is_denied(self):
  manifest = self.manifest()
  del manifest['files']['client/src/components/CtfRecoveryNotice.js']
  with self.assertRaisesRegex(RuntimeError, 'rendered source closure missing'):
   self.validate(manifest)

 def test_arbitrary_extra_client_file_is_denied(self):
  for path in ['client/src/unreviewed.js', 'client/public/unreviewed.svg']:
   with self.subTest(path=path):
    manifest = self.manifest()
    manifest['files'][path] = '1' * 64
    with self.assertRaisesRegex(RuntimeError, 'unexpected client source inventory'):
     self.validate(manifest)

 def test_each_reviewed_active_family_file_is_required(self):
  for path in ['client/src/utils/adminExerciseLoading.js', 'client/src/pages/ComprehensiveAdminDashboard.exerciseLoading.test.js']:
   with self.subTest(path=path):
    self.assertIn(path, contract.RENDERED_SOURCE_FILES)
    manifest=self.manifest();del manifest['files'][path]
    with self.assertRaisesRegex(RuntimeError, 'rendered source closure missing'):
     self.validate(manifest)

 def test_each_platform_authority_file_is_required(self):
  for path in ['client/src/utils/platformAdmin.js','client/src/utils/platformAdmin.test.js','client/src/App.platformAdmin.test.jsx']:
   with self.subTest(path=path):
    self.assertIn(path,contract.RENDERED_SOURCE_FILES)
    manifest=self.manifest();del manifest['files'][path]
    with self.assertRaisesRegex(RuntimeError,'rendered source closure missing'):
     self.validate(manifest)


if __name__ == '__main__':
 unittest.main()
