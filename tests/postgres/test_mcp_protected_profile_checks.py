import unittest
from mcp_protected_profile_checks import expected_profiles, assert_enforcing, assert_absent
class ProfileChecks(unittest.TestCase):
 def setUp(self):
  self.parent='dvaia-mcp-sandbox-123456abcdef'
  self.expected=expected_profiles('profile "'+self.parent+'" flags=(x) {\n profile bwrap flags=(x) {\n }\n}',self.parent)
 def test_exact_tree(self):
  listing='other (enforce)\n'+self.parent+'//bwrap (enforce)\n'+self.parent+' (enforce)\n'
  self.assertEqual(len(assert_enforcing(listing,self.expected,self.parent)),2)
 def test_missing_unknown_mode_and_duplicate_rejected(self):
  valid=self.parent+' (enforce)\n'+self.parent+'//bwrap (enforce)'
  for text in [self.parent+' (enforce)',valid.replace('(enforce)','(complain)',1),valid+'\n'+self.parent+'//unknown (enforce)',valid+'\n'+self.parent+' (enforce)']:
   with self.assertRaises(ValueError):assert_enforcing(text,self.expected,self.parent)
 def test_cleanup_rejects_orphan_child(self):
  with self.assertRaises(ValueError):assert_absent(self.parent+'//bwrap (enforce)',self.expected,self.parent)
  self.assertEqual(len(assert_absent('unrelated (enforce)',self.expected,self.parent)),2)
 def test_unknown_declaration_rejected(self):
  with self.assertRaises(ValueError):expected_profiles('profile "'+self.parent+'" flags=(x) {\n profile unknown flags=(x) {',self.parent)
if __name__=='__main__':unittest.main()
