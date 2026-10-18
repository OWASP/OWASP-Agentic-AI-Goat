import copy
import unittest
from authenticated_run_ownership_contract import REQUIRED, REVIEWED_AGENTS_MIGRATIONS, validate_manifest

class Admission(unittest.TestCase):
 def fixture(self):
  return dict(version=1,scope='authenticated_agent_run_ownership',files={key:'a'*64 for key in REQUIRED | REVIEWED_AGENTS_MIGRATIONS},symlinks={},directories=[])
 def test_admission(self):
  validate_manifest(self.fixture())
 def test_reject_scope_and_missing_closure(self):
  for change in [lambda m:m.update(scope='sql_nosql_route_actual8b'),lambda m:m['files'].pop('server/middleware/postgresAdminAuth.js')]:
   manifest=self.fixture();change(manifest)
   with self.assertRaises(RuntimeError):validate_manifest(manifest)
 def test_reject_unreviewed_migrations(self):
  for filename in ['db/postgres/identity-migrations/0062_unreviewed.sql','db/postgres/workshop-migrations/nova/0001_schema.sql','db/postgres/workshop-migrations/secureshop_agents/0014_unreviewed.sql']:
   manifest=self.fixture();manifest['files'][filename]='b'*64
   with self.assertRaises(RuntimeError):validate_manifest(manifest)

if __name__=='__main__':unittest.main()
