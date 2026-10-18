"""Pure closed-profile admission controls; no processes or database operations."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
import full_backend_auth_contract as c

class Admission(unittest.TestCase):
    def manifest(self):
        files={name:'a'*64 for name in c.REQUIRED|c.REVIEWED_MIGRATIONS}
        files.update(c.EMBEDDING_ASSETS);files.update(c.QUALIFIED_ADDITIONAL_MIGRATIONS)
        return {'version':1,'scope':'full_backend_auth','files':files,'directories':{},'symlinks':{}}
    def sql_digest(self,m):
        sql={k:v for k,v in m['files'].items() if k.startswith(('db/postgres/identity-migrations/','db/postgres/workshop-migrations/','db/postgres/maintenance-migrations/'))}
        return hashlib.sha256(json.dumps(sql,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def test_retained_pin_and_unknown_profile(self):
        self.assertEqual(c.DPI_PHASE_A_MIGRATION_DIGEST,'bd38b2eb359ca3d611b683af0394b06da391f65f1b39b5185d28f3beaec72900')
        with self.assertRaises(RuntimeError):c.validate_manifest(self.manifest(),profile='anything')
    def test_default_policy_unchanged(self):
        m=self.manifest();self.assertIs(c.validate_manifest(m),m)
        del m['files'][next(iter(c.QUALIFIED_ADDITIONAL_MIGRATIONS))]
        with self.assertRaises(RuntimeError):c.validate_manifest(m)
    def test_phase_only_exact_sql_bytes_and_set(self):
        m=self.manifest()
        for name in c.QUALIFIED_ADDITIONAL_MIGRATIONS:m['files'].pop(name)
        with patch.object(c,'DPI_PHASE_A_MIGRATION_DIGEST',self.sql_digest(m)):
            self.assertIs(c.validate_manifest(m,profile='dpi-technique-phase-a'),m)
            for mutation in ('missing','wrong','extra'):
                bad=copy.deepcopy(m);key=next(k for k in bad['files'] if k.startswith('db/postgres/identity-migrations/'))
                if mutation=='missing':del bad['files'][key]
                elif mutation=='wrong':bad['files'][key]='b'*64
                else:bad['files']['db/postgres/maintenance-migrations/0004_unrelated.sql']='c'*64
                with self.assertRaises(RuntimeError):c.validate_manifest(bad,profile='dpi-technique-phase-a')
    def test_profile_still_requires_source_and_cache(self):
        m=self.manifest()
        with patch.object(c,'DPI_PHASE_A_MIGRATION_DIGEST',self.sql_digest(m)):
            bad=copy.deepcopy(m);del bad['files']['package.json']
            with self.assertRaises(RuntimeError):c.validate_manifest(bad,profile='dpi-technique-phase-a')
            bad=copy.deepcopy(m);bad['files'][next(iter(c.EMBEDDING_ASSETS))]='b'*64
            with self.assertRaises(RuntimeError):c.validate_manifest(bad,profile='dpi-technique-phase-a')

if __name__=='__main__':unittest.main()
