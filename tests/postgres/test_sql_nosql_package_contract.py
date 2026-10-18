"""Pure filesystem contracts; no native launcher, executable or network calls."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from sql_nosql_package_contract import (REQUIRED, IDENTITY_MIGRATION_IDS, digest, inventory,
                                        validate_package, prepare_evidence_root)

class Contract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.package = self.base / 'package'; self.source = self.package / 'source'
        self.source.mkdir(parents=True)
        for relative in REQUIRED:
            path = self.source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('controlled fixture\n')
        migration_dir = self.source / 'db/postgres/identity-migrations'
        existing_ids = {int(path.name[:4]) for path in migration_dir.glob('*.sql')}
        for sequence in IDENTITY_MIGRATION_IDS - existing_ids:
            (migration_dir / f'{sequence:04d}_reviewed.sql').write_text('controlled migration\n')
        self.node = self.base / 'node'; self.node.write_text('never execute\n'); self.node.chmod(0o500)
        self.manifest = self.package / 'manifest.json'
        self.freeze()

    def tearDown(self):
        for entry in self.base.rglob('*'):
            if not entry.is_symlink(): entry.chmod(0o700)
        self.temp.cleanup()

    def freeze(self):
        for entry in self.source.rglob('*'):
            if not entry.is_symlink(): entry.chmod(0o500 if entry.is_dir() else 0o400)
        self.source.chmod(0o500)
        value = dict(version=1, scope='sql_nosql_route_actual8b', **inventory(self.source))
        self.package.chmod(0o700)
        if self.manifest.exists(): self.manifest.chmod(0o600)
        self.manifest.write_text(json.dumps(value)); self.manifest.chmod(0o400); self.package.chmod(0o500)
        self.hash = digest(self.manifest)

    def check(self):
        return validate_package(self.source, self.manifest, self.hash, self.node, digest(self.node))

    def test_complete_manifest_and_node_hash(self):
        self.check()
        with self.assertRaises(RuntimeError): validate_package(self.source,self.manifest,'0'*64,self.node,digest(self.node))
        with self.assertRaises(RuntimeError): validate_package(self.source,self.manifest,self.hash,self.node,'0'*64)

    def test_unlisted_missing_and_changed_source_rejected(self):
        target = self.source/'package.json'; target.chmod(0o600)
        with self.assertRaises(RuntimeError): self.check()
        target.write_text('modified'); target.chmod(0o400)
        with self.assertRaises(RuntimeError): self.check()
        self.freeze(); self.check()
        target.parent.chmod(0o700); target.unlink(); target.parent.chmod(0o500)
        self.freeze()
        with self.assertRaises(RuntimeError): self.check()

    def test_conditional_lifecycle_fixtures_are_required_before_launch(self):
        for name in ['sqlNoSqlResetQualification.js', 'sqlNoSqlFixedSessionQualification.js']:
            target = self.source / 'tests/fixtures' / name
            target.parent.chmod(0o700); target.unlink(); target.parent.chmod(0o500)
            self.freeze()
            with self.assertRaisesRegex(RuntimeError, 'source closure missing'):
                self.check()
            target.parent.chmod(0o700); target.write_text('controlled fixture'); target.parent.chmod(0o500)
            self.freeze(); self.check()

    def test_current_catalog_curriculum_dependency_is_required_before_launch(self):
        target = self.source / 'server/config/legacyFileSsiCurriculum.js'
        target.parent.chmod(0o700); target.unlink(); target.parent.chmod(0o500)
        self.freeze()
        with self.assertRaisesRegex(RuntimeError, 'source closure missing'):
            self.check()

    def test_judgment_repository_lazy_binding_dependencies_are_required_before_launch(self):
        for relative in ['server/database/postgres/xssJudgmentBindingRepository.js',
                         'server/agent-runtime/durableGeneration.js']:
            target = self.source / relative
            target.parent.chmod(0o700); target.unlink(); target.parent.chmod(0o500)
            self.freeze()
            with self.assertRaisesRegex(RuntimeError, 'source closure missing'):
                self.check()
            target.parent.chmod(0o700); target.write_text('controlled fixture'); target.parent.chmod(0o500)
            self.freeze(); self.check()

    def test_new_transitive_fixture_import_cannot_be_omitted_from_valid_manifest(self):
        entry = self.source / 'tests/postgres/sqlNoSqlRoute.integration.test.js'
        entry.chmod(0o600); entry.write_text("if (false) require('../fixtures/nestedQualification');")
        self.freeze()
        with self.assertRaisesRegex(RuntimeError, 'relative JavaScript dependency missing'):
            self.check()
        nested = self.source / 'tests/fixtures/nestedQualification.js'
        nested.parent.chmod(0o700); nested.write_text("require('./nestedDependency');")
        self.freeze()
        with self.assertRaisesRegex(RuntimeError, 'relative JavaScript dependency missing'):
            self.check()
        dependency = nested.with_name('nestedDependency.js')
        dependency.parent.chmod(0o700); dependency.write_text('module.exports = {};')
        self.freeze(); self.check()

    def test_lazy_production_dependency_cannot_be_omitted_from_valid_manifest(self):
        graph = self.source / 'server/agent-runtime/workshopGraph.js'
        entry = self.source / 'tests/postgres/sqlNoSqlRoute.integration.test.js'
        entry.chmod(0o600); entry.write_text("require('../../server/agent-runtime/workshopGraph');")
        graph.chmod(0o600); graph.write_text("if (false) require('./omittedLazyDependency');")
        self.freeze()
        with self.assertRaisesRegex(RuntimeError, 'relative JavaScript dependency missing'):
            self.check()

    def test_extra_file_or_symlink_cannot_hide_from_inventory(self):
        self.source.chmod(0o700); (self.source/'extra').write_text('extra'); (self.source/'extra').chmod(0o400); self.source.chmod(0o500)
        with self.assertRaises(RuntimeError): self.check()
        dep=self.source/'node_modules';dep.chmod(0o700)
        (dep/'outside').symlink_to('../../../node');dep.chmod(0o500)
        with self.assertRaises(RuntimeError): self.freeze()

    def test_internal_dependency_links_permitted_and_exact(self):
        dep=self.source/'node_modules';dep.chmod(0o700)
        (dep/'pg-link').symlink_to('pg');dep.chmod(0o500)
        self.freeze();self.check()
        dep.chmod(0o700);(dep/'pg-link').unlink();(dep/'pg-link').symlink_to('@langchain/ollama');dep.chmod(0o500)
        with self.assertRaises(RuntimeError):self.check()

    def test_private_files_and_later_migrations_rejected(self):
        self.source.chmod(0o700);(self.source/'.env').write_text('do not include');(self.source/'.env').chmod(0o400);self.source.chmod(0o500)
        with self.assertRaises(RuntimeError):self.freeze()
        self.source.chmod(0o700);(self.source/'.env').unlink();self.source.chmod(0o500)
        directory=self.source/'db/postgres/identity-migrations';directory.chmod(0o700)
        extra=directory/'0103_unreviewed.sql';extra.write_text('fixture');extra.chmod(0o400);directory.chmod(0o500)
        self.freeze()
        with self.assertRaises(RuntimeError):self.check()

    def test_identity_migration_predecessor_cannot_be_omitted(self):
        directory=self.source/'db/postgres/identity-migrations';directory.chmod(0o700)
        predecessor=next(path for path in directory.glob('0099_*.sql'))
        predecessor.unlink();directory.chmod(0o500)
        self.freeze()
        with self.assertRaisesRegex(RuntimeError, 'complete reviewed identity migration closure required'):
            self.check()

    def test_evidence_root_rejects_nonempty_symlink_and_package_descendant(self):
        evidence=self.base/'evidence';evidence.mkdir()
        self.assertEqual(prepare_evidence_root(evidence,[self.package]),evidence)
        (evidence/'existing').write_text('preserve')
        with self.assertRaises(RuntimeError):prepare_evidence_root(evidence,[self.package])
        link=self.base/'link';link.symlink_to(evidence)
        with self.assertRaises(RuntimeError):prepare_evidence_root(link,[self.package])
        self.package.chmod(0o700);nested=self.package/'evidence';nested.mkdir()
        with self.assertRaises(RuntimeError):prepare_evidence_root(nested,[self.package])
        with self.assertRaises(RuntimeError):prepare_evidence_root(Path('relative'),[self.package])

    def test_launcher_validates_before_resources_and_after_cleanup_uses_pinned_children(self):
        text=Path(__file__).with_name('run-sql-nosql-route-isolated.py').read_text()
        self.assertLess(text.index('manifest = validate_package('),text.index('tempfile.mkdtemp'))
        self.assertLess(text.index('manifest = validate_package('),text.index("run(docker + ['run'"))
        self.assertGreater(text.rindex('observed = validate_package('),text.index("record_ownership('container-cleanup.json', cleanup)"))
        self.assertEqual(text.count('owned_processes.launch([str(node),'),2)
        self.assertNotIn('shutil.copytree',text);self.assertNotIn('symlink_to',text)
        compile(text,'launcher','exec')

if __name__=='__main__':unittest.main()
