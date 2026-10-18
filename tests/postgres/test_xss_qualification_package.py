import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from xss_qualification_package import package_inventory, validate_package, verify_copy, SCOPE


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        (self.source / 'node_modules/pkg').mkdir(parents=True)
        (self.source / 'server').mkdir()
        (self.source / 'server/app.js').write_text('source')
        binary = self.source / 'node_modules/pkg/bin'
        binary.write_text('executable'); binary.chmod(0o555)
        (self.source / 'node_modules/bin').symlink_to('pkg/bin')
        self.freeze()
        self.manifest = {'version': 1, 'scope': SCOPE, **package_inventory(self.source)}
        self.path = self.root / 'manifest.json'
        self.path.write_text(json.dumps(self.manifest)); self.path.chmod(0o444)
        self.root.chmod(0o555)
        self.digest = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def freeze(self):
        for p in self.source.rglob('*'):
            if not p.is_symlink(): p.chmod(0o555 if p.is_dir() or p.stat().st_mode & 0o111 else 0o444)
        self.source.chmod(0o555)

    def tearDown(self):
        self.root.chmod(0o700)
        for p in self.root.rglob('*'):
            if not p.is_symlink(): p.chmod(0o700 if p.is_dir() else 0o600)
        self.temp.cleanup()

    def test_full_tree_and_detached_copy_verify(self):
        self.assertEqual(validate_package(self.root, self.path, self.digest), self.manifest)
        self.root.chmod(0o755)
        copy = self.root / 'copy'
        shutil.copytree(self.source, copy, symlinks=True)
        self.assertEqual(verify_copy(copy, self.manifest), package_inventory(self.source))
        self.assertNotEqual((copy/'server/app.js').stat().st_ino, (self.source/'server/app.js').stat().st_ino)

    def test_dependency_substitution_rejected(self):
        p=self.source/'node_modules/pkg/bin'; p.chmod(0o755); p.write_text('substitute'); p.chmod(0o555)
        with self.assertRaisesRegex(RuntimeError, 'inventory mismatch'): validate_package(self.root,self.path,self.digest)

    def test_extra_source_and_missing_source_rejected(self):
        folder=self.source/'server'; folder.chmod(0o755)
        extra=folder/'extra.js'; extra.write_text('extra'); extra.chmod(0o444); folder.chmod(0o555)
        with self.assertRaisesRegex(RuntimeError,'inventory mismatch'): verify_copy(self.source,self.manifest)
        folder.chmod(0o755); extra.unlink(); (folder/'app.js').unlink(); folder.chmod(0o555)
        with self.assertRaisesRegex(RuntimeError,'inventory mismatch'): verify_copy(self.source,self.manifest)

    def test_executable_mode_loss_rejected(self):
        (self.source/'node_modules/pkg/bin').chmod(0o444)
        with self.assertRaisesRegex(RuntimeError,'inventory mismatch'): verify_copy(self.source,self.manifest)

    def test_external_symlink_and_hardlink_rejected(self):
        folder=self.source/'node_modules'; folder.chmod(0o755)
        link=folder/'bin'; link.unlink(); link.symlink_to(self.path); folder.chmod(0o555)
        with self.assertRaises(RuntimeError): verify_copy(self.source,self.manifest)
        folder.chmod(0o755); link.unlink(); os.link(self.source/'server/app.js',folder/'linked'); folder.chmod(0o555)
        with self.assertRaisesRegex(RuntimeError,'Hardlinked'): verify_copy(self.source,self.manifest)

    def test_manifest_digest_and_writable_source_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'digest mismatch'): validate_package(self.root,self.path,'0'*64)
        (self.source/'server/app.js').chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'writable'): validate_package(self.root,self.path,self.digest)


if __name__ == '__main__': unittest.main()
