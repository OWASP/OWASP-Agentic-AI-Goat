import hashlib
import tempfile
import unittest
from pathlib import Path
from dpi_dependency_authority import NAMES, validate_dpi_dependency_authority

class DependencyAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hashes = {}
        for name in NAMES:
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(name)
            self.hashes[name] = hashlib.sha256(file.read_bytes()).hexdigest()
        self.authority = {'version': 1, 'root': str(self.root), 'sha256': self.hashes.copy()}

    def test_exact_six_hashes_allow_only_reviewed_root(self):
        self.assertTrue(validate_dpi_dependency_authority(self.root, self.hashes, self.authority))
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaisesRegex(ValueError, 'Unreviewed'):
                validate_dpi_dependency_authority(other, self.hashes, self.authority)

    def test_missing_extra_or_changed_supplied_entry_denied(self):
        for supplied in [{}, {**self.hashes, 'extra': 'a'*64}, {**self.hashes, 'package.json': 'a'*64}]:
            with self.assertRaises(ValueError):
                validate_dpi_dependency_authority(self.root, supplied, self.authority)

    def test_changed_installed_file_denied(self):
        (self.root / 'node_modules/.package-lock.json').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            validate_dpi_dependency_authority(self.root, self.hashes, self.authority)

    def test_escape_and_missing_file_denied(self):
        file = self.root / 'package.json'
        file.unlink()
        with self.assertRaisesRegex(ValueError, 'missing or escaped'):
            validate_dpi_dependency_authority(self.root, self.hashes, self.authority)
        with tempfile.TemporaryDirectory() as other:
            target = Path(other)/'manifest';target.write_text('package.json');file.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'missing or escaped'):
                validate_dpi_dependency_authority(self.root, self.hashes, self.authority)

if __name__ == '__main__':
    unittest.main()
