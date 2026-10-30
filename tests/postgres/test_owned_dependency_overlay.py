import importlib.util
import pathlib
import tempfile
import hashlib
import unittest

spec = importlib.util.spec_from_file_location('overlay', pathlib.Path(__file__).with_name('owned_dependency_overlay.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MetadataOverlay(unittest.TestCase):
    def test_identical_readonly_file_and_directory_are_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve(); source = root / 'frozen'; source.write_bytes(b'approved'); source.chmod(0o444)
            owned = root / 'runtime'; owned.mkdir(); destination = owned / 'package.json'; destination.write_bytes(source.read_bytes()); destination.chmod(0o444); owned.chmod(0o555)
            before = destination.stat()
            try:
                self.assertEqual(m.install_owned_metadata(source, destination, owned, hashlib.sha256(b'approved').hexdigest()), 'unchanged')
                self.assertEqual(destination.stat().st_ino, before.st_ino)
                self.assertEqual(destination.stat().st_mode, before.st_mode)
                self.assertEqual(owned.stat().st_mode & 0o777, 0o555)
                self.assertEqual(source.stat().st_mode & 0o777, 0o444)
            finally: owned.chmod(0o700)
    def test_changed_owned_file_replaced_without_chmod_parent_or_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve(); source = root / 'frozen'; source.write_bytes(b'approved'); source.chmod(0o444)
            owned = root / 'runtime'; owned.mkdir(mode=0o700); destination = owned / 'package.json'; destination.write_bytes(b'old'); destination.chmod(0o444)
            self.assertEqual(m.install_owned_metadata(source, destination, owned, hashlib.sha256(b'approved').hexdigest()), 'replaced')
            self.assertEqual(destination.read_bytes(), b'approved'); self.assertEqual(destination.stat().st_mode & 0o777, 0o444)
            self.assertEqual(owned.stat().st_mode & 0o777, 0o700); self.assertEqual(source.stat().st_mode & 0o777, 0o444)
    def test_wrong_hash_and_symlink_destination_are_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve(); source = root / 'source'; source.write_bytes(b'approved'); owned = root / 'runtime'; owned.mkdir(); destination = owned / 'package.json'; destination.write_bytes(b'old')
            with self.assertRaises(ValueError): m.install_owned_metadata(source, destination, owned, '0' * 64)
            self.assertEqual(destination.read_bytes(), b'old'); destination.unlink(); destination.symlink_to(source)
            with self.assertRaises(ValueError): m.install_owned_metadata(source, destination, owned, hashlib.sha256(b'approved').hexdigest())
            self.assertEqual(source.read_bytes(), b'approved')

    def test_traversal_rejected_in_bounded_subprocess_without_mutation(self):
        import subprocess, sys
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve(); source = root / 'source'; source.write_bytes(b'approved')
            owned = root / 'runtime'; owned.mkdir(); outside = root / 'outside'; outside.write_bytes(b'private-fixture')
            code = "import sys;sys.path.insert(0,sys.argv[1]);from owned_dependency_overlay import install_owned_metadata;from pathlib import Path;\ntry:install_owned_metadata(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5])\nexcept ValueError:raise SystemExit(0)\nraise SystemExit(1)"
            result = subprocess.run([sys.executable, '-B', '-c', code, str(pathlib.Path(__file__).parent.resolve()), str(source), str(owned / '..' / 'outside'), str(owned), hashlib.sha256(b'approved').hexdigest()], capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outside.read_bytes(), b'private-fixture')

    def test_actual_readonly_copy_links_and_runtime_directory_creation(self):
        import subprocess
        node = '/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node'
        copier = pathlib.Path(__file__).resolve().parents[2] / 'scripts/lib/isolated-source-copy.js'
        with tempfile.TemporaryDirectory() as temp:
            parent = pathlib.Path(temp).resolve(); frozen = parent / 'frozen'; frozen.mkdir()
            for directory in ['client/src', 'server/sensitive_files/config', 'db/postgres']:
                (frozen / directory).mkdir(parents=True, exist_ok=True)
            for name in ['package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json', 'client/src/index.js']:
                (frozen / name).write_bytes(b'{}'); (frozen / name).chmod(0o444)
            directories = [frozen, *[p for p in frozen.rglob('*') if p.is_dir()]]
            for d in directories: d.chmod(0o555)
            evidence = parent / 'evidence'; evidence.mkdir(mode=0o700); runtime = evidence / 'source'
            try:
                subprocess.run([node, '-e', 'require(process.argv[1]).copyIsolatedSource(process.argv[2],process.argv[3])', str(copier), str(frozen), str(runtime)], check=True, capture_output=True, timeout=10)
                before = {str(p.relative_to(runtime)): (p.read_bytes(), p.stat().st_mode) for p in runtime.rglob('*') if p.is_file()}
                self.assertGreater(m.prepare_owned_runtime_directories(frozen, runtime, evidence), 3)
                for name in ['package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json']:
                    self.assertEqual(m.install_owned_metadata(frozen/name, runtime/name, runtime, hashlib.sha256(b'{}').hexdigest()), 'unchanged')
                dependencies = parent / 'dependencies'; dependencies.mkdir(); (dependencies/'client').mkdir()
                (runtime/'node_modules').symlink_to(dependencies, target_is_directory=True)
                (runtime/'client/node_modules').symlink_to(dependencies/'client', target_is_directory=True)
                for name in ['client/build/assets', 'server/logs', 'server/sensitive_files/config/generated', 'canonical-through-0021']:
                    (runtime/name).mkdir(parents=True, exist_ok=True)
                self.assertEqual(before, {name: ((runtime/name).read_bytes(), (runtime/name).stat().st_mode) for name in before})
                self.assertTrue(all(d.stat().st_mode & 0o777 == 0o555 for d in directories))
                self.assertEqual(m.vite_config_arguments(True), ['--configLoader', 'native'])
                self.assertEqual(m.vite_config_arguments(False), [])
            finally:
                for d in directories: d.chmod(0o700)

    def test_directory_preparation_rejects_source_escape_and_links_before_chmod(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = pathlib.Path(temp).resolve(); frozen = parent/'frozen'; frozen.mkdir(); evidence = parent/'evidence'; evidence.mkdir(mode=0o700); runtime=evidence/'source';runtime.mkdir();runtime.chmod(0o555)
            try:
                with self.assertRaises(ValueError): m.prepare_owned_runtime_directories(frozen, frozen, evidence)
                runtime.chmod(0o700); (runtime/'escape').symlink_to(frozen, target_is_directory=True);runtime.chmod(0o555)
                with self.assertRaises(ValueError): m.prepare_owned_runtime_directories(frozen, runtime, evidence)
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o555)
            finally: runtime.chmod(0o700)
