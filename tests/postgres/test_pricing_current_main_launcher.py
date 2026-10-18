"""Offline main-source and package-context controls; no launcher import or resources."""
import ast
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

SOURCE_FILE = Path(__file__).with_name('run-pricing-actual-isolated.py')
TREE = ast.parse(SOURCE_FILE.read_text())
NAMES = {'main_source_inventory', 'main_dependency_inventory', 'validate_main_source', 'copy_main_embedding_cache'}
FUNCTIONS = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in NAMES]
assert {node.name for node in FUNCTIONS} == NAMES
SCOPE = {'Path': Path, 'os': os, 'stat': stat, 'hashlib': hashlib, 'json': json,
         'SOURCE': None, 'MAIN_SOURCE_FILES': ('run.py',), 'MAIN_SOURCE_FOLDERS': ('code',)}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), '<pricing-main-contract>', 'exec'), SCOPE)


class PricingCurrentMainContract(unittest.TestCase):
    def test_exact_inventory_and_manifest_reject_drift_and_links(self):
        with tempfile.TemporaryDirectory(prefix='pricing-main-contract-') as raw:
            root = Path(raw).resolve()
            (root/'code').mkdir()
            (root/'node_modules').mkdir()
            (root/'run.py').write_text('launcher\n')
            (root/'code'/'module.js').write_text('module\n')
            SCOPE['SOURCE'] = root
            inventory = SCOPE['main_source_inventory'](root)
            self.assertEqual(set(inventory), {'run.py', 'code/module.js'})
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({'version': 1, 'workspace': str(root),
                                            'cohort': 'pricing-final-positive-v1',
                                            'mode': 'remaining', 'sourcePins': inventory,
                                            'dependencyInventory': {}}))
            pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self.assertEqual(SCOPE['validate_main_source'](str(manifest), pin,
                              'pricing-final-positive-v1')['sourcePins'], inventory)
            (root/'code'/'module.js').write_text('changed\n')
            with self.assertRaisesRegex(RuntimeError, 'closure mismatch'):
                SCOPE['validate_main_source'](str(manifest), pin, 'pricing-final-positive-v1')
            (root/'code'/'module.js').unlink()
            (root/'code'/'module.js').symlink_to(root/'run.py')
            with self.assertRaisesRegex(RuntimeError, 'source link refused'):
                SCOPE['main_source_inventory'](root)

    def test_closed_docker_context_excludes_unrelated_bytes(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from pricing_owned_listener import closed_package_context
        with tempfile.TemporaryDirectory(prefix='pricing-package-context-') as raw:
            root = Path(raw).resolve()
            files = {}
            for index in range(14):
                rel = f'sidecars/sandbox-runner/owned-pricing-http/file-{index}.txt'
                file = root/rel
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(f'public-{index}'.encode())
                files[rel] = hashlib.sha256(file.read_bytes()).hexdigest()
            (root/'private.env').write_text('must not be packaged')
            context = closed_package_context(root, {'files': files})
            with tarfile.open(fileobj=io.BytesIO(context)) as archive:
                self.assertEqual(set(archive.getnames()), set(files))
                self.assertNotIn(b'must not be packaged', context)
            first = root/next(iter(files))
            first.unlink()
            first.symlink_to(root/'private.env')
            with self.assertRaises(OSError):
                closed_package_context(root, {'files': files})

    def test_dependency_links_are_pinned_without_following_external_targets(self):
        with tempfile.TemporaryDirectory(prefix='pricing-dependency-contract-') as raw:
            root = Path(raw).resolve()
            package = root/'node_modules'/'package'
            package.mkdir(parents=True)
            (package/'cli.js').write_text('local\n')
            (root/'node_modules'/'.bin').mkdir()
            (root/'node_modules'/'.bin'/'cli').symlink_to('../package/cli.js')
            inventory = SCOPE['main_dependency_inventory'](root)
            self.assertEqual(inventory['.bin/cli'], {'symlink': '../package/cli.js'})
            (root/'node_modules'/'.bin'/'cli').unlink()
            (root/'node_modules'/'.bin'/'cli').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError, 'link escapes root'):
                SCOPE['main_dependency_inventory'](root)

    def test_nested_embedding_cache_copy_keeps_four_files_and_rejects_links(self):
        with tempfile.TemporaryDirectory(prefix='pricing-nested-cache-') as raw:
            root = Path(raw).resolve()
            cache = root/'cache'
            model = cache/'Xenova'/'all-MiniLM-L6-v2'
            (model/'onnx').mkdir(parents=True)
            for name in ('config.json', 'tokenizer.json', 'tokenizer_config.json'):
                (model/name).write_text(name)
            (model/'onnx'/'model_quantized.onnx').write_bytes(b'synthetic model bytes')
            destination = root/'private-cache'
            SCOPE['copy_main_embedding_cache'](cache, destination)
            copied = {p.relative_to(destination).as_posix(): p.read_bytes()
                      for p in destination.rglob('*') if p.is_file()}
            self.assertEqual(len(copied), 4)
            self.assertEqual(copied['Xenova/all-MiniLM-L6-v2/onnx/model_quantized.onnx'], b'synthetic model bytes')
            self.assertEqual(destination.stat().st_mode & 0o077, 0)
            (cache/'external').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError, 'cache link refused'):
                SCOPE['copy_main_embedding_cache'](cache, root/'rejected-cache')


if __name__ == '__main__': unittest.main(verbosity=2)
