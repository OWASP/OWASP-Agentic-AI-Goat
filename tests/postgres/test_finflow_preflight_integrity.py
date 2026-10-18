"""Exercise the extracted preflight with memory-only paths and process doubles."""
import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest


class PreflightIntegrityTests(unittest.TestCase):
    def invoke(self, mutation):
        files = {'server/source.js': b'reviewed source'}

        class Leaf:
            def __init__(self, name):
                self.name = name

            def is_file(self):
                return True

            def is_symlink(self):
                return False

            def relative_to(self, root):
                return self.name

            def read_bytes(self):
                return files[self.name]

        class Root:
            def __init__(self, *args):
                pass

            def resolve(self):
                return self

            def rglob(self, pattern):
                return [Leaf(name) for name in files]

        calls = []

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            mutation(files)
            return SimpleNamespace(returncode=0, stderr='', stdout='loaded')

        tree = ast.parse(Path(__file__).with_name('finflow_native_gate.py').read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == 'preflight_staged_imports')
        namespace = {'Path': Root, 'hashlib': hashlib,
                     'subprocess': SimpleNamespace(run=fake_run),
                     'PREFLIGHT_MODULES': ('./synthetic',)}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     'extracted-preflight', 'exec'), namespace)
        result = namespace['preflight_staged_imports'](
            '/synthetic', node_binary='never-executed', environment={})
        self.assertEqual(len(calls), 1)
        return result

    def test_unchanged_source_passes(self):
        self.assertEqual(self.invoke(lambda files: None), 'loaded')

    def test_same_name_same_length_changed_bytes_fail(self):
        with self.assertRaisesRegex(RuntimeError, 'mutated the source copy'):
            self.invoke(lambda files: files.update({'server/source.js': b'modified source'}))

    def test_added_file_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'mutated the source copy'):
            self.invoke(lambda files: files.update({'server/extra.js': b'added'}))

    def test_deleted_file_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'mutated the source copy'):
            self.invoke(lambda files: files.pop('server/source.js'))


if __name__ == '__main__':
    unittest.main()
