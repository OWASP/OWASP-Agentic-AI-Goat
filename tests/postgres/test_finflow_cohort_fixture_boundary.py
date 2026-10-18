"""AST-extracted cohort controls using synthetic paths and memory-only staging."""
import ast
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest


class CohortFixtureBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.files = {}
        self.directories = {'/source', '/dependencies'}
        self.links = set()
        files, directories, links = self.files, self.directories, self.links

        class MemoryPath:
            def __init__(self, path):
                self.path = str(path)

            def __str__(self):
                return self.path

            def __truediv__(self, relative):
                return MemoryPath(PurePosixPath(self.path) / relative)

            @property
            def parent(self):
                return MemoryPath(PurePosixPath(self.path).parent)

            def resolve(self):
                return self

            def exists(self):
                return self.path in files or self.path in directories

            def is_dir(self):
                return self.path in directories

            def is_file(self):
                return self.path in files

            def is_symlink(self):
                return self.path in links

            def mkdir(self, **kwargs):
                directories.add(self.path)

            def symlink_to(self, target, **kwargs):
                links.add(self.path)

            def relative_to(self, root):
                return PurePosixPath(self.path).relative_to(str(root))

            def read_text(self):
                return files[self.path]

            def glob(self, pattern):
                return []

            def rglob(self, pattern):
                if pattern != '*':
                    return []
                return [MemoryPath(name) for name in files
                        if name.startswith(self.path + '/')]

        self.namespace = {
            'Path': MemoryPath, 'json': json,
            'validate_staged_path': lambda relative: relative,
            'verified_source_file': lambda root, relative: root / relative,
            'shutil': SimpleNamespace(copy2=lambda source, target:
                                     files.update({str(target): 'synthetic'})),
        }
        candidate = ast.parse(Path(__file__).with_name('finflow_candidate_source.py').read_text())
        assignment = next(n for n in candidate.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'APPROVED_SOURCE_FIXTURES'
                                  for t in n.targets))
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), 'fixtures', 'exec'),
             self.namespace)
        tree = ast.parse(Path(__file__).with_name('finflow_native_gate.py').read_text())
        functions = {'cohort_contract', '_validate_cohort_path', 'stage_source_copy',
                     'finflow_executable_closure'}
        constants = {'COHORTS', 'INVENTORY_RELATIVE', 'LAUNCHER_CLOSURE'}
        nodes = [n for n in tree.body
                 if isinstance(n, ast.FunctionDef) and n.name in functions
                 or isinstance(n, ast.Assign) and any(
                     isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'gate-functions', 'exec'),
             self.namespace)
        self.allowed = self.namespace['cohort_contract']('durable-v9')['fixtures']
        self.extras = sorted(self.namespace['APPROVED_SOURCE_FIXTURES'] - set(self.allowed))
        self.assertEqual(len(self.allowed), 4)
        self.assertEqual(len(self.extras), 7)

    def stage(self, paths, cohort):
        self.namespace['stage_source_copy']('/source', '/copy', paths,
                                            dependency_root='/dependencies', cohort=cohort)

    def closure(self, paths, cohort, dependency=None):
        inventory = self.namespace['INVENTORY_RELATIVE']
        tracked = sorted(set([inventory, 'tests/postgres/run-finflow-route-isolated.py', *paths]))
        self.files['/source/' + inventory] = json.dumps({'version': 1, 'trackedFiles': tracked})
        self.namespace['_expand_local_dependencies'] = lambda source, paths, seeds: sorted(
            set(paths) | ({dependency} if dependency else set()))
        return self.namespace['finflow_executable_closure']('/source', cohort=cohort)

    def test_durable_stage_rejects_each_extra_before_copy(self):
        for extra in self.extras:
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'outside the selected'):
                self.stage([extra], 'durable-v9')
        self.assertNotIn('/copy', self.directories)

    def test_durable_closure_rejects_each_extra_in_inventory(self):
        for extra in self.extras:
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'outside the selected'):
                self.closure([extra], 'durable-v9')

    def test_durable_closure_rejects_each_extra_dependency(self):
        for extra in self.extras:
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'outside the selected'):
                self.closure([], 'durable-v9', dependency=extra)

    def test_durable_accepts_exact_four_in_stage_and_closure(self):
        self.stage(self.allowed, 'durable-v9')
        self.assertEqual(len([p for p in self.files if p.startswith('/copy/')]), 4)
        self.assertTrue(set(self.allowed).issubset(self.closure(self.allowed, 'durable-v9')))

    def test_other_cohorts_accept_all_eleven_in_stage_and_closure(self):
        for cohort in ('combined-admin-durable', 'admin-error-r2'):
            with self.subTest(cohort=cohort):
                self.setUp()
                allowed = self.namespace['cohort_contract'](cohort)['fixtures']
                self.assertEqual(len(allowed), 11)
                self.stage(allowed, cohort)
                self.assertEqual(len([p for p in self.files if p.startswith('/copy/')]), 11)
                self.assertTrue(set(allowed).issubset(self.closure(allowed, cohort)))

    def test_caller_passes_explicit_cohort_to_stage(self):
        tree = ast.parse(Path(__file__).with_name('run-finflow-route-isolated.py').read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'stage_source_copy']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(next(k.value for k in calls[0].keywords
                                         if k.arg == 'cohort')), 'a.cohort')


if __name__ == '__main__':
    unittest.main()
