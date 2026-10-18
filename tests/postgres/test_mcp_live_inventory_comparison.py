"""Controlled AST extraction only: never import or execute the live launcher."""
import ast
import copy
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).with_name('run-mcp-owned-runtime-live-promotion.py')


class InventoryComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text())
        comparisons = [node for node in ast.walk(cls.tree) if isinstance(node, ast.If)
                       and ast.dump(node.test) == ast.dump(ast.parse(
                           'final_inventory != post_inventory', mode='eval').body)]
        if len(comparisons) != 1:
            raise AssertionError('Exactly one full-inventory comparison required')
        cls.guard = comparisons[0]
        # Admit only the comparison and its explicit error, with no executable
        # launcher setup, imports, subprocesses or environment access.
        expected = ast.parse("if final_inventory != post_inventory:\n"
                             "    raise RuntimeError('post-restart database inventory differs from verified promotion state')").body[0]
        if ast.dump(cls.guard) != ast.dump(expected):
            raise AssertionError('Unexpected executable comparison body')
        cls.code = compile(ast.Module(body=[cls.guard], type_ignores=[]), str(SOURCE), 'exec')

    def inventory(self):
        return {'identity': {'identity.users': {'rows': 2, 'sha256': 'owned-row-hash'},
                             '@sequences': {'rows': 1, 'sha256': 'owned-sequence-hash'},
                             '@ownership_acl_effective': {'records': [{'grantee': 'runtime', 'privilege': 'SELECT'}]}},
                'mcp': {'mcp.progress': {'rows': 1, 'sha256': 'owned-progress-hash'}}}

    def check_inventory(self, before, after):
        exec(self.code, {'__builtins__': {'RuntimeError': RuntimeError},
                         'post_inventory': before, 'final_inventory': after})

    def test_unchanged_inventory_passes_without_mutating_inputs(self):
        before = self.inventory()
        after = copy.deepcopy(before)
        original = copy.deepcopy(before)
        self.check_inventory(before, after)
        self.assertEqual(before, original)
        self.assertEqual(after, original)

    def test_every_inventory_difference_fails(self):
        mutations = {
            'rows': lambda x: x['identity']['identity.users'].update(sha256='changed'),
            'count': lambda x: x['identity']['identity.users'].update(rows=3),
            'sequence': lambda x: x['identity']['@sequences'].update(sha256='advanced'),
            'acl': lambda x: x['identity']['@ownership_acl_effective']['records'][0].update(privilege='UPDATE'),
            'new_relation': lambda x: x['mcp'].update({'mcp.extra': {'rows': 0, 'sha256': 'empty'}}),
            'missing_relation': lambda x: x['mcp'].pop('mcp.progress'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                before = self.inventory()
                after = copy.deepcopy(before)
                mutate(after)
                original_before, original_after = copy.deepcopy(before), copy.deepcopy(after)
                with self.assertRaisesRegex(RuntimeError, 'post-restart database inventory differs'):
                    self.check_inventory(before, after)
                self.assertEqual(before, original_before)
                self.assertEqual(after, original_after)

    def test_guard_follows_capture_and_precedes_pass_in_same_try(self):
        owners = [node for node in ast.walk(self.tree)
                  if isinstance(node, ast.Try) and self.guard in node.body]
        self.assertEqual(len(owners), 1)
        body = owners[0].body
        index = body.index(self.guard)
        capture = body[index - 1]
        self.assertIsInstance(capture, ast.Assign)
        self.assertEqual([ast.unparse(t) for t in capture.targets], ['final_inventory'])
        pass_assignments = [i for i, node in enumerate(body) if isinstance(node, ast.Assign)
                            and any(ast.unparse(t) == "state['runStatus']" for t in node.targets)
                            and isinstance(node.value, ast.Constant) and node.value.value == 'passed']
        self.assertEqual(len(pass_assignments), 1)
        self.assertLess(index, pass_assignments[0])
        self.assertTrue(owners[0].handlers, 'Failure must retain the existing repair handler')


if __name__ == '__main__':
    unittest.main(verbosity=2)
