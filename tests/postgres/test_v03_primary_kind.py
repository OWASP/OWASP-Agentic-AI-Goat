"""Offline controls for the unapplied fixed-enum primary-record refinement."""
import importlib.util
from pathlib import Path
import unittest

import ast
ROOT = Path(__file__).resolve().parents[2]
tree = ast.parse((ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py').read_text())
assignments = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == 'private_kind' for t in n.targets)]
assert len(assignments) == 1
expression = compile(ast.Expression(assignments[0].value), '<actual-main-kind>', 'eval')

class PrimaryKindRefinement(unittest.TestCase):
    def test_bounded_categories_and_original_fallback(self):
        expected = (
            (TimeoutError('secret'), 'timeout'), (OSError('secret'), 'io'),
            (ValueError('secret'), 'value'), (AttributeError('secret'), 'attribute'),
            (AssertionError('secret'), 'assertion'), (TypeError('secret'), 'type'),
            (ImportError('secret'), 'import'), (RuntimeError('secret'), 'other'),
        )
        for error, category in expected:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(eval(expression, {'error': error}), category)


if __name__ == '__main__':
    unittest.main()
