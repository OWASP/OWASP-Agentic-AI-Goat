"""Offline v6 profile and CLI fences; no runtime provisioning or inference."""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('run-pricing-grounding-judge-main.py')

class PricingV6Profile(unittest.TestCase):
    def test_profile_preserves_old_budget_and_tightens_successor(self):
        tree = ast.parse(SCRIPT.read_text())
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
            and any((isinstance(target, ast.Name) and target.id == 'PROFILES')
                or (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                    and target.value.id == 'PROFILES') for target in node.targets)]
        scope = {}
        exec(compile(ast.Module(body=assignments, type_ignores=[]), str(SCRIPT), 'exec'), scope)
        profiles = scope['PROFILES']
        self.assertEqual(profiles['manual70bv5']['maxInference'], 24)
        self.assertEqual(profiles['manual70bv6']['maxInference'], 16)
        self.assertEqual(profiles['manual70bv6']['model'], profiles['manual70b']['model'])
        self.assertEqual(profiles['manual70bv6']['fixture'], 'tests/fixtures/pricingManualActualJudgeCalibration70bV6.js')
        self.assertEqual(profiles['manual70bv6']['verifier'], 'server/agent-runtime/pricingSemanticDecompositionV6Verifier.js')

    def test_conflicting_versions_reject_before_runtime(self):
        value = subprocess.run([sys.executable, '-B', str(SCRIPT), '--manual-calibration-70b-v5',
            '--manual-calibration-70b-v6'], capture_output=True, text=True, timeout=10)
        self.assertEqual(value.returncode, 2)
        self.assertIn('not allowed', value.stderr)
        self.assertNotIn('evidence', value.stdout)

if __name__ == '__main__':
    unittest.main()
