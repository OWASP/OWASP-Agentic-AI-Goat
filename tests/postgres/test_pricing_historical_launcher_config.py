"""Pure AST-extracted controls. Never import or execute the launcher."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('run-pricing-actual-isolated.py')
TREE = ast.parse(SOURCE.read_text())
NAMES = {'historical_pricing_config', 'pricing_cohort_environment', 'validate_pricing_result'}
FUNCTIONS = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in NAMES]
assert {node.name for node in FUNCTIONS} == NAMES
SCOPE = {}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), '<pricing-pure-config>', 'exec'), SCOPE)
config = SCOPE['historical_pricing_config']
environment = SCOPE['pricing_cohort_environment']
validate = SCOPE['validate_pricing_result']

class HistoricalPricingConfiguration(unittest.TestCase):
    def test_exact_modes_and_ceilings(self):
        cases = [('baseline', False, 'manual', 20, 12), ('near-market-v1', False, 'manual', 20, 12),
                 ('historical-strong-10-v1', False, 'full', 10, 3),
                 ('historical-strong-20-v1', False, 'full', 20, 3),
                 ('historical-strong-remaining-3-v1', True, 'remaining', 20, 3),
                 ('historical-strong-remaining-4-v1', True, 'remaining', 20, 4),
                 ('historical-strong-manual-3-v1', False, 'manual', 20, 3),
                 ('pricing-final-positive-v1', True, 'remaining', 20, 4)]
        for name, remaining, mode, actor, judge in cases:
            with self.subTest(cohort=name):
                c = config(name, remaining)
                self.assertEqual((c['mode'], c['actor'], c['judge']), (mode, actor, judge))
                self.assertEqual(c['manualAcceptance'], mode == 'manual')
                e = environment(name, c)
                self.assertEqual(e['PERSONA_PRICING_COHORT'], name)
                self.assertEqual(e['PERSONA_PRICING_MANUAL_ONLY'], '1' if mode == 'manual' else '0')
                self.assertEqual(e['PERSONA_PRICING_ACTUAL_REMAINING'], '1' if remaining else '0')
                validate({'status': 'passed', 'actualModelCalls': actor, 'actualJudgeCalls': judge}, c)
                for field, value in [('actualModelCalls', actor + 1), ('actualJudgeCalls', judge + 1),
                                     ('actualJudgeCalls', True), ('actualJudgeCalls', -1), ('actualJudgeCalls', None)]:
                    bad = {'status': 'passed', 'actualModelCalls': actor, 'actualJudgeCalls': judge, field: value}
                    with self.assertRaises(RuntimeError): validate(bad, c)
    def test_incompatible_and_unknown_rejected(self):
        for name, remaining in [('baseline', True), ('near-market-v1', True),
                                ('historical-strong-10-v1', True), ('historical-strong-manual-3-v1', True),
                                ('historical-strong-remaining-3-v1', False), ('historical-strong-remaining-4-v1', False),
                                ('pricing-final-positive-v1', False), ('invented', False)]:
            with self.subTest(cohort=name), self.assertRaises(ValueError): config(name, remaining)
    def test_actual_dispatch_and_acceptance_wiring(self):
        text = SOURCE.read_text()
        self.assertIn('cohort_config=historical_pricing_config(args.cohort,args.remaining)', text)
        self.assertIn('env.update(pricing_cohort_environment(args.cohort,cohort_config))', text)
        self.assertIn('validate_pricing_result(result,cohort_config)', text)
        branches = [n for n in ast.walk(TREE) if isinstance(n, ast.If)
                    and ast.unparse(n.test) == "cohort_config['manualAcceptance']"]
        self.assertEqual(len(branches), 1)
        self.assertIn('require_manual_acceptance(observation)', ast.unparse(branches[0]))
        self.assertIn("'historical_observation_only'", ast.unparse(branches[0]))
        self.assertIn("if args.cohort == 'pricing-final-positive-v1'", ast.unparse(TREE))
        self.assertIn('require_final_positive_acceptance(observation)', ast.unparse(TREE))
        self.assertIn("'passed_final_two_positive'", ast.unparse(TREE))
        self.assertLess(text.index('validate_pricing_result(result,cohort_config)'), text.index("state['runStatus']='passed'"))

if __name__ == '__main__': unittest.main(verbosity=2)
