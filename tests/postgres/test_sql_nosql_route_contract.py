import json
import unittest
from sql_nosql_route_contract import (OBJECTIVES, MODEL, MODEL_DIGEST,
                                    selected_objectives, cohort_timeout_seconds,
                                    validate_model_inventory)


class ContractTests(unittest.TestCase):
    def test_complete_selection_and_bounded_timeout(self):
        self.assertEqual(selected_objectives(','.join(OBJECTIVES)), OBJECTIVES)
        self.assertEqual(cohort_timeout_seconds(OBJECTIVES), 24120)
        self.assertEqual(cohort_timeout_seconds(OBJECTIVES, lifecycle=True), 24720)
        self.assertEqual(cohort_timeout_seconds(('sqli_1', 'sqli_5'), lifecycle=True), 2820)
        self.assertEqual(cohort_timeout_seconds(('sqli_5', 'nosqli_3'), lifecycle=True), 3120)
        self.assertEqual(cohort_timeout_seconds(('sqli_5',), fixed_session=True), 2520)
        self.assertEqual(cohort_timeout_seconds(('sqli_5', 'nosqli_3'), lifecycle=True, fixed_session=True), 5520)
        self.assertEqual(cohort_timeout_seconds(('sqli_1', 'nosqli_1'), credit_gate=True), 600)
        for flag in ('lifecycle', 'fixed_session', 'observation_controls'):
            with self.assertRaises(ValueError):
                cohort_timeout_seconds(('sqli_1',), credit_gate=True, **{flag: True})
        for value in ('', 'sqli_1,sqli_1', 'sqli_11', 'sqli_1,', ' sqli_1'):
            with self.assertRaises(ValueError):
                selected_objectives(value)

    def test_model_name_alone_or_conflicting_inventory_is_not_proof(self):
        valid = {'name': MODEL, 'model': MODEL, 'digest': MODEL_DIGEST}
        self.assertEqual(validate_model_inventory(json.dumps({'models': [valid]}))['digest'], MODEL_DIGEST)
        for rows in ([], [valid, valid], [{'name': MODEL}],
                     [{**valid, 'digest': '0' * 64}], [{**valid, 'model': 'other'}],
                     [{'name': 'other', 'digest': MODEL_DIGEST}]):
            with self.assertRaises(ValueError):
                validate_model_inventory(json.dumps({'models': rows}))


if __name__ == '__main__':
    unittest.main()
