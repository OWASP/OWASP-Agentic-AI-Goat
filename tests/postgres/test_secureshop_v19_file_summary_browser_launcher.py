"""Resource-free controls: parse the prepared/current launcher, never import its runtime."""
import ast
import copy
import hashlib
import re
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')

def namespace(*functions):
    tree = ast.parse(SOURCE.read_text())
    values = {'re': re, 'hashlib': hashlib}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in functions]
    assert len(selected) == len(functions)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), 'exec'), values)
    return values

class V19LauncherTest(unittest.TestCase):
    def fixture(self):
        values = namespace('validate_v19_summary_receipt')
        pins = dict.fromkeys(('sourceManifestSha256', 'frontendInventorySha256', 'modelManifestSha256',
                              'browserSha256', 'nodeSha256'), 'a' * 64)
        wire = [{'index': index + 1, 'kind': 'actor' if index < 10 else 'judge', 'model': 'llama3.1:8b',
                 'status': 200, 'responseComplete': True, 'responseCaptureTruncated': False,
                 **{field: '{}' for field in ('request', 'response')},
                 **{field + 'Bytes': 2 for field in ('request', 'response')},
                 **{field + 'Sha256': hashlib.sha256(b'{}').hexdigest() for field in ('request', 'response')}}
                for index in range(18)]
        receipt = dict.fromkeys(values['V19_SUMMARY_FLAGS'], True)
        receipt.update(version=1, scope=values['V19_SUMMARY_SCOPE'], actualModelCalls=10, judgeCalls=4,
            cleanupErrors=[], inputsSha256=values['V19_SUMMARY_INPUTS_SHA256'], originalEvidenceSha256='f' * 64,
            physicalModelCalls=18, semanticReviewRequired=True, qualificationPins=pins,
            qualificationComplete=False, qualificationStatus='provisional-original-answer-review-required')
        original = {'version': 1, 'scope': values['V19_SUMMARY_SCOPE'], 'passed': True, 'failures': [],
                    'inputsSha256': values['V19_SUMMARY_INPUTS_SHA256'], 'cases': [{}] * 5,
                    'judgeTranscripts': [{}] * 4, 'wire': wire, 'qualificationPins': pins,
                    'semanticReviewRequired': True, 'qualificationComplete': False,
                    'qualificationStatus': 'provisional-original-answer-review-required'}
        return values, receipt, original, pins

    def test_receipt_requires_exact_manifests_and_complete_bounded_wire(self):
        values, receipt, original, pins = self.fixture()
        validate = values['validate_v19_summary_receipt']
        self.assertEqual(validate(receipt, original, pins), receipt)
        mutations = [('version', True), ('actualModelCalls', 9), ('actualModelCalls', True), ('judgeCalls', 5),
            ('physicalModelCalls', 27), ('semanticReviewRequired', False), ('cleanupErrors', ['failure']),
            ('qualificationPins', {}), ('inputsSha256', '0' * 64), ('passed', False)]
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate({**receipt, field: value}, original, pins)
        for field, value in [('responseComplete', False), ('responseCaptureTruncated', True),
            ('responseSha256', '0' * 64), ('requestBytes', 3), ('index', 2), ('index', True), ('status', 503),
            ('kind', 'unexpected'), ('model', 'other')]:
            changed = copy.deepcopy(original); changed['wire'][0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(receipt, changed, pins)

    def test_receipt_counts_physical_calls_independently_of_declared_application_calls(self):
        values, receipt, original, pins = self.fixture()
        original['wire'][10]['kind'] = 'actor'
        with self.assertRaisesRegex(RuntimeError, 'physical actor or Judge budget'):
            values['validate_v19_summary_receipt'](receipt, original, pins)
        values, receipt, original, pins = self.fixture()
        original['judgeTranscripts'].pop()
        with self.assertRaises(RuntimeError):
            values['validate_v19_summary_receipt'](receipt, original, pins)

    def test_protocol_pass_remains_provisional_in_receipt_and_original_document(self):
        values, receipt, original, pins = self.fixture()
        validate = values['validate_v19_summary_receipt']
        self.assertIn('negativeVerdictsObserved', values['V19_SUMMARY_FLAGS'])
        self.assertNotIn('canonicalNegatives', values['V19_SUMMARY_FLAGS'])
        self.assertTrue(validate(receipt, original, pins)['passed'])
        for target in ('receipt', 'original'):
            for field, value in [('qualificationComplete', True), ('qualificationComplete', 0),
                ('qualificationStatus', 'qualified'), ('qualificationStatus', None),
                ('semanticReviewRequired', False), ('semanticReviewRequired', 1)]:
                changed_receipt, changed_original = copy.deepcopy(receipt), copy.deepcopy(original)
                (changed_receipt if target == 'receipt' else changed_original)[field] = value
                with self.subTest(target=target, field=field, value=value), self.assertRaises(RuntimeError):
                    validate(changed_receipt, changed_original, pins)
            for field in ('qualificationComplete', 'qualificationStatus', 'semanticReviewRequired'):
                changed_receipt, changed_original = copy.deepcopy(receipt), copy.deepcopy(original)
                del (changed_receipt if target == 'receipt' else changed_original)[field]
                with self.subTest(target=target, missing=field), self.assertRaises(RuntimeError):
                    validate(changed_receipt, changed_original, pins)
        source = SOURCE.read_text()
        projection = source[source.index('receipt.update(selectedFixtures=[V19_SUMMARY_TEST]'):]
        projection = projection[:projection.index("elif args.cohort == V08_SVG_BROWSER")]
        self.assertIn('qualificationComplete=False', projection)
        self.assertIn("else 'provisional-original-answer-review-required'", projection)
        self.assertIn('semanticReviewRequired=True', projection)

    def test_distinct_closed_declaration_and_limits(self):
        values = namespace()
        self.assertEqual(values['V19_SUMMARY_BROWSER'], 'customer-file-summary-v19-browser')
        self.assertEqual(values['V19_SUMMARY_TEST'], 'tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js')
        self.assertEqual(values['V19_SUMMARY_LIMITS'], {'cases': 5, 'maximumActorCalls': 10,
            'canonicalAssessmentInvocations': 4, 'maximumJudgeCalls': 16, 'maximumModelCalls': 26,
            'fixedJudgeCalls': 0, 'postRetries': 0})

    def test_pin_validation_rejects_unfrozen_and_each_changed_member(self):
        values = namespace('validate_v19_summary_pins')
        paths = tuple(values['V19_SUMMARY_PINS'])
        self.assertGreaterEqual(len(paths), 14)
        values['V19_SUMMARY_PINS'] = dict.fromkeys(paths, '1' * 64)
        self.assertEqual(values['validate_v19_summary_pins'](Path('/owned'), lambda path: '1' * 64), paths)
        for changed in paths:
            with self.assertRaisesRegex(RuntimeError, 'Pinned V19 source changed'):
                values['validate_v19_summary_pins'](Path('/owned'), lambda path: '2' * 64 if str(path) == '/owned/' + changed else '1' * 64)
        values['V19_SUMMARY_PINS'][paths[0]] = 'UNFROZEN'
        with self.assertRaisesRegex(RuntimeError, 'V19 source pins are not frozen'):
            values['validate_v19_summary_pins'](Path('/owned'), lambda path: self.fail('Unfrozen pin read source'))

    def test_static_gate_precedes_resource_creation_and_model_probe(self):
        source = SOURCE.read_text()
        static = source[source.index('def validate_static'):source.index('\ndef vulnerability_registry')]
        self.assertIn('validate_v19_summary_pins(source, digest)', static)
        self.assertIn('V19_SUMMARY_MODEL_SHA256', static)
        self.assertIn("LIVE_BROWSER_COHORTS = (V19_SUMMARY_BROWSER,) + LIVE_BROWSER_COHORTS", source)
        self.assertIn('cohort_action.choices = (V19_SUMMARY_BROWSER,) + tuple(cohort_action.choices)', source)

    def test_execution_selects_private_files_root_and_exact_customer_fixture(self):
        source = SOURCE.read_text()
        for value in ["SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE='1'", 'SECURESHOP_V19_OWNED_FILES_ROOT',
            'SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH', "v19_files_root.mkdir(mode=0o700)",
            "PG_SECURESHOP_CUSTOMER_CHECKOUT_{name}_RUNTIME_URL", '600 if args.v19_graph_diagnostic else 1800',
            'v19-original-evidence.json', 'validate_v19_summary_pins(source,digest)',
            'sourceManifestSha256', 'frontendInventorySha256', 'modelManifestSha256', 'nodeSha256',
            "cleanup['v19OwnedFilesAbsent']", 'cleanup_v19_files_root(v19_files_root, v19_files_identity, runtime)']:
            self.assertIn(value, source)

    def test_graph_diagnostic_is_one_case_nonqualification_with_hard_zero_judge(self):
        source = SOURCE.read_text()
        for token in ["SECURESHOP_V19_FILE_SUMMARY_DIAGNOSTIC_NATIVE':'1'", "expected_failure=args.v19_graph_diagnostic",
            "'cases':1", "'maximumActorCalls':2", "'canonicalAssessmentInvocations':0",
            "'maximumJudgeCalls':0", "'maximumModelCalls':2", "'qualificationComplete':False",
            "receipt.get('qualificationStatus') != 'diagnostic-nonqualification'",
            "len(original.get('graphFailures', [])) != 1", "original.get('judgeTranscripts') != []"]:
            self.assertIn(token, source)
        for token in ["qualificationStatus=('diagnostic-nonqualification' if args.v19_graph_diagnostic",
            "objectiveScope=(V19_GRAPH_DIAGNOSTIC_SCOPE if args.v19_graph_diagnostic",
            'v19_graph_diagnostic_outer_fields(v19_summary_result, args.v19_graph_diagnostic)']:
            self.assertIn(token, source)
        project = namespace('v19_graph_diagnostic_outer_fields')['v19_graph_diagnostic_outer_fields']
        self.assertEqual(project(None, True), {'passed': False, 'diagnosticCaptured': False, 'actualModelCalls': None})
        self.assertEqual(project({'actualModelCalls': 1}, True),
            {'passed': False, 'diagnosticCaptured': True, 'actualModelCalls': 1})
        self.assertEqual(project(None, False), {})
        self.assertIn("if code != 1: raise RuntimeError(f'{label} diagnostic must fail exactly once')", source)
        self.assertIn("args.v19_graph_diagnostic and args.cohort != V19_SUMMARY_BROWSER", source)

    def test_v19_judge_admission_evaluates_actual_plan_expression(self):
        from types import SimpleNamespace
        tree = ast.parse(SOURCE.read_text())
        expressions = [
            value for node in ast.walk(tree) if isinstance(node, ast.Dict)
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant) and key.value == 'actualJudgeRequired'
            and any(isinstance(child, ast.Attribute) and child.attr == 'v19_graph_diagnostic'
                    for child in ast.walk(value))
        ]
        self.assertEqual(len(expressions), 1)
        expression = compile(ast.Expression(expressions[0]), str(SOURCE), 'eval')
        for diagnostic in (False, True):
            args = SimpleNamespace(cohort='customer-file-summary-v19-browser',
                                   v19_graph_diagnostic=diagnostic,
                                   user_lookup_benign_capture=False,
                                   user_lookup_disclosure=False,
                                   restart_injection_graded=False)
            with self.subTest(diagnostic=diagnostic):
                self.assertIs(eval(expression, {'__builtins__': {}}, {**namespace(), 'args': args}),
                              not diagnostic)

    def test_cleanup_authority_requires_original_created_root_identity(self):
        source = SOURCE.read_text()
        function = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == 'cleanup_v19_files_root')
        body = ast.get_source_segment(source, function)
        for token in ['target != runtime', 'target.is_symlink()', 'st_dev', 'st_ino', 'st_uid', 'identity is None', 'shutil.rmtree(target)']:
            self.assertIn(token, body)

    def test_cleanup_rejects_swapped_root_and_never_deletes_foreign_path(self):
        import stat
        from types import SimpleNamespace
        values = namespace('cleanup_v19_files_root')
        deleted = []
        class Target:
            link = False
            present = True
            identity = (1, 2, 3)
            def is_symlink(self): return self.link
            def exists(self): return self.present
            def lstat(self):
                return SimpleNamespace(st_dev=self.identity[0], st_ino=self.identity[1],
                    st_uid=self.identity[2], st_mode=stat.S_IFDIR | 0o700)
        target = Target()
        class Runtime:
            def __truediv__(self, name):
                assert name == 'v19-owned-files'
                return target
        def remove(value):
            deleted.append(value); value.present = False
        values.update(stat=stat, os=SimpleNamespace(getuid=lambda:3), shutil=SimpleNamespace(rmtree=remove))
        cleanup = values['cleanup_v19_files_root']
        for identity, link in [(None, False), ((1, 9, 3), False), ((1, 2, 3), True)]:
            target.link = link
            with self.assertRaises(RuntimeError): cleanup(target, identity, Runtime())
            self.assertEqual(deleted, [])
        target.link = False
        self.assertTrue(cleanup(target, (1, 2, 3), Runtime()))
        self.assertEqual(deleted, [target])

if __name__ == '__main__':
    unittest.main()
