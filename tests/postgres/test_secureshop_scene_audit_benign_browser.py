"""Portable V15 benign admission controls; synthetic bytes are not a genuine negative."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('v15_benign_adapter', HERE / 'run-secureshop-scene-audit-benign-browser.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
UUID = '11111111-1111-4111-8111-111111111111'


class BenignAdmission(unittest.TestCase):
    def receipt(self):
        return dict(dict.fromkeys(A.FLAGS, True), scope=A.SCOPE,
                    merchantEventId='review:' + UUID, summaryRunId=UUID,
                    actorCalls=2, judgeCalls=1, errors=[])

    def capture(self):
        raw = b'controlled artifact, not a native observation'
        ref = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        refs = {name: dict(ref) for name in ('effects', 'log', 'sources', 'messages', 'traces')}
        reads = {name: dict(ref, observedBytes=len(raw), complete=True, oversized=False,
                            base64=base64.b64encode(raw).decode()) for name in refs}
        return dict(scope=A.SCOPE, actualQualification=False,
                    originalSource={'entry': {'id': 'review:' + UUID}},
                    observed={'failure': None, 'actorCalls': 2, 'judgeCalls': 1,
                              'configuredJudge': [{'result': {'verdict': 'fail'}}],
                              'judgeTranscripts': [{'outcome': {'value': {'verdict': 'fail'}}}]},
                    runs={'vuln': dict(mode='vuln', savedResult={'runId': UUID,
                        'objectiveCredit': False, 'evidence': {'artifacts': refs}},
                        completions=[], contributions=[], judgments=[{'verdict': 'fail'}],
                        artifactRefs=refs, artifactReads=reads)})

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def test_exact_benign_contract_and_source_pins(self):
        fixture = (ROOT / A.TEST).read_text()
        self.assertIn("const V15_BENIGN_ASSERTION = '" + A.ASSERTION + "';", fixture)
        self.assertIn("const V15_BENIGN_SCOPE = '" + A.SCOPE + "';", fixture)
        self.assertIn('V15_BENIGN_ENABLED', fixture)
        self.assertIn("assert.equal(judgment.verdict, 'fail'", fixture)
        for name in A.PINS:
            self.assertEqual(A.digest(ROOT / name), A.PINS[name], name)
        base = A.load(A.BASE, 'benign_test_base')
        A.validate_pins(base)
        with patch.object(A, 'digest', side_effect=lambda path: '0' * 64 if str(path).endswith(A.TEST)
                          else hashlib.sha256(Path(path).read_bytes()).hexdigest()):
            with self.assertRaisesRegex(RuntimeError, 'frozen source mismatch'):
                A.validate_pins(base)

    def test_receipt_and_original_no_credit_artifacts_fail_closed(self):
        shared = SimpleNamespace(scene_audit_private_json=lambda path, limit: json.loads(Path(path).read_text()))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'private.json'
            receipt = self.receipt()
            self.write(target, receipt)
            self.assertEqual(A.benign_receipt(shared, target), receipt)
            for mutation in ({'actorCalls': 1}, {'actorCalls': 5}, {'judgeCalls': 3},
                             {'passed': False}, {'scope': 'original positive scope'},
                             {'errors': [{'stage': 'failure'}]}):
                with self.subTest(mutation=mutation):
                    self.write(target, dict(receipt, **mutation))
                    with self.assertRaises(RuntimeError): A.benign_receipt(shared, target)
            capture = self.capture()
            self.write(target, capture)
            result = A.benign_evidence(shared, target, receipt)
            self.assertEqual(result['originalArtifactReads'], 5)
            self.assertFalse(result['creditAuthorized'])
            for mutate in (
                    lambda v: v['runs']['vuln']['savedResult'].update(objectiveCredit=True),
                    lambda v: v['runs']['vuln']['judgments'][0].update(verdict='unavailable'),
                    lambda v: v['observed']['judgeTranscripts'][0]['outcome']['value'].update(verdict='pass'),
                    lambda v: v['runs']['vuln']['artifactReads']['log'].update(base64='YWx0ZXJlZA=='),
                    lambda v: v['runs']['vuln']['artifactReads']['sources'].update(complete=False),
                    lambda v: v['originalSource']['entry'].update(id='review:other'),
                    lambda v: v['runs'].update(fixed={}),
            ):
                value = copy.deepcopy(capture)
                mutate(value)
                self.write(target, value)
                with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                    A.benign_evidence(shared, target, receipt)

    def test_plan_remains_nonallocating_and_private(self):
        base = SimpleNamespace(COHORT='scene-audit-v15-browser', HELPER='helper', CONTRACT='contract',
                               arguments=lambda argv: argv, CONTROL_SOURCES=())
        shared = SimpleNamespace(SCENE_AUDIT_BROWSER=base.COHORT, ADMIN_AUDIT_JOBS_TEST=A.TEST,
            parse=lambda argv: SimpleNamespace(main_workspace=str(ROOT), current_host_profile='profile',
                                               browser='/pinned/browser', browser_sha256='a' * 64, plan=True),
            validate_static=lambda parsed: None)
        with patch.object(A, 'load', side_effect=[base, shared]), \
                patch.object(A, 'validate_pins', return_value=None), \
                patch.object(A, 'inventory', return_value={'controlled': True}), \
                patch.object(A, 'PINS', {A.TEST: 'a' * 64, 'helper': 'b' * 64, 'contract': 'c' * 64}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(A.main(['--plan']), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result['diagnosticOnly'])
        self.assertFalse(result['nativeStarted'])
        self.assertFalse(result['sourceCopy'])
        self.assertEqual(shared.SCENE_AUDIT_CAPTURE, A.EVIDENCE)
        self.assertIsNotNone(shared.scene_audit_receipt)
        self.assertIsNotNone(shared.scene_audit_evidence)
        self.assertNotEqual(A.REPORT, A.EVIDENCE)

    def test_isolated_environment_requires_original_v15_route(self):
        evidence = ROOT / 'tasks/qualification/run-controlled'
        base = SimpleNamespace(owned_environment=lambda env, parsed: (env, evidence))
        env, owned = A.owned_environment(base, {'SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE': '1'}, None)
        self.assertEqual(owned, evidence)
        self.assertEqual(env['SECURESHOP_SCENE_AUDIT_BENIGN_DIAGNOSTIC'], '1')
        with self.assertRaisesRegex(RuntimeError, 'Exact benign diagnostic selector'):
            A.owned_environment(base, {'SECURESHOP_SCENE_AUDIT_BENIGN_DIAGNOSTIC': '0'}, None)


if __name__ == '__main__':
    unittest.main()
