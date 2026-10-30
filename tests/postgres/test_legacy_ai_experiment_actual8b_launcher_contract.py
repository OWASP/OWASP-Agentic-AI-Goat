#!/usr/bin/env python3
"""Hermetic, non-native contracts for the legacy AI actual-8B launcher."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
LAUNCHER = HERE / 'run-legacy-ai-experiment-actual8b-isolated.py'


def load_launcher():
    spec = importlib.util.spec_from_file_location('legacy_ai_actual8b_launcher', LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def valid_result(module):
    cases = []
    for route in sorted(module.ROUTES):
        for kind in sorted(module.KINDS):
            actor_output = route + kind + 'actor output'
            cases.append({
                'route': route,
                'kind': kind,
                'actorOutputSha256': digest(actor_output),
                'actorOutputBytes': 123,
                'actorCallCount': 1,
                'judgeCallCount': 1,
                'verdict': 'pass' if kind == 'attack' else 'fail',
                'passed': True,
                'failedPositive': False,
                'observedDisclosure': kind == 'attack',
                'evaluationPassed': kind == 'attack',
                'calls': [
                    {'phase': 'actor', 'requestSha256': digest(route + kind + 'actor request'),
                     'requestBytes': 400, 'outputSha256': digest(actor_output),
                     'outputBytes': 123, 'configuredContextTokens': 32768, 'completed': True},
                    {'phase': 'judge', 'requestSha256': digest(route + kind + 'judge request'),
                     'requestBytes': 500, 'outputSha256': digest(route + kind + 'judge output'),
                     'outputBytes': 100, 'configuredContextTokens': 32768, 'completed': True},
                ],
            })
    return {
        'version': 1,
        'cohort': module.COHORT,
        'model': module.MODEL,
        'digest': module.MODEL_DIGEST,
        'qualification': 'qualified',
        'modelVerifiedBefore': True,
        'modelVerifiedAfter': True,
        'cases': cases,
        'judgeCalibrations': [
            {'kind': 'positive', 'verdict': 'pass', 'judgeCallCount': 1, 'passed': True,
             'calls': [{'phase': 'judge', 'requestSha256': digest('positive request'),
                 'requestBytes': 500, 'outputSha256': digest('positive output'), 'outputBytes': 100,
                 'configuredContextTokens': 32768, 'completed': True}]},
            {'kind': 'negative', 'verdict': 'fail', 'judgeCallCount': 1, 'passed': True,
             'calls': [{'phase': 'judge', 'requestSha256': digest('negative request'),
                 'requestBytes': 500, 'outputSha256': digest('negative output'), 'outputBytes': 100,
                 'configuredContextTokens': 32768, 'completed': True}]},
        ],
        'cancellation': {'passed': True, 'calls': [
            {'phase': 'actor', 'requestSha256': digest('cancel request'), 'requestBytes': 300,
             'outputSha256': digest('cancel output'), 'outputBytes': 50,
             'configuredContextTokens': 32768, 'completed': True},
        ]},
        'failures': [],
        'configuredActorContextTokens': 32768,
        'configuredJudgeContextTokens': 32768,
    }


class LauncherContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LAUNCHER.read_text()
        cls.module = load_launcher()

    def write_result(self, value):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'qualification.json'
        path.write_text(json.dumps(value) + '\n')
        os.chmod(path, 0o600)
        return path

    def test_static_ownership_freeze_and_cleanup_contract(self):
        required = (
            "STAGE = 'actual8b-v1'",
            "SCOPE = 'legacy_ai_experiment_production_actual8b'",
            '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
            "OLLAMA_BASE_URL = 'http://127.0.0.1:11434'",
            "NODE_VERSION = 'v26.8.2'",
            'dependencyFilesSha256', 'dependencySymlinksSha256',
            'expectedOwnerHandle', 'ownerHandleFileSha256', 'expectedLauncherPid',
            'WAITING_OWNER_HANDLE', 'grant already consumed', 'postflightManifestVerified',
            'start_new_session=True', 'os.killpg', 'signal.SIGTERM', 'signal.SIGKILL',
            'allProcessGroupsAbsent', 'allProcessIdsAbsent', 'terminal_pass_cleaned',
            'LEGACY_AI_EXPERIMENT_ACTUAL8B_ISOLATED',
            'LEGACY_AI_EXPERIMENT_ACTUAL8B_EVIDENCE_PATH',
            'configuredActorContextTokens', 'configuredJudgeContextTokens',
            "manifest.get('qualification') != 'actual-model-candidate'",
            "manifest.get('activation') != 'no-database-no-persistence'",
        )
        for token in required:
            self.assertIn(token, self.source, token)
        forbidden = ('os.environ.copy()', 'dict(os.environ)', 'dotenv', 'docker ',
                     'PG_TEST_DISPOSABLE', 'DATABASE_URL=', 'OPENAI_API_KEY',
                     'ANTHROPIC_API_KEY', 'AWS_ACCESS_KEY_ID')
        for token in forbidden:
            self.assertNotIn(token, self.source, token)

    def test_child_environment_is_an_explicit_allowlist(self):
        start = self.source.index('child_env = {')
        end = self.source.index("state['suite'].update", start)
        environment_block = self.source[start:end]
        for key in ('PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'NODE_ENV',
                    'AWS_EC2_METADATA_DISABLED', 'LANGCHAIN_TRACING_V2',
                    'LANGSMITH_TRACING', 'NO_PROXY', 'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE',
                    'LEGACY_AI_EXPERIMENT_ACTUAL8B_ISOLATED',
                    'LEGACY_AI_EXPERIMENT_ACTUAL8B_STAGE', 'OLLAMA_BASE_URL',
                    'AI_PROVIDER', 'OLLAMA_MODEL', 'JUDGE_PROVIDER', 'JUDGE_MODEL',
                    'LEGACY_AI_EXPERIMENT_MODEL_DIGEST',
                    'LEGACY_AI_EXPERIMENT_ACTUAL8B_EVIDENCE_PATH'):
            self.assertIn(repr(key), environment_block)
        self.assertNotIn('os.environ', environment_block)

    def test_accepts_complete_redacted_qualification(self):
        path = self.write_result(valid_result(self.module))
        result = self.module.validate_qualification(path)
        self.assertEqual(result['qualification'], 'qualified')
        self.assertEqual(len(result['cases']), 8)

    def test_rejects_raw_private_material(self):
        for key in ('prompt', 'response', 'canary', 'artifactId', 'explanation', 'raw'):
            with self.subTest(key=key):
                value = valid_result(self.module)
                value['cases'][0][key] = 'private material'
                with self.assertRaisesRegex(RuntimeError, 'private result key forbidden'):
                    self.module.validate_qualification(self.write_result(value))

    def test_rejects_unknown_nested_fields_and_call_shapes(self):
        value = valid_result(self.module)
        value['cases'][0]['providerMetadata'] = {'safeLooking': True}
        with self.assertRaisesRegex(RuntimeError, 'case schema'):
            self.module.validate_qualification(self.write_result(value))
        value = valid_result(self.module)
        value['cases'][0]['calls'][0]['extra'] = True
        with self.assertRaisesRegex(RuntimeError, 'model call schema'):
            self.module.validate_qualification(self.write_result(value))

    def test_postconsume_setup_failure_records_terminal_failure(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        grant_path = root / 'grant.json'
        expected = {'grantId': 'grant-1', 'owner': '/root', 'ownerHandle': None}
        grant_path.write_text(json.dumps({'status': 'granted', **expected}) + '\n')
        os.chmod(grant_path, 0o600)
        self.module.consume_one_use_grant(grant_path, expected, root / 'evidence')
        consumed = json.loads(grant_path.read_text())
        self.assertEqual(consumed['status'], 'consumed')
        state = {
            'runStatus': 'terminal_fail_cleaned', 'completedAt': self.module.utc_now(),
            'evidence': str(root / 'evidence'), 'cleanupErrors': [],
            'allProcessGroupsAbsent': True, 'allProcessIdsAbsent': True,
            'suite': {},
        }
        self.module.record_terminal_grant(grant_path, 'grant-1', 9981, state, True)
        terminal = json.loads(grant_path.read_text())
        self.assertEqual(terminal['runStatus'], 'terminal_fail')
        self.assertTrue(terminal['cleanup']['clean'])

    def test_immediate_getpgid_failure_journals_then_uses_group_and_pid_fallback(self):
        class ImmediateChild:
            pid = 44117
            @staticmethod
            def poll():
                return 1
        state = {'processes': {}}
        snapshots = []
        with self.assertRaisesRegex(OSError, 'already exited'):
            self.module.register_owned_process(ImmediateChild(), state,
                lambda: snapshots.append(json.loads(json.dumps(state))),
                getpgid=lambda _pid: (_ for _ in ()).throw(OSError('already exited')))
        self.assertEqual(snapshots[0]['processes']['test']['pid'], 44117)
        self.assertEqual(snapshots[0]['processes']['test']['expectedPgid'], 44117)
        cleanup_calls = []
        cleaned = self.module.cleanup_owned_process(state['processes']['test'], ImmediateChild(),
            group_cleanup=lambda pgid, _process, grace: cleanup_calls.append(('group', pgid)) or True,
            pid_cleanup=lambda pid, _process, grace: cleanup_calls.append(('pid', pid)) or True)
        self.assertTrue(cleaned)
        self.assertEqual(cleanup_calls, [('group', 44117), ('pid', 44117)])

    def test_rejects_failed_positive_and_incomplete_result(self):
        value = valid_result(self.module)
        attack = next(row for row in value['cases'] if row['kind'] == 'attack')
        attack.update(passed=False, failedPositive=True, verdict='fail')
        value.update(qualification='incomplete', failures=[attack['route'] + ':attack'])
        structurally_valid = self.module.validate_qualification(
            self.write_result(value), require_qualified=False)
        self.assertEqual(structurally_valid['qualification'], 'incomplete')
        with self.assertRaisesRegex(RuntimeError, 'failed case'):
            self.module.validate_qualification(self.write_result(value))

    def test_rejects_actor_summary_and_route_kind_semantic_drift(self):
        value = valid_result(self.module)
        value['cases'][0]['actorOutputBytes'] += 1
        with self.assertRaisesRegex(RuntimeError, 'output summary'):
            self.module.validate_qualification(self.write_result(value))
        value = valid_result(self.module)
        baseline = next(row for row in value['cases'] if row['kind'] == 'baseline')
        baseline.update(verdict='pass', observedDisclosure=True, evaluationPassed=True)
        with self.assertRaisesRegex(RuntimeError, 'route-kind semantics'):
            self.module.validate_qualification(self.write_result(value))
        value = valid_result(self.module)
        value['judgeCalibrations'][1]['verdict'] = 'pass'
        with self.assertRaisesRegex(RuntimeError, 'contradicts its label'):
            self.module.validate_qualification(self.write_result(value))

    def test_rejects_missing_route_kind_or_wrong_digest(self):
        value = valid_result(self.module)
        value['cases'][0]['route'] = value['cases'][1]['route']
        value['cases'][0]['kind'] = value['cases'][1]['kind']
        with self.assertRaisesRegex(RuntimeError, 'identity invalid|route-kind semantics'):
            self.module.validate_qualification(self.write_result(value))
        value = valid_result(self.module)
        value['digest'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'identity/configuration mismatch'):
            self.module.validate_qualification(self.write_result(value))

    def test_rejects_unqualified_calibration_or_cancellation(self):
        value = valid_result(self.module)
        value['judgeCalibrations'][0]['passed'] = False
        with self.assertRaisesRegex(RuntimeError, 'Judge calibrations'):
            self.module.validate_qualification(self.write_result(value))
        value = valid_result(self.module)
        value['cancellation']['passed'] = False
        with self.assertRaisesRegex(RuntimeError, 'cancellation'):
            self.module.validate_qualification(self.write_result(value))

    def test_preserves_sparse_preflight_failure_as_incomplete_evidence(self):
        value = valid_result(self.module)
        value.update(qualification='incomplete', modelVerifiedBefore=False,
            modelVerifiedAfter=False, cases=[], judgeCalibrations=[],
            cancellation={'passed': False}, failures=['model-provenance'])
        result = self.module.validate_qualification(
            self.write_result(value), require_qualified=False)
        self.assertEqual(result['cases'], [])
        self.assertEqual(result['failures'], ['model-provenance'])
        with self.assertRaisesRegex(RuntimeError, 'exact eight'):
            self.module.validate_qualification(self.write_result(value))

    def test_invalid_binding_fails_before_files_or_network(self):
        command = [
            sys.executable, str(LAUNCHER), '--package-root', '/', '--manifest', '/dev/null',
            '--managed-node', '/dev/null', '--run-nonce', '000000000000',
            '--evidence-root', '/private/tmp/unused-legacy-ai-actual8b-evidence',
            '--grant-file', '/dev/null', '--grant-id', 'probe', '--owner', '/nobody',
            '--owner-handle-file', '/dev/null', '--canonical-workspace', '/',
            '--model-digest', '0' * 64, '--scope', self.module.SCOPE,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10,
            env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('launch binding invalid', result.stderr)


if __name__ == '__main__':
    unittest.main()
