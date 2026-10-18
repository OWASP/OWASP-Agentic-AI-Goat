"""Controlled V15 launcher/retained-capture contract; no actual resource proof."""
import ast
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('v15_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(L)
COHORT = L.SCENE_AUDIT_BROWSER
UUID = '11111111-1111-4111-8111-111111111111'

class SceneAuditLauncher(unittest.TestCase):
    def receipt(self):
        return dict(dict.fromkeys(L.SCENE_AUDIT_FLAGS, True), scope=L.SCENE_AUDIT_SCOPE,
                    merchantEventId='review:' + UUID, summaryRunId=UUID, actorCalls=4, judgeCalls=2, errors=[])

    def capture(self):
        raw = b'original observed artifact'
        ref = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        refs = {name: dict(ref) for name in ('effects', 'log', 'sources', 'messages', 'traces')}
        reads = {name: dict(ref, observedBytes=len(raw), complete=True, oversized=False,
                           base64=base64.b64encode(raw).decode()) for name in refs}
        return dict(scope=L.SCENE_AUDIT_SCOPE, actualQualification=False,
                    physicalMerchantSave={}, originalSource={'entry': {'id': 'review:' + UUID}}, fences={},
                    observed={'failure': None, 'actorCalls': 4, 'judgeCalls': 2,
                              'configuredJudge': [{'controlled': 'test observation'}], 'judgeTranscripts': [{}]},
                    runs={mode: dict(mode=mode, savedResult={'runId': UUID, 'evidence': {'artifacts': refs}},
                                     artifactRefs=refs, artifactReads=reads) for mode in ('vuln', 'fixed')})

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def argv(self):
        return ['--cohort', COHORT, '--main-workspace', str(ROOT), '--node', '/pinned/node',
                '--docker', '/pinned/docker', '--docker-sha256', 'a' * 64,
                '--docker-host', L.EXPECTED_DOCKER_HOST, '--docker-daemon', 'owned',
                '--ollama-model-sha256', 'b' * 64, '--plan']

    def test_exact_frozen_producer_and_closed_receipt(self):
        fixture = (ROOT / L.ADMIN_AUDIT_JOBS_TEST).read_text()
        for name, pin in ((L.ADMIN_AUDIT_JOBS_TEST, L.SCENE_AUDIT_TEST_SHA256),
                          (L.SCENE_AUDIT_HELPER, L.SCENE_AUDIT_HELPER_SHA256),
                          (L.SCENE_AUDIT_CONTRACT, L.SCENE_AUDIT_CONTRACT_SHA256)):
            self.assertEqual(L.digest(ROOT / name), pin)
        for name in ('ASSERTION', 'SCOPE'):
            self.assertIn("const V15_" + name + " = '" + getattr(L, 'SCENE_AUDIT_' + name) + "';", fixture)
        flags = ast.literal_eval('[' + fixture.split('const V15_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0] + ']')
        self.assertEqual(tuple(flags), L.SCENE_AUDIT_FLAGS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'; value = self.receipt()
            self.write(path, value); self.assertEqual(L.scene_audit_receipt(path), value)
            variants = [{key: False} for key in L.SCENE_AUDIT_FLAGS] + [
                {'actorCalls': 1}, {'actorCalls': 29}, {'actorCalls': True}, {'judgeCalls': 0},
                {'judgeCalls': 13}, {'judgeCalls': True}, {'merchantEventId': UUID},
                {'summaryRunId': 'bad'}, {'scope': L.ADMIN_AUDIT_JOBS_SCOPE}, {'extra': True}, {'errors': ['failed']}]
            for change in variants:
                self.write(path, dict(value, **change))
                with self.subTest(change=change), self.assertRaises(RuntimeError): L.scene_audit_receipt(path)
            for actors, judges in ((2, 1), (28, 12)):
                self.write(path, dict(value, actorCalls=actors, judgeCalls=judges)); L.scene_audit_receipt(path)

    def test_original_capture_integrity_not_a_qualification_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / L.SCENE_AUDIT_CAPTURE; capture = self.capture()
            self.write(path, capture)
            result = L.scene_audit_evidence(path, self.receipt())
            self.assertEqual(result['sha256'], L.digest(path)); self.assertEqual(result['originalArtifactReads'], 10)
            for case in range(8):
                changed = copy.deepcopy(capture)
                if case == 0: changed['actualQualification'] = True
                if case == 1: changed['observed']['judgeCalls'] = 0
                if case == 2: changed['observed']['failure'] = {'stage': 'failed'}
                if case == 3: changed['runs']['vuln']['artifactReads']['log']['base64'] = 'dGFtcGVy'
                if case == 4: changed['runs']['fixed']['artifactReads']['log']['complete'] = False
                if case == 5: del changed['runs']['fixed']['artifactReads']['traces']
                if case == 6: changed['runs']['vuln']['savedResult']['runId'] = 'other'
                if case == 7: changed['originalSource']['entry']['id'] = 'review:other'
                self.write(path, changed)
                with self.subTest(case=case), self.assertRaises(RuntimeError): L.scene_audit_evidence(path, self.receipt())
            self.write(path, capture); path.chmod(0o644)
            with self.assertRaises(RuntimeError): L.scene_audit_evidence(path, self.receipt())
            path.chmod(0o600); alias = path.with_name('alias'); alias.symlink_to(path)
            with self.assertRaises(RuntimeError): L.scene_audit_evidence(alias, self.receipt())
            alias.unlink(); os.link(path, alias)
            with self.assertRaises(RuntimeError): L.scene_audit_evidence(path, self.receipt())

    def test_nonallocating_plan_keeps_four_stores_real_judge_and_narrow_scope(self):
        output = io.StringIO()
        with patch.object(L, 'validate_static', return_value=ROOT), \
                patch.object(L, 'policy_renderer_admission', return_value=None), \
                patch.object(L.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(L.subprocess, 'run', side_effect=AssertionError('process')), contextlib.redirect_stdout(output):
            self.assertEqual(L.main(self.argv()), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['cohort'], L.SCENE_AUDIT_COHORT)
        self.assertEqual(value['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertTrue(value['actualJudgeRequired']); self.assertFalse(value['sourceCopy']); self.assertFalse(value['nativeStarted'])
        self.assertEqual(value['objectiveScope'], L.SCENE_AUDIT_SCOPE)
        self.assertIn('outside this qualification', L.SCENE_AUDIT_SCOPE)

    def test_source_closure_and_preallocation_source_drift_denial(self):
        with patch.object(L, 'dependency_inventory', return_value={'controlled': True}):
            value = L.source_snapshot(ROOT, '/unused/node', COHORT, browser_root=ROOT / 'client/build')
        for relative in (L.ADMIN_AUDIT_JOBS_TEST, L.SCENE_AUDIT_HELPER, L.SCENE_AUDIT_CONTRACT,
                         L.ADMIN_DIRECT_AUDIT_HELPER, 'tests/postgres/test_secureshop_scene_audit_v15_launcher.py',
                         'sidecars/audit-sql-target/service.js', 'server/agent-runtime/objectiveJudge.js',
                         'server/database/postgres/secureshopAssessmentStore.js'):
            self.assertEqual(value['sourcePins'][relative], L.digest(ROOT / relative))
        args = L.parser().parse_args(self.argv()); real_digest = L.digest
        for relative in (L.ADMIN_AUDIT_JOBS_TEST, L.SCENE_AUDIT_HELPER, L.SCENE_AUDIT_CONTRACT):
            with patch.object(L, 'digest', side_effect=lambda path: 'f' * 64 if Path(path) == ROOT / relative else real_digest(path)):
                with self.assertRaisesRegex(RuntimeError, 'Frozen V15'): L.validate_static(args)

    def test_actual_environment_dispatch_and_audit_container_cleanup_gate(self):
        tree = ast.parse(Path(L.__file__).read_text())
        branches = [n for n in ast.walk(tree) if isinstance(n, ast.If)]
        environment = next(n for n in branches if 'SCENE_AUDIT_BROWSER' in ast.unparse(n.test)
                           and any('SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_NATIVE' in ast.unparse(v) for v in n.body))
        ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, browser='/pinned/browser'), source=ROOT,
                  env={}, audit_port=54321, audit_database='dvaia_audit_control_abc',
                  **{name: {'runtime': name + ':runtime', 'migration': name + ':migration'} for name in ('identity', 'agents', 'reviews', 'commerce')})
        exec(compile(ast.fix_missing_locations(ast.Module(body=environment.body, type_ignores=[])), '<environment>', 'exec'), ns)
        env = ns['env']
        for key in ('SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_NATIVE', 'SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE', 'LIVE_OLLAMA_TEST'):
            self.assertEqual(env[key], '1')
        self.assertNotIn('SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE', env)
        self.assertEqual(env['JUDGE_PROVIDER'], 'ollama'); self.assertEqual(env['JUDGE_MODEL'], L.OLLAMA_MODEL)
        self.assertEqual(len([key for key in env if key.startswith('PG_SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_')]), 8)
        cleanup = dict(containerNameAbsent=True, containerIdAbsent=True, browserProfilesAbsent=True,
                       browserProcessesAbsent=True, auditControlContainerNameAbsent=True, auditControlContainerIdAbsent=True)
        assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'clean_cleanup' for t in n.targets))
        expression = compile(ast.Expression(assignment.value), '<cleanup>', 'eval')
        ns.update(cleanup=cleanup, cleanup_errors=[])
        self.assertTrue(eval(expression, ns))
        cleanup['auditControlContainerIdAbsent'] = False; self.assertFalse(eval(expression, ns))

    def test_child_dispatch_requires_original_capture_and_postchecks(self):
        tree = ast.parse(Path(L.__file__).read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                      and ast.unparse(n.test) == 'args.cohort == SCENE_AUDIT_BROWSER'
                      and any('run_node(' in ast.unparse(v) for v in n.body))
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory); calls = []; checked = []
            def run_node(label, command, timeout):
                calls.append((label, command, timeout))
                self.write(Path(ns['env']['SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH']), self.receipt())
                self.write(evidence / L.SCENE_AUDIT_CAPTURE, self.capture())
                title = L.SCENE_AUDIT_ASSERTION
                tap = evidence / (label + '.tap')
                tap.write_text(f'# Subtest: {title}\nok 1 - {title}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
                ns['tap_paths'][label] = tap
            def digest(path):
                checked.append(str(path))
                return L.NODE_SHA256 if str(path) == '/pinned/node' else 'a' * 64
            ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, node='/pinned/node', browser='/pinned/browser',
                      browser_sha256='a' * 64, ollama_model_sha256='b' * 64), env={}, evidence=evidence,
                      runtime=evidence, run_node=run_node, tap_paths={}, effect_counts={}, digest=digest,
                      model_pin={'digest': 'b' * 64}, verify_ollama_model=lambda pin: {'digest': pin},
                      standalone_browser_cleanup_state=lambda path: {'profilesAbsent': True, 'processesAbsent': True})
            exec(compile(ast.fix_missing_locations(ast.Module(body=branch.body, type_ignores=[])), '<child>', 'exec'), ns)
            self.assertEqual(calls, [(COHORT, ['/pinned/node', '--test', '--test-reporter=tap', '--test-concurrency=1', L.ADMIN_AUDIT_JOBS_TEST], 900)])
            self.assertEqual(ns['scene_audit_result'], self.receipt())
            self.assertEqual(ns['scene_audit_capture']['sha256'], L.digest(evidence / L.SCENE_AUDIT_CAPTURE))
            self.assertEqual(checked.count('/pinned/browser'), 2); self.assertEqual(checked.count('/pinned/node'), 2)
            self.assertTrue((evidence / 'local-model-after.json').is_file())

    def test_exact_tap_rejects_old_jobs_or_skipped_proof(self):
        title = L.SCENE_AUDIT_ASSERTION
        tap = f'# Subtest: {title}\nok 1 - {title}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(L.complete_tap_counts(tap, COHORT, [title])['tests'], 1)
        for bad in (tap.replace('# skipped 0', '# skipped 1'), tap.replace(title, L.ADMIN_AUDIT_JOBS_ASSERTION)):
            with self.assertRaises(RuntimeError): L.complete_tap_counts(bad, COHORT, [title])

if __name__ == '__main__': unittest.main()
