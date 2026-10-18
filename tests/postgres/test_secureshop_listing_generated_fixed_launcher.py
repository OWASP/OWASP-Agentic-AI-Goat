"""Resource-free V28 launcher contracts, not rendered/model qualification."""
import ast
import contextlib
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
SPEC = importlib.util.spec_from_file_location('v28_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
COHORT = L.GENERATED_FIXED_BROWSER

class GeneratedFixedLauncher(unittest.TestCase):
    def write(self, path, **changes):
        value = dict.fromkeys(L.STANDALONE_LISTINGS_FLAGS + L.GENERATED_FIXED_FLAGS, True)
        value.update(scope=L.GENERATED_FIXED_SCOPE, cleanupErrors=[])
        value.update(changes)
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return value

    def argv(self):
        return ['--cohort', COHORT, '--main-workspace', str(ROOT), '--node', '/pinned/node',
                '--docker', '/pinned/docker', '--docker-sha256', 'a' * 64,
                '--docker-host', L.EXPECTED_DOCKER_HOST, '--docker-daemon', 'controlled-owned',
                '--ollama-model-sha256', 'b' * 64, '--listings-image-id', 'sha256:' + 'c' * 64, '--plan']

    def test_exact_frozen_producer_and_receipt(self):
        fixture = (ROOT / L.STANDALONE_LISTINGS_TEST).read_text()
        for name, pin in ((L.STANDALONE_LISTINGS_TEST, L.GENERATED_FIXED_TEST_SHA256),
                          (L.GENERATED_FIXED_HELPER, L.GENERATED_FIXED_HELPER_SHA256),
                          (L.GENERATED_FIXED_CONTRACT, L.GENERATED_FIXED_CONTRACT_SHA256)):
            self.assertEqual(L.digest(ROOT / name), pin)
        for name in ('ASSERTION', 'SCOPE'):
            self.assertIn("const GENERATED_FIXED_" + name + " = '" + getattr(L, 'GENERATED_FIXED_' + name) + "';", fixture)
        flags = ast.literal_eval('[' + fixture.split('const GENERATED_FIXED_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0] + ']')
        self.assertEqual(tuple(flags), L.GENERATED_FIXED_FLAGS)
        self.assertEqual(len(flags), 7)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            value = self.write(path)
            self.assertEqual(L.generated_fixed_receipt(path), value)

    def test_false_missing_extra_wrong_scope_failure_and_private_file_denied(self):
        changes = [{key: False} for key in L.STANDALONE_LISTINGS_FLAGS + L.GENERATED_FIXED_FLAGS]
        changes += [{'scope': L.STANDALONE_LISTINGS_SCOPE}, {'cleanupErrors': ['failed']},
                    {'failure': {'message': 'failed'}}, {'actorCalls': 4}, {'extra': True},
                    {'fixedGeneratedActualModel': 1}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for change in changes:
                self.write(path, **change)
                with self.subTest(change=change), self.assertRaises(RuntimeError): L.generated_fixed_receipt(path)
            value = self.write(path); del value['fixedGeneratedOwnerResetFenced']; path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): L.generated_fixed_receipt(path)
            self.write(path); path.chmod(0o644)
            with self.assertRaises(RuntimeError): L.generated_fixed_receipt(path)
            path.chmod(0o600); alias = path.with_name('alias'); alias.symlink_to(path)
            with self.assertRaises(RuntimeError): L.generated_fixed_receipt(alias)
            alias.unlink(); os.link(path, alias)
            with self.assertRaises(RuntimeError): L.generated_fixed_receipt(path)

    def test_static_rejects_changed_sources_and_template_injection_before_allocation(self):
        args = L.parser().parse_args(self.argv())
        real_digest = L.digest
        for relative in (L.STANDALONE_LISTINGS_TEST, L.GENERATED_FIXED_HELPER, L.GENERATED_FIXED_CONTRACT):
            with patch.object(L, 'digest', side_effect=lambda path: 'f' * 64 if Path(path) == ROOT / relative else real_digest(path)):
                with self.assertRaisesRegex(RuntimeError, 'Frozen V28'): L.validate_static(args)
        args.listing_template_qualification = '/foreign/template.json'
        args.listing_template_qualification_sha256 = 'f' * 64
        with self.assertRaisesRegex(RuntimeError, 'exclusive to Listings browser'): L.validate_static(args)

    def test_plan_no_allocation_four_stores_and_real_judge(self):
        output = io.StringIO()
        with patch.object(L, 'validate_static', return_value=ROOT), \
                patch.object(L, 'policy_renderer_admission', return_value=None), \
                patch.object(L.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(L.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(L, 'validate_ssh', side_effect=AssertionError('SSH')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main(self.argv()), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['cohort'], L.GENERATED_FIXED_COHORT)
        self.assertEqual(result['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        for name in ('browser', 'actualJudgeRequired'): self.assertIs(result[name], True)
        for name in ('sourceCopy', 'nativeStarted'): self.assertIs(result[name], False)
        self.assertEqual(result['tests'], 1)

    def test_executes_real_four_store_and_environment_dispatch(self):
        tree = ast.parse(Path(L.__file__).read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        branches = [n for n in ast.walk(main) if isinstance(n, ast.If)]
        provision = next(n for n in branches if "'standalone-actor'" in ast.unparse(n.test)
                         and any('create_store' in ast.unparse(v) for v in n.body))
        manager = next(n for n in branches if 'GENERATED_FIXED_BROWSER' in ast.unparse(n.test)
                       and any('listings_candidate(' in ast.unparse(v) for v in n.body))
        calls = []
        def create_store(*args):
            calls.append(args[-1]); return {'runtime': 'runtime:' + args[-1], 'migration': 'migration:' + args[-1]}
        ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, browser='/pinned/browser',
                  docker_host='owned-host', docker_daemon='owned-daemon'),
                  source=ROOT, env={}, clean={}, captured_id='owned', port=1234, nonce='nonce',
                  create_store=create_store, manager_origin='http://127.0.0.1:1234', manager_token='synthetic',
                  manager_image='sha256:' + 'a' * 64, manager_id='b' * 64, template_admission=None,
                  candidate=dict(runtimeDigest='c' * 64, sourceSha256='d' * 64, authoritySha256='e' * 64))
        def execute(body):
            exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), '<controlled-branch>', 'exec'), ns)
        execute([ast.If(test=provision.test, body=provision.body, orelse=[])])
        self.assertEqual(calls, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertTrue(eval(compile(ast.Expression(manager.test), '<manager-dispatch>', 'eval'), ns))
        start = next(i for i, n in enumerate(manager.body) if isinstance(n, ast.Expr)
                     and isinstance(n.value, ast.Call) and ast.unparse(n.value.func) == 'env.update')
        execute(manager.body[start:])
        env = ns['env']
        self.assertEqual(env[L.GENERATED_FIXED_FLAG], '1')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['JUDGE_PROVIDER'], 'ollama'); self.assertEqual(env['JUDGE_MODEL'], L.OLLAMA_MODEL)
        self.assertEqual(len([key for key in env if key.startswith('PG_SECURESHOP_STANDALONE_LISTINGS_')]), 8)
        for key in ('SECURESHOP_STANDALONE_LISTINGS_NATIVE', 'SECURESHOP_PRODUCT_MANUAL_BROWSER_NATIVE',
                    'SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_NATIVE', 'SECURESHOP_STANDALONE_LISTINGS_TEMPLATE_URL'):
            self.assertNotIn(key, env)

    def test_exact_tap_and_required_manager_browser_cleanup(self):
        title = L.GENERATED_FIXED_ASSERTION
        tap = f'# Subtest: {title}\nok 1 - {title}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(L.complete_tap_counts(tap, COHORT, [title])['tests'], 1)
        for bad in (tap.replace('# skipped 0', '# skipped 1'), tap.replace(title, L.STANDALONE_LISTINGS_ASSERTION)):
            with self.assertRaises(RuntimeError): L.complete_tap_counts(bad, COHORT, [title])
        tree = ast.parse(Path(L.__file__).read_text())
        assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'clean_cleanup' for t in n.targets))
        cleanup = dict(containerNameAbsent=True, containerIdAbsent=True, browserProfilesAbsent=True,
                       browserProcessesAbsent=True, listings=dict.fromkeys(('containerAbsent', 'volumeAbsent', 'networkAbsent', 'profileAbsent'), True))
        ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT), cleanup_errors=[], cleanup=cleanup)
        expression = compile(ast.Expression(assignment.value), '<cleanup>', 'eval')
        self.assertTrue(eval(expression, ns))
        for key in list(cleanup['listings']):
            cleanup['listings'][key] = False; self.assertFalse(eval(expression, ns)); cleanup['listings'][key] = True
        del cleanup['listings']; self.assertFalse(eval(expression, ns))

    def test_executes_exact_native_dispatch_evidence_and_postchecks(self):
        tree = ast.parse(Path(L.__file__).read_text())
        branches = [n for n in ast.walk(tree) if isinstance(n, ast.If)]
        child = next(n for n in branches if 'GENERATED_FIXED_BROWSER' in ast.unparse(n.test)
                     and any('standalone_listings_result =' in ast.unparse(v) for v in n.body))
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory); calls = []; checked = []
            def run_node(label, command, timeout):
                calls.append((label, command, timeout))
                receipt_path = Path(ns['env'][L.GENERATED_FIXED_EVIDENCE_ENV])
                self.write(receipt_path)
                title = L.GENERATED_FIXED_ASSERTION
                tap = evidence / (label + '.tap')
                tap.write_text(f'# Subtest: {title}\nok 1 - {title}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
                ns['tap_paths'][label] = tap
            def digest(path):
                checked.append(str(path))
                return L.NODE_SHA256 if str(path) == '/pinned/node' else 'a' * 64
            ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, node='/pinned/node', browser='/pinned/browser',
                      browser_sha256='a' * 64, ollama_model_sha256='b' * 64), env={}, evidence=evidence,
                      runtime=evidence, run_node=run_node, tap_paths={}, effect_counts={}, template_resources=None,
                      template_admission=None, digest=digest, model_pin={'digest': 'b' * 64},
                      verify_ollama_model=lambda pin: {'digest': pin},
                      standalone_browser_cleanup_state=lambda path: {'profilesAbsent': True, 'processesAbsent': True})
            exec(compile(ast.fix_missing_locations(ast.Module(body=child.body, type_ignores=[])), '<child-dispatch>', 'exec'), ns)
            self.assertEqual(calls, [(COHORT, ['/pinned/node', '--test', '--test-reporter=tap', '--test-concurrency=1', L.STANDALONE_LISTINGS_TEST], 600)])
            self.assertEqual(ns['env'], {L.GENERATED_FIXED_EVIDENCE_ENV: str(evidence / (COHORT + '.json'))})
            self.assertEqual(ns['standalone_listings_result']['scope'], L.GENERATED_FIXED_SCOPE)
            self.assertEqual(checked.count('/pinned/browser'), 2); self.assertEqual(checked.count('/pinned/node'), 2)
            self.assertTrue((evidence / 'local-model-after.json').is_file())

    def test_actual_source_snapshot_includes_fixture_helper_runtime_and_inventories(self):
        with patch.object(L, 'dependency_inventory', return_value={'controlled': 'inventory'}):
            snapshot = L.source_snapshot(ROOT, '/unused/node', COHORT, browser_root=ROOT / 'client/build')
        for relative in (L.STANDALONE_LISTINGS_TEST, L.GENERATED_FIXED_HELPER, L.GENERATED_FIXED_CONTRACT,
                         'tests/postgres/test_secureshop_listing_generated_fixed_launcher.py',
                         'tests/postgres/listings_native_resources.py', 'sidecars/sandbox-runner/owned-listings/namespace-worker.js',
                         'server/services/secureshopBoundReviewComposition.js', 'server/agent-runtime/objectiveJudge.js',
                         'server/database/postgres/secureshopAssessmentStore.js'):
            self.assertEqual(snapshot['sourcePins'][relative], L.digest(ROOT / relative))
        self.assertIn('clientDependencyInventory', snapshot); self.assertIn('browserInventory', snapshot)

if __name__ == '__main__': unittest.main()
