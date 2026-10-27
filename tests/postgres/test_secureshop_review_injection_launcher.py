"""Resource-free V17 launcher contract; constructed receipts are not actual proof."""
import ast
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
SPEC = importlib.util.spec_from_file_location('v17_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
COHORT = 'review-injection-browser'


class ReviewInjectionLauncher(unittest.TestCase):
    def value(self, **changes):
        value = dict.fromkeys(L.REVIEW_INJECTION_FLAGS, True)
        value.update(scope=L.REVIEW_INJECTION_SCOPE, moderationTurns=2,
                     actorCalls=6, judgeCalls=1, genuineCredit=1, errors=[])
        value.update(changes)
        return value

    def write(self, path, **changes):
        value = self.value(**changes)
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return value

    def test_closed_receipt_matches_original_caller(self):
        fixture = (ROOT / L.REVIEW_INJECTION_TEST).read_text()
        for key in ('ASSERTION', 'SCOPE'):
            self.assertIn(f"const REVIEW_INJECTION_{key} = '{getattr(L, 'REVIEW_INJECTION_' + key)}';", fixture)
        flags = fixture.split('const REVIEW_INJECTION_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), L.REVIEW_INJECTION_FLAGS)
        # Shared fixture bytes evolved for the separate Q05 cohort. V17 binds
        # the current file independently; historical cohort pins remain frozen.
        for name, expected in ((L.REVIEW_INJECTION_TEST, L.REVIEW_INJECTION_TEST_SHA256),
                               (L.REVIEW_INJECTION_HELPER, L.REVIEW_INJECTION_HELPER_SHA256),
                               (L.REVIEW_INJECTION_RECEIPT_TEST, L.REVIEW_INJECTION_RECEIPT_TEST_SHA256)):
            self.assertEqual(L.digest(ROOT / name), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for actor, judge in ((4, 1), (13, 1), (10, 4)):
                expected = self.write(path, actorCalls=actor, judgeCalls=judge)
                self.assertEqual(L.review_injection_receipt(path), expected)

    def test_denies_incomplete_false_extra_wrong_scope_and_budgets(self):
        variants = [{key: False} for key in L.REVIEW_INJECTION_FLAGS] + [
            {'actorCalls': 3}, {'actorCalls': 14}, {'actorCalls': True},
            {'judgeCalls': 0}, {'judgeCalls': 5}, {'judgeCalls': True},
            {'actorCalls': 13, 'judgeCalls': 2}, {'moderationTurns': 1},
            {'moderationTurns': True}, {'genuineCredit': 0}, {'genuineCredit': True},
            {'errors': ['failure']}, {'scope': L.MERCHANT_REVIEW_SCOPE}, {'extra': True}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.write(path, **variant)
                    with self.assertRaises(RuntimeError): L.review_injection_receipt(path)
            value = self.write(path); del value['siblingPositivePreserved']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): L.review_injection_receipt(path)

    def test_private_receipt_and_existing_profile_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'; self.write(path)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): L.review_injection_receipt(path)
            path.chmod(0o600)
            alias = path.with_name('alias.json'); alias.symlink_to(path)
            with self.assertRaises(RuntimeError): L.review_injection_receipt(alias)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp' / 'dvaia-role-choices-unit').mkdir(parents=True)
            self.assertFalse(L.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_original_capture_bodies_model_counts_and_cleanup(self):
        receipt = self.value(actorCalls=4, judgeCalls=1)
        calls = []
        for index in range(1, 6):
            call = dict(index=index, kind='actor' if index < 5 else 'judge', model=L.OLLAMA_MODEL,
                        status=200, responseComplete=True, responseCaptureTruncated=False, terminalReason='end')
            for part, body in [('request', json.dumps({'model': L.OLLAMA_MODEL})), ('response', '{"done":true}')]:
                raw = body.encode(); call.update({part: body, part+'Bytes': len(raw), part+'Sha256': hashlib.sha256(raw).hexdigest()})
            call['responseObservedBytes'] = call['responseBytes']; calls.append(call)
        value = dict(version=1, modelIdentity=dict(model=L.OLLAMA_MODEL, digest='a'*64, maximumPhysicalCalls=14),
                     cleanup=dict(fixtureCleaned=True, errors=[]), wire=calls,
                     cases=[dict(label='vulnerable'), dict(label='fixed')],
                     transcripts=[{}], judgments=[{}], completions=[{}], contributions=[{}])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            def write(candidate):
                path.write_text(json.dumps(candidate)); path.chmod(0o600)
            write(value)
            self.assertEqual(L.review_injection_capture(path, receipt, 'a'*64), L.digest(path))
            changes = [('wire', []), ('cleanup', dict(fixtureCleaned=False, errors=[])),
                       ('modelIdentity', dict(model=L.OLLAMA_MODEL, digest='b'*64, maximumPhysicalCalls=14)),
                       ('cases', [dict(label='vulnerable')]), ('judgments', [])]
            for key, replacement in changes:
                bad = copy.deepcopy(value); bad[key] = replacement; write(bad)
                with self.assertRaises(RuntimeError): L.review_injection_capture(path, receipt, 'a'*64)
            for key, replacement in [('request', 'tampered'), ('responseSha256', 'b'*64), ('index', 3),
                                     ('responseComplete', False), ('responseCaptureTruncated', True),
                                     ('status', 503), ('terminalReason', 'aborted'), ('error', 'failure')]:
                bad = copy.deepcopy(value); bad['wire'][0][key] = replacement; write(bad)
                with self.assertRaises(RuntimeError): L.review_injection_capture(path, receipt, 'a'*64)
            inverse=copy.deepcopy(value);inverse['sourceCase']='reject_product_feedback'
            for row in inverse['cases']:row['sourceCase']='reject_product_feedback'
            selected={**receipt,'sourceCase':'reject_product_feedback'};write(inverse)
            self.assertEqual(L.review_injection_capture(path,selected,'a'*64,source_case='reject_product_feedback'),L.digest(path))
            with self.assertRaises(RuntimeError):L.review_injection_capture(path,receipt,'a'*64,source_case='reject_product_feedback')
            for mutate in (lambda v:v.update(sourceCase='approve_advertisement'),
                           lambda v:v['cases'][1].update(sourceCase='approve_advertisement')):
                bad=copy.deepcopy(inverse);mutate(bad);write(bad)
                with self.assertRaises(RuntimeError):L.review_injection_capture(path,selected,'a'*64,source_case='reject_product_feedback')
            write(value); alias = path.with_name('hardlink.json'); os.link(path, alias)
            with self.assertRaises(RuntimeError): L.review_injection_capture(path, receipt, 'a'*64)

    def test_plan_requires_genuine_judge_four_stores_and_no_allocation(self):
        argv = ['--cohort', COHORT, '--main-workspace', str(ROOT), '--node', '/pinned/node',
                '--docker', '/pinned/docker', '--docker-sha256', 'a'*64,
                '--docker-host', L.EXPECTED_DOCKER_HOST, '--docker-daemon', 'owned-unit',
                '--ollama-model-sha256', 'b'*64, '--plan']
        output = io.StringIO()
        with patch.object(L, 'validate_static', return_value=ROOT), \
                patch.object(L, 'policy_renderer_admission', return_value=None), \
                patch.object(L.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(L.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(L, 'validate_ssh', side_effect=AssertionError('SSH')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], L.REVIEW_INJECTION_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertEqual([plan[key] for key in ('maximumActorCalls', 'maximumJudgeCalls', 'maximumModelCalls', 'moderationTurns')], [13, 4, 14, 2])
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['browser'], True)

    def test_executes_real_provisioning_and_environment_branches_without_resources(self):
        tree = ast.parse(Path(L.__file__).read_text())
        main = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'main')
        statements = [x for x in ast.walk(main) if isinstance(x, ast.If)]
        provisioning = next(x for x in statements if "'standalone-actor'" in ast.unparse(x.test)
                            and any('create_store' in ast.unparse(y) for y in x.body))
        env_branch = next(x for x in statements if ast.unparse(x.test) == "args.cohort == 'review-injection-browser'"
                          and any('env.update' in ast.unparse(y) for y in x.body))
        calls = []
        def create_store(*args):
            calls.append(args[-1]); return {'runtime': 'runtime:' + args[-1], 'migration': 'migration:' + args[-1]}
        ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, browser='/pinned/browser', review_injection_case=None), clean={},
                  captured_id='owned', port=1234, nonce='unit', create_store=create_store,
                  source=ROOT, env={})
        def execute(body):
            exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), '<owned-branch>', 'exec'), ns)
        execute([ast.If(test=provisioning.test, body=provisioning.body, orelse=[])])
        self.assertEqual(calls, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        execute(env_branch.body)
        env = ns['env']
        self.assertEqual(env['SECURESHOP_REVIEW_INJECTION_BROWSER_NATIVE'], '1')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['JUDGE_PROVIDER'], 'ollama')
        pairs = {key: value for key, value in env.items() if key.startswith('PG_')}
        self.assertEqual(len(pairs), 8)
        for role, store in [('IDENTITY', 'identity'), ('AGENTS', 'secureshop_agents'),
                            ('COMMERCE', 'secureshop'), ('REVIEW', 'secureshop_review')]:
            for kind in ('RUNTIME', 'MIGRATION'):
                self.assertEqual(pairs[f'PG_SECURESHOP_REVIEW_INJECTION_BROWSER_{role}_{kind}_URL'], kind.lower()+':'+store)
        self.assertNotIn('SECURESHOP_MERCHANT_REVIEW_BROWSER_NATIVE', env)
        self.assertNotIn('SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_NATIVE', env)
        self.assertEqual(env['SECURESHOP_REVIEW_INJECTION_SOURCE_CASE'],'approve_advertisement')
        ns['args'].review_injection_case='reject_product_feedback'
        execute(env_branch.body)
        self.assertEqual(env['SECURESHOP_REVIEW_INJECTION_SOURCE_CASE'],'reject_product_feedback')

    def test_inverse_selector_is_closed_cohort_only_and_receipt_bound(self):
        argv=['--cohort',COHORT,'--review-injection-case','reject_product_feedback',
            '--main-workspace',str(ROOT),'--node','/pinned/node','--docker','/pinned/docker',
            '--docker-sha256','a'*64,'--docker-host',L.EXPECTED_DOCKER_HOST,
            '--docker-daemon','owned-unit','--ollama-model-sha256','b'*64,'--plan']
        self.assertEqual(L.parse(argv).review_injection_case,'reject_product_feedback')
        invalid=argv.copy();invalid[3]='unknown'
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):L.parse(invalid)
        wrong=argv.copy();wrong[1]='merchant-review-browser'
        with self.assertRaises(ValueError):L.main(wrong)
        output=io.StringIO()
        with patch.object(L,'validate_static',return_value=ROOT), \
                patch.object(L,'policy_renderer_admission',return_value=None), \
                patch.object(L.tempfile,'mkdtemp',side_effect=AssertionError('allocation')), \
                patch.object(L.subprocess,'run',side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main(argv),0)
        plan=json.loads(output.getvalue());self.assertEqual(plan['sourceCase'],'reject_product_feedback')
        self.assertEqual(plan['maximumModelCalls'],14);self.assertEqual(plan['moderationTurns'],2)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt.json';value=self.write(path,sourceCase='reject_product_feedback')
            self.assertEqual(L.review_injection_receipt(path,'reject_product_feedback'),value)
            with self.assertRaises(RuntimeError):L.review_injection_receipt(path)
            for change in ({'sourceCase':'approve_advertisement'},{'sourceCase':None},{'configuredJudgeCredit':False}):
                self.write(path,sourceCase='reject_product_feedback',**{k:v for k,v in change.items() if k!='sourceCase'})
                changed={**value,**change};path.write_text(json.dumps(changed))
                with self.assertRaises(RuntimeError):L.review_injection_receipt(path,'reject_product_feedback')

    def test_exact_tap_rejects_skips_and_wrong_cohort(self):
        text = f'# Subtest: {L.REVIEW_INJECTION_ASSERTION}\nok 1 - {L.REVIEW_INJECTION_ASSERTION}\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n'
        self.assertEqual(L.complete_tap_counts(text, COHORT, [L.REVIEW_INJECTION_ASSERTION])['tests'], 1)
        for changed in (text.replace('# skipped 0', '# skipped 1'), text.replace(L.REVIEW_INJECTION_ASSERTION, L.MERCHANT_REVIEW_ASSERTION)):
            with self.assertRaises(RuntimeError): L.complete_tap_counts(changed, COHORT, [L.REVIEW_INJECTION_ASSERTION])

    def test_source_snapshot_includes_fixture_transport_and_browser_inventories(self):
        with patch.object(L, 'dependency_inventory', return_value={'controlled': 'inventory'}):
            snapshot = L.source_snapshot(ROOT, '/unused/node', COHORT, browser_root=ROOT / 'client/build')
        for name in (L.REVIEW_INJECTION_TEST, 'tests/postgres/secureshopMailActualTransport.js',
                     'sidecars/sandbox-runner/owned-system/contract.js',
                     'tests/fixtures/secureshopOwnedPolicyRendererAdmission.js',
                     'tests/fixtures/secureshopReviewInjectionQualification.js',
                     'tests/secureshopReviewInjectionQualification.test.js',
                     'tests/secureshopReviewInjectionRoleChoicesReceipt.test.js',
                     'tests/postgres/test_secureshop_review_injection_launcher.py'):
            self.assertIn(name, snapshot['sourcePins'])
        # V17's small additive block is followed by the shared production
        # browser closure. Exercise the resulting snapshot, not an AST string.
        directories = ('server/services', 'server/routes', 'server/database/postgres',
                       'server/agent-runtime', 'server/config', 'server/data',
                       'server/utils', 'server/middleware', 'db/postgres', 'client/src')
        for directory in directories:
            expected = {path.relative_to(ROOT).as_posix() for path in (ROOT / directory).rglob('*')
                        if path.is_file() and path.suffix in {'.js', '.cjs', '.mjs', '.jsx', '.json', '.css', '.sql'}}
            self.assertTrue(expected, directory)
            self.assertFalse(expected - snapshot['sourcePins'].keys(), directory)
        for relative in ('server/routes/secureshop/boundGateway.js',
                         'server/services/secureshopBoundReviewComposition.js',
                         'server/services/secureshopReviewContentEvidence.js',
                         'server/database/postgres/secureshopBoundReviewRepository.js',
                         'server/agent-runtime/secureshopSupervisorGraph.js'):
            self.assertEqual(snapshot['sourcePins'][relative], L.digest(ROOT / relative))
        self.assertIn('clientDependencyInventory', snapshot)
        self.assertIn('browserInventory', snapshot)


if __name__ == '__main__': unittest.main()
