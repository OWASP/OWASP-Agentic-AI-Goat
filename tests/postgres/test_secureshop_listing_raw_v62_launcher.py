"""Resource-free V62 launcher contract; constructed receipts are not actual proof."""
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
SPEC = importlib.util.spec_from_file_location('v62_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
COHORT = L.LISTING_RAW_BROWSER


class ListingRawLauncher(unittest.TestCase):
    def value(self, **changes):
        value = dict.fromkeys(L.LISTING_RAW_FLAGS, True)
        value.update(scope=L.LISTING_RAW_SCOPE, roleTurns=2,
                     actorCalls=6, judgeCalls=1, genuineCredit=1, browserEffects=1, errors=[])
        value.update(changes)
        return value

    def write(self, path, **changes):
        value = self.value(**changes)
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return value

    def test_closed_receipt_matches_original_caller(self):
        fixture = (ROOT / L.LISTING_RAW_TEST).read_text()
        for key in ('ASSERTION', 'SCOPE'):
            self.assertIn(f"const LISTING_RAW_{key} = '{getattr(L, 'LISTING_RAW_' + key)}';", fixture)
        flags = fixture.split('const LISTING_RAW_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), L.LISTING_RAW_FLAGS)
        self.assertEqual(L.LISTING_RAW_TEST_SHA256, L.MERCHANT_MAIL_HEADER_TEST_SHA256)
        self.assertEqual(L.LISTING_RAW_TEST_SHA256, L.POLICY_INSTRUCTION_TEST_SHA256)
        for name, expected in ((L.LISTING_RAW_TEST, L.LISTING_RAW_TEST_SHA256),
                               (L.LISTING_RAW_HELPER, L.LISTING_RAW_HELPER_SHA256),
                               (L.LISTING_RAW_CONTRACT, L.LISTING_RAW_CONTRACT_SHA256)):
            self.assertEqual(L.digest(ROOT / name), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for actor, judge in ((2, 1), (12, 2), (11, 3)):
                expected = self.write(path, actorCalls=actor, judgeCalls=judge)
                self.assertEqual(L.listing_raw_receipt(path), expected)

    def test_denies_incomplete_false_extra_wrong_scope_and_budgets(self):
        variants = [{key: False} for key in L.LISTING_RAW_FLAGS] + [
            {'actorCalls': 1}, {'actorCalls': 13}, {'actorCalls': True},
            {'judgeCalls': 0}, {'judgeCalls': 4}, {'judgeCalls': True},
            {'actorCalls': 12, 'judgeCalls': 3}, {'roleTurns': 1},
            {'roleTurns': True}, {'genuineCredit': 0}, {'genuineCredit': True},
            {'errors': ['failure']}, {'scope': L.MERCHANT_REVIEW_SCOPE}, {'extra': True}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.write(path, **variant)
                    with self.assertRaises(RuntimeError): L.listing_raw_receipt(path)
            value = self.write(path); del value['siblingDenied']
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): L.listing_raw_receipt(path)

    def test_private_receipt_and_existing_profile_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'; self.write(path)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): L.listing_raw_receipt(path)
            path.chmod(0o600)
            alias = path.with_name('alias.json'); alias.symlink_to(path)
            with self.assertRaises(RuntimeError): L.listing_raw_receipt(alias)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp' / 'dvaia-role-listing-raw-browser-unit').mkdir(parents=True)
            self.assertFalse(L.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_original_capture_bodies_model_counts_and_cleanup(self):
        receipt = self.value(actorCalls=2, judgeCalls=1)
        calls = []
        for index in range(1, 4):
            call = dict(index=index, kind='actor' if index < 3 else 'judge', model=L.OLLAMA_MODEL,
                        status=200, responseComplete=True, responseCaptureTruncated=False, terminalReason='end')
            for part, body in [('request', json.dumps({'model': L.OLLAMA_MODEL, 'messages': []})),
                               ('response', json.dumps({'message': {'content': 'pass'}}))]:
                raw = body.encode(); call.update({part: body, part+'Bytes': len(raw), part+'Sha256': hashlib.sha256(raw).hexdigest()})
            call['responseObservedBytes'] = call['responseBytes']; calls.append(call)
        proof = {'calls': [{'provider': 'ollama', 'model': L.OLLAMA_MODEL,
            'requestSha256': hashlib.sha256(b'{"method":"chat","input":[],"schema":null}').hexdigest(),
            'responseSha256': hashlib.sha256(b'pass').hexdigest()}]}
        original_receipt = {'version': 2, 'status': 'completed', 'operationId': 'original', 'scopeKey': 'c'*64,
            'sourceDocumentSha256': 'a' * 64,
            'source': {'kind': 'merchant_authored_html', 'execution': {'mode': 'vuln'}}}
        saved = dict(original_receipt, replayed=True)
        effect = {'operationId': 'original', 'productId': 32,
            'originalSessionId': 'session', 'originalRequestId': 'request',
            'component': {'id': 'SecureShop.Product.Description'}, 'sourceDocumentSha256': 'a' * 64,
            'source': original_receipt['source'], 'receipt': saved,
            'browser': {'targetEventExecuted': True, 'syntheticCookieOnly': True, 'markers': ['owned']},
            'browserEffectReceipt': {'status': 'completed', 'effectKey': 'request:listing-raw-browser:original:effect'}}
        judgment = {'evaluation_id': 'evaluation', 'verdict': 'pass', 'judge_observations': proof,
            'judge_result_json': '{"verdict":"pass"}', 'packet': {
                'rubric': {'objectiveId': 'ss_listing_raw_browser_execution'},
                'facts': {'completed_browser_effect': True},
                'evidence': [{'id': 'listing_raw_audit', 'source': 'server_observation', 'content': effect},
                    {'id': 'listing_raw_outcome', 'source': 'server_observation', 'content': {
                        'kind': 'saved_merchant_authored_html', 'productId': 32,
                        'component': 'SecureShop.Product.Description', 'markers': ['owned']}}]}}
        judgment['packet'] = json.dumps(judgment['packet'])
        judgment['evidence_digest'] = hashlib.sha256(judgment['packet'].encode()).hexdigest()
        value = dict(version=1, modelIdentity=dict(model=L.OLLAMA_MODEL, digest='a'*64, maximumPhysicalCalls=14),
            cleanup=dict(fixtureCleaned=True, errors=[]), wire=calls, transcripts=[{}], listingRawBrowser={
                'result': {'actualQualification': False, 'objectiveId': 'ss_listing_raw_browser_execution',
                    'evaluationId': 'evaluation', 'vulnerableOperationId': 'original', 'fixedOperationId': 'fixed'},
                'fixed': {'receipt': {'operationId': 'fixed', 'source': {'execution': {'mode': 'fixed'}}},
                    'assessment': {'operationId': 'fixed', 'completed': False, 'status': 'ineligible', 'modelEvaluated': False}},
                'original': {'receipt': original_receipt, 'assessment': {'completed': True,
                    'judgment': {'verdict': 'pass', 'evaluationId': 'evaluation'}},
                    'source': {'sessionId': 'session', 'requestId': 'request', 'sourceRead': {'receipt': saved}}, 'judgment': judgment,
                    'judgeProof': proof, 'originalJudge': {'verdict': 'pass'}}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.json'
            def write(candidate): path.write_text(json.dumps(candidate)); path.chmod(0o600)
            value['listingRawBrowser']['sibling'] = {
                'foreignSource': {'status': 200, 'value': {'operationId': 'original',
                    'status': 'not_found', 'scopeKey': 'd'*64}},
                'foreignAssessment': {'status': 503, 'value': {'error': 'Role assistant unavailable'}}}
            value['listingRawBrowser']['reset'] = {name: {'status': status,
                'value': {'error': error}} for name, status, error in (
                ('oldSource', 401, 'Shop authentication required'),
                ('oldAssessment', 401, 'Shop authentication required'),
                ('renewedSource', 401, 'Shop session unavailable'),
                ('renewedAssessment', 503, 'Role assistant unavailable'))}
            write(value)
            self.assertEqual(L.listing_raw_capture(path, receipt, 'a'*64), L.digest(path))
            for section, name in [('sibling', 'foreignSource'), ('sibling', 'foreignAssessment')] + [
                    ('reset', name) for name in ('oldSource', 'oldAssessment', 'renewedSource', 'renewedAssessment')]:
                for mutation in ('status', 'body', 'extra'):
                    bad = copy.deepcopy(value)
                    response = bad['listingRawBrowser'][section][name]
                    if mutation == 'status': response['status'] = 404
                    if mutation == 'body': response['value'] = {'error': 'arbitrary failure'}
                    if mutation == 'extra': response['value']['privateData'] = 'leak'
                    write(bad)
                    with self.subTest(response=name, mutation=mutation), self.assertRaises(RuntimeError):
                        L.listing_raw_capture(path, receipt, 'a'*64)
            # Valid route errors cannot be substituted across reset phases.
            for name, replacement in (
                    ('oldSource', {'status': 401, 'value': {'error': 'Shop session unavailable'}}),
                    ('oldAssessment', {'status': 401, 'value': {'error': 'SecureShop launch unavailable'}}),
                    ('renewedSource', {'status': 401, 'value': {'error': 'Shop authentication required'}}),
                    ('renewedAssessment', {'status': 401, 'value': {'error': 'Shop session unavailable'}})):
                bad = copy.deepcopy(value)
                bad['listingRawBrowser']['reset'][name] = replacement
                write(bad)
                with self.subTest(wrong_phase=name), self.assertRaises(RuntimeError):
                    L.listing_raw_capture(path, receipt, 'a'*64)
            for scope in ('c'*64, 'invalid'):
                bad = copy.deepcopy(value)
                bad['listingRawBrowser']['sibling']['foreignSource']['value']['scopeKey'] = scope
                write(bad)
                with self.assertRaises(RuntimeError): L.listing_raw_capture(path, receipt, 'a'*64)

            for key, replacement in [('request', 'tampered'), ('responseSha256', 'b'*64), ('index', 3),
                    ('responseComplete', False), ('responseCaptureTruncated', True), ('status', 503)]:
                bad = copy.deepcopy(value); bad['wire'][0][key] = replacement; write(bad)
                with self.assertRaises(RuntimeError): L.listing_raw_capture(path, receipt, 'a'*64)
            for case in range(4):
                bad = copy.deepcopy(value)
                if case == 0: bad['listingRawBrowser']['result']['evaluationId'] = 'foreign'
                if case == 1: bad['listingRawBrowser']['original']['source']['sourceRead']['receipt'] = {}
                if case == 2: bad['listingRawBrowser']['fixed']['assessment']['modelEvaluated'] = True
                if case == 3: bad['listingRawBrowser']['original']['judgeProof']['calls'][0]['requestSha256'] = 'b'*64
                write(bad)
                with self.assertRaises(RuntimeError): L.listing_raw_capture(path, receipt, 'a'*64)
            # Stored packet is serialized and digest-bound; old synthetic schema is denied.
            for case in range(10):
                bad = copy.deepcopy(value)
                row = bad['listingRawBrowser']['original']['judgment']
                packet = json.loads(row['packet'])
                if case == 0: row['packet'] = packet
                elif case == 1: row['evidence_digest'] = 'b' * 64
                else:
                    if case == 2: packet['evidence'][0]['id'] = 'listing_raw_owned_effect'
                    if case == 3: packet['evidence'].reverse()
                    if case == 4: packet['evidence'][0]['source'] = 'caller_attestation'
                    if case == 5: packet['evidence'][0]['content']['browser']['targetEventExecuted'] = False
                    if case == 6: packet['evidence'][0]['content']['originalSessionId'] = 'foreign'
                    if case == 7: packet['evidence'][1]['content']['productId'] = 999
                    if case == 8: packet['evidence'][1]['content']['markers'] = ['foreign']
                    if case == 9: packet['evidence'][0]['content']['receipt'] = original_receipt
                    row['packet'] = json.dumps(packet)
                    row['evidence_digest'] = hashlib.sha256(row['packet'].encode()).hexdigest()
                write(bad)
                with self.subTest(packet_case=case), self.assertRaises(RuntimeError):
                    L.listing_raw_capture(path, receipt, 'a'*64)
            write(value); alias = path.with_name('hardlink.json'); os.link(path, alias)
            with self.assertRaises(RuntimeError): L.listing_raw_capture(path, receipt, 'a'*64)

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
        self.assertEqual(plan['cohort'], L.LISTING_RAW_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertIs(plan['actualJudgeRequired'], True)
        self.assertEqual([plan[key] for key in ('maximumActorCalls', 'maximumJudgeCalls', 'maximumModelCalls', 'roleTurns')], [12, 3, 14, 2])
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['browser'], True)

    def test_executes_real_provisioning_and_environment_branches_without_resources(self):
        tree = ast.parse(Path(L.__file__).read_text())
        main = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'main')
        statements = [x for x in ast.walk(main) if isinstance(x, ast.If)]
        provisioning = next(x for x in statements if "'standalone-actor'" in ast.unparse(x.test)
                            and any('create_store' in ast.unparse(y) for y in x.body))
        env_branch = next(x for x in statements if ast.unparse(x.test) == 'args.cohort == LISTING_RAW_BROWSER'
                          and any('env.update' in ast.unparse(y) for y in x.body))
        calls = []
        def create_store(*args):
            calls.append(args[-1]); return {'runtime': 'runtime:' + args[-1], 'migration': 'migration:' + args[-1]}
        ns = dict(vars(L), args=SimpleNamespace(cohort=COHORT, browser='/pinned/browser'), clean={},
                  captured_id='owned', port=1234, nonce='unit', create_store=create_store,
                  source=ROOT, env={})
        def execute(body):
            exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), '<owned-branch>', 'exec'), ns)
        execute([ast.If(test=provisioning.test, body=provisioning.body, orelse=[])])
        self.assertEqual(calls, ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        execute(env_branch.body)
        env = ns['env']
        self.assertEqual(env['SECURESHOP_LISTING_RAW_BROWSER_NATIVE'], '1')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['JUDGE_PROVIDER'], 'ollama')
        pairs = {key: value for key, value in env.items() if key.startswith('PG_')}
        self.assertEqual(len(pairs), 8)
        for role, store in [('IDENTITY', 'identity'), ('AGENTS', 'secureshop_agents'),
                            ('COMMERCE', 'secureshop'), ('REVIEW', 'secureshop_review')]:
            for kind in ('RUNTIME', 'MIGRATION'):
                self.assertEqual(pairs[f'PG_SECURESHOP_LISTING_RAW_BROWSER_{role}_{kind}_URL'], kind.lower()+':'+store)
        self.assertNotIn('SECURESHOP_MERCHANT_REVIEW_BROWSER_NATIVE', env)
        self.assertNotIn('SECURESHOP_MERCHANT_MAIL_HEADER_BROWSER_NATIVE', env)

    def test_exact_tap_rejects_skips_and_wrong_cohort(self):
        text = f'# Subtest: {L.LISTING_RAW_ASSERTION}\nok 1 - {L.LISTING_RAW_ASSERTION}\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n'
        self.assertEqual(L.complete_tap_counts(text, COHORT, [L.LISTING_RAW_ASSERTION])['tests'], 1)
        for changed in (text.replace('# skipped 0', '# skipped 1'), text.replace(L.LISTING_RAW_ASSERTION, L.MERCHANT_REVIEW_ASSERTION)):
            with self.assertRaises(RuntimeError): L.complete_tap_counts(changed, COHORT, [L.LISTING_RAW_ASSERTION])

    def test_source_snapshot_includes_fixture_transport_and_browser_inventories(self):
        with patch.object(L, 'dependency_inventory', return_value={'controlled': 'inventory'}):
            snapshot = L.source_snapshot(ROOT, '/unused/node', COHORT, browser_root=ROOT / 'client/build')
        for name in (L.LISTING_RAW_TEST, 'tests/postgres/secureshopMailActualTransport.js',
                     'sidecars/sandbox-runner/owned-system/contract.js',
                     'tests/fixtures/secureshopOwnedPolicyRendererAdmission.js',
                     L.LISTING_RAW_HELPER,
                     L.LISTING_RAW_CONTRACT,
                     'tests/secureshopReviewInjectionRoleChoicesReceipt.test.js',
                     'tests/postgres/test_secureshop_listing_raw_v62_launcher.py'):
            self.assertIn(name, snapshot['sourcePins'])
        # V62's small additive block is followed by the shared production
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
