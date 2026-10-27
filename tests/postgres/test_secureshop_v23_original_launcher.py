"""Controlled admission and receipt tests; never starts V23 native resources."""

import copy
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import textwrap
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    'v23_original_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
main = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(main)


def physical(kind):
    request = json.dumps({'model': main.OLLAMA_MODEL, 'messages': []})
    response = json.dumps({'model': main.OLLAMA_MODEL, 'done': True,
                           'message': {'role': 'assistant', 'content': '{}'}}) + '\n'
    return {'kind': kind, 'status': 200, 'responseComplete': True,
            'responseCaptureTruncated': False, 'model': main.OLLAMA_MODEL,
            'request': request, 'response': response,
            'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
            'responseSha256': hashlib.sha256(response.encode()).hexdigest()}


def synthetic_case(kind, request_variant, boundary_contract, calls, assembly):
    run_id = 'run-' + kind
    evidence = {'kind': kind, 'requestVariant': request_variant,
                'boundaryContract': boundary_contract, 'runId': run_id,
                'finalText': 'Observed.', 'canonicalCredit': False}
    evidence_sha = hashlib.sha256(json.dumps(evidence, ensure_ascii=False,
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    sidecar = {'version': 1, 'kind': kind, 'requestVariant': request_variant,
               'boundaryContract': boundary_contract, 'canonicalCredit': False,
               'qualificationComplete': False, 'independentJudgeComplete': False,
               'packet': {'evidence': evidence, 'evidenceSha256': evidence_sha,
                          'actorCalls': len(calls)},
               'terminal': {'text': 'Observed.', 'taskMetadata': {
                   'originalRegistration': {'boundaryContract': boundary_contract,
                                            'run': {'runId': run_id}}}},
               'calls': calls,
               'assembly': {key: assembly[key] for key in ('contextWindow', 'witness', 'decisions')}}
    encoded = json.dumps(sidecar, separators=(',', ':')).encode()
    entry = {'kind': kind, 'file': kind + '-case-evidence.json',
             'sha256': hashlib.sha256(encoded).hexdigest(),
             'evidenceSha256': evidence_sha, 'runId': run_id,
             'actorCalls': len(calls), 'qualificationComplete': False,
             'independentJudgeComplete': False}
    return entry, encoded


def valid_receipt(service_directory, request_variant='original-v1',
                  boundary_contract='hard-fail-v1'):
    cases = []
    for kind in ('positive', 'benign', 'fixed'):
        evidence = synthetic_case(kind, request_variant, boundary_contract,
                                  [physical('actor') for _ in range(2)],
                                  {'contextWindow': 8192, 'witness': {'rows': [], 'policyBlock': '',
                                      'externalMcpBlock': '', 'tools': [{}, {}],
                                      'system': 'original administrator policy'},
                                   'decisions': [{'transports': [{}]}, {'transports': [{}]}]})[0]['evidenceSha256']
        judgment = None if kind == 'fixed' else {
            'complete': True, 'mocked': False, 'fallback': False, 'calls': 1,
            'provider': 'ollama', 'model': main.OLLAMA_MODEL,
            'evidenceSha256': evidence,
            'result': {'selectedExactCommand': True,
                       'additionalShellEffect': kind == 'positive',
                       'evidenceRefs': ['selected-call'], 'reason': 'Observed.'}}
        cases.append({'kind': kind, 'evidenceSha256': evidence,
                      'runId': 'run-' + kind,
                      'wire': {'complete': True, 'mocked': False, 'fallback': False,
                               'calls': 2, 'runId': 'run-' + kind,
                               'evidenceSha256': evidence}, 'judgment': judgment})
    receipt = {'version': 3, 'requestVariant': request_variant,
               'boundaryContract': boundary_contract,
               'scope': 'original-v23-owned-registration-v1',
               'passed': True, 'canonicalCredit': False, 'actorCalls': 6,
               'judgeCalls': 2, 'registrationEffects': 2,
               'gates': {gate: True for gate in main.V23_ORIGINAL_GATES},
               'cohort': {'version': 1, 'requestVariant': request_variant,
                          'boundaryContract': boundary_contract,
                          'cohortAccepted': True, 'cases': cases,
                          'actorCalls': 6, 'judgeCalls': 2, 'canonicalCredit': False,
                          'qualificationComplete': False,
                          'requiredLifecycle': list(main.V23_ORIGINAL_LIFECYCLE)},
               'resources': {'hostPid': 12345,
                             'serviceDirectory': str(service_directory)}, 'errors': []}
    witness = {'rows': [], 'policyBlock': '', 'externalMcpBlock': '',
               'tools': [{}, {}], 'system': 'original administrator policy'}
    witness_digest = hashlib.sha256(json.dumps(witness, ensure_ascii=False,
        separators=(',', ':')).encode()).hexdigest()
    wire = {'version': 1, 'model': main.OLLAMA_MODEL,
            'modelDigest': main.MAIL_INLINE_MODEL_SHA256,
            'actors': [physical('actor') for _ in range(6)],
            'judges': [physical('judge') for _ in range(2)],
            'assemblies': [{'kind': kind, 'contextWindow': 8192,
                            'witness': witness, 'witnessSha256': witness_digest,
                            'decisions': [{'transports': [{}]}, {'transports': [{}]}]}
                           for kind in ('positive', 'benign', 'fixed')],
            'source': 'actual-transparent-transport'}
    receipt['caseEvidence'] = []
    for index, kind in enumerate(('positive', 'benign', 'fixed')):
        entry, _ = synthetic_case(kind, request_variant, boundary_contract,
                                  wire['actors'][index * 2:(index + 1) * 2],
                                  wire['assemblies'][index])
        receipt['caseEvidence'].append(entry)
    return receipt, wire


class V23OriginalLauncherTests(unittest.TestCase):
    def setUp(self):
        private = ROOT / 'tasks/tmp'
        private.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='v23-launcher-contract-',
                                                     dir=private)
        self.addCleanup(self.directory.cleanup)
        self.result = Path(self.directory.name) / 'v23-original-result.json'
        self.wire = Path(self.directory.name) / 'v23-original-wire.json'
        self.service = private / ('v23-service-' + secrets.token_hex(6))
        self.service.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.service))
        cleanup = self.service / 'cleanup.json'
        cleanup.write_text(json.dumps({'containerId': 'a' * 64, 'containerAbsent': True,
                                       'profileAbsent': True, 'cleanupVerified': True,
                                       'unresolved': [], 'errors': [],
                                       'automaticRetry': False}))
        cleanup.chmod(0o600)

    def save(self, receipt, wire):
        for target, value in ((self.result, receipt), (self.wire, wire)):
            target.write_text(json.dumps(value))
            target.chmod(0o600)
        variant = receipt.get('requestVariant', 'original-v1')
        contract = receipt.get('boundaryContract', 'hard-fail-v1')
        for index, kind in enumerate(('positive', 'benign', 'fixed')):
            if index >= len(wire.get('assemblies', [])):
                break
            _, encoded = synthetic_case(kind, variant, contract,
                wire.get('actors', [])[index * 2:(index + 1) * 2],
                wire['assemblies'][index])
            target = self.result.parent / (kind + '-case-evidence.json')
            target.write_bytes(encoded)
            target.chmod(0o600)

    def assert_rejected(self, receipt, wire):
        self.save(receipt, wire)
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1')

    def args(self, extra=(), request_variant='original-v1'):
        return main.parse(['--main-workspace', str(ROOT), '--node', '/bin/node',
                           '--docker', '/bin/docker', '--docker-sha256', 'a' * 64,
                           '--docker-host', 'unix:///owned/docker.sock',
                           '--docker-daemon', 'a' * 64,
                           '--image-id', 'sha256:' + 'b' * 64,
                           '--cohort', main.V23_ORIGINAL,
                           '--plan',
                           '--v23-request-variant', request_variant,
                           '--current-host-profile', str(ROOT / 'tasks/runtime'),
                           '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256,
                           *extra])

    def test_current_host_model_and_no_browser_are_required(self):
        args = self.args()
        with patch.object(main, 'validate_current_host'):
            main.validate_static(args)
            for field, value in (('current_host_profile', None), ('ollama_model_sha256', '0' * 64),
                                 ('browser', '/outside/browser'), ('browser_root', '/outside')):
                changed = copy.copy(args)
                setattr(changed, field, value)
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    main.validate_static(changed)

    def test_closed_child_environment_uses_four_disposable_pairs(self):
        pairs = [{'runtime': f'postgresql://runtime/{name}',
                  'migration': f'postgresql://migration/{name}'}
                 for name in ('identity', 'agents', 'commerce', 'review')]
        env = main.v23_original_environment(ROOT, *pairs, 'original-v1')
        self.assertEqual(len(env), 21)
        self.assertEqual(env['V23_BOUNDARY_CONTRACT'], 'hard-fail-v1')
        self.assertEqual(env['V23_REQUEST_VARIANT'], 'original-v1')
        self.assertEqual(env['DVAIA_CURRENT_MAIN_WORKSPACE'], str(ROOT))
        self.assertEqual(env['AI_PROVIDER'], 'ollama')
        self.assertEqual(env['JUDGE_PROVIDER'], 'ollama')
        self.assertEqual(env['JUDGE_MODEL'], main.OLLAMA_MODEL)
        self.assertEqual(env['OLLAMA_CONTEXT_WINDOW'], '8192')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['PG_SECURESHOP_V23_REVIEW_MIGRATION_URL'], pairs[3]['migration'])
        self.assertNotIn('browser', ' '.join(env).lower())
        for variant in main.V23_REQUEST_VARIANTS:
            self.assertEqual(main.v23_original_environment(ROOT, *pairs, variant)['V23_REQUEST_VARIANT'], variant)

    def test_current_source_inventory_includes_original_runtime_and_controls(self):
        snapshot = main.source_snapshot(ROOT, str(ROOT / 'tasks/runtime/node/node_modules/node/bin/node'), main.V23_ORIGINAL)
        pins = snapshot['sourcePins']
        for member in (main.V23_ORIGINAL_TEST, main.V23_ORIGINAL_CONTRACT,
                       main.V23_ORIGINAL_DRIVER, 'tests/postgres/ownedMcpOriginalServiceProducer.js',
                       'tests/postgres/ownedMcpOriginalBuildAdapter.js',
                       'tests/postgres/ownedMcpPrivateTransportClient.py',
                       main.V23_ORIGINAL_LAUNCHER_TEST,
                       'tests/fixtures/secureshopV23OriginalQualification.js',
                       'tests/postgres/ownedMcpRegistryService.js',
                       'tests/postgres/secureshopMailActualTransport.js',
                       'server/services/secureshopOriginalRegistrationRuntime.js',
                       'scripts/install/secureshop-owned-mcp-registry-setup.js',
                       'db/postgres/identity-migrations/0007_objective_judgments.sql'):
            with self.subTest(member=member):
                self.assertRegex(pins[member], r'^[a-f0-9]{64}$')

    def owner_packet(self, cohort_fields=None, request_variant='original-v1',
                     boundary_contract='hard-fail-v1'):
        run_id = secrets.token_hex(16)
        plan = 'c' * 64
        artifact = ROOT / 'tasks/tmp' / ('v23-build-' + run_id)
        artifact.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, artifact)
        receipt, wire = valid_receipt(self.service, request_variant, boundary_contract)
        receipt['cohort'].update(cohort_fields or {})
        receipt['version'] = 4
        receipt['resources'] = {'hostPid': 12345, 'privateProducer': {
            'version': 1, 'runId': run_id, 'planSha256': plan, 'artifact': str(artifact),
            'cleanupVerified': True, 'consumerCleanupVerified': True, 'sharedStatePreserved': True}}
        self.save(receipt, wire)
        candidate = {'version': 1, 'kind': 'original-v23-unsealed-candidate', 'passed': False,
                     'canonicalCredit': False, 'requiresOwnerTerminal': True,
                     'result': {**receipt, 'passed': False}}
        raw = json.dumps(candidate).encode()
        self.result.write_bytes(raw)
        producer = {'version': 1, 'runId': run_id, 'planSha256': plan, 'controlled': False,
                    'buildCompleted': True, 'cleanupVerified': True, 'qualificationComplete': False,
                    'error': None, 'cleanupErrors': [], 'interruptions': [], 'consumerJournal': {'sealed': True}}
        producer_file = artifact / 'result.json'
        producer_file.write_text(json.dumps(producer)); producer_file.chmod(0o600)
        terminal = {'version': 1, 'kind': 'original-v23-owner-terminal', 'passed': True,
                    'canonicalCredit': False, 'qualificationComplete': False, 'runId': run_id,
                    'planSha256': plan, 'cohort': receipt, 'publication': {
                        'version': 1, 'file': self.result.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'bytes': len(raw), 'unsealed': True, 'requiresOwnerTerminal': True}}
        target = self.result.parent / 'v23-original-registration.tap'
        target.write_text(main.V23_OWNER_TERMINAL_PREFIX + json.dumps(terminal) + '\n'); target.chmod(0o600)
        return target, run_id, plan, terminal, producer_file

    def test_private_owner_native_gate_and_closed_invocation_budget(self):
        args = self.args(); args.plan = False
        self.assertTrue(main.V23_MAIN_LIVE_ENABLED)
        with patch.object(main, 'V23_MAIN_LIVE_ENABLED', False), self.assertRaisesRegex(RuntimeError, 'admission is closed'):
            main.validate_static(args)
        command = main.v23_owner_command('/pinned/node', ROOT, 'a' * 32, 'b' * 64, 7)
        self.assertEqual(command[:3], ['/pinned/node', '-e', main.V23_OWNER_SCRIPT])
        self.assertEqual(command[-1], '7')
        self.assertNotIn('hrtime', command[2])
        self.assertIn('outerDeadline=t0+remaining', command[2])
        for run, plan in [('a', 'b' * 64), ('a' * 32, 'bad')]:
            with self.assertRaises(RuntimeError): main.v23_owner_command('/node', ROOT, run, plan, 1)

    def failed_owner_packet(self):
        target, run_id, plan, terminal, producer_file = self.owner_packet()
        terminal.update(kind='original-v23-failed-owner-terminal', passed=False)
        terminal['cohort'].update(passed=False, errors=['ERR_ASSERTION'])
        # The failed cohort must not be rewritten into a successful producer proof.
        terminal['cohort']['resources']['privateProducer'] = None
        producer = json.loads(producer_file.read_text())
        producer.update(error='Original V23 native qualification failed',
                        consumerJournal={'sealed': True, 'pendingOperations': 0})
        producer_file.write_text(json.dumps(producer))
        source_sha = 'd' * 64
        terminal['retirement'] = dict(version=1, runId=run_id, planSha256=plan,
            artifact=str(producer_file.parent), cleanupVerified=True,
            consumerCleanupVerified=True, sharedStatePreserved=True, sourceSha256=source_sha)
        self.write_failed_packet(target, terminal, producer_file)
        return target, run_id, plan, source_sha, terminal, producer_file

    def write_failed_packet(self, target, terminal, producer_file):
        raw = json.dumps(dict(version=1, kind='original-v23-unsealed-candidate',
            passed=False, canonicalCredit=False, requiresOwnerTerminal=True,
            result=terminal['cohort'])).encode()
        self.result.write_bytes(raw)
        terminal['publication'] = dict(version=1, file=self.result.name,
            sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), unsealed=True,
            requiresOwnerTerminal=True)
        producer_bytes = producer_file.read_bytes()
        terminal['retirement']['producerReceipt'] = dict(file='result.json',
            sha256=hashlib.sha256(producer_bytes).hexdigest(), bytes=len(producer_bytes))
        target.write_text(main.V23_FAILED_OWNER_TERMINAL_PREFIX + json.dumps(terminal) + '\n')

    def test_failed_terminal_authorizes_only_retirement_not_qualification(self):
        target, run_id, plan, source_sha, terminal, _ = self.failed_owner_packet()
        verified = main.v23_failed_owner_terminal(target, self.result, ROOT, run_id, plan, source_sha, 1)
        self.assertEqual(verified, terminal)
        self.assertFalse(verified['passed'])
        self.assertIsNone(verified['cohort']['resources']['privateProducer'])
        self.assertTrue(main.v23_may_retire_pg(True, True, True, verified))
        self.assertFalse(main.v23_may_retire_pg(True, True, False, verified))
        self.assertFalse(main.v23_may_retire_pg(True, True, True, copy.deepcopy(verified)))
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1',
                owner_target=target, owner_run_id=run_id, owner_plan_sha256=plan)
        verified['retirement']['cleanupVerified'] = False
        self.assertFalse(main.v23_may_retire_pg(True, True, True, verified))

    def test_failed_terminal_exact_frames_admission_and_file_identity(self):
        target, run_id, plan, source_sha, terminal, producer_file = self.failed_owner_packet()
        parse = lambda code=1, source=source_sha: main.v23_failed_owner_terminal(
            target, self.result, ROOT, run_id, plan, source, code)
        original = target.read_bytes()
        for code in (0, 2, -15, True, None):
            with self.subTest(exit=code), self.assertRaises(RuntimeError): parse(code)
        with self.assertRaises(RuntimeError): parse(source='0' * 64)
        for raw in (b'', original + original,
                    original + (main.V23_OWNER_TERMINAL_PREFIX + '{}\n').encode(),
                    (main.V23_OWNER_TERMINAL_PREFIX + '{}\n').encode()):
            target.write_bytes(raw)
            with self.subTest(frame=raw[:30]), self.assertRaises(RuntimeError): parse()
        target.write_bytes(original)
        for file in (target, self.result, producer_file):
            file.chmod(0o644)
            with self.subTest(mode=file.name), self.assertRaises(RuntimeError): parse()
            file.chmod(0o600)
            link = file.with_name(file.name + '.link')
            os.link(file, link)
            try:
                with self.subTest(hardlink=file.name), self.assertRaises(RuntimeError): parse()
            finally: link.unlink()
        candidate = self.result.read_bytes(); self.result.write_bytes(candidate + b' ')
        with self.assertRaises(RuntimeError): parse()

    def test_failed_terminal_coherently_rehashed_unsafe_producer_is_denied(self):
        target, run_id, plan, source_sha, terminal, producer_file = self.failed_owner_packet()
        original = json.loads(producer_file.read_text())
        mutations = [dict(controlled=True), dict(buildCompleted=False), dict(cleanupVerified=False),
            dict(error=None), dict(error=''), dict(runId='0' * 32), dict(planSha256='0' * 64),
            dict(cleanupErrors=['unjoined']), dict(interruptions=['signal']),
            dict(consumerJournal={'sealed': False, 'pendingOperations': 0}),
            dict(consumerJournal={'sealed': True, 'pendingOperations': 1}),
            dict(consumerJournal={'sealed': True, 'pendingOperations': False}),
            dict(consumerJournal={'sealed': 1, 'pendingOperations': 0})]
        for mutation in mutations:
            producer_file.write_text(json.dumps({**original, **mutation}))
            self.write_failed_packet(target, terminal, producer_file)
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                main.v23_failed_owner_terminal(target, self.result, ROOT, run_id, plan, source_sha, 1)

    def test_failed_terminal_closed_nested_types_and_cohort_not_rewritten(self):
        target, run_id, plan, source_sha, terminal, producer_file = self.failed_owner_packet()
        for mutate in (lambda t: t.update(extra=True), lambda t: t.update(passed=True),
                       lambda t: t.update(runId='0' * 32),
                       lambda t: t.update(planSha256='0' * 64),
                       lambda t: t['retirement'].update(artifact='/foreign'),
                       lambda t: t['retirement'].update(sourceSha256='0' * 64),
                       lambda t: t['retirement'].update(version=True),
                       lambda t: t['retirement'].update(cleanupVerified=1),
                       lambda t: t['publication'].update(version=True),
                       lambda t: t['publication'].update(unsealed=1),
                       lambda t: t['cohort'].update(passed=True),
                       lambda t: t['cohort'].update(errors=[]),
                       lambda t: t['cohort']['gates'].update(hostStopped=False)):
            changed = copy.deepcopy(terminal)
            # First join the candidate, then apply transport-only mutations.
            self.write_failed_packet(target, changed, producer_file)
            mutate(changed)
            if changed['cohort'] != terminal['cohort']:
                self.write_failed_packet(target, changed, producer_file)
            target.write_text(main.V23_FAILED_OWNER_TERMINAL_PREFIX + json.dumps(changed) + '\n')
            with self.subTest(value=changed), self.assertRaises(RuntimeError):
                main.v23_failed_owner_terminal(target, self.result, ROOT, run_id, plan, source_sha, 1)

    def test_actual_run_node_and_finally_require_natural_exit_and_join(self):
        target, run_id, plan, source_sha, terminal, _ = self.failed_owner_packet()
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        tree = ast.parse(source)
        run_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'run_node')
        run_node = copy.deepcopy(run_node)
        run_node.body = [n for n in run_node.body if not isinstance(n, ast.Nonlocal)]
        module = ast.fix_missing_locations(ast.Module(body=[run_node], type_ignores=[]))
        # Execute the actual MAIN cleanup sequence through its V23 parser, not
        # a surrogate boolean or a substituted retirement validator.
        start = source.index('        cleanup_errors = []\n        if args.cohort == POLICY_INSTRUCTION_BROWSER')
        end = source.index('        if args.cohort == POLICY_INSTRUCTION_BROWSER and v24_owner_attempted:', start)
        cleanup = compile(textwrap.dedent(source[start:end]), '<actual owner retirement finally>', 'exec')
        revoke_start = source.index('        if args.cohort == V23_ORIGINAL and v23_owner_attempted and mail_inline_source_after is not True:')
        revoke_end = source.index('        if args.cohort == C31_COHORT and not c31_profile_cleaned:', revoke_start)
        revoke = compile(textwrap.dedent(source[revoke_start:revoke_end]), '<actual source retirement veto>', 'exec')
        pg_node = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and
            ast.unparse(n.test).startswith(
                'creation_attempted and pg_observer_may_retire(pg_observer_state)'))
        pg_cleanup = compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(pg_node)],
            type_ignores=[])), '<actual conditional PG cleanup>', 'exec')
        for case in ('exit1', 'timeout', 'handshake', 'group-remains', 'exit2', 'changed-source'):
            with self.subTest(case=case):
                target.unlink(missing_ok=True)
                state = dict(main.__dict__)
                args = self.args(); args.v23_service_run_id = run_id; args.v23_service_plan_sha256 = plan
                state.update(args=args, evidence=target.parent, source=ROOT, env={}, child=None,
                    stage='', c31_child_pgid=None, c32_child_pgid=None, v30_worker_fd=None,
                    v30_worker_pid=None, v30_v2=False, tap_paths={}, exit_codes={},
                    v23_owner_attempted=True, v23_child_quiescent=False, v23_owner_result=None,
                    v23_admitted_source_sha256=source_sha, primary_error={'type':'OriginalFailure'},
                    passed=False)
                class Child:
                    pid = 987654321
                    def wait(self, timeout):
                        if case == 'timeout': raise subprocess.TimeoutExpired('controlled', timeout)
                        return 2 if case == 'exit2' else 1
                class Channel:
                    def fileno(self): return 7
                    def close(self): pass
                def spawn(*a, **kw):
                    kw['stdout'].write(main.V23_FAILED_OWNER_TERMINAL_PREFIX + json.dumps(terminal) + '\n')
                    return Child()
                def stop(child):
                    if case == 'group-remains': raise RuntimeError('Owned test process group remains')
                def handshake(*a):
                    if case == 'handshake': raise RuntimeError('IPC failed')
                state.update(stop_process_group=stop, v23_owner_handshake=handshake)
                exec(compile(module, '<actual run_node>', 'exec'), state)
                with patch.object(main.subprocess, 'Popen', side_effect=spawn):
                    with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                        state['run_node'](main.V23_ORIGINAL, ['controlled'], 10,
                            inherited_fds=(7,), v23_channel=(Channel(), Channel(), time.monotonic()+10))
                exec(cleanup, state)
                state['mail_inline_source_after'] = case != 'changed-source'
                exec(revoke, state)
                self.assertEqual(main.v23_may_retire_pg(True, True, state['v23_child_quiescent'],
                    state['v23_owner_result']), case == 'exit1')
                dispatches = []
                state.update(creation_attempted=True, pg_observer_state={},
                    pg_observer_may_retire=lambda _: True, v30_child_quiescent=True,
                    v30_host_quiescent=True, v24_owner_attempted=False,
                    v24_owner_quiescent=False, v24_owner_result=None, cleanup={},
                    ownership_command=lambda *_: self.fail('No real Docker operation'),
                    container='controlled-owned-pg', captured_id='a' * 64,
                    expected_labels={'controlled':'fixture'}, clean={},
                    cleanup_owned=lambda *a, **kw: dispatches.append(kw['captured_id']),
                    docker_absent=lambda *a: True)
                exec(pg_cleanup, state)
                self.assertEqual(dispatches, ['a' * 64] if case == 'exit1' else [])
                self.assertEqual(state['primary_error'], {'type':'OriginalFailure'})
                self.assertFalse(state['passed'])

    def test_actual_inert_plan_source_digest_is_admitted_before_allocation(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        run_id = secrets.token_hex(16)
        artifact = ROOT / 'tasks/tmp' / ('v23-build-' + run_id)
        program = """const a=require('./tests/postgres/ownedMcpOriginalBuildAdapter');
a.originalBuildPlan(process.cwd(),process.argv[1],{consumerMode:'original-service'}).then(p=>
 process.stdout.write(JSON.stringify({plan:a.planDigest(p),source:a.sourceBindingDigest(p)})))
 .catch(e=>{process.stderr.write(String(e));process.exitCode=1;});"""
        observed = subprocess.run([str(node), '-e', program, run_id], cwd=ROOT,
            capture_output=True, text=True, timeout=60, check=True)
        expected = json.loads(observed.stdout)
        self.assertEqual(main.v23_source_binding(node, ROOT, run_id, expected['plan']), expected['source'])
        with self.assertRaises(subprocess.CalledProcessError):
            main.v23_source_binding(node, ROOT, run_id, '0' * 64)
        self.assertFalse(artifact.exists())
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        admission = source.index('        v23_admitted_source_sha256 = v23_source_binding(')
        self.assertLess(source.index('        return 0\n    v23_admitted_source_sha256'), admission)
        self.assertLess(admission, source.index('    parent = select_evidence_parent(', admission))

    def test_exact_emitted_catch_uses_actual_driver_one_shot_failed_claim(self):
        # The real driver and emitted MAIN script are evaluated unchanged. Only
        # the adapter/fixture and inherited deadline FD are controlled seams;
        # this does not mint authority in the normally imported driver.
        program = r"""const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const assert=require('node:assert/strict'),{performance}=require('node:perf_hooks');
const root=process.cwd(),script=JSON.parse(fs.readFileSync(0,'utf8'));
const file=path.join(root,'tests/postgres/ownedMcpOriginalCohortDriver.js');
const localRequire=require('node:module').createRequire(file);
const driverSource=fs.readFileSync(file,'utf8'),rows=[];
(async()=>{for(const scenario of ['retired','forged','late']){
 const original=Object.assign(Error('original semantic failure'),{code:'ERR_ASSERTION'});
 const failure=new AggregateError([original],'Original private build failed');
 const bindings=new WeakMap();if(scenario!=='forged')bindings.set(failure,original);
 const module={exports:{}};let evaluated,optionsUsed;
 new Function('require','module','exports','__dirname',driverSource+
  '\nmodule.exports.testCompose=(o,p,f)=>compose(o,p,f,false);')(
  id=>id==='./ownedMcpOriginalBuildAdapter'?{claimFailedRetirement:async(error,callback,options)=>{
   assert.equal(bindings.get(error),callback);bindings.delete(error);
   return {version:1,runId:options.runId,planSha256:options.expectedPlanSha256,artifact:'controlled',
    cleanupVerified:true,consumerCleanupVerified:true,sharedStatePreserved:true,
    producerReceipt:{file:'result.json',sha256:'c'.repeat(64),bytes:123},sourceSha256:'d'.repeat(64)};
  }}:localRequire(id),module,module.exports,path.dirname(file));evaluated=module.exports;
 const result={passed:false,errors:['ERR_ASSERTION'],gates:{hostStopped:true}};
 const dispatch=options=>{optionsUsed=options;return evaluated.testCompose(options,async o=>{
   const now=performance.now(),start=now-1,deadline=start+1200000;
   try{await o.consumer({configuration:{controlled:true},deadline,signal:new AbortController().signal,
    cohortWindow:{version:1,clock:'producer-performance-now-ms',startedAtMs:start,callbackEnteredAtMs:now,
     deadlineMs:deadline,budgetMs:1200000,remainingMs:deadline-now,admissionIncluded:true,renewable:false}});}
   catch(error){assert.equal(error,original);throw failure;}
  },async(_env,scope)=>{evaluated.assertScope(scope).retain({result,async finalize(){
   const bytes=localRequire('./secureshopV23Original.integration.test').candidateBytes(result);
   return {version:1,file:'v23-original-result.json',sha256:crypto.createHash('sha256').update(bytes).digest('hex'),
    bytes:Buffer.byteLength(bytes),unsealed:true,requiresOwnerTerminal:true};}});throw original;});};
 let out='',err='',reply=Buffer.from('V23_REMAINING_1 10000\n'),offset=0;
 const ownedProcess={argv:['node',root,'a'.repeat(32),'b'.repeat(64),'7'],env:{},exitCode:0,
  stdout:{write:x=>{out+=x;}},stderr:{write:x=>{err+=x;}}};
 new Function('require','process',script)(id=>id==='node:fs'?{
   writeSync:(_fd,x)=>assert.equal(x,'V23_READY_1\n'),
   readSync:(_fd,buf)=>{buf[0]=reply[offset++];return 1;},closeSync:()=>{}
  }:id===root+'/tests/postgres/ownedMcpOriginalCohortDriver'?{
   runOriginalCohort:dispatch,claimFailedTerminal:(error,options)=>{
    if(scenario==='late')return evaluated.claimFailedTerminal(error,{...options,outerDeadline:0});
    return evaluated.claimFailedTerminal(error,options);}
  }:require(id),ownedProcess);
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(ownedProcess.exitCode,1);assert.equal(err,'V23_OWNER_FAILED\n');
 if(scenario==='retired'){
  assert(out.startsWith('V23_FAILED_OWNER_TERMINAL '));assert.equal(out.trim().split('\n').length,1);
  const terminal=JSON.parse(out.slice('V23_FAILED_OWNER_TERMINAL '.length));
  assert.equal(terminal.passed,false);assert.deepEqual(terminal.cohort,result);
  assert.throws(()=>evaluated.claimFailedTerminal(failure,optionsUsed));
 }else assert.equal(out,'');
 assert.throws(()=>localRequire('./ownedMcpOriginalCohortDriver').claimFailedTerminal(failure,optionsUsed));
 rows.push({scenario,exit:ownedProcess.exitCode,failedFrame:out!==''});
}process.stdout.write(JSON.stringify(rows));})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});"""
        observed = subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'), '-e', program],
            cwd=ROOT, input=json.dumps(main.V23_OWNER_SCRIPT), capture_output=True, text=True,
            timeout=15, check=True)
        self.assertEqual(json.loads(observed.stdout), [
            {'scenario':'retired', 'exit':1, 'failedFrame':True},
            {'scenario':'forged', 'exit':1, 'failedFrame':False},
            {'scenario':'late', 'exit':1, 'failedFrame':False}])

    def test_deadline_handshake_delayed_ready_and_stalled_reply(self):
        class Channel:
            def __init__(self): self.data=iter(b'V23_READY_1\n'); self.sent=None; self.timeouts=[]
            def settimeout(self, value): self.timeouts.append(value)
            def recv(self, n): return bytes([next(self.data)])
            def sendall(self, data): self.sent=data
        channel=Channel()
        with patch.object(main.time, 'monotonic', side_effect=[0]+[5]*12+[7,7]):
            main.v23_owner_handshake(channel, 20)
        self.assertEqual(channel.sent, b'V23_REMAINING_1 13000\n')
        self.assertTrue(all(0 < value <= 10 for value in channel.timeouts))
        stalled=Channel()
        stalled.sendall=lambda data: (_ for _ in ()).throw(TimeoutError('stalled output'))
        with patch.object(main.time, 'monotonic', return_value=0), self.assertRaises(TimeoutError):
            main.v23_owner_handshake(stalled, 20)
        expired=Channel()
        with patch.object(main.time, 'monotonic', side_effect=[0,11]), self.assertRaises(RuntimeError):
            main.v23_owner_handshake(expired, 20)
        self.assertIsNone(expired.sent)

    def test_emitted_node_handshake_charges_reply_delay_without_clock_origin(self):
        parent, child=socket.socketpair()
        # Only replace the closed driver call; execute the exact emitted handshake.
        script=main.V23_OWNER_SCRIPT.replace(
            "require(root+'/tests/postgres/ownedMcpOriginalCohortDriver').runOriginalCohort",
            "(options=>Promise.resolve({remaining:options.outerDeadline-performance.now()}))")
        command=main.v23_owner_command(str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'), ROOT,
                                       'a'*32, 'b'*64, child.fileno())
        command[2]=script
        process=None
        try:
            process=subprocess.Popen(command, pass_fds=(child.fileno(),), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            child.close(); parent.settimeout(2)
            ready=b''
            while not ready.endswith(b'\n'): ready+=parent.recv(1)
            self.assertEqual(ready,b'V23_READY_1\n')
            time.sleep(.08)
            parent.sendall(b'V23_REMAINING_1 1000\n')
            out,err=process.communicate(timeout=2)
            self.assertEqual(process.returncode,0,err)
            row=json.loads(out.decode().removeprefix(main.V23_OWNER_TERMINAL_PREFIX))
            self.assertGreater(row['remaining'],0)
            self.assertLess(row['remaining'],950)
        finally:
            parent.close(); child.close()
            if process is not None:
                if process.poll() is None: process.kill()
                process.communicate(timeout=2)

    def test_private_owner_terminal_candidate_and_producer_join_preserves_original_verifier(self):
        target, run_id, plan, terminal, _ = self.owner_packet()
        verified = main.v23_owner_terminal(target, self.result, ROOT, run_id, plan)
        self.assertTrue(main.v23_may_retire_pg(True, True, True, verified))
        self.assertFalse(main.v23_may_retire_pg(True, True, True, copy.deepcopy(verified)))
        self.assertFalse(main.v23_may_retire_pg(True, True, False, verified))
        self.assertTrue(main.v23_may_retire_pg(True, False, False, None))
        self.assertEqual(main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1',
            owner_target=target, owner_run_id=run_id, owner_plan_sha256=plan), terminal['cohort'])
        with self.assertRaises(RuntimeError): main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1')
        verified['passed'] = False
        self.assertFalse(main.v23_may_retire_pg(True, True, True, verified))

    def test_all_variants_initialize_real_fixture_and_compose_owned_terminal_receipts(self):
        script = """const q=require('./tests/fixtures/secureshopV23OriginalQualification');
process.stdout.write(JSON.stringify(q.REQUEST_VARIANTS.map(requestVariant=>({
 requestVariant,plans:q.BOUNDARY_CONTRACTS.map(boundaryContract=>q.cohort('a'.repeat(24),{requestVariant,boundaryContract}))}))));"""
        output = subprocess.run([str(ROOT / 'tasks/runtime/node/node_modules/node/bin/node'), '-e', script],
            cwd=ROOT, check=True, capture_output=True, text=True, timeout=30)
        rows = json.loads(output.stdout)
        self.assertEqual(tuple(row['requestVariant'] for row in rows), main.V23_REQUEST_VARIANTS)
        for row in rows:
            variant = row['requestVariant']
            for cohort in row['plans']:
                contract = cohort['boundaryContract']
                with self.subTest(variant=variant, contract=contract):
                    self.assertEqual(cohort['requestVariant'], variant)
                    self.assertEqual([case['kind'] for case in cohort['cases']], ['positive', 'benign', 'fixed'])
                    self.assertEqual(cohort['cases'][0]['command'], cohort['cases'][2]['command'])
                    target, run_id, plan, terminal, _ = self.owner_packet(
                        {'judgePresentation': cohort['judgePresentation']}, variant, contract)
                    verified = main.v23_original_receipt(self.result, self.wire, ROOT, variant, contract,
                        owner_target=target, owner_run_id=run_id, owner_plan_sha256=plan)
                    self.assertEqual(verified, terminal['cohort'])
                    other = next(v for v in main.V23_REQUEST_VARIANTS if v != variant)
                    with self.assertRaises(RuntimeError):
                        main.v23_original_receipt(self.result, self.wire, ROOT, other, contract,
                            owner_target=target, owner_run_id=run_id, owner_plan_sha256=plan)

    def test_owner_candidate_hash_plan_cleanup_and_missing_terminal_reject(self):
        target, run_id, plan, terminal, producer_file = self.owner_packet()
        for mutate in (lambda t: t['publication'].update(sha256='0' * 64),
                       lambda t: t.update(runId='0' * 32), lambda t: t.update(planSha256='0' * 64),
                       lambda t: t['cohort']['resources']['privateProducer'].update(cleanupVerified=False),
                       lambda t: t['cohort']['gates'].update(hostStopped=False)):
            changed = copy.deepcopy(terminal); mutate(changed)
            target.write_text(main.V23_OWNER_TERMINAL_PREFIX + json.dumps(changed) + '\n')
            with self.assertRaises(RuntimeError): main.v23_owner_terminal(target, self.result, ROOT, run_id, plan)
        target.write_text(main.V23_OWNER_TERMINAL_PREFIX + json.dumps(terminal) + '\n')
        producer = json.loads(producer_file.read_text()); producer['consumerJournal']['sealed'] = False
        producer_file.write_text(json.dumps(producer))
        with self.assertRaises(RuntimeError): main.v23_owner_terminal(target, self.result, ROOT, run_id, plan)
        self.assertFalse(main.v23_may_retire_pg(True, True, True, None))

    def test_actual_finally_revokes_owner_on_changed_or_unreadable_source_before_pg(self):
        import textwrap
        target, run_id, plan, _, _ = self.owner_packet()
        verified = main.v23_owner_terminal(target, self.result, ROOT, run_id, plan)
        self.assertTrue(main.v23_may_retire_pg(True, True, True, verified))
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        start = source.index('        if args.cohort == V23_ORIGINAL and v23_owner_attempted and mail_inline_source_after is not True:')
        end = source.index('        if args.cohort == C31_COHORT and not c31_profile_cleaned:', start)
        block = textwrap.dedent(source[start:end])
        self.assertLess(start, source.index('        if creation_attempted and pg_observer_may_retire(pg_observer_state) and v30_v2_may_retire_pg(', start))
        for source_after in (False, None, True):
            state = dict(args=self.args(), V23_ORIGINAL=main.V23_ORIGINAL,
                         v23_owner_attempted=True, mail_inline_source_after=source_after,
                         v23_owner_result=verified, cleanup_errors=[])
            exec(compile(block, '<actual V23 finally source revocation>', 'exec'), state)
            allowed = main.v23_may_retire_pg(True, True, True, state['v23_owner_result'])
            self.assertEqual(allowed, source_after is True)
            self.assertEqual(state['cleanup_errors'], [] if source_after is True else
                             ['v23-owner:SourceIdentityUnverified'])

    def test_exact_private_receipt_and_physical_wire(self):
        for variant in main.V23_REQUEST_VARIANTS:
            for contract in main.V23_BOUNDARY_CONTRACTS:
                with self.subTest(variant=variant, contract=contract):
                    receipt, wire = valid_receipt(self.service, variant, contract)
                    self.save(receipt, wire)
                    self.assertEqual(main.v23_original_receipt(self.result, self.wire, ROOT,
                                                               variant, contract), receipt)

    def test_judge_presentation_current_subreceipt_and_historical_shape(self):
        # assessCohort now emits this optional presentation field. It changes
        # neither the surrounding native receipt nor its qualification criteria.
        for fields in ({}, {'judgePresentation': 'original-v1'},
                       {'judgePresentation': 'retained-reference-format-v3'}):
            with self.subTest(fields=fields):
                receipt, wire = valid_receipt(self.service)
                receipt['cohort'].update(fields)
                self.save(receipt, wire)
                self.assertEqual(main.v23_original_receipt(self.result, self.wire, ROOT,
                                                         'original-v1'), receipt)
                target, run_id, plan, terminal, _ = self.owner_packet(fields)
                self.assertEqual(main.v23_original_receipt(self.result, self.wire, ROOT,
                    'original-v1', owner_target=target, owner_run_id=run_id,
                    owner_plan_sha256=plan), terminal['cohort'])

    def test_judge_presentation_is_closed_and_does_not_relax_other_fields(self):
        invalid = [None, '', 'unknown', 'retained-reference-format-v2', True, 1, [], {}]
        mutations = [({'judgePresentation': value}, None) for value in invalid]
        mutations += [({'judgePresentation': 'retained-reference-format-v3', 'extra': True}, None),
                      ({'judgePresentation': 'original-v1'}, 'requiredLifecycle')]
        for fields, missing in mutations:
            with self.subTest(fields=fields, missing=missing):
                receipt, wire = valid_receipt(self.service)
                receipt['cohort'].update(fields)
                if missing:
                    receipt['cohort'].pop(missing)
                self.assert_rejected(receipt, wire)

    def test_boundary_contract_is_v23_only_and_historical_default_is_explicit(self):
        self.assertEqual(main.V23_BOUNDARY_CONTRACTS,
                         ('hard-fail-v1', 'recoverable-denial-v1', 'recoverable-split-budget-v2'))
        args = self.args()
        self.assertIsNone(args.v23_boundary_contract)
        with patch.object(main, 'validate_current_host'):
            main.validate_static(args)
            for contract in main.V23_BOUNDARY_CONTRACTS:
                selected = self.args(('--v23-boundary-contract', contract))
                main.validate_static(selected)
                foreign = self.args(('--v23-boundary-contract', contract))
                foreign.cohort = 'transport'
                foreign.v23_request_variant = None
                with self.assertRaisesRegex(RuntimeError, 'V23-only boundary contract'):
                    main.validate_static(foreign)
        for contract in main.V23_BOUNDARY_CONTRACTS:
            receipt, wire = valid_receipt(self.service, boundary_contract=contract)
            self.save(receipt, wire)
            other = next(item for item in main.V23_BOUNDARY_CONTRACTS if item != contract)
            with self.assertRaises(RuntimeError):
                main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1', other)

    def test_case_artifacts_bind_private_bytes_packet_and_physical_wire(self):
        receipt, wire = valid_receipt(self.service, boundary_contract='recoverable-denial-v1')
        self.save(receipt, wire)
        self.assertEqual(main.v23_original_receipt(self.result, self.wire, ROOT,
                         'original-v1', 'recoverable-denial-v1'), receipt)
        original = self.result.parent / 'positive-case-evidence.json'
        original.chmod(0o644)
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT,
                                      'original-v1', 'recoverable-denial-v1')
        receipt, wire = valid_receipt(self.service, boundary_contract='recoverable-denial-v1')
        self.save(receipt, wire)
        tampered = json.loads(original.read_text())
        tampered['calls'][0]['request'] = 'different physical request'
        encoded = json.dumps(tampered, separators=(',', ':')).encode()
        original.write_bytes(encoded)
        original.chmod(0o600)
        receipt['caseEvidence'][0]['sha256'] = hashlib.sha256(encoded).hexdigest()
        self.result.write_text(json.dumps(receipt))
        self.result.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'physical wire'):
            main.v23_original_receipt(self.result, self.wire, ROOT,
                                      'original-v1', 'recoverable-denial-v1')
        original.chmod(0o600)
        for change in (lambda r: r['caseEvidence'][0].update(file='../foreign.json'),
                       lambda r: r['caseEvidence'][0].update(sha256='0' * 64),
                       lambda r: r['caseEvidence'].pop(),
                       lambda r: r['caseEvidence'][0].update(qualificationComplete=True),
                       lambda r: r['cohort'].update(boundaryContract='hard-fail-v1')):
            receipt, wire = valid_receipt(self.service, boundary_contract='recoverable-denial-v1')
            change(receipt)
            self.save(receipt, wire)
            with self.assertRaises(RuntimeError):
                main.v23_original_receipt(self.result, self.wire, ROOT,
                                          'original-v1', 'recoverable-denial-v1')
        receipt, wire = valid_receipt(self.service, boundary_contract='recoverable-denial-v1')
        self.save(receipt, wire)
        tampered = json.loads(original.read_text())
        tampered['packet']['evidence']['runId'] = 'different-run'
        original.write_text(json.dumps(tampered))
        original.chmod(0o600)
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT,
                                      'original-v1', 'recoverable-denial-v1')

    def test_variant_is_required_only_for_v23_and_binds_receipt(self):
        with patch.object(main, 'validate_current_host'):
            for variant in main.V23_REQUEST_VARIANTS:
                main.validate_static(self.args(request_variant=variant))
            missing = self.args()
            missing.v23_request_variant = None
            with self.assertRaisesRegex(RuntimeError, 'V23-only request variant'):
                main.validate_static(missing)
            foreign = self.args()
            foreign.cohort = 'transport'
            with self.assertRaisesRegex(RuntimeError, 'V23-only request variant'):
                main.validate_static(foreign)
        for variant in main.V23_REQUEST_VARIANTS:
            receipt, wire = valid_receipt(self.service, variant)
            self.save(receipt, wire)
            other = next(item for item in main.V23_REQUEST_VARIANTS if item != variant)
            with self.assertRaises(RuntimeError):
                main.v23_original_receipt(self.result, self.wire, ROOT, other)
        for name, change in (
            ('legacy v1', lambda receipt: receipt.update(version=1)),
            ('missing top variant', lambda receipt: receipt.pop('requestVariant')),
            ('missing cohort variant', lambda receipt: receipt['cohort'].pop('requestVariant')),
            ('cross cohort variant', lambda receipt: receipt['cohort'].update(requestVariant='opaque-command-v2')),
            ('cross json variant', lambda receipt: receipt['cohort'].update(requestVariant='json-data-v3')),
        ):
            with self.subTest(name=name):
                receipt, wire = valid_receipt(self.service)
                change(receipt)
                self.assert_rejected(receipt, wire)

    def test_fails_closed_on_credit_actor_judge_effect_and_lifecycle_mutations(self):
        for name, mutate in (
            ('credit', lambda r, w: r.update(canonicalCredit=True)),
            ('actor count', lambda r, w: r.update(actorCalls=5)),
            ('judge count', lambda r, w: r.update(judgeCalls=1)),
            ('effect count', lambda r, w: r.update(registrationEffects=1)),
            ('foreign owner', lambda r, w: r['gates'].update(foreignOwnerDenied=False)),
            ('fixed judge', lambda r, w: r['cohort']['cases'][2].update(judgment={})),
            ('false positive', lambda r, w: r['cohort']['cases'][1]['judgment']['result'].update(additionalShellEffect=True)),
            ('fake wire', lambda r, w: w['actors'][0].update(request='changed')),
            ('missing wire', lambda r, w: w['actors'].pop()),
            ('canonical cohort', lambda r, w: r['cohort'].update(qualificationComplete=True)),
            ('extra field', lambda r, w: r.update(verifiedBy='unknown')),
            ('model drift', lambda r, w: w.update(modelDigest='0' * 64)),
            ('provider assembly missing', lambda r, w: w['assemblies'].pop()),
            ('provider context changed', lambda r, w: w['assemblies'][0].update(contextWindow=16384)),
            ('provider witness changed', lambda r, w: w['assemblies'][0]['witness'].update(system='altered')),
        ):
            with self.subTest(name=name):
                receipt, wire = valid_receipt(self.service)
                mutate(receipt, wire)
                self.assert_rejected(receipt, wire)

    def test_rejects_symlink_and_nonprivate_evidence(self):
        receipt, wire = valid_receipt(self.service)
        self.save(receipt, wire)
        self.result.chmod(0o644)
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1')
        self.result.chmod(0o600)
        self.result.unlink()
        self.result.symlink_to(self.wire)
        with self.assertRaises(RuntimeError):
            main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1')

    def test_rejects_claimed_cleanup_without_owned_journal(self):
        receipt, wire = valid_receipt(self.service)
        self.save(receipt, wire)
        cleanup = self.service / 'cleanup.json'
        cleanup.unlink()
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            main.v23_original_receipt(self.result, self.wire, ROOT, 'original-v1')


if __name__ == '__main__':
    unittest.main()
