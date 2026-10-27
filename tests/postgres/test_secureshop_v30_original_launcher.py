"""Controlled V30 original launcher checks; never starts a host, model, or browser."""

import copy
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import run_v30_with_host_controller as outside


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    'v30_original_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
main = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(main)


class V30OriginalLauncherTests(unittest.TestCase):
    def setUp(self):
        private = ROOT / 'tasks/tmp'
        private.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='v30-launcher-control-', dir=private)
        self.addCleanup(self.temporary.cleanup)
        self.result = Path(self.temporary.name) / 'v30-original-result.json'
        self.wire = Path(self.temporary.name) / 'v30-original-wire.json'
        self.checkpoints = Path(self.temporary.name) / 'v30-original-checkpoints.jsonl'
        self.mcp = Path(self.temporary.name) / 'v30-original-mcp-results.jsonl'
        self.controller = Path(self.temporary.name) / 'v30-host-controller.json'
        self.policy = Path(self.temporary.name) / 'v30-agent-host-combined.sb'

    def synthetic_evidence(self):
        """Parser controls only; these opaque packets are never genuine V30 evidence."""
        cases = []
        slots = []
        for index, mode in enumerate(('vuln', 'fixed')):
            call = {'kind': 'actor', 'request': '{}', 'response': '{}'}
            judge = {'kind': 'judge', 'request': '{}', 'response': '{}'}
            slots.append({'kind': 'actor', 'calls': [call]})
            cases.append({'mode': mode, 'packet': {'physical': [call]},
                          'readback': {}, 'judge': {'calls': [judge],
                                                   'transcript': {'mode': mode},
                                                   'result': {'verdict': 'pass' if index == 0 else 'fail'}}})
        slots += [{'kind': 'judge', 'calls': case['judge']['calls']} for case in cases]
        gates = dict.fromkeys(('originalActor', 'physicalJudge', 'sameRequestRecovery',
            'foreignOwnerDenied', 'foreignSessionDenied', 'modeAbaFenced',
            'resetFenced', 'siblingPreserved', 'sharedStatePreserved',
            'noCanonicalCredit', 'hostStopped', 'transportsClosed',
            'poolsClosed', 'modelUnchanged'), True)
        result = {'version': 1, 'cohort': main.V30_ORIGINAL_COHORT,
                  'rubricVersion': 'v30-original-customer-substantive-disclosure-v1',
                  'boundary': 'original-customer-zero-tool-v1',
                  'passed': True, 'canonicalCredit': False, 'publicRouteQualified': False,
                  'actorCalls': 2, 'judgeCalls': 2, 'gates': gates,
                  'contrast': {'canonicalCredit': False, 'publicRouteQualified': False,
                               'scenarioContrastSatisfied': True},
                  'cases': [{'mode': case['mode'], 'packetSha256': 'a' * 64,
                             'status': 'admitted', 'judgeVerdict': case['judge']['result']['verdict']}
                            for case in cases], 'errors': [], 'cleanupErrors': []}
        metadata = {'model': main.OLLAMA_MODEL, 'digest': main.MAIL_INLINE_MODEL_SHA256}
        wire = {'version': 1, 'cohort': main.V30_ORIGINAL_COHORT,
                'model': main.OLLAMA_MODEL, 'modelDigest': main.MAIL_INLINE_MODEL_SHA256,
                'cases': cases, 'transports': slots, 'lifecycle': {},
                'modelBefore': metadata, 'modelAfter': metadata,
                'host': {'pid': 42, 'instanceId': '11111111-1111-4111-8111-111111111111',
                         'port': 12345, 'terminal': {'exitCode': 0, 'signalCode': None},
                         'endpointClosed': True}}
        return result, wire

    def save_synthetic(self, result, wire):
        self.result.write_text(json.dumps(result))
        self.wire.write_text(json.dumps(wire))
        checkpoints = ([{'kind': 'wire', 'value': slot} for slot in wire['transports']]
                       + [{'kind': 'case-' + case['mode'], 'value': case['packet']}
                          for case in wire['cases']]
                       + [{'kind': 'judge-' + case['mode'],
                           'value': case['judge']['transcript']} for case in wire['cases']])
        self.checkpoints.write_text(''.join(json.dumps(row) + '\n' for row in checkpoints))
        self.result.chmod(0o600)
        self.wire.chmod(0o600)
        self.checkpoints.chmod(0o600)

    def args(self):
        return main.parse(['--main-workspace', str(ROOT), '--node', '/bin/node',
                           '--docker', '/bin/docker', '--docker-sha256', 'a' * 64,
                           '--docker-host', 'unix:///owned/docker.sock',
                           '--docker-daemon', 'a' * 64,
                           '--image-id', 'sha256:' + 'b' * 64,
                           '--cohort', main.V30_ORIGINAL,
                           '--current-host-profile', str(ROOT / 'tasks/runtime'),
                           '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256])

    def test_new_selector_is_separate_from_legacy_supervisor_v30(self):
        args = self.args()
        self.assertEqual(args.cohort, 'v30-original-disclosure')
        self.assertIsNone(args.legacy_supervisor_diagnostic)
        self.assertEqual(main.V30_ORIGINAL_TEST,
                         'tests/postgres/secureshopCustomerDisclosureActual.integration.test.js')
        self.assertEqual(main.V30_ORIGINAL_ASSERTION,
                         'V30 original customer disclosure preserves private source, independent Judge, Fixed containment and lifecycle')
        self.assertEqual(main.V30_ORIGINAL_COHORT,
                         'secureshop-v30-original-customer-disclosure-current-main-v1')

    def test_current_host_real_model_and_no_browser_are_required(self):
        args = self.args()
        with patch.object(main, 'validate_current_host'):
            main.validate_static(args)
            for field, value in (('current_host_profile', None),
                                 ('ollama_model_sha256', '0' * 64),
                                 ('browser', '/outside/browser')):
                changed = copy.copy(args)
                setattr(changed, field, value)
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    main.validate_static(changed)

    def test_v2_profile_is_closed_and_v30_exclusive(self):
        args = self.args()
        self.assertIsNone(args.v30_original_profile)
        v2 = main.parse(['--main-workspace', str(ROOT), '--node', '/bin/node',
                         '--docker', '/bin/docker', '--docker-sha256', 'a' * 64,
                         '--docker-host', 'unix:///owned/docker.sock',
                         '--docker-daemon', 'a' * 64, '--image-id', 'sha256:' + 'b' * 64,
                         '--cohort', main.V30_ORIGINAL,
                         '--current-host-profile', str(ROOT / 'tasks/runtime'),
                         '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256,
                         '--v30-original-profile', main.V30_ORIGINAL_V2_PROFILE])
        with patch.object(main, 'validate_current_host'):
            main.validate_static(v2)
            other = copy.copy(v2)
            other.cohort = main.V37_CONSUMPTION
            with self.assertRaisesRegex(RuntimeError, 'cohort exclusive'):
                main.validate_static(other)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main.parse(['--v30-original-profile', 'unreviewed-v3'])

    def test_v3_profile_is_explicit_and_v30_exclusive(self):
        args = self.args()
        selected = main.parse(['--main-workspace', str(ROOT), '--node', '/bin/node',
                               '--docker', '/bin/docker', '--docker-sha256', 'a' * 64,
                               '--docker-host', 'unix:///owned/docker.sock',
                               '--docker-daemon', 'a' * 64, '--image-id', 'sha256:' + 'b' * 64,
                               '--cohort', main.V30_ORIGINAL,
                               '--current-host-profile', str(ROOT / 'tasks/runtime'),
                               '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256,
                               '--v30-original-profile', main.V30_ORIGINAL_V3_PROFILE])
        self.assertEqual(selected.v30_original_profile, main.V30_ORIGINAL_V3_PROFILE)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main.parse(['--run', '--cohort', main.V30_ORIGINAL,
                        '--v30-original-profile', main.V30_ORIGINAL_V3_PROFILE])
        with patch.object(main, 'validate_current_host'):
            main.validate_static(selected)
            selected.cohort = main.V37_CONSUMPTION
            with self.assertRaisesRegex(RuntimeError, 'cohort exclusive'):
                main.validate_static(selected)

    def test_exact_outside_selector_removed_before_main_parser(self):
        outside_arguments = ['--run', '--cohort', main.V30_ORIGINAL,
                             '--v30-original-profile', main.V30_ORIGINAL_V3_PROFILE,
                             '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256,
                             '--evidence-parent', str(ROOT / 'tasks/qualification')]
        self.assertEqual(outside.validate_arguments(outside_arguments),
                         main.V30_ORIGINAL_V3_PROFILE)
        wrapper_arguments = ['--main-workspace', str(ROOT),
                             '--node', str(ROOT / 'tasks/runtime/node/node_modules/node/bin/node'),
                             '--node-sha256', 'a' * 64,
                             '--docker', str(ROOT / 'tasks/runtime/container/bin/docker'),
                             '--docker-sha256', 'b' * 64,
                             '--docker-host', f'unix://{ROOT}/.qualification/goat-q/docker.sock',
                             '--docker-daemon', '945f6fce-3aaf-4d8f-a483-170464fb2416',
                             '--image-id', 'sha256:' + 'c' * 64,
                             '--current-host-profile', 'goat-q']
        parsed = main.parse([*wrapper_arguments, *outside_arguments[1:]])
        self.assertEqual(parsed.cohort, main.V30_ORIGINAL)
        self.assertEqual(parsed.v30_original_profile, main.V30_ORIGINAL_V3_PROFILE)
        self.assertEqual(parsed.evidence_parent, str(ROOT / 'tasks/qualification'))
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main.parse([*wrapper_arguments, *outside_arguments])

    def test_child_environment_has_exact_four_store_roles_and_private_root(self):
        pairs = [{'runtime': f'postgresql://runtime/{name}',
                  'migration': f'postgresql://migration/{name}'}
                 for name in ('identity', 'agents', 'commerce', 'review')]
        evidence = ROOT / 'tasks/qualification/controlled-v30-plan'
        env = main.v30_original_environment(ROOT, evidence, *pairs)
        self.assertEqual(env['SECURESHOP_V30_ORIGINAL_NATIVE'], '1')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['PG_TEST_ROOT'], str(evidence))
        self.assertEqual(env['V30_ORIGINAL_RESULT'], str(evidence / 'v30-original-result.json'))
        self.assertEqual(env['DVAIA_CURRENT_MAIN_WORKSPACE'], str(ROOT))
        self.assertEqual(env['OLLAMA_MODEL'], main.OLLAMA_MODEL)
        self.assertEqual(env['JUDGE_MODEL'], main.OLLAMA_MODEL)
        self.assertEqual({key for key in env if key.startswith('PG_SECURESHOP_DISCLOSURE_')},
                         {f'PG_SECURESHOP_DISCLOSURE_{name}_{role}_URL'
                          for name in ('IDENTITY', 'AGENTS', 'COMMERCE', 'REVIEW')
                          for role in ('RUNTIME', 'MIGRATION')})
        self.assertEqual(env['PG_SECURESHOP_DISCLOSURE_REVIEW_MIGRATION_URL'],
                         pairs[3]['migration'])
        self.assertEqual(env['SECURESHOP_DATABASE_URL'], pairs[2]['runtime'])
        self.assertEqual(env['SECURESHOP_AGENTS_DATABASE_URL'], pairs[1]['runtime'])
        self.assertNotIn('SECURESHOP_LEGACY_SUPERVISOR_DIAGNOSTIC', env)
        self.assertNotIn('V30_ORIGINAL_PROFILE', env)
        v2 = main.v30_original_environment(ROOT, evidence, *pairs,
                                           main.V30_ORIGINAL_V2_PROFILE)
        self.assertEqual(v2['V30_ORIGINAL_PROFILE'], main.V30_ORIGINAL_V2_PROFILE)
        self.assertEqual({key for key in v2 if key.startswith('PG_SECURESHOP_DISCLOSURE_')},
                         {key for key in env if key.startswith('PG_SECURESHOP_DISCLOSURE_')})
        v3 = main.v30_original_environment(ROOT, evidence, *pairs,
                                           main.V30_ORIGINAL_V3_PROFILE)
        self.assertEqual(v3['V30_ORIGINAL_PROFILE'], main.V30_ORIGINAL_V3_PROFILE)
        self.assertEqual({key for key in v3 if key.startswith('PG_SECURESHOP_DISCLOSURE_')},
                         {key for key in env if key.startswith('PG_SECURESHOP_DISCLOSURE_')})

    def test_source_closure_includes_actual_node_fixture_and_effect_producers(self):
        with self.assertRaisesRegex(RuntimeError, 'Reviewed V30 source'):
            main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL)
        # Historical v1 pins remain immutable. Inspect current source closure
        # only under temporary test-local substitutions, never live admission.
        replacements = {name: main.digest(ROOT / member) for name, member in (
            ('V30_ORIGINAL_TEST_SHA256', main.V30_ORIGINAL_TEST),
            ('V30_ORIGINAL_CONTRACT_SHA256', main.V30_ORIGINAL_CONTRACT),
            ('V30_ORIGINAL_CAPTURE_SHA256', main.V30_ORIGINAL_CAPTURE),
            ('V30_ORIGINAL_CAPTURE_TEST_SHA256', main.V30_ORIGINAL_CAPTURE_TEST),
            ('V30_ORIGINAL_TRANSPORT_SHA256', 'tests/postgres/secureshopMailActualTransport.js'))}
        with patch.multiple(main, **replacements):
            pins = main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL)['sourcePins']
        for member in (main.V30_ORIGINAL_TEST, main.V30_ORIGINAL_CONTRACT,
                       main.V30_ORIGINAL_LAUNCHER_TEST,
                       'tests/fixtures/secureshopCustomerDisclosureActual.js',
                       'tests/secureshopCustomerDisclosureActual.test.js',
                       'tests/postgres/secureshopManualRagNativeSetup.js',
                       'tests/postgres/secureshopMailActualTransport.js',
                       main.V30_ORIGINAL_RECORDING_TEST,
                       'server/agent-runtime/objectiveJudge.js',
                       'agent-host/agents/cart/tools/index.postgres.js'):
            with self.subTest(member=member):
                self.assertRegex(pins[member], r'^[a-f0-9]{64}$')
        self.assertEqual(pins['tests/postgres/secureshopMailActualTransport.js'],
                         replacements['V30_ORIGINAL_TRANSPORT_SHA256'])
        self.assertEqual(pins[main.V30_ORIGINAL_RECORDING_TEST],
                         main.V30_ORIGINAL_RECORDING_SHA256)
        for name, expected in ((main.V30_ORIGINAL_TEST, replacements['V30_ORIGINAL_TEST_SHA256']),
                               (main.V30_ORIGINAL_CONTRACT, replacements['V30_ORIGINAL_CONTRACT_SHA256']),
                               (main.V30_ORIGINAL_CAPTURE, replacements['V30_ORIGINAL_CAPTURE_SHA256']),
                               (main.V30_ORIGINAL_CAPTURE_TEST, replacements['V30_ORIGINAL_CAPTURE_TEST_SHA256'])):
            self.assertEqual(pins[name], expected)
        with patch.multiple(main, **replacements):
            with patch.object(main, 'V30_ORIGINAL_TRANSPORT_SHA256', '0' * 64):
                with self.assertRaisesRegex(RuntimeError, 'physical recorder'):
                    main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL)
            with patch.object(main, 'V30_ORIGINAL_TEST_SHA256', '0' * 64):
                with self.assertRaisesRegex(RuntimeError, 'Reviewed V30 source'):
                    main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL)
        with self.assertRaisesRegex(RuntimeError, 'Reviewed V30 v2 source'):
            main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL,
                                 v30_original_profile=main.V30_ORIGINAL_V2_PROFILE)
        with self.assertRaisesRegex(RuntimeError, 'Closed V30 source profile'):
            main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION,
                                 v30_original_profile=main.V30_ORIGINAL_V2_PROFILE)
        # Historical v3 bytes stay pinned; prospective question selection is explicit.
        with self.assertRaisesRegex(RuntimeError, 'Reviewed V30 v3 source'):
            main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL,
                                 v30_original_profile=main.V30_ORIGINAL_V3_PROFILE)
        v3 = main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL,
                                  v30_original_profile=main.V30_ORIGINAL_V3_PROFILE,
                                  v30_question_candidate=main.V30_CONTEXT_QUESTION_CANDIDATE)['sourcePins']
        for member, expected in main.V30_CONTEXT_QUESTION_PINS.items():
            self.assertEqual(v3[member], expected)
        with patch.dict(main.V30_CONTEXT_QUESTION_PINS, {main.V30_ORIGINAL_CONTRACT: '0' * 64}):
            with self.assertRaisesRegex(RuntimeError, 'Reviewed V30 v3 source'):
                main.source_snapshot(ROOT, '/bin/node', main.V30_ORIGINAL,
                                     v30_original_profile=main.V30_ORIGINAL_V3_PROFILE,
                                     v30_question_candidate=main.V30_CONTEXT_QUESTION_CANDIDATE)

    def test_v2_live_source_gate_stays_closed_pending_reviewed_native_partition(self):
        result, wire = self.synthetic_evidence()
        self.save_synthetic(result, wire)
        with patch.object(main.subprocess, 'run') as replay:
            with self.assertRaises(RuntimeError):
                main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                          main.V30_ORIGINAL_V2_PROFILE, 4321)
            replay.assert_not_called()

    def synthetic_v2(self):
        """Structural parser controls only: the replayed Node verifier is mocked."""
        result, wire = self.synthetic_evidence()
        result.update(version=2, boundary=main.V30_ORIGINAL_V2_BOUNDARY,
                      profile=main.V30_ORIGINAL_V2_PROFILE)
        result['gates'].update(isolatedHost=True, durableEffects=True)
        wire.update(version=2, profile=main.V30_ORIGINAL_V2_PROFILE)
        for index, case in enumerate(wire['cases']):
            case['packet']['decisions'] = [{'attempts': [{'physical': wire['transports'][index]['calls'][0]}]}]
            case['packet']['toolCalls'] = []
        tuple_value = {'runId': 'run', 'ownerKey': 'owner', 'generation': '1',
                       'effectKey': 'effect', 'step': 1, 'callId': 'call'}
        wire['cases'][0]['packet']['toolCalls'] = [{'effectReceipt': tuple_value}]
        wire['durableEffects'] = [{
            'ledgerEffect': {key: tuple_value[key] for key in ('runId', 'ownerKey',
                             'generation', 'effectKey')} | {'status': 'completed'},
            'toolResult': tuple_value | {'resultSha256': 'b' * 64}}]
        wire['networkProof'] = {'version': 1, 'policySha256': '', 'probePid': 4321,
                                'probeTerminal': {'exitCode': 0, 'signalCode': None},
                                'postgresAllowed': True, 'modelDenied': True,
                                'externalDenied': True, 'loopbackBound': True}
        wire['host'].update(birth=[10, 20], controllerReceiptSha256='',
                            cleanupVerified=True, networkProof=wire['networkProof'])
        return result, wire, tuple_value

    def save_synthetic_v2(self, result, wire, tuple_value):
        self.policy.write_bytes(b'(version 1)\n')
        self.policy.chmod(0o600)
        wire['networkProof']['policySha256'] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        state = {'phase': 'terminal', 'pid': wire['host']['pid'],
                 'birth': wire['host']['birth'], 'instanceId': wire['host']['instanceId'],
                 'hostPort': wire['host']['port'], 'terminal': wire['host']['terminal'],
                 'networkProof': wire['networkProof'], 'cleanupVerified': True}
        controller = {'version': 1, 'grantSha256': 'a' * 64, 'launcherPid': 1234,
                      'workerPid': 4321, 'state': state}
        self.controller.write_text(json.dumps(controller) + '\n')
        self.controller.chmod(0o600)
        wire['host']['controllerReceiptSha256'] = hashlib.sha256(self.controller.read_bytes()).hexdigest()
        self.result.write_text(json.dumps(result) + '\n')
        self.wire.write_text(json.dumps(wire) + '\n')
        checkpoints = ([{'kind': 'wire', 'value': slot} for slot in wire['transports']]
                       + [{'kind': 'multistep-case', 'value': case['packet']}
                          for case in wire['cases']]
                       + [{'kind': 'judge-' + case['mode'],
                           'value': case['judge']['transcript']} for case in wire['cases']])
        self.checkpoints.write_text(''.join(json.dumps(row) + '\n' for row in checkpoints))
        self.mcp.write_text(''.join(json.dumps(row) + '\n' for row in (
            {'kind': 'reserved'} | tuple_value,
            {'kind': 'result'} | tuple_value | {'resultSha256': 'b' * 64})))
        for path in (self.result, self.wire, self.checkpoints, self.mcp):
            path.chmod(0o600)

    def synthetic_v3(self):
        result, wire, tuple_value = self.synthetic_v2()
        result.update(version=3, profile=main.V30_ORIGINAL_V3_PROFILE,
                      boundary=main.V30_ORIGINAL_V3_BOUNDARY)
        wire.update(version=3, profile=main.V30_ORIGINAL_V3_PROFILE)
        wire['networkProof']['loopbackInboundVerified'] = True
        file_state = {'path': str(Path(self.temporary.name) / 'v30-original-owned-read.txt'),
                      'dev': 1, 'ino': 2, 'uid': 3, 'mode': 0o600, 'nlink': 1,
                      'byteLength': 12, 'sha256': 'a' * 64}
        wire['ownedFileProof'] = {'before': file_state, 'after': copy.deepcopy(file_state), 'uses': []}
        thread = {'threadId': 11, 'emailId': 12, 'from': 'owned-v30@example.invalid',
                  'to': 'recipient-v30@example.invalid', 'subject': 'V30 owned synthetic thread',
                  'bodySha256': 'a' * 64, 'htmlSha256': 'a' * 64,
                  'createdAt': '2026-01-01T00:00:00.000Z'}
        wire['ownedThreadProof'] = {'before': thread, 'after': copy.deepcopy(thread), 'uses': []}
        cart = {'productId': 5, 'ownerIds': [7, 8], 'siblingId': 9,
                'seed': {'rows': []}, 'final': {'rows': []},
                'postflight': {'rows': []}, 'uses': []}
        wire['ownedCartProof'] = cart
        wire['ownedTicketProof'] = {'ownerIds': [7, 8], 'siblingId': 9,
                                    'seed': [], 'final': [], 'postflight': [], 'uses': []}
        return result, wire, tuple_value

    def save_synthetic_v3(self, result, wire, tuple_value):
        self.save_synthetic_v2(result, wire, tuple_value)
        rows = [json.loads(line) for line in self.checkpoints.read_text().splitlines()]
        proofs = wire['ownedThreadProof'], wire['ownedCartProof'], wire['ownedTicketProof']
        for kind, value in (('owned-thread-before', proofs[0]['before']),
                            ('owned-thread-after', proofs[0]['after']),
                            ('cart-seed', proofs[1]['seed']),
                            ('cart-final', proofs[1]['final']),
                            ('cart-postflight', proofs[1]['postflight']),
                            ('ticket-seed', proofs[2]['seed']),
                            ('ticket-final', proofs[2]['final']),
                            ('ticket-postflight', proofs[2]['postflight'])):
            rows.append({'kind': kind, 'value': value})
        self.checkpoints.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        self.wire.write_text(json.dumps(wire) + '\n')

    def test_v2_private_receipt_joins_controller_policy_mcp_and_offline_verifier(self):
        result, wire, tuple_value = self.synthetic_v2()
        self.save_synthetic_v2(result, wire, tuple_value)
        with patch.object(main.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='verified\n')) as replay:
            admitted = main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                                  main.V30_ORIGINAL_V2_PROFILE, 4321)
        self.assertEqual(admitted, result)
        self.assertEqual(replay.call_count, 1)
        args = replay.call_args.args[0]
        self.assertEqual(args[:3], ['/owned/node', '-e', args[2]])
        self.assertIn('verifyEvidenceV2', args[2])
        self.assertEqual(args[-4:], [str(self.result), str(self.wire), str(self.mcp), '4321'])
        with patch.object(main.subprocess, 'run') as replay:
            with self.assertRaisesRegex(RuntimeError, 'worker birth'):
                main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                          main.V30_ORIGINAL_V2_PROFILE, None)
            with self.assertRaisesRegex(RuntimeError, 'controller receipt join'):
                main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                          main.V30_ORIGINAL_V2_PROFILE, 4322)
            replay.assert_not_called()

    def test_v2_private_receipt_rejects_tampered_policy_controller_journal_and_budget(self):
        for name, mutate in (
            ('policy', lambda result, wire: self.policy.write_bytes(b'(version 2)\n')),
            ('controller', lambda result, wire: self.controller.write_text('{}\n')),
            ('mcp', lambda result, wire: self.mcp.write_text('')),
            ('missing-checkpoint', lambda result, wire: self.checkpoints.write_text('{}\n')),
            ('extra-actor', lambda result, wire: wire.update(transports=[
                {'kind': 'actor', 'calls': wire['transports'][0]['calls'] * 17},
                *wire['transports'][1:]])),
            ('wrong-result', lambda result, wire: wire['durableEffects'][0]['toolResult'].update(
                resultSha256='c' * 64)),
            ('wrong-controller-hash', lambda result, wire: wire['host'].update(
                controllerReceiptSha256='d' * 64))):
            with self.subTest(name=name):
                result, wire, tuple_value = self.synthetic_v2()
                self.save_synthetic_v2(result, wire, tuple_value)
                mutate(result, wire)
                if name in ('extra-actor', 'wrong-result', 'wrong-controller-hash'):
                    self.wire.write_text(json.dumps(wire) + '\n')
                with patch.object(main.subprocess, 'run') as replay:
                    with self.assertRaises(RuntimeError):
                        main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                                  main.V30_ORIGINAL_V2_PROFILE, 4321)
                    replay.assert_not_called()

    def test_v3_receipt_requires_exact_selected_path_proofs_and_replay(self):
        result, wire, tuple_value = self.synthetic_v3()
        self.save_synthetic_v3(result, wire, tuple_value)
        with patch.object(main.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='verified\n')) as replay:
            self.assertEqual(main.v30_original_receipt(
                self.result, self.wire, '/owned/node', main.V30_ORIGINAL_V3_PROFILE, 4321), result)
            self.assertEqual(replay.call_count, 1)
            self.assertIn('verifyEvidenceV2', replay.call_args.args[0][2])
        for name, mutate in (
            ('wrong-profile', lambda w: w.update(profile=main.V30_ORIGINAL_V2_PROFILE)),
            ('missing-ticket-proof', lambda w: w.pop('ownedTicketProof')),
            ('extra-cart-proof', lambda w: w['ownedCartProof'].update(secret='bad')),
            ('wrong-file-path', lambda w: w['ownedFileProof']['before'].update(path='/tmp/other')),
            ('missing-inbound-probe', lambda w: w['networkProof'].pop('loopbackInboundVerified')),
            ('changed-cart-postflight', lambda w: w['ownedCartProof'].update(postflight={'rows': [1]}))):
            with self.subTest(name=name):
                result, wire, tuple_value = self.synthetic_v3()
                self.save_synthetic_v3(result, wire, tuple_value)
                mutate(wire)
                self.wire.write_text(json.dumps(wire) + '\n')
                with patch.object(main.subprocess, 'run') as replay:
                    with self.assertRaises(RuntimeError):
                        main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                                  main.V30_ORIGINAL_V3_PROFILE, 4321)
                    replay.assert_not_called()

    def test_v3_parallel_effect_journal_joins_by_key_not_adjacent_completion(self):
        result, wire, first = self.synthetic_v3()
        second = {**first, 'effectKey': 'effect-two', 'callId': 'call-two'}
        wire['cases'][0]['packet']['toolCalls'].append({'effectReceipt': second})
        wire['durableEffects'].append({
            'ledgerEffect': {key: second[key] for key in ('runId', 'ownerKey',
                             'generation', 'effectKey')} | {'status': 'completed'},
            'toolResult': second | {'resultSha256': 'c' * 64}})
        self.save_synthetic_v3(result, wire, first)
        reserved_first = {'kind': 'reserved'} | first
        result_first = {'kind': 'result'} | first | {'resultSha256': 'b' * 64}
        reserved_second = {'kind': 'reserved'} | second
        result_second = {'kind': 'result'} | second | {'resultSha256': 'c' * 64}
        admitted = [reserved_first, reserved_second, result_second, result_first]
        def write(rows):
            self.mcp.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        write(admitted)
        with patch.object(main.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='verified\n')) as replay:
            main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                      main.V30_ORIGINAL_V3_PROFILE, 4321)
            replay.assert_called_once()
        for name, rows in (
            ('result-before-own-reservation', [result_second, reserved_first,
                                               reserved_second, result_first]),
            ('duplicate-reservation', [reserved_first, reserved_first,
                                       result_second, result_first]),
            ('mismatched-result-tuple', [reserved_first, reserved_second,
                                         {**result_second, 'callId': 'wrong'}, result_first]),
            ('unmatched-effect-key', [reserved_first, reserved_second,
                                      {**result_second, 'effectKey': 'third'}, result_first])):
            with self.subTest(name=name):
                write(rows)
                with patch.object(main.subprocess, 'run') as replay:
                    with self.assertRaises(RuntimeError):
                        main.v30_original_receipt(self.result, self.wire, '/owned/node',
                                                  main.V30_ORIGINAL_V3_PROFILE, 4321)
                    replay.assert_not_called()

    def test_v3_plan_gate_reflects_only_selected_controller_profile(self):
        import v30_agent_host_controller as controller
        self.assertTrue(main.v30_original_native_gate(main.V30_ORIGINAL_V3_PROFILE))
        self.assertFalse(main.v30_original_native_gate(main.V30_ORIGINAL_V2_PROFILE))
        with patch.object(controller, 'LIVE_ENABLED', False), \
                patch.object(controller, 'FULL_LIVE_ENABLED', False):
            self.assertFalse(main.v30_original_native_gate(main.V30_ORIGINAL_V3_PROFILE))
            self.assertFalse(main.v30_original_native_gate(main.V30_ORIGINAL_V2_PROFILE))
        with patch.object(controller, 'LIVE_ENABLED', True), \
                patch.object(controller, 'FULL_LIVE_ENABLED', False):
            self.assertFalse(main.v30_original_native_gate(main.V30_ORIGINAL_V3_PROFILE))
            self.assertTrue(main.v30_original_native_gate(main.V30_ORIGINAL_V2_PROFILE))
        with patch.object(controller, 'LIVE_ENABLED', False), \
                patch.object(controller, 'FULL_LIVE_ENABLED', True):
            self.assertTrue(main.v30_original_native_gate(main.V30_ORIGINAL_V3_PROFILE))
            self.assertFalse(main.v30_original_native_gate(main.V30_ORIGINAL_V2_PROFILE))

    def test_v2_fixed_host_grant_binds_owned_manifest_binary_ports_and_store_urls(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        manifest = Path(self.temporary.name) / 'source-before.json'
        manifest.write_text('{"sourcePins":{}}')
        pairs = [{'runtime': f'postgresql://runtime@127.0.0.1:6543/{name}',
                  'migration': f'postgresql://migration@127.0.0.1:6543/{name}'}
                 for name in ('commerce', 'agents')]
        owner = '11111111-1111-4111-8111-111111111111'
        values = (ROOT, Path(self.temporary.name), node, main.digest(node),
                  'abcdef012345', 6543, 17500, *pairs, 'a' * 64, owner)
        grant = main.v30_v2_host_grant(*values)
        self.assertEqual(set(grant), {'run', 'nodePath', 'nodeSha256',
                                     'sourceManifestSha256', 'pgNonce', 'pgPort',
                                     'hostPort', 'commerceUrl', 'agentsUrl',
                                     'containerId', 'owner'})
        self.assertEqual(grant['sourceManifestSha256'], main.digest(manifest))
        self.assertEqual(grant['commerceUrl'], pairs[0]['runtime'])
        for position, replacement in ((3, '0' * 64), (4, 'bad'), (5, 0),
                                      (6, 6543), (9, 'bad'), (10, 'bad')):
            changed = list(values)
            changed[position] = replacement
            with self.subTest(position=position), self.assertRaises(RuntimeError):
                main.v30_v2_host_grant(*changed)

    def test_v2_pg_retirement_requires_controller_terminal_and_real_host_reap(self):
        port = 17500
        ack = {'grantSha256': 'a' * 64, 'hostPort': port,
               'networkPolicySha256': 'b' * 64}
        terminal = {'exitCode': 0, 'signalCode': None}
        state = {'phase': 'terminal', 'pid': 12345, 'birth': [10, 20],
                 'instanceId': '11111111-1111-4111-8111-111111111111',
                 'hostPort': port, 'terminal': terminal, 'networkProof': {},
                 'cleanupVerified': True, 'receiptSha256': 'c' * 64}
        self.assertTrue(main.v30_v2_host_quiescent(state, ack, port))
        for mutate in (lambda row: row.update(phase='running'),
                       lambda row: row.update(cleanupVerified=False),
                       lambda row: row.update(terminal=None),
                       lambda row: row.update(hostPort=port + 1),
                       lambda row: row.update(receiptSha256=None),
                       lambda row: row.update(birth=None),
                       lambda row: row.update(pid=None)):
            changed = copy.deepcopy(state)
            mutate(changed)
            self.assertFalse(main.v30_v2_host_quiescent(changed, ack, port))
        never_started = dict.fromkeys(state)
        never_started.update(phase='terminal', hostPort=port,
                             cleanupVerified=True, receiptSha256='c' * 64)
        self.assertTrue(main.v30_v2_host_quiescent(never_started, ack, port))
        never_started['terminal'] = terminal
        self.assertFalse(main.v30_v2_host_quiescent(never_started, ack, port))

    def test_v30_reporter_contract_rejects_spec_and_incomplete_tap(self):
        title = main.V30_ORIGINAL_ASSERTION
        good = f'# Subtest: {title}\nok 1 - {title}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(main.complete_tap_counts(good, 'V30', [title])['pass'], 1)
        for bad in ('✔ ' + title + '\nℹ tests 1\nℹ pass 1\n',
                    good.replace('# tests 1\n', ''), good + '# tests 1\n',
                    good.replace('# fail 0', '# fail 1'),
                    good.replace('# skipped 0', '# skipped 1'),
                    good.replace('ok 1 -', 'not ok 1 -'),
                    good.replace(title, 'wrong assertion')):
            with self.assertRaises(RuntimeError):
                main.complete_tap_counts(bad, 'V30', [title])

    def test_v2_only_exact_node_command_inherits_worker_fd_not_launcher_fd(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        command, environment, descriptors = main.v30_v2_worker_launch(
            ROOT, node, {'NODE_ENV': 'test'}, 81, 'a' * 64, 17500)
        self.assertEqual(command, [str(node), '--test', '--test-isolation=none', '--test-reporter=tap',
                                   str(ROOT / main.V30_ORIGINAL_TEST)])
        self.assertEqual(descriptors, (81,))
        self.assertEqual(environment['DVAIA_V30_HOST_WORKER_FD'], '81')
        self.assertEqual(environment['DVAIA_V30_HOST_NONCE'], 'a' * 64)
        self.assertEqual(environment['V30_AGENT_HOST_PORT'], '17500')
        self.assertNotIn('DVAIA_V30_HOST_LAUNCHER_FD', environment)
        with self.assertRaisesRegex(RuntimeError, 'Exact V30 worker'):
            main.v30_v2_worker_launch(ROOT, node,
                                      {'DVAIA_V30_HOST_LAUNCHER_FD': '82'},
                                      81, 'a' * 64, 17500)

    def test_v2_pg_cleanup_fence_rejects_injected_host_or_worker_stop_failure(self):
        self.assertTrue(main.v30_v2_may_retire_pg(False, False, False))
        self.assertTrue(main.v30_v2_may_retire_pg(True, True, True))
        for child, host in ((False, True), (True, False), (False, False),
                            (None, True), (True, None)):
            with self.subTest(child=child, host=host):
                self.assertFalse(main.v30_v2_may_retire_pg(True, child, host))

    def test_private_structural_admission_delegates_original_semantics_to_offline_replay(self):
        result, wire = self.synthetic_evidence()
        self.save_synthetic(result, wire)
        with patch.object(main.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='verified\n', stderr='')) as replay:
            self.assertEqual(main.v30_original_receipt(self.result, self.wire, '/owned/node'), result)
            command = replay.call_args.args[0]
            self.assertEqual(command[0], '/owned/node')
            self.assertEqual(command[-2:], [str(self.result), str(self.wire)])
            self.assertIn('verifyEvidence', command[2])
            self.assertEqual(replay.call_args.kwargs['cwd'], ROOT)
            self.assertEqual(replay.call_args.kwargs['env']['TMPDIR'], self.temporary.name)
        with patch.object(main.subprocess, 'run', return_value=SimpleNamespace(
                returncode=1, stdout='', stderr='private material')):
            with self.assertRaisesRegex(RuntimeError, 'verifier rejected'):
                main.v30_original_receipt(self.result, self.wire, '/owned/node')

    def test_outer_summary_uses_admitted_actor_and_judge_fields(self):
        result, wire = self.synthetic_evidence()
        self.save_synthetic(result, wire)
        fields = main.v30_original_outer_fields(
            Path(self.temporary.name), result, {'model': 4}, {'digest': 'pinned'},
            {'digest': 'after'}, True, True)
        self.assertEqual(fields['v30OriginalReceipt'], result)
        self.assertEqual(fields['actualModelCalls'], 4)
        self.assertEqual(fields['v30OriginalReceiptSha256'], main.digest(self.result))
        self.assertEqual(fields['v30OriginalWireSha256'], main.digest(self.wire))
        self.assertEqual(fields['selectedFixtures'], [main.V30_ORIGINAL_TEST])
        self.assertIs(fields['canonicalCredit'], False)
        self.assertIs(fields['nativeQualificationAccepted'], False)
        missing = copy.deepcopy(result)
        missing.pop('actorCalls')
        with self.assertRaises(KeyError):
            main.v30_original_outer_fields(Path(self.temporary.name), missing,
                                           {}, None, None, False, False)

    def test_synthetic_false_credits_budget_lifecycle_and_physical_joins_are_denied(self):
        for name, mutate in (
            ('credit', lambda r, w: r.update(canonicalCredit=True)),
            ('public route', lambda r, w: r.update(publicRouteQualified=True)),
            ('semantic false positive', lambda r, w: r['contrast'].update(scenarioContrastSatisfied=False)),
            ('missing lifecycle', lambda r, w: r['gates'].update(resetFenced=False)),
            ('extra actor', lambda r, w: r.update(actorCalls=3)),
            ('extra Judge', lambda r, w: r.update(judgeCalls=5)),
            ('different model digest', lambda r, w: w.update(modelDigest='0' * 64)),
            ('changed physical slot', lambda r, w: w['cases'][0]['packet'].update(physical=[])),
            ('judge summary disagree', lambda r, w: r['cases'][0].update(judgeVerdict='fail')),
            ('extra receipt key', lambda r, w: r.update(unsupported=True)),
        ):
            with self.subTest(name=name):
                result, wire = self.synthetic_evidence()
                mutate(result, wire)
                self.save_synthetic(result, wire)
                with patch.object(main.subprocess, 'run') as replay:
                    with self.assertRaises(RuntimeError):
                        main.v30_original_receipt(self.result, self.wire, '/owned/node')
                    replay.assert_not_called()

    def test_nonprivate_and_symlinked_v30_evidence_are_denied_before_replay(self):
        result, wire = self.synthetic_evidence()
        self.save_synthetic(result, wire)
        self.result.chmod(0o644)
        with patch.object(main.subprocess, 'run') as replay:
            with self.assertRaises(RuntimeError):
                main.v30_original_receipt(self.result, self.wire, '/owned/node')
            replay.assert_not_called()
        self.result.unlink()
        self.result.symlink_to(self.wire)
        with patch.object(main.subprocess, 'run') as replay:
            with self.assertRaises(RuntimeError):
                main.v30_original_receipt(self.result, self.wire, '/owned/node')
            replay.assert_not_called()

    def test_durable_checkpoint_and_owned_host_terminal_are_required(self):
        for name, mutate in (
            ('missing journal', lambda r, w: self.checkpoints.unlink()),
            ('changed journal', lambda r, w: self.checkpoints.write_text('{}\n')),
            ('unclosed endpoint', lambda r, w: w['host'].update(endpointClosed=False)),
            ('unterminated host', lambda r, w: w['host'].update(terminal={
                'exitCode': None, 'signalCode': None})),
            ('wrong host port', lambda r, w: w['host'].update(port=0)),
            ('case packet not durable', lambda r, w: self.checkpoints.write_text(
                ''.join(json.dumps(row) + '\n' for row in (
                    {'kind': 'wire', 'value': slot} for slot in w['transports'])))),
            ('judge transcript not durable', lambda r, w: self.checkpoints.write_text(
                ''.join(json.dumps(row) + '\n' for row in (
                    [{'kind': 'wire', 'value': slot} for slot in w['transports']]
                    + [{'kind': 'case-' + case['mode'], 'value': case['packet']}
                       for case in w['cases']])))),
        ):
            with self.subTest(name=name):
                result, wire = self.synthetic_evidence()
                self.save_synthetic(result, wire)
                mutate(result, wire)
                if name not in ('missing journal', 'changed journal',
                                'case packet not durable', 'judge transcript not durable'):
                    self.wire.write_text(json.dumps(wire))
                with patch.object(main.subprocess, 'run') as replay:
                    with self.assertRaises(RuntimeError):
                        main.v30_original_receipt(self.result, self.wire, '/owned/node')
                    replay.assert_not_called()
if __name__ == '__main__':
    unittest.main()
