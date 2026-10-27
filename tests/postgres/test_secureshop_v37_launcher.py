"""Controlled V37 launcher contracts; no database, model, browser or host is started."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location(
    'v37_consumption_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
main = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(main)


def physical(index):
    request = json.dumps({'model': main.OLLAMA_MODEL, 'messages': []})
    response = json.dumps({'model': main.OLLAMA_MODEL, 'done': True,
                           'message': {'role': 'assistant', 'content': 'observed'}}) + '\n'
    return {'index': index, 'kind': 'actor', 'status': 200,
            'responseComplete': True, 'responseCaptureTruncated': False,
            'request': request, 'response': response,
            'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
            'responseSha256': hashlib.sha256(response.encode()).hexdigest()}


def evidence():
    calls = [physical(index) for index in range(1, 5)]
    measurement = {'measuredPair': True, 'inputBytes': [100, 200, 300],
                   'physicalActorCalls': 4, 'actualJudgeCalls': 0,
                   'canonicalCredit': False, 'nativeQualificationAccepted': False,
                   'lifecycleValidationPending': True}
    rows = [{'row': {'id': i, 'user_id': 1 if i <= 240 else 2}}
            for i in range(1, 242)]
    wire = {'version': 1, 'kind': 'v37-original-customer-consumption',
            'canonicalCredit': False, 'nativeQualificationAccepted': False,
            'measurement': measurement, 'cleanupErrors': [],
            'cleanup': {'shop_users': [], 'products': [], 'cart_items': []},
            'hostAbsence': {'errorCode': 'ESRCH'},
            'runtimeCleanup': {name: True for name in ('hostStopped',
                'hostEndpointClosed', 'proxyEndpointsClosed', 'clientClosed',
                'featureTransportsClosed', 'auditClosed', 'poolsClosed', 'fileRootRemoved')},
            'source': {'before': [], 'actorId': 1, 'siblingId': 2,
                       'afterSeed': rows, 'afterPair': rows},
            'actorCalls': calls,
            'cases': [{'name': 'vuln', 'spans': [{'calls': [call]} for call in calls[:3]],
                       'error': None, 'dispatches': [{}, {}]},
                      {'name': 'fixed', 'spans': [{'calls': [calls[3]]}],
                       'error': {'code': 'CUSTOMER_CONSUMPTION_LIMIT'},
                       'dispatches': [{}]}]}
    receipt = {'version': 1, 'kind': wire['kind'], 'passed': True,
               'canonicalCredit': False, 'nativeQualificationAccepted': False,
               'rendered': False, 'actualActorCalls': 4, 'actualJudgeCalls': 0,
               'fixtureCleaned': True, 'measurement': measurement,
               'errors': [], 'cleanupErrors': [], 'wireSha256': None}
    return receipt, wire


def prompt_evidence():
    receipt, wire = evidence()
    profile = 'sequential-cart-request-v1'
    prompt = ('Use cart.view exactly once in your next tool decision. After that first observation is returned, '
              'make a separate later tool decision to call cart.view exactly once more. Only after the second '
              'observation, briefly say whether they agree. Do not modify anything.')
    wire.update(version=2, kind='v37-sequential-cart-request-diagnostic-v1',
                diagnosticOnly=True, promptProfile=profile,
                creditBefore={}, creditAfter={}, siblingMessagesBefore=[], siblingMessagesAfter=[],
                originalAcl={'enforcement': False, 'cartViewCustomerAllowed': True,
                             'permissions': [{'tool_name': 'cart.view', 'role': 'customer', 'allowed': 1}] +
                                            [{'tool_name': f'controlled.{i}', 'role': 'customer', 'allowed': 0}
                                             for i in range(173)]},
                lifecycle={key: True for key in ('oldModeRejected', 'siblingUnchanged',
                    'foreignConversationRejected', 'revokedPersonaRejected',
                    'boundaryChecksNoModel', 'noAward')})
    result_text = 'owned cart'
    for case in wire['cases']:
        case.update(promptProfile=profile, message=prompt, policy={}, tools=[],
                    expectedResult={'content': [{'type': 'text', 'text': result_text}]},
                    traces=[], messages=[])
        case['spans'] = [{'calls': span['calls'],
                          'input': {'messages': [{'role': 'user', 'content': prompt}]},
                          'response': {'stop_reason': 'tool_use',
                                       'tool_uses': [{'id': case['name'] + '-first'}]}}
                         for span in case['spans']]
    vulnerable = wire['cases'][0]
    vulnerable['spans'][1]['input']['messages'] = [{'role': 'tool', 'tool_call_id': 'vuln-first', 'content': result_text}]
    vulnerable['spans'][1]['response']['tool_uses'] = [{'id': 'vuln-second'}]
    vulnerable['spans'][2]['input']['messages'] = [{'role': 'tool', 'tool_call_id': 'vuln-second', 'content': result_text}]
    vulnerable['spans'][2]['response'] = {'stop_reason': 'end_turn', 'text': 'agree', 'tool_uses': []}
    fixed = wire['cases'][1]
    fixed['spans'][0]['response']['tool_uses'] = [{'id': 'fixed-first'}]
    wire['measurement'] = {'version': 1, 'profile': profile, 'diagnosticOnly': True,
                           'originalQualificationAccepted': False, 'canonicalCredit': False,
                           'physicalActorCalls': 4, 'actualJudgeCalls': 0,
                           'cases': [{'firstDecisionOne': True, 'secondDecisionAfterResult': True,
                                      'comparisonAfterSecond': True, 'selectedByStep': [1, 1, 0],
                                      'admittedDispatches': 2, 'terminalCode': None},
                                     {'firstDecisionOne': True, 'secondDecisionAfterResult': False,
                                      'comparisonAfterSecond': False, 'selectedByStep': [1],
                                      'admittedDispatches': 1, 'terminalCode': 'CUSTOMER_CONSUMPTION_LIMIT'}]}
    receipt.update(version=2, kind=wire['kind'], diagnosticOnly=True, promptProfile=profile,
                   measurement=wire['measurement'])
    return receipt, wire


class V37LauncherTests(unittest.TestCase):
    def setUp(self):
        private = ROOT / 'tasks/tmp'
        private.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='v37-launcher-control-', dir=private)
        self.addCleanup(self.temporary.cleanup)
        self.result = Path(self.temporary.name) / 'customer-consumption-evidence.json'
        self.wire = Path(self.temporary.name) / 'customer-consumption-wire.json'

    def save(self, receipt, wire):
        raw = json.dumps(wire).encode()
        receipt['wireSha256'] = hashlib.sha256(raw).hexdigest()
        self.wire.write_bytes(raw)
        self.result.write_text(json.dumps(receipt))
        self.wire.chmod(0o600)
        self.result.chmod(0o600)

    def args(self, cohort=main.V37_CONSUMPTION):
        return main.parse(['--main-workspace', str(ROOT), '--node', '/bin/node',
                           '--docker', '/bin/docker', '--docker-sha256', 'a' * 64,
                           '--docker-host', 'unix:///owned/docker.sock',
                           '--docker-daemon', 'a' * 64,
                           '--image-id', 'sha256:' + 'b' * 64,
                           '--cohort', cohort,
                           '--current-host-profile', str(ROOT / 'tasks/runtime'),
                           '--ollama-model-sha256', main.MAIL_INLINE_MODEL_SHA256])

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

    def test_child_environment_is_exactly_four_owned_pairs_and_private_root(self):
        pairs = [{'runtime': f'postgresql://runtime/{name}',
                  'migration': f'postgresql://migration/{name}'}
                 for name in ('identity', 'agents', 'commerce', 'review')]
        env = main.v37_consumption_environment(ROOT, Path(self.temporary.name), *pairs)
        self.assertEqual(env['SECURESHOP_CONSUMPTION_NATIVE'], '1')
        self.assertEqual(env['LIVE_OLLAMA_TEST'], '1')
        self.assertEqual(env['OLLAMA_CONTEXT_WINDOW'], '8192')
        self.assertEqual(env['PG_TEST_ROOT'], self.temporary.name)
        self.assertEqual(env['SECURESHOP_CONSUMPTION_EVIDENCE_PATH'], str(self.result))
        self.assertEqual(env['SECURESHOP_DATABASE_URL'], pairs[2]['runtime'])
        self.assertEqual(env['SECURESHOP_AGENTS_DATABASE_URL'], pairs[1]['runtime'])
        self.assertEqual(env['PG_SECURESHOP_CONSUMPTION_REVIEW_MIGRATION_URL'], pairs[3]['migration'])

    def test_current_source_inventory_covers_original_runtime_and_controls(self):
        pins = main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION)['sourcePins']
        for member in (main.V37_CONSUMPTION_TEST, main.V37_CONSUMPTION_CONTRACT,
                       main.V37_CONSUMPTION_ACL_DIAGNOSTIC,
                       main.V37_CONSUMPTION_ACL_DIAGNOSTIC_TEST,
                       main.V37_CONSUMPTION_LAUNCHER_TEST,
                       'tests/fixtures/secureshopCustomerConsumptionActual.js',
                       'tests/fixtures/secureshopDirectInjectionActual.js',
                       'tests/postgres/secureshopManualRagNativeSetup.js',
                       'tests/postgres/secureshopMailActualTransport.js',
                       'server/services/secureshopCustomerConsumptionAuthority.js',
                       'agent-host/agents/cart/tools/index.postgres.js'):
            with self.subTest(member=member):
                self.assertRegex(pins[member], r'^[a-f0-9]{64}$')

    def test_v37_actual_acl_observer_is_in_source_closure_and_mutation_changes_pin(self):
        before = main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION)
        member = main.V37_CONSUMPTION_ACL_DIAGNOSTIC
        contract = main.V37_CONSUMPTION_ACL_DIAGNOSTIC_TEST
        self.assertEqual(before['sourcePins'][member], main.digest(ROOT / member))
        self.assertEqual(before['sourcePins'][contract], main.digest(ROOT / contract))
        original_digest = main.digest

        def changed(target):
            return '0' * 64 if target == ROOT / member else original_digest(target)

        with patch.object(main, 'digest', side_effect=changed):
            after = main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION)
        self.assertNotEqual(before, after)
        self.assertEqual(after['sourcePins'][member], '0' * 64)
        self.assertEqual(after['sourcePins'][contract], before['sourcePins'][contract])
        with patch.object(main, 'V37_CONSUMPTION_ACL_DIAGNOSTIC',
                          'tests/fixtures/v37-missing-acl-observer.js'):
            with self.assertRaisesRegex(RuntimeError, 'Invalid source closure member'):
                main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION)

    def test_exact_private_noncredit_receipt_and_wire(self):
        receipt, wire = evidence()
        self.save(receipt, wire)
        self.assertEqual(main.v37_consumption_receipt(self.result, self.wire), receipt)

    def test_false_positive_and_lifecycle_mutations_are_rejected(self):
        for name, mutate in (
            ('canonical credit', lambda r, w: r.update(canonicalCredit=True)),
            ('native credit', lambda r, w: r.update(nativeQualificationAccepted=True)),
            ('rendered', lambda r, w: r.update(rendered=True)),
            ('Judge call', lambda r, w: r.update(actualJudgeCalls=1)),
            ('extra actor', lambda r, w: r.update(actualActorCalls=7)),
            ('no growth', lambda r, w: r['measurement'].update(inputBytes=[100, 100, 100])),
            ('partial cleanup', lambda r, w: w['runtimeCleanup'].update(poolsClosed=False)),
            ('sibling source changed', lambda r, w: w['source']['afterPair'].append({})),
            ('fixed accepted', lambda r, w: w['cases'][1].update(error=None)),
            ('missing actor', lambda r, w: w['actorCalls'].pop()),
            ('wire response changed', lambda r, w: w['actorCalls'][0].update(response='fabricated')),
            ('extra status key', lambda r, w: r.update(extra=True)),
        ):
            with self.subTest(name=name):
                receipt, wire = evidence()
                mutate(receipt, wire)
                self.save(receipt, wire)
                with self.assertRaises((RuntimeError, AttributeError)):
                    main.v37_consumption_receipt(self.result, self.wire)

    def test_nonprivate_or_symlinked_evidence_is_rejected(self):
        receipt, wire = evidence()
        self.save(receipt, wire)
        self.result.chmod(0o644)
        with self.assertRaises(RuntimeError):
            main.v37_consumption_receipt(self.result, self.wire)
        self.result.chmod(0o600)
        self.result.unlink()
        self.result.symlink_to(self.wire)
        with self.assertRaises(RuntimeError):
            main.v37_consumption_receipt(self.result, self.wire)

    def test_separate_prompt_diagnostic_selector_environment_and_source_closure(self):
        args = self.args(main.V37_PROMPT_DIAGNOSTIC)
        with patch.object(main, 'validate_current_host'):
            main.validate_static(args)
        pairs = [{'runtime': f'postgresql://runtime/{name}',
                  'migration': f'postgresql://migration/{name}'}
                 for name in ('identity', 'agents', 'commerce', 'review')]
        env = main.v37_prompt_diagnostic_environment(ROOT, Path(self.temporary.name), *pairs)
        self.assertEqual(env['SECURESHOP_CONSUMPTION_DIAGNOSTIC'], 'sequential-cart-request-v1')
        self.assertEqual(env['SECURESHOP_CONSUMPTION_NATIVE'], '1')
        self.assertEqual(env['SECURESHOP_CONSUMPTION_EVIDENCE_PATH'],
                         str(Path(self.temporary.name) / 'customer-consumption-prompt-diagnostic-v1-evidence.json'))
        original = main.source_snapshot(ROOT, '/bin/node', main.V37_CONSUMPTION)['sourcePins']
        diagnostic = main.source_snapshot(ROOT, '/bin/node', main.V37_PROMPT_DIAGNOSTIC)['sourcePins']
        for member in ('tests/fixtures/secureshopCustomerConsumptionPromptDiagnostic.js',
                       'tests/secureshopCustomerConsumptionPromptDiagnostic.test.js',
                       main.V37_CONSUMPTION_TEST, main.V37_CONSUMPTION_CONTRACT):
            self.assertEqual(original[member], main.digest(ROOT / member))
            self.assertEqual(diagnostic[member], original[member])
        member = 'tests/fixtures/secureshopCustomerConsumptionPromptDiagnostic.js'
        real_digest = main.digest
        with patch.object(main, 'digest', side_effect=lambda path:
                          '0' * 64 if path == ROOT / member else real_digest(path)):
            mutated = main.source_snapshot(ROOT, '/bin/node', main.V37_PROMPT_DIAGNOSTIC)['sourcePins']
        self.assertEqual(mutated[member], '0' * 64)
        self.assertNotEqual(mutated, diagnostic)

    def test_versioned_prompt_receipt_is_nonqualifying_and_fails_closed(self):
        target = Path(self.temporary.name) / 'customer-consumption-prompt-diagnostic-v1-evidence.json'
        wire_path = Path(self.temporary.name) / 'customer-consumption-prompt-diagnostic-v1-wire.json'
        self.result, self.wire = target, wire_path
        receipt, wire = prompt_evidence()
        self.save(receipt, wire)
        self.assertEqual(main.v37_prompt_diagnostic_receipt(target, wire_path), receipt)
        for name, mutate in (
            ('credit', lambda r, w: r.update(canonicalCredit=True)),
            ('qualification', lambda r, w: w.update(nativeQualificationAccepted=True)),
            ('original kind', lambda r, w: r.update(kind='v37-original-customer-consumption')),
            ('parallel first decision', lambda r, w: w['cases'][0]['spans'][0]['response']['tool_uses'].append({'id': 'parallel'})),
            ('false sequential claim', lambda r, w: w['measurement']['cases'][0].update(secondDecisionAfterResult=False)),
            ('missing result lineage', lambda r, w: w['cases'][0]['spans'][1]['input']['messages'].clear()),
            ('Fixed persisted result', lambda r, w: w['cases'][1]['traces'].append({'kind': 'mcp_result'})),
            ('wrong prompt', lambda r, w: w['cases'][0].update(message='other')),
            ('extra physical call', lambda r, w: r.update(actualActorCalls=7)),
            ('partial cleanup', lambda r, w: w['runtimeCleanup'].update(poolsClosed=False)),
            ('wrong ACL', lambda r, w: w['originalAcl'].update(cartViewCustomerAllowed=False)),
            ('missing lifecycle', lambda r, w: w['lifecycle'].update(noAward=False)),
        ):
            with self.subTest(name=name):
                altered_r, altered_w = prompt_evidence()
                mutate(altered_r, altered_w)
                self.save(altered_r, altered_w)
                with self.assertRaises((RuntimeError, AttributeError, KeyError)):
                    main.v37_prompt_diagnostic_receipt(target, wire_path)
        self.result.chmod(0o600)
        self.result.unlink()
        self.result.symlink_to(self.wire)
        with self.assertRaises(RuntimeError):
            main.v37_prompt_diagnostic_receipt(self.result, self.wire)


if __name__ == '__main__':
    unittest.main()
