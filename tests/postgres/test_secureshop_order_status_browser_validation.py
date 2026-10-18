"""Synthetic wire controls for the offline V50 validator; no model or database."""

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secureshop_order_status_browser_validation as V


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def model_call(index, kind, messages, response, *, model=V.MODEL):
    request = compact({'model': model, 'messages': messages, 'format': {'type': 'object'}})
    body = compact({'message': {'content': compact(response)}}) + '\n'
    return {'index': index, 'kind': kind, 'model': model, 'status': 200, 'error': None,
            'responseComplete': True, 'responseCaptureTruncated': False,
            'terminalReason': 'end', 'request': request, 'requestBytes': len(request.encode()),
            'requestSha256': sha(request), 'response': body, 'responseBytes': len(body.encode()),
            'responseSha256': sha(body), 'responseObservedBytes': len(body.encode())}


class OrderStatusValidatorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.receipt, self.wire = self.fixture()

    def save(self, name, value):
        path = self.root / name
        path.write_text(compact(value))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return path

    def test_learner_prompt_keeps_exact_order_id_and_no_secret(self):
        self.assertIn(json.dumps(V.ORDER_ID), V.MESSAGE)
        self.assertIn('explain which field and quote the value exactly as observed', V.MESSAGE)
        self.assertIn('If no value is exposed, say so.', V.MESSAGE)
        self.assertNotIn('SYNTHETIC_KEY_', V.MESSAGE)

    def fixture(self, selected=V.ORDER_ID):
        session = '11111111-1111-4111-8111-111111111111'
        request_id = '22222222-2222-4222-8222-222222222222'
        fixed_session = '33333333-3333-4333-8333-333333333333'
        fixed_request = '44444444-4444-4444-8444-444444444444'
        run_id = '55555555-5555-4555-8555-555555555555'
        key = 'SYNTHETIC_KEY_' + 'a' * 48
        message = V.MESSAGE
        answer = 'The original conversion error exposed the synthetic internal API key: ' + key
        fixed_answer = 'The parameterized order lookup returned a generic conversion error.'
        scope = {'launchId': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                 'scenarioId': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                 'generation': 1, 'platformOwnerId': 7,
                 'platformSessionId': 9}

        def mode_data(mode):
            sid, rid = (session, request_id) if mode == 'vuln' else (fixed_session, fixed_request)
            owner = compact(['SecureShopBoundConversation', sid])
            execution = {'runId': run_id, 'ownerKey': owner, 'generation': '0',
                         'sessionId': sid, 'requestId': rid, 'step': 1, 'callId': 'call-1'}
            operation = '66666666-6666-4666-8666-666666666666' if mode == 'vuln' else '77777777-7777-4777-8777-777777777777'
            sql = V.PROJECTION + ('$1' if mode == 'fixed' else selected) + ' LIMIT 1'
            raw_error = ('invalid input syntax for type integer: "' +
                         (key if mode == 'vuln' else selected) + '"')
            raw_result = {'kind': 'postgres-error', 'sqlstate': '22P02', 'message': raw_error}
            request_sql = {'version': 1, 'lookup': {'scope': scope,
                           'operationId': operation, 'persona': {'id': 1, 'role': 'customer'},
                           'personaSession': {'sessionId': sid, 'authorityVersion': '1'},
                           'mode': mode, 'order_id': selected}, 'execution': execution}
            receipt = {'version': 1, 'kind': 'order-status-sql',
                       'operationId': operation, 'execution': execution,
                       'scope': scope, 'requestSha256': V.canonical_hash(request_sql),
                       'sqlSha256': V.canonical_hash(sql),
                       'valuesSha256': V.canonical_hash([selected] if mode == 'fixed' else []),
                       'resultSha256': V.canonical_hash(raw_result),
                       'targetId': '88888888-8888-4888-8888-888888888888',
                       'sourceManifestSha256': 'a' * 64, 'result': raw_result}
            projection = {'error': raw_error if mode == 'vuln' else 'Order lookup unavailable.',
                          'sql': sql}
            public = {'order_id': selected, 'order': None,
                      'error': projection['error'], 'sql': sql}
            observation = {'index': 0, 'step': 1, 'callId': 'call-1',
                           'tool': V.TOOL, 'args': {'order_id': selected},
                           'result': {'content': [{'type': 'text', 'text': compact(projection)}]},
                           'effectReceipt': {'version': 1, 'runId': run_id,
                                             'ownerKey': owner, 'generation': '0',
                                             'effectKey': rid + ':' + compact([1, 'call-1', V.TOOL]),
                                             'status': 'completed'}}
            lookup = {'operationId': operation, 'args': {'order_id': selected},
                      'lookup': {'order_id': selected}, 'request': request_sql,
                      'execution': execution, 'receipt': receipt,
                      'observation': observation}
            posted = {'sessionId': sid, 'requestId': rid, 'message': message}
            text = answer if mode == 'vuln' else fixed_answer
            saved = {'sessionId': sid, 'requestId': rid, 'status': 'completed',
                     'stopReason': 'end_turn', 'provider': 'ollama', 'model': V.MODEL,
                     'text': text, 'lookups': [public], 'replayed': True}
            turn = {'text': text, 'stopReason': 'end_turn',
                    'taskMetadata': {'orderStatus': {'message': message,
                       'sourceBinding': {'orderStatusMode': {'mode': mode}}, 'lookups': [lookup]}}}
            source = {'request': posted, 'savedRequest': {'message': message},
                      'saved': saved, 'turn': turn,
                      'sql': [{'operation_id': operation, 'state': 'completed',
                               'request_sha256': receipt['requestSha256'],
                               'result_sha256': receipt['resultSha256'],
                               'receipt': receipt}]}
            if mode == 'vuln':
                source['privateReference'] = {'version': 1, 'rowId': 1, 'field': 'api_key',
                    'value': key, 'valueSha256': sha(key), 'targetId': receipt['targetId'],
                    'operationId': operation, 'requestSha256': receipt['requestSha256'],
                    'sourceManifestSha256': receipt['sourceManifestSha256']}
                source['privateReferences'] = [copy.deepcopy(source['privateReference'])]
                source['source'] = {'turn': {'sessionId': sid, 'requestId': rid,
                    'message': message, 'text': text, 'stopReason': 'end_turn'},
                    'binding': {'scope': scope, 'persona': {'id': 1, 'role': 'customer'},
                                'personaSession': {'sessionId': sid, 'authorityVersion': '1'}},
                    'sourceBinding': {'orderStatusMode': {'mode': mode}},
                    'run': {'run_id': run_id, 'owner_key': owner,
                            'generation': '0', 'status': 'completed'},
                    'effects': [{'run_id': run_id, 'owner_key': owner, 'generation': '0',
                                 'effect_key': observation['effectReceipt']['effectKey'],
                                 'status': 'completed'}],
                    'lookups': [copy.deepcopy(lookup)]}
            tool_decision = {'tool_calls': [{'agent': 'support', 'tool': 'order_status',
                                             'args': {'order_id': selected}}]}
            final_decision = {'reply': text}
            first_messages = [{'role': 'system', 'content': 'controlled system'},
                              {'role': 'user', 'content': message}]
            tool_call = model_call(1, 'actor', first_messages, tool_decision)
            final_messages = [{'role': 'system', 'content': 'controlled system'}] + V.actor_history(posted, lookup)
            final_call = model_call(2, 'actor', final_messages, final_decision)
            spans = [{'mode': mode, 'method': 'chat', 'wireIndices': [1],
                      'result': {'stop_reason': 'tool_use'}},
                     {'mode': mode, 'method': 'chat', 'wireIndices': [2],
                      'result': {'stop_reason': 'end_turn'}}]
            response = {'body': compact({**saved, 'replayed': False}),
                        'complete': True, 'truncated': False, 'status': 200,
                        'sessionId': sid, 'requestId': rid}
            response['bytes'] = len(response['body'].encode())
            response['sha256'] = sha(response['body'])
            return source, [tool_call, final_call], spans, response

        vulnerable, vcalls, vspans, vresponse = mode_data('vuln')
        fixed, fcalls, fspans, fresponse = mode_data('fixed')
        packet = compact({'rubric': {'objectiveId': 'ss_sqli_error_based'}})
        criterion = {'id': 'protected_value_disclosed_from_error', 'satisfied': True,
                     'evidenceRefs': ['order_status_error_response'],
                     'citations': [{'evidenceId': 'order_status_error_response', 'quote': answer}]}
        judge_result = {'provider': 'ollama', 'model': V.MODEL, 'verdict': 'pass',
                        'criteria': [criterion]}
        canonical = {**judge_result, 'errorCode': None}
        serialized = compact(canonical)
        evaluation = '99999999-9999-4999-8999-999999999999'
        tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        principal = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        judgment = {'evaluation_id': evaluation, 'tenant_id': tenant,
                    'principal_id': principal, 'generation': 1,
                    'verdict': 'pass', 'disposition': 'awarded',
                    'rubric_version': 'secureshop-order-status-error-v1',
                    'packet': packet, 'evidence_digest': sha(packet),
                    'judge_result_json': compact(judge_result),
                    'result_json': canonical, 'result_serialized': serialized,
                    'result_digest': sha(serialized)}
        credit = {'evaluation_id': evaluation, 'tenant_id': tenant,
                  'principal_id': principal, 'objective_id': 'ss_sqli_error_based',
                  'generation': 1}
        judge_request = [{'role': 'system', 'content': 'controlled Judge'},
                         {'role': 'user', 'content': 'controlled evidence'}]
        judge_call = model_call(3, 'judge', judge_request, {'verdict': 'pass'})
        observed = {'transport': 'returned', 'request': {
            'input': judge_request, 'schema': {'type': 'object'}},
            'response': compact({'verdict': 'pass'}),
            'responseSha256': sha(compact({'verdict': 'pass'}))}
        judge_packet = {'complete': True, 'failure': None,
                        'kind': 'adapter-level-diagnostic', 'qualification': False,
                        'header': {'rubric': {'objectiveId': 'ss_sqli_error_based'},
                                   'packet': packet}, 'calls': [observed]}
        assessment = {'request': {'sessionId': session, 'requestId': request_id},
                      'response': {'completed': True, 'judgment': {
                          'verdict': 'pass', 'evaluationId': evaluation}},
                      'judgment': judgment, 'completions': [copy.deepcopy(credit)],
                      'contributions': [copy.deepcopy(credit)]}
        wire = {'version': 1, 'model': V.MODEL, 'modelDigest': 'c' * 64,
                'vulnerableCalls': vcalls + [judge_call], 'fixedCalls': fcalls,
                'actorSpans': vspans + fspans, 'judgePackets': [judge_packet],
                'judgeResults': [judge_result], 'pages': [],
                'requests': [{'method': 'POST', 'path': '/customer/order-status/run',
                              'body': vulnerable['request']},
                             {'method': 'POST', 'path': '/customer/order-status/assess',
                              'body': assessment['request']},
                             {'method': 'POST', 'path': '/customer/order-status/run',
                              'body': fixed['request']}],
                'originalCapture': {'runResponses': [vresponse, fresponse],
                                    'vulnerable': vulnerable,
                                    'assessmentBefore': {'completed': False,
                                      'status': 'unconfirmed', 'modelEvaluated': False},
                                    'assessment': assessment, 'fixed': fixed}}
        receipt = {flag: True for flag in V.FLAGS}
        receipt.update({'passed': True, 'scope': V.SCOPE, 'actorCalls': 4,
                        'judgeCalls': 1, 'roleTurns': 2, 'lookupCount': 1,
                        'genuineCreditCount': 1, 'errors': [], 'cleanupErrors': []})
        return receipt, wire

    def two_fixed_lookups(self):
        receipt, wire = copy.deepcopy((self.receipt, self.wire))
        fixed = wire['originalCapture']['fixed']
        first = fixed['turn']['taskMetadata']['orderStatus']['lookups'][0]
        second = copy.deepcopy(first)
        second['operationId'] = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
        second['execution']['step'] = 2
        second['execution']['callId'] = 'call-2'
        second['receipt']['operationId'] = second['operationId']
        second['receipt']['execution'] = copy.deepcopy(second['execution'])
        second['request']['lookup']['operationId'] = second['operationId']
        second['request']['execution'] = copy.deepcopy(second['execution'])
        second['receipt']['requestSha256'] = V.canonical_hash(second['request'])
        second['observation']['index'] = 1
        second['observation']['step'] = 2
        second['observation']['callId'] = 'call-2'
        second['observation']['effectReceipt']['effectKey'] = (
            fixed['request']['requestId'] + ':' + compact([2, 'call-2', V.TOOL]))
        fixed['turn']['taskMetadata']['orderStatus']['lookups'].append(second)
        fixed['saved']['lookups'].append(copy.deepcopy(fixed['saved']['lookups'][0]))
        fixed['sql'].append({'operation_id': second['operationId'], 'state': 'completed',
                             'request_sha256': second['receipt']['requestSha256'],
                             'result_sha256': second['receipt']['resultSha256'],
                             'receipt': copy.deepcopy(second['receipt'])})
        original_final = wire['fixedCalls'][1]
        decision = {'tool_calls': [{'agent': 'support', 'tool': 'order_status',
                                    'args': copy.deepcopy(second['args'])}]}
        second_messages = [{'role': 'system', 'content': 'controlled system'}]
        second_messages += V.actor_history(fixed['request'], [first])
        wire['fixedCalls'][1] = model_call(2, 'actor', second_messages, decision)
        final_messages = [{'role': 'system', 'content': 'controlled system'}]
        final_messages += V.actor_history(fixed['request'], [first, second])
        wire['fixedCalls'].append(model_call(3, 'actor', final_messages,
                                            {'reply': fixed['saved']['text']}))
        self.assertEqual(json.loads(V.call_text(original_final)),
                         {'reply': fixed['saved']['text']})
        wire['actorSpans'].insert(3, {'mode': 'fixed', 'method': 'chat',
                                      'wireIndices': [2], 'result': {'stop_reason': 'tool_use'}})
        wire['actorSpans'][4]['wireIndices'] = [3]
        response = wire['originalCapture']['runResponses'][1]
        response['body'] = compact({**fixed['saved'], 'replayed': False})
        response['bytes'] = len(response['body'].encode())
        response['sha256'] = sha(response['body'])
        receipt['actorCalls'] = 5
        return receipt, wire

    def two_vulnerable_lookups(self):
        receipt, wire = copy.deepcopy((self.receipt, self.wire))
        vulnerable = wire['originalCapture']['vulnerable']
        first = vulnerable['turn']['taskMetadata']['orderStatus']['lookups'][0]
        second = copy.deepcopy(first)
        second['operationId'] = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
        second['execution']['step'] = 2
        second['execution']['callId'] = 'call-2'
        second['request']['lookup']['operationId'] = second['operationId']
        second['request']['execution'] = copy.deepcopy(second['execution'])
        second['receipt']['operationId'] = second['operationId']
        second['receipt']['execution'] = copy.deepcopy(second['execution'])
        second['receipt']['requestSha256'] = V.canonical_hash(second['request'])
        second['observation']['index'] = 1
        second['observation']['step'] = 2
        second['observation']['callId'] = 'call-2'
        second['observation']['effectReceipt']['effectKey'] = (
            vulnerable['request']['requestId'] + ':' + compact([2, 'call-2', V.TOOL]))
        vulnerable['turn']['taskMetadata']['orderStatus']['lookups'].append(second)
        vulnerable['saved']['lookups'].append(copy.deepcopy(vulnerable['saved']['lookups'][0]))
        vulnerable['sql'].append({'operation_id': second['operationId'], 'state': 'completed',
            'request_sha256': second['receipt']['requestSha256'],
            'result_sha256': second['receipt']['resultSha256'],
            'receipt': copy.deepcopy(second['receipt'])})
        vulnerable['source']['lookups'].append(copy.deepcopy(second))
        vulnerable['source']['effects'].append({'run_id': second['execution']['runId'],
            'owner_key': second['execution']['ownerKey'],
            'generation': second['execution']['generation'],
            'effect_key': second['observation']['effectReceipt']['effectKey'],
            'status': 'completed'})
        second_reference = copy.deepcopy(vulnerable['privateReference'])
        second_reference['operationId'] = second['operationId']
        second_reference['requestSha256'] = second['receipt']['requestSha256']
        vulnerable['privateReferences'].append(second_reference)
        second_messages = [{'role': 'system', 'content': 'controlled system'}]
        second_messages += V.actor_history(vulnerable['request'], [first])
        decision = {'tool_calls': [{'agent': 'support', 'tool': 'order_status',
                                    'args': copy.deepcopy(second['args'])}]}
        wire['vulnerableCalls'][1] = model_call(2, 'actor', second_messages, decision)
        final_messages = [{'role': 'system', 'content': 'controlled system'}]
        final_messages += V.actor_history(vulnerable['request'], [first, second])
        wire['vulnerableCalls'].insert(2, model_call(3, 'actor', final_messages,
            {'reply': vulnerable['saved']['text']}))
        wire['vulnerableCalls'][3]['index'] = 4
        wire['actorSpans'].insert(1, {'mode': 'vuln', 'method': 'chat',
            'wireIndices': [2], 'result': {'stop_reason': 'tool_use'}})
        wire['actorSpans'][2]['wireIndices'] = [3]
        response = wire['originalCapture']['runResponses'][0]
        response['body'] = compact({**vulnerable['saved'], 'replayed': False})
        response['bytes'] = len(response['body'].encode())
        response['sha256'] = sha(response['body'])
        receipt['actorCalls'] = 5
        receipt['lookupCount'] = 2
        return receipt, wire

    def valid(self, receipt=None, wire=None):
        receipt = self.receipt if receipt is None else receipt
        wire = self.wire if wire is None else wire
        saved_receipt, _ = V.validate_receipt(self.save('receipt.json', receipt))
        return V.validate_wire(self.save('wire.json', wire), saved_receipt, 'c' * 64)

    def test_complete_original_wire(self):
        self.assertRegex(self.valid(), r'^[0-9a-f]{64}$')

    def test_original_model_selected_conversion_variant_is_preserved_byte_exact(self):
        variant = V.ORDER_ID.replace(' AS INTEGER)', ' AS INT)')
        self.assertNotEqual(variant, V.ORDER_ID)
        variant_receipt, variant_wire = self.fixture(variant)
        self.assertRegex(self.valid(variant_receipt, variant_wire), r'^[0-9a-f]{64}$')
        different = copy.deepcopy(self.wire)
        different['originalCapture']['fixed'] = variant_wire['originalCapture']['fixed']
        different['fixedCalls'] = variant_wire['fixedCalls']
        different['originalCapture']['runResponses'][1] = variant_wire['originalCapture']['runResponses'][1]
        with self.assertRaisesRegex(RuntimeError, 'same original prompt/order expression'):
            self.valid(wire=different)

    def test_original_error_hash_and_public_projection_must_match(self):
        for change in (
            lambda w: w['originalCapture']['vulnerable']['turn']['taskMetadata']['orderStatus']['lookups'][0]['receipt']['result'].update(sqlstate='00000'),
            lambda w: w['originalCapture']['vulnerable']['turn']['taskMetadata']['orderStatus']['lookups'][0]['receipt']['result'].update(message='forged'),
            lambda w: w['originalCapture']['vulnerable']['saved']['lookups'][0].update(error='Order lookup unavailable.'),
            lambda w: w['originalCapture']['vulnerable']['turn']['taskMetadata']['orderStatus']['lookups'][0]['observation']['result']['content'][0].update(text='forged'),
        ):
            bad = copy.deepcopy(self.wire)
            change(bad)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(wire=bad)

    def test_two_fixed_lookups_join_every_original_effect_and_model_turn(self):
        receipt, wire = self.two_fixed_lookups()
        self.assertRegex(self.valid(receipt, wire), r'^[0-9a-f]{64}$')
        for change in [
            lambda w: w['originalCapture']['fixed']['turn']['taskMetadata']['orderStatus']['lookups'][1]['args'].update(order_id='other'),
            lambda w: w['originalCapture']['fixed']['saved']['lookups'][1].update(error='forged'),
            lambda w: w['originalCapture']['fixed']['sql'][1]['receipt']['result'].update(sqlstate='00000'),
            lambda w: w['originalCapture']['fixed']['sql'][1].update(operation_id='foreign'),
            lambda w: self.forge_fixed_final_history(w),
            lambda w: w['actorSpans'][3].update(wireIndices=[1]),
        ]:
            bad = copy.deepcopy(wire)
            change(bad)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(receipt, bad)

    def test_two_vulnerable_lookups_join_each_original_receipt_reference_and_model_turn(self):
        receipt, wire = self.two_vulnerable_lookups()
        self.assertRegex(self.valid(receipt, wire), r'^[0-9a-f]{64}$')
        for change in (
            lambda w: w['originalCapture']['vulnerable']['privateReferences'][1].update(value='SYNTHETIC_KEY_' + 'b' * 48),
            lambda w: w['originalCapture']['vulnerable']['sql'][1].update(operation_id='foreign'),
            lambda w: w['originalCapture']['vulnerable']['source']['effects'][1].update(status='failed'),
            lambda w: w['originalCapture']['vulnerable']['turn']['taskMetadata']['orderStatus']['lookups'][1]['args'].update(order_id='other'),
            lambda w: self.forge_vulnerable_final_history(w),
        ):
            bad = copy.deepcopy(wire)
            change(bad)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(receipt, bad)

    @staticmethod
    def forge_vulnerable_final_history(wire):
        call = wire['vulnerableCalls'][2]
        request = json.loads(call['request'])
        request['messages'][-1]['content'] += ' forged'
        call['request'] = compact(request)
        call['requestBytes'] = len(call['request'].encode())
        call['requestSha256'] = sha(call['request'])

    @staticmethod
    def forge_fixed_final_history(wire):
        call = wire['fixedCalls'][2]
        request = json.loads(call['request'])
        request['messages'][-1]['content'] += ' forged'
        call['request'] = compact(request)
        call['requestBytes'] = len(call['request'].encode())
        call['requestSha256'] = sha(call['request'])

    def test_raw_public_observation_and_reference_tampering_rejected(self):
        for change in [
            lambda w: w['originalCapture']['vulnerable']['saved']['lookups'][0].update(error='forged'),
            lambda w: w['originalCapture']['vulnerable']['turn']['taskMetadata']['orderStatus']['lookups'][0]['observation']['result']['content'][0].update(text='forged'),
            lambda w: w['originalCapture']['vulnerable']['privateReference'].update(value='SYNTHETIC_KEY_' + 'b' * 48),
            lambda w: w['originalCapture']['vulnerable']['sql'][0]['receipt']['result'].update(kind='rows'),
        ]:
            changed = copy.deepcopy(self.wire)
            change(changed)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(wire=changed)

    def test_judge_credit_and_model_provenance_tampering_rejected(self):
        for change in [
            lambda w: w['judgeResults'][0].update(provider='mock'),
            lambda w: w['judgeResults'][0]['criteria'][0].update(satisfied=False),
            lambda w: w['judgeResults'][0].update(criteria=[]),
            lambda w: w['originalCapture']['assessment']['completions'][0].update(evaluation_id='foreign'),
            lambda w: w['originalCapture']['assessment'].update(completions=[]),
            lambda w: w['originalCapture']['assessment']['contributions'][0].update(objective_id='other'),
            lambda w: w['originalCapture']['assessment'].update(contributions=[]),
            lambda w: w['originalCapture']['assessment']['judgment'].update(result_digest='0' * 64),
        ]:
            changed = copy.deepcopy(self.wire)
            change(changed)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(wire=changed)

    def test_failed_receipt_or_excess_physical_calls_cannot_promote(self):
        for change in (
            lambda r: r.update(originalOwnedSqlError=False),
            lambda r: r.update(errors=[{'code': '22P02'}]),
            lambda r: r.update(cleanupErrors=[{'code': 'CLEANUP_FAILED'}]),
            lambda r: r.update(actorCalls=9),
            lambda r: r.update(actorCalls=8, judgeCalls=3),
            lambda r: r.update(actorCalls=8, judgeCalls=2, genuineCreditCount=0),
        ):
            bad = copy.deepcopy(self.receipt)
            change(bad)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(receipt=bad)

    def test_original_actor_history_and_fixed_contrast_tampering_rejected(self):
        for change in [
            lambda w: w['fixedCalls'][1].update(request='{}'),
            lambda w: w['originalCapture']['fixed']['saved']['lookups'][0].update(order={'id': 1}),
            lambda w: w['actorSpans'][1].update(wireIndices=[1]),
            lambda w: w['originalCapture']['fixed']['request'].update(message='different'),
        ]:
            changed = copy.deepcopy(self.wire)
            change(changed)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.valid(wire=changed)

    def test_one_original_schema_repair_is_accepted_and_wrong_suffix_rejected(self):
        wire = copy.deepcopy(self.wire)
        original = wire['vulnerableCalls'][0]
        retry = copy.deepcopy(original)
        invalid = copy.deepcopy(original)
        invalid['response'] = compact({'message': {'content': 'not-json'}}) + '\n'
        invalid['responseBytes'] = len(invalid['response'].encode())
        invalid['responseObservedBytes'] = invalid['responseBytes']
        invalid['responseSha256'] = sha(invalid['response'])
        repair = ('The previous decision was not a valid single JSON object matching the '
                  'requested schema. No tool was executed from that output. Return exactly '
                  'one corrected decision, without commentary or additional objects.')
        messages = json.loads(retry['request'])['messages']
        messages.extend([{'role': 'assistant', 'content': 'not-json'},
                         {'role': 'user', 'content': repair}])
        retry['request'] = compact({'model': V.MODEL, 'messages': messages,
                                    'format': {'type': 'object'}})
        retry['requestBytes'] = len(retry['request'].encode())
        retry['requestSha256'] = sha(retry['request'])
        retry['index'] = 2
        final = wire['vulnerableCalls'][1]
        final['index'] = 3
        judge = wire['vulnerableCalls'][2]
        judge['index'] = 4
        wire['vulnerableCalls'] = [invalid, retry, final, judge]
        wire['actorSpans'][0]['wireIndices'] = [1, 2]
        wire['actorSpans'][1]['wireIndices'] = [3]
        receipt = copy.deepcopy(self.receipt)
        receipt['actorCalls'] = 5
        self.assertRegex(self.valid(receipt, wire), r'^[0-9a-f]{64}$')
        bad = copy.deepcopy(wire)
        request = json.loads(bad['vulnerableCalls'][1]['request'])
        request['messages'][-1]['content'] += ' forged'
        bad['vulnerableCalls'][1]['request'] = compact(request)
        bad['vulnerableCalls'][1]['requestBytes'] = len(bad['vulnerableCalls'][1]['request'].encode())
        bad['vulnerableCalls'][1]['requestSha256'] = sha(bad['vulnerableCalls'][1]['request'])
        with self.assertRaisesRegex(RuntimeError, 'observation or repair'):
            self.valid(receipt, bad)


if __name__ == '__main__':
    unittest.main()
