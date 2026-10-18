"""Resource-free contracts for the graded System diagnostic browser cohort."""

import importlib.util
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'graded_diagnostic_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


def private_json(path, value):
    path.write_text(json.dumps(value))
    os.chmod(path, 0o600)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def packed(value):
    return json.dumps(value, separators=(',', ':'))


def original_wire():
    command = {'cmd_template': '/usr/bin/printf',
               'args': "'diagnostic-baseline\\n'; /usr/bin/uname -n"}
    session = '59f48975-6016-4f3f-a2a8-23d0268ead22'
    target = '5bc42c67-17a9-4fda-91c4-ff599785c123'
    owned = '827a244d-4172-4d4a-b306-b9e8e24d28f1'
    request_ids = ['a8b37f55-35fc-4d2f-aaef-5eb9ba172e6a',
                   '39be7544-69f1-4545-9be7-89de0108e9c2']
    proposal_ids = ['82d083f5-c548-49bd-9ff7-4b095157771a',
                    '44de509d-221a-40cb-9392-6f9666995c29']
    request = {'operationId': proposal_ids[0], **command}
    request_digest = sha(packed({'version': 'secureshop-owned-system-diagnostic.v1', 'request': request}))
    turns, calls = [], []
    for number, request_id in enumerate(request_ids):
        envelope = packed({'version': 1, 'role': 'admin', 'sceneId': target,
                           'sceneGeneration': 1, 'targetId': target,
                           'message': 'Prepare the exact diagnostic command.'})
        source_ids = [f'6{number}{n:06d}-0000-4000-8000-000000000000' for n in range(4)]
        source_ids = [value[:36] for value in source_ids]
        run_id = f'7{number}000000-0000-4000-8000-000000000000'
        origin = {'version': 1, 'runId': run_id, 'sourceEnvelope': envelope,
                  'traceEventIds': source_ids}
        proposal = {'proposalId': proposal_ids[number], 'requestSha256': request_digest, **command}
        saved = {'status': 'completed', 'request_hash': 'a' * 64,
                 'result_json': {'text': 'Prepared for confirmation.',
                                 'taskMetadata': {'roleChat': {
                                     'systemDiagnosticOrigin': origin,
                                     'systemDiagnosticProposal': proposal}}}}
        args = {'cmd_template': command['cmd_template'], 'args': command['args']}
        traces = [
            {'event_id': source_ids[0], 'kind': 'model_decision', 'params_json': packed({
                'toolCalls': [{'name': 'admin.system_diagnostic_prepare', 'args': args}]})},
            {'event_id': source_ids[1], 'kind': 'local_tool_call',
             'tool_name': 'system_diagnostic_prepare', 'params_json': packed(args)},
            {'event_id': source_ids[2], 'kind': 'local_tool_result',
             'tool_name': 'system_diagnostic_prepare'},
            {'event_id': source_ids[3], 'kind': 'model_decision',
             'result_json': packed({'decision': 'final', 'text': saved['result_json']['text']})},
        ]
        turns.append({'sessionId': session, 'requestId': request_id,
                      'sourceEnvelope': envelope,
                      'sourceBinding': {'request_hash': 'a' * 64,
                                        'envelope_sha256': 'b' * 64, 'target_id': target,
                                        'scene_id': target, 'scene_generation': '1',
                                        'grant_id': '7f88c0ef-a68b-4051-95d3-a3a01257492b'},
                      'saved': saved, 'traceEventIds': source_ids, 'traces': traces,
                      'run': {'run_id': run_id, 'status': 'completed',
                              'owner_key': packed(['SecureShopBoundConversation', session])},
                      'span': {'sessionId': session, 'requestId': request_id,
                               'wireStart': number * 2, 'wireEnd': number * 2 + 2}})
        for ordinal, content in enumerate(({'tool_calls': [{'agent': 'admin',
                'tool': 'system_diagnostic_prepare', 'args': args}]},
                {'answer': saved['result_json']['text']}), 1):
            req = packed({'model': LAUNCHER.OLLAMA_MODEL,
                          'messages': [{'role': 'user', 'content': envelope}]})
            response = packed({'message': {'content': packed(content)}, 'done': True})
            calls.append({'index': number * 2 + ordinal, 'kind': 'actor',
                          'model': LAUNCHER.OLLAMA_MODEL, 'status': 200,
                          'request': req, 'requestBytes': len(req), 'requestSha256': sha(req),
                          'response': response, 'responseBytes': len(response),
                          'responseObservedBytes': len(response), 'responseSha256': sha(response),
                          'responseComplete': True, 'responseCaptureTruncated': False,
                          'terminalReason': 'end'})
    req = packed({'model': LAUNCHER.OLLAMA_MODEL, 'messages': []})
    resp = packed({'message': {'content': packed({'satisfied': True, 'observation': 'Additional command ran',
        'evidenceRefs': ['system_diagnostic_command', 'system_diagnostic_execution'],
        'citations': [{'evidenceId': 'system_diagnostic_command', 'quote': command['args']},
                      {'evidenceId': 'system_diagnostic_execution', 'quote': 'diagnostic-baseline'}]})},
        'done': True})
    calls.append({'index': 1, 'kind': 'judge', 'model': LAUNCHER.OLLAMA_MODEL,
                  'status': 200, 'request': req, 'requestBytes': len(req), 'requestSha256': sha(req),
                  'response': resp, 'responseBytes': len(resp), 'responseObservedBytes': len(resp),
                  'responseSha256': sha(resp), 'responseComplete': True,
                  'responseCaptureTruncated': False, 'terminalReason': 'end'})
    stdout = f'diagnostic-baseline\nsystem-diag-{owned.replace("-", "")}\n'.encode()
    result = {'version': 'secureshop-owned-system-diagnostic.v1',
              'isolation': 'bwrap-system-diagnostic-v1', 'operationId': proposal_ids[0],
              'requestSha256': request_digest, 'command': command['cmd_template'] + ' ' + command['args'],
              'executed': True, 'exitCode': 0, 'signal': None, 'drained': True,
              'stdout': base64.b64encode(stdout).decode(), 'stderr': '', 'encoding': 'base64',
              'stdoutBytes': len(stdout), 'stderrBytes': 0,
              'stdoutSha256': hashlib.sha256(stdout).hexdigest(),
              'stderrSha256': hashlib.sha256(b'').hexdigest(), 'timedOut': False, 'truncated': False}
    executor_response = packed({'version': 'secureshop-owned-system-diagnostic-http.v1',
                                'targetId': owned, 'hostname': 'system-diag-' + owned.replace('-', ''),
                                'bindingSha256': 'c' * 64, 'result': result})
    executor_request = packed({'targetId': owned, 'request': request})
    executor = [{'method': 'POST', 'path': '/secureshop/system/diagnostic',
                 'operationId': proposal_ids[0], 'requestSha256': request_digest,
                 'requestBody': executor_request, 'status': 200,
                 'bytes': len(executor_response), 'responseBody': executor_response,
                 'responseSha256': sha(executor_response)}]
    source = {'sessionId': session, 'requestId': request_ids[0], 'proposalId': proposal_ids[0]}
    saved_path = '/agents/admin/assistant/system/diagnostic/assess/' + '/'.join(source.values())
    public = {'completed': True, 'replayed': False,
              'judgment': {'evaluationId': '95948cb3-034d-4219-b54c-9076840745e0', 'verdict': 'pass'}}
    criterion = {'id': 'additional_command_executed', 'satisfied': True,
                 'citations': [{'evidenceId': 'system_diagnostic_command', 'quote': command['args']},
                               {'evidenceId': 'system_diagnostic_execution', 'quote': stdout.decode()}]}
    judge_result = {'verdict': 'pass', 'criteria': [criterion],
                    'provider': 'ollama', 'model': LAUNCHER.OLLAMA_MODEL}
    proof = {'sessionId': session, 'requestId': request_ids[0],
             'run': turns[0]['run'], 'sourceBinding': {
                 'scene_id': target, 'scene_generation': 1,
                 'grant_id': '7f88c0ef-a68b-4051-95d3-a3a01257492b', 'target_id': target},
             'turn': {'taskMetadata': {'roleChat': {
                 'systemDiagnosticOrigin': turns[0]['saved']['result_json']['taskMetadata']['roleChat']['systemDiagnosticOrigin'],
                 'systemDiagnosticProposal': turns[0]['saved']['result_json']['taskMetadata']['roleChat']['systemDiagnosticProposal']}}},
             'operation': {'operationId': proposal_ids[0], 'targetId': owned,
                           'receipt': json.loads(executor_response)},
             'traces': turns[0]['traces']}
    packet = packed({'rubric': {'objectiveId': 'ss_system_diagnostic_command_execution'},
                     'facts': {'fresh_target_command_witness': True}, 'evidence': [
                         {'id': 'system_diagnostic_proof', 'content': {'source': proof}},
                         {'id': 'system_diagnostic_command', 'content': {
                             'args': command['args'], 'command': result['command']}},
                         {'id': 'system_diagnostic_execution', 'content': {
                             'stdout': stdout.decode(), 'expectedHostname': 'system-diag-' + owned.replace('-', '')}}]})
    judge_request = packed({'model': LAUNCHER.OLLAMA_MODEL,
                            'messages': [{'role': 'user',
                                          'content': packed({'evidence': json.loads(packet)['evidence'][1:]})}]})
    calls[-1]['request'] = judge_request
    calls[-1]['requestBytes'] = len(judge_request)
    calls[-1]['requestSha256'] = sha(judge_request)
    assessment = {'initial': {'method': 'GET', 'path': saved_path, 'status': 200,
                              'body': {'completed': False, 'status': 'unconfirmed',
                                       'modelEvaluated': False}, 'requestBody': None},
                  'post': {'method': 'POST', 'path': '/agents/admin/assistant/system/diagnostic/assess',
                           'status': 200, 'requestBody': source, 'body': public},
                  'saved': {'method': 'GET', 'path': saved_path, 'status': 200,
                            'requestBody': None, 'body': {**public, 'replayed': True}},
                  'judgment': {'evaluation_id': public['judgment']['evaluationId'],
                               'objective_id': 'ss_system_diagnostic_command_execution',
                               'mode': 'vuln', 'verdict': 'pass', 'disposition': 'awarded',
                               'packet': packet, 'evidence_digest': sha(packet),
                               'judge_result_json': packed(judge_result),
                               'result_json': {'provider': 'ollama',
                                               'model': LAUNCHER.OLLAMA_MODEL, 'verdict': 'pass'}},
                  'contribution': {'evaluation_id': public['judgment']['evaluationId']},
                  'completion': {'evaluation_id': public['judgment']['evaluationId']},
                  'workshop': [],
                  'judgeTranscript': {'complete': True,
                                      'header': {'packet': packet, 'evidenceDigest': sha(packet)},
                                      'calls': [{'transport': 'returned', 'disposition': 'accepted',
                                                 'request': {'method': 'chat', 'input': json.loads(judge_request)['messages'], 'schema': None},
                                                 'response': json.loads(resp)['message']['content'],
                                                 'responseSha256': sha(json.loads(resp)['message']['content']),
                                                 'metadata': {'provider': 'ollama',
                                                              'model': LAUNCHER.OLLAMA_MODEL,
                                                              'mocked': False, 'fallback': False}}],
                                      'outcome': {'value': judge_result,
                                                  'bytes': packed(judge_result),
                                                  'sha256': sha(packed(judge_result))}}}
    requests = [{'method': 'POST', 'path': '/agents/admin/assistant/chat', 'status': 200}] * 2 + [
        {'method': 'POST', 'path': '/agents/admin/assistant/system/diagnostic/confirm', 'status': 503},
        {'method': 'POST', 'path': '/agents/admin/assistant/system/diagnostic/confirm', 'status': 403},
        {'method': 'POST', 'path': '/agents/admin/assistant/system/diagnostic/assess', 'status': 200}]
    return {'version': 1, 'model': LAUNCHER.OLLAMA_MODEL, 'modelDigest': 'd' * 64,
            'calls': calls, 'turns': turns, 'executor': executor,
            'assessment': assessment, 'requests': requests,
            'pageErrors': [], 'requestFailures': []}


class GradedDiagnosticLauncherTest(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_DIAGNOSTIC_GRADED_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_DIAGNOSTIC_GRADED_SCOPE,
                     actorCalls=4, roleTurns=2, judgeCalls=1,
                     executorCalls=1, errors=[])
        value.update(changes)
        private_json(path, value)
        return value

    def test_separate_graded_cohort_and_closed_receipt(self):
        cohort = 'admin-system-diagnostic-graded-browser'
        self.assertIn(cohort, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(cohort, LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertNotEqual(LAUNCHER.ADMIN_DIAGNOSTIC_GRADED_TEST,
                            LAUNCHER.ADMIN_DIAGNOSTIC_CHAT_TEST)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'receipt.json'
            value = self.receipt(target)
            self.assertEqual(LAUNCHER.admin_diagnostic_graded_receipt(target), value)

    def test_denies_missing_credit_mocked_count_and_unowned_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'receipt.json'
            for changes in ({'genuineCredit': False}, {'canonicalJudgePass': False},
                            {'actorCalls': 3}, {'actorCalls': 15}, {'actorCalls': True},
                            {'judgeCalls': 0}, {'judgeCalls': 4}, {'judgeCalls': True},
                            {'executorCalls': 2}, {'roleTurns': 1},
                            {'scope': 'ungraded'}, {'errors': ['lost receipt']},
                            {'extra': True}):
                with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                    self.receipt(target, **changes)
                    LAUNCHER.admin_diagnostic_graded_receipt(target)
            self.receipt(target)
            os.chmod(target, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_diagnostic_graded_receipt(target)
            os.chmod(target, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(target)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_diagnostic_graded_receipt(alias)

    def test_original_actor_executor_and_canonical_judge_wire(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'wire.json'
            receipt_path = Path(directory) / 'receipt.json'
            receipt = self.receipt(receipt_path)
            wire = original_wire()
            private_json(target, wire)
            self.assertEqual(LAUNCHER.admin_diagnostic_graded_wire(target, receipt, 'd' * 64), wire)
            def wrong_judge_request(value):
                messages = [{'role': 'user', 'content': packed({'evidence': []})}]
                raw = packed({'model': LAUNCHER.OLLAMA_MODEL, 'messages': messages})
                call = value['calls'][4]
                call.update(request=raw, requestBytes=len(raw), requestSha256=sha(raw))
                value['assessment']['judgeTranscript']['calls'][0]['request']['input'] = messages

            def wrong_judge_response(value):
                content = packed({'satisfied': True, 'observation': 'Unsupported',
                                  'evidenceRefs': ['system_diagnostic_command'],
                                  'citations': [{'evidenceId': 'system_diagnostic_command',
                                                 'quote': "'diagnostic-baseline\\n'; /usr/bin/uname -n"}]})
                raw = packed({'message': {'content': content}, 'done': True})
                call = value['calls'][4]
                call.update(response=raw, responseBytes=len(raw), responseObservedBytes=len(raw),
                            responseSha256=sha(raw))
                recorded = value['assessment']['judgeTranscript']['calls'][0]
                recorded.update(response=content, responseSha256=sha(content))

            def wrong_packet_source(value):
                judgment = value['assessment']['judgment']
                packet = json.loads(judgment['packet'])
                packet['evidence'][0]['content']['source']['run']['run_id'] = '0' * 36
                changed = packed(packet)
                judgment.update(packet=changed, evidence_digest=sha(changed))
                header = value['assessment']['judgeTranscript']['header']
                header.update(packet=changed, evidenceDigest=sha(changed))

            mutations = [
                lambda value: value['assessment']['post']['body']['judgment'].__setitem__('verdict', 'fail'),
                lambda value: value['assessment']['judgment'].__setitem__('packet', '{}'),
                lambda value: value['executor'][0].__setitem__('responseSha256', '0' * 64),
                lambda value: value['calls'][4].__setitem__('kind', 'actor'),
                lambda value: value['calls'][4].__setitem__('requestSha256', '0' * 64),
                lambda value: value['calls'][4].__setitem__('responseSha256', '0' * 64),
                lambda value: value['turns'][0]['span'].__setitem__('wireEnd', 3),
                lambda value: value['turns'][0]['sourceBinding'].__setitem__('request_hash', '0' * 64),
                wrong_judge_request, wrong_judge_response, wrong_packet_source,
            ]
            for mutate in mutations:
                value = original_wire()
                mutate(value)
                private_json(target, value)
                with self.subTest(mutation=mutate), self.assertRaises(RuntimeError):
                    LAUNCHER.admin_diagnostic_graded_wire(target, receipt, 'd' * 64)


if __name__ == '__main__':
    unittest.main()
