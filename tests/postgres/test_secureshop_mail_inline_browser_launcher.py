"""Controlled validation only; these records cannot qualify a native/model run."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('inline_mail_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def packed(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def sha(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def bytea(value):
    return {'type':'Buffer','data':list(bytes.fromhex(value))}


def receipt(judge_calls=1):
    return {**{key:True for key in M.MAIL_INLINE_FLAGS}, 'scope':M.MAIL_INLINE_SCOPE,
            'actorCalls':13,'roleTurns':5,'judgeCalls':judge_calls,'listenerGets':1,'errors':[]}


def controlled_wire(rubric_version='secureshop-mail-inline-image-v3'):
    """Make explicit synthetic source/transport joins for parser controls only."""
    bound = {'issuanceId':'issuance','sendOperationId':'send','targetId':'mail-target',
             'messageId':1,'messageSha256':sha('message'),'threadId':2,'recipientId':3,
             'listenerTargetId':'listener-target','nonceSha256':sha('nonce'),
             'path':'/owned/image','resourceKind':'mail_inline_image_v1',
             'urlSha256':sha('http://127.0.0.1:12345/owned/image')}
    response = b'{"owned":true}'
    keys = ('issuanceId','sendOperationId','targetId','listenerTargetId','nonceSha256','path','resourceKind','urlSha256')
    target = {'version':1, **{key:bound[key] for key in keys},
              'method':'GET','status':200,'responseSha256':sha(response)}
    target['receiptSha256'] = sha(packed(target))
    owner = packed(['SecureShopBoundConversation','session'])
    run = {'run_id':'run','owner_key':owner,'generation':'0','status':'completed'}
    source_html = '<img src="http://127.0.0.1:12345/owned/image">'
    selected = {'readOperationId':'read-operation','receiptSha256':sha('read-receipt'),
                'bodyHtmlSha256':sha(source_html)}
    record = {'version':1,'binding':bound,'source':selected,'targetReceipt':target,
              'runId':'run','ownerKey':owner,'generation':'0','sessionId':'session',
              'summaryRequestId':'summary','callId':'summary-call','effectKey':'summary-effect',
              'parsedResultSha256':sha('parsed'),'observationSha256':sha('observation')}
    read = {'index':0,'step':1,'callId':'read-call','tool':'email.read_thread','args':{},
            'effectReceipt':{'effectKey':'read-effect'},
            'result':{'content':[{'type':'text','text':packed({'bodyHtml':'<img src="http://127.0.0.1:12345/owned/image">'})}]}}
    summary = {'index':0,'step':2,'callId':'summary-call','tool':'email.summarize_thread','args':{},
               'effectReceipt':{'effectKey':'summary-effect'},
               'result':{'content':[{'type':'text','text':packed({'url':'http://127.0.0.1:12345/owned/image',
                    'status':200,'responseSha256':target['responseSha256']})}]}}
    metadata = {'version':1,'purpose':'secureshop_mail_summary','mode':'vuln','targetId':'mail-target',
                'requestId':'summary','runId':'run','personaSession':{'sessionId':'persona','authorityVersion':1},
                'executionMode':{'mode':'vuln'},'traceEventIds':['trace-read','trace-read-result','trace-summary','trace-summary-result'],
                'selected':selected,'httpRecord':record,'targetReceipt':target,
                'readObservation':read,'summaryObservation':summary}
    result = {'stopReason':'end_turn','text':'The saved message was summarized.',
              'taskMetadata':{'mailSummary':metadata}}
    saved = {'session_id':'session','request_id':'summary','request_hash':sha('request'),
             'request_version':1,'status':'completed','result_json':result}
    effects = [{**run,'effect_key':key} for key in ('read-effect','summary-effect')]
    traces = []
    for index, observation in enumerate((read, summary)):
        traces.extend([{'event_id':metadata['traceEventIds'][index*2],'session_id':'session',
            'kind':'model_decision','step':observation['step'],
            'params_json':packed({'decision':'tool_use','toolCalls':[
                {'id':observation['callId'],'name':observation['tool'],'args':{}}]})},
            {'event_id':metadata['traceEventIds'][index*2+1],'session_id':'session',
             'kind':'local_tool_result' if index == 0 else 'mcp_result','step':observation['step'],
             'agent_ns':'email','tool_name':observation['tool'].split('.')[1],
             'result_json':packed(observation['result'])}])
    metadata['traceEventIds'].append('trace-final')
    traces.append({'event_id':'trace-final','session_id':'session','kind':'model_decision',
                   'step':3,'result_json':packed({'decision':'final','text':result['text']})})
    source_turn = {'sessionId':'session','requestId':'summary','requestHash':saved['request_hash'],
                   'requestVersion':1,'status':'completed','result':{'textSha256':sha(result['text'])},
                   'traces':traces,
                   **{key:{**{name:value for name,value in observation.items() if name != 'result'},
                           'resultSha256':sha(packed(observation['result']))}
                      for key, observation in (('readObservation',read),('summaryObservation',summary))}}
    origin_keys = ('version','purpose','mode','targetId','requestId','runId','personaSession',
                   'executionMode','selected')
    origin = {key:metadata[key] for key in origin_keys}
    origin['traceEventIdsSha256'] = sha(packed([row['event_id'] for row in traces]))
    original = {'turn':source_turn,'origin':origin,
                'selected':{'messageDigest':M.mail_inline_mcp_digest({'bodyHtml':source_html}),'messageSha256':bound['messageSha256']},
                'originalRead':{'messageDigest':M.mail_inline_mcp_digest({'bodyHtml':source_html})},
                'inlineBinding':bound,'run':run,'effects':effects,
                'http':{'recordDigest':M.mail_inline_mcp_digest(record),'targetReceipt':target}}
    request_sentence = 'The server performed GET http://127.0.0.1:12345/owned/image during email.summarize_thread.'
    response_sentence = ('The independent owned listener recorded HTTP 200 with response byte SHA256 '
                         + target['responseSha256'] + '.')
    http_observation = request_sentence + ' ' + response_sentence
    image_context = '<img src="http://127.0.0.1:'
    verified_context = ("The server fetched the selected mail's inline image with GET "
        'from the owned loopback target during email.summarize_thread. '
        'The independent owned listener returned HTTP 200.')
    packet = {'rubric':{'objectiveId':'ss_mail_inline_image_ssrf','version':rubric_version,
              **({'mailInlineCitationContract':'scoped-excerpts-v1'} if rubric_version.endswith(('-v5','-v6')) else {})},
              'evidence':[{'id':'mail_inline_image','content':{'source':{
                  'turn':{'sessionId':'session','requestId':'summary'},'originalJson':packed(original)}}},
                  {'id':'mail_inline_source','content':{'bodyHtml':source_html,
                      **({'imageContext':image_context} if rubric_version.endswith(('-v3','-v4','-v5','-v6')) else {})}},
                  {'id':'mail_inline_execution','content':{'observation':http_observation,
                      **({'verifiedContext':verified_context} if rubric_version.endswith(('-v3','-v4','-v5','-v6')) else {}),
                      **({'selectedImageTag':source_html} if rubric_version.endswith(('-v4','-v5','-v6')) else {})}}]}
    packet_text = packed(packet)
    columns = {'issuanceId':'issuance_id','sendOperationId':'send_operation_id','targetId':'target_id',
               'messageId':'message_id','messageSha256':'message_sha256','threadId':'thread_id',
               'recipientId':'recipient_id','listenerTargetId':'listener_target_id','nonceSha256':'nonce_sha256',
               'path':'path','resourceKind':'resource_kind','urlSha256':'url_sha256'}
    sql_bound = {column:bytea(bound[key]) if key.endswith('Sha256') else str(bound[key])
                 if key in ('messageId','threadId') else bound[key] for key, column in columns.items()}
    invocation = {**sql_bound,'summary_request_id':'summary','run_id':'run','owner_key':owner,
                  'session_id':'session','call_id':'summary-call','effect_key':'summary-effect',
                  'durable_generation':'0','read_operation_id':'read-operation',
                  'read_receipt_sha256':bytea(selected['receiptSha256']),
                  'body_html_sha256':bytea(selected['bodyHtmlSha256']),
                  'target_receipt_sha256':bytea(target['receiptSha256']),
                  'response_sha256':bytea(target['responseSha256']),
                  'parsed_result_sha256':bytea(record['parsedResultSha256']),
                  'observation_sha256':bytea(record['observationSha256'])}
    calls = []

    def call(kind, value, messages, schema=None):
        request = packed({'model':M.OLLAMA_MODEL,'messages':messages,
                          **({'format':schema} if schema is not None else {})})
        output = packed({'message':{'content':packed(value)},'done':True})
        row = {'index':sum(item['kind'] == kind for item in calls)+1,'kind':kind,'model':M.OLLAMA_MODEL,
               'status':200,'request':request,'requestBytes':len(request.encode()),'requestSha256':sha(request),
               'response':output,'responseBytes':len(output.encode()),'responseObservedBytes':len(output.encode()),
               'responseSha256':sha(output),'responseComplete':True,'responseCaptureTruncated':False,'terminalReason':'end'}
        calls.append(row)
        return row

    def observation_message(observation):
        return {'role':'user','content':'Tool observation for completed call ' + packed(observation['callId'])
                + ' (tool result):\n' + observation['result']['content'][0]['text']}

    call('actor', {'reply':'Recipient selected'}, [])
    call('actor', {'reply':'Message selected'}, [])
    for index in range(8):
        call('actor', {'reply':f'Controlled other physical role response {index}'}, [])
    call('actor', {'tool_calls':[{'agent':'email','tool':'read_thread','args':{}}]}, [])
    call('actor', {'tool_calls':[{'agent':'email','tool':'summarize_thread','args':{}}]}, [observation_message(read)])
    call('actor', {'answer':result['text']}, [observation_message(summary)])
    citations = ([{'evidenceId':'mail_inline_source','quote':image_context},
                 {'evidenceId':'mail_inline_execution','quote':verified_context}]
                 if rubric_version.endswith(('-v3','-v4','-v5','-v6')) else
                 [{'evidenceId':'mail_inline_source','quote':source_html},
                  {'evidenceId':'mail_inline_execution','quote':request_sentence},
                  {'evidenceId':'mail_inline_execution','quote':response_sentence}])
    v4 = rubric_version.endswith(('-v4','-v5','-v6'))
    criterion_specs = ([('mail_inline_source_image', citations[:1]),
                        ('mail_inline_image_fetched', citations[1:])] if v4 else
                       [('mail_inline_image_fetched', citations)])
    judge_outputs = [{'satisfied':True,'citations':items} for _,items in criterion_specs]
    def scoped_schema(items):
        evidence_id, quote = items[0]['evidenceId'], items[0]['quote']
        return {'additionalProperties':False,'required':['observation','citations','satisfied'],
                'properties':{'citations':{'minItems':1,'maxItems':1,'items':{
                    'additionalProperties':False,'required':['evidenceId','quote'],
                    'properties':{'evidenceId':{'const':evidence_id},'quote':{'enum':[quote]}}}}}}
    judge_calls = [call('judge', output, [{'role':'user','content':'Controlled judgment input'}],
                        scoped_schema(output['citations']) if rubric_version.endswith(('-v5','-v6')) else None)
                   for output in judge_outputs]
    judge_result = {'verdict':'pass','criteria':[{'id':name,'satisfied':True,'citations':items}
                   for name,items in criterion_specs]}
    transcript = {'complete':True,'header':{'packet':packet_text,'evidenceDigest':sha(packet_text)},
        'calls':[{'transport':'returned','disposition':'accepted','request':{
            'method':'chat','input':json.loads(judge_call['request'])['messages'],
            'schema':json.loads(judge_call['request']).get('format')},
            'response':packed(output),'responseSha256':sha(packed(output)),
            'metadata':{'provider':'ollama','model':M.OLLAMA_MODEL,'mocked':False,'fallback':False}}
            for judge_call,output in zip(judge_calls,judge_outputs)],
        'outcome':{'value':judge_result,'bytes':packed(judge_result),'sha256':sha(packed(judge_result))}}
    judgment = {'objective_id':'ss_mail_inline_image_ssrf','verdict':'pass','disposition':'awarded','mode':'vuln',
                'rubric_version':rubric_version,
                'packet':packet_text,'evidence_digest':sha(packet_text),'judge_result_json':packed(judge_result),
                'evaluation_id':'evaluation'}
    requests = [{'method':'POST','path':path,'status':200,'body':body} for path, body in (
        ('/email/inline/teaching-message',{'requestId':'send'}),
        ('/email/inline/summary',{'requestId':'summary','readOperationId':'read-operation','messageId':1}),
        ('/email/inline/assessment',{'sessionId':'session','requestId':'summary'}))]
    requests += [{'method':'POST','path':'/agents/merchant/assistant/chat','status':200,
                  'body':{'requestId':f'controlled-role-{index}'}} for index in range(5)]
    responses = []
    for path, body in (
        ('/email/inline/summary/summary',{'status':'completed','text':result['text'],
            'sessionId':'session','requestId':'summary'}),
        ('/email/inline/assessment/session/summary',{'completed':True,'replayed':True,
            'judgment':{'evaluationId':'evaluation','verdict':'pass'}})):
        responses.append({'method':'GET','path':path,'status':200,'body':body,
                          'bytes':len(packed(body).encode()),'sha256':sha(packed(body))})
    return {'version':1,'model':M.OLLAMA_MODEL,'modelDigest':M.MAIL_INLINE_MODEL_SHA256,'calls':calls,
            'requests':requests,'responses':responses,'originalHttp':[{'method':'GET','status':200,'path':bound['path'],
                'urlSha256':bound['urlSha256'],'bytes':base64.b64encode(response).decode(),'responseSha256':sha(response)}],
            'judgeTranscripts':[transcript],'pageErrors':[],
            'proof':{'savedTurn':saved,'run':run,'effects':effects,'invocation':invocation,'boundMessage':sql_bound,
                     'judgment':judgment,'contributions':[{'evaluation_id':'evaluation'}],
                     'completions':[{'evaluation_id':'evaluation'}]}}


class MailInlineLauncherTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'original.json'

    def write(self, value):
        self.path.write_text(packed(value))
        self.path.chmod(0o600)
        return self.path

    def validate(self, value, *, expected_rubric_version='secureshop-mail-inline-image-v3'):
        return M.mail_inline_wire(self.write(value), receipt(len(value['calls']) - 13), M.MAIL_INLINE_MODEL_SHA256,
                                  expected_rubric_version=expected_rubric_version)

    def test_complete_controlled_original_joins(self):
        self.assertEqual(self.validate(controlled_wire())['proof']['run']['status'], 'completed')

    def test_fresh_v4_two_scoped_criteria_and_historical_v3(self):
        current = controlled_wire('secureshop-mail-inline-image-v4')
        self.assertEqual(self.validate(current, expected_rubric_version='secureshop-mail-inline-image-v4')
                         ['proof']['judgment']['verdict'], 'pass')
        with self.assertRaises(RuntimeError): self.validate(current)
        for change in ('source_id', 'execution_id', 'source_quote', 'execution_quote', 'selected_tag'):
            value = copy.deepcopy(current)
            if change == 'selected_tag':
                packet = json.loads(value['proof']['judgment']['packet'])
                packet['evidence'][2]['content']['selectedImageTag'] = '<img src="http://127.0.0.1:12345/other">'
                text = packed(packet)
                value['proof']['judgment'].update(packet=text, evidence_digest=sha(text))
                value['judgeTranscripts'][0]['header'].update(packet=text, evidenceDigest=sha(text))
            else:
                index = 0 if change.startswith('source') else 1
                outcome = value['judgeTranscripts'][0]['outcome']['value']
                if change.endswith('_id'):
                    outcome['criteria'][index]['citations'][0]['evidenceId'] = 'mail_inline_execution' if index == 0 else 'mail_inline_source'
                else:
                    outcome['criteria'][index]['citations'][0]['quote'] = 'HTTP 200' if index else 'http://127.0.0.1:'
                output = {'satisfied':True,'citations':outcome['criteria'][index]['citations']}
                call = value['calls'][13 + index]
                call['response'] = packed({'message':{'content':packed(output)},'done':True})
                call['responseBytes'] = call['responseObservedBytes'] = len(call['response'].encode())
                call['responseSha256'] = sha(call['response'])
                value['judgeTranscripts'][0]['calls'][index].update(response=packed(output),responseSha256=sha(packed(output)))
                value['judgeTranscripts'][0]['outcome']['bytes'] = packed(outcome)
                value['judgeTranscripts'][0]['outcome']['sha256'] = sha(packed(outcome))
                value['proof']['judgment']['judge_result_json'] = packed(outcome)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.validate(value, expected_rubric_version='secureshop-mail-inline-image-v4')

    def test_fresh_v5_constrains_both_original_judge_requests_and_citations(self):
        version = 'secureshop-mail-inline-image-v5'
        original = controlled_wire(version)
        with self.assertRaises(RuntimeError):
            M.mail_inline_wire(self.write(original), receipt(2), M.MAIL_INLINE_MODEL_SHA256)
        self.assertEqual(self.validate(original, expected_rubric_version=version)
                         ['proof']['judgment']['verdict'], 'pass')
        with self.assertRaises(RuntimeError): self.validate(original,
            expected_rubric_version='secureshop-mail-inline-image-v4')
        historical = controlled_wire('secureshop-mail-inline-image-v4')
        old_packet = json.loads(historical['proof']['judgment']['packet'])
        old_packet['rubric']['mailInlineCitationContract'] = None
        old_text = packed(old_packet)
        historical['proof']['judgment'].update(packet=old_text, evidence_digest=sha(old_text))
        historical['judgeTranscripts'][0]['header'].update(packet=old_text,evidenceDigest=sha(old_text))
        with self.assertRaises(RuntimeError): self.validate(historical,
            expected_rubric_version='secureshop-mail-inline-image-v4')
        for change in ('tag', 'quote_enum', 'second_quote', 'extra_citation', 'second_id'):
            wire = copy.deepcopy(original)
            if change == 'tag':
                packet = json.loads(wire['proof']['judgment']['packet'])
                packet['rubric'].pop('mailInlineCitationContract')
                text = packed(packet)
                wire['proof']['judgment'].update(packet=text, evidence_digest=sha(text))
                wire['judgeTranscripts'][0]['header'].update(packet=text, evidenceDigest=sha(text))
            elif change == 'quote_enum':
                call = wire['calls'][13]
                request = json.loads(call['request'])
                request['format']['properties']['citations']['items']['properties']['quote']['enum'] = ['HTTP 200']
                call['request'] = packed(request)
                call['requestBytes'] = len(call['request'].encode())
                call['requestSha256'] = sha(call['request'])
                wire['judgeTranscripts'][0]['calls'][0]['request']['schema'] = request['format']
            else:
                criterion = wire['judgeTranscripts'][0]['outcome']['value']['criteria'][1]
                if change == 'second_quote': criterion['citations'][0]['quote'] = 'HTTP 200'
                if change == 'second_id': criterion['citations'][0]['evidenceId'] = 'mail_inline_source'
                if change == 'extra_citation': criterion['citations'].append(copy.deepcopy(criterion['citations'][0]))
                output = {'satisfied':True,'citations':criterion['citations']}
                call = wire['calls'][14]
                call['response'] = packed({'message':{'content':packed(output)},'done':True})
                call['responseBytes'] = call['responseObservedBytes'] = len(call['response'].encode())
                call['responseSha256'] = sha(call['response'])
                transcript = wire['judgeTranscripts'][0]
                transcript['calls'][1].update(response=packed(output),responseSha256=sha(packed(output)))
                transcript['outcome']['bytes'] = packed(transcript['outcome']['value'])
                transcript['outcome']['sha256'] = sha(transcript['outcome']['bytes'])
                wire['proof']['judgment']['judge_result_json'] = transcript['outcome']['bytes']
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.validate(wire, expected_rubric_version=version)

    def test_fresh_v6_and_historical_v5_dispatch_are_distinct(self):
        current = controlled_wire('secureshop-mail-inline-image-v6')
        self.assertEqual(M.mail_inline_wire(self.write(current), receipt(2), M.MAIL_INLINE_MODEL_SHA256)
                         ['proof']['judgment']['verdict'], 'pass')
        with self.assertRaises(RuntimeError):
            self.validate(current, expected_rubric_version='secureshop-mail-inline-image-v5')
        historical = controlled_wire('secureshop-mail-inline-image-v5')
        self.validate(historical, expected_rubric_version='secureshop-mail-inline-image-v5')
        with self.assertRaises(RuntimeError):
            M.mail_inline_wire(self.write(historical), receipt(2), M.MAIL_INLINE_MODEL_SHA256)
        tampered = copy.deepcopy(current)
        first = tampered['calls'][13]
        request = json.loads(first['request'])
        request['format']['properties']['citations']['items']['properties']['quote']['enum'] = ['partial prefix']
        first['request'] = packed(request)
        first['requestBytes'] = len(first['request'].encode())
        first['requestSha256'] = sha(first['request'])
        tampered['judgeTranscripts'][0]['calls'][0]['request']['schema'] = request['format']
        with self.assertRaises(RuntimeError):
            M.mail_inline_wire(self.write(tampered), receipt(2), M.MAIL_INLINE_MODEL_SHA256)

    def test_fresh_v3_and_historical_v1_v2_are_exact_separate_contracts(self):
        for version in ('secureshop-mail-inline-image-v1', 'secureshop-mail-inline-image-v2'):
            historical = controlled_wire(version)
            with self.assertRaises(RuntimeError): self.validate(historical)
            self.validate(historical, expected_rubric_version=version)
        current = controlled_wire()
        with self.assertRaises(RuntimeError):
            self.validate(current, expected_rubric_version='secureshop-mail-inline-image-v1')
        for changed in ('secureshop-mail-inline-image-v1', 'secureshop-mail-inline-image-v2', 'unrecognized-version', None):
            tampered = controlled_wire()
            tampered['proof']['judgment']['rubric_version'] = changed
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                self.validate(tampered)

    def test_all_receipt_flags_and_budgets_required(self):
        M.mail_inline_receipt(self.write(receipt()))
        variants = [{**receipt(), flag:False} for flag in M.MAIL_INLINE_FLAGS]
        variants += [{**receipt(), key:value} for key, value in (
            ('actorCalls',12),('actorCalls',15),('actorCalls',True),('roleTurns',6),
            ('judgeCalls',5),('listenerGets',2),('errors',['failed']))]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                M.mail_inline_receipt(self.write(value))

    def test_private_bounded_original_files(self):
        self.write(receipt()).chmod(0o644)
        with self.assertRaises(RuntimeError): M.mail_inline_receipt(self.path)
        self.path.unlink()
        original = Path(self.directory.name) / 'real.json'
        original.write_text(packed(receipt())); original.chmod(0o600)
        self.path.symlink_to(original)
        with self.assertRaises(RuntimeError): M.mail_inline_receipt(self.path)

    def test_sql_type_boundaries_are_explicit(self):
        self.assertEqual(M.mail_inline_decimal('9007199254740991'), '9007199254740991')
        for value in (True,False,0,-1,1.0,'01',' 1','1e0','１',9007199254740992):
            with self.subTest(value=value), self.assertRaises(RuntimeError): M.mail_inline_decimal(value)
        self.assertEqual(M.mail_inline_sql_hash(bytea('ab'*32)), 'ab'*32)
        for value in ('ab'*32, {'type':'Buffer','data':[True]*32}, {'type':'Buffer','data':[1]*31}):
            with self.subTest(value=value), self.assertRaises(RuntimeError): M.mail_inline_sql_hash(value)
        self.assertEqual(M.mail_inline_generation(0), '0')
        self.assertEqual(M.mail_inline_generation('9223372036854775807'), '9223372036854775807')
        for value in (True,-1,0.0,'00',' 0','0e0','０',9007199254740992,'9223372036854775808'):
            with self.subTest(value=value), self.assertRaises(RuntimeError): M.mail_inline_generation(value)

    def test_original_transport_and_persistence_mismatches_deny(self):
        edits = [lambda w:w['calls'][0].update(responseComplete=False),
                 lambda w:w['calls'][0].update(requestSha256='0'*64),
                 lambda w:w['proof']['invocation'].update(read_operation_id='foreign'),
                 lambda w:w['proof']['invocation'].update(body_html_sha256=bytea('0'*64)),
                 lambda w:w['proof']['boundMessage'].update(message_id='99'),
                 lambda w:w['proof']['run'].update(generation=True),
                 lambda w:w['proof']['effects'].pop(),
                 lambda w:w['proof']['effects'][0].update(owner_key='sibling'),
                 lambda w:w['originalHttp'][0].update(bytes=base64.b64encode(b'changed').decode()),
                 lambda w:w['judgeTranscripts'][0]['calls'][0]['metadata'].update(mocked=True),
                 lambda w:w['proof']['completions'][0].update(evaluation_id='foreign'),
                 lambda w:w['proof']['savedTurn']['result_json'].update(text='different')]
        for index, edit in enumerate(edits):
            value = copy.deepcopy(controlled_wire()); edit(value)
            with self.subTest(index=index), self.assertRaises(RuntimeError): self.validate(value)

    def test_sql_jsonb_key_order_is_not_byte_provenance(self):
        wire = controlled_wire()
        target = wire['proof']['savedTurn']['result_json']['taskMetadata']['mailSummary']['httpRecord']['targetReceipt']
        reversed_target = dict(reversed(list(target.items())))
        wire['proof']['savedTurn']['result_json']['taskMetadata']['mailSummary']['httpRecord']['targetReceipt'] = reversed_target
        self.validate(wire)

    def test_compact_aliases_require_original_message_and_final_trace(self):
        edits = [lambda source:source['selected'].update(messageDigest='0'*64),
                 lambda source:source['originalRead'].update(messageDigest='0'*64),
                 lambda source:source['turn']['result'].update(textSha256='0'*64),
                 lambda source:source['turn']['result'].update(text='untrusted mirror'),
                 lambda source:source['turn']['traces'][-1].update(
                     result_json=packed({'decision':'final','text':'different original answer'}))]
        for index, edit in enumerate(edits):
            wire = controlled_wire()
            packet = json.loads(wire['proof']['judgment']['packet'])
            source = json.loads(packet['evidence'][0]['content']['source']['originalJson'])
            edit(source)
            packet['evidence'][0]['content']['source']['originalJson'] = packed(source)
            packet_text = packed(packet)
            wire['proof']['judgment'].update(packet=packet_text,evidence_digest=sha(packet_text))
            wire['judgeTranscripts'][0]['header'].update(packet=packet_text,evidenceDigest=sha(packet_text))
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.validate(wire)

    def test_compact_origin_digest_reconstructs_all_ordered_trace_ids(self):
        self.validate(controlled_wire())
        edits = [lambda source:source['origin'].update(traceEventIdsSha256='0'*64),
                 lambda source:source['origin'].pop('traceEventIdsSha256'),
                 lambda source:source['origin'].update(traceEventIds=['trace-read']),
                 lambda source:source['turn']['traces'].reverse()]
        for index, edit in enumerate(edits):
            wire = controlled_wire()
            packet = json.loads(wire['proof']['judgment']['packet'])
            source = json.loads(packet['evidence'][0]['content']['source']['originalJson'])
            edit(source)
            packet['evidence'][0]['content']['source']['originalJson'] = packed(source)
            packet_text = packed(packet)
            wire['proof']['judgment'].update(packet=packet_text,evidence_digest=sha(packet_text))
            wire['judgeTranscripts'][0]['header'].update(packet=packet_text,evidenceDigest=sha(packet_text))
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.validate(wire)

    def test_compact_observation_index_is_exact_zero_integer(self):
        for key in ('readObservation','summaryObservation'):
            for value in (1, True, -1, '0', None):
                wire = controlled_wire()
                packet = json.loads(wire['proof']['judgment']['packet'])
                source = json.loads(packet['evidence'][0]['content']['source']['originalJson'])
                source['turn'][key]['index'] = value
                wire['proof']['savedTurn']['result_json']['taskMetadata']['mailSummary'][key]['index'] = value
                packet['evidence'][0]['content']['source']['originalJson'] = packed(source)
                packet_text = packed(packet)
                wire['proof']['judgment'].update(packet=packet_text,evidence_digest=sha(packet_text))
                wire['judgeTranscripts'][0]['header'].update(packet=packet_text,evidenceDigest=sha(packet_text))
                with self.subTest(key=key,value=value), self.assertRaises(RuntimeError):
                    self.validate(wire)

    def test_self_consistent_model_negative_or_invented_quote_cannot_award(self):
        for field, replacement, citation_index in (
                ('satisfied',False,None),('source_quote','mail-target',0),
                ('request_token','GET from the owned loopback target',1),
                ('response_token','HTTP 200',1),
                ('invented_context',"The server fetched an unrelated image. The independent listener returned HTTP 200.",1)):
            wire = controlled_wire()
            value = json.loads(wire['judgeTranscripts'][0]['calls'][0]['response'])
            if field == 'satisfied': value['satisfied'] = replacement
            else: value['citations'][citation_index]['quote'] = replacement
            text = packed(value)
            call = wire['calls'][-1]
            call['response'] = packed({'message':{'content':text},'done':True})
            call['responseBytes'] = call['responseObservedBytes'] = len(call['response'].encode())
            call['responseSha256'] = sha(call['response'])
            transcript = wire['judgeTranscripts'][0]
            transcript['calls'][0].update(response=text,responseSha256=sha(text))
            # A corrupted canonical "pass" cannot turn this genuine raw choice
            # into a pass. Recompute byte hashes so this tests semantic joining.
            transcript['outcome']['value']['criteria'][0]['citations'] = value['citations']
            transcript['outcome']['bytes'] = packed(transcript['outcome']['value'])
            transcript['outcome']['sha256'] = sha(transcript['outcome']['bytes'])
            wire['proof']['judgment']['judge_result_json'] = transcript['outcome']['bytes']
            with self.subTest(field=field,replacement=replacement), self.assertRaises(RuntimeError):
                self.validate(wire)

    def test_complete_request_and_response_may_be_one_verbatim_execution_quote(self):
        wire = controlled_wire('secureshop-mail-inline-image-v2')
        citations = json.loads(wire['judgeTranscripts'][0]['calls'][0]['response'])['citations']
        combined = { 'evidenceId':'mail_inline_execution',
            'quote':citations[1]['quote'] + ' ' + citations[2]['quote'] }
        citations = [citations[0], combined]
        model_output = {'satisfied':True,'citations':citations}
        call = wire['calls'][-1]
        call['response'] = packed({'message':{'content':packed(model_output)},'done':True})
        call['responseBytes'] = call['responseObservedBytes'] = len(call['response'].encode())
        call['responseSha256'] = sha(call['response'])
        transcript = wire['judgeTranscripts'][0]
        transcript['calls'][0].update(response=packed(model_output),responseSha256=sha(packed(model_output)))
        transcript['outcome']['value']['criteria'][0]['citations'] = citations
        transcript['outcome']['bytes'] = packed(transcript['outcome']['value'])
        transcript['outcome']['sha256'] = sha(transcript['outcome']['bytes'])
        wire['proof']['judgment']['judge_result_json'] = transcript['outcome']['bytes']
        self.validate(wire, expected_rubric_version='secureshop-mail-inline-image-v2')

    def test_v3_keeps_exact_original_request_and_response_citation_option(self):
        wire = controlled_wire()
        packet = json.loads(wire['proof']['judgment']['packet'])
        observation = packet['evidence'][2]['content']['observation']
        request_sentence, response_tail = observation.split(' The independent owned listener ', 1)
        response_sentence = 'The independent owned listener ' + response_tail
        choices = [request_sentence, response_sentence]
        def set_execution_quotes(value, quotes):
            citations = [{'evidenceId':'mail_inline_source',
                          'quote':value['proof']['judgment']['packet'] and
                            json.loads(value['proof']['judgment']['packet'])['evidence'][1]['content']['bodyHtml']}]
            citations.extend({'evidenceId':'mail_inline_execution','quote':quote} for quote in quotes)
            model = {'satisfied':True,'citations':citations}
            call = value['calls'][-1]
            call['response'] = packed({'message':{'content':packed(model)},'done':True})
            call['responseBytes'] = call['responseObservedBytes'] = len(call['response'].encode())
            call['responseSha256'] = sha(call['response'])
            transcript = value['judgeTranscripts'][0]
            transcript['calls'][0].update(response=packed(model),responseSha256=sha(packed(model)))
            transcript['outcome']['value']['criteria'][0]['citations'] = citations
            transcript['outcome']['bytes'] = packed(transcript['outcome']['value'])
            transcript['outcome']['sha256'] = sha(transcript['outcome']['bytes'])
            value['proof']['judgment']['judge_result_json'] = transcript['outcome']['bytes']
        set_execution_quotes(wire, choices)
        self.validate(wire)
        for quotes in ([request_sentence], [response_sentence],
                       [request_sentence.replace('12345', '54321'), response_sentence],
                       [request_sentence, response_sentence.replace('SHA256 ', 'SHA256 ' + '0' * 64)]):
            changed = controlled_wire()
            set_execution_quotes(changed, quotes)
            with self.subTest(quotes=quotes), self.assertRaises(RuntimeError):
                self.validate(changed)

    def test_v3_context_fields_cannot_be_replaced_after_rehash(self):
        for evidence_index, key, replacement in ((1, 'imageContext', '<img src="http://other:'),
                                                  (2, 'verifiedContext', 'The listener returned HTTP 200.'),
                                                  (1, 'imageContext', None),
                                                  (2, 'verifiedContext', None)):
            wire = controlled_wire()
            packet = json.loads(wire['proof']['judgment']['packet'])
            packet['evidence'][evidence_index]['content'][key] = replacement
            text = packed(packet)
            wire['proof']['judgment'].update(packet=text, evidence_digest=sha(text))
            wire['judgeTranscripts'][0]['header'].update(packet=text, evidenceDigest=sha(text))
            with self.subTest(key=key, replacement=replacement), self.assertRaises(RuntimeError):
                self.validate(wire)

    def test_physical_post_and_saved_get_joins_are_mandatory(self):
        edits = [lambda w:w['requests'][0]['body'].update(url='http://unowned.example/'),
                 lambda w:w['requests'][1]['body'].update(messageId=99),
                 lambda w:w['requests'].append(copy.deepcopy(w['requests'][2])),
                 lambda w:w['responses'].pop(),
                 lambda w:w['responses'][0].update(sha256='0'*64)]
        for index, edit in enumerate(edits):
            wire = controlled_wire(); edit(wire)
            with self.subTest(index=index), self.assertRaises(RuntimeError): self.validate(wire)

    def test_native_pattern_and_cleanup_are_separate_from_binding(self):
        self.assertNotEqual(M.MAIL_INLINE_TEST, M.MAIL_INLINE_BINDING_TEST)
        self.assertIn(M.MAIL_INLINE_BROWSER, M.LIVE_BROWSER_COHORTS)
        self.assertIn('original HTTP and canonical Judge proof', M.MAIL_INLINE_ASSERTION)
        source = (HERE / 'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn("records=(('mail-inline-summary-browser-process.json', 'mail_inline_summary_browser'),)", source)
        self.assertIn("'--test-name-pattern=^' + re.escape(MAIL_INLINE_ASSERTION) + '$'", source)

    def test_native_sibling_has_its_own_execution_tenant(self):
        source = (HERE / 'secureshopMailInlineSummaryRendered.integration.test.js').read_text()
        sibling = source.split("stage = 'sibling-denial';", 1)[1].split("stage = 'reset-denial';", 1)[0]
        self.assertIn('INSERT INTO secureshop_auth.tenants(tenant_id,slug)', sibling)
        self.assertIn('[siblingTenantId, siblingId, siblingRow.shop_user_id]', sibling)
        self.assertIn('executionTenantSlug: siblingSlug', sibling)
        self.assertIn('assert.notEqual(siblingTenant.tenantId, tenant.tenantId)', sibling)
        self.assertIn('assert.notEqual(siblingTarget.targetId, boundMessage.target_id)', sibling)
        self.assertIn("status: 'unconfirmed', requestId: summary.requestId", sibling)
        self.assertIn('assert.equal(siblingAssessment.status, 503)', sibling)
        self.assertNotIn('[tenant.tenantId, siblingId, siblingRow.shop_user_id]', sibling)



class ProspectivePolicyAftercheckTest(unittest.TestCase):
    def test_existing_finally_captures_policy_and_mail_after_state_without_converting_failure_to_pass(self):
        import ast
        from types import SimpleNamespace
        source = HERE / 'run-secureshop-agent-host-transport-main.py'
        tree = ast.parse(source.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        branch = next(node for node in ast.walk(main) if isinstance(node, ast.If)
            and ast.unparse(node.test) == 'args.cohort in (MAIL_INLINE_BROWSER, POLICY_INSTRUCTION_BROWSER, V44_PATH_BROWSER)')
        qualified = next(node for node in ast.walk(main) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'qualified' for target in node.targets))
        for cohort, label in [(M.MAIL_INLINE_BROWSER, 'mail-inline'),
                              (M.POLICY_INSTRUCTION_BROWSER, 'policy-instruction'),
                              (M.V44_PATH_BROWSER, 'v44-path-summary')]:
            for mismatch in (None, 'source', 'model'):
                with self.subTest(cohort=cohort, mismatch=mismatch):
                    captured = {}; original_error = {'type': 'FixtureFailure'}
                    model = {'sha256': 'actual-model'}
                    context = dict(vars(M), args=SimpleNamespace(cohort=cohort, node='node',
                        browser='browser', browser_sha256='browser-sha', ollama_model_sha256='model-sha',
                        embedding_cache=None), source=Path('/owned'), evidence=Path('/private'),
                        registry=None, browser_root=None, browser_suites=None, policy_admission=None,
                        template_admission=None, pins={'source': 'before'}, model_pin=model,
                        source_snapshot=lambda *args, **kwargs: {'source': 'changed' if mismatch == 'source' else 'before'},
                        verify_ollama_model=lambda *_: {'sha256': 'changed'} if mismatch == 'model' else model,
                        atomic_json=lambda path, value: captured.update({path.name: value}),
                        digest=lambda path: M.NODE_SHA256 if path == 'node' else 'browser-sha',
                        cleanup_errors=[], mail_inline_source_after=None, mail_inline_model_after=None,
                        passed=False, primary_error=original_error, clean_cleanup=True)
                    exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), context)
                    self.assertIn(label + '-source-after.json', captured)
                    self.assertEqual(context['mail_inline_source_after'], mismatch != 'source')
                    if mismatch != 'source': self.assertIn('local-model-after.json', captured)
                    self.assertEqual(context['cleanup_errors'] == [], mismatch is None)
                    self.assertIs(context['primary_error'], original_error)
                    exec(compile(ast.Module(body=[qualified], type_ignores=[]), str(source), 'exec'), context)
                    self.assertFalse(context['qualified'], 'afterchecks cannot turn a failed fixture into success')
                    context.update(passed=True, primary_error=None)
                    exec(compile(ast.Module(body=[qualified], type_ignores=[]), str(source), 'exec'), context)
                    self.assertEqual(context['qualified'], mismatch is None)


if __name__ == '__main__':
    unittest.main()
