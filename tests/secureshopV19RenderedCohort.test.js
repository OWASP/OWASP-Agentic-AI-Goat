'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { assertActorWire, assertJudgeWire, parseMultipart } = require('./fixtures/secureshopV19RenderedCohort');
const { DECISION_SCHEMA, serializeTools } = require('../server/services/secureshop/providers/ollamaProvider');
const sha = value => createHash('sha256').update(value).digest('hex');
function fixture() {
  const tool = { agent: 'summarizer', tool: 'summarize_file', inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false } };
  const span = { method: 'chat', wireStart: 0, wireEnd: 1,
    request: { system: 'Summarize the document.', messages: [{ role: 'user', content: 'original envelope' }], tools: [tool], closedToolCatalog: true },
    response: { provider: 'ollama', model: 'llama3.1:8b', mocked: false, stop_reason: 'tool_use', tool_uses: [{ id: 'owned-call', name: 'summarizer.summarize_file', args: {} }] } };
  const format = structuredClone(DECISION_SCHEMA);
  format.oneOf[1].properties.tool_calls.items = { oneOf: [{ type: 'object', properties: {
    agent: { type: 'string', enum: ['summarizer'] }, tool: { type: 'string', enum: ['summarize_file'] }, args: tool.inputSchema
  }, required: ['agent', 'tool', 'args'], additionalProperties: false }] };
  const request = JSON.stringify({ model: 'llama3.1:8b', format,
    messages: [{ role: 'system', content: span.request.system + '\n\n' + serializeTools([tool]) }, ...span.request.messages] });
  const response = JSON.stringify({ message: { content: JSON.stringify({ tool_calls: [{ agent: 'summarizer', tool: 'summarize_file', args: {} }] }) }, done: true }) + '\n';
  const wire = { kind: 'actor', request, requestSha256: sha(request), response, responseSha256: sha(response),
    status: 200, responseComplete: true, responseCaptureTruncated: false };
  return { span, wire };
}
test('actor audit joins original physical structured choice to the adapter result', () => {
  const { span, wire } = fixture(); assert.equal(assertActorWire(span, wire), true);
});
for (const [label, mutate] of [
  ['extra physical retry', ({ span }) => { span.wireEnd = 2; }],
  ['mutated response', ({ wire }) => { wire.response += 'x'; }],
  ['foreign tool', ({ span }) => { span.response.tool_uses[0].name = 'filesystem.read'; }],
  ['truncated response', ({ wire }) => { wire.responseCaptureTruncated = true; }],
  ['changed original prompt', ({ span }) => { span.request.messages[0].content += 'x'; }],
  ['foreign physical provider stream', ({ wire }) => { wire.kind = 'judge'; }]
]) test(`actor physical audit rejects ${label}`, () => {
  const value = fixture(); mutate(value); assert.throws(() => assertActorWire(value.span, value.wire));
});
test('actor final audit requires the second wire-authored answer verbatim', () => {
  const { span, wire } = fixture(); span.response = { ...span.response, stop_reason: 'end_turn', text: 'Original answer' };
  delete span.response.tool_uses;
  wire.response = JSON.stringify({ message: { content: JSON.stringify({ reply: 'Original answer' }) }, done: true });
  wire.responseSha256 = sha(wire.response); assert.equal(assertActorWire(span, wire), true);
  span.response.text = 'Substituted answer'; assert.throws(() => assertActorWire(span, wire));
});
function multipart(extra = '') {
  const boundary = 'v19-controlled-boundary';
  const field = (name, value) => `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;
  const file = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="notes.md"\r\nContent-Type: application/octet-stream\r\n\r\nExact source bytes\r\n`;
  return { bytes: Buffer.from(field('sessionId', 'session') + field('requestId', 'request') + field('message', 'Summarize') + file + extra.replaceAll('$BOUNDARY', boundary) + `--${boundary}--\r\n`),
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}
test('raw multipart observer uses the actual parser and preserves MIME and exact bytes', async () => {
  const value = multipart(), parsed = await parseMultipart(value.bytes, value.headers);
  assert.deepEqual(parsed.fields, { sessionId: 'session', requestId: 'request', message: 'Summarize' });
  assert.equal(parsed.file.mime, 'application/octet-stream'); assert.equal(parsed.file.filename, 'notes.md');
  assert.equal(parsed.file.bodyBase64, Buffer.from('Exact source bytes').toString('base64'));
  assert.equal(parsed.file.bodySha256, sha('Exact source bytes'));
});
test('raw multipart observer rejects a second file rather than accepting a truncated part inventory', async () => {
  const value = multipart('--$BOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="other.txt"\r\n\r\nOther\r\n');
  await assert.rejects(parseMultipart(value.bytes, value.headers));
});
test('passive multipart observer preserves delayed real Multer parsing without flowing the request', async t => {
  const http = require('node:http'), express = require('express'), multer = require('multer');
  const { observeMultipartRequest } = require('./fixtures/secureshopV19RenderedCohort');
  const value = multipart(), app = express();
  let observedPromise, parsed, flowingBeforeNext, incoming, originalEmit;
  app.use('/run', (request, _response, next) => {
    incoming = request; originalEmit = request.emit; const observer = observeMultipartRequest(request);
    observedPromise = observer.result; flowingBeforeNext = request.readableFlowing; setTimeout(next, 20);
  });
  app.post('/run', multer({ storage: multer.memoryStorage(), limits: { files: 1, fields: 3, parts: 5 } }).single('file'),
    (request, response) => {
      parsed = { fields: { ...request.body }, filename: request.file.originalname,
        bodySha256: sha(request.file.buffer), byteCount: request.file.size };
      response.status(200).json({ ok: true });
    });
  const server = http.createServer(app);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '::1', resolve); });
  t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const response = await new Promise((resolve, reject) => {
    const request = http.request({ hostname: '::1', port: server.address().port, path: '/run', method: 'POST', headers: {
      ...value.headers, 'content-length': value.bytes.length
    } }, resolve);
    request.once('error', reject); request.end(value.bytes);
  });
  const responseBytes = []; for await (const chunk of response) responseBytes.push(chunk);
  const observed = await observedPromise;
  assert.equal(response.statusCode, 200); assert.deepEqual(JSON.parse(Buffer.concat(responseBytes)), { ok: true });
  assert.equal(flowingBeforeNext, null); assert.equal(incoming.emit, originalEmit);
  assert.deepEqual(parsed, { fields: { sessionId: 'session', requestId: 'request', message: 'Summarize' },
    filename: 'notes.md', bodySha256: sha('Exact source bytes'), byteCount: 18 });
  assert.deepEqual(observed.fields, parsed.fields); assert.equal(observed.file.filename, parsed.filename);
  assert.equal(observed.file.bodySha256, parsed.bodySha256); assert.equal(observed.file.byteCount, parsed.byteCount);
});
test('passive multipart observer restores the emitter after an early HTTP denial without downstream parsing', async t => {
  const http = require('node:http'), express = require('express');
  const { observeMultipartRequest } = require('./fixtures/secureshopV19RenderedCohort');
  const value = multipart(), app = express();
  let incoming, originalEmit, observedPromise, clientRequest;
  app.use('/run', (request, response) => {
    incoming = request; originalEmit = request.emit; const observer = observeMultipartRequest(request, { timeoutMs: 500 });
    observedPromise = observer.result; setTimeout(() => response.status(403).json({ error: 'denied' }), 20);
  });
  const server = http.createServer(app);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '::1', resolve); });
  t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const response = await new Promise((resolve, reject) => {
    const request = http.request({ hostname: '::1', port: server.address().port, path: '/run', method: 'POST', headers: {
      ...value.headers, 'content-length': value.bytes.length
    } }, resolve);
    clientRequest = request; request.once('error', reject); request.write(value.bytes.subarray(0, 16));
  });
  for await (const _chunk of response) {}; clientRequest.destroy();
  await assert.rejects(observedPromise, error => ['MULTIPART_REQUEST_CLOSED', 'MULTIPART_OBSERVER_TIMEOUT'].includes(error.code));
  assert.equal(response.statusCode, 403); assert.equal(incoming.emit, originalEmit);
});
for (const [event, code] of [['aborted', 'MULTIPART_REQUEST_ABORTED'], ['close', 'MULTIPART_REQUEST_CLOSED']]) {
  test(`passive multipart observer restores the emitter after request ${event}`, async () => {
    const { EventEmitter } = require('node:events');
    const { observeMultipartRequest } = require('./fixtures/secureshopV19RenderedCohort');
    const request = new EventEmitter(); request.headers = multipart().headers;
    const originalEmit = request.emit; let downstream = 0; request.on(event, () => { downstream++; });
    const observer = observeMultipartRequest(request);
    assert.equal(request.emit(event), true);
    await assert.rejects(observer.result, error => error.code === code);
    assert.equal(downstream, 1); assert.equal(request.emit, originalEmit);
  });
}
test('passive multipart observer bounds capture without changing downstream request delivery', async () => {
  const { EventEmitter } = require('node:events');
  const { observeMultipartRequest } = require('./fixtures/secureshopV19RenderedCohort');
  const request = new EventEmitter(); request.headers = multipart().headers;
  const originalEmit = request.emit, received = [];
  request.on('data', chunk => received.push(Buffer.from(chunk)));
  const observer = observeMultipartRequest(request, { maxBytes: 4 });
  assert.equal(request.emit('data', Buffer.from('Exact source bytes')), true); request.emit('end');
  await assert.rejects(observer.result, error => error.code === 'MULTIPART_CAPTURE_OVERFLOW');
  assert.equal(Buffer.concat(received).toString(), 'Exact source bytes'); assert.equal(request.emit, originalEmit);
});
test('rejected multipart persistence operation unregisters without an ignored finally rejection', async () => {
  const { trackOwnedOperation, takeOwnedOperationFailures } = require('./fixtures/secureshopV19RenderedCohort');
  const pending = new Set(), owners = new Set(), failures = [], owner = Object.freeze({ close() {} });
  const failure = Object.assign(Error('bounded evidence persistence failed'), { code: 'EVIDENCE_WRITE_FAILED' });
  const operation = Promise.reject(failure);
  assert.equal(trackOwnedOperation(operation, pending, owner, owners, failures), operation);
  assert.equal(pending.has(operation), true); assert.equal(owners.has(owner), true);
  await assert.rejects(operation, error => error === failure);
  await Promise.resolve();
  assert.equal(pending.size, 0); assert.equal(owners.size, 0);
  assert.deepEqual(takeOwnedOperationFailures(failures), [failure],
    'A failure settled before close is consumed by the exact fail-closed cleanup path');
  assert.deepEqual(failures, []);
});
test('Judge physical audit preserves request and original response identities', () => {
  const calls = [], wires = [];
  for (let index = 0; index < 2; index++) {
    const input = [{ role: 'user', content: 'criterion ' + index }], schema = { type: 'object' }, response = '{"verdict":"fail"}';
    const request = JSON.stringify({ messages: input, format: schema }), raw = JSON.stringify({ message: { content: response }, done: true });
    calls.push({ transport: 'returned', request: { method: 'chat', input, schema }, response, responseSha256: sha(response), metadata: { provider: 'ollama', mocked: false } });
    wires.push({ kind: 'judge', request, requestSha256: sha(request), response: raw, responseSha256: sha(raw), status: 200, responseComplete: true, responseCaptureTruncated: false });
  }
  const transcript = { complete: true, header: { maximumCalls: 4 }, calls };
  assertJudgeWire(transcript, wires); calls[1].response = 'changed'; assert.throws(() => assertJudgeWire(transcript, wires));
});
test('complete offline cohort audit accepts controlled joins and rejects missing or unjoined physical calls', () => {
  const { SCOPE, INPUT_SHA, validateV19OriginalEvidence } = require('./fixtures/secureshopV19RenderedCohort');
  const expected = require('./fixtures/secureshopV19ActualCases.json').cases;
  const document = { version: 1, scope: SCOPE, inputsSha256: INPUT_SHA, passed: true, failures: [], qualificationComplete: false,
    qualificationStatus: 'provisional-original-answer-review-required', semanticReviewRequired: true,
    cases: [], actorSpans: [], wire: [], multipart: [], judgeTranscripts: [],
    siblingSetup: { fixtureOwned: true, claimsModelEvidence: false, receipt: { controlled: true } },
    baselineCounters: { actorDecisions: 0, toolCalls: 0, fileWrites: 1, judgeCalls: 0, canonicalJudgments: 0, completionRows: 0 },
    finalCounters: { actorDecisions: 10, toolCalls: 5, fileWrites: 6, judgeCalls: 4, canonicalJudgments: 4, completionRows: 1 } };
  for (const [index, value] of expected.entries()) {
    const first = fixture(), second = fixture(), callId = 'owned-call';
    const body = value.attachmentText, answer = 'Controlled answer ' + index;
    const attachment = { filename: value.filename, mime: value.mime, byteCount: Buffer.byteLength(body), bodySha256: sha(body) };
    const envelope = JSON.stringify({ message: value.message, attachment });
    first.span.request.messages = [{ role: 'user', content: envelope }];
    second.span.request.messages = [{ role: 'tool', tool_call_id: callId, content: body }];
    second.span.response = { provider: 'ollama', model: 'llama3.1:8b', mocked: false, stop_reason: 'end_turn', text: answer };
    for (const [item, reply] of [[first, null], [second, answer]]) {
      item.span.caseId = value.id; item.span.wireStart = document.wire.length; item.span.wireEnd = document.wire.length + 1;
      const request = JSON.parse(item.wire.request);
      request.messages = [request.messages[0], ...item.span.request.messages.map(require('../server/services/secureshop/providers/ollamaProvider').serializeMessage)];
      item.wire.request = JSON.stringify(request); item.wire.requestSha256 = sha(item.wire.request);
      if (reply) { item.wire.response = JSON.stringify({ message: { content: JSON.stringify({ reply }) }, done: true }); item.wire.responseSha256 = sha(item.wire.response); }
      document.actorSpans.push(item.span); document.wire.push(item.wire);
    }
    const model = { provider: 'ollama', model: 'llama3.1:8b', mocked: false };
    const traces = [{ kind: 'model_decision', provider: 'ollama', step: 1,
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: callId, name: 'summarizer.summarize_file', args: {} }] }), result_json: JSON.stringify(model) },
    { kind: 'model_decision', provider: 'ollama', step: 2, result_json: JSON.stringify({ ...model, decision: 'final', text: answer }) },
    { kind: 'local_tool_call' }, { kind: 'local_tool_result' }, { kind: 'final' }, { kind: 'terminal', provider: 'ollama', step: 2, result_json: JSON.stringify(model) }];
    const original = { row: { result_json: { text: answer, steps: 2, stopReason: 'end_turn',
      hops: [{ tool: 'summarizer.summarize_file', params: {}, error: null, policyViolation: null, result: { content: [{ type: 'text', text: body }] } }],
      taskMetadata: { boundFileSummary: { originalEnvelope: envelope, graphEffect: { callId } } } } }, traces,
    retained: { bodyBase64: Buffer.from(body).toString('base64'), receipt: { attachment, file: { targetId: 'controlled-target-' + index } } },
    graphEffect: { status: 'completed', run_status: 'completed' }, candidate: value.mode === 'fixed' ? null : { controlled: true } };
    const reference = { sessionId: 'session-' + index, requestId: 'request-' + index };
    const response = { ...reference, text: answer, replayed: index === 0 };
    const counter = { actorDecisions: 2, toolCalls: 1, fileWrites: 1, judgeCalls: 0, canonicalJudgments: 0, completionRows: 0 };
    const entry = { ...value, passed: true, actorCalls: 2, runPosts: 1, reference, response, original,
      reset: { status: 'committed', resetId: 'controlled-reset-' + index },
      cleanupReceipt: { kind: 'files', targetId: 'controlled-target-' + index, operationId: 'controlled-reset-' + index }, resetFileAbsent: true, historyPreserved: true, siblingPreserved: true,
      recoveryCounters: { before: counter, after: { ...counter } }, assessmentCalls: value.mode === 'fixed' ? 0 : 1,
      publicProgress: { objectives: [{ objectiveId: 'ss_file_upload_instruction_adoption', completed: value.expectedAssessment === 'pass' }] },
      publicProgressAfterReset: { objectives: [{ objectiveId: 'ss_file_upload_instruction_adoption', completed: false }] } };
    if (index === 0) Object.assign(entry, { responseAckLost: true, committedRun: { ...response, replayed: false }, ackLossCounters: { before: counter, after: { ...counter } } });
    if (value.mode === 'fixed') entry.assessment = { completed: false, status: 'ineligible', modelEvaluated: false };
    else {
      entry.assessment = { completed: value.expectedAssessment === 'pass', judgment: { verdict: value.expectedAssessment } };
      const packet = 'controlled packet ' + index, digest = sha(packet), calls = [];
      entry.judgeWireStart = document.wire.length;
      for (let criterion = 0; criterion < 2; criterion++) {
        const input = [{ role: 'user', content: packet + criterion }], schema = { type: 'object' }, reply = '{"controlled":true}';
        const request = JSON.stringify({ messages: input, format: schema }), raw = JSON.stringify({ message: { content: reply }, done: true });
        document.wire.push({ kind: 'judge', request, requestSha256: sha(request), response: raw, responseSha256: sha(raw), status: 200, responseComplete: true, responseCaptureTruncated: false });
        calls.push({ stage: 'criterion-' + criterion, attempt: 1, transport: 'returned', request: { method: 'chat', input, schema }, response: reply, responseSha256: sha(reply), metadata: { provider: 'ollama', model: 'llama3.1:8b', mocked: false, fallback: false } });
      }
      entry.judgeWireEnd = document.wire.length;
      entry.judgeResult = { controlled: true };
      const outcomeBytes = JSON.stringify(entry.judgeResult);
      document.judgeTranscripts.push({ complete: true, header: { maximumCalls: 4, packet, evidenceDigest: digest, judgeVersion: 'controlled', runId: 'run-' + index }, calls,
        outcome: { value: entry.judgeResult, bytes: outcomeBytes, sha256: sha(outcomeBytes) } });
      const result = { verdict: value.expectedAssessment }, serialized = JSON.stringify(result), raw = JSON.stringify(entry.judgeResult);
      entry.canonical = { judgment: { packet, evidence_digest: digest, result_serialized: serialized, result_digest: sha(serialized),
        result_json: result, judge_result_json: raw, judge_observations: { version: 1, judgeVersion: 'controlled', runId: 'run-' + index, evidenceDigest: digest, resultSha256: sha(raw),
          calls: calls.map(call => ({ stage: call.stage, attempt: call.attempt, provider: call.metadata.provider, model: call.metadata.model,
            requestSha256: sha(JSON.stringify({ method: 'chat', input: call.request.input, schema: call.request.schema })), responseSha256: sha(call.response) })) } } };
    }
    document.multipart.push({ fields: { ...reference, message: value.message }, file: { bodyBase64: original.retained.bodyBase64 } });
    document.cases.push(entry);
  }
  assert.equal(validateV19OriginalEvidence(document), true);
  for (const mutate of [
    value => { value.wire.push(value.wire[0]); },
    value => { value.cases[0].responseAckLost = false; },
    value => { value.cases[2].original.retained.bodyBase64 = Buffer.from('tamper').toString('base64'); },
    value => { value.cases[3].canonical.judgment.result_digest = '0'.repeat(64); },
    value => { value.cases[4].assessmentCalls = 1; },
    value => { value.cases[1].historyPreserved = false; },
    value => { value.cases[0].canonical.judgment.judge_observations.calls[0].responseSha256 = '0'.repeat(64); },
    value => { value.finalCounters.fileWrites++; },
    value => { value.cases[2].cleanupReceipt.operationId = 'other-reset'; },
    value => { value.qualificationComplete = true; }
  ]) { const changed = structuredClone(document); mutate(changed); assert.throws(() => validateV19OriginalEvidence(changed)); }
});
test('ACK-loss callback cannot resolve JSON until the actual response finish event and exact IDs', () => {
  const { EventEmitter } = require('node:events');
  const { captureFinishedJson, findCommittedRunResponse } = require('./fixtures/secureshopV19RenderedCohort');
  const record = { method: 'POST', path: '/agents/customer/file-summary/run' };
  const response = new EventEmitter(); response.statusCode = 200; response.json = function() { return this; };
  let saves = 0; captureFinishedJson(record, response, () => { saves++; });
  const ids = { sessionId: 'controlled-session', requestId: 'controlled-request' };
  const body = { ...ids, replayed: false, text: 'Original committed response' };
  response.json(body); body.text = 'Later mutation';
  assert.equal(findCommittedRunResponse([record], ids), null); assert.equal(saves, 0);
  response.emit('close'); assert.equal(findCommittedRunResponse([record], ids), null);
  response.emit('finish'); assert.equal(saves, 1);
  assert.deepEqual(findCommittedRunResponse([record], ids), { ...ids, replayed: false, text: 'Original committed response' });
  assert.equal(findCommittedRunResponse([record], { ...ids, requestId: 'foreign' }), null);
  assert.throws(() => findCommittedRunResponse([record, structuredClone(record)], ids));
});
