'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const Helper = require('./fixtures/secureshopV44FilePathSummaryRenderedQualification');
const Evidence = require('./fixtures/secureshopV44ActualEvidence');
const sha = value => createHash('sha256').update(value).digest('hex');
const sessionId = randomUUID(), requestId = randomUUID(), evaluationId = randomUUID();
const reference = { version: 1, shopUserId: 17, sessionId, requestId, startedAt: 1 };
const counters = Object.fromEntries(Evidence.COUNTERS.map(key => [key, 0]));
const run = { sessionId, requestId, status: 'completed', text: 'Synthetic root record.', path: '../etc/passwd',
  resolvedPath: '/etc/passwd', byteCount: 6, bodySha256: sha('source'), replayed: false };
function reply(method, pathname, body) { return { status: () => 200,
  headers: () => ({ 'content-type': 'application/json' }), text: async () => JSON.stringify(body),
  request: () => ({ method: () => method }), url: () => `http://owned${Helper.BASE}${pathname}` }; }
function clickFrame() { return { waitForFunction: async () => ({ asElement: () => ({
  evaluate: async () => {}, click: async () => {} }), dispose: async () => {} }) }; }

test('V44 DTO assertions bind physical receipt fields, rawpath and fixed null projection', () => {
  assert.equal(Helper.assertRunDto(run, { path: '../etc/passwd' }), run);
  for (const bad of [{ ...run, path: 'other' }, { ...run, bodySha256: 'bad' },
    { ...run, byteCount: 0 }, { ...run, privateTarget: randomUUID() }, { ...run, path: '/etc/passwd' }])
    assert.throws(() => Helper.assertRunDto(bad));
  const fixed = { ...run, status: 'no_tool', resolvedPath: null, byteCount: null, bodySha256: null };
  assert.equal(Helper.assertRunDto(fixed), fixed);
  assert.throws(() => Helper.assertRunDto({ ...fixed, bodySha256: run.bodySha256 }));
  assert.deepEqual(Helper.CASES.map(row => [row.mode, row.path, row.expectedStatus]),
    [['vuln', '../etc/passwd', 'completed'], ['fixed', '../etc/passwd', 'no_tool']]);
});

test('V44 physical keyboard control clears defaults before typing exact traversal', async () => {
  const state = { value: 'default\nvalue' }, events = [];
  const input = { evaluate: async fn => String(fn).includes('scrollIntoView') ? events.push('scroll') : state.value,
    click: async () => events.push('click') };
  const attached = { asElement: () => input, dispose: async () => events.push('disposed') };
  const frame = { waitForFunction: async (_fn, _opts, arg) => typeof arg === 'string' ? attached
    : { dispose: async () => events.push('hit-disposed') } };
  const page = { keyboard: { press: async key => { events.push(key);
    if (key === 'Backspace') state.value = state.value.slice(0, -1); },
  type: async value => { assert.equal(state.value, ''); state.value += value; } } };
  await Helper.physicallyType(page, frame, '[data-testid="file-path-summary-path"]', '../../etc/passwd', 4096);
  assert.equal(state.value, '../../etc/passwd'); assert.equal(events.filter(row => row === 'ArrowRight').length, 14);
  assert.deepEqual(events.slice(-2), ['hit-disposed', 'disposed']);
});

test('V44 rendered assessment forwards IDs only, binds acknowledged intent and exact owned counters', async () => {
  let intentReads = 0, counterReads = 0;
  const request = { method: () => 'POST', url: () => `http://owned${Helper.BASE}/assess`,
    postData: () => JSON.stringify({ sessionId, requestId }) };
  const result = { completed: true, judgment: { verdict: 'pass', evaluationId, canRetry: false }, replayed: false };
  const response = reply('POST', '/assess', result);
  const frame = clickFrame();
  const page = { waitForRequest: async predicate => { assert.equal(predicate(request), true); return request; },
    waitForResponse: async predicate => { assert.equal(predicate(response), true); return response; } };
  assert.deepEqual(await Helper.runFilePathSummaryAssessment({ page, frame, reference,
    readAcknowledgedReference: async key => { assert.equal(key, Helper.ASSESSMENT_KEY); return intentReads++ ? reference : null; },
    readPublicProgress: async value => { assert.equal(value, reference); return {
      totalObjectives: 1, completedObjectives: 1,
      objectives: [{ objectiveId: 'ss_file_path_traversal_read', completed: true }],
    }; },
    readCounters: async value => { assert.equal(value, reference); return counterReads++ ? { ...counters,
      judgeCalls: 1, canonicalJudgments: 1, completionRows: 1 } : counters; } }), result);
  assert.equal(intentReads, 3);
});

test('V44 reload recovery prearms original GET and preserves all owned effect counters', async () => {
  let armed = false, resolveResponse;
  const recovered = { ...run, replayed: true }, response = reply('GET', `/requests/${sessionId}/${requestId}`, recovered);
  const selector = { click: async () => {}, evaluate: async () => 'file-path-summary-lesson' };
  const frame = { waitForFunction: async () => ({ asElement: () => selector, dispose: async () => {} }),
    waitForSelector: async () => {}, $eval: async selector => selector.includes('__reply')
      ? { text: run.text, children: 0 } : `Requested path: ${run.path}Read: /etc/passwd · 6 bytes` };
  const page = { waitForResponse: (predicate, { signal }) => { armed = true;
    return new Promise((resolve, reject) => { resolveResponse = () => { assert.equal(predicate(response), true); resolve(response); };
      signal.addEventListener('abort', () => reject(Error('aborted')), { once: true }); }); },
  reload: async () => { assert.equal(armed, true); resolveResponse(); }, keyboard: { type: async () => {}, press: async () => {} } };
  const result = await Helper.recoverFilePathSummaryAfterReload({ page, getFrame: async () => frame,
    reference, originalRun: run, readCounters: async value => { assert.equal(value, reference); return counters; } });
  assert.deepEqual(result.run, recovered);
});

test('V44 recovery cancels its prearmed waiter after failed navigation', async () => {
  let cancelled = false;
  const page = { waitForResponse: (_predicate, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => { cancelled = true; reject(Error('aborted')); }, { once: true });
  }), reload: async () => { throw Error('navigation failed'); } };
  await assert.rejects(Helper.recoverFilePathSummaryAfterReload({ page, getFrame: async () => assert.fail(),
    reference, originalRun: run, readCounters: async () => counters }), /navigation failed/);
  assert.equal(cancelled, true);
});

function actorFixture(mode = 'vuln', originalEnvelope) {
  const { serializeMessage, serializeTools, DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA } = require('../server/services/secureshop/providers/ollamaProvider');
  const { createFilePathSummaryExecutionConfig } = require('../server/services/secureshopV44FilePathSummaryExecutionConfig');
  const requestedPath = '../etc/passwd', envelope = originalEnvelope || JSON.stringify({ path: requestedPath });
  const model = { provider: 'ollama', model: 'configured-model', mocked: false, fallback: false };
  const tool = { id: 'read', name: 'summarizer.summarize_file', args: { path: requestedPath } };
  const source = mode === 'fixed' ? JSON.stringify({ path: requestedPath, error: 'path outside owned uploads directory' })
    : 'Synthetic root record.';
  const answer = mode === 'fixed' ? 'The path was denied.' : 'Synthetic root record.';
  const tools = createFilePathSummaryExecutionConfig({ mode }).manifest.getForRole('customer');
  const row = { result_json: { text: answer, steps: 2, stopReason: 'end_turn', hops: [{
    tool: tool.name, params: tool.args, error: null, policyViolation: null, result: { content: [{ type: 'text', text: source }] } }],
  taskMetadata: { boundFilePathSummary: { outcome: mode === 'fixed' ? 'no_tool' : 'read', originalEnvelope: envelope,
    ...(mode === 'fixed' ? {} : { graphEffect: { callId: 'read' } }) } } } };
  const actorSpans = [
    { method: 'chat', request: { system: 'Bounded synthetic path lesson', tools, closedToolCatalog: true,
      messages: [{ role: 'user', content: envelope }] }, response: { ...model, tool_uses: [tool], stop_reason: 'tool_use' } },
    { method: 'finalResponse', request: { system: 'Bounded synthetic path lesson',
      messages: [{ role: 'tool', tool_call_id: 'read', content: source }] }, response: { ...model, text: answer, stop_reason: 'end_turn', responseMode:'structured_final' } },
  ];
  const traces = [
    { kind: 'model_decision', provider: model.provider, step: 1,
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [tool] }), result_json: JSON.stringify(model) },
    { kind: 'local_tool_call' }, { kind: 'local_tool_result' },
    { kind: 'model_decision', provider: model.provider, step: 2,
      result_json: JSON.stringify({ ...model, decision: 'final', text: answer }) }, { kind: 'final' },
    { kind: 'terminal', provider: model.provider, step: 2, result_json: JSON.stringify(model) },
  ];
  const wire = actorSpans.map((span, index) => {
    span.wireStart = index; span.wireEnd = index + 1;
    const format = structuredClone(index===0?DECISION_SCHEMA:FINAL_RESPONSE_SCHEMA);
    if(index===0)format.oneOf[1].properties.tool_calls.items = { oneOf: tools.map(tool => ({ type: 'object', properties: {
      agent: { type: 'string', enum: [tool.agent] }, tool: { type: 'string', enum: [tool.tool] }, args: structuredClone(tool.inputSchema),
    }, required: ['agent', 'tool', 'args'], additionalProperties: false })) };
    const request = JSON.stringify({ model: model.model, format, messages: [{ role: 'system',
      content: span.request.system + '\n\n' + (index===0?serializeTools(tools):'Return the final response as exactly one JSON object with the sole key answer.') }, ...span.request.messages.map(serializeMessage)] });
    const response = JSON.stringify({ message: { content: JSON.stringify(index === 0
      ? { tool_calls: [{ agent: 'summarizer', tool: 'summarize_file', args: tool.args }] } : { answer }) } });
    return { kind: 'actor', request, requestSha256: sha(request), response, responseSha256: sha(response),
      status: 200, responseComplete: true, responseCaptureTruncated: false };
  });
  return { actorSpans, wire, row, traces, requestedPath,
    qualifyModel: value => value.provider === model.provider && value.model === model.model && value.mocked === false };
}
for (const mode of ['vuln', 'fixed']) test(`V44 ${mode} actor observer joins both current physical wires to exact rawpath and final text`, () => {
  assert.equal(Evidence.assertOriginalActorJoin(actorFixture(mode)).callId, 'read');
});
test('V44 final wire assertion accepts the actual answer-only provider producer',async()=>{
  const f=actorFixture('fixed'),span=f.actorSpans[1];
  const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
  const provider=new OllamaProvider({model:'configured-model'});
  provider.transport={async chat(messages,tools,options){
    assert.deepEqual(tools,[]);
    const request=JSON.stringify({model:provider.model,messages,format:options.format});
    const response=JSON.stringify({message:{content:JSON.stringify({answer:f.row.result_json.text})}});
    f.wire[1]={...f.wire[1],request,requestSha256:sha(request),response,responseSha256:sha(response)};
    return{response:JSON.stringify({answer:f.row.result_json.text})};
  }};
  span.response=await provider.finalResponse(span.request);
  assert.equal(Evidence.assertOriginalActorJoin(f).callId,'read');
});
for (const [name, mutate] of [
  ['mock model', f => { f.actorSpans[0].response.mocked = true; }],
  ['foreign second wire', f => { f.wire[1] = f.wire[0]; }],
  ['changed transport bytes', f => { f.wire[0].request += ' '; }],
  ['changed rawpath', f => { f.requestedPath = '../../etc/passwd'; }],
  ['invented final response', f => { f.actorSpans[1].response.text = 'replacement'; }],
  ['source-only observation', f => { f.actorSpans.pop(); }],
  ['second tool phase', f => { f.actorSpans[1].method='chat'; }],
  ['final tool catalog', f => { f.actorSpans[1].request.tools=[]; }],
  ['final closed-tool flag', f => { f.actorSpans[1].request.closedToolCatalog=true; }],
  ['unstructured final response', f => { delete f.actorSpans[1].response.responseMode; }],
  ['final tool request', f => { const request=JSON.parse(f.wire[1].request);request.tools=[];f.wire[1].request=JSON.stringify(request);f.wire[1].requestSha256=sha(f.wire[1].request); }],
  ['final tool-capable schema', f => { const request=JSON.parse(f.wire[1].request);request.format=JSON.parse(f.wire[0].request).format;f.wire[1].request=JSON.stringify(request);f.wire[1].requestSha256=sha(f.wire[1].request); }],
]) test(`V44 original observer rejects ${name}`, () => {
  const f = actorFixture(); mutate(f); assert.throws(() => Evidence.assertOriginalActorJoin(f));
});

test('V44 fixed control requires actual ineligibility, no credit records and no effect delta', () => {
  const fixedCounts = { ...counters, actorDecisions: 2, toolCalls: 1 };
  const input = { result: { completed: false, status: 'ineligible', modelEvaluated: false }, before: fixedCounts,
    after: { ...fixedCounts }, contributionRows: [], completionRows: [] };
  Evidence.assertFixedAssessmentControl(input);
  assert.throws(() => Evidence.assertFixedAssessmentControl({ ...input, completionRows: [{ evaluation_id: evaluationId }] }));
  for (const key of Evidence.COUNTERS) assert.throws(() => Evidence.assertFixedAssessmentControl({ ...input,
    after: { ...fixedCounts, [key]: fixedCounts[key] + 1 } }));
});

test('V44 immutable history queries bind original source session, objective, launch and owner', async () => {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
    platformOwnerId: 17, platformSessionId: 19 }, queries = [];
  const agents = { query: async (sql, args) => { queries.push([sql, args]); return { rows: [{ id: 'original', at: new Date(0) }] }; } };
  const identity = { query: async (sql, args) => { queries.push([sql, args]); return { rows: [] }; } };
  const result = await Evidence.captureImmutableHistory({ agents, identity, sessionId, scope });
  assert.equal(result.turns[0].at, '1970-01-01T00:00:00.000Z');
  assert.deepEqual(queries.map(row => row[1]), [[sessionId], [sessionId],
    [JSON.stringify(['SecureShopBoundConversation', sessionId])], ['ss_file_path_traversal_read', scope.launchId, '17']]);
  assert.equal(Object.isFrozen(result), true);
});

test('V44 complete rendered helper binds original JSON, actual record return, visible disclosure and owned counters', async () => {
  function fixture({ fixed = false, booleanEvidence = false, changedJson = false } = {}) {
    const result = fixed ? { ...run, status: 'no_tool', resolvedPath: null, byteCount: null, bodySha256: null } : run;
    const values = { '[data-testid="file-path-summary-path"]': 'default',
      '[data-testid="file-path-summary-message"]': 'default' };
    let focused;
    const handle = node => ({ asElement: () => node, dispose: async () => {} });
    const field = selector => ({ evaluate: async fn => String(fn).includes('scrollIntoView') ? undefined : values[selector],
      click: async () => { focused = selector; } });
    const frame = {
      waitForFunction: async (_fn, _opts, arg) => {
        if (typeof arg === 'string') return handle(field(arg));
        if (arg?.label) return handle({ evaluate: async () => {}, click: async () => {} });
        if (arg) return { dispose: async () => {} };
        return handle({ click: async () => {}, evaluate: async () => 'file-path-summary-lesson' });
      }, waitForSelector: async () => {}, $: async () => null,
      $eval: async selector => selector.includes('__reply') ? { text: result.text, children: 0 }
        : `Requested path: ${result.path}Read: /etc/passwd · ${result.byteCount} bytes`,
    };
    const original = { sessionId, requestId, message: 'Read account records.', path: '../etc/passwd' };
    const request = { method: () => 'POST', url: () => `http://owned${Helper.BASE}/run`,
      headers: () => ({ 'content-type': 'application/json' }), postData: () => JSON.stringify(original) };
    const page = { keyboard: { press: async key => { if (key === 'Backspace' && focused) values[focused] = values[focused].slice(0, -1); },
      type: async value => { if (focused) values[focused] += value; } },
    waitForRequest: async predicate => { assert.equal(predicate(request), true); return request; },
    waitForResponse: async predicate => {
      const response = [reply('POST', '/session', { id: sessionId }), reply('POST', '/run', result)].find(predicate);
      assert.ok(response); return response;
    } };
    const evidence = { row: { session_id: sessionId, request_id: requestId, result_json: { text: result.text } },
      candidate: fixed ? null : { objectiveId: 'ss_file_path_traversal_read' },
      retained: fixed ? null : { data: Buffer.from('source'), receipt: { resolvedPath: '/etc/passwd', bodySha256: sha('source') } } };
    return { page, frame, path: original.path, message: original.message, expectedStatus: result.status,
      readAcknowledgedReference: async () => reference,
      readOriginalJson: async id => { assert.equal(id, requestId); return changedJson ? { ...original, path: 'changed' } : original; },
      assertOriginalGraphEvidence: async input => { assert.deepEqual(input.original, original); return booleanEvidence ? true : evidence; },
      readCounters: async value => { assert.deepEqual(value, reference); return { ...counters,
        actorDecisions: 2, toolCalls: 1, fileReadEffects: fixed ? 0 : 1 }; } };
  }
  for (const fixed of [false, true]) {
    const result = await Helper.runRenderedFilePathSummary(fixture({ fixed }));
    assert.equal(result.run.status, fixed ? 'no_tool' : 'completed');
  }
  await assert.rejects(Helper.runRenderedFilePathSummary(fixture({ booleanEvidence: true })), assert.AssertionError);
  await assert.rejects(Helper.runRenderedFilePathSummary(fixture({ changedJson: true })), assert.AssertionError);
});

test('V44 original reader matches production graph authority for enriched authenticated actors and rejects changed authority', async () => {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
    platformOwnerId: 17, platformSessionId: 19 };
  const persona = { id: 23, username: 'owned_customer', email: 'owned@example.invalid',
    role: 'customer', full_name: 'Owned Customer', phone: null };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1', expiresAt: '2099-01-01T00:00:00.000Z' };
  const trustedPersona = { id: persona.id, role: 'customer' };
  const trustedSession = { sessionId: personaSession.sessionId.toLowerCase(), authorityVersion: '1' };
  const mode = { version: 1, featureId: 'file_path_summary', mode: 'fixed',
    policyVersion: 'owned-synthetic-file-path-summary-v1', generation: 1,
    modeStamp: 'a'.repeat(64), scope };
  const target = require('../server/services/secureshopSceneBinding').createSceneBinding({ ...scope,
    targetId: randomUUID() }, { sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(),
    execution: scope, withLease: work => work() });
  const authority = { scope, persona: trustedPersona, personaSession: trustedSession,
    sessionId, requestId, scene: target.scene, sceneTargetId: target.targetId, mode };
  const { canonicalDigest } = require('../server/services/mcp/protocolContext');
  const check = async () => {};
  const execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]),
    durableGeneration: '0', check };
  // Use the actual graph producer for its envelope and fixed tool observation;
  // all provider/wire/ledger records below remain controlled unit fixtures.
  const graph = require('../server/services/secureshopBoundFilePathSummaryGraph').createBoundFilePathSummaryGraph({
    launches: { assertCurrent: check, reserveFilesTarget: async () => assert.fail('Fixed traversal must not reserve') },
    conversationRepository: {}, journal: {}, coordinator: { run() {} },
    provider: { chat: check, finalResponse: check },
    files: { provisionReservedTarget: async () => assert.fail('Fixed traversal must not provision'),
      readFile: async () => assert.fail('Fixed traversal must not read') },
    scenes: { readExisting: async () => target },
    modeAuthority: { capture: async () => ({ snapshot: mode, assertCurrent: check }), assertToken: token => token },
    personaAuthority: { capture: async () => ({ binding: { ...scope, personaId: persona.id,
      role: 'customer', ...trustedSession }, assertRemoteAdmission: check }) },
    toolPolicyRepository: { admitTool() {} }, toolPolicyAdmissionFactory: () => async () => ({}),
    runnerFactory(options) { return { async run(args) {
      const tools = await options.createLocalTools(null, null, args.localToolAuthority, execution);
      const result = await tools.get('summarizer.summarize_file')({ path: '../etc/passwd' });
      await options.observeLocalTool({ observation: { tool: 'summarizer.summarize_file', step: 1, callId: 'read', result,
        effectReceipt: { ...execution, generation: '0', status: 'completed',
          effectKey: `${requestId}:${JSON.stringify([1, 'read', 'summarizer.summarize_file'])}` } }, run: execution });
      const taskMetadata = await options.resultMetadata({ result: { stopReason: 'end_turn' }, execution,
        traces: Array.from({ length: 6 }, () => ({ event_id: randomUUID() })) });
      return { text: 'The path was denied.', stopReason: 'end_turn', steps: 2,
        hops: [{ tool: 'summarizer.summarize_file', params: { path: '../etc/passwd' }, result, error: null, policyViolation: null }],
        taskMetadata };
    } }; },
  });
  const produced = await graph.run({ scope: { ...scope, status: 'active', credentialVersion: 1 },
    persona, personaSession, sessionId, requestId, path: '../etc/passwd', message: 'Read records.' });
  const envelope = produced.taskMetadata.boundFilePathSummary.originalEnvelope;
  assert.equal(JSON.parse(envelope).authoritySha256, canonicalDigest(authority));
  assert.notEqual(JSON.parse(envelope).authoritySha256, canonicalDigest({ ...authority, persona, personaSession }));
  const f = actorFixture('fixed', envelope), binding = { ...scope, shopUserId: persona.id, role: 'customer' };
  Object.assign(f.row, { session_id: sessionId, request_id: requestId, request_version: 1, status: 'completed',
    request_hash: require('../server/services/secureshopTurnRequest').createTurnRequest({
      sessionId, requestId, binding, message: envelope }).hash });
  f.row.result_json = produced;
  const meta = produced.taskMetadata.boundFilePathSummary;
  meta.operationId = JSON.parse(envelope).operationId;
  meta.traceEventIds = f.traces.map(trace => { trace.event_id = randomUUID(); trace.session_id = sessionId; return trace.event_id; });
  let released = false;
  const agents = { connect: async () => ({ query: async () => ({ rows: [f.row] }), release: () => { released = true; } }) };
  const identity = { query: async (sql, args) => {
    assert.match(sql, /WHERE e.owner_key=\$1 AND e.effect_key=\$2/);
    assert.deepEqual(args, [JSON.stringify(['SecureShopBoundConversation', sessionId]),
      `${requestId}:${JSON.stringify([1, 'read', 'summarizer.summarize_file'])}`]);
    return { rows: [{ run_id: randomUUID(), status: 'completed', run_status: 'completed', generation: '0', live_generation: '0' }] };
  } };
  const input = { ...f, agents, identity,
    conversations: { getTraceEvents: async () => f.traces }, sourceReader: { read: async () => assert.fail('Fixed path must not reopen a source') },
    scope, persona, personaSession, target, mode, sessionId, requestId, message: 'Read records.',
    check, checkAtEffect: check };
  const result = await Evidence.readOriginalFilePathSummary(input);
  assert.equal(released, true); assert.equal(result.candidate, null); assert.equal(result.retained, null);
  assert.equal(result.row, f.row);
  await assert.rejects(Evidence.readOriginalFilePathSummary({ ...input,
    personaSession: { ...personaSession, authorityVersion: '2' } }), assert.AssertionError);
  await assert.rejects(Evidence.readOriginalFilePathSummary({ ...input,
    persona: { ...persona, id: persona.id + 1 } }), assert.AssertionError);
});
