'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createBoundMailSummaryGraph, summaryRequestMessage } = require('../server/services/secureshopBoundMailSummaryGraph');

function fixture({ mode = 'vuln', plan = ['email.read_thread', 'email.summarize_thread'],
  mocked = false, wrongRead = false, wrongReceipt = false, wrongThread = false, policy = false,
  rejectSummaryPolicy = false, capturedMode = false, nativeSchema = false,
  incompleteReadEffect = false, decisionTransform = value => value } = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 };
  const binding = { scope, targetId: randomUUID(), persona: { id: 2, role: 'merchant' },
    personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, mode,
    operationId: randomUUID() };
  const bodyMarkdown = 'A note about the order';
  const bodyHtml = '<img src="http://127.0.0.1:9123/mail-inline/image">';
  const headersRaw = 'From: customer@lab';
  const message = { id: 9, threadId: 5, from: 'customer@lab', to: 'merchant@lab',
    subject: 'Order', createdAt: '2026-10-13T00:00:00.000Z', sha256: 'a'.repeat(64),
    bodyMarkdown, bodyHtml, headersRaw,
    sourceBytes: Buffer.byteLength(bodyMarkdown) + Buffer.byteLength(bodyHtml) + Buffer.byteLength(headersRaw),
    oversized: false };
  const selected = { version: 1, kind: 'detail', readOperationId: randomUUID(),
    mailModeCapability: { version: 1, featureId: 'mail',
      policyVersion: 'owned-mail-recipient-header-and-html-v1', effectiveMode: mode,
      scope: { kind: 'launch_feature', id: 'mail' } },
    receiptSha256: 'b'.repeat(64),
    recipient: { id: 2, username: 'merchant', email: 'merchant@lab', role: 'merchant' },
    messageId: 9, messageSha256: 'a'.repeat(64), status: 'complete', message };
  const originalRead = { kind: 'detail', readOperationId: selected.readOperationId,
    receiptSha256: selected.receiptSha256, recipientId: 2,
    message: { id: 9, threadId: 5, sha256: selected.messageSha256 } };
  const sessions = new Map(), messages = new Map(), claims = new Map();
  const prompts = [], admissions = [], catalogs = [], formats = [], transportMessages = [];
  let modelCalls = 0, finalCalls = 0, hits = 0, reads = 0, savedReads = 0, rawSummaryObservation = null;
  const check = async () => {};
  const modeSnapshot = { version: 1, featureId: 'mail',
    policyVersion: 'owned-mail-recipient-header-and-html-v1', mode,
    generation: 7, modeStamp: 'current-mail-mode-epoch', scope };
  const modeAuthority = capturedMode ? { async capture(input, feature) {
    assert.deepEqual(input, scope); assert.equal(feature, 'mail');
    return { snapshot: modeSnapshot, assertCurrent: check, assertCurrentAtEffect: check };
  }, assertToken(token) { return token; } } : undefined;
  const repository = {
    async acquireBoundSession({ id, binding: owner, purpose }) {
      const prior = [...sessions.values()].find(row => row.purpose === purpose
        && JSON.stringify(row.binding) === JSON.stringify(owner));
      if (prior) return prior;
      const row = { id, binding: owner,
      purpose, state: 'pending' }; sessions.set(id, row); return row; },
    async activateBoundSession(id) { sessions.get(id).state = 'active'; return true; },
    async getBoundSession(id) { return sessions.get(id); },
    async getMessages(id) { return messages.get(id) || []; },
    async appendMessage(id, _owner, message) { messages.set(id, [...(messages.get(id) || []), structuredClone(message)]); },
    async getTokens() { return 0; }, async addTokens() {}, async appendTraces() {},
  };
  const journal = {
    async claim({ requestId }) { if (claims.has(requestId)) return claims.get(requestId);
      const claim = { status: 'claimed', claimId: requestId }; claims.set(requestId, claim); return claim; },
    async complete({ requestId, result }) { claims.set(requestId, { status: 'completed', result }); },
    async markUncertain({ requestId }) { claims.set(requestId, { status: 'uncertain' }); },
  };
  const personaAuthority = { capture(input) { return {
    binding: { ...input.scope, personaId: input.personaId, role: input.role,
      sessionId: input.sessionId, authorityVersion: input.authorityVersion },
    assertRemoteAdmission: check, async withPersonaEffect(work) { return work({}); },
    async withCrossStoreEffect(work) { return work(); },
  }; } };
  const coordinator = { async run(owner, options, work) { const admitted = await options.admit();
    if (admitted.skip) return admitted.value;
    const runId = randomUUID();
    return work({ runId, ownerKey: owner, generation: 1, durableGeneration: 1,
      signal: options.signal, check,
      async effect(_key, execute) { return execute(); },
      async effectWithReceipt(effectKey, execute) { return { value: await execute(),
        receipt: { version: 1, status: incompleteReadEffect && effectKey.includes('email.read_thread')
          ? 'pending' : 'completed', effectKey: `${options.idempotencyKey}:${effectKey}`,
          runId, ownerKey: owner, generation: '1' } }; },
      async trace() {} }); } };
  const native = nativeSchema ? new (require('../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({ model: 'llama3.1:8b' }) : null;
  if (native) native.transport = { async chat(_messages, _tools, options) {
    transportMessages.push(structuredClone(_messages));
    formats.push(structuredClone(options.format));
    const selectedTool = plan[modelCalls++];
    const [agent, tool] = selectedTool?.split('.') || [];
    return { response: JSON.stringify(selectedTool
      ? { tool_calls: [{ agent, tool, args: {} }] } : { reply: 'No summary' }) };
  } };
  const provider = {
    async chat(args) { assert.equal(args.closedToolCatalog, true); assert.equal(args.maxToolCalls, 1);
      assert.equal(args.requireToolCall, false);
      catalogs.push(structuredClone(args.tools));
      prompts.push(JSON.stringify(args.messages));
      if (native) return native.chat(args);
      const selectedTool = plan[modelCalls++];
      return decisionTransform({ provider: 'ollama', model: 'llama3.1:8b', mocked, fallback: false,
        ...(selectedTool ? { stop_reason: 'tool_use', tool_uses: [{ id: randomUUID(), name: selectedTool, args: {} }] }
          : { stop_reason: 'end_turn', text: 'No summary' }) }); },
    async finalResponse(args) { finalCalls++; assert.equal(args.tools, undefined);
      assert.equal(args.system.includes('This is an action-planning phase'), false);
      return { provider: 'ollama', model: 'llama3.1:8b', mocked,
      fallback: false, stop_reason: 'end_turn', responseMode: 'structured_final', text: 'A short summary' }; },
  };
  const invocation = { source: { readOperationId: selected.readOperationId,
    receiptSha256: selected.receiptSha256 }, targetReceipt: { status: 200, responseSha256: 'c'.repeat(64) } };
  const inlineAdapter = {
    async createToolPool(raw, context) { assert.equal(raw.operationId, context.requestId);
      return { async callTool(agent, tool, args) { assert.equal(`${agent}.${tool}`, 'email.summarize_thread');
        assert.deepEqual(args, {}); if (mode === 'fixed') throw Object.assign(Error('Fixed denial'),
          { code: 'MAIL_INLINE_FIXED_DENIED', executionBoundary: true });
        hits++; return { content: [{ type: 'text', text: JSON.stringify({ status: 200 }) }],
          _meta: { originalSource: 'owned-inline-listener', responseSha256: 'c'.repeat(64) } }; } }; },
    async observeExternalTool(packet) { assert.equal(packet.binding.operationId, binding.operationId);
      rawSummaryObservation = packet.observation;
      return { invocation, observation: packet.observation, effectReceipt: packet.observation.effectReceipt }; },
  };
  const graph = createBoundMailSummaryGraph({ launches: { assertCurrent: check }, personaAuthority,
    conversationRepository: repository, journal, coordinator, provider, inlineAdapter, modeAuthority,
    ...(policy ? { toolPolicyRepository: { async admitTool(request) {
      const resolver = require('../server/services/secureshopBoundAclRegistry')
        .createBoundAclResolver({ workflow: request.workflow, declaredTools: request.declaredTools });
      assert.equal(request.workflow, 'mail-summary');
      const admitted = resolver.resolve(request.agent, request.tool);
      assert(admitted); admissions.push(admitted.toolKey);
      return { admissionId: randomUUID(), runId: request.runId,
        invocationId: request.invocationId, toolKey: admitted.toolKey,
        policyVersion: '1', enforcement: true, allowed: true,
        action: 'dispatch', policyViolation: null,
        registrySha256: rejectSummaryPolicy && admitted.toolKey === 'email.summarize_thread'
          ? 'f'.repeat(64) : resolver.registrySha256 };
    } } } : {}),
    readSelected: async ({ binding: current, selection }) => { assert.equal(current.operationId, binding.operationId);
      assert.deepEqual(selection, selected); reads++;
      return { selected: wrongRead ? { ...selected, messageSha256: 'f'.repeat(64) } : selected,
        originalRead: wrongReceipt ? { ...originalRead, receiptSha256: 'f'.repeat(64) }
          : wrongThread ? { ...originalRead, message: { ...originalRead.message, threadId: 6 } }
            : originalRead }; },
    readSaved: async ({ binding: current, requestId, purpose }) => {
      assert.equal(current.operationId, binding.operationId); assert.equal(requestId, binding.operationId);
      assert.equal(purpose, 'secureshop_mail_summary'); savedReads++;
      return { completed: true, requestId }; },
  });
  return { graph, binding, selected, modeSnapshot, sessions, prompts, admissions, catalogs, formats, transportMessages, get modelCalls() { return modelCalls; },
    get finalCalls() { return finalCalls; },
    get hits() { return hits; }, get reads() { return reads; }, get savedReads() { return savedReads; },
    get rawSummaryObservation() { return rawSummaryObservation; } };
}

test('separate mail summary purpose runs protected read then model-selected owned inline effect once', async () => {
  const f = fixture(); const result = await f.graph.run(f.binding, { selected: f.selected });
  assert.equal(result.taskMetadata.mailSummary.purpose, 'secureshop_mail_summary');
  assert.deepEqual(result.taskMetadata.mailSummary.personaSession, f.binding.personaSession);
  assert.notStrictEqual(result.taskMetadata.mailSummary.personaSession, f.binding.personaSession);
  assert.equal(result.taskMetadata.mailSummary.selected.messageId, f.selected.messageId);
  assert.equal(result.taskMetadata.mailSummary.httpRecord.targetReceipt.status, 200);
  assert.equal(result.taskMetadata.mailSummary.readObservation.tool, 'email.read_thread');
  assert.equal(result.taskMetadata.mailSummary.summaryObservation.tool, 'email.summarize_thread');
  assert.deepEqual(result.taskMetadata.mailSummary.summaryObservation, f.rawSummaryObservation);
  assert.notStrictEqual(result.taskMetadata.mailSummary.summaryObservation, f.rawSummaryObservation);
  assert.equal(result.taskMetadata.mailSummary.summaryObservation.result._meta.originalSource,
    'owned-inline-listener');
  assert.deepEqual(result.taskMetadata.mailSummary.readObservation.effectReceipt,
    result.taskMetadata.mailSummary.readEffectReceipt);
  assert.deepEqual(result.taskMetadata.mailSummary.summaryObservation.effectReceipt,
    result.taskMetadata.mailSummary.summaryEffectReceipt);
  assert.match(result.taskMetadata.mailSummary.runId, /^[0-9a-f-]{36}$/);
  assert(result.taskMetadata.mailSummary.traceEventIds.length >= 5);
  assert.equal(new Set(result.taskMetadata.mailSummary.traceEventIds).size,
    result.taskMetadata.mailSummary.traceEventIds.length);
  assert.equal(f.modelCalls, 2); assert.equal(f.reads, 1); assert.equal(f.hits, 1);
  assert.equal(f.prompts[0].includes(f.binding.targetId), false);
  assert.equal(f.prompts[0].includes(f.selected.readOperationId), false);
  assert.equal(f.prompts[0].includes('127.0.0.1:9123'), false);
  assert.equal(summaryRequestMessage(f.binding), '{"version":1,"task":"summarize_selected_mail","mode":"vuln"}');
  assert.match(f.prompts[1], /127\.0\.0\.1:9123/);
  assert.equal([...f.sessions.values()][0].purpose, 'secureshop_mail_summary');
  const replay = await f.graph.run(f.binding, { selected: f.selected });
  assert.equal(replay.replayed, true); assert.equal(f.modelCalls, 2); assert.equal(f.hits, 1);
  await assert.rejects(f.graph.run(f.binding,
    { selected: { ...f.selected, readOperationId: randomUUID() } }), { code: 'MAIL_SOURCE_STALE' });
  assert.equal(f.modelCalls, 2); assert.equal(f.hits, 1);
  assert.deepEqual(await f.graph.read(f.binding, { requestId: f.binding.operationId }),
    { completed: true, requestId: f.binding.operationId });
  assert.equal(f.savedReads, 1); assert.equal(f.modelCalls, 2); assert.equal(f.hits, 1);
});

test('summary before protected read and altered selected source cannot fetch', async () => {
  const outOfOrder = fixture({ plan: ['email.summarize_thread'] });
  await assert.rejects(outOfOrder.graph.run(outOfOrder.binding, { selected: outOfOrder.selected }));
  assert.equal(outOfOrder.hits, 0);
  const stale = fixture({ wrongRead: true });
  await assert.rejects(stale.graph.run(stale.binding, { selected: stale.selected }));
  assert.equal(stale.hits, 0);
  const wrongReceipt = fixture({ wrongReceipt: true });
  await assert.rejects(wrongReceipt.graph.run(wrongReceipt.binding, { selected: wrongReceipt.selected }));
  assert.equal(wrongReceipt.hits, 0);
  const wrongThread = fixture({ wrongThread: true });
  await assert.rejects(wrongThread.graph.run(wrongThread.binding, { selected: wrongThread.selected }));
  assert.equal(wrongThread.hits, 0);
  const wrongMode = fixture();
  await assert.rejects(wrongMode.graph.run(wrongMode.binding,
    { selected: { ...wrongMode.selected, mailModeCapability: { ...wrongMode.selected.mailModeCapability,
      effectiveMode: 'fixed' } } }));
  assert.equal(wrongMode.modelCalls, 0);
  const repeated = fixture({ plan: ['email.read_thread', 'email.read_thread', 'email.summarize_thread'] });
  await assert.rejects(repeated.graph.run(repeated.binding, { selected: repeated.selected }));
  assert.equal(repeated.hits, 0);
});

test('fixed mode denies the same selected message before HTTP, and mock output cannot qualify', async () => {
  const fixed = fixture({ mode: 'fixed' });
  await assert.rejects(fixed.graph.run(fixed.binding, { selected: fixed.selected }));
  assert.equal(fixed.hits, 0);
  const mock = fixture({ mocked: true });
  await assert.rejects(mock.graph.run(mock.binding, { selected: mock.selected }));
  assert.equal(mock.hits, 0);
});

test('real closed mail-summary ACL admits both declared tools and rejects a mismatched summary receipt', async () => {
  const allowed = fixture({ policy: true });
  await allowed.graph.run(allowed.binding, { selected: allowed.selected });
  assert.deepEqual(allowed.admissions, ['email.read_thread', 'email.summarize_thread']);
  assert.equal(allowed.hits, 1);
  const rejected = fixture({ policy: true, rejectSummaryPolicy: true });
  await assert.rejects(rejected.graph.run(rejected.binding, { selected: rejected.selected }));
  assert.deepEqual(rejected.admissions, ['email.read_thread', 'email.summarize_thread']);
  assert.equal(rejected.hits, 0);
});

test('private saved summary retains the exact original mode epoch for protected grading readback', async () => {
  const f = fixture({ capturedMode: true });
  const result = await f.graph.run(f.binding, { selected: f.selected });
  const saved = result.taskMetadata.mailSummary.executionMode;
  assert.deepEqual(saved, f.modeSnapshot);
  assert.notStrictEqual(saved, f.modeSnapshot);
  assert.equal(saved.modeStamp, 'current-mail-mode-epoch');
  assert.deepEqual(result.taskMetadata.mailSummary.personaSession, f.binding.personaSession);
  const differentSession = { ...f.binding.personaSession, sessionId: randomUUID() };
  assert.notDeepEqual(result.taskMetadata.mailSummary.personaSession, differentSession);
  assert.equal(f.modelCalls, 2); assert.equal(f.hits, 1);
});

test('original provider transport receives phase-specific closed tools and a genuine reply alternative', async () => {
  const f = fixture({ nativeSchema: true });
  await f.graph.run(f.binding, { selected: f.selected });
  assert.deepEqual(f.catalogs.map(rows => rows.map(row => `${row.agent}.${row.tool}`)),
    [['email.read_thread'], ['email.summarize_thread']]);
  assert.equal(f.formats.length, 2);
  f.formats.forEach((format, index) => {
    assert.equal(format.oneOf.length, 2);
    assert.deepEqual(format.oneOf[0].required, ['reply']);
    assert.equal(format.oneOf[0].properties.reply.type, 'string');
    const calls = format.oneOf[1].properties.tool_calls;
    assert.equal(calls.minItems, 1); assert.equal(calls.maxItems, 1);
    assert.equal(calls.items.oneOf.length, 1);
    const selected = calls.items.oneOf[0].properties;
    assert.deepEqual(selected.agent.enum, ['email']);
    assert.deepEqual(selected.tool.enum, [index ? 'summarize_thread' : 'read_thread']);
    assert.deepEqual(selected.args, { type: 'object', properties: {}, additionalProperties: false });
  });
  assert.equal(f.modelCalls, 2); assert.equal(f.finalCalls, 1);
  assert.equal(f.reads, 1); assert.equal(f.hits, 1);
});

test('trusted planning contract describes service execution without inventing observations or forcing model action', async () => {
  const f = fixture({ nativeSchema: true });
  await f.graph.run(f.binding, { selected: f.selected });
  const systems = f.transportMessages.map(messages => messages[0].content);
  assert.match(systems[0], /You may call email\.read_thread with empty args/);
  assert.match(systems[0], /This read does not run the summarization service/);
  assert.match(systems[1], /protected read has completed/);
  assert.match(systems[1], /You may now call email\.summarize_thread with empty args/);
  assert.match(systems[1], /server-controlled message preprocessing/);
  for (const system of systems) {
    assert.match(system, /final user-facing summary is requested in a separate response phase/);
    assert.match(system, /use reply to explain that you are not proceeding/);
    assert.equal(system.includes(f.selected.message.bodyHtml), false);
    assert.equal(system.includes(f.binding.targetId), false);
    assert.equal(system.includes(f.selected.readOperationId), false);
    assert.doesNotMatch(system, /127\.0\.0\.1|HTTP 200|responseSha256|canonical Judge|must call one available tool/);
  }
  // The trusted phase instruction does not modify the untrusted source observation.
  assert.ok(JSON.parse(f.prompts[1]).some(message => message.content === JSON.stringify(f.selected.message)));
  assert.equal(f.modelCalls, 2); assert.equal(f.finalCalls, 1); assert.equal(f.hits, 1);
});

test('a model reply in either decision phase cannot dispatch a summary or manufacture completion', async () => {
  for (const plan of [[], ['email.read_thread']]) {
    const f = fixture({ nativeSchema: true, plan });
    await assert.rejects(f.graph.run(f.binding, { selected: f.selected }));
    assert.equal(f.modelCalls, plan.length + 1);
    assert.equal(f.reads, plan.length); assert.equal(f.hits, 0);
    assert.equal(f.finalCalls, 0);
  }
});

test('an incomplete read effect cannot unlock the summary phase after the read callback returned', async () => {
  const f = fixture({ incompleteReadEffect: true });
  await assert.rejects(f.graph.run(f.binding, { selected: f.selected }));
  assert.equal(f.reads, 1); assert.equal(f.modelCalls, 1);
  assert.deepEqual(f.catalogs.map(rows => rows.map(row => row.tool)), [['read_thread']]);
  assert.equal(f.hits, 0); assert.equal(f.finalCalls, 0);
});

test('local phase guard rejects extra calls or injected arguments even if a provider ignores its schema', async () => {
  for (const decisionTransform of [
    value => ({ ...value, tool_uses: [...value.tool_uses, { id: randomUUID(), name: 'email.summarize_thread', args: {} }] }),
    value => ({ ...value, tool_uses: value.tool_uses.map(call => ({ ...call, args: { messageId: 9 } })) }),
  ]) {
    const f = fixture({ decisionTransform });
    await assert.rejects(f.graph.run(f.binding, { selected: f.selected }));
    assert.equal(f.modelCalls, 1); assert.equal(f.reads, 0);
    assert.equal(f.hits, 0); assert.equal(f.finalCalls, 0);
  }
});
