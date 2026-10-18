'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { createMailInlineHttpAdapter } = require('../server/services/secureshopMailInlineHttpAdapter');
const { captureFeatureMode, guardFeatureFence, projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const { digestMcpValue } = require('../server/services/secureshopMcpTrustTools');
const hash = value => createHash('sha256').update(value).digest('hex');
const clone = structuredClone;
async function fixture(mode = 'vuln') {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 };
  const raw = { scope, targetId: randomUUID(), persona: { id: 12, role: 'merchant' },
    personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, mode, operationId: randomUUID() };
  const execution = { runId: randomUUID(), ownerKey: 'owned-summary', durableGeneration: '1', async check() {} };
  const context = { sessionId: randomUUID(), requestId: raw.operationId, execution };
  const token = await captureFeatureMode(null, scope, 'mail', mode);
  const fence = guardFeatureFence({ async assertRemoteAdmission() {} }, token);
  const path = `/image/${randomUUID()}`, url = `http://127.0.0.1:32123${path}`;
  const html = `<p>Owned teaching message</p><img src="${url}">`;
  const selected = { version: 1, kind: 'detail', readOperationId: randomUUID(),
    mailModeCapability: projectFeatureMode(token), receiptSha256: hash('read receipt'),
    recipient: { id: 12, username: 'merchant', email: 'merchant@owned.invalid', role: 'merchant' },
    messageId: 23, messageSha256: hash('original complete mail content'), status: 'complete',
    message: { id: 23, threadId: 23, from: 'sender@owned.invalid', to: 'merchant@owned.invalid',
      subject: 'Owned image', createdAt: '2026-10-13T00:00:00.000Z', sha256: hash('original complete mail content'),
      bodyMarkdown: '', bodyHtml: html, headersRaw: '', sourceBytes: Buffer.byteLength(html), oversized: false } };
  const binding = { issuanceId: randomUUID(), sendOperationId: randomUUID(), targetId: raw.targetId,
    messageId: 23, messageSha256: selected.messageSha256, threadId: 23, recipientId: 12,
    listenerTargetId: randomUUID(), nonceSha256: hash('nonce'), path,
    resourceKind: 'mail_inline_image_v1', urlSha256: hash(url) };
  const source = { selected, binding }, bytes = Buffer.from('{"owned":"image"}');
  const receiptBase = { version: 1, issuanceId: binding.issuanceId, sendOperationId: binding.sendOperationId,
    targetId: binding.targetId, listenerTargetId: binding.listenerTargetId, nonceSha256: binding.nonceSha256,
    path, resourceKind: binding.resourceKind, urlSha256: binding.urlSha256,
    method: 'GET', status: 200, responseSha256: hash(bytes) };
  const receipt = { ...receiptBase, receiptSha256: hash(JSON.stringify(receiptBase)) };
  const events = [], state = { claimed: false, consumed: false, http: 0, source, receipt, bytes,
    async check() {}, async record(record) { return record; } };
  const deps = {
    async resolveSource() { return clone(state.source); },
    async checkCurrent(actual) { assert.deepEqual(actual.scope, raw.scope); await state.check(); },
    targetPool: {
      async assertBound(actual, descriptor) { assert.equal(actual.targetId, binding.targetId); assert.deepEqual(descriptor, binding); events.push('assert'); return { url }; },
      async claimFetch() { if (state.claimed) throw Error('already attempted'); state.claimed = true; events.push('claim'); return { url }; },
      async readReceipt() { if (!state.http || state.consumed) throw Error('no receipt'); events.push('receipt'); return clone(state.receipt); },
      async consume() { events.push('consume'); state.consumed = true; return clone(state.receipt); },
    },
    async recordInvocation(actual, record, receivedFence) { assert.equal(actual.targetId, binding.targetId); assert.equal(receivedFence, fence); events.push('record'); return state.record(record); },
    async fetchImpl(actual, options) {
      assert.equal(actual, url); assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'error');
      assert.equal(options.credentials, 'omit'); assert.ok(options.signal); state.http++; events.push('http');
      const response = new Response(state.bytes, { status: 200 }); Object.defineProperty(response, 'url', { value: url }); return response;
    },
  };
  const adapter = createMailInlineHttpAdapter(deps);
  async function invoke() { const pool = await adapter.createToolPool(raw, context, fence); return pool.callTool('email', 'summarize_thread', {}, { callId: 'summary-call' }); }
  const packet = result => ({ binding: raw, sessionId: context.sessionId, requestId: context.requestId, run: execution,
    observation: { tool: 'email.summarize_thread', args: {}, step: 2, callId: 'summary-call', result,
      effectReceipt: { version: 1, status: 'completed', runId: execution.runId, ownerKey: execution.ownerKey,
        generation: '1', effectKey: `${context.requestId}:${JSON.stringify([2, 'summary-call', 'email.summarize_thread'])}` } } });
  return { raw, context, fence, source, binding, receipt, state, deps, events, adapter, invoke, packet, url };
}
test('one owned GET joins separate issuance and summary IDs and persists three digest domains before consume', async () => {
  const f = await fixture(), result = await f.invoke();
  assert.notEqual(f.binding.issuanceId, f.context.requestId);
  assert.notEqual(f.binding.sendOperationId, f.context.requestId);
  const completed = await f.adapter.observeExternalTool(f.packet(result), f.fence);
  assert.equal(f.state.http, 1); assert.equal(f.state.consumed, true);
  assert.ok(f.events.indexOf('record') < f.events.indexOf('consume'));
  const record = completed.invocation, parsed = JSON.parse(result.content[0].text);
  assert.equal(record.parsedResultSha256, digestMcpValue(parsed));
  assert.equal(record.observationSha256, hash(JSON.stringify(result)));
  assert.equal(record.targetReceipt.responseSha256, hash(f.state.bytes));
  assert.notEqual(record.parsedResultSha256, record.observationSha256);
  assert.deepEqual(record.binding, f.binding);
  await assert.rejects(f.invoke()); assert.equal(f.state.http, 1);
});
test('fixed mode denies before listener claim, GET, record or consumption', async () => {
  const f = await fixture('fixed');
  await assert.rejects(f.invoke(), { code: 'MAIL_INLINE_FIXED_DENIED' });
  assert.deepEqual(f.events, []); assert.equal(f.state.http, 0);
});
test('unbound, foreign, substituted, duplicate-image and issuance-as-summary sources deny before GET', async () => {
  for (const mutate of [
    f => { f.source.binding.targetId = randomUUID(); },
    f => { f.source.binding.messageSha256 = hash('different'); },
    f => { f.source.binding.recipientId = 13; },
    f => { f.source.binding.issuanceId = f.context.requestId; },
    f => { f.source.binding.sendOperationId = f.context.requestId; },
    f => { f.source.binding.urlSha256 = hash('http://example.invalid'); },
    f => { f.source.selected.kind = 'list'; },
    f => { f.source.selected.message.bodyHtml += `<img src="${f.url}">`; f.source.selected.message.sourceBytes = Buffer.byteLength(f.source.selected.message.bodyHtml); },
    f => { f.source.selected.message.bodyHtml = '<img src="http://169.254.169.254/">'; f.source.selected.message.sourceBytes = Buffer.byteLength(f.source.selected.message.bodyHtml); },
  ]) {
    const f = await fixture(); mutate(f); await assert.rejects(f.invoke()); assert.equal(f.state.http, 0);
  }
});
test('redirect, overflow and wrong independent receipt deny without record/consume and cannot redispatch', async () => {
  for (const scenario of ['redirect', 'overflow', 'receipt']) {
    const f = await fixture();
    if (scenario === 'overflow') f.state.bytes = Buffer.alloc(32769);
    if (scenario === 'receipt') f.state.receipt.responseSha256 = hash('not received');
    if (scenario === 'redirect') {
      f.deps.fetchImpl = async () => { f.state.http++; return { status: 302, url: f.url, redirected: true, body: { async cancel() {} } }; };
      f.adapter = createMailInlineHttpAdapter(f.deps);
    }
    const invoke = async () => (await f.adapter.createToolPool(f.raw, f.context, f.fence)).callTool('email', 'summarize_thread', {}, { callId: 'summary-call' });
    await assert.rejects(invoke()); await assert.rejects(invoke());
    assert.equal(f.state.http, 1); assert.equal(f.state.consumed, false); assert(!f.events.includes('record'));
  }
});
test('source or authority changes after HTTP leave receipt unconsumed and reject effect release', async () => {
  for (const drift of ['source', 'authority']) {
    const f = await fixture(); const fetch = f.deps.fetchImpl;
    f.deps.fetchImpl = async (...args) => { const result = await fetch(...args);
      if (drift === 'source') f.source.selected.message.subject = 'changed';
      else f.state.check = async () => { throw Error('retired'); }; return result; };
    const adapter = createMailInlineHttpAdapter(f.deps);
    await assert.rejects(async () => (await adapter.createToolPool(f.raw, f.context, f.fence))
      .callTool('email', 'summarize_thread', {}, { callId: 'summary-call' }));
    assert.equal(f.state.http, 1); assert.equal(f.state.consumed, false);
  }
});
test('completed effect, exact result and receipt hashes are mandatory before durable record', async () => {
  for (const edit of [
    p => { p.observation.effectReceipt.status = 'running'; },
    p => { p.observation.effectReceipt.effectKey = 'foreign'; },
    p => { p.observation.result._meta.summaryRequestId = randomUUID(); },
    p => { p.observation.result._meta.parsedResultSha256 = hash(JSON.stringify(p.observation.result)); },
    p => { p.observation.result._meta.targetReceipt.url = 'forged'; },
  ]) {
    const f = await fixture(), original = f.packet(await f.invoke());
    const packet = { ...original, observation: clone(original.observation) }; edit(packet);
    await assert.rejects(f.adapter.observeExternalTool(packet, f.fence));
    assert(!f.events.includes('record')); assert.equal(f.state.consumed, false);
  }
});
test('durable recording failure or mismatch never consumes and a successful record is checked against current source', async () => {
  for (const scenario of ['throw', 'mismatch', 'reset']) {
    const f = await fixture(), result = await f.invoke();
    f.state.record = async record => {
      if (scenario === 'throw') throw Error('persist failed');
      if (scenario === 'mismatch') return { ...record, summaryRequestId: randomUUID() };
      f.state.check = async () => { throw Error('reset'); }; return record;
    };
    await assert.rejects(f.adapter.observeExternalTool(f.packet(result), f.fence));
    assert.equal(f.state.consumed, false); await assert.rejects(f.invoke()); assert.equal(f.state.http, 1);
  }
});
test('model cannot supply URL/extra args or another tool; absent lifecycle fails construction', async () => {
  const f = await fixture(), pool = await f.adapter.createToolPool(f.raw, f.context, f.fence);
  await assert.rejects(pool.callTool('email', 'summarize_thread', { url: f.url }, { callId: 'x' }));
  await assert.rejects(pool.callTool('email', 'send_reply', {}, { callId: 'x' }));
  assert.equal(f.state.http, 0);
  assert.throws(() => createMailInlineHttpAdapter({ ...f.deps, targetPool: {} }));
});
test('abort before dispatch makes no HTTP call; abort after dispatch never records or consumes', async () => {
  for (const when of ['before', 'after']) {
    const f = await fixture(), controller = new AbortController();
    f.context.execution.signal = controller.signal;
    if (when === 'before') controller.abort(Error('cancelled'));
    else {
      const fetch = f.deps.fetchImpl;
      f.deps.fetchImpl = async (...args) => { const response = await fetch(...args); controller.abort(Error('cancelled')); return response; };
    }
    const adapter = createMailInlineHttpAdapter(f.deps);
    await assert.rejects(async () => (await adapter.createToolPool(f.raw, f.context, f.fence))
      .callTool('email', 'summarize_thread', {}, { callId: 'summary-call' }));
    assert.equal(f.state.http, when === 'before' ? 0 : 1);
    assert.equal(f.state.consumed, false); assert(!f.events.includes('record'));
  }
});
