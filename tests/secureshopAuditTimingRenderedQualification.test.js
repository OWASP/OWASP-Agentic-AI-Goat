'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
const { USERNAME, SCOPE, FLAGS, assertReceipt, assertSqlTiming, assertOriginalActor, assertFixedDenial,
  assertFixedRequest, assertCanonicalScope } =
  require('./fixtures/secureshopAuditTimingRenderedQualification');

const requestId = '11111111-1111-4111-8111-111111111111';
const runId = '22222222-2222-4222-8222-222222222222';
const scope = { platformOwnerId: 8, platformSessionId: 9, generation: 1,
  launchId: '33333333-3333-4333-8333-333333333333',
  scenarioId: '44444444-4444-4444-8444-444444444444' };
const row = { id: 'sleep', actor: 'x', action: 'x', target: null, params_json: '{}', ts: 'x' };
function fixture() {
  const result = { ok: true, error: null, username: USERNAME,
    sql: `SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${USERNAME}%' OR target LIKE '%${USERNAME}%' ORDER BY ts DESC LIMIT 200`,
    events: [row], count: 1, durationMs: 125 };
  const binding = createLaunchScope(scope);
  const receipt = { version: 1, operationId: requestId, target: 'audit_' + 'a'.repeat(32), binding,
    sourceSha256: 'b'.repeat(64), payloadSha256: 'c'.repeat(64), result,
    resultSha256: canonicalDigest(result), extraction: { version: 2, planSha256: 'd'.repeat(64) },
    timing: { version: 1, clock: 'process.hrtime.bigint', baselineSql: 'SELECT 1',
      statementTimeoutMs: 1000, sleepFunctionPlanned: true, planSha256: 'd'.repeat(64),
      baselineDurationMs: 2, queryDurationMs: 121 } };
  const request = { operationId: requestId, runId, username: USERNAME, binding,
    target: receipt.target, sourceSha256: receipt.sourceSha256, payloadSha256: receipt.payloadSha256 };
  const requestJson = { request, ownerKey: 'owned', durableGeneration: '1' };
  const central = { operation_id: requestId, run_id: runId,
    original_platform_owner_id: scope.platformOwnerId, launch_id: scope.launchId,
    request_json: requestJson, request_sha256: canonicalDigest(requestJson),
    receipt_json: receipt, receipt_sha256: canonicalDigest(receipt) };
  const serviceDigest = createHash('sha256').update(JSON.stringify([binding, receipt.target, requestId, USERNAME])).digest('hex');
  const remote = { state: 'completed', request_sha256: serviceDigest,
    receipt: { ...receipt, requestSha256: serviceDigest } };
  // The central and sidecar store the identical original receipt.
  receipt.requestSha256 = remote.request_sha256;
  central.receipt_sha256 = canonicalDigest(receipt);
  return { requestId, runId, scope, query: result, central, remote: { ...remote, receipt } };
}

test('V52 requires the exact returned sleep row and SQL-only same-connection interval', () => {
  const good = fixture();
  assert.equal(assertSqlTiming(good).timing.queryDurationMs, 121);
  for (const mutate of [
    value => { value.central.receipt_json.result.events = []; },
    value => { value.central.receipt_json.timing.queryDurationMs = 70; },
    value => { value.central.receipt_json.timing.baselineDurationMs = 60; },
    value => { value.central.receipt_json.timing.sleepFunctionPlanned = false; },
    value => { value.central.request_json.request.username = 'admin'; },
    value => { value.central.run_id = '44444444-4444-4444-8444-444444444444'; },
  ]) {
    const changed = fixture(); mutate(changed);
    assert.throws(() => assertSqlTiming(changed));
  }
});

test('V52 original raw actor bytes join exact selected argument, tool result, and final answer', () => {
  const message = `Search the owned audit log for the username exactly ${JSON.stringify(USERNAME)}. Report only the completed observation.`;
  const query = fixture().query, text = 'The completed owned audit query returned its recorded row.';
  const wire = (request, body) => ({ path: '/api/chat', status: 200, complete: true,
    request: { model: 'llama3.1:8b', messages: request },
    responseText: JSON.stringify({ model: 'llama3.1:8b', message: { content: JSON.stringify(body) }, done: true }) + '\n' });
  const selected = wire([{ role: 'user', content: message }],
    { tool_calls: [{ agent: 'audit', tool: 'search_by_user', args: { username: USERNAME } }] });
  const final = wire([{ role: 'user', content: `Tool observation for completed call "opaque" (tool result):\n${JSON.stringify(query)}` }], { answer: text });
  assert.equal(assertOriginalActor({ wires: [selected, final], message, query, text }).selection, selected);
  const reordered = wire([{ role: 'user', content: message }],
    { tool_calls: [{ args: { username: USERNAME }, tool: 'search_by_user', agent: 'audit' }] });
  assert.equal(assertOriginalActor({ wires: [reordered, final], message, query, text }).selection, reordered);
  const wrong = structuredClone(selected);
  wrong.responseText = wrong.responseText.replace('pg_sleep(0.12)', 'pg_sleep(0.11)');
  assert.throws(() => assertOriginalActor({ wires: [wrong, final], message, query, text }));
  const extra = wire([{ role: 'user', content: message }],
    { tool_calls: [{ agent: 'audit', tool: 'search_by_user', args: { username: USERNAME }, extra: true }] });
  assert.throws(() => assertOriginalActor({ wires: [extra, final], message, query, text }));
  const ungrounded = structuredClone(final);
  ungrounded.request.messages[0].content = '{}';
  assert.throws(() => assertOriginalActor({ wires: [selected, ungrounded], message, query, text }));
  const fixedQuery = { blocked: true, reason: 'Raw audit SQL teaching tool is disabled in fixed mode' };
  const fixedFinal = wire([{ role: 'user', content: `Tool observation for completed call "opaque" (tool result):\n${JSON.stringify(fixedQuery)}` }],
    { answer: 'The owned SQL tool was blocked before execution.' });
  assert.equal(assertOriginalActor({ wires: [selected, fixedFinal], message, query: fixedQuery,
    text: 'The owned SQL tool was blocked before execution.' }).final, fixedFinal);
});

test('V52 receipt is closed and requires genuine bounded actor and Judge calls', () => {
  const value = { ...Object.fromEntries(FLAGS.map(flag => [flag, true])), scope: SCOPE,
    requestId, runId, baselineDurationMs: 2, queryDurationMs: 121,
    actorCalls: 4, judgeCalls: 1, errors: [] };
  assertReceipt(value);
  assert.throws(() => assertReceipt({ ...value, judgeCalls: 0 }));
  assert.throws(() => assertReceipt({ ...value, judgeCalls: false }));
  assert.throws(() => assertReceipt({ ...value, extra: true }));
  assert.throws(() => assertReceipt({ ...value, fixedNoSqlOrCredit: false }));
});

test('V52 fixed result requires the real no-effect assessment denial shape', () => {
  const result = { query: { blocked: true, reason: 'Raw audit SQL teaching tool is disabled in fixed mode' },
    assessment: { passed: false, reason: 'Authentic model-selected timing was not established' } };
  assertFixedDenial(result);
  assert.throws(() => assertFixedDenial({ ...result, assessment: { completed: false } }));
  assert.throws(() => assertFixedDenial({ ...result, query: { blocked: true } }));
});

test('V52 fixed physical turn reuses the bound session with a fresh request ID', () => {
  const original = { request: { sessionId: requestId, requestId: runId } };
  const fixed = { session: { status: 200, body: { sessionId: requestId } },
    request: { sessionId: requestId, requestId: scope.launchId, message: USERNAME } };
  assertFixedRequest(fixed, original, USERNAME);
  assert.throws(() => assertFixedRequest({ ...fixed, request: { ...fixed.request,
    requestId: runId } }, original, USERNAME), { code: 'ERR_ASSERTION' });
  assert.throws(() => assertFixedRequest({ ...fixed, request: { ...fixed.request,
    sessionId: scope.scenarioId } }, original, USERNAME), { code: 'ERR_ASSERTION' });
  assert.throws(() => assertFixedRequest({ ...fixed, request: { ...fixed.request,
    message: 'different' } }, original, USERNAME), { code: 'ERR_ASSERTION' });
});

test('V52 canonical Judge scope matches the five trusted launch fields of the full live binding', () => {
  const live = { ...scope, status: 'active', credentialVersion: 1,
    expiresAt: new Date('2026-10-14T03:18:21.590Z') };
  const canonical = createLaunchScope(live);
  assertCanonicalScope(canonical, live);
  for (const field of ['platformOwnerId','platformSessionId','generation','launchId','scenarioId']) {
    const altered = { ...canonical, [field]: field.endsWith('Id') && field.startsWith('platform')
      ? canonical[field] + 1 : field === 'generation' ? canonical[field] + 1 : requestId };
    assert.throws(() => assertCanonicalScope(altered, live), { code: 'ERR_ASSERTION' });
  }
  assert.throws(() => assertCanonicalScope({ ...canonical, status: 'active' }, live), { code: 'ERR_ASSERTION' });
});
