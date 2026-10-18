'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { createBoundAuditChat, auditSearchOperationId, boundedAuditObservation, MAX_OBSERVATION_BYTES } = require('../server/services/secureshopBoundAuditChat');
const { createAuditManualRepository } = require('../server/database/postgres/secureshopAuditManualRepository');
const { createOwnedAuditManualAdapter, witnessFor } = require('../server/services/secureshopOwnedAuditManualAdapter');
const { createOwnedAuditSearchApplication } = require('../server/services/secureshopOwnedAuditSearchApplication');
const { createFeatureModeAuthority } = require('../server/services/secureshopFeatureModeAuthority');
const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 7, platformSessionId: 8 };
const persona = { id: 9, role: 'admin' }, personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
const context = { scope, persona, personaSession };
const source = { sessionId: randomUUID(), requestId: randomUUID() }, origin = { step: 2, callId: 'sql-1' };
const token = 'private-credential-not-a-journal-field';
const selected = { target: 'audit_' + 'a'.repeat(32), sourceSha256: 'b'.repeat(64), payloadSha256: 'c'.repeat(64) };
function fixture() {
  const rows = new Map(), remote = new Map(), calls = [], sqlValues = [];
  let mode = 'vuln', revoked = false, lost = false, noReceipt = false, lastManual;
  const check = async () => { if (revoked) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
  const personaAuth = { async authenticateBoundToken(input) { await check(); assert.equal(input.token, token); return { user: persona, ...personaSession }; } };
  const pool = { async connect() { return { release() {}, async query(sql, values = []) {
    sqlValues.push(structuredClone(values));
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql)) return { rows: [], rowCount: 0 };
    if (sql.startsWith('SELECT') && sql.includes('FROM identity.secureshop_authority_owners')) return { rows: [{ is_active: true }] };
    if (sql.includes('FROM identity.secureshop_authority_sessions')) return { rows: [{ user_id: 7, is_active: true, expires_at: new Date('2099-01-01') }] };
    if (sql.includes('FROM identity.secureshop_launches')) return { rows: [{ launch_id: scope.launchId, status: 'active', expires_at: new Date('2099-01-01'), original_platform_owner_id: 7, platform_session_id: 8, scenario_id: scope.scenarioId, generation: 1 }] };
    if (sql.includes('clock_timestamp() AS now')) return { rows: [{ now: new Date('2026-01-01') }] };
    if (sql.includes('FROM identity.secureshop_audit_query_operations')) return { rows: [], rowCount: 0 };
    if (sql.startsWith('SELECT') && sql.includes('secureshop_audit_manual_operations')) {
      const row = rows.get(values[0]);
      const matches = row && (values.length === 1 || row.request_json.binding.launchId === values[1] && row.request_json.binding.platformOwnerId === values[2]);
      return { rows: matches ? [structuredClone(row)] : [], rowCount: matches ? 1 : 0 };
    }
    if (sql.startsWith('INSERT INTO identity.secureshop_audit_manual_operations')) {
      calls.push('begin'); rows.set(values[0], { request_sha256: values[3], request_json: structuredClone(values[4]), receipt_json: null, receipt_sha256: null }); return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith('UPDATE identity.secureshop_audit_manual_operations')) {
      calls.push('complete'); Object.assign(rows.get(values[0]), { receipt_json: structuredClone(values[1]), receipt_sha256: values[2] }); return { rows: [], rowCount: 1 };
    }
    throw Error('Unexpected controlled SQL: ' + sql);
  } }; } };
  const repository = createAuditManualRepository({ pool, personaAuth });
  const client = {
    async target() { calls.push('target'); return selected; },
    async provision() { throw Error('No provisioning in this existing-target fixture'); },
    async search(body) {
      calls.push('search');
      const sql = `SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${body.username}%' OR target LIKE '%${body.username}%' ORDER BY ts DESC LIMIT 200`;
      const result = { ok: true, username: body.username, sql, count: 1, events: [{ id: 'owned-row', actor: body.username, action: 'login' }], error: null, durationMs: 1 };
      const receipt = { version: 1, ...body, ...selected,
        requestSha256: createHash('sha256').update(JSON.stringify([body.binding, selected.target, body.operationId, body.username])).digest('hex'), resultSha256: canonicalDigest(result), result };
      // The real remote envelope has username only in result, never alongside the receipt.
      delete receipt.username;
      remote.set(body.operationId, receipt);
      if (lost) throw Object.assign(Error('lost ACK'), { code: 'AUDIT_SERVICE_UNAVAILABLE' });
      return receipt;
    },
    async receipt(body) { calls.push('receipt'); if (noReceipt || !remote.has(body.operationId)) throw Object.assign(Error('unknown'), { code: 'AUDIT_QUERY_UNCERTAIN' }); return structuredClone(remote.get(body.operationId)); },
  };
  const adapter = createOwnedAuditManualAdapter({ repository, client });
  const manualAdapter = { ...adapter, async execute(...args) { lastManual = await adapter.execute(...args); return lastManual; } };
  const modeAuthority = createFeatureModeAuthority({ progress: { getEvaluationScope: async () => ({ mode, generation: 0, modeStamp: mode }) }, launches: { assertCurrent: check } });
  const app = createOwnedAuditSearchApplication({ launches: { assertCurrent: check }, personaAuth, modeAuthority,
    personaAuthority: { capture: async input => ({ binding: { ...input.scope, personaId: input.personaId, role: input.role, sessionId: input.sessionId, authorityVersion: input.authorityVersion }, assertRemoteAdmission: check, withPersonaEffect: async work => work({}) }) },
    client, manualAdapter, journal: { claim() {}, complete() {}, markUncertain() {} } });
  const admin = { async audit(input) { calls.push('list'); assert.deepEqual(input.scope, scope); return { count: 1, events: [{ actor: input.query.actor, params_json: '{"untrusted":"raw text"}' }], hasMore: false, nextCursor: null }; } };
  const chat = createBoundAuditChat({ admin, getAuditSearch: () => app });
  const input = { context, token, source, origin, username: "admin' UNION SELECT 'owned' --" };
  return { chat, app, repository, calls, rows, remote, sqlValues, input, setMode(value) { mode = value; }, revoke() { revoked = true; }, loseAck() { lost = true; }, noReceipt() { noReceipt = true; }, get witness() { return witnessFor(lastManual); } };
}
test('audit chat SQL preserves raw bytes, deterministic operation and manual provenance; exact reads/replay do not query again', async () => {
  const f = fixture();
  const saved = await f.chat.search(f.input);
  assert.equal(saved.operationId, auditSearchOperationId(context, source, origin)); assert.equal(saved.status, 'completed');
  assert.equal(saved.result.username, f.input.username); assert.ok(saved.result.sql.includes(f.input.username));
  assert.deepEqual(saved.source, { sourceSha256: selected.sourceSha256, payloadSha256: selected.payloadSha256 });
  assert.equal(saved.modeCapability.featureId, 'audit'); assert.equal(f.witness.decisionSource, 'manual'); assert.equal(f.witness.modelProvenance, false);
  const reread = await f.chat.read({ context, token, operationId: saved.operationId });
  assert.deepEqual(reread, saved); assert.deepEqual(await f.chat.search(f.input), saved);
  assert.equal(f.calls.filter(x => x === 'search').length, 1);
  assert.equal(JSON.stringify([...f.rows.values()]).includes(token), false); assert.equal(JSON.stringify(f.sqlValues).includes(token), false); assert.equal(JSON.stringify(saved).includes(token), false);
  await assert.rejects(f.chat.search({ ...f.input, username: 'changed' }), { code: 'AUDIT_QUERY_CONFLICT' });
});
test('lost remote ACK recovers exact durable receipt without query/provision or another model', async () => {
  const f = fixture(); f.loseAck();
  await assert.rejects(f.chat.search(f.input), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' });
  const before = [...f.calls];
  const saved = await f.chat.read({ context, token, operationId: auditSearchOperationId(context, source, origin) });
  assert.equal(saved.status, 'completed'); assert.equal(saved.result.username, f.input.username);
  assert.deepEqual(f.calls.slice(before.length), ['receipt','complete']);
});
test('missing and unfinished operations stay honest and never dispatch SQL', async () => {
  const f = fixture(), operationId = auditSearchOperationId(context, source, origin);
  assert.equal((await f.chat.read({ context, token, operationId })).status, 'not_found'); assert.deepEqual(f.calls, []);
  f.loseAck(); await assert.rejects(f.chat.search(f.input)); f.noReceipt();
  const before = [...f.calls];
  assert.equal((await f.chat.read({ context, token, operationId })).status, 'unconfirmed');
  assert.deepEqual(f.calls.slice(before.length), ['receipt']);
});
test('the source guard runs after ledger begin and blocks remote search on changed authority', async () => {
  const f = fixture();
  await assert.rejects(f.chat.search({ ...f.input, beforeEffect: async () => { if (f.calls.at(-1) === 'begin') throw Object.assign(Error('scene changed'), { code: 'SHOP_SCENE_STALE' }); } }), { code: 'SHOP_SCENE_STALE' });
  assert.equal(f.calls.includes('search'), false); assert.equal(f.rows.size, 1);
});
test('fixed mode blocks before target/admission and readback never reopens vulnerable data', async () => {
  const f = fixture(); f.setMode('fixed');
  const result = await f.chat.search(f.input); assert.equal(result.status, 'blocked'); assert.equal(result.modeCapability.effectiveMode, 'fixed');
  assert.deepEqual(f.calls, []); assert.equal(f.rows.size, 0);
  assert.equal((await f.chat.read({ context, token, operationId: result.operationId })).status, 'blocked'); assert.deepEqual(f.calls, []);
});
test('token persona session substitution and revoked authority fail before query/readback', async () => {
  const f = fixture(), operationId = auditSearchOperationId(context, source, origin);
  const foreign = { ...context, personaSession: { ...personaSession, sessionId: randomUUID() } };
  await assert.rejects(f.chat.search({ ...f.input, context: foreign }), { code: 'SHOP_AUTH_INVALID' });
  await assert.rejects(f.chat.read({ context: foreign, token, operationId }), { code: 'SHOP_AUTH_INVALID' });
  assert.deepEqual(f.calls, []);
  f.revoke(); await assert.rejects(f.chat.read({ context, token, operationId }), { code: 'SHOP_AUTH_INVALID' });
});
test('exact repository read denies retained request/hash/receipt substitutions', async () => {
  for (const mutate of [row => { row.request_json.persona.id++; }, row => { row.request_sha256 = '0'.repeat(64); }, row => { row.receipt_json.operationId = randomUUID(); row.receipt_sha256 = canonicalDigest(row.receipt_json); }]) {
    const f = fixture(), saved = await f.chat.search(f.input); mutate(f.rows.get(saved.operationId));
    await assert.rejects(f.chat.read({ context, token, operationId: saved.operationId }));
  }
});
test('list reuses scoped query validation and preserves raw source strings', async () => {
  const f = fixture(); const page = await f.chat.list({ context, query: { limit: 5, actor: 'admin', action: 'login', from: '2026-10-01' } });
  assert.equal(page.events[0].actor, 'admin'); assert.equal(page.events[0].params_json, '{"untrusted":"raw text"}');
  for (const query of [{ ownerId: 7 }, { from: '2026-02-30' }, { actor: 'x'.repeat(513) }]) await assert.rejects(f.chat.list({ context, query }));
  assert.equal(f.calls.filter(x => x === 'list').length, 1);
});
test('operation domain and bounds are closed; abort and oversize fail before remote calls', async () => {
  const f = fixture();
  assert.notEqual(auditSearchOperationId(context, source, origin), auditSearchOperationId(context, source, { ...origin, callId: 'sql-2' }));
  for (const other of [{ ...context, scope: { ...scope, generation: 2 } }, { ...context, persona: { id: 10, role: 'admin' } }, { ...context, personaSession: { ...personaSession, sessionId: randomUUID() } }, { ...context, personaSession: { ...personaSession, authorityVersion: '2' } }]) assert.notEqual(auditSearchOperationId(context, source, origin), auditSearchOperationId(other, source, origin));
  assert.throws(() => auditSearchOperationId(context, { ...source, other: 1 }, origin));
  await assert.rejects(f.chat.search({ ...f.input, username: 'x'.repeat(8193) }));
  const c = new AbortController(); c.abort(); await assert.rejects(f.chat.search({ ...f.input, signal: c.signal })); assert.deepEqual(f.calls, []);
});

test('stale source is rejected before target lookup or provisioning', async () => {
  const f = fixture();
  await assert.rejects(f.chat.search({ ...f.input, beforeEffect: async () => { throw Object.assign(Error('stale scene'), { code: 'SHOP_SCENE_STALE' }); } }), { code: 'SHOP_SCENE_STALE' });
  assert.deepEqual(f.calls, []); assert.equal(f.rows.size, 0);
});

test('audit mode change during the late source guard prevents SQL dispatch', async () => {
  const f = fixture();
  await assert.rejects(f.chat.search({ ...f.input, beforeEffect: async () => { if (f.calls.at(-1) === 'begin') f.setMode('fixed'); } }));
  assert.equal(f.calls.includes('search'), false);
});


test('bounded audit observation preserves exact raw result and canonical source attribution', async () => {
  const f = fixture(), saved = await f.chat.search(f.input);
  saved.result.events[0].params_json = { raw: '<script>teaching()</script>', annotation: ['original', { nested: true }] };
  const observation = boundedAuditObservation(saved);
  assert.deepEqual(observation, { version: 1, kind: 'audit.sql_search', operationId: saved.operationId,
    status: 'completed', resultSha256: canonicalDigest(saved.result), resultBytes: Buffer.byteLength(JSON.stringify(saved.result)),
    count: 1, ok: true, source: saved.source, modeCapability: saved.modeCapability, oversized: false, result: saved.result });
  assert.equal(JSON.stringify(observation).includes(token), false);
  observation.result.events[0].actor = 'changed local copy';
  assert.equal(saved.result.events[0].actor, f.input.username);
  const reverseKeys = value => Array.isArray(value) ? value.map(reverseKeys) : value && typeof value === 'object'
    ? Object.fromEntries(Object.entries(value).reverse().map(([key, entry]) => [key, reverseKeys(entry)])) : value;
  const reordered = boundedAuditObservation(reverseKeys(saved));
  assert.equal(reordered.resultSha256, canonicalDigest(saved.result));
  assert.equal(reordered.resultBytes, Buffer.byteLength(JSON.stringify(saved.result)));
  const changed = structuredClone(saved); changed.result.events[0].params_json.annotation.reverse();
  assert.notEqual(boundedAuditObservation(changed).resultSha256, reordered.resultSha256);
});

test('oversized observation binds the entire result without truncation or replacing full readback', async () => {
  const f = fixture(), saved = await f.chat.search(f.input);
  const row = f.rows.get(saved.operationId);
  row.receipt_json.result.events[0].raw = '界'.repeat(9000);
  row.receipt_json.resultSha256 = canonicalDigest(row.receipt_json.result);
  row.receipt_sha256 = canonicalDigest(row.receipt_json);
  const full = await f.chat.read({ context, token, operationId: saved.operationId });
  const observation = boundedAuditObservation(full);
  assert.equal(observation.oversized, true); assert.equal(observation.result, null);
  assert.equal(observation.resultSha256, canonicalDigest(full.result));
  assert.equal(observation.resultBytes, Buffer.byteLength(JSON.stringify(full.result)));
  assert.equal(observation.count, 1); assert.equal(observation.ok, true);
  assert.ok(Buffer.byteLength(JSON.stringify(observation)) <= MAX_OBSERVATION_BYTES);
  assert.deepEqual(await f.chat.read({ context, token, operationId: saved.operationId }), full);
  assert.equal(f.calls.filter(x => x === 'search').length, 1);
});

test('observation limit covers descriptor overhead and oversized query failures stay failures', async () => {
  const f = fixture(), saved = await f.chat.search(f.input);
  saved.result.events = []; saved.result.count = 0; saved.result.ok = false; saved.result.error = '';
  const base = boundedAuditObservation(saved);
  const padding = MAX_OBSERVATION_BYTES - Buffer.byteLength(JSON.stringify(base));
  saved.result.error = 'x'.repeat(padding - 5);
  assert.equal(boundedAuditObservation(saved).oversized, false);
  saved.result.error += 'x'.repeat(10);
  assert.ok(Buffer.byteLength(JSON.stringify(saved.result)) < MAX_OBSERVATION_BYTES);
  const large = boundedAuditObservation(saved);
  assert.equal(large.oversized, true); assert.equal(large.result, null); assert.equal(large.ok, false);
  assert.equal(large.count, 0); assert.equal(large.resultSha256, canonicalDigest(saved.result));
});

test('noncompleted audit observations preserve blocked and uncertain states without invented data', async () => {
  const f = fixture(), operationId = auditSearchOperationId(context, source, origin);
  const missing = await f.chat.read({ context, token, operationId });
  for (const status of ['not_found', 'unconfirmed']) {
    const value = boundedAuditObservation({ ...missing, status });
    assert.equal(value.status, status);
    for (const key of ['resultSha256', 'count', 'ok', 'source', 'result']) assert.equal(value[key], null);
    assert.equal(value.resultBytes, 0); assert.equal(value.oversized, false);
  }
  f.setMode('fixed'); const blocked = await f.chat.read({ context, token, operationId });
  const value = boundedAuditObservation(blocked);
  assert.equal(value.status, 'blocked'); assert.equal(value.reason, blocked.reason); assert.equal(value.ok, null);
  assert.throws(() => boundedAuditObservation({ ...blocked, reason: 'x'.repeat(MAX_OBSERVATION_BYTES) }), { code: 'AUDIT_CHAT_INVALID' });
});

test('bounded observation rejects malformed full envelopes instead of legitimizing them with a digest', async () => {
  const f = fixture(), saved = await f.chat.search(f.input);
  for (const mutate of [value => { value.operationId = 'invalid'; }, value => { value.extra = true; },
    value => { value.result.count++; }, value => { value.source.sourceSha256 = 'invalid'; },
    value => { value.modeCapability.scope.id = 'other'; }, value => { value.result.extra = true; }]) {
    const changed = structuredClone(saved); mutate(changed);
    assert.throws(() => boundedAuditObservation(changed), { code: 'AUDIT_CHAT_INVALID' });
  }
});
