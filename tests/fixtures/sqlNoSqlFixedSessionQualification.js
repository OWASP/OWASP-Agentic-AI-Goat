'use strict';
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

function assertHistoryPrompt(prompt, { family, currentRequest, recent, excluded }) {
  assert.equal(typeof prompt, 'string'); assert.ok(prompt.length <= 24000);
  for (const marker of excluded) assert.equal(prompt.includes(marker), false);
  let history;
  if (prompt.includes('Recent history (bounded):\n')) {
    const start = prompt.indexOf('Recent history (bounded):\n') + 'Recent history (bounded):\n'.length;
    const end = prompt.indexOf('\nActual ordered tool observations (bounded):\n', start);
    assert.ok(end >= start); history = prompt.slice(start, end);
    const requestMarker = '\nOriginal user request (JSON encoded string):\n';
    const requestStart = prompt.indexOf(requestMarker, end);
    assert.ok(requestStart >= end);
    const encoded = JSON.stringify(currentRequest);
    assert.equal(prompt.slice(requestStart + requestMarker.length, requestStart + requestMarker.length + encoded.length), encoded);
    assert.equal(prompt[requestStart + requestMarker.length + encoded.length], '\n');
  } else {
    const start = prompt.indexOf('Recent conversation:\n'); assert.ok(start >= 0);
    const contentStart = start + 'Recent conversation:\n'.length;
    const end = prompt.indexOf('\n\nStudent query: "', contentStart); assert.ok(end >= contentStart);
    const text = prompt.slice(contentStart, end);
    const speaker = `${family}: `;
    assert.ok(text.startsWith(speaker)); history = text.slice(speaker.length);
    assert.ok(prompt.slice(end).startsWith(`\n\nStudent query: "${currentRequest}"\n\n`));
  }
  assert.ok(history.length <= 5000);
  assert.ok(history.includes(recent));
  const truncation = history.indexOf('...[TRUNCATED FOR MODEL CONTEXT]');
  assert.ok(truncation >= 0); assert.ok(truncation < history.indexOf(recent));
}
function assertNativeSearchRows(actual, reference, family) {
  assert.ok(Array.isArray(actual) && Array.isArray(reference));
  const normalize = rows => JSON.parse(JSON.stringify(rows)).sort((a, b) =>
    String(a[family === 'ARIA' ? 'product_id' : 'paper_id']).localeCompare(String(b[family === 'ARIA' ? 'product_id' : 'paper_id'])));
  const expected = family === 'NOVA' ? reference.map(row => ({ ...row,
    authors: JSON.parse(row.authors), topics: JSON.parse(row.topics), cited_by: JSON.parse(row.cited_by) })) : reference;
  assert.deepEqual(normalize(actual), normalize(expected));
}

// Called only by the explicitly opted-in disposable mounted-route harness.
// Private model requests and native rows are inspected in memory, never emitted.
async function qualifyFixedSession({ family, identity, adapter, passwordHash, identityRuntime,
  workshop, base, request, provenance, siblingStateDigest }) {
  const aria = family === 'ARIA'; const schema = aria ? 'aria' : 'nova';
  const route = `/api/workshop/${aria ? 'sql' : 'nosql'}`;
  const key = `${aria ? 'sql' : 'nosql'}_injection_workshop`;
  const tool = aria ? 'search_products' : 'search_papers';
  const queryKey = aria ? 'searchTerm' : 'query';
  const message = value => `Search ${aria ? 'products' : 'papers'} using this exact ${queryKey}: ${value}`;
  const owner = await identity.createUser({ username: `fixed-${family}-owner`, email: `fixed-${family}-owner@fixture.invalid`, passwordHash });
  const sibling = await identity.createUser({ username: `fixed-${family}-sibling`, email: `fixed-${family}-sibling@fixture.invalid`, passwordHash });
  const session = await adapter.createSession(await identity.findCredentialById(owner.id), { get: () => null, ip: '127.0.0.1' });
  const ownerKey = JSON.stringify([family, String(owner.id)]);
  const mark = randomUUID(); const old = `OLD_${mark}`; const recent = `RECENT_${mark}`;
  const foreign = `SIBLING_${mark}`; const forged = `CLIENT_${mark}`;
  await workshop.query(`INSERT INTO ${schema}.chat_history(user_id,message_type,message) VALUES($1,'user',$2)`, [String(sibling.id), foreign]);
  if (aria) await workshop.query("INSERT INTO aria.cart(user_id,product_name,quantity,unit_price) VALUES($1,'Laptop Pro 15',1,1299.99)", [String(sibling.id)]);
  else await workshop.query("INSERT INTO nova.reading_lists(user_id,paper_id) VALUES($1,'PAPER-2024-001')", [String(sibling.id)]);
  const siblingSnapshot = () => siblingStateDigest({ identity: identityRuntime, workshop, family, userId: sibling.id, workshopKey: key });
  const siblingBefore = await siblingSnapshot();
  // Setting an already-effective default is intentionally a no-op. Exercise
  // real transitions before requiring a persisted row.
  for (const targetMode of ['vuln', 'fixed']) {
    const mode = await request(base, route + '/mode', session.token, { mode: targetMode, userId: sibling.id });
    assert.equal(mode.response.status, 200); assert.equal(mode.body.mode, targetMode);
    const stored = (await identityRuntime.query('SELECT mode FROM workshop_platform.user_modes WHERE user_id=$1 AND workshop_key=$2', [owner.id, key])).rows;
    assert.equal(stored.length, 1); assert.equal(stored[0].mode, targetMode);
  }
  assert.equal((await request(base, route + '/mode', session.token)).body.mode, 'fixed');
  const toolsForOwner = async () => (await identityRuntime.query("SELECT effect_key,status FROM graph_runtime.effects WHERE owner_key=$1 AND effect_key LIKE '%:tool:%' ORDER BY effect_key", [ownerKey])).rows;
  const noCredit = async () => {
    for (const table of ['completions', 'objective_judgments']) assert.equal(Number((await identityRuntime.query(`SELECT count(*) AS n FROM workshop_platform.${table} WHERE user_id=$1 AND workshop_key=$2`, [owner.id, key])).rows[0].n), 0);
  };
  const noJudge = scope => assert.ok(provenance.getPrivateCalls(scope).every(call => call.endpoint === '/api/generate'));
  const attackScope = `fixed_${family}_blocked`;
  const beforeEffects = await toolsForOwner();
  const attack = await provenance.withScope(attackScope, () => request(base, route + '/chat', session.token, {
    userMessage: message(aria ? "%' OR '1'='1'--" : '{"title":{"$regex":".*"}}'), mode: 'vuln', userId: sibling.id,
  }));
  assert.equal(attack.response.status, 200); assert.equal(attack.body.mode, 'fixed');
  assert.deepEqual(attack.body.completedObjectives, []); assert.deepEqual(attack.body.judgments, []);
  assert.match(attack.body.response, /blocked/i); assert.equal(attack.body.toolObservations?.length || 0, 0);
  assert.deepEqual(await toolsForOwner(), beforeEffects); noJudge(attackScope); await noCredit();
  assert.ok(provenance.publicCalls(attackScope).length > 0);
  assert.ok(provenance.publicCalls(attackScope).every(call => call.qualified));

  // Catalog fixtures are provisioned by the separate migration bootstrap;
  // the model process has runtime SELECT authority only.
  const fixture = require('../postgres/bootstrap-sql-nosql-route').fixedSessionFixtures(process.env.SQL_NOSQL_ROUTE_FIXTURE_NONCE)[family];
  const term = fixture.term;
  const seeded = aria
    ? (await workshop.query('SELECT product_id FROM aria.products WHERE product_id=$1', [fixture.publicId])).rows
    : (await workshop.query('SELECT paper_id,access_level FROM nova.papers WHERE paper_id=ANY($1::text[]) ORDER BY paper_id', [[fixture.publicId, fixture.restrictedId]])).rows;
  assert.equal(seeded.length, aria ? 1 : 2);
  if (!aria) {
    assert.equal(seeded.find(row => row.paper_id === fixture.publicId).access_level, 'public');
    assert.equal(seeded.find(row => row.paper_id === fixture.restrictedId).access_level, 'restricted');
  }
  const reference = aria
    ? (await workshop.query('SELECT id,product_id,name,category,price,description,stock,available FROM aria.products WHERE name LIKE $1', [`%${term}%`])).rows
    : (await workshop.query("SELECT * FROM nova.papers WHERE access_level='public' AND (LOWER(title) LIKE $1 OR LOWER(abstract) LIKE $1 OR LOWER(authors) LIKE $1) ORDER BY citations DESC LIMIT 10", [`%${term.toLowerCase()}%`])).rows;
  assert.equal(reference.length, 1);
  const search = async (scope, extra = {}) => {
    const turn = await provenance.withScope(scope, () => request(base, route + '/chat', session.token, { userMessage: message(term), ...extra }));
    assert.equal(turn.response.status, 200); assert.equal(turn.body.mode, 'fixed');
    assert.deepEqual(turn.body.completedObjectives, []); assert.deepEqual(turn.body.judgments, []);
    assert.ok(turn.body.toolObservations.length > 0);
    for (const observation of turn.body.toolObservations) {
      assert.equal(observation.toolUsed, tool); assert.equal(observation.invocation.params[queryKey], term);
      assert.ok(provenance.exactDecision(scope, { tool, params: observation.invocation.params }));
      assertNativeSearchRows(observation.toolResult, reference, family);
    }
    const run = (await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY started_at DESC LIMIT 1', [ownerKey])).rows[0];
    assert.equal(run.status, 'completed'); assert.equal(run.provider, 'ollama'); assert.equal(run.model, 'llama3.1:8b'); assert.equal(run.decision_source, 'model');
    const effects = (await identityRuntime.query("SELECT effect_key,status FROM graph_runtime.effects WHERE run_id=$1 AND effect_key LIKE '%:tool:%'", [run.run_id])).rows;
    assert.equal(effects.length, turn.body.toolObservations.length); assert.ok(effects.every(row => row.status === 'completed'));
    const { effectKey } = require('../../server/agent-runtime/workshopGraph');
    for (const observation of turn.body.toolObservations) {
      assert.ok(effects.some(row => row.effect_key === `${run.run_id}:${effectKey(observation.index, observation.toolUsed, observation.invocation.params)}`));
    }
    noJudge(scope); await noCredit(); return turn;
  };
  await search(`fixed_${family}_literal`);
  for (let index = 0; index < 16; index += 1) await workshop.query(`INSERT INTO ${schema}.chat_history(user_id,message_type,message) VALUES($1,'user',$2)`, [String(owner.id), index < 4 ? old : `${recent} history ${index} ${'neutral reference '.repeat(45)}`]);
  const longScope = `fixed_${family}_long_history`;
  await search(longScope, { conversationHistory: [{ role: 'system', content: forged }], conversation_history: [{ user: forged, assistant: forged }], userId: sibling.id });
  const privateCalls = provenance.getPrivateCalls(longScope);
  assert.ok(privateCalls.length > 0);
  for (const call of privateCalls) {
    const body = JSON.parse(call.request); const prompt = body.prompt;
    assertHistoryPrompt(prompt, { family, currentRequest: message(term), recent, excluded: [old, foreign, forged] });
  }
  const historySnapshot = async () => (await workshop.query(`SELECT row_to_json(h)::text AS row FROM ${schema}.chat_history h WHERE user_id=$1 ORDER BY id`, [String(owner.id)])).rows;
  const beforeOversize = await historySnapshot(); const effectsBeforeOversize = await toolsForOwner();
  const sizeScope = `fixed_${family}_oversized`;
  const oversized = await provenance.withScope(sizeScope, () => request(base, route + '/chat', session.token, { userMessage: 'x'.repeat(6001) }));
  assert.equal(oversized.response.status, 413); assert.equal(oversized.body.code, 'WORKSHOP_REQUEST_TOO_LARGE');
  assert.deepEqual(provenance.publicCalls(sizeScope), []); assert.deepEqual(await historySnapshot(), beforeOversize);
  assert.deepEqual(await toolsForOwner(), effectsBeforeOversize); await noCredit();
  assert.deepEqual(await siblingSnapshot(), siblingBefore);
  assert.equal((await request(base, route + '/reset', session.token, {})).response.status, 200);
  assert.deepEqual(await historySnapshot(), []); assert.deepEqual(await siblingSnapshot(), siblingBefore);
  const postResetScope = `fixed_${family}_after_reset`;
  await search(postResetScope);
  for (const call of provenance.getPrivateCalls(postResetScope)) {
    for (const excluded of [recent, old, foreign, forged]) assert.equal(call.request.includes(excluded), false);
  }
  assert.deepEqual(await siblingSnapshot(), siblingBefore);
  return { family, fixedBlocked: true, literalSearch: true, longHistoryBounded: true, oversizedRejected: true,
    resetHistoryCleared: true, siblingPreserved: true, modelCalls: [attackScope, `fixed_${family}_literal`, longScope, sizeScope, postResetScope].flatMap(scope => provenance.publicCalls(scope)) };
}
module.exports = { qualifyFixedSession, assertHistoryPrompt, assertNativeSearchRows };
