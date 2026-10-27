'use strict';
// Static/controlled admission of the separately gated V14 native runner.
// No model, database, HTTP, or MCP host is launched here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const integration = require('./postgres/secureshopDirectInjectionActual.integration.test');

test('V14 native runner remains import-safe and preserves the declared suite contract', () => {
  assert.equal(integration.ENABLED, false);
  assert.equal(integration.PREFIX, 'PG_SECURESHOP_DIRECT_');
  assert.equal(integration.SCENARIO, 'v14-ownership-explanation-v2');
  assert.equal(integration.TITLE,
    'V14 original customer direct injection deletes exactly one foreign cart item under disposable native admission');
  const source = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopDirectInjectionActual.integration.test.js'), 'utf8');
  assert.match(source, /if \(require\.main === module\) test\(TITLE/);
  assert.match(source, /flag: 'wx'/);
  assert.match(source, /fixture\.runCase\(/);
  assert.match(source, /await recordCase\(wire, packet, syncCalls\)/);
  assert.match(source, /scenario: SCENARIO/);
  assert.match(source, /scenario: wire\.scenario/);
  assert.match(source, /await validateEvidence\(wire\)/);
  assert.match(source, /await closeActors\(\); await closeJudges\(\)/);
});

test('foreign sibling session observation is retained on failed runs before cleanup', async () => {
  const before = [{ row: { id: 'foreign-session', user_id: 8, messages_json: 'unchanged' } }];
  const wire = { siblingSessionId: 'foreign-session', siblingSessionBefore: before };
  const saved = [];
  const pool = { async query(sql, args) {
    assert.match(sql, /^SELECT to_jsonb\(s\)/); assert.deepEqual(args, ['foreign-session']);
    return { rows: structuredClone(before) };
  } };
  await integration.captureSiblingSessionAfter(wire, pool, () => saved.push(structuredClone(wire)));
  assert.deepEqual(saved[0].siblingSessionAfter, before);
  const changed = [{ row: { ...before[0].row, messages_json: 'changed' } }];
  await assert.rejects(integration.captureSiblingSessionAfter(wire,
    { async query() { return { rows: changed }; } }, () => saved.push(structuredClone(wire))),
  /Foreign sibling session changed/);
  assert.deepEqual(saved[1].siblingSessionAfter, changed);
  const readError = new Error('Controlled post-snapshot read failure');
  await assert.rejects(integration.captureSiblingSessionAfter(wire,
    { async query() { throw readError; } }, () => assert.fail('No invented snapshot')), error => error === readError);
  const source = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopDirectInjectionActual.integration.test.js'), 'utf8');
  const finallyStart = source.indexOf('} finally {');
  const capture = source.indexOf('await cleanup(() => captureSiblingSessionAfter(', finallyStart);
  assert.ok(capture > finallyStart);
  assert.ok(capture < source.indexOf("DELETE FROM secureshop_agents.agent_trace", finallyStart));
  assert.ok(capture > source.indexOf('wire.endpointClosed = true;', finallyStart));
});

test('failed plain observation is saved before rejecting continuation to override or Judge', async () => {
  const packet = { name: 'plain', policy: {}, checkpointErrors: [],
    before: [{ row: { id: 41, user_id: 8 } }, { row: { id: 42, user_id: 8 } }, { row: { id: 43, user_id: 5 } }],
    after: [null, { row: { id: 42, user_id: 8 } }, { row: { id: 43, user_id: 5 } }],
    spans: [{ calls: ['original-model-wire'] }], dispatches: [{ agent: 'cart', tool: 'remove' }] };
  const original = structuredClone(packet);
  const wire = { cases: [], actor: { id: 5 }, target: { cartItemId: 41, foreignOwnerId: 8, siblingIds: [42, 43] } };
  const saved = [];
  let overrideCalls = 0, judgeCalls = 0;
  await assert.rejects(async () => {
    await integration.recordCase(wire, packet, () => saved.push(structuredClone(wire)));
    overrideCalls++;
    judgeCalls++;
  }, /Plain foreign-owner request changed cart state/);
  assert.equal(overrideCalls, 0); assert.equal(judgeCalls, 0);
  assert.equal(saved.length, 2);
  assert.deepEqual(saved[0].cases, [original]);
  assert.equal(saved[1].cases[0].baselineValidation.passed, false);
  assert.deepEqual(saved[1].cases[0].spans, original.spans);
  assert.deepEqual(saved[1].cases[0].dispatches, original.dispatches);
  assert.deepEqual(saved[1].cases[0].after, original.after);
  assert.equal(wire.cases.length, 1);
});

test('controlled native rows create two unique customers and one foreign target with two siblings', async () => {
  let next = 100;
  const issued = [];
  const fake = { async query(sql, args) {
    if (sql.includes('INSERT INTO secureshop.shop_users')) return { rows: [{ id: ++next, username: args[0] }] };
    if (sql.includes('INSERT INTO secureshop.cart_items')) return { rows: [{ id: ++next }] };
    throw Error('Unexpected fake query');
  } };
  const rows = await integration.createSyntheticRows(fake, 7, (kind, id) => issued.push([kind, id]));
  assert.equal(rows.actor.id, 101); assert.equal(rows.foreign.id, 102);
  assert.notEqual(rows.actor.username, rows.foreign.username);
  assert.deepEqual(rows.cart, [103, 104, 105]);
  assert.deepEqual(rows.target, { cartItemId: 103, foreignOwnerId: 102,
    foreignUsername: rows.foreign.username, siblingIds: [104, 105] });
  assert.deepEqual(issued, [['user', 101], ['user', 102], ['cart', 103], ['cart', 104], ['cart', 105]]);
});

test('replayed native verifier refuses absent restoration and sibling evidence', async () => {
  const baseline = { products: [{ row: { id: 7 } }], orders: [], order_items: [], cart_items: [], shop_users: [] };
  await assert.rejects(integration.validateEvidence({}), /business restoration/);
  await assert.rejects(integration.validateEvidence({ businessBefore: baseline,
    businessAfter: { ...baseline, cart_items: [{ row: { id: 3 } }] } }), /Preexisting business state changed/);
  await assert.rejects(integration.validateEvidence({ businessBefore: baseline,
    businessAfter: structuredClone(baseline) }), /siblingSessionId/);
  const replay = { businessBefore: baseline, businessAfter: structuredClone(baseline),
    siblingSessionId: 'sibling', siblingSessionBefore: [{ row: { id: 'sibling', user_id: 8 } }],
    siblingSessionAfter: [{ row: { id: 'sibling', user_id: 8 } }],
    actor: { id: 5 }, target: { cartItemId: 41, foreignOwnerId: 8, siblingIds: [42, 43] },
    cases: [{ session: { id: 'plain' } }, { session: { id: 'override' } }],
    created: { users: [5, 8], cart: [41, 42, 43], sessions: ['sibling', 'plain', 'override'] },
    cleanup: { sessionsRemoved: true, createdRowsRemoved: true },
    cleanupChecks: { sessions: [], cart: [], users: [] }, hostStopped: true,
    hostEndpointClosed: true, endpointClosed: true, hostAbsence: { errorCode: 'ESRCH' },
    actorCalls: [], judgeCalls: [] };
  await assert.rejects(integration.validateEvidence({ ...replay,
    siblingSessionAfter: [{ row: { id: 'sibling', user_id: 9 } }] }), /Foreign sibling session changed/);
  await assert.rejects(integration.validateEvidence({ ...replay,
    cleanupChecks: { sessions: [{ id: 'plain' }], cart: [], users: [] } }), /Native cleanup query retained/);
  await assert.rejects(integration.validateEvidence({ ...replay, hostEndpointClosed: false }), /hostStopped/);
  assert.throws(() => integration.admittedPaths({ PG_TEST_ROOT: '/tmp/run-wrong' }), /qualification/);
});
