'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { buildReceipt, digestSessionIds } = require('../server/database/postgres/secureshopConversationLifecycleRepository');
const { createBoundConversationsRepository } = require('../server/database/postgres/secureshopBoundConversationsRepository');

function scope() {
  return { resetId: randomUUID(), launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 3, platformOwnerId: 11, platformSessionId: 12 };
}

test('generation retirement receipt is deterministic, bounded, and exact-scope', () => {
  const value = scope(), first = randomUUID(), second = randomUUID();
  const sessionSetSha256 = digestSessionIds([second, first]);
  assert.equal(sessionSetSha256, digestSessionIds([first, second]));
  const receipt = buildReceipt(value, { completedAt: '2026-09-13T12:34:56.789Z',
    sessionCount: 2, uncertainTurnCount: 1, sessionSetSha256 });
  assert.deepEqual(Object.keys(receipt), ['version','resetId','launchId','scenarioId','fromGeneration',
    'platformOwnerId','platformSessionId','status','sessionCount','uncertainTurnCount',
    'sessionSetSha256','completedAt','receiptSha256']);
  assert.match(receipt.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(buildReceipt(value, { completedAt: new Date(receipt.completedAt), sessionCount: 2,
    uncertainTurnCount: 1, sessionSetSha256 }).receiptSha256, receipt.receiptSha256);
  assert.notEqual(buildReceipt({ ...value, generation: 4 }, { completedAt: receipt.completedAt,
    sessionCount: 2, uncertainTurnCount: 1, sessionSetSha256 }).receiptSha256, receipt.receiptSha256);
  assert.throws(() => digestSessionIds([first, first]), { code: 'INVALID_RETIREMENT_RECEIPT' });
  assert.throws(() => buildReceipt(value, { completedAt: 'invalid', sessionCount: 2,
    uncertainTurnCount: 1, sessionSetSha256 }), { code: 'INVALID_RETIREMENT_RECEIPT' });
  assert.throws(() => buildReceipt(value, { completedAt: '2026-09-13T12:34:56Z', sessionCount: 2,
    uncertainTurnCount: 1, sessionSetSha256 }), { code: 'INVALID_RETIREMENT_RECEIPT' });
  assert.throws(() => buildReceipt(value, { completedAt: '2026-09-13T05:34:56.789-07:00', sessionCount: 2,
    uncertainTurnCount: 1, sessionSetSha256 }), { code: 'INVALID_RETIREMENT_RECEIPT' });
  for (const completedAt of [null, false, 0, undefined]) {
    assert.throws(() => buildReceipt(value, { completedAt, sessionCount: 2,
      uncertainTurnCount: 1, sessionSetSha256 }), { code: 'INVALID_RETIREMENT_RECEIPT' });
  }
});

test('bound conversation admission checks the retirement journal under the launch lock', async () => {
  const binding = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 8,
    platformOwnerId: 21, platformSessionId: 22, shopUserId: 23, role: 'customer' };
  const calls = [];
  const client = { async query(sql, args) {
    calls.push([sql.replace(/\s+/g, ' ').trim(), args]);
    if (sql === 'BEGIN' || sql === 'ROLLBACK') return { rows: [], rowCount: 0 };
    if (sql.includes('information_schema.columns')) return { rows: [{ ready: false }], rowCount: 1 };
    if (sql.includes('pg_advisory_xact_lock')) return { rows: [{ pg_advisory_xact_lock: null }], rowCount: 1 };
    if (sql.includes('to_regclass')) return { rows: [{ relation: 'conversation_generation_retirements' }], rowCount: 1 };
    if (sql.includes('FROM secureshop_agents.conversation_generation_retirements')) return { rows: [{ '?column?': 1 }], rowCount: 1 };
    throw new Error(`unexpected query: ${sql}`);
  }, release() { calls.push(['release']); } };
  const repository = createBoundConversationsRepository({ pool: { async connect() { return client; }, async query() {} },
    queue: async (_id, action) => action() });
  await assert.rejects(repository.acquireBoundSession({ id: randomUUID(), binding }), { code: 'CONVERSATION_UNAVAILABLE' });
  const sqlCalls=calls.map(row=>row[0]);
  const lockIndex=sqlCalls.findIndex(sql=>/pg_advisory_xact_lock/.test(sql));
  const retirementIndex=sqlCalls.findIndex(sql=>/conversation_generation_retirements/.test(sql));
  assert.ok(lockIndex>=0,'launch advisory lock must be acquired');
  assert.ok(retirementIndex>=0,'retirement journal must be checked');
  assert.ok(lockIndex<retirementIndex,'launch lock precedes retirement check');
  assert.ok(sqlCalls.some(sql=>/information_schema\.columns/.test(sql)));
  assert.ok(sqlCalls.some(sql=>/to_regclass/.test(sql)));
  assert.ok(sqlCalls.some(sql=>/conversation_generation_retirements/.test(sql)));
  assert.equal(calls.some(([sql]) => /INSERT INTO secureshop_agents\.agent_sessions/.test(sql)), false);
  assert.equal(calls.at(-2)[0], 'ROLLBACK');
  assert.equal(calls.at(-1)[0], 'release');
});
