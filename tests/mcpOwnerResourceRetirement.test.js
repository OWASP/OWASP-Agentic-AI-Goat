'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createMcpResourceRepository } = require('../server/database/postgres/mcpResourceRepository');

const OWNER = 7;
const TARGET = '11111111-1111-4111-8111-111111111111';
const OPERATION = '22222222-2222-4222-8222-222222222222';
const INTENT = '33333333-3333-4333-8333-333333333333';
const MESSAGE = `mcp-${INTENT}@owasp-ai-goat.local`;
const MAIL_COMPLETED = '2026-09-16T12:34:55.000Z';
const RUNNER_COMPLETED = '2026-09-16T12:34:56.000Z';
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
const signed = body => ({ ...body, receiptSha256: crypto.createHash('sha256').update(canonical(body)).digest('hex') });
const clone = value => structuredClone(value);

function retiredSnapshot() {
  const runnerReceipt = signed({ version: 1, targetId: TARGET, ownerId: OWNER,
    platformSessionId: 71, generation: 3, operationId: OPERATION, status: 'completed',
    completedAt: RUNNER_COMPLETED, cleanupPending: false });
  const mailReceipt = signed({ version: 1, targetId: TARGET, platformOwnerId: OWNER,
    platformSessionId: 71, generation: 3, operationId: OPERATION, status: 'completed',
    intentCount: 1, completedAt: MAIL_COMPLETED, cleanupPending: false });
  return {
    runner_targets: [{ targetId: TARGET, ownerKey: String(OWNER), platformSessionId: '71',
      generation: '3', state: 'retired', retiredAt: RUNNER_COMPLETED }],
    runner_cleanups: [{ operationId: OPERATION, targetId: TARGET, ownerKey: String(OWNER),
      platformSessionId: '71', generation: '3', status: 'completed', receiptVersion: 1,
      receiptSha256: runnerReceipt.receiptSha256, receiptJson: runnerReceipt, completedAt: RUNNER_COMPLETED }],
    mail_intents: [{ intentId: INTENT, targetId: TARGET, ownerKey: String(OWNER),
      platformSessionId: '71', generation: '3', messageId: MESSAGE,
      recipientSha256: 'a'.repeat(64), payloadSha256: 'b'.repeat(64), status: 'accepted',
      settledAt: '2026-09-16T12:34:54.000Z', cleanedAt: MAIL_COMPLETED }],
    mail_cleanups: [{ operationId: OPERATION, targetId: TARGET, ownerKey: String(OWNER),
      platformSessionId: '71', generation: '3', status: 'completed', messageIds: [MESSAGE],
      receiptVersion: 1, receiptSha256: mailReceipt.receiptSha256,
      receiptJson: mailReceipt, completedAt: MAIL_COMPLETED }],
  };
}

function repositoryFor(snapshot, observe = () => {}) {
  return createMcpResourceRepository({
    async query(sql, params) {
      observe(String(sql), params);
      return { rows: [{ ...clone(snapshot) }], rowCount: 1 };
    },
  });
}

test('owner retirement proof accepts empty history from one four-ledger snapshot', async () => {
  const calls = [];
  const repository = repositoryFor({ runner_targets: [], runner_cleanups: [], mail_intents: [], mail_cleanups: [] },
    (sql, params) => calls.push({ sql, params }));
  const proof = await repository.assertOwnerResourcesRetired({ platformOwnerId: OWNER });
  assert.deepEqual(proof, { platformOwnerId: OWNER, status: 'retired', targetCount: 0, mailIntentCount: 0 });
  assert.equal(Object.isFrozen(proof), true);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].params, [String(OWNER)]);
  for (const relation of ['mcp.runner_targets', 'mcp.runner_target_cleanups', 'mcp.mail_intents', 'mcp.mail_cleanups']) {
    assert.match(calls[0].sql, new RegExp(relation.replace('.', '\\.')));
  }
  assert.match(calls[0].sql, /platform_session_id::text/);
  assert.match(calls[0].sql, /generation::text/);
  assert.match(calls[0].sql, /to_char\(retired_at AT TIME ZONE 'UTC'/);
});

test('owner retirement proof accepts only fully bound completed historical receipts', async () => {
  const proof = await repositoryFor(retiredSnapshot()).assertOwnerResourcesRetired({ platformOwnerId: OWNER });
  assert.deepEqual(proof, { platformOwnerId: OWNER, status: 'retired', targetCount: 1, mailIntentCount: 1 });
  assert.equal(Object.isFrozen(proof), true);
});

test('owner retirement proof distinguishes valid outstanding resource debt', async () => {
  const active = { runner_targets: [{ targetId: TARGET, ownerKey: String(OWNER), platformSessionId: '71',
    generation: '3', state: 'active', retiredAt: null }], runner_cleanups: [], mail_intents: [], mail_cleanups: [] };
  await assert.rejects(repositoryFor(active).assertOwnerResourcesRetired({ platformOwnerId: OWNER }),
    { code: 'MCP_OWNER_RESOURCES_PENDING' });

  const retiring = clone(retiredSnapshot());
  retiring.runner_targets[0].state = 'retiring';
  retiring.runner_targets[0].retiredAt = null;
  retiring.runner_cleanups[0] = { ...retiring.runner_cleanups[0], status: 'pending', receiptVersion: null,
    receiptSha256: null, receiptJson: null, completedAt: null };
  retiring.mail_cleanups[0] = { ...retiring.mail_cleanups[0], status: 'pending', receiptVersion: null,
    receiptSha256: null, receiptJson: null, completedAt: null };
  retiring.mail_intents[0].cleanedAt = null;
  await assert.rejects(repositoryFor(retiring).assertOwnerResourcesRetired({ platformOwnerId: OWNER }),
    { code: 'MCP_OWNER_RESOURCES_PENDING' });
  const changedPendingSet = clone(retiring);
  changedPendingSet.mail_cleanups[0].messageIds = [];
  await assert.rejects(repositoryFor(changedPendingSet).assertOwnerResourcesRetired({ platformOwnerId: OWNER }),
    { code: 'MCP_RESOURCE_CONFLICT' });
});

test('owner retirement proof fails closed on inconsistent or foreign durable history', async () => {
  const cases = [
    snapshot => { snapshot.runner_cleanups[0].receiptJson.receiptSha256 = 'c'.repeat(64); },
    snapshot => { snapshot.runner_cleanups[0].ownerKey = '8'; },
    snapshot => { snapshot.mail_cleanups[0].messageIds = []; },
    snapshot => { snapshot.mail_intents[0].cleanedAt = null; },
    snapshot => { snapshot.mail_cleanups = []; },
    snapshot => { snapshot.runner_cleanups.push(clone(snapshot.runner_cleanups[0])); },
    snapshot => { snapshot.mail_intents.push(clone(snapshot.mail_intents[0])); },
    snapshot => { snapshot.runner_targets = []; },
    snapshot => { snapshot.runner_targets = [null]; },
    snapshot => { snapshot.runner_targets = [7]; },
    snapshot => { snapshot.runner_cleanups = [null]; },
    snapshot => { snapshot.mail_intents = [null]; },
    snapshot => { snapshot.mail_cleanups = [null]; },
  ];
  for (const mutate of cases) {
    const snapshot = retiredSnapshot();
    mutate(snapshot);
    await assert.rejects(repositoryFor(snapshot).assertOwnerResourcesRetired({ platformOwnerId: OWNER }),
      { code: 'MCP_RESOURCE_CONFLICT' });
  }
});

test('owner retirement proof rejects non-durable owner coordinates before querying', async () => {
  let queries = 0;
  const repository = repositoryFor({ runner_targets: [], runner_cleanups: [], mail_intents: [], mail_cleanups: [] },
    () => { queries += 1; });
  for (const platformOwnerId of [0, -1, 1.5, Number.MAX_SAFE_INTEGER, '7', null]) {
    await assert.rejects(repository.assertOwnerResourcesRetired({ platformOwnerId }),
      { code: 'MCP_RESOURCE_SCOPE_INVALID' });
  }
  assert.equal(queries, 0);
});

test('owner retirement proof does not translate query or partial-schema failures into absence', async () => {
  const queryError = Object.assign(new Error('relation unavailable'), { code: '42P01' });
  const unavailable = createMcpResourceRepository({ async query() { throw queryError; } });
  await assert.rejects(unavailable.assertOwnerResourcesRetired({ platformOwnerId: OWNER }), error => error === queryError);
  const partial = repositoryFor({ runner_targets: [], runner_cleanups: [], mail_intents: [] });
  await assert.rejects(partial.assertOwnerResourcesRetired({ platformOwnerId: OWNER }),
    { code: 'MCP_RESOURCE_CONFLICT' });
});
