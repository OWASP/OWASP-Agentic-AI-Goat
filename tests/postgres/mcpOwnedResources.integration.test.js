'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { Pool } = require('pg');
const { createMcpWorkshopDb } = require('../../server/database/postgres/mcpWorkshopDb');
const { createMcpResourceRepository } = require('../../server/database/postgres/mcpResourceRepository');
const { createDurableMcpMailResources } = require('../../server/services/mcp/durableMailResources');

const migrationUrl = process.env.PG_MCP_OWNED_RESOURCES_TEST_MIGRATION_URL;
const runtimeUrl = process.env.PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && migrationUrl && runtimeUrl;
const executionFor = scope => ({ ownerKey: JSON.stringify(['MCP', String(scope.platformOwnerId)]),
  durableGeneration: String(scope.generation), check: async () => true, effect: async (_key, work) => work() });
const signed = body => ({ ...body, receiptSha256: createHash('sha256').update(JSON.stringify(
  Object.fromEntries(Object.keys(body).sort().map(key => [key, body[key]])))).digest('hex') });

test('native MCP resource repository binds mail intent, retirement cleanup and immutable replay', { skip: !enabled }, async t => {
  for (const value of [migrationUrl, runtimeUrl]) {
    const url = new URL(value);
    assert.match(url.pathname, /^\/owasp_ai_goat_test_mcp_owned_resources$/);
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  }
  const migration = new Pool({ connectionString: migrationUrl, max: 2 });
  let runtime = new Pool({ connectionString: runtimeUrl, max: 8 });
  t.after(async () => Promise.allSettled([runtime.end(), migration.end()]));
  await createMcpWorkshopDb(runtime).initialize(migration);
  await migration.query(await fs.readFile(path.join(__dirname, '../../docs/modernization/drafts/mcp-owned-resources.sql'), 'utf8'));
  await migration.query(`GRANT SELECT,INSERT,UPDATE ON mcp.runner_targets,mcp.runner_target_cleanups,mcp.mail_intents,mcp.mail_cleanups TO dvaia_mcp_runtime`);

  const alice = Object.freeze({ targetId: randomUUID(), platformOwnerId: 7, platformSessionId: 71, generation: 3 });
  const sibling = Object.freeze({ targetId: randomUUID(), platformOwnerId: 8, platformSessionId: 81, generation: 3 });
  let repository = createMcpResourceRepository(runtime);
  await repository.reserveRunnerTarget(alice);
  await repository.reserveRunnerTarget(sibling);

  const mailbox = new Map();
  const sends = [];
  const adapter = clock => createDurableMcpMailResources({ repository,
    sendMail: async mail => { sends.push({ to: mail.to, subject: mail.subject, messageId: mail.messageId }); mailbox.set(mail.messageId, { ...mail }); return { ok: true, messageId: `<${mail.messageId}>` }; },
    deleteMessages: async ids => { for (const id of ids) mailbox.delete(id); return { ok: true }; },
    listMessages: async ids => ({ ok: true, messages: ids.filter(id => mailbox.has(id)) }), clock });
  const service = adapter(() => '2026-09-13T12:34:56.000Z');
  const aliceIntentA = randomUUID();
  const aliceIntentB = randomUUID();
  const siblingIntent = randomUUID();
  const send = (scope, intentId, subject, body) => service.send({ scope, execution: executionFor(scope), intentId,
    to: 'shared@example.test', subject, body });
  const first = await send(alice, aliceIntentA, 'first subject', 'same body');
  await send(alice, aliceIntentB, 'second subject', 'second body');
  await send(sibling, siblingIntent, 'sibling subject', 'sibling body');
  assert.deepEqual(await send(alice, aliceIntentA, 'first subject', 'same body'), { ...first, replayed: true });
  await assert.rejects(send(alice, aliceIntentA, 'changed subject', 'same body'), { code: 'MCP_RESOURCE_CONFLICT' });
  assert.equal(sends.length, 3, 'intent conflict does not repeat SMTP');

  const operationId = randomUUID();
  assert.deepEqual(await repository.beginRunnerRetirement({ ...alice, operationId }), { replayed: false });
  const twoClocks = ['2026-09-13T12:34:57.000Z', '2026-09-13T12:34:58.000Z'];
  const concurrent = adapter(() => twoClocks.shift());
  const [receiptA, receiptB] = await Promise.all([
    concurrent.cleanup({ scope: alice, operationId }),
    concurrent.cleanup({ scope: alice, operationId }),
  ]);
  assert.deepEqual(receiptB, receiptA, 'concurrent completion returns the committed receipt');
  assert.equal(receiptA.intentCount, 2);
  assert.equal(mailbox.has(first.messageId), false);
  assert.equal(mailbox.has(`mcp-${aliceIntentB}@owasp-ai-goat.local`), false);
  assert.equal(mailbox.has(`mcp-${siblingIntent}@owasp-ai-goat.local`), true);
  const cleanupRow = (await runtime.query(`SELECT operation_id,status,message_ids,receipt_json FROM mcp.mail_cleanups
    WHERE target_id=$1`, [alice.targetId])).rows[0];
  assert.equal(cleanupRow.operation_id, operationId);
  assert.equal(cleanupRow.status, 'completed');
  assert.deepEqual(cleanupRow.receipt_json, receiptA);
  assert.deepEqual([...cleanupRow.message_ids].sort(), [`mcp-${aliceIntentA}@owasp-ai-goat.local`, `mcp-${aliceIntentB}@owasp-ai-goat.local`].sort());

  const differentOperation = randomUUID();
  await assert.rejects(concurrent.cleanup({ scope: alice, operationId: differentOperation }), { code: 'MCP_RESOURCE_CONFLICT' });
  assert.equal((await runtime.query('SELECT count(*)::integer n FROM mcp.mail_cleanups WHERE target_id=$1', [alice.targetId])).rows[0].n, 1);
  await assert.rejects(send(alice, randomUUID(), 'late', 'late body'), { code: 'MCP_RESOURCE_RETIRED' });
  const runnerBody = { version: 1, targetId: alice.targetId, ownerId: alice.platformOwnerId,
    platformSessionId: alice.platformSessionId, generation: alice.generation, operationId,
    status: 'completed', completedAt: '2026-09-13T12:35:00.000Z', cleanupPending: false };
  const runnerReceipt = signed(runnerBody);
  assert.deepEqual(await repository.completeRunnerRetirement({ ...alice, operationId, receipt: runnerReceipt }), runnerReceipt);

  await runtime.end();
  runtime = new Pool({ connectionString: runtimeUrl, max: 8 });
  repository = createMcpResourceRepository(runtime);
  const restarted = createDurableMcpMailResources({ repository, sendMail: async () => { throw new Error('replay must not send'); },
    deleteMessages: async () => { throw new Error('replay must not delete'); },
    listMessages: async ids => ({ ok: true, messages: ids.filter(id => mailbox.has(id)) }) });
  assert.deepEqual(await restarted.readCleanup({ scope: alice, operationId }), receiptA);
  assert.deepEqual(await restarted.cleanup({ scope: alice, operationId }), receiptA);
  assert.deepEqual(await repository.readRunnerRetirement({ ...alice, operationId }), runnerReceipt);
  assert.equal((await runtime.query(`SELECT state FROM mcp.runner_targets WHERE target_id=$1`, [sibling.targetId])).rows[0].state, 'active');
  assert.equal((await runtime.query(`SELECT status FROM mcp.mail_intents WHERE intent_id=$1`, [siblingIntent])).rows[0].status, 'accepted');
});
