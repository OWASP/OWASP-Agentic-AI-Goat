'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Pool } = require('pg');
const { createMcpWorkshopDb } = require('../../server/database/postgres/mcpWorkshopDb');
const { createMcpResourceRepository } = require('../../server/database/postgres/mcpResourceRepository');
const { createDurableMcpMailResources, _internals } = require('../../server/services/mcp/durableMailResources');

const enabled = process.env.MCP_OWNED_RESOURCES_MAILPIT === 'yes';
const executionFor = scope => ({ ownerKey: JSON.stringify(['MCP', String(scope.platformOwnerId)]),
  durableGeneration: String(scope.generation), check: async () => true, effect: async (_key, work) => work() });
const signed = body => ({ ...body, receiptSha256: _internals.sha(Buffer.from(_internals.canonical(body))) });
const assigned = intentId => `mcp-${intentId.toLowerCase()}@owasp-ai-goat.local`;

async function waitFor(mail, ids, count) {
  let result;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    result = await mail.listMessagesBySmtpIds(ids);
    if (result.ok && result.messages.length === count) return result;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail(`Mailpit did not expose ${count} exact SMTP receipts: ${JSON.stringify(result)}`);
}

test('native durable MCP mail uses real SMTP receipts and exact Mailpit retirement', { skip: !enabled, timeout: 120000 }, async t => {
  require('../fixtures/mcpMailpitAdmission').assertMcpMailpitAdmission(process.env, path.resolve(__dirname, '../..'));
  const migrationUrl = process.env.PG_MCP_OWNED_RESOURCES_TEST_MIGRATION_URL;
  const runtimeUrl = process.env.PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL;
  assert.ok(migrationUrl && runtimeUrl);
  assert.equal(new URL(process.env.MAILPIT_API_URL).hostname, '127.0.0.1');
  assert.notEqual(new URL(process.env.MAILPIT_API_URL).port, '8025');
  assert.equal(process.env.MAILPIT_SMTP_HOST, '127.0.0.1');
  assert.notEqual(process.env.MAILPIT_SMTP_PORT, '1025');
  const mail = require('../../server/services/mcp/mailClient');
  let migration = new Pool({ connectionString: migrationUrl, max: 2 });
  let runtime = new Pool({ connectionString: runtimeUrl, max: 8 });
  const cleanupIds = [];
  t.after(async () => {
    await mail.deleteMessagesBySmtpIds(cleanupIds);
    await Promise.allSettled([runtime.end(), migration.end()]);
  });
  await createMcpWorkshopDb(runtime).initialize(migration);
  await migration.query(await fs.readFile(path.join(__dirname, '../../docs/modernization/drafts/mcp-owned-resources.sql'), 'utf8'));
  await migration.query('GRANT SELECT,INSERT,UPDATE ON mcp.runner_targets,mcp.runner_target_cleanups,mcp.mail_intents,mcp.mail_cleanups TO dvaia_mcp_runtime');

  const owner = Object.freeze({ targetId: crypto.randomUUID(), platformOwnerId: 17, platformSessionId: 171, generation: 4 });
  const sibling = Object.freeze({ targetId: crypto.randomUUID(), platformOwnerId: 18, platformSessionId: 181, generation: 4 });
  let repository = createMcpResourceRepository(runtime);
  await repository.reserveRunnerTarget(owner);
  await repository.reserveRunnerTarget(sibling);
  const acceptedRunId = crypto.randomUUID();
  const acceptedEffect = 'mcp_indirect_injection_consequence';
  const acceptedIntent = require('../../server/services/mcp/confusedDeputyObservation').intentIdFor(acceptedRunId, acceptedEffect);
  const protectedContent = 'SYNTHETIC_LAB_VALUE=owned-mailpit-test';
  const acceptedBody = `owner accepted bytes\n\n--- attached internal data (auto-collected by send_report) ---\n${protectedContent}`;
  const uncertainIntent = crypto.randomUUID();
  const siblingIntent = crypto.randomUUID();
  cleanupIds.push(assigned(acceptedIntent), assigned(uncertainIntent), assigned(siblingIntent));
  let injectPostAcceptanceLoss = true;
  const sendMail = async value => {
    const result = await mail.sendOwnedReport(value);
    if (result.ok !== true) return result;
    if (value.subject === 'uncertain after DATA' && injectPostAcceptanceLoss) {
      injectPostAcceptanceLoss = false;
      throw new Error('controlled connection loss after Mailpit SMTP acceptance');
    }
    return result;
  };
  const service = createDurableMcpMailResources({ repository, sendMail,
    deleteMessages: ids => mail.deleteMessagesBySmtpIds(ids),
    listMessages: ids => mail.listMessagesBySmtpIds(ids),
    clock: (() => { const times = ['2026-09-14T06:00:00.000Z', '2026-09-14T06:00:01.000Z']; return () => times.shift(); })() });
  const send = (scope, intentId, subject, body) => service.send({ scope, execution: executionFor(scope), intentId,
    to: 'owned-mcp@example.test', subject, body });

  const accepted = await send(owner, acceptedIntent, 'accepted delivery', acceptedBody);
  assert.equal(accepted.messageId, assigned(acceptedIntent), 'Nodemailer returns the preassigned durable Message-ID');
  await assert.rejects(send(owner, uncertainIntent, 'uncertain after DATA', 'owner uncertain bytes'),
    /controlled connection loss after Mailpit SMTP acceptance/);
  const siblingReceipt = await send(sibling, siblingIntent, 'sibling delivery', 'sibling bytes');
  const captured = await waitFor(mail, cleanupIds, 3);
  assert.deepEqual(captured.messages.map(row => row.messageId).sort(), [...cleanupIds].sort());
  assert.match(captured.messages.find(row => row.messageId === accepted.messageId).snippet, /owner accepted bytes/);
  assert.match(captured.messages.find(row => row.messageId === assigned(uncertainIntent)).snippet, /owner uncertain bytes/);
  const expectedDelivery = { messageId: accepted.messageId, to: 'owned-mcp@example.test',
    subject: 'accepted delivery', body: acceptedBody };
  const readback = await mail.verifyMessageReadback(expectedDelivery);
  assert.equal(readback.ok, true, 'actual received full message matches the submitted report');
  assert.equal(mail.isTrustedMessageReadback(readback.receipt), true);
  assert.equal(readback.receipt.submittedBodySha256,
    crypto.createHash('sha256').update(expectedDelivery.body).digest('hex'));
  for (const mismatch of [
    { to: 'different-owner@example.test' }, { subject: 'changed subject' },
    { body: 'owner accepted bytes with altered content' }, { messageId: siblingReceipt.messageId },
  ]) {
    assert.deepEqual(await mail.verifyMessageReadback({ ...expectedDelivery, ...mismatch }),
      { ok: false, status: 'mismatch' });
  }

  const { createDeliveredMailObservation, isTrustedObservation } = require('../../server/services/mcp/deliveredMailObservation');
  const deliveryObserver = createDeliveredMailObservation({ mailResources: service });
  const deliveryInput = { ...expectedDelivery, scope: owner,
    execution: { ...executionFor(owner), runId: acceptedRunId },
    intentId: acceptedIntent, runId: acceptedRunId, effectKey: acceptedEffect, protectedContent };
  const joined = await deliveryObserver.observe(deliveryInput);
  assert.equal(isTrustedObservation(joined), true, 'accepted intent and actual mailbox content join under current ownership');
  assert.equal(joined.runId, acceptedRunId);
  assert.equal(joined.platformOwnerId, owner.platformOwnerId);
  const persisted = (await runtime.query(`SELECT intent_id,status,assigned_message_id FROM mcp.mail_intents
    WHERE intent_id=ANY($1::uuid[]) ORDER BY intent_id`, [[acceptedIntent, uncertainIntent, siblingIntent]])).rows;
  assert.equal(persisted.find(row => row.intent_id === acceptedIntent).status, 'accepted');
  assert.equal(persisted.find(row => row.intent_id === uncertainIntent).status, 'uncertain');
  assert.equal(persisted.find(row => row.intent_id === siblingIntent).status, 'accepted');

  const operationId = crypto.randomUUID();
  await repository.beginRunnerRetirement({ ...owner, operationId });
  const [receiptA, receiptB] = await Promise.all([
    service.cleanup({ scope: owner, operationId }), service.cleanup({ scope: owner, operationId }),
  ]);
  assert.deepEqual(receiptB, receiptA, 'concurrent real-Mailpit cleanup returns one canonical receipt');
  assert.equal(receiptA.intentCount, 2);
  await waitFor(mail, [assigned(acceptedIntent), assigned(uncertainIntent)], 0);
  assert.deepEqual(await mail.verifyMessageReadback(expectedDelivery), { ok: false, status: 'not_found' });
  assert.equal(await deliveryObserver.observe(deliveryInput), null, 'retired intent cannot retain delivered credit');
  assert.equal((await waitFor(mail, [siblingReceipt.messageId], 1)).messages[0].subject, 'sibling delivery');

  const runnerBody = { version: 1, targetId: owner.targetId, ownerId: owner.platformOwnerId,
    platformSessionId: owner.platformSessionId, generation: owner.generation, operationId,
    status: 'completed', completedAt: '2026-09-14T06:00:02.000Z', cleanupPending: false };
  await repository.completeRunnerRetirement({ ...owner, operationId, receipt: signed(runnerBody) });
  await runtime.end();
  runtime = new Pool({ connectionString: runtimeUrl, max: 8 });
  repository = createMcpResourceRepository(runtime);
  const restarted = createDurableMcpMailResources({ repository,
    sendMail: async () => { throw new Error('cleanup replay must not send'); },
    deleteMessages: async () => { throw new Error('cleanup replay must not delete'); },
    listMessages: ids => mail.listMessagesBySmtpIds(ids) });
  assert.deepEqual(await restarted.readCleanup({ scope: owner, operationId }), receiptA);
  assert.deepEqual(await restarted.cleanup({ scope: owner, operationId }), receiptA);
  assert.equal((await mail.listMessagesBySmtpIds([siblingReceipt.messageId])).messages.length, 1);
});
