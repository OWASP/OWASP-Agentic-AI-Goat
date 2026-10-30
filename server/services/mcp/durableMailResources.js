'use strict';

const crypto = require('node:crypto');
const confusedDeputyObservation = require('./confusedDeputyObservation');
const VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));

function scope(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) fail('MCP_RESOURCE_SCOPE_INVALID', 'Exact MCP resource scope is required');
  const keys = ['generation', 'platformOwnerId', 'platformSessionId', 'targetId'];
  if (Object.keys(value).sort().join(',') !== keys.join(',')) fail('MCP_RESOURCE_SCOPE_INVALID', 'MCP resource scope fields are invalid');
  if (!UUID.test(value.targetId || '') || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1
      || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1
      || !Number.isSafeInteger(value.generation) || value.generation < 0) fail('MCP_RESOURCE_SCOPE_INVALID', 'MCP resource scope values are invalid');
  return Object.freeze({ targetId: value.targetId.toLowerCase(), platformOwnerId: value.platformOwnerId,
    platformSessionId: value.platformSessionId, generation: value.generation });
}
function text(value, name, maximum) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maximum) fail('MCP_MAIL_INVALID', `${name} is invalid`);
  return value;
}
function messageId(intentId) { return `mcp-${intentId.toLowerCase()}@owasp-ai-goat.local`; }
function exactMessageIds(values) {
  if (!Array.isArray(values)) fail('MCP_MAIL_CLEANUP_INCOMPLETE', 'Owned SMTP message set is invalid');
  const ids = values.map(value => text(value, 'messageId', 320));
  if (ids.some(value => !/^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@owasp-ai-goat\.local$/i.test(value))
      || new Set(ids).size !== ids.length) fail('MCP_MAIL_CLEANUP_INCOMPLETE', 'Owned SMTP message set is invalid');
  return ids;
}
function executionFor(bound, execution) {
  if (!execution || execution.ownerKey !== JSON.stringify(['MCP', String(bound.platformOwnerId)])
      || String(execution.durableGeneration) !== String(bound.generation) || typeof execution.check !== 'function'
      || typeof execution.effect !== 'function') fail('MCP_RESOURCE_SCOPE_INVALID', 'Current MCP owner execution is required');
  return execution;
}
function receipt(coordinates, completedAt, intentCount) {
  const body = Object.freeze({ version: VERSION, ...coordinates, status: 'completed', intentCount, completedAt, cleanupPending: false });
  return Object.freeze({ ...body, receiptSha256: sha(Buffer.from(canonical(body))) });
}

// Used by the owned-resource composition. Callers must first resolve the canonical
// platform session and serialize retirement with the target repository.
// observeAccepted proves durable SMTP acceptance, not full mailbox readback.
function createDurableMcpMailResources({ repository, sendMail, deleteMessages, listMessages, clock = () => new Date().toISOString() } = {}) {
  for (const [name, dependency] of Object.entries({ repository, sendMail, deleteMessages, listMessages })) {
    if ((name === 'repository' && (!dependency || typeof dependency !== 'object')) || (name !== 'repository' && typeof dependency !== 'function')) throw new TypeError(`${name} is required`);
  }
  return Object.freeze({
    async observeAccepted(input) {
      const bound = scope(input?.scope);
      const execution = executionFor(bound, input?.execution);
      const intentId = input?.intentId;
      if (!UUID.test(intentId || '') || !UUID.test(input?.runId || '')
          || input.runId !== execution.runId || typeof input.effectKey !== 'string'
          || intentId.toLowerCase() !== confusedDeputyObservation.intentIdFor(input.runId, input.effectKey)) {
        return Object.freeze({});
      }
      const to = text(input.to, 'recipient', 320);
      const subject = text(input.subject, 'subject', 512);
      const body = text(input.body, 'body', 65536);
      const protectedContent = text(input.protectedContent, 'protectedContent', 65536);
      const assignedMessageId = messageId(intentId);
      const marker = '--- attached internal data (auto-collected by send_report) ---\n';
      const external = !/@(?:acme-corp\.internal|acme\.internal|acme-corp\.com)$/i.test(to);
      await execution.check();
      let stored;
      try { stored = await repository.readAcceptedMailIntent({ ...bound, intentId: intentId.toLowerCase() }); }
      catch (error) {
        if (['MCP_RESOURCE_SCOPE_INVALID', 'MCP_RESOURCE_RETIRED', 'MCP_RESOURCE_CONFLICT'].includes(error?.code)) {
          return Object.freeze({});
        }
        throw error;
      }
      await execution.check();
      const payloadSha256 = sha(Buffer.from(canonical({ body, subject })));
      const valid = external && input.messageId === assignedMessageId && body.endsWith(`${marker}${protectedContent}`)
        && stored?.status === 'accepted' && stored.assignedMessageId === assignedMessageId
        && stored.recipientSha256 === sha(Buffer.from(to)) && stored.payloadSha256 === payloadSha256;
      if (!valid) return Object.freeze({});
      return Object.freeze({ confusedDeputyWitness: confusedDeputyObservation.trustWitness({
        version: 'mcp-confused-deputy-observation.v1', runId: input.runId,
        effectKeySha256: sha(Buffer.from(input.effectKey)),
        targetId: bound.targetId, platformOwnerId: bound.platformOwnerId,
        platformSessionId: bound.platformSessionId, generation: bound.generation,
        protectedRead: Object.freeze({ source: 'owned_runner_current_tool',
          sha256: sha(Buffer.from(protectedContent)), byteCount: Buffer.byteLength(protectedContent) }),
        delivery: Object.freeze({ status: 'accepted', external: true, recipient: to,
          intentId: intentId.toLowerCase(), messageId: assignedMessageId, payloadSha256 }),
      }) });
    },
    async project(input) {
      scope(input?.scope);
      const messageIds = exactMessageIds(input?.messageIds || []);
      const observed = await listMessages(messageIds);
      if (observed?.ok !== true || !Array.isArray(observed.messages)) {
        return Object.freeze({ ok: false, messages: Object.freeze([]) });
      }
      return Object.freeze({ ok: true, messages: Object.freeze([...observed.messages]) });
    },
    async send(input) {
      const bound = scope(input?.scope);
      const execution = executionFor(bound, input?.execution);
      const intentId = input?.intentId;
      if (!UUID.test(intentId || '')) fail('MCP_MAIL_INVALID', 'intentId is invalid');
      const assignedMessageId = messageId(intentId);
      const mail = { to: text(input.to, 'recipient', 320), subject: text(input.subject, 'subject', 512), body: text(input.body, 'body', 65536), messageId: assignedMessageId };
      await execution.check();
      return execution.effect(`mcp_mail:${intentId.toLowerCase()}`, async () => {
        const admitted = await repository.beginMailIntent({ ...bound, intentId: intentId.toLowerCase(), assignedMessageId,
          recipientSha256: sha(Buffer.from(mail.to)),
          payloadSha256: sha(Buffer.from(canonical({ body: mail.body, subject: mail.subject }))) });
        if (admitted?.replayed === true) {
          if (admitted.status === 'accepted') return Object.freeze({ ok: true, messageId: assignedMessageId, replayed: true });
          fail('MCP_MAIL_UNCERTAIN', 'A prior SMTP attempt has no conclusive accepted receipt; cleanup is required');
        }
        await execution.check();
        let result;
        try { result = await sendMail(mail); }
        catch (error) { await repository.markMailUncertain({ ...bound, intentId: intentId.toLowerCase() }); throw error; }
        const returned = String(result?.messageId || '').replace(/^<|>$/g, '');
        if (result?.ok !== true || returned !== assignedMessageId) {
          await repository.markMailUncertain({ ...bound, intentId: intentId.toLowerCase() });
          fail('MCP_MAIL_UNCERTAIN', 'SMTP did not return the preassigned delivery receipt');
        }
        await repository.markMailAccepted({ ...bound, intentId: intentId.toLowerCase(), assignedMessageId });
        await execution.check();
        return Object.freeze({ ok: true, messageId: assignedMessageId });
      });
    },
    async cleanup(input) {
      const bound = scope(input?.scope);
      if (!UUID.test(input?.operationId || '')) fail('MCP_MAIL_INVALID', 'operationId is invalid');
      const operationId = input.operationId.toLowerCase();
      const pending = await repository.beginMailCleanup({ ...bound, operationId });
      if (pending.replayed === true) return this.readCleanup({ scope: bound, operationId });
      const messageIds = exactMessageIds(pending.messageIds);
      const deletion = await deleteMessages(messageIds);
      if (deletion?.ok !== true) fail('MCP_MAIL_CLEANUP_INCOMPLETE', 'Owned SMTP cleanup is incomplete');
      const observed = await listMessages(messageIds);
      if (observed?.ok !== true || (observed.messages || []).length !== 0) fail('MCP_MAIL_CLEANUP_INCOMPLETE', 'Owned SMTP messages remain observable');
      const completedAt = clock();
      if (typeof completedAt !== 'string' || !Number.isFinite(Date.parse(completedAt)) || new Date(completedAt).toISOString() !== completedAt) fail('MCP_MAIL_INVALID', 'Cleanup clock is invalid');
      const value = receipt({ ...bound, operationId }, completedAt, messageIds.length);
      return repository.completeMailCleanup({ ...bound, operationId, receipt: value, messageIds });
    },
    async readCleanup(input) {
      const bound = scope(input?.scope);
      if (!UUID.test(input?.operationId || '')) fail('MCP_MAIL_INVALID', 'operationId is invalid');
      const value = await repository.readMailCleanup({ ...bound, operationId: input.operationId.toLowerCase() });
      if (!value) return null;
      const claimed = value.receipt;
      const body = claimed && Object.fromEntries(Object.entries(claimed).filter(([key]) => key !== 'receiptSha256'));
      const expected = claimed && { version: VERSION, ...bound, operationId: input.operationId.toLowerCase(), status: 'completed',
        intentCount: claimed.intentCount, completedAt: claimed.completedAt, cleanupPending: false };
      if (!claimed || canonical(body) !== canonical(expected) || !Number.isSafeInteger(claimed.intentCount) || claimed.intentCount < 0
          || claimed.intentCount !== (value.messageIds || []).length
          || typeof claimed.completedAt !== 'string' || !Number.isFinite(Date.parse(claimed.completedAt))
          || new Date(claimed.completedAt).toISOString() !== claimed.completedAt
          || claimed.receiptSha256 !== sha(Buffer.from(canonical(body)))) fail('MCP_MAIL_RECEIPT_INVALID', 'Mail cleanup receipt is invalid');
      const messageIds = exactMessageIds(value.messageIds);
      const observed = await listMessages(messageIds);
      if (observed?.ok !== true || (observed.messages || []).length !== 0) fail('MCP_MAIL_CLEANUP_INCOMPLETE', 'Owned SMTP messages remain observable');
      return Object.freeze(claimed);
    },
  });
}

module.exports = { createDurableMcpMailResources, VERSION, _internals: { scope, executionFor, messageId, exactMessageIds, receipt, canonical, sha, SHA } };
