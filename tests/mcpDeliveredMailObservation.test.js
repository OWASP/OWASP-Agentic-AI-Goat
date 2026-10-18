'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const confusedDeputyObservation = require('../server/services/mcp/confusedDeputyObservation');
const mailClient = require('../server/services/mcp/mailClient');
const deliveredMail = require('../server/services/mcp/deliveredMailObservation');

const scope = Object.freeze({ targetId: '123e4567-e89b-42d3-a456-426614174000',
  platformOwnerId: 7, platformSessionId: 71, generation: 3 });
const runId = '223e4567-e89b-42d3-a456-426614174000';
const intentId = '323e4567-e89b-42d3-a456-426614174000';
const effectKey = 'mcp_indirect_injection_consequence';
const messageId = `mcp-${intentId}@dvaia.local`;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
const execution = overrides => ({ ownerKey: JSON.stringify(['MCP', '7']), durableGeneration: '3',
  runId, async check() {}, ...overrides });
const input = overrides => ({ scope, execution: execution(), intentId, runId, effectKey,
  messageId, to: 'mcp-audit-0123456789abcdefabcd@dvaia.invalid',
  subject: 'RE: Integration diagnostic', body: 'Ticket escalation report',
  protectedContent: 'DB_PASSWORD=TRAINING_ONLY\n', ...overrides });

function accepted(value) {
  return confusedDeputyObservation.trustWitness({ version: 'mcp-confused-deputy-observation.v1',
    runId: value.runId, effectKeySha256: sha(Buffer.from(value.effectKey)), ...value.scope,
    protectedRead: Object.freeze({ source: 'owned_runner_current_tool',
      sha256: sha(Buffer.from(value.protectedContent)), byteCount: Buffer.byteLength(value.protectedContent) }),
    delivery: Object.freeze({ status: 'accepted', external: true, recipient: value.to,
      intentId: value.intentId, messageId: value.messageId,
      payloadSha256: sha(Buffer.from(canonical({ body: value.body, subject: value.subject }))) }) });
}
function resource(first, second = first) {
  let calls = 0;
  return { get calls() { return calls; }, async observeAccepted() {
    calls++; const value = calls === 1 ? first : second;
    return value ? { confusedDeputyWitness: value } : {};
  } };
}
function response(body, ok = true) { return { ok, async json() { return body; } }; }
function realVerifier(value, calls) {
  return mailClient.verifyMessageReadback({ messageId: value.messageId, to: value.to,
    subject: value.subject, body: value.body }, { fetcher: async (url, options) => {
    calls.push({ url, options });
    if (url.includes('/api/v1/search')) return response({ messages_count: 1,
      messages: [{ ID: 'ownedMailpitRow', MessageID: `<${value.messageId}>` }] });
    return response({ ID: 'ownedMailpitRow', MessageID: value.messageId,
      To: [{ Address: value.to }], Subject: value.subject, Text: `${value.body}\r\n` });
  } });
}

test('joins durable accepted intent with trusted exact full-message readback as hash-only evidence', async () => {
  const value = input(); const witness = accepted(value); const durable = resource(witness); const fetches = [];
  const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
    verifyMessageReadback: expected => realVerifier(expected, fetches) });
  const observed = await observer.observe(value);
  assert.equal(deliveredMail.isTrustedObservation(observed), true);
  assert.equal(deliveredMail.acceptedWitnessFor(observed), witness);
  assert.equal(deliveredMail.acceptedWitnessFor({ ...observed }), null);
  assert.equal(observed.version, deliveredMail.VERSION); assert.equal(observed.runId, runId);
  assert.equal(observed.acceptedWitnessSha256, deliveredMail._internals.sha(Buffer.from(
    deliveredMail._internals.canonical(witness))));
  assert.match(observed.readbackReceiptSha256, /^[a-f0-9]{64}$/);
  assert.match(observed.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(durable.calls, 2); assert.equal(fetches.length, 2);
  assert.equal(fetches.every(call => call.options.redirect === 'error'), true);
  const serialized = JSON.stringify(observed);
  for (const raw of [value.to, value.subject, value.body, value.protectedContent, value.messageId]) {
    assert.equal(serialized.includes(raw), false);
  }
});

test('unrecorded canonical Message-ID and invalid owner, run, effect or generation never reach mailbox lookup', async () => {
  const base = input(); let fetches = 0;
  const cases = [
    { value: base, durable: resource(null) },
    { value: input({ scope: { ...scope, platformOwnerId: 8 } }), durable: resource(accepted(base)) },
    { value: input({ runId: crypto.randomUUID() }), durable: resource(accepted(base)) },
    { value: input({ effectKey: 'different-effect' }), durable: resource(accepted(base)) },
    { value: input({ execution: execution({ durableGeneration: '4' }) }), durable: resource(accepted(base)) },
  ];
  for (const entry of cases) {
    const observer = deliveredMail.createDeliveredMailObservation({ mailResources: entry.durable,
      verifyMessageReadback: async () => { fetches++; return {}; } });
    assert.equal(await observer.observe(entry.value), null);
  }
  assert.equal(fetches, 0);
});

test('retired, deleted or changed durable intent after mailbox fetch cannot produce joined evidence', async () => {
  const value = input(); const first = accepted(value); const changed = accepted({ ...value,
    protectedContent: `${value.protectedContent}changed` });
  for (const second of [null, changed]) {
    const durable = resource(first, second); let fetches = 0;
    const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
      verifyMessageReadback: expected => { fetches++; return realVerifier(expected, []); } });
    assert.equal(await observer.observe(value), null); assert.equal(fetches, 1); assert.equal(durable.calls, 2);
  }
});

test('unavailable, mismatched and forged readbacks fail without a joined receipt', async () => {
  const value = input(); const witness = accepted(value);
  for (const returned of [
    { ok: false, status: 'unavailable' }, { ok: false, status: 'mismatch' },
    { ok: true, status: 'verified', receipt: { version: 'mcp-mailpit-readback.v1',
      messageId, receiptSha256: 'a'.repeat(64) } },
  ]) {
    const durable = resource(witness);
    const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
      verifyMessageReadback: async () => returned });
    assert.equal(await observer.observe(value), null); assert.equal(durable.calls, 1);
  }
  assert.equal(deliveredMail.isTrustedObservation({}), false);
});

test('revoked execution during mailbox lookup fails before durable revalidation', async () => {
  let checks = 0; const value = input({ execution: execution({ async check() {
    checks++; if (checks === 3) throw Object.assign(Error('retired'), { code: 'MCP_RESOURCE_RETIRED' });
  } }) });
  const durable = resource(accepted(value));
  const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
    verifyMessageReadback: expected => realVerifier(expected, []) });
  await assert.rejects(observer.observe(value), { code: 'MCP_RESOURCE_RETIRED' });
  assert.equal(durable.calls, 1);
});

test('final authority callback cannot rewrite the snapshotted observation coordinates', async () => {
  let checks = 0; const mutableScope = { ...scope }; let value;
  const current = execution({ async check() {
    checks++;
    if (checks === 4) {
      value.scope = { ...mutableScope, platformOwnerId: 999, generation: 999 };
      value.runId = crypto.randomUUID(); value.effectKey = 'mutated-effect'; value.body = 'mutated body';
    }
  } });
  value = input({ scope: mutableScope, execution: current });
  const durable = resource(accepted(value));
  const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
    verifyMessageReadback: expected => realVerifier(expected, []) });
  const observed = await observer.observe(value);
  assert.equal(deliveredMail.isTrustedObservation(observed), true);
  assert.deepEqual({ targetId: observed.targetId, platformOwnerId: observed.platformOwnerId,
    platformSessionId: observed.platformSessionId, generation: observed.generation, runId: observed.runId },
  { ...scope, runId });
  assert.equal(observed.effectKeySha256, sha(Buffer.from(effectKey)));
});

test('oversized input is rejected before durable repository or mailbox work', async () => {
  for (const oversized of [
    { to: 'a'.repeat(321) }, { subject: 's'.repeat(513) }, { body: 'b'.repeat(65537) },
    { protectedContent: 'p'.repeat(65537) }, { messageId: 'm'.repeat(321) },
  ]) {
    const durable = resource(accepted(input())); let fetches = 0;
    const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
      verifyMessageReadback: async () => { fetches++; return {}; } });
    assert.equal(await observer.observe(input(oversized)), null);
    assert.equal(durable.calls, 0); assert.equal(fetches, 0);
  }
});

test('unavailable mailbox result cannot swallow cancellation during lookup', async () => {
  let revoked = false;
  const value = input({ execution: execution({ async check() {
    if (revoked) throw Object.assign(Error('cancelled'), { name: 'AbortError' });
  } }) });
  const durable = resource(accepted(value));
  const observer = deliveredMail.createDeliveredMailObservation({ mailResources: durable,
    verifyMessageReadback: async () => { revoked = true; return { ok: false, status: 'unavailable' }; } });
  await assert.rejects(observer.observe(value), { name: 'AbortError' });
  assert.equal(durable.calls, 1);
});
