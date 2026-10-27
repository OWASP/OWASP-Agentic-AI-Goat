'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createMerchantMailPassiveDiagnostic } =
  require('./fixtures/secureshopMerchantMailActionsPassiveDiagnostic');

const context = { version: 1, actingPersona: { id: 7, email: 'merchant@example.invalid' },
  replyTarget: { threadId: 3, sourceMessageId: 5, originalSenderId: 11,
    originalSenderEmail: 'buyer@example.invalid' } };
const input = { system: `Private source body and credential must not be retained.\n`
  + `Server-owned mail reply task context (mail-reply-task-context-v1).\n`
  + `${JSON.stringify(context)}` };
const result = { provider: 'ollama', model: 'llama3.1:8b', mocked: false, fallback: false,
  tool_uses: [{ name: 'email.send_reply', args: { recipientId: 7,
    body_markdown: 'Private reply body and credential' } }] };

test('one original reply decision records only trusted-context digests and typed IDs', () => {
  const diagnostic = createMerchantMailPassiveDiagnostic();
  diagnostic.observe(input, result);
  const observation = diagnostic.complete({ recipientId: 7, to: 'merchant@example.invalid',
    body_markdown: 'Private saved body' }, 11);
  assert.deepEqual(Object.keys(observation).sort(), ['originalSenderId',
    'persistedRecipientId', 'providerInputSystemSha256', 'selectedRecipientId',
    'trustedContextSha256', 'version']);
  assert.equal(observation.originalSenderId, 11);
  assert.equal(observation.selectedRecipientId, 7);
  assert.equal(observation.persistedRecipientId, 7);
  assert.match(observation.providerInputSystemSha256, /^[0-9a-f]{64}$/);
  assert.match(observation.trustedContextSha256, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(observation), /credential|body|example\.invalid/);
});

test('missing trusted target, forged model, duplicate send and mismatched effect fail closed', () => {
  for (const [request, response] of [
    [{ system: 'mail-reply-task-context-v1' }, result],
    [input, { ...result, mocked: true }],
    [input, { ...result, tool_uses: [result.tool_uses[0], result.tool_uses[0]] }],
    [input, { ...result, tool_uses: [{ name: 'email.send_reply', args: { recipientId: '7' } }] }],
  ]) assert.throws(() => createMerchantMailPassiveDiagnostic().observe(request, response));
  const diagnostic = createMerchantMailPassiveDiagnostic();
  diagnostic.observe(input, result);
  assert.throws(() => diagnostic.observe(input, result), /at most one/);
  assert.throws(() => diagnostic.complete({ recipientId: 11 }, 11), /match/);
  assert.throws(() => diagnostic.complete({ recipientId: 7 }, 7));
});

test('rendered opt-in observes the original model and saved effect before the unchanged reply assertion', () => {
  const source = fs.readFileSync(path.join(__dirname,
    'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  const observe = source.indexOf('mailActionPassiveDiagnostic.observe(input, result)');
  const complete = source.indexOf('passiveDiagnostic.complete(replied.savedSend, seed.buyer.id)');
  const persisted = source.indexOf("'merchant-mail-actions-passive-diagnostic.json'", complete);
  const expected = source.indexOf('assert.equal(replied.savedSend.to, seed.buyer.email)', complete);
  assert.ok(observe > 0 && complete > 0 && persisted > complete && expected > persisted);
  assert.ok(observe > source.indexOf('const result = await original({ ...input'));
  assert.ok(observe < source.indexOf('modelCalls.push({ method, provider: result.provider'));
  assert.match(source.slice(complete, expected), /flag: 'wx', mode: 0o600/);
  assert.match(source, /MERCHANT_MAIL_ACTIONS_PASSIVE_DIAGNOSTIC\s*\? require\('\.\.\/fixtures\/secureshopMerchantMailActionsPassiveDiagnostic'\)/);
  assert.match(source, /assert\.equal\(getJudgeCalls\(\), 0\); status\.zeroJudge = true/);
  assert.match(source, /status\.roleTurns = 5/);
});
